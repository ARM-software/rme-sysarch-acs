/** @file
 * Copyright (c) 2023-2026, Arm Limited or its affiliates. All rights reserved.
 * SPDX-License-Identifier : Apache-2.0

 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 **/
#include "val/include/val.h"
#include "val/include/val_interface.h"
#include "val/include/val_memory.h"
#include "val/include/val_exerciser.h"

#include "val/include/val_smmu.h"
#include "val/include/val_iovirt.h"
#include "val/include/val_pcie.h"
#include "val/include/val_pcie_enumeration.h"
#include "val/include/val_mem_interface.h"
#include "val/include/val_pe.h"
#include "val/include/val_el32.h"

#define TEST_NAME  "rme_smmu_blocks_request_at_registers_reset"
#define TEST_DESC  "SMMU blocks the access if its CNT REGs are under reset "
#define TEST_RULE  "RGFGZM"

#define TEST_DATA_BLK_SIZE  (4 * 1024)
#define DMA_LEN_BYTES      (TEST_DATA_BLK_SIZE / 2)
#define SEED_DATA          0xA5
#define BLOCKED_DATA       0xDE
#define READBACK_SENTINEL  0x5A

/* Configure and execute one DMA command, recording whether it may still be active. */
static uint32_t
execute_dma_transfer(uint64_t address, uint32_t direction, uint32_t instance, uint32_t *pending)
{
    uint32_t status;

    status = val_exerciser_set_param(DMA_ATTRIBUTES, address, DMA_LEN_BYTES, instance);
    if (status == EXERCISER_DMA_SUCCESS)
        status = val_exerciser_ops(START_DMA, direction, instance);
    if (status == EXERCISER_DMA_TIMEOUT || status == EXERCISER_DMA_BUSY)
        *pending = 1;
    if (status != EXERCISER_DMA_SUCCESS)
        val_print(ACS_PRINT_DEBUG, " DMA result 0x%x", status);
    return status;
}

/* Wait for the posted readback writes to reach the entire destination buffer. */
static uint32_t
read_exerciser_buffer(uint8_t *buffer, uint64_t address, uint32_t instance, uint32_t *pending)
{
    uint32_t poll, offset, status;

    val_memory_set(buffer, DMA_LEN_BYTES, READBACK_SENTINEL);
    val_pe_cache_clean_invalidate_range((uint64_t)buffer, DMA_LEN_BYTES);
    status = execute_dma_transfer(address, EDMA_FROM_DEVICE, instance, pending);
    if (status != EXERCISER_DMA_SUCCESS) {
        /* An errored/late command may still have posted writes in flight. */
        if (status == EXERCISER_DMA_INTERNAL_ERROR || status == EXERCISER_DMA_RESERVED ||
            status == EXERCISER_DMA_TIMEOUT || status == EXERCISER_DMA_BUSY)
            *pending = 2;
        return 1;
    }

    for (poll = 0; poll < TIMEOUT_SMALL; ++poll) {
        val_pe_cache_invalidate_range((uint64_t)buffer, DMA_LEN_BYTES);
        for (offset = 0; offset < DMA_LEN_BYTES; ++offset)
            if (buffer[offset] == READBACK_SENTINEL)
                break;
        if (offset == DMA_LEN_BYTES)
            return 0;
    }
    /* Trigger completion alone does not establish visibility of posted writes. */
    *pending = 2;
    val_print(ACS_PRINT_ERR, " DMA readback did not become visible for exerciser %x", instance);
    return 1;
}

/* Verify the permitted DMA path by copying data to the endpoint and back. */
static uint32_t
verify_dma_round_trip(uint8_t *source, uint64_t address, uint32_t instance, uint32_t *pending)
{
    uint8_t *destination = source + DMA_LEN_BYTES;

    val_pe_cache_clean_invalidate_range((uint64_t)source, DMA_LEN_BYTES);
    if (execute_dma_transfer(address, EDMA_TO_DEVICE, instance, pending) != EXERCISER_DMA_SUCCESS ||
        read_exerciser_buffer(destination, address + DMA_LEN_BYTES, instance, pending))
        return 1;
    if (val_memory_compare(source, destination, DMA_LEN_BYTES)) {
        val_print(ACS_PRINT_ERR, " DMA positive control failed for exerciser %x", instance);
        return 1;
    }
    return 0;
}

/* Check blocked reads at reset between successful DMA round trips. */
static uint32_t
verify_smmu_reset_dma_blocking(uint8_t *buffer, uint64_t address, uint32_t instance,
                              uint64_t smmu_base, uint32_t root_control, uint32_t *pending)
{
    uint32_t status, offset;
    uint8_t *destination = buffer + DMA_LEN_BYTES;

    /* Prove the same address, length and endpoint work with access permitted. */
    val_memory_set(buffer, DMA_LEN_BYTES, SEED_DATA);
    if (verify_dma_round_trip(buffer, address, instance, pending))
        return 1;

    /* The endpoint contains SEED_DATA; the prohibited read must not fetch this new data. */
    val_memory_set(buffer, DMA_LEN_BYTES, BLOCKED_DATA);
    val_pe_cache_clean_invalidate_range((uint64_t)buffer, DMA_LEN_BYTES);
    if (val_smmu_root_cr0_write(smmu_base, 0))
        return 1;

    val_print(ACS_PRINT_TEST, " Performing DMA with SMMU controls at reset values", 0);
    status = execute_dma_transfer(address, EDMA_TO_DEVICE, instance, pending);
    if (status != EXERCISER_DMA_SUCCESS && status != EXERCISER_DMA_INTERNAL_ERROR) {
        val_print(ACS_PRINT_ERR, " Invalid blocked-DMA result 0x%x", status);
        return 1;
    }

    /* The read has completed. Reopen access solely to retrieve the endpoint data. */
    if (val_smmu_root_cr0_write(smmu_base, root_control | SMMU_ROOT_ACCESSEN) ||
        read_exerciser_buffer(destination, address + DMA_LEN_BYTES, instance, pending))
        return 1;

    for (offset = 0; offset < DMA_LEN_BYTES; ++offset) {
        /* Allow an aborted read to retain the seed or a RAZ response to return zero. */
        if (destination[offset] != SEED_DATA && destination[offset] != 0) {
            val_print(ACS_PRINT_ERR, " Prohibited read changed endpoint data at offset 0x%x",
                      offset);
            return 1;
        }
    }

    /* An endpoint/configuration failure must not manufacture a protection PASS. */
    return verify_dma_round_trip(buffer, address, instance, pending);
}

/* Test each associated SMMU independently and restore it before the next device. */
static void
payload(void)
{
    uint32_t pe_index = val_pe_get_index_mpid(val_pe_get_mpid());
    uint32_t num_smmu = val_iovirt_get_smmu_info(SMMU_NUM_CTRL, 0);
    uint32_t num_exercisers;
    uint32_t instance, e_bdf, smmu_index;
    uint32_t root_control, ns_control, gbpa, pending, failed, restore_failed, tested = 0;
    uint64_t smmu_base;
    void *buffer, *physical;

    if (num_smmu == 0 || val_pcie_get_info(PCIE_INFO_NUM_ECAM, 0) == 0) {
        val_set_status(pe_index, "SKIP", 1);
        return;
    }
    num_exercisers = val_exerciser_get_info(EXERCISER_NUM_CARDS);
    for (instance = 0; instance < num_exercisers; ++instance) {
        e_bdf = val_exerciser_get_bdf(instance);
        smmu_index = val_iovirt_get_rc_smmu_index(PCIE_EXTRACT_BDF_SEG(e_bdf),
                                                PCIE_CREATE_BDF_PACKED(e_bdf));
        if (smmu_index == ACS_INVALID_INDEX)
            continue;
        if (val_exerciser_init(instance)) {
            val_set_status(pe_index, "FAIL", 1);
            return;
        }
        /* Do not change SMMU state underneath a command from an earlier test. */
        if (val_exerciser_ops(DMA_WAIT, 0, instance) > EXERCISER_DMA_RESERVED) {
            val_print(ACS_PRINT_ERR, " Exerciser already has an outstanding DMA: %x", instance);
            val_set_status(pe_index, "FAIL", 1);
            return;
        }
        tested = 1;
        pending = 0;
        smmu_base = val_smmu_get_info(SMMU_CTRL_BASE, smmu_index);
        if (!smmu_base || val_smmu_root_cr0_read(smmu_base, &root_control)) {
            val_print(ACS_PRINT_ERR, " Cannot save SMMU Root control for exerciser %x", instance);
            val_set_status(pe_index, "FAIL", 2);
            return;
        }
        ns_control = val_smmu_read_cfg(SMMUv3_CR0, smmu_index);
        if (val_smmu_read_gbpa(smmu_base, &gbpa)) {
            val_set_status(pe_index, "FAIL", 2);
            return;
        }
        physical = NULL;
        buffer = val_memory_alloc_cacheable(e_bdf, TEST_DATA_BLK_SIZE, &physical);
        if (buffer == NULL) {
            val_set_status(pe_index, "FAIL", 3);
            return;
        }

        /* Only change this endpoint's SMMU; preserve the original translation state. */
        failed = val_smmu_access_disable(smmu_base);
        if (!failed)
            failed = val_smmu_disable(smmu_index);
        if (!failed)
            failed = val_smmu_write_gbpa(smmu_base, gbpa & ~SMMUv3_GBPA_ABORT);
        if (!failed)
            failed = val_smmu_root_cr0_write(smmu_base, root_control | SMMU_ROOT_ACCESSEN);
        if (!failed)
            failed = verify_smmu_reset_dma_blocking(buffer, (uint64_t)physical, instance,
                                                    smmu_base, root_control, &pending);

        if (pending == 1 && val_exerciser_ops(DMA_WAIT, 0, instance) <= EXERCISER_DMA_RESERVED)
            pending = 0;
        if (pending) {
            /* No reference abort operation exists. Do not recycle a live DMA buffer. */
            val_pcie_disable_bme(e_bdf);
            if (val_smmu_access_disable(smmu_base))
                val_print(ACS_PRINT_ERR, " Failed to block access after DMA timeout", 0);
            val_print(ACS_PRINT_ERR,
                      " DMA not quiescent: buffer retained, BME disabled; reset exerciser %x",
                      instance);
            val_set_status(pe_index, "FAIL", 4);
            return;
        }

        /* Keep access blocked while restoring translation and Root control state. */
        restore_failed = val_smmu_access_disable(smmu_base);
        if (val_smmu_write_gbpa(smmu_base, gbpa))
            restore_failed = 1;
        if (ns_control & SMMUv3_CR0_SMMUEN) {
            if (val_smmu_enable(smmu_index))
                restore_failed = 1;
        } else if (val_smmu_disable(smmu_index)) {
            restore_failed = 1;
        }
        if (!restore_failed && val_smmu_root_cr0_write(smmu_base, root_control))
            restore_failed = 1;
        if (restore_failed) {
            val_print(ACS_PRINT_ERR, " SMMU state restoration failed at 0x%lx", smmu_base);
            failed = 1;
        }
        val_memory_free_cacheable(e_bdf, TEST_DATA_BLK_SIZE, buffer, physical);
        if (failed) {
            val_set_status(pe_index, "FAIL", 5);
            return;
        }
    }
    val_set_status(pe_index, tested ? "PASS" : "SKIP", 0);
}

uint32_t
rme_smmu_blocks_request_at_registers_reset_entry(uint32_t num_pe)
{
  num_pe = 1;
  uint32_t status = ACS_STATUS_FAIL;

  status = val_initialize_test(TEST_NAME, TEST_DESC, num_pe, TEST_RULE);
  if (status != ACS_STATUS_SKIP)
      val_run_test_payload(num_pe, payload, 0);

  /* Get the result from all PE and check for failure */
  status = val_check_for_error(num_pe);

  val_report_status(0, "END");

  return status;
}
