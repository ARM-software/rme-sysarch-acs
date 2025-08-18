/** @file
 * Copyright (c) 2023, 2025, Arm Limited or its affiliates. All rights reserved.
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
#include "val/include/val_iovirt.h"
#include "val/include/val_el32.h"

#define TEST_NAME  "rme_smmu_blocks_request_at_registers_reset"
#define TEST_DESC  "SMMU blocks the access if its CNT REGs are under reset "
#define TEST_RULE  "RGFGZM"

#define TEST_DATA_BLK_SIZE  (4*1024)
#define KNOWN_DATA 0xDE

/**
 * @brief  This function initiates the DMA transactions from PCIe endpoint device
 *         for the Non Secure address..
 * @param  *dram_buf1_virt - Pointer to the virtual address.
 * @param  *dram_buf1_phys - Pointer to the physical address.
 * @param  instance - INstance of the exerciser.
 * @return Returns 0 if DMA transaction is unsuccessful otherwise 1.
 */
static
uint32_t test_sequence(void *dram_buf1_virt, void *dram_buf1_phys, uint32_t instance)
{

  uint32_t dma_len;

  dma_len = TEST_DATA_BLK_SIZE / 2;

  /* Write dram_buf1 with known data and flush the buffer to main memory */
  val_memory_set(dram_buf1_virt, dma_len, KNOWN_DATA);
  val_data_cache_ops_by_va((addr_t)dram_buf1_virt, CLEAN_AND_INVALIDATE);

  /* Perform DMA OUT to copy contents of dram_buf1 to exerciser memory */
  val_print(ACS_PRINT_TEST, " Performing the DMA when SMMU is in reset", instance);
  val_exerciser_set_param(DMA_ATTRIBUTES, (uint64_t)dram_buf1_phys, dma_len, instance);
  if (!val_exerciser_ops(START_DMA, EDMA_TO_DEVICE, instance)) {
      val_print(ACS_PRINT_ERR, " DMA write is successful to exerciser %4x", instance);
      return 1;
  }
  //Otherwise, PASS
  return 0;
}

/*
 * @brief  The test validates that the SMMU when it's control register values are
 *         same as their reset values, blocks the memory access request from it's device.
 * 1. Program ACCESSEN flag to 0 & SMMUEN flag to 0 of SMMU_ROOT_CR0 and SMMU_CR0
 *    registers respectively.
 * 2. Initiate DMA access from PCIe endpoint device.
 * 3. Check that DMA accesses are unsuccessful.
 */
static
void
payload(void)
{

  uint32_t pe_index;
  uint32_t instance;
  uint32_t e_bdf, num_smmu;
  uint32_t smmu_index;
  uint64_t smmu_base;
  void *dram_buf1_virt;
  void *dram_buf1_phys;

  dram_buf1_virt = NULL;
  dram_buf1_phys = NULL;

  pe_index = val_pe_get_index_mpid(val_pe_get_mpid());

  num_smmu = val_iovirt_get_smmu_info(SMMU_NUM_CTRL, 0);

  /* Disable All SMMU's */
  for (instance = 0; instance < num_smmu; ++instance)
      val_smmu_disable(instance);

  /* Read the number of excerciser cards */
  instance = val_exerciser_get_info(EXERCISER_NUM_CARDS);

  while (instance-- != 0) {

    /* if init fail moves to next exerciser */
    if (val_exerciser_init(instance))
        continue;

    /* Get the exerciser BDF */
    e_bdf = val_exerciser_get_bdf(instance);

    /* Find SMMU node index for this exerciser instance */
    smmu_index = val_iovirt_get_rc_smmu_index(PCIE_EXTRACT_BDF_SEG(e_bdf),
                    PCIE_CREATE_BDF_PACKED(e_bdf));

    smmu_base = val_smmu_get_info(SMMU_CTRL_BASE, smmu_index);
    /* Disable SMMU globally by writing reset values to SMMU_CR0.SMMUEN and
     * SMMU_ROOT_CR0.ACCESSEN thereby setting the SMMU in reset state.
     */
    val_print(ACS_PRINT_TEST,
      " Disabling SMMU %d through it's Control registers in both Root and NS state", smmu_index);
    if (smmu_index != ACS_INVALID_INDEX) {
        if (val_smmu_access_disable(smmu_base))
        {
            val_print(ACS_PRINT_ERR, " Exerciser %x smmu root access disable error", instance);
            val_smmu_access_enable(smmu_base);
            val_set_status(pe_index, "FAIL", 01);
            return;
        }
        if (val_smmu_disable(smmu_index)) {
            val_print(ACS_PRINT_ERR, " Exerciser %x smmu disable error", instance);
            val_smmu_access_enable(smmu_base);
            val_set_status(pe_index, "FAIL", 02);
            return;
        }
    }

    /* Get a WB, outer shareable DDR Buffer which is Non-Secure of size TEST_DATA_BLK_SIZE */
    dram_buf1_virt = val_memory_alloc_cacheable(e_bdf, TEST_DATA_BLK_SIZE, &dram_buf1_phys);
    if (!dram_buf1_virt) {
      val_print(ACS_PRINT_ERR, " WB and OSH mem alloc failure %x", 02);
      val_smmu_access_enable(smmu_base);
      val_set_status(pe_index, "FAIL", 05);
      return;
    }

    if (test_sequence(dram_buf1_virt, dram_buf1_phys, instance))
        goto test_fail;
    /* Return this exerciser dma memory back to the heap manager */
    val_memory_free_cacheable(e_bdf, TEST_DATA_BLK_SIZE, dram_buf1_virt, dram_buf1_phys);

  }

  val_smmu_access_enable(smmu_base);
  val_set_status(pe_index, "PASS", 0);
  return;

test_fail:
  val_smmu_access_enable(smmu_base);
  val_set_status(pe_index, "FAIL", 06);
  val_memory_free_cacheable(e_bdf, TEST_DATA_BLK_SIZE, dram_buf1_virt, dram_buf1_phys);
  return;
}

uint32_t
rme_smmu_blocks_request_at_registers_reset_entry(void)
{
  uint32_t num_pe = 1;
  uint32_t status = ACS_STATUS_FAIL;

  status = val_initialize_test(TEST_NAME, TEST_DESC, num_pe, TEST_RULE);
  if (status != ACS_STATUS_SKIP)
      val_run_test_payload(num_pe, payload, 0);

  /* Get the result from all PE and check for failure */
  status = val_check_for_error(num_pe);

  val_report_status(0, "END");

  return status;
}

