/** @file
 * Copyright (c) 2023-2024, 2025-2026, Arm Limited or its affiliates. All rights reserved.
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
#include "val/include/val_pe.h"
#include "val/include/val_iovirt.h"
#include "val/include/val_smmu.h"
#include "val/include/val_pcie.h"
#include "val/include/val_pcie_enumeration.h"
#include "val/include/val_pgt.h"
#include "val/include/val_el32.h"

#define TEST_NAME  "rme_pcie_devices_support_gpc"
#define TEST_DESC  "PCiE devices subjected to PAS protection check or not  "
#define TEST_RULE  "RMZJXC"

#define TEST_DATA_NUM_PAGES  1
#define KNOWN_DATA 0xDE
#define NUM_PAS 4

uint32_t dma_len;
uint32_t attr;
uint32_t test_data_blk_size;

/* Keep cache maintenance at EL3 for buffers written through the EL3 mapping */
static uint32_t clean_invalidate_range_el3(uint64_t address, uint32_t length)
{
    uint64_t line_size = 4ULL << ((val_pe_reg_read(CTR_EL0) >> 16) & 0xf);
    uint64_t end = address + length;

    for (address &= ~(line_size - 1); address < end; address += line_size) {
        if (val_data_cache_ops_by_va_el3(address, CLEAN_AND_INVALIDATE))
            return 1;
    }
    /* Each EL3 cache operation completes with DSB SY. */
    return 0;
}

static
uint32_t test_sequence1(void *dram_buf1_virt, void *dram_buf1_phys, uint32_t instance)
{

  uint64_t res_pas[4] = {GPT_REALM, GPT_NONSECURE, GPT_SECURE, GPT_ROOT}, PA;
  void *dram_buf2_virt;
  uint64_t dram_buf2_phys;

  dram_buf2_virt = (uint8_t *)dram_buf1_virt + dma_len;
  dram_buf2_phys = (uint64_t)dram_buf1_phys + dma_len;

  val_print(ACS_PRINT_TEST, " DMA transaction for Non-Secure memory", 0);
  /* Write dram_buf1 with known data and flush the buffer to main memory */
  if (val_memory_set_el3((uint64_t *)dram_buf1_virt, dma_len, KNOWN_DATA))
  {
      val_print(ACS_PRINT_ERR, "\n        Failed to set memory to 0 for instance %4x", instance);
      return 1;
  }

  if (clean_invalidate_range_el3((uint64_t)dram_buf1_virt, dma_len))
  {
      val_print(ACS_PRINT_ERR,
        "\n        Failed to clean and invalidate dram_buf1 for instance %4x", instance);
      return 1;
  }

  /* Perform DMA OUT to copy contents of dram_buf1 to exerciser memory */
  if (val_exerciser_set_param(DMA_ATTRIBUTES, (uint64_t)dram_buf1_phys, dma_len, instance)) {
      val_print(ACS_PRINT_ERR, " Failed to program DMA source for exerciser %4x", instance);
      return 1;
  }
  /* The exerciser clears transaction attributes after each DMA command. */
  if (val_exerciser_set_param(CFG_TXN_ATTRIBUTES, TXN_ADDR_TYPE, AT_TRANSLATED, instance)) {
      val_print(ACS_PRINT_ERR, " Unable to configure translated DMA for exerciser %4x", instance);
      return 1;
  }
  if (val_exerciser_ops(START_DMA, EDMA_TO_DEVICE, instance)) {
      val_print(ACS_PRINT_ERR, " DMA write failure to exerciser %4x", instance);
      return 1;
  }

  /* AT=Translated requires the destination PA; the VA is only for CPU access. */
  if (val_exerciser_set_param(DMA_ATTRIBUTES, dram_buf2_phys, dma_len, instance)) {
      val_print(ACS_PRINT_ERR, " Failed to program DMA destination for exerciser %4x", instance);
      return 1;
  }
  if (val_exerciser_set_param(CFG_TXN_ATTRIBUTES, TXN_ADDR_TYPE, AT_TRANSLATED, instance)) {
      val_print(ACS_PRINT_ERR, " Unable to configure translated DMA for exerciser %4x", instance);
      return 1;
  }
  if (val_exerciser_ops(START_DMA, EDMA_FROM_DEVICE, instance)) {
      val_print(ACS_PRINT_ERR, " DMA read failure from exerciser %4x", instance);
      return 1;
  }

  /* Invalidate the CPU alias after the endpoint has completed its writes. */
  val_pe_cache_invalidate_range((uint64_t)dram_buf2_virt, dma_len);
  __asm__ volatile ("dsb sy" ::: "memory");

  /* Compare the contents of ddr_buf1 and ddr_buf2 for NEW_DATA */
  if (val_memory_compare(dram_buf1_virt, dram_buf2_virt, dma_len)) {
      val_print(ACS_PRINT_ERR, "  DMA transaction to NonSecure Memory is incoherent \
                      and PAS protection check is not observed for Exerciser %4x", instance);
      return 1;
  }

  //Clean the memory before further process
  val_memory_set(dram_buf1_virt, dma_len, 0);
  val_pe_cache_clean_invalidate_range((uint64_t)dram_buf1_virt, dma_len);
  __asm__ volatile ("dsb sy" ::: "memory");

  val_print(ACS_PRINT_DEBUG, " DMA transaction is done for NS memory", 0);

  /* DMA transaction using Secure, Realm and Root memories */
  for (int mem_cnt = 0; mem_cnt < 4; ++mem_cnt) {

    PA = (uint64_t)dram_buf1_phys;

    /* Skip for a Non-Secure memory */
    if (res_pas[mem_cnt] == GPT_NONSECURE)
      continue;

    if (val_add_gpt_entry_el3(PA, res_pas[mem_cnt]))
    {
      val_print(ACS_PRINT_ERR, "\n  Failed to add GPT entry for PA 0x%llx", PA);
      return 1;
    }

    val_print(ACS_PRINT_TEST, " DMA transaction for PAS: %lld", res_pas[mem_cnt]);

    /* Perform DMA OUT to copy contents of PA to exerciser memory and
     * observe that DMA transaction is not successful
     * */
    if (val_exerciser_set_param(DMA_ATTRIBUTES, PA, dma_len/2, instance)) {
      val_print(ACS_PRINT_ERR, " Failed to program protected DMA for GPI 0x%x", res_pas[mem_cnt]);
      return 1;
    }
    if (val_exerciser_set_param(CFG_TXN_ATTRIBUTES, TXN_ADDR_TYPE, AT_TRANSLATED, instance)) {
      val_print(ACS_PRINT_ERR, " Unable to configure translated DMA for exerciser %4x", instance);
      return 1;
    }
    if (val_exerciser_ops(START_DMA, EDMA_TO_DEVICE, instance) !=
        EXERCISER_DMA_INTERNAL_ERROR) {
      val_print(ACS_PRINT_ERR, " Expected completed DMA rejection for GPI 0x%x", res_pas[mem_cnt]);
      /* The payload drains DMA before its common GPT cleanup. */
      return 1;
    }
    //Clear the memory and it's protection by making it NS
    if (val_add_gpt_entry_el3(PA, GPT_ANY))
    {
      val_print(ACS_PRINT_ERR, "\n  Failed to clear GPT entry for PA 0x%llx", PA);
      return 1;
    }

    if (val_add_mmu_entry_el3((uint64_t)dram_buf1_virt, PA,
                      (attr | LOWER_ATTRS(PAS_ATTR(NONSECURE_PAS)))))
    {
      val_print(ACS_PRINT_ERR, "\n  Failed to add MMU entry for PA 0x%llx", PA);
      return 1;
    }

    if (val_memory_set_el3((uint64_t *)dram_buf1_virt, dma_len/2, 0))
    {
      val_print(ACS_PRINT_ERR, "\n  Failed to set memory to 0 for instance %4x", instance);
      return 1;
    }

    if (clean_invalidate_range_el3((uint64_t)dram_buf1_virt, dma_len/2))
    {
      val_print(ACS_PRINT_ERR,
        "\n  Failed to clean and invalidate dram_buf1 for instance %4x", instance);
      return 1;
    }

  }
  /* Return success */
  return 0;
}

/*
 * @brief  The test validates the PAS protection check of PCIe devices.
 * 1. Perform DMA transaction using Non-secure memory,
 * 2. See that the transactions are successful.
 * 3. Perform the same DMA transaction by changing the GPI to Secure, Realm and Root,
 * 4. See that the transactions result in failure.
 */
static
void
payload (void)
{

    uint32_t pe_index;
    uint32_t instance = 0;
    uint32_t e_bdf = 0, num_smmu;
    uint32_t smmu_instance;
    void *dram_buf1_virt;
    void *dram_buf1_phys;
    uint32_t cap_base = 0;
    uint32_t reg_value = 0;
    uint32_t device_id, its_id;
    uint32_t page_size = val_memory_page_size();
    uint32_t size;
    uint32_t smmu_mapped = 0;
    uint32_t gpt_modified = 0;
    uint32_t exerciser_ready = 0;
    uint32_t exerciser_found = 0;
    uint32_t num_exercisers;
    smmu_master_attributes_t master;
    memory_region_descriptor_t mem_desc_array[2], *mem_desc;
    pgt_descriptor_t cpu_pgt_desc;
    pgt_descriptor_t smmu_pgt_desc;
    uint64_t ttbr = 0;

    dram_buf1_virt = NULL;
    dram_buf1_phys = NULL;
    val_memory_set(&master, sizeof(master), 0);
    master.smmu_index = ACS_INVALID_INDEX;
    val_memory_set(&cpu_pgt_desc, sizeof(cpu_pgt_desc), 0);
    val_memory_set(&smmu_pgt_desc, sizeof(smmu_pgt_desc), 0);

    test_data_blk_size = page_size * TEST_DATA_NUM_PAGES;
    dma_len = test_data_blk_size / 2U;
    pe_index = val_pe_get_index_mpid(val_pe_get_mpid());

    attr = LOWER_ATTRS(PGT_ENTRY_ACCESS | SHAREABLE_ATTR(NON_SHAREABLE) | PGT_ENTRY_AP_RW);

    if (val_pcie_get_info(PCIE_INFO_NUM_ECAM, 0) == 0) {
        val_print(ACS_PRINT_WARN, " No PCIe ECAM regions discovered", 0);
        val_set_status(pe_index, "SKIP", 01);
        return;
    }

    num_exercisers = val_exerciser_get_info(EXERCISER_NUM_CARDS);
    if (num_exercisers == 0) {
        val_print(ACS_PRINT_WARN, " No exerciser cards discovered", 0);
        val_set_status(pe_index, "SKIP", 02);
        return;
    }

    num_smmu = val_iovirt_get_smmu_info(SMMU_NUM_CTRL, 0);
    if (num_smmu == 0) {
        val_print(ACS_PRINT_WARN, " No SMMU controllers discovered", 0);
        val_set_status(pe_index, "SKIP", 03);
        return;
    }

    for (instance = 0; instance < num_exercisers; ++instance) {
        if (val_exerciser_init(instance)) {
            val_print(ACS_PRINT_WARN, " Exerciser init failed for instance %d", instance);
            continue;
        }

        e_bdf = val_exerciser_get_bdf(instance);
        if (val_pcie_find_capability(e_bdf, PCIE_ECAP, ECID_ATS, &cap_base) != PCIE_SUCCESS) {
            val_print(ACS_PRINT_WARN, " ATS capability not found for BDF 0x%x", e_bdf);
            continue;
        }

        exerciser_found = 1;
        exerciser_ready = 1;
        break;
    }

    if (!exerciser_found) {
        val_print(ACS_PRINT_WARN, " No usable exerciser with ATS capability found", 0);
        val_set_status(pe_index, "SKIP", 04);
        return;
    }

    /* Disable All SMMU's */
    for (smmu_instance = 0; smmu_instance < num_smmu; ++smmu_instance)
        val_smmu_disable(smmu_instance);

    /* Get translation attributes via TCR and translation table base via TTBR */
    if (val_pe_reg_read_tcr(0 /*for TTBR0*/,
                            &cpu_pgt_desc.tcr)) {
      val_print(ACS_PRINT_ERR, " TCR read failure", 0);
      goto test_fail;
    }

    if (val_pe_reg_read_ttbr(0 /*for TTBR0*/,
                             &ttbr)) {
      val_print(ACS_PRINT_ERR, " TTBR0 read failure", 0);
      goto test_fail;
    }

    /* Initialize DMA master and memory descriptors */
    val_memory_set(mem_desc_array, sizeof(mem_desc_array), 0);
    mem_desc = &mem_desc_array[0];

    /* Find SMMU node index for this exerciser instance */
    master.smmu_index = val_iovirt_get_rc_smmu_index(PCIE_EXTRACT_BDF_SEG(e_bdf),
                    PCIE_CREATE_BDF_PACKED(e_bdf));

    if (master.smmu_index >= num_smmu) {
        val_print(ACS_PRINT_ERR, " No SMMU mapping found for exerciser BDF 0x%x", e_bdf);
        goto test_fail;
    }

    /* Enable SMMU globally so that the transaction passes
     * through the SMMU.
     */
    if (master.smmu_index != ACS_INVALID_INDEX) {
        if (val_smmu_enable(master.smmu_index)) {
            val_print(ACS_PRINT_ERR, " Exerciser %x smmu disable error", instance);
            val_set_status(pe_index, "FAIL", 02);
            goto test_fail;
        }
    }

    /* Get a WB, outer shareable DDR Buffer of size test_data_blk_size */
    size = val_get_min_tg();
    dram_buf1_phys = (void *)val_get_free_pa(test_data_blk_size * NUM_PAS, size);
    dram_buf1_virt = (void *)val_get_free_va(test_data_blk_size * NUM_PAS);
    /* The free-address helpers return 1 on failure. */
    if ((uint64_t)dram_buf1_phys <= 1U || (uint64_t)dram_buf1_virt <= 1U) {
        val_print(ACS_PRINT_ERR, " Unable to allocate DMA test VA/PA buffers", 0);
        goto test_fail;
    }
    attr = LOWER_ATTRS(PGT_ENTRY_ACCESS | SHAREABLE_ATTR(NON_SHAREABLE) | PGT_ENTRY_AP_RW);


    /* ATS capability was verified while selecting the exerciser. */
    val_pcie_read_cfg(e_bdf, cap_base + ATS_CTRL, &reg_value);
    reg_value |= ATS_CACHING_EN;
    val_pcie_write_cfg(e_bdf, cap_base + ATS_CTRL, reg_value);

    cpu_pgt_desc.pgt_base = (ttbr & AARCH64_TTBR_ADDR_MASK);
    cpu_pgt_desc.mair = val_pe_reg_read(MAIR_ELx);
    cpu_pgt_desc.stage = PGT_STAGE1;

    cpu_pgt_desc.ias = 48;
    cpu_pgt_desc.oas = 48;
    mem_desc->virtual_address = (uint64_t)dram_buf1_virt;
    mem_desc->physical_address = (uint64_t)dram_buf1_phys;
    mem_desc->length = test_data_blk_size * NUM_PAS;
    mem_desc->attributes |= (PGT_STAGE1_AP_RW);

  if (val_pgt_create(mem_desc, &cpu_pgt_desc)) {
        val_print(ACS_PRINT_ERR,
                      " Unable to create page table with given attributes", 0);
            goto test_fail;
      }

    /* Get memory attributes of the test buffer, we'll use the same attibutes to create
     * our own page table later.
     */
    if (val_pgt_get_attributes(cpu_pgt_desc, (uint64_t)dram_buf1_virt, &mem_desc->attributes)) {
        val_print(ACS_PRINT_ERR, " Unable to get memory attributes of the test buffer", 0);
        goto test_fail;
    }

    if (master.smmu_index != ACS_INVALID_INDEX &&
        val_iovirt_get_smmu_info(SMMU_CTRL_ARCH_MAJOR_REV, master.smmu_index) == 3) {
      if (val_iovirt_get_device_info(PCIE_CREATE_BDF_PACKED(e_bdf),
                                     PCIE_EXTRACT_BDF_SEG(e_bdf),
                                     &device_id, &master.streamid,
                                     &its_id))
            goto test_fail;

      /* We create the requisite page tables and configure the SMMU for exerciser*/
      mem_desc->virtual_address = (uint64_t)dram_buf1_virt;
      mem_desc->physical_address = (uint64_t)dram_buf1_phys;
      mem_desc->length = test_data_blk_size;
      mem_desc->attributes |= (PGT_STAGE1_AP_RW);

      /* Include partial GPT setup failures in the common cleanup path. */
      gpt_modified = 1;
      if (val_add_gpt_entry_el3(mem_desc->physical_address, GPT_NONSECURE))
      {
          val_print(ACS_PRINT_ERR,
            "\n       Failed to add GPT entry for PA 0x%llx", mem_desc->physical_address);
          goto test_fail;
      }

      if (val_add_mmu_entry_el3(mem_desc->virtual_address, mem_desc->physical_address,
                      (attr | LOWER_ATTRS(PAS_ATTR(NONSECURE_PAS)))))
      {
          val_print(ACS_PRINT_ERR,
            "\n       Failed to add MMU entry for PA 0x%llx", mem_desc->physical_address);
          goto test_fail;
      }

      /* Prepare both halves so dirty CPU lines cannot overwrite incoming DMA. */
      if (val_memory_set_el3((uint64_t *)dram_buf1_virt, test_data_blk_size, 0))
      {
          val_print(ACS_PRINT_ERR,
            "\n       Failed to set memory to 0 for instance %4x", instance);
          goto test_fail;
      }

      if (clean_invalidate_range_el3((uint64_t)dram_buf1_virt, test_data_blk_size))
      {
          val_print(ACS_PRINT_ERR,
            "\n       Failed to clean and invalidate dram_buf1 for instance %4x", instance);
          goto test_fail;
      }

      /* Need to know input and output address sizes before creating page table */
      smmu_pgt_desc = cpu_pgt_desc;
      /* Never let an early failure destroy the CPU's existing page table. */
      smmu_pgt_desc.pgt_base = (uint64_t) NULL;
      smmu_pgt_desc.ias = val_smmu_get_info(SMMU_IN_ADDR_SIZE, master.smmu_index);
      if ((smmu_pgt_desc.ias) == 0) {
            val_print(ACS_PRINT_ERR,
                          " Input address size of SMMU %d is 0", master.smmu_index);
            goto test_fail;
      }

      smmu_pgt_desc.oas = val_smmu_get_info(SMMU_OUT_ADDR_SIZE, master.smmu_index);
      if ((smmu_pgt_desc.oas) == 0) {
            val_print(ACS_PRINT_ERR,
                          " Output address size of SMMU %d is 0", master.smmu_index);
            goto test_fail;
      }

      if (val_pgt_create(mem_desc, &smmu_pgt_desc)) {
            val_print(ACS_PRINT_ERR,
                      " Unable to create page table with given attributes", 0);
            goto test_fail;
      }

      /* Configure the SMMU tables for this exerciser to use this page table
         for VA to PA translations*/
      if (val_smmu_map(master, smmu_pgt_desc))
      {
            val_print(ACS_PRINT_ERR, " SMMU mapping failed (%x)     ", e_bdf);
            goto test_fail;
      }
      smmu_mapped = 1;
    }

    if (test_sequence1(dram_buf1_virt, dram_buf1_phys, instance))
        goto test_fail;

    val_set_status(pe_index, "PASS", 0);
    goto test_clean;

test_fail:
    val_set_status(pe_index, "FAIL", 02);

test_clean:
  /* A timed-out command can still access the buffers and translation tables. */
  if (exerciser_ready &&
      val_exerciser_ops(DMA_WAIT, 0, instance) > EXERCISER_DMA_RESERVED) {
      val_pcie_disable_bme(e_bdf);
      val_print(ACS_PRINT_ERR, " DMA still active; retain mappings and reset exerciser %x",
                instance);
      val_set_status(pe_index, "FAIL", 02);
      return;
  }

  /* Retain the test's existing GPT_ANY teardown, including all failure paths. */
  if (gpt_modified && val_add_gpt_entry_el3((uint64_t)dram_buf1_phys, GPT_ANY)) {
      val_pcie_disable_bme(e_bdf);
      val_print(ACS_PRINT_ERR, " Failed to clear test GPT entry for PA 0x%llx",
                (uint64_t)dram_buf1_phys);
      val_set_status(pe_index, "FAIL", 02);
      return;
  }

  if (smmu_mapped)
      val_smmu_unmap(master);

  if (smmu_pgt_desc.pgt_base != (uint64_t) NULL) {
      val_pgt_destroy(smmu_pgt_desc);
  }

  if (exerciser_ready &&
      (val_pcie_find_capability(e_bdf, PCIE_ECAP, ECID_ATS, &cap_base) == PCIE_SUCCESS))
  {
        val_pcie_read_cfg(e_bdf, cap_base + ATS_CTRL, &reg_value);
        reg_value &= ATS_CACHING_DIS;
        val_pcie_write_cfg(e_bdf, cap_base + ATS_CTRL, reg_value);
  }

  /* Disable all SMMUs */
  for (smmu_instance = 0; smmu_instance < num_smmu; ++smmu_instance)
     val_smmu_disable(smmu_instance);

}

uint32_t
rme_pcie_devices_support_gpc_entry(uint32_t num_pe)
{
  num_pe = 1;
  uint32_t status = ACS_STATUS_FAIL;

  status = val_initialize_test(TEST_NAME, TEST_DESC, num_pe, TEST_RULE);
  if (status != ACS_STATUS_SKIP) {
      val_run_test_payload(num_pe, payload, 0);
  }

  /* Get the result from all PE and check for failure */
  status = val_check_for_error(num_pe);

  val_report_status(0, "END");

  return status;
}
