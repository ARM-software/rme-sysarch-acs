/** @file
 * Copyright (c) 2023, Arm Limited or its affiliates. All rights reserved.
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
#include "val/include/rme_acs_val.h"
#include "val/include/val_interface.h"
#include "val/include/rme_acs_memory.h"
#include "val/include/rme_acs_exerciser.h"
#include "val/include/rme_acs_pe.h"
#include "val/include/rme_acs_iovirt.h"
#include "val/include/rme_acs_smmu.h"
#include "val/include/rme_acs_pcie.h"
#include "val/include/rme_acs_pcie_enumeration.h"
#include "val/include/rme_acs_pgt.h"
#include "val/include/rme_acs_el32.h"
#include "val/include/sys_config.h"

#define TEST_NUM   (ACS_RME_TEST_NUM_BASE  +  13)
#define TEST_DESC  "PCiE devices subjected to PAS protection check or not  "
#define TEST_RULE  "EXRCR_01"

#define TEST_DATA_NUM_PAGES  1
#define KNOWN_DATA 0xDE
#define NUM_PAS 4

uint32_t dma_len;
uint32_t test_data_blk_size;

static
uint32_t test_sequence1(void *dram_buf1_virt, void *dram_buf1_phys, uint32_t instance)
{

  uint64_t res_pas[4] = {GPT_REALM, GPT_NONSECURE, GPT_SECURE, GPT_ROOT}, PA;
  void *dram_buf2_virt;

  dram_buf2_virt = dram_buf1_virt + (test_data_blk_size / 2);
  dma_len = test_data_blk_size / 2;

  /* Write dram_buf1 with known data and flush the buffer to main memory */
  val_memory_set_el3((uint64_t *)dram_buf1_virt, dma_len, KNOWN_DATA);
  val_data_cache_ops_by_va_el3((uint64_t)dram_buf1_virt, CLEAN_AND_INVALIDATE);

  /* Perform DMA OUT to copy contents of dram_buf1 to exerciser memory */
  val_exerciser_set_param(DMA_ATTRIBUTES, (uint64_t)dram_buf1_phys, dma_len, instance);
  if (val_exerciser_ops(START_DMA, EDMA_TO_DEVICE, instance)) {
      val_print(ACS_PRINT_ERR, "\n      DMA write failure to exerciser %4x", instance);
      return 1;
  }

  /* Perform DMA IN to copy the content from exerciser memory to dram_buf1 */
  val_exerciser_set_param(DMA_ATTRIBUTES, (uint64_t)dram_buf2_virt, dma_len, instance);
  if (val_exerciser_ops(START_DMA, EDMA_FROM_DEVICE, instance)) {
      val_print(ACS_PRINT_ERR, "\n      DMA read failure from exerciser %4x", instance);
      return 1;
  }

  /* Compare the contents of ddr_buf1 and ddr_buf2 for NEW_DATA */
  if (val_memory_compare(dram_buf1_virt, dram_buf2_virt, dma_len)) {
      val_print(ACS_PRINT_ERR, "\n        DMA transaction to NonSecure Memory is incoherent \
                      and PAS protection check is not observed for Exerciser %4x", instance);
      return 1;
  }

  //Clean the memory before further process
  val_memory_set(dram_buf1_virt, dma_len, 0);
  val_data_cache_ops_by_va((addr_t)dram_buf1_virt, CLEAN_AND_INVALIDATE);

  val_print(ACS_PRINT_INFO, "\n DMA transaction is done for NS memory", 0);

  /* DMA transaction using Secure, Realm and Root memories */
  for (int mem_cnt = 0; mem_cnt < 4; ++mem_cnt) {

    PA = (uint64_t)dram_buf1_phys;

    /* Skip for a Non-Secure memory */
    if (res_pas[mem_cnt] == GPT_NONSECURE)
      continue;

    val_add_gpt_entry_el3(PA, res_pas[mem_cnt]);

    /* Perform DMA OUT to copy contents of PA to exerciser memory and
     * observe that DMA transaction is not successful
     * */
    val_exerciser_set_param(DMA_ATTRIBUTES, PA, dma_len/2, instance);
    if (!(val_exerciser_ops(START_DMA, EDMA_TO_DEVICE, instance))) {
      val_print(ACS_PRINT_ERR, "\n  PAS protection is not observed for GPI 0x%x", res_pas[mem_cnt]);
      //Clear the memory and it's protection by making it NS
      val_add_gpt_entry_el3(PA, GPT_ANY);
      val_add_mmu_entry_el3((uint64_t)dram_buf1_virt, PA,
                      SHAREABLE_ATTR(OUTER_SHAREABLE) | NONSECURE_PAS);
      val_memory_set_el3((uint64_t *)dram_buf1_virt, dma_len/2, 0);
      val_data_cache_ops_by_va_el3((uint64_t)dram_buf1_virt, CLEAN_AND_INVALIDATE);
      return 1;
    }
    //Clear the memory and it's protection by making it NS
    val_add_gpt_entry_el3(PA, GPT_ANY);
    val_add_mmu_entry_el3((uint64_t)dram_buf1_virt, PA,
                    SHAREABLE_ATTR(OUTER_SHAREABLE) | NONSECURE_PAS);
    val_memory_set_el3((uint64_t *)dram_buf1_virt, dma_len/2, 0);
    val_data_cache_ops_by_va_el3((uint64_t)dram_buf1_virt, CLEAN_AND_INVALIDATE);

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
    uint32_t instance;
    uint32_t e_bdf, num_smmu;
    void *dram_buf1_virt;
    void *dram_buf1_phys;
    uint32_t cap_base;
    uint32_t reg_value = 0;
    uint32_t device_id, its_id;
    uint32_t page_size = val_memory_page_size();
    uint64_t ttbr;
    smmu_master_attributes_t master;
    memory_region_descriptor_t mem_desc_array[2], *mem_desc;
    pgt_descriptor_t pgt_desc;

    dram_buf1_virt = NULL;
    dram_buf1_phys = NULL;

    test_data_blk_size = page_size * TEST_DATA_NUM_PAGES;
    pe_index = val_pe_get_index_mpid(val_pe_get_mpid());

    num_smmu = val_iovirt_get_smmu_info(SMMU_NUM_CTRL, 0);

    /* Get translation attributes via TCR and translation table base via TTBR */
    if (val_pe_reg_read_tcr(0 /*for TTBR0*/,
                            &pgt_desc.tcr)) {
      val_print(ACS_PRINT_ERR, "\n       TCR read failure", 0);
      goto test_fail;
    }

    if (val_pe_reg_read_ttbr(0 /*for TTBR0*/,
                             &ttbr)) {
      val_print(ACS_PRINT_ERR, "\n       TTBR0 read failure", 0);
      goto test_fail;
    }

    /* Initialize DMA master and memory descriptors */
    val_memory_set(&master, sizeof(master), 0);
    val_memory_set(mem_desc_array, sizeof(mem_desc_array), 0);
    mem_desc = &mem_desc_array[0];

    /* Disable All SMMU's */
    for (instance = 0; instance < num_smmu; ++instance)
        val_smmu_disable(instance);

    instance = 0;
    /* Initialise the exerciser */
    val_exerciser_init(instance);

    /* Get the exerciser BDF */
    e_bdf = val_exerciser_get_bdf(instance);

    /* Find SMMU node index for this exerciser instance */
    master.smmu_index = val_iovirt_get_rc_smmu_index(PCIE_EXTRACT_BDF_SEG(e_bdf),
                    PCIE_CREATE_BDF_PACKED(e_bdf));

    /* Enable SMMU globally so that the transaction passes
     * through the SMMU.
     */
    if (master.smmu_index != ACS_INVALID_INDEX) {
        if (val_smmu_enable(master.smmu_index)) {
            val_print(ACS_PRINT_ERR, "\n       Exerciser %x smmu disable error", instance);
            val_set_status(pe_index, RESULT_FAIL(TEST_NUM, 02));
            goto test_fail;
        }
    }

    /* Get a WB, outer shareable DDR Buffer of size test_data_blk_size */
    dram_buf1_virt = val_memory_alloc_cacheable(e_bdf,
                    test_data_blk_size * NUM_PAS, &dram_buf1_phys);
    if (!dram_buf1_virt) {
      val_print(ACS_PRINT_ERR, "\n       WB and OSH mem alloc failure %x", 02);
      val_set_status(pe_index, RESULT_FAIL(TEST_NUM, 02));
      goto test_fail;
    }

    /* If ATS Capability Not Present, Skip. */
    if (val_pcie_find_capability(e_bdf, PCIE_ECAP, ECID_ATS, &cap_base) != PCIE_SUCCESS)
       goto test_fail;

    val_pcie_read_cfg(e_bdf, cap_base + ATS_CTRL, &reg_value);
    reg_value |= ATS_CACHING_EN;
    val_pcie_write_cfg(e_bdf, cap_base + ATS_CTRL, reg_value);

    pgt_desc.pgt_base = (ttbr & AARCH64_TTBR_ADDR_MASK);
    pgt_desc.mair = val_pe_reg_read(MAIR_ELx);
    pgt_desc.stage = PGT_STAGE1;

    /* Get memory attributes of the test buffer, we'll use the same attibutes to create
     * our own page table later.
     */
    if (val_pgt_get_attributes(pgt_desc, (uint64_t)dram_buf1_virt, &mem_desc->attributes)) {
        val_print(ACS_PRINT_ERR, "\n       Unable to get memory attributes of the test buffer", 0);
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
      mem_desc->virtual_address = (uint64_t)dram_buf1_virt + instance * test_data_blk_size;
      mem_desc->physical_address = (uint64_t)dram_buf1_phys;
      mem_desc->length = test_data_blk_size;
      mem_desc->attributes |= (PGT_STAGE1_AP_RW);

      val_add_gpt_entry_el3(mem_desc->physical_address, GPT_NONSECURE);
      val_add_mmu_entry_el3(mem_desc->virtual_address, mem_desc->physical_address,
                      SHAREABLE_ATTR(OUTER_SHAREABLE) | NONSECURE_PAS);

      //Clear the memory
      val_memory_set_el3((uint64_t *)dram_buf1_virt, dma_len/2, 0);
      val_data_cache_ops_by_va_el3((uint64_t)dram_buf1_virt, CLEAN_AND_INVALIDATE);

      /* Need to know input and output address sizes before creating page table */
      pgt_desc.ias = val_smmu_get_info(SMMU_IN_ADDR_SIZE, master.smmu_index);
      if ((pgt_desc.ias) == 0) {
            val_print(ACS_PRINT_ERR,
                          "\n       Input address size of SMMU %d is 0", master.smmu_index);
            goto test_fail;
      }

      pgt_desc.oas = val_smmu_get_info(SMMU_OUT_ADDR_SIZE, master.smmu_index);
      if ((pgt_desc.oas) == 0) {
            val_print(ACS_PRINT_ERR,
                          "\n       Output address size of SMMU %d is 0", master.smmu_index);
            goto test_fail;
      }

      /* set pgt_desc.pgt_base to NULL to create new translation table, val_pgt_create
         will update pgt_desc.pgt_base to point to created translation table */
      pgt_desc.pgt_base = (uint64_t) NULL;
      if (val_pgt_create(mem_desc, &pgt_desc)) {
            val_print(ACS_PRINT_ERR,
                      "\n       Unable to create page table with given attributes", 0);
            goto test_fail;
      }

      /* Configure the SMMU tables for this exerciser to use this page table
         for VA to PA translations*/
      if (val_smmu_map(master, pgt_desc))
      {
            val_print(ACS_PRINT_ERR, "\n       SMMU mapping failed (%x)     ", e_bdf);
            goto test_fail;
      }
    }

    /* Configure Exerciser to issue subsequent DMA transactions with Address Translated bit Set */
    val_exerciser_set_param(CFG_TXN_ATTRIBUTES, TXN_ADDR_TYPE, AT_TRANSLATED, instance);

    if (test_sequence1(dram_buf1_virt, dram_buf1_phys, instance))
        goto test_fail;

    val_set_status(pe_index, RESULT_PASS(TEST_NUM, 0));
    goto test_clean;

test_fail:
    val_set_status(pe_index, RESULT_FAIL(TEST_NUM, 02));

test_clean:
  /* Return this exerciser dma memory back to the heap manager */
  val_memory_free_cacheable(e_bdf, test_data_blk_size * NUM_PAS, dram_buf1_virt, dram_buf1_phys);

  val_smmu_unmap(master);

  if (pgt_desc.pgt_base != (uint64_t) NULL) {
      val_pgt_destroy(pgt_desc);
  }

  if (val_pcie_find_capability(e_bdf, PCIE_ECAP, ECID_ATS, &cap_base) == PCIE_SUCCESS)
  {
        val_pcie_read_cfg(e_bdf, cap_base + ATS_CTRL, &reg_value);
        reg_value &= ATS_CACHING_DIS;
        val_pcie_write_cfg(e_bdf, cap_base + ATS_CTRL, reg_value);
  }

  /* Disable all SMMUs */
  for (instance = 0; instance < num_smmu; ++instance)
     val_smmu_disable(instance);

}

uint32_t
rme013_entry (void)
{
  uint32_t num_pe = 1;
  uint32_t status = ACS_STATUS_FAIL;

  status = val_initialize_test(TEST_NUM, TEST_DESC, num_pe, TEST_RULE);
  if (status != ACS_STATUS_SKIP) {
      val_run_test_payload(TEST_NUM, num_pe, payload, 0);
  }

  /* Get the result from all PE and check for failure */
  status = val_check_for_error(TEST_NUM, num_pe, TEST_RULE);

  val_report_status(0, RME_ACS_END (TEST_NUM), TEST_RULE);

  return status;
}
