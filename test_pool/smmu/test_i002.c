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

#include "val/include/rme_acs_pe.h"
#include "val/include/rme_acs_smmu.h"
#include "val/include/rme_acs_pgt.h"
#include "val/include/rme_acs_iovirt.h"
#include "val/include/rme_acs_memory.h"
#include "val/include/rme_acs_pcie_enumeration.h"
#include "val/include/rme_acs_pcie.h"
#include "val/include/rme_acs_exerciser.h"
#include "val/include/rme_acs_el32.h"
#include "val/include/rme_test_entry.h"
#include "val/include/mem_interface.h"

#define TEST_NUM   (ACS_SMMU_TEST_NUM_BASE + 2)
#define TEST_DESC  "Check SMMU responds to GPT TLBI PAALLOS operation"
#define TEST_RULE  "SMMU_02"

#define TEST_DATA_NUM_PAGES  1
#define TEST_DATA 0xDE

/*
 * @brief  The test validates the PAS filter in IN-Active mode responds to GPT cache invalidate.
 * 1. Initialize PA1 from PE.
 * 2. PA1 is marked as NS in GPT.
 * 3. Issue DMA access from PCiE endpoint device to PA1.
 * 4. Expect successful access.
 * 5. Change PA1 resource pas as Root in GPT.
 * 6. Issue TLBI PAALLOS.
 * 7. Issue DMA access from PCiE endpoint device to PA1.
 * 8. Expect unsuccessful access.
 */
static
void
payload(void)
{
  uint32_t pe_index;
  uint32_t dma_len;
  uint32_t instance;
  uint32_t e_bdf;
  uint32_t cap_base;
  void *dram_buf_in_virt;
  void *dram_buf_out_virt;
  uint64_t dram_buf_in_phys;
  uint64_t dram_buf_out_phys;
  uint64_t dram_buf_in_iova;
  uint64_t dram_buf_out_iova;
  uint32_t num_smmus;
  uint32_t device_id, its_id;
  uint32_t page_size = val_memory_page_size();
  memory_region_descriptor_t mem_desc_array[2], *mem_desc;
  pgt_descriptor_t pgt_desc;
  smmu_master_attributes_t master;
  uint64_t ttbr;
  uint32_t test_data_blk_size = page_size * TEST_DATA_NUM_PAGES;
  uint32_t reg_value = 0;

  /* Enable all SMMUs */
  num_smmus = val_iovirt_get_smmu_info(SMMU_NUM_CTRL, 0);

  /* Initialize DMA master and memory descriptors */
  val_memory_set(&master, sizeof(master), 0);
  val_memory_set(mem_desc_array, sizeof(mem_desc_array), 0);
  mem_desc = &mem_desc_array[0];
  dram_buf_in_phys = 0;

  pe_index = val_pe_get_index_mpid(val_pe_get_mpid());

  /* Allocate a buffer to perform DMA tests on */
  dram_buf_in_virt = val_memory_alloc_pages(TEST_DATA_NUM_PAGES);
  if (!dram_buf_in_virt) {
      val_print(ACS_PRINT_ERR, "\n       Cacheable mem alloc failure", 0);
      val_set_status(pe_index, RESULT_FAIL(TEST_NUM, 03));
      return;
  }

  /* Set the virtual and physical addresses for test buffers */
  dram_buf_in_phys = (uint64_t)val_memory_virt_to_phys(dram_buf_in_virt);

  dram_buf_out_virt = dram_buf_in_virt + (test_data_blk_size / 2);
  dram_buf_out_phys = dram_buf_in_phys + (test_data_blk_size / 2);
  dma_len = test_data_blk_size / 2;

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

  /* Enable all SMMUs */
  for (instance = 0; instance < num_smmus; ++instance)
     val_smmu_enable(instance);

  instance = 0;
  /* if init fail moves to next exerciser */
  if (val_exerciser_init(instance))
        goto test_fail;

  /* Get exerciser bdf */
  e_bdf = val_exerciser_get_bdf(instance);
  val_print(ACS_PRINT_DEBUG, "\n       Exerciser BDF - 0x%x", e_bdf);

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
  if (val_pgt_get_attributes(pgt_desc, (uint64_t)dram_buf_in_virt, &mem_desc->attributes)) {
        val_print(ACS_PRINT_ERR, "\n       Unable to get memory attributes of the test buffer", 0);
        goto test_fail;
  }

  /* Get SMMU node index for this exerciser instance */
  master.smmu_index = val_iovirt_get_rc_smmu_index(PCIE_EXTRACT_BDF_SEG(e_bdf),
                                                   PCIE_CREATE_BDF_PACKED(e_bdf));


  dram_buf_in_iova = dram_buf_in_phys;
  dram_buf_out_iova = dram_buf_out_phys;
  if (master.smmu_index != ACS_INVALID_INDEX &&
      val_iovirt_get_smmu_info(SMMU_CTRL_ARCH_MAJOR_REV, master.smmu_index) == 3) {
      if (val_iovirt_get_device_info(PCIE_CREATE_BDF_PACKED(e_bdf),
                                     PCIE_EXTRACT_BDF_SEG(e_bdf),
                                     &device_id, &master.streamid,
                                     &its_id))
            goto test_fail;

      /* We create the requisite page tables and configure the SMMU for exerciser*/
      mem_desc->virtual_address = (uint64_t)dram_buf_in_virt + instance * test_data_blk_size;
      mem_desc->physical_address = dram_buf_in_phys;
      mem_desc->length = test_data_blk_size;
      mem_desc->attributes |= (PGT_STAGE1_AP_RW);

      //Map the memory as Non-secure for the instance
      //shared_data->generic_flag = SET;
      val_add_gpt_entry_el3(mem_desc->physical_address, GPT_NONSECURE);
      val_add_mmu_entry_el3(mem_desc->virtual_address, mem_desc->physical_address,
                      SHAREABLE_ATTR(OUTER_SHAREABLE) | NONSECURE_PAS);

      //Clear the memory
      val_memory_set((uint64_t *)dram_buf_in_virt, dma_len, 0);
      val_data_cache_ops_by_va((uint64_t)dram_buf_in_virt, CLEAN_AND_INVALIDATE);

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

      dram_buf_in_iova = mem_desc->virtual_address;
      dram_buf_out_iova = dram_buf_in_iova + (test_data_blk_size / 2);
  }

  /* Initialize the sender buffer with test specific data */
  val_memory_set((uint64_t *)dram_buf_in_virt, dma_len, TEST_DATA);
  val_data_cache_ops_by_va((uint64_t)dram_buf_in_virt, CLEAN_AND_INVALIDATE);

  /* Configure Exerciser to issue subsequent DMA transactions with Address Translated bit Set */
  val_exerciser_set_param(CFG_TXN_ATTRIBUTES, TXN_ADDR_TYPE, AT_TRANSLATED, instance);

  if (val_exerciser_set_param(DMA_ATTRIBUTES, dram_buf_in_phys, dma_len, instance)) {
        val_print(ACS_PRINT_ERR, "\n       DMA attributes setting failure %4x", instance);
        goto test_fail;
  }

  /* Trigger DMA from input buffer to exerciser memory */
  if (val_exerciser_ops(START_DMA, EDMA_TO_DEVICE, instance)) {
        val_print(ACS_PRINT_ERR, "\n       DMA write failure to exerciser %4x", instance);
        goto test_fail;
  }

  if (val_exerciser_set_param(DMA_ATTRIBUTES, dram_buf_out_iova, dma_len, instance)) {
        val_print(ACS_PRINT_ERR, "\n       DMA attributes setting failure %4x", instance);
        goto test_fail;
  }

  /* Trigger DMA from exerciser memory to output buffer*/
  if (val_exerciser_ops(START_DMA, EDMA_FROM_DEVICE, instance)) {
        val_print(ACS_PRINT_ERR, "\n       DMA read failure from exerciser %4x", instance);
        goto test_fail;
  }

  if (val_memory_compare(dram_buf_in_virt, dram_buf_out_virt, dma_len)) {
        val_print(ACS_PRINT_ERR, "\n       Data Comparasion failure for Exerciser %4x", instance);
        goto test_fail;
  }
  val_print(ACS_PRINT_DEBUG, "\n      The Nonsecure DMA transaction is successful", 0);

  //clear the memory before the next transaction
  val_memory_set((uint64_t *)dram_buf_in_virt, dma_len, 0);
  val_data_cache_ops_by_va((uint64_t)dram_buf_in_virt, CLEAN_AND_INVALIDATE);

  //Disable smmu now
  val_print(ACS_PRINT_INFO, "\n      Disabling SMMU of index: %d", master.smmu_index);
  val_smmu_disable(master.smmu_index);

  //Change the GPI for the PA
  val_add_gpt_entry_el3(dram_buf_in_phys, GPT_ROOT);

  //Enable smmu now
  val_print(ACS_PRINT_INFO, "\n      Enabling SMMU of index: %d", master.smmu_index);
  val_smmu_enable(master.smmu_index);

  if (val_exerciser_set_param(DMA_ATTRIBUTES, dram_buf_in_phys, dma_len, instance)) {
        val_print(ACS_PRINT_ERR, "\n GPI:      DMA attributes setting failure %4x", instance);
        goto test_fail;
  }

  // Trigger DMA from input buffer to exerciser memory
  if (!(val_exerciser_ops(START_DMA, EDMA_TO_DEVICE, instance))) {
        val_print(ACS_PRINT_ERR, "\n ERROR:      DMA write success to exerciser %4x", instance);
        goto test_fail;
  }

  val_set_status(pe_index, RESULT_PASS(TEST_NUM, 01));
  val_print(ACS_PRINT_INFO, "\n      The test is passed", 0);
  goto test_clean;

test_fail:
  val_set_status(pe_index, RESULT_FAIL(TEST_NUM, 01));

test_clean:
  val_add_gpt_entry_el3(dram_buf_in_phys, GPT_ANY);
  val_add_mmu_entry_el3((uint64_t)dram_buf_in_virt, dram_buf_in_phys,
                  SHAREABLE_ATTR(OUTER_SHAREABLE) | NONSECURE_PAS);

  //Clear the memory
  val_memory_set_el3((uint64_t *)dram_buf_in_virt, dma_len/2, 0);
  val_data_cache_ops_by_va_el3((uint64_t)dram_buf_in_virt, CLEAN_AND_INVALIDATE);

  /* Return the pages to the heap manager */
  val_memory_free_pages(dram_buf_in_virt, TEST_DATA_NUM_PAGES);

  /* Remove all address mappings for this exerciser */
  e_bdf = val_exerciser_get_bdf(instance);
  master.smmu_index = val_iovirt_get_rc_smmu_index(PCIE_EXTRACT_BDF_SEG(e_bdf),
                                                   PCIE_CREATE_BDF_PACKED(e_bdf));

  val_smmu_unmap(master);

  if (pgt_desc.pgt_base != (uint64_t) NULL)
      val_pgt_destroy(pgt_desc);

  if (val_pcie_find_capability(e_bdf, PCIE_ECAP, ECID_ATS, &cap_base) == PCIE_SUCCESS)
  {
        val_pcie_read_cfg(e_bdf, cap_base + ATS_CTRL, &reg_value);
        reg_value &= ATS_CACHING_DIS;
        val_pcie_write_cfg(e_bdf, cap_base + ATS_CTRL, reg_value);
  }

  /* Disable all SMMUs */
  for (instance = 0; instance < num_smmus; ++instance)
     val_smmu_disable(instance);

}

uint32_t
i002_entry(void)
{
  uint32_t num_pe = 1;
  uint32_t status = ACS_STATUS_FAIL;

  status = val_initialize_test(TEST_NUM, TEST_DESC, num_pe, TEST_RULE);
  if (status != ACS_STATUS_SKIP)
      val_run_test_payload(TEST_NUM, num_pe, payload, 0);

  /* Get the result from all PE and check for failure */
  status = val_check_for_error(TEST_NUM, num_pe, TEST_RULE);

  val_report_status(0, RME_ACS_END(TEST_NUM), TEST_RULE);

  return status;
}

