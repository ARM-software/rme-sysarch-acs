/** @file
 * Copyright (c) 2025, Arm Limited or its affiliates. All rights reserved.
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
#include "val/include/rme_acs_smmu.h"
#include "val/include/rme_acs_dpt.h"
#include "val/include/rme_acs_da.h"
#include "val/include/rme_acs_exerciser.h"
#include "val/include/rme_acs_memory.h"
#include "val/include/rme_acs_iovirt.h"
#include "val/include/rme_acs_pgt.h"
#include "val/include/rme_acs_pcie.h"
#include "val/include/rme_acs_pe.h"
#include "val/include/rme_acs_el32.h"

#define TEST_NAME "dpt_system_resource_invalid"
#define TEST_DESC  "TDI DPT Check - System Resource - Invalid Access       "
#define TEST_RULE  "RQRMPD"

#define TEST_DATA_NUM_PAGES 1
#define TEST_DATA 0xAB

static
void
payload(void)
{
  uint32_t pe_index;
  uint32_t instance, num_exercisers;
  uint32_t bdf, rp_bdf, da_cap_base, cap_base;
  uint32_t dma_len, test_data_blk_size;
  uint32_t status, reg_value;
  uint32_t count;
  void *dram_buf_in_virt, *dram_buf_in_virt2;
  uint64_t va1, va2, bar_base;
  uint32_t test_fail = 0, test_skip = 1;
  uint32_t sel_str_lock_bit;
  uint32_t stream_id;
  uint32_t pgt_attr_el3;
  uint32_t cfg_addr;
  uint32_t str_index;
  uint32_t device_id, its_id;
  uint32_t page_size = val_memory_page_size();
  smmu_master_attributes_t master;
  memory_region_descriptor_t mem_desc_array[2], *mem_desc;
  pgt_descriptor_t pgt_desc;
  uint64_t translated_addr, m_vir_addr, dram_buf_in_phys;

  pe_index = val_pe_get_index_mpid(val_pe_get_mpid());

  test_data_blk_size = page_size * TEST_DATA_NUM_PAGES;
  dma_len = test_data_blk_size / 2;

  num_exercisers = val_exerciser_get_info(EXERCISER_NUM_CARDS);

  /* Initialize DMA master and memory descriptors */
  val_memory_set(&master, sizeof(master), 0);
  val_memory_set(mem_desc_array, sizeof(mem_desc_array), 0);
  mem_desc = &mem_desc_array[0];

  /* Map the Pointers in EL3 as NS Access PAS so that EL3 can access this struct pointers */
  pgt_attr_el3 = LOWER_ATTRS(PGT_ENTRY_ACCESS | SHAREABLE_ATTR(OUTER_SHAREABLE) |
                                 PGT_ENTRY_AP_RW | PAS_ATTR(NONSECURE_PAS));
  val_add_mmu_entry_el3((uint64_t)(&pgt_desc), (uint64_t)(&pgt_desc), pgt_attr_el3);
  val_add_mmu_entry_el3((uint64_t)(&master), (uint64_t)(&master), pgt_attr_el3);
  val_add_mmu_entry_el3((uint64_t)(mem_desc), (uint64_t)(mem_desc), pgt_attr_el3);

  for (instance = 0; instance < num_exercisers; ++instance)
  {
      /* if init fail moves to next exerciser */
      if (val_exerciser_init(instance))
          continue;

      bdf = val_exerciser_get_bdf(instance);
      val_print(ACS_PRINT_TEST, " Exerciser BDF - 0x%x", bdf);

      /* Get the RP of the exerciser */
      if (val_pcie_get_rootport(bdf, &rp_bdf))
          continue;

      /* If ATS Capability Not Present, Skip. */
      if (val_pcie_find_capability(bdf, PCIE_ECAP, ECID_ATS, &cap_base) != PCIE_SUCCESS)
            continue;

      val_print(ACS_PRINT_TEST, " Enabling the ATS Cache for the exerciser: 0x%x", bdf);
      val_pcie_read_cfg(bdf, cap_base + ATS_CTRL, &reg_value);
      reg_value |= ATS_CACHING_EN;
      val_pcie_write_cfg(bdf, cap_base + ATS_CTRL, reg_value);

      test_skip = 0;

      /* Check for DA Capability */
      if (val_pcie_find_da_capability(rp_bdf, &da_cap_base) != PCIE_SUCCESS)
      {
          val_print(ACS_PRINT_ERR,
                        " PCIe DA DVSEC capability not present,bdf 0x%x", bdf);
          continue;
      }

      /* Enable RMEDA_CTL1.TDISP_EN*/
      if (val_pcie_enable_tdisp(rp_bdf))
      {
          val_print(ACS_PRINT_ERR, " Unable to set tdisp_en for BDF: 0x%x", rp_bdf);
          test_fail++;
          continue;
      }

      /* Establish IDE Stream between RP and Exerciser EP */
      count = 1;
      stream_id = val_generate_stream_id();

      status = val_ide_establish_stream(bdf, count, stream_id,
                                     PCIE_CREATE_BDF_PACKED(bdf));
      if (status)
      {
          val_print(ACS_PRINT_ERR, " Failed to establish stream for bdf: 0x%x", bdf);
          test_fail++;
          continue;
      }

      status = val_ide_establish_stream(rp_bdf, count, stream_id,
                                     PCIE_CREATE_BDF_PACKED(bdf));
      if (status)
      {
          val_print(ACS_PRINT_ERR, " Failed to establish stream for RP bdf: 0x%x", rp_bdf);
          test_fail++;
          continue;
      }

      val_pcie_read_cfg(rp_bdf, da_cap_base + RMEDA_CTL2, &reg_value);
      val_print(ACS_PRINT_DEBUG, " RMEDA_CTL2 before write = 0x%llx", reg_value);

      /* Lock the corresponding Selective IDE register block in RMEDA_CTL2 register */
      str_index = count - 1;
      sel_str_lock_bit = 1 << (str_index % 32);
      val_print(ACS_PRINT_DEBUG, " Sel steam lock bit: 0x%lx", sel_str_lock_bit);

      /* Map the configuration address before writing from root as ROOT PAS */
      va1 = val_get_free_va(val_get_min_tg());
      cfg_addr = val_pcie_get_bdf_config_addr(rp_bdf);
      pgt_attr_el3 = LOWER_ATTRS(PGT_ENTRY_ACCESS | SHAREABLE_ATTR(OUTER_SHAREABLE)
                          | GET_ATTR_INDEX(DEV_MEM_nGnRnE) | PGT_ENTRY_AP_RW | PAS_ATTR(ROOT_PAS));
      val_add_mmu_entry_el3(va1, cfg_addr, pgt_attr_el3);

      shared_data->num_access = 1;
      shared_data->shared_data_access[0].addr = va1 + da_cap_base + RMEDA_CTL2;
      shared_data->shared_data_access[0].data = sel_str_lock_bit;
      shared_data->shared_data_access[0].access_type = WRITE_DATA;
      val_pe_access_mut_el3();

      val_pcie_read_cfg(rp_bdf, da_cap_base + RMEDA_CTL2, &reg_value);
      val_print(ACS_PRINT_DEBUG, " RMEDA_CTL2 after write = 0x%llx", reg_value);

      /* Map the MMIO bar to REALM PAS */
      val_pcie_get_mmio_bar(bdf, &bar_base);
      if (bar_base == 0)
          continue;

      va2 = val_get_free_va(val_get_min_tg());
      pgt_attr_el3 = LOWER_ATTRS(PGT_ENTRY_ACCESS | SHAREABLE_ATTR(OUTER_SHAREABLE)
                          | GET_ATTR_INDEX(DEV_MEM_nGnRnE) | PGT_ENTRY_AP_RW | PAS_ATTR(REALM_PAS));
      val_add_mmu_entry_el3(va2, bar_base, pgt_attr_el3);

      /* Transition the EP to TDISP RUN state */
      if (val_device_lock(bdf))
      {
          val_print(ACS_PRINT_ERR, " Failed to lock the device: 0x%lx", bdf);
          test_fail++;
          continue;
      }

      /* Create a buffer of size TEST_DMA_SIZE in DRAM */
      dram_buf_in_virt = val_memory_alloc_pages(TEST_DATA_NUM_PAGES);
      dram_buf_in_phys = (uint64_t)val_memory_virt_to_phys(dram_buf_in_virt);

      /* Change the AccessPAS of the buffer to Realm PAS */
      val_add_gpt_entry_el3(dram_buf_in_phys, GPT_ANY);
      pgt_attr_el3 = LOWER_ATTRS(PGT_ENTRY_ACCESS | SHAREABLE_ATTR(OUTER_SHAREABLE)
                        | GET_ATTR_INDEX(DEV_MEM_nGnRnE) | PGT_ENTRY_AP_RW | PAS_ATTR(REALM_PAS));
      val_add_mmu_entry_el3((uint64_t)dram_buf_in_virt, (uint64_t)dram_buf_in_virt, pgt_attr_el3);


      /* Set the buffer to value 0 */
      val_memory_set_el3(dram_buf_in_virt, test_data_blk_size, 0);
      val_pe_cache_clean_invalidate_range((uint64_t)dram_buf_in_virt,
                                          (uint64_t)(test_data_blk_size));

      dram_buf_in_virt2 = dram_buf_in_virt + dma_len;

      /* Set the input buffer with the Test Data */
      val_memory_set_el3(dram_buf_in_virt, dma_len, TEST_DATA);
      val_pe_cache_clean_invalidate_range((uint64_t)dram_buf_in_virt, (uint64_t)(dma_len));

      mem_desc->virtual_address = (uint64_t)dram_buf_in_virt;
      mem_desc->physical_address = (uint64_t)dram_buf_in_phys;
      mem_desc->length = test_data_blk_size;
      mem_desc->attributes = PGT_STAGE2_AP_RW;

      /* Find SMMU node index for this exerciser instance */
      master.smmu_index = val_iovirt_get_rc_smmu_index(PCIE_EXTRACT_BDF_SEG(bdf),
                          PCIE_CREATE_BDF_PACKED(bdf));

      /* Enable SMMU globally so that the transaction passes
       * through the SMMU.
       */
      if (master.smmu_index != ACS_INVALID_INDEX) {
          if (val_smmu_enable(master.smmu_index)) {
                val_print(ACS_PRINT_ERR, " Exerciser %x smmu disable error", instance);
                val_set_status(pe_index, "FAIL", 02);
                test_fail++;
                continue;
          }
      }

      val_iovirt_get_device_info(PCIE_CREATE_BDF_PACKED(bdf),
                                     PCIE_EXTRACT_BDF_SEG(bdf),
                                     &device_id, &master.streamid,
                                     &its_id);

      /* Get the VTTBR_EL2 and VTCR_EL2, populate them if they aren't already */
      if (val_pe_get_vtcr(&pgt_desc.vtcr))
      {
          val_print(ACS_PRINT_ERR, " Failed to get the VTCR", 0);
          test_fail++;
          goto free_mem;
      }

      /* Need to know input and output address sizes before creating page table */
      pgt_desc.ias = val_smmu_get_info(SMMU_IN_ADDR_SIZE, master.smmu_index);
      if ((pgt_desc.ias) == 0) {
          val_print(ACS_PRINT_ERR,
                          " Input address size of SMMU %d is 0", master.smmu_index);
          test_fail++;
          goto free_mem;
      }

      pgt_desc.oas = val_smmu_get_info(SMMU_OUT_ADDR_SIZE, master.smmu_index);
      if ((pgt_desc.oas) == 0) {
          val_print(ACS_PRINT_ERR,
                          " Output address size of SMMU %d is 0", master.smmu_index);
          test_fail++;
          goto free_mem;
      }

      /* Set pgt_desc.pgt_base to NULL to create new translation table, val_realm_pgt_create
         will update pgt_desc.pgt_base to point to created translation table */
      pgt_desc.pgt_base = (uint64_t) NULL;
      val_rlm_pgt_create(mem_desc, &pgt_desc);

      /* Write pgt_base to the VTTBR register so that EL3 can update while programming STE */
      val_pe_reg_write(VTTBR, pgt_desc.pgt_base);

      /* Enable the stage2 mapping for Realm SMMU Transaction */
      master.stage2 = 1;
      val_print(ACS_PRINT_DEBUG, " Stream ID: 0x%lx", master.streamid);

      /* Configure the SMMU tables for this exerciser to use this page table
         for VA to PA translations */
      val_smmu_rlm_map_el3(&master, &pgt_desc);

      /* Send an ATS Translation Request for the VA */
      val_exerciser_set_param(DMA_ATTRIBUTES, (uint64_t)dram_buf_in_virt, dma_len, instance);
      if (val_exerciser_ops(ATS_TXN_REQ, (uint64_t)dram_buf_in_virt, instance))
      {
	  val_print(ACS_PRINT_ERR, " ATS Translation Req Failed exerciser %4x", instance);
          test_fail++;
          goto free_mem;
      }

      /* Get ATS Translation Response */
      m_vir_addr = (uint64_t)dram_buf_in_virt;
      if (val_exerciser_get_param(ATS_RES_ATTRIBUTES, &translated_addr, &m_vir_addr, instance)) {
          val_print(ACS_PRINT_ERR, " ATS Response failure %4x", instance);
          test_fail++;
          goto free_mem;
      }

      val_print(ACS_PRINT_DEBUG, " The translated address obtained is: 0x%llx", translated_addr);

      /* Compare Translated Addr with Physical Address from the Mappings */
      if (translated_addr != dram_buf_in_phys) {
          val_print(ACS_PRINT_ERR, " ATS Translation failure %4x", instance);
          test_fail++;
          goto free_mem;
      }

      /* Add DPT entry for the PA with Read Write Access */
      val_dpt_add_entry((uint64_t)dram_buf_in_virt,
                       ((((uint64_t)(master.smmu_index)) << 32) | DPT_NO_ACCESS_ENTRY));

      val_dpt_invalidate_all(((uint64_t)(master.smmu_index)));


      /* Configure Exerciser to issue subsequent DMA transactions with Address Translated bit Set */
      val_exerciser_set_param(CFG_TXN_ATTRIBUTES, TXN_ADDR_TYPE, AT_TRANSLATED, instance);
      if (val_exerciser_set_param(DMA_ATTRIBUTES, dram_buf_in_phys, dma_len, instance)) {
          val_print(ACS_PRINT_ERR, " DMA attributes setting failure %4x", instance);
          test_fail++;
          goto free_mem;
      }

      /* Trigger DMA from input buffer to exerciser memory */
      val_exerciser_ops(START_DMA, EDMA_TO_DEVICE, instance);

      if (val_exerciser_set_param(DMA_ATTRIBUTES, (uint64_t)dram_buf_in_virt2, dma_len, instance))
      {
          val_print(ACS_PRINT_ERR, " DMA attributes setting failure %4x", instance);
          test_fail++;
          goto free_mem;
      }

      /* Trigger DMA from exerciser memory to output buffer*/
      val_exerciser_ops(START_DMA, EDMA_FROM_DEVICE, instance);

      if (!val_memory_compare(dram_buf_in_virt, dram_buf_in_virt2, dma_len))
      {
          val_print(ACS_PRINT_ERR,
                    " DPT entry was set to No Access, but access was granted for %4x", instance);
          test_fail++;
          goto free_mem;
      }

free_mem:
      val_exerciser_ops(ATS_INV_CACHE, 0, instance);

      pgt_attr_el3 = LOWER_ATTRS(PGT_ENTRY_ACCESS | SHAREABLE_ATTR(NON_SHAREABLE) |
      PGT_ENTRY_AP_RW | PAS_ATTR(NONSECURE_PAS));

      //Clear the memory and it's protection by making it NS
      val_add_mmu_entry_el3((uint64_t)dram_buf_in_virt, dram_buf_in_phys, pgt_attr_el3);
      val_memory_set_el3((uint64_t *)dram_buf_in_virt, test_data_blk_size, 0);
      val_pe_cache_clean_invalidate_range((uint64_t)dram_buf_in_virt,
                                          (uint64_t)(test_data_blk_size));

      /* Return the buffer to the heap manager */
      val_memory_free_pages(dram_buf_in_virt, TEST_DATA_NUM_PAGES);

      val_print(ACS_PRINT_DEBUG, " Disabling the ATS Cache for exerciser: 0x%x", bdf);
      if (val_pcie_find_capability(bdf, PCIE_ECAP, ECID_ATS, &cap_base) == PCIE_SUCCESS)
      {
          val_pcie_read_cfg(bdf, cap_base + ATS_CTRL, &reg_value);
          reg_value &= ATS_CACHING_DIS;
          val_pcie_write_cfg(bdf, cap_base + ATS_CTRL, reg_value);
      }

      val_pcie_disable_tdisp(rp_bdf);
      val_device_unlock(bdf);
  }

  if (test_skip)
      val_set_status(pe_index, "SKIP", 01);
  else if (test_fail)
      val_set_status(pe_index, "FAIL", 01);
  else
      val_set_status(pe_index, "PASS", 01);

  return;

}


uint32_t
dpt_system_resource_invalid_entry(void)
{
  uint32_t num_pe = 1;
  uint32_t status = ACS_STATUS_FAIL;  //default value

  status = val_initialize_test(TEST_NAME, TEST_DESC, num_pe, TEST_RULE);

  /* This check is when user is forcing us to skip this test */
  if (status != ACS_STATUS_SKIP)
      val_run_test_payload(num_pe, payload, 0);

  /*get the result from all PE and check for failure */
  status = val_check_for_error(num_pe);

  val_report_status(0, "END");

  return  status;
}

