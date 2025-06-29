/** @file
 * Copyright (c) 2024-2025, Arm Limited or its affiliates. All rights reserved.
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

#include "val/include/rme_acs_el32.h"
#include "val/include/rme_acs_pcie.h"
#include "val/include/rme_acs_memory.h"
#include "val/include/rme_acs_pcie_enumeration.h"
#include "val/include/rme_acs_exerciser.h"
#include "val/include/rme_acs_smmu.h"
#include "val/include/rme_acs_pe.h"
#include "val/include/rme_acs_pgt.h"
#include "val/include/rme_acs_iovirt.h"
#include "val/include/mem_interface.h"
#include "val/include/sys_config.h"
#include "val/include/rme_acs_da.h"
#include "val/include/rme_acs_mec.h"

#define TEST_NUM  (ACS_RME_MEC_TEST_NUM_BASE  +  2)
#define TEST_DESC  "Check MECID assosiation and encryption for mem access  "
#define TEST_RULE  "RTRBZM, RMLFBL, RMYWVB"

#define TEST_DATA_NUM_PAGES 1
#define TEST_DATA 0xAB

#define MECID1 0x1
#define MECID2 0x2

static
void
payload(void)
{

  uint32_t pe_index;
  uint32_t instance, num_exercisers;
  uint32_t bdf, rp_bdf, da_cap_base;
  uint32_t dma_len, test_data_blk_size;
  uint32_t status, reg_value;
  uint32_t count;
  void *dram_buf_in_virt, *dram_buf_in_virt2;
  uint64_t dram_buf_in_phys;
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

  pe_index = val_pe_get_index_mpid(val_pe_get_mpid());

  test_data_blk_size = page_size * TEST_DATA_NUM_PAGES;
  dma_len = test_data_blk_size / 2;

  num_exercisers = val_exerciser_get_info(EXERCISER_NUM_CARDS);

  val_rlm_enable_mec();

  /* Validate MECID1 and MECI2 */
  if (!val_mec_validate_mecid(MECID1, MECID2, PoE))
  {
      val_print(ACS_PRINT_ERR, "\nInvalid MECID behaviour", 0);
      val_set_status(pe_index, RESULT_FAIL(TEST_NUM, 01));
      return;
  }

  if (!val_mec_validate_mecid(MECID1, MECID2, PoPA))
  {
      val_print(ACS_PRINT_ERR, "\nInvalid MECID behaviour", 0);
      val_set_status(pe_index, RESULT_FAIL(TEST_NUM, 02));
      return;
  }

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

  val_rlm_configure_mecid(VAL_GMECID);

  for (instance = 0; instance < num_exercisers; ++instance)
  {
      /* if init fail moves to next exerciser */
      if (val_exerciser_init(instance))
          continue;

      bdf = val_exerciser_get_bdf(instance);
      val_print(ACS_PRINT_DEBUG, "\n       Exerciser BDF - 0x%x", bdf);

      if (val_pcie_get_rootport(bdf, &rp_bdf))
          continue;

      test_skip = 0;

      /* Check for DA Capability */
      if (val_pcie_find_da_capability(rp_bdf, &da_cap_base) != PCIE_SUCCESS)
      {
          val_print(ACS_PRINT_ERR,
                        "\n       PCIe DA DVSEC capability not present,bdf 0x%x", bdf);
          test_fail++;
          continue;
      }

      /* Enable RMEDA_CTL1.TDISP_EN*/
      if (val_pcie_enable_tdisp(rp_bdf))
      {
          val_print(ACS_PRINT_ERR, "\n        Unable to set tdisp_en for BDF: 0x%x", rp_bdf);
          test_fail++;
          continue;
      }

      count = 1;
      stream_id = val_generate_stream_id();

      status = val_ide_establish_stream(bdf, count, stream_id,
                                     PCIE_CREATE_BDF_PACKED(bdf));
      if (status)
      {
          val_print(ACS_PRINT_ERR, "\n       Failed to establish stream for bdf: 0x%x", bdf);
          test_fail++;
          continue;
      }

      status = val_ide_establish_stream(rp_bdf, count, stream_id,
                                     PCIE_CREATE_BDF_PACKED(bdf));
      if (status)
      {
          val_print(ACS_PRINT_ERR, "\n       Failed to establish stream for RP bdf: 0x%x", rp_bdf);
          test_fail++;
          continue;
      }

      val_pcie_read_cfg(rp_bdf, da_cap_base + RMEDA_CTL2, &reg_value);
      val_print(ACS_PRINT_DEBUG, "\n  RMEDA_CTL2 before write = 0x%llx", reg_value);

      /* Lock the corresponding Selective IDE register block in RMEDA_CTL2 register */
      str_index = count - 1;
      sel_str_lock_bit = 1 << (str_index % 32);
      val_print(ACS_PRINT_DEBUG, "\n  Sel steam lock bit: 0x%lx", sel_str_lock_bit);

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
      val_print(ACS_PRINT_DEBUG, "\n  RMEDA_CTL2 after write = 0x%llx", reg_value);

      /* Map the MMIO bar to REALM PAS */
      val_pcie_get_mmio_bar(bdf, &bar_base);
      if (bar_base == 0)
          continue;

      va2 = val_get_free_va(val_get_min_tg());
      pgt_attr_el3 = LOWER_ATTRS(PGT_ENTRY_ACCESS | SHAREABLE_ATTR(OUTER_SHAREABLE)
                          | GET_ATTR_INDEX(DEV_MEM_nGnRnE) | PGT_ENTRY_AP_RW | PAS_ATTR(REALM_PAS));
      val_add_mmu_entry_el3(va2, bar_base, pgt_attr_el3);

      if (val_device_lock(bdf))
      {
          val_print(ACS_PRINT_ERR, "\n       Failed to lock the device: 0x%lx", bdf);
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
                val_print(ACS_PRINT_ERR, "\n       Exerciser %x smmu disable error", instance);
                test_fail++;
                continue;
          }
      }

      val_iovirt_get_device_info(PCIE_CREATE_BDF_PACKED(bdf),
                                     PCIE_EXTRACT_BDF_SEG(bdf),
                                     &device_id, &master.streamid,
                                     &its_id);


      /* Configure PE MECID and STE.MECID to MECID1 */
      val_smmu_rlm_configure_mecid(&master, MECID1);
      val_rlm_configure_mecid(MECID1);

      /* Set the buffer to value 0 */
      val_memory_set_el3(dram_buf_in_virt, dma_len * 2, 0);
      val_pe_cache_clean_invalidate_range((uint64_t)dram_buf_in_virt, (uint64_t)(dma_len * 2));
      dram_buf_in_virt2 = dram_buf_in_virt + dma_len;

      val_memory_set_el3(dram_buf_in_virt, dma_len, TEST_DATA);
      val_pe_cache_clean_invalidate_range((uint64_t)dram_buf_in_virt, (uint64_t)dma_len);

      /* Get the VTTBR_EL2 and VTCR_EL2, populate them if they aren't already */
      if (val_pe_get_vtcr(&pgt_desc.vtcr))
      {
          val_print(ACS_PRINT_ERR, "\n        Failed to get the VTCR", 0);
          test_fail++;
          goto free_mem;
      }

      /* Need to know input and output address sizes before creating page table */
      pgt_desc.ias = val_smmu_get_info(SMMU_IN_ADDR_SIZE, master.smmu_index);
      if ((pgt_desc.ias) == 0) {
          val_print(ACS_PRINT_ERR,
                          "\n       Input address size of SMMU %d is 0", master.smmu_index);
          test_fail++;
          goto free_mem;
      }

      pgt_desc.oas = val_smmu_get_info(SMMU_OUT_ADDR_SIZE, master.smmu_index);
      if ((pgt_desc.oas) == 0) {
          val_print(ACS_PRINT_ERR,
                          "\n       Output address size of SMMU %d is 0", master.smmu_index);
          test_fail++;
          goto free_mem;;
      }

      /* set pgt_desc.pgt_base to NULL to create new translation table, val_realm_pgt_create
         will update pgt_desc.pgt_base to point to created translation table */
      pgt_desc.pgt_base = (uint64_t) NULL;
      val_rlm_pgt_create(mem_desc, &pgt_desc);

      /* Write pgt_base to the VTTBR register so that EL3 can update while programming STE */
      val_pe_reg_write(VTTBR, pgt_desc.pgt_base);

      /* Enable the stage2 mapping for Realm SMMU Transaction */
      master.stage2 = 1;
      val_print(ACS_PRINT_DEBUG, "\n    Stream ID: 0x%lx", master.streamid);

      /* Restore MECID to VAL_GMECID to write to STE */
      val_rlm_configure_mecid(VAL_GMECID);
      val_smmu_rlm_map_el3(&master, &pgt_desc);

      /* DMA from DRAM -> DEVICE followed by DEVICE -> DRAM using MECID1 */
      val_exerciser_set_param(DMA_ATTRIBUTES, (uint64_t)dram_buf_in_virt, dma_len, instance);
      if (val_exerciser_ops(START_DMA, EDMA_TO_DEVICE, instance))
      {
          val_print(ACS_PRINT_ERR, "\n        DMA write failure to exerciser %4x", instance);
          test_fail++;
          goto free_mem;
      }

      val_exerciser_set_param(DMA_ATTRIBUTES, (uint64_t)dram_buf_in_virt2, dma_len, instance);
      if (val_exerciser_ops(START_DMA, EDMA_FROM_DEVICE, instance))
      {
          val_print(ACS_PRINT_ERR, "\n        DMA write failure from exerciser %4x", instance);
          test_fail++;
          goto free_mem;
      }

      val_pe_cache_invalidate_range((uint64_t)dram_buf_in_virt, (uint64_t)(dma_len * 2));
      /* Memory buffers must be same */
      if (val_memory_compare(dram_buf_in_virt, dram_buf_in_virt2, dma_len))
      {
          val_print(ACS_PRINT_ERR,
                    "\n Buffer mismatch for excerciser %4x", instance);
          test_fail++;
          goto free_mem;
      }

      /* Resotre MECID back to MECID1 to destroy SMMU page tables */
      val_rlm_configure_mecid(MECID1);
      val_rlm_pgt_destroy(&pgt_desc);

      /* MECID must be VAL_GMECID to access STE, and change the STE.MECID to MECID2 */
      val_rlm_configure_mecid(VAL_GMECID);
      val_smmu_rlm_configure_mecid(&master, MECID2);

      /* Configure PE MECID to MECI2 before writing the SMMU page tables */
      val_rlm_configure_mecid(MECID2);
      pgt_desc.pgt_base = (uint64_t) NULL;
      val_rlm_pgt_create(mem_desc, &pgt_desc);

      /* Restore MECID to VAL_GMECID to write to STE */
      val_rlm_configure_mecid(VAL_GMECID);
      val_smmu_rlm_map_el3(&master, &pgt_desc);

      /* DMA from DRAM -> DEVICE followed by DEVICE -> DRAM using MECID1 */
      val_exerciser_set_param(DMA_ATTRIBUTES, (uint64_t)dram_buf_in_virt, dma_len, instance);
      if (val_exerciser_ops(START_DMA, EDMA_TO_DEVICE, instance))
      {
          val_print(ACS_PRINT_ERR, "\n        DMA write failure to exerciser %4x", instance);
          test_fail++;
          goto free_mem;
      }

      val_exerciser_set_param(DMA_ATTRIBUTES, (uint64_t)dram_buf_in_virt2, dma_len, instance);
      if (val_exerciser_ops(START_DMA, EDMA_FROM_DEVICE, instance))
      {
          val_print(ACS_PRINT_ERR, "\n        DMA write failure from exerciser %4x", instance);
          test_fail++;
          goto free_mem;
      }

      val_pe_cache_invalidate_range((uint64_t)dram_buf_in_virt, (uint64_t)(dma_len * 2));
      /* Memory buffers must not be same */
      if (!val_memory_compare(dram_buf_in_virt, dram_buf_in_virt2, dma_len))
      {
          val_print(ACS_PRINT_ERR,
                    "\n Buffer match for excerciser %4x", instance);
          test_fail++;
          goto free_mem;
      }

free_mem:
      pgt_attr_el3 = LOWER_ATTRS(PGT_ENTRY_ACCESS | SHAREABLE_ATTR(OUTER_SHAREABLE)
                     | GET_ATTR_INDEX(DEV_MEM_nGnRnE) | PGT_ENTRY_AP_RW | PAS_ATTR(NONSECURE_PAS));

      //Clear the memory and it's protection by making it NS
      val_add_mmu_entry_el3((uint64_t)dram_buf_in_virt, dram_buf_in_phys, pgt_attr_el3);
      val_memory_set_el3((uint64_t *)dram_buf_in_virt, dma_len * 2, 0);
      val_pe_cache_clean_invalidate_range((uint64_t)dram_buf_in_virt, (uint64_t)(dma_len * 2));

      /* Return the buffer to the heap manager */
      val_memory_free_pages(dram_buf_in_virt, TEST_DATA_NUM_PAGES);

      /* Restore MECID to GMECID */
      val_rlm_configure_mecid(VAL_GMECID);
  }


  val_rlm_disable_mec();

  while (instance--)
  {
    bdf = val_exerciser_get_bdf(instance);
    if (val_pcie_get_rootport(bdf, &rp_bdf))
          continue;

    val_print(ACS_PRINT_DEBUG, "\n     Disabling TDISP for RP: 0x%x", rp_bdf);
    val_pcie_disable_tdisp(rp_bdf);
    val_print(ACS_PRINT_DEBUG, "\n     Putting the device into unlockes state for bdf: 0x%x", bdf);
    val_device_unlock(bdf);

  }

  if (test_skip)
      val_set_status(pe_index, RESULT_SKIP(TEST_NUM, 01));
  else if (test_fail)
      val_set_status(pe_index, RESULT_FAIL(TEST_NUM, 03));
  else
      val_set_status(pe_index, RESULT_PASS(TEST_NUM, 01));

  return;

}


uint32_t
mec002_entry(void)
{

  uint32_t num_pe = 1;
  uint32_t status = ACS_STATUS_FAIL;  //default value

  status = val_initialize_test(TEST_NUM, TEST_DESC, num_pe, TEST_RULE);

  /* This check is when user is forcing us to skip this test */
  if (status != ACS_STATUS_SKIP)
      val_run_test_payload(TEST_NUM, num_pe, payload, 0);

  /* get the result from all PE and check for failure */
  status = val_check_for_error(TEST_NUM, num_pe, TEST_RULE);

  val_report_status(0, RME_ACS_END(TEST_NUM), TEST_RULE);

  return status;
}
