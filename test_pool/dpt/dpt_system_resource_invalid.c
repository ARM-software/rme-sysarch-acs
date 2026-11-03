/** @file
 * Copyright (c) 2025-2026, Arm Limited or its affiliates. All rights reserved.
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
#include "val/include/val_smmu.h"
#include "val/include/val_dpt.h"
#include "val/include/val_da.h"
#include "val/include/val_exerciser.h"
#include "val/include/val_memory.h"
#include "val/include/val_iovirt.h"
#include "val/include/val_pgt.h"
#include "val/include/val_pcie.h"
#include "val/include/val_pe.h"
#include "val/include/val_el32.h"

#define TEST_NAME "dpt_system_resource_invalid"
#define TEST_DESC  "TDI DPT Check - System Resource - Invalid Access       "
#define TEST_RULE  "RQRMPD"

#define TEST_DATA_NUM_PAGES 1
#define TEST_DATA 0xAB
#define DENIED_READ_DATA 0xCD

/* A denied read may preserve the exerciser seed or return RAZ data. Check
 * every byte so a partial read of DENIED_READ_DATA cannot count as denial.
 */
static uint32_t
check_denied_read_data(uint64_t buffer, uint32_t length)
{
  uint32_t data, byte;

  for (uint32_t offset = 0; offset < length; offset += sizeof(uint32_t))
  {
      if (val_memory_read_el3(buffer + offset, &data) != ACS_STATUS_PASS)
          return ACS_STATUS_ERR;

      for (uint32_t shift = 0; shift < 32; shift += 8)
      {
          byte = (data >> shift) & 0xFFu;
          if (byte != TEST_DATA && byte != 0)
              return ACS_STATUS_FAIL;
      }
  }
  return ACS_STATUS_PASS;
}

static
void
payload(void)
{
  uint32_t ide_unsupported = 0;
  uint32_t dpt_entry_active;
  uint32_t pe_index;
  uint32_t instance, num_exercisers;
  uint32_t bdf, rp_bdf, da_cap_base, cap_base;
  uint32_t dma_len, test_data_blk_size;
  uint32_t status, reg_value;
  uint32_t ats_changed, ats_capability, saved_ats_control;
  uint32_t count;
  void *dram_buf_in_virt, *dram_buf_in_virt2;
  uint64_t va1, va2, bar_base;
  uint32_t test_fail = 0, test_skip = 1;
  uint32_t sel_str_lock_bit;
  uint32_t stream_id;
  uint32_t pgt_attr_el3;
  uint64_t cfg_addr;
  uint32_t str_index;
  uint32_t device_id, its_id;
  uint32_t page_size = val_memory_page_size();
  smmu_master_attributes_t master;
  memory_region_descriptor_t mem_desc_array[2], *mem_desc;
  pgt_descriptor_t pgt_desc;
  uint32_t rlm_mapped, cleanup_failed;
  VAL_DPT_GPT_STATE dram_gpt;
  uint64_t translated_addr, m_vir_addr, dram_buf_in_phys;

  pe_index = val_pe_get_index_mpid(val_pe_get_mpid());

  test_data_blk_size = page_size * TEST_DATA_NUM_PAGES;
  dma_len = test_data_blk_size / 2;

  num_exercisers = val_exerciser_get_info(EXERCISER_NUM_CARDS);
  if (num_exercisers == 0)
  {
    val_print(ACS_PRINT_WARN, " No exerciser cards discovered", 0);
    val_set_status(pe_index, "SKIP", 01);
    return;
  }

  /* Initialize DMA master and memory descriptors */
  val_memory_set(&master, sizeof(master), 0);
  val_memory_set(mem_desc_array, sizeof(mem_desc_array), 0);
  mem_desc = &mem_desc_array[0];

  /* Map the Pointers in EL3 as NS Access PAS so that EL3 can access this struct pointers */
  pgt_attr_el3 = LOWER_ATTRS(PGT_ENTRY_ACCESS | SHAREABLE_ATTR(OUTER_SHAREABLE) |
                                 PGT_ENTRY_AP_RW | PAS_ATTR(NONSECURE_PAS));
  if (val_add_mmu_entry_el3((uint64_t)(&pgt_desc), (uint64_t)(&pgt_desc), pgt_attr_el3))
  {
      val_print(ACS_PRINT_ERR, " Failed to add MMU entry for pgt_desc", 0);
      val_set_status(pe_index, "FAIL", 01);
      return;
  }

  if (val_add_mmu_entry_el3((uint64_t)(&master), (uint64_t)(&master), pgt_attr_el3))
  {
      val_print(ACS_PRINT_ERR, " Failed to add MMU entry for master", 0);
      val_set_status(pe_index, "FAIL", 02);
      return;
  }

  if (val_add_mmu_entry_el3((uint64_t)(mem_desc), (uint64_t)(mem_desc), pgt_attr_el3))
  {
      val_print(ACS_PRINT_ERR, " Failed to add MMU entry for mem_desc", 0);
      val_set_status(pe_index, "FAIL", 03);
      return;
  }

  for (instance = 0; instance < num_exercisers; ++instance)
  {
      pgt_desc.pgt_base = 0;
      ats_changed = 0;
      rlm_mapped = 0;
      dram_gpt.saved = 0;
      dpt_entry_active = 0;
      dram_buf_in_virt = NULL;
      /* if init fail moves to next exerciser */
      if (val_exerciser_init(instance))
          continue;

      bdf = val_exerciser_get_bdf(instance);
      val_print(ACS_PRINT_TEST, " Exerciser BDF - 0x%x", bdf);
      if (val_dpt_wait_for_dma(instance) != ACS_STATUS_PASS)
      {
          val_set_status(pe_index, "FAIL", 06);
          return;
      }

      /* Get the RP of the exerciser */
      if (val_pcie_get_rootport(bdf, &rp_bdf))
          continue;

      /* If ATS Capability Not Present, Skip. */
      if (val_pcie_find_capability(bdf, PCIE_ECAP, ECID_ATS, &cap_base) != PCIE_SUCCESS)
            continue;

      /* Check for DA Capability */
      if (val_pcie_find_da_capability(rp_bdf, &da_cap_base) != PCIE_SUCCESS)
      {
          val_print(ACS_PRINT_WARN,
                        " PCIe DA DVSEC capability not present,bdf 0x%x", bdf);
          continue;
      }

      test_skip = 0;


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

      /* Establish SPDM and matching EP/RP keys before enabling IDE. */
      status = val_pcie_ide_establish(bdf, rp_bdf, count, stream_id,
                                      PCIE_CREATE_BDF_PACKED(bdf));
      if (status == ACS_STATUS_SKIP)
      {
          ide_unsupported = 1;
          val_pcie_disable_tdisp(rp_bdf);
          continue;
      }

      if (status)
      {
          val_print(ACS_PRINT_ERR, " Failed to establish stream for bdf: 0x%x", bdf);
          test_fail++;
          if (val_pcie_disable_tdisp(rp_bdf))
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
      if (val_add_mmu_entry_el3(va1, cfg_addr, pgt_attr_el3))
      {
        val_print(ACS_PRINT_ERR, " Failed to add MMU entry for cfg_addr: 0x%lx", cfg_addr);
        test_fail++;
        goto ide_cleanup;
      }

      shared_data->num_access = 1;
      shared_data->shared_data_access[0].addr = va1 + da_cap_base + RMEDA_CTL2;
      shared_data->shared_data_access[0].data = sel_str_lock_bit;
      shared_data->shared_data_access[0].access_type = WRITE_DATA;
      if (val_pe_access_mut_el3())
      {
          val_print(ACS_PRINT_ERR,
            " Failed to access RMEDA_CTL2 = 0x%llx", va1 + da_cap_base + RMEDA_CTL2);
          test_fail++;
          goto ide_cleanup;
      }

      val_pcie_read_cfg(rp_bdf, da_cap_base + RMEDA_CTL2, &reg_value);
      val_print(ACS_PRINT_DEBUG, " RMEDA_CTL2 after write = 0x%llx", reg_value);

      /* Map the MMIO bar to REALM PAS */
      val_pcie_get_mmio_bar(bdf, &bar_base);
      if (bar_base == 0)
      {
          val_print(ACS_PRINT_ERR, " Exerciser BAR is missing, BDF 0x%x", bdf);
          test_fail++;
          goto ide_cleanup;
      }

      va2 = val_get_free_va(val_get_min_tg());
      pgt_attr_el3 = LOWER_ATTRS(PGT_ENTRY_ACCESS | SHAREABLE_ATTR(OUTER_SHAREABLE)
                          | GET_ATTR_INDEX(DEV_MEM_nGnRnE) | PGT_ENTRY_AP_RW | PAS_ATTR(REALM_PAS));
      if (val_add_mmu_entry_el3(va2, bar_base, pgt_attr_el3))
      {
          val_print(ACS_PRINT_ERR,
            " Failed to add MMU entry for bar_base: 0x%llx", bar_base);
          test_fail++;
          goto ide_cleanup;
      }

      /* Transition the EP to TDISP RUN state */
      if (val_device_lock(bdf))
      {
          val_print(ACS_PRINT_ERR, " Failed to lock the device: 0x%lx", bdf);
          test_fail++;
          goto ide_cleanup;
      }

      /* Enable ATS only after target and IDE setup checks have succeeded. */
      if (val_pcie_find_capability(bdf, PCIE_ECAP, ECID_ATS, &ats_capability) ||
          val_pcie_read_cfg(bdf, ats_capability + ATS_CTRL, &saved_ats_control))
      {
          test_fail++;
          goto ide_cleanup;
      }

      ats_changed = 1;
      val_pcie_write_cfg(bdf, ats_capability + ATS_CTRL,
                         saved_ats_control | ATS_CACHING_EN);


      /* Resolve the requester before GPT updates so failure cleanup can
       * restore both the GPT and this SMMU's cached view.
       */
      master.smmu_index = val_iovirt_get_rc_smmu_index(PCIE_EXTRACT_BDF_SEG(bdf),
                                                     PCIE_CREATE_BDF_PACKED(bdf));
      if (master.smmu_index == ACS_INVALID_INDEX ||
          val_smmu_enable(master.smmu_index) ||
          val_iovirt_get_device_info(PCIE_CREATE_BDF_PACKED(bdf),
                                     PCIE_EXTRACT_BDF_SEG(bdf), &device_id,
                                     &master.streamid, &its_id))
      {
          val_print(ACS_PRINT_ERR, " Failed to configure requester SMMU, BDF 0x%x", bdf);
          test_fail++;
          goto ide_cleanup;
      }

      /* Create a buffer of size TEST_DMA_SIZE in DRAM */
      dram_buf_in_virt = val_memory_alloc_pages(TEST_DATA_NUM_PAGES);
      if (dram_buf_in_virt == NULL)
      {
          val_print(ACS_PRINT_ERR, " DMA buffer allocation failed", 0);
          test_fail++;
          goto free_mem;
      }

      dram_buf_in_phys = (uint64_t)val_memory_virt_to_phys(dram_buf_in_virt);

      /* Save the GPI before allowing the Realm DMA prerequisite. */
      if (val_dpt_allow_gpt(dram_buf_in_phys, &dram_gpt))
      {
          val_print(ACS_PRINT_ERR,
            " Failed to add GPT entry for PA 0x%llx", dram_buf_in_phys);
          test_fail++;
          goto free_mem;
      }

      pgt_attr_el3 = LOWER_ATTRS(PGT_ENTRY_ACCESS | SHAREABLE_ATTR(OUTER_SHAREABLE)
                        | GET_ATTR_INDEX(DEV_MEM_nGnRnE) | PGT_ENTRY_AP_RW | PAS_ATTR(REALM_PAS));

      if (val_add_mmu_entry_el3((uint64_t)dram_buf_in_virt,
                                dram_buf_in_phys, pgt_attr_el3))
      {
          val_print(ACS_PRINT_ERR, " Failed to add MMU entry for dram_buf_in_virt: 0x%llx",
                    (uint64_t)dram_buf_in_virt);
          test_fail++;
          goto free_mem;
      }


      /* Set the buffer to value 0 */
      if (val_memory_set_el3(dram_buf_in_virt, test_data_blk_size, 0))
      {
          val_print(ACS_PRINT_ERR, " Failed to set memory to 0 for instance %4x", instance);
          test_fail++;
          goto free_mem;
      }

      val_pe_cache_clean_invalidate_range((uint64_t)dram_buf_in_virt,
                                          (uint64_t)(test_data_blk_size));

      dram_buf_in_virt2 = dram_buf_in_virt + dma_len;

      /* Set the input buffer with the Test Data */
      if (val_memory_set_el3(dram_buf_in_virt, dma_len, TEST_DATA))
      {
          val_print(ACS_PRINT_ERR, " Failed to set memory to 0x%x for ", TEST_DATA);
          val_print(ACS_PRINT_ERR, "0x%4x ", instance);
          test_fail++;
          goto free_mem;
      }

      val_pe_cache_clean_invalidate_range((uint64_t)dram_buf_in_virt, (uint64_t)(dma_len));

      mem_desc->virtual_address = (uint64_t)dram_buf_in_virt;
      mem_desc->physical_address = (uint64_t)dram_buf_in_phys;
      mem_desc->length = test_data_blk_size;
      mem_desc->attributes = PGT_STAGE2_AP_RW;


      /* Invalidate SMMU GPT cache entries after GPT updates for this stream. */
      if (val_smmu_gpt_invalidate_el3(&master))
      {
          val_print(ACS_PRINT_ERR, " Failed to invalidate SMMU GPT cache for stream 0x%lx",
                    master.streamid);
          test_fail++;
          goto free_mem;
      }

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
      if (val_rlm_pgt_create(mem_desc, &pgt_desc))
      {
          val_print(ACS_PRINT_ERR,
            " Failed to create page table for instance %4x", instance);
          test_fail++;
          goto free_mem;
      }

      /* Write pgt_base to the VTTBR register so that EL3 can update while programming STE */
      val_pe_reg_write(VTTBR, pgt_desc.pgt_base);

      /* Enable the stage2 mapping for Realm SMMU Transaction */
      master.stage2 = 1;
      val_print(ACS_PRINT_DEBUG, " Stream ID: 0x%lx", master.streamid);

      /* Configure the SMMU tables for this exerciser to use this page table
         for VA to PA translations */
      if (val_smmu_rlm_map_el3(&master, &pgt_desc))
      {
          val_print(ACS_PRINT_ERR, " Failed to map SMMU for instance %4x", instance);
          test_fail++;
          goto free_mem;
      }

      rlm_mapped = 1;

      /* Send an ATS Translation Request for the VA */
      if (val_exerciser_set_param(DMA_ATTRIBUTES, (uint64_t)dram_buf_in_virt, dma_len, instance))
      {
          val_print(ACS_PRINT_ERR, " ATS DMA attributes setting failure %4x", instance);
          test_fail++;
          goto free_mem;
      }

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

      /* Prove the translated source read before testing either denial. */
      dpt_entry_active = 1;
      if (val_dpt_add_entry(dram_buf_in_phys,
                           ((uint64_t)master.smmu_index << 32) | DPT_RDWR_ACCESS_ENTRY) ||
          val_dpt_invalidate_all(master.smmu_index) ||
          val_exerciser_set_param(CFG_TXN_ATTRIBUTES, TXN_ADDR_TYPE,
                                  AT_TRANSLATED, instance) ||
          val_exerciser_set_param(CFG_TXN_ATTRIBUTES, TXN_ATC_ENTRY,
                                  ATC_ENTRY_DISABLE, instance) ||
          val_exerciser_set_param(DMA_ATTRIBUTES, dram_buf_in_phys, dma_len, instance) ||
          val_exerciser_ops(START_DMA, EDMA_TO_DEVICE, instance) != EXERCISER_DMA_SUCCESS)
      {
          val_print(ACS_PRINT_ERR, " DPT permitted source read failed, instance %4x", instance);
          test_fail++;
          goto free_mem;
      }

      /* The permitted write also proves that the source supplied TEST_DATA. */
      if (val_dpt_check_denied_write(instance, master.smmu_index,
                                    (uint64_t)dram_buf_in_virt2, dram_buf_in_phys + dma_len,
                                    dma_len, TEST_DATA) != ACS_STATUS_PASS)
      {
          test_fail++;
          goto free_mem;
      }

      /* Both halves share the same DPT block. Keep it denied, change the host
       * source, and test the translated read independently of the blocked write.
       */
      if (val_memory_set_el3(dram_buf_in_virt, dma_len, DENIED_READ_DATA))
      {
          test_fail++;
          goto free_mem;
      }

      val_pe_cache_clean_invalidate_range((uint64_t)dram_buf_in_virt, dma_len);
      /* Transaction attributes must be programmed again for each DMA. */
      if (val_exerciser_set_param(CFG_TXN_ATTRIBUTES, TXN_ADDR_TYPE,
                                  AT_TRANSLATED, instance) ||
          val_exerciser_set_param(CFG_TXN_ATTRIBUTES, TXN_ATC_ENTRY,
                                  ATC_ENTRY_DISABLE, instance) ||
          val_exerciser_set_param(DMA_ATTRIBUTES, dram_buf_in_phys, dma_len, instance) ||
          !val_exerciser_dma_status_valid(val_exerciser_ops(START_DMA, EDMA_TO_DEVICE, instance)))
      {
          test_fail++;
          goto free_mem;
      }

      /* Reopen access only after the denied read has completed, then observe
       * the exerciser contents using a permitted destination write.
       */
      if (val_dpt_add_entry(dram_buf_in_phys,
                           ((uint64_t)master.smmu_index << 32) | DPT_RDWR_ACCESS_ENTRY) ||
          val_dpt_invalidate_all(master.smmu_index) ||
          val_exerciser_set_param(CFG_TXN_ATTRIBUTES, TXN_ADDR_TYPE,
                                  AT_TRANSLATED, instance) ||
          val_exerciser_set_param(CFG_TXN_ATTRIBUTES, TXN_ATC_ENTRY,
                                  ATC_ENTRY_DISABLE, instance) ||
          val_exerciser_set_param(DMA_ATTRIBUTES, dram_buf_in_phys + dma_len,
                                  dma_len, instance) ||
          val_exerciser_ops(START_DMA, EDMA_FROM_DEVICE, instance) != EXERCISER_DMA_SUCCESS ||
          check_denied_read_data((uint64_t)dram_buf_in_virt2, dma_len) != ACS_STATUS_PASS)
      {
          val_print(ACS_PRINT_ERR, " DPT denied read exposed data or readback failed, instance %4x",
                    instance);
          test_fail++;
          goto free_mem;
      }

free_mem:
      if (val_dpt_wait_for_dma(instance) != ACS_STATUS_PASS)
      {
          val_set_status(pe_index, "FAIL", 06);
          return;
      }

      if (val_exerciser_set_param(CFG_TXN_ATTRIBUTES, TXN_ADDR_TYPE,
                                  AT_UNTRANSLATED, instance))
          test_fail++;

      if (val_exerciser_set_param(CFG_TXN_ATTRIBUTES, TXN_ATC_ENTRY,
                                  ATC_ENTRY_DISABLE, instance))
          test_fail++;

      val_exerciser_ops(ATS_INV_CACHE, 0, instance);

      if (val_pcie_find_capability(bdf, PCIE_ECAP, ECID_ATS, &cap_base) == PCIE_SUCCESS)
      {
          val_pcie_read_cfg(bdf, cap_base + ATS_CTRL, &reg_value);
          reg_value &= ATS_CACHING_DIS;
          val_pcie_write_cfg(bdf, cap_base + ATS_CTRL, reg_value);
      }

      if (pgt_desc.pgt_base &&
          ((rlm_mapped && val_smmu_rlm_unmap_el3(&master)) ||
           val_rlm_pgt_destroy(&pgt_desc)))
      {
          val_print(ACS_PRINT_ERR, " Failed to release Realm page table for instance %4x",
                    instance);
          test_fail++;
          /* Keep mapped buffers reserved when page-table teardown fails. */
          goto ide_cleanup;
      }

      /* Do not leave a denied DPT range behind when the buffer is reused. */
      if (dpt_entry_active &&
          (val_dpt_add_entry(dram_buf_in_phys,
                            (((uint64_t)master.smmu_index << 32) | DPT_RDWR_ACCESS_ENTRY)) ||
           val_dpt_invalidate_all(master.smmu_index)))
      {
          val_print(ACS_PRINT_ERR, " Failed to restore DPT access, instance %4x", instance);
          test_fail++;
          goto ide_cleanup;
      }

      pgt_attr_el3 = LOWER_ATTRS(PGT_ENTRY_ACCESS | SHAREABLE_ATTR(NON_SHAREABLE) |
      PGT_ENTRY_AP_RW | PAS_ATTR(NONSECURE_PAS));

      /* Restore the buffer before returning it to the allocator. A failed
       * restore leaves it reserved rather than reusing Realm-protected memory.
       */
      if (dram_buf_in_virt != NULL)
      {
          cleanup_failed = 0;
          if (val_add_mmu_entry_el3((uint64_t)dram_buf_in_virt,
                                   dram_buf_in_phys, pgt_attr_el3))
              cleanup_failed = 1;
          else
          {
              if (val_memory_set_el3(dram_buf_in_virt, test_data_blk_size, 0))
                  cleanup_failed = 1;

              val_pe_cache_clean_invalidate_range((uint64_t)dram_buf_in_virt,
                                                  test_data_blk_size);
          }

          if (val_dpt_restore_gpt(&dram_gpt, &master) != ACS_STATUS_PASS)
              cleanup_failed = 1;

          if (cleanup_failed)
          {
              val_print(ACS_PRINT_ERR, " DMA buffer cleanup failed; keeping buffer reserved", 0);
              test_fail++;
          }
          else
          {
              val_memory_free_pages(dram_buf_in_virt, TEST_DATA_NUM_PAGES);
              dram_buf_in_virt = NULL;
          }
      }

ide_cleanup:
      /* Restore requester controls on setup failures as well as normal exits. */
      if (ats_changed)
      {
          val_exerciser_ops(ATS_INV_CACHE, 0, instance);
          val_pcie_write_cfg(bdf, ats_capability + ATS_CTRL, saved_ats_control);
      }

      /* Use shared TDISP/IDE teardown before clearing the RP associations. */
      if (val_dpt_ide_stop(bdf, rp_bdf, count, count))
          test_fail++;

      if (val_pcie_disable_tdisp(rp_bdf))
          test_fail++;
  }

  if (test_fail)
      val_set_status(pe_index, "FAIL", 05);
  else if (ide_unsupported || test_skip)
      val_set_status(pe_index, "SKIP", 01);
  else
      val_set_status(pe_index, "PASS", 01);

  return;

}


uint32_t
dpt_system_resource_invalid_entry(uint32_t num_pe)
{
  num_pe = 1;
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
