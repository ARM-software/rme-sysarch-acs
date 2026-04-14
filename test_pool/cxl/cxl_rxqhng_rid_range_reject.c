/** @file
 * Copyright (c) 2026, Arm Limited or its affiliates. All rights reserved.
 * SPDX-License-Identifier : Apache-2.0
 *
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

#include "val/include/val_el32.h"
#include "val/include/val_exerciser.h"
#include "val/include/val_iovirt.h"
#include "val/include/val_cxl.h"
#include "val/include/val_memory.h"
#include "val/include/val_pcie.h"
#include "val/include/val_pcie_spec.h"
#include "val/include/val_pgt.h"
#include "val/include/val_smmu.h"

#define TEST_NAME "cxl_rxqhng_rid_range_reject"
#define TEST_DESC "LINK_STR_LOCK enforces RID range on incoming requests "
#define TEST_RULE "RXQHNG"


#define TEST_DATA_NUM_PAGES 1
#define TEST_DATA 0xAB

#define RMECDA_CTL1_LINK_STR_LOCK_MASK (1u << 1)

#define RMECDA_CTL3_RID_LIMIT_SHIFT 8u
#define RMECDA_CTL3_RID_LIMIT_MASK  (0xFFFFu << RMECDA_CTL3_RID_LIMIT_SHIFT)

#define RMECDA_CTL4_RID_BASE_SHIFT 8u
#define RMECDA_CTL4_RID_BASE_MASK  (0xFFFFu << RMECDA_CTL4_RID_BASE_SHIFT)
#define RMECDA_CTL4_RID_RANGE_VALID_MASK (1u << 0)

/* Wrapper for Root/EL3 reads. */
static uint32_t
read_from_root(uint64_t address, uint32_t *value)
{
  if (value == NULL)
    return ACS_STATUS_ERR;

  shared_data->num_access = 1;
  shared_data->shared_data_access[0].addr = address;
  shared_data->shared_data_access[0].access_type = READ_DATA;

  if (val_pe_access_mut_el3())
  {
    val_print(ACS_PRINT_ERR, " RXQHNG: MUT read failed for 0x%llx", address);
    return ACS_STATUS_ERR;
  }

  *value = (uint32_t)shared_data->shared_data_access[0].data;
  return ACS_STATUS_PASS;
}

/* Wrapper for Root/EL3 writes. */
static uint32_t
write_from_root(uint64_t address, uint32_t value)
{
  shared_data->num_access = 1;
  shared_data->shared_data_access[0].addr = address;
  shared_data->shared_data_access[0].data = value;
  shared_data->shared_data_access[0].access_type = WRITE_DATA;

  if (val_pe_access_mut_el3())
  {
    val_print(ACS_PRINT_ERR, " RXQHNG: MUT write failed for 0x%llx", address);
    return ACS_STATUS_ERR;
  }

  return ACS_STATUS_PASS;
}

static uint32_t
map_root_config(uint32_t bdf, uint64_t *cfg_va_out)
{
  uint64_t cfg_addr;
  uint64_t tg;
  uint64_t cfg_va;
  uint32_t attr;

  if (cfg_va_out == NULL)
    return ACS_STATUS_ERR;

  tg = val_get_min_tg();
  if (tg == 0u)
    return ACS_STATUS_ERR;

  cfg_addr = val_pcie_get_bdf_config_addr(bdf);
  if (cfg_addr == 0u)
    return ACS_STATUS_ERR;

  cfg_va = val_get_free_va(tg);
  if (cfg_va == 0u)
    return ACS_STATUS_ERR;

  attr = LOWER_ATTRS(PGT_ENTRY_ACCESS | SHAREABLE_ATTR(OUTER_SHAREABLE) |
                     GET_ATTR_INDEX(DEV_MEM_nGnRnE) | PGT_ENTRY_AP_RW |
                     PAS_ATTR(ROOT_PAS));
  if (val_add_mmu_entry_el3(cfg_va, cfg_addr, attr))
    return ACS_STATUS_ERR;

  *cfg_va_out = cfg_va;
  return ACS_STATUS_PASS;
}

static uint32_t
configure_smmu_identity_map(uint32_t endpoint_bdf,
                            uint64_t page_pa,
                            uint64_t map_len,
                            smmu_master_attributes_t *master_out,
                            pgt_descriptor_t *pgt_desc_out)
{
  uint32_t device_id;
  uint32_t its_id;
  uint32_t pgt_status;
  uint32_t smmu_index;
  uint32_t ias;
  uint32_t oas;
  memory_region_descriptor_t mem_desc[2];
  pgt_descriptor_t pgt_desc;

  if ((master_out == NULL) || (pgt_desc_out == NULL))
    return ACS_STATUS_ERR;

  val_memory_set(master_out, sizeof(*master_out), 0);
  val_memory_set(pgt_desc_out, sizeof(*pgt_desc_out), 0);

  smmu_index = val_iovirt_get_rc_smmu_index(PCIE_EXTRACT_BDF_SEG(endpoint_bdf),
                                           PCIE_CREATE_BDF_PACKED(endpoint_bdf));
  if (smmu_index == ACS_INVALID_INDEX)
    return ACS_STATUS_SKIP;

  if (val_iovirt_get_smmu_info(SMMU_CTRL_ARCH_MAJOR_REV, smmu_index) != 3u)
    return ACS_STATUS_SKIP;

  if (val_smmu_enable(smmu_index))
    return ACS_STATUS_ERR;

  if (val_iovirt_get_device_info(PCIE_CREATE_BDF_PACKED(endpoint_bdf),
                                 PCIE_EXTRACT_BDF_SEG(endpoint_bdf),
                                 &device_id,
                                 &master_out->streamid,
                                 &its_id))
    return ACS_STATUS_SKIP;

  master_out->smmu_index = smmu_index;
  master_out->stage2 = 0u;

  ias = (uint32_t)val_smmu_get_info(SMMU_IN_ADDR_SIZE, smmu_index);
  oas = (uint32_t)val_smmu_get_info(SMMU_OUT_ADDR_SIZE, smmu_index);
  if ((ias == 0u) || (oas == 0u))
    return ACS_STATUS_SKIP;

  val_memory_set(mem_desc, sizeof(mem_desc), 0);
  mem_desc[0].virtual_address = page_pa;
  mem_desc[0].physical_address = page_pa;
  mem_desc[0].length = (uint32_t)map_len;
  mem_desc[0].attributes =
    LOWER_ATTRS(PGT_ENTRY_ACCESS | SHAREABLE_ATTR(NON_SHAREABLE) |
                GET_ATTR_INDEX(NON_CACHEABLE) | PGT_ENTRY_AP_RW);
  mem_desc[1].length = 0u;

  val_memory_set(&pgt_desc, sizeof(pgt_desc), 0);
  pgt_desc.pgt_base = (uint64_t)NULL;
  pgt_desc.ias = ias;
  pgt_desc.oas = oas;
  pgt_desc.stage = PGT_STAGE1;

  if (val_pe_reg_read_tcr(0, &pgt_desc.tcr))
    return ACS_STATUS_ERR;

  pgt_status = val_pgt_create(mem_desc, &pgt_desc);
  if (pgt_status != 0u)
    return ACS_STATUS_ERR;

  if (val_smmu_map(*master_out, pgt_desc))
  {
    val_pgt_destroy(pgt_desc);
    return ACS_STATUS_ERR;
  }

  *pgt_desc_out = pgt_desc;
  return ACS_STATUS_PASS;
}

static uint32_t
run_dma_compare(uint32_t endpoint_bdf,
                uint64_t src_pa,
                uint64_t dst_pa,
                uint8_t *src_va,
                uint8_t *dst_va,
                uint32_t len,
                uint32_t expect_match)
{
  uint32_t dma_status;
  uint32_t compare_match;

  if ((src_va == NULL) || (dst_va == NULL))
    return ACS_STATUS_ERR;

  val_memory_set(src_va, len, 0x5Au);
  val_memory_set(dst_va, len, 0xA5u);
  (void)val_data_cache_ops_by_va_el3((uint64_t)src_va, CLEAN_AND_INVALIDATE);
  (void)val_data_cache_ops_by_va_el3((uint64_t)dst_va, CLEAN_AND_INVALIDATE);

  val_pcie_clear_device_status_error(endpoint_bdf);

  if (val_exerciser_set_param_by_bdf(DMA_ATTRIBUTES, src_pa, len, endpoint_bdf))
    return ACS_STATUS_ERR;

  dma_status = val_exerciser_ops_by_bdf(START_DMA, EDMA_TO_DEVICE, endpoint_bdf);
  val_print(ACS_PRINT_DEBUG, " RXQHNG DBG: DMA TO status 0x%x", dma_status);

  if (val_exerciser_set_param_by_bdf(DMA_ATTRIBUTES, dst_pa, len, endpoint_bdf))
    return ACS_STATUS_ERR;

  dma_status = val_exerciser_ops_by_bdf(START_DMA, EDMA_FROM_DEVICE, endpoint_bdf);
  val_print(ACS_PRINT_DEBUG, " RXQHNG DBG: DMA FROM status 0x%x", dma_status);

  (void)val_data_cache_ops_by_va_el3((uint64_t)dst_va, CLEAN_AND_INVALIDATE);
  compare_match = (val_memory_compare(src_va, dst_va, len) == 0u) ? 1u : 0u;

  if (expect_match != 0u)
    return (compare_match != 0u) ? ACS_STATUS_PASS : ACS_STATUS_FAIL;
  else
    return (compare_match != 0u) ? ACS_STATUS_FAIL : ACS_STATUS_PASS;
}

static uint32_t
find_downstream_chi_c2c_exerciser_endpoint(uint32_t root_bdf,
                                           uint32_t *endpoint_bdf_out)
{
  CXL_COMPONENT_TABLE *table;
  uint32_t reg_value;
  uint32_t secondary_bus;
  uint32_t subordinate_bus;
  uint32_t segment;

  if (endpoint_bdf_out == NULL)
    return ACS_STATUS_ERR;

  *endpoint_bdf_out = ACS_INVALID_INDEX;

  table = val_cxl_component_table_ptr();
  if ((table == NULL) || (table->num_entries == 0u))
    return ACS_STATUS_ERR;

  if (val_pcie_read_cfg(root_bdf, TYPE1_PBN, &reg_value) != PCIE_SUCCESS)
    return ACS_STATUS_ERR;

  secondary_bus = (reg_value >> SECBN_SHIFT) & SECBN_MASK;
  subordinate_bus = (reg_value >> SUBBN_SHIFT) & SUBBN_MASK;
  segment = PCIE_EXTRACT_BDF_SEG(root_bdf);

  if ((secondary_bus == 0u) && (subordinate_bus == 0u))
    return ACS_STATUS_SKIP;

  for (uint32_t idx = 0u; idx < table->num_entries; ++idx)
  {
    const CXL_COMPONENT_ENTRY *candidate = &table->component[idx];
    uint32_t candidate_bdf = candidate->bdf;
    uint32_t candidate_bus;

    if (candidate->role != CXL_COMPONENT_ROLE_ENDPOINT)
      continue;

    if (candidate->chi_c2c_supported == 0u)
      continue;

    if (PCIE_EXTRACT_BDF_SEG(candidate_bdf) != segment)
      continue;

    candidate_bus = PCIE_EXTRACT_BDF_BUS(candidate_bdf);
    if ((candidate_bus < secondary_bus) || (candidate_bus > subordinate_bus))
      continue;

    if (val_exerciser_init_by_bdf(candidate_bdf) == 0u) {
      *endpoint_bdf_out = candidate_bdf;
      return ACS_STATUS_PASS;
    }
  }

  return ACS_STATUS_SKIP;
}

static uint32_t
program_rid_range(uint64_t cfg_va,
                  uint32_t rmecda_cap_base,
                  uint32_t ctl3_template,
                  uint32_t ctl4_template,
                  uint16_t rid_base,
                  uint16_t rid_limit,
                  uint32_t rid_range_valid,
                  uint32_t *ctl3_program_out,
                  uint32_t *ctl4_program_out)
{
  uint32_t ctl3_program;
  uint32_t ctl4_program;
  uint32_t ctl3_readback;
  uint32_t ctl4_readback;

  ctl3_program = (ctl3_template & ~RMECDA_CTL3_RID_LIMIT_MASK) |
                 ((uint32_t)rid_limit << RMECDA_CTL3_RID_LIMIT_SHIFT);
  ctl4_program = (ctl4_template & ~(RMECDA_CTL4_RID_BASE_MASK | RMECDA_CTL4_RID_RANGE_VALID_MASK)) |
                 ((uint32_t)rid_base << RMECDA_CTL4_RID_BASE_SHIFT);
  if (rid_range_valid != 0u)
    ctl4_program |= RMECDA_CTL4_RID_RANGE_VALID_MASK;

  if (write_from_root(cfg_va + rmecda_cap_base + RMECDA_CTL3_OFFSET, ctl3_program) !=
      ACS_STATUS_PASS)
    return ACS_STATUS_ERR;

  if (write_from_root(cfg_va + rmecda_cap_base + RMECDA_CTL4_OFFSET, ctl4_program) !=
      ACS_STATUS_PASS)
    return ACS_STATUS_ERR;

  if (read_from_root(cfg_va + rmecda_cap_base + RMECDA_CTL3_OFFSET, &ctl3_readback) !=
      ACS_STATUS_PASS ||
      read_from_root(cfg_va + rmecda_cap_base + RMECDA_CTL4_OFFSET, &ctl4_readback) !=
      ACS_STATUS_PASS)
    return ACS_STATUS_ERR;

  if (((ctl3_readback & RMECDA_CTL3_RID_LIMIT_MASK) !=
       (ctl3_program & RMECDA_CTL3_RID_LIMIT_MASK)) ||
      ((ctl4_readback & (RMECDA_CTL4_RID_BASE_MASK | RMECDA_CTL4_RID_RANGE_VALID_MASK)) !=
       (ctl4_program & (RMECDA_CTL4_RID_BASE_MASK | RMECDA_CTL4_RID_RANGE_VALID_MASK))))
    return ACS_STATUS_SKIP;

  if (ctl3_program_out != NULL)
    *ctl3_program_out = ctl3_program;
  if (ctl4_program_out != NULL)
    *ctl4_program_out = ctl4_program;

  return ACS_STATUS_PASS;
}

static uint32_t
verify_root_port(uint32_t root_bdf, uint32_t rmecda_cap_base)
{
  uint32_t status;
  uint64_t cfg_va = 0u;
  uint32_t endpoint_bdf = ACS_INVALID_INDEX;
  uint32_t endpoint_rid = 0u;
  uint32_t ctl1_original = 0u;
  uint32_t ctl3_original = 0u;
  uint32_t ctl4_original = 0u;
  uint32_t regs_read = 0u;
  uint32_t ctl1_unlocked;
  uint32_t ctl1_locked;
  uint32_t ctl3_readback;
  uint16_t rid_base;
  uint16_t rid_limit;
  uint32_t rid_range_checks = 0u;
  uint32_t failures = 0u;

  smmu_master_attributes_t master;
  pgt_descriptor_t pgt_desc;
  uint32_t smmu_active = 0u;
  uint32_t page_size = val_memory_page_size();
  uint32_t test_data_blk_size;
  uint32_t dma_len;
  uint64_t page_pa = 0u;
  uint64_t page_va = 0u;
  uint64_t next_page_pa = 0u;
  uint64_t next_page_va = 0u;
  uint32_t gpt_entry_added = 0u;
  uint32_t gpt_entry_added_next = 0u;
  uint32_t attr;
  uint8_t *dram_buf_in_virt = NULL, *dram_buf_in_virt2 = NULL;
  uint64_t dram_buf_in_phys = 0u;

  test_data_blk_size = page_size * TEST_DATA_NUM_PAGES;
  dma_len = test_data_blk_size / 2u;

  status = find_downstream_chi_c2c_exerciser_endpoint(root_bdf, &endpoint_bdf);
  if (status == ACS_STATUS_SKIP)
  {
    val_print(ACS_PRINT_INFO,
              " RXQHNG: No downstream CHI-C2C exerciser endpoint for RP 0x%x - skipping",
              root_bdf);
    return ACS_STATUS_SKIP;
  }
  if (status != ACS_STATUS_PASS)
  {
    val_print(ACS_PRINT_ERR, " RXQHNG: Endpoint discovery failed for RP 0x%x", root_bdf);
    return status;
  }

  if (endpoint_bdf == ACS_INVALID_INDEX)
    return ACS_STATUS_SKIP;

  val_print(ACS_PRINT_INFO, " RXQHNG: RP BDF 0x%x", root_bdf);
  val_print(ACS_PRINT_INFO, " RXQHNG: EP BDF 0x%x", endpoint_bdf);

  /* Ensure we can access the exerciser BARs and issue DMA. */
  val_pcie_enable_msa(endpoint_bdf);
  val_pcie_enable_bme(endpoint_bdf);

  if (map_root_config(root_bdf, &cfg_va) != ACS_STATUS_PASS)
  {
    status = ACS_STATUS_ERR;
    goto cleanup_restore;
  }

  if (read_from_root(cfg_va + rmecda_cap_base + RMECDA_CTL1_OFFSET, &ctl1_original) !=
      ACS_STATUS_PASS)
  {
    status = ACS_STATUS_ERR;
    goto cleanup_restore;
  }

  if (read_from_root(cfg_va + rmecda_cap_base + RMECDA_CTL3_OFFSET, &ctl3_original) !=
      ACS_STATUS_PASS)
  {
    status = ACS_STATUS_ERR;
    goto cleanup_restore;
  }

  if (read_from_root(cfg_va + rmecda_cap_base + RMECDA_CTL4_OFFSET, &ctl4_original) !=
      ACS_STATUS_PASS)
  {
    status = ACS_STATUS_ERR;
    goto cleanup_restore;
  }
  regs_read = 1u;

  ctl1_unlocked = ctl1_original & ~RMECDA_CTL1_LINK_STR_LOCK_MASK;
  if (write_from_root(cfg_va + rmecda_cap_base + RMECDA_CTL1_OFFSET, ctl1_unlocked) !=
      ACS_STATUS_PASS ||
      read_from_root(cfg_va + rmecda_cap_base + RMECDA_CTL1_OFFSET, &ctl3_readback) !=
      ACS_STATUS_PASS)
  {
    status = ACS_STATUS_ERR;
    goto cleanup_restore;
  }

  if ((ctl3_readback & RMECDA_CTL1_LINK_STR_LOCK_MASK) != 0u)
  {
    val_print(ACS_PRINT_INFO, " RXQHNG: LINK_STR_LOCK refused to clear for RP 0x%x", root_bdf);
    status = ACS_STATUS_SKIP;
    goto cleanup_restore;
  }

  endpoint_rid = (uint32_t)PCIE_CREATE_BDF_PACKED(endpoint_bdf);

  /* Ensure the exerciser uses its own Requester ID for requests. */
  (void)val_exerciser_set_param_by_bdf(CFG_TXN_ATTRIBUTES, TXN_REQ_ID_VALID, RID_NOT_VALID,
                                       endpoint_bdf);

  if (val_exerciser_set_param_by_bdf(CFG_TXN_ATTRIBUTES,
                                     TXN_ADDR_TYPE, AT_TRANSLATED, endpoint_bdf))
  {
    status = ACS_STATUS_SKIP;
    goto cleanup_restore;
  }

  /* Create a buffer of size TEST_DMA_SIZE in DRAM */
  dram_buf_in_virt = (uint8_t *)val_memory_alloc_pages(TEST_DATA_NUM_PAGES);
  if (dram_buf_in_virt == NULL)
  {
    status = ACS_STATUS_ERR;
    goto cleanup_restore;
  }

  /* Split one allocated DRAM region into source and destination buffers for DMA. */
  dram_buf_in_virt2 = dram_buf_in_virt + dma_len;
  dram_buf_in_phys = (uint64_t)val_memory_virt_to_phys(dram_buf_in_virt);
  page_va = (uint64_t)dram_buf_in_virt;
  page_pa = dram_buf_in_phys;
  next_page_va = (uint64_t)dram_buf_in_virt2;
  next_page_pa = (uint64_t)val_memory_virt_to_phys(dram_buf_in_virt2);

  if (val_add_gpt_entry_el3(dram_buf_in_phys, GPT_ANY))
  {
    status = ACS_STATUS_ERR;
    goto cleanup_restore;
  }
  gpt_entry_added = 1u;
  if (val_add_gpt_entry_el3(next_page_pa, GPT_NONSECURE))
  {
    status = ACS_STATUS_ERR;
    goto cleanup_restore;
  }
  gpt_entry_added_next = 1u;

  attr = LOWER_ATTRS(PGT_ENTRY_ACCESS | SHAREABLE_ATTR(NON_SHAREABLE) |
                     GET_ATTR_INDEX(NON_CACHEABLE) | PGT_ENTRY_AP_RW |
                     PAS_ATTR(NONSECURE_PAS));
  if (val_add_mmu_entry_el3(page_va, page_pa, attr))
  {
    status = ACS_STATUS_ERR;
    goto cleanup_restore;
  }
  if (val_add_mmu_entry_el3(next_page_va, next_page_pa, attr))
  {
    status = ACS_STATUS_ERR;
    goto cleanup_restore;
  }

  (void)val_memory_set_el3((void *)page_va, test_data_blk_size, TEST_DATA);
  (void)val_data_cache_ops_by_va_el3(page_va, CLEAN_AND_INVALIDATE);
  (void)val_data_cache_ops_by_va_el3(next_page_va, CLEAN_AND_INVALIDATE);

  status = configure_smmu_identity_map(endpoint_bdf, page_pa, test_data_blk_size, &master,
                                       &pgt_desc);
  if (status != ACS_STATUS_PASS)
  {
    val_print(ACS_PRINT_WARN, " RXQHNG: SMMU map not possible for EP 0x%x - skipping",
              endpoint_bdf);
    val_print(ACS_PRINT_WARN, " RXQHNG: RP BDF 0x%x", root_bdf);
    goto cleanup_restore;
  }
  smmu_active = 1u;

  /* Baseline: RID range wide-open + LINK_STR_LOCK==1 => request must succeed. */
  rid_base = 0u;
  rid_limit = 0xFFFFu;
  status = program_rid_range(cfg_va, rmecda_cap_base, ctl3_original, ctl4_original,
                             rid_base, rid_limit, 1u, NULL, NULL);
  if (status != ACS_STATUS_PASS)
  {
    val_print(ACS_PRINT_INFO, " RXQHNG: RID range fields not writable for RP 0x%x - skipping",
              root_bdf);
    status = ACS_STATUS_SKIP;
    goto cleanup_restore;
  }

  ctl1_locked = ctl1_unlocked | RMECDA_CTL1_LINK_STR_LOCK_MASK;
  if (write_from_root(cfg_va + rmecda_cap_base + RMECDA_CTL1_OFFSET, ctl1_locked) !=
      ACS_STATUS_PASS ||
      read_from_root(cfg_va + rmecda_cap_base + RMECDA_CTL1_OFFSET, &ctl3_readback) !=
      ACS_STATUS_PASS)
  {
    status = ACS_STATUS_ERR;
    goto cleanup_restore;
  }

  if ((ctl3_readback & RMECDA_CTL1_LINK_STR_LOCK_MASK) == 0u)
  {
    val_print(ACS_PRINT_INFO, " RXQHNG: LINK_STR_LOCK refused to set for RP 0x%x", root_bdf);
    status = ACS_STATUS_SKIP;
    goto cleanup_restore;
  }

  status = run_dma_compare(endpoint_bdf,
                           page_pa,
                           next_page_pa,
                           dram_buf_in_virt,
                           dram_buf_in_virt2,
                           dma_len,
                           1u);
  if (status != ACS_STATUS_PASS)
  {
    val_print(ACS_PRINT_INFO, " RXQHNG: baseline DMA failed for EP 0x%x", endpoint_bdf);
    status = ACS_STATUS_SKIP;
    goto cleanup_restore;
  }

  /* Case 1: RID_RANGE_VALID==0 => request must be rejected (with LINK_STR_LOCK==1). */
  (void)write_from_root(cfg_va + rmecda_cap_base + RMECDA_CTL1_OFFSET, ctl1_unlocked);
  status = program_rid_range(cfg_va, rmecda_cap_base, ctl3_original, ctl4_original,
                             rid_base, rid_limit, 0u, NULL, NULL);
  if (status != ACS_STATUS_PASS)
  {
    val_print(ACS_PRINT_INFO, " RXQHNG: RID_RANGE_VALID not writable for RP 0x%x - skipping",
              root_bdf);
    status = ACS_STATUS_SKIP;
    goto cleanup_restore;
  }
  (void)write_from_root(cfg_va + rmecda_cap_base + RMECDA_CTL1_OFFSET, ctl1_locked);

  status = run_dma_compare(endpoint_bdf,
                           page_pa,
                           next_page_pa,
                           dram_buf_in_virt,
                           dram_buf_in_virt2,
                           dma_len,
                           0u);
  if (status != ACS_STATUS_PASS)
  {
    val_print(ACS_PRINT_ERR, " RXQHNG: request accepted with RID_RANGE_VALID==0 (RP 0x%x)",
              root_bdf);
    failures++;
  }

  /* Case 2: RID_BASE above Requester ID => request must be rejected. */
  if ((endpoint_rid & 0xFFFFu) != 0xFFFFu)
  {
    rid_base = (uint16_t)((endpoint_rid & 0xFFFFu) + 1u);
    rid_limit = 0xFFFFu;

    (void)write_from_root(cfg_va + rmecda_cap_base + RMECDA_CTL1_OFFSET, ctl1_unlocked);
    status = program_rid_range(cfg_va, rmecda_cap_base, ctl3_original, ctl4_original,
                               rid_base, rid_limit, 1u, NULL, NULL);
    if (status != ACS_STATUS_PASS)
    {
      val_print(ACS_PRINT_INFO, " RXQHNG: RID_BASE/RID_LIMIT not writable for RP 0x%x - skipping",
                root_bdf);
      status = ACS_STATUS_SKIP;
      goto cleanup_restore;
    }

    rid_range_checks++;

    (void)write_from_root(cfg_va + rmecda_cap_base + RMECDA_CTL1_OFFSET, ctl1_locked);
    status = run_dma_compare(endpoint_bdf,
                             page_pa,
                             next_page_pa,
                             dram_buf_in_virt,
                             dram_buf_in_virt2,
                             dma_len,
                             0u);
    if (status != ACS_STATUS_PASS)
    {
      val_print(ACS_PRINT_ERR, " RXQHNG: request accepted when RID < RID_BASE (RP 0x%x)",
                root_bdf);
      failures++;
    }
  }

  /* Case 3: RID_LIMIT below Requester ID => request must be rejected. */
  if ((endpoint_rid & 0xFFFFu) != 0u)
  {
    rid_base = 0u;
    rid_limit = (uint16_t)((endpoint_rid & 0xFFFFu) - 1u);

    (void)write_from_root(cfg_va + rmecda_cap_base + RMECDA_CTL1_OFFSET, ctl1_unlocked);
    status = program_rid_range(cfg_va, rmecda_cap_base, ctl3_original, ctl4_original,
                               rid_base, rid_limit, 1u, NULL, NULL);
    if (status != ACS_STATUS_PASS)
    {
      val_print(ACS_PRINT_INFO, " RXQHNG: RID_BASE/RID_LIMIT not writable for RP 0x%x - skipping",
                root_bdf);
      status = ACS_STATUS_SKIP;
      goto cleanup_restore;
    }

    rid_range_checks++;

    (void)write_from_root(cfg_va + rmecda_cap_base + RMECDA_CTL1_OFFSET, ctl1_locked);
    status = run_dma_compare(endpoint_bdf,
                             page_pa,
                             next_page_pa,
                             dram_buf_in_virt,
                             dram_buf_in_virt2,
                             dma_len,
                             0u);
    if (status != ACS_STATUS_PASS)
    {
      val_print(ACS_PRINT_ERR, " RXQHNG: request accepted when RID > RID_LIMIT (RP 0x%x)",
                root_bdf);
      failures++;
    }
  }

  if (rid_range_checks == 0u)
  {
    status = ACS_STATUS_SKIP;
    goto cleanup_restore;
  }

  status = (failures == 0u) ? ACS_STATUS_PASS : ACS_STATUS_FAIL;

cleanup_restore:
  if (smmu_active != 0u)
  {
    //val_smmu_unmap(master);
    val_pgt_destroy(pgt_desc);
  }

  if (endpoint_bdf != ACS_INVALID_INDEX)
  {
    (void)val_exerciser_set_param_by_bdf(CFG_TXN_ATTRIBUTES, TXN_REQ_ID_VALID, RID_NOT_VALID,
                                         endpoint_bdf);
  }

  if ((page_pa != 0u) && (gpt_entry_added != 0u))
  {
    (void)val_add_gpt_entry_el3(page_pa, GPT_ANY);
  }
  if ((next_page_pa != 0u) && (gpt_entry_added_next != 0u))
  {
    (void)val_add_gpt_entry_el3(next_page_pa, GPT_ANY);
  }

  if (dram_buf_in_virt != NULL)
  {
    val_memory_free_pages(dram_buf_in_virt, TEST_DATA_NUM_PAGES);
  }

  if ((cfg_va != 0u) && (regs_read != 0u))
  {
    (void)write_from_root(cfg_va + rmecda_cap_base + RMECDA_CTL3_OFFSET, ctl3_original);
    (void)write_from_root(cfg_va + rmecda_cap_base + RMECDA_CTL4_OFFSET, ctl4_original);
    (void)write_from_root(cfg_va + rmecda_cap_base + RMECDA_CTL1_OFFSET, ctl1_original);
  }

  return status;
}

static void
payload(void)
{
  uint32_t pe_index = val_pe_get_index_mpid(val_pe_get_mpid());
  CXL_COMPONENT_TABLE *table = val_cxl_component_table_ptr();
  uint32_t executed = 0u;
  uint32_t failures = 0u;
  uint32_t skipped = 0u;

  if ((table == NULL) || (table->num_entries == 0u))
  {
    val_print(ACS_PRINT_DEBUG, " RXQHNG: no CXL component table - skipping", 0);
    val_set_status(pe_index, "SKIP", 01);
    return;
  }

  if (val_cxl_exerciser_get_info(CXL_EXERCISER_NUM_CARDS) == 0u)
  {
    val_print(ACS_PRINT_DEBUG, " RXQHNG: no CXL exerciser endpoints discovered", 0);
    val_set_status(pe_index, "SKIP", 02);
    return;
  }

  for (uint32_t idx = 0u; idx < table->num_entries; ++idx)
  {
    uint32_t role = (uint32_t)val_cxl_get_component_info(CXL_COMPONENT_INFO_ROLE, idx);
    uint32_t root_bdf = (uint32_t)val_cxl_get_component_info(CXL_COMPONENT_INFO_BDF_INDEX, idx);
    uint32_t chi_c2c_supported =
      (uint32_t)val_cxl_get_component_info(CXL_COMPONENT_INFO_CHI_C2C_SUPPORTED, idx);
    uint32_t rmecda_cap_base;

    if (role != CXL_COMPONENT_ROLE_ROOT_PORT)
      continue;

    if (chi_c2c_supported == 0u)
      continue;

    if (val_pcie_find_cda_capability(root_bdf, &rmecda_cap_base) != PCIE_SUCCESS)
      continue;

    {
      uint32_t status;

      executed++;
      status = verify_root_port(root_bdf, rmecda_cap_base);

      if (status == ACS_STATUS_PASS)
        continue;
      if (status == ACS_STATUS_SKIP)
        skipped++;
      else
        failures++;
    }
  }

  if ((executed == 0u) || (skipped == executed))
    val_set_status(pe_index, "SKIP", 04);
  else if (failures != 0u)
    val_set_status(pe_index, "FAIL", failures);
  else
    val_set_status(pe_index, "PASS", 01);
}

uint32_t
cxl_rxqhng_rid_range_reject_entry(uint32_t num_pe)
{
  num_pe = 1;
  uint32_t status;

  status = val_initialize_test(TEST_NAME, TEST_DESC, num_pe, TEST_RULE);

  if (status != ACS_STATUS_SKIP)
    val_run_test_payload(num_pe, payload, 0);

  status = val_check_for_error(num_pe);

  val_report_status(0, "END");

  return status;
}
