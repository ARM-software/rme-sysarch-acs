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
#include "val/include/val_pcie.h"
#include "val/include/val_cxl.h"
#include "val/include/val_cxl_spec.h"
#include "val/include/val_memory.h"
#include "val/include/val_exerciser.h"
#include "val/include/val_pcie_spec.h"
#include "val/include/val_pcie_enumeration.h"
#include "val/include/val_smmu.h"
#include "val/include/val_iovirt.h"
#include "val/include/val_pgt.h"
#include "val/include/val_el32.h"
#include "val/include/val_pe.h"
#include "val/include/val_spdm.h"

#define TEST_NAME "cxl_rgtvgz_tdisp_enable_link_gate"
#define TEST_DESC "TDISP/IDE gating for Realm device-to-host requests"
#define TEST_RULE "RGTVGZ"

#define RMECDA_CTL1_TDISP_EN_MASK 0x1u
#define RMECDA_CTL1_LINK_STR_LOCK_MASK (1u << 1)
#define RMECDA_CTL3_RID_LIMIT_SHIFT 8u
#define RMECDA_CTL3_RID_LIMIT_MASK (0xFFFFu << RMECDA_CTL3_RID_LIMIT_SHIFT)
#define RMECDA_CTL4_RID_RANGE_VALID_MASK 0x1u
#define RMECDA_CTL4_RID_BASE_SHIFT 8u
#define RMECDA_CTL4_RID_BASE_MASK (0xFFFFu << RMECDA_CTL4_RID_BASE_SHIFT)

#define SEC_SID_NONSECURE 0x0u
#define SEC_SID_REALM 0x2u

typedef struct {
  uint32_t root_index;
  uint32_t endpoint_index;
  uint32_t rmecda_ctl1_orig;
  uint32_t rmecda_ctl1_valid;
  uint32_t rmecda_ctl3_orig;
  uint32_t rmecda_ctl3_valid;
  uint32_t rmecda_ctl4_orig;
  uint32_t rmecda_ctl4_valid;
  uint32_t rmecda_cap_base;
  uint64_t rmecda_cfg_va;
} RGTVGZ_CONTEXT;

static uint32_t
find_component_index_by_bdf(const CXL_COMPONENT_TABLE *table,
                            uint32_t bdf,
                            uint32_t *index_out)
{
  if ((table == NULL) || (index_out == NULL))
    return ACS_STATUS_ERR;

  for (uint32_t idx = 0; idx < table->num_entries; ++idx)
  {
    if (table->component[idx].bdf == bdf)
    {
      *index_out = idx;
      return ACS_STATUS_PASS;
    }
  }

  return ACS_STATUS_FAIL;
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

    if (val_exerciser_init_by_bdf(candidate_bdf) == 0u)
    {
      *endpoint_bdf_out = candidate_bdf;
      return ACS_STATUS_PASS;
    }
  }

  return ACS_STATUS_SKIP;
}

static uint32_t
map_el3_data_structure(uint64_t va, uint32_t size, uint32_t pas)
{
  uint32_t attr;
  uint64_t pa;
  uint64_t page_size;
  uint64_t page_mask;
  uint64_t map_va;
  uint64_t end_va;

  if ((va == 0u) || (size == 0u))
    return ACS_STATUS_ERR;

  page_size = val_memory_page_size();
  if ((page_size == 0u) || ((page_size & (page_size - 1u)) != 0u))
    return ACS_STATUS_ERR;
  page_mask = ~(page_size - 1u);

  attr = LOWER_ATTRS(PGT_ENTRY_ACCESS |
                     SHAREABLE_ATTR(OUTER_SHAREABLE) |
                     PGT_ENTRY_AP_RW |
                     PAS_ATTR(pas));

  map_va = va & page_mask;
  end_va = (va + size - 1u) & page_mask;
  while (map_va <= end_va)
  {
    pa = (uint64_t)val_memory_virt_to_phys((void *)map_va);
    if (pa == 0u)
      return ACS_STATUS_ERR;

    if (val_add_mmu_entry_el3(map_va, pa & page_mask, attr))
      return ACS_STATUS_ERR;

    map_va += page_size;
  }

  return ACS_STATUS_PASS;
}

static uint32_t
run_realm_dma_roundtrip(uint32_t endpoint_bdf,
                        uint8_t *buffer_src,
                        uint8_t *buffer_dst,
                        uint32_t length,
                        uint32_t expect_reject)
{
  uint32_t status;

  /* Prepare source/destination buffers for one DMA round trip check. */
  val_memory_set(buffer_src, length, 0xAB);
  val_memory_set(buffer_dst, length, 0x0);
  val_pe_cache_clean_invalidate_range((uint64_t)buffer_src, length);
  val_pe_cache_clean_invalidate_range((uint64_t)buffer_dst, length);

  if (val_exerciser_set_param_by_bdf(EXERCISER_SEC_SID,
                                     SEC_SID_REALM,
                                     0u,
                                     endpoint_bdf))
    return ACS_STATUS_ERR;

  status = val_exerciser_set_param_by_bdf(DMA_ATTRIBUTES,
                                          (uint64_t)buffer_src,
                                          length,
                                          endpoint_bdf);
  if (status != 0u)
    return ACS_STATUS_ERR;

  val_exerciser_ops_by_bdf(START_DMA, EDMA_TO_DEVICE, endpoint_bdf);

  status = val_exerciser_set_param_by_bdf(DMA_ATTRIBUTES,
                                          (uint64_t)buffer_dst,
                                          length,
                                          endpoint_bdf);
  if (status != 0u)
    return ACS_STATUS_ERR;

  val_exerciser_ops_by_bdf(START_DMA, EDMA_FROM_DEVICE, endpoint_bdf);

  val_pe_cache_invalidate_range((uint64_t)buffer_src, length);
  val_pe_cache_invalidate_range((uint64_t)buffer_dst, length);

  status = (val_memory_compare(buffer_src, buffer_dst, length) == 0u) ? 0u : 1u;
  if ((expect_reject == 0u) && (status != 0u))
    return ACS_STATUS_FAIL;
  if ((expect_reject != 0u) && (status == 0u))
    return ACS_STATUS_FAIL;

  return ACS_STATUS_PASS;
}

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
    val_print(ACS_PRINT_ERR, "  RGTVGZ: MUT read failed for 0x%llx", address);
    return ACS_STATUS_ERR;
  }

  *value = (uint32_t)shared_data->shared_data_access[0].data;
  return ACS_STATUS_PASS;
}

static uint32_t
write_from_root(uint64_t address, uint32_t value)
{
  shared_data->num_access = 1;
  shared_data->shared_data_access[0].addr = address;
  shared_data->shared_data_access[0].data = value;
  shared_data->shared_data_access[0].access_type = WRITE_DATA;

  if (val_pe_access_mut_el3())
  {
    val_print(ACS_PRINT_ERR, "  RGTVGZ: MUT write failed for 0x%llx", address);
    return ACS_STATUS_ERR;
  }

  return ACS_STATUS_PASS;
}

static uint32_t
init_rmecda_context(const CXL_COMPONENT_ENTRY *root_port,
                    RGTVGZ_CONTEXT *context)
{
  uint32_t rmecda_cap_base;
  uint64_t cfg_addr;
  uint64_t tg;
  uint32_t attr;

  if ((root_port == NULL) || (context == NULL))
    return ACS_STATUS_ERR;

  if (val_pcie_find_cda_capability(root_port->bdf, &rmecda_cap_base) !=
      PCIE_SUCCESS)
  {
    val_print(ACS_PRINT_INFO, "  RGTVGZ: RME-CDA DVSEC missing", 0);
    return ACS_STATUS_SKIP;
  }

  cfg_addr = val_pcie_get_bdf_config_addr(root_port->bdf);
  tg = val_get_min_tg();
  if ((cfg_addr == 0u) || (tg == 0u))
  {
    val_print(ACS_PRINT_ERR, "  RGTVGZ: Invalid config mapping", 0);
    return ACS_STATUS_FAIL;
  }
  val_print(ACS_PRINT_DEBUG, "  RGTVGZ: RMECDA cfg PA 0x%llx", cfg_addr);
  val_print(ACS_PRINT_DEBUG, "  RGTVGZ: RMECDA map granule 0x%llx", tg);

  context->rmecda_cfg_va = val_get_free_va(tg);
  if (context->rmecda_cfg_va == 0u)
  {
    val_print(ACS_PRINT_ERR, "  RGTVGZ: Config VA allocation failed", 0);
    return ACS_STATUS_FAIL;
  }
  val_print(ACS_PRINT_DEBUG, "  RGTVGZ: RMECDA cfg VA 0x%llx",
            context->rmecda_cfg_va);

  attr = LOWER_ATTRS(PGT_ENTRY_ACCESS | SHAREABLE_ATTR(OUTER_SHAREABLE) |
                     GET_ATTR_INDEX(DEV_MEM_nGnRnE) | PGT_ENTRY_AP_RW |
                     PAS_ATTR(ROOT_PAS));
  if (val_add_mmu_entry_el3(context->rmecda_cfg_va, cfg_addr, attr))
  {
    val_print(ACS_PRINT_ERR, "  RGTVGZ: Config map failed", 0);
    return ACS_STATUS_FAIL;
  }

  context->rmecda_cap_base = rmecda_cap_base;
  val_print(ACS_PRINT_DEBUG, "  RGTVGZ: RMECDA cap base 0x%x",
            context->rmecda_cap_base);
  if (read_from_root(context->rmecda_cfg_va + rmecda_cap_base +
                     RMECDA_CTL1_OFFSET,
                     &context->rmecda_ctl1_orig) != ACS_STATUS_PASS)
  {
    val_print(ACS_PRINT_ERR, "  RGTVGZ: RMECDA_CTL1 read failed", 0);
    return ACS_STATUS_FAIL;
  }

  context->rmecda_ctl1_valid = 1u;

  if (read_from_root(context->rmecda_cfg_va + rmecda_cap_base +
                     RMECDA_CTL3_OFFSET,
                     &context->rmecda_ctl3_orig) != ACS_STATUS_PASS)
  {
    val_print(ACS_PRINT_ERR, "  RGTVGZ: RMECDA_CTL3 read failed", 0);
    return ACS_STATUS_FAIL;
  }
  context->rmecda_ctl3_valid = 1u;

  if (read_from_root(context->rmecda_cfg_va + rmecda_cap_base +
                     RMECDA_CTL4_OFFSET,
                     &context->rmecda_ctl4_orig) != ACS_STATUS_PASS)
  {
    val_print(ACS_PRINT_ERR, "  RGTVGZ: RMECDA_CTL4 read failed", 0);
    return ACS_STATUS_FAIL;
  }
  context->rmecda_ctl4_valid = 1u;

  return ACS_STATUS_PASS;
}

static uint32_t
program_ctl1_mode(const RGTVGZ_CONTEXT *context,
                  uint32_t tdisp_en,
                  uint32_t link_str_lock)
{
  uint32_t rmecda_ctl1;
  uint32_t readback;
  uint32_t expected_bits = 0u;
  uint32_t checked_bits;

  if (context == NULL)
    return ACS_STATUS_ERR;

  rmecda_ctl1 = context->rmecda_ctl1_orig &
                ~(RMECDA_CTL1_TDISP_EN_MASK |
                  RMECDA_CTL1_LINK_STR_LOCK_MASK);
  if (tdisp_en != 0u)
  {
    rmecda_ctl1 |= RMECDA_CTL1_TDISP_EN_MASK;
    expected_bits |= RMECDA_CTL1_TDISP_EN_MASK;
  }

  if (link_str_lock != 0u)
  {
    rmecda_ctl1 |= RMECDA_CTL1_LINK_STR_LOCK_MASK;
    expected_bits |= RMECDA_CTL1_LINK_STR_LOCK_MASK;
  }

  if (write_from_root(context->rmecda_cfg_va + context->rmecda_cap_base +
                      RMECDA_CTL1_OFFSET,
                      rmecda_ctl1) != ACS_STATUS_PASS)
  {
    val_print(ACS_PRINT_ERR, "  RGTVGZ: RMECDA_CTL1 write failed", 0);
    return ACS_STATUS_FAIL;
  }

  if (read_from_root(context->rmecda_cfg_va + context->rmecda_cap_base +
                     RMECDA_CTL1_OFFSET,
                     &readback) != ACS_STATUS_PASS)
  {
    val_print(ACS_PRINT_ERR, "  RGTVGZ: RMECDA_CTL1 readback failed", 0);
    return ACS_STATUS_FAIL;
  }

  checked_bits = readback & (RMECDA_CTL1_TDISP_EN_MASK |
                             RMECDA_CTL1_LINK_STR_LOCK_MASK);
  if (checked_bits != expected_bits)
  {
    val_print(ACS_PRINT_ERR, "  RGTVGZ: RMECDA_CTL1 mode mismatch", 0);
    return ACS_STATUS_FAIL;
  }

  return ACS_STATUS_PASS;
}

static uint32_t
program_rid_range_mode(const RGTVGZ_CONTEXT *context,
                       uint16_t rid_base,
                       uint16_t rid_limit,
                       uint32_t rid_range_valid)
{
  uint32_t rmecda_ctl3;
  uint32_t rmecda_ctl4;
  uint32_t readback;
  uint32_t expected_ctl3;
  uint32_t expected_ctl4;

  if (context == NULL)
    return ACS_STATUS_ERR;

  rmecda_ctl3 = context->rmecda_ctl3_orig & ~RMECDA_CTL3_RID_LIMIT_MASK;
  rmecda_ctl3 |= ((uint32_t)rid_limit << RMECDA_CTL3_RID_LIMIT_SHIFT) &
                 RMECDA_CTL3_RID_LIMIT_MASK;

  rmecda_ctl4 = context->rmecda_ctl4_orig &
                ~(RMECDA_CTL4_RID_RANGE_VALID_MASK | RMECDA_CTL4_RID_BASE_MASK);
  if (rid_range_valid != 0u)
    rmecda_ctl4 |= RMECDA_CTL4_RID_RANGE_VALID_MASK;
  rmecda_ctl4 |= ((uint32_t)rid_base << RMECDA_CTL4_RID_BASE_SHIFT) &
                 RMECDA_CTL4_RID_BASE_MASK;

  if (write_from_root(context->rmecda_cfg_va + context->rmecda_cap_base +
                      RMECDA_CTL3_OFFSET,
                      rmecda_ctl3) != ACS_STATUS_PASS)
  {
    val_print(ACS_PRINT_ERR, "  RGTVGZ: RMECDA_CTL3 write failed", 0);
    return ACS_STATUS_FAIL;
  }

  if (write_from_root(context->rmecda_cfg_va + context->rmecda_cap_base +
                      RMECDA_CTL4_OFFSET,
                      rmecda_ctl4) != ACS_STATUS_PASS)
  {
    val_print(ACS_PRINT_ERR, "  RGTVGZ: RMECDA_CTL4 write failed", 0);
    return ACS_STATUS_FAIL;
  }

  expected_ctl3 = rmecda_ctl3 & RMECDA_CTL3_RID_LIMIT_MASK;
  if (read_from_root(context->rmecda_cfg_va + context->rmecda_cap_base +
                     RMECDA_CTL3_OFFSET,
                     &readback) != ACS_STATUS_PASS)
  {
    val_print(ACS_PRINT_ERR, "  RGTVGZ: RMECDA_CTL3 readback failed", 0);
    return ACS_STATUS_FAIL;
  }
  if ((readback & RMECDA_CTL3_RID_LIMIT_MASK) != expected_ctl3)
  {
    val_print(ACS_PRINT_ERR, "  RGTVGZ: RMECDA_CTL3 mode mismatch", 0);
    return ACS_STATUS_FAIL;
  }

  expected_ctl4 = rmecda_ctl4 &
                  (RMECDA_CTL4_RID_RANGE_VALID_MASK | RMECDA_CTL4_RID_BASE_MASK);
  if (read_from_root(context->rmecda_cfg_va + context->rmecda_cap_base +
                     RMECDA_CTL4_OFFSET,
                     &readback) != ACS_STATUS_PASS)
  {
    val_print(ACS_PRINT_ERR, "  RGTVGZ: RMECDA_CTL4 readback failed", 0);
    return ACS_STATUS_FAIL;
  }
  if ((readback & (RMECDA_CTL4_RID_RANGE_VALID_MASK | RMECDA_CTL4_RID_BASE_MASK))
      != expected_ctl4)
  {
    val_print(ACS_PRINT_ERR, "  RGTVGZ: RMECDA_CTL4 mode mismatch", 0);
    return ACS_STATUS_FAIL;
  }

  return ACS_STATUS_PASS;
}

static uint32_t
is_ide_link_active(uint32_t root_index,
                   uint32_t *is_active,
                   uint32_t *ide_supported)
{
  uint32_t status;
  uint32_t ide_status;
  uint32_t rx_state;
  uint32_t tx_state;

  if ((is_active == NULL) || (ide_supported == NULL))
    return ACS_STATUS_ERR;

  *is_active = 0u;
  *ide_supported = 0u;

  status = val_cxl_ide_get_status(root_index, &ide_status);
  if (status == ACS_STATUS_SKIP)
    return ACS_STATUS_PASS;
  if (status != ACS_STATUS_PASS)
    return status;

  *ide_supported = 1u;
  rx_state = ide_status & CXL_IDE_STATUS_FIELD_MASK;
  tx_state = (ide_status >> CXL_IDE_STATUS_TX_SHIFT) & CXL_IDE_STATUS_FIELD_MASK;
  if ((rx_state != CXL_IDE_STATE_INSECURE) && (tx_state != CXL_IDE_STATE_INSECURE))
    *is_active = 1u;

  return ACS_STATUS_PASS;
}

static uint32_t
verify_root_port(const CXL_COMPONENT_TABLE *table,
                 uint32_t root_index)
{
  const CXL_COMPONENT_ENTRY *root_port = &table->component[root_index];
  const CXL_COMPONENT_ENTRY *endpoint;
  RGTVGZ_CONTEXT context;
  uint32_t status;
  uint64_t page_size;
  uint32_t endpoint_index = CXL_COMPONENT_INVALID_INDEX;
  uint32_t endpoint_bdf = ACS_INVALID_INDEX;
  uint32_t ide_active = 0u;
  uint32_t ide_supported = 0u;
  uint32_t session_id = 0u;
  uint32_t session_active = 0u;
  uint16_t endpoint_rid;
  val_spdm_context_t spdm_ctx;
  smmu_master_attributes_t master;
  memory_region_descriptor_t mem_desc[2];
  pgt_descriptor_t pgt_desc_rlm;
  uint8_t *buffer_va = NULL;
  uint8_t *buffer_src = NULL;
  uint8_t *buffer_dst = NULL;
  uint64_t buffer_pa = 0u;
  uint64_t total_len = 0u;
  uint32_t its_id = 0u;
  uint32_t device_id = 0u;
  uint32_t smmu_index;
  uint32_t pgt_rlm_created = 0u;
  uint32_t smmu_rlm_mapped = 0u;
  uint32_t buffer_valid = 0u;
  uint32_t result;

  val_memory_set(&master, sizeof(master), 0);
  val_memory_set(mem_desc, sizeof(mem_desc), 0);
  val_memory_set(&pgt_desc_rlm, sizeof(pgt_desc_rlm), 0);
  master.smmu_index = ACS_INVALID_INDEX;

  /* Select a downstream CHI C2C-capable exerciser endpoint for this root port. */
  status = find_downstream_chi_c2c_exerciser_endpoint(root_port->bdf, &endpoint_bdf);
  if (status != ACS_STATUS_PASS)
    return ACS_STATUS_SKIP;

  status = find_component_index_by_bdf(table, endpoint_bdf, &endpoint_index);
  if (status != ACS_STATUS_PASS)
    return ACS_STATUS_SKIP;

  endpoint = &table->component[endpoint_index];

  val_print(ACS_PRINT_DEBUG, "  RGTVGZ: Selected RP BDF 0x%x",
            (uint64_t)root_port->bdf);
  val_print(ACS_PRINT_DEBUG, "  RGTVGZ: Selected EP BDF 0x%x",
            (uint64_t)endpoint->bdf);

  status = val_cxl_enable_mem(endpoint->bdf);
  if (status != ACS_STATUS_PASS)
  {
    val_print(ACS_PRINT_ERR, "  RGTVGZ: CXL.mem enable failed", 0);
    return (status == ACS_STATUS_SKIP) ? ACS_STATUS_SKIP : ACS_STATUS_FAIL;
  }

  val_memory_set(&context, sizeof(context), 0);
  context.root_index = root_index;
  context.endpoint_index = endpoint_index;

  status = init_rmecda_context(root_port, &context);
  if (status != ACS_STATUS_PASS)
  {
    result = status;
    goto cleanup;
  }

  /* Establish IDE link so RGTVGZ can validate the IDE Active branch. */
  status = val_spdm_session_open(endpoint->bdf, &spdm_ctx, &session_id);
  if (status == ACS_STATUS_SKIP)
  {
    result = ACS_STATUS_SKIP;
    goto cleanup;
  }
  if (status != ACS_STATUS_PASS)
  {
    val_print(ACS_PRINT_ERR, "  RGTVGZ: SPDM session open failed", 0);
    result = ACS_STATUS_FAIL;
    goto cleanup;
  }
  session_active = 1u;

  status = val_cxl_ide_establish_link(root_index,
                                      endpoint_index,
                                      &spdm_ctx,
                                      session_id);
  if (status == ACS_STATUS_SKIP)
  {
    result = ACS_STATUS_SKIP;
    goto cleanup;
  }
  if (status != ACS_STATUS_PASS)
  {
    val_print(ACS_PRINT_ERR, "  RGTVGZ: IDE link establish failed", 0);
    result = ACS_STATUS_FAIL;
    goto cleanup;
  }

  /* Read IDE status and require active state for this case. */
  status = is_ide_link_active(root_index, &ide_active, &ide_supported);
  if (status != ACS_STATUS_PASS)
  {
    val_print(ACS_PRINT_ERR, "  RGTVGZ: IDE status read failed", 0);
    result = ACS_STATUS_FAIL;
    goto cleanup;
  }

  if ((ide_supported == 0u) || (ide_active == 0u))
  {
    val_print(ACS_PRINT_INFO, "  RGTVGZ: IDE not active after establish", 0);
    result = ACS_STATUS_SKIP;
    goto cleanup;
  }

  /* Allocate two page-sized buffers used for DMA round-trip verification. */
  page_size = (uint64_t)val_memory_page_size();
  if (page_size == 0u)
  {
    result = ACS_STATUS_SKIP;
    goto cleanup;
  }
  if ((uint32_t)page_size == 0u)
  {
    result = ACS_STATUS_SKIP;
    goto cleanup;
  }

  buffer_va = val_memory_alloc_pages(2);
  if (buffer_va == NULL)
  {
    result = ACS_STATUS_SKIP;
    goto cleanup;
  }

  buffer_pa = (uint64_t)val_memory_virt_to_phys(buffer_va);
  if (buffer_pa == 0u)
  {
    result = ACS_STATUS_SKIP;
    goto cleanup;
  }

  buffer_src = buffer_va;
  buffer_dst = buffer_va + page_size;
  buffer_valid = 1u;
  total_len = page_size * 2u;

  endpoint_rid = (uint16_t)PCIE_CREATE_BDF_PACKED(endpoint->bdf);
  status = program_rid_range_mode(&context,
                                  endpoint_rid,
                                  endpoint_rid,
                                  1u);
  if (status != ACS_STATUS_PASS)
  {
    val_print(ACS_PRINT_ERR, "  RGTVGZ: RID range program failed", 0);
    result = ACS_STATUS_FAIL;
    goto cleanup;
  }

  /* Program SMMU translation context for exerciser DMA. */
  smmu_index = val_iovirt_get_rc_smmu_index(PCIE_EXTRACT_BDF_SEG(endpoint_bdf),
                                            PCIE_CREATE_BDF_PACKED(endpoint_bdf));
  if (smmu_index == ACS_INVALID_INDEX)
  {
    result = ACS_STATUS_SKIP;
    goto cleanup;
  }

  master.smmu_index = smmu_index;
  if (val_smmu_enable(master.smmu_index))
  {
    val_print(ACS_PRINT_ERR, "  RGTVGZ: SMMU enable failed", 0);
    result = ACS_STATUS_ERR;
    goto cleanup;
  }

  status = val_iovirt_get_device_info(PCIE_CREATE_BDF_PACKED(endpoint_bdf),
                                      PCIE_EXTRACT_BDF_SEG(endpoint_bdf),
                                      &device_id,
                                      &master.streamid,
                                      &its_id);
  if (status != 0u)
  {
    result = ACS_STATUS_SKIP;
    goto cleanup;
  }

  val_print(ACS_PRINT_DEBUG, "  RGTVGZ: EP BDF 0x%x", (uint64_t)endpoint_bdf);
  val_print(ACS_PRINT_DEBUG, "  RGTVGZ: SMMU index %u", master.smmu_index);
  val_print(ACS_PRINT_DEBUG, "  RGTVGZ: StreamID 0x%lx", master.streamid);
  val_print(ACS_PRINT_DEBUG, "  RGTVGZ: DeviceID 0x%x", (uint64_t)device_id);
  val_print(ACS_PRINT_DEBUG, "  RGTVGZ: ITS ID 0x%x", (uint64_t)its_id);

  mem_desc[0].virtual_address = buffer_pa;
  mem_desc[0].physical_address = buffer_pa;
  mem_desc[0].length = (uint32_t)total_len;
  mem_desc[1].length = 0u;

  pgt_desc_rlm.ias = val_smmu_get_info(SMMU_IN_ADDR_SIZE, master.smmu_index);
  pgt_desc_rlm.oas = val_smmu_get_info(SMMU_OUT_ADDR_SIZE, master.smmu_index);
  if ((pgt_desc_rlm.ias == 0u) || (pgt_desc_rlm.oas == 0u))
  {
    val_print(ACS_PRINT_ERR, "  RGTVGZ: SMMU address size invalid", 0);
    result = ACS_STATUS_SKIP;
    goto cleanup;
  }

  if (val_pe_get_vtcr(&pgt_desc_rlm.vtcr))
  {
    val_print(ACS_PRINT_ERR, "  RGTVGZ: VTCR read failed", 0);
    result = ACS_STATUS_ERR;
    goto cleanup;
  }

  pgt_desc_rlm.pgt_base = (uint64_t)NULL;
  mem_desc[0].attributes = PGT_STAGE2_AP_RW;

  if (map_el3_data_structure((uint64_t)mem_desc,
                             sizeof(mem_desc),
                             NONSECURE_PAS) != ACS_STATUS_PASS)
  {
    val_print(ACS_PRINT_ERR, "  RGTVGZ: EL3 map failed for mem_desc", 0);
    result = ACS_STATUS_ERR;
    goto cleanup;
  }
  if (map_el3_data_structure((uint64_t)&pgt_desc_rlm,
                             sizeof(pgt_desc_rlm),
                             NONSECURE_PAS) != ACS_STATUS_PASS)
  {
    val_print(ACS_PRINT_ERR, "  RGTVGZ: EL3 map failed for pgt_desc_rlm", 0);
    result = ACS_STATUS_ERR;
    goto cleanup;
  }
  if (map_el3_data_structure((uint64_t)&master,
                             sizeof(master),
                             NONSECURE_PAS) != ACS_STATUS_PASS)
  {
    val_print(ACS_PRINT_ERR, "  RGTVGZ: EL3 map failed for smmu master", 0);
    result = ACS_STATUS_ERR;
    goto cleanup;
  }

  val_print(ACS_PRINT_DEBUG, "  RGTVGZ: Realm pgt mem_desc ptr 0x%llx",
            (uint64_t)&mem_desc);
  val_print(ACS_PRINT_DEBUG, "  RGTVGZ: Realm pgt_desc ptr 0x%llx",
            (uint64_t)&pgt_desc_rlm);
  val_print(ACS_PRINT_DEBUG, "  RGTVGZ: Realm pgt VA 0x%llx",
            mem_desc[0].virtual_address);
  val_print(ACS_PRINT_DEBUG, "  RGTVGZ: Realm pgt PA 0x%llx",
            mem_desc[0].physical_address);
  val_print(ACS_PRINT_DEBUG, "  RGTVGZ: Realm pgt length 0x%llx",
            mem_desc[0].length);
  val_print(ACS_PRINT_DEBUG, "  RGTVGZ: Realm pgt ias %d",
            pgt_desc_rlm.ias);
  val_print(ACS_PRINT_DEBUG, "  RGTVGZ: Realm pgt oas %d",
            pgt_desc_rlm.oas);

  if (val_rlm_pgt_create(mem_desc, &pgt_desc_rlm))
  {
    val_print(ACS_PRINT_ERR, "  RGTVGZ: Realm PGT create failed", 0);
    result = ACS_STATUS_ERR;
    goto cleanup;
  }
  pgt_rlm_created = 1u;

  val_pe_reg_write(VTTBR, pgt_desc_rlm.pgt_base);
  master.stage2 = 1;
  if (val_smmu_rlm_map_el3(&master, &pgt_desc_rlm))
  {
    val_print(ACS_PRINT_ERR, "  RGTVGZ: Realm SMMU map failed", 0);
    result = ACS_STATUS_ERR;
    goto cleanup;
  }
  smmu_rlm_mapped = 1u;

  if (val_add_gpt_entry_el3(buffer_pa, GPT_ANY))
  {
    result = ACS_STATUS_ERR;
    goto cleanup;
  }
  if (val_add_gpt_entry_el3(buffer_pa + page_size, GPT_ANY))
  {
    result = ACS_STATUS_ERR;
    goto cleanup;
  }

  if (val_smmu_gpt_invalidate_el3(&master))
  {
    val_print(ACS_PRINT_ERR, "  RGTVGZ: SMMU invalidate failed", 0);
    result = ACS_STATUS_ERR;
    goto cleanup;
  }

  /*
   * Case 1: TDISP_EN=1, LINK_STR_LOCK=1 and IDE active -> request permitted.
   * The payload should propagate, so source and destination buffers must match.
   */
  status = program_ctl1_mode(&context, 1u, 1u);
  if (status != ACS_STATUS_PASS)
  {
    val_print(ACS_PRINT_ERR, "  RGTVGZ: RMECDA_CTL1 setup failed", 0);
    result = ACS_STATUS_ERR;
    goto cleanup;
  }

  status = run_realm_dma_roundtrip(endpoint_bdf,
                                   buffer_src,
                                   buffer_dst,
                                   (uint32_t)page_size,
                                   0u);
  if (status != ACS_STATUS_PASS)
  {
    val_print(ACS_PRINT_ERR, "  RGTVGZ: IDE active permit check failed", 0);
    result = ACS_STATUS_FAIL;
    goto cleanup;
  }

  /*
   * Case 2: send KEY_SET_STOP to disable IDE and verify reject behaviour.
   * A rejected request should not propagate payload, so buffers must mismatch.
   */
  status = val_cxl_ide_disable_link(context.root_index,
                                    context.endpoint_index,
                                    &spdm_ctx,
                                    session_id);
  if (status == ACS_STATUS_SKIP)
  {
    val_print(ACS_PRINT_INFO, "  RGTVGZ: KEY_SET_STOP unsupported", 0);
    result = ACS_STATUS_SKIP;
    goto cleanup;
  }
  if (status != ACS_STATUS_PASS)
  {
    val_print(ACS_PRINT_ERR, "  RGTVGZ: IDE disable failed", 0);
    result = ACS_STATUS_ERR;
    goto cleanup;
  }

  status = run_realm_dma_roundtrip(endpoint_bdf,
                                   buffer_src,
                                   buffer_dst,
                                   (uint32_t)page_size,
                                   1u);
  if (status != ACS_STATUS_PASS)
  {
    val_print(ACS_PRINT_ERR, "  RGTVGZ: IDE inactive reject check failed", 0);
    result = ACS_STATUS_FAIL;
    goto cleanup;
  }

  /* Case 3: TDISP_EN=1, LINK_STR_LOCK=0 -> request rejected. */
  status = program_ctl1_mode(&context, 1u, 0u);
  if (status != ACS_STATUS_PASS)
  {
    val_print(ACS_PRINT_ERR, "  RGTVGZ: LINK_STR_LOCK clear failed", 0);
    result = ACS_STATUS_ERR;
    goto cleanup;
  }

  status = run_realm_dma_roundtrip(endpoint_bdf,
                                   buffer_src,
                                   buffer_dst,
                                   (uint32_t)page_size,
                                   1u);
  if (status != ACS_STATUS_PASS)
  {
    val_print(ACS_PRINT_ERR, "  RGTVGZ: LINK_STR_LOCK=0 reject check failed", 0);
    result = ACS_STATUS_FAIL;
    goto cleanup;
  }

  /* Case 4: TDISP_EN=0 -> request rejected as per RNYCLL fallback path. */
  status = program_ctl1_mode(&context, 0u, 1u);
  if (status != ACS_STATUS_PASS)
  {
    val_print(ACS_PRINT_ERR, "  RGTVGZ: TDISP_EN clear failed", 0);
    result = ACS_STATUS_ERR;
    goto cleanup;
  }

  status = run_realm_dma_roundtrip(endpoint_bdf,
                                   buffer_src,
                                   buffer_dst,
                                   (uint32_t)page_size,
                                   1u);
  if (status != ACS_STATUS_PASS)
  {
    val_print(ACS_PRINT_ERR, "  RGTVGZ: TDISP_EN=0 reject check failed", 0);
    result = ACS_STATUS_FAIL;
    goto cleanup;
  }

  result = ACS_STATUS_PASS;

cleanup:
  if (buffer_valid != 0u)
  {
    if (val_add_gpt_entry_el3(buffer_pa, GPT_ANY))
      result = ACS_STATUS_ERR;
    if (val_add_gpt_entry_el3(buffer_pa + page_size, GPT_ANY))
      result = ACS_STATUS_ERR;
  }

  if (pgt_desc_rlm.pgt_base != 0u)
  {
    if (val_add_gpt_entry_el3(pgt_desc_rlm.pgt_base, GPT_ANY))
      result = ACS_STATUS_ERR;
  }

  if (smmu_rlm_mapped != 0u)
    smmu_rlm_mapped = 0u;
  if (pgt_rlm_created != 0u)
    val_rlm_pgt_destroy(&pgt_desc_rlm);
  if (master.smmu_index != ACS_INVALID_INDEX)
    val_smmu_disable(master.smmu_index);
  if (buffer_valid != 0u)
    val_memory_free_pages(buffer_va, 2);

  if (session_active != 0u)
    (void)val_spdm_session_close(&spdm_ctx, session_id);

  if ((context.rmecda_ctl1_valid != 0u) && (context.rmecda_cfg_va != 0u))
    (void)write_from_root(context.rmecda_cfg_va + context.rmecda_cap_base +
                          RMECDA_CTL1_OFFSET,
                          context.rmecda_ctl1_orig);
  if ((context.rmecda_ctl3_valid != 0u) && (context.rmecda_cfg_va != 0u))
    (void)write_from_root(context.rmecda_cfg_va + context.rmecda_cap_base +
                          RMECDA_CTL3_OFFSET,
                          context.rmecda_ctl3_orig);
  if ((context.rmecda_ctl4_valid != 0u) && (context.rmecda_cfg_va != 0u))
    (void)write_from_root(context.rmecda_cfg_va + context.rmecda_cap_base +
                          RMECDA_CTL4_OFFSET,
                          context.rmecda_ctl4_orig);

  return result;
}

static void
payload(void)
{
  uint32_t pe_index = val_pe_get_index_mpid(val_pe_get_mpid());
  CXL_COMPONENT_TABLE *table = val_cxl_component_table_ptr();
  uint32_t tested = 0u;
  uint32_t failures = 0u;

  if ((table == NULL) || (table->num_entries == 0u))
  {
    val_print(ACS_PRINT_DEBUG, "  RGTVGZ: No CXL components", 0);
    val_set_status(pe_index, "SKIP", 01);
    return;
  }

  for (uint32_t idx = 0; idx < table->num_entries; ++idx)
  {
    const CXL_COMPONENT_ENTRY *component = &table->component[idx];
    uint32_t status;

    if (component->role != CXL_COMPONENT_ROLE_ROOT_PORT)
      continue;
    if (component->chi_c2c_supported == 0u)
      continue;

    val_print(ACS_PRINT_DEBUG, "  RGTVGZ: Considering RP BDF 0x%x",
              (uint64_t)component->bdf);

    status = verify_root_port(table, idx);
    if (status == ACS_STATUS_SKIP)
    {
      val_print(ACS_PRINT_INFO,
                "  RGTVGZ: Skipping RP BDF 0x%x",
                (uint64_t)component->bdf);
      continue;
    }

    if (status != ACS_STATUS_PASS)
    {
      val_print(ACS_PRINT_ERR,
                "  RGTVGZ: RP BDF 0x%x failed",
                (uint64_t)component->bdf);
      failures++;
      continue;
    }

    tested++;
  }

  if ((tested == 0u) && (failures == 0u))
  {
    val_set_status(pe_index, "SKIP", 02);
    return;
  }

  if (failures != 0u)
    val_set_status(pe_index, "FAIL", failures);
  else
    val_set_status(pe_index, "PASS", 01);
}

uint32_t
cxl_rgtvgz_tdisp_enable_link_gate_entry(uint32_t num_pe)
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
