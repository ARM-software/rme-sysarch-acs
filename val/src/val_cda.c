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

#include "include/val.h"
#include "include/val_common.h"
#include "include/val_interface.h"
#include "include/val_cda.h"
#include "include/val_cxl.h"
#include "include/val_cxl_spec.h"
#include "include/val_el32.h"
#include "include/val_exerciser.h"
#include "include/val_iovirt.h"
#include "include/val_memory.h"
#include "include/val_pcie.h"
#include "include/val_pcie_spec.h"
#include "include/val_pgt.h"

#define RMECDA_CTL1_LINK_STR_LOCK_MASK  (1u << 1)
#define RMECDA_CTL3_RID_LIMIT_SHIFT       8u
#define RMECDA_CTL3_RID_LIMIT_MASK        (0xFFFFu << RMECDA_CTL3_RID_LIMIT_SHIFT)
#define RMECDA_CTL4_RID_BASE_SHIFT        8u
#define RMECDA_CTL4_RID_BASE_MASK         (0xFFFFu << RMECDA_CTL4_RID_BASE_SHIFT)
#define RMECDA_CTL4_RID_RANGE_VALID_MASK  0x1u

/**
  @brief  Find a CHI-C2C exerciser endpoint downstream of a root port.

  @param  root_bdf          Root port BDF.
  @param  endpoint_bdf_out  Output pointer for the endpoint BDF.

  @return ACS_STATUS_PASS if a usable endpoint was found.
          ACS_STATUS_SKIP if no matching endpoint is present.
          ACS_STATUS_ERR  if discovery data cannot be read.
**/
uint32_t
val_cda_find_downstream_chi_c2c_exerciser_endpoint(uint32_t root_bdf,
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

/**
  @brief  Set or clear RMECDA_CTL1.LINK_STR_LOCK and verify the readback.

  @param  cfg_va           Root-accessible VA for the root port config space.
  @param  rmecda_cap_base  RME-CDA DVSEC capability offset.
  @param  ctl1_template    Existing RMECDA_CTL1 value; non-lock fields are preserved.
  @param  lock             Nonzero to set LINK_STR_LOCK, zero to clear it.

  @return ACS_STATUS_PASS if the requested state was programmed and verified.
          ACS_STATUS_SKIP if the bit did not take the requested state.
          ACS_STATUS_ERR  if Root access failed.
**/
uint32_t
val_cda_set_link_stream_lock(uint64_t cfg_va,
                             uint32_t rmecda_cap_base,
                             uint32_t ctl1_template,
                             uint32_t lock)
{
  uint32_t value;
  uint32_t readback;

  if (cfg_va == 0u)
    return ACS_STATUS_ERR;

  value = ctl1_template;
  if (lock != 0u)
    value |= RMECDA_CTL1_LINK_STR_LOCK_MASK;
  else
    value &= ~RMECDA_CTL1_LINK_STR_LOCK_MASK;

  if (val_memory_write_el3(cfg_va + rmecda_cap_base + RMECDA_CTL1_OFFSET,
                           value) != ACS_STATUS_PASS)
    return ACS_STATUS_ERR;

  if (val_memory_read_el3(cfg_va + rmecda_cap_base + RMECDA_CTL1_OFFSET,
                          &readback) != ACS_STATUS_PASS)
    return ACS_STATUS_ERR;

  if (((readback & RMECDA_CTL1_LINK_STR_LOCK_MASK) != 0u) != (lock != 0u))
    return ACS_STATUS_SKIP;

  return ACS_STATUS_PASS;
}

/**
  @brief  Program the RMECDA_CTL3/CTL4 Requester ID range.

  @param  cfg_va           Root-accessible VA for the root port config space.
  @param  rmecda_cap_base  RME-CDA DVSEC capability offset.
  @param  ctl3_template    Existing RMECDA_CTL3 value; non-RID fields are preserved.
  @param  ctl4_template    Existing RMECDA_CTL4 value; non-RID fields are preserved.
  @param  rid_base         RID_BASE value to program.
  @param  rid_limit        RID_LIMIT value to program.
  @param  rid_range_valid  Nonzero to set RID_RANGE_VALID.

  @return ACS_STATUS_PASS if the fields were programmed and verified.
          ACS_STATUS_SKIP if the RID fields are not writable.
          ACS_STATUS_ERR  if Root access failed.
**/
uint32_t
val_cda_program_rid_range(uint64_t cfg_va,
                          uint32_t rmecda_cap_base,
                          uint32_t ctl3_template,
                          uint32_t ctl4_template,
                          uint32_t rid_base,
                          uint32_t rid_limit,
                          uint32_t rid_range_valid)
{
  uint32_t ctl3_program;
  uint32_t ctl4_program;
  uint32_t ctl3_readback;
  uint32_t ctl4_readback;

  if (cfg_va == 0u)
    return ACS_STATUS_ERR;

  ctl3_program = (ctl3_template & ~RMECDA_CTL3_RID_LIMIT_MASK) |
                 (((rid_limit & 0xFFFFu) << RMECDA_CTL3_RID_LIMIT_SHIFT) &
                  RMECDA_CTL3_RID_LIMIT_MASK);
  ctl4_program = ctl4_template &
                 ~(RMECDA_CTL4_RID_BASE_MASK |
                   RMECDA_CTL4_RID_RANGE_VALID_MASK);
  ctl4_program |= ((rid_base & 0xFFFFu) << RMECDA_CTL4_RID_BASE_SHIFT) &
                  RMECDA_CTL4_RID_BASE_MASK;
  if (rid_range_valid != 0u)
    ctl4_program |= RMECDA_CTL4_RID_RANGE_VALID_MASK;

  if (val_memory_write_el3(cfg_va + rmecda_cap_base + RMECDA_CTL3_OFFSET,
                           ctl3_program) != ACS_STATUS_PASS)
    return ACS_STATUS_ERR;

  if (val_memory_write_el3(cfg_va + rmecda_cap_base + RMECDA_CTL4_OFFSET,
                           ctl4_program) != ACS_STATUS_PASS)
    return ACS_STATUS_ERR;

  if ((val_memory_read_el3(cfg_va + rmecda_cap_base + RMECDA_CTL3_OFFSET,
                           &ctl3_readback) != ACS_STATUS_PASS) ||
      (val_memory_read_el3(cfg_va + rmecda_cap_base + RMECDA_CTL4_OFFSET,
                           &ctl4_readback) != ACS_STATUS_PASS))
    return ACS_STATUS_ERR;

  if (((ctl3_readback & RMECDA_CTL3_RID_LIMIT_MASK) !=
       (ctl3_program & RMECDA_CTL3_RID_LIMIT_MASK)) ||
      ((ctl4_readback & (RMECDA_CTL4_RID_BASE_MASK |
                         RMECDA_CTL4_RID_RANGE_VALID_MASK)) !=
       (ctl4_program & (RMECDA_CTL4_RID_BASE_MASK |
                        RMECDA_CTL4_RID_RANGE_VALID_MASK))))
    return ACS_STATUS_SKIP;

  return ACS_STATUS_PASS;
}

/**
  @brief   Execute all CDA compliance tests registered for the suite.

  @param  num_pe  Number of processing elements available for test execution. Unused.

  @return Consolidated status of the executed tests.
**/
uint32_t
val_rme_cda_execute_tests(uint32_t num_pe)
{
  uint32_t status = ACS_STATUS_SKIP;
  uint64_t num_smmus = val_smmu_get_info(SMMU_NUM_CTRL, 0);
  uint64_t *smmu_base_arr = NULL;
  uint64_t pgt_attr_el3;
  uint32_t smmu_cnt;

  g_curr_module = 1 << CDA_MODULE_ID;

  if ((num_smmus != 0u) && !g_rl_smmu_init)
  {
    smmu_base_arr = val_memory_alloc_pages(1);
    if (smmu_base_arr == NULL)
    {
      val_print(ACS_PRINT_ERR, " Failed to allocate CDA smmu_base_arr", 0);
      return ACS_STATUS_ERR;
    }

    smmu_cnt = 0u;
    while (smmu_cnt < num_smmus)
    {
      smmu_base_arr[smmu_cnt] = val_smmu_get_info(SMMU_CTRL_BASE, smmu_cnt);
      smmu_cnt++;
    }

    pgt_attr_el3 = LOWER_ATTRS(PGT_ENTRY_ACCESS |
                               SHAREABLE_ATTR(OUTER_SHAREABLE) |
                               PGT_ENTRY_AP_RW |
                               PAS_ATTR(NONSECURE_PAS));
    if (val_add_mmu_entry_el3((uint64_t)smmu_base_arr,
                              (uint64_t)val_memory_virt_to_phys(smmu_base_arr),
                              pgt_attr_el3))
    {
      val_print(ACS_PRINT_ERR, " MMU mapping failed for CDA smmu_base_arr", 0);
      val_memory_free_pages(smmu_base_arr, 1);
      return ACS_STATUS_ERR;
    }

    if (val_rlm_smmu_init(num_smmus, smmu_base_arr))
    {
      val_print(ACS_PRINT_ERR, " CDA SMMU REALM INIT failed", 0);
      val_memory_free_pages(smmu_base_arr, 1);
      return ACS_STATUS_ERR;
    }

    g_rl_smmu_init = 1u;
    val_memory_free_pages(smmu_base_arr, 1);
  }

  val_print(ACS_PRINT_ALWAYS, "\n\n*******************************************************\n", 0);
  status = val_execute_module_tests(CDA_MODULE_ID,
                                    CDA_MODULE_START,
                                    CDA_MODULE_END,
                                    num_pe,
                                    status);

  return status;
}
