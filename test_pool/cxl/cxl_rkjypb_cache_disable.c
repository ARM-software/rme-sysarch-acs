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

#include "val/include/val_cxl.h"
#include "val/include/val_cxl_spec.h"
#include "val/include/val_da.h"
#include "val/include/val_el32.h"
#include "val/include/val_memory.h"
#include "val/include/val_pcie.h"
#include "val/include/val_pcie_spec.h"

#define TEST_NAME "cxl_rkjypb_cache_disable"
#define TEST_DESC "CXL.cache disabled if RP not subject to GPC            "
#define TEST_RULE "RKJYPB"

#define RMECDA_CTL1_TDISP_EN_MASK 0x1u

static uint32_t
msd_write_protect_check(uint64_t pa,
                        uint32_t new_value,
                        uint32_t original_value)
{
  static const uint64_t pas_list[] = {ROOT_PAS, REALM_PAS, NONSECURE_PAS, SECURE_PAS};
  uint32_t failures = 0u;
  uint64_t attr;
  uint64_t tg;
  uint64_t pa_page;
  uint64_t offset;
  uint64_t root_va;

  tg = val_get_min_tg();
  if (tg == 0u)
    return 1u;

  pa_page = pa & ~(tg - 1u);
  offset = pa - pa_page;
  attr = LOWER_ATTRS(PGT_ENTRY_ACCESS |
                     SHAREABLE_ATTR(OUTER_SHAREABLE) |
                     GET_ATTR_INDEX(DEV_MEM_nGnRnE) |
                     PGT_ENTRY_AP_RW);

  /*
   * Reads via non-ROOT PAS can be rejected by the model (for example, Realm
   * requests when TDISP is disabled). Use a ROOT alias to validate the backing
   * register contents after each write attempt.
   */
  root_va = val_get_free_va(tg);
  if (root_va == 0u)
    return 1u;

  if (val_add_mmu_entry_el3(root_va, pa_page, attr | LOWER_ATTRS(PAS_ATTR(ROOT_PAS))))
    return 1u;

  for (uint32_t index = 0u; index < (sizeof(pas_list) / sizeof(pas_list[0])); ++index)
  {
    uint64_t pas = pas_list[index];
    uint64_t va = root_va;

    if (pas != ROOT_PAS)
    {
      va = val_get_free_va(tg);
      if (va == 0u)
      {
        failures++;
        continue;
      }

      if (val_add_mmu_entry_el3(va, pa_page, attr | LOWER_ATTRS(PAS_ATTR(pas))))
      {
        failures++;
        continue;
      }
    }

    shared_data->num_access = 1;
    shared_data->shared_data_access[0].addr = va + offset;
    shared_data->shared_data_access[0].access_type = WRITE_DATA;
    shared_data->shared_data_access[0].data = new_value;
    if (val_pe_access_mut_el3())
    {
      if (pas == ROOT_PAS)
      {
        failures++;
        continue;
      }
    }

    shared_data->num_access = 1;
    shared_data->shared_data_access[0].addr = root_va + offset;
    shared_data->shared_data_access[0].access_type = READ_DATA;
    if (val_pe_access_mut_el3())
    {
      failures++;
      continue;
    }

    uint32_t read_value = shared_data->shared_data_access[0].data;

    if (pas == ROOT_PAS)
    {
      if (read_value == original_value)
        failures++;
    }
    else
    {
      if (read_value != original_value)
        failures++;
    }

    shared_data->num_access = 1;
    shared_data->shared_data_access[0].addr = root_va + offset;
    shared_data->shared_data_access[0].access_type = WRITE_DATA;
    shared_data->shared_data_access[0].data = original_value;
    if (val_pe_access_mut_el3())
      failures++;
  }

  return failures;
}

static void
payload(void)
{
  uint32_t pe_index;
  uint32_t component_count;
  uint32_t tested_ports;
  uint32_t failure_count;
  uint64_t tg;

  pe_index = val_pe_get_index_mpid(val_pe_get_mpid());
  component_count = (uint32_t)val_cxl_get_component_info(CXL_COMPONENT_INFO_COUNT, 0);

  if (component_count == 0u)
  {
    val_set_status(pe_index, "SKIP", 01);
    return;
  }

  tested_ports = 0u;
  failure_count = 0u;

  for (uint32_t comp = 0u; comp < component_count; ++comp)
  {
    uint32_t role;
    uint32_t bdf;
    uint64_t component_base;
    uint64_t cap_base;
    uint32_t status;
    uint32_t port_id;
    uint32_t policy;
    uint64_t policy_pa;
    uint32_t trust_level;
    uint32_t rmecda_ctl1 = 0u;
    uint32_t tdisp_en = 0u;
    uint32_t new_trust_level;
    uint32_t new_policy;
    uint32_t wp_failures;

    role = (uint32_t)val_cxl_get_component_info(CXL_COMPONENT_INFO_ROLE, comp);
    if (role != CXL_COMPONENT_ROLE_ROOT_PORT)
      continue;

    bdf = (uint32_t)val_cxl_get_component_info(CXL_COMPONENT_INFO_BDF_INDEX, comp);
    if (bdf == CXL_COMPONENT_INVALID_INDEX)
      continue;

    if (val_cxl_rp_is_not_subject_to_host_gpc(bdf) == 0u)
      continue;

    tested_ports = 1u;

    status = val_cxl_find_component_register_base(bdf, &component_base);
    if (status != ACS_STATUS_PASS)
    {
      val_print(ACS_PRINT_ERR,
                " RKJYPB: failed to locate component regs for RP 0x%x",
                bdf);
      failure_count++;
      continue;
    }

    status = val_cxl_find_capability(component_base,
                                     CXL_CAPID_EXT_SECURITY,
                                     &cap_base);
    if (status != ACS_STATUS_PASS)
    {
      val_print(ACS_PRINT_ERR,
                " RKJYPB: missing CXL Extended Security Capability on RP 0x%x",
                bdf);
      failure_count++;
      continue;
    }

    status = val_pcie_get_root_port_id(bdf, &port_id);
    if (status != ACS_STATUS_PASS)
    {
      val_print(ACS_PRINT_ERR,
                " RKJYPB: failed to read Port ID for RP 0x%x",
                bdf);
      failure_count++;
      continue;
    }

    status = val_cxl_find_ext_security_policy(cap_base, port_id, &policy, &policy_pa);
    if (status != ACS_STATUS_PASS)
    {
      val_print(ACS_PRINT_ERR,
                " RKJYPB: missing policy entry for RP 0x%x",
                bdf);
      val_print(ACS_PRINT_ERR, " RKJYPB: Port ID %u", port_id);
      failure_count++;
      continue;
    }

    trust_level = (policy >> CXL_SECURITY_POLICY_TRUST_LEVEL_SHIFT) &
                  CXL_SECURITY_POLICY_TRUST_LEVEL_MASK;

    if (trust_level == CXL_TRUST_LEVEL_TRUSTED)
    {
      val_print(ACS_PRINT_ERR,
                " RKJYPB: Device Trust Level Trusted for RP 0x%x",
                bdf);
      val_print(ACS_PRINT_ERR, " RKJYPB: Port ID %u", port_id);
      failure_count++;
    }

    status = val_pcie_read_rmecda_ctl1(bdf, &rmecda_ctl1);
    if (status == ACS_STATUS_PASS)
      tdisp_en = (rmecda_ctl1 & RMECDA_CTL1_TDISP_EN_MASK) ? 1u : 0u;
    else
      tdisp_en = 0u;

    if (trust_level == CXL_TRUST_LEVEL_DEVICE_MEMORY_ONLY)
      new_trust_level = CXL_TRUST_LEVEL_UNTRUSTED;
    else
      new_trust_level = CXL_TRUST_LEVEL_DEVICE_MEMORY_ONLY;

    new_policy = (policy & ~CXL_SECURITY_POLICY_TRUST_LEVEL_MASK) |
                 (new_trust_level & CXL_SECURITY_POLICY_TRUST_LEVEL_MASK);

    /*
     * EL3 exercises MSD/RMSD write-protect behaviour by issuing accesses with
     * varying PAS values. Ensure the backing MMIO page is mapped as GPT_ANY so
     * that PAS-tagged accesses do not trigger a Granule Protection Fault.
     */
    tg = val_get_min_tg();
    if (tg == 0u)
    {
      val_print(ACS_PRINT_ERR, " RKJYPB: invalid translation granule", 0);
      val_print(ACS_PRINT_ERR, " RKJYPB: RP BDF 0x%x", bdf);
      failure_count++;
      continue;
    }

    {
      uint64_t policy_page_pa = policy_pa & ~(tg - 1u);

      if (val_add_gpt_entry_el3(policy_page_pa, GPT_ANY))
      {
        val_print(ACS_PRINT_ERR,
                  " RKJYPB: failed to set GPT_ANY for Policy PA 0x%llx",
                  policy_pa);
        val_print(ACS_PRINT_ERR, " RKJYPB: RP BDF 0x%x", bdf);
        failure_count++;
        continue;
      }
    }

    if (tdisp_en)
      wp_failures = val_rmsd_write_protect_check(policy_pa, new_policy, policy);
    else
      wp_failures = msd_write_protect_check(policy_pa, new_policy, policy);

    if (wp_failures != 0u)
    {
      val_print(ACS_PRINT_ERR, " RKJYPB: write-protection failures %u", wp_failures);
      val_print(ACS_PRINT_ERR, " RKJYPB: RP BDF 0x%x", bdf);
      val_print(ACS_PRINT_ERR, " RKJYPB: Policy PA 0x%llx", policy_pa);
      failure_count++;
    }
  }

  if (!tested_ports)
    val_set_status(pe_index, "SKIP", 02);
  else if (failure_count)
    val_set_status(pe_index, "FAIL", failure_count);
  else
    val_set_status(pe_index, "PASS", 01);
}

uint32_t
cxl_rkjypb_cache_disable_entry(uint32_t num_pe)
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
