/** @file
 * Copyright (c) 2022-2025, Arm Limited or its affiliates. All rights reserved.
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

#include "include/rme_acs_val.h"
#include "include/rme_acs_common.h"
#include "include/rme_test_entry.h"
#include "include/rme_acs_exerciser.h"
#include "include/rme_acs_iovirt.h"
#include "include/rme_acs_smmu.h"
#include "include/rme_acs_pcie.h"

#include "include/val_interface.h"
#include "include/rme_acs_el32.h"
#include "include/mem_interface.h"

MEM_REGN_INFO_TABLE *g_mem_region_cfg;
MEM_REGN_INFO_TABLE *g_mem_region_pas_filter_cfg;

/**
  @brief   This API will execute all RME tests designated for a given compliance level
           1. Caller       -  Application layer.
           2. Prerequisite -  val_pe_create_info_table, val_allocate_shared_mem
  @param   num_pe - the number of PE to run these tests on.
  @return  Consolidated status of all the tests run.
**/
uint32_t
val_rme_execute_tests(uint32_t num_pe)
{
  uint32_t status = ACS_STATUS_SKIP, i, reset_status;

  for (i = 0 ; i < g_num_skip ; i++) {
      if (val_memory_compare((char8_t *)g_skip_test_str[i], RME_MODULE,
                              val_strnlen(g_skip_test_str[i])) == 0)
      {
          val_print(ACS_PRINT_ALWAYS, "\n USER Override - Skipping all RME tests \n", 0);
          return ACS_STATUS_SKIP;
      }
  }

  /* Check if there are any tests to be executed in current module with user override options*/
  status = val_check_skip_module(RME_MODULE);
  if (status) {
    val_print(ACS_PRINT_ALWAYS, "\n USER Override - Skipping all RME tests \n", 0);
    return ACS_STATUS_SKIP;
  }

  reset_status = val_read_reset_status();
  val_print(ACS_PRINT_DEBUG, " reset_status = %lx\n", reset_status);
  if (reset_status == RESET_TST12_FLAG)
          goto reset_done_12;

  else if (reset_status == RESET_TST31_FLAG)
          goto reset_done_31;

  else if (reset_status == RESET_TST32_FLAG)
          goto reset_done_32;

  else if (reset_status == RESET_TST2_FLAG)
          goto reset_done_2;

  else if (reset_status == RESET_LS_DISBL_FLAG || reset_status == RESET_LS_TEST3_FLAG)
          goto reset_done_ls;

  g_curr_module = 1 << RME_MODULE_ID;

  /* RME-ACS tests */
  val_print(ACS_PRINT_ALWAYS, "\n\n******************************************************* \n", 0);
  status = rme_support_in_pe_entry(num_pe);
  status |= rme_gprs_scrubbed_after_reset_entry();
reset_done_2:
  status = rme_gprs_scrubbed_after_reset_entry();
  status |= rme_all_pe_has_feat_rng_or_rng_trap_entry(num_pe);
  status |= rme_gpc_for_system_resource_entry();
  status |= rme_coherent_interconnect_supports_cmo_popa_entry();
  status |= rme_resources_aligned_to_granularity_entry();
  status |= rme_resources_are_not_physically_aliased_entry();
  status |= rme_pe_do_not_have_arch_diff_entry(num_pe);
  status |= rme_mte_region_in_root_pas_entry();
  status |= rme_encryption_for_all_pas_except_ns_entry();
  status |= rme_pas_filter_functionality_entry();
  status |= rme_realm_smem_behaviour_after_reset_entry();
reset_done_12:
  status = rme_realm_smem_behaviour_after_reset_entry();
  status |= rme_pcie_devices_support_gpc_entry();
  status |= rme_data_encryption_beyond_popa_entry();
  status |= rme_data_encryption_with_different_tweak_entry();
  status |= rme_msd_smem_in_root_pas_entry();
  status |= rme_realm_smem_in_realm_pas_entry();
  status |= rme_snoop_filter_considers_pas_entry(2);
  status |= rme_cmo_popa_for_cacheability_shareability_entry();
  status |= rme_memory_associated_with_pas_till_popa_entry();
  status |= rme_interconnect_supports_tlbi_pa_entry();
  status |= rme_ns_encryption_is_immutable_entry();
  status |= rme_pe_context_after_exit_wfi_entry();
  status |= rme_pe_context_after_pe_suspend_entry();
  status |= rme_msd_save_restore_mem_in_root_pas_entry();
  status |= rme_rnvs_in_root_pas_entry();
  status |= rme_root_wdog_from_root_pas_entry();
  status |= rme_root_wdog_fails_in_non_root_state_entry();
  status |= rme_pas_filter_in_inactive_mode_entry();
  status |= rme_smmu_blocks_request_at_registers_reset_entry();
  status |= rme_system_reset_propagation_to_all_pe_entry(num_pe);
reset_done_31:
  status = rme_system_reset_propagation_to_all_pe_entry(num_pe);
  status |= rme_msd_smem_in_root_after_reset_entry();
reset_done_32:
  status = rme_msd_smem_in_root_after_reset_entry();

reset_done_ls:
  return status;

}

void
val_mem_region_create_info_table(uint64_t *mem_gpc_region_table, uint64_t *mem_pas_region_table)
{
  g_mem_region_cfg = (MEM_REGN_INFO_TABLE *)mem_gpc_region_table;
  g_mem_region_pas_filter_cfg = (MEM_REGN_INFO_TABLE *)mem_pas_region_table;

  pal_mem_region_create_info_table(g_mem_region_cfg, g_mem_region_pas_filter_cfg);
}

MEM_REGN_INFO_TABLE *
val_mem_gpc_info_table(void)
{
  return g_mem_region_cfg;
}

MEM_REGN_INFO_TABLE *
val_mem_pas_info_table(void)
{
  return g_mem_region_pas_filter_cfg;
}