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

#include "include/rme_acs_val.h"
#include "include/rme_acs_common.h"
#include "include/rme_acs_pcie.h"
#include "include/rme_acs_da.h"
#include "include/rme_acs_dpt.h"
#include "include/rme_acs_smmu.h"
#include "include/rme_acs_iovirt.h"

#include "include/rme_acs_memory.h"
#include "include/mem_interface.h"
#include "include/rme_acs_el32.h"
#include "include/mem_interface.h"
#include "include/val_interface.h"

/**
  @brief   This API will execute all RME DPT tests designated for a given compliance level
           1. Caller       -  Application layer.
           2. Prerequisite -  val_pe_create_info_table, val_allocate_shared_mem
  @param   num_pe - the number of PE to run these tests on.
  @return  Consolidated status of all the tests run.
**/

uint32_t
val_rme_dpt_execute_tests(uint32_t num_pe)
{
  uint32_t status = ACS_STATUS_SKIP, i, reset_status, smmu_cnt;
  uint64_t num_smmus = val_smmu_get_info(SMMU_NUM_CTRL, 0);
  uint64_t smmu_base_arr[num_smmus], pgt_attr_el3;
  (void)num_pe;

  for (i = 0 ; i < MAX_TEST_SKIP_NUM ; i++) {
      if (val_memory_compare(g_skip_test_str[i], DPT_MODULE, val_strnlen(g_skip_test_str[i])) == 0)
      {
          val_print(ACS_PRINT_ALWAYS, "\n USER Override - Skipping all RME-DPT tests \n", 0);
          return ACS_STATUS_SKIP;
      }
  }

  if ((val_memory_compare(g_single_module_str, SINGLE_MODULE_SENTINEL_STR,
                          val_strnlen(g_single_module_str)) != 0 &&
      val_memory_compare(g_single_module_str, DPT_MODULE, val_strnlen(g_single_module_str)) != 0) &&
      (val_memory_compare(g_single_test_str, SINGLE_TEST_SENTINEL_STR,
                          val_strnlen(g_single_test_str)) == 0 ||
       val_memory_compare(DPT_MODULE, g_single_test_str, val_strnlen(DPT_MODULE)) != 0)) {
    val_print(ACS_PRINT_ALWAYS, "\n USER Override - Skipping all RME-DPT tests \n", 0);
    val_print(ACS_PRINT_ALWAYS, " (Running only a single module)\n", 0);
    return ACS_STATUS_SKIP;
  }

  g_curr_module = 1 << DPT_MODULE_ID;

  if (!g_rl_smmu_init)
  {
      smmu_cnt = 0;

      while (smmu_cnt < num_smmus)
      {
        smmu_base_arr[smmu_cnt] = val_smmu_get_info(SMMU_CTRL_BASE, smmu_cnt);
        smmu_cnt++;
      }
      /* Map the Pointer in EL3 as NS Access PAS so that EL3 can access this struct pointers */
      pgt_attr_el3 = LOWER_ATTRS(PGT_ENTRY_ACCESS | SHAREABLE_ATTR(OUTER_SHAREABLE) |
                                 PGT_ENTRY_AP_RW | PAS_ATTR(NONSECURE_PAS));
      if (val_add_mmu_entry_el3((uint64_t)(smmu_base_arr), (uint64_t)(smmu_base_arr), pgt_attr_el3))
      {
        val_print(ACS_PRINT_ERR, " MMU mapping failed for smmu_base_arr", 0);
        return ACS_STATUS_ERR;
      }
      if (val_rlm_smmu_init(num_smmus, smmu_base_arr))
      {
        val_print(ACS_PRINT_ERR, " SMMU REALM INIT failed", 0);
        return ACS_STATUS_ERR;
      }

      g_rl_smmu_init = 1;
  }

  reset_status = val_read_reset_status();

  if (reset_status != RESET_TST12_FLAG &&
      reset_status != RESET_TST31_FLAG &&
      reset_status != RESET_TST2_FLAG &&
      reset_status != RESET_LS_DISBL_FLAG &&
      reset_status != RESET_LS_TEST3_FLAG)
  {
    val_print(ACS_PRINT_ALWAYS, "\n*******************************************************\n", 0);
    status = dpt_system_resource_valid_without_dpti_entry();
    status |= dpt_system_resource_valid_with_dpti_entry();
    status |= dpt_system_resource_invalid_entry();
    status |= dpt_p2p_different_rootport_valid_entry();
    status |= dpt_p2p_different_rootport_invalid_entry();
    status |= dpt_p2p_same_rootport_valid_entry();
    status |= dpt_p2p_same_rootport_invalid_entry();
  }

  return status;

}
