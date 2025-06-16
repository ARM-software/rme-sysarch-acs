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
#include "include/sys_config.h"
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
  uint32_t status = ACS_STATUS_SKIP, i, reset_status, num_smmus;
  (void)num_pe;

  for (i = 0 ; i < MAX_TEST_SKIP_NUM ; i++) {
      if (g_skip_test_num[i] == ACS_RME_DPT_TEST_NUM_BASE) {
          val_print(ACS_PRINT_TEST, "\n USER Override - Skipping all RME tests \n", 0);
          return ACS_STATUS_SKIP;
      }
  }

  if (g_single_module != SINGLE_MODULE_SENTINEL && g_single_module != ACS_RME_DPT_TEST_NUM_BASE &&
       (g_single_test == SINGLE_MODULE_SENTINEL ||
       (g_single_test - ACS_RME_DPT_TEST_NUM_BASE > 100 ||
          g_single_test - ACS_RME_DPT_TEST_NUM_BASE <= 0))) {
    val_print(ACS_PRINT_TEST, " USER Override - Skipping all RME tests \
                    (running only a single module)\n", 0);
    return ACS_STATUS_SKIP;
  }

  g_curr_module = 1 << DPT_MODULE;

  if (!g_rl_smmu_init)
  {
      num_smmus = val_iovirt_get_smmu_info(SMMU_NUM_CTRL, 0);
      val_rlm_smmu_init(num_smmus);

      g_rl_smmu_init = 1;
  }

  reset_status = val_read_reset_status();

  if (reset_status != RESET_TST12_FLAG &&
      reset_status != RESET_TST31_FLAG &&
      reset_status != RESET_TST2_FLAG &&
      reset_status != RESET_LS_DISBL_FLAG &&
      reset_status != RESET_LS_TEST3_FLAG)
  {
    status = dpt001_entry();
    status |= dpt002_entry();
    status |= dpt003_entry();
    status |= dpt004_entry();
    status |= dpt005_entry();
    status |= dpt006_entry();
    status |= dpt007_entry();
    val_print_test_end(status, "RME-DPT");
  }

  return status;

}
