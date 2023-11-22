/** @file
 * Copyright (c) 2023, Arm Limited or its affiliates. All rights reserved.
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
#include "include/rme_legacy.h"

#include "include/val_interface.h"
#include "include/rme_acs_el32.h"
#include "include/platform_overrride_fvp.h"
#include "include/sys_config.h"
#include "include/mem_interface.h"

/**
  @brief   This API will execute all Legacy system related tests designated.
           1. Caller       -  Application layer.
           2. Prerequisite -  val_pe_create_info_table, val_allocate_shared_mem
  @param   num_pe - the number of PE to run these tests on.
  @return  Consolidated status of all the tests run.
**/
uint32_t
val_legacy_execute_tests(uint32_t num_pe)
{
  uint32_t status, i, reset_status;
  uint64_t sp_val;

  for (i = 0 ; i < MAX_TEST_SKIP_NUM ; i++) {
      if (g_skip_test_num[i] == ACS_LEGACY_TEST_NUM_BASE) {
          val_print(ACS_PRINT_TEST, "\n USER Override - Skipping all Legacy tests \n", 0);
          return ACS_STATUS_SKIP;
      }
  }

  if (g_single_module != SINGLE_MODULE_SENTINEL && g_single_module != ACS_LEGACY_TEST_NUM_BASE) {
    val_print(ACS_PRINT_TEST, " USER Override - Skipping all Legacy system related tests \
                    (running only a single module)\n", 0);
    return ACS_STATUS_SKIP;
  }
  if (!IS_LEGACY_TZ_ENABLED) {
    val_print(ACS_PRINT_TEST, " Skipping Legacy system tests since the system doesn't \
support the feature \n", 0);
    return ACS_STATUS_SKIP;
  }

  if (g_single_module != SINGLE_MODULE_SENTINEL && g_single_module != ACS_RME_TEST_NUM_BASE &&
       (g_single_test == SINGLE_MODULE_SENTINEL ||
       (g_single_test - ACS_RME_TEST_NUM_BASE > 100 ||
          g_single_test - ACS_RME_TEST_NUM_BASE < 0))) {
    val_print(ACS_PRINT_TEST, " RME module is skipped\n", 0);
    val_print(ACS_PRINT_TEST, " Installing the handler for legacy tests\n", 0);
    //struct_sh_data *shared_data = (struct_sh_data *)SHARED_ADDRESS;
    sp_val = AA64ReadSP_EL0();
    val_add_mmu_entry_el3(SHARED_ADDRESS, SHARED_ADDRESS, NONSECURE_PAS);
    val_add_mmu_entry_el3(sp_val, sp_val, NONSECURE_PAS);
    val_rme_install_handler_el3();
    reset_status = val_read_reset_status();

    if (reset_status == RESET_LS_DISBL_FLAG)
            goto reset_done_ls_dis;
    else if (reset_status == RESET_LS_TEST3_FLAG)
            goto reset_done_ls3;
  }

  reset_status = val_read_reset_status();
  if (reset_status == RESET_LS_TEST3_FLAG)
          goto reset_done_ls3;

  else if (reset_status == RESET_LS_DISBL_FLAG)
          goto reset_done_ls_dis;

  status = ls001_entry();
  status |= ls002_entry();

  status |= ls003_entry();
reset_done_ls3:
  status = ls003_entry();

  //Disablie the legacy tie-off before moving on to the next tests
  val_prog_legacy_tz(CLEAR);
  val_write_reset_status(RESET_LS_DISBL_FLAG);
  val_system_reset();

reset_done_ls_dis:
  status |= ls004_entry();

  val_print_test_end(status, "Legacy System");

  return status;

}
