/** @file
 * Copyright (c) 2023-2025, Arm Limited or its affiliates. All rights reserved.
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

#include "include/val.h"
#include "include/val_common.h"
#include "include/val_legacy.h"

#include "include/val_interface.h"
#include "include/val_el32.h"
#include "include/val_mem_interface.h"

ROOT_REGSTR_TABLE *g_root_reg_info_table;

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
  uint32_t status = ACS_STATUS_SKIP, i, reset_status;
  (void) num_pe;

  for (i = 0 ; i < g_num_skip ; i++) {
      if (val_memory_compare((char8_t *)g_skip_test_str[i], LEGACY_MODULE,
          val_strnlen(g_skip_test_str[i])) == 0) {
          val_print(ACS_PRINT_ALWAYS, "\n USER Override - Skipping all Legacy tests \n", 0);
          return ACS_STATUS_SKIP;
      }
  }

  /* Check if there are any tests to be executed in current module with user override options*/
  status = val_check_skip_module(LEGACY_MODULE);
  if (status) {
    val_print(ACS_PRINT_ALWAYS, "\n USER Override - Skipping all Legacy system tests \n", 0);
    return ACS_STATUS_SKIP;
  }
  if (!pal_is_legacy_tz_enabled()) {
    val_print(ACS_PRINT_ALWAYS, "\n******************************************************* \n", 0);
    val_print(ACS_PRINT_ALWAYS, "\n Skipping Legacy system tests since the system doesn't \
support the feature \n", 0);
    val_print(ACS_PRINT_ALWAYS, "\n******************************************************* \n", 0);
    return ACS_STATUS_SKIP;
  }

  g_curr_module = 1 << LEGACY_MODULE_ID;

  reset_status = val_read_reset_status();
  if (reset_status == RESET_LS_TEST3_FLAG)
          goto reset_done_ls3;

  else if (reset_status == RESET_LS_DISBL_FLAG)
          goto reset_done_ls_dis;

  val_print(ACS_PRINT_ALWAYS, "\n\n******************************************************* \n", 0);
  status = legacy_tz_support_check_entry();
  status |= legacy_tz_en_drives_root_to_secure_entry();

  status |= legacy_tz_enable_before_resetv_entry();
reset_done_ls3:
  status = legacy_tz_enable_before_resetv_entry();

  //Disablie the legacy tie-off before moving on to the next tests
  if (val_prog_legacy_tz(CLEAR))
  {
    val_print(ACS_PRINT_ERR, "\n  Programming LEGACY_TZ_EN failed", 0);
    return ACS_STATUS_ERR;
  }
  val_write_reset_status(RESET_LS_DISBL_FLAG);
  val_system_reset();

reset_done_ls_dis:
  status |= legacy_tz_enable_after_reset_entry();

  return status;

}

/**
  @brief   This API will populate the ROOT_REGSTR_TABLE from PAL.
           1. Caller       -  Test.
  @param   root_registers_cfg - Pointer to the structure ROOT_REGSTR_TABLE.
  @return  NULL
**/
void val_root_register_create_info_table(uint64_t *root_registers_cfg)
{
  g_root_reg_info_table = (ROOT_REGSTR_TABLE *)root_registers_cfg;

  pal_root_register_create_info_table(g_root_reg_info_table);
}

ROOT_REGSTR_TABLE *val_root_reg_info_table(void)
{
  return g_root_reg_info_table;
}
