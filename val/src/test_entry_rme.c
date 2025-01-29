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
#include "include/sys_config.h"


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
  uint32_t status, i, reset_status;

  for (i = 0 ; i < MAX_TEST_SKIP_NUM ; i++) {
      if (g_skip_test_num[i] == ACS_RME_TEST_NUM_BASE) {
          val_print(ACS_PRINT_TEST, "\n USER Override - Skipping all RME tests \n", 0);
          return ACS_STATUS_SKIP;
      }
  }

  if (g_single_module != SINGLE_MODULE_SENTINEL && g_single_module != ACS_RME_TEST_NUM_BASE &&
       (g_single_test == SINGLE_MODULE_SENTINEL ||
       (g_single_test - ACS_RME_TEST_NUM_BASE > 100 ||
          g_single_test - ACS_RME_TEST_NUM_BASE <= 0))) {
    val_print(ACS_PRINT_TEST, " USER Override - Skipping all RME tests \
                    (running only a single module)\n", 0);
    return ACS_STATUS_SKIP;
  }


  reset_status = val_read_reset_status();
  val_print(ACS_PRINT_TEST, "      reset_status = %lx\n", reset_status);
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

  g_curr_module = 1 << RME_MODULE;

  /* RME-ACS tests */
  status = rme001_entry(num_pe);
  status |= rme002_entry();
reset_done_2:
  status = rme002_entry();
  status |= rme003_entry(num_pe);
  status |= rme004_entry();
  status |= rme005_entry();
  status |= rme006_entry();
  status |= rme007_entry();
  status |= rme008_entry(num_pe);
  status |= rme009_entry();
  status |= rme010_entry();
  status |= rme011_entry();
  status |= rme012_entry();
reset_done_12:
  status = rme012_entry();
  status |= rme013_entry();
  status |= rme014_entry();
  status |= rme015_entry();
  status |= rme016_entry();
  status |= rme017_entry();
  status |= rme018_entry(2);
  status |= rme019_entry();
  status |= rme020_entry();
  status |= rme021_entry();
  status |= rme022_entry();
  status |= rme023_entry();
  status |= rme024_entry();
  status |= rme025_entry();
  status |= rme026_entry();
  status |= rme027_entry();
  status |= rme028_entry();
  status |= rme029_entry();
  status |= rme030_entry();
  status |= rme031_entry(num_pe);
reset_done_31:
  status = rme031_entry(num_pe);
  status |= rme032_entry();
reset_done_32:
  status = rme032_entry();

  val_print_test_end(status, "RME");
reset_done_ls:
  return status;

}

