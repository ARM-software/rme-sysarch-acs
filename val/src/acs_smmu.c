/** @file
 * Copyright (c) 2022-2024, Arm Limited or its affiliates. All rights reserved.
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

#include "include/rme_acs_smmu.h"
#include "include/rme_acs_iovirt.h"

/**
  @brief  This API reads 32-bit data from a register of an SMMU controller
          specified by index
  @param offset   32-bit register offset
  @param index    when multiple SMMU controllers are present in the system.
                  '0' based index to uniquely identify them

  @return  32-bit data value
**/
uint32_t
val_smmu_read_cfg(uint32_t offset, uint32_t index)
{

  uint64_t ctrl_base = val_smmu_get_info(SMMU_CTRL_BASE, index);

  if (ctrl_base == 0)
      return 0;

  return val_mmio_read(ctrl_base + offset);
}

/**
  @brief   This API executes all the SMMU tests sequentially
           1. Caller       -  Application layer.
           2. Prerequisite -  val_smmu_create_info_table()
  @param   num_pe - the number of PE to run these tests on.
  @return  Consolidated status of all the tests run.
**/
uint32_t
val_smmu_execute_tests(uint32_t num_pe)
{
  uint32_t status = ACS_STATUS_PASS, i;
  uint32_t num_smmu;

  for (i = 0; i < MAX_TEST_SKIP_NUM; i++) {
      if (g_skip_test_num[i] == ACS_SMMU_TEST_NUM_BASE) {
          val_print(ACS_PRINT_TEST, "      USER Override - Skipping all SMMU tests \n", 0);
          return ACS_STATUS_SKIP;
      }
  }

  if (g_single_module != SINGLE_MODULE_SENTINEL && g_single_module != ACS_SMMU_TEST_NUM_BASE &&
       (g_single_test == SINGLE_MODULE_SENTINEL ||
         (g_single_test - ACS_SMMU_TEST_NUM_BASE > 100 ||
          g_single_test - ACS_SMMU_TEST_NUM_BASE < 0))) {
    val_print(ACS_PRINT_TEST, " USER Override - Skipping all SMMU tests \n", 0);
    val_print(ACS_PRINT_TEST, " (Running only a single module)\n", 0);
    return ACS_STATUS_SKIP;
  }

  num_smmu = val_iovirt_get_smmu_info(SMMU_NUM_CTRL, 0);
  if (num_smmu == 0) {
    val_print(ACS_PRINT_WARN, "\n     No SMMU Controller Found, Skipping SMMU tests...\n", 0);
    return ACS_STATUS_SKIP;
  }

  g_curr_module = 1 << SMMU_MODULE;

  status |= i001_entry(num_pe);
  status |= i002_entry();
  val_print_test_end(status, "SMMU");

  return status;
}
