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
  uint32_t status = ACS_STATUS_SKIP, i;
  uint32_t num_smmu;

  for (i = 0; i < MAX_TEST_SKIP_NUM; i++) {
      if (val_memory_compare(g_skip_test_str[i], SMMU_MODULE, val_strnlen(g_skip_test_str[i])) == 0)
      {
          val_print(ACS_PRINT_ALWAYS, "\n USER Override - Skipping all SMMU tests \n", 0);
          return ACS_STATUS_SKIP;
      }
  }

  if ((val_memory_compare(g_single_module_str, SINGLE_MODULE_SENTINEL_STR,
                          val_strnlen(g_single_module_str)) != 0 &&
       val_memory_compare(g_single_module_str, SMMU_MODULE,
                          val_strnlen(g_single_module_str)) != 0) &&
      (val_memory_compare(g_single_test_str, SINGLE_TEST_SENTINEL_STR,
                          val_strnlen(g_single_test_str)) == 0 ||
       val_memory_compare(g_single_test_str, SMMU_MODULE, val_strnlen(SMMU_MODULE)) != 0)) {
    val_print(ACS_PRINT_ALWAYS, "\n USER Override - Skipping all SMMU tests \n", 0);
    val_print(ACS_PRINT_ALWAYS, " (Running only a single module)\n", 0);
    return ACS_STATUS_SKIP;
  }

  num_smmu = val_iovirt_get_smmu_info(SMMU_NUM_CTRL, 0);
  if (num_smmu == 0) {
    val_print(ACS_PRINT_WARN, " No SMMU Controller Found, Skipping SMMU tests...", 0);
    return ACS_STATUS_SKIP;
  }

  g_curr_module = 1 << SMMU_MODULE_ID;

  status |= smmu_implements_rme_entry(num_pe);
  status |= smmu_responds_to_gpt_tlb_entry();

  return status;
}
