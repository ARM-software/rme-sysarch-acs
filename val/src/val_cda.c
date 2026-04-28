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

/**
  @brief   Execute all CDA compliance tests registered for the suite.

  @param  num_pe  Number of processing elements available for test execution. Unused.

  @return Consolidated status of the executed tests.
**/
uint32_t
val_rme_cda_execute_tests(uint32_t num_pe)
{
  uint32_t status = ACS_STATUS_SKIP;
  (void)num_pe;

  for (uint32_t i = 0; i < g_num_skip; i++)
  {
    if (val_memory_compare(g_skip_test_str[i], CDA_MODULE,
                           val_strnlen(g_skip_test_str[i])) == 0)
    {
      val_print(ACS_PRINT_ALWAYS, "\n USER Override - Skipping all CDA tests \n", 0);
      return ACS_STATUS_SKIP;
    }
  }

  status = val_check_skip_module(CDA_MODULE);
  if (status)
  {
    val_print(ACS_PRINT_ALWAYS, "\n USER Override - Skipping all CDA tests \n", 0);
    return ACS_STATUS_SKIP;
  }

  g_curr_module = 1 << CDA_MODULE_ID;

  val_print(ACS_PRINT_ALWAYS, "\n\n*******************************************************\n", 0);
  status = cda_rjzqcp_reset_transition_entry();
  status |= cda_rkrcwk_host_side_gpc_entry();
  status |= cda_rfzbmw_external_dcm_ide_gate_entry();
  status |= cda_rwwbpm_internal_dcm_run_gate_entry();

  return status;
}
