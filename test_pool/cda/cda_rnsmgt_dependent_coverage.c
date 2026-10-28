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
#include "val/include/val_common.h"
#include "val/include/val_interface.h"
#include "val/include/val_pe.h"

#define TEST_NAME "cda_rnsmgt_dependent_coverage"
#define TEST_DESC "DCM range identification covered by dependent host checks"
#define TEST_RULE "RNSMGT"

static void
payload(void)
{
  uint32_t pe_index;
  uint32_t rshsxk_result;
  uint32_t rjsyps_result;

  pe_index = val_pe_get_index_mpid(val_pe_get_mpid());

  /*
   * RNSMGT defines the host-port capability used by RSHSXK and RJSYPS.
   * Those tests execute before this entry, so their recorded outcomes can be
   * combined without repeating either hardware stimulus.
   */
  rshsxk_result = val_get_module_test_result(
                    CDA_MODULE_ID,
                    CDA_ENTRY_CDA_RSHSXK_D2H_GPC_DPT_ENTRY);
  rjsyps_result = val_get_module_test_result(
                    CDA_MODULE_ID,
                    CDA_ENTRY_CDA_RJSYPS_D2H_SNP_RANGE_ENTRY);

  if ((rshsxk_result == ACS_STATUS_PASS) &&
      (rjsyps_result == ACS_STATUS_PASS))
  {
    val_set_status(pe_index, "PASS", 01);
  }
  else if (((rshsxk_result == ACS_STATUS_PASS) &&
            (rjsyps_result == ACS_STATUS_SKIP)) ||
           ((rshsxk_result == ACS_STATUS_SKIP) &&
            (rjsyps_result == ACS_STATUS_PASS)))
  {
    if (rshsxk_result == ACS_STATUS_PASS)
      val_print(ACS_PRINT_TEST,
                " RNSMGT: partial; RSHSXK passed, RJSYPS skipped",
                0);
    else
      val_print(ACS_PRINT_TEST,
                " RNSMGT: partial; RJSYPS passed, RSHSXK skipped",
                0);

    val_set_status(pe_index, "PASS_PARTIAL", 02);
  }
  else if ((rshsxk_result == ACS_STATUS_SKIP) &&
           (rjsyps_result == ACS_STATUS_SKIP))
  {
    val_print(ACS_PRINT_TEST,
              " RNSMGT: both prerequisite tests were skipped",
              0);
    val_set_status(pe_index, "SKIP", 03);
  }
  else
  {
    if ((rshsxk_result != ACS_STATUS_PASS) &&
        (rshsxk_result != ACS_STATUS_SKIP))
      val_print(ACS_PRINT_ERR,
                " RNSMGT: failed because RSHSXK did not pass",
                0);

    if ((rjsyps_result != ACS_STATUS_PASS) &&
        (rjsyps_result != ACS_STATUS_SKIP))
      val_print(ACS_PRINT_ERR,
                " RNSMGT: failed because RJSYPS did not pass",
                0);

    val_set_status(pe_index, "FAIL", 04);
  }

  /* Keep detailed status values after the user-facing result explanation. */
  val_print(ACS_PRINT_DEBUG, " RNSMGT: RSHSXK result 0x%x", rshsxk_result);
  val_print(ACS_PRINT_DEBUG, " RNSMGT: RJSYPS result 0x%x", rjsyps_result);
}

uint32_t
cda_rnsmgt_dependent_coverage_entry(uint32_t num_pe)
{
  uint32_t status;

  num_pe = 1u;
  status = val_initialize_test(TEST_NAME, TEST_DESC, num_pe, TEST_RULE);

  if (status != ACS_STATUS_SKIP)
    val_run_test_payload(num_pe, payload, 0);

  status = val_check_for_error(num_pe);
  val_report_status(0, "END");
  return status;
}
