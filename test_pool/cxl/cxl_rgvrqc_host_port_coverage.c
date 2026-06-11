/** @file
 * Copyright (c) 2025-2026, Arm Limited or its affiliates. All rights reserved.
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

#include "val/include/val.h"
#include "val/include/val_interface.h"

#include "cxl_rgvrqc_host_port_coverage.h"

#define TEST_NAME "cxl_rgvrqc_host_port_coverage"
#define TEST_DESC "Verify RME-CDA DVSEC register configuration          "
#define TEST_RULE "RGVRQC"

static void
payload(void)
{
  uint32_t pe_index;
  uint32_t ret;
  uint32_t table_entries;

  pe_index = val_pe_get_index_mpid(val_pe_get_mpid());

  table_entries = (uint32_t)(sizeof(cxl_rgvrqc_bf_info_table) /
                             sizeof(cxl_rgvrqc_bf_info_table[0]));
  /* Determine how many DVSEC bitfield descriptors must be validated. */
  ret = val_pcie_register_bitfields_check((void *)&cxl_rgvrqc_bf_info_table,
                                          table_entries,
                                          VAL_DVSEC_SELECT_RMECDA);
  /* Validate the host port RME-CDA DVSEC register programming. */

  if (ret == ACS_STATUS_SKIP)
  {
      val_print(ACS_PRINT_TEST,
                " No CXL host port RME-CDA DVSEC instances discovered, skipping", 0);
      val_set_status(pe_index, "SKIP", 01);
  }
  else if (ret != 0u)
    val_set_status(pe_index, "FAIL", 01);
  else
    val_set_status(pe_index, "PASS", 01);
}

uint32_t
cxl_rgvrqc_host_port_coverage_entry(uint32_t num_pe)
{
  num_pe = 1;
  uint32_t status = ACS_STATUS_FAIL;

  status = val_initialize_test(TEST_NAME, TEST_DESC, num_pe, TEST_RULE);

  if (status != ACS_STATUS_SKIP)
    /* Execute the coverage payload when the test is active for this platform. */
    val_run_test_payload(num_pe, payload, 0);

  status = val_check_for_error(num_pe);

  val_report_status(0, "END");

  return status;
}
