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

#include "val/include/rme_acs_val.h"
#include "val/include/val_interface.h"

#include "val/include/rme_acs_el32.h"
#include "val/include/rme_acs_pcie.h"
#include "val/include/rme_acs_memory.h"
#include "val/include/rme_acs_pcie_enumeration.h"
#include "val/include/rme_acs_exerciser.h"
#include "val/include/pal_interface.h"
#include "val/include/rme_acs_pe.h"
#include "val/include/rme_acs_da.h"
#include "val/include/sys_config.h"

#define TEST_NUM (ACS_RME_DA_TEST_NUM_BASE  +  19)
#define TEST_DESC "Check RP RMSD Write-protect & full-protect properties"
#define TEST_RULE "RXHMDQ, RNXJKQ"

static
void
payload(void)
{
  uint32_t pe_index;
  uint32_t ret = 1;
  uint32_t index;
  uint32_t table_entries;
  uint32_t test_skip = 1;
  uint32_t test_fail = 0;

  REGISTER_INFO_TABLE *register_tbl_ptr;

  pe_index = val_pe_get_index_mpid(val_pe_get_mpid());

  table_entries = val_register_get_num_entries();
  register_tbl_ptr = val_register_table_ptr();
  val_print(ACS_PRINT_DEBUG, "\n table entries: %d", table_entries);

  for (index = 0; index < table_entries; index++)
  {
      test_skip = 0;
      ret = val_pcie_rp_sec_prpty_check((void *)register_tbl_ptr);
      if (ret)
          test_fail++;

      register_tbl_ptr++;
  }

  if (test_skip)
      val_set_status(pe_index, RESULT_SKIP(TEST_NUM, 01));
  else if (test_fail)
      val_set_status(pe_index, RESULT_FAIL(TEST_NUM, 01));
  else
      val_set_status(pe_index, RESULT_PASS(TEST_NUM, 01));
}

uint32_t
da019_entry(void)
{

  uint32_t num_pe = 1;
  uint32_t status = ACS_STATUS_FAIL;  //default value

  status = val_initialize_test(TEST_NUM, TEST_DESC, num_pe, TEST_RULE);

  /* This check is when user is forcing us to skip this test */
  if (status != ACS_STATUS_SKIP)
      val_run_test_payload(TEST_NUM, num_pe, payload, 0);

  /* get the result from all PE and check for failure */
  status = val_check_for_error(TEST_NUM, num_pe, TEST_RULE);

  val_report_status(0, RME_ACS_END(TEST_NUM), TEST_RULE);

  return status;
}
