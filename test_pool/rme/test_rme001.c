/** @file
 * Copyright (c) 2022-2023, Arm Limited or its affiliates. All rights reserved.
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
#include "val/include/rme_acs_pe.h"
#include "val/include/val_interface.h"

#define TEST_NUM   (ACS_RME_TEST_NUM_BASE  +  01)
#define TEST_DESC  "Check for RME extensions                              "
#define TEST_RULE  "PE_07"

#define RME_EXTN_SHIFT 52
#define RME_EXTN_MASK  (0xFULL << RME_EXTN_SHIFT)

/*
 * @brief  The test validates that all the PEs implement the RME extensions.
 * 1. The bit[52] of ID_AA64PFR0_EL1 register is checked.
 * 2. The bit is expected to be set which ensures that RME Extension is implemented.
 */
static
void
payload(void)
{
  uint64_t feat_rme_extnsn = 0;
  uint32_t index = val_pe_get_index_mpid(val_pe_get_mpid());

  feat_rme_extnsn = val_pe_reg_read(ID_AA64PFR0_EL1);
  feat_rme_extnsn = (feat_rme_extnsn & RME_EXTN_MASK) >> RME_EXTN_SHIFT;

  if (feat_rme_extnsn == 0x1)
        val_set_status(index, RESULT_PASS(TEST_NUM, 01));
  else
        val_set_status(index, RESULT_FAIL(TEST_NUM, 01));

  return;

}

uint32_t
rme001_entry(uint32_t num_pe)
{

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

