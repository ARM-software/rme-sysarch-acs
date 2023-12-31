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

#include "val/include/rme_acs_val.h"
#include "val/include/rme_acs_pe.h"
#include "val/include/rme_acs_common.h"

#include "val/include/rme_test_entry.h"
#include "val/include/val_interface.h"
#include "val/include/rme_acs_el32.h"
#include "val/include/sys_config.h"
#include "val/include/mem_interface.h"

#define TEST_NUM   (ACS_RME_TEST_NUM_BASE + 2)
#define TEST_DESC  "Check if GPRs are scrubbed after reset in realm state  "
#define TEST_RULE  "SYS_RST_06"

/*
 * @brief  The test validates that the GPRs are scrubbed after reset in realm state.
 * 1. Select the Realm Security State of EL2, by writing to SCR_EL3.NSE and NS bit.
 * 2. Write 0x1234567890ABCDEF to GPRs from x19-x29 using asm function and execute reset.
 * 3. Check if GPRs have retained their value or have they been scrubbed!
 */
static
void payload(void)
{

  uint32_t index = val_pe_get_index_mpid(val_pe_get_mpid());
  uint32_t check_status;

  if (val_read_reset_status() == RESET_TST2_FLAG)
          goto reset_done;

  //Change the security state to Realm from NS by writing to SCR_EL#.NS and NSE bits
  val_change_security_state_el3(REALM_STATE);

  //Write to the GPRs from x19-x29 and execute reset
  val_write_reset_status(RESET_TST2_FLAG);
  val_save_global_test_data();
  write_gpr_and_reset();

reset_done:
  //Check the status of the GPR comparision which is already completed right after the reset
  val_restore_global_test_data();
  check_status = check_gpr_after_reset();
  if (check_status) {
    val_print(ACS_PRINT_ERR, "\n  The GPRs have not been scrubbed after the reset ", 0);
    val_set_status(index, RESULT_FAIL(TEST_NUM, 01));
    return;
  }
  //Otherwise PASS
  val_set_status(index, RESULT_PASS(TEST_NUM, 01));
  return;
}

uint32_t
rme002_entry(void)
{

  uint32_t num_pe = 1;
  uint32_t status = ACS_STATUS_FAIL;

  status = val_initialize_test(TEST_NUM, TEST_DESC, num_pe, TEST_RULE);

  if (status != ACS_STATUS_SKIP)
      val_run_test_payload(TEST_NUM, num_pe, payload, 0);

  status = val_check_for_error(TEST_NUM, num_pe, TEST_RULE);

  val_report_status(0, RME_ACS_END(TEST_NUM), TEST_RULE);

  return status;
}

