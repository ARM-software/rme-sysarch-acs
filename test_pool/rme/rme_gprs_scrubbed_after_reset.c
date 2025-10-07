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

#include "val/include/val.h"
#include "val/include/val_pe.h"
#include "val/include/val_common.h"

#include "val/include/val_test_entry.h"
#include "val/include/val_interface.h"
#include "val/include/val_el32.h"
#include "val/include/val_mem_interface.h"

#define TEST_NAME  "rme_gprs_scrubbed_after_reset"
#define TEST_DESC  "Check if GPRs are scrubbed after reset in realm state  "
#define TEST_RULE  "RNULL"

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
  if (val_change_security_state_el3(REALM_STATE))
  {
    val_print(ACS_PRINT_ERR,
      "\n    Security State change failure to 0x%lx State", (uint64_t)REALM_STATE);
    val_set_status(index, "FAIL", 01);
    return;
  }

  //Write to the GPRs from x19-x29 and execute reset
  val_write_reset_status(RESET_TST2_FLAG);
  val_save_global_test_data();
  write_gpr_and_reset();

reset_done:
  //Check the status of the GPR comparision which is already completed right after the reset
  val_restore_global_test_data();
  check_status = check_gpr_after_reset();
  if (check_status) {
    val_print(ACS_PRINT_ERR, " The GPRs have not been scrubbed after the reset ", 0);
    val_set_status(index, "FAIL", 01);
    return;
  }
  //Otherwise PASS
  val_set_status(index, "PASS", 01);
  return;
}

uint32_t
rme_gprs_scrubbed_after_reset_entry(void)
{

  uint32_t num_pe = 1;
  uint32_t status = ACS_STATUS_FAIL;

  status = val_initialize_test(TEST_NAME, TEST_DESC, num_pe, TEST_RULE);

  if (status != ACS_STATUS_SKIP)
      val_run_test_payload(num_pe, payload, 0);

  status = val_check_for_error(num_pe);

  val_report_status(0, "END");

  return status;
}

