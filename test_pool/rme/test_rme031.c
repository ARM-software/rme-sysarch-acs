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

#define TEST_NUM   (ACS_RME_TEST_NUM_BASE + 31)
#define TEST_DESC  "To Verify that RME system reset propagates to all application PEs"
#define TEST_RULE  "SYS_RST_03"

#define WRITE_VAL_SCTLR_EL1 0x7ULL
#define WRITE_SCTLR_EL1_MASK 0x7ULL

void
write_reg(void)
{
  uint32_t index = val_pe_get_index_mpid(val_pe_get_mpid());
  uint64_t data;

  /* Write value 1 to the first three bits of SCTLR_EL1*/
  data = AA64ReadSctlr1();
  data |= WRITE_VAL_SCTLR_EL1;
  AA64WriteSctlr1(data);
  //Status is set here to indicate the write completion for the main PE
  val_set_status(index, RESULT_PASS(TEST_NUM, 01));
  return;
}

void
check_reg_val(void)
{
  uint32_t index = val_pe_get_index_mpid(val_pe_get_mpid());
  uint64_t rd_data;

  /* Read the first Three bits of SCTLR_EL1  after reset */
  rd_data = AA64ReadSctlr1();
  rd_data &= WRITE_SCTLR_EL1_MASK;

  if (WRITE_VAL_SCTLR_EL1 == rd_data)
    val_set_status(index, RESULT_FAIL(TEST_NUM, 01));

  else
    val_set_status(index, RESULT_PASS(TEST_NUM, 01));

  return;
}

/*
 * @brief  The test validates that RME system reset propagates to all application PEs.
 * 1. Write the value 1 to first three bits of SCTLR_EL1 register.
 * 2. And aldo write 0x1234567890ABCDEF to GPRs from x19-x29 using asm function and
 *    execute reset.
 * 3. Check if GPRs have retained their value or have they been scrubbed and
 *    read the SCTLR_EL1 register and observe that the value is reset to 0.
 */
static
void payload(uint32_t num_pe)
{

  uint32_t index = val_pe_get_index_mpid(val_pe_get_mpid()), timeout;
  uint32_t check_status;

  if (val_read_reset_status() == RESET_TST31_FLAG)
          goto reset_done;

  /* Write to SCTLR_EL1 from the current PE */
  write_reg();

  /* Execute the same write operation from the rest of the PEs */
  for (int i = 0; i < num_pe; i++) {
    if (i != index) {
          timeout = TIMEOUT_LARGE;
          val_execute_on_pe(i, write_reg, 0);
          while ((--timeout) && (IS_RESULT_PENDING(val_get_status(i))))
                  ;

          if (timeout == 0) {
              val_print(ACS_PRINT_ERR, "\n       **Timed out** for PE index = %d", i);
              val_set_status(i, RESULT_FAIL(TEST_NUM, 02));
              return;
          }
    }
  }
  val_write_reset_status(RESET_TST31_FLAG);
  val_save_global_test_data();
  write_gpr_and_reset();

reset_done:
  val_restore_global_test_data();
  val_print(ACS_PRINT_INFO, "\n  After system reset", 0);

  //GPR check
  check_status = check_gpr_after_reset();

  if (check_status) {
    val_print(ACS_PRINT_ERR, "\n  The GPRs have not been scrubbed after the reset ", 0);
    val_set_status(index, RESULT_FAIL(TEST_NUM, 01));
    return;
  }

  /* Read the SCTLR_EL1 register after reset from the current PE */
  check_reg_val();
  /* Execute the same read operation from the rest of the PEs */
  for (int i = 0; i < num_pe; i++) {
    if (i != index) {
          timeout = TIMEOUT_LARGE;
          val_execute_on_pe(i, check_reg_val, 0);
	  while ((--timeout) && (IS_RESULT_PENDING(val_get_status(i))))
                  ;

          if (timeout == 0) {
              val_print(ACS_PRINT_ERR, "\n       **Timed out** for PE index = %d", i);
              val_set_status(i, RESULT_FAIL(TEST_NUM, 02));
              return;
          }
    }
  }
  return;
}

uint32_t
rme031_entry(uint32_t num_pe)
{

  uint32_t status = ACS_STATUS_FAIL;

  status = val_initialize_test(TEST_NUM, TEST_DESC, num_pe, TEST_RULE);

  if (status != ACS_STATUS_SKIP)
    payload(num_pe);

  status = val_check_for_error(TEST_NUM, num_pe, TEST_RULE);

  val_report_status(0, RME_ACS_END(TEST_NUM), TEST_RULE);

  return status;
}

