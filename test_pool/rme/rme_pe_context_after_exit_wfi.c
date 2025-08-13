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

#include "val/include/rme_acs_val.h"
#include "val/include/val_interface.h"

#include "val/include/rme_acs_timer.h"
#include "val/include/rme_acs_pe.h"
#include "val/include/rme_acs_el32.h"
#include "val/include/rme_test_entry.h"

#define TEST_NAME  "rme_pe_context_after_exit_wfi"
#define TEST_DESC  "PE context preserve after exit from low pow state WFI  "
#define TEST_RULE  "RMLJVR"

static int irq_received;
static uint32_t intid;

static
void
isr()
{
  val_timer_set_phy_el1(0);
  irq_received = 1;
  val_print(ACS_PRINT_TEST, " Received el1_phy interrupt   ", 0);
  val_gic_end_of_interrupt(intid);
}

/*
 * @brief  The test validates that the PE context is preserved after
 *         an exit from the low power state from WFI.
 * 1. Install the ISR for PE timer interrupt ID.
 * 2. Save all the RME related PE registers before going to low power mode.
 * 3. Start the PE timer that is set to pe_timer_ticks.
 * 4. Initiate the low power state entry from WFI.
 * 5. PE interrupt wakes up the PE before the timeout and is handled.
 * 6. The same PE registers are checked against the saved values.
 * 7. The test expects the values to be similar and if so, test will PASS, otherwise will FAIL.
 */
static
void
payload()
{
  uint32_t index = val_pe_get_index_mpid(val_pe_get_mpid());
  uint64_t pe_timer_ticks = val_get_counter_frequency();
  uint32_t reg_list_chck[] = {GPCCR_EL3_MSD, GPTBR_EL3_MSD, TCR_EL3_MSD, TTBR_EL3_MSD,
                              SCR_EL3_MSD, SCTLR_EL2_MSD, SCTLR_EL3_MSD};
  irq_received = 0;

  intid = val_timer_get_info(TIMER_INFO_PHY_EL1_INTID, 0);
  val_gic_install_isr(intid, isr);

  shared_data->reg_info.num_regs = 7;
  for (uint32_t reg_num = 0; reg_num < shared_data->reg_info.num_regs; ++reg_num)
  {
    val_reg_update_shared_struct_msd(reg_list_chck[reg_num], reg_num);
  }
  /* Save all the registers before going to low power mode */
  if (val_read_pe_regs_bfr_low_pwr_el3())
  {
    val_print(ACS_PRINT_ERR, "\n    Saving the PE Regsiter failed before low power state", 0);
    val_set_status(index, "FAIL", 1);
    return;
  }

  /* Start EL1 PHY timer and initiate low power state entry for PE(WFI) */
  val_print(ACS_PRINT_TEST, " Putting the PE into low power state using WFI", 0);
  val_timer_set_phy_el1(pe_timer_ticks);
  val_power_enter_semantic(RME_POWER_SEM_B);

  //PE wakes up and starts executing here
  /* Read the same registers again and compare them with the saved ones to see
   * if they've retained their original value after an exit from low power state
   */
  shared_data->generic_flag = CLEAR;
  val_print(ACS_PRINT_TEST, " Checking the PE registers after low power state", 0);
  if (val_cmpr_pe_regs_aftr_low_pwr_el3())
  {
    val_print(ACS_PRINT_ERR, "\n    Comparision failed for PE Regsiters after low power state", 0);
    val_set_status(index, "FAIL", 2);
    return;
  }

  /* Check whether pe timer interrupt is recieved or not */
  if (irq_received == 0) {
      val_print(ACS_PRINT_ERR, " PE timer interrupt not generated", 0);
      val_timer_set_phy_el1(0);
      val_gic_clear_interrupt(intid);
      val_set_status(index, "FAIL", 3);
      return;
  }

  /* If compared data in the register list is equal, shared_data->generic_flag
  will be CLEARed in val_cmpr_pe_regs_aftr_low_pwr_el3 operation,
  making the test PASS otherwise FAIL */
  if (shared_data->generic_flag)
    val_set_status(index, "FAIL", 2);

  else
    val_set_status(index, "PASS", 2);
}

uint32_t
rme_pe_context_after_exit_wfi_entry(void)
{

  uint32_t status = ACS_STATUS_FAIL;

  uint32_t num_pe = 1;  //This Timer test is run on single processor

  status = val_initialize_test(TEST_NAME, TEST_DESC, num_pe, TEST_RULE);
  if (status != ACS_STATUS_SKIP)
      val_run_test_payload(num_pe, payload, 0);

  /* get the result from all PE and check for failure */
  status = val_check_for_error(num_pe);

  val_report_status(0, "END");
  return status;

}

