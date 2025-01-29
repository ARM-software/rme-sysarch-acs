/** @file
 * Copyright (c) 2023, 2025, Arm Limited or its affiliates. All rights reserved.
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

#define TEST_NUM   (ACS_RME_TEST_NUM_BASE + 24)
#define TEST_DESC  "PE Context preserve check after exit from PE suspend   "
#define TEST_RULE  "PE_15"

static uint32_t intid;
static uint64_t cnt_base_n;
static int irq_received;

static
void
isr()
{
  val_timer_disable_system_timer((addr_t)cnt_base_n);
  val_gic_end_of_interrupt(intid);
  irq_received = 1;
  val_print(ACS_PRINT_INFO, "\n       System timer interrupt received", 0);
}

/*
 * @brief  The test validates that the PE context is preserved after
 *         an exit from the low power state from PE suspension.
 * 1. Install the ISR for System timer interrupt ID.
 * 2. Save all the RME related PE registers before going to low power mode.
 * 3. Start the system timer that is set to sys_timer_ticks.
 * 4. Initiate the low power state entry by suspending the PE using SMC call with PSCI_CPU_SUSPEND.
 * 5. PE interrupt wakes up the PE before the timeout and is handled.
 * 6. The same PE registers are checked against the saved values.
 * 7. The test expects the values to be similar and if so, test will PASS, otherwise will FAIL.
 */
static
void
payload()
{
  uint32_t index = val_pe_get_index_mpid(val_pe_get_mpid());
  uint64_t sys_timer_ticks = val_get_counter_frequency() * 1;
  uint32_t ns_timer = 0;
  uint64_t timer_num;
  int32_t status;
  uint32_t reg_list_chck[] = {GPCCR_EL3_MSD, GPTBR_EL3_MSD, TCR_EL3_MSD, TTBR_EL3_MSD,
                              SCR_EL3_MSD, SCTLR_EL2_MSD, SCTLR_EL3_MSD};

  timer_num = val_timer_get_info(TIMER_INFO_NUM_PLATFORM_TIMERS, 0);

  while (timer_num--) {
      if (val_timer_get_info(TIMER_INFO_IS_PLATFORM_TIMER_SECURE, timer_num))
        continue;
      else{
        ns_timer++;
        break;
      }
  }

  if (!ns_timer) {
      val_print(ACS_PRINT_DEBUG, "\n       No non-secure systimer implemented", 0);
      val_set_status(index, RESULT_SKIP(TEST_NUM, 1));
      return;
  }

  irq_received = 0;

  intid = val_timer_get_info(TIMER_INFO_SYS_INTID, timer_num);
  val_gic_install_isr(intid, isr);

  /* Develop the register list to be checked */
  shared_data->reg_info.num_regs = 7;
  for (uint32_t reg_num = 0; reg_num < shared_data->reg_info.num_regs; ++reg_num)
  {
    val_reg_update_shared_struct_msd(reg_list_chck[reg_num], reg_num);
  }
  /* Save all the registers before going to low power mode */
  val_read_pe_regs_bfr_low_pwr_el3();

  /* Start Sys timer*/
  cnt_base_n = val_timer_get_info(TIMER_INFO_SYS_CNT_BASE_N, timer_num);
  val_timer_set_system_timer((addr_t)cnt_base_n, sys_timer_ticks);

  /* Put current PE in to low power mode*/
  status = val_suspend_pe(0, 0);
  if (status) {
      val_print(ACS_PRINT_DEBUG, "\n       Not able to suspend the PE : %d", status);
      val_timer_disable_system_timer((addr_t)cnt_base_n);
      val_gic_clear_interrupt(intid);
      val_set_status(index, RESULT_SKIP(TEST_NUM, 2));
      return;
  }

  //PE wakes up and starts executing here
  /* Read the same registers again and compare them with the saved ones to see
   * if they've retained their original value after an exit from low power state
   */
  shared_data->generic_flag = CLEAR;
  val_cmpr_pe_regs_aftr_low_pwr_el3();

  if (irq_received == 0) {
      val_print(ACS_PRINT_ERR, "\n       System timer interrupt not generated", 0);
      val_timer_disable_system_timer((addr_t)cnt_base_n);
      val_gic_clear_interrupt(intid);
      val_timer_set_phy_el1(0);
      val_set_status(index, RESULT_FAIL(TEST_NUM, 1));
      return;
  }

  /* If compared data in the register list is equal, shared_data->generic_flag
  will be CLEARed in val_cmpr_pe_regs_aftr_low_pwr_el3 operation,
  making the test PASS otherwise FAIL */
  if (shared_data->generic_flag)
    val_set_status(index, RESULT_FAIL(TEST_NUM, 2));

  else
    val_set_status(index, RESULT_PASS(TEST_NUM, 2));
}

uint32_t
rme024_entry(void)
{

  uint32_t status = ACS_STATUS_FAIL;

  uint32_t num_pe = 1;  //This Timer test is run on single processor

  status = val_initialize_test(TEST_NUM, TEST_DESC, num_pe, TEST_RULE);
  if (status != ACS_STATUS_SKIP)
      val_run_test_payload(TEST_NUM, num_pe, payload, 0);

  /* get the result from all PE and check for failure */
  status = val_check_for_error(TEST_NUM, num_pe, TEST_RULE);

  val_report_status(0, RME_ACS_END(TEST_NUM), TEST_RULE);
  return status;

}
