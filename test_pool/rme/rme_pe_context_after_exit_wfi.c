/** @file
 * Copyright (c) 2023-2026, Arm Limited or its affiliates. All rights reserved.
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

#include "val/include/val_timer.h"
#include "val/include/val_pe.h"
#include "val/include/val_el32.h"
#include "val/include/val_test_entry.h"

#define TEST_NAME  "rme_pe_context_after_exit_wfi"
#define TEST_DESC  "PE context preserved after exit from low power state  "
#define TEST_RULE  "RMLJVR"

#define NUM_MSD_CONTEXT_REGS 7

/* Keep ISR state separate so a late WFI interrupt cannot satisfy the suspend check. */
static uint32_t wfi_intid;
static uint32_t suspend_intid;
static uint64_t cnt_base_n;

static uint32_t wfi_irq_received;
static uint32_t suspend_irq_received;

/*
 * @brief  Check selected PE register preservation across WFI and CPU standby.
 * 1. Save seven selected RME-related PE registers before entering low power state.
 * 2. Enter low power using WFI and wake using the PE physical timer interrupt.
 * 3. Check that the saved PE register values are preserved after WFI exit.
 * 4. If a non-secure system timer and PSCI suspend are supported, repeat the
 *    same context preservation check across PSCI_CPU_SUSPEND.
 * This provides partial RMLJVR coverage: it does not establish system-level
 * low-power entry, preservation of all MSD state, or reset on MSD state loss.
 */

static
void
wfi_isr(void)
{
  val_timer_set_phy_el1(0);
  wfi_irq_received = 1;
  val_print(ACS_PRINT_TEST, " Received el1_phy interrupt", 0);
  val_gic_end_of_interrupt(wfi_intid);
}

static
void
suspend_isr(void)
{
  val_timer_disable_system_timer((addr_t)cnt_base_n);
  suspend_irq_received = 1;
  val_print(ACS_PRINT_TEST, " System timer interrupt received", 0);
  val_gic_end_of_interrupt(suspend_intid);
}

static
uint32_t
save_msd_context(void)
{
  uint32_t reg_list_chck[NUM_MSD_CONTEXT_REGS] = {
      GPCCR_EL3_MSD, GPTBR_EL3_MSD, TCR_EL3_MSD, TTBR_EL3_MSD,
      SCR_EL3_MSD, SCTLR_EL2_MSD, SCTLR_EL3_MSD
  };

  shared_data->reg_info.num_regs = NUM_MSD_CONTEXT_REGS;
  for (uint32_t reg_num = 0; reg_num < shared_data->reg_info.num_regs; ++reg_num)
  {
    val_reg_update_shared_struct_msd(reg_list_chck[reg_num], reg_num);
  }

  if (val_read_pe_regs_bfr_low_pwr_el3())
  {
    val_print(ACS_PRINT_ERR, " Saving PE registers before low power failed", 0);
    return ACS_STATUS_FAIL;
  }

  return ACS_STATUS_PASS;
}

static
uint32_t
check_msd_context(void)
{
  /* EL3 sets this flag on mismatch; it does not clear it on a successful comparison. */
  shared_data->generic_flag = CLEAR;
  val_print(ACS_PRINT_TEST, " Checking PE registers after low power state", 0);

  if (val_cmpr_pe_regs_aftr_low_pwr_el3())
  {
    val_print(ACS_PRINT_ERR, " Comparison failed for PE registers after low power", 0);
    return ACS_STATUS_FAIL;
  }

  if (shared_data->generic_flag)
      return ACS_STATUS_FAIL;

  return ACS_STATUS_PASS;
}

static
uint32_t
run_wfi_context_check(void)
{
  uint64_t pe_timer_ticks = val_get_counter_frequency();
  uint32_t status = ACS_STATUS_FAIL;

  /* Save before installing the ISR so a save failure leaves no new handler behind. */
  if (save_msd_context())
      return ACS_STATUS_FAIL;

  wfi_intid = val_timer_get_info(TIMER_INFO_PHY_EL1_INTID, 0);
  wfi_irq_received = 0;
  if (val_gic_install_isr(wfi_intid, wfi_isr))
  {
    val_print(ACS_PRINT_ERR, " GIC install handler failed", 0);
    return ACS_STATUS_FAIL;
  }

  val_print(ACS_PRINT_TEST, " Putting PE into low power state using WFI", 0);
  val_timer_set_phy_el1(pe_timer_ticks);
  val_power_enter_semantic(RME_POWER_SEM_B);

  if (check_msd_context())
      goto cleanup;

  if (wfi_irq_received == 0)
  {
    val_print(ACS_PRINT_ERR, " PE timer interrupt not generated", 0);
    goto cleanup;
  }

  status = ACS_STATUS_PASS;

cleanup:
  /* All exits after arming the timer must quiesce it, including comparison failures. */
  /* Disabling the timer deasserts its level-sensitive PPI; the ISR handles EOI.
   * val_gic_clear_interrupt() only supports SPIs and must not be used for this PPI.
   */
  val_timer_set_phy_el1(0);
  return status;
}

static
uint32_t
get_non_secure_system_timer(uint64_t *timer_num)
{
  uint64_t num_timer;

  num_timer = val_timer_get_info(TIMER_INFO_NUM_PLATFORM_TIMERS, 0);
  while (num_timer--)
  {
    if (val_timer_get_info(TIMER_INFO_IS_PLATFORM_TIMER_SECURE, num_timer))
        continue;

    *timer_num = num_timer;
    return ACS_STATUS_PASS;
  }

  val_print(ACS_PRINT_WARN, " No non-secure system timer implemented", 0);
  return ACS_STATUS_SKIP;
}

static
uint32_t
run_suspend_context_check(void)
{
  uint64_t sys_timer_ticks = val_get_counter_frequency();
  uint64_t timer_num;
  int32_t suspend_status;
  uint32_t status;

  status = get_non_secure_system_timer(&timer_num);
  if (status != ACS_STATUS_PASS)
      return status;

  /* Take a fresh snapshot for suspend before installing its interrupt handler. */
  if (save_msd_context())
      return ACS_STATUS_FAIL;

  suspend_intid = val_timer_get_info(TIMER_INFO_SYS_INTID, timer_num);
  cnt_base_n = val_timer_get_info(TIMER_INFO_SYS_CNT_BASE_N, timer_num);
  suspend_irq_received = 0;
  if (val_gic_install_isr(suspend_intid, suspend_isr))
  {
    val_print(ACS_PRINT_ERR, " GIC install handler failed", 0);
    return ACS_STATUS_FAIL;
  }

  status = ACS_STATUS_FAIL;
  val_timer_set_system_timer((addr_t)cnt_base_n, sys_timer_ticks);

  val_print(ACS_PRINT_TEST, " Suspending PE using PSCI_CPU_SUSPEND", 0);
  /* VAL selects standby; these arguments are the unused resume entry and context ID. */
  suspend_status = val_suspend_pe(0, 0);
  /* Skip the suspend check when PSCI cannot complete the request. */
  if (suspend_status != 0)
  {
    val_print(ACS_PRINT_WARN, " PSCI_CPU_SUSPEND returned %d; skipping suspend check",
              suspend_status);
    status = ACS_STATUS_SKIP;
    goto cleanup;
  }

  if (check_msd_context())
      goto cleanup;

  if (suspend_irq_received == 0)
  {
    val_print(ACS_PRINT_ERR, " System timer interrupt not generated", 0);
    goto cleanup;
  }

  status = ACS_STATUS_PASS;

cleanup:
  /* Stop the wake source on success, skipped suspend, and every failure path. */
  val_timer_disable_system_timer((addr_t)cnt_base_n);
  val_gic_clear_interrupt(suspend_intid);
  return status;
}

static
void
payload(void)
{
  uint32_t index = val_pe_get_index_mpid(val_pe_get_mpid());
  uint32_t executed_checks = 0;
  uint32_t failed_checks = 0;
  uint32_t status;

  status = run_wfi_context_check();
  if (status == ACS_STATUS_PASS)
      executed_checks++;
  else if (status == ACS_STATUS_FAIL)
      failed_checks++;

  /* Suspend is optional. A skip leaves WFI coverage intact and is reported below. */
  status = run_suspend_context_check();
  if (status == ACS_STATUS_PASS)
      executed_checks++;
  else if (status == ACS_STATUS_FAIL)
      failed_checks++;
  else if (status == ACS_STATUS_SKIP)
      val_print(ACS_PRINT_WARN,
                " CPU suspend context check skipped; only WFI coverage was attempted", 0);

  /* A failure in either scenario takes precedence over a pass in the other. */
  if (failed_checks)
  {
    val_set_status(index, "FAIL", 1);
    return;
  }

  if (executed_checks == 0)
  {
    val_set_status(index, "SKIP", 1);
    return;
  }

  val_set_status(index, "PASS", 1);
}

uint32_t
rme_pe_context_after_exit_wfi_entry(uint32_t num_pe)
{

  uint32_t status = ACS_STATUS_FAIL;

  num_pe = 1;  /* This timer test is run on a single processor. */

  status = val_initialize_test(TEST_NAME, TEST_DESC, num_pe, TEST_RULE);
  if (status != ACS_STATUS_SKIP)
      val_run_test_payload(num_pe, payload, 0);

  status = val_check_for_error(num_pe);

  val_report_status(0, "END");
  return status;

}
