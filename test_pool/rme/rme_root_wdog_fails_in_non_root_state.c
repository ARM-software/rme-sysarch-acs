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

#include "val/include/val_wd.h"
#include "val/include/val_timer.h"
#include "val/include/val_timer_support.h"
#include "val/include/val_el32.h"
#include "val/include/val_pgt.h"
#include "val/include/val_memory.h"
#include "val/sys_arch_src/gic/val_sys_arch_gic.h"

#define TEST_NAME  "rme_root_wdog_fails_in_non_root_state"
#define TEST_DESC  "Check Root Watchdog registers are accessible only in Root"
#define TEST_RULE  "RZHBBL"

static uint32_t int_id;
static uint64_t counter_freq;
static uint64_t VA_RT_WDOG;
static volatile uint32_t wdog_irq_received;
static volatile uint32_t wdog_isr_failed;

/**
 * @brief  The test validates that Root watchdog registers are in the Root PAS.
 * 1. Get the INT_ID for Root watchdog and install the ISR using the same.
 * 2. Map the Root watchdog control base register with VA_RT_WDOG as Root PAS.
 * 3. Program the watchdog from Root PAS and expect the interrupt.
 * 4. Map the Root watchdog control base register as Non-secure PAS.
 * 5. Access the watchdog register through the Non-secure PAS mapping and
 *    expect the access to be blocked.
 */

static void root_wdog_isr(void)
{
  if (val_wd_set_ws0_el3(VA_RT_WDOG, CLEAR, counter_freq))
  {
    val_print(ACS_PRINT_ERR, " Failed to program the WDOG", 0);
    wdog_isr_failed = 1;
  } else {
    val_print(ACS_PRINT_DEBUG, "  Received WS0 interrupt", 0);
    wdog_irq_received = 1;
  }

  val_gic_end_of_interrupt(int_id);
}

static uint32_t get_root_wdog_info(uint64_t *rt_wdog_ctl)
{
  uint64_t rt_wdog_ctl_available = val_get_rt_wdog_ctrl();

  if (rt_wdog_ctl_available)
  {
    *rt_wdog_ctl = rt_wdog_ctl_available;
    int_id = val_get_rt_wdog_int_id();
    return ACS_STATUS_PASS;
  }

  val_print(ACS_PRINT_WARN, " ROOT Watchdog not available in the platform", 0);
  return ACS_STATUS_SKIP;
}

static uint32_t root_wdog_cleanup(uint32_t wdog_mapped, uint32_t isr_installed)
{
  uint32_t status = ACS_STATUS_PASS;

  if (wdog_mapped)
  {
    if (val_wd_set_ws0_el3(VA_RT_WDOG, CLEAR, counter_freq))
    {
      val_print(ACS_PRINT_ERR, " Failed to disable Root Watchdog during cleanup", 0);
      status = ACS_STATUS_FAIL;
    }
  }

  if (isr_installed)
  {
    val_gic_clear_interrupt(int_id);
    val_gic_disableInterruptSource(int_id);
  }

  wdog_irq_received = 0;
  wdog_isr_failed = 0;
  return status;
}

static uint32_t run_root_pas_access_check(void)
{
  uint64_t timer_expire_ticks = 1;
  uint64_t timeout_ticks, start_cnt;
  uint32_t attr, status, wdog_mapped = 0, isr_installed = 0;
  uint64_t size, rt_wdog_ctl_reg;

  size = val_get_min_tg();
  status = get_root_wdog_info(&rt_wdog_ctl_reg);
  if (status != ACS_STATUS_PASS)
    return status;

  VA_RT_WDOG = val_get_free_va(size);
  if (!VA_RT_WDOG)
  {
    val_print(ACS_PRINT_ERR, " Failed to allocate Root Watchdog VA", 0);
    return ACS_STATUS_FAIL;
  }

  counter_freq = val_get_counter_frequency();
  if (!counter_freq)
  {
    val_print(ACS_PRINT_ERR, " Invalid counter frequency", 0);
    return ACS_STATUS_FAIL;
  }
  timeout_ticks = counter_freq * 2;
  val_print(ACS_PRINT_DEBUG, " Timer value = 0x%lx  ", timeout_ticks);
  val_print(ACS_PRINT_DEBUG, " Root watchdog Interrupt id  %d", int_id);

  if (val_gic_install_isr(int_id, root_wdog_isr))
  {
    val_print(ACS_PRINT_ERR, " GIC Install Handler Failed...", 0);
    return ACS_STATUS_FAIL;
  }
  isr_installed = 1;

  val_gic_set_intr_trigger(int_id, INTR_TRIGGER_INFO_LEVEL_HIGH);

  shared_data->generic_flag = CLEAR;
  attr = LOWER_ATTRS(PGT_ENTRY_ACCESS | SHAREABLE_ATTR(NON_SHAREABLE) | PGT_ENTRY_AP_RW
                     | GET_ATTR_INDEX(DEV_MEM_nGnRnE));
  if (val_add_mmu_entry_el3(VA_RT_WDOG, rt_wdog_ctl_reg,
                            (attr | LOWER_ATTRS(PAS_ATTR(ROOT_PAS)))))
  {
    val_print(ACS_PRINT_ERR, " Failed to map RT_WDOG_CTRL register in MMU", 0);
    status = ACS_STATUS_FAIL;
    goto root_wdog_exit;
  }
  wdog_mapped = 1;

  wdog_irq_received = 0;
  wdog_isr_failed = 0;
  val_print(ACS_PRINT_TEST, " Programming the Root Watchdog register from Root PAS", 0);
  if (val_wd_set_ws0_el3(VA_RT_WDOG, timer_expire_ticks, counter_freq))
  {
    val_print(ACS_PRINT_ERR, " Failed to program  the WDOG", 0);
    status = ACS_STATUS_FAIL;
    goto root_wdog_exit;
  }

  start_cnt = val_timer_ArmArchTimerReadReg(CntPct);
  while (((val_timer_ArmArchTimerReadReg(CntPct) - start_cnt) < timeout_ticks) &&
         (wdog_irq_received == 0) && (wdog_isr_failed == 0)) {
  }

  if (wdog_isr_failed)
  {
    status = ACS_STATUS_FAIL;
    goto root_wdog_exit;
  }

  if (wdog_irq_received == 0)
  {
    val_print(ACS_PRINT_ERR, " WS0 Interrupt not received on %d", int_id);
    status = ACS_STATUS_FAIL;
    goto root_wdog_exit;
  }

  status = ACS_STATUS_PASS;

root_wdog_exit:
  if (root_wdog_cleanup(wdog_mapped, isr_installed) != ACS_STATUS_PASS)
    status = ACS_STATUS_FAIL;
  return status;
}

static uint32_t run_non_root_pas_access_check(void)
{
  uint64_t size, rt_wdog_ctl, esr;
  uint32_t attr, status;

  size = val_get_min_tg();
  status = get_root_wdog_info(&rt_wdog_ctl);
  if (status != ACS_STATUS_PASS)
    return status;

  val_print(ACS_PRINT_DEBUG, " Root watchdog Interrupt id  %d", int_id);

  VA_RT_WDOG = val_get_free_va(size);
  if (!VA_RT_WDOG)
  {
    val_print(ACS_PRINT_ERR, " Failed to allocate Root Watchdog VA", 0);
    return ACS_STATUS_FAIL;
  }
  attr = LOWER_ATTRS(PGT_ENTRY_ACCESS | SHAREABLE_ATTR(NON_SHAREABLE) | PGT_ENTRY_AP_RW
                     | GET_ATTR_INDEX(DEV_MEM_nGnRnE));
  if (val_add_mmu_entry_el3(VA_RT_WDOG, rt_wdog_ctl,
                            (attr | LOWER_ATTRS(PAS_ATTR(NONSECURE_PAS)))))
  {
    val_print(ACS_PRINT_ERR, " Failed to map RT_WDOG_CTRL register in MMU", 0);
    return ACS_STATUS_FAIL;
  }

  shared_data->num_access = 1;
  shared_data->arg1 = VA_RT_WDOG;
  shared_data->shared_data_access[0].addr = VA_RT_WDOG;
  shared_data->shared_data_access[0].data = INIT_DATA;
  shared_data->shared_data_access[0].access_type = READ_DATA;
  shared_data->exception_expected = SET;
  shared_data->exception_generated = CLEAR;
  shared_data->access_mut = SET;
  shared_data->pas_filter_flag = SET;

  val_print(ACS_PRINT_DEBUG, " Accessing Root Watchdog register from NS PAS", 0);
  if (val_pe_access_mut_el3())
  {
    val_print(ACS_PRINT_ERR, " Failed to access RT_WDOG_CTRL register", 0);
    return ACS_STATUS_FAIL;
  }

  shared_data->access_mut = CLEAR;
  shared_data->pas_filter_flag = CLEAR;
  shared_data->exception_expected = CLEAR;

  if (shared_data->exception_generated == CLEAR)
  {
    val_print(ACS_PRINT_ERR, " Root Watchdog register access succeeded from NS PAS", 0);
    return ACS_STATUS_FAIL;
  }

  val_print(ACS_PRINT_DEBUG, " Non-secure PAS access generated an exception", 0);
  shared_data->exception_generated = CLEAR;

  esr = shared_data->esr_value;

  /*
   * Require a same-EL data read abort: GPF or synchronous external abort.
   * Reject translation/alignment faults, table walks and cache maintenance faults;
   * these do not demonstrate denial of the watchdog register read.
   */
  if (VAL_EXTRACT_BITS(esr, 26, 31) != 0x25 ||
      (esr & ((1U << 6) | (1U << 7) | (1U << 8) | (1U << 10))) ||
      ((esr & 0x3F) != 0x28 && (esr & 0x3F) != 0x10))
  {
    val_print(ACS_PRINT_ERR, " Unexpected NS watchdog access ESR: 0x%lx", esr);
    return ACS_STATUS_FAIL;
  }

  val_print(ACS_PRINT_DEBUG, " Non-secure PAS watchdog read was blocked", 0);

  return ACS_STATUS_PASS;
}


static void payload(void)
{
  uint32_t index = val_pe_get_index_mpid(val_pe_get_mpid());
  uint32_t status;

  if (!shared_data)
  {
    val_print(ACS_PRINT_ERR, " Shared data is unavailable", 0);
    val_set_status(index, "FAIL", 1);
    return;
  }

  status = run_root_pas_access_check();
  if (status == ACS_STATUS_SKIP)
  {
    val_set_status(index, "SKIP", 1);
    return;
  }
  if (status != ACS_STATUS_PASS)
  {
    val_set_status(index, "FAIL", 1);
    return;
  }

  status = run_non_root_pas_access_check();
  if (status == ACS_STATUS_SKIP)
  {
    val_set_status(index, "SKIP", 2);
    return;
  }
  if (status != ACS_STATUS_PASS)
  {
    val_set_status(index, "FAIL", 2);
    return;
  }

  val_set_status(index, "PASS", 1);
}

uint32_t rme_root_wdog_fails_in_non_root_state_entry(uint32_t num_pe)
{

  uint32_t status = ACS_STATUS_FAIL;

  num_pe = 1; /*This Timer test is run on single processor*/

  status = val_initialize_test(TEST_NAME, TEST_DESC, num_pe, TEST_RULE);

  if (status != ACS_STATUS_SKIP)
    val_run_test_payload(num_pe, payload, 0);

  /* get the result from all PE and check for failure */
  status = val_check_for_error(num_pe);

  val_report_status(0, "END");
  return status;
}
