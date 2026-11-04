/** @file
 * Copyright (c) 2023-2026, Arm Limited or its affiliates. All rights reserved.
 * SPDX-License-Identifier : Apache-2.0
 *
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
#include "val/include/val_mem_interface.h"

#define TEST_NAME  "rme_root_wdog_expiration_from_root"
#define TEST_DESC  "Check Root Watchdog triggers RME system reset          "
#define TEST_RULE  "RVXGBP"

static uint64_t counter_freq;
static uint64_t VA_RT_WDOG;

/**
 * @brief  The test validates that programming the Root Watchdog from Root state
 *         triggers an RME system reset.
 * 1. If returning after reset, restore the test state and pass.
 * 2. Map the root watchdog control base register with VA_RT_WDOG as Root PAS.
 * 3. Save the test state and program the Root watchdog from Root PAS.
 * 4. The watchdog must progress to WS1 and cause an RME system reset.
 */
static
void
payload(void)
{

    uint64_t timer_expire_ticks = 1;
    uint64_t timeout, start_cnt, now_cnt;
    uint32_t index = val_pe_get_index_mpid(val_pe_get_mpid()), attr;
    uint64_t size, rt_wdog_ctl_reg;
    uint64_t rt_wdog_ctl_available = val_get_rt_wdog_ctrl();

    if (val_read_reset_status() == RESET_RT_WDOG_FLAG) {
        val_restore_global_test_data();
        val_write_reset_status(0);
        val_print(ACS_PRINT_TEST, " Root watchdog triggered RME system reset", 0);
        val_set_status(index, "PASS", 1);
        return;
    }

    size = val_get_min_tg();

    val_print(ACS_PRINT_TEST, " ROOT watchdog control register is at 0x%lx", rt_wdog_ctl_available);
    if (rt_wdog_ctl_available) {
        rt_wdog_ctl_reg = rt_wdog_ctl_available;
    } else {
        val_print(ACS_PRINT_WARN, " ROOT Watchdog not available in the platform", 0);
        val_set_status(index, "SKIP", 01);
        return;
    }

    VA_RT_WDOG = val_get_free_va(size);

    if (!VA_RT_WDOG) {
        val_print(ACS_PRINT_ERR, " Failed to allocate Root Watchdog VA", 0);
        val_set_status(index, "FAIL", 2);
        return;
    }

    counter_freq = val_get_counter_frequency();
    if (!counter_freq) {
        val_print(ACS_PRINT_ERR, " Invalid counter frequency", 0);
        val_set_status(index, "FAIL", 2);
        return;
    }
    timeout = counter_freq * 4;
    val_print(ACS_PRINT_TEST, " Timer value = 0x%lx  ", timeout);

    shared_data->generic_flag = CLEAR;
    attr = LOWER_ATTRS(PGT_ENTRY_ACCESS | SHAREABLE_ATTR(NON_SHAREABLE) | PGT_ENTRY_AP_RW
                       | GET_ATTR_INDEX(DEV_MEM_nGnRnE));
    if (val_add_mmu_entry_el3(VA_RT_WDOG, rt_wdog_ctl_reg,
                                (attr | LOWER_ATTRS(PAS_ATTR(ROOT_PAS)))))
    {
        val_print(ACS_PRINT_ERR, " Failed to map RT_WDOG_CTRL register in MMU", 0);
        val_set_status(index, "FAIL", 2);
        return;
    }

    val_write_reset_status(RESET_RT_WDOG_FLAG);
    val_save_global_test_data();

    val_print(ACS_PRINT_TEST, " Programming Root Watchdog and waiting for RME reset", 0);
    if (val_wd_set_ws0_el3(VA_RT_WDOG, timer_expire_ticks, counter_freq))
    {
        val_print(ACS_PRINT_ERR, " Failed to program  the WDOG", 0);
        val_write_reset_status(0);
        (void)val_wd_set_ws0_el3(VA_RT_WDOG, CLEAR, counter_freq);
        val_set_status(index, "FAIL", 3);
        return;
    }

    start_cnt = val_timer_ArmArchTimerReadReg(CntPct);
    while (1) {
        now_cnt = val_timer_ArmArchTimerReadReg(CntPct);
        if ((now_cnt - start_cnt) >= timeout)
            break;
    }

    val_print(ACS_PRINT_TEST, " Timer expired", 0);
    (void)val_wd_set_ws0_el3(VA_RT_WDOG, CLEAR, counter_freq);
    val_write_reset_status(0);
    val_print(ACS_PRINT_ERR, " Root watchdog did not trigger RME system reset", 0);
    val_set_status(index, "FAIL", 4);
}

uint32_t
rme_root_wdog_expiration_from_root_entry(uint32_t num_pe)
{

    uint32_t status = ACS_STATUS_FAIL;

    num_pe = 1;  /* This timer test is run on a single processor */

    status = val_initialize_test(TEST_NAME, TEST_DESC, num_pe, TEST_RULE);

    if (status != ACS_STATUS_SKIP)
        val_run_test_payload(num_pe, payload, 0);

    /* Get the result from all PEs and check for failure */
    status = val_check_for_error(num_pe);

    val_report_status(0, "END");
    return status;
}
