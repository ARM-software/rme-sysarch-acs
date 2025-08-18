/** @file
 * Copyright (c) 2023-2024, 2025, Arm Limited or its affiliates. All rights reserved.
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
#include "val/include/val_el32.h"

#define TEST_NAME  "rme_root_wdog_from_root_pas"
#define TEST_DESC  "Check Root Watchdog interrupt from Root state          "
#define TEST_RULE  "RZHBBL"

static uint32_t int_id;
static uint64_t counter_freq;
static uint64_t VA_RT_WDOG;

static
void
isr()
{
    uint32_t index = val_pe_get_index_mpid(val_pe_get_mpid());

    /* Clear the interrupt */
    if (val_wd_set_ws0_el3(VA_RT_WDOG, CLEAR, counter_freq))
    {
        val_print(ACS_PRINT_ERR, " Failed to program the WDOG", 0);
        val_set_status(index, "FAIL", 1);
        return;
    }
    val_print(ACS_PRINT_DEBUG, "  Received WS0 interrupt", 0);
    val_set_status(index, "PASS", 1);
    val_gic_end_of_interrupt(int_id);
}

/**
 * @brief  The test validates that the programming of root watchdog from Root state
 *         will successfully generate an interrupt.
 * 1. Get the INT_ID for Root watchdog and install the ISR using the same.
 * 2. Map the root watchdog control base register with VA_RT_WDOG as Root access PAS.
 * 3. Set the interrupt type and set the timer in EL3 by writing counter timer to WOR
 *    offset of the VA_RT_WDOG.
 * 4. The inerrupt will be generated within the given timeout, and will be handled
 *    making the test PASS otherwise FAIL.
 */
static
void
payload()
{

    uint64_t timer_expire_ticks = 1;
    uint32_t index = val_pe_get_index_mpid(val_pe_get_mpid()), timeout, attr;
    uint64_t size, rt_wdog_ctl_reg;
    uint64_t rt_wdog_ctl_available = val_get_rt_wdog_ctrl();

    size = val_get_min_tg();

    if (rt_wdog_ctl_available) {
        rt_wdog_ctl_reg = rt_wdog_ctl_available;
        /* INT_ID for RT_WDOG is 114 */
        int_id = val_get_rt_wdog_int_id();
    } else {
        val_print(ACS_PRINT_ERR, " ROOT Watchdog not available in the platform", 0);
        val_set_status(index, "FAIL", 01);
        return;
    }

    VA_RT_WDOG = val_get_free_va(size);

    timeout = val_get_counter_frequency() * 2;
    counter_freq = val_get_counter_frequency();
    val_print(ACS_PRINT_DEBUG, " Timer value = 0x%lx  ", timeout);
    val_print(ACS_PRINT_DEBUG, " Root watchdog Interrupt id  %d", int_id);

    if (val_gic_install_isr(int_id, isr)) {
        val_print(ACS_PRINT_ERR, " GIC Install Handler Failed...", 0);
        val_set_status(index, "FAIL", 2);
        return;
    }

    /* Set Interrupt Type: Level Trigger */
    val_gic_set_intr_trigger(int_id, INTR_TRIGGER_INFO_LEVEL_HIGH);

    shared_data->generic_flag = CLEAR;
    attr = LOWER_ATTRS(PGT_ENTRY_ACCESS | SHAREABLE_ATTR(NON_SHAREABLE) | PGT_ENTRY_AP_RW);
    if (val_add_mmu_entry_el3(VA_RT_WDOG, rt_wdog_ctl_reg,
                                (attr | LOWER_ATTRS(PAS_ATTR(ROOT_PAS)))))
    {
        val_print(ACS_PRINT_ERR, " Failed to map RT_WDOG_CTRL register in MMU", 0);
        val_set_status(index, "FAIL", 3);
        return;
    }

    val_print(ACS_PRINT_TEST, " Programming the Root Watchdog register from Root PAS", 0);
    if (val_wd_set_ws0_el3(VA_RT_WDOG, timer_expire_ticks, counter_freq))
    {
        val_print(ACS_PRINT_ERR, " Failed to program  the WDOG", 0);
        val_set_status(index, "FAIL", 4);
        return;
    }

    while ((--timeout > 0) && (IS_RESULT_PENDING(val_get_status(index))));

    if (timeout == 0) {
            val_print(ACS_PRINT_ERR, " WS0 Interrupt not received on %d", int_id);
            val_set_status(index, "FAIL", 05);
            return;
    }
}

uint32_t
rme_root_wdog_from_root_pas_entry(void)
{

    uint32_t num_pe;
    uint32_t status = ACS_STATUS_FAIL;

    num_pe = 1;  /*This Timer test is run on single processor*/

    status = val_initialize_test(TEST_NAME, TEST_DESC, num_pe, TEST_RULE);

    if (status != ACS_STATUS_SKIP)
        val_run_test_payload(num_pe, payload, 0);

    /* get the result from all PE and check for failure */
    status = val_check_for_error(num_pe);

    val_report_status(0, "END");
    return status;

}
