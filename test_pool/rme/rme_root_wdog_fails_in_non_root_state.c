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


#include "val/include/rme_acs_val.h"
#include "val/include/val_interface.h"

#include "val/include/rme_acs_wd.h"
#include "val/include/rme_acs_timer.h"
#include "val/include/rme_acs_el32.h"
#include "val/include/rme_acs_pgt.h"
#include "val/include/rme_acs_memory.h"

#define TEST_NAME  "rme_root_wdog_fails_in_non_root_state"
#define TEST_DESC  "Check Root Watchdog programming fails in Non-Root state"
#define TEST_RULE  "RZHBBL/RVXGBP"

static uint32_t int_id;
static uint64_t counter_freq;
static uint64_t VA_RT_WDOG;

static
void
isr()
{
    uint32_t index = val_pe_get_index_mpid(val_pe_get_mpid());
    //Disable the root watchdog timer
    if (val_wd_set_ws0_el3(VA_RT_WDOG, CLEAR, counter_freq))
    {
        val_print(ACS_PRINT_ERR, " Failed to program the WDOG", 0);
        val_set_status(index, "FAIL", 4);
        return;
    }
    val_print(ACS_PRINT_DEBUG, " Received WS0 interrupt", 0);
    val_set_status(index, "FAIL", 5);
    val_gic_end_of_interrupt(int_id);
}

/**
 * @brief  The test validates that the programming of root watchdog from non-Root state
 *         will successfully generate an interrupt.
 * 1. Get the INT_ID for Root watchdog and install the ISR using the same.
 * 2. Map the root watchdog control base register with VA_RT_WDOG as Non-secure access PAS.
 * 3. Set the interrupt type and set the timer in EL3 by writing counter timer to WOR
 *    offset of the VA_RT_WDOG.
 * 4. The inerrupt will not be generated within the given timeout, making the test PASS
 *    otherwise FAIL.
 */
static
void
payload()
{

    uint32_t timeout;
    uint64_t timer_expire_ticks = 1;
    uint64_t size, rt_wdog_ctl;
    uint32_t index = val_pe_get_index_mpid(val_pe_get_mpid()), attr;
    uint64_t rt_wdog_ctl_available = val_get_rt_wdog_ctrl();

    size = val_get_min_tg();

    if (rt_wdog_ctl_available) {
        rt_wdog_ctl = rt_wdog_ctl_available;
        /* INT_ID for RT_WDOG is 114 */
        int_id = val_get_rt_wdog_int_id();
    } else {
        val_print(ACS_PRINT_ERR, " ROOT Watchdog not available in the platform", 0);
        val_set_status(index, "FAIL", 1);
        return;
    }

    timeout = val_get_counter_frequency() * 2;
    counter_freq = val_get_counter_frequency();

    val_print(ACS_PRINT_TEST, " Root watchdog Interrupt id  %d", int_id);

    if (val_gic_install_isr(int_id, isr)) {
            val_print(ACS_PRINT_ERR, " GIC Install Handler Failed...", 0);
            val_set_status(index, "FAIL", 2);
            return;
    }

    /* Set Interrupt Type Edge/Level Trigger */
    val_gic_set_intr_trigger(int_id, INTR_TRIGGER_INFO_LEVEL_HIGH);

    VA_RT_WDOG = val_get_free_va(size);
    rt_wdog_ctl = PLAT_RT_WDOG_CTRL;
    attr = LOWER_ATTRS(PGT_ENTRY_ACCESS | SHAREABLE_ATTR(NON_SHAREABLE) | PGT_ENTRY_AP_RW);
    if (val_add_mmu_entry_el3(VA_RT_WDOG, rt_wdog_ctl,
                                (attr | LOWER_ATTRS(PAS_ATTR(NONSECURE_PAS)))))
    {
        val_print(ACS_PRINT_ERR, " Failed to map RT_WDOG_CTRL register in MMU", 0);
        val_set_status(index, "FAIL", 3);
        return;
    }
    //Generic flag will be set to ensure the disabling of I.A.F bit in PSTATE in el3
    shared_data->generic_flag = SET;
    if (val_wd_set_ws0_el3(VA_RT_WDOG, timer_expire_ticks, counter_freq))
    {
        val_print(ACS_PRINT_ERR, "\n    Failed to program  the WDOG", 0);
        val_set_status(index, "FAIL", 3);
        return;
    }

    while ((--timeout > 0) && (IS_RESULT_PENDING(val_get_status(index))));

    if (timeout == 0) {
            val_print(ACS_PRINT_ERR, " WS0 Interrupt not received on %d", int_id);
            val_set_status(index, "PASS", 3);
            return;
    }
}

uint32_t
rme_root_wdog_fails_in_non_root_state_entry(void)
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

