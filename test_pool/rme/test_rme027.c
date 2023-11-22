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
#include "val/include/val_interface.h"

#include "val/include/rme_acs_wd.h"
#include "val/include/rme_acs_el32.h"
#include "val/include/sys_config.h"

#define TEST_NUM   (ACS_RME_TEST_NUM_BASE + 27)
#define TEST_DESC  "Check Root Watchdog interrupt from Root state          "
#define TEST_RULE  "PE_19"

static uint32_t int_id;
static uint64_t counter_freq;
static uint64_t VA_RT_WDOG;

static
void
isr()
{
    uint32_t index = val_pe_get_index_mpid(val_pe_get_mpid());

    /* Clear the interrupt */
    val_wd_set_ws0_el3(VA_RT_WDOG, CLEAR, counter_freq);
    val_print(ACS_PRINT_DEBUG, "\n       Received WS0 interrupt                ", 0);
    val_set_status(index, RESULT_PASS(TEST_NUM, 1));
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
    uint32_t index = val_pe_get_index_mpid(val_pe_get_mpid()), timeout;
    uint64_t size;

    size = val_get_min_tg();
    VA_RT_WDOG = val_get_free_va(size);

    timeout = val_get_counter_frequency() * 2;
    counter_freq = val_get_counter_frequency();
    val_print(ACS_PRINT_DEBUG, "\n       Timer value = 0x%lx  ", timeout);
    /* INT_ID for RT_WDOG is 114 */
    int_id       = RT_WDOG_INT_ID;
    val_print(ACS_PRINT_DEBUG, "\n       Root watchdog Interrupt id  %d        ", int_id);

    if (val_gic_install_isr(int_id, isr)) {
            val_print(ACS_PRINT_ERR, "\n       GIC Install Handler Failed...", 0);
            val_set_status(index, RESULT_FAIL(TEST_NUM, 2));
            return;
    }

    /* Set Interrupt Type: Level Trigger */
    val_gic_set_intr_trigger(int_id, INTR_TRIGGER_INFO_LEVEL_HIGH);

    shared_data->generic_flag = CLEAR;
    val_add_mmu_entry_el3(VA_RT_WDOG, RT_WDOG_CTRL, ROOT_PAS);
    val_wd_set_ws0_el3(VA_RT_WDOG, timer_expire_ticks, counter_freq);

    while ((--timeout > 0) && (IS_RESULT_PENDING(val_get_status(index))));

    if (timeout == 0) {
            val_print(ACS_PRINT_ERR, "\n       WS0 Interrupt not received on %d   ", int_id);
            val_set_status(index, RESULT_FAIL(TEST_NUM, 4));
            return;
    }
}

uint32_t
rme027_entry(void)
{

    uint32_t num_pe;
    uint32_t status = ACS_STATUS_FAIL;

    num_pe = 1;  /*This Timer test is run on single processor*/

    status = val_initialize_test(TEST_NUM, TEST_DESC, num_pe, TEST_RULE);

    if (status != ACS_STATUS_SKIP)
        val_run_test_payload(TEST_NUM, num_pe, payload, 0);

    /* get the result from all PE and check for failure */
    status = val_check_for_error(TEST_NUM, num_pe, TEST_RULE);

    val_report_status(0, RME_ACS_END(TEST_NUM), TEST_RULE);
    return status;

}
