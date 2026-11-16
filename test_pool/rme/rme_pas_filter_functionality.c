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
#include "val/include/val_pe.h"
#include "val/include/val_common.h"
#include "val/include/val_test_entry.h"
#include "val/include/val_interface.h"
#include "val/include/val_el32.h"
#include "val/include/val_memory.h"

#define TEST_NAME "rme_pas_filter_functionality"
#define TEST_DESC "Check private PAS filter access control"
#define TEST_RULE "RDVPGT"

/*
 * @brief Exercise private PAS filter access control through EL3 accesses.
 * 1. Retain the platform GPT configuration, use non-shareable mappings and mask exceptions.
 * 2. Select Root, Realm, Secure and Non-secure PAS.
 * 3. Use the ordinary EL3 access path for a matching PAS, expecting no fault.
 *    For a differing PAS, use the protected-load path and accept an exception
 *    or an unchanged INIT_DATA sentinel.
 * 4. Fail on setup/access errors or unexpected results; skip when no resources
 *    are provided. Clear the shared access state after each case and restore
 *    the original DAIF before reporting the result.
 *
 */
static void
payload(void)
{
    uint32_t index = val_pe_get_index_mpid(val_pe_get_mpid());
    MEM_REGN_INFO_TABLE *table = val_mem_pas_info_table();
    uint32_t region, case_index, attr, failed = 0;
    uint64_t size, pa, resource_pas, pas, va, saved_daif;
    const uint64_t pas_list[] = {ROOT_PAS, REALM_PAS, SECURE_PAS, NONSECURE_PAS};

    if (table == NULL || table->header.num_of_regn_pas_filter == 0) {
        val_print(ACS_PRINT_WARN, " No platform PAS-filter resources", 0);
        val_set_status(index, "SKIP", 01);
        return;
    }
    size = val_get_min_tg();
    if (shared_data == NULL || !size || (size & (size - 1U))) {
        val_set_status(index, "FAIL", 01);
        return;
    }
    __asm__ volatile("mrs %0, daif" : "=r" (saved_daif) : : "memory");
    set_daif();
    shared_data->generic_flag = CLEAR;
    attr = LOWER_ATTRS(PGT_ENTRY_ACCESS | SHAREABLE_ATTR(NON_SHAREABLE) | PGT_ENTRY_AP_RW);

    for (region = 0; region < table->header.num_of_regn_pas_filter; ++region) {
        pa = table->regn_info[region].base_addr;
        resource_pas = table->regn_info[region].resourse_pas;
        val_print(ACS_PRINT_TEST, " Resource PA: 0x%llx", pa);
        val_print(ACS_PRINT_TEST, " Resource PAS: 0x%llx", resource_pas);
        if (!pa || (pa & (sizeof(uint64_t) - 1U)) ||
            table->regn_info[region].regn_size < sizeof(uint64_t) ||
            resource_pas > REALM_PAS) {
            val_print(ACS_PRINT_ERR, " Invalid platform resource entry", 0);
            failed = 1;
            continue;
        }
        for (case_index = 0; case_index < 4; ++case_index) {
            pas = pas_list[case_index];
            val_print(ACS_PRINT_TEST, " Access PAS: 0x%llx", pas);
            va = val_get_free_va(size);
            if (!va || (va & (size - 1U)) ||
                val_add_mmu_entry_el3(va, pa & ~(size - 1U),
                                      attr | LOWER_ATTRS(PAS_ATTR(pas)))) {
                val_print(ACS_PRINT_ERR, " Failed to map resource", 0);
                failed = 1;
                continue;
            }
            va += pa & (size - 1U);
            val_memory_clear_el3_access_state();
            shared_data->access_mut = SET;
            shared_data->arg1 = va;
            shared_data->shared_data_access[0].data = INIT_DATA;
            if (pas != resource_pas) {
                shared_data->exception_expected = SET;
                shared_data->pas_filter_flag = SET;
            }
            if (val_pe_access_mut_el3()) {
                val_print(ACS_PRINT_ERR, " EL3 access failed", 0);
                failed = 1;
            } else if (pas == resource_pas) {
                if (shared_data->exception_generated == SET) {
                    val_print(ACS_PRINT_ERR, " Unexpected fault for matching PAS", 0);
                    failed = 1;
                }
            } else if (shared_data->exception_generated == CLEAR &&
                       shared_data->shared_data_access[0].data != INIT_DATA) {
                val_print(ACS_PRINT_ERR, " Unexpected read completion for mismatching PAS", 0);
                failed = 1;
            }
            val_memory_clear_el3_access_state();
        }
    }
    __asm__ volatile("msr daif, %0\n\tisb" : : "r" (saved_daif) : "memory");
    if (failed)
        val_set_status(index, "FAIL", 01);
    else
        val_set_status(index, "PASS", 01);
}

uint32_t
rme_pas_filter_functionality_entry(uint32_t num_pe)
{
    uint32_t status;

    num_pe = 1;
    status = val_initialize_test(TEST_NAME, TEST_DESC, num_pe, TEST_RULE);
    if (status != ACS_STATUS_SKIP)
        val_run_test_payload(num_pe, payload, 0);

    status = val_check_for_error(num_pe);
    val_report_status(0, "END");
    return status;
}
