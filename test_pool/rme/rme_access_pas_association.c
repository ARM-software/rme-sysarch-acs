/** @file
 * Copyright (c) 2026, Arm Limited or its affiliates. All rights reserved.
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

#include "val/include/val_mec.h"
#include "val/include/val_iovirt.h"
#include "val/include/val_smmu.h"

#define TEST_NAME "rme_access_pas_association"
#define TEST_DESC "Check Root Access PAS and PE MECID association"
#define TEST_RULE "RBJVZS"

#define SMMU_R_MECIDR_OFFSET 0x0220U

static uint32_t *pe_mecidw;
static uint32_t common_pe_width;

static uint32_t
check_mecid_association(void)
{
    uint32_t saved_enabled, saved_mecid, width, max_mecid, common_width = common_pe_width;
    uint32_t num_smmu, i, case_index, attr, case_status, reg;
    uint64_t size, pa, va, original_gpi;
    const uint8_t cmo_points[] = {PoE, PoPA};
    uint32_t status = ACS_STATUS_FAIL;

    if (!val_is_mec_supported()) {
        val_print(ACS_PRINT_INFO, " MEC not supported; MECID sub-check skipped", 0);
        return ACS_STATUS_SKIP;
    }

    if (common_width == 0 || common_width > 16U)
        return ACS_STATUS_FAIL;

    num_smmu = val_smmu_get_info(SMMU_NUM_CTRL, 0);
    if (!num_smmu) {
        val_print(ACS_PRINT_WARN, " No SMMU controllers; MECID sub-check skipped", 0);
        return ACS_STATUS_SKIP;
    }
    if (val_rlm_get_mec_state(&saved_enabled) || val_rlm_get_mecid(&saved_mecid)) {
        val_print(ACS_PRINT_ERR, " Failed to save PE MEC context", 0);
        return ACS_STATUS_FAIL;
    }
    if (!saved_enabled && val_rlm_enable_mec())
        goto cleanup;

    for (i = 0; i < num_smmu; ++i) {
        /* Read capability registers without initializing SMMU streams or queues. */
        val_memory_clear_el3_access_state();
        if (val_smmu_read_realm_cfg(SMMUv3_IDR3, i, &reg)) {
            val_print(ACS_PRINT_ERR, " MEC capability query failed for SMMU index: %u", i);
            goto cleanup;
        }
        if (!VAL_EXTRACT_BITS(reg, 16, 16)) {
            val_print(ACS_PRINT_ERR, " MEC not supported by SMMU index: %u", i);
            goto cleanup;
        }
        if (val_smmu_read_realm_cfg(SMMU_R_MECIDR_OFFSET, i, &reg)) {
            val_print(ACS_PRINT_ERR, " MECID width query failed for SMMU index: %u", i);
            goto cleanup;
        }
        /* SMMU_R_MECIDR.MECIDWidthm1 is bits [3:0], encoding widths 1..16. */
        width = (uint32_t)VAL_EXTRACT_BITS(reg, 0, 3) + 1U;
        if (width < common_width)
            common_width = width;
    }

    /* Both MECIDs must fit every PE and SMMU; common_width is in 1..16. */
    val_print(ACS_PRINT_TEST, " Common PE/SMMU MECID width: %u", common_width);
    max_mecid = (1U << common_width) - 1U;
    size = val_get_min_tg();
    if (!size || (size & (size - 1U)))
        goto cleanup;
    attr = LOWER_ATTRS(PGT_ENTRY_ACCESS | SHAREABLE_ATTR(NON_SHAREABLE) |
                      PGT_ENTRY_AP_RW | PAS_ATTR(REALM_PAS));
    for (case_index = 0; case_index < 2; ++case_index) {
        case_status = ACS_STATUS_FAIL;
        val_memory_clear_el3_access_state();
        val_print(ACS_PRINT_TEST, " PE MECID validation point: %u", cmo_points[case_index]);
        pa = val_get_free_pa(size, size);
        va = val_get_free_va(size);
        if (!pa || !va || (pa & (size - 1U)) || (va & (size - 1U)))
            goto cleanup;
        if (val_get_gpt_entry_el3(pa, &original_gpi))
            goto cleanup;

        /* Restore this GPI even if the update reports a partial setup failure. */
        if (val_add_gpt_entry_el3(pa, GPT_ANY))
            goto restore_mec_scratch;
        if (val_add_mmu_entry_el3(va, pa, attr))
            goto restore_mec_scratch;
        if (val_rlm_configure_mecid(max_mecid))
            goto restore_mec_scratch;

        shared_data->num_access = 1;
        shared_data->shared_data_access[0].addr = va;
        shared_data->shared_data_access[0].data = RANDOM_DATA_4;
        shared_data->shared_data_access[0].access_type = WRITE_DATA;
        if (val_pe_access_mut_el3())
            goto restore_mec_scratch;

        if (cmo_points[case_index] == PoE) {
            if (val_cmo_to_poe(pa))
                goto restore_mec_scratch;
        } else {
            if (val_data_cache_ops_by_pa_el3(pa, REALM_PAS))
                goto restore_mec_scratch;
        }
        if (val_rlm_configure_mecid(max_mecid - 1U))
            goto restore_mec_scratch;

        shared_data->num_access = 1;
        shared_data->shared_data_access[0].addr = va;
        shared_data->shared_data_access[0].access_type = READ_DATA;
        if (val_pe_access_mut_el3())
            goto restore_mec_scratch;
        if (shared_data->shared_data_access[0].data != RANDOM_DATA_4)
            case_status = ACS_STATUS_PASS;

restore_mec_scratch:
        val_memory_clear_el3_access_state();
        if (val_add_gpt_entry_el3(pa, original_gpi)) {
            val_print(ACS_PRINT_ERR, " Failed to restore MEC scratch GPI for PA: 0x%llx", pa);
            val_print(ACS_PRINT_ERR, " Original MEC scratch GPI: 0x%llx", original_gpi);
            goto cleanup;
        }
        if (case_status != ACS_STATUS_PASS) {
            val_print(ACS_PRINT_ERR, " PE MECID validation failed at point: %u",
                      cmo_points[case_index]);
            goto cleanup;
        }
    }
    status = ACS_STATUS_PASS;

cleanup:
    val_memory_clear_el3_access_state();
    if (val_rlm_configure_mecid(saved_mecid)) {
        val_print(ACS_PRINT_ERR, " Failed to restore PE MECID", 0);
        status = ACS_STATUS_FAIL;
    }
    if (!saved_enabled && val_rlm_disable_mec()) {
        val_print(ACS_PRINT_ERR, " Failed to restore MEC enable state", 0);
        status = ACS_STATUS_FAIL;
    }
    return status;
}

/*
 * @brief  The test exercises RBJVZS through Root-state Access PAS selection
 *         and PE MECID checks on systems with and without MEC support.
 * 1. Initialize the test for all PEs. If the primary PE supports MEC, collect
 *    MECID widths on all PEs. Require completed collection and valid widths,
 *    then record the minimum PE width before single-PE validation.
 * 2. On one PE, check RME support. Skip the PAS sub-check if unsupported;
 *    otherwise save DAIF and mask exceptions for the scratch PAS accesses.
 * 3. Allocate separate scratch memory for Root, Realm, Secure, and Non-secure
 *    PAS. Save each granule's GPT entry and mark it All Access Permitted.
 * 4. Map each scratch address at EL3 with non-cacheable attributes and the
 *    selected PAS. Write a PAS-specific pattern and read it back, requiring
 *    successful accesses and matching data.
 * 5. Restore each original GPT entry, including failure paths. Stop further
 *    PAS and MECID probes if restoration fails. Restore DAIF before MECID
 *    validation or when exiting after a restoration failure.
 * 6. Skip the MECID sub-check if the primary PE lacks MEC or no SMMU is found.
 *    Otherwise save the PE MECID and enable state, enabling MEC if necessary.
 * 7. Check each SMMU's Realm MEC capability and MECID width. Require MEC support
 *    and select two MECIDs using the minimum width across all PEs and SMMUs.
 * 8. For each of PoE and PoPA, allocate Realm scratch memory, save its GPI,
 *    set GPT_ANY, and create an EL3 mapping. Write using the first MECID,
 *    perform cache maintenance to the selected point, then read using the
 *    second MECID. Require the returned data to differ from the written data.
 * 9. Restore each MEC scratch GPI, including failure paths, and stop remaining
 *    MEC probes on failure. Restore the saved PE MECID and disable MEC if it
 *    was originally disabled. Treat cleanup failures as test failures.
 * 10. Report FAIL for collection, setup, access, comparison, or cleanup errors.
 *     Report SKIP if both PAS and MECID sub-checks are skipped; otherwise
 *     report PASS when at least one passes and neither fails.
 *
 */
static void
payload(void)
{
    uint32_t index = val_pe_get_index_mpid(val_pe_get_mpid());
    uint32_t scratch_status = ACS_STATUS_SKIP, mec_status = ACS_STATUS_SKIP;
    uint32_t i, attr, read_data, daif_saved = 0;
    uint64_t size, pa, va, original_gpi, saved_daif = 0;
    const uint64_t pas_list[] = {ROOT_PAS, REALM_PAS, SECURE_PAS, NONSECURE_PAS};

    /* Refresh the pointer published by the entry before starting secondary PEs. */
    val_data_cache_ops_by_va((addr_t)&pe_mecidw, INVALIDATE);
    /* The multi-PE invocation only collects widths into the shared array. */
    if (pe_mecidw != NULL) {
        uint32_t width = 0xFFFFFFFFU;

        if (!val_is_mec_supported()) {
            val_print(ACS_PRINT_ERR, " MEC not supported by PE index: %u", index);
        } else {
            /* MECIDR_EL2.MECIDWidthm1 encodes widths 1..16. */
            width = (uint32_t)VAL_EXTRACT_BITS(val_pe_reg_read(MECIDR_EL2), 0, 3) + 1U;
        }
        pe_mecidw[index] = width;
        val_data_cache_ops_by_va((addr_t)&pe_mecidw[index], CLEAN_AND_INVALIDATE);
        /* Collection completed; the caller rejects the unsupported-MEC sentinel. */
        val_set_status(index, "PASS", 01);
        return;
    }

    if (shared_data == NULL) {
        val_set_status(index, "FAIL", 01);
        return;
    }
    shared_data->generic_flag = CLEAR;
    val_memory_clear_el3_access_state();
    if (VAL_EXTRACT_BITS(val_pe_reg_read(ID_AA64PFR0_EL1), 52, 55) != 1U) {
        val_print(ACS_PRINT_WARN, " RME not supported; Access PAS sub-check skipped", 0);
        goto mec_checks;
    }

    val_print(ACS_PRINT_WARN,
              " PAS coverage is Root EL3 only; Secure/Realm/Non-secure execution not tested", 0);

    scratch_status = ACS_STATUS_FAIL;
    size = val_get_min_tg();
    if (!size || (size & (size - 1U)))
        goto mec_checks;

    __asm__ volatile("mrs %0, daif" : "=r" (saved_daif) : : "memory");
    set_daif();
    daif_saved = 1;

    for (i = 0; i < 4; ++i) {
        /* Different scratch PAs avoid relying on data aliasing across PAS. */
        scratch_status = ACS_STATUS_FAIL;
        pa = val_get_free_pa(size, size);
        va = val_get_free_va(size);
        if (!pa || !va || (pa & (size - 1U)) || (va & (size - 1U)))
            goto mec_checks;
        if (val_get_gpt_entry_el3(pa, &original_gpi))
            goto mec_checks;

        val_print(ACS_PRINT_TEST, " Root-state Access PAS: 0x%llx", pas_list[i]);
        if (val_add_gpt_entry_el3(pa, GPT_ANY))
            goto restore_scratch;
        attr = LOWER_ATTRS(PGT_ENTRY_ACCESS | SHAREABLE_ATTR(NON_SHAREABLE) |
                          PGT_ENTRY_AP_RW | GET_ATTR_INDEX(NON_CACHEABLE) |
                          PAS_ATTR(pas_list[i]));
        if (val_add_mmu_entry_el3(va, pa, attr))
            goto restore_scratch;
        if (val_memory_write_el3(va, RANDOM_DATA_1 + i) ||
            val_memory_read_el3(va, &read_data))
            goto restore_scratch;
        if (read_data != RANDOM_DATA_1 + i) {
            val_print(ACS_PRINT_ERR, " Scratch readback mismatch: 0x%x", read_data);
            goto restore_scratch;
        }
        scratch_status = ACS_STATUS_PASS;

restore_scratch:
        if (val_add_gpt_entry_el3(pa, original_gpi)) {
            val_print(ACS_PRINT_ERR, " Failed to restore scratch GPI", 0);
            goto restoration_failed;
        }
        if (scratch_status != ACS_STATUS_PASS)
            goto mec_checks;
    }

mec_checks:
    val_memory_clear_el3_access_state();
    if (daif_saved) {
        __asm__ volatile("msr daif, %0\n\tisb" : : "r" (saved_daif) : "memory");
        daif_saved = 0;
    }
    mec_status = check_mecid_association();
    goto report_result;

restoration_failed:
    val_print(ACS_PRINT_ERR, " Stopping RBJVZS probes; recovery required for PA: 0x%llx", pa);
    val_print(ACS_PRINT_ERR, " Original GPI to restore: 0x%llx", original_gpi);
    scratch_status = ACS_STATUS_FAIL;

report_result:
    val_memory_clear_el3_access_state();
    if (daif_saved)
        __asm__ volatile("msr daif, %0\n\tisb" : : "r" (saved_daif) : "memory");
    if (scratch_status == ACS_STATUS_FAIL || mec_status == ACS_STATUS_FAIL)
        val_set_status(index, "FAIL", 01);
    else if (scratch_status == ACS_STATUS_SKIP && mec_status == ACS_STATUS_SKIP)
        val_set_status(index, "SKIP", 01);
    else
        val_set_status(index, "PASS", 01);
}

uint32_t
rme_access_pas_association_entry(uint32_t num_pe)
{
    uint32_t status, i, width, pe_failed = 0, pe_incomplete = 0;
    uint32_t index = val_pe_get_index_mpid(val_pe_get_mpid());

    num_pe = val_pe_get_num();
    status = val_initialize_test(TEST_NAME, TEST_DESC, num_pe, TEST_RULE);
    if (status == ACS_STATUS_SKIP)
        goto report;
    if (pe_mecidw != NULL) {
        val_print(ACS_PRINT_ERR, " Previous PE width collection did not complete", 0);
        goto failed;
    }

    if (val_is_mec_supported()) {
        if (!num_pe || num_pe > 0xFFFFFFFFU / sizeof(*pe_mecidw))
            goto failed;
        pe_mecidw = val_memory_alloc(num_pe * sizeof(*pe_mecidw));
        if (pe_mecidw == NULL) {
            val_print(ACS_PRINT_ERR, " Failed to allocate PE MECID widths", 0);
            goto failed;
        }
        common_pe_width = 16U;
        for (i = 0; i < num_pe; ++i) {
            pe_mecidw[i] = 0;
            /* Publish array contents separately from the pointer itself. */
            val_data_cache_ops_by_va((addr_t)&pe_mecidw[i], CLEAN_AND_INVALIDATE);
            val_set_status(i, "PENDING", 01);
        }
        /* Publish the pointer before dispatch; PAL cache operations include barriers. */
        val_data_cache_ops_by_va((addr_t)&pe_mecidw, CLEAN_AND_INVALIDATE);
        val_run_test_payload(num_pe, payload, 0);
        for (i = 0; i < num_pe; ++i) {
            if (!IS_TEST_PASS(val_get_status(i)))
                pe_incomplete = 1;
            val_data_cache_ops_by_va((addr_t)&pe_mecidw[i], INVALIDATE);
            width = pe_mecidw[i];
            if (width == 0 || width > 16U) {
                val_print(ACS_PRINT_ERR, " MECID width check failed for PE index: %u", i);
                pe_failed = 1;
            }
            if (width < common_pe_width)
                common_pe_width = width;
        }
        if (pe_incomplete) {
            /* A delayed secondary PE can still write to this array. */
            val_print(ACS_PRINT_ERR, " PE width collection incomplete; retaining shared array", 0);
            goto failed;
        }
        val_memory_free(pe_mecidw);
        pe_mecidw = NULL;
        val_data_cache_ops_by_va((addr_t)&pe_mecidw, CLEAN_AND_INVALIDATE);
        if (pe_failed)
            goto failed;
    }

    /* Run validation only after collection has completed and released its array. */
    val_set_status(index, "PENDING", 01);
    val_run_test_payload(1, payload, 0);
    goto report;

failed:
    val_set_status(index, "FAIL", 01);
report:
    status = val_check_for_error(1);
    val_report_status(0, "END");
    return status;
}
