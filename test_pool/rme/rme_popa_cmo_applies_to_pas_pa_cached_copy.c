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
#include "val/include/val_mem_interface.h"
#include "val/include/val_mec.h"
#include "val/include/val_memory.h"

#define NUM_SHAREABILITY  3
#define MECID1            0x1
#define MECID2            0x2
#define TEST_NAME         "rme_popa_cmo_applies_to_pas_pa_cached_copy"
#define TEST_DESC         "PoPA CMO applies to PAS PA cached copies          "
#define TEST_RULE         "RQBNJF"

/* Published before dispatch and left unchanged until the remote payload finishes. */
static uint64_t cmo_pa;
static uint64_t cmo_pas;
static uint64_t cmo_pas_second;

static
void secondary_cmo_pair_payload(void)
{
  uint32_t index = val_pe_get_index_mpid(val_pe_get_mpid());

  /*
   * The coordinator cleans these parameter cache lines before dispatch.
   * Discard this PE's stale copies before reading the published PA/PAS values.
   * This maintains the variables' cache lines, not the target test PA or TLB.
   */
  val_data_cache_ops_by_va((addr_t)&cmo_pa, INVALIDATE);
  val_data_cache_ops_by_va((addr_t)&cmo_pas, INVALIDATE);
  val_data_cache_ops_by_va((addr_t)&cmo_pas_second, INVALIDATE);

  /* Issue PoPA CMOs for the target PA in each requested PAS. */
  if (val_data_cache_ops_by_pa_el3(cmo_pa, cmo_pas) ||
      val_data_cache_ops_by_pa_el3(cmo_pa, cmo_pas_second)) {
    val_set_status(index, "FAIL", 01);
    return;
  }

  /* Publish CMO completion; the coordinator still has to verify its data. */
  val_set_status(index, "PASS", 01);
}

static uint32_t
get_secondary_pe_index(uint32_t primary_index, uint32_t num_pe)
{
  uint32_t i;
  uint32_t secondary_index = primary_index;
  uint64_t primary_mpidr;
  uint64_t primary_affinity;
  uint64_t pe_affinity;

  primary_mpidr = val_pe_get_mpid_index(primary_index);
  primary_affinity = primary_mpidr &
                     (PAL_MPIDR_AFFINITY_MASK &
                      ~(PAL_MPIDR_AFFLVL_MASK << PAL_MPIDR_AFF0_SHIFT));

  /*
   * PE_INFO_TABLE does not expose Outer Shareable domain IDs. Prefer a PE in
   * a different MPIDR affinity group when available; otherwise use any
   * non-primary PE as the best generic cross-PE CMO issuer.
   */
  for (i = 0; i < num_pe; i++) {
    if (i == primary_index)
      continue;

    if (secondary_index == primary_index)
      secondary_index = i;

    pe_affinity = val_pe_get_mpid_index(i) &
                  (PAL_MPIDR_AFFINITY_MASK &
                   ~(PAL_MPIDR_AFFLVL_MASK << PAL_MPIDR_AFF0_SHIFT));
    if (pe_affinity != primary_affinity)
      return i;
  }

  return secondary_index;
}

static uint32_t
execute_cmo_pair_on_pe(uint32_t index, uint32_t cmo_pe_index, uint64_t PA,
                       uint64_t first_pas, uint64_t second_pas,
                       uint32_t fail_code)
{
  uint32_t timeout;

  /* A single PE can exercise each shareability attribute with a local CMO. */
  if (cmo_pe_index == index) {
    if (val_data_cache_ops_by_pa_el3(PA, first_pas) ||
        val_data_cache_ops_by_pa_el3(PA, second_pas)) {
      val_print(ACS_PRINT_ERR, " Local PE failed CMO for PA 0x%lx", PA);
      val_set_status(index, "FAIL", fail_code);
      return ACS_STATUS_FAIL;
    }
    return ACS_STATUS_PASS;
  }

  cmo_pa = PA;
  cmo_pas = first_pas;
  cmo_pas_second = second_pas;
  /* Clean parameter cache lines to PoC before dispatch, then invalidate them.
   * &cmo_pa identifies the variable holding PA, not the memory at that PA.
   */
  val_data_cache_ops_by_va((addr_t)&cmo_pa, CLEAN_AND_INVALIDATE);
  val_data_cache_ops_by_va((addr_t)&cmo_pas, CLEAN_AND_INVALIDATE);
  val_data_cache_ops_by_va((addr_t)&cmo_pas_second, CLEAN_AND_INVALIDATE);

  /* Clear the previous result before the secondary can publish PASS or FAIL. */
  val_set_status(cmo_pe_index, "PENDING", 0);
  val_execute_on_pe(cmo_pe_index, secondary_cmo_pair_payload, 0);
  timeout = TIMEOUT_LARGE;
  /* Poll while the shared status is PENDING, within an iteration budget.
   * val_get_status() invalidates the status cache line and includes a DSB.
   */
  while (timeout && IS_RESULT_PENDING(val_get_status(cmo_pe_index)))
    timeout--;

  /* Timeout reports failure; it does not cancel the secondary payload. */
  if (IS_RESULT_PENDING(val_get_status(cmo_pe_index))) {
    val_print(ACS_PRINT_ERR, " Timed out waiting for secondary PE", 0);
    val_set_status(index, "FAIL", fail_code);
    return ACS_STATUS_FAIL;
  }

  if (!IS_TEST_PASS(val_get_status(cmo_pe_index))) {
    val_print(ACS_PRINT_ERR, " Secondary PE failed CMO for PA 0x%lx", PA);
    val_set_status(index, "FAIL", fail_code);
    return ACS_STATUS_FAIL;
  }

  return ACS_STATUS_PASS;
}

static uint32_t
run_mecid_independence_check(uint32_t index)
{
  uint32_t mec_restore_needed = CLEAR;
  uint32_t original_mec_enabled, original_mecid;
  uint32_t gpt_ready = CLEAR;
  uint32_t status = ACS_STATUS_FAIL, access_status;
  uint32_t mecid_width;
  uint64_t PA, VA_REALM, size, attr_realm;
  uint64_t data_wt_rl, data_rd_rl;

  if (val_is_mec_supported() == 0U) {
    val_print(ACS_PRINT_INFO, " MEC not supported, skipping MECID sub-check", 0);
    return ACS_STATUS_SKIP;
  }

  /* Use MECIDs 1 and 2, as in mec_effect_of_popa_cmo. Both must be implemented. */
  mecid_width = (uint32_t)VAL_EXTRACT_BITS(val_pe_reg_read(MECIDR_EL2), 0, 3) + 1U;
  if (MECID2 >= (1U << mecid_width)) {
    val_print(ACS_PRINT_INFO, " MECID 2 not supported, skipping MECID sub-check", 0);
    return ACS_STATUS_SKIP;
  }

  /* Save this PE's context before changing GPT, mappings or MEC state. */
  if (val_rlm_get_mec_state(&original_mec_enabled) ||
      val_rlm_get_mecid(&original_mecid)) {
    val_print(ACS_PRINT_ERR, " Failed to save original MEC context", 0);
    val_set_status(index, "FAIL", 50);
    return ACS_STATUS_FAIL;
  }

  size = val_get_min_tg();
  PA = val_get_free_pa(size, size);
  VA_REALM = val_get_free_va(size);
  if (PA == 1 || !VA_REALM || (PA & (size - 1)) || (VA_REALM & (size - 1))) {
    val_print(ACS_PRINT_ERR, " Failed to allocate aligned MEC test memory", 0);
    val_set_status(index, "FAIL", 38);
    return ACS_STATUS_FAIL;
  }

  /* Scratch PA/VA allocations stay reserved for this run; retain their GPT entries. */
  if (val_add_gpt_entry_el3(PA, GPT_ANY)) {
    val_print(ACS_PRINT_ERR, " Failed to add GPT entry for PA 0x%lx", PA);
    val_set_status(index, "FAIL", 20);
    goto mec_check_done;
  }
  gpt_ready = SET;

  /* Cache Realm data under M1 on this PE. */
  attr_realm = LOWER_ATTRS(PGT_ENTRY_ACCESS | SHAREABLE_ATTR(NON_SHAREABLE)
                           | GET_ATTR_INDEX(WRITE_BACK_NT) | PGT_ENTRY_AP_RW
                           | PAS_ATTR(REALM_PAS));
  if (val_add_mmu_entry_el3(VA_REALM, PA, attr_realm)) {
    val_print(ACS_PRINT_ERR, " Failed to add Realm MMU entry for VA 0x%lx", VA_REALM);
    val_set_status(index, "FAIL", 22);
    goto mec_check_done;
  }

  /* Arm restoration before the first MEC update, including its error path. */
  mec_restore_needed = SET;
  if (!original_mec_enabled && val_rlm_enable_mec()) {
    val_print(ACS_PRINT_ERR, " Failed to enable MEC", 0);
    val_set_status(index, "FAIL", 23);
    goto mec_check_done;
  }

  if (val_rlm_configure_mecid(MECID1)) {
    val_print(ACS_PRINT_ERR, " Failed to configure MECID %d", MECID1);
    val_set_status(index, "FAIL", 25);
    goto mec_check_done;
  }

  data_wt_rl = RANDOM_DATA_1;
  val_memory_clear_el3_access_state();
  shared_data->num_access = 1;
  shared_data->shared_data_access[0].addr = VA_REALM;
  shared_data->shared_data_access[0].data = data_wt_rl;
  shared_data->shared_data_access[0].access_type = WRITE_DATA;
  access_status = val_pe_access_mut_el3();
  val_memory_clear_el3_access_state();
  if (access_status) {
    val_print(ACS_PRINT_ERR, " Failed to write Realm VA = 0x%lx", VA_REALM);
    val_set_status(index, "FAIL", 27);
    goto mec_check_done;
  }

  /* Change to M2 and issue the Realm PoPA CMO on this same PE. */
  if (val_rlm_configure_mecid(MECID2)) {
    val_print(ACS_PRINT_ERR, " Failed to configure MECID %d", MECID2);
    val_set_status(index, "FAIL", 24);
    goto mec_check_done;
  }
  if (val_data_cache_ops_by_pa_el3(PA, REALM_PAS)) {
    val_print(ACS_PRINT_ERR, " Failed to issue Realm CMO for PA 0x%lx", PA);
    val_set_status(index, "FAIL", 28);
    goto mec_check_done;
  }

  /* Read the first pattern through a Non-cacheable Realm mapping under M1. */
  attr_realm = LOWER_ATTRS(PGT_ENTRY_ACCESS | SHAREABLE_ATTR(NON_SHAREABLE)
                           | GET_ATTR_INDEX(NON_CACHEABLE) | PGT_ENTRY_AP_RW
                           | PAS_ATTR(REALM_PAS));
  if (val_add_mmu_entry_el3(VA_REALM, PA, attr_realm)) {
    val_print(ACS_PRINT_ERR, " Failed to map Realm VA as Non-cacheable", 0);
    val_set_status(index, "FAIL", 29);
    goto mec_check_done;
  }
  if (val_rlm_configure_mecid(MECID1)) {
    val_print(ACS_PRINT_ERR, " Failed to restore MECID %d for readback", MECID1);
    val_set_status(index, "FAIL", 30);
    goto mec_check_done;
  }

  val_memory_clear_el3_access_state();
  shared_data->num_access = 1;
  shared_data->shared_data_access[0].addr = VA_REALM;
  shared_data->shared_data_access[0].data = ~data_wt_rl;
  shared_data->shared_data_access[0].access_type = READ_DATA;
  access_status = val_pe_access_mut_el3();
  data_rd_rl = shared_data->shared_data_access[0].data;
  val_memory_clear_el3_access_state();
  if (access_status) {
    val_print(ACS_PRINT_ERR, " Failed to read Non-cacheable Realm data", 0);
    val_set_status(index, "FAIL", 32);
    goto mec_check_done;
  }
  if (data_rd_rl != data_wt_rl) {
    val_print(ACS_PRINT_ERR, " Realm data mismatch after PoPA CMO under M2", 0);
    val_set_status(index, "FAIL", 33);
    goto mec_check_done;
  }

  /* Write a second pattern through the Non-cacheable mapping under M1. */
  data_wt_rl = RANDOM_DATA_2;
  val_memory_clear_el3_access_state();
  shared_data->num_access = 1;
  shared_data->shared_data_access[0].addr = VA_REALM;
  shared_data->shared_data_access[0].data = data_wt_rl;
  shared_data->shared_data_access[0].access_type = WRITE_DATA;
  access_status = val_pe_access_mut_el3();
  val_memory_clear_el3_access_state();
  if (access_status) {
    val_print(ACS_PRINT_ERR, " Failed to write Non-cacheable Realm data", 0);
    val_set_status(index, "FAIL", 26);
    goto mec_check_done;
  }

  /* Return to cacheable attributes and check that the second pattern is observed. */
  attr_realm = LOWER_ATTRS(PGT_ENTRY_ACCESS | SHAREABLE_ATTR(NON_SHAREABLE)
                           | GET_ATTR_INDEX(WRITE_BACK_NT) | PGT_ENTRY_AP_RW
                           | PAS_ATTR(REALM_PAS));
  if (val_add_mmu_entry_el3(VA_REALM, PA, attr_realm)) {
    val_print(ACS_PRINT_ERR, " Failed to restore cacheable Realm mapping", 0);
    val_set_status(index, "FAIL", 31);
    goto mec_check_done;
  }
  val_memory_clear_el3_access_state();
  shared_data->num_access = 1;
  shared_data->shared_data_access[0].addr = VA_REALM;
  shared_data->shared_data_access[0].data = ~data_wt_rl;
  shared_data->shared_data_access[0].access_type = READ_DATA;
  access_status = val_pe_access_mut_el3();
  data_rd_rl = shared_data->shared_data_access[0].data;
  val_memory_clear_el3_access_state();
  if (access_status) {
    val_print(ACS_PRINT_ERR, " Failed to read cacheable Realm data", 0);
    val_set_status(index, "FAIL", 34);
    goto mec_check_done;
  }
  if (data_rd_rl != data_wt_rl) {
    val_print(ACS_PRINT_ERR, " Cacheable Realm read returned an unexpected pattern", 0);
    val_set_status(index, "FAIL", 35);
    goto mec_check_done;
  }

  /* Successful checks fall through to cleanup, which can still change PASS to FAIL. */
  status = ACS_STATUS_PASS;

mec_check_done:
  val_memory_clear_el3_access_state();
  /* Remove cached Realm data before restoring MEC state. */
  if (gpt_ready && val_data_cache_ops_by_pa_el3(PA, REALM_PAS)) {
    val_set_status(index, "FAIL", 43);
    status = ACS_STATUS_FAIL;
  }

  /* Restore the saved MECID even when MEC was originally disabled. */
  if (mec_restore_needed) {
    if (val_rlm_configure_mecid(original_mecid)) {
      val_print(ACS_PRINT_ERR, " Failed to restore original MECID", 0);
      val_set_status(index, "FAIL", 36);
      status = ACS_STATUS_FAIL;
    }
    /* MEC stays enabled throughout the check if it was already enabled. */
    if (!original_mec_enabled && val_rlm_disable_mec()) {
      val_print(ACS_PRINT_ERR, " Failed to restore MEC-disabled state", 0);
      val_set_status(index, "FAIL", 37);
      status = ACS_STATUS_FAIL;
    }
  }
  return status;
}

/*
 * @brief  The test validates that a PoPA CMO applies to cached copies with
 *         the specified {PAS, PA}, regardless of the shareability domain used
 *         when the line was cached.
 * 1. The caller coordinates. Use another PE for CMOs when at least two PEs
 *    are selected; otherwise issue CMOs locally. PE0 and PE1 denote these roles,
 *    not fixed PE indices. Single-PE execution does not exercise cross-PE effects.
 * 2. Mark PA1 as All Access Permitted.
 * 3. For each shareability attribute, map VA1 to PA1 as Secure PAS and VA2 to
 *    PA1 as Non-secure PAS, both with cacheable attributes.
 * 4. On PE0, issue clean-and-invalidate to PoPA for Secure and Non-secure PAS
 *    to remove pre-existing cached state.
 * 5. Read VA1 and VA2 on PE0 to capture known Secure and Non-secure values.
 * 6. Store data3 through VA1 on PE0 and order it before the CMO request.
 * 7. PE1, or PE0 in single-PE mode, issues Secure then Non-secure PoPA CMOs.
 * 8. PE0 reads VA1 without additional cache maintenance and verifies the Secure
 *    value is preserved. Read VA2 for cross-PAS diagnostics only.
 * 9. Repeat the flow for each required shareability attribute.
 * 10. After the shareability checks, if MEC supports IDs 1 and 2, run the
 *     MECID check on PE0: write Realm data under M1, select M2 and issue
 *     a Realm PoPA CMO.
 *     Remap as Non-cacheable, restore M1 and verify the first pattern. Write
 *     a second pattern, remap as cacheable and verify the second pattern.
 *
 * Note: This test provides best-effort software-visible coverage. Platforms can
 * place the selected PEs in different Outer Shareable domains to increase
 * coverage; cache residency is not guaranteed, so natural eviction or writeback
 * can mask missing CMO effects. Same-PAS readback checks data preservation;
 * it does not prove that all matching cached copies were invalidated.
 */
static
void payload(uint32_t cmo_pe_index)
{
  uint32_t index = val_pe_get_index_mpid(val_pe_get_mpid());
  uint32_t sh_cnt, access_status;
  uint32_t gpt_ready, scenario_passed;
  uint64_t PA, VA_S, VA_NS, size;
  uint64_t attr_sec, attr_ns;
  uint64_t data1, data2, data3, data4, secure_data_after_cmo;
  uint64_t sh_list[NUM_SHAREABILITY] = {NON_SHAREABLE, INNER_SHAREABLE, OUTER_SHAREABLE};

  size = val_get_min_tg();

  for (sh_cnt = 0; sh_cnt < NUM_SHAREABILITY; sh_cnt++) {
    PA = val_get_free_pa(size, size);
    VA_S = val_get_free_va(size);
    VA_NS = val_get_free_va(size);
    if (PA == 1 || !VA_S || !VA_NS || (PA & (size - 1)) ||
        (VA_S & (size - 1)) || (VA_NS & (size - 1)) || VA_S == VA_NS) {
      val_print(ACS_PRINT_ERR, " Failed to allocate aligned shareability test memory", 0);
      val_set_status(index, "FAIL", 39);
      return;
    }
    data3 = RANDOM_DATA_1 + sh_cnt;

    val_print(ACS_PRINT_TEST, " Testing shareability 0x%lx", sh_list[sh_cnt]);

    gpt_ready = CLEAR;
    scenario_passed = CLEAR;

    /* GPT_ANY allows Secure and Non-secure aliases to target the same PA. */
    if (val_add_gpt_entry_el3(PA, GPT_ANY)) {
      val_print(ACS_PRINT_ERR, " Failed to add GPT entry for PA 0x%lx", PA);
      val_set_status(index, "FAIL", 01);
      goto scenario_done;
    }

    gpt_ready = SET;

    attr_sec = LOWER_ATTRS(PGT_ENTRY_ACCESS | SHAREABLE_ATTR(sh_list[sh_cnt])
                           | GET_ATTR_INDEX(WRITE_BACK_NT) | PGT_ENTRY_AP_RW
                           | PAS_ATTR(SECURE_PAS));
    attr_ns = LOWER_ATTRS(PGT_ENTRY_ACCESS | SHAREABLE_ATTR(sh_list[sh_cnt])
                          | GET_ATTR_INDEX(WRITE_BACK_NT) | PGT_ENTRY_AP_RW
                          | PAS_ATTR(NONSECURE_PAS));

    if (val_add_mmu_entry_el3(VA_S, PA, attr_sec)) {
      val_print(ACS_PRINT_ERR, " Failed to add Secure MMU entry for VA 0x%lx", VA_S);
      val_set_status(index, "FAIL", 02);
      goto scenario_done;
    }

    if (val_add_mmu_entry_el3(VA_NS, PA, attr_ns)) {
      val_print(ACS_PRINT_ERR, " Failed to add Non-secure MMU entry for VA 0x%lx", VA_NS);
      val_set_status(index, "FAIL", 03);
      goto scenario_done;
    }

    /*
     * Remove pre-existing cached state for both PAS views before creating the
     * Secure cached update and capturing the diagnostic Non-secure baseline.
     */
    if (val_data_cache_ops_by_pa_el3(PA, SECURE_PAS) ||
        val_data_cache_ops_by_pa_el3(PA, NONSECURE_PAS)) {
      val_set_status(index, "FAIL", 04);
      goto scenario_done;
    }

    val_memory_clear_el3_access_state();
    shared_data->num_access = 2;
    shared_data->shared_data_access[0].addr = VA_S;
    shared_data->shared_data_access[0].data = INIT_DATA;
    shared_data->shared_data_access[0].access_type = READ_DATA;
    shared_data->shared_data_access[1].addr = VA_NS;
    shared_data->shared_data_access[1].data = INIT_DATA;
    shared_data->shared_data_access[1].access_type = READ_DATA;

    access_status = val_pe_access_mut_el3();
    val_memory_clear_el3_access_state();
    if (access_status) {
      val_print(ACS_PRINT_ERR, " Failed to read Secure/Non-secure aliases", 0);
      val_set_status(index, "FAIL", 05);
      goto scenario_done;
    }

    data1 = shared_data->shared_data_access[0].data;
    data2 = shared_data->shared_data_access[1].data;

    val_memory_clear_el3_access_state();
    shared_data->num_access = 1;
    shared_data->shared_data_access[0].addr = VA_S;
    shared_data->shared_data_access[0].data = data3;
    shared_data->shared_data_access[0].access_type = WRITE_DATA;

    access_status = val_pe_access_mut_el3();
    val_memory_clear_el3_access_state();
    if (access_status) {
      val_print(ACS_PRINT_ERR, " Failed to write Secure VA = 0x%lx", VA_S);
      val_set_status(index, "FAIL", 06);
      goto scenario_done;
    }

    /*
     * Order the cacheable Secure write before the CMO request. The CMO
     * must operate on the state created above, not race with an outstanding
     * store from PE0. DMB orders accesses; it does not clean the test data.
     */
    ArmExecuteMemoryBarrier();

    if (execute_cmo_pair_on_pe(index, cmo_pe_index, PA, SECURE_PAS,
                               NONSECURE_PAS, 07) != ACS_STATUS_PASS)
      goto scenario_done;

    /* Verify the targeted PAS before the NS diagnostic, without local maintenance. */
    val_memory_clear_el3_access_state();
    shared_data->num_access = 1;
    shared_data->shared_data_access[0].addr = VA_S;
    shared_data->shared_data_access[0].data = ~data3;
    shared_data->shared_data_access[0].access_type = READ_DATA;
    access_status = val_pe_access_mut_el3();
    secure_data_after_cmo = shared_data->shared_data_access[0].data;
    val_memory_clear_el3_access_state();
    if (access_status) {
      val_print(ACS_PRINT_ERR, " Failed to read Secure data after CMO", 0);
      val_set_status(index, "FAIL", 11);
      goto scenario_done;
    }
    val_print(ACS_PRINT_DEBUG, " Secure data after CMO = 0x%lx", secure_data_after_cmo);
    if (secure_data_after_cmo != data3) {
      val_print(ACS_PRINT_ERR, " Secure data mismatch after PoPA CMO", 0);
      val_set_status(index, "FAIL", 12);
      goto scenario_done;
    }

    /* NS access must succeed, but its returned value is diagnostic only. */
    val_memory_clear_el3_access_state();
    shared_data->num_access = 1;
    shared_data->shared_data_access[0].addr = VA_NS;
    shared_data->shared_data_access[0].data = data2;
    shared_data->shared_data_access[0].access_type = READ_DATA;

    access_status = val_pe_access_mut_el3();
    val_memory_clear_el3_access_state();
    if (access_status) {
      val_print(ACS_PRINT_ERR, " Failed to read Non-secure VA after CMO = 0x%lx", VA_NS);
      val_set_status(index, "FAIL", 8);
      goto scenario_done;
    }

    data4 = shared_data->shared_data_access[0].data;
    val_print(ACS_PRINT_DEBUG, " Initial Secure data = 0x%lx", data1);
    val_print(ACS_PRINT_DEBUG, " Initial Non-secure data = 0x%lx", data2);
    val_print(ACS_PRINT_DEBUG, " Secure write data = 0x%lx", data3);
    val_print(ACS_PRINT_DEBUG, " Non-secure data after CMO = 0x%lx", data4);

    /* A Secure write/CMO need not change NS data; equality is not a verdict. */
    if (data4 == data2)
      val_print(ACS_PRINT_TEST, " Non-secure data remained unchanged (diagnostic)", 0);
    else
      val_print(ACS_PRINT_TEST, " Non-secure data changed after CMO (diagnostic)", 0);

    if (data4 == data3)
      val_print(ACS_PRINT_TEST, " NS value matches Secure write pattern (diagnostic)", 0);
    else
      val_print(ACS_PRINT_TEST, " NS value differs from Secure write pattern (diagnostic)", 0);
    scenario_passed = SET;

scenario_done:
    /* Run cleanup after success or failure, including a secondary timeout.
     * A timed-out secondary may still run; these calls do not cancel it.
     */
    val_memory_clear_el3_access_state();
    if (gpt_ready) {
      if (val_data_cache_ops_by_pa_el3(PA, SECURE_PAS)) {
        val_set_status(index, "FAIL", 47);
        scenario_passed = CLEAR;
      }
      if (val_data_cache_ops_by_pa_el3(PA, NONSECURE_PAS)) {
        val_set_status(index, "FAIL", 48);
        scenario_passed = CLEAR;
      }
    }
    if (!scenario_passed)
      return;
  }

  /* MEC adds coverage; skipping it does not discard successful shareability checks. */
  if (run_mecid_independence_check(index) == ACS_STATUS_FAIL)
    return;

  val_set_status(index, "PASS", 01);
}

uint32_t
rme_popa_cmo_applies_to_pas_pa_cached_copy_entry(uint32_t num_pe)
{
  uint32_t index = val_pe_get_index_mpid(val_pe_get_mpid());
  uint32_t primary_index = val_get_primary_pe_index();
  uint32_t cmo_pe_index = index;
  uint32_t status;

  if (num_pe > val_pe_get_num())
    num_pe = val_pe_get_num();
  status = val_initialize_test(TEST_NAME, TEST_DESC, num_pe, TEST_RULE);

  if (status != ACS_STATUS_SKIP) {
    if (num_pe == 0) {
      val_print(ACS_PRINT_WARN, " No PEs selected", 0);
      val_set_status(index, "SKIP", 01);
    } else if (!shared_data) {
      val_print(ACS_PRINT_ERR, " Shared data is unavailable", 0);
      val_set_status(index, "FAIL", 40);
    } else {
      val_memory_clear_el3_access_state();
      val_set_status(index, "PENDING", 0);
      /* Shareability checks apply whether or not MEC is supported. */
      /* Keep the CMO on the caller when only one PE is selected. */
      if (num_pe > 1)
        cmo_pe_index = get_secondary_pe_index(index, num_pe);
      if (cmo_pe_index == index)
        val_print(ACS_PRINT_TEST, " Local CMO: cross-PE coverage not exercised", 0);
      else
        val_print(ACS_PRINT_TEST, " CMO issuer PE index = %d", cmo_pe_index);
      payload(cmo_pe_index);
    }
  } else {
    val_set_status(index, "SKIP", 01);
  }

  /* Remote errors are folded into the coordinator result. The reporter's
   * single-result mode supports arbitrary PE indices, unlike its [0, num_pe)
   * scan. Report one aggregate for either local or remote CMO execution.
   */
  if (index != primary_index) {
    if (IS_TEST_PASS(val_get_status(index)))
      val_set_status(primary_index, "PASS", 01);
    else if (IS_TEST_SKIP(val_get_status(index)))
      val_set_status(primary_index, "SKIP", 01);
    else
      val_set_status(primary_index, "FAIL", 41);
  }
  status = val_check_for_error(1);
  val_report_status(0, "END");
  return status;
}
