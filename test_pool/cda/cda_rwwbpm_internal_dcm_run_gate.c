/** @file
 * Copyright (c) 2026, Arm Limited or its affiliates. All rights reserved.
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

#include "val/include/val_cda.h"
#include "val/include/val_cxl.h"
#include "val/include/val_cxl_spec.h"
#include "val/include/val_da.h"
#include "val/include/val_el32.h"
#include "val/include/val_exerciser.h"
#include "val/include/val_memory.h"
#include "val/include/val_pcie.h"
#include "val/include/val_pcie_spec.h"
#include "val/include/val_pe.h"

#define TEST_NAME "cda_rwwbpm_internal_dcm_run_gate"
#define TEST_DESC "Internal Realm DCM access allowed only in RUN     "
#define TEST_RULE "RWWBPM"

#define RMECDA_CTL1_TDISP_EN_MASK 0x1u
#define RMECDA_CTL1_LINK_STR_LOCK_MASK (1u << 1)

#define RUN_BASELINE_VALUE  0x0123456789ABCDEFull
#define RUN_WRITE_VALUE     0xF0E1D2C3B4A59687ull
#define STOP_BASELINE_VALUE 0x13579BDF2468ACE0ull
#define STOP_WRITE_VALUE    0x0ACE2468FDB97531ull

#if ENABLE_SPDM

typedef struct {
  /* CHI-C2C capable Root Port under test. */
  uint32_t root_bdf;
  /* Downstream CHI-C2C exerciser endpoint used to generate internal accesses. */
  uint32_t endpoint_index;
  uint32_t endpoint_bdf;
  /* Device-local DPA page used by the exerciser's internal DCM access path. */
  uint64_t dcm_base;
  uint64_t dcm_size;
  /* Original RMECDA_CTL1 value restored during cleanup. */
  uint32_t rmecda_ctl1_orig;
  uint32_t rmecda_ctl1_valid;
  uint32_t rmecda_cap_base;
  uint64_t rmecda_cfg_va;
} TEST_CONTEXT;

static void
init_context(TEST_CONTEXT *context)
{
  if (context == NULL)
    return;

  val_memory_set(context, sizeof(*context), 0);
  context->endpoint_index = CXL_COMPONENT_INVALID_INDEX;
}

static uint32_t
find_component_index_by_bdf(const CXL_COMPONENT_TABLE *table,
                            uint32_t bdf,
                            uint32_t *index_out)
{
  if ((table == NULL) || (index_out == NULL))
    return ACS_STATUS_ERR;

  for (uint32_t idx = 0; idx < table->num_entries; ++idx)
  {
    if (table->component[idx].bdf == bdf)
    {
      *index_out = idx;
      return ACS_STATUS_PASS;
    }
  }

  return ACS_STATUS_FAIL;
}

static uint32_t
restore_context_state(const TEST_CONTEXT *context)
{
  uint32_t restore_status;
  uint32_t readback;

  if (context == NULL)
    return ACS_STATUS_ERR;

  restore_status = ACS_STATUS_PASS;
  readback = 0u;

  if (context->rmecda_ctl1_valid != 0u)
  {
    if (context->rmecda_cfg_va == 0u)
      return ACS_STATUS_ERR;

    if ((val_memory_write_el3(context->rmecda_cfg_va +
                              context->rmecda_cap_base +
                              RMECDA_CTL1_OFFSET,
                              context->rmecda_ctl1_orig) != ACS_STATUS_PASS) ||
        (val_memory_read_el3(context->rmecda_cfg_va +
                             context->rmecda_cap_base +
                             RMECDA_CTL1_OFFSET,
                             &readback) != ACS_STATUS_PASS) ||
        (readback != context->rmecda_ctl1_orig))
    {
      val_print(ACS_PRINT_WARN,
                " RWWBPM: RMECDA_CTL1 restore readback 0x%x",
                (uint64_t)readback);
      restore_status = ACS_STATUS_ERR;
    }
  }

  return restore_status;
}

static uint32_t
select_test_base(uint64_t window_base,
                 uint64_t window_size,
                 uint64_t *test_base_out)
{
  uint64_t page_size;
  uint64_t window_end;
  uint64_t aligned_base;

  if (test_base_out == NULL)
    return ACS_STATUS_ERR;

  page_size = (uint64_t)val_memory_page_size();
  if (page_size == 0u)
    return ACS_STATUS_ERR;

  if (window_size < page_size)
    return ACS_STATUS_SKIP;

  window_end = window_base + window_size;
  if (window_end < window_base)
    return ACS_STATUS_ERR;

  aligned_base = (window_base + page_size - 1u) & ~(page_size - 1u);
  if ((aligned_base + page_size) > window_end)
    return ACS_STATUS_SKIP;

  *test_base_out = aligned_base;
  return ACS_STATUS_PASS;
}

static uint32_t
prepare_context(TEST_CONTEXT *context)
{
  CXL_COMPONENT_TABLE *table;

  if (context == NULL)
    return ACS_STATUS_ERR;

  init_context(context);

  table = val_cxl_component_table_ptr();
  if ((table == NULL) || (table->num_entries == 0u))
    return ACS_STATUS_SKIP;

  /*
   * Find a CHI-C2C Root Port / endpoint pair that can exercise the rule,
   * use a device-local DPA page for the internal access path,
   * and pre-enable the Root Port controls that gate Realm traffic:
   * TDISP_EN and LINK_STR_LOCK.
   */
  for (uint32_t root_idx = 0u; root_idx < table->num_entries; ++root_idx)
  {
    TEST_CONTEXT candidate;
    const CXL_COMPONENT_ENTRY *root_port;
    const CXL_COMPONENT_ENTRY *endpoint;
    uint32_t endpoint_bdf;
    uint32_t status;
    uint32_t ctl1_programmed;
    uint32_t ctl1_readback;

    init_context(&candidate);

    root_port = &table->component[root_idx];
    if (root_port->role != CXL_COMPONENT_ROLE_ROOT_PORT)
      continue;

    val_print(ACS_PRINT_DEBUG,
              " RWWBPM: considering RP BDF 0x%x",
              (uint64_t)root_port->bdf);
    val_print(ACS_PRINT_DEBUG,
              " RWWBPM: RP chi_c2c flag %u",
              (uint64_t)root_port->chi_c2c_supported);

    if (root_port->chi_c2c_supported == 0u)
    {
      val_print(ACS_PRINT_DEBUG,
                " RWWBPM: skipping RP 0x%x because CHI-C2C is not detected",
                (uint64_t)root_port->bdf);
      continue;
    }

    status = val_cda_find_downstream_chi_c2c_exerciser_endpoint(root_port->bdf,
                                                                &endpoint_bdf);
    if (status != ACS_STATUS_PASS)
    {
      val_print(ACS_PRINT_DEBUG,
                " RWWBPM: no downstream CHI-C2C exerciser for RP 0x%x",
                (uint64_t)root_port->bdf);
      val_print(ACS_PRINT_DEBUG,
                " RWWBPM: downstream endpoint search status %u",
                (uint64_t)status);
      continue;
    }

    if (find_component_index_by_bdf(table, endpoint_bdf, &candidate.endpoint_index)
        != ACS_STATUS_PASS)
    {
      val_print(ACS_PRINT_DEBUG,
                " RWWBPM: endpoint 0x%x missing from component table",
                (uint64_t)endpoint_bdf);
      continue;
    }

    endpoint = &table->component[candidate.endpoint_index];
    if (endpoint->chi_c2c_supported == 0u)
    {
      val_print(ACS_PRINT_DEBUG,
                " RWWBPM: endpoint 0x%x is not marked CHI-C2C",
                (uint64_t)endpoint->bdf);
      continue;
    }

    candidate.root_bdf = root_port->bdf;
    candidate.endpoint_bdf = endpoint->bdf;

    val_print(ACS_PRINT_DEBUG,
              " RWWBPM: selected RP 0x%x",
              (uint64_t)candidate.root_bdf);
    val_print(ACS_PRINT_DEBUG,
              " RWWBPM: selected EP 0x%x",
              (uint64_t)candidate.endpoint_bdf);

    if (val_pcie_find_cda_capability(root_port->bdf, &candidate.rmecda_cap_base)
        != ACS_STATUS_PASS)
    {
      val_print(ACS_PRINT_DEBUG,
                " RWWBPM: root 0x%x lacks RME-CDA capability",
                (uint64_t)candidate.root_bdf);
      continue;
    }

    if (endpoint->component_reg_base == 0u)
    {
      val_print(ACS_PRINT_DEBUG,
                " RWWBPM: missing component register base for EP 0x%x",
                (uint64_t)candidate.endpoint_bdf);
      continue;
    }

    candidate.dcm_size = (uint64_t)val_memory_page_size();
    if (candidate.dcm_size == 0u)
    {
      val_print(ACS_PRINT_DEBUG,
                " RWWBPM: invalid page size for EP 0x%x",
                (uint64_t)candidate.endpoint_bdf);
      continue;
    }

    /*
     * Internal exerciser accesses target device-local DPA directly. Use the
     * first non-zero page so the address is page-aligned without depending on
     * pre-programmed HDM decoder state.
     */
    candidate.dcm_base = candidate.dcm_size;

    if (val_cxl_enable_mem(endpoint->bdf) != ACS_STATUS_PASS)
    {
      val_print(ACS_PRINT_DEBUG,
                " RWWBPM: CXL.mem enable failed for EP 0x%x",
                (uint64_t)endpoint->bdf);
      if (restore_context_state(&candidate) != ACS_STATUS_PASS)
        return ACS_STATUS_ERR;
      continue;
    }

    if (val_pcie_map_root_config(candidate.root_bdf,
                                 &candidate.rmecda_cfg_va) != ACS_STATUS_PASS)
    {
      val_print(ACS_PRINT_DEBUG,
                " RWWBPM: config map failed for RP 0x%x",
                (uint64_t)candidate.root_bdf);
      if (restore_context_state(&candidate) != ACS_STATUS_PASS)
        return ACS_STATUS_ERR;
      continue;
    }

    if (val_memory_read_el3(candidate.rmecda_cfg_va +
                            candidate.rmecda_cap_base +
                            RMECDA_CTL1_OFFSET,
                            &candidate.rmecda_ctl1_orig) != ACS_STATUS_PASS)
    {
      if (restore_context_state(&candidate) != ACS_STATUS_PASS)
        return ACS_STATUS_ERR;
      continue;
    }

    ctl1_programmed = candidate.rmecda_ctl1_orig |
                      RMECDA_CTL1_TDISP_EN_MASK |
                      RMECDA_CTL1_LINK_STR_LOCK_MASK;

    val_print(ACS_PRINT_DEBUG,
              " RWWBPM: RMECDA_CTL1 initial readback 0x%x",
              (uint64_t)candidate.rmecda_ctl1_orig);

    if ((candidate.rmecda_ctl1_orig &
         (RMECDA_CTL1_TDISP_EN_MASK | RMECDA_CTL1_LINK_STR_LOCK_MASK)) ==
        (RMECDA_CTL1_TDISP_EN_MASK | RMECDA_CTL1_LINK_STR_LOCK_MASK))
    {
      ctl1_readback = candidate.rmecda_ctl1_orig;
    }
    else
    {
      candidate.rmecda_ctl1_valid = 1u;
      if (val_memory_write_el3(candidate.rmecda_cfg_va +
                               candidate.rmecda_cap_base +
                               RMECDA_CTL1_OFFSET,
                               ctl1_programmed) != ACS_STATUS_PASS)
      {
        if (restore_context_state(&candidate) != ACS_STATUS_PASS)
          return ACS_STATUS_ERR;
        continue;
      }

      if (val_memory_read_el3(candidate.rmecda_cfg_va +
                              candidate.rmecda_cap_base +
                              RMECDA_CTL1_OFFSET,
                              &ctl1_readback) != ACS_STATUS_PASS)
      {
        if (restore_context_state(&candidate) != ACS_STATUS_PASS)
          return ACS_STATUS_ERR;
        continue;
      }

      val_print(ACS_PRINT_DEBUG,
                " RWWBPM: RMECDA_CTL1 root-write readback 0x%x",
                (uint64_t)ctl1_readback);
    }

    if ((ctl1_readback &
         (RMECDA_CTL1_TDISP_EN_MASK | RMECDA_CTL1_LINK_STR_LOCK_MASK)) !=
        (RMECDA_CTL1_TDISP_EN_MASK | RMECDA_CTL1_LINK_STR_LOCK_MASK))
    {
      val_print(ACS_PRINT_DEBUG,
                " RWWBPM: RMECDA_CTL1 cannot enable required bits via config",
                0);
      if (restore_context_state(&candidate) != ACS_STATUS_PASS)
        return ACS_STATUS_ERR;
      continue;
    }

    val_print(ACS_PRINT_INFO,
              " RWWBPM: using RP 0x%x for CHI-C2C CDA check",
              (uint64_t)candidate.root_bdf);
    val_print(ACS_PRINT_INFO,
              " RWWBPM: using EP 0x%x for CHI-C2C CDA check",
              (uint64_t)candidate.endpoint_bdf);
    *context = candidate;
    return ACS_STATUS_PASS;
  }

  return ACS_STATUS_SKIP;
}

static uint32_t
exercise_rule(TEST_CONTEXT *context)
{
  uint32_t result;
  uint32_t status;
  uint32_t device_locked;
  uint32_t realm_assigned;
  uint64_t test_base;
  uint64_t observed;

  if (context == NULL)
    return ACS_STATUS_ERR;

  status = select_test_base(context->dcm_base,
                            context->dcm_size,
                            &test_base);
  if (status != ACS_STATUS_PASS)
    return status;

  val_print(ACS_PRINT_INFO, " RWWBPM: endpoint DPA test base 0x%llx",
            context->dcm_base);
  val_print(ACS_PRINT_INFO, " RWWBPM: Realm DCM page 0x%llx", test_base);

  device_locked = 0u;
  realm_assigned = 0u;
  result = ACS_STATUS_FAIL;

  status = val_device_lock(context->endpoint_bdf);
  if (status != ACS_STATUS_PASS)
  {
    val_print(ACS_PRINT_INFO, " RWWBPM: TDI RUN setup failed", 0);
    return ACS_STATUS_SKIP;
  }
  device_locked = 1u;

  /*
   * Mark the selected DCM page as Realm-assigned and confirm that an internal
   * access specifying PAS==Realm succeeds while the TDI remains in RUN.
   */
  status = val_cxl_exerciser_execute_cmd(context->endpoint_bdf,
                                         CXL_CMD_OP_DCM_SET_REALM_ASSIGNMENT,
                                         test_base,
                                         1u,
                                         NULL);
  if (status != ACS_STATUS_PASS)
  {
    val_print(ACS_PRINT_INFO,
              " RWWBPM: Realm DCM assignment hook unavailable",
              0);
    result = ACS_STATUS_SKIP;
    goto cleanup;
  }
  realm_assigned = 1u;

  if (val_cxl_exerciser_write64(context->endpoint_bdf,
                         test_base,
                         RUN_BASELINE_VALUE) != ACS_STATUS_PASS)
  {
    result = ACS_STATUS_SKIP;
    goto cleanup;
  }

  if (val_cxl_exerciser_read64(context->endpoint_bdf,
                        test_base,
                        &observed) != ACS_STATUS_PASS)
  {
    result = ACS_STATUS_SKIP;
    goto cleanup;
  }

  if (observed != RUN_BASELINE_VALUE)
  {
    val_print(ACS_PRINT_INFO,
              " RWWBPM: Realm RUN baseline media readback mismatch",
              0);
    val_print(ACS_PRINT_INFO,
              " RWWBPM: Realm RUN baseline observed 0x%llx",
              observed);
    result = ACS_STATUS_SKIP;
    goto cleanup;
  }

  status = val_cxl_exerciser_execute_cmd_with_ctrl(context->endpoint_bdf,
                                                   CXL_CMD_OP_BACKDOOR_WRITE64,
                                                   CXL_CMD_CTRL_PAS_REALM,
                                                   test_base,
                                                   RUN_WRITE_VALUE,
                                                   NULL);
  if (status != ACS_STATUS_PASS)
  {
    val_print(ACS_PRINT_ERR,
              " RWWBPM: PAS=Realm DCM write failed in RUN",
              0);
    result = ACS_STATUS_FAIL;
    goto cleanup;
  }

  if (val_cxl_exerciser_read64(context->endpoint_bdf,
                        test_base,
                        &observed) != ACS_STATUS_PASS)
  {
    result = ACS_STATUS_FAIL;
    goto cleanup;
  }

  if (observed != RUN_WRITE_VALUE)
  {
    val_print(ACS_PRINT_ERR,
              " RWWBPM: Realm-assigned DCM write failed in RUN",
              0);
    val_print(ACS_PRINT_ERR,
              " RWWBPM: Realm RUN observed 0x%llx",
              observed);
    result = ACS_STATUS_FAIL;
    goto cleanup;
  }
  val_print(ACS_PRINT_INFO,
            " RWWBPM: Realm-assigned DCM access succeeded in RUN",
            0);

  /*
   * Move the TDI out of RUN.  The same PAS==Realm access to the same
   * Realm-assigned DCM page must now be blocked or become non-destructive.
   */
  status = val_device_unlock(context->endpoint_bdf);
  if (status != ACS_STATUS_PASS)
  {
    val_print(ACS_PRINT_ERR, " RWWBPM: STOP_INTERFACE failed", 0);
    result = ACS_STATUS_FAIL;
    goto cleanup;
  }
  device_locked = 0u;

  if (val_cxl_exerciser_write64(context->endpoint_bdf,
                         test_base,
                         STOP_BASELINE_VALUE) != ACS_STATUS_PASS)
  {
    result = ACS_STATUS_FAIL;
    goto cleanup;
  }

  if (val_cxl_exerciser_read64(context->endpoint_bdf,
                        test_base,
                        &observed) != ACS_STATUS_PASS)
  {
    result = ACS_STATUS_FAIL;
    goto cleanup;
  }

  if (observed != STOP_BASELINE_VALUE)
  {
    val_print(ACS_PRINT_ERR,
              " RWWBPM: Realm post-STOP baseline seed failed",
              0);
    val_print(ACS_PRINT_ERR,
              " RWWBPM: Realm STOP baseline observed 0x%llx",
              observed);
    result = ACS_STATUS_FAIL;
    goto cleanup;
  }

  status = val_cxl_exerciser_execute_cmd_with_ctrl(context->endpoint_bdf,
                                                   CXL_CMD_OP_BACKDOOR_WRITE64,
                                                   CXL_CMD_CTRL_PAS_REALM,
                                                   test_base,
                                                   STOP_WRITE_VALUE,
                                                   NULL);

  if (val_cxl_exerciser_read64(context->endpoint_bdf,
                        test_base,
                        &observed) != ACS_STATUS_PASS)
  {
    result = ACS_STATUS_FAIL;
    goto cleanup;
  }

  if (observed == STOP_WRITE_VALUE)
  {
    val_print(ACS_PRINT_ERR,
              " RWWBPM: non-RUN TDI still modified Realm-assigned DCM",
              0);
    result = ACS_STATUS_FAIL;
    goto cleanup;
  }

  if (observed != STOP_BASELINE_VALUE)
  {
    val_print(ACS_PRINT_ERR,
              " RWWBPM: unexpected Realm DCM value after non-RUN access",
              0);
    val_print(ACS_PRINT_ERR,
              " RWWBPM: Realm non-RUN observed 0x%llx",
              observed);
    result = ACS_STATUS_FAIL;
    goto cleanup;
  }

  if (status != ACS_STATUS_PASS)
  {
    /* Rejection is an allowed outcome as long as the media contents stay intact. */
    val_print(ACS_PRINT_INFO,
              " RWWBPM: non-RUN Realm access rejected as expected",
              0);
  }
  val_print(ACS_PRINT_INFO,
            " RWWBPM: Realm-assigned DCM access blocked after STOP",
            0);

  result = ACS_STATUS_PASS;

cleanup:
  if (realm_assigned != 0u)
  {
    if (val_cxl_exerciser_execute_cmd(context->endpoint_bdf,
                                      CXL_CMD_OP_DCM_SET_REALM_ASSIGNMENT,
                                      test_base,
                                      0u,
                                      NULL) != ACS_STATUS_PASS)
    {
      val_print(ACS_PRINT_ERR,
                " RWWBPM: failed to clear Realm DCM assignment",
                0);
      result = ACS_STATUS_FAIL;
    }
  }

  if (device_locked != 0u)
  {
    if (val_device_unlock(context->endpoint_bdf) != ACS_STATUS_PASS)
    {
      val_print(ACS_PRINT_ERR,
                " RWWBPM: cleanup STOP_INTERFACE failed",
                0);
      result = ACS_STATUS_FAIL;
    }
  }

  return result;
}

static void
payload(void)
{
  uint32_t pe_index;
  uint32_t cleanup_status;
  uint32_t status;
  TEST_CONTEXT context;

  pe_index = val_pe_get_index_mpid(val_pe_get_mpid());

  status = prepare_context(&context);
  if (status == ACS_STATUS_SKIP)
  {
    val_print(ACS_PRINT_INFO, " RWWBPM: no suitable CHI-C2C CDA context", 0);
    val_set_status(pe_index, "SKIP", 01);
    return;
  }

  if (status != ACS_STATUS_PASS)
  {
    val_set_status(pe_index, "FAIL", 01);
    return;
  }

  /* Run the rule body and then restore all Root Port / decoder state. */
  status = exercise_rule(&context);
  cleanup_status = restore_context_state(&context);
  if (cleanup_status != ACS_STATUS_PASS)
  {
    val_print(ACS_PRINT_ERR,
              " RWWBPM: platform cleanup failed after test execution",
              0);
    status = ACS_STATUS_FAIL;
  }

  if (status == ACS_STATUS_PASS)
    val_set_status(pe_index, "PASS", 01);
  else if (status == ACS_STATUS_SKIP)
    val_set_status(pe_index, "SKIP", 02);
  else
    val_set_status(pe_index, "FAIL", 02);
}

#else

static void
payload(void)
{
  uint32_t pe_index;

  pe_index = val_pe_get_index_mpid(val_pe_get_mpid());
  val_set_status(pe_index, "SKIP", 01);
}

#endif

uint32_t
cda_rwwbpm_internal_dcm_run_gate_entry(uint32_t num_pe)
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
