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
#include "val/include/val_el32.h"
#include "val/include/val_exerciser.h"
#include "val/include/val_memory.h"
#include "val/include/val_pcie.h"
#include "val/include/val_pcie_spec.h"
#include "val/include/val_pe.h"
#include "val/include/val_spdm.h"
#include "val/include/val_tdisp.h"

#define TEST_NAME "cda_rfrfjg_tdi_snoop_access"
#define TEST_DESC "TDI snoops only directly accessible PAs       "
#define TEST_RULE "RFRFJG"

#define DECODER_SLOT CXL_HDM_DECODER_SLOT_DEFAULT
#define RMECDA_CTL1_TDISP_EN_MASK 0x1u
#define RMECDA_CTL1_LINK_STR_LOCK_MASK (1u << 1)

#define RFRFJG_PAGE_A 0u
#define RFRFJG_PAGE_B 1u
#define RFRFJG_PAGE_COUNT 2u

#if ENABLE_SPDM

typedef struct {
  uint32_t root_bdf;
  uint32_t root_index;
  uint32_t endpoint_index;
  uint32_t endpoint_bdf;
  uint32_t host_index;
  uint64_t dcm_hpa[RFRFJG_PAGE_COUNT];
  uint64_t endpoint_decoder_base_orig;
  uint64_t endpoint_decoder_size_orig;
  uint32_t endpoint_decoder_changed;
  uint32_t rmecda_ctl1_orig;
  uint32_t rmecda_ctl1_valid;
  uint32_t rmecda_ctl3_orig;
  uint32_t rmecda_ctl3_valid;
  uint32_t rmecda_ctl4_orig;
  uint32_t rmecda_ctl4_valid;
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
  context->host_index = CXL_COMPONENT_INVALID_INDEX;
  context->root_index = CXL_COMPONENT_INVALID_INDEX;
}

static uint32_t
restore_context_state(const TEST_CONTEXT *context)
{
  uint32_t ctl1_unlocked;
  uint32_t readback;
  uint32_t status;

  if (context == NULL)
    return ACS_STATUS_ERR;

  status = ACS_STATUS_PASS;
  readback = 0u;

  if ((context->rmecda_ctl1_valid != 0u) &&
      (context->rmecda_cfg_va != 0u))
  {
    /* CTL3/CTL4 cannot be restored while LINK_STR_LOCK remains asserted. */
    ctl1_unlocked = context->rmecda_ctl1_orig &
                    ~RMECDA_CTL1_LINK_STR_LOCK_MASK;
    if (val_memory_write_el3(context->rmecda_cfg_va +
                             context->rmecda_cap_base +
                             RMECDA_CTL1_OFFSET,
                             ctl1_unlocked) != ACS_STATUS_PASS)
      status = ACS_STATUS_ERR;
  }

  if ((context->rmecda_ctl3_valid != 0u) &&
      ((context->rmecda_cfg_va == 0u) ||
       (val_memory_write_el3(context->rmecda_cfg_va +
                             context->rmecda_cap_base +
                             RMECDA_CTL3_OFFSET,
                             context->rmecda_ctl3_orig) != ACS_STATUS_PASS)))
    status = ACS_STATUS_ERR;

  if ((context->rmecda_ctl4_valid != 0u) &&
      ((context->rmecda_cfg_va == 0u) ||
       (val_memory_write_el3(context->rmecda_cfg_va +
                             context->rmecda_cap_base +
                             RMECDA_CTL4_OFFSET,
                             context->rmecda_ctl4_orig) != ACS_STATUS_PASS)))
    status = ACS_STATUS_ERR;

  if (context->rmecda_ctl1_valid != 0u)
  {
    if ((context->rmecda_cfg_va == 0u) ||
        (val_memory_write_el3(context->rmecda_cfg_va +
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
                " RFRFJG: RMECDA_CTL1 restore readback 0x%x",
                (uint64_t)readback);
      status = ACS_STATUS_ERR;
    }
  }

  if ((context->rmecda_ctl3_valid != 0u) &&
      ((val_memory_read_el3(context->rmecda_cfg_va +
                            context->rmecda_cap_base +
                            RMECDA_CTL3_OFFSET,
                            &readback) != ACS_STATUS_PASS) ||
       (readback != context->rmecda_ctl3_orig)))
  {
    val_print(ACS_PRINT_WARN,
              " RFRFJG: RMECDA_CTL3 restore readback 0x%x",
              (uint64_t)readback);
    status = ACS_STATUS_ERR;
  }

  if ((context->rmecda_ctl4_valid != 0u) &&
      ((val_memory_read_el3(context->rmecda_cfg_va +
                            context->rmecda_cap_base +
                            RMECDA_CTL4_OFFSET,
                            &readback) != ACS_STATUS_PASS) ||
       (readback != context->rmecda_ctl4_orig)))
  {
    val_print(ACS_PRINT_WARN,
              " RFRFJG: RMECDA_CTL4 restore readback 0x%x",
              (uint64_t)readback);
    status = ACS_STATUS_ERR;
  }

  if ((context->endpoint_decoder_changed != 0u) &&
      (context->endpoint_decoder_size_orig != 0u) &&
      (val_cxl_program_component_decoder(context->endpoint_index,
                                         DECODER_SLOT,
                                         context->endpoint_decoder_base_orig,
                                         context->endpoint_decoder_size_orig)
       != ACS_STATUS_PASS))
  {
    val_print(ACS_PRINT_WARN, " RFRFJG: endpoint decoder restore failed", 0);
    status = ACS_STATUS_ERR;
  }

  return status;
}

static uint32_t
select_test_pages(uint64_t window_base,
                  uint64_t window_size,
                  uint64_t *page_a,
                  uint64_t *page_b)
{
  uint64_t page_size;
  uint64_t window_end;

  if ((page_a == NULL) || (page_b == NULL))
    return ACS_STATUS_ERR;

  page_size = (uint64_t)val_memory_page_size();
  if (page_size == 0u)
    return ACS_STATUS_ERR;

  window_end = window_base + window_size;
  if (window_end < window_base)
    return ACS_STATUS_ERR;

  if ((window_size < (RFRFJG_PAGE_COUNT * page_size)) ||
      ((window_end - page_size) < page_size))
    return ACS_STATUS_SKIP;

  /* Use high pages to avoid CFMWS-backed allocations made from low addresses. */
  *page_b = (window_end - page_size) & ~(page_size - 1u);
  *page_a = *page_b - page_size;
  if ((*page_a < window_base) || ((*page_b + page_size) > window_end))
    return ACS_STATUS_SKIP;

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

  for (uint32_t root_idx = 0u; root_idx < table->num_entries; ++root_idx)
  {
    TEST_CONTEXT candidate;
    const CXL_COMPONENT_ENTRY *endpoint;
    const CXL_COMPONENT_ENTRY *root_port;
    uint32_t ctl1_programmed;
    uint32_t ctl1_readback;
    uint32_t endpoint_bdf;
    uint32_t endpoint_rid;
    uint32_t status;
    uint64_t window_base;
    uint64_t window_size;

    init_context(&candidate);
    root_port = &table->component[root_idx];
    if ((root_port->role != CXL_COMPONENT_ROLE_ROOT_PORT) ||
        (root_port->chi_c2c_supported == 0u))
      continue;

    status = val_cda_find_downstream_chi_c2c_exerciser_endpoint(root_port->bdf,
                                                                &endpoint_bdf);
    if (status != ACS_STATUS_PASS)
      continue;

    if (val_cxl_find_component_index_by_bdf(endpoint_bdf,
                                            &candidate.endpoint_index)
        != ACS_STATUS_PASS)
      continue;

    endpoint = &table->component[candidate.endpoint_index];
    if ((endpoint->role != CXL_COMPONENT_ROLE_ENDPOINT) ||
        (endpoint->chi_c2c_supported == 0u) ||
        (endpoint->component_reg_base == 0u))
      continue;

    candidate.root_bdf = root_port->bdf;
    candidate.root_index = root_idx;
    candidate.endpoint_bdf = endpoint_bdf;
    candidate.host_index = root_port->host_bridge_index;

    if ((candidate.host_index == CXL_COMPONENT_INVALID_INDEX) ||
        (val_pcie_find_cda_capability(candidate.root_bdf,
                                      &candidate.rmecda_cap_base)
         != ACS_STATUS_PASS) ||
        (val_cxl_select_cfmws_window(candidate.host_index,
                                     &window_base,
                                     &window_size) != ACS_STATUS_PASS))
      continue;

    if (val_cxl_get_component_decoder(candidate.endpoint_index,
                                      DECODER_SLOT,
                                      &candidate.endpoint_decoder_base_orig,
                                      &candidate.endpoint_decoder_size_orig) != 0u)
      continue;

    if (candidate.endpoint_decoder_size_orig == 0u)
      continue;

    if (val_cxl_enable_mem(candidate.endpoint_bdf) != ACS_STATUS_PASS)
    {
      if (restore_context_state(&candidate) != ACS_STATUS_PASS)
        return ACS_STATUS_ERR;
      continue;
    }

    /* Program the endpoint decoder only when its current range differs. */
    if ((candidate.endpoint_decoder_base_orig != window_base) ||
        (candidate.endpoint_decoder_size_orig != window_size))
    {
      if (val_cxl_program_component_decoder(candidate.endpoint_index,
                                            DECODER_SLOT,
                                            window_base,
                                            window_size) != ACS_STATUS_PASS)
      {
        if (restore_context_state(&candidate) != ACS_STATUS_PASS)
          return ACS_STATUS_ERR;
        continue;
      }
      candidate.endpoint_decoder_changed = 1u;
    }

    status = select_test_pages(window_base,
                               window_size,
                               &candidate.dcm_hpa[RFRFJG_PAGE_A],
                               &candidate.dcm_hpa[RFRFJG_PAGE_B]);
    if (status != ACS_STATUS_PASS)
    {
      if (restore_context_state(&candidate) != ACS_STATUS_PASS)
        return ACS_STATUS_ERR;
      continue;
    }

    if (val_pcie_map_root_config(candidate.root_bdf,
                                 &candidate.rmecda_cfg_va) != ACS_STATUS_PASS)
    {
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
    candidate.rmecda_ctl1_valid = 1u;

    if (val_memory_read_el3(candidate.rmecda_cfg_va +
                            candidate.rmecda_cap_base +
                            RMECDA_CTL3_OFFSET,
                            &candidate.rmecda_ctl3_orig) != ACS_STATUS_PASS)
    {
      if (restore_context_state(&candidate) != ACS_STATUS_PASS)
        return ACS_STATUS_ERR;
      continue;
    }
    candidate.rmecda_ctl3_valid = 1u;

    if (val_memory_read_el3(candidate.rmecda_cfg_va +
                            candidate.rmecda_cap_base +
                            RMECDA_CTL4_OFFSET,
                            &candidate.rmecda_ctl4_orig) != ACS_STATUS_PASS)
    {
      if (restore_context_state(&candidate) != ACS_STATUS_PASS)
        return ACS_STATUS_ERR;
      continue;
    }
    candidate.rmecda_ctl4_valid = 1u;

    /* Program the selected TDI's RID before asserting LINK_STR_LOCK. */
    ctl1_programmed = candidate.rmecda_ctl1_orig &
                      ~RMECDA_CTL1_LINK_STR_LOCK_MASK;
    if ((val_memory_write_el3(candidate.rmecda_cfg_va +
                              candidate.rmecda_cap_base +
                              RMECDA_CTL1_OFFSET,
                              ctl1_programmed) != ACS_STATUS_PASS) ||
        (val_memory_read_el3(candidate.rmecda_cfg_va +
                             candidate.rmecda_cap_base +
                             RMECDA_CTL1_OFFSET,
                             &ctl1_readback) != ACS_STATUS_PASS) ||
        ((ctl1_readback & RMECDA_CTL1_LINK_STR_LOCK_MASK) != 0u))
    {
      if (restore_context_state(&candidate) != ACS_STATUS_PASS)
        return ACS_STATUS_ERR;
      continue;
    }

    endpoint_rid = (uint32_t)PCIE_CREATE_BDF_PACKED(candidate.endpoint_bdf);
    status = val_cda_program_rid_range(candidate.rmecda_cfg_va,
                                       candidate.rmecda_cap_base,
                                       candidate.rmecda_ctl3_orig,
                                       candidate.rmecda_ctl4_orig,
                                       endpoint_rid,
                                       endpoint_rid,
                                       1u);
    if (status != ACS_STATUS_PASS)
    {
      val_print(ACS_PRINT_DEBUG,
                " RFRFJG: RID range programming status %u",
                (uint64_t)status);
      if (restore_context_state(&candidate) != ACS_STATUS_PASS)
        return ACS_STATUS_ERR;
      if (status == ACS_STATUS_ERR)
        return ACS_STATUS_ERR;
      continue;
    }

    ctl1_programmed = candidate.rmecda_ctl1_orig |
                      RMECDA_CTL1_TDISP_EN_MASK |
                      RMECDA_CTL1_LINK_STR_LOCK_MASK;
    ctl1_readback = candidate.rmecda_ctl1_orig;

    if ((val_memory_write_el3(candidate.rmecda_cfg_va +
                              candidate.rmecda_cap_base +
                              RMECDA_CTL1_OFFSET,
                              ctl1_programmed) != ACS_STATUS_PASS) ||
        (val_memory_read_el3(candidate.rmecda_cfg_va +
                             candidate.rmecda_cap_base +
                             RMECDA_CTL1_OFFSET,
                             &ctl1_readback) != ACS_STATUS_PASS))
    {
      if (restore_context_state(&candidate) != ACS_STATUS_PASS)
        return ACS_STATUS_ERR;
      continue;
    }

    if ((ctl1_readback &
         (RMECDA_CTL1_TDISP_EN_MASK | RMECDA_CTL1_LINK_STR_LOCK_MASK)) !=
        (RMECDA_CTL1_TDISP_EN_MASK | RMECDA_CTL1_LINK_STR_LOCK_MASK))
    {
      if (restore_context_state(&candidate) != ACS_STATUS_PASS)
        return ACS_STATUS_ERR;
      continue;
    }

    val_print(ACS_PRINT_INFO, " RFRFJG: selected RP 0x%x",
              (uint64_t)candidate.root_bdf);
    val_print(ACS_PRINT_INFO, " RFRFJG: selected TDI EP 0x%x",
              (uint64_t)candidate.endpoint_bdf);
    val_print(ACS_PRINT_INFO, " RFRFJG: permitted TDI RID 0x%x",
              (uint64_t)endpoint_rid);
    val_print(ACS_PRINT_INFO, " RFRFJG: DCM PA_A 0x%llx",
              candidate.dcm_hpa[RFRFJG_PAGE_A]);
    val_print(ACS_PRINT_INFO, " RFRFJG: DCM PA_B 0x%llx",
              candidate.dcm_hpa[RFRFJG_PAGE_B]);

    *context = candidate;
    return ACS_STATUS_PASS;
  }

  return ACS_STATUS_SKIP;
}

static uint32_t
set_realm_assignment(uint32_t endpoint_bdf, uint64_t target_hpa, uint32_t assigned)
{
  return val_cxl_exerciser_execute_cmd(endpoint_bdf,
                                       CXL_CMD_OP_DCM_SET_REALM_ASSIGNMENT,
                                       target_hpa,
                                       assigned,
                                       NULL);
}

static uint32_t
check_allowed_snoop(const TEST_CONTEXT *context, uint32_t page)
{
  uint32_t result;
  uint32_t status;

  status = val_cda_tdi_snoop_attempt(context->endpoint_bdf,
                                     context->dcm_hpa[page],
                                     REALM_PAS,
                                     &result);
  if (status == ACS_STATUS_SKIP)
  {
    val_print(ACS_PRINT_INFO,
              " RFRFJG: positive-control snoop observation unavailable for PA 0x%llx",
              context->dcm_hpa[page]);
    return ACS_STATUS_SKIP;
  }

  if (status != ACS_STATUS_PASS)
    return ACS_STATUS_FAIL;

  if ((result & CXL_SNOOP_RESULT_EMITTED) == 0u)
  {
    val_print(ACS_PRINT_INFO,
              " RFRFJG: positive-control TDI snoop blocked for PA 0x%llx",
              context->dcm_hpa[page]);
    return ACS_STATUS_SKIP;
  }

  val_print(ACS_PRINT_INFO,
            " RFRFJG: allowed TDI snoop emitted for PA 0x%llx",
            context->dcm_hpa[page]);
  return ACS_STATUS_PASS;
}

static uint32_t
check_forbidden_snoop(const TEST_CONTEXT *context, uint32_t page)
{
  uint32_t result;
  uint32_t status;

  status = val_cda_tdi_snoop_attempt(context->endpoint_bdf,
                                     context->dcm_hpa[page],
                                     REALM_PAS,
                                     &result);
  if (status == ACS_STATUS_SKIP)
  {
    /* An error completion does not prove that the TDI prevented emission. */
    val_print(ACS_PRINT_INFO,
              " RFRFJG: local snoop blocking is not observable for PA 0x%llx",
              context->dcm_hpa[page]);
    return ACS_STATUS_SKIP;
  }

  if (status != ACS_STATUS_PASS)
    return ACS_STATUS_FAIL;

  if ((result & CXL_SNOOP_RESULT_EMITTED) != 0u)
  {
    val_print(ACS_PRINT_ERR,
              " RFRFJG: TDI emitted snoop to unassigned PA 0x%llx",
              context->dcm_hpa[page]);
    return ACS_STATUS_FAIL;
  }

  if ((result & CXL_SNOOP_RESULT_BLOCKED) == 0u)
    return ACS_STATUS_FAIL;

  val_print(ACS_PRINT_INFO,
            " RFRFJG: TDI snoop to unassigned PA 0x%llx was blocked",
            context->dcm_hpa[page]);
  return ACS_STATUS_PASS;
}

static uint32_t
exercise_rule(TEST_CONTEXT *context)
{
  pci_tdisp_interface_id_t interface_id;
  val_spdm_context_t spdm_ctx;
  uint32_t assigned_mask;
  uint32_t ide_enabled;
  uint32_t result;
  uint32_t session_id;
  uint32_t session_open;
  uint32_t status;

  if (context == NULL)
    return ACS_STATUS_ERR;

  assigned_mask = 0u;
  ide_enabled = 0u;
  result = ACS_STATUS_FAIL;
  session_id = 0u;
  session_open = 0u;
  val_memory_set(&spdm_ctx, sizeof(spdm_ctx), 0);

  status = val_tdisp_establish_run(context->endpoint_bdf,
                                   &spdm_ctx,
                                   &session_id,
                                   &interface_id);
  if (status != ACS_STATUS_PASS)
  {
    val_print(ACS_PRINT_INFO, " RFRFJG: unable to place TDI in RUN", 0);
    return ACS_STATUS_SKIP;
  }
  session_open = 1u;

  status = val_cxl_ide_establish_link(context->root_index,
                                      context->endpoint_index,
                                      &spdm_ctx,
                                      session_id);
  if (status != ACS_STATUS_PASS)
  {
    val_print(ACS_PRINT_INFO, " RFRFJG: unable to establish IDE stream", 0);
    result = (status == ACS_STATUS_SKIP) ? ACS_STATUS_SKIP : ACS_STATUS_FAIL;
    goto cleanup;
  }
  ide_enabled = 1u;

  /* Establish a known state: neither page is directly accessible. */
  for (uint32_t page = 0u; page < RFRFJG_PAGE_COUNT; ++page)
  {
    if (set_realm_assignment(context->endpoint_bdf,
                             context->dcm_hpa[page],
                             0u) != ACS_STATUS_PASS)
    {
      val_print(ACS_PRINT_INFO,
                " RFRFJG: Realm assignment hook unavailable",
                0);
      result = ACS_STATUS_SKIP;
      goto cleanup;
    }
  }

  /* PA_A allowed, PA_B forbidden. */
  if (set_realm_assignment(context->endpoint_bdf,
                           context->dcm_hpa[RFRFJG_PAGE_A],
                           1u) != ACS_STATUS_PASS)
  {
    result = ACS_STATUS_SKIP;
    goto cleanup;
  }
  assigned_mask |= (1u << RFRFJG_PAGE_A);

  /*
   * Calibrate the snoop path only after RUN, IDE, and page permissions are
   * established. A rejected request before setup cannot identify an absent
   * command or distinguish it from a security-policy rejection.
   */
  status = check_allowed_snoop(context, RFRFJG_PAGE_A);
  if (status != ACS_STATUS_PASS)
  {
    result = status;
    goto cleanup;
  }

  status = check_forbidden_snoop(context, RFRFJG_PAGE_B);
  if (status != ACS_STATUS_PASS)
  {
    result = status;
    goto cleanup;
  }

  /* Swap the assignment and repeat the permission checks for both pages. */
  if (set_realm_assignment(context->endpoint_bdf,
                           context->dcm_hpa[RFRFJG_PAGE_A],
                           0u) != ACS_STATUS_PASS)
    goto cleanup;
  assigned_mask &= ~(1u << RFRFJG_PAGE_A);

  if (set_realm_assignment(context->endpoint_bdf,
                           context->dcm_hpa[RFRFJG_PAGE_B],
                           1u) != ACS_STATUS_PASS)
    goto cleanup;
  assigned_mask |= (1u << RFRFJG_PAGE_B);

  status = check_allowed_snoop(context, RFRFJG_PAGE_B);
  if (status != ACS_STATUS_PASS)
  {
    result = status;
    goto cleanup;
  }

  status = check_forbidden_snoop(context, RFRFJG_PAGE_A);
  if (status != ACS_STATUS_PASS)
  {
    result = status;
    goto cleanup;
  }

  result = ACS_STATUS_PASS;

cleanup:
  for (uint32_t page = 0u; page < RFRFJG_PAGE_COUNT; ++page)
  {
    if ((assigned_mask & (1u << page)) != 0u)
    {
      if (set_realm_assignment(context->endpoint_bdf,
                               context->dcm_hpa[page],
                               0u) != ACS_STATUS_PASS)
      {
        val_print(ACS_PRINT_ERR,
                  " RFRFJG: failed to clear Realm assignment for PA 0x%llx",
                  context->dcm_hpa[page]);
        result = ACS_STATUS_FAIL;
      }
    }
  }

  if (ide_enabled != 0u)
  {
    if (val_cxl_ide_disable_link(context->root_index,
                                 context->endpoint_index,
                                 &spdm_ctx,
                                 session_id) != ACS_STATUS_PASS)
    {
      val_print(ACS_PRINT_ERR, " RFRFJG: cleanup IDE disable failed", 0);
      result = ACS_STATUS_FAIL;
    }
    ide_enabled = 0u;
  }

  if (session_open != 0u)
  {
    if (val_tdisp_stop_if_needed(&spdm_ctx,
                                 session_id,
                                 &interface_id,
                                 0u) != ACS_STATUS_PASS)
    {
      val_print(ACS_PRINT_ERR, " RFRFJG: cleanup TDISP session failed", 0);
      result = ACS_STATUS_FAIL;
    }
    session_open = 0u;
  }

  return result;
}

static void
payload(void)
{
  TEST_CONTEXT context;
  uint32_t cleanup_status;
  uint32_t pe_index;
  uint32_t status;

  pe_index = val_pe_get_index_mpid(val_pe_get_mpid());
  status = prepare_context(&context);
  if (status == ACS_STATUS_SKIP)
  {
    val_print(ACS_PRINT_INFO, " RFRFJG: no suitable CHI-C2C CDA context", 0);
    val_set_status(pe_index, "SKIP", 01);
    return;
  }

  if (status != ACS_STATUS_PASS)
  {
    val_set_status(pe_index, "FAIL", 01);
    return;
  }

  status = exercise_rule(&context);
  cleanup_status = restore_context_state(&context);
  if (cleanup_status != ACS_STATUS_PASS)
  {
    val_print(ACS_PRINT_ERR, " RFRFJG: platform cleanup failed", 0);
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
  val_print(ACS_PRINT_INFO, " RFRFJG: SPDM/TDISP support not enabled", 0);
  val_set_status(pe_index, "SKIP", 01);
}

#endif

uint32_t
cda_rfrfjg_tdi_snoop_access_entry(uint32_t num_pe)
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
