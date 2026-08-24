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

#define TEST_NAME "cda_rqwnbn_error_poison_response"
#define TEST_DESC "TDI ERROR cached Realm snoop response is poisoned"
#define TEST_RULE "RQWNBN"

#define DECODER_SLOT 0u
#define AER_POISONED_TLP (1u << 12)

#define RMECDA_CTL1_TDISP_EN_MASK 0x1u
#define RMECDA_CTL1_LINK_STR_LOCK_MASK (1u << 1)

#define RQWNBN_SNOOP_SEED_VALUE     0xA55A0123456789EFULL
#define RQWNBN_WRITEBACK_SEED_VALUE 0x5AA5FEDCBA987610ULL
#define RQWNBN_POISON_FIXED_VALUE   0xFFFFFFFFFFFFFFFFULL

#if ENABLE_SPDM

typedef struct {
  uint32_t host_index;
  uint32_t root_index;
  uint32_t root_bdf;
  uint32_t endpoint_index;
  uint32_t endpoint_bdf;
  uint64_t window_base;
  uint64_t window_size;
  uint64_t host_decoder_base_orig;
  uint64_t host_decoder_size_orig;
  uint64_t endpoint_decoder_base_orig;
  uint64_t endpoint_decoder_size_orig;
  uint32_t host_target_low_orig;
  uint32_t host_target_high_orig;
  uint32_t host_target_valid;
  uint32_t rmecda_ctl1_orig;
  uint32_t rmecda_ctl1_valid;
  uint32_t rmecda_cap_base;
  uint64_t rmecda_cfg_va;
  uint32_t aer_offset;
} TEST_CONTEXT;

static void
init_context(TEST_CONTEXT *context)
{
  if (context == NULL)
    return;

  val_memory_set(context, sizeof(*context), 0);
  context->host_index = CXL_COMPONENT_INVALID_INDEX;
  context->root_index = CXL_COMPONENT_INVALID_INDEX;
  context->endpoint_index = CXL_COMPONENT_INVALID_INDEX;
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
    if (context->rmecda_cfg_va != 0u)
    {
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
                  " RQWNBN: RMECDA_CTL1 root restore readback 0x%x",
                  (uint64_t)readback);
        restore_status = ACS_STATUS_ERR;
      }
    }
    else
    {
      val_pcie_write_cfg(context->root_bdf,
                         context->rmecda_cap_base + RMECDA_CTL1_OFFSET,
                         context->rmecda_ctl1_orig);

      if ((val_pcie_read_cfg(context->root_bdf,
                             context->rmecda_cap_base + RMECDA_CTL1_OFFSET,
                             &readback) != PCIE_SUCCESS) ||
          (readback != context->rmecda_ctl1_orig))
      {
        val_print(ACS_PRINT_WARN,
                  " RQWNBN: RMECDA_CTL1 restore readback 0x%x",
                  (uint64_t)readback);
        restore_status = ACS_STATUS_ERR;
      }
    }
  }

  if ((context->endpoint_index != CXL_COMPONENT_INVALID_INDEX) &&
      (context->endpoint_decoder_size_orig != 0u) &&
      (val_cxl_program_component_decoder(context->endpoint_index,
                                         DECODER_SLOT,
                                         context->endpoint_decoder_base_orig,
                                         context->endpoint_decoder_size_orig)
       != ACS_STATUS_PASS))
  {
    restore_status = ACS_STATUS_ERR;
  }

  if (val_cxl_restore_host_decoder(context->host_index,
                                   DECODER_SLOT,
                                   context->host_decoder_base_orig,
                                   context->host_decoder_size_orig,
                                   context->host_target_valid,
                                   context->host_target_low_orig,
                                   context->host_target_high_orig)
      != ACS_STATUS_PASS)
  {
    restore_status = ACS_STATUS_ERR;
  }

  return restore_status;
}

static uint32_t
select_test_pages(uint64_t window_base,
                  uint64_t window_size,
                  uint64_t *snoop_hpa_out,
                  uint64_t *writeback_hpa_out)
{
  uint64_t page_size;
  uint64_t window_end;
  uint64_t snoop_hpa;
  uint64_t writeback_hpa;

  if ((snoop_hpa_out == NULL) || (writeback_hpa_out == NULL))
    return ACS_STATUS_ERR;

  page_size = (uint64_t)val_memory_page_size();
  if (page_size == 0u)
    return ACS_STATUS_ERR;

  if (window_size < (2u * page_size))
    return ACS_STATUS_SKIP;

  window_end = window_base + window_size;
  if (window_end < window_base)
    return ACS_STATUS_ERR;

  snoop_hpa = (window_end - page_size) & ~(page_size - 1u);
  if ((snoop_hpa < window_base) || ((snoop_hpa + page_size) > window_end))
    return ACS_STATUS_SKIP;

  writeback_hpa = snoop_hpa - page_size;
  if ((writeback_hpa < window_base) || ((writeback_hpa + page_size) > snoop_hpa))
    return ACS_STATUS_SKIP;

  *snoop_hpa_out = snoop_hpa;
  *writeback_hpa_out = writeback_hpa;
  return ACS_STATUS_PASS;
}

static uint32_t
force_tdi_error(val_spdm_context_t *spdm_ctx,
                uint32_t session_id)
{
  if ((spdm_ctx == NULL) || (session_id == 0u))
    return ACS_STATUS_ERR;

  /*
   * Closing the SPDM session while the interface is CONFIG_LOCKED or RUN is
   * one of the TDI ERROR transition paths implemented by the model. After this
   * point the secure session is gone, so the caller must not issue STOP_INTERFACE
   * during cleanup.
   */
  return val_spdm_session_close(spdm_ctx, session_id);
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
   * Walk CHI-C2C Root Ports first, then use the CDA helper to find a
   * downstream CHI-C2C exerciser endpoint. This matches the other CDA tests
   * and avoids depending on a separate CXL exerciser table being populated.
   */
  for (uint32_t root_idx = 0u; root_idx < table->num_entries; ++root_idx)
  {
    TEST_CONTEXT candidate;
    const CXL_COMPONENT_ENTRY *root_port;
    const CXL_COMPONENT_ENTRY *endpoint;
    uint32_t endpoint_bdf;
    uint32_t dev_properties;
    uint32_t status;
    uint32_t ctl1_programmed;
    uint32_t ctl1_readback;

    init_context(&candidate);

    root_port = &table->component[root_idx];
    if (root_port->role != CXL_COMPONENT_ROLE_ROOT_PORT)
      continue;

    val_print(ACS_PRINT_DEBUG,
              " RQWNBN: considering RP BDF 0x%x",
              (uint64_t)root_port->bdf);
    val_print(ACS_PRINT_DEBUG,
              " RQWNBN: RP chi_c2c flag %u",
              (uint64_t)root_port->chi_c2c_supported);

    if (root_port->chi_c2c_supported == 0u)
      continue;

    status = val_cda_find_downstream_chi_c2c_exerciser_endpoint(root_port->bdf,
                                                                &endpoint_bdf);
    if (status != ACS_STATUS_PASS)
    {
      val_print(ACS_PRINT_DEBUG,
                " RQWNBN: no downstream CHI-C2C exerciser for RP 0x%x",
                (uint64_t)root_port->bdf);
      val_print(ACS_PRINT_DEBUG,
                " RQWNBN: downstream endpoint search status %u",
                (uint64_t)status);
      continue;
    }

    if (val_cxl_find_component_index_by_bdf(endpoint_bdf,
                                            &candidate.endpoint_index)
        != ACS_STATUS_PASS)
    {
      val_print(ACS_PRINT_DEBUG,
                " RQWNBN: endpoint 0x%x missing from component table",
                (uint64_t)endpoint_bdf);
      continue;
    }

    endpoint = &table->component[candidate.endpoint_index];
    if ((endpoint->role != CXL_COMPONENT_ROLE_ENDPOINT) ||
        (endpoint->chi_c2c_supported == 0u))
    {
      val_print(ACS_PRINT_DEBUG,
                " RQWNBN: endpoint 0x%x is not CHI-C2C endpoint",
                (uint64_t)endpoint_bdf);
      continue;
    }

    /* Cache-line setup uses direct coherent Realm host accesses. */
    if ((val_tdisp_get_device_properties(endpoint_bdf, &dev_properties)
         != ACS_STATUS_PASS) ||
        ((dev_properties & VAL_TDISP_DEV_PROP_PAS_CHECK) == 0u))
      continue;

    candidate.root_index = root_idx;
    candidate.root_bdf = root_port->bdf;
    candidate.endpoint_bdf = endpoint_bdf;

    if (val_pcie_find_cda_capability(candidate.root_bdf, &candidate.rmecda_cap_base)
        != PCIE_SUCCESS)
    {
      val_print(ACS_PRINT_DEBUG,
                " RQWNBN: root 0x%x lacks RME-CDA capability",
                (uint64_t)candidate.root_bdf);
      continue;
    }

    if (val_pcie_find_capability(candidate.root_bdf,
                                 PCIE_ECAP,
                                 ECID_AER,
                                 &candidate.aer_offset) != PCIE_SUCCESS)
    {
      val_print(ACS_PRINT_DEBUG,
                " RQWNBN: root 0x%x lacks AER capability",
                (uint64_t)candidate.root_bdf);
      continue;
    }

    candidate.host_index = root_port->host_bridge_index;
    if (candidate.host_index == CXL_COMPONENT_INVALID_INDEX)
    {
      val_print(ACS_PRINT_DEBUG,
                " RQWNBN: root 0x%x missing host bridge index",
                (uint64_t)candidate.root_bdf);
      continue;
    }

    if (val_cxl_select_cfmws_window(candidate.host_index,
                                    &candidate.window_base,
                                    &candidate.window_size) != ACS_STATUS_PASS)
    {
      val_print(ACS_PRINT_DEBUG,
                " RQWNBN: host index %u has no CFMWS window",
                (uint64_t)candidate.host_index);
      continue;
    }

    if (val_cxl_get_decoder(candidate.host_index,
                            DECODER_SLOT,
                            &candidate.host_decoder_base_orig,
                            &candidate.host_decoder_size_orig) != 0u)
    {
      (void)restore_context_state(&candidate);
      val_print(ACS_PRINT_DEBUG,
                " RQWNBN: failed to save host decoder state",
                0);
      continue;
    }

    if (val_cxl_get_host_decoder_target(candidate.host_index,
                                        DECODER_SLOT,
                                        &candidate.host_target_low_orig,
                                        &candidate.host_target_high_orig) != 0u)
    {
      (void)restore_context_state(&candidate);
      val_print(ACS_PRINT_DEBUG,
                " RQWNBN: failed to save host decoder target",
                0);
      continue;
    }
    candidate.host_target_valid = 1u;

    if (val_cxl_get_component_decoder(candidate.endpoint_index,
                                      DECODER_SLOT,
                                      &candidate.endpoint_decoder_base_orig,
                                      &candidate.endpoint_decoder_size_orig)
        != 0u)
    {
      (void)restore_context_state(&candidate);
      val_print(ACS_PRINT_DEBUG,
                " RQWNBN: failed to save endpoint decoder state",
                0);
      continue;
    }

    if (val_pcie_read_cfg(candidate.root_bdf,
                          candidate.rmecda_cap_base + RMECDA_CTL1_OFFSET,
                          &candidate.rmecda_ctl1_orig) != PCIE_SUCCESS)
    {
      (void)restore_context_state(&candidate);
      continue;
    }

    val_print(ACS_PRINT_DEBUG,
              " RQWNBN: RMECDA_CTL1 initial readback 0x%x",
              (uint64_t)candidate.rmecda_ctl1_orig);

    if ((candidate.rmecda_ctl1_orig &
         (RMECDA_CTL1_TDISP_EN_MASK | RMECDA_CTL1_LINK_STR_LOCK_MASK)) != 0u)
    {
      /*
       * RQWNBN owns its setup and does not consume state from any earlier CDA
       * test. If RMECDA is already enabled/locked, skip this Root Port rather
       * than depending on a preserved route or alias.
       */
      val_print(ACS_PRINT_DEBUG,
                " RQWNBN: RMECDA_CTL1 not clean 0x%x",
                (uint64_t)candidate.rmecda_ctl1_orig);
      continue;
    }

    if (val_pcie_map_root_config(candidate.root_bdf,
                                 &candidate.rmecda_cfg_va) != ACS_STATUS_PASS)
    {
      (void)restore_context_state(&candidate);
      val_print(ACS_PRINT_DEBUG,
                " RQWNBN: config map failed for RP 0x%x",
                (uint64_t)candidate.root_bdf);
      continue;
    }

    if (val_memory_read_el3(candidate.rmecda_cfg_va +
                            candidate.rmecda_cap_base +
                            RMECDA_CTL1_OFFSET,
                            &candidate.rmecda_ctl1_orig) != ACS_STATUS_PASS)
    {
      (void)restore_context_state(&candidate);
      continue;
    }

    candidate.rmecda_ctl1_valid = 1u;
    if ((candidate.rmecda_ctl1_orig &
         (RMECDA_CTL1_TDISP_EN_MASK | RMECDA_CTL1_LINK_STR_LOCK_MASK)) != 0u)
    {
      (void)restore_context_state(&candidate);
      val_print(ACS_PRINT_DEBUG,
                " RQWNBN: RMECDA_CTL1 root state not clean 0x%x",
                (uint64_t)candidate.rmecda_ctl1_orig);
      continue;
    }

    if (val_cxl_enable_mem(candidate.endpoint_bdf) != ACS_STATUS_PASS)
    {
      (void)restore_context_state(&candidate);
      val_print(ACS_PRINT_DEBUG,
                " RQWNBN: CXL.mem enable failed for EP 0x%x",
                (uint64_t)candidate.endpoint_bdf);
      continue;
    }

    if (val_cxl_program_host_decoder_for_root(candidate.root_bdf,
                                             candidate.host_index,
                                             DECODER_SLOT,
                                             candidate.window_base,
                                             candidate.window_size) != ACS_STATUS_PASS)
    {
      (void)restore_context_state(&candidate);
      val_print(ACS_PRINT_DEBUG,
                " RQWNBN: failed to program host decoder target",
                0);
      continue;
    }

    if (val_cxl_program_component_decoder(candidate.endpoint_index,
                                          DECODER_SLOT,
                                          candidate.window_base,
                                          candidate.window_size) != ACS_STATUS_PASS)
    {
      (void)restore_context_state(&candidate);
      val_print(ACS_PRINT_DEBUG,
                " RQWNBN: failed to program endpoint decoder",
                0);
      continue;
    }

    ctl1_programmed = candidate.rmecda_ctl1_orig |
                      RMECDA_CTL1_TDISP_EN_MASK |
                      RMECDA_CTL1_LINK_STR_LOCK_MASK;

    if (val_memory_write_el3(candidate.rmecda_cfg_va +
                             candidate.rmecda_cap_base +
                             RMECDA_CTL1_OFFSET,
                             ctl1_programmed) != ACS_STATUS_PASS)
    {
      (void)restore_context_state(&candidate);
      continue;
    }

    if (val_memory_read_el3(candidate.rmecda_cfg_va +
                            candidate.rmecda_cap_base +
                            RMECDA_CTL1_OFFSET,
                            &ctl1_readback) != ACS_STATUS_PASS)
    {
      (void)restore_context_state(&candidate);
      continue;
    }

    val_print(ACS_PRINT_DEBUG,
              " RQWNBN: RMECDA_CTL1 root-write readback 0x%x",
              (uint64_t)ctl1_readback);

    if ((ctl1_readback &
         (RMECDA_CTL1_TDISP_EN_MASK | RMECDA_CTL1_LINK_STR_LOCK_MASK)) !=
        (RMECDA_CTL1_TDISP_EN_MASK | RMECDA_CTL1_LINK_STR_LOCK_MASK))
    {
      (void)restore_context_state(&candidate);
      val_print(ACS_PRINT_DEBUG,
                " RQWNBN: RMECDA_CTL1 required bits did not stick",
                0);
      continue;
    }

    *context = candidate;
    val_print(ACS_PRINT_INFO, " RQWNBN: selected RP 0x%x", context->root_bdf);
    val_print(ACS_PRINT_INFO, " RQWNBN: selected EP 0x%x", context->endpoint_bdf);
    return ACS_STATUS_PASS;
  }

  return ACS_STATUS_SKIP;
}

static uint32_t
exercise_rule(TEST_CONTEXT *context)
{
  volatile uint64_t *snoop_realm_alias;
  volatile uint64_t *writeback_realm_alias;
  PCIE_ENDPOINT_CFG endpoint_cfg;
  val_spdm_context_t spdm_ctx;
  pci_tdisp_interface_id_t interface_id;
  uint32_t session_id;
  uint32_t session_open;
  uint32_t ide_enabled;
  uint32_t tdi_in_error;
  uint32_t snoop_realm_assigned;
  uint32_t writeback_realm_assigned;
  uint32_t result;
  uint32_t status;
  uint32_t aer_uncorr;
  uint32_t endpoint_cfg_valid;
  uint32_t host_fault;
  uint64_t snoop_hpa;
  uint64_t writeback_hpa;
  uint64_t observed;

  if (context == NULL)
    return ACS_STATUS_ERR;

  status = select_test_pages(context->window_base,
                             context->window_size,
                             &snoop_hpa,
                             &writeback_hpa);
  if (status != ACS_STATUS_PASS)
    return status;

  val_print(ACS_PRINT_INFO, " RQWNBN: snoop DCM HPA 0x%llx", snoop_hpa);
  val_print(ACS_PRINT_INFO, " RQWNBN: writeback DCM HPA 0x%llx", writeback_hpa);

  snoop_realm_alias = NULL;
  writeback_realm_alias = NULL;
  if ((val_memory_map_realm_cacheable_alias(snoop_hpa,
                                             &snoop_realm_alias) != ACS_STATUS_PASS) ||
      (val_memory_map_realm_cacheable_alias(writeback_hpa,
                                             &writeback_realm_alias) != ACS_STATUS_PASS))
    return ACS_STATUS_ERR;

  val_memory_set(&endpoint_cfg, sizeof(endpoint_cfg), 0);
  endpoint_cfg_valid = 0u;
  if (val_pcie_save_endpoint_cfg(context->endpoint_bdf, &endpoint_cfg) == ACS_STATUS_PASS)
    endpoint_cfg_valid = 1u;
  else
    val_print(ACS_PRINT_WARN, " RQWNBN: endpoint config snapshot failed", 0);

  val_memory_set(&spdm_ctx, sizeof(spdm_ctx), 0);
  session_id = 0u;
  session_open = 0u;
  ide_enabled = 0u;
  tdi_in_error = 0u;
  snoop_realm_assigned = 0u;
  writeback_realm_assigned = 0u;
  result = ACS_STATUS_FAIL;

  /*
   * Associate both CFMWS-backed pages with this TDI. Use one page for the
   * snoop-response poison check and one page for the writeback poison check so
   * the two observations do not depend on whether a snoop evicts the cacheline.
   */
  status = val_cxl_exerciser_execute_cmd(context->endpoint_bdf,
                                         CXL_CMD_OP_DCM_SET_REALM_ASSIGNMENT,
                                         snoop_hpa,
                                         1u,
                                         NULL);
  if (status != ACS_STATUS_PASS)
  {
    val_print(ACS_PRINT_INFO, " RQWNBN: Realm DCM assignment hook unavailable", 0);
    result = ACS_STATUS_SKIP;
    goto cleanup;
  }
  snoop_realm_assigned = 1u;

  status = val_cxl_exerciser_execute_cmd(context->endpoint_bdf,
                                         CXL_CMD_OP_DCM_SET_REALM_ASSIGNMENT,
                                         writeback_hpa,
                                         1u,
                                         NULL);
  if (status != ACS_STATUS_PASS)
  {
    val_print(ACS_PRINT_INFO, " RQWNBN: writeback DCM assignment unavailable", 0);
    result = ACS_STATUS_SKIP;
    goto cleanup;
  }
  writeback_realm_assigned = 1u;

  status = val_tdisp_establish_run(context->endpoint_bdf,
                                   &spdm_ctx,
                                   &session_id,
                                   &interface_id);
  if (status != ACS_STATUS_PASS)
  {
    result = ACS_STATUS_SKIP;
    goto cleanup;
  }
  session_open = 1u;

  status = val_cxl_ide_establish_link(context->root_index,
                                      context->endpoint_index,
                                      &spdm_ctx,
                                      session_id);
  if (status != ACS_STATUS_PASS)
  {
    val_print(ACS_PRINT_INFO, " RQWNBN: IDE establish unavailable", 0);
    result = (status == ACS_STATUS_SKIP) ? ACS_STATUS_SKIP : ACS_STATUS_FAIL;
    goto cleanup;
  }
  ide_enabled = 1u;

  /*
   * Create each Realm cache line with a normal cacheable HPA access while the
   * TDI is in RUN and IDE is secure. CACHE_DIRTY only changes the state of an
   * existing line; it does not allocate the line or write Data0 as payload.
   */
  if ((val_cda_seed_realm_cache_line(snoop_realm_alias,
                                     RQWNBN_SNOOP_SEED_VALUE) != ACS_STATUS_PASS) ||
      (val_cda_seed_realm_cache_line(writeback_realm_alias,
                                     RQWNBN_WRITEBACK_SEED_VALUE) != ACS_STATUS_PASS))
  {
    val_print(ACS_PRINT_ERR, " RQWNBN: failed to create Realm cache lines", 0);
    result = ACS_STATUS_FAIL;
    goto cleanup;
  }

  status = val_cxl_exerciser_execute_cmd(context->endpoint_bdf,
                                         CXL_CMD_OP_DCM_CACHE_DIRTY,
                                         snoop_hpa,
                                         0u,
                                         NULL);
  if (status != ACS_STATUS_PASS)
  {
    val_print(ACS_PRINT_INFO,
              " RQWNBN: required Realm cache-line stimulus unavailable",
              0);
    result = ACS_STATUS_SKIP;
    goto cleanup;
  }

  status = val_cxl_exerciser_execute_cmd(context->endpoint_bdf,
                                         CXL_CMD_OP_DCM_CACHE_DIRTY,
                                         writeback_hpa,
                                         0u,
                                         NULL);
  if (status != ACS_STATUS_PASS)
  {
    val_print(ACS_PRINT_INFO,
              " RQWNBN: required Realm cache-line stimulus unavailable",
              0);
    result = ACS_STATUS_SKIP;
    goto cleanup;
  }

  status = force_tdi_error(&spdm_ctx, session_id);
  if (status != ACS_STATUS_PASS)
  {
    result = ACS_STATUS_SKIP;
    goto cleanup;
  }
  session_open = 0u;
  tdi_in_error = 1u;

  val_cxl_aer_clear(context->root_bdf, context->aer_offset);
  observed = 0u;
  host_fault = 0u;
  status = val_memory_read64_el3_protected(snoop_realm_alias, &observed, &host_fault);
  (void)val_cxl_aer_read_uncorr(context->root_bdf,
                                context->aer_offset,
                                &aer_uncorr);
  val_print(ACS_PRINT_DEBUG, " RQWNBN: host read status %u", status);
  val_print(ACS_PRINT_DEBUG, " RQWNBN: host read fault %u", host_fault);
  val_print(ACS_PRINT_DEBUG, " RQWNBN: host read observed 0x%llx", observed);
  val_print(ACS_PRINT_DEBUG, " RQWNBN: AER uncorrectable 0x%x", aer_uncorr);

  if (status != ACS_STATUS_PASS)
  {
    val_print(ACS_PRINT_ERR, " RQWNBN: protected host read failed", 0);
    result = ACS_STATUS_ERR;
    goto cleanup;
  }

  if ((aer_uncorr & AER_POISONED_TLP) == 0u)
  {
    val_print(ACS_PRINT_ERR,
              " RQWNBN: Poisoned TLP not logged after TDI ERROR snoop",
              0);
    result = ACS_STATUS_FAIL;
    goto cleanup;
  }

  /*
   * AER proves that the root port reported a poisoned completion, but the host
   * read must also show poison/fixed data. A synchronous fault is an acceptable
   * platform poison mechanism. If no fault is raised, accept the fixed all-ones
   * poison value, or an implementation-defined poison/fixed value that is not
   * the original dirty data cached by the TDI before ERROR.
   */
  if (host_fault == 0u)
  {
    if (observed == RQWNBN_POISON_FIXED_VALUE)
    {
      val_print(ACS_PRINT_DEBUG,
                " RQWNBN: host read returned fixed poison data 0x%llx",
                observed);
    }
    else if (observed != RQWNBN_SNOOP_SEED_VALUE)
    {
      val_print(ACS_PRINT_INFO,
                " RQWNBN: host read returned non-original poison data 0x%llx",
                observed);
    }
    else
    {
      val_print(ACS_PRINT_ERR,
                " RQWNBN: host read returned clean TDI data 0x%llx",
                observed);
      result = ACS_STATUS_FAIL;
      goto cleanup;
    }
  }

  val_cxl_aer_clear(context->root_bdf, context->aer_offset);
  status = val_cxl_exerciser_execute_cmd(context->endpoint_bdf,
                                         CXL_CMD_OP_DCM_CACHE_WRITEBACK,
                                         writeback_hpa,
                                         0u,
                                         NULL);
  (void)val_cxl_aer_read_uncorr(context->root_bdf,
                                context->aer_offset,
                                &aer_uncorr);
  val_print(ACS_PRINT_DEBUG, " RQWNBN: writeback status %u", status);
  val_print(ACS_PRINT_DEBUG, " RQWNBN: writeback AER uncorrectable 0x%x",
            aer_uncorr);

  /*
   * If the platform provides an explicit writeback trigger and it completes
   * without poison, the rule check fails. If the trigger is unavailable, keep
   * the mandatory snoop result and report the writeback stimulus limitation.
   */
  if ((aer_uncorr & AER_POISONED_TLP) == 0u)
  {
    if (status != ACS_STATUS_PASS)
    {
      val_print(ACS_PRINT_WARN,
                " RQWNBN: DCM cache writeback stimulus unavailable",
                0);
    }
    else
    {
      val_print(ACS_PRINT_ERR,
                " RQWNBN: Poisoned TLP not logged after TDI ERROR writeback",
                0);
      result = ACS_STATUS_FAIL;
      goto cleanup;
    }
  }

  result = ACS_STATUS_PASS;

cleanup:
  if (context->aer_offset != 0u)
    val_cxl_aer_clear(context->root_bdf, context->aer_offset);

  if (session_open != 0u)
  {
    if ((ide_enabled != 0u) &&
        (val_cxl_ide_disable_link(context->root_index,
                                  context->endpoint_index,
                                  &spdm_ctx,
                                  session_id) != ACS_STATUS_PASS))
    {
      val_print(ACS_PRINT_WARN, " RQWNBN: IDE cleanup failed", 0);
    }

    if (val_tdisp_stop_if_needed(&spdm_ctx,
                                 session_id,
                                 &interface_id,
                                 tdi_in_error) != ACS_STATUS_PASS)
    {
      val_print(ACS_PRINT_WARN, " RQWNBN: TDISP session cleanup failed", 0);
    }
  }

  if (snoop_realm_assigned != 0u)
  {
    if (val_cxl_exerciser_execute_cmd(context->endpoint_bdf,
                                      CXL_CMD_OP_DCM_SET_REALM_ASSIGNMENT,
                                      snoop_hpa,
                                      0u,
                                      NULL) != ACS_STATUS_PASS)
    {
      val_print(ACS_PRINT_WARN, " RQWNBN: failed to clear snoop DCM assignment", 0);
    }
  }

  if (writeback_realm_assigned != 0u)
  {
    if (val_cxl_exerciser_execute_cmd(context->endpoint_bdf,
                                      CXL_CMD_OP_DCM_SET_REALM_ASSIGNMENT,
                                      writeback_hpa,
                                      0u,
                                      NULL) != ACS_STATUS_PASS)
    {
      val_print(ACS_PRINT_WARN,
                " RQWNBN: failed to clear writeback DCM assignment",
                0);
    }
  }

  if (tdi_in_error != 0u)
  {
    /*
     * Forcing ERROR is the RQWNBN stimulus. Reset/unlock the endpoint before
     * the next CDA test so this test does not leave TDISP state behind.
     */
    if (val_cxl_unlock_tsp_best_effort(context->root_bdf,
                                       context->endpoint_bdf,
                                       (endpoint_cfg_valid != 0u) ? &endpoint_cfg : NULL)
        != ACS_STATUS_PASS)
    {
      val_print(ACS_PRINT_WARN, " RQWNBN: endpoint reset after ERROR failed", 0);
      result = ACS_STATUS_FAIL;
    }
  }

  return result;
}

static void
payload(void)
{
  TEST_CONTEXT context;
  uint32_t pe_index;
  uint32_t status;
  uint32_t cleanup_status;

  pe_index = val_pe_get_index_mpid(val_pe_get_mpid());

  status = prepare_context(&context);
  if (status == ACS_STATUS_SKIP)
  {
    val_print(ACS_PRINT_INFO, " RQWNBN: no suitable CHI-C2C CDA context", 0);
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
    val_print(ACS_PRINT_ERR, " RQWNBN: platform cleanup failed", 0);
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
  val_print(ACS_PRINT_INFO, " RQWNBN: SPDM/TDISP support not enabled", 0);
  val_set_status(pe_index, "SKIP", 01);
}

#endif

uint32_t
cda_rqwnbn_error_poison_response_entry(uint32_t num_pe)
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
