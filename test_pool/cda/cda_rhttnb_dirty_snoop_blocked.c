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

#define TEST_NAME "cda_rhttnb_dirty_snoop_blocked"
#define TEST_DESC "Blocked snoop to dirty TDI cache returns poison"
#define TEST_RULE "RHTTNB"

#define DECODER_SLOT 0u

#define ESR_EC_SHIFT                 26u
#define ESR_EC_MASK                  0x3Fu
#define ESR_EC_DATA_ABORT_SAME_EL    0x25u
#define ESR_ABORT_FSC_MASK           0x3Fu
#define ESR_FSC_SYNC_EXTERNAL_ABORT  0x10u

#define RMECDA_CTL1_TDISP_EN_MASK 0x1u
#define RMECDA_CTL1_LINK_STR_LOCK_MASK (1u << 1)

#define RHTTNB_SEED_VALUE 0xA55A0123456789EFULL
#define RHTTNB_POISON_FIXED_VALUE 0xFFFFFFFFFFFFFFFFULL

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
                  " RHTTNB: RMECDA_CTL1 root restore readback 0x%x",
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
                  " RHTTNB: RMECDA_CTL1 restore readback 0x%x",
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
              " RHTTNB: considering RP BDF 0x%x",
              (uint64_t)root_port->bdf);
    val_print(ACS_PRINT_DEBUG,
              " RHTTNB: RP chi_c2c flag %u",
              (uint64_t)root_port->chi_c2c_supported);

    if (root_port->chi_c2c_supported == 0u)
      continue;

    status = val_cda_find_downstream_chi_c2c_exerciser_endpoint(root_port->bdf,
                                                                &endpoint_bdf);
    if (status != ACS_STATUS_PASS)
    {
      val_print(ACS_PRINT_DEBUG,
                " RHTTNB: no downstream CHI-C2C exerciser for RP 0x%x",
                (uint64_t)root_port->bdf);
      val_print(ACS_PRINT_DEBUG,
                " RHTTNB: downstream endpoint search status %u",
                (uint64_t)status);
      continue;
    }

    if (val_cxl_find_component_index_by_bdf(endpoint_bdf,
                                            &candidate.endpoint_index)
        != ACS_STATUS_PASS)
    {
      val_print(ACS_PRINT_DEBUG,
                " RHTTNB: endpoint 0x%x missing from component table",
                (uint64_t)endpoint_bdf);
      continue;
    }

    endpoint = &table->component[candidate.endpoint_index];
    if ((endpoint->role != CXL_COMPONENT_ROLE_ENDPOINT) ||
        (endpoint->chi_c2c_supported == 0u))
    {
      val_print(ACS_PRINT_DEBUG,
                " RHTTNB: endpoint 0x%x is not CHI-C2C endpoint",
                (uint64_t)endpoint_bdf);
      continue;
    }

    /* This test seeds the cache through a direct coherent Realm host access. */
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
                " RHTTNB: root 0x%x lacks RME-CDA capability",
                (uint64_t)candidate.root_bdf);
      continue;
    }

    /* AER is useful diagnostic information, but is not the poison response. */
    candidate.aer_offset = 0u;
    if (val_pcie_find_capability(candidate.root_bdf,
                                 PCIE_ECAP,
                                 ECID_AER,
                                 &candidate.aer_offset) != PCIE_SUCCESS)
      candidate.aer_offset = 0u;

    candidate.host_index = root_port->host_bridge_index;
    if (candidate.host_index == CXL_COMPONENT_INVALID_INDEX)
    {
      val_print(ACS_PRINT_DEBUG,
                " RHTTNB: root 0x%x missing host bridge index",
                (uint64_t)candidate.root_bdf);
      continue;
    }

    if (val_cxl_select_cfmws_window(candidate.host_index,
                                    &candidate.window_base,
                                    &candidate.window_size) != ACS_STATUS_PASS)
    {
      val_print(ACS_PRINT_DEBUG,
                " RHTTNB: host index %u has no CFMWS window",
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
                " RHTTNB: failed to save host decoder state",
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
                " RHTTNB: failed to save host decoder target",
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
                " RHTTNB: failed to save endpoint decoder state",
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
              " RHTTNB: RMECDA_CTL1 initial readback 0x%x",
              (uint64_t)candidate.rmecda_ctl1_orig);

    if ((candidate.rmecda_ctl1_orig &
         (RMECDA_CTL1_TDISP_EN_MASK | RMECDA_CTL1_LINK_STR_LOCK_MASK)) != 0u)
    {
      /*
       * RHTTNB owns its setup and does not consume state from any earlier CDA
       * test. If RMECDA is already enabled/locked, skip this Root Port rather
       * than depending on a preserved route or alias.
       */
      val_print(ACS_PRINT_DEBUG,
                " RHTTNB: RMECDA_CTL1 not clean 0x%x",
                (uint64_t)candidate.rmecda_ctl1_orig);
      continue;
    }

    if (val_pcie_map_root_config(candidate.root_bdf,
                                 &candidate.rmecda_cfg_va) != ACS_STATUS_PASS)
    {
      (void)restore_context_state(&candidate);
      val_print(ACS_PRINT_DEBUG,
                " RHTTNB: config map failed for RP 0x%x",
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
                " RHTTNB: RMECDA_CTL1 root state not clean 0x%x",
                (uint64_t)candidate.rmecda_ctl1_orig);
      continue;
    }

    if (val_cxl_enable_cache(candidate.endpoint_bdf) != ACS_STATUS_PASS)
    {
      (void)restore_context_state(&candidate);
      continue;
    }

    if (val_cxl_enable_mem(candidate.endpoint_bdf) != ACS_STATUS_PASS)
    {
      (void)restore_context_state(&candidate);
      val_print(ACS_PRINT_DEBUG,
                " RHTTNB: CXL.mem enable failed for EP 0x%x",
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
                " RHTTNB: failed to program host decoder target",
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
                " RHTTNB: failed to program endpoint decoder",
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
              " RHTTNB: RMECDA_CTL1 root-write readback 0x%x",
              (uint64_t)ctl1_readback);

    if ((ctl1_readback &
         (RMECDA_CTL1_TDISP_EN_MASK | RMECDA_CTL1_LINK_STR_LOCK_MASK)) !=
        (RMECDA_CTL1_TDISP_EN_MASK | RMECDA_CTL1_LINK_STR_LOCK_MASK))
    {
      (void)restore_context_state(&candidate);
      val_print(ACS_PRINT_DEBUG,
                " RHTTNB: RMECDA_CTL1 required bits did not stick",
                0);
      continue;
    }

    *context = candidate;
    val_print(ACS_PRINT_INFO, " RHTTNB: selected RP 0x%x", context->root_bdf);
    val_print(ACS_PRINT_INFO, " RHTTNB: selected EP 0x%x", context->endpoint_bdf);
    return ACS_STATUS_PASS;
  }

  return ACS_STATUS_SKIP;
}

static uint32_t
exercise_rule(TEST_CONTEXT *context)
{
  volatile uint64_t *realm_alias;
  val_spdm_context_t spdm_ctx;
  pci_tdisp_interface_id_t interface_id;
  PCIE_ENDPOINT_CFG endpoint_cfg;
  uint32_t session_id;
  uint32_t session_open;
  uint32_t ide_enabled;
  uint32_t realm_assigned;
  uint32_t endpoint_cfg_valid;
  uint32_t cache_dirty;
  uint32_t result;
  uint32_t status;
  uint32_t aer_uncorr;
  uint32_t host_fault;
  uint64_t test_hpa;
  uint64_t observed;
  uint64_t read_esr;
  uint8_t tdi_state;

  if (context == NULL)
    return ACS_STATUS_ERR;

  status = val_cda_select_dcm_page(context->window_base,
                                   context->window_size,
                                   &test_hpa);
  if (status != ACS_STATUS_PASS)
    return status;

  val_print(ACS_PRINT_INFO, " RHTTNB: Realm DCM HPA 0x%llx", test_hpa);

  realm_alias = NULL;
  if (val_memory_map_realm_cacheable_alias(test_hpa, &realm_alias) != ACS_STATUS_PASS)
    return ACS_STATUS_ERR;

  val_memory_set(&spdm_ctx, sizeof(spdm_ctx), 0);
  val_memory_set(&endpoint_cfg, sizeof(endpoint_cfg), 0);
  session_id = 0u;
  session_open = 0u;
  ide_enabled = 0u;
  realm_assigned = 0u;
  endpoint_cfg_valid = 0u;
  cache_dirty = 0u;
  result = ACS_STATUS_FAIL;

  if (val_pcie_save_endpoint_cfg(context->endpoint_bdf, &endpoint_cfg) == ACS_STATUS_PASS)
    endpoint_cfg_valid = 1u;
  else
    val_print(ACS_PRINT_WARN, " RHTTNB: endpoint config snapshot failed", 0);

  /* Associate the CFMWS-backed page with this TDI. */
  status = val_cxl_exerciser_execute_cmd(context->endpoint_bdf,
                                         CXL_CMD_OP_DCM_SET_REALM_ASSIGNMENT,
                                         test_hpa,
                                         1u,
                                         NULL);
  if (status != ACS_STATUS_PASS)
  {
    val_print(ACS_PRINT_INFO, " RHTTNB: Realm DCM assignment hook unavailable", 0);
    return ACS_STATUS_SKIP;
  }
  realm_assigned = 1u;

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
    val_print(ACS_PRINT_INFO, " RHTTNB: IDE establish unavailable", 0);
    result = (status == ACS_STATUS_SKIP) ? ACS_STATUS_SKIP : ACS_STATUS_FAIL;
    goto cleanup;
  }
  ide_enabled = 1u;

  /*
   * Initialize backing DCM without creating dirty state, then populate a clean
   * Realm line through the coherent HPA path. CACHE_DIRTY changes only the
   * state of this existing line and does not supply its contents.
   */
  status = val_cda_seed_realm_cache_line(test_hpa,
                                         realm_alias,
                                         RHTTNB_SEED_VALUE);
  if (status != ACS_STATUS_PASS)
  {
    val_print(ACS_PRINT_ERR, " RHTTNB: failed to seed Realm cache line", 0);
    result = status;
    goto cleanup;
  }

  /* Mark the populated line dirty before making its snoop path unavailable. */
  status = val_cxl_exerciser_execute_cmd(context->endpoint_bdf,
                                         CXL_CMD_OP_DCM_CACHE_DIRTY,
                                         test_hpa,
                                         0u,
                                         NULL);
  if (status != ACS_STATUS_PASS)
  {
    val_print(ACS_PRINT_INFO, " RHTTNB: DCM cache-dirty stimulus unavailable", 0);
    result = ACS_STATUS_SKIP;
    goto cleanup;
  }
  cache_dirty = 1u;

  status = val_cxl_ide_disable_link(context->root_index,
                                    context->endpoint_index,
                                    &spdm_ctx,
                                    session_id);
  if (status != ACS_STATUS_PASS)
  {
    val_print(ACS_PRINT_ERR, " RHTTNB: IDE disable failed", 0);
    result = ACS_STATUS_FAIL;
    goto cleanup;
  }
  ide_enabled = 0u;

  status = val_tdisp_get_interface_state(&spdm_ctx, session_id, &interface_id, &tdi_state);
  if (status != ACS_STATUS_PASS)
  {
    result = ACS_STATUS_FAIL;
    goto cleanup;
  }

  if (tdi_state != PCI_TDISP_INTERFACE_STATE_RUN)
  {
    val_print(ACS_PRINT_ERR, " RHTTNB: TDI left RUN after IDE disable 0x%x", tdi_state);
    result = ACS_STATUS_FAIL;
    goto cleanup;
  }

  if (context->aer_offset != 0u)
    val_cxl_aer_clear(context->root_bdf, context->aer_offset);
  observed = 0u;
  host_fault = 0u;
  read_esr = 0u;
  aer_uncorr = 0u;
  status = val_memory_read64_el3_protected_with_esr(realm_alias,
                                                     &observed,
                                                     &host_fault,
                                                     &read_esr);
  if (context->aer_offset != 0u)
    (void)val_cxl_aer_read_uncorr(context->root_bdf,
                                  context->aer_offset,
                                  &aer_uncorr);
  val_print(ACS_PRINT_DEBUG, " RHTTNB: host read status %u", status);
  val_print(ACS_PRINT_DEBUG, " RHTTNB: host read fault %u", host_fault);
  val_print(ACS_PRINT_DEBUG, " RHTTNB: host read ESR 0x%llx", read_esr);
  val_print(ACS_PRINT_DEBUG, " RHTTNB: host read observed 0x%llx", observed);
  val_print(ACS_PRINT_DEBUG, " RHTTNB: AER uncorrectable 0x%x", aer_uncorr);

  if (status != ACS_STATUS_PASS)
  {
    val_print(ACS_PRINT_ERR, " RHTTNB: protected host read failed", 0);
    result = ACS_STATUS_ERR;
    goto cleanup;
  }

  /*
   * RHTTNB requires poison and fixed data when the host port cannot forward a
   * snoop for a location it tracks as potentially device-owned dirty. Consuming
   * the poison may raise a synchronous external abort. If the access completes,
   * it must return fixed poison data rather than the dirty TDI value. AER is
   * diagnostic because this coherent poison response is not necessarily a PCIe
   * Poisoned TLP event.
   */
  if (host_fault != 0u)
  {
    if ((((read_esr >> ESR_EC_SHIFT) & ESR_EC_MASK) !=
         ESR_EC_DATA_ABORT_SAME_EL) ||
        ((read_esr & ESR_ABORT_FSC_MASK) != ESR_FSC_SYNC_EXTERNAL_ABORT))
    {
      val_print(ACS_PRINT_ERR,
                " RHTTNB: blocked snoop raised unexpected ESR 0x%llx",
                read_esr);
      result = ACS_STATUS_FAIL;
      goto cleanup;
    }
  }
  else
  {
    if (observed == RHTTNB_POISON_FIXED_VALUE)
    {
      val_print(ACS_PRINT_DEBUG,
                " RHTTNB: host read returned fixed poison data 0x%llx",
                observed);
    }
    else if (observed != RHTTNB_SEED_VALUE)
    {
      val_print(ACS_PRINT_INFO,
                " RHTTNB: host read returned non-original poison data 0x%llx",
                observed);
    }
    else
    {
      val_print(ACS_PRINT_ERR,
                " RHTTNB: host read returned clean TDI data 0x%llx",
                observed);
      result = ACS_STATUS_FAIL;
      goto cleanup;
    }
  }

  result = ACS_STATUS_PASS;

cleanup:
  if (context->aer_offset != 0u)
    val_cxl_aer_clear(context->root_bdf, context->aer_offset);

  if (ide_enabled != 0u)
  {
    if (val_cxl_ide_disable_link(context->root_index,
                                 context->endpoint_index,
                                 &spdm_ctx,
                                 session_id) != ACS_STATUS_PASS)
    {
      val_print(ACS_PRINT_WARN, " RHTTNB: cleanup IDE disable failed", 0);
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
      val_print(ACS_PRINT_WARN, " RHTTNB: TDISP session cleanup failed", 0);
    }
    session_open = 0u;
  }

  if (realm_assigned != 0u)
  {
    if (val_cxl_exerciser_execute_cmd(context->endpoint_bdf,
                                      CXL_CMD_OP_DCM_SET_REALM_ASSIGNMENT,
                                      test_hpa,
                                      0u,
                                      NULL) != ACS_STATUS_PASS)
    {
      val_print(ACS_PRINT_WARN, " RHTTNB: failed to clear DCM assignment", 0);
    }
  }

  if (cache_dirty != 0u)
  {
    /* Discard test-owned cache state so the next CDA test starts independently. */
    if (val_cxl_unlock_tsp_best_effort(context->root_bdf,
                                       context->endpoint_bdf,
                                       (endpoint_cfg_valid != 0u) ?
                                       &endpoint_cfg : NULL) != ACS_STATUS_PASS)
    {
      val_print(ACS_PRINT_WARN, " RHTTNB: endpoint reset cleanup failed", 0);
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
    val_print(ACS_PRINT_INFO, " RHTTNB: no suitable CHI-C2C CDA context", 0);
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
    val_print(ACS_PRINT_ERR, " RHTTNB: platform cleanup failed", 0);
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
  val_print(ACS_PRINT_INFO, " RHTTNB: SPDM/TDISP support not enabled", 0);
  val_set_status(pe_index, "SKIP", 01);
}

#endif

uint32_t
cda_rhttnb_dirty_snoop_blocked_entry(uint32_t num_pe)
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
