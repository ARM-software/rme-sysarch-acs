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
#include "val/include/val_memory.h"
#include "val/include/val_pcie.h"
#include "val/include/val_pcie_spec.h"
#include "val/include/val_pe.h"
#include "val/include/val_spdm.h"
#include "val/include/val_tdisp.h"

#define TEST_NAME "cda_rwfylw_dev_prop_lock"
#define TEST_DESC "DSM verifies and locks RME-sensitive device state"
#define TEST_RULE "RWFYLW"

#define RWFYLW_GET_DEV_PROP_PROPERTIES_OFF VAL_TDISP_ARM_VDM_BASE_SIZE
#define RWFYLW_GET_DEV_PROP_REG_LIST_OFF \
  (RWFYLW_GET_DEV_PROP_PROPERTIES_OFF + sizeof(uint32_t))
#define RWFYLW_DEV_PROP_VALID_BITS \
  (VAL_TDISP_DEV_PROP_PAS_CHECK | VAL_TDISP_DEV_PROP_MEC | \
   VAL_TDISP_DEV_PROP_MECID_MASK)
#define RWFYLW_HDM_ALIGNMENT       (1ULL << 28)
#define RWFYLW_INVALID_BASE_TRIES  64u
#define RMECDA_CTL1_TDISP_EN_MASK  0x1u
#define RMECDA_CTL1_LINK_STR_LOCK_MASK (1u << 1)
#define RWFYLW_RMECDA_CTL1_PROTECT_MASK \
  (RMECDA_CTL1_TDISP_EN_MASK | RMECDA_CTL1_LINK_STR_LOCK_MASK)

#ifndef PCI_TDISP_INTERFACE_STATE_CONFIG_LOCKED
#define PCI_TDISP_INTERFACE_STATE_CONFIG_LOCKED 1u
#endif

#ifndef PCI_TDISP_INTERFACE_INFO_NO_UPDATE_AFTER_LOCK
#define PCI_TDISP_INTERFACE_INFO_NO_UPDATE_AFTER_LOCK 0x1u
#endif

#if ENABLE_SPDM

typedef struct {
  uint32_t host_index;
  uint32_t endpoint_index;
  uint32_t root_bdf;
  uint32_t endpoint_bdf;
  uint32_t rmecda_cap_base;
  uint64_t rmecda_cfg_va;
  uint32_t rmecda_ctl1_orig;
  uint32_t rmecda_ctl1_saved;
  uint64_t window_base;
  uint64_t window_size;
  uint64_t test_size;
  uint64_t invalid_base;
  uint64_t host_decoder_base_orig;
  uint64_t host_decoder_size_orig;
  uint64_t endpoint_decoder_base_orig;
  uint64_t endpoint_decoder_size_orig;
  uint32_t decoder_state_saved;
} RWFYLW_CONTEXT;

typedef struct {
  uint8_t response[VAL_TDISP_ARM_VDM_MAX_RSP_SIZE];
  uint32_t response_size;
  uint32_t properties;
  uint32_t register_list_size;
} RWFYLW_DEV_PROP;

static uint32_t
read_u32_le(const uint8_t *buffer, uint32_t offset)
{
  return ((uint32_t)buffer[offset]) |
         ((uint32_t)buffer[offset + 1u] << 8) |
         ((uint32_t)buffer[offset + 2u] << 16) |
         ((uint32_t)buffer[offset + 3u] << 24);
}

static uint32_t
range_overlaps(uint64_t base_a,
               uint64_t size_a,
               uint64_t base_b,
               uint64_t size_b)
{
  uint64_t end_a;
  uint64_t end_b;

  if ((size_a == 0u) || (size_b == 0u))
    return 0u;

  end_a = base_a + size_a;
  end_b = base_b + size_b;
  if ((end_a < base_a) || (end_b < base_b))
    return 1u;

  return ((base_a < end_b) && (base_b < end_a)) ? 1u : 0u;
}

static uint32_t
candidate_overlaps_cfmws(uint32_t host_index,
                         uint64_t candidate_base,
                         uint64_t candidate_size)
{
  uint32_t count;

  count = val_cxl_get_cfmws_count(host_index);
  for (uint32_t idx = 0u; idx < count; ++idx)
  {
    uint64_t cfmws_base;
    uint64_t cfmws_size;

    if (val_cxl_get_cfmws(host_index, idx, &cfmws_base, &cfmws_size) != 0u)
      continue;

    if (range_overlaps(candidate_base, candidate_size, cfmws_base, cfmws_size) != 0u)
      return 1u;
  }

  return 0u;
}

static uint32_t
find_component_index_by_bdf(const CXL_COMPONENT_TABLE *table,
                            uint32_t bdf,
                            uint32_t *index_out)
{
  if ((table == NULL) || (index_out == NULL))
    return ACS_STATUS_ERR;

  for (uint32_t idx = 0u; idx < table->num_entries; ++idx)
  {
    if (table->component[idx].bdf == bdf)
    {
      *index_out = idx;
      return ACS_STATUS_PASS;
    }
  }

  return ACS_STATUS_SKIP;
}

static uint32_t
select_invalid_dcm_base(RWFYLW_CONTEXT *context)
{
  uint64_t candidate;

  if ((context == NULL) || (context->test_size == 0u))
    return ACS_STATUS_ERR;

  candidate = (context->window_base + context->window_size +
               (RWFYLW_HDM_ALIGNMENT - 1u)) & ~(RWFYLW_HDM_ALIGNMENT - 1u);
  if (candidate < context->window_base)
    return ACS_STATUS_SKIP;

  for (uint32_t attempt = 0u; attempt < RWFYLW_INVALID_BASE_TRIES; ++attempt)
  {
    if ((candidate + context->test_size) < candidate)
      return ACS_STATUS_SKIP;

    if (candidate_overlaps_cfmws(context->host_index,
                                 candidate,
                                 context->test_size) == 0u)
    {
      context->invalid_base = candidate;
      return ACS_STATUS_PASS;
    }

    candidate += RWFYLW_HDM_ALIGNMENT;
  }

  return ACS_STATUS_SKIP;
}

static uint32_t
find_test_context(RWFYLW_CONTEXT *context)
{
  CXL_COMPONENT_TABLE *table;

  if (context == NULL)
    return ACS_STATUS_ERR;

  val_memory_set(context, sizeof(*context), 0);
  context->host_index = CXL_COMPONENT_INVALID_INDEX;
  context->endpoint_index = CXL_COMPONENT_INVALID_INDEX;

  table = val_cxl_component_table_ptr();
  if ((table == NULL) || (table->num_entries == 0u))
    return ACS_STATUS_SKIP;

  for (uint32_t idx = 0u; idx < table->num_entries; ++idx)
  {
    const CXL_COMPONENT_ENTRY *entry = &table->component[idx];
    uint32_t rmecda_cap_base;
    uint32_t endpoint_bdf;
    uint32_t status;

    if (entry->role != CXL_COMPONENT_ROLE_ROOT_PORT)
      continue;

    if (entry->chi_c2c_supported == 0u)
      continue;

    if (val_pcie_find_cda_capability(entry->bdf, &rmecda_cap_base) != PCIE_SUCCESS)
      continue;

    status = val_cda_find_downstream_chi_c2c_exerciser_endpoint(entry->bdf,
                                                                &endpoint_bdf);
    if (status != ACS_STATUS_PASS)
    {
      val_print(ACS_PRINT_DEBUG,
                " RWFYLW: no downstream CHI-C2C endpoint for RP 0x%x",
                entry->bdf);
      continue;
    }

    if (find_component_index_by_bdf(table,
                                    endpoint_bdf,
                                    &context->endpoint_index)
        != ACS_STATUS_PASS)
      continue;

    context->host_index = entry->host_bridge_index;
    if (context->host_index == CXL_COMPONENT_INVALID_INDEX)
      continue;

    if (val_cxl_select_cfmws_window(context->host_index,
                                    &context->window_base,
                                    &context->window_size) != ACS_STATUS_PASS)
      continue;

    if (context->window_size < RWFYLW_HDM_ALIGNMENT)
      continue;

    /*
     * Use one 256MB HDM-aligned slice for the valid decoder setup.  The invalid
     * base is a same-sized range outside all CFMWS windows, so changing the
     * endpoint decoder to it would make DCM reachable outside the host-visible
     * address map.
     */
    context->test_size = RWFYLW_HDM_ALIGNMENT;
    if (select_invalid_dcm_base(context) != ACS_STATUS_PASS)
      continue;

    context->root_bdf = entry->bdf;
    context->endpoint_bdf = endpoint_bdf;
    context->rmecda_cap_base = rmecda_cap_base;
    if (val_pcie_map_root_config(context->root_bdf,
                                 &context->rmecda_cfg_va) != ACS_STATUS_PASS)
      continue;

    if (val_memory_read_el3(context->rmecda_cfg_va +
                            context->rmecda_cap_base +
                            RMECDA_CTL1_OFFSET,
                            &context->rmecda_ctl1_orig) != ACS_STATUS_PASS)
      continue;

    context->rmecda_ctl1_saved = 1u;
    val_print(ACS_PRINT_INFO, " RWFYLW: selected RP 0x%x", context->root_bdf);
    val_print(ACS_PRINT_INFO, " RWFYLW: selected EP 0x%x", context->endpoint_bdf);
    val_print(ACS_PRINT_INFO, " RWFYLW: valid DCM base 0x%llx",
              context->window_base);
    val_print(ACS_PRINT_INFO, " RWFYLW: invalid DCM base 0x%llx",
              context->invalid_base);
    val_print(ACS_PRINT_DEBUG, " RWFYLW: RMECDA_CTL1 initial 0x%x",
              context->rmecda_ctl1_orig);
    return ACS_STATUS_PASS;
  }

  return ACS_STATUS_SKIP;
}

static uint32_t
save_decoder_state(RWFYLW_CONTEXT *context)
{
  if (context == NULL)
    return ACS_STATUS_ERR;

  /*
   * Decoder state is restored only if it was readable.  Some platforms may not
   * have decoder 0 committed before ACS programs its own known-good window.
   */
  if (val_cxl_get_decoder(context->host_index,
                          CXL_HDM_DECODER_SLOT_DEFAULT,
                          &context->host_decoder_base_orig,
                          &context->host_decoder_size_orig) != 0u)
  {
    context->host_decoder_base_orig = 0u;
    context->host_decoder_size_orig = 0u;
  }

  if (val_cxl_get_component_decoder(context->endpoint_index,
                                    CXL_HDM_DECODER_SLOT_DEFAULT,
                                    &context->endpoint_decoder_base_orig,
                                    &context->endpoint_decoder_size_orig) != 0u)
  {
    context->endpoint_decoder_base_orig = 0u;
    context->endpoint_decoder_size_orig = 0u;
  }

  context->decoder_state_saved = 1u;
  return ACS_STATUS_PASS;
}

static uint32_t
write_rmecda_ctl1(const RWFYLW_CONTEXT *context,
                  uint32_t value,
                  uint32_t *readback_out)
{
  uint32_t readback;

  if ((context == NULL) || (context->rmecda_cfg_va == 0u))
    return ACS_STATUS_ERR;

  if (val_memory_write_el3(context->rmecda_cfg_va +
                           context->rmecda_cap_base +
                           RMECDA_CTL1_OFFSET,
                           value) != ACS_STATUS_PASS)
    return ACS_STATUS_ERR;

  if (val_memory_read_el3(context->rmecda_cfg_va +
                          context->rmecda_cap_base +
                          RMECDA_CTL1_OFFSET,
                          &readback) != ACS_STATUS_PASS)
    return ACS_STATUS_ERR;

  if (readback_out != NULL)
    *readback_out = readback;

  return ACS_STATUS_PASS;
}

static uint32_t
clear_rmecda_protection(const RWFYLW_CONTEXT *context)
{
  uint32_t value;
  uint32_t readback;

  if (context == NULL)
    return ACS_STATUS_ERR;

  /*
   * Decoder programming is the ACS setup phase.  Clear TDISP_EN and
   * LINK_STR_LOCK through Root access so the test can install a known-good
   * decoder configuration before checking that the protected state is locked.
   */
  value = context->rmecda_ctl1_orig & ~RWFYLW_RMECDA_CTL1_PROTECT_MASK;
  if (write_rmecda_ctl1(context, value, &readback) != ACS_STATUS_PASS)
    return ACS_STATUS_ERR;

  if ((readback & RWFYLW_RMECDA_CTL1_PROTECT_MASK) != 0u)
  {
    val_print(ACS_PRINT_DEBUG,
              " RWFYLW: RMECDA_CTL1 clear readback 0x%x",
              readback);
    return ACS_STATUS_SKIP;
  }

  return ACS_STATUS_PASS;
}

static uint32_t
enable_rmecda_protection(const RWFYLW_CONTEXT *context)
{
  uint32_t value;
  uint32_t readback;

  if (context == NULL)
    return ACS_STATUS_ERR;

  /*
   * Preserve unrelated CTL1 fields from firmware and only force the protection
   * bits needed for the observable RME-sensitive register lock check.
   */
  value = context->rmecda_ctl1_orig | RWFYLW_RMECDA_CTL1_PROTECT_MASK;
  if (write_rmecda_ctl1(context, value, &readback) != ACS_STATUS_PASS)
    return ACS_STATUS_ERR;

  val_print(ACS_PRINT_DEBUG, " RWFYLW: RMECDA_CTL1 protected readback 0x%x",
            readback);

  if ((readback & RWFYLW_RMECDA_CTL1_PROTECT_MASK) !=
      RWFYLW_RMECDA_CTL1_PROTECT_MASK)
    return ACS_STATUS_SKIP;

  return ACS_STATUS_PASS;
}

static uint32_t
restore_rmecda_ctl1(const RWFYLW_CONTEXT *context)
{
  uint32_t readback;

  if (context == NULL)
    return ACS_STATUS_ERR;

  if (context->rmecda_ctl1_saved == 0u)
    return ACS_STATUS_PASS;

  if (write_rmecda_ctl1(context,
                        context->rmecda_ctl1_orig,
                        &readback) != ACS_STATUS_PASS)
    return ACS_STATUS_ERR;

  if (readback != context->rmecda_ctl1_orig)
  {
    val_print(ACS_PRINT_WARN,
              " RWFYLW: RMECDA_CTL1 restore readback 0x%x",
              readback);
    return ACS_STATUS_ERR;
  }

  return ACS_STATUS_PASS;
}

static uint32_t
restore_decoder_state(const RWFYLW_CONTEXT *context)
{
  uint32_t status;
  uint32_t restore_status;

  if (context == NULL)
    return ACS_STATUS_ERR;

  if (context->decoder_state_saved == 0u)
    return ACS_STATUS_PASS;

  /*
   * Caller clears RMECDA protection before entering this helper.  Restoring HDM
   * decoders while TDISP_EN/LINK_STR_LOCK are active would correctly be blocked
   * by the device model.
   */
  restore_status = ACS_STATUS_PASS;

  if (context->host_decoder_size_orig != 0u)
  {
    status = val_cxl_program_host_decoder(context->host_index,
                                          CXL_HDM_DECODER_SLOT_DEFAULT,
                                          context->host_decoder_base_orig,
                                          context->host_decoder_size_orig);
    if (status != ACS_STATUS_PASS)
      restore_status = ACS_STATUS_ERR;
  }

  if (context->endpoint_decoder_size_orig != 0u)
  {
    status = val_cxl_program_component_decoder(context->endpoint_index,
                                               CXL_HDM_DECODER_SLOT_DEFAULT,
                                               context->endpoint_decoder_base_orig,
                                               context->endpoint_decoder_size_orig);
    if (status != ACS_STATUS_PASS)
      restore_status = ACS_STATUS_ERR;
  }

  return restore_status;
}

static uint32_t
program_consistent_decoders(const RWFYLW_CONTEXT *context)
{
  uint32_t status;

  if (context == NULL)
    return ACS_STATUS_ERR;

  status = val_cxl_program_host_decoder(context->host_index,
                                        CXL_HDM_DECODER_SLOT_DEFAULT,
                                        context->window_base,
                                        context->test_size);
  if (status != ACS_STATUS_PASS)
    return status;

  return val_cxl_program_component_decoder(context->endpoint_index,
                                           CXL_HDM_DECODER_SLOT_DEFAULT,
                                           context->window_base,
                                           context->test_size);
}

static uint32_t
validate_get_dev_prop_response(const RWFYLW_DEV_PROP *prop)
{
  if (prop == NULL)
    return ACS_STATUS_ERR;

  if (prop->response_size < RWFYLW_GET_DEV_PROP_REG_LIST_OFF)
  {
    val_print(ACS_PRINT_ERR, " RWFYLW: GET_DEV_PROP response too small", 0);
    return ACS_STATUS_FAIL;
  }

  if ((prop->response[VAL_TDISP_HDR_MSG_TYPE_OFF] != PCI_TDISP_VDM_RSP) ||
      (prop->response[VAL_TDISP_REQ_RESP_HDR_OFF +
                      VAL_TDISP_REQ_RESP_TYPE_OFF] !=
       VAL_TDISP_ARM_MSG_GET_DEV_PROP_RESP))
  {
    val_print(ACS_PRINT_ERR, " RWFYLW: invalid GET_DEV_PROP response", 0);
    return ACS_STATUS_FAIL;
  }

  if ((prop->properties & ~RWFYLW_DEV_PROP_VALID_BITS) != 0u)
  {
    val_print(ACS_PRINT_ERR,
              " RWFYLW: GET_DEV_PROP reserved property bits set 0x%x",
              prop->properties);
    return ACS_STATUS_FAIL;
  }

  return ACS_STATUS_PASS;
}

static uint32_t
get_dev_prop_snapshot(val_spdm_context_t *spdm_ctx,
                      uint32_t session_id,
                      const pci_tdisp_interface_id_t *interface_id,
                      RWFYLW_DEV_PROP *prop)
{
  uint32_t status;

  if ((spdm_ctx == NULL) || (session_id == 0u) ||
      (interface_id == NULL) || (prop == NULL))
    return ACS_STATUS_ERR;

  val_memory_set(prop, sizeof(*prop), 0);
  prop->response_size = (uint32_t)sizeof(prop->response);

  status = val_tdisp_vdm_get_dev_prop(spdm_ctx,
                                      session_id,
                                      interface_id,
                                      prop->response,
                                      &prop->response_size);
  if (status != ACS_STATUS_PASS)
    return status;

  if (prop->response_size >= RWFYLW_GET_DEV_PROP_REG_LIST_OFF)
  {
    prop->properties = read_u32_le(prop->response,
                                   RWFYLW_GET_DEV_PROP_PROPERTIES_OFF);
    prop->register_list_size =
      prop->response_size - RWFYLW_GET_DEV_PROP_REG_LIST_OFF;
  }

  return validate_get_dev_prop_response(prop);
}

static uint32_t
get_no_update_after_lock(val_spdm_context_t *spdm_ctx,
                         uint32_t session_id,
                         const pci_tdisp_interface_id_t *interface_id,
                         uint32_t *no_update_out)
{
  uint8_t report[VAL_TDISP_ARM_VDM_MAX_RSP_SIZE];
  uint32_t report_size;
  uint16_t interface_info;
  uint32_t status;

  if ((spdm_ctx == NULL) || (session_id == 0u) ||
      (interface_id == NULL) || (no_update_out == NULL))
    return ACS_STATUS_ERR;

  *no_update_out = 0u;
  val_memory_set(report, sizeof(report), 0);
  report_size = (uint32_t)sizeof(report);

  status = val_spdm_send_pci_tdisp_get_interface_report(spdm_ctx,
                                                        session_id,
                                                        interface_id,
                                                        report,
                                                        &report_size);
  if (status != ACS_STATUS_PASS)
    return status;

  if (report_size < sizeof(uint16_t))
  {
    val_print(ACS_PRINT_ERR, " RWFYLW: interface report too small", 0);
    return ACS_STATUS_FAIL;
  }

  interface_info = (uint16_t)report[0] | ((uint16_t)report[1] << 8);
  *no_update_out =
    ((interface_info & PCI_TDISP_INTERFACE_INFO_NO_UPDATE_AFTER_LOCK) != 0u)
      ? 1u : 0u;

  val_print(ACS_PRINT_INFO, " RWFYLW: interface_info 0x%x", interface_info);
  return ACS_STATUS_PASS;
}

static uint32_t
open_tdisp_session(uint32_t endpoint_bdf,
                   val_spdm_context_t *spdm_ctx,
                   uint32_t *session_id_out,
                   pci_tdisp_interface_id_t *interface_id)
{
  pci_tdisp_requester_capabilities_t req_caps;
  pci_tdisp_responder_capabilities_t rsp_caps;
  uint32_t session_id;
  uint32_t status;

  if ((spdm_ctx == NULL) || (session_id_out == NULL) || (interface_id == NULL))
    return ACS_STATUS_ERR;

  *session_id_out = 0u;
  val_memory_set(spdm_ctx, sizeof(*spdm_ctx), 0);
  val_memory_set(&req_caps, sizeof(req_caps), 0);
  val_memory_set(&rsp_caps, sizeof(rsp_caps), 0);

  interface_id->function_id = (uint32_t)PCIE_CREATE_BDF_PACKED(endpoint_bdf);
  interface_id->reserved = 0ull;

  status = val_spdm_session_open(endpoint_bdf, spdm_ctx, &session_id);
  if (status != ACS_STATUS_PASS)
    return status;

  status = val_spdm_send_pci_tdisp_get_version(spdm_ctx,
                                               session_id,
                                               interface_id);
  if (status != ACS_STATUS_PASS)
    goto close_session;

  status = val_spdm_send_pci_tdisp_get_capabilities(spdm_ctx,
                                                    session_id,
                                                    interface_id,
                                                    &req_caps,
                                                    &rsp_caps);
  if (status != ACS_STATUS_PASS)
    goto close_session;

  *session_id_out = session_id;
  return ACS_STATUS_PASS;

close_session:
  (void)val_spdm_session_close(spdm_ctx, session_id);
  return status;
}

static uint32_t
lock_tdisp_interface(val_spdm_context_t *spdm_ctx,
                     uint32_t session_id,
                     const pci_tdisp_interface_id_t *interface_id,
                     uint32_t *locked_out)
{
  pci_tdisp_lock_interface_param_t lock_param;
  uint8_t nonce[PCI_TDISP_START_INTERFACE_NONCE_SIZE];
  uint8_t tdi_state;
  uint32_t status;

  if ((spdm_ctx == NULL) || (session_id == 0u) ||
      (interface_id == NULL) || (locked_out == NULL))
    return ACS_STATUS_ERR;

  *locked_out = 0u;
  val_memory_set(&lock_param, sizeof(lock_param), 0);
  val_memory_set(nonce, sizeof(nonce), 0);

  status = val_spdm_send_pci_tdisp_lock_interface(spdm_ctx,
                                                  session_id,
                                                  interface_id,
                                                  &lock_param,
                                                  nonce);
  if (status != ACS_STATUS_PASS)
    return status;
  *locked_out = 1u;

  status = val_tdisp_get_interface_state(spdm_ctx,
                                         session_id,
                                         interface_id,
                                         &tdi_state);
  if (status != ACS_STATUS_PASS)
    return status;

  if (tdi_state != PCI_TDISP_INTERFACE_STATE_CONFIG_LOCKED)
  {
    val_print(ACS_PRINT_ERR, " RWFYLW: TDI not CONFIG_LOCKED 0x%x", tdi_state);
    return ACS_STATUS_FAIL;
  }

  return ACS_STATUS_PASS;
}

static uint32_t
validate_locked_dev_prop(const RWFYLW_DEV_PROP *before,
                         const RWFYLW_DEV_PROP *after,
                         uint32_t no_update_after_lock)
{
  const uint8_t *before_list;
  const uint8_t *after_list;

  if ((before == NULL) || (after == NULL))
    return ACS_STATUS_ERR;

  val_print(ACS_PRINT_INFO,
            " RWFYLW: GET_DEV_PROP register-list size %u",
            before->register_list_size);

  if (before->properties != after->properties)
  {
    val_print(ACS_PRINT_ERR,
              " RWFYLW: GET_DEV_PROP properties changed after lock 0x%x",
              after->properties);
    return ACS_STATUS_FAIL;
  }

  if (before->register_list_size != after->register_list_size)
  {
    val_print(ACS_PRINT_ERR,
              " RWFYLW: register-list size changed after lock %u",
              after->register_list_size);
    return ACS_STATUS_FAIL;
  }

  if (before->register_list_size == 0u)
  {
    /*
     * The register list is implementation-defined. A zero-length list can be
     * compliant only when the device also reports that host-visible interface
     * state cannot be updated after LOCK_INTERFACE, which covers devices whose
     * RME-sensitive registers are DSM-owned or globally locked by TDISP.
     */
    if (no_update_after_lock == 0u)
    {
      val_print(ACS_PRINT_ERR,
                " RWFYLW: empty register-list without no-update-after-lock",
                0);
      return ACS_STATUS_FAIL;
    }

    return ACS_STATUS_PASS;
  }

  before_list = &before->response[RWFYLW_GET_DEV_PROP_REG_LIST_OFF];
  after_list = &after->response[RWFYLW_GET_DEV_PROP_REG_LIST_OFF];
  if (val_memory_compare((void *)before_list,
                         (void *)after_list,
                         before->register_list_size) != 0)
  {
    val_print(ACS_PRINT_ERR, " RWFYLW: register-list changed after lock", 0);
    return ACS_STATUS_FAIL;
  }

  return ACS_STATUS_PASS;
}

static uint32_t
verify_endpoint_decoder_immutable(const RWFYLW_CONTEXT *context)
{
  uint64_t before_base;
  uint64_t before_size;
  uint64_t after_base;
  uint64_t after_size;
  uint32_t program_status;

  if (context == NULL)
    return ACS_STATUS_ERR;

  if (val_cxl_get_component_decoder(context->endpoint_index,
                                    CXL_HDM_DECODER_SLOT_DEFAULT,
                                    &before_base,
                                    &before_size) != 0u)
  {
    val_print(ACS_PRINT_ERR, " RWFYLW: endpoint decoder read failed", 0);
    return ACS_STATUS_FAIL;
  }

  /*
   * With RME-CDA protection active, try to mutate an RME-sensitive endpoint
   * decoder to a non-host-visible DCM range.  The observable requirement is
   * that the decoder remains unchanged; the write may be rejected, trapped, or
   * ignored.
   */
  val_print(ACS_PRINT_INFO,
            " RWFYLW: attempt protected endpoint decoder mutation", 0);
  program_status =
    val_cxl_program_component_decoder(context->endpoint_index,
                                      CXL_HDM_DECODER_SLOT_DEFAULT,
                                      context->invalid_base,
                                      context->test_size);

  if (val_cxl_get_component_decoder(context->endpoint_index,
                                    CXL_HDM_DECODER_SLOT_DEFAULT,
                                    &after_base,
                                    &after_size) != 0u)
  {
    val_print(ACS_PRINT_ERR, " RWFYLW: endpoint decoder reread failed", 0);
    return ACS_STATUS_FAIL;
  }

  /*
   * The write helper may return PASS if the posted writes complete, even when
   * protected registers ignore the data.  The compliance observable is the
   * decoder readback, not the helper return code.
   */
  if ((before_base != after_base) || (before_size != after_size))
  {
    val_print(ACS_PRINT_ERR,
              " RWFYLW: protected endpoint decoder changed base 0x%llx",
              after_base);
    val_print(ACS_PRINT_ERR,
              " RWFYLW: protected endpoint decoder changed size 0x%llx",
              after_size);
    return ACS_STATUS_FAIL;
  }

  if (program_status == ACS_STATUS_PASS)
    val_print(ACS_PRINT_INFO,
              " RWFYLW: protected decoder write completed with no mutation", 0);
  else
    val_print(ACS_PRINT_INFO, " RWFYLW: protected decoder write rejected", 0);

  return ACS_STATUS_PASS;
}

static void
payload(void)
{
  RWFYLW_CONTEXT context;
  RWFYLW_DEV_PROP before_lock;
  RWFYLW_DEV_PROP after_lock;
  val_spdm_context_t spdm_ctx;
  pci_tdisp_interface_id_t interface_id;
  uint32_t session_id;
  uint32_t session_open;
  uint32_t locked;
  uint32_t no_update_after_lock;
  uint32_t status;
  uint32_t cleanup_status;
  uint32_t pe_index = val_get_primary_pe_index();

  session_id = 0u;
  session_open = 0u;
  locked = 0u;
  no_update_after_lock = 0u;
  cleanup_status = ACS_STATUS_PASS;
  val_memory_set(&spdm_ctx, sizeof(spdm_ctx), 0);
  val_memory_set(&interface_id, sizeof(interface_id), 0);

  status = find_test_context(&context);
  if (status != ACS_STATUS_PASS)
  {
    val_print(ACS_PRINT_INFO, " RWFYLW: no suitable CHI-C2C CDA context", 0);
    val_set_status(pe_index, "SKIP", 01);
    return;
  }

  status = save_decoder_state(&context);
  if (status != ACS_STATUS_PASS)
  {
    val_print(ACS_PRINT_ERR, " RWFYLW: failed to save decoder state", 0);
    val_set_status(pe_index, "FAIL", 01);
    return;
  }

  status = clear_rmecda_protection(&context);
  if (status != ACS_STATUS_PASS)
  {
    val_print(ACS_PRINT_INFO, " RWFYLW: cannot clear RMECDA protection", 0);
    if (status != ACS_STATUS_SKIP)
      status = ACS_STATUS_FAIL;
    goto cleanup;
  }

  /*
   * Install a consistent address-decoder state before enabling RME-CDA
   * protection.  The endpoint decoder is then treated as an RME-sensitive
   * configuration register for the remaining checks.
   */
  status = program_consistent_decoders(&context);
  if (status != ACS_STATUS_PASS)
  {
    val_print(ACS_PRINT_INFO,
              " RWFYLW: valid decoder programming unavailable", 0);
    status = ACS_STATUS_SKIP;
    goto cleanup;
  }

  status = enable_rmecda_protection(&context);
  if (status != ACS_STATUS_PASS)
  {
    val_print(ACS_PRINT_INFO, " RWFYLW: cannot enable RMECDA protection", 0);
    goto cleanup;
  }

  status = verify_endpoint_decoder_immutable(&context);
  if (status != ACS_STATUS_PASS)
    goto cleanup;

  status = open_tdisp_session(context.endpoint_bdf,
                              &spdm_ctx,
                              &session_id,
                              &interface_id);
  if (status != ACS_STATUS_PASS)
  {
    val_print(ACS_PRINT_INFO, " RWFYLW: SPDM/TDISP setup unavailable", 0);
    status = ACS_STATUS_SKIP;
    goto cleanup;
  }
  session_open = 1u;

  /*
   * Snapshot GET_DEV_PROP while the interface is still CONFIG_UNLOCKED.  The
   * register-list bytes are implementation-defined, so ACS treats them as an
   * opaque DSM validation blob.
   */
  status = get_dev_prop_snapshot(&spdm_ctx,
                                 session_id,
                                 &interface_id,
                                 &before_lock);
  if (status != ACS_STATUS_PASS)
    goto cleanup;

  status = lock_tdisp_interface(&spdm_ctx, session_id, &interface_id, &locked);
  if (status != ACS_STATUS_PASS)
    goto cleanup;

  status = get_dev_prop_snapshot(&spdm_ctx,
                                 session_id,
                                 &interface_id,
                                 &after_lock);
  if (status != ACS_STATUS_PASS)
    goto cleanup;

  /*
   * If the implementation does not expose a GET_DEV_PROP register list, use the
   * standard TDISP interface report as the generic observable that updates are
   * prohibited after LOCK_INTERFACE.
   */
  if (before_lock.register_list_size == 0u)
  {
    status = get_no_update_after_lock(&spdm_ctx,
                                      session_id,
                                      &interface_id,
                                      &no_update_after_lock);
    if (status != ACS_STATUS_PASS)
      goto cleanup;
  }

  status = validate_locked_dev_prop(&before_lock,
                                    &after_lock,
                                    no_update_after_lock);
  if (status != ACS_STATUS_PASS)
    goto cleanup;

  status = verify_endpoint_decoder_immutable(&context);

cleanup:
  if (locked != 0u)
  {
    if (val_spdm_send_pci_tdisp_stop_interface(&spdm_ctx,
                                               session_id,
                                               &interface_id) != ACS_STATUS_PASS)
    {
      val_print(ACS_PRINT_WARN, " RWFYLW: STOP_INTERFACE cleanup failed", 0);
      cleanup_status = ACS_STATUS_ERR;
    }
  }

  if (session_open != 0u)
  {
    if (val_spdm_session_close(&spdm_ctx, session_id) != ACS_STATUS_PASS)
    {
      val_print(ACS_PRINT_WARN, " RWFYLW: SPDM session cleanup failed", 0);
      cleanup_status = ACS_STATUS_ERR;
    }
  }

  /*
   * Cleanup order matters: clear RMECDA protection first, then restore the HDM
   * decoder registers, and finally restore the original RMECDA_CTL1 value.
   */
  if (clear_rmecda_protection(&context) != ACS_STATUS_PASS)
  {
    val_print(ACS_PRINT_WARN, " RWFYLW: RMECDA clear cleanup failed", 0);
    cleanup_status = ACS_STATUS_ERR;
  }

  if (restore_decoder_state(&context) != ACS_STATUS_PASS)
  {
    val_print(ACS_PRINT_WARN, " RWFYLW: decoder restore cleanup failed", 0);
    cleanup_status = ACS_STATUS_ERR;
  }

  if (restore_rmecda_ctl1(&context) != ACS_STATUS_PASS)
  {
    val_print(ACS_PRINT_WARN, " RWFYLW: RMECDA restore cleanup failed", 0);
    cleanup_status = ACS_STATUS_ERR;
  }

  if ((status == ACS_STATUS_PASS) && (cleanup_status == ACS_STATUS_PASS))
    val_set_status(pe_index, "PASS", 01);
  else if ((status == ACS_STATUS_SKIP) && (cleanup_status == ACS_STATUS_PASS))
    val_set_status(pe_index, "SKIP", 01);
  else
    val_set_status(pe_index, "FAIL", 01);
}

#else

static void
payload(void)
{
  uint32_t pe_index = val_get_primary_pe_index();

  val_print(ACS_PRINT_INFO, " RWFYLW: SPDM/TDISP support not enabled", 0);
  val_set_status(pe_index, "SKIP", 01);
}

#endif

uint32_t
cda_rwfylw_dev_prop_lock_entry(uint32_t num_pe)
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
