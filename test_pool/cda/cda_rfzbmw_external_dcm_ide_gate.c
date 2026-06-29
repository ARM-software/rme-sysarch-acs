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

#define TEST_NAME "cda_rfzbmw_external_dcm_ide_gate"
#define TEST_DESC "External Realm DCM access requires TDISP IDE"
#define TEST_RULE "RFZBMW"

#define DECODER_SLOT 0u

#define PCIE_LNKCAP_OFFSET 0x0Cu
#define PCIE_LNKCAP_PN_SHIFT 24u
#define PCIE_LNKCAP_PN_MASK 0xFFu

#define RMECDA_CTL1_TDISP_EN_MASK 0x1u
#define RMECDA_CTL1_LINK_STR_LOCK_MASK (1u << 1)

#define POSITIVE_BASELINE_VALUE 0x0123456789ABCDEFull
#define NEGATIVE_BASELINE_VALUE 0x13579BDF2468ACE0ull

#if ENABLE_SPDM

typedef struct {
  /* Host bridge that owns the selected CFMWS window. */
  uint32_t host_index;
  /* CHI-C2C capable Root Port under test. */
  uint32_t root_index;
  uint32_t root_bdf;
  /* Downstream CHI-C2C exerciser endpoint used to exercise DCM accesses. */
  uint32_t endpoint_index;
  uint32_t endpoint_bdf;
  /* Shared CXL.mem window used for both the host and endpoint decoder programming. */
  uint64_t window_base;
  uint64_t window_size;
  /* Original decoder programming restored during cleanup. */
  uint64_t host_decoder_base_orig;
  uint64_t host_decoder_size_orig;
  uint64_t endpoint_decoder_base_orig;
  uint64_t endpoint_decoder_size_orig;
  /* Original Host Decoder target list restored during cleanup. */
  uint32_t host_target_low_orig;
  uint32_t host_target_high_orig;
  uint32_t host_target_valid;
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
  context->host_index = CXL_COMPONENT_INVALID_INDEX;
  context->root_index = CXL_COMPONENT_INVALID_INDEX;
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
read_from_root(uint64_t address, uint32_t *value)
{
  if (value == NULL)
    return ACS_STATUS_ERR;

  val_memory_clear_el3_access_state();
  shared_data->num_access = 1;
  shared_data->shared_data_access[0].addr = address;
  shared_data->shared_data_access[0].access_type = READ_DATA;

  if (val_pe_access_mut_el3())
  {
    val_memory_clear_el3_access_state();
    val_print(ACS_PRINT_ERR, " RFZBMW: MUT read failed for 0x%llx", address);
    return ACS_STATUS_ERR;
  }

  *value = (uint32_t)shared_data->shared_data_access[0].data;
  val_memory_clear_el3_access_state();
  return ACS_STATUS_PASS;
}

static uint32_t
write_from_root(uint64_t address, uint32_t value)
{
  val_memory_clear_el3_access_state();
  shared_data->num_access = 1;
  shared_data->shared_data_access[0].addr = address;
  shared_data->shared_data_access[0].data = value;
  shared_data->shared_data_access[0].access_type = WRITE_DATA;

  if (val_pe_access_mut_el3())
  {
    val_memory_clear_el3_access_state();
    val_print(ACS_PRINT_ERR, " RFZBMW: MUT write failed for 0x%llx", address);
    return ACS_STATUS_ERR;
  }

  val_memory_clear_el3_access_state();
  return ACS_STATUS_PASS;
}

static uint32_t
program_host_target_list(uint32_t bdf,
                         uint64_t comp_base,
                         TEST_CONTEXT *context)
{
  uint32_t pcie_cap_offset;
  uint32_t lnkcap;
  uint32_t port_id;
  uint64_t hdm_cap_base;

  if (context == NULL)
    return ACS_STATUS_ERR;

  if (val_pcie_find_capability(bdf, PCIE_CAP, CID_PCIECS, &pcie_cap_offset) != 0u)
    return ACS_STATUS_ERR;

  if (val_pcie_read_cfg(bdf, pcie_cap_offset + PCIE_LNKCAP_OFFSET, &lnkcap) != 0u)
    return ACS_STATUS_ERR;

  port_id = (lnkcap >> PCIE_LNKCAP_PN_SHIFT) & PCIE_LNKCAP_PN_MASK;

  if (val_cxl_find_capability(comp_base, CXL_CAPID_HDM_DECODER, &hdm_cap_base)
      != ACS_STATUS_PASS)
    return ACS_STATUS_ERR;

  context->host_target_low_orig =
    val_mmio_read(hdm_cap_base + CXL_HDM_DECODER_TARGET_LOW(DECODER_SLOT));
  context->host_target_high_orig =
    val_mmio_read(hdm_cap_base + CXL_HDM_DECODER_TARGET_HIGH(DECODER_SLOT));
  context->host_target_valid = 1u;

  val_mmio_write(hdm_cap_base + CXL_HDM_DECODER_TARGET_LOW(DECODER_SLOT), port_id);
  val_mmio_write(hdm_cap_base + CXL_HDM_DECODER_TARGET_HIGH(DECODER_SLOT), 0u);

  return ACS_STATUS_PASS;
}

static uint32_t
restore_context_state(const TEST_CONTEXT *context)
{
  uint32_t restore_status;
  uint64_t comp_base;
  uint64_t hdm_cap_base;

  if (context == NULL)
    return ACS_STATUS_ERR;

  restore_status = ACS_STATUS_PASS;

  if ((context->rmecda_ctl1_valid != 0u) && (context->rmecda_cfg_va != 0u) &&
      (write_from_root(context->rmecda_cfg_va + context->rmecda_cap_base +
                       RMECDA_CTL1_OFFSET,
                       context->rmecda_ctl1_orig) != ACS_STATUS_PASS))
  {
    restore_status = ACS_STATUS_ERR;
  }

  if (context->host_target_valid != 0u)
  {
    comp_base = val_cxl_get_info(CXL_INFO_COMPONENT_BASE, context->host_index);
    if ((comp_base != 0u) &&
        (val_cxl_find_capability(comp_base,
                                 CXL_CAPID_HDM_DECODER,
                                 &hdm_cap_base) == ACS_STATUS_PASS))
    {
      val_mmio_write(hdm_cap_base + CXL_HDM_DECODER_TARGET_LOW(DECODER_SLOT),
                     context->host_target_low_orig);
      val_mmio_write(hdm_cap_base + CXL_HDM_DECODER_TARGET_HIGH(DECODER_SLOT),
                     context->host_target_high_orig);
    }
    else
    {
      restore_status = ACS_STATUS_ERR;
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

  if ((context->host_index != CXL_COMPONENT_INVALID_INDEX) &&
      (context->host_decoder_size_orig != 0u) &&
      (val_cxl_program_host_decoder(context->host_index,
                                    DECODER_SLOT,
                                    context->host_decoder_base_orig,
                                    context->host_decoder_size_orig)
       != ACS_STATUS_PASS))
  {
    restore_status = ACS_STATUS_ERR;
  }

  return restore_status;
}

static uint32_t
restore_rmecda_ctl1(TEST_CONTEXT *context)
{
  uint32_t status;

  if (context == NULL)
    return ACS_STATUS_ERR;

  if ((context->rmecda_ctl1_valid == 0u) || (context->rmecda_cfg_va == 0u))
    return ACS_STATUS_PASS;

  status = write_from_root(context->rmecda_cfg_va + context->rmecda_cap_base +
                           RMECDA_CTL1_OFFSET,
                           context->rmecda_ctl1_orig);
  context->rmecda_ctl1_valid = 0u;

  return status;
}

static void
best_effort_restore_rmecda_ctl1_cfg(TEST_CONTEXT *context)
{
  uint32_t readback;

  if (context == NULL)
    return;

  if (context->rmecda_ctl1_valid == 0u)
    return;

  val_pcie_write_cfg(context->root_bdf,
                     context->rmecda_cap_base + RMECDA_CTL1_OFFSET,
                     context->rmecda_ctl1_orig);

  if ((val_pcie_read_cfg(context->root_bdf,
                         context->rmecda_cap_base + RMECDA_CTL1_OFFSET,
                         &readback) == PCIE_SUCCESS) &&
      (readback != context->rmecda_ctl1_orig))
  {
    val_print(ACS_PRINT_WARN,
              " RFZBMW: non-SMC RMECDA_CTL1 restore readback 0x%x",
              readback);
  }

  context->rmecda_ctl1_valid = 0u;
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

  aligned_base = (window_end - page_size) & ~(page_size - 1u);
  if ((aligned_base < window_base) || ((aligned_base + page_size) > window_end))
    return ACS_STATUS_SKIP;

  *test_base_out = aligned_base;
  return ACS_STATUS_PASS;
}

static uint32_t
map_window_alias(uint64_t phys,
                 uint32_t pas,
                 volatile uint64_t **virt_out)
{
  uint64_t page_size;
  uint64_t va;
  uint32_t attr;

  if ((phys == 0u) || (virt_out == NULL))
    return ACS_STATUS_ERR;

  page_size = (uint64_t)val_memory_page_size();
  if (page_size == 0u)
    return ACS_STATUS_ERR;

  va = val_get_free_va(page_size);
  if (va == 0u)
    return ACS_STATUS_ERR;

  attr = LOWER_ATTRS(PGT_ENTRY_ACCESS |
                     SHAREABLE_ATTR(OUTER_SHAREABLE) |
                     GET_ATTR_INDEX(DEV_MEM_nGnRnE) |
                     PGT_ENTRY_AP_RW |
                     PAS_ATTR(pas));

  if (val_add_mmu_entry_el3(va, phys, attr))
    return ACS_STATUS_ERR;

  *virt_out = (volatile uint64_t *)va;
  return ACS_STATUS_PASS;
}

static uint32_t
read_device_media(uint32_t endpoint_bdf,
                  uint64_t phys,
                  uint64_t *value_out)
{
  uint64_t readback = 0u;

  if (value_out == NULL)
    return ACS_STATUS_ERR;

  if (val_exerciser_set_param_by_bdf(EXERCISER_CXL_CMD_CTRL,
                                     0u,
                                     0u,
                                     endpoint_bdf))
    return ACS_STATUS_FAIL;

  if (val_exerciser_set_param_by_bdf(EXERCISER_CXL_CMD_OP,
                                     CXL_CMD_OP_BACKDOOR_READ64,
                                     0u,
                                     endpoint_bdf))
    return ACS_STATUS_FAIL;

  if (val_exerciser_set_param_by_bdf(EXERCISER_CXL_CMD_ADDR,
                                     phys,
                                     0u,
                                     endpoint_bdf))
    return ACS_STATUS_FAIL;

  if (val_exerciser_ops_by_bdf(CXL_CMD_START, 0u, endpoint_bdf))
    return ACS_STATUS_FAIL;

  if (val_exerciser_get_param_by_bdf(EXERCISER_CXL_CMD_DATA0,
                                     &readback,
                                     NULL,
                                     endpoint_bdf))
    return ACS_STATUS_FAIL;

  *value_out = readback;
  return ACS_STATUS_PASS;
}

static uint32_t
seed_device_media(uint32_t endpoint_bdf,
                  uint64_t phys,
                  uint64_t value)
{
  uint64_t observed;

  if (val_cxl_exerciser_write64(endpoint_bdf, phys, value) != ACS_STATUS_PASS)
    return ACS_STATUS_SKIP;

  if (read_device_media(endpoint_bdf, phys, &observed) != ACS_STATUS_PASS)
    return ACS_STATUS_FAIL;

  if (observed != value)
  {
    val_print(ACS_PRINT_ERR, " RFZBMW: media seed mismatch at 0x%llx", phys);
    val_print(ACS_PRINT_ERR, " RFZBMW: expected 0x%llx", value);
    val_print(ACS_PRINT_ERR, " RFZBMW: observed 0x%llx", observed);
    return ACS_STATUS_FAIL;
  }

  return ACS_STATUS_PASS;
}

static uint32_t
is_ide_link_active(uint32_t component_index,
                   uint32_t *is_active,
                   uint32_t *ide_supported)
{
  uint32_t status;
  uint32_t ide_status;
  uint32_t rx_state;
  uint32_t tx_state;

  if ((is_active == NULL) || (ide_supported == NULL))
    return ACS_STATUS_ERR;

  *is_active = 0u;
  *ide_supported = 0u;

  status = val_cxl_ide_get_status(component_index, &ide_status);
  if (status == ACS_STATUS_SKIP)
    return ACS_STATUS_PASS;
  if (status != ACS_STATUS_PASS)
    return status;

  *ide_supported = 1u;
  rx_state = ide_status & CXL_IDE_STATUS_FIELD_MASK;
  tx_state = (ide_status >> CXL_IDE_STATUS_TX_SHIFT) & CXL_IDE_STATUS_FIELD_MASK;
  if ((rx_state != CXL_IDE_STATE_INSECURE) && (tx_state != CXL_IDE_STATE_INSECURE))
    *is_active = 1u;

  return ACS_STATUS_PASS;
}

static uint32_t
get_tdisp_interface_state(uint32_t endpoint_bdf,
                          val_spdm_context_t *spdm_ctx,
                          uint32_t session_id,
                          uint8_t *tdi_state_out)
{
  pci_tdisp_interface_id_t interface_id;

  if ((spdm_ctx == NULL) || (session_id == 0u) || (tdi_state_out == NULL))
    return ACS_STATUS_ERR;

  interface_id.function_id = (uint32_t)PCIE_CREATE_BDF_PACKED(endpoint_bdf);
  interface_id.reserved = 0ull;

  return val_spdm_send_pci_tdisp_get_interface_state(spdm_ctx,
                                                     session_id,
                                                     &interface_id,
                                                     tdi_state_out);
}

static uint32_t
establish_tdisp_run(uint32_t endpoint_bdf,
                    val_spdm_context_t *spdm_ctx,
                    uint32_t *session_id_out)
{
  pci_tdisp_interface_id_t interface_id;
  pci_tdisp_requester_capabilities_t req_caps;
  pci_tdisp_responder_capabilities_t rsp_caps;
  pci_tdisp_lock_interface_param_t lock_param;
  uint8_t nonce[PCI_TDISP_START_INTERFACE_NONCE_SIZE];
  uint32_t session_id;
  uint32_t status;
  uint8_t tdi_state;

  if ((spdm_ctx == NULL) || (session_id_out == NULL))
    return ACS_STATUS_ERR;

  *session_id_out = 0u;

  interface_id.function_id = (uint32_t)PCIE_CREATE_BDF_PACKED(endpoint_bdf);
  interface_id.reserved = 0ull;

  val_memory_set(spdm_ctx, sizeof(*spdm_ctx), 0);
  val_memory_set(&req_caps, sizeof(req_caps), 0);
  val_memory_set(&rsp_caps, sizeof(rsp_caps), 0);
  val_memory_set(&lock_param, sizeof(lock_param), 0);
  val_memory_set(nonce, sizeof(nonce), 0);

  status = val_spdm_session_open(endpoint_bdf, spdm_ctx, &session_id);
  if (status != ACS_STATUS_PASS)
    return status;

  status = val_spdm_send_pci_tdisp_get_version(spdm_ctx, session_id, &interface_id);
  if (status != ACS_STATUS_PASS)
    goto close_session;

  status = val_spdm_send_pci_tdisp_get_capabilities(spdm_ctx,
                                                    session_id,
                                                    &interface_id,
                                                    &req_caps,
                                                    &rsp_caps);
  if (status != ACS_STATUS_PASS)
    goto close_session;

  lock_param.flags = 0u;
  lock_param.default_stream_id = 0u;
  lock_param.reserved = 0u;
  lock_param.mmio_reporting_offset = 0ull;
  lock_param.bind_p2p_address_mask = 0ull;

  status = val_spdm_send_pci_tdisp_lock_interface(spdm_ctx,
                                                  session_id,
                                                  &interface_id,
                                                  &lock_param,
                                                  nonce);
  if (status != ACS_STATUS_PASS)
    goto close_session;

  status = get_tdisp_interface_state(endpoint_bdf, spdm_ctx, session_id, &tdi_state);
  if (status != ACS_STATUS_PASS)
    goto close_session;

  if (tdi_state != PCI_TDISP_INTERFACE_STATE_CONFIG_LOCKED)
  {
    status = ACS_STATUS_FAIL;
    goto close_session;
  }

  status = val_spdm_send_pci_tdisp_start_interface(spdm_ctx,
                                                   session_id,
                                                   &interface_id,
                                                   nonce);
  if (status != ACS_STATUS_PASS)
    goto close_session;

  status = get_tdisp_interface_state(endpoint_bdf, spdm_ctx, session_id, &tdi_state);
  if (status != ACS_STATUS_PASS)
    goto close_session;

  if (tdi_state != PCI_TDISP_INTERFACE_STATE_RUN)
  {
    status = ACS_STATUS_FAIL;
    goto close_session;
  }

  *session_id_out = session_id;
  return ACS_STATUS_PASS;

close_session:
  (void)val_spdm_session_close(spdm_ctx, session_id);
  return status;
}

static uint32_t
stop_tdisp_session(uint32_t endpoint_bdf,
                   val_spdm_context_t *spdm_ctx,
                   uint32_t session_id)
{
  pci_tdisp_interface_id_t interface_id;
  uint32_t status;
  uint32_t result;

  if ((spdm_ctx == NULL) || (session_id == 0u))
    return ACS_STATUS_PASS;

  interface_id.function_id = (uint32_t)PCIE_CREATE_BDF_PACKED(endpoint_bdf);
  interface_id.reserved = 0ull;

  result = ACS_STATUS_PASS;

  status = val_spdm_send_pci_tdisp_stop_interface(spdm_ctx, session_id, &interface_id);
  if ((status != ACS_STATUS_PASS) && (status != ACS_STATUS_SKIP))
    result = ACS_STATUS_FAIL;

  status = val_spdm_session_close(spdm_ctx, session_id);

  if ((status != ACS_STATUS_PASS) && (status != ACS_STATUS_SKIP))
    result = ACS_STATUS_FAIL;

  return result;
}

static uint32_t
access_realm_dcm_allowed(uint32_t endpoint_bdf,
                         uint64_t phys,
                         volatile uint64_t *mapped)
{
  uint64_t baseline = 0u;
  uint64_t observed = 0u;
  uint32_t pattern;
  uint32_t access_status;

  if (mapped == NULL)
    return ACS_STATUS_ERR;

  if (read_device_media(endpoint_bdf, phys, &baseline) != ACS_STATUS_PASS)
    return ACS_STATUS_ERR;

  pattern = (uint32_t)baseline ^ 0xA5A5A5A5u;
  if (pattern == (uint32_t)baseline)
    pattern ^= 0x1u;

  val_memory_clear_el3_access_state();
  shared_data->num_access = 2;
  shared_data->shared_data_access[0].addr = (uint64_t)mapped;
  shared_data->shared_data_access[0].data = (uint64_t)pattern;
  shared_data->shared_data_access[0].access_type = WRITE_DATA;
  shared_data->shared_data_access[1].addr = (uint64_t)mapped;
  shared_data->shared_data_access[1].data = 0u;
  shared_data->shared_data_access[1].access_type = READ_DATA;

  access_status = val_pe_access_mut_el3();
  val_memory_clear_el3_access_state();

  if (read_device_media(endpoint_bdf, phys, &observed) != ACS_STATUS_PASS)
    return ACS_STATUS_ERR;

  if (access_status != 0u)
    return ACS_STATUS_FAIL;

  if ((uint32_t)shared_data->shared_data_access[1].data != pattern)
    return ACS_STATUS_FAIL;

  if ((uint32_t)observed != pattern)
    return ACS_STATUS_FAIL;

  return ACS_STATUS_PASS;
}

static uint32_t
access_realm_dcm_rejected(uint32_t root_bdf,
                          uint32_t aer_offset,
                          volatile uint64_t *mapped)
{
  uint32_t access_status;

  if (mapped == NULL)
    return ACS_STATUS_ERR;

  if (aer_offset != 0u)
    val_cxl_aer_clear(root_bdf, aer_offset);

  /*
   * Expected RFZBMW rejects must use the access_mut path.  The normal MUT
   * write path reports this model's reject as a non-GPF exception, so use the
   * same terminal fault-stimulus pattern as the host-side GPC CDA test.
   */
  val_memory_clear_el3_access_state();
  shared_data->access_mut = SET;
  shared_data->arg1 = (uint64_t)mapped;
  shared_data->exception_expected = SET;

  access_status = val_pe_access_mut_el3();
  val_memory_clear_el3_access_state();

  if (access_status != 0u)
    return ACS_STATUS_FAIL;

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
    const CXL_COMPONENT_ENTRY *root_port;
    const CXL_COMPONENT_ENTRY *endpoint;
    uint32_t endpoint_bdf;
    uint32_t status;
    uint64_t host_comp_base;
    uint64_t endpoint_comp_base;
    uint64_t cfg_addr;
    uint64_t tg;
    uint32_t attr;
    uint32_t ctl1_programmed;
    uint32_t ctl1_readback;

    init_context(&candidate);

    root_port = &table->component[root_idx];
    if (root_port->role != CXL_COMPONENT_ROLE_ROOT_PORT)
      continue;

    if (root_port->chi_c2c_supported == 0u)
      continue;

    status = val_cda_find_downstream_chi_c2c_exerciser_endpoint(root_port->bdf,
                                                                &endpoint_bdf);
    if (status != ACS_STATUS_PASS)
      continue;

    if (find_component_index_by_bdf(table, endpoint_bdf, &candidate.endpoint_index)
        != ACS_STATUS_PASS)
      continue;

    endpoint = &table->component[candidate.endpoint_index];
    if (endpoint->chi_c2c_supported == 0u)
      continue;

    candidate.root_index = root_idx;
    candidate.root_bdf = root_port->bdf;
    candidate.endpoint_bdf = endpoint->bdf;
    candidate.host_index = root_port->host_bridge_index;

    if (candidate.host_index == CXL_COMPONENT_INVALID_INDEX)
      continue;

    if (val_pcie_find_cda_capability(root_port->bdf, &candidate.rmecda_cap_base)
        != ACS_STATUS_PASS)
      continue;

    status = val_cxl_select_cfmws_window(candidate.host_index,
                                         &candidate.window_base,
                                         &candidate.window_size);
    if (status != ACS_STATUS_PASS)
      continue;

    host_comp_base = val_cxl_get_info(CXL_INFO_COMPONENT_BASE, candidate.host_index);
    endpoint_comp_base = endpoint->component_reg_base;
    if ((host_comp_base == 0u) || (endpoint_comp_base == 0u))
      continue;

    if ((val_cxl_find_capability(host_comp_base, CXL_CAPID_HDM_DECODER, NULL)
         != ACS_STATUS_PASS) ||
        (val_cxl_find_capability(endpoint_comp_base, CXL_CAPID_HDM_DECODER, NULL)
         != ACS_STATUS_PASS))
    {
      continue;
    }

    if (val_cxl_get_decoder(candidate.host_index,
                            DECODER_SLOT,
                            &candidate.host_decoder_base_orig,
                            &candidate.host_decoder_size_orig) != 0u)
    {
      candidate.host_decoder_base_orig = 0u;
      candidate.host_decoder_size_orig = 0u;
    }

    if (val_cxl_get_component_decoder(candidate.endpoint_index,
                                      DECODER_SLOT,
                                      &candidate.endpoint_decoder_base_orig,
                                      &candidate.endpoint_decoder_size_orig) != 0u)
    {
      candidate.endpoint_decoder_base_orig = 0u;
      candidate.endpoint_decoder_size_orig = 0u;
    }

    if (val_cxl_enable_mem(endpoint->bdf) != ACS_STATUS_PASS)
    {
      if (restore_context_state(&candidate) != ACS_STATUS_PASS)
        return ACS_STATUS_ERR;
      continue;
    }

    if (program_host_target_list(root_port->bdf, host_comp_base, &candidate)
        != ACS_STATUS_PASS)
    {
      if (restore_context_state(&candidate) != ACS_STATUS_PASS)
        return ACS_STATUS_ERR;
      continue;
    }

    if (val_cxl_program_host_decoder(candidate.host_index,
                                     DECODER_SLOT,
                                     candidate.window_base,
                                     candidate.window_size) != ACS_STATUS_PASS)
    {
      if (restore_context_state(&candidate) != ACS_STATUS_PASS)
        return ACS_STATUS_ERR;
      continue;
    }

    if (val_cxl_program_component_decoder(candidate.endpoint_index,
                                          DECODER_SLOT,
                                          candidate.window_base,
                                          candidate.window_size) != ACS_STATUS_PASS)
    {
      if (restore_context_state(&candidate) != ACS_STATUS_PASS)
        return ACS_STATUS_ERR;
      continue;
    }

    cfg_addr = val_pcie_get_bdf_config_addr(root_port->bdf);
    tg = val_get_min_tg();
    if ((cfg_addr == 0u) || (tg == 0u))
    {
      if (restore_context_state(&candidate) != ACS_STATUS_PASS)
        return ACS_STATUS_ERR;
      continue;
    }

    candidate.rmecda_cfg_va = val_get_free_va(tg);
    if (candidate.rmecda_cfg_va == 0u)
    {
      if (restore_context_state(&candidate) != ACS_STATUS_PASS)
        return ACS_STATUS_ERR;
      continue;
    }

    attr = LOWER_ATTRS(PGT_ENTRY_ACCESS | SHAREABLE_ATTR(OUTER_SHAREABLE) |
                       GET_ATTR_INDEX(DEV_MEM_nGnRnE) | PGT_ENTRY_AP_RW |
                       PAS_ATTR(ROOT_PAS));
    if (val_add_mmu_entry_el3(candidate.rmecda_cfg_va, cfg_addr, attr))
    {
      if (restore_context_state(&candidate) != ACS_STATUS_PASS)
        return ACS_STATUS_ERR;
      continue;
    }

    if (read_from_root(candidate.rmecda_cfg_va + candidate.rmecda_cap_base +
                       RMECDA_CTL1_OFFSET,
                       &candidate.rmecda_ctl1_orig) != ACS_STATUS_PASS)
    {
      if (restore_context_state(&candidate) != ACS_STATUS_PASS)
        return ACS_STATUS_ERR;
      continue;
    }

    candidate.rmecda_ctl1_valid = 1u;
    ctl1_programmed = candidate.rmecda_ctl1_orig |
                      RMECDA_CTL1_TDISP_EN_MASK |
                      RMECDA_CTL1_LINK_STR_LOCK_MASK;

    if (write_from_root(candidate.rmecda_cfg_va + candidate.rmecda_cap_base +
                        RMECDA_CTL1_OFFSET,
                        ctl1_programmed) != ACS_STATUS_PASS)
    {
      if (restore_context_state(&candidate) != ACS_STATUS_PASS)
        return ACS_STATUS_ERR;
      continue;
    }

    if (read_from_root(candidate.rmecda_cfg_va + candidate.rmecda_cap_base +
                       RMECDA_CTL1_OFFSET,
                       &ctl1_readback) != ACS_STATUS_PASS)
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
  uint32_t aer_offset;
  uint32_t realm_assigned;
  uint32_t dcm_cleanup_allowed;
  uint32_t negative_stimulus_done;
  uint32_t ide_enabled;
  uint32_t session_active;
  uint32_t root_ide_active;
  uint32_t root_ide_supported;
  uint32_t endpoint_ide_active;
  uint32_t endpoint_ide_supported;
  uint64_t test_base;
  uint64_t observed;
  uint32_t session_id;
  uint8_t tdi_state;
  volatile uint64_t *realm_alias;
  val_spdm_context_t spdm_ctx;

  if (context == NULL)
    return ACS_STATUS_ERR;

  status = select_test_base(context->window_base,
                            context->window_size,
                            &test_base);
  if (status != ACS_STATUS_PASS)
    return status;

  if (val_pcie_find_capability(context->root_bdf,
                               PCIE_ECAP,
                               ECID_AER,
                               &aer_offset) != PCIE_SUCCESS)
  {
    aer_offset = 0u;
  }

  val_print(ACS_PRINT_INFO, " RFZBMW: Realm DCM page 0x%llx", test_base);

  realm_alias = NULL;
  val_memory_clear_el3_access_state();
  if (map_window_alias(test_base, REALM_PAS, &realm_alias) != ACS_STATUS_PASS)
    return ACS_STATUS_ERR;

  val_memory_set(&spdm_ctx, sizeof(spdm_ctx), 0);
  realm_assigned = 0u;
  dcm_cleanup_allowed = 1u;
  negative_stimulus_done = 0u;
  ide_enabled = 0u;
  session_active = 0u;
  session_id = 0u;
  result = ACS_STATUS_FAIL;

  status = establish_tdisp_run(context->endpoint_bdf, &spdm_ctx, &session_id);
  if (status != ACS_STATUS_PASS)
  {
    val_print(ACS_PRINT_INFO, " RFZBMW: TDI RUN setup unavailable", 0);
    return (status == ACS_STATUS_SKIP) ? ACS_STATUS_SKIP : ACS_STATUS_FAIL;
  }
  session_active = 1u;

  status = val_cxl_ide_establish_link(context->root_index,
                                      context->endpoint_index,
                                      &spdm_ctx,
                                      session_id);
  if (status != ACS_STATUS_PASS)
  {
    result = (status == ACS_STATUS_SKIP) ? ACS_STATUS_SKIP : ACS_STATUS_FAIL;
    goto cleanup;
  }
  ide_enabled = 1u;

  status = is_ide_link_active(context->root_index, &root_ide_active, &root_ide_supported);
  if (status != ACS_STATUS_PASS)
  {
    result = ACS_STATUS_FAIL;
    goto cleanup;
  }

  status = is_ide_link_active(context->endpoint_index,
                              &endpoint_ide_active,
                              &endpoint_ide_supported);
  if (status != ACS_STATUS_PASS)
  {
    result = ACS_STATUS_FAIL;
    goto cleanup;
  }

  if ((root_ide_supported == 0u) || (root_ide_active == 0u) ||
      (endpoint_ide_supported == 0u) || (endpoint_ide_active == 0u))
  {
    val_print(ACS_PRINT_INFO, " RFZBMW: IDE not active after establish", 0);
    result = ACS_STATUS_SKIP;
    goto cleanup;
  }

  status = val_cxl_exerciser_execute_cmd(context->endpoint_bdf,
                                         CXL_CMD_OP_DCM_SET_REALM_ASSIGNMENT,
                                         test_base,
                                         1u,
                                         NULL);
  if (status != ACS_STATUS_PASS)
  {
    val_print(ACS_PRINT_INFO, " RFZBMW: Realm DCM assignment hook unavailable", 0);
    result = ACS_STATUS_SKIP;
    goto cleanup;
  }
  realm_assigned = 1u;

  status = seed_device_media(context->endpoint_bdf, test_base, POSITIVE_BASELINE_VALUE);
  if (status != ACS_STATUS_PASS)
  {
    result = status;
    goto cleanup;
  }

  /*
   * Positive branch: with TDI in RUN and the link protected by IDE, an
   * external Realm access to the Realm-assigned DCM page must succeed.
   */
  status = access_realm_dcm_allowed(context->endpoint_bdf,
                                    test_base,
                                    realm_alias);
  if (status != ACS_STATUS_PASS)
  {
    val_print(ACS_PRINT_ERR,
              " RFZBMW: external Realm DCM access failed with IDE active",
              0);
    result = ACS_STATUS_FAIL;
    goto cleanup;
  }
  val_print(ACS_PRINT_INFO, " RFZBMW: external Realm DCM access succeeded with IDE", 0);

  status = seed_device_media(context->endpoint_bdf, test_base, NEGATIVE_BASELINE_VALUE);
  if (status != ACS_STATUS_PASS)
  {
    result = status;
    goto cleanup;
  }

  /*
   * Negative branch: keep TDI in RUN but disable the IDE stream.  The same
   * external Realm access must now be rejected or become non-destructive.
   */
  status = val_cxl_ide_disable_link(context->root_index,
                                    context->endpoint_index,
                                    &spdm_ctx,
                                    session_id);
  if (status != ACS_STATUS_PASS)
  {
    val_print(ACS_PRINT_ERR, " RFZBMW: IDE disable failed", 0);
    result = ACS_STATUS_FAIL;
    goto cleanup;
  }
  ide_enabled = 0u;

  status = is_ide_link_active(context->root_index, &root_ide_active, &root_ide_supported);
  if (status != ACS_STATUS_PASS)
  {
    result = ACS_STATUS_FAIL;
    goto cleanup;
  }

  status = is_ide_link_active(context->endpoint_index,
                              &endpoint_ide_active,
                              &endpoint_ide_supported);
  if (status != ACS_STATUS_PASS)
  {
    result = ACS_STATUS_FAIL;
    goto cleanup;
  }

  if ((root_ide_active != 0u) || (endpoint_ide_active != 0u))
  {
    val_print(ACS_PRINT_ERR, " RFZBMW: IDE still active after disable", 0);
    result = ACS_STATUS_FAIL;
    goto cleanup;
  }

  status = get_tdisp_interface_state(context->endpoint_bdf,
                                     &spdm_ctx,
                                     session_id,
                                     &tdi_state);
  if (status != ACS_STATUS_PASS)
  {
    result = ACS_STATUS_FAIL;
    goto cleanup;
  }

  if (tdi_state != PCI_TDISP_INTERFACE_STATE_RUN)
  {
    val_print(ACS_PRINT_ERR, " RFZBMW: TDI left RUN while IDE was disabled", 0);
    result = ACS_STATUS_FAIL;
    goto cleanup;
  }

  status = access_realm_dcm_rejected(context->root_bdf,
                                     aer_offset,
                                     realm_alias);
  if (status != ACS_STATUS_PASS)
  {
    val_print(ACS_PRINT_ERR,
              " RFZBMW: IDE-disabled external Realm DCM access was not blocked",
              0);
    result = ACS_STATUS_FAIL;
  }
  else
  {
    negative_stimulus_done = 1u;
    result = ACS_STATUS_PASS;
  }

  /*
   * Leave the RFZBMW stimulus state by moving the TDI out of RUN before any
   * media readback or DCM sideband cleanup.  Re-establishing IDE here requires
   * IDE_KM EL3 services, which are not safe immediately after the expected
   * rejected access on this model.
   */
  status = stop_tdisp_session(context->endpoint_bdf, &spdm_ctx, session_id);
  session_active = 0u;
  if (status != ACS_STATUS_PASS)
  {
    val_print(ACS_PRINT_ERR,
              " RFZBMW: cleanup TDISP session stop failed after reject",
              0);
    result = ACS_STATUS_FAIL;
    goto cleanup;
  }

  if (aer_offset != 0u)
    val_cxl_aer_clear(context->root_bdf, aer_offset);

  if (read_device_media(context->endpoint_bdf, test_base, &observed) != ACS_STATUS_PASS)
  {
    result = ACS_STATUS_FAIL;
    goto cleanup;
  }

  if (observed != NEGATIVE_BASELINE_VALUE)
  {
    val_print(ACS_PRINT_ERR, " RFZBMW: external Realm write modified DCM without IDE", 0);
    val_print(ACS_PRINT_ERR, " RFZBMW: observed 0x%llx", observed);
    result = ACS_STATUS_FAIL;
    goto cleanup;
  }

  if (result == ACS_STATUS_PASS)
    val_print(ACS_PRINT_INFO, " RFZBMW: external Realm DCM access blocked without IDE", 0);

cleanup:
  val_memory_clear_el3_access_state();

  if ((negative_stimulus_done == 0u) && (context->rmecda_ctl1_valid != 0u))
  {
    val_print(ACS_PRINT_INFO, " RFZBMW: restoring RMECDA_CTL1 before DCM cleanup", 0);
    if (restore_rmecda_ctl1(context) != ACS_STATUS_PASS)
    {
      val_print(ACS_PRINT_ERR, " RFZBMW: RMECDA_CTL1 restore failed", 0);
      dcm_cleanup_allowed = 0u;
      result = ACS_STATUS_FAIL;
    }
    else
    {
      val_print(ACS_PRINT_INFO, " RFZBMW: RMECDA_CTL1 restored", 0);
    }
  }
  else if (negative_stimulus_done != 0u)
  {
    val_print(ACS_PRINT_INFO,
              " RFZBMW: terminal reject observed; avoiding post-reject SMC cleanup",
              0);
    best_effort_restore_rmecda_ctl1_cfg(context);
    /*
     * RMECDA_CTL1 can remain enabled after the terminal reject. In that state
     * post-reject EL3 config or host-decoder writes are not safe, so do not
     * attempt further restore operations from this test.
     */
    context->host_target_valid = 0u;
    context->host_decoder_size_orig = 0u;
    dcm_cleanup_allowed = 0u;
  }

  if ((realm_assigned != 0u) && (dcm_cleanup_allowed != 0u))
  {
    if (val_cxl_exerciser_execute_cmd(context->endpoint_bdf,
                                      CXL_CMD_OP_DCM_SET_REALM_ASSIGNMENT,
                                      test_base,
                                      0u,
                                      NULL) != ACS_STATUS_PASS)
    {
      val_print(ACS_PRINT_ERR, " RFZBMW: failed to clear Realm DCM assignment", 0);
      result = ACS_STATUS_FAIL;
    }
  }
  else if (realm_assigned != 0u)
  {
    val_print(ACS_PRINT_WARN, " RFZBMW: skipped DCM assignment cleanup", 0);
  }

  if (ide_enabled != 0u)
  {
    if (val_cxl_ide_disable_link(context->root_index,
                                 context->endpoint_index,
                                 &spdm_ctx,
                                 session_id) != ACS_STATUS_PASS)
    {
      val_print(ACS_PRINT_ERR, " RFZBMW: cleanup IDE disable failed", 0);
      result = ACS_STATUS_FAIL;
    }
  }

  if (session_active != 0u)
  {
    if (stop_tdisp_session(context->endpoint_bdf, &spdm_ctx, session_id) != ACS_STATUS_PASS)
    {
      val_print(ACS_PRINT_ERR, " RFZBMW: cleanup TDISP session stop failed", 0);
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
    val_print(ACS_PRINT_INFO, " RFZBMW: no suitable CHI-C2C CDA context", 0);
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
    val_print(ACS_PRINT_ERR,
              " RFZBMW: platform cleanup failed after test execution",
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
cda_rfzbmw_external_dcm_ide_gate_entry(uint32_t num_pe)
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
