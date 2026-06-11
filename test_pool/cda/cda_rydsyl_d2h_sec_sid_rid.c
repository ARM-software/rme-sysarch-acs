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
#include "val/include/val_iovirt.h"
#include "val/include/val_memory.h"
#include "val/include/val_pcie.h"
#include "val/include/val_pcie_spec.h"
#include "val/include/val_pe.h"
#include "val/include/val_pgt.h"
#include "val/include/val_smmu.h"
#include "val/include/val_spdm.h"
#include "val/include/val_tdisp.h"

#define TEST_NAME "cda_rydsyl_d2h_sec_sid_rid"
#define TEST_DESC "D2H SEC_SID and RID track TDI RUN state"
#define TEST_RULE "RYDSYL"

#define RMECDA_CTL1_TDISP_EN_MASK       0x1u
#define RMECDA_CTL1_LINK_STR_LOCK_MASK  (1u << 1)

#if ENABLE_SPDM

/*
 * RYDSYL cannot be checked by directly reading CHI SEC_SID/RID fields from
 * ACS software.  The test therefore constrains the host port to accept only
 * the selected TDI Requester ID and uses Realm DMA accept/reject behavior as
 * the observable result.
 */
typedef struct {
  uint32_t root_index;
  uint32_t endpoint_index;
  uint32_t root_bdf;
  uint32_t endpoint_bdf;
  uint32_t rmecda_ctl1_orig;
  uint32_t rmecda_ctl1_valid;
  uint32_t rmecda_ctl3_orig;
  uint32_t rmecda_ctl3_valid;
  uint32_t rmecda_ctl4_orig;
  uint32_t rmecda_ctl4_valid;
  uint32_t rmecda_cap_base;
  uint64_t rmecda_cfg_va;
} RYDSYL_CONTEXT;

static void
init_context(RYDSYL_CONTEXT *context)
{
  if (context == NULL)
    return;

  val_memory_set(context, sizeof(*context), 0);
  context->root_index = CXL_COMPONENT_INVALID_INDEX;
  context->endpoint_index = CXL_COMPONENT_INVALID_INDEX;
  context->root_bdf = ACS_INVALID_INDEX;
  context->endpoint_bdf = ACS_INVALID_INDEX;
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

  return ACS_STATUS_FAIL;
}

static uint32_t
find_downstream_chi_c2c_exerciser_endpoint(uint32_t root_bdf,
                                           uint32_t *endpoint_bdf_out)
{
  CXL_COMPONENT_TABLE *table;
  uint32_t reg_value;
  uint32_t secondary_bus;
  uint32_t subordinate_bus;
  uint32_t segment;

  if (endpoint_bdf_out == NULL)
    return ACS_STATUS_ERR;

  *endpoint_bdf_out = ACS_INVALID_INDEX;

  table = val_cxl_component_table_ptr();
  if ((table == NULL) || (table->num_entries == 0u))
    return ACS_STATUS_ERR;

  if (val_pcie_read_cfg(root_bdf, TYPE1_PBN, &reg_value) != PCIE_SUCCESS)
    return ACS_STATUS_ERR;

  secondary_bus = (reg_value >> SECBN_SHIFT) & SECBN_MASK;
  subordinate_bus = (reg_value >> SUBBN_SHIFT) & SUBBN_MASK;
  segment = PCIE_EXTRACT_BDF_SEG(root_bdf);

  if ((secondary_bus == 0u) && (subordinate_bus == 0u))
    return ACS_STATUS_SKIP;

  for (uint32_t idx = 0u; idx < table->num_entries; ++idx)
  {
    const CXL_COMPONENT_ENTRY *candidate = &table->component[idx];
    uint32_t candidate_bdf = candidate->bdf;
    uint32_t candidate_bus;

    if (candidate->role != CXL_COMPONENT_ROLE_ENDPOINT)
      continue;

    if (candidate->chi_c2c_supported == 0u)
      continue;

    if (PCIE_EXTRACT_BDF_SEG(candidate_bdf) != segment)
      continue;

    candidate_bus = PCIE_EXTRACT_BDF_BUS(candidate_bdf);
    if ((candidate_bus < secondary_bus) || (candidate_bus > subordinate_bus))
      continue;

    if (val_exerciser_init_by_bdf(candidate_bdf) == 0u)
    {
      *endpoint_bdf_out = candidate_bdf;
      return ACS_STATUS_PASS;
    }
  }

  return ACS_STATUS_SKIP;
}

static uint32_t
restore_rmecda_registers(const RYDSYL_CONTEXT *context)
{
  uint32_t readback;
  uint32_t ctl1_unlocked;

  if (context == NULL)
    return ACS_STATUS_ERR;

  readback = 0u;

  if ((context->rmecda_ctl1_valid == 0u) &&
      (context->rmecda_ctl3_valid == 0u) &&
      (context->rmecda_ctl4_valid == 0u))
    return ACS_STATUS_PASS;

  if (context->rmecda_cfg_va != 0u)
  {
    if (context->rmecda_ctl1_valid != 0u)
    {
      ctl1_unlocked = context->rmecda_ctl1_orig &
                      ~RMECDA_CTL1_LINK_STR_LOCK_MASK;
      if (val_memory_write_el3(context->rmecda_cfg_va + context->rmecda_cap_base +
                          RMECDA_CTL1_OFFSET,
                          ctl1_unlocked) != ACS_STATUS_PASS)
      {
        return ACS_STATUS_ERR;
      }
    }

    if (context->rmecda_ctl3_valid != 0u)
    {
      if (val_memory_write_el3(context->rmecda_cfg_va + context->rmecda_cap_base +
                          RMECDA_CTL3_OFFSET,
                          context->rmecda_ctl3_orig) != ACS_STATUS_PASS)
      {
        return ACS_STATUS_ERR;
      }
    }

    if (context->rmecda_ctl4_valid != 0u)
    {
      if (val_memory_write_el3(context->rmecda_cfg_va + context->rmecda_cap_base +
                          RMECDA_CTL4_OFFSET,
                          context->rmecda_ctl4_orig) != ACS_STATUS_PASS)
      {
        return ACS_STATUS_ERR;
      }
    }

    if (context->rmecda_ctl1_valid != 0u)
    {
      if (val_memory_write_el3(context->rmecda_cfg_va + context->rmecda_cap_base +
                          RMECDA_CTL1_OFFSET,
                          context->rmecda_ctl1_orig) != ACS_STATUS_PASS)
      {
        return ACS_STATUS_ERR;
      }

      if ((val_memory_read_el3(context->rmecda_cfg_va + context->rmecda_cap_base +
                          RMECDA_CTL1_OFFSET,
                          &readback) != ACS_STATUS_PASS) ||
          (readback != context->rmecda_ctl1_orig))
      {
        val_print(ACS_PRINT_WARN,
                  " RYDSYL: RMECDA_CTL1 restore readback 0x%x",
                  (uint64_t)readback);
        return ACS_STATUS_ERR;
      }
    }

    if (context->rmecda_ctl3_valid != 0u)
    {
      if ((val_memory_read_el3(context->rmecda_cfg_va + context->rmecda_cap_base +
                          RMECDA_CTL3_OFFSET,
                          &readback) != ACS_STATUS_PASS) ||
          (readback != context->rmecda_ctl3_orig))
      {
        val_print(ACS_PRINT_WARN,
                  " RYDSYL: RMECDA_CTL3 restore readback 0x%x",
                  (uint64_t)readback);
        return ACS_STATUS_ERR;
      }
    }

    if (context->rmecda_ctl4_valid != 0u)
    {
      if ((val_memory_read_el3(context->rmecda_cfg_va + context->rmecda_cap_base +
                          RMECDA_CTL4_OFFSET,
                          &readback) != ACS_STATUS_PASS) ||
          (readback != context->rmecda_ctl4_orig))
      {
        val_print(ACS_PRINT_WARN,
                  " RYDSYL: RMECDA_CTL4 restore readback 0x%x",
                  (uint64_t)readback);
        return ACS_STATUS_ERR;
      }
    }

    return ACS_STATUS_PASS;
  }

  if (context->rmecda_ctl1_valid != 0u)
  {
    ctl1_unlocked = context->rmecda_ctl1_orig &
                    ~RMECDA_CTL1_LINK_STR_LOCK_MASK;
    val_pcie_write_cfg(context->root_bdf,
                       context->rmecda_cap_base + RMECDA_CTL1_OFFSET,
                       ctl1_unlocked);
  }

  if (context->rmecda_ctl3_valid != 0u)
  {
    val_pcie_write_cfg(context->root_bdf,
                       context->rmecda_cap_base + RMECDA_CTL3_OFFSET,
                       context->rmecda_ctl3_orig);
  }

  if (context->rmecda_ctl4_valid != 0u)
  {
    val_pcie_write_cfg(context->root_bdf,
                       context->rmecda_cap_base + RMECDA_CTL4_OFFSET,
                       context->rmecda_ctl4_orig);
  }

  if (context->rmecda_ctl1_valid != 0u)
  {
    val_pcie_write_cfg(context->root_bdf,
                       context->rmecda_cap_base + RMECDA_CTL1_OFFSET,
                       context->rmecda_ctl1_orig);

    if ((val_pcie_read_cfg(context->root_bdf,
                           context->rmecda_cap_base + RMECDA_CTL1_OFFSET,
                           &readback) == PCIE_SUCCESS) &&
        (readback == context->rmecda_ctl1_orig))
      return ACS_STATUS_PASS;

    val_print(ACS_PRINT_WARN,
              " RYDSYL: RMECDA_CTL1 restore readback 0x%x",
              (uint64_t)readback);
    return ACS_STATUS_ERR;
  }

  return ACS_STATUS_PASS;
}

static uint32_t
prepare_context(RYDSYL_CONTEXT *context)
{
  CXL_COMPONENT_TABLE *table;

  if (context == NULL)
    return ACS_STATUS_ERR;

  init_context(context);

  table = val_cxl_component_table_ptr();
  if ((table == NULL) || (table->num_entries == 0u))
    return ACS_STATUS_SKIP;

  for (uint32_t idx = 0u; idx < table->num_entries; ++idx)
  {
    RYDSYL_CONTEXT candidate;
    const CXL_COMPONENT_ENTRY *root_port = &table->component[idx];
    const CXL_COMPONENT_ENTRY *endpoint;
    uint32_t endpoint_bdf;
    uint32_t endpoint_index;
    uint32_t endpoint_rid;
    uint32_t ctl1;
    uint32_t readback;
    uint32_t status;

    init_context(&candidate);

    if (root_port->role != CXL_COMPONENT_ROLE_ROOT_PORT)
      continue;

    val_print(ACS_PRINT_DEBUG,
              " RYDSYL: considering RP BDF 0x%x",
              (uint64_t)root_port->bdf);
    val_print(ACS_PRINT_DEBUG,
              " RYDSYL: RP chi_c2c flag %u",
              (uint64_t)root_port->chi_c2c_supported);

    if (root_port->chi_c2c_supported == 0u)
    {
      val_print(ACS_PRINT_DEBUG,
                " RYDSYL: skipping RP 0x%x because CHI-C2C is not detected",
                (uint64_t)root_port->bdf);
      continue;
    }

    status = find_downstream_chi_c2c_exerciser_endpoint(root_port->bdf,
                                                        &endpoint_bdf);
    if (status != ACS_STATUS_PASS)
    {
      val_print(ACS_PRINT_DEBUG,
                " RYDSYL: no downstream CHI-C2C exerciser for RP 0x%x",
                (uint64_t)root_port->bdf);
      val_print(ACS_PRINT_DEBUG,
                " RYDSYL: downstream endpoint search status %u",
                (uint64_t)status);
      continue;
    }

    status = find_component_index_by_bdf(table, endpoint_bdf, &endpoint_index);
    if (status != ACS_STATUS_PASS)
    {
      val_print(ACS_PRINT_DEBUG,
                " RYDSYL: endpoint 0x%x missing from component table",
                (uint64_t)endpoint_bdf);
      continue;
    }

    endpoint = &table->component[endpoint_index];
    if (endpoint->chi_c2c_supported == 0u)
    {
      val_print(ACS_PRINT_DEBUG,
                " RYDSYL: endpoint 0x%x is not marked CHI-C2C",
                (uint64_t)endpoint->bdf);
      continue;
    }

    candidate.root_index = idx;
    candidate.endpoint_index = endpoint_index;
    candidate.root_bdf = root_port->bdf;
    candidate.endpoint_bdf = endpoint->bdf;

    val_print(ACS_PRINT_DEBUG,
              " RYDSYL: selected RP 0x%x",
              (uint64_t)candidate.root_bdf);
    val_print(ACS_PRINT_DEBUG,
              " RYDSYL: selected EP 0x%x",
              (uint64_t)candidate.endpoint_bdf);

    if (endpoint->component_reg_base == 0u)
    {
      val_print(ACS_PRINT_DEBUG,
                " RYDSYL: missing component register base for EP 0x%x",
                (uint64_t)candidate.endpoint_bdf);
      continue;
    }

    if (val_pcie_find_cda_capability(candidate.root_bdf, &candidate.rmecda_cap_base)
        != PCIE_SUCCESS)
    {
      val_print(ACS_PRINT_DEBUG,
                " RYDSYL: root 0x%x lacks RME-CDA capability",
                (uint64_t)candidate.root_bdf);
      continue;
    }

    if (val_cxl_enable_mem(candidate.endpoint_bdf) != ACS_STATUS_PASS)
    {
      val_print(ACS_PRINT_DEBUG,
                " RYDSYL: CXL.mem enable failed for EP 0x%x",
                (uint64_t)candidate.endpoint_bdf);
      continue;
    }

    if (val_pcie_map_root_config(candidate.root_bdf,
                                &candidate.rmecda_cfg_va) != ACS_STATUS_PASS)
    {
      val_print(ACS_PRINT_DEBUG,
                " RYDSYL: config map failed for RP 0x%x",
                (uint64_t)candidate.root_bdf);
      if (restore_rmecda_registers(&candidate) != ACS_STATUS_PASS)
        return ACS_STATUS_ERR;
      continue;
    }

    /*
     * Save all RMECDA registers that this test changes.  CTL1 is the
     * TDISP/link-lock control register; CTL3/CTL4 hold the Requester ID
     * acceptance window used by the host port when LINK_STR_LOCK is set.
     */
    if (val_memory_read_el3(candidate.rmecda_cfg_va + candidate.rmecda_cap_base +
                          RMECDA_CTL1_OFFSET,
                          &candidate.rmecda_ctl1_orig) != ACS_STATUS_PASS)
    {
      if (restore_rmecda_registers(&candidate) != ACS_STATUS_PASS)
        return ACS_STATUS_ERR;
      continue;
    }
    candidate.rmecda_ctl1_valid = 1u;

    val_print(ACS_PRINT_DEBUG,
              " RYDSYL: RMECDA_CTL1 initial readback 0x%x",
              (uint64_t)candidate.rmecda_ctl1_orig);

    if (val_memory_read_el3(candidate.rmecda_cfg_va + candidate.rmecda_cap_base +
                          RMECDA_CTL3_OFFSET,
                          &candidate.rmecda_ctl3_orig) != ACS_STATUS_PASS)
    {
      if (restore_rmecda_registers(&candidate) != ACS_STATUS_PASS)
        return ACS_STATUS_ERR;
      continue;
    }
    candidate.rmecda_ctl3_valid = 1u;

    if (val_memory_read_el3(candidate.rmecda_cfg_va + candidate.rmecda_cap_base +
                          RMECDA_CTL4_OFFSET,
                          &candidate.rmecda_ctl4_orig) != ACS_STATUS_PASS)
    {
      if (restore_rmecda_registers(&candidate) != ACS_STATUS_PASS)
        return ACS_STATUS_ERR;
      continue;
    }
    candidate.rmecda_ctl4_valid = 1u;

    /*
     * RMECDA_CTL3/CTL4 are write-protected while LINK_STR_LOCK is set.  Clear
     * the lock first, program the window to admit only the selected endpoint's
     * Requester ID, then set TDISP_EN and LINK_STR_LOCK for the actual check.
     */
    ctl1 = candidate.rmecda_ctl1_orig & ~RMECDA_CTL1_LINK_STR_LOCK_MASK;
    if (val_memory_write_el3(candidate.rmecda_cfg_va + candidate.rmecda_cap_base +
                           RMECDA_CTL1_OFFSET,
                           ctl1) != ACS_STATUS_PASS)
    {
      if (restore_rmecda_registers(&candidate) != ACS_STATUS_PASS)
        return ACS_STATUS_ERR;
      continue;
    }

    if (val_memory_read_el3(candidate.rmecda_cfg_va + candidate.rmecda_cap_base +
                          RMECDA_CTL1_OFFSET,
                          &readback) != ACS_STATUS_PASS)
    {
      if (restore_rmecda_registers(&candidate) != ACS_STATUS_PASS)
        return ACS_STATUS_ERR;
      continue;
    }

    if ((readback & RMECDA_CTL1_LINK_STR_LOCK_MASK) != 0u)
    {
      val_print(ACS_PRINT_DEBUG,
                " RYDSYL: LINK_STR_LOCK refused to clear for RP 0x%x",
                (uint64_t)candidate.root_bdf);
      if (restore_rmecda_registers(&candidate) != ACS_STATUS_PASS)
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
                " RYDSYL: RID range programming status %u",
                (uint64_t)status);
      if (restore_rmecda_registers(&candidate) != ACS_STATUS_PASS)
        return ACS_STATUS_ERR;
      continue;
    }

    ctl1 = candidate.rmecda_ctl1_orig |
           RMECDA_CTL1_TDISP_EN_MASK |
           RMECDA_CTL1_LINK_STR_LOCK_MASK;
    if (val_memory_write_el3(candidate.rmecda_cfg_va + candidate.rmecda_cap_base +
                           RMECDA_CTL1_OFFSET,
                           ctl1) != ACS_STATUS_PASS)
    {
      if (restore_rmecda_registers(&candidate) != ACS_STATUS_PASS)
        return ACS_STATUS_ERR;
      continue;
    }

    if (val_memory_read_el3(candidate.rmecda_cfg_va + candidate.rmecda_cap_base +
                          RMECDA_CTL1_OFFSET,
                          &readback) != ACS_STATUS_PASS)
    {
      if (restore_rmecda_registers(&candidate) != ACS_STATUS_PASS)
        return ACS_STATUS_ERR;
      continue;
    }

    val_print(ACS_PRINT_DEBUG,
              " RYDSYL: RMECDA_CTL1 config-write readback 0x%x",
              (uint64_t)readback);

    if ((readback & (RMECDA_CTL1_TDISP_EN_MASK |
                     RMECDA_CTL1_LINK_STR_LOCK_MASK)) !=
        (RMECDA_CTL1_TDISP_EN_MASK | RMECDA_CTL1_LINK_STR_LOCK_MASK))
    {
      val_print(ACS_PRINT_DEBUG,
                " RYDSYL: RMECDA_CTL1 cannot enable required bits via config",
                0);
      if (restore_rmecda_registers(&candidate) != ACS_STATUS_PASS)
        return ACS_STATUS_ERR;
      continue;
    }

    val_print(ACS_PRINT_INFO, " RYDSYL: using CHI-C2C RP 0x%x",
              (uint64_t)candidate.root_bdf);
    val_print(ACS_PRINT_INFO, " RYDSYL: using CHI-C2C EP 0x%x",
              (uint64_t)candidate.endpoint_bdf);
    *context = candidate;
    return ACS_STATUS_PASS;
  }

  return ACS_STATUS_SKIP;
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
stop_tdisp_interface(uint32_t endpoint_bdf,
                     val_spdm_context_t *spdm_ctx,
                     uint32_t session_id)
{
  pci_tdisp_interface_id_t interface_id;
  uint8_t tdi_state;
  uint32_t status;

  if ((spdm_ctx == NULL) || (session_id == 0u))
    return ACS_STATUS_ERR;

  interface_id.function_id = (uint32_t)PCIE_CREATE_BDF_PACKED(endpoint_bdf);
  interface_id.reserved = 0ull;

  status = val_spdm_send_pci_tdisp_stop_interface(spdm_ctx, session_id, &interface_id);
  if (status != ACS_STATUS_PASS)
    return status;

  status = get_tdisp_interface_state(endpoint_bdf, spdm_ctx, session_id, &tdi_state);
  if (status != ACS_STATUS_PASS)
    return status;

  if (tdi_state == PCI_TDISP_INTERFACE_STATE_RUN)
    return ACS_STATUS_FAIL;

  return ACS_STATUS_PASS;
}

static uint32_t
run_realm_dma_round(uint32_t endpoint_bdf,
                    uint64_t buffer_src_pa,
                    uint64_t buffer_dst_pa,
                    uint64_t buffer_src_va,
                    uint64_t buffer_dst_va,
                    uint32_t length,
                    uint32_t load_device,
                    uint32_t expect_success)
{
  uint32_t status;

  /*
   * Load device memory from the source buffer first, then issue the D2H DMA
   * into the destination buffer.  The final compare is the observable result:
   * match means the host accepted the D2H request, mismatch means it did not.
   */
  if (load_device != 0u)
  {
    status = val_exerciser_set_param_by_bdf(DMA_ATTRIBUTES,
                                            buffer_src_pa,
                                            length,
                                            endpoint_bdf);
    if (status != 0u)
      return ACS_STATUS_ERR;

    status = val_exerciser_ops_by_bdf(START_DMA, EDMA_TO_DEVICE, endpoint_bdf);
    if ((expect_success != 0u) && (status != 0u))
      return ACS_STATUS_FAIL;
  }

  status = val_exerciser_set_param_by_bdf(DMA_ATTRIBUTES,
                                          buffer_dst_pa,
                                          length,
                                          endpoint_bdf);
  if (status != 0u)
    return ACS_STATUS_ERR;

  status = val_exerciser_ops_by_bdf(START_DMA, EDMA_FROM_DEVICE, endpoint_bdf);
  if ((expect_success != 0u) && (status != 0u))
    return ACS_STATUS_FAIL;

  status = val_memory_compare_el3(buffer_src_va, buffer_dst_va, length);
  if (status == ACS_STATUS_ERR)
    return ACS_STATUS_ERR;

  if (expect_success != 0u)
    return (status == 0u) ? ACS_STATUS_PASS : ACS_STATUS_FAIL;

  return (status == 0u) ? ACS_STATUS_FAIL : ACS_STATUS_PASS;
}

static uint32_t
check_implicit_sec_sid_and_rid(uint32_t endpoint_bdf,
                               uint32_t length,
                               uint32_t *positive_done)
{
  smmu_master_attributes_t master;
  memory_region_descriptor_t mem_desc[2];
  pgt_descriptor_t pgt_desc_ns;
  pgt_descriptor_t pgt_desc_rlm;
  uint8_t *buffer_va;
  uint8_t *buffer_src;
  uint8_t *buffer_dst;
  uint64_t buffer_pa;
  uint64_t buffer_src_pa;
  uint64_t buffer_dst_pa;
  uint64_t total_len;
  uint32_t its_id = 0u;
  uint32_t device_id = 0u;
  uint32_t status;
  uint32_t smmu_index;
  uint32_t pgt_ns_created = 0u;
  uint32_t pgt_rlm_created = 0u;
  uint32_t smmu_ns_mapped = 0u;
  uint32_t smmu_rlm_mapped = 0u;
  uint32_t buffer_valid = 0u;
  uint32_t result = ACS_STATUS_PASS;

  /*
   * Positive RYDSYL check.  The TDI is already in RUN when this function is
   * called.  The SMMU/GPT state below creates Realm source/destination buffers
   * and routes the endpoint through the Realm stage-2 path.  If the device
   * sends the wrong RID or does not present the expected Realm identity, the
   * host path rejects the D2H request and the copy will not complete.
   */
  if (positive_done == NULL)
    return ACS_STATUS_ERR;

  *positive_done = 0u;

  val_memory_set(&master, sizeof(master), 0);
  val_memory_set(mem_desc, sizeof(mem_desc), 0);
  val_memory_set(&pgt_desc_ns, sizeof(pgt_desc_ns), 0);
  val_memory_set(&pgt_desc_rlm, sizeof(pgt_desc_rlm), 0);
  master.smmu_index = ACS_INVALID_INDEX;

  total_len = (uint64_t)length * 2u;
  buffer_va = (uint8_t *)val_get_free_va(total_len);
  if (buffer_va == NULL)
    return ACS_STATUS_SKIP;

  buffer_pa = (uint64_t)val_memory_virt_to_phys(buffer_va);
  if (buffer_pa == 0u)
    return ACS_STATUS_SKIP;

  buffer_src = buffer_va;
  buffer_dst = buffer_va + length;
  buffer_src_pa = buffer_pa;
  buffer_dst_pa = buffer_pa + length;
  buffer_valid = 1u;

  smmu_index = val_iovirt_get_rc_smmu_index(PCIE_EXTRACT_BDF_SEG(endpoint_bdf),
                                            PCIE_CREATE_BDF_PACKED(endpoint_bdf));
  if (smmu_index == ACS_INVALID_INDEX)
    return ACS_STATUS_SKIP;

  master.smmu_index = smmu_index;
  if (val_smmu_enable(master.smmu_index))
  {
    val_print(ACS_PRINT_ERR, " RYDSYL: SMMU enable failed", 0);
    result = ACS_STATUS_ERR;
    goto cleanup;
  }

  status = val_iovirt_get_device_info(PCIE_CREATE_BDF_PACKED(endpoint_bdf),
                                      PCIE_EXTRACT_BDF_SEG(endpoint_bdf),
                                      &device_id,
                                      &master.streamid,
                                      &its_id);
  if (status != 0u)
  {
    result = ACS_STATUS_SKIP;
    goto cleanup;
  }

  val_print(ACS_PRINT_DEBUG, " RYDSYL: EP BDF 0x%x", (uint64_t)endpoint_bdf);
  val_print(ACS_PRINT_DEBUG, " RYDSYL: SMMU index %u", master.smmu_index);
  val_print(ACS_PRINT_DEBUG, " RYDSYL: StreamID 0x%lx", master.streamid);
  val_print(ACS_PRINT_DEBUG, " RYDSYL: DeviceID 0x%x", (uint64_t)device_id);
  val_print(ACS_PRINT_DEBUG, " RYDSYL: ITS ID 0x%x", (uint64_t)its_id);

  mem_desc[0].virtual_address = buffer_pa;
  mem_desc[0].physical_address = buffer_pa;
  mem_desc[0].length = (uint32_t)total_len;
  mem_desc[1].length = 0u;

  pgt_desc_ns.ias = val_smmu_get_info(SMMU_IN_ADDR_SIZE, master.smmu_index);
  pgt_desc_ns.oas = val_smmu_get_info(SMMU_OUT_ADDR_SIZE, master.smmu_index);
  if ((pgt_desc_ns.ias == 0u) || (pgt_desc_ns.oas == 0u))
  {
    result = ACS_STATUS_SKIP;
    goto cleanup;
  }

  if (val_pe_reg_read_tcr(0, &pgt_desc_ns.tcr))
  {
    result = ACS_STATUS_ERR;
    goto cleanup;
  }

  pgt_desc_ns.mair = val_pe_reg_read(MAIR_ELx);
  pgt_desc_ns.stage = PGT_STAGE1;
  pgt_desc_ns.pgt_base = (uint64_t)NULL;
  mem_desc[0].attributes = PGT_STAGE1_AP_RW;

  if (val_pgt_create(mem_desc, &pgt_desc_ns))
  {
    result = ACS_STATUS_ERR;
    goto cleanup;
  }
  pgt_ns_created = 1u;

  master.stage2 = 0;
  if (val_smmu_map(master, pgt_desc_ns))
  {
    result = ACS_STATUS_ERR;
    goto cleanup;
  }
  smmu_ns_mapped = 1u;

  if (val_pe_get_vtcr(&pgt_desc_rlm.vtcr))
  {
    result = ACS_STATUS_ERR;
    goto cleanup;
  }

  pgt_desc_rlm.ias = pgt_desc_ns.ias;
  pgt_desc_rlm.oas = pgt_desc_ns.oas;
  pgt_desc_rlm.pgt_base = (uint64_t)NULL;
  mem_desc[0].attributes = PGT_STAGE2_AP_RW;

  if (val_memory_map_el3_data((uint64_t)mem_desc,
                              sizeof(mem_desc),
                              NONSECURE_PAS) != ACS_STATUS_PASS)
  {
    result = ACS_STATUS_ERR;
    goto cleanup;
  }
  if (val_memory_map_el3_data((uint64_t)&pgt_desc_rlm,
                              sizeof(pgt_desc_rlm),
                              NONSECURE_PAS) != ACS_STATUS_PASS)
  {
    result = ACS_STATUS_ERR;
    goto cleanup;
  }
  if (val_memory_map_el3_data((uint64_t)&master,
                              sizeof(master),
                              NONSECURE_PAS) != ACS_STATUS_PASS)
  {
    result = ACS_STATUS_ERR;
    goto cleanup;
  }

  if (val_rlm_pgt_create(mem_desc, &pgt_desc_rlm))
  {
    result = ACS_STATUS_ERR;
    goto cleanup;
  }
  pgt_rlm_created = 1u;

  val_pe_reg_write(VTTBR, pgt_desc_rlm.pgt_base);
  master.stage2 = 1;
  if (val_smmu_rlm_map_el3(&master, &pgt_desc_rlm))
  {
    result = ACS_STATUS_ERR;
    goto cleanup;
  }
  smmu_rlm_mapped = 1u;

  /*
   * Use translated requests and the endpoint's own requester identity.  The
   * test deliberately does not override RID from the exerciser; the host port
   * RID window was programmed to admit only the selected TDI Requester ID.
   */
  if (val_exerciser_set_param_by_bdf(CFG_TXN_ATTRIBUTES,
                                     TXN_ADDR_TYPE,
                                     AT_TRANSLATED,
                                     endpoint_bdf))
  {
    result = ACS_STATUS_SKIP;
    goto cleanup;
  }

  if (val_exerciser_set_param_by_bdf(CFG_TXN_ATTRIBUTES,
                                     TXN_REQ_ID_VALID,
                                     RID_NOT_VALID,
                                     endpoint_bdf))
  {
    result = ACS_STATUS_SKIP;
    goto cleanup;
  }

  if (val_add_gpt_entry_el3(buffer_src_pa, GPT_REALM))
  {
    result = ACS_STATUS_ERR;
    goto cleanup;
  }
  if (val_add_gpt_entry_el3(buffer_dst_pa, GPT_REALM))
  {
    result = ACS_STATUS_ERR;
    goto cleanup;
  }

  if (val_smmu_gpt_invalidate_el3(&master))
  {
    result = ACS_STATUS_ERR;
    goto cleanup;
  }

  /* Map the same buffers as Realm for Root-side initialization and compare. */
  if (val_memory_map_dma_buffers_el3(buffer_va,
                                     buffer_pa,
                                     length,
                                     REALM_PAS) != ACS_STATUS_PASS)
  {
    result = ACS_STATUS_ERR;
    goto cleanup;
  }

  if (val_memory_prepare_dma_buffers_el3(buffer_src,
                                         buffer_dst,
                                         length,
                                         0x5Au,
                                         0x00u) != ACS_STATUS_PASS)
  {
    result = ACS_STATUS_ERR;
    goto cleanup;
  }

  /*
   * RUN branch: do not program EXERCISER_SEC_SID.  A successful Realm DMA
   * proves the endpoint/root complex supplied the TDI RID and Realm SEC_SID.
   */
  result = run_realm_dma_round(endpoint_bdf,
                               buffer_src_pa,
                               buffer_dst_pa,
                               (uint64_t)buffer_src,
                               (uint64_t)buffer_dst,
                               length,
                               1u,
                               1u);
  if (result != ACS_STATUS_PASS)
  {
    val_print(ACS_PRINT_ERR, " RYDSYL: RUN Realm DMA did not complete", 0);
    goto cleanup;
  }
  *positive_done = 1u;

cleanup:
  if (buffer_valid != 0u)
  {
    if (val_add_gpt_entry_el3(buffer_src_pa, GPT_ANY))
      result = ACS_STATUS_ERR;
    if (val_add_gpt_entry_el3(buffer_dst_pa, GPT_ANY))
      result = ACS_STATUS_ERR;
  }

  if (pgt_desc_ns.pgt_base != 0u)
  {
    if (val_add_gpt_entry_el3(pgt_desc_ns.pgt_base, GPT_ANY))
      result = ACS_STATUS_ERR;
  }
  if (pgt_desc_rlm.pgt_base != 0u)
  {
    if (val_add_gpt_entry_el3(pgt_desc_rlm.pgt_base, GPT_ANY))
      result = ACS_STATUS_ERR;
  }

  if (smmu_rlm_mapped != 0u)
    smmu_rlm_mapped = 0u;
  if (pgt_rlm_created != 0u)
    val_rlm_pgt_destroy(&pgt_desc_rlm);
  if (smmu_ns_mapped != 0u)
    smmu_ns_mapped = 0u;
  if (pgt_ns_created != 0u)
    val_pgt_destroy(pgt_desc_ns);
  if (master.smmu_index != ACS_INVALID_INDEX)
    val_smmu_disable(master.smmu_index);

  return result;
}

static uint32_t
check_non_run_realm_dma_rejected(uint32_t endpoint_bdf,
                                 uint32_t length)
{
  smmu_master_attributes_t master;
  memory_region_descriptor_t mem_desc[2];
  pgt_descriptor_t pgt_desc_ns;
  pgt_descriptor_t pgt_desc_rlm;
  uint8_t *buffer_va;
  uint8_t *buffer_src;
  uint8_t *buffer_dst;
  uint64_t buffer_pa;
  uint64_t buffer_src_pa;
  uint64_t buffer_dst_pa;
  uint64_t total_len;
  uint32_t its_id = 0u;
  uint32_t device_id = 0u;
  uint32_t status;
  uint32_t smmu_index;
  uint32_t pgt_ns_created = 0u;
  uint32_t pgt_rlm_created = 0u;
  uint32_t smmu_ns_mapped = 0u;
  uint32_t smmu_rlm_mapped = 0u;
  uint32_t buffer_valid = 0u;
  uint32_t result = ACS_STATUS_PASS;

  /*
   * Negative RYDSYL check.  The caller has stopped the TDI, so the same
   * endpoint must no longer be able to generate a D2H request that is accepted
   * as Realm.  The setup mirrors the RUN path so the only intended behavioral
   * difference is the TDI state.
   */
  val_memory_set(&master, sizeof(master), 0);
  val_memory_set(mem_desc, sizeof(mem_desc), 0);
  val_memory_set(&pgt_desc_ns, sizeof(pgt_desc_ns), 0);
  val_memory_set(&pgt_desc_rlm, sizeof(pgt_desc_rlm), 0);
  master.smmu_index = ACS_INVALID_INDEX;

  total_len = (uint64_t)length * 2u;
  buffer_va = (uint8_t *)val_get_free_va(total_len);
  if (buffer_va == NULL)
    return ACS_STATUS_SKIP;

  buffer_pa = (uint64_t)val_memory_virt_to_phys(buffer_va);
  if (buffer_pa == 0u)
    return ACS_STATUS_SKIP;

  buffer_src = buffer_va;
  buffer_dst = buffer_va + length;
  buffer_src_pa = buffer_pa;
  buffer_dst_pa = buffer_pa + length;
  buffer_valid = 1u;

  smmu_index = val_iovirt_get_rc_smmu_index(PCIE_EXTRACT_BDF_SEG(endpoint_bdf),
                                            PCIE_CREATE_BDF_PACKED(endpoint_bdf));
  if (smmu_index == ACS_INVALID_INDEX)
    return ACS_STATUS_SKIP;

  master.smmu_index = smmu_index;
  if (val_smmu_enable(master.smmu_index))
  {
    result = ACS_STATUS_ERR;
    goto cleanup;
  }

  status = val_iovirt_get_device_info(PCIE_CREATE_BDF_PACKED(endpoint_bdf),
                                      PCIE_EXTRACT_BDF_SEG(endpoint_bdf),
                                      &device_id,
                                      &master.streamid,
                                      &its_id);
  if (status != 0u)
  {
    result = ACS_STATUS_SKIP;
    goto cleanup;
  }

  mem_desc[0].virtual_address = buffer_pa;
  mem_desc[0].physical_address = buffer_pa;
  mem_desc[0].length = (uint32_t)total_len;
  mem_desc[1].length = 0u;

  pgt_desc_ns.ias = val_smmu_get_info(SMMU_IN_ADDR_SIZE, master.smmu_index);
  pgt_desc_ns.oas = val_smmu_get_info(SMMU_OUT_ADDR_SIZE, master.smmu_index);
  if ((pgt_desc_ns.ias == 0u) || (pgt_desc_ns.oas == 0u))
  {
    result = ACS_STATUS_SKIP;
    goto cleanup;
  }

  if (val_pe_reg_read_tcr(0, &pgt_desc_ns.tcr))
  {
    result = ACS_STATUS_ERR;
    goto cleanup;
  }

  pgt_desc_ns.mair = val_pe_reg_read(MAIR_ELx);
  pgt_desc_ns.stage = PGT_STAGE1;
  pgt_desc_ns.pgt_base = (uint64_t)NULL;
  mem_desc[0].attributes = PGT_STAGE1_AP_RW;

  if (val_pgt_create(mem_desc, &pgt_desc_ns))
  {
    result = ACS_STATUS_ERR;
    goto cleanup;
  }
  pgt_ns_created = 1u;

  master.stage2 = 0;
  if (val_smmu_map(master, pgt_desc_ns))
  {
    result = ACS_STATUS_ERR;
    goto cleanup;
  }
  smmu_ns_mapped = 1u;

  if (val_pe_get_vtcr(&pgt_desc_rlm.vtcr))
  {
    result = ACS_STATUS_ERR;
    goto cleanup;
  }

  pgt_desc_rlm.ias = pgt_desc_ns.ias;
  pgt_desc_rlm.oas = pgt_desc_ns.oas;
  pgt_desc_rlm.pgt_base = (uint64_t)NULL;
  mem_desc[0].attributes = PGT_STAGE2_AP_RW;

  if (val_memory_map_el3_data((uint64_t)mem_desc,
                              sizeof(mem_desc),
                              NONSECURE_PAS) != ACS_STATUS_PASS)
  {
    result = ACS_STATUS_ERR;
    goto cleanup;
  }
  if (val_memory_map_el3_data((uint64_t)&pgt_desc_rlm,
                              sizeof(pgt_desc_rlm),
                              NONSECURE_PAS) != ACS_STATUS_PASS)
  {
    result = ACS_STATUS_ERR;
    goto cleanup;
  }
  if (val_memory_map_el3_data((uint64_t)&master,
                              sizeof(master),
                              NONSECURE_PAS) != ACS_STATUS_PASS)
  {
    result = ACS_STATUS_ERR;
    goto cleanup;
  }

  if (val_rlm_pgt_create(mem_desc, &pgt_desc_rlm))
  {
    result = ACS_STATUS_ERR;
    goto cleanup;
  }
  pgt_rlm_created = 1u;

  val_pe_reg_write(VTTBR, pgt_desc_rlm.pgt_base);
  master.stage2 = 1;
  if (val_smmu_rlm_map_el3(&master, &pgt_desc_rlm))
  {
    result = ACS_STATUS_ERR;
    goto cleanup;
  }
  smmu_rlm_mapped = 1u;

  if (val_exerciser_set_param_by_bdf(CFG_TXN_ATTRIBUTES,
                                     TXN_ADDR_TYPE,
                                     AT_TRANSLATED,
                                     endpoint_bdf))
  {
    result = ACS_STATUS_SKIP;
    goto cleanup;
  }

  if (val_exerciser_set_param_by_bdf(CFG_TXN_ATTRIBUTES,
                                     TXN_REQ_ID_VALID,
                                     RID_NOT_VALID,
                                     endpoint_bdf))
  {
    result = ACS_STATUS_SKIP;
    goto cleanup;
  }

  if (val_add_gpt_entry_el3(buffer_src_pa, GPT_REALM))
  {
    result = ACS_STATUS_ERR;
    goto cleanup;
  }
  if (val_add_gpt_entry_el3(buffer_dst_pa, GPT_REALM))
  {
    result = ACS_STATUS_ERR;
    goto cleanup;
  }

  if (val_smmu_gpt_invalidate_el3(&master))
  {
    result = ACS_STATUS_ERR;
    goto cleanup;
  }

  if (val_memory_map_dma_buffers_el3(buffer_va,
                                     buffer_pa,
                                     length,
                                     REALM_PAS) != ACS_STATUS_PASS)
  {
    result = ACS_STATUS_ERR;
    goto cleanup;
  }

  if (val_memory_prepare_dma_buffers_el3(buffer_src,
                                         buffer_dst,
                                         length,
                                         0x5Au,
                                         0x00u) != ACS_STATUS_PASS)
  {
    result = ACS_STATUS_ERR;
    goto cleanup;
  }

  /*
   * First try a complete to-device/from-device DMA cycle.  In non-RUN state,
   * accepting this as a Realm transfer means the device/root path is still
   * presenting RUN-style identity, which violates RYDSYL.
   */
  if (run_realm_dma_round(endpoint_bdf,
                          buffer_src_pa,
                          buffer_dst_pa,
                          (uint64_t)buffer_src,
                          (uint64_t)buffer_dst,
                          length,
                          1u,
                          0u) != ACS_STATUS_PASS)
  {
    val_print(ACS_PRINT_ERR, " RYDSYL: non-RUN Realm DMA was accepted", 0);
    result = ACS_STATUS_FAIL;
    goto cleanup;
  }

  /*
   * Also check a pure D2H write using whatever data the exerciser already has.
   * This avoids depending only on the to-device load phase being rejected.
   */
  if (val_memory_set_el3(buffer_dst, length, 0x00u))
  {
    result = ACS_STATUS_ERR;
    goto cleanup;
  }

  result = run_realm_dma_round(endpoint_bdf,
                               buffer_src_pa,
                               buffer_dst_pa,
                               (uint64_t)buffer_src,
                               (uint64_t)buffer_dst,
                               length,
                               0u,
                               0u);
  if (result != ACS_STATUS_PASS)
    val_print(ACS_PRINT_ERR, " RYDSYL: non-RUN D2H write was accepted", 0);

cleanup:
  if (buffer_valid != 0u)
  {
    if (val_add_gpt_entry_el3(buffer_src_pa, GPT_ANY))
      result = ACS_STATUS_ERR;
    if (val_add_gpt_entry_el3(buffer_dst_pa, GPT_ANY))
      result = ACS_STATUS_ERR;
  }

  if (pgt_desc_ns.pgt_base != 0u)
  {
    if (val_add_gpt_entry_el3(pgt_desc_ns.pgt_base, GPT_ANY))
      result = ACS_STATUS_ERR;
  }
  if (pgt_desc_rlm.pgt_base != 0u)
  {
    if (val_add_gpt_entry_el3(pgt_desc_rlm.pgt_base, GPT_ANY))
      result = ACS_STATUS_ERR;
  }

  if (smmu_rlm_mapped != 0u)
    smmu_rlm_mapped = 0u;
  if (pgt_rlm_created != 0u)
    val_rlm_pgt_destroy(&pgt_desc_rlm);
  if (smmu_ns_mapped != 0u)
    smmu_ns_mapped = 0u;
  if (pgt_ns_created != 0u)
    val_pgt_destroy(pgt_desc_ns);
  if (master.smmu_index != ACS_INVALID_INDEX)
    val_smmu_disable(master.smmu_index);

  return result;
}

static uint32_t
exercise_rule(const RYDSYL_CONTEXT *context)
{
  val_spdm_context_t spdm_ctx;
  uint32_t session_id;
  uint32_t ide_enabled;
  uint32_t session_active;
  uint32_t root_ide_active;
  uint32_t root_ide_supported;
  uint32_t endpoint_ide_active;
  uint32_t endpoint_ide_supported;
  uint32_t positive_done;
  uint32_t page_size;
  uint32_t status;
  uint32_t result;

  if (context == NULL)
    return ACS_STATUS_ERR;

  /*
   * Test sequence:
   * 1. Put the TDI in RUN and establish IDE when required by the platform.
   * 2. Verify the D2H Realm DMA is accepted with implicit TDI RID/Realm state.
   * 3. Stop the TDI and verify the same Realm DMA path is rejected.
   */
  val_memory_set(&spdm_ctx, sizeof(spdm_ctx), 0);
  session_id = 0u;
  ide_enabled = 0u;
  session_active = 0u;
  positive_done = 0u;
  result = ACS_STATUS_FAIL;

  page_size = val_memory_page_size();
  if (page_size == 0u)
    return ACS_STATUS_ERR;

  status = establish_tdisp_run(context->endpoint_bdf, &spdm_ctx, &session_id);
  if (status != ACS_STATUS_PASS)
  {
    val_print(ACS_PRINT_INFO, " RYDSYL: TDI RUN setup unavailable", 0);
    return (status == ACS_STATUS_SKIP) ? ACS_STATUS_SKIP : ACS_STATUS_FAIL;
  }
  session_active = 1u;

  status = val_cxl_ide_establish_link(context->root_index,
                                      context->endpoint_index,
                                      &spdm_ctx,
                                      session_id);
  if (status == ACS_STATUS_PASS)
  {
    ide_enabled = 1u;
  }
  else if (status != ACS_STATUS_SKIP)
  {
    result = ACS_STATUS_FAIL;
    goto cleanup;
  }

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

  if (((root_ide_supported != 0u) && (root_ide_active == 0u)) ||
      ((endpoint_ide_supported != 0u) && (endpoint_ide_active == 0u)))
  {
    val_print(ACS_PRINT_INFO, " RYDSYL: IDE supported but not active", 0);
    result = ACS_STATUS_SKIP;
    goto cleanup;
  }

  status = check_implicit_sec_sid_and_rid(context->endpoint_bdf,
                                          page_size,
                                          &positive_done);
  if (status != ACS_STATUS_PASS)
  {
    result = status;
    goto cleanup;
  }

  val_print(ACS_PRINT_INFO, " RYDSYL: RUN Realm DMA accepted", 0);

  status = stop_tdisp_interface(context->endpoint_bdf, &spdm_ctx, session_id);
  if (status != ACS_STATUS_PASS)
  {
    result = ACS_STATUS_FAIL;
    goto cleanup;
  }

  status = check_non_run_realm_dma_rejected(context->endpoint_bdf, page_size);
  if (status != ACS_STATUS_PASS)
  {
    result = status;
    goto cleanup;
  }

  val_print(ACS_PRINT_INFO, " RYDSYL: non-RUN Realm DMA rejected", 0);
  result = ACS_STATUS_PASS;

cleanup:
  if (ide_enabled != 0u)
  {
    if (val_cxl_ide_disable_link(context->root_index,
                                 context->endpoint_index,
                                 &spdm_ctx,
                                 session_id) != ACS_STATUS_PASS)
    {
      val_print(ACS_PRINT_ERR, " RYDSYL: IDE disable failed", 0);
      result = ACS_STATUS_FAIL;
    }
  }

  if (session_active != 0u)
  {
    if (val_spdm_session_close(&spdm_ctx, session_id) != ACS_STATUS_PASS)
    {
      val_print(ACS_PRINT_ERR, " RYDSYL: SPDM session close failed", 0);
      result = ACS_STATUS_FAIL;
    }
  }

  if ((positive_done == 0u) && (result == ACS_STATUS_PASS))
    result = ACS_STATUS_FAIL;

  return result;
}

static void
payload(void)
{
  uint32_t pe_index;
  uint32_t cleanup_status;
  uint32_t status;
  RYDSYL_CONTEXT context;

  pe_index = val_pe_get_index_mpid(val_pe_get_mpid());

  status = prepare_context(&context);
  if (status == ACS_STATUS_SKIP)
  {
    val_print(ACS_PRINT_INFO, " RYDSYL: no suitable CHI-C2C CDA context", 0);
    val_set_status(pe_index, "SKIP", 01);
    return;
  }

  if (status != ACS_STATUS_PASS)
  {
    val_set_status(pe_index, "FAIL", 01);
    return;
  }

  status = exercise_rule(&context);
  cleanup_status = restore_rmecda_registers(&context);
  if (cleanup_status != ACS_STATUS_PASS)
  {
    val_print(ACS_PRINT_ERR, " RYDSYL: RMECDA cleanup failed", 0);
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
cda_rydsyl_d2h_sec_sid_rid_entry(uint32_t num_pe)
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
