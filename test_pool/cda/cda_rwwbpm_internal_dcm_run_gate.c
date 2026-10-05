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
#include "val/include/val_dpt.h"
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

#define TEST_NAME "cda_rwwbpm_internal_dcm_run_gate"
#define TEST_DESC "Internal Realm DCM access allowed only in RUN     "
#define TEST_RULE "RWWBPM"

#define RMECDA_CTL1_TDISP_EN_MASK 0x1u
#define RMECDA_CTL1_LINK_STR_LOCK_MASK (1u << 1)
#define DECODER_SLOT CXL_HDM_DECODER_SLOT_DEFAULT
#define DMA_TEST_LENGTH ((uint32_t)sizeof(uint64_t))
#define SEC_SID_REALM_VALID ((1u << 31) | (1u << 1))

#define RUN_BASELINE_VALUE  0x0123456789ABCDEFull
#define RUN_WRITE_VALUE     0xF0E1D2C3B4A59687ull
#define STOP_BASELINE_VALUE 0x13579BDF2468ACE0ull
#define STOP_WRITE_VALUE    0x0ACE2468FDB97531ull

#if ENABLE_SPDM

typedef struct {
  /* CHI-C2C capable Root Port under test. */
  uint32_t root_index;
  uint32_t root_bdf;
  /* Downstream CHI-C2C exerciser endpoint used to generate internal accesses. */
  uint32_t endpoint_index;
  uint32_t endpoint_bdf;
  uint32_t host_index;
  uint64_t host_decoder_base_orig;
  uint64_t host_decoder_size_orig;
  uint32_t host_target_low_orig;
  uint32_t host_target_high_orig;
  uint32_t host_decoder_valid;
  /* One DCM location represented in both host and device address spaces. */
  uint64_t dcm_hpa;
  uint64_t dcm_dpa;
  uint64_t endpoint_decoder_base_orig;
  uint64_t endpoint_decoder_size_orig;
  uint32_t endpoint_decoder_valid;
  /* Original RMECDA_CTL1 value restored during cleanup. */
  uint32_t rmecda_ctl1_orig;
  uint32_t rmecda_ctl1_valid;
  uint32_t rmecda_cap_base;
  uint64_t rmecda_cfg_va;
} TEST_CONTEXT;

typedef struct {
  val_spdm_context_t spdm_ctx;
  pci_tdisp_interface_id_t interface_id;
  uint32_t session_id;
  uint32_t session_active;
  uint32_t ide_active;
  uint32_t tdi_run;
} LINK_CONTEXT;

static void
init_context(TEST_CONTEXT *context)
{
  if (context == NULL)
    return;

  val_memory_set(context, sizeof(*context), 0);
  context->root_index = CXL_COMPONENT_INVALID_INDEX;
  context->endpoint_index = CXL_COMPONENT_INVALID_INDEX;
  context->host_index = CXL_COMPONENT_INVALID_INDEX;
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

  if ((context->endpoint_decoder_valid != 0u) &&
      (((context->endpoint_decoder_size_orig == 0u) &&
        (val_cxl_disable_component_decoder(context->endpoint_index,
                                           DECODER_SLOT) != ACS_STATUS_PASS)) ||
       ((context->endpoint_decoder_size_orig != 0u) &&
        (val_cxl_program_component_decoder(context->endpoint_index,
                                           DECODER_SLOT,
                                           context->endpoint_decoder_base_orig,
                                           context->endpoint_decoder_size_orig)
         != ACS_STATUS_PASS))))
  {
    val_print(ACS_PRINT_WARN, " RWWBPM: endpoint decoder restore failed", 0);
    restore_status = ACS_STATUS_ERR;
  }

  if ((context->host_decoder_valid != 0u) &&
      (val_cxl_restore_host_decoder(context->host_index,
                                    DECODER_SLOT,
                                    context->host_decoder_base_orig,
                                    context->host_decoder_size_orig,
                                    1u,
                                    context->host_target_low_orig,
                                    context->host_target_high_orig)
       != ACS_STATUS_PASS))
  {
    val_print(ACS_PRINT_WARN, " RWWBPM: host decoder restore failed", 0);
    restore_status = ACS_STATUS_ERR;
  }

  return restore_status;
}

static uint32_t
select_test_hpa(uint64_t window_base,
                uint64_t window_size,
                uint64_t *test_hpa_out)
{
  uint64_t page_size;
  uint64_t window_end;
  uint64_t aligned_base;

  if (test_hpa_out == NULL)
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

  *test_hpa_out = aligned_base;
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
    uint64_t window_base;
    uint64_t window_size;
    uint64_t test_hpa;

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

    if (val_cxl_find_component_index_by_bdf(endpoint_bdf,
                                            &candidate.endpoint_index)
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
    candidate.root_index = root_idx;
    candidate.endpoint_bdf = endpoint->bdf;
    candidate.host_index = root_port->host_bridge_index;

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

    if ((candidate.host_index == CXL_COMPONENT_INVALID_INDEX) ||
        (val_cxl_select_cfmws_window(candidate.host_index,
                                     &window_base,
                                     &window_size) != ACS_STATUS_PASS))
    {
      val_print(ACS_PRINT_DEBUG,
                " RWWBPM: no CFMWS window for EP 0x%x",
                (uint64_t)candidate.endpoint_bdf);
      continue;
    }

    if ((val_cxl_get_decoder(candidate.host_index,
                             DECODER_SLOT,
                             &candidate.host_decoder_base_orig,
                             &candidate.host_decoder_size_orig) != 0u) ||
        (val_cxl_get_host_decoder_target(candidate.host_index,
                                         DECODER_SLOT,
                                         &candidate.host_target_low_orig,
                                         &candidate.host_target_high_orig) != 0u))
    {
      val_print(ACS_PRINT_DEBUG, " RWWBPM: failed to save host decoder state", 0);
      continue;
    }
    candidate.host_decoder_valid = 1u;

    if (val_cxl_get_component_decoder(candidate.endpoint_index,
                                      DECODER_SLOT,
                                      &candidate.endpoint_decoder_base_orig,
                                      &candidate.endpoint_decoder_size_orig) != 0u)
    {
      val_print(ACS_PRINT_DEBUG,
                " RWWBPM: failed to save endpoint decoder state",
                0);
      continue;
    }
    candidate.endpoint_decoder_valid = 1u;

    if (val_cxl_enable_mem(endpoint->bdf) != ACS_STATUS_PASS)
    {
      val_print(ACS_PRINT_DEBUG,
                " RWWBPM: CXL.mem enable failed for EP 0x%x",
                (uint64_t)endpoint->bdf);
      if (restore_context_state(&candidate) != ACS_STATUS_PASS)
        return ACS_STATUS_ERR;
      continue;
    }

    if (val_cxl_program_host_decoder_for_root(candidate.root_bdf,
                                              candidate.host_index,
                                              DECODER_SLOT,
                                              window_base,
                                              window_size) != ACS_STATUS_PASS)
    {
      val_print(ACS_PRINT_DEBUG, " RWWBPM: failed to program host decoder", 0);
      if (restore_context_state(&candidate) != ACS_STATUS_PASS)
        return ACS_STATUS_ERR;
      continue;
    }

    if (val_cxl_program_component_decoder(candidate.endpoint_index,
                                          DECODER_SLOT,
                                          window_base,
                                          window_size) != ACS_STATUS_PASS)
    {
      val_print(ACS_PRINT_DEBUG,
                " RWWBPM: failed to program endpoint decoder",
                0);
      if (restore_context_state(&candidate) != ACS_STATUS_PASS)
        return ACS_STATUS_ERR;
      continue;
    }

    status = select_test_hpa(window_base, window_size, &test_hpa);
    if ((status != ACS_STATUS_PASS) ||
        (val_cxl_hpa_to_dpa(candidate.endpoint_index,
                            test_hpa,
                            &candidate.dcm_dpa) != ACS_STATUS_PASS))
    {
      val_print(ACS_PRINT_DEBUG,
                " RWWBPM: cannot derive a test DPA from endpoint HDM",
                0);
      if (restore_context_state(&candidate) != ACS_STATUS_PASS)
        return ACS_STATUS_ERR;
      continue;
    }
    candidate.dcm_hpa = test_hpa;

    val_print(ACS_PRINT_DEBUG, " RWWBPM: selected DCM HPA 0x%llx", test_hpa);
    val_print(ACS_PRINT_DEBUG,
              " RWWBPM: translated DCM DPA 0x%llx",
              candidate.dcm_dpa);

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
prepare_smmu_mapping(uint32_t endpoint_bdf,
                     uint64_t source_pa,
                     uint64_t dcm_hpa,
                     uint64_t page_size,
                     smmu_master_attributes_t *master,
                     pgt_descriptor_t *pgt_desc)
{
  memory_region_descriptor_t mem_desc[3];
  uint32_t device_id;
  uint32_t its_id;
  uint32_t smmu_index;

  if ((source_pa == 0u) || (dcm_hpa == 0u) || (page_size == 0u) ||
      (master == NULL) || (pgt_desc == NULL))
    return ACS_STATUS_ERR;

  val_memory_set(master, sizeof(*master), 0);
  val_memory_set(pgt_desc, sizeof(*pgt_desc), 0);
  master->smmu_index = ACS_INVALID_INDEX;

  smmu_index = val_iovirt_get_rc_smmu_index(PCIE_EXTRACT_BDF_SEG(endpoint_bdf),
                                            PCIE_CREATE_BDF_PACKED(endpoint_bdf));
  if ((smmu_index == ACS_INVALID_INDEX) ||
      (val_iovirt_get_smmu_info(SMMU_CTRL_ARCH_MAJOR_REV, smmu_index) != 3u))
    return ACS_STATUS_SKIP;

  device_id = 0u;
  its_id = 0u;
  if (val_iovirt_get_device_info(PCIE_CREATE_BDF_PACKED(endpoint_bdf),
                                 PCIE_EXTRACT_BDF_SEG(endpoint_bdf),
                                 &device_id,
                                 &master->streamid,
                                 &its_id) != 0u)
    return ACS_STATUS_SKIP;

  if (val_smmu_enable(smmu_index) != 0u)
    return ACS_STATUS_ERR;

  master->smmu_index = smmu_index;
  master->stage2 = 1u;

  val_memory_set(mem_desc, sizeof(mem_desc), 0);
  mem_desc[0].virtual_address = source_pa;
  mem_desc[0].physical_address = source_pa;
  mem_desc[0].length = page_size;
  /* The host source remains Non-secure after Realm stage-2 translation. */
  mem_desc[0].attributes = PGT_STAGE2_AP_RW | PGT_STAGE2_RME_NS_MASK;
  mem_desc[1].virtual_address = dcm_hpa;
  mem_desc[1].physical_address = dcm_hpa;
  mem_desc[1].length = page_size;
  /* RME_NS clear makes the DCM translation a Realm output translation. */
  mem_desc[1].attributes = PGT_STAGE2_AP_RW;

  pgt_desc->ias = (uint32_t)val_smmu_get_info(SMMU_IN_ADDR_SIZE, smmu_index);
  pgt_desc->oas = (uint32_t)val_smmu_get_info(SMMU_OUT_ADDR_SIZE, smmu_index);
  pgt_desc->stage = PGT_STAGE2;
  if ((pgt_desc->ias == 0u) || (pgt_desc->oas == 0u))
    return ACS_STATUS_SKIP;

  if (val_pe_get_vtcr(&pgt_desc->vtcr) != 0u)
    return ACS_STATUS_ERR;

  if ((val_memory_map_el3_data((uint64_t)mem_desc,
                               sizeof(mem_desc),
                               NONSECURE_PAS) != ACS_STATUS_PASS) ||
      (val_memory_map_el3_data((uint64_t)pgt_desc,
                               sizeof(*pgt_desc),
                               NONSECURE_PAS) != ACS_STATUS_PASS) ||
      (val_memory_map_el3_data((uint64_t)master,
                               sizeof(*master),
                               NONSECURE_PAS) != ACS_STATUS_PASS))
    return ACS_STATUS_ERR;

  if (val_rlm_pgt_create(mem_desc, pgt_desc) != 0u)
    return ACS_STATUS_ERR;

  val_pe_reg_write(VTTBR, pgt_desc->pgt_base);
  if (val_smmu_rlm_map_el3(master, pgt_desc) != 0u)
  {
    val_rlm_pgt_destroy(pgt_desc);
    pgt_desc->pgt_base = 0u;
    return ACS_STATUS_ERR;
  }

  return ACS_STATUS_PASS;
}

static uint32_t
establish_realm_link(const TEST_CONTEXT *context, LINK_CONTEXT *link)
{
  uint32_t status;

  if ((context == NULL) || (link == NULL))
    return ACS_STATUS_ERR;

  val_memory_set(link, sizeof(*link), 0);
  status = val_tdisp_establish_run(context->endpoint_bdf,
                                   &link->spdm_ctx,
                                   &link->session_id,
                                   &link->interface_id);
  if (status != ACS_STATUS_PASS)
    return status;

  link->session_active = 1u;
  link->tdi_run = 1u;
  status = val_cxl_ide_establish_link(context->root_index,
                                      context->endpoint_index,
                                      &link->spdm_ctx,
                                      link->session_id);
  if (status != ACS_STATUS_PASS)
    return status;

  link->ide_active = 1u;
  return ACS_STATUS_PASS;
}

static uint32_t
stop_tdi_keep_ide(LINK_CONTEXT *link)
{
  if ((link == NULL) || (link->session_active == 0u) || (link->tdi_run == 0u))
    return ACS_STATUS_ERR;

  if (val_spdm_send_pci_tdisp_stop_interface(&link->spdm_ctx,
                                              link->session_id,
                                              &link->interface_id)
      != ACS_STATUS_PASS)
    return ACS_STATUS_FAIL;

  link->tdi_run = 0u;
  return ACS_STATUS_PASS;
}

static uint32_t
cleanup_realm_link(const TEST_CONTEXT *context, LINK_CONTEXT *link)
{
  uint32_t result;

  if ((context == NULL) || (link == NULL))
    return ACS_STATUS_ERR;

  result = ACS_STATUS_PASS;
  if (link->ide_active != 0u)
  {
    if (val_cxl_ide_disable_link(context->root_index,
                                 context->endpoint_index,
                                 &link->spdm_ctx,
                                 link->session_id) != ACS_STATUS_PASS)
      result = ACS_STATUS_FAIL;
    link->ide_active = 0u;
  }

  if (link->session_active != 0u)
  {
    if (link->tdi_run != 0u)
      (void)val_spdm_send_pci_tdisp_stop_interface(&link->spdm_ctx,
                                                   link->session_id,
                                                   &link->interface_id);
    if (val_spdm_session_close(&link->spdm_ctx, link->session_id)
        != ACS_STATUS_PASS)
      result = ACS_STATUS_FAIL;
    link->session_active = 0u;
    link->tdi_run = 0u;
  }

  return result;
}

static uint32_t
cache_ats_translation(uint32_t endpoint_bdf,
                      uint64_t iova,
                      uint64_t expected_pa,
                      uint32_t expected_te,
                      uint32_t page_size)
{
  VAL_ATS_TRANSLATION_RESULT response;
  uint32_t status;

  status = val_exerciser_ats_translate_by_bdf(endpoint_bdf,
                                               iova,
                                               page_size,
                                               VAL_ATS_REQUEST_T,
                                               &response);
  if (status != ACS_STATUS_PASS)
    return status;

  if ((response.completion_success == 0u) ||
      (response.translated_pa != expected_pa) ||
      (response.te != expected_te) ||
      ((response.response_attributes & VAL_ATS_PERMISSION_MASK) == 0u))
  {
    val_print(ACS_PRINT_ERR, " RWWBPM: ATS PA 0x%llx", response.translated_pa);
    val_print(ACS_PRINT_ERR, " RWWBPM: ATS TE %u", (uint64_t)response.te);
    val_print(ACS_PRINT_ERR,
              " RWWBPM: ATS attributes 0x%x",
              (uint64_t)response.response_attributes);
    return ACS_STATUS_FAIL;
  }

  return ACS_STATUS_PASS;
}

static uint32_t
run_atc_backed_dma(uint32_t endpoint_bdf,
                   uint64_t iova,
                   EXERCISER_DMA_ATTR direction)
{
  uint32_t status;

  status = val_exerciser_dma_with_atc_by_bdf(endpoint_bdf,
                                              iova,
                                              DMA_TEST_LENGTH,
                                              direction);
  if (status != ACS_STATUS_PASS)
  {
    /* This helper also serves the negative case; callers report unexpected failures. */
    val_print(ACS_PRINT_DEBUG, " RWWBPM: ATC DMA direction %u failed", (uint64_t)direction);
    val_print(ACS_PRINT_DEBUG, " RWWBPM: ATC DMA status %u", (uint64_t)status);
  }

  return status;
}

static uint32_t
run_direct_pa_dma(uint32_t endpoint_bdf,
                  uint64_t physical_address,
                  EXERCISER_DMA_ATTR direction)
{
  uint32_t status;

  /*
   * For PAS_CHECK==TRUE, submit the physical address directly and keep ATC
   * use disabled; this path does not depend on a host-provided ATS result.
   */
  if ((val_exerciser_set_param_by_bdf(CFG_TXN_ATTRIBUTES,
                                      TXN_ATC_ENTRY,
                                      ATC_ENTRY_DISABLE,
                                      endpoint_bdf) != 0u) ||
      (val_exerciser_set_param_by_bdf(CFG_TXN_ATTRIBUTES,
                                      TXN_ADDR_TYPE,
                                      AT_TRANSLATED,
                                      endpoint_bdf) != 0u) ||
      (val_exerciser_set_param_by_bdf(DMA_ATTRIBUTES,
                                      physical_address,
                                      DMA_TEST_LENGTH,
                                      endpoint_bdf) != 0u))
    return ACS_STATUS_ERR;

  status = val_exerciser_ops_by_bdf(START_DMA, direction, endpoint_bdf);
  if (status != 0u)
  {
    val_print(ACS_PRINT_DEBUG,
              " RWWBPM: direct PA DMA direction %u rejected",
              (uint64_t)direction);
    val_print(ACS_PRINT_DEBUG,
              " RWWBPM: direct PA DMA status %u",
              (uint64_t)status);
    return ACS_STATUS_FAIL;
  }

  return ACS_STATUS_PASS;
}

static uint32_t
run_internal_dma(uint32_t endpoint_bdf,
                 uint64_t address,
                 uint32_t expected_te,
                 uint32_t page_size,
                 EXERCISER_DMA_ATTR direction,
                 uint32_t pas_check)
{
  uint32_t status;

  if (pas_check != 0u)
    return run_direct_pa_dma(endpoint_bdf, address, direction);

  /* PAS_CHECK==FALSE requires a host-provided Realm translation. */
  status = cache_ats_translation(endpoint_bdf,
                                 address,
                                 address,
                                 expected_te,
                                 page_size);
  if (status != ACS_STATUS_PASS)
    return status;

  return run_atc_backed_dma(endpoint_bdf, address, direction);
}

static uint32_t
exercise_rule(TEST_CONTEXT *context)
{
  LINK_CONTEXT link;
  VAL_SMMU_DPT_CFG_STATE dpt_cfg_state;
  smmu_master_attributes_t master;
  pgt_descriptor_t pgt_desc;
  uint8_t *source_va;
  uint64_t source_pa;
  uint64_t max_pa;
  uint64_t observed;
  uint64_t test_dpa;
  uint64_t test_hpa;
  uint32_t ats_cap_base;
  uint32_t ats_ctrl_orig;
  uint32_t ats_enabled;
  uint32_t dcm_dpt_set;
  uint32_t dcm_gpt_set;
  uint32_t device_properties;
  uint32_t endpoint_rid;
  uint32_t page_size;
  uint32_t pas_check;
  uint32_t pgt_created;
  uint32_t realm_assigned;
  uint32_t result;
  uint32_t rid_range_programmed;
  uint32_t rmecda_ctl3_orig;
  uint32_t rmecda_ctl4_orig;
  uint32_t smmu_enabled;
  uint32_t sec_sid_programmed;
  uint32_t source_dpt_set;
  uint32_t source_gpt_set;
  uint32_t status;

  if (context == NULL)
    return ACS_STATUS_ERR;

  val_memory_set(&link, sizeof(link), 0);
  val_memory_set(&dpt_cfg_state, sizeof(dpt_cfg_state), 0);
  val_memory_set(&master, sizeof(master), 0);
  val_memory_set(&pgt_desc, sizeof(pgt_desc), 0);
  master.smmu_index = ACS_INVALID_INDEX;

  test_hpa = context->dcm_hpa;
  test_dpa = context->dcm_dpa;
  val_print(ACS_PRINT_INFO, " RWWBPM: Realm DCM HPA 0x%llx", test_hpa);
  val_print(ACS_PRINT_INFO, " RWWBPM: Realm DCM DPA 0x%llx", test_dpa);

  source_va = NULL;
  ats_enabled = 0u;
  dcm_dpt_set = 0u;
  dcm_gpt_set = 0u;
  pgt_created = 0u;
  realm_assigned = 0u;
  rid_range_programmed = 0u;
  sec_sid_programmed = 0u;
  smmu_enabled = 0u;
  source_dpt_set = 0u;
  source_gpt_set = 0u;
  result = ACS_STATUS_FAIL;

  status = val_tdisp_get_device_properties(context->endpoint_bdf,
                                            &device_properties);
  if (status != ACS_STATUS_PASS)
  {
    result = status;
    goto cleanup;
  }
  pas_check = ((device_properties & VAL_TDISP_DEV_PROP_PAS_CHECK) != 0u) ? 1u : 0u;
  val_print(ACS_PRINT_INFO,
            " RWWBPM: endpoint PAS_CHECK %u",
            (uint64_t)pas_check);

  page_size = val_memory_page_size();
  if (page_size == 0u)
    return ACS_STATUS_ERR;

  source_va = (uint8_t *)val_memory_alloc_pages(1u);
  if (source_va == NULL)
    return ACS_STATUS_ERR;

  source_pa = (uint64_t)val_memory_virt_to_phys(source_va);
  if (source_pa == 0u)
  {
    result = ACS_STATUS_ERR;
    goto cleanup;
  }

  if ((val_memory_map_el3_data((uint64_t)source_va,
                               page_size,
                               NONSECURE_PAS) != ACS_STATUS_PASS) ||
      (val_add_gpt_entry_el3(source_pa, GPT_ANY) != 0u))
  {
    result = ACS_STATUS_ERR;
    goto cleanup;
  }
  source_gpt_set = 1u;

  if (val_add_gpt_entry_el3(test_hpa, GPT_ANY) != 0u)
  {
    result = ACS_STATUS_ERR;
    goto cleanup;
  }
  dcm_gpt_set = 1u;

  status = prepare_smmu_mapping(context->endpoint_bdf,
                                source_pa,
                                test_hpa,
                                page_size,
                                &master,
                                &pgt_desc);
  if (status != ACS_STATUS_PASS)
  {
    result = status;
    goto cleanup;
  }
  smmu_enabled = 1u;
  pgt_created = 1u;

  if (val_smmu_gpt_invalidate_el3(&master) != 0u)
  {
    result = ACS_STATUS_ERR;
    goto cleanup;
  }

  max_pa = (source_pa > test_hpa) ? source_pa : test_hpa;
  status = val_smmu_configure_dpt_coverage(master.smmu_index,
                                           max_pa,
                                           &dpt_cfg_state);
  if (status != ACS_STATUS_PASS)
  {
    result = status;
    goto cleanup;
  }

  if (val_dpt_add_entry(source_pa,
                        (((uint64_t)master.smmu_index << 32) |
                         DPT_RDWR_NS_ACCESS_ENTRY)) != 0u)
  {
    result = ACS_STATUS_ERR;
    goto cleanup;
  }
  source_dpt_set = 1u;

  if (val_dpt_add_entry(test_hpa,
                        (((uint64_t)master.smmu_index << 32) |
                         DPT_RDWR_ACCESS_ENTRY)) != 0u)
  {
    result = ACS_STATUS_ERR;
    goto cleanup;
  }
  dcm_dpt_set = 1u;

  if (val_dpt_invalidate_all(master.smmu_index) != 0u)
  {
    result = ACS_STATUS_ERR;
    goto cleanup;
  }

  if (pas_check == 0u)
  {
    status = val_pcie_enable_ats(context->endpoint_bdf,
                                 &ats_cap_base,
                                 &ats_ctrl_orig);
    if (status != ACS_STATUS_PASS)
    {
      result = status;
      goto cleanup;
    }
    ats_enabled = 1u;
  }
  else
  {
    /*
     * Preserve Realm PAS as the TDI leaves RUN so the negative transaction
     * differs from the positive transaction only in its TDISP state.
     */
    if (val_exerciser_set_param_by_bdf(EXERCISER_SEC_SID,
                                       SEC_SID_REALM_VALID,
                                       0u,
                                       context->endpoint_bdf) != 0u)
    {
      result = ACS_STATUS_SKIP;
      goto cleanup;
    }
    sec_sid_programmed = 1u;
  }

  if ((val_memory_read_el3(context->rmecda_cfg_va + context->rmecda_cap_base +
                           RMECDA_CTL3_OFFSET,
                           &rmecda_ctl3_orig) != ACS_STATUS_PASS) ||
      (val_memory_read_el3(context->rmecda_cfg_va + context->rmecda_cap_base +
                           RMECDA_CTL4_OFFSET,
                           &rmecda_ctl4_orig) != ACS_STATUS_PASS))
  {
    result = ACS_STATUS_ERR;
    goto cleanup;
  }

  endpoint_rid = (uint32_t)PCIE_CREATE_BDF_PACKED(context->endpoint_bdf);
  status = val_cda_program_rid_range(context->rmecda_cfg_va,
                                     context->rmecda_cap_base,
                                     rmecda_ctl3_orig,
                                     rmecda_ctl4_orig,
                                     endpoint_rid,
                                     endpoint_rid,
                                     1u);
  if (status != ACS_STATUS_PASS)
  {
    result = status;
    goto cleanup;
  }
  rid_range_programmed = 1u;

  /* TDI RUN and CXL IDE are both prerequisites for a Realm DCM access. */
  status = establish_realm_link(context, &link);
  if (status != ACS_STATUS_PASS)
  {
    val_print(ACS_PRINT_INFO, " RWWBPM: Realm link setup failed", 0);
    result = status;
    goto cleanup;
  }

  /*
   * Mark the selected DCM page as Realm-assigned. The DPA backdoor is used
   * only to initialize and observe media; it is not the access under test.
   */
  status = val_cxl_exerciser_execute_cmd(context->endpoint_bdf,
                                         CXL_CMD_OP_DCM_SET_REALM_ASSIGNMENT,
                                         test_hpa,
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

  /* Seed and confirm the initial media value through the DPA-only backdoor. */
  if (val_cxl_exerciser_backdoor_write64(context->endpoint_bdf,
                                          test_dpa,
                                          RUN_BASELINE_VALUE) != ACS_STATUS_PASS)
  {
    result = ACS_STATUS_SKIP;
    goto cleanup;
  }

  if (val_cxl_exerciser_backdoor_read64(context->endpoint_bdf,
                                         test_dpa,
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

  /* Load a host-owned source value into the exerciser. */
  *(uint64_t *)source_va = RUN_WRITE_VALUE;
  if (val_memory_cache_clean_invalidate_range_el3((uint64_t)source_va,
                                                   DMA_TEST_LENGTH)
      != ACS_STATUS_PASS)
  {
    result = ACS_STATUS_ERR;
    goto cleanup;
  }

  if (run_internal_dma(context->endpoint_bdf,
                       source_pa,
                       0u,
                       page_size,
                       EDMA_TO_DEVICE,
                       pas_check) != ACS_STATUS_PASS)
  {
    val_print(ACS_PRINT_ERR, " RWWBPM: source DMA failed in RUN", 0);
    result = ACS_STATUS_FAIL;
    goto cleanup;
  }

  /* Write the loaded value to the DCM HPA through the coherent path. */
  if (run_internal_dma(context->endpoint_bdf,
                       test_hpa,
                       1u,
                       page_size,
                       EDMA_FROM_DEVICE,
                       pas_check) != ACS_STATUS_PASS)
  {
    val_print(ACS_PRINT_ERR, " RWWBPM: Realm DCM DMA failed in RUN", 0);
    result = ACS_STATUS_FAIL;
    goto cleanup;
  }

  if (val_cxl_exerciser_backdoor_read64(context->endpoint_bdf,
                                         test_dpa,
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

  /* Load the negative-case value while the TDI is still in RUN. */
  *(uint64_t *)source_va = STOP_WRITE_VALUE;
  if ((val_memory_cache_clean_invalidate_range_el3((uint64_t)source_va,
                                                    DMA_TEST_LENGTH)
       != ACS_STATUS_PASS) ||
      (run_internal_dma(context->endpoint_bdf,
                        source_pa,
                        0u,
                        page_size,
                        EDMA_TO_DEVICE,
                        pas_check) != ACS_STATUS_PASS))
  {
    val_print(ACS_PRINT_ERR, " RWWBPM: negative source DMA setup failed", 0);
    result = ACS_STATUS_FAIL;
    goto cleanup;
  }

  if (val_cxl_exerciser_backdoor_write64(context->endpoint_bdf,
                                          test_dpa,
                                          STOP_BASELINE_VALUE) != ACS_STATUS_PASS)
  {
    result = ACS_STATUS_FAIL;
    goto cleanup;
  }

  if (val_cxl_exerciser_backdoor_read64(context->endpoint_bdf,
                                         test_dpa,
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

  /* PAS_CHECK==FALSE needs the Realm DCM translation cached before STOP. */
  if ((pas_check == 0u) &&
      (cache_ats_translation(context->endpoint_bdf,
                             test_hpa,
                             test_hpa,
                             1u,
                             page_size) != ACS_STATUS_PASS))
  {
    result = ACS_STATUS_FAIL;
    goto cleanup;
  }

  /* Leave RUN while retaining IDE and, when required, the Realm ATC entry. */
  if (stop_tdi_keep_ide(&link) != ACS_STATUS_PASS)
  {
    val_print(ACS_PRINT_ERR, " RWWBPM: STOP_INTERFACE failed", 0);
    result = ACS_STATUS_FAIL;
    goto cleanup;
  }

  status = (pas_check != 0u) ?
           run_direct_pa_dma(context->endpoint_bdf,
                             test_hpa,
                             EDMA_FROM_DEVICE) :
           run_atc_backed_dma(context->endpoint_bdf,
                              test_hpa,
                              EDMA_FROM_DEVICE);

  if (val_cxl_exerciser_backdoor_read64(context->endpoint_bdf,
                                         test_dpa,
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

  /*
   * STOP_INTERFACE transitions the TDI to CONFIG_UNLOCKED. The coherent
   * device is permitted, and may be required, to scrub TDI-associated DCM as
   * part of that transition. Therefore the old baseline is not a valid oracle
   * here. The access is prohibited if its requested value reached the media;
   * any other value can result from the independent scrub operation.
   */
  if (observed != STOP_BASELINE_VALUE)
    val_print(ACS_PRINT_INFO,
              " RWWBPM: CONFIG_UNLOCKED changed DCM to 0x%llx",
              observed);

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
  if ((sec_sid_programmed != 0u) &&
      (val_exerciser_set_param_by_bdf(EXERCISER_SEC_SID,
                                      0u,
                                      0u,
                                      context->endpoint_bdf) != 0u))
    result = ACS_STATUS_FAIL;

  (void)val_exerciser_set_param_by_bdf(CFG_TXN_ATTRIBUTES,
                                       TXN_ATC_ENTRY,
                                       ATC_ENTRY_DISABLE,
                                       context->endpoint_bdf);
  if (ats_enabled != 0u)
  {
    (void)val_exerciser_set_param_by_bdf(EXERCISER_ATS_REQUEST_ATTRIBUTES,
                                         0u,
                                         0u,
                                         context->endpoint_bdf);
    (void)val_exerciser_ops_by_bdf(ATS_INV_CACHE, 0u, context->endpoint_bdf);
  }

  if (realm_assigned != 0u)
  {
    if (val_cxl_exerciser_execute_cmd(context->endpoint_bdf,
                                      CXL_CMD_OP_DCM_SET_REALM_ASSIGNMENT,
                                      test_hpa,
                                      0u,
                                      NULL) != ACS_STATUS_PASS)
    {
      val_print(ACS_PRINT_ERR,
                " RWWBPM: failed to clear Realm DCM assignment",
                0);
      result = ACS_STATUS_FAIL;
    }
  }

  if (cleanup_realm_link(context, &link) != ACS_STATUS_PASS)
    result = ACS_STATUS_FAIL;

  if (rid_range_programmed != 0u)
  {
    if (val_cda_program_rid_range(context->rmecda_cfg_va,
                                  context->rmecda_cap_base,
                                  rmecda_ctl3_orig,
                                  rmecda_ctl4_orig,
                                  (rmecda_ctl4_orig >> 8) & 0xFFFFu,
                                  (rmecda_ctl3_orig >> 8) & 0xFFFFu,
                                  rmecda_ctl4_orig & 0x1u) != ACS_STATUS_PASS)
      result = ACS_STATUS_FAIL;
  }

  if ((source_dpt_set != 0u) || (dcm_dpt_set != 0u))
  {
    if (source_dpt_set != 0u)
      (void)val_dpt_add_entry(source_pa,
                              (((uint64_t)master.smmu_index << 32) |
                               DPT_RDWR_ACCESS_ENTRY));
    if (dcm_dpt_set != 0u)
      (void)val_dpt_add_entry(test_hpa,
                              (((uint64_t)master.smmu_index << 32) |
                               DPT_RDWR_ACCESS_ENTRY));
    (void)val_dpt_invalidate_all(master.smmu_index);
  }

  if (val_smmu_restore_dpt_coverage(&dpt_cfg_state) != ACS_STATUS_PASS)
    result = ACS_STATUS_FAIL;

  if (pgt_desc.pgt_base != 0u)
    (void)val_add_gpt_entry_el3(pgt_desc.pgt_base, GPT_ANY);
  if (pgt_created != 0u)
    val_rlm_pgt_destroy(&pgt_desc);
  if (smmu_enabled != 0u)
    (void)val_smmu_disable(master.smmu_index);

  if ((dcm_gpt_set != 0u) && (val_add_gpt_entry_el3(test_hpa, GPT_ANY) != 0u))
    result = ACS_STATUS_FAIL;
  if ((source_gpt_set != 0u) && (val_add_gpt_entry_el3(source_pa, GPT_ANY) != 0u))
    result = ACS_STATUS_FAIL;

  if (source_va != NULL)
    val_memory_free_pages(source_va, 1u);

  if (ats_enabled != 0u)
    val_pcie_write_cfg(context->endpoint_bdf,
                       ats_cap_base + ATS_CTRL,
                       ats_ctrl_orig);

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
