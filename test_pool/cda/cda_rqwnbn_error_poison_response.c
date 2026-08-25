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

#define TEST_NAME "cda_rqwnbn_error_poison_response"
#define TEST_DESC "TDI ERROR cached Realm responses are poisoned"
#define TEST_RULE "RQWNBN"

#define DECODER_SLOT 0u
#define AER_POISONED_TLP (1u << 12)
#define PGT_STAGE2_RME_NS_MASK (1ull << 55)
#define DMA_TEST_LENGTH ((uint32_t)sizeof(uint64_t))

#define ESR_EC_SHIFT                 26u
#define ESR_EC_MASK                  0x3Fu
#define ESR_EC_DATA_ABORT_SAME_EL    0x25u
#define ESR_ABORT_FSC_MASK           0x3Fu
#define ESR_FSC_SYNC_EXTERNAL_ABORT  0x10u

#define RMECDA_CTL1_TDISP_EN_MASK 0x1u
#define RMECDA_CTL1_LINK_STR_LOCK_MASK (1u << 1)

#define RQWNBN_SNOOP_SEED_VALUE     0xA55A0123456789EFULL
#define RQWNBN_WRITEBACK_SEED_VALUE 0x5AA5FEDCBA987610ULL

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
prepare_realm_dma_mapping(uint32_t endpoint_bdf,
                          uint64_t dcm_hpa,
                          uint64_t verify_pa,
                          uint64_t page_size,
                          smmu_master_attributes_t *master,
                          pgt_descriptor_t *pgt_desc)
{
  memory_region_descriptor_t mem_desc[3];
  uint32_t device_id;
  uint32_t its_id;
  uint32_t smmu_index;

  if ((dcm_hpa == 0u) || (verify_pa == 0u) || (page_size == 0u) ||
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
  mem_desc[0].virtual_address = dcm_hpa;
  mem_desc[0].physical_address = dcm_hpa;
  mem_desc[0].length = 2u * page_size;
  /* Map the adjacent writeback and snoop pages into Realm PAS. */
  mem_desc[0].attributes = PGT_STAGE2_AP_RW;
  mem_desc[1].virtual_address = verify_pa;
  mem_desc[1].physical_address = verify_pa;
  mem_desc[1].length = page_size;
  /* The verification page remains in Non-secure PAS. */
  mem_desc[1].attributes = PGT_STAGE2_AP_RW | PGT_STAGE2_RME_NS_MASK;

  pgt_desc->ias = (uint32_t)val_smmu_get_info(SMMU_IN_ADDR_SIZE, smmu_index);
  pgt_desc->oas = (uint32_t)val_smmu_get_info(SMMU_OUT_ADDR_SIZE, smmu_index);
  pgt_desc->stage = PGT_STAGE2;
  if ((pgt_desc->ias == 0u) || (pgt_desc->oas == 0u))
  {
    (void)val_smmu_disable(smmu_index);
    master->smmu_index = ACS_INVALID_INDEX;
    return ACS_STATUS_SKIP;
  }

  if (val_pe_get_vtcr(&pgt_desc->vtcr) != 0u)
  {
    (void)val_smmu_disable(smmu_index);
    master->smmu_index = ACS_INVALID_INDEX;
    return ACS_STATUS_ERR;
  }

  if ((val_memory_map_el3_data((uint64_t)mem_desc,
                               sizeof(mem_desc),
                               NONSECURE_PAS) != ACS_STATUS_PASS) ||
      (val_memory_map_el3_data((uint64_t)pgt_desc,
                               sizeof(*pgt_desc),
                               NONSECURE_PAS) != ACS_STATUS_PASS) ||
      (val_memory_map_el3_data((uint64_t)master,
                               sizeof(*master),
                               NONSECURE_PAS) != ACS_STATUS_PASS))
  {
    (void)val_smmu_disable(smmu_index);
    master->smmu_index = ACS_INVALID_INDEX;
    return ACS_STATUS_ERR;
  }

  if (val_rlm_pgt_create(mem_desc, pgt_desc) != 0u)
  {
    (void)val_smmu_disable(smmu_index);
    master->smmu_index = ACS_INVALID_INDEX;
    return ACS_STATUS_ERR;
  }

  val_pe_reg_write(VTTBR, pgt_desc->pgt_base);
  if (val_smmu_rlm_map_el3(master, pgt_desc) != 0u)
  {
    val_rlm_pgt_destroy(pgt_desc);
    pgt_desc->pgt_base = 0u;
    (void)val_smmu_disable(smmu_index);
    master->smmu_index = ACS_INVALID_INDEX;
    return ACS_STATUS_ERR;
  }

  return ACS_STATUS_PASS;
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
    val_print(ACS_PRINT_ERR, " RQWNBN: ATS PA 0x%llx", response.translated_pa);
    val_print(ACS_PRINT_ERR, " RQWNBN: ATS TE %u", (uint64_t)response.te);
    val_print(ACS_PRINT_ERR,
              " RQWNBN: ATS attributes 0x%x",
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
    val_print(ACS_PRINT_ERR,
              " RQWNBN: ATC DMA direction %u failed",
              (uint64_t)direction);
  }

  return status;
}

static uint32_t
populate_device_cache_line(uint32_t endpoint_bdf,
                           volatile uint64_t *realm_alias,
                           uint64_t dcm_hpa,
                           uint8_t *verify_va,
                           uint64_t verify_pa,
                           uint64_t seed_value,
                           uint32_t page_size)
{
  uint64_t observed;

  if ((realm_alias == NULL) || (dcm_hpa == 0u) || (verify_va == NULL) ||
      (verify_pa == 0u) || (page_size == 0u))
    return ACS_STATUS_ERR;

  /* Initialize backing DCM, then establish a clean cacheable Realm line. */
  if (val_cda_seed_realm_cache_line(dcm_hpa,
                                    realm_alias,
                                    seed_value) != ACS_STATUS_PASS)
    return ACS_STATUS_FAIL;

  if ((val_memory_set_el3(verify_va, DMA_TEST_LENGTH, 0u) != 0u) ||
      (val_memory_cache_clean_invalidate_range_el3((uint64_t)verify_va,
                                                    DMA_TEST_LENGTH)
       != ACS_STATUS_PASS))
    return ACS_STATUS_ERR;

  /*
   * Fetch the Realm DCM Location through the TDI's ATS-backed coherent path.
   * This verifies that the populated line is reachable with the TDI's Realm
   * translation before the existing line is explicitly marked dirty.
   */
  if ((cache_ats_translation(endpoint_bdf,
                             dcm_hpa,
                             dcm_hpa,
                             1u,
                             page_size) != ACS_STATUS_PASS) ||
      (run_atc_backed_dma(endpoint_bdf,
                          dcm_hpa,
                          EDMA_TO_DEVICE) != ACS_STATUS_PASS))
    return ACS_STATUS_FAIL;

  /*
   * Return the data captured by the device to an ordinary host page. This
   * avoids relying on the exerciser's implementation-defined internal buffer.
   */
  if ((cache_ats_translation(endpoint_bdf,
                             verify_pa,
                             verify_pa,
                             0u,
                             page_size) != ACS_STATUS_PASS) ||
      (run_atc_backed_dma(endpoint_bdf,
                          verify_pa,
                          EDMA_FROM_DEVICE) != ACS_STATUS_PASS) ||
      (val_memory_cache_invalidate_range_el3((uint64_t)verify_va,
                                             DMA_TEST_LENGTH)
       != ACS_STATUS_PASS))
    return ACS_STATUS_FAIL;

  observed = *(volatile uint64_t *)verify_va;
  if (observed != seed_value)
  {
    val_print(ACS_PRINT_ERR,
              " RQWNBN: device cache-fill readback 0x%llx",
              observed);
    return ACS_STATUS_FAIL;
  }

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

    /* Cache-line setup requires Realm output PAS for the device DMA read. */
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

    /* AER is one possible host-visible poison indication, not a prerequisite. */
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

    /* Cache-state stimulus requires an advertised and enabled CXL.cache. */
    if (val_cxl_enable_cache(candidate.endpoint_bdf) != ACS_STATUS_PASS)
    {
      (void)restore_context_state(&candidate);
      val_print(ACS_PRINT_DEBUG,
                " RQWNBN: CXL.cache enable failed for EP 0x%x",
                (uint64_t)candidate.endpoint_bdf);
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
  VAL_SMMU_DPT_CFG_STATE dpt_cfg_state;
  PCIE_ENDPOINT_CFG endpoint_cfg;
  smmu_master_attributes_t master;
  pgt_descriptor_t pgt_desc;
  val_spdm_context_t spdm_ctx;
  pci_tdisp_interface_id_t interface_id;
  uint8_t *verify_va;
  uint64_t verify_pa;
  uint64_t max_pa;
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
  uint32_t ats_cap_base;
  uint32_t ats_ctrl_orig;
  uint32_t ats_enabled;
  uint32_t dcm_dpt_set;
  uint32_t dcm_gpt_set;
  uint32_t dpt_coverage_configured;
  uint32_t pgt_created;
  uint32_t rid_range_programmed;
  uint32_t rmecda_ctl3_orig;
  uint32_t rmecda_ctl4_orig;
  uint32_t smmu_enabled;
  uint32_t verify_dpt_set;
  uint32_t verify_gpt_set;
  uint32_t page_size;
  uint64_t snoop_hpa;
  uint64_t writeback_hpa;
  uint64_t observed;
  uint64_t read_esr;

  if (context == NULL)
    return ACS_STATUS_ERR;

  page_size = val_memory_page_size();
  if (page_size == 0u)
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

  val_memory_set(&dpt_cfg_state, sizeof(dpt_cfg_state), 0);
  val_memory_set(&endpoint_cfg, sizeof(endpoint_cfg), 0);
  val_memory_set(&master, sizeof(master), 0);
  val_memory_set(&pgt_desc, sizeof(pgt_desc), 0);
  val_memory_set(&spdm_ctx, sizeof(spdm_ctx), 0);
  master.smmu_index = ACS_INVALID_INDEX;
  verify_va = NULL;
  verify_pa = 0u;
  session_id = 0u;
  session_open = 0u;
  ide_enabled = 0u;
  tdi_in_error = 0u;
  snoop_realm_assigned = 0u;
  writeback_realm_assigned = 0u;
  endpoint_cfg_valid = 0u;
  ats_enabled = 0u;
  dcm_dpt_set = 0u;
  dcm_gpt_set = 0u;
  dpt_coverage_configured = 0u;
  pgt_created = 0u;
  rid_range_programmed = 0u;
  smmu_enabled = 0u;
  verify_dpt_set = 0u;
  verify_gpt_set = 0u;
  result = ACS_STATUS_FAIL;

  /* Save endpoint state before enabling ATS or starting the secure session. */
  if (val_pcie_save_endpoint_cfg(context->endpoint_bdf, &endpoint_cfg) == ACS_STATUS_PASS)
    endpoint_cfg_valid = 1u;
  else
    val_print(ACS_PRINT_WARN, " RQWNBN: endpoint config snapshot failed", 0);

  verify_va = (uint8_t *)val_memory_alloc_pages(1u);
  if (verify_va == NULL)
    return ACS_STATUS_SKIP;

  verify_pa = (uint64_t)val_memory_virt_to_phys(verify_va);
  if ((verify_pa == 0u) ||
      (val_memory_map_el3_data((uint64_t)verify_va,
                               page_size,
                               NONSECURE_PAS) != ACS_STATUS_PASS))
  {
    result = ACS_STATUS_ERR;
    goto cleanup;
  }

  if (val_add_gpt_entry_el3(verify_pa, GPT_ANY) != 0u)
  {
    result = ACS_STATUS_ERR;
    goto cleanup;
  }
  verify_gpt_set = 1u;

  if ((val_add_gpt_entry_el3(writeback_hpa, GPT_ANY) != 0u) ||
      (val_add_gpt_entry_el3(snoop_hpa, GPT_ANY) != 0u))
  {
    result = ACS_STATUS_ERR;
    goto cleanup;
  }
  dcm_gpt_set = 1u;

  status = prepare_realm_dma_mapping(context->endpoint_bdf,
                                     writeback_hpa,
                                     verify_pa,
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

  max_pa = (snoop_hpa > verify_pa) ? snoop_hpa : verify_pa;
  status = val_smmu_configure_dpt_coverage(master.smmu_index,
                                           max_pa,
                                           &dpt_cfg_state);
  if (status != ACS_STATUS_PASS)
  {
    result = status;
    goto cleanup;
  }
  dpt_coverage_configured = 1u;

  if ((val_dpt_add_entry(writeback_hpa,
                         (((uint64_t)master.smmu_index << 32) |
                          DPT_RDWR_ACCESS_ENTRY)) != 0u) ||
      (val_dpt_add_entry(snoop_hpa,
                         (((uint64_t)master.smmu_index << 32) |
                          DPT_RDWR_ACCESS_ENTRY)) != 0u))
  {
    result = ACS_STATUS_ERR;
    goto cleanup;
  }
  dcm_dpt_set = 1u;

  if (val_dpt_add_entry(verify_pa,
                        (((uint64_t)master.smmu_index << 32) |
                         DPT_RDWR_NS_ACCESS_ENTRY)) != 0u)
  {
    result = ACS_STATUS_ERR;
    goto cleanup;
  }
  verify_dpt_set = 1u;

  if (val_dpt_invalidate_all(master.smmu_index) != 0u)
  {
    result = ACS_STATUS_ERR;
    goto cleanup;
  }

  status = val_pcie_enable_ats(context->endpoint_bdf,
                               &ats_cap_base,
                               &ats_ctrl_orig);
  if (status != ACS_STATUS_PASS)
  {
    result = status;
    goto cleanup;
  }
  ats_enabled = 1u;

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

  status = val_cda_program_rid_range(
             context->rmecda_cfg_va,
             context->rmecda_cap_base,
             rmecda_ctl3_orig,
             rmecda_ctl4_orig,
             (uint32_t)PCIE_CREATE_BDF_PACKED(context->endpoint_bdf),
             (uint32_t)PCIE_CREATE_BDF_PACKED(context->endpoint_bdf),
             1u);
  if (status != ACS_STATUS_PASS)
  {
    result = status;
    goto cleanup;
  }
  rid_range_programmed = 1u;

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
   * Populate each line with a device-originated coherent read and verify the
   * captured data through a separate host page. Only then ask the exerciser to
   * change the existing line's state to dirty.
   */
  status = populate_device_cache_line(context->endpoint_bdf,
                                      snoop_realm_alias,
                                      snoop_hpa,
                                      verify_va,
                                      verify_pa,
                                      RQWNBN_SNOOP_SEED_VALUE,
                                      page_size);
  if (status != ACS_STATUS_PASS)
  {
    val_print(ACS_PRINT_ERR, " RQWNBN: snoop cache-line population failed", 0);
    result = status;
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

  status = populate_device_cache_line(context->endpoint_bdf,
                                      writeback_realm_alias,
                                      writeback_hpa,
                                      verify_va,
                                      verify_pa,
                                      RQWNBN_WRITEBACK_SEED_VALUE,
                                      page_size);
  if (status != ACS_STATUS_PASS)
  {
    val_print(ACS_PRINT_ERR,
              " RQWNBN: writeback cache-line population failed",
              0);
    result = status;
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

  if (context->aer_offset != 0u)
    val_cxl_aer_clear(context->root_bdf, context->aer_offset);
  observed = 0u;
  read_esr = 0u;
  host_fault = 0u;
  aer_uncorr = 0u;
  status = val_memory_read64_el3_protected_with_esr(snoop_realm_alias,
                                                     &observed,
                                                     &host_fault,
                                                     &read_esr);
  if (context->aer_offset != 0u)
    (void)val_cxl_aer_read_uncorr(context->root_bdf,
                                  context->aer_offset,
                                  &aer_uncorr);
  val_print(ACS_PRINT_DEBUG, " RQWNBN: host read status %u", status);
  val_print(ACS_PRINT_DEBUG, " RQWNBN: host read fault %u", host_fault);
  val_print(ACS_PRINT_DEBUG, " RQWNBN: host read ESR 0x%llx", read_esr);
  val_print(ACS_PRINT_DEBUG, " RQWNBN: host read observed 0x%llx", observed);
  val_print(ACS_PRINT_DEBUG, " RQWNBN: AER uncorrectable 0x%x", aer_uncorr);

  if (status != ACS_STATUS_PASS)
  {
    val_print(ACS_PRINT_ERR, " RQWNBN: protected host read failed", 0);
    result = ACS_STATUS_ERR;
    goto cleanup;
  }

  /*
   * RAS requires a demand read that consumes poisoned data to take a
   * synchronous external abort. Returned data and AER state are diagnostic;
   * neither substitutes for the architectural exception.
   */
  if (host_fault == 0u)
  {
    val_print(ACS_PRINT_ERR,
              " RQWNBN: poisoned demand read did not take an external abort",
              0u);
    result = ACS_STATUS_FAIL;
    goto cleanup;
  }

  if ((((read_esr >> ESR_EC_SHIFT) & ESR_EC_MASK) !=
       ESR_EC_DATA_ABORT_SAME_EL) ||
      ((read_esr & ESR_ABORT_FSC_MASK) != ESR_FSC_SYNC_EXTERNAL_ABORT))
  {
    val_print(ACS_PRINT_ERR,
              " RQWNBN: demand read raised unexpected ESR 0x%llx",
              read_esr);
    result = ACS_STATUS_FAIL;
    goto cleanup;
  }

  if (context->aer_offset != 0u)
    val_cxl_aer_clear(context->root_bdf, context->aer_offset);
  status = val_cxl_exerciser_execute_cmd(context->endpoint_bdf,
                                         CXL_CMD_OP_DCM_CACHE_WRITEBACK,
                                         writeback_hpa,
                                         0u,
                                         NULL);
  aer_uncorr = 0u;
  if (context->aer_offset != 0u)
    (void)val_cxl_aer_read_uncorr(context->root_bdf,
                                  context->aer_offset,
                                  &aer_uncorr);
  val_print(ACS_PRINT_DEBUG, " RQWNBN: writeback status %u", status);
  val_print(ACS_PRINT_DEBUG, " RQWNBN: writeback AER uncorrectable 0x%x",
            aer_uncorr);

  /*
   * A poisoned writeback can be terminated by the receiving port. Therefore,
   * the command status alone cannot distinguish an unavailable stimulus from
   * the expected rejection. A freshly observed Poisoned TLP Received bit is
   * authoritative evidence that the writeback reached the Root Port.
   */
  if ((aer_uncorr & AER_POISONED_TLP) == 0u)
  {
    if (status != ACS_STATUS_PASS)
      val_print(ACS_PRINT_INFO,
                " RQWNBN: DCM cache writeback stimulus unavailable",
                0u);
    else
      val_print(ACS_PRINT_INFO,
                " RQWNBN: writeback poison indication is not observable",
                0u);
    result = ACS_STATUS_SKIP;
    goto cleanup;
  }

  if (status != ACS_STATUS_PASS)
    val_print(ACS_PRINT_INFO,
              " RQWNBN: poisoned writeback was terminated by the receiver",
              0u);

  result = ACS_STATUS_PASS;

cleanup:
  if (context->aer_offset != 0u)
    val_cxl_aer_clear(context->root_bdf, context->aer_offset);

  (void)val_exerciser_set_param_by_bdf(CFG_TXN_ATTRIBUTES,
                                       TXN_ATC_ENTRY,
                                       ATC_ENTRY_DISABLE,
                                       context->endpoint_bdf);
  (void)val_exerciser_set_param_by_bdf(EXERCISER_ATS_REQUEST_ATTRIBUTES,
                                       0u,
                                       0u,
                                       context->endpoint_bdf);
  (void)val_exerciser_ops_by_bdf(ATS_INV_CACHE, 0u, context->endpoint_bdf);

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

  if ((smmu_enabled != 0u) &&
      ((dcm_dpt_set != 0u) || (verify_dpt_set != 0u)))
  {
    if (dcm_dpt_set != 0u)
    {
      (void)val_dpt_add_entry(writeback_hpa,
                              (((uint64_t)master.smmu_index << 32) |
                               DPT_RDWR_ACCESS_ENTRY));
      (void)val_dpt_add_entry(snoop_hpa,
                              (((uint64_t)master.smmu_index << 32) |
                               DPT_RDWR_ACCESS_ENTRY));
    }
    if (verify_dpt_set != 0u)
      (void)val_dpt_add_entry(verify_pa,
                              (((uint64_t)master.smmu_index << 32) |
                               DPT_RDWR_ACCESS_ENTRY));
    (void)val_dpt_invalidate_all(master.smmu_index);
  }

  if ((dpt_coverage_configured != 0u) &&
      (val_smmu_restore_dpt_coverage(&dpt_cfg_state) != ACS_STATUS_PASS))
    result = ACS_STATUS_FAIL;

  if (pgt_created != 0u)
    val_rlm_pgt_destroy(&pgt_desc);
  if (smmu_enabled != 0u)
    (void)val_smmu_disable(master.smmu_index);

  if ((dcm_gpt_set != 0u) &&
      ((val_add_gpt_entry_el3(writeback_hpa, GPT_ANY) != 0u) ||
       (val_add_gpt_entry_el3(snoop_hpa, GPT_ANY) != 0u)))
    result = ACS_STATUS_FAIL;
  if ((verify_gpt_set != 0u) && (val_add_gpt_entry_el3(verify_pa, GPT_ANY) != 0u))
    result = ACS_STATUS_FAIL;

  if (ats_enabled != 0u)
    val_pcie_write_cfg(context->endpoint_bdf,
                       ats_cap_base + ATS_CTRL,
                       ats_ctrl_orig);

  if (verify_va != NULL)
    val_memory_free_pages(verify_va, 1u);

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
