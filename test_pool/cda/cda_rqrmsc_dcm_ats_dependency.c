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

#define TEST_NAME "cda_rqrmsc_dcm_ats_dependency"
#define TEST_DESC "PAS_CHECK false DCM access requires ATS              "
#define TEST_RULE "RQRMSC"

#define DECODER_SLOT 0u

#define PCIE_LNKCAP_OFFSET 0x0Cu
#define PCIE_LNKCAP_PN_SHIFT 24u
#define PCIE_LNKCAP_PN_MASK 0xFFu

#define RMECDA_CTL1_TDISP_EN_MASK 0x1u
#define RMECDA_CTL1_LINK_STR_LOCK_MASK (1u << 1)

#define PGT_STAGE2_RME_NS_MASK (1ull << 55)
#define DMA_TEST_LENGTH ((uint32_t)sizeof(uint64_t))

#define RQRMSC_WRITE_VALUE    0xA5C35A96F00F6996ull
#define RQRMSC_DENIED_BASELINE 0x3CC35AA55AC39669ull

#if ENABLE_SPDM

typedef struct {
  /* Host bridge and decoder window used to expose DCM through CXL.mem. */
  uint32_t root_index;
  uint32_t host_index;
  uint32_t root_bdf;
  uint32_t endpoint_index;
  uint32_t endpoint_bdf;
  uint64_t window_base;
  uint64_t window_size;

  /* Original HDM programming restored during cleanup. */
  uint64_t host_decoder_base_orig;
  uint64_t host_decoder_size_orig;
  uint64_t endpoint_decoder_base_orig;
  uint64_t endpoint_decoder_size_orig;
  uint32_t host_target_low_orig;
  uint32_t host_target_high_orig;
  uint32_t host_target_valid;

  /* Original config state restored during cleanup. */
  uint32_t rmecda_ctl1_orig;
  uint32_t rmecda_ctl1_valid;
  uint32_t rmecda_ctl3_orig;
  uint32_t rmecda_ctl4_orig;
  uint32_t rmecda_regs_valid;
  uint32_t rmecda_cap_base;
  uint64_t rmecda_cfg_va;
  uint32_t ats_ctrl_orig;
  uint32_t ats_ctrl_valid;
  uint32_t ats_cap_base;
} RQRMSC_CONTEXT;

typedef struct {
  val_spdm_context_t spdm_ctx;
  pci_tdisp_interface_id_t interface_id;
  uint32_t session_id;
  uint32_t session_active;
  uint32_t ide_active;
} RQRMSC_LINK_CONTEXT;

static void
init_context(RQRMSC_CONTEXT *context)
{
  if (context == NULL)
    return;

  val_memory_set(context, sizeof(*context), 0);
  context->root_index = CXL_COMPONENT_INVALID_INDEX;
  context->host_index = CXL_COMPONENT_INVALID_INDEX;
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
program_host_target_list(uint32_t bdf,
                         uint64_t comp_base,
                         RQRMSC_CONTEXT *context)
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
restore_context_state(const RQRMSC_CONTEXT *context)
{
  uint32_t restore_status;
  uint32_t readback;

  if (context == NULL)
    return ACS_STATUS_ERR;

  restore_status = ACS_STATUS_PASS;
  readback = 0u;

  if (context->ats_ctrl_valid != 0u)
  {
    val_pcie_write_cfg(context->endpoint_bdf,
                       context->ats_cap_base + ATS_CTRL,
                       context->ats_ctrl_orig);
  }

  if (context->rmecda_ctl1_valid != 0u)
  {
    if (context->rmecda_cfg_va != 0u)
    {
      if (val_cda_set_link_stream_lock(context->rmecda_cfg_va,
                                       context->rmecda_cap_base,
                                       context->rmecda_ctl1_orig,
                                       0u) != ACS_STATUS_PASS)
      {
        restore_status = ACS_STATUS_ERR;
      }
      else if ((context->rmecda_regs_valid != 0u) &&
               ((val_memory_write_el3(context->rmecda_cfg_va +
                                      context->rmecda_cap_base +
                                      RMECDA_CTL3_OFFSET,
                                      context->rmecda_ctl3_orig) != ACS_STATUS_PASS) ||
                (val_memory_write_el3(context->rmecda_cfg_va +
                                      context->rmecda_cap_base +
                                      RMECDA_CTL4_OFFSET,
                                      context->rmecda_ctl4_orig) != ACS_STATUS_PASS)))
      {
        restore_status = ACS_STATUS_ERR;
      }
      else if (val_memory_write_el3(context->rmecda_cfg_va +
                                    context->rmecda_cap_base +
                                    RMECDA_CTL1_OFFSET,
                                    context->rmecda_ctl1_orig) != ACS_STATUS_PASS)
      {
        restore_status = ACS_STATUS_ERR;
      }
      else if (val_memory_read_el3(context->rmecda_cfg_va +
                                   context->rmecda_cap_base +
                                   RMECDA_CTL1_OFFSET,
                                   &readback) != ACS_STATUS_PASS)
      {
        restore_status = ACS_STATUS_ERR;
      }
    }
    else
    {
      val_pcie_write_cfg(context->root_bdf,
                         context->rmecda_cap_base + RMECDA_CTL1_OFFSET,
                         context->rmecda_ctl1_orig);

      if (val_pcie_read_cfg(context->root_bdf,
                            context->rmecda_cap_base + RMECDA_CTL1_OFFSET,
                            &readback) != PCIE_SUCCESS)
      {
        restore_status = ACS_STATUS_ERR;
      }
    }

    if ((restore_status == ACS_STATUS_PASS) && (readback != context->rmecda_ctl1_orig))
    {
      val_print(ACS_PRINT_WARN,
                " RQRMSC: RMECDA_CTL1 restore readback 0x%x",
                (uint64_t)readback);
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
configure_smmu_map(uint32_t endpoint_bdf,
                   uint64_t source_iova,
                   uint64_t source_pa,
                   uint64_t dcm_iova,
                   uint64_t dcm_hpa,
                   uint64_t page_size,
                   smmu_master_attributes_t *master_out,
                   pgt_descriptor_t *pgt_desc_out)
{
  memory_region_descriptor_t mem_desc[3];
  pgt_descriptor_t pgt_desc;
  uint32_t device_id = 0u;
  uint32_t its_id = 0u;
  uint32_t endpoint_streamid = 0u;
  uint32_t smmu_index;
  uint32_t ias;
  uint32_t oas;

  if ((master_out == NULL) || (pgt_desc_out == NULL) ||
      (source_iova == 0u) || (source_pa == 0u) ||
      (dcm_iova == 0u) || (dcm_hpa == 0u) ||
      (source_iova == dcm_iova) || (page_size == 0u))
    return ACS_STATUS_ERR;

  val_memory_set(master_out, sizeof(*master_out), 0);
  val_memory_set(pgt_desc_out, sizeof(*pgt_desc_out), 0);
  master_out->smmu_index = ACS_INVALID_INDEX;

  smmu_index = val_iovirt_get_rc_smmu_index(PCIE_EXTRACT_BDF_SEG(endpoint_bdf),
                                            PCIE_CREATE_BDF_PACKED(endpoint_bdf));
  if (smmu_index == ACS_INVALID_INDEX)
    return ACS_STATUS_SKIP;

  if (val_iovirt_get_smmu_info(SMMU_CTRL_ARCH_MAJOR_REV, smmu_index) != 3u)
    return ACS_STATUS_SKIP;

  if (val_iovirt_get_device_info(PCIE_CREATE_BDF_PACKED(endpoint_bdf),
                                 PCIE_EXTRACT_BDF_SEG(endpoint_bdf),
                                 &device_id,
                                 &endpoint_streamid,
                                 &its_id))
    return ACS_STATUS_SKIP;

  ias = (uint32_t)val_smmu_get_info(SMMU_IN_ADDR_SIZE, smmu_index);
  oas = (uint32_t)val_smmu_get_info(SMMU_OUT_ADDR_SIZE, smmu_index);
  if ((ias == 0u) || (oas == 0u))
    return ACS_STATUS_SKIP;

  val_print(ACS_PRINT_DEBUG, " RQRMSC: SMMU index %u", (uint64_t)smmu_index);
  val_print(ACS_PRINT_DEBUG, " RQRMSC: endpoint SMMU streamid 0x%x",
            (uint64_t)endpoint_streamid);
  val_print(ACS_PRINT_DEBUG, " RQRMSC: translated SMMU streamid 0x%x",
            (uint64_t)endpoint_streamid);
  val_print(ACS_PRINT_DEBUG, " RQRMSC: SMMU device id 0x%x",
            (uint64_t)device_id);
  val_print(ACS_PRINT_DEBUG, " RQRMSC: SMMU ITS id 0x%x", (uint64_t)its_id);
  val_print(ACS_PRINT_DEBUG, " RQRMSC: SMMU IAS %u", (uint64_t)ias);
  val_print(ACS_PRINT_DEBUG, " RQRMSC: SMMU OAS %u", (uint64_t)oas);

  val_memory_set(mem_desc, sizeof(mem_desc), 0);
  mem_desc[0].virtual_address = source_iova;
  mem_desc[0].physical_address = source_pa;
  mem_desc[0].length = page_size;
  /* The host source remains in Non-secure PAS after stage-2 translation. */
  mem_desc[0].attributes = PGT_STAGE2_AP_RW | PGT_STAGE2_RME_NS_MASK;
  mem_desc[1].virtual_address = dcm_iova;
  mem_desc[1].physical_address = dcm_hpa;
  mem_desc[1].length = page_size;
  /* RME_NS clear selects Realm as the DCM translation output PAS. */
  mem_desc[1].attributes = PGT_STAGE2_AP_RW;
  mem_desc[2].length = 0u;

  val_memory_set(&pgt_desc, sizeof(pgt_desc), 0);
  pgt_desc.pgt_base = (uint64_t)NULL;
  pgt_desc.ias = ias;
  pgt_desc.oas = oas;
  pgt_desc.stage = PGT_STAGE2;

  if (val_pe_get_vtcr(&pgt_desc.vtcr))
    return ACS_STATUS_ERR;

  val_print(ACS_PRINT_DEBUG, " RQRMSC: VTCR tsz %u",
            (uint64_t)pgt_desc.vtcr.tsz);
  val_print(ACS_PRINT_DEBUG, " RQRMSC: VTCR tg log2 %u",
            (uint64_t)pgt_desc.vtcr.tg_size_log2);
  val_print(ACS_PRINT_DEBUG, " RQRMSC: source IOVA 0x%llx", source_iova);
  val_print(ACS_PRINT_DEBUG, " RQRMSC: source PA 0x%llx", source_pa);
  val_print(ACS_PRINT_DEBUG, " RQRMSC: DCM IOVA 0x%llx", dcm_iova);
  val_print(ACS_PRINT_DEBUG, " RQRMSC: DCM HPA 0x%llx", dcm_hpa);
  val_print(ACS_PRINT_DEBUG, " RQRMSC: SMMU map length 0x%llx", page_size);

  if (val_smmu_enable(smmu_index))
    return ACS_STATUS_ERR;

  master_out->smmu_index = smmu_index;
  /* Use the IOVIRT StreamID that identifies this endpoint to the SMMU. */
  master_out->streamid = endpoint_streamid;
  master_out->stage2 = 1u;

  /*
   * Translated device traffic must use the RME-aware SMMU path.  A normal
   * stage-1 STE can translate host memory, but it does not give this request the
   * stage-2/GPC context that RQRMSC is validating.
   */
  if ((val_memory_map_el3_data((uint64_t)mem_desc,
                               sizeof(mem_desc),
                               NONSECURE_PAS) != ACS_STATUS_PASS) ||
      (val_memory_map_el3_data((uint64_t)&pgt_desc,
                               sizeof(pgt_desc),
                               NONSECURE_PAS) != ACS_STATUS_PASS) ||
      (val_memory_map_el3_data((uint64_t)master_out,
                               sizeof(*master_out),
                               NONSECURE_PAS) != ACS_STATUS_PASS))
  {
    (void)val_smmu_disable(smmu_index);
    master_out->smmu_index = ACS_INVALID_INDEX;
    return ACS_STATUS_ERR;
  }

  if (val_rlm_pgt_create(mem_desc, &pgt_desc))
  {
    (void)val_smmu_disable(smmu_index);
    master_out->smmu_index = ACS_INVALID_INDEX;
    return ACS_STATUS_ERR;
  }

  val_print(ACS_PRINT_DEBUG, " RQRMSC: realm PGT base 0x%llx",
            pgt_desc.pgt_base);

  val_pe_reg_write(VTTBR, pgt_desc.pgt_base);
  if (val_smmu_rlm_map_el3(master_out, &pgt_desc))
  {
    val_rlm_pgt_destroy(&pgt_desc);
    (void)val_smmu_disable(smmu_index);
    master_out->smmu_index = ACS_INVALID_INDEX;
    return ACS_STATUS_ERR;
  }

  *pgt_desc_out = pgt_desc;
  return ACS_STATUS_PASS;
}

static uint32_t
establish_realm_link(const RQRMSC_CONTEXT *context,
                     RQRMSC_LINK_CONTEXT *link)
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
cleanup_realm_link(const RQRMSC_CONTEXT *context,
                   RQRMSC_LINK_CONTEXT *link)
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
    (void)val_spdm_send_pci_tdisp_stop_interface(&link->spdm_ctx,
                                                  link->session_id,
                                                  &link->interface_id);
    if (val_spdm_session_close(&link->spdm_ctx,
                               link->session_id) != ACS_STATUS_PASS)
      result = ACS_STATUS_FAIL;
    link->session_active = 0u;
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
    val_print(ACS_PRINT_ERR, " RQRMSC: ATS PA 0x%llx", response.translated_pa);
    val_print(ACS_PRINT_ERR, " RQRMSC: ATS TE %u", (uint64_t)response.te);
    val_print(ACS_PRINT_ERR,
              " RQRMSC: ATS attributes 0x%x",
              (uint64_t)response.response_attributes);
    return ACS_STATUS_FAIL;
  }

  return ACS_STATUS_PASS;
}

static uint32_t
verify_dma_rejected_without_atc(uint32_t endpoint_bdf,
                                uint64_t iova,
                                uint32_t length,
                                EXERCISER_DMA_ATTR direction)
{
  uint32_t dma_status;

  if ((iova == 0u) || (length == 0u))
    return ACS_STATUS_ERR;

  /* An ATC-backed operation cannot proceed until ATS populates the ATC. */
  if (val_exerciser_ops_by_bdf(ATS_INV_CACHE, 0u, endpoint_bdf) != 0u)
    return ACS_STATUS_ERR;

  dma_status = val_exerciser_dma_with_atc_by_bdf(endpoint_bdf,
                                                  iova,
                                                  length,
                                                  direction);
  if (dma_status == ACS_STATUS_PASS)
    return ACS_STATUS_FAIL;

  return (dma_status == ACS_STATUS_FAIL) ? ACS_STATUS_PASS : dma_status;
}

static uint32_t
prepare_context(RQRMSC_CONTEXT *context)
{
  CXL_COMPONENT_TABLE *table;
  uint32_t host_count;

  if (context == NULL)
    return ACS_STATUS_ERR;

  init_context(context);

  table = val_cxl_component_table_ptr();
  if ((table == NULL) || (table->num_entries == 0u))
    return ACS_STATUS_SKIP;

  host_count = (uint32_t)val_cxl_get_info(CXL_INFO_NUM_DEVICES, 0);
  if (host_count == 0u)
    return ACS_STATUS_SKIP;

  for (uint32_t root_idx = 0u; root_idx < table->num_entries; ++root_idx)
  {
    RQRMSC_CONTEXT candidate;
    const CXL_COMPONENT_ENTRY *root_port;
    const CXL_COMPONENT_ENTRY *endpoint;
    uint32_t endpoint_bdf;
    uint32_t status;
    uint32_t ctl1_programmed;
    uint32_t ctl1_readback;
    uint32_t ctl3_readback;
    uint32_t ctl4_readback;
    uint32_t endpoint_rid;
    uint64_t host_comp_base;
    uint64_t endpoint_comp_base;

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

    if ((endpoint->device_type != CXL_DEVICE_TYPE_TYPE2) &&
        (endpoint->device_type != CXL_DEVICE_TYPE_TYPE3))
      continue;

    candidate.root_bdf = root_port->bdf;
    candidate.root_index = root_idx;
    candidate.endpoint_bdf = endpoint->bdf;
    candidate.host_index = root_port->host_bridge_index;

    if ((candidate.host_index == CXL_COMPONENT_INVALID_INDEX) ||
        (candidate.host_index >= host_count))
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

    if (val_pcie_map_root_config(candidate.root_bdf,
                                 &candidate.rmecda_cfg_va) != ACS_STATUS_PASS)
    {
      val_print(ACS_PRINT_DEBUG,
                " RQRMSC: config map failed for RP 0x%x",
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

    if (val_memory_read_el3(candidate.rmecda_cfg_va +
                            candidate.rmecda_cap_base +
                            RMECDA_CTL3_OFFSET,
                            &candidate.rmecda_ctl3_orig) != ACS_STATUS_PASS)
    {
      if (restore_context_state(&candidate) != ACS_STATUS_PASS)
        return ACS_STATUS_ERR;
      continue;
    }

    if (val_memory_read_el3(candidate.rmecda_cfg_va +
                            candidate.rmecda_cap_base +
                            RMECDA_CTL4_OFFSET,
                            &candidate.rmecda_ctl4_orig) != ACS_STATUS_PASS)
    {
      if (restore_context_state(&candidate) != ACS_STATUS_PASS)
        return ACS_STATUS_ERR;
      continue;
    }

    candidate.rmecda_ctl1_valid = 1u;
    candidate.rmecda_regs_valid = 1u;

    val_print(ACS_PRINT_DEBUG,
              " RQRMSC: RMECDA_CTL1 initial readback 0x%x",
              (uint64_t)candidate.rmecda_ctl1_orig);

    status = val_cda_set_link_stream_lock(candidate.rmecda_cfg_va,
                                          candidate.rmecda_cap_base,
                                          candidate.rmecda_ctl1_orig,
                                          0u);
    if (status != ACS_STATUS_PASS)
    {
      val_print(ACS_PRINT_DEBUG,
                " RQRMSC: LINK_STR_LOCK clear status %u",
                (uint64_t)status);
      if (restore_context_state(&candidate) != ACS_STATUS_PASS)
        return ACS_STATUS_ERR;
      continue;
    }

    endpoint_rid = (uint32_t)PCIE_CREATE_BDF_PACKED(candidate.endpoint_bdf);
    val_print(ACS_PRINT_DEBUG, " RQRMSC: endpoint RID 0x%x",
              (uint64_t)endpoint_rid);
    val_print(ACS_PRINT_DEBUG, " RQRMSC: programming RID base 0x%x",
              (uint64_t)endpoint_rid);
    val_print(ACS_PRINT_DEBUG, " RQRMSC: programming RID limit 0x%x",
              (uint64_t)endpoint_rid);
    /* Admit only the endpoint identity so RID filtering cannot mask this check. */
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
                " RQRMSC: RID range programming status %u",
                (uint64_t)status);
      if (restore_context_state(&candidate) != ACS_STATUS_PASS)
        return ACS_STATUS_ERR;
      continue;
    }

    if ((val_memory_read_el3(candidate.rmecda_cfg_va +
                             candidate.rmecda_cap_base +
                             RMECDA_CTL3_OFFSET,
                             &ctl3_readback) == ACS_STATUS_PASS) &&
        (val_memory_read_el3(candidate.rmecda_cfg_va +
                             candidate.rmecda_cap_base +
                             RMECDA_CTL4_OFFSET,
                             &ctl4_readback) == ACS_STATUS_PASS))
    {
      val_print(ACS_PRINT_DEBUG, " RQRMSC: RMECDA_CTL3 RID readback 0x%x",
                (uint64_t)ctl3_readback);
      val_print(ACS_PRINT_DEBUG, " RQRMSC: RMECDA_CTL4 RID readback 0x%x",
                (uint64_t)ctl4_readback);
    }

    ctl1_programmed = candidate.rmecda_ctl1_orig |
                      RMECDA_CTL1_TDISP_EN_MASK;
    status = val_cda_set_link_stream_lock(candidate.rmecda_cfg_va,
                                          candidate.rmecda_cap_base,
                                          ctl1_programmed,
                                          1u);
    if (status != ACS_STATUS_PASS)
    {
      val_print(ACS_PRINT_DEBUG,
                " RQRMSC: LINK_STR_LOCK set status %u",
                (uint64_t)status);
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
              " RQRMSC: RMECDA_CTL1 config-write readback 0x%x",
              (uint64_t)ctl1_readback);

    if ((ctl1_readback &
         (RMECDA_CTL1_TDISP_EN_MASK | RMECDA_CTL1_LINK_STR_LOCK_MASK)) !=
        (RMECDA_CTL1_TDISP_EN_MASK | RMECDA_CTL1_LINK_STR_LOCK_MASK))
    {
      val_print(ACS_PRINT_DEBUG,
                " RQRMSC: RMECDA_CTL1 cannot enable required bits",
                0);
      if (restore_context_state(&candidate) != ACS_STATUS_PASS)
        return ACS_STATUS_ERR;
      continue;
    }

    val_print(ACS_PRINT_INFO,
              " RQRMSC: using RP 0x%x for CHI-C2C CDA check",
              (uint64_t)candidate.root_bdf);
    val_print(ACS_PRINT_INFO,
              " RQRMSC: using EP 0x%x for CHI-C2C CDA check",
              (uint64_t)candidate.endpoint_bdf);
    val_print(ACS_PRINT_INFO,
              " RQRMSC: CXL.mem window base 0x%llx",
              candidate.window_base);
    *context = candidate;
    return ACS_STATUS_PASS;
  }

  return ACS_STATUS_SKIP;
}

static uint32_t
exercise_rule(RQRMSC_CONTEXT *context)
{
  RQRMSC_LINK_CONTEXT link;
  smmu_master_attributes_t master;
  pgt_descriptor_t pgt_desc;
  VAL_ATS_TRANSLATION_RESULT denied_response;
  uint8_t *buffer_base_va;
  uint8_t *source_va;
  uint64_t dcm_dpa;
  uint64_t dcm_hpa;
  uint64_t dcm_iova;
  uint64_t observed;
  uint64_t source_pa;
  uint32_t dcm_gpt_set;
  uint32_t link_active;
  uint32_t page_size;
  uint32_t properties;
  uint32_t result;
  uint32_t rlm_pgt_created;
  uint32_t smmu_active;
  uint32_t source_gpt_set;
  uint32_t status;

  if (context == NULL)
    return ACS_STATUS_ERR;

  val_memory_set(&link, sizeof(link), 0);
  val_memory_set(&master, sizeof(master), 0);
  val_memory_set(&pgt_desc, sizeof(pgt_desc), 0);
  val_memory_set(&denied_response, sizeof(denied_response), 0);
  master.smmu_index = ACS_INVALID_INDEX;
  buffer_base_va = NULL;
  source_va = NULL;
  dcm_dpa = 0u;
  dcm_hpa = 0u;
  dcm_iova = 0u;
  source_pa = 0u;
  dcm_gpt_set = 0u;
  link_active = 0u;
  rlm_pgt_created = 0u;
  smmu_active = 0u;
  source_gpt_set = 0u;
  result = ACS_STATUS_FAIL;

  status = val_tdisp_get_device_properties(context->endpoint_bdf, &properties);
  if (status != ACS_STATUS_PASS)
    return status;

  val_print(ACS_PRINT_INFO, " RQRMSC: TDISP properties 0x%x", properties);
  if ((properties & VAL_TDISP_DEV_PROP_PAS_CHECK) != 0u)
  {
    val_print(ACS_PRINT_INFO,
              " RQRMSC: PAS_CHECK is implemented; ATS dependency is not required",
              0);
    return ACS_STATUS_SKIP;
  }

  page_size = val_memory_page_size();
  if (page_size == 0u)
    return ACS_STATUS_ERR;

  status = val_cda_select_dcm_page(context->window_base,
                                   context->window_size,
                                   &dcm_hpa);
  if (status != ACS_STATUS_PASS)
    return status;

  if (val_cxl_hpa_to_dpa(context->endpoint_index,
                         dcm_hpa,
                         &dcm_dpa) != ACS_STATUS_PASS)
  {
    val_print(ACS_PRINT_INFO, " RQRMSC: cannot derive DCM DPA", 0);
    return ACS_STATUS_SKIP;
  }

  /*
   * The second page provides a stable IOVA only. Mapping that IOVA to DCM
   * makes translation observable and prevents accidental direct-HPA access.
   */
  buffer_base_va = (uint8_t *)val_memory_alloc_pages(2u);
  if (buffer_base_va == NULL)
    return ACS_STATUS_ERR;

  source_va = buffer_base_va;
  source_pa = (uint64_t)val_memory_virt_to_phys(source_va);
  dcm_iova = (uint64_t)val_memory_virt_to_phys(buffer_base_va + page_size);
  if ((source_pa == 0u) || (dcm_iova == 0u) ||
      (source_pa == dcm_iova) || (dcm_iova == dcm_hpa))
  {
    result = ACS_STATUS_ERR;
    goto cleanup;
  }

  val_print(ACS_PRINT_INFO, " RQRMSC: DCM HPA 0x%llx", dcm_hpa);
  val_print(ACS_PRINT_INFO, " RQRMSC: DCM DPA 0x%llx", dcm_dpa);
  val_print(ACS_PRINT_INFO, " RQRMSC: DCM IOVA 0x%llx", dcm_iova);

  status = val_pcie_enable_ats(context->endpoint_bdf,
                               &context->ats_cap_base,
                               &context->ats_ctrl_orig);
  if (status != ACS_STATUS_PASS)
  {
    if (status == ACS_STATUS_SKIP)
    {
      val_print(ACS_PRINT_ERR,
                " RQRMSC: PAS_CHECK==FALSE endpoint lacks ATS",
                0);
      result = ACS_STATUS_FAIL;
    }
    else
    {
      result = status;
    }
    goto cleanup;
  }
  context->ats_ctrl_valid = 1u;

  val_memory_clear_el3_access_state();
  if (val_add_gpt_entry_el3(source_pa, GPT_ANY) != 0u)
  {
    result = ACS_STATUS_ERR;
    goto cleanup;
  }
  source_gpt_set = 1u;

  if ((val_memory_map_el3_data((uint64_t)source_va,
                               page_size,
                               NONSECURE_PAS) != ACS_STATUS_PASS) ||
      (val_add_gpt_entry_el3(dcm_hpa, GPT_ANY) != 0u))
  {
    result = ACS_STATUS_ERR;
    goto cleanup;
  }
  dcm_gpt_set = 1u;

  status = configure_smmu_map(context->endpoint_bdf,
                              source_pa,
                              source_pa,
                              dcm_iova,
                              dcm_hpa,
                              page_size,
                              &master,
                              &pgt_desc);
  if (status != ACS_STATUS_PASS)
  {
    result = status;
    goto cleanup;
  }
  smmu_active = 1u;
  rlm_pgt_created = 1u;

  if (val_smmu_gpt_invalidate_el3(&master) != 0u)
  {
    result = ACS_STATUS_ERR;
    goto cleanup;
  }

  /*
   * Realm DCM traffic requires the TDI in RUN and an active IDE stream.
   * ATS is issued only after both conditions have been established.
   */
  status = establish_realm_link(context, &link);
  link_active = link.session_active;
  if (status != ACS_STATUS_PASS)
  {
    val_print(ACS_PRINT_INFO, " RQRMSC: Realm link setup unavailable", 0);
    result = status;
    goto cleanup;
  }

  /*
   * Direct DPA access is used only to initialize and observe media. The access
   * under test below uses an IOVA through ATS, the ATC, GPC, and HDM decoding.
   */
  if ((val_cxl_exerciser_backdoor_write64(context->endpoint_bdf,
                                           dcm_dpa,
                                           RQRMSC_DENIED_BASELINE)
       != ACS_STATUS_PASS) ||
      (val_cxl_exerciser_backdoor_read64(context->endpoint_bdf,
                                          dcm_dpa,
                                          &observed)
       != ACS_STATUS_PASS))
  {
    val_print(ACS_PRINT_INFO, " RQRMSC: DCM observation unavailable", 0);
    result = ACS_STATUS_SKIP;
    goto cleanup;
  }

  if (observed != RQRMSC_DENIED_BASELINE)
  {
    val_print(ACS_PRINT_ERR, " RQRMSC: initial DCM value 0x%llx", observed);
    result = ACS_STATUS_FAIL;
    goto cleanup;
  }

  /*
   * Load the exerciser payload from a host page through a valid Non-secure ATC
   * entry. The test does not depend on where the device stores that payload.
   */
  *(uint64_t *)source_va = RQRMSC_WRITE_VALUE;
  if ((val_memory_cache_clean_invalidate_range_el3((uint64_t)source_va,
                                                    DMA_TEST_LENGTH)
       != ACS_STATUS_PASS) ||
      (cache_ats_translation(context->endpoint_bdf,
                             source_pa,
                             source_pa,
                             0u,
                             page_size) != ACS_STATUS_PASS) ||
      (val_exerciser_dma_with_atc_by_bdf(context->endpoint_bdf,
                                         source_pa,
                                         DMA_TEST_LENGTH,
                                         EDMA_TO_DEVICE) != ACS_STATUS_PASS))
  {
    val_print(ACS_PRINT_ERR, " RQRMSC: source DMA setup failed", 0);
    result = ACS_STATUS_FAIL;
    goto cleanup;
  }

  /*
   * Negative case 1: invalidate the ATC and request the same ATC-backed DCM
   * operation before issuing ATS for the DCM IOVA. The operation must be
   * rejected locally because no ATS-derived translation is available.
   */
  status = verify_dma_rejected_without_atc(context->endpoint_bdf,
                                            dcm_iova,
                                            DMA_TEST_LENGTH,
                                            EDMA_FROM_DEVICE);
  if (status != ACS_STATUS_PASS)
  {
    if (status == ACS_STATUS_FAIL)
      val_print(ACS_PRINT_ERR,
                " RQRMSC: DCM write proceeded without a valid ATC entry",
                0);
    else
      val_print(ACS_PRINT_ERR,
                " RQRMSC: unable to verify rejection without an ATC entry",
                0);
    result = status;
    goto cleanup;
  }

  if ((val_cxl_exerciser_backdoor_read64(context->endpoint_bdf,
                                          dcm_dpa,
                                          &observed) != ACS_STATUS_PASS) ||
      (observed != RQRMSC_DENIED_BASELINE))
  {
    val_print(ACS_PRINT_ERR,
              " RQRMSC: no-ATS access modified DCM to 0x%llx",
              observed);
    result = ACS_STATUS_FAIL;
    goto cleanup;
  }
  val_print(ACS_PRINT_INFO,
            " RQRMSC: DCM write without an ATS-derived ATC entry was blocked",
            0);

  /*
   * Positive case: cache the Realm translation, submit DMA with the original
   * DCM IOVA, and verify that the corresponding DPA media was modified.
   */
  if ((cache_ats_translation(context->endpoint_bdf,
                             dcm_iova,
                             dcm_hpa,
                             1u,
                             page_size) != ACS_STATUS_PASS) ||
      (val_exerciser_dma_with_atc_by_bdf(context->endpoint_bdf,
                                         dcm_iova,
                                         DMA_TEST_LENGTH,
                                         EDMA_FROM_DEVICE) != ACS_STATUS_PASS))
  {
    val_print(ACS_PRINT_ERR, " RQRMSC: ATS-backed DCM write failed", 0);
    result = ACS_STATUS_FAIL;
    goto cleanup;
  }

  if ((val_cxl_exerciser_backdoor_read64(context->endpoint_bdf,
                                          dcm_dpa,
                                          &observed) != ACS_STATUS_PASS) ||
      (observed != RQRMSC_WRITE_VALUE))
  {
    val_print(ACS_PRINT_ERR, " RQRMSC: positive DCM value 0x%llx", observed);
    result = ACS_STATUS_FAIL;
    goto cleanup;
  }
  val_print(ACS_PRINT_INFO, " RQRMSC: ATS-backed DCM write completed", 0);

  /*
   * Negative case 2: make the Realm translation fail its host-side GPC check.
   * A Realm output PA cannot access a GPT entry assigned to Non-secure PAS, so
   * ATS must not return usable permissions and DCM must remain unchanged.
   */
  if ((val_cxl_exerciser_backdoor_write64(context->endpoint_bdf,
                                           dcm_dpa,
                                           RQRMSC_DENIED_BASELINE)
       != ACS_STATUS_PASS) ||
      (val_add_gpt_entry_el3(dcm_hpa, GPT_NONSECURE) != 0u) ||
      (val_smmu_gpt_invalidate_el3(&master) != 0u))
  {
    result = ACS_STATUS_ERR;
    goto cleanup;
  }

  status = val_exerciser_ats_translate_by_bdf(context->endpoint_bdf,
                                               dcm_iova,
                                               page_size,
                                               VAL_ATS_REQUEST_T,
                                               &denied_response);
  if (status != ACS_STATUS_PASS)
  {
    result = status;
    goto cleanup;
  }

  if ((denied_response.completion_success != 0u) &&
      ((denied_response.response_attributes & VAL_ATS_PERMISSION_MASK) != 0u))
  {
    val_print(ACS_PRINT_ERR,
              " RQRMSC: denied ATS returned PA 0x%llx",
              denied_response.translated_pa);
    val_print(ACS_PRINT_ERR,
              " RQRMSC: denied ATS attributes 0x%x",
              (uint64_t)denied_response.response_attributes);
    result = ACS_STATUS_FAIL;
    goto cleanup;
  }

  val_print(ACS_PRINT_INFO,
            " RQRMSC: GPC denial prevented a usable ATS translation",
            0);

  /* Media integrity is definitive even if the exerciser reports stale status. */
  (void)val_exerciser_dma_with_atc_by_bdf(context->endpoint_bdf,
                                          dcm_iova,
                                          DMA_TEST_LENGTH,
                                          EDMA_FROM_DEVICE);

  if ((val_cxl_exerciser_backdoor_read64(context->endpoint_bdf,
                                          dcm_dpa,
                                          &observed) != ACS_STATUS_PASS) ||
      (observed != RQRMSC_DENIED_BASELINE))
  {
    val_print(ACS_PRINT_ERR, " RQRMSC: denied DCM value 0x%llx", observed);
    result = ACS_STATUS_FAIL;
    goto cleanup;
  }

  val_print(ACS_PRINT_INFO,
            " RQRMSC: DCM unchanged after denied translation",
            0);
  result = ACS_STATUS_PASS;

cleanup:
  (void)val_exerciser_set_param_by_bdf(CFG_TXN_ATTRIBUTES,
                                       TXN_ATC_ENTRY,
                                       ATC_ENTRY_DISABLE,
                                       context->endpoint_bdf);
  (void)val_exerciser_set_param_by_bdf(EXERCISER_ATS_REQUEST_ATTRIBUTES,
                                       0u,
                                       0u,
                                       context->endpoint_bdf);
  (void)val_exerciser_ops_by_bdf(ATS_INV_CACHE, 0u, context->endpoint_bdf);

  if ((link_active != 0u) &&
      (cleanup_realm_link(context, &link) != ACS_STATUS_PASS))
    result = ACS_STATUS_FAIL;

  if (pgt_desc.pgt_base != 0u)
    (void)val_add_gpt_entry_el3(pgt_desc.pgt_base, GPT_ANY);

  if ((dcm_gpt_set != 0u) &&
      (val_add_gpt_entry_el3(dcm_hpa, GPT_ANY) != 0u))
    result = ACS_STATUS_FAIL;
  if ((source_gpt_set != 0u) &&
      (val_add_gpt_entry_el3(source_pa, GPT_ANY) != 0u))
    result = ACS_STATUS_FAIL;

  if ((smmu_active != 0u) && (val_smmu_gpt_invalidate_el3(&master) != 0u))
    result = ACS_STATUS_FAIL;

  if (rlm_pgt_created != 0u)
    val_rlm_pgt_destroy(&pgt_desc);
  if (smmu_active != 0u)
    (void)val_smmu_disable(master.smmu_index);

  if (buffer_base_va != NULL)
    val_memory_free_pages(buffer_base_va, 2u);

  val_memory_clear_el3_access_state();
  return result;
}

static void
payload(void)
{
  uint32_t pe_index;
  uint32_t cleanup_status;
  uint32_t status;
  RQRMSC_CONTEXT context;

  pe_index = val_pe_get_index_mpid(val_pe_get_mpid());
  val_memory_clear_el3_access_state();

  status = prepare_context(&context);
  if (status == ACS_STATUS_SKIP)
  {
    val_print(ACS_PRINT_INFO, " RQRMSC: no suitable CHI-C2C CDA context", 0);
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
  val_memory_clear_el3_access_state();
  if (cleanup_status != ACS_STATUS_PASS)
  {
    val_print(ACS_PRINT_ERR, " RQRMSC: platform cleanup failed", 0);
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
cda_rqrmsc_dcm_ats_dependency_entry(uint32_t num_pe)
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
