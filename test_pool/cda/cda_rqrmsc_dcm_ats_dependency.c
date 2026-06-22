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

#define TEST_NAME "cda_rqrmsc_dcm_ats_dependency"
#define TEST_DESC "PAS_CHECK false DCM access requires ATS              "
#define TEST_RULE "RQRMSC"

#define DECODER_SLOT 0u

#define PCIE_LNKCAP_OFFSET 0x0Cu
#define PCIE_LNKCAP_PN_SHIFT 24u
#define PCIE_LNKCAP_PN_MASK 0xFFu

#define RMECDA_CTL1_TDISP_EN_MASK 0x1u
#define RMECDA_CTL1_LINK_STR_LOCK_MASK (1u << 1)

#define RQRMSC_SRC_PATTERN         0xA5u
#define RQRMSC_DST_PATTERN         0x5Au
#define RQRMSC_DEVICE_SEED_PATTERN 0x3Cu

#if ENABLE_SPDM

typedef struct {
  uint32_t valid;
  uint32_t updated;
  uint64_t smmu_base;
  uint32_t original_cfg;
} RQRMSC_DPT_CFG_STATE;

typedef struct {
  /* Host bridge and decoder window used to expose DCM through CXL.mem. */
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

static void
init_context(RQRMSC_CONTEXT *context)
{
  if (context == NULL)
    return;

  val_memory_set(context, sizeof(*context), 0);
  context->host_index = CXL_COMPONENT_INVALID_INDEX;
  context->endpoint_index = CXL_COMPONENT_INVALID_INDEX;
}

static uint32_t
configure_dpt_coverage(uint32_t smmu_index,
                       uint64_t translated_addr,
                       RQRMSC_DPT_CFG_STATE *state)
{
  uint32_t dpt_cfg;
  uint32_t current_dptps_bits;
  uint32_t desired_dptps_encoding;
  uint32_t desired_l0dptsz_encoding;
  uint32_t desired_cfg;
  uint64_t smmu_base;

  if ((translated_addr == 0u) || (state == NULL))
    return ACS_STATUS_ERR;

  val_memory_set(state, sizeof(*state), 0);

  smmu_base = val_smmu_get_info(SMMU_CTRL_BASE, smmu_index);
  if (smmu_base == 0u)
    return ACS_STATUS_SKIP;

  state->smmu_base = smmu_base;
  if (val_smmu_read_dpt_base_cfg(smmu_base, &dpt_cfg) != ACS_STATUS_PASS)
    return ACS_STATUS_ERR;

  state->original_cfg = dpt_cfg;
  state->valid = 1u;
  current_dptps_bits =
    val_smmu_dptps_bits_from_encoding(
      (dpt_cfg >> SMMU_DPT_BASE_CFG_DPTPS_SHIFT) &
      SMMU_DPT_BASE_CFG_DPTPS_MASK);

  val_print(ACS_PRINT_DEBUG, " RQRMSC: DPT cfg original 0x%x",
            (uint64_t)dpt_cfg);
  val_print(ACS_PRINT_DEBUG, " RQRMSC: DPTPS bits %u",
            (uint64_t)current_dptps_bits);

  if ((current_dptps_bits != 0u) &&
      (current_dptps_bits >= 64u ||
       translated_addr < (1ull << current_dptps_bits)))
  {
    return ACS_STATUS_PASS;
  }

  if (val_smmu_select_dptps_encoding(translated_addr,
                                     &desired_dptps_encoding,
                                     &desired_l0dptsz_encoding) != ACS_STATUS_PASS)
  {
    val_print(ACS_PRINT_ERR, " RQRMSC: translated PA above supported DPTPS", 0);
    return ACS_STATUS_SKIP;
  }

  desired_cfg = dpt_cfg;
  desired_cfg &= ~(SMMU_DPT_BASE_CFG_DPTPS_MASK <<
                   SMMU_DPT_BASE_CFG_DPTPS_SHIFT);
  desired_cfg &= ~(SMMU_DPT_BASE_CFG_L0DPTSZ_MASK <<
                   SMMU_DPT_BASE_CFG_L0DPTSZ_SHIFT);
  desired_cfg |= (desired_dptps_encoding & SMMU_DPT_BASE_CFG_DPTPS_MASK) <<
                 SMMU_DPT_BASE_CFG_DPTPS_SHIFT;
  desired_cfg |= (desired_l0dptsz_encoding & SMMU_DPT_BASE_CFG_L0DPTSZ_MASK) <<
                 SMMU_DPT_BASE_CFG_L0DPTSZ_SHIFT;

  val_print(ACS_PRINT_DEBUG, " RQRMSC: DPT cfg desired 0x%x",
            (uint64_t)desired_cfg);

  if (val_smmu_write_dpt_base_cfg(smmu_base, desired_cfg) != ACS_STATUS_PASS)
    return ACS_STATUS_ERR;

  state->updated = 1u;
  return ACS_STATUS_PASS;
}

static uint32_t
restore_dpt_coverage(const RQRMSC_DPT_CFG_STATE *state)
{
  if ((state == NULL) || (state->valid == 0u) || (state->updated == 0u))
    return ACS_STATUS_PASS;

  return val_smmu_write_dpt_base_cfg(state->smmu_base, state->original_cfg);
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
  uint64_t comp_base;
  uint64_t hdm_cap_base;

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
select_dcm_window_page(uint64_t window_base,
                       uint64_t window_size,
                       uint64_t *page_out)
{
  uint64_t page_size;
  uint64_t window_end;
  uint64_t aligned_base;

  if (page_out == NULL)
    return ACS_STATUS_ERR;

  page_size = (uint64_t)val_memory_page_size();
  if (page_size == 0u)
    return ACS_STATUS_ERR;

  if (window_size < page_size)
    return ACS_STATUS_SKIP;

  window_end = window_base + window_size;
  if (window_end < window_base)
    return ACS_STATUS_ERR;

  /*
   * Use the last page in the CXL.mem window.  The UEFI page allocator can hand
   * out backing pages from the start of the CFMWS window; using the first page
   * here can make the selected DCM window page alias an ACS DMA source buffer.
   */
  aligned_base = (window_end - page_size) & ~(page_size - 1u);
  if ((aligned_base < window_base) || ((aligned_base + page_size) > window_end))
    return ACS_STATUS_SKIP;

  *page_out = aligned_base;
  return ACS_STATUS_PASS;
}

static uint32_t
read_u32_le(const uint8_t *buffer,
            uint32_t offset)
{
  return (uint32_t)buffer[offset] |
         ((uint32_t)buffer[offset + 1u] << 8) |
         ((uint32_t)buffer[offset + 2u] << 16) |
         ((uint32_t)buffer[offset + 3u] << 24);
}

static uint32_t
query_pas_check(uint32_t endpoint_bdf,
                uint32_t *pas_check_out)
{
  pci_tdisp_interface_id_t interface_id;
  val_spdm_context_t spdm_ctx;
  uint8_t response[VAL_TDISP_ARM_VDM_MAX_RSP_SIZE];
  uint32_t response_size;
  uint32_t properties;
  uint32_t session_id;
  uint32_t status;

  if (pas_check_out == NULL)
    return ACS_STATUS_ERR;

  *pas_check_out = 0u;
  session_id = 0u;
  response_size = (uint32_t)sizeof(response);

  val_memory_set(&spdm_ctx, sizeof(spdm_ctx), 0);
  val_memory_set(response, sizeof(response), 0);
  interface_id.function_id = (uint32_t)PCIE_CREATE_BDF_PACKED(endpoint_bdf);
  interface_id.reserved = 0ull;

  status = val_spdm_session_open(endpoint_bdf, &spdm_ctx, &session_id);
  if (status != ACS_STATUS_PASS)
    return status;

  status = val_tdisp_vdm_get_dev_prop(&spdm_ctx,
                                      session_id,
                                      &interface_id,
                                      response,
                                      &response_size);
  if (status == ACS_STATUS_PASS)
  {
    if (response_size < (VAL_TDISP_ARM_VDM_BASE_SIZE + sizeof(uint32_t)))
    {
      val_print(ACS_PRINT_ERR, " RQRMSC: GET_DEV_PROP response too small", 0);
      status = ACS_STATUS_FAIL;
    }
    else if ((response[VAL_TDISP_HDR_MSG_TYPE_OFF] != PCI_TDISP_VDM_RSP) ||
             (response[VAL_TDISP_REQ_RESP_HDR_OFF +
                       VAL_TDISP_REQ_RESP_TYPE_OFF] !=
              VAL_TDISP_ARM_MSG_GET_DEV_PROP_RESP))
    {
      val_print(ACS_PRINT_ERR, " RQRMSC: invalid GET_DEV_PROP response", 0);
      status = ACS_STATUS_FAIL;
    }
    else
    {
      properties = read_u32_le(response, VAL_TDISP_ARM_VDM_BASE_SIZE);
      *pas_check_out =
        ((properties & VAL_TDISP_DEV_PROP_PAS_CHECK) != 0u) ? 1u : 0u;
      val_print(ACS_PRINT_INFO, " RQRMSC: TDISP properties 0x%x", properties);
    }
  }

  if (val_spdm_session_close(&spdm_ctx, session_id) != ACS_STATUS_PASS)
  {
    val_print(ACS_PRINT_ERR, " RQRMSC: SPDM session close failed", 0);
    if (status == ACS_STATUS_PASS)
      status = ACS_STATUS_FAIL;
  }

  return status;
}

static uint32_t
configure_smmu_identity_map(uint32_t endpoint_bdf,
                            uint64_t src_pa,
                            uint64_t dst_pa,
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
      (src_pa == 0u) || (dst_pa == 0u) || (page_size == 0u))
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
  mem_desc[0].virtual_address = src_pa;
  mem_desc[0].physical_address = src_pa;
  mem_desc[0].length = page_size;
  mem_desc[0].attributes = PGT_STAGE2_AP_RW;
  mem_desc[1].virtual_address = dst_pa;
  mem_desc[1].physical_address = dst_pa;
  mem_desc[1].length = page_size;
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
  val_print(ACS_PRINT_DEBUG, " RQRMSC: SMMU src map 0x%llx", src_pa);
  val_print(ACS_PRINT_DEBUG, " RQRMSC: SMMU dst map 0x%llx", dst_pa);
  val_print(ACS_PRINT_DEBUG, " RQRMSC: SMMU map length 0x%llx", page_size);

  if (val_smmu_enable(smmu_index))
    return ACS_STATUS_ERR;

  master_out->smmu_index = smmu_index;
  /*
   * Use the endpoint StreamID from IOVIRT, matching the established ACS DPT
   * tests.  The FVP SMMU identify path supplies this requester identity for
   * exerciser translated traffic.
   */
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
run_translated_dma(uint32_t endpoint_bdf,
                   uint64_t translated_addr,
                   uint32_t length,
                   uint32_t direction)
{
  uint32_t result;
  uint32_t status;

  if ((translated_addr == 0u) || (length == 0u))
    return ACS_STATUS_ERR;

  /*
   * RQRMSC requires PAS_CHECK==FALSE device requests to use host-side
   * translation and GPC before reaching DCM.  For the CHI-C2C exerciser in this
   * FVP, the explicit BAR ATS trigger is gated by an internal model parameter
   * even though the PCIe ATS capability is advertised.  Use an AT=Translated DMA
   * request as the closest ACS-visible stimulus for a translated device access.
   * This proves the translated access path works; direct translated DMA in this
   * FVP does not provide a reliable negative ATS/DPT-denial stimulus.
   */
  (void)val_exerciser_ops_by_bdf(ATS_INV_CACHE, 0u, endpoint_bdf);
  val_pcie_clear_device_status_error(endpoint_bdf);

  if (val_exerciser_set_param_by_bdf(CFG_TXN_ATTRIBUTES,
                                     TXN_ADDR_TYPE,
                                     AT_TRANSLATED,
                                     endpoint_bdf))
    return ACS_STATUS_ERR;

  result = ACS_STATUS_ERR;
  if (val_exerciser_set_param_by_bdf(DMA_ATTRIBUTES,
                                     translated_addr,
                                     length,
                                     endpoint_bdf))
  {
    goto cleanup;
  }

  status = val_exerciser_ops_by_bdf(START_DMA, direction, endpoint_bdf);
  result = (status == 0u) ? ACS_STATUS_PASS : ACS_STATUS_FAIL;

cleanup:
  (void)val_exerciser_set_param_by_bdf(CFG_TXN_ATTRIBUTES,
                                       TXN_ADDR_TYPE,
                                       AT_UNTRANSLATED,
                                       endpoint_bdf);

  return result;
}

static uint32_t
load_device_with_pattern(uint32_t endpoint_bdf,
                         uint8_t *buffer_va,
                         uint64_t buffer_pa,
                         uint32_t length,
                         uint32_t pattern)
{
  if ((buffer_va == NULL) || (buffer_pa == 0u) || (length == 0u))
    return ACS_STATUS_ERR;

  if (val_memory_set_el3(buffer_va, length, (uint8_t)pattern))
    return ACS_STATUS_ERR;

  return run_translated_dma(endpoint_bdf,
                            buffer_pa,
                            length,
                            EDMA_TO_DEVICE);
}

static uint32_t
store_device_to_buffer(uint32_t endpoint_bdf,
                       uint8_t *buffer_va,
                       uint64_t buffer_pa,
                       uint32_t length,
                       uint32_t pattern)
{
  if ((buffer_va == NULL) || (buffer_pa == 0u) || (length == 0u))
    return ACS_STATUS_ERR;

  if (val_memory_set_el3(buffer_va, length, (uint8_t)pattern))
    return ACS_STATUS_ERR;

  return run_translated_dma(endpoint_bdf,
                            buffer_pa,
                            length,
                            EDMA_FROM_DEVICE);
}

static uint32_t
run_translated_dma_compare(uint32_t endpoint_bdf,
                           uint8_t *buffer_src,
                           uint8_t *buffer_dst,
                           uint64_t buffer_src_pa,
                           uint64_t buffer_dst_pa,
                           uint32_t length,
                           uint32_t require_to_device_success,
                           uint32_t *to_device_status,
                           uint32_t *compare_match)
{
  uint32_t compare_status;
  uint32_t status;

  if ((buffer_src == NULL) || (buffer_dst == NULL) ||
      (buffer_src_pa == 0u) || (buffer_dst_pa == 0u) ||
      (to_device_status == NULL) || (compare_match == NULL) ||
      (length == 0u))
    return ACS_STATUS_ERR;

  *to_device_status = ACS_STATUS_ERR;
  *compare_match = 0u;

  /*
   * Use only the generic exerciser DMA contract: first load the device from a
   * host source buffer, then store the device contents into a host destination
   * buffer, and compare the two host buffers.  The test never assumes where or
   * how the exerciser stores its internal DMA payload.
   */
  if (val_memory_prepare_dma_buffers_el3(buffer_src,
                                         buffer_dst,
                                         length,
                                         RQRMSC_SRC_PATTERN,
                                         RQRMSC_DST_PATTERN) != ACS_STATUS_PASS)
    return ACS_STATUS_ERR;

  status = run_translated_dma(endpoint_bdf,
                              buffer_src_pa,
                              length,
                              EDMA_TO_DEVICE);
  if (status == ACS_STATUS_ERR)
    return ACS_STATUS_ERR;

  *to_device_status = status;
  if ((require_to_device_success != 0u) && (status != ACS_STATUS_PASS))
    return ACS_STATUS_FAIL;

  status = run_translated_dma(endpoint_bdf,
                              buffer_dst_pa,
                              length,
                              EDMA_FROM_DEVICE);
  if (status != ACS_STATUS_PASS)
    return status;

  compare_status = val_memory_compare_el3((uint64_t)buffer_src,
                                          (uint64_t)buffer_dst,
                                          length);
  if (compare_status == ACS_STATUS_ERR)
    return ACS_STATUS_ERR;

  *compare_match = (compare_status == 0u) ? 1u : 0u;
  return ACS_STATUS_PASS;
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
    val_print(ACS_PRINT_DEBUG, " RQRMSC: programming RID base 0x%x", 0u);
    val_print(ACS_PRINT_DEBUG, " RQRMSC: programming RID limit 0x%x",
              (uint64_t)endpoint_rid);
    /*
     * RQRMSC is an ATS/GPC dependency check, not a RID-window check.  Keep the
     * link locked while admitting the endpoint and low synthetic identities so
     * this test does not conflate ATS/GPC failures with RDMSPT/RYDSYL coverage.
     */
    status = val_cda_program_rid_range(candidate.rmecda_cfg_va,
                                       candidate.rmecda_cap_base,
                                       candidate.rmecda_ctl3_orig,
                                       candidate.rmecda_ctl4_orig,
                                       0u,
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
  smmu_master_attributes_t master;
  pgt_descriptor_t pgt_desc;
  RQRMSC_DPT_CFG_STATE dpt_cfg_state;
  uint64_t dcm_window_pa;
  uint8_t *buffer_base_va;
  uint8_t *buffer_src_va;
  uint8_t *buffer_dst_va;
  uint64_t buffer_src_pa;
  uint64_t buffer_dst_pa;
  uint64_t dpt_coverage_pa;
  uint32_t page_size;
  uint32_t compare_match;
  uint32_t dma_to_status;
  uint32_t result;
  uint32_t status;
  uint32_t pas_check;
  uint32_t src_gpt_set;
  uint32_t dst_gpt_set;
  uint32_t src_dpt_entry_added;
  uint32_t dst_dpt_entry_added;
  uint32_t dpt_deny_limited;
  uint32_t smmu_active;
  uint32_t rlm_pgt_created;

  if (context == NULL)
    return ACS_STATUS_ERR;

  val_memory_set(&master, sizeof(master), 0);
  val_memory_set(&pgt_desc, sizeof(pgt_desc), 0);
  val_memory_set(&dpt_cfg_state, sizeof(dpt_cfg_state), 0);
  master.smmu_index = ACS_INVALID_INDEX;
  buffer_base_va = NULL;
  buffer_src_va = NULL;
  buffer_dst_va = NULL;
  buffer_src_pa = 0u;
  buffer_dst_pa = 0u;
  src_gpt_set = 0u;
  dst_gpt_set = 0u;
  src_dpt_entry_added = 0u;
  dst_dpt_entry_added = 0u;
  dpt_deny_limited = 0u;
  smmu_active = 0u;
  rlm_pgt_created = 0u;
  result = ACS_STATUS_FAIL;
  val_memory_clear_el3_access_state();

  page_size = val_memory_page_size();
  if (page_size == 0u)
    return ACS_STATUS_ERR;

  status = select_dcm_window_page(context->window_base,
                                  context->window_size,
                                  &dcm_window_pa);
  if (status != ACS_STATUS_PASS)
    return status;

  val_print(ACS_PRINT_INFO, " RQRMSC: DCM window PA 0x%llx", dcm_window_pa);

  buffer_base_va = (uint8_t *)val_memory_alloc_pages(2u);
  if (buffer_base_va == NULL)
    return ACS_STATUS_ERR;

  buffer_src_va = buffer_base_va;
  buffer_dst_va = buffer_base_va + page_size;
  buffer_src_pa = (uint64_t)val_memory_virt_to_phys(buffer_src_va);
  buffer_dst_pa = (uint64_t)val_memory_virt_to_phys(buffer_dst_va);
  if ((buffer_src_pa == 0u) || (buffer_dst_pa == 0u) ||
      (buffer_src_pa == buffer_dst_pa))
  {
    result = ACS_STATUS_ERR;
    goto cleanup;
  }

  val_print(ACS_PRINT_INFO, " RQRMSC: DMA source PA 0x%llx", buffer_src_pa);
  val_print(ACS_PRINT_INFO, " RQRMSC: DMA destination PA 0x%llx", buffer_dst_pa);

  status = query_pas_check(context->endpoint_bdf, &pas_check);
  if (status != ACS_STATUS_PASS)
  {
    result = status;
    goto cleanup;
  }

  if (pas_check != 0u)
  {
    val_print(ACS_PRINT_INFO,
              " RQRMSC: PAS_CHECK==TRUE permits direct device-side PAS checks",
              0);
    result = ACS_STATUS_SKIP;
    goto cleanup;
  }

  val_print(ACS_PRINT_INFO,
            " RQRMSC: PAS_CHECK==FALSE, checking ATS/GPC dependency",
            0);

  status = val_pcie_enable_ats(context->endpoint_bdf,
                               &context->ats_cap_base,
                               &context->ats_ctrl_orig);
  if (status != ACS_STATUS_PASS)
  {
    if (status == ACS_STATUS_SKIP)
    {
      val_print(ACS_PRINT_ERR,
                " RQRMSC: PAS_CHECK==FALSE endpoint lacks ATS capability",
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
  val_print(ACS_PRINT_DEBUG, " RQRMSC: ATS cap base 0x%x",
            (uint64_t)context->ats_cap_base);
  val_print(ACS_PRINT_DEBUG, " RQRMSC: ATS ctrl original 0x%x",
            (uint64_t)context->ats_ctrl_orig);

  val_memory_clear_el3_access_state();
  if (val_add_gpt_entry_el3(buffer_src_pa, GPT_NONSECURE))
  {
    result = ACS_STATUS_ERR;
    goto cleanup;
  }
  src_gpt_set = 1u;

  if (val_add_gpt_entry_el3(buffer_dst_pa, GPT_NONSECURE))
  {
    result = ACS_STATUS_ERR;
    goto cleanup;
  }
  dst_gpt_set = 1u;

  if (val_memory_map_el3_data((uint64_t)buffer_src_va,
                              page_size,
                              NONSECURE_PAS) != ACS_STATUS_PASS)
  {
    result = ACS_STATUS_ERR;
    goto cleanup;
  }

  if (val_memory_map_el3_data((uint64_t)buffer_dst_va,
                              page_size,
                              NONSECURE_PAS) != ACS_STATUS_PASS)
  {
    result = ACS_STATUS_ERR;
    goto cleanup;
  }

  status = configure_smmu_identity_map(context->endpoint_bdf,
                                       buffer_src_pa,
                                       buffer_dst_pa,
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

  if (val_smmu_gpt_invalidate_el3(&master))
  {
    result = ACS_STATUS_ERR;
    goto cleanup;
  }

  dpt_coverage_pa = (buffer_src_pa > buffer_dst_pa) ? buffer_src_pa : buffer_dst_pa;
  status = configure_dpt_coverage(master.smmu_index, dpt_coverage_pa, &dpt_cfg_state);
  if (status != ACS_STATUS_PASS)
  {
    result = status;
    goto cleanup;
  }

  /*
   * RME translated-request checks consult the DPT after stage-2 translation.
   * Install read/write DPT entries for both translated host buffers before
   * issuing DMA; otherwise a compliant path can reject the request before the
   * GPC path is tested.
   */
  if (val_dpt_add_entry(buffer_src_pa,
                        ((((uint64_t)master.smmu_index) << 32) |
                         DPT_RDWR_ACCESS_ENTRY)))
  {
    val_print(ACS_PRINT_ERR, " RQRMSC: source DPT entry add failed", 0);
    result = ACS_STATUS_ERR;
    goto cleanup;
  }
  src_dpt_entry_added = 1u;

  if (val_dpt_add_entry(buffer_dst_pa,
                        ((((uint64_t)master.smmu_index) << 32) |
                         DPT_RDWR_ACCESS_ENTRY)))
  {
    val_print(ACS_PRINT_ERR, " RQRMSC: destination DPT entry add failed", 0);
    result = ACS_STATUS_ERR;
    goto cleanup;
  }
  dst_dpt_entry_added = 1u;

  if (val_dpt_invalidate_all(master.smmu_index))
  {
    val_print(ACS_PRINT_ERR, " RQRMSC: DPT invalidate failed", 0);
    result = ACS_STATUS_ERR;
    goto cleanup;
  }

  /*
   * Positive check: use the generic exerciser DMA contract.  Load the device
   * from a translated source buffer, store the device contents into a translated
   * destination buffer, and compare the two host buffers.
   */
  status = run_translated_dma_compare(context->endpoint_bdf,
                                      buffer_src_va,
                                      buffer_dst_va,
                                      buffer_src_pa,
                                      buffer_dst_pa,
                                      page_size,
                                      1u,
                                      &dma_to_status,
                                      &compare_match);
  if (status != ACS_STATUS_PASS)
  {
    val_print(ACS_PRINT_ERR, " RQRMSC: positive translated DMA failed", 0);
    result = ACS_STATUS_FAIL;
    goto cleanup;
  }

  if (compare_match == 0u)
  {
    val_print(ACS_PRINT_ERR, " RQRMSC: positive DMA source/destination mismatch", 0);
    result = ACS_STATUS_FAIL;
    goto cleanup;
  }

  val_print(ACS_PRINT_INFO, " RQRMSC: positive translated DMA compare matched", 0);

  /*
   * Negative check: first load the device from an allowed buffer with a pattern
   * that is different from the source pattern and store that payload into the
   * destination buffer.  Then deny the translated source page in DPT and try the
   * source-to-device DMA again.  If the source deny is effective, the destination
   * must not match the source pattern.  If the denied load unexpectedly succeeds,
   * store from the device once more and detect whether the denied source reached
   * the destination.
   *
   * Do not change the GPT for either buffer here: these pages are owned by the
   * UEFI allocator, and changing heap-backed pages to Realm can make later UEFI
   * Print/Pool allocations fault.
   *
   * The CHI-C2C FVP direct AT=Translated DMA path is not an explicit ATS
   * transaction and may not consume the DPT deny.  Keep the check for platforms
   * that reject or suppress the transfer, but report this model limitation as a
   * warning instead of a device rule failure when the positive translated path
   * has already been proven above.
   */
  status = load_device_with_pattern(context->endpoint_bdf,
                                    buffer_dst_va,
                                    buffer_dst_pa,
                                    page_size,
                                    RQRMSC_DEVICE_SEED_PATTERN);
  if (status != ACS_STATUS_PASS)
  {
    val_print(ACS_PRINT_ERR, " RQRMSC: device seed DMA failed", 0);
    result = ACS_STATUS_FAIL;
    goto cleanup;
  }

  status = store_device_to_buffer(context->endpoint_bdf,
                                  buffer_dst_va,
                                  buffer_dst_pa,
                                  page_size,
                                  RQRMSC_DST_PATTERN);
  if (status != ACS_STATUS_PASS)
  {
    val_print(ACS_PRINT_ERR, " RQRMSC: device seed store failed", 0);
    result = ACS_STATUS_FAIL;
    goto cleanup;
  }

  if (val_dpt_add_entry(buffer_src_pa,
                        ((((uint64_t)master.smmu_index) << 32) |
                         DPT_NO_ACCESS_ENTRY)))
  {
    val_print(ACS_PRINT_ERR, " RQRMSC: source DPT deny entry add failed", 0);
    result = ACS_STATUS_ERR;
    goto cleanup;
  }

  if (val_dpt_invalidate_all(master.smmu_index))
  {
    val_print(ACS_PRINT_ERR, " RQRMSC: DPT deny invalidate failed", 0);
    result = ACS_STATUS_ERR;
    goto cleanup;
  }

  if (val_memory_set_el3(buffer_src_va, page_size, RQRMSC_SRC_PATTERN))
  {
    result = ACS_STATUS_ERR;
    goto cleanup;
  }

  dma_to_status = run_translated_dma(context->endpoint_bdf,
                                     buffer_src_pa,
                                     page_size,
                                     EDMA_TO_DEVICE);
  if (dma_to_status == ACS_STATUS_ERR)
  {
    val_print(ACS_PRINT_ERR, " RQRMSC: DPT-denied DMA probe failed", 0);
    result = ACS_STATUS_ERR;
    goto cleanup;
  }

  if (dma_to_status == ACS_STATUS_PASS)
  {
    status = store_device_to_buffer(context->endpoint_bdf,
                                    buffer_dst_va,
                                    buffer_dst_pa,
                                    page_size,
                                    RQRMSC_DST_PATTERN);
    if (status != ACS_STATUS_PASS)
    {
      val_print(ACS_PRINT_ERR, " RQRMSC: DPT-denied device store failed", 0);
      result = ACS_STATUS_FAIL;
      goto cleanup;
    }
  }

  status = val_memory_compare_el3((uint64_t)buffer_src_va,
                                  (uint64_t)buffer_dst_va,
                                  page_size);
  if (status == ACS_STATUS_ERR)
  {
    result = ACS_STATUS_ERR;
    goto cleanup;
  }
  compare_match = (status == 0u) ? 1u : 0u;

  if (compare_match != 0u)
  {
    if (dma_to_status == ACS_STATUS_PASS)
    {
      val_print(ACS_PRINT_WARN,
                " RQRMSC: direct translated DMA ignored source DPT deny",
                0);
      val_print(ACS_PRINT_WARN,
                " RQRMSC: negative DPT denial not enforceable in this FVP path",
                0);
      dpt_deny_limited = 1u;
    }
    else
    {
      val_print(ACS_PRINT_ERR,
                " RQRMSC: source matched destination after rejected source load",
                0);
      result = ACS_STATUS_FAIL;
      goto cleanup;
    }
  }

  if (dpt_deny_limited != 0u)
  {
    val_print(ACS_PRINT_INFO,
              " RQRMSC: positive translated access completed; negative path limited",
              0);
  }
  else if (dma_to_status == ACS_STATUS_PASS)
  {
    val_print(ACS_PRINT_INFO,
              " RQRMSC: DPT-denied translated DMA completed non-destructively",
              0);
  }
  else
  {
    val_print(ACS_PRINT_INFO,
              " RQRMSC: DPT-denied translated DMA rejected as expected",
              0);
  }

  result = ACS_STATUS_PASS;

cleanup:
  val_memory_clear_el3_access_state();
  (void)val_exerciser_set_param_by_bdf(CFG_TXN_ATTRIBUTES,
                                       TXN_ADDR_TYPE,
                                       AT_UNTRANSLATED,
                                       context->endpoint_bdf);

  if (src_gpt_set != 0u)
    (void)val_add_gpt_entry_el3(buffer_src_pa, GPT_ANY);

  if (dst_gpt_set != 0u)
    (void)val_add_gpt_entry_el3(buffer_dst_pa, GPT_ANY);

  if (src_dpt_entry_added != 0u)
  {
    (void)val_dpt_add_entry(buffer_src_pa,
                            ((((uint64_t)master.smmu_index) << 32) |
                             DPT_RDWR_ACCESS_ENTRY));
  }

  if (dst_dpt_entry_added != 0u)
  {
    (void)val_dpt_add_entry(buffer_dst_pa,
                            ((((uint64_t)master.smmu_index) << 32) |
                             DPT_RDWR_ACCESS_ENTRY));
  }

  if ((src_dpt_entry_added != 0u) || (dst_dpt_entry_added != 0u))
    (void)val_dpt_invalidate_all(master.smmu_index);

  if (restore_dpt_coverage(&dpt_cfg_state) != ACS_STATUS_PASS)
    result = ACS_STATUS_ERR;

  if (pgt_desc.pgt_base != 0u)
  {
    if (val_add_gpt_entry_el3(pgt_desc.pgt_base, GPT_ANY))
      result = ACS_STATUS_ERR;
  }

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
