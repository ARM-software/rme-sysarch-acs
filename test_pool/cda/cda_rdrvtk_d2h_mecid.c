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
#include "val/include/val_dpt.h"
#include "val/include/val_el32.h"
#include "val/include/val_exerciser.h"
#include "val/include/val_iovirt.h"
#include "val/include/val_mec.h"
#include "val/include/val_memory.h"
#include "val/include/val_pcie.h"
#include "val/include/val_pcie_spec.h"
#include "val/include/val_pe.h"
#include "val/include/val_pgt.h"
#include "val/include/val_smmu.h"
#include "val/include/val_spdm.h"
#include "val/include/val_tdisp.h"

#define TEST_NAME "cda_rdrvtk_d2h_mecid"
#define TEST_DESC "Host constrains MECID for device-to-host traffic"
#define TEST_RULE "RDRVTK"

#define DECODER_SLOT 0u
#define RDRVTK_ALLOWED_MECID 1u
#define RDRVTK_DENIED_MECID  VAL_GMECID
#define RDRVTK_SRC_PATTERN   0xA5u
#define RDRVTK_DST_PATTERN   0x5Au
#define RDRVTK_ALLOWED_SEED  0xA55A1029384756EFULL
#define RDRVTK_DENIED_SEED   0x5AA5FEDCBA987601ULL
#define RDRVTK_ALLOWED_BACKING 0x1122334455667788ULL
#define RDRVTK_DENIED_BACKING  0x8877665544332211ULL
#define RDRVTK_PASS_PARTIAL  0xAC500001u
#define SEC_SID_NONSECURE    0x0u
#define SEC_SID_REALM        0x2u

#define RMECDA_CTL1_TDISP_EN_MASK  0x1u

#if ENABLE_SPDM

/*
 * Test outline:
 *  1. Select a MEC-capable CHI-C2C TDI and configure PMECID=1.
 *  2. Program Realm SMMU translations whose STE selects MECID=1.
 *  3. Perform a device read followed by a device write to ACS-owned HCM.
 *  4. Prove that the resulting plaintext is visible with MECID=1 and is not
 *     visible with MECID=0. This is the mandatory D2H request check.
 *  5. When the exerciser can select the MECID of a snoop response, compare an
 *     allowed response against a response carrying an unpermitted MECID.
 *
 * The snoop-response control is an exerciser stimulus, not a host-port status
 * hook. The verdict is inferred from the protected host read and returned
 * data. A platform without this stimulus reports partial coverage after the
 * mandatory request-path check passes.
 */

typedef struct {
  val_spdm_context_t spdm_ctx;
  pci_tdisp_interface_id_t interface_id;
  uint32_t session_id;
  uint32_t session_active;
  uint32_t ide_active;
} RDRVTK_LINK_STATE;

static uint32_t
select_dcm_pages(uint64_t window_base,
                 uint64_t window_size,
                 uint64_t *lower_hpa,
                 uint64_t *upper_hpa)
{
  uint64_t page_size;
  uint64_t window_end;
  uint64_t selected;

  if ((lower_hpa == NULL) || (upper_hpa == NULL))
    return ACS_STATUS_ERR;

  page_size = (uint64_t)val_memory_page_size();
  if ((page_size == 0u) || (window_size < (2u * page_size)))
    return ACS_STATUS_SKIP;

  window_end = window_base + window_size;
  if (window_end < window_base)
    return ACS_STATUS_ERR;

  if (val_cda_select_dcm_page(window_base, window_size, &selected)
      != ACS_STATUS_PASS)
    return ACS_STATUS_SKIP;

  if ((selected < (window_base + page_size)) ||
      ((selected + page_size) < selected) ||
      ((selected + page_size) > window_end))
    return ACS_STATUS_SKIP;

  *upper_hpa = selected;
  *lower_hpa = selected - page_size;
  return ACS_STATUS_PASS;
}

static uint32_t
start_realm_link(const VAL_CDA_DCM_WINDOW_CONTEXT *context,
                 RDRVTK_LINK_STATE *link)
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
stop_realm_link(const VAL_CDA_DCM_WINDOW_CONTEXT *context,
                RDRVTK_LINK_STATE *link)
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
    if (val_tdisp_stop_if_needed(&link->spdm_ctx,
                                 link->session_id,
                                 &link->interface_id,
                                 0u) != ACS_STATUS_PASS)
      result = ACS_STATUS_FAIL;
    link->session_active = 0u;
  }

  return result;
}

/* Create one Realm stage-2 context covering both HCM and DCM test pages. */
static uint32_t
configure_realm_smmu(uint32_t endpoint_bdf,
                     uint64_t source_pa,
                     uint64_t destination_pa,
                     uint64_t dcm_base,
                     uint64_t verify_pa,
                     uint32_t page_size,
                     smmu_master_attributes_t *master,
                     pgt_descriptor_t *pgt_desc)
{
  memory_region_descriptor_t mem_desc[5];
  uint32_t device_id;
  uint32_t its_id;
  uint32_t smmu_index;
  uint64_t vttbr_orig;

  if ((source_pa == 0u) || (destination_pa == 0u) || (dcm_base == 0u) ||
      (verify_pa == 0u) || (page_size == 0u) || (master == NULL) ||
      (pgt_desc == NULL))
    return ACS_STATUS_ERR;

  val_memory_set(master, sizeof(*master), 0);
  val_memory_set(pgt_desc, sizeof(*pgt_desc), 0);
  val_memory_set(mem_desc, sizeof(mem_desc), 0);
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

  master->smmu_index = smmu_index;
  if (val_smmu_enable(smmu_index) != 0u)
    return ACS_STATUS_ERR;

  mem_desc[0].virtual_address = source_pa;
  mem_desc[0].physical_address = source_pa;
  mem_desc[0].length = page_size;
  mem_desc[0].attributes = PGT_STAGE2_AP_RW;
  mem_desc[1].virtual_address = destination_pa;
  mem_desc[1].physical_address = destination_pa;
  mem_desc[1].length = page_size;
  mem_desc[1].attributes = PGT_STAGE2_AP_RW;
  mem_desc[2].virtual_address = dcm_base;
  mem_desc[2].physical_address = dcm_base;
  mem_desc[2].length = 2u * page_size;
  mem_desc[2].attributes = PGT_STAGE2_AP_RW;
  mem_desc[3].virtual_address = verify_pa;
  mem_desc[3].physical_address = verify_pa;
  mem_desc[3].length = page_size;
  mem_desc[3].attributes = PGT_STAGE2_AP_RW | PGT_STAGE2_RME_NS_MASK;

  pgt_desc->ias = (uint32_t)val_smmu_get_info(SMMU_IN_ADDR_SIZE, smmu_index);
  pgt_desc->oas = (uint32_t)val_smmu_get_info(SMMU_OUT_ADDR_SIZE, smmu_index);
  pgt_desc->stage = PGT_STAGE2;
  if ((pgt_desc->ias == 0u) || (pgt_desc->oas == 0u))
    goto setup_skip;

  if (val_pe_get_vtcr(&pgt_desc->vtcr) != 0u)
    goto setup_error;

  if ((val_memory_map_el3_data((uint64_t)mem_desc,
                               sizeof(mem_desc),
                               NONSECURE_PAS) != ACS_STATUS_PASS) ||
      (val_memory_map_el3_data((uint64_t)pgt_desc,
                               sizeof(*pgt_desc),
                               NONSECURE_PAS) != ACS_STATUS_PASS) ||
      (val_memory_map_el3_data((uint64_t)master,
                               sizeof(*master),
                               NONSECURE_PAS) != ACS_STATUS_PASS))
    goto setup_error;

  /* Realm page-table memory is created and later destroyed under MECID=1. */
  if (val_rlm_configure_mecid(RDRVTK_ALLOWED_MECID) != 0u)
    goto setup_error;

  if (val_rlm_pgt_create(mem_desc, pgt_desc) != 0u)
  {
    (void)val_rlm_configure_mecid(VAL_GMECID);
    goto setup_error;
  }

  if (val_rlm_configure_mecid(VAL_GMECID) != 0u)
    goto setup_error_with_pgt;

  vttbr_orig = val_pe_reg_read(VTTBR);
  val_pe_reg_write(VTTBR, pgt_desc->pgt_base);
  master->stage2 = 1u;
  if (val_smmu_rlm_map_el3(master, pgt_desc) != 0u)
  {
    val_pe_reg_write(VTTBR, vttbr_orig);
    goto setup_error_with_pgt;
  }
  val_pe_reg_write(VTTBR, vttbr_orig);

  /* Program MECID after the map has installed the Realm STE. */
  if (val_smmu_rlm_configure_mecid(master, RDRVTK_ALLOWED_MECID) != 0u)
    goto setup_error_with_pgt;

  val_print(ACS_PRINT_DEBUG, " RDRVTK: SMMU index %u", smmu_index);
  val_print(ACS_PRINT_DEBUG, " RDRVTK: StreamID 0x%x", master->streamid);
  return ACS_STATUS_PASS;

setup_error_with_pgt:
  (void)val_smmu_disable(smmu_index);
  (void)val_rlm_configure_mecid(RDRVTK_ALLOWED_MECID);
  val_rlm_pgt_destroy(pgt_desc);
  pgt_desc->pgt_base = 0u;
  (void)val_rlm_configure_mecid(VAL_GMECID);
  master->smmu_index = ACS_INVALID_INDEX;
  return ACS_STATUS_ERR;
setup_error:
  (void)val_rlm_configure_mecid(VAL_GMECID);
  (void)val_smmu_disable(smmu_index);
  master->smmu_index = ACS_INVALID_INDEX;
  return ACS_STATUS_ERR;

setup_skip:
  (void)val_smmu_disable(smmu_index);
  master->smmu_index = ACS_INVALID_INDEX;
  return ACS_STATUS_SKIP;
}

static uint32_t
start_dma(uint32_t endpoint_bdf,
          uint64_t address,
          uint32_t length,
          uint32_t direction)
{
  uint32_t status;

  if ((val_exerciser_set_param_by_bdf(CFG_TXN_ATTRIBUTES,
                                      TXN_ADDR_TYPE,
                                      AT_UNTRANSLATED,
                                      endpoint_bdf) != 0u) ||
      (val_exerciser_set_param_by_bdf(CFG_TXN_ATTRIBUTES,
                                      TXN_ATC_ENTRY,
                                      ATC_ENTRY_DISABLE,
                                      endpoint_bdf) != 0u) ||
      (val_exerciser_set_param_by_bdf(DMA_ATTRIBUTES,
                                      address,
                                      length,
                                      endpoint_bdf) != 0u))
    return ACS_STATUS_ERR;

  status = val_exerciser_ops_by_bdf(START_DMA, direction, endpoint_bdf);
  val_print(ACS_PRINT_DEBUG, " RDRVTK: DMA direction %u", direction);
  val_print(ACS_PRINT_DEBUG, " RDRVTK: DMA status 0x%x", status);
  return (status == 0u) ? ACS_STATUS_PASS : ACS_STATUS_FAIL;
}

static uint32_t
check_request_mecid(uint32_t endpoint_bdf,
                    uint8_t *source,
                    uint8_t *destination,
                    uint64_t source_pa,
                    uint64_t destination_pa,
                    uint32_t page_size)
{
  uint32_t status;

  if (val_memory_prepare_dma_buffers_el3(source,
                                         destination,
                                         page_size,
                                         RDRVTK_SRC_PATTERN,
                                         RDRVTK_DST_PATTERN) != ACS_STATUS_PASS)
    return ACS_STATUS_ERR;

  if ((val_memory_cache_clean_invalidate_range_el3((uint64_t)source,
                                                    page_size)
       != ACS_STATUS_PASS) ||
      (val_memory_cache_clean_invalidate_range_el3((uint64_t)destination,
                                                    page_size)
       != ACS_STATUS_PASS))
    return ACS_STATUS_ERR;

  /* Use untranslated IOVAs so the Realm STE resolves both request MECIDs. */
  if ((start_dma(endpoint_bdf,
                 source_pa,
                 page_size,
                 EDMA_TO_DEVICE) != ACS_STATUS_PASS) ||
      (start_dma(endpoint_bdf,
                 destination_pa,
                 page_size,
                 EDMA_FROM_DEVICE) != ACS_STATUS_PASS))
  {
    val_print(ACS_PRINT_ERR, " RDRVTK: permitted D2H DMA failed", 0);
    return ACS_STATUS_FAIL;
  }

  if (val_memory_cache_invalidate_range_el3((uint64_t)destination,
                                             page_size) != ACS_STATUS_PASS)
    return ACS_STATUS_ERR;

  if (val_memory_compare_el3((uint64_t)source,
                             (uint64_t)destination,
                             page_size) != 0u)
  {
    val_print(ACS_PRINT_ERR,
              " RDRVTK: data is not visible with the permitted MECID",
              0);
    return ACS_STATUS_FAIL;
  }

  /* Push the data through the encryption point before changing PE MECID. */
  if ((val_cmo_to_poe(source_pa) != 0u) ||
      (val_cmo_to_poe(destination_pa) != 0u))
    return ACS_STATUS_ERR;

  if (val_rlm_configure_mecid(RDRVTK_DENIED_MECID) != 0u)
    return ACS_STATUS_ERR;

  if (val_memory_cache_invalidate_range_el3((uint64_t)destination,
                                             page_size) != ACS_STATUS_PASS)
  {
    (void)val_rlm_configure_mecid(RDRVTK_ALLOWED_MECID);
    return ACS_STATUS_ERR;
  }

  status = val_memory_has_byte_pattern_el3((uint64_t)destination,
                                           page_size,
                                           RDRVTK_SRC_PATTERN);
  if (val_rlm_configure_mecid(RDRVTK_ALLOWED_MECID) != 0u)
    return ACS_STATUS_ERR;

  if (status == ACS_STATUS_ERR)
    return ACS_STATUS_ERR;
  if (status == ACS_STATUS_PASS)
  {
    val_print(ACS_PRINT_ERR,
              " RDRVTK: D2H data is visible with an unselected MECID",
              0);
    return ACS_STATUS_FAIL;
  }

  if ((val_memory_cache_invalidate_range_el3((uint64_t)source,
                                              page_size) != ACS_STATUS_PASS) ||
      (val_memory_cache_invalidate_range_el3((uint64_t)destination,
                                              page_size) != ACS_STATUS_PASS) ||
      (val_memory_compare_el3((uint64_t)source,
                              (uint64_t)destination,
                              page_size) != 0u))
  {
    val_print(ACS_PRINT_ERR,
              " RDRVTK: permitted MECID did not recover D2H plaintext",
              0);
    return ACS_STATUS_FAIL;
  }

  val_print(ACS_PRINT_INFO,
            " RDRVTK: D2H requests used the SMMU-selected MECID",
            0);
  return ACS_STATUS_PASS;
}

static uint32_t
prepare_dirty_dcm_line(uint32_t endpoint_bdf,
                       volatile uint64_t *realm_alias,
                       uint64_t dcm_hpa,
                       uint64_t dcm_dpa,
                       uint8_t *verify_va,
                       uint64_t verify_pa,
                       uint64_t seed,
                       uint64_t backing_value,
                       uint32_t page_size)
{
  uint32_t status;

  status = val_cda_populate_realm_device_cache_line(endpoint_bdf,
                                                     realm_alias,
                                                     dcm_hpa,
                                                     verify_va,
                                                     verify_pa,
                                                     seed,
                                                     page_size);
  if (status != ACS_STATUS_PASS)
  {
    val_print(ACS_PRINT_INFO,
              " RDRVTK: coherent cache-line population unavailable",
              0);
    return ACS_STATUS_SKIP;
  }

  if (val_cxl_exerciser_execute_cmd(endpoint_bdf,
                                     CXL_CMD_OP_DCM_CACHE_DIRTY,
                                     dcm_hpa,
                                     0u,
                                     NULL) != ACS_STATUS_PASS)
  {
    val_print(ACS_PRINT_INFO,
              " RDRVTK: coherent cache-state stimulus unavailable",
              0);
    return ACS_STATUS_SKIP;
  }

  /*
   * Change only backing media through the direct-DPA test interface. The
   * dirty coherent line retains seed, while a rejected response can resolve
   * to the distinct backing value. This makes the host outcome observable.
   */
  if (val_cxl_exerciser_backdoor_write64(endpoint_bdf,
                                          dcm_dpa,
                                          backing_value) != ACS_STATUS_PASS)
  {
    val_print(ACS_PRINT_INFO,
              " RDRVTK: direct-DPA backing-data stimulus unavailable",
              0);
    return ACS_STATUS_SKIP;
  }

  return ACS_STATUS_PASS;
}

static uint32_t
check_snoop_response_mecid(const VAL_CDA_DCM_WINDOW_CONTEXT *context,
                           volatile uint64_t *allowed_alias,
                           volatile uint64_t *denied_alias,
                           uint64_t allowed_hpa,
                           uint64_t denied_hpa,
                           uint64_t allowed_dpa,
                           uint64_t denied_dpa,
                           uint8_t *verify_va,
                           uint64_t verify_pa,
                           uint32_t page_size)
{
  uint64_t observed;
  uint64_t read_esr;
  uint32_t host_fault;
  uint32_t status;

  status = prepare_dirty_dcm_line(context->endpoint_bdf,
                                  allowed_alias,
                                  allowed_hpa,
                                  allowed_dpa,
                                  verify_va,
                                  verify_pa,
                                  RDRVTK_ALLOWED_SEED,
                                  RDRVTK_ALLOWED_BACKING,
                                  page_size);
  if (status != ACS_STATUS_PASS)
    return status;

  status = val_cxl_exerciser_set_snoop_response_mecid(context->endpoint_bdf,
                                                       RDRVTK_ALLOWED_MECID,
                                                       1u);
  if (status != ACS_STATUS_PASS)
    return status;

  observed = 0u;
  read_esr = 0u;
  host_fault = 0u;
  status = val_memory_read64_el3_protected_with_esr(allowed_alias,
                                                     &observed,
                                                     &host_fault,
                                                     &read_esr);
  if (status != ACS_STATUS_PASS)
    return ACS_STATUS_ERR;

  if ((host_fault != 0u) || (observed != RDRVTK_ALLOWED_SEED))
  {
    val_print(ACS_PRINT_ERR,
              " RDRVTK: permitted snoop-response MECID was not accepted",
              0);
    val_print(ACS_PRINT_DEBUG, " RDRVTK: permitted read ESR 0x%llx", read_esr);
    val_print(ACS_PRINT_DEBUG,
              " RDRVTK: permitted read data 0x%llx",
              observed);
    return ACS_STATUS_FAIL;
  }

  status = prepare_dirty_dcm_line(context->endpoint_bdf,
                                  denied_alias,
                                  denied_hpa,
                                  denied_dpa,
                                  verify_va,
                                  verify_pa,
                                  RDRVTK_DENIED_SEED,
                                  RDRVTK_DENIED_BACKING,
                                  page_size);
  if (status != ACS_STATUS_PASS)
    return status;

  status = val_cxl_exerciser_set_snoop_response_mecid(context->endpoint_bdf,
                                                       RDRVTK_DENIED_MECID,
                                                       1u);
  if (status != ACS_STATUS_PASS)
    return status;

  observed = 0u;
  read_esr = 0u;
  host_fault = 0u;
  status = val_memory_read64_el3_protected_with_esr(denied_alias,
                                                     &observed,
                                                     &host_fault,
                                                     &read_esr);
  if (status != ACS_STATUS_PASS)
    return ACS_STATUS_ERR;

  val_print(ACS_PRINT_DEBUG, " RDRVTK: denied read fault %u", host_fault);
  val_print(ACS_PRINT_DEBUG, " RDRVTK: denied read ESR 0x%llx", read_esr);
  val_print(ACS_PRINT_DEBUG, " RDRVTK: denied read data 0x%llx", observed);

  if ((host_fault == 0u) && (observed == RDRVTK_DENIED_SEED))
  {
    val_print(ACS_PRINT_ERR,
              " RDRVTK: host consumed an unpermitted-MECID snoop response",
              0);
    return ACS_STATUS_FAIL;
  }

  if ((host_fault == 0u) && (observed != RDRVTK_DENIED_BACKING))
  {
    val_print(ACS_PRINT_INFO,
              " RDRVTK: wrong-MECID response outcome is inconclusive",
              0);
    return ACS_STATUS_SKIP;
  }

  val_print(ACS_PRINT_INFO,
            " RDRVTK: host rejected or isolated the unpermitted response MECID",
            0);
  return ACS_STATUS_PASS;
}

static uint32_t
exercise_rule(VAL_CDA_DCM_WINDOW_CONTEXT *context)
{
  RDRVTK_LINK_STATE link;
  VAL_SMMU_DPT_CFG_STATE dpt_state;
  smmu_master_attributes_t master;
  pgt_descriptor_t pgt_desc;
  volatile uint64_t *allowed_alias;
  volatile uint64_t *denied_alias;
  uint8_t *buffer;
  uint8_t *source;
  uint8_t *destination;
  uint8_t *verify_va;
  uint64_t source_pa;
  uint64_t destination_pa;
  uint64_t verify_pa;
  uint64_t allowed_hpa;
  uint64_t denied_hpa;
  uint64_t allowed_dpa;
  uint64_t denied_dpa;
  uint64_t max_pa;
  uint32_t page_size;
  uint32_t properties;
  uint32_t mecid_width;
  uint32_t rmecda_ctl3_orig;
  uint32_t rmecda_ctl4_orig;
  uint32_t ats_cap_base;
  uint32_t ats_ctrl_orig;
  uint32_t response_cmd_supported;
  uint32_t response_stimulus;
  uint32_t cache_enable_saved;
  uint32_t cache_enable_orig;
  uint32_t root_rid_saved;
  uint32_t allowed_assigned;
  uint32_t denied_assigned;
  uint32_t pmecid_configured;
  uint32_t mec_was_enabled;
  uint32_t mec_enabled_locally;
  uint32_t pe_mecid_selected;
  uint32_t smmu_ready;
  uint32_t dpt_ready;
  uint32_t hcm_gpt_set;
  uint32_t dcm_gpt_set;
  uint32_t verify_gpt_set;
  uint32_t ats_enabled;
  uint32_t sec_sid_set;
  uint32_t result;
  uint32_t status;

  if (context == NULL)
    return ACS_STATUS_ERR;

  val_memory_set(&link, sizeof(link), 0);
  val_memory_set(&dpt_state, sizeof(dpt_state), 0);
  val_memory_set(&master, sizeof(master), 0);
  val_memory_set(&pgt_desc, sizeof(pgt_desc), 0);
  master.smmu_index = ACS_INVALID_INDEX;
  allowed_alias = NULL;
  denied_alias = NULL;
  buffer = NULL;
  source = NULL;
  destination = NULL;
  verify_va = NULL;
  source_pa = 0u;
  destination_pa = 0u;
  verify_pa = 0u;
  allowed_hpa = 0u;
  denied_hpa = 0u;
  allowed_dpa = 0u;
  denied_dpa = 0u;
  response_cmd_supported = 0u;
  response_stimulus = 0u;
  cache_enable_saved = 0u;
  cache_enable_orig = 0u;
  root_rid_saved = 0u;
  allowed_assigned = 0u;
  denied_assigned = 0u;
  pmecid_configured = 0u;
  mec_was_enabled = 0u;
  mec_enabled_locally = 0u;
  pe_mecid_selected = 0u;
  smmu_ready = 0u;
  dpt_ready = 0u;
  hcm_gpt_set = 0u;
  dcm_gpt_set = 0u;
  verify_gpt_set = 0u;
  ats_enabled = 0u;
  sec_sid_set = 0u;
  result = ACS_STATUS_FAIL;

  page_size = val_memory_page_size();
  if ((page_size == 0u) || (page_size > (0xFFFFFFFFu / 3u)))
    return ACS_STATUS_ERR;

  status = val_tdisp_get_device_properties(context->endpoint_bdf, &properties);
  if (status != ACS_STATUS_PASS)
    return status;

  mecid_width = (properties & VAL_TDISP_DEV_PROP_MECID_MASK) >>
                VAL_TDISP_DEV_PROP_MECID_SHIFT;
  if (((properties & VAL_TDISP_DEV_PROP_MEC) == 0u) || (mecid_width == 0u))
    return ACS_STATUS_SKIP;

  if (val_is_mec_supported() == 0u)
  {
    val_print(ACS_PRINT_INFO, " RDRVTK: host MEC support is unavailable", 0);
    return ACS_STATUS_SKIP;
  }

  status = select_dcm_pages(context->window_base,
                            context->window_size,
                            &allowed_hpa,
                            &denied_hpa);
  if (status != ACS_STATUS_PASS)
    return status;

  /* Use ACS-reserved memory so changing GPT ownership cannot affect UEFI. */
  buffer = (uint8_t *)val_get_free_va(3u * page_size);
  if ((buffer == NULL) || ((uint64_t)buffer == 1u))
    return ACS_STATUS_SKIP;

  source = buffer;
  destination = buffer + page_size;
  verify_va = buffer + (2u * page_size);
  source_pa = (uint64_t)val_memory_virt_to_phys(source);
  destination_pa = (uint64_t)val_memory_virt_to_phys(destination);
  verify_pa = (uint64_t)val_memory_virt_to_phys(verify_va);
  if ((source_pa == 0u) || (destination_pa == 0u) || (verify_pa == 0u))
  {
    result = ACS_STATUS_ERR;
    goto cleanup;
  }

  val_print(ACS_PRINT_INFO, " RDRVTK: CHI-C2C RP 0x%x", context->root_bdf);
  val_print(ACS_PRINT_INFO, " RDRVTK: CHI-C2C EP 0x%x", context->endpoint_bdf);
  val_print(ACS_PRINT_DEBUG, " RDRVTK: HCM source PA 0x%llx", source_pa);
  val_print(ACS_PRINT_DEBUG,
            " RDRVTK: HCM destination PA 0x%llx",
            destination_pa);
  val_print(ACS_PRINT_DEBUG, " RDRVTK: DCM HPAs 0x%llx", allowed_hpa);
  val_print(ACS_PRINT_DEBUG, " RDRVTK: second DCM HPA 0x%llx", denied_hpa);

  /*
   * Remove any non-secure cached copies before changing the HCM pages to
   * Realm ownership. Complete GPT maintenance before configuring the test
   * MEC context so ownership and encryption setup remain independent.
   */
  val_pe_cache_clean_invalidate_range((uint64_t)buffer, 3u * page_size);

  if (val_add_gpt_entry_el3(source_pa, GPT_REALM) != 0u)
  {
    result = ACS_STATUS_ERR;
    goto cleanup;
  }
  hcm_gpt_set |= 1u;

  if (val_add_gpt_entry_el3(destination_pa, GPT_REALM) != 0u)
  {
    result = ACS_STATUS_ERR;
    goto cleanup;
  }
  hcm_gpt_set |= 2u;

  if (val_add_gpt_entry_el3(allowed_hpa, GPT_REALM) != 0u)
  {
    result = ACS_STATUS_ERR;
    goto cleanup;
  }
  dcm_gpt_set |= 1u;

  if (val_add_gpt_entry_el3(denied_hpa, GPT_REALM) != 0u)
  {
    result = ACS_STATUS_ERR;
    goto cleanup;
  }
  dcm_gpt_set |= 2u;

  if (val_add_gpt_entry_el3(verify_pa, GPT_ANY) != 0u)
  {
    result = ACS_STATUS_ERR;
    goto cleanup;
  }
  verify_gpt_set = 1u;

  if ((val_memory_map_realm_cacheable_alias(allowed_hpa, &allowed_alias)
       != ACS_STATUS_PASS) ||
      (val_memory_map_realm_cacheable_alias(denied_hpa, &denied_alias)
       != ACS_STATUS_PASS) ||
      (val_memory_map_dma_buffer_el3(source,
                                     source_pa,
                                     page_size,
                                     REALM_PAS) != ACS_STATUS_PASS) ||
      (val_memory_map_dma_buffer_el3(destination,
                                     destination_pa,
                                     page_size,
                                     REALM_PAS) != ACS_STATUS_PASS) ||
      (val_memory_map_el3_data((uint64_t)verify_va,
                               page_size,
                               NONSECURE_PAS) != ACS_STATUS_PASS))
  {
    result = ACS_STATUS_ERR;
    goto cleanup;
  }

  if (val_rlm_get_mec_state(&mec_was_enabled) != 0u)
  {
    result = ACS_STATUS_ERR;
    goto cleanup;
  }

  if ((mec_was_enabled == 0u) && (val_rlm_enable_mec() != 0u))
  {
    result = ACS_STATUS_ERR;
    goto cleanup;
  }
  mec_enabled_locally = (mec_was_enabled == 0u) ? 1u : 0u;

  if (val_rlm_configure_mecid(VAL_GMECID) != 0u)
  {
    result = ACS_STATUS_ERR;
    goto cleanup;
  }

  status = val_tdisp_configure_pmecid(context->endpoint_bdf,
                                      RDRVTK_ALLOWED_MECID);
  if (status != ACS_STATUS_PASS)
  {
    result = status;
    goto cleanup;
  }
  pmecid_configured = 1u;

  /* Probe the optional response-MECID stimulus before entering TDISP RUN. */
  if (val_cxl_exerciser_set_snoop_response_mecid(context->endpoint_bdf,
                                                  0u,
                                                  0u) == ACS_STATUS_PASS)
  {
    response_cmd_supported = 1u;
    response_stimulus = 1u;
    status = val_cxl_get_cache_enable(context->endpoint_bdf,
                                      &cache_enable_orig);
    if (status == ACS_STATUS_SKIP)
    {
      response_stimulus = 0u;
    }
    else if (status != ACS_STATUS_PASS)
    {
      result = status;
      goto cleanup;
    }
    else
    {
      cache_enable_saved = 1u;
      status = val_cxl_enable_cache(context->endpoint_bdf);
      if (status == ACS_STATUS_SKIP)
        response_stimulus = 0u;
      else if (status != ACS_STATUS_PASS)
      {
        result = status;
        goto cleanup;
      }
    }
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
  root_rid_saved = 1u;

  if ((val_cda_set_link_stream_lock(context->rmecda_cfg_va,
                                    context->rmecda_cap_base,
                                    context->rmecda_ctl1_orig |
                                    RMECDA_CTL1_TDISP_EN_MASK,
                                    0u) != ACS_STATUS_PASS) ||
      (val_cda_program_rid_range(
                 context->rmecda_cfg_va,
                 context->rmecda_cap_base,
                 rmecda_ctl3_orig,
                 rmecda_ctl4_orig,
                 (uint32_t)PCIE_CREATE_BDF_PACKED(context->endpoint_bdf),
                 (uint32_t)PCIE_CREATE_BDF_PACKED(context->endpoint_bdf),
                 1u) != ACS_STATUS_PASS) ||
      (val_cda_set_link_stream_lock(context->rmecda_cfg_va,
                                    context->rmecda_cap_base,
                                    context->rmecda_ctl1_orig |
                                    RMECDA_CTL1_TDISP_EN_MASK,
                                    1u) != ACS_STATUS_PASS))
  {
    result = ACS_STATUS_ERR;
    goto cleanup;
  }

  if (response_stimulus != 0u)
  {
    if ((val_cxl_hpa_to_dpa(context->endpoint_index,
                            allowed_hpa,
                            &allowed_dpa) != ACS_STATUS_PASS) ||
        (val_cxl_hpa_to_dpa(context->endpoint_index,
                            denied_hpa,
                            &denied_dpa) != ACS_STATUS_PASS))
    {
      val_print(ACS_PRINT_INFO,
                " RDRVTK: HPA-to-DPA translation unavailable",
                0);
      response_stimulus = 0u;
    }
  }

  if (response_stimulus != 0u)
  {
    if (val_cxl_exerciser_execute_cmd(
                    context->endpoint_bdf,
                    CXL_CMD_OP_DCM_SET_REALM_ASSIGNMENT,
                    allowed_hpa,
                    1u,
                    NULL) != ACS_STATUS_PASS)
    {
      val_print(ACS_PRINT_INFO,
                " RDRVTK: DCM assignment stimulus unavailable",
                0);
      response_stimulus = 0u;
    }
    else
    {
      allowed_assigned = 1u;
    }

    if ((response_stimulus != 0u) &&
        (val_cxl_exerciser_execute_cmd(
                    context->endpoint_bdf,
                    CXL_CMD_OP_DCM_SET_REALM_ASSIGNMENT,
                    denied_hpa,
                    1u,
                    NULL) != ACS_STATUS_PASS))
    {
      val_print(ACS_PRINT_INFO,
                " RDRVTK: DCM assignment stimulus unavailable",
                0);
      response_stimulus = 0u;
    }
    else if (response_stimulus != 0u)
    {
      denied_assigned = 1u;
    }
  }

  status = configure_realm_smmu(context->endpoint_bdf,
                                source_pa,
                                destination_pa,
                                allowed_hpa,
                                verify_pa,
                                page_size,
                                &master,
                                &pgt_desc);
  if (status != ACS_STATUS_PASS)
  {
    result = status;
    goto cleanup;
  }
  smmu_ready = 1u;

  if (val_smmu_gpt_invalidate_el3(&master) != 0u)
  {
    result = ACS_STATUS_ERR;
    goto cleanup;
  }

  if ((val_exerciser_set_param_by_bdf(CFG_TXN_ATTRIBUTES,
                                      TXN_REQ_ID_VALID,
                                      RID_NOT_VALID,
                                      context->endpoint_bdf) != 0u) ||
      (val_exerciser_set_param_by_bdf(EXERCISER_SEC_SID,
                                      SEC_SID_REALM,
                                      0u,
                                      context->endpoint_bdf) != 0u))
  {
    result = ACS_STATUS_SKIP;
    goto cleanup;
  }
  sec_sid_set = 1u;

  status = start_realm_link(context, &link);
  if (status != ACS_STATUS_PASS)
  {
    result = status;
    goto cleanup;
  }

  if (val_rlm_configure_mecid(RDRVTK_ALLOWED_MECID) != 0u)
  {
    result = ACS_STATUS_ERR;
    goto cleanup;
  }
  pe_mecid_selected = 1u;

  status = check_request_mecid(context->endpoint_bdf,
                               source,
                               destination,
                               source_pa,
                               destination_pa,
                               page_size);
  if (status != ACS_STATUS_PASS)
  {
    result = status;
    goto cleanup;
  }

  if (response_stimulus == 0u)
  {
    val_print(ACS_PRINT_INFO,
              " RDRVTK: partial coverage; snoop-response MECID stimulus unavailable",
              0);
    result = RDRVTK_PASS_PARTIAL;
    goto cleanup;
  }

  /* DPT is required only by the optional ATS-backed response stimulus. */
  max_pa = denied_hpa;
  if (verify_pa > max_pa)
    max_pa = verify_pa;

  status = val_smmu_configure_dpt_coverage(master.smmu_index,
                                           max_pa,
                                           &dpt_state);
  if (status != ACS_STATUS_PASS)
  {
    if (status == ACS_STATUS_SKIP)
    {
      val_print(ACS_PRINT_INFO,
                " RDRVTK: partial coverage; DPT response stimulus unavailable",
                0);
      result = RDRVTK_PASS_PARTIAL;
    }
    else
    {
      result = status;
    }
    goto cleanup;
  }
  dpt_ready = 1u;

  if ((val_dpt_add_entry(allowed_hpa,
                         ((uint64_t)master.smmu_index << 32) |
                         DPT_RDWR_ACCESS_ENTRY) != 0u) ||
      (val_dpt_add_entry(denied_hpa,
                         ((uint64_t)master.smmu_index << 32) |
                         DPT_RDWR_ACCESS_ENTRY) != 0u) ||
      (val_dpt_add_entry(verify_pa,
                         ((uint64_t)master.smmu_index << 32) |
                         DPT_RDWR_NS_ACCESS_ENTRY) != 0u) ||
      (val_dpt_invalidate_all(master.smmu_index) != 0u))
  {
    result = ACS_STATUS_ERR;
    goto cleanup;
  }

  status = val_pcie_enable_ats(context->endpoint_bdf,
                               &ats_cap_base,
                               &ats_ctrl_orig);
  if (status != ACS_STATUS_PASS)
  {
    if (status == ACS_STATUS_SKIP)
    {
      val_print(ACS_PRINT_INFO,
                " RDRVTK: partial coverage; ATS cache-fill stimulus unavailable",
                0);
      result = RDRVTK_PASS_PARTIAL;
    }
    else
    {
      result = status;
    }
    goto cleanup;
  }
  ats_enabled = 1u;

  status = check_snoop_response_mecid(context,
                                      allowed_alias,
                                      denied_alias,
                                      allowed_hpa,
                                      denied_hpa,
                                      allowed_dpa,
                                      denied_dpa,
                                      verify_va,
                                      verify_pa,
                                      page_size);
  if (status == ACS_STATUS_SKIP)
  {
    val_print(ACS_PRINT_INFO,
              " RDRVTK: partial coverage; snoop-response path unavailable",
              0);
    result = RDRVTK_PASS_PARTIAL;
    goto cleanup;
  }
  if (status != ACS_STATUS_PASS)
  {
    result = status;
    goto cleanup;
  }

  result = ACS_STATUS_PASS;

cleanup:
  if (response_cmd_supported != 0u)
    (void)val_cxl_exerciser_set_snoop_response_mecid(context->endpoint_bdf,
                                                      0u,
                                                      0u);
  (void)val_exerciser_set_param_by_bdf(CFG_TXN_ATTRIBUTES,
                                       TXN_ATC_ENTRY,
                                       ATC_ENTRY_DISABLE,
                                       context->endpoint_bdf);
  (void)val_exerciser_ops_by_bdf(ATS_INV_CACHE, 0u, context->endpoint_bdf);

  /* Keep TDISP cleanup and endpoint commands in the default host context. */
  if (pe_mecid_selected != 0u)
  {
    if (val_rlm_configure_mecid(VAL_GMECID) != 0u)
      result = ACS_STATUS_FAIL;
    else
      pe_mecid_selected = 0u;
  }

  if (stop_realm_link(context, &link) != ACS_STATUS_PASS)
    result = ACS_STATUS_FAIL;

  if ((cache_enable_saved != 0u) &&
      (val_cxl_set_cache_enable(context->endpoint_bdf,
                                cache_enable_orig) != ACS_STATUS_PASS))
    result = ACS_STATUS_FAIL;

  if ((allowed_assigned != 0u) &&
      (val_cxl_exerciser_execute_cmd(
                     context->endpoint_bdf,
                     CXL_CMD_OP_DCM_SET_REALM_ASSIGNMENT,
                     allowed_hpa,
                     0u,
                     NULL) != ACS_STATUS_PASS))
    result = ACS_STATUS_FAIL;

  if ((denied_assigned != 0u) &&
      (val_cxl_exerciser_execute_cmd(
                     context->endpoint_bdf,
                     CXL_CMD_OP_DCM_SET_REALM_ASSIGNMENT,
                     denied_hpa,
                     0u,
                     NULL) != ACS_STATUS_PASS))
    result = ACS_STATUS_FAIL;

  if (sec_sid_set != 0u)
  {
    if (val_exerciser_set_param_by_bdf(EXERCISER_SEC_SID,
                                       SEC_SID_NONSECURE,
                                       0u,
                                       context->endpoint_bdf) != 0u)
      result = ACS_STATUS_FAIL;
  }

  if ((dpt_ready != 0u) &&
      (val_smmu_restore_dpt_coverage(&dpt_state) != ACS_STATUS_PASS))
    result = ACS_STATUS_FAIL;

  if (smmu_ready != 0u)
  {
    (void)val_smmu_disable(master.smmu_index);
    if (val_rlm_configure_mecid(RDRVTK_ALLOWED_MECID) != 0u)
      result = ACS_STATUS_FAIL;
    else
    {
      pe_mecid_selected = 1u;
      if (val_rlm_pgt_destroy(&pgt_desc) != 0u)
        result = ACS_STATUS_FAIL;
      pgt_desc.pgt_base = 0u;
    }

    if (val_rlm_configure_mecid(VAL_GMECID) != 0u)
      result = ACS_STATUS_FAIL;
    else
      pe_mecid_selected = 0u;
  }
  else if ((pe_mecid_selected != 0u) &&
           (val_rlm_configure_mecid(VAL_GMECID) != 0u))
  {
    result = ACS_STATUS_FAIL;
  }

  if (ats_enabled != 0u)
    val_pcie_write_cfg(context->endpoint_bdf,
                       ats_cap_base + ATS_CTRL,
                       ats_ctrl_orig);

  if (root_rid_saved != 0u)
  {
    if ((val_cda_set_link_stream_lock(context->rmecda_cfg_va,
                                      context->rmecda_cap_base,
                                      context->rmecda_ctl1_orig,
                                      0u) != ACS_STATUS_PASS) ||
        (val_cda_program_rid_range(
                          context->rmecda_cfg_va,
                          context->rmecda_cap_base,
                          rmecda_ctl3_orig,
                          rmecda_ctl4_orig,
                          (rmecda_ctl4_orig >> 8) & 0xFFFFu,
                          (rmecda_ctl3_orig >> 8) & 0xFFFFu,
                          rmecda_ctl4_orig & 0x1u) != ACS_STATUS_PASS))
      result = ACS_STATUS_FAIL;
  }

  /* SET_INTERFACE has no PMECID readback; restore its defined default value. */
  if ((pmecid_configured != 0u) &&
      (val_tdisp_configure_pmecid(context->endpoint_bdf, VAL_GMECID)
       != ACS_STATUS_PASS))
    result = ACS_STATUS_FAIL;

  if ((mec_enabled_locally != 0u) && (val_rlm_disable_mec() != 0u))
    result = ACS_STATUS_FAIL;

  /* Restore GPT ownership only after returning EL3 to the non-MEC context. */
  if (((hcm_gpt_set & 1u) != 0u) &&
      (val_add_gpt_entry_el3(source_pa, GPT_ANY) != 0u))
    result = ACS_STATUS_FAIL;
  if (((hcm_gpt_set & 2u) != 0u) &&
      (val_add_gpt_entry_el3(destination_pa, GPT_ANY) != 0u))
    result = ACS_STATUS_FAIL;

  if (((dcm_gpt_set & 1u) != 0u) &&
      (val_add_gpt_entry_el3(allowed_hpa, GPT_ANY) != 0u))
    result = ACS_STATUS_FAIL;
  if (((dcm_gpt_set & 2u) != 0u) &&
      (val_add_gpt_entry_el3(denied_hpa, GPT_ANY) != 0u))
    result = ACS_STATUS_FAIL;

  if ((verify_gpt_set != 0u) &&
      (val_add_gpt_entry_el3(verify_pa, GPT_ANY) != 0u))
    result = ACS_STATUS_FAIL;

  return result;
}

static void
payload(void)
{
  VAL_CDA_DCM_WINDOW_CONTEXT context;
  uint32_t context_prepared;
  uint32_t pe_index;
  uint32_t status;

  pe_index = val_pe_get_index_mpid(val_pe_get_mpid());
  context_prepared = 0u;

  status = val_cda_prepare_dcm_window_with_dev_props(DECODER_SLOT,
                                                      VAL_TDISP_DEV_PROP_MEC,
                                                      &context);
  if (status == ACS_STATUS_PASS)
  {
    context_prepared = 1u;
    status = exercise_rule(&context);
  }

  if ((context_prepared != 0u) &&
      (val_cda_restore_dcm_window(&context) != ACS_STATUS_PASS))
  {
    val_print(ACS_PRINT_ERR, " RDRVTK: platform state restoration failed", 0);
    status = ACS_STATUS_FAIL;
  }

  if (status == ACS_STATUS_PASS)
    val_set_status(pe_index, "PASS", 01);
  else if (status == RDRVTK_PASS_PARTIAL)
    val_set_status(pe_index, "PASS_PARTIAL", 02);
  else if (status == ACS_STATUS_SKIP)
    val_set_status(pe_index, "SKIP", 03);
  else
    val_set_status(pe_index, "FAIL", 03);
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
cda_rdrvtk_d2h_mecid_entry(uint32_t num_pe)
{
  uint32_t status;

  num_pe = 1u;
  status = val_initialize_test(TEST_NAME, TEST_DESC, num_pe, TEST_RULE);

  if (status != ACS_STATUS_SKIP)
    val_run_test_payload(num_pe, payload, 0);

  status = val_check_for_error(num_pe);
  val_report_status(0, "END");
  return status;
}
