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

#define TEST_NAME "cda_rlmflx_config_unlocked_invalidate"
#define TEST_DESC "CONFIG_UNLOCKED invalidates TDI cache/ATC state"
#define TEST_RULE "RLMFLX"

#define DECODER_SLOT 0u

#define RMECDA_CTL1_TDISP_EN_MASK 0x1u
#define RMECDA_CTL1_LINK_STR_LOCK_MASK (1u << 1)

#define RLMFLX_DIRTY_VALUE 0xC0DA5A5A11223344ULL
#define RLMFLX_ATS_PATTERN 0x5Au

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
  uint32_t rmecda_ctl3_orig;
  uint32_t rmecda_ctl4_orig;
  uint32_t rmecda_regs_valid;
  uint32_t rmecda_cap_base;
  uint64_t rmecda_cfg_va;
  uint32_t ats_ctrl_orig;
  uint32_t ats_ctrl_valid;
  uint32_t ats_cap_base;
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
  uint32_t ctl3_readback;
  uint32_t ctl4_readback;

  if (context == NULL)
    return ACS_STATUS_ERR;

  restore_status = ACS_STATUS_PASS;
  readback = 0u;
  ctl3_readback = 0u;
  ctl4_readback = 0u;

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
                  " RLMFLX: RMECDA_CTL1 root restore readback 0x%x",
                  (uint64_t)readback);
        restore_status = ACS_STATUS_ERR;
      }
    }
    else
    {
      val_pcie_write_cfg(context->root_bdf,
                         context->rmecda_cap_base + RMECDA_CTL1_OFFSET,
                         context->rmecda_ctl1_orig);
    }
  }

  /* Restore the writable RID fields only after restoring the unlocked state. */
  if ((context->rmecda_regs_valid != 0u) && (context->rmecda_cfg_va != 0u))
  {
    if ((val_memory_write_el3(context->rmecda_cfg_va +
                              context->rmecda_cap_base +
                              RMECDA_CTL3_OFFSET,
                              context->rmecda_ctl3_orig) != ACS_STATUS_PASS) ||
        (val_memory_write_el3(context->rmecda_cfg_va +
                              context->rmecda_cap_base +
                              RMECDA_CTL4_OFFSET,
                              context->rmecda_ctl4_orig) != ACS_STATUS_PASS) ||
        (val_memory_read_el3(context->rmecda_cfg_va +
                             context->rmecda_cap_base +
                             RMECDA_CTL3_OFFSET,
                             &ctl3_readback) != ACS_STATUS_PASS) ||
        (val_memory_read_el3(context->rmecda_cfg_va +
                             context->rmecda_cap_base +
                             RMECDA_CTL4_OFFSET,
                             &ctl4_readback) != ACS_STATUS_PASS) ||
        (ctl3_readback != context->rmecda_ctl3_orig) ||
        (ctl4_readback != context->rmecda_ctl4_orig))
    {
      val_print(ACS_PRINT_WARN,
                " RLMFLX: RMECDA RID state restore failed",
                0);
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
    restore_status = ACS_STATUS_ERR;

  return restore_status;
}

static uint32_t
configure_smmu_master(uint32_t endpoint_bdf, smmu_master_attributes_t *master_out)
{
  uint32_t device_id;
  uint32_t its_id;
  uint32_t endpoint_streamid;
  uint32_t smmu_index;

  if (master_out == NULL)
    return ACS_STATUS_ERR;

  val_memory_set(master_out, sizeof(*master_out), 0);
  master_out->smmu_index = ACS_INVALID_INDEX;

  smmu_index = val_iovirt_get_rc_smmu_index(PCIE_EXTRACT_BDF_SEG(endpoint_bdf),
                                            PCIE_CREATE_BDF_PACKED(endpoint_bdf));
  if (smmu_index == ACS_INVALID_INDEX)
    return ACS_STATUS_SKIP;

  if (val_iovirt_get_smmu_info(SMMU_CTRL_ARCH_MAJOR_REV, smmu_index) != 3u)
    return ACS_STATUS_SKIP;

  device_id = 0u;
  its_id = 0u;
  endpoint_streamid = 0u;
  if (val_iovirt_get_device_info(PCIE_CREATE_BDF_PACKED(endpoint_bdf),
                                 PCIE_EXTRACT_BDF_SEG(endpoint_bdf),
                                 &device_id,
                                 &endpoint_streamid,
                                 &its_id))
  {
    return ACS_STATUS_SKIP;
  }

  if (val_smmu_enable(smmu_index))
    return ACS_STATUS_ERR;

  master_out->smmu_index = smmu_index;
  master_out->streamid = endpoint_streamid;
  master_out->stage2 = 1u;

  val_print(ACS_PRINT_DEBUG, " RLMFLX: SMMU index %u", (uint64_t)smmu_index);
  val_print(ACS_PRINT_DEBUG, " RLMFLX: SMMU streamid 0x%x",
            (uint64_t)endpoint_streamid);
  val_print(ACS_PRINT_DEBUG, " RLMFLX: SMMU device id 0x%x",
            (uint64_t)device_id);
  val_print(ACS_PRINT_DEBUG, " RLMFLX: SMMU ITS id 0x%x", (uint64_t)its_id);

  return ACS_STATUS_PASS;
}

static uint32_t
install_smmu_mapping(const smmu_master_attributes_t *master,
                     uint64_t iova,
                     uint64_t target_pa,
                     uint64_t page_size,
                     pgt_descriptor_t *pgt_desc_out)
{
  memory_region_descriptor_t mem_desc[2];
  pgt_descriptor_t pgt_desc;
  uint32_t ias;
  uint32_t oas;

  if ((master == NULL) || (pgt_desc_out == NULL) ||
      (master->smmu_index == ACS_INVALID_INDEX) ||
      (iova == 0u) || (target_pa == 0u) || (page_size == 0u))
  {
    return ACS_STATUS_ERR;
  }

  ias = (uint32_t)val_smmu_get_info(SMMU_IN_ADDR_SIZE, master->smmu_index);
  oas = (uint32_t)val_smmu_get_info(SMMU_OUT_ADDR_SIZE, master->smmu_index);
  if ((ias == 0u) || (oas == 0u))
    return ACS_STATUS_SKIP;

  val_memory_set(mem_desc, sizeof(mem_desc), 0);
  mem_desc[0].virtual_address = iova;
  mem_desc[0].physical_address = target_pa;
  mem_desc[0].length = page_size;
  mem_desc[0].attributes = PGT_STAGE2_AP_RW;
  mem_desc[1].length = 0u;

  val_memory_set(&pgt_desc, sizeof(pgt_desc), 0);
  pgt_desc.ias = ias;
  pgt_desc.oas = oas;
  pgt_desc.stage = PGT_STAGE2;

  if (val_pe_get_vtcr(&pgt_desc.vtcr))
    return ACS_STATUS_ERR;

  if ((val_memory_map_el3_data((uint64_t)mem_desc,
                               sizeof(mem_desc),
                               NONSECURE_PAS) != ACS_STATUS_PASS) ||
      (val_memory_map_el3_data((uint64_t)&pgt_desc,
                               sizeof(pgt_desc),
                               NONSECURE_PAS) != ACS_STATUS_PASS) ||
      (val_memory_map_el3_data((uint64_t)master,
                               sizeof(*master),
                               NONSECURE_PAS) != ACS_STATUS_PASS))
  {
    return ACS_STATUS_ERR;
  }

  if (val_rlm_pgt_create(mem_desc, &pgt_desc))
    return ACS_STATUS_ERR;

  val_pe_reg_write(VTTBR, pgt_desc.pgt_base);
  if (val_smmu_rlm_map_el3((smmu_master_attributes_t *)master, &pgt_desc))
  {
    val_rlm_pgt_destroy(&pgt_desc);
    return ACS_STATUS_ERR;
  }

  *pgt_desc_out = pgt_desc;
  val_print(ACS_PRINT_DEBUG, " RLMFLX: IOVA 0x%llx", iova);
  val_print(ACS_PRINT_DEBUG, " RLMFLX: target PA 0x%llx", target_pa);
  return ACS_STATUS_PASS;
}

static uint32_t
issue_ats_translation(uint32_t endpoint_bdf,
                      uint64_t iova,
                      uint32_t length,
                      uint64_t *translated_addr_out)
{
  uint64_t request_addr;

  if ((iova == 0u) || (length == 0u) || (translated_addr_out == NULL))
    return ACS_STATUS_ERR;

  if (val_exerciser_set_param_by_bdf(DMA_ATTRIBUTES,
                                     iova,
                                     length,
                                     endpoint_bdf))
    return ACS_STATUS_ERR;

  if (val_exerciser_ops_by_bdf(ATS_TXN_REQ, iova, endpoint_bdf))
    return ACS_STATUS_FAIL;

  request_addr = iova;
  if (val_exerciser_get_param_by_bdf(ATS_RES_ATTRIBUTES,
                                     translated_addr_out,
                                     &request_addr,
                                     endpoint_bdf))
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
    uint32_t dev_properties;
    uint32_t status;
    uint32_t endpoint_rid;
    uint32_t ctl1_programmed;
    uint32_t ctl1_readback;

    init_context(&candidate);
    root_port = &table->component[root_idx];

    if ((root_port->role != CXL_COMPONENT_ROLE_ROOT_PORT) ||
        (root_port->chi_c2c_supported == 0u))
    {
      continue;
    }

    status = val_cda_find_downstream_chi_c2c_exerciser_endpoint(root_port->bdf,
                                                                &endpoint_bdf);
    if (status != ACS_STATUS_PASS)
      continue;

    if (val_cxl_find_component_index_by_bdf(endpoint_bdf,
                                            &candidate.endpoint_index)
        != ACS_STATUS_PASS)
    {
      continue;
    }

    endpoint = &table->component[candidate.endpoint_index];
    if ((endpoint->role != CXL_COMPONENT_ROLE_ENDPOINT) ||
        (endpoint->chi_c2c_supported == 0u))
    {
      continue;
    }

    /* Cache-line setup uses a direct coherent Realm host access. */
    if ((val_tdisp_get_device_properties(endpoint_bdf, &dev_properties)
         != ACS_STATUS_PASS) ||
        ((dev_properties & VAL_TDISP_DEV_PROP_PAS_CHECK) == 0u))
      continue;

    candidate.root_index = root_idx;
    candidate.root_bdf = root_port->bdf;
    candidate.endpoint_bdf = endpoint_bdf;
    candidate.host_index = root_port->host_bridge_index;

    if (candidate.host_index == CXL_COMPONENT_INVALID_INDEX)
      continue;

    if (val_pcie_find_cda_capability(candidate.root_bdf,
                                     &candidate.rmecda_cap_base) != PCIE_SUCCESS)
      continue;

    if (val_pcie_find_capability(candidate.root_bdf,
                                 PCIE_ECAP,
                                 ECID_AER,
                                 &candidate.aer_offset) != PCIE_SUCCESS)
      continue;

    if (val_cxl_select_cfmws_window(candidate.host_index,
                                    &candidate.window_base,
                                    &candidate.window_size) != ACS_STATUS_PASS)
      continue;

    if (val_cxl_get_decoder(candidate.host_index,
                            DECODER_SLOT,
                            &candidate.host_decoder_base_orig,
                            &candidate.host_decoder_size_orig) != 0u)
      continue;

    if (val_cxl_get_host_decoder_target(candidate.host_index,
                                        DECODER_SLOT,
                                        &candidate.host_target_low_orig,
                                        &candidate.host_target_high_orig) != 0u)
      continue;
    candidate.host_target_valid = 1u;

    if (val_cxl_get_component_decoder(candidate.endpoint_index,
                                      DECODER_SLOT,
                                      &candidate.endpoint_decoder_base_orig,
                                      &candidate.endpoint_decoder_size_orig) != 0u)
      continue;

    if (val_pcie_read_cfg(candidate.root_bdf,
                          candidate.rmecda_cap_base + RMECDA_CTL1_OFFSET,
                          &candidate.rmecda_ctl1_orig) != PCIE_SUCCESS)
      continue;

    if ((candidate.rmecda_ctl1_orig &
         (RMECDA_CTL1_TDISP_EN_MASK | RMECDA_CTL1_LINK_STR_LOCK_MASK)) != 0u)
    {
      val_print(ACS_PRINT_DEBUG,
                " RLMFLX: RMECDA_CTL1 not clean 0x%x",
                (uint64_t)candidate.rmecda_ctl1_orig);
      continue;
    }

    if (val_pcie_map_root_config(candidate.root_bdf,
                                 &candidate.rmecda_cfg_va) != ACS_STATUS_PASS)
      continue;

    if (val_memory_read_el3(candidate.rmecda_cfg_va +
                            candidate.rmecda_cap_base +
                            RMECDA_CTL1_OFFSET,
                            &candidate.rmecda_ctl1_orig) != ACS_STATUS_PASS)
    {
      (void)restore_context_state(&candidate);
      continue;
    }

    if ((val_memory_read_el3(candidate.rmecda_cfg_va +
                             candidate.rmecda_cap_base +
                             RMECDA_CTL3_OFFSET,
                             &candidate.rmecda_ctl3_orig) != ACS_STATUS_PASS) ||
        (val_memory_read_el3(candidate.rmecda_cfg_va +
                             candidate.rmecda_cap_base +
                             RMECDA_CTL4_OFFSET,
                             &candidate.rmecda_ctl4_orig) != ACS_STATUS_PASS))
    {
      (void)restore_context_state(&candidate);
      continue;
    }
    candidate.rmecda_ctl1_valid = 1u;
    candidate.rmecda_regs_valid = 1u;

    if (val_cxl_enable_cache(candidate.endpoint_bdf) != ACS_STATUS_PASS)
    {
      (void)restore_context_state(&candidate);
      continue;
    }

    if (val_cxl_enable_mem(candidate.endpoint_bdf) != ACS_STATUS_PASS)
    {
      (void)restore_context_state(&candidate);
      continue;
    }

    if (val_cxl_program_host_decoder_for_root(candidate.root_bdf,
                                             candidate.host_index,
                                             DECODER_SLOT,
                                             candidate.window_base,
                                             candidate.window_size) != ACS_STATUS_PASS)
    {
      (void)restore_context_state(&candidate);
      continue;
    }

    if (val_cxl_program_component_decoder(candidate.endpoint_index,
                                          DECODER_SLOT,
                                          candidate.window_base,
                                          candidate.window_size) != ACS_STATUS_PASS)
    {
      (void)restore_context_state(&candidate);
      continue;
    }

    /* Admit the selected TDI's requester ID before locking the stream policy. */
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
      (void)restore_context_state(&candidate);
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

    if ((ctl1_readback &
         (RMECDA_CTL1_TDISP_EN_MASK | RMECDA_CTL1_LINK_STR_LOCK_MASK)) !=
        (RMECDA_CTL1_TDISP_EN_MASK | RMECDA_CTL1_LINK_STR_LOCK_MASK))
    {
      (void)restore_context_state(&candidate);
      continue;
    }

    *context = candidate;
    val_print(ACS_PRINT_INFO, " RLMFLX: selected RP 0x%x", context->root_bdf);
    val_print(ACS_PRINT_INFO, " RLMFLX: selected EP 0x%x", context->endpoint_bdf);
    return ACS_STATUS_PASS;
  }

  return ACS_STATUS_SKIP;
}

static uint32_t
exercise_rule(TEST_CONTEXT *context)
{
  volatile uint64_t *realm_alias;
  smmu_master_attributes_t master;
  pgt_descriptor_t pgt_desc_old;
  pgt_descriptor_t pgt_desc_new;
  VAL_SMMU_DPT_CFG_STATE dpt_cfg_state;
  val_spdm_context_t spdm_ctx;
  pci_tdisp_interface_id_t interface_id;
  val_spdm_context_t spdm_ctx_second;
  pci_tdisp_interface_id_t interface_id_second;
  uint8_t *ats_buffer;
  uint64_t dcm_hpa;
  uint64_t ats_iova;
  uint64_t ats_old_pa;
  uint64_t ats_new_pa;
  uint64_t ats_translated;
  uint64_t observed;
  uint32_t page_size;
  uint32_t session_id;
  uint32_t session_open;
  uint32_t tdi_stopped;
  uint32_t second_session_id;
  uint32_t second_session_open;
  uint32_t ide_enabled;
  uint32_t second_ide_enabled;
  uint32_t realm_assigned;
  uint32_t atc_probe_enabled;
  uint32_t smmu_active;
  uint32_t old_pgt_created;
  uint32_t new_pgt_created;
  uint32_t old_gpt_set;
  uint32_t new_gpt_set;
  uint32_t old_dpt_set;
  uint32_t new_dpt_set;
  uint32_t host_fault;
  uint32_t aer_uncorr;
  uint32_t status;
  uint32_t result;

  if (context == NULL)
    return ACS_STATUS_ERR;

  val_memory_clear_el3_access_state();
  val_memory_set(&master, sizeof(master), 0);
  val_memory_set(&pgt_desc_old, sizeof(pgt_desc_old), 0);
  val_memory_set(&pgt_desc_new, sizeof(pgt_desc_new), 0);
  val_memory_set(&dpt_cfg_state, sizeof(dpt_cfg_state), 0);
  val_memory_set(&spdm_ctx, sizeof(spdm_ctx), 0);
  val_memory_set(&spdm_ctx_second, sizeof(spdm_ctx_second), 0);
  master.smmu_index = ACS_INVALID_INDEX;

  realm_alias = NULL;
  ats_buffer = NULL;
  ats_iova = 0u;
  ats_old_pa = 0u;
  ats_new_pa = 0u;
  session_id = 0u;
  session_open = 0u;
  tdi_stopped = 0u;
  second_session_id = 0u;
  second_session_open = 0u;
  ide_enabled = 0u;
  second_ide_enabled = 0u;
  realm_assigned = 0u;
  atc_probe_enabled = 0u;
  smmu_active = 0u;
  old_pgt_created = 0u;
  new_pgt_created = 0u;
  old_gpt_set = 0u;
  new_gpt_set = 0u;
  old_dpt_set = 0u;
  new_dpt_set = 0u;
  result = ACS_STATUS_FAIL;

  page_size = val_memory_page_size();
  if (page_size == 0u)
    return ACS_STATUS_ERR;

  status = val_cda_select_dcm_page(context->window_base,
                                   context->window_size,
                                   &dcm_hpa);
  if (status != ACS_STATUS_PASS)
    return status;

  val_print(ACS_PRINT_INFO, " RLMFLX: Realm DCM HPA 0x%llx", dcm_hpa);

  if (val_memory_map_realm_cacheable_alias(dcm_hpa, &realm_alias) != ACS_STATUS_PASS)
    return ACS_STATUS_ERR;

  status = val_cxl_exerciser_execute_cmd(context->endpoint_bdf,
                                         CXL_CMD_OP_DCM_SET_REALM_ASSIGNMENT,
                                         dcm_hpa,
                                         1u,
                                         NULL);
  if (status != ACS_STATUS_PASS)
  {
    val_print(ACS_PRINT_INFO, " RLMFLX: Realm DCM assignment hook unavailable", 0);
    result = ACS_STATUS_SKIP;
    goto cleanup;
  }
  realm_assigned = 1u;

  /*
   * Prepare an optional ATC probe. The exerciser must be able to issue an ATS
   * request for IOVA->PA before STOP and again after the same IOVA is remapped.
   * Some FVP exerciser configurations do not expose this path, so the dirty
   * cache invalidation check remains the mandatory part of this ACS test.
   */
  ats_buffer = (uint8_t *)val_memory_alloc_pages(2u);
  if (ats_buffer != NULL)
  {
    ats_old_pa = (uint64_t)val_memory_virt_to_phys(ats_buffer);
    ats_new_pa = (uint64_t)val_memory_virt_to_phys(ats_buffer + page_size);
    ats_iova = ats_old_pa;
  }

  if ((ats_old_pa != 0u) && (ats_new_pa != 0u) && (ats_old_pa != ats_new_pa))
  {
    status = val_pcie_enable_ats(context->endpoint_bdf,
                                 &context->ats_cap_base,
                                 &context->ats_ctrl_orig);
    if (status == ACS_STATUS_PASS)
    {
      context->ats_ctrl_valid = 1u;
      status = configure_smmu_master(context->endpoint_bdf, &master);
      if (status == ACS_STATUS_PASS)
        smmu_active = 1u;
    }

    if (status == ACS_STATUS_PASS)
    {
      if (val_add_gpt_entry_el3(ats_old_pa, GPT_NONSECURE) == 0u)
        old_gpt_set = 1u;
      else
        status = ACS_STATUS_ERR;
    }

    if (status == ACS_STATUS_PASS)
    {
      if (val_add_gpt_entry_el3(ats_new_pa, GPT_NONSECURE) == 0u)
        new_gpt_set = 1u;
      else
        status = ACS_STATUS_ERR;
    }

    if (status == ACS_STATUS_PASS)
    {
      if ((val_memory_map_el3_data((uint64_t)ats_buffer,
                                   page_size,
                                   NONSECURE_PAS) != ACS_STATUS_PASS) ||
          (val_memory_map_el3_data((uint64_t)(ats_buffer + page_size),
                                   page_size,
                                   NONSECURE_PAS) != ACS_STATUS_PASS))
      {
        status = ACS_STATUS_ERR;
      }
    }

    if (status == ACS_STATUS_PASS)
    {
      (void)val_memory_set_el3(ats_buffer, page_size, RLMFLX_ATS_PATTERN);
      (void)val_memory_set_el3(ats_buffer + page_size, page_size, 0u);

      status = val_smmu_configure_dpt_coverage(master.smmu_index,
                                               (ats_old_pa > ats_new_pa) ?
                                               ats_old_pa : ats_new_pa,
                                               &dpt_cfg_state);
    }

    if (status == ACS_STATUS_PASS)
    {
      if (val_dpt_add_entry(ats_old_pa,
                            ((((uint64_t)master.smmu_index) << 32) |
                             DPT_RDWR_ACCESS_ENTRY)) == 0u)
        old_dpt_set = 1u;
      else
        status = ACS_STATUS_ERR;
    }

    if (status == ACS_STATUS_PASS)
    {
      if (val_dpt_add_entry(ats_new_pa,
                            ((((uint64_t)master.smmu_index) << 32) |
                             DPT_RDWR_ACCESS_ENTRY)) == 0u)
        new_dpt_set = 1u;
      else
        status = ACS_STATUS_ERR;
    }

    if ((status == ACS_STATUS_PASS) &&
        (val_dpt_invalidate_all(master.smmu_index) == 0u) &&
        (install_smmu_mapping(&master,
                              ats_iova,
                              ats_old_pa,
                              page_size,
                              &pgt_desc_old) == ACS_STATUS_PASS))
    {
      old_pgt_created = 1u;
      atc_probe_enabled = 1u;
    }

    if (atc_probe_enabled == 0u)
    {
      val_print(ACS_PRINT_WARN, " RLMFLX: ATS stale-translation probe unavailable", 0);
    }
  }
  else
  {
    val_print(ACS_PRINT_WARN, " RLMFLX: ATS stale-translation probe not enabled", 0);
  }

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
    val_print(ACS_PRINT_INFO, " RLMFLX: IDE establish unavailable", 0);
    result = (status == ACS_STATUS_SKIP) ? ACS_STATUS_SKIP : ACS_STATUS_FAIL;
    goto cleanup;
  }
  ide_enabled = 1u;

  if (atc_probe_enabled != 0u)
  {
    (void)val_exerciser_ops_by_bdf(ATS_INV_CACHE, 0u, context->endpoint_bdf);
    ats_translated = 0u;
    status = issue_ats_translation(context->endpoint_bdf,
                                   ats_iova,
                                   page_size,
                                   &ats_translated);
    if (status != ACS_STATUS_PASS)
    {
      val_print(ACS_PRINT_WARN, " RLMFLX: initial ATS request unavailable", 0);
      atc_probe_enabled = 0u;
    }
    else if (ats_translated != ats_old_pa)
    {
      val_print(ACS_PRINT_WARN,
                " RLMFLX: initial ATS translated to 0x%llx",
                ats_translated);
      atc_probe_enabled = 0u;
    }
  }

  /*
   * Initialize backing DCM through a non-cacheable Realm mapping, then use a
   * cacheable Realm read to populate a clean line through CXL.mem. The cache
   * command marks that existing line dirty. STOP_INTERFACE must write the value
   * back before invalidating the line.
   */
  if (val_cda_seed_realm_cache_line(dcm_hpa,
                                    realm_alias,
                                    RLMFLX_DIRTY_VALUE) != ACS_STATUS_PASS)
  {
    val_print(ACS_PRINT_ERR, " RLMFLX: failed to create Realm cache line", 0);
    result = ACS_STATUS_FAIL;
    goto cleanup;
  }

  status = val_cxl_exerciser_execute_cmd(context->endpoint_bdf,
                                         CXL_CMD_OP_DCM_CACHE_DIRTY,
                                         dcm_hpa,
                                         0u,
                                         NULL);
  if (status != ACS_STATUS_PASS)
  {
    val_print(ACS_PRINT_INFO,
              " RLMFLX: required Realm cache-line stimulus unavailable",
              0);
    result = ACS_STATUS_SKIP;
    goto cleanup;
  }

  status = val_tdisp_stop_to_config_unlocked(&spdm_ctx, session_id, &interface_id);
  if (status != ACS_STATUS_PASS)
  {
    result = ACS_STATUS_FAIL;
    goto cleanup;
  }
  tdi_stopped = 1u;

  if (atc_probe_enabled != 0u)
  {
    status = install_smmu_mapping(&master,
                                  ats_iova,
                                  ats_new_pa,
                                  page_size,
                                  &pgt_desc_new);
    if (status != ACS_STATUS_PASS)
    {
      result = status;
      goto cleanup;
    }
    new_pgt_created = 1u;
  }

  if (ide_enabled != 0u)
  {
    status = val_cxl_ide_disable_link(context->root_index,
                                      context->endpoint_index,
                                      &spdm_ctx,
                                      session_id);
    if (status != ACS_STATUS_PASS)
    {
      val_print(ACS_PRINT_WARN, " RLMFLX: IDE disable after STOP failed", 0);
      result = ACS_STATUS_FAIL;
      goto cleanup;
    }
    ide_enabled = 0u;
  }

  if (session_open != 0u)
  {
    status = val_spdm_session_close(&spdm_ctx, session_id);
    if (status != ACS_STATUS_PASS)
    {
      result = ACS_STATUS_FAIL;
      goto cleanup;
    }
    session_open = 0u;
  }

  /*
   * External Realm DCM access is gated while the TDI is CONFIG_UNLOCKED.
   * Re-enter RUN and enable IDE before reading from the host path. If STOP
   * failed to invalidate dirty TDI state, this read is still poisoned; if it
   * succeeded, the writeback data is visible without an error response.
   */
  status = val_tdisp_establish_run(context->endpoint_bdf,
                                   &spdm_ctx_second,
                                   &second_session_id,
                                   &interface_id_second);
  if (status != ACS_STATUS_PASS)
  {
    result = (status == ACS_STATUS_SKIP) ? ACS_STATUS_SKIP : ACS_STATUS_FAIL;
    goto cleanup;
  }
  second_session_open = 1u;

  status = val_cxl_ide_establish_link(context->root_index,
                                      context->endpoint_index,
                                      &spdm_ctx_second,
                                      second_session_id);
  if (status != ACS_STATUS_PASS)
  {
    val_print(ACS_PRINT_INFO, " RLMFLX: second IDE establish unavailable", 0);
    result = (status == ACS_STATUS_SKIP) ? ACS_STATUS_SKIP : ACS_STATUS_FAIL;
    goto cleanup;
  }
  second_ide_enabled = 1u;

  /*
   * Invalidate the PE copy so the read fetches data written back by the device.
   * Invalidate-only avoids cleaning PE data over the value that STOP_INTERFACE
   * had to preserve.
   */
  if (val_data_cache_ops_by_va_el3((uint64_t)realm_alias, INVALIDATE) != 0u)
  {
    result = ACS_STATUS_ERR;
    goto cleanup;
  }

  val_cxl_aer_clear(context->root_bdf, context->aer_offset);
  observed = 0u;
  host_fault = 0u;
  status = val_memory_read64_el3_protected(realm_alias, &observed, &host_fault);
  (void)val_cxl_aer_read_uncorr(context->root_bdf,
                                context->aer_offset,
                                &aer_uncorr);
  val_print(ACS_PRINT_DEBUG, " RLMFLX: re-RUN host read status %u", status);
  val_print(ACS_PRINT_DEBUG, " RLMFLX: re-RUN host read fault %u", host_fault);
  val_print(ACS_PRINT_DEBUG, " RLMFLX: re-RUN host observed 0x%llx", observed);
  val_print(ACS_PRINT_DEBUG, " RLMFLX: re-RUN AER uncorrectable 0x%x", aer_uncorr);

  if (status != ACS_STATUS_PASS)
  {
    result = ACS_STATUS_ERR;
    goto cleanup;
  }

  if (host_fault != 0u)
  {
    val_print(ACS_PRINT_ERR,
              " RLMFLX: host read faulted after re-RUN",
              0);
    result = ACS_STATUS_FAIL;
    goto cleanup;
  }

  if (observed != RLMFLX_DIRTY_VALUE)
  {
    val_print(ACS_PRINT_ERR,
              " RLMFLX: dirty data was not preserved after re-RUN, observed 0x%llx",
              observed);
    result = ACS_STATUS_FAIL;
    goto cleanup;
  }

  if (atc_probe_enabled != 0u)
  {
    ats_translated = 0u;
    status = issue_ats_translation(context->endpoint_bdf,
                                   ats_iova,
                                   page_size,
                                   &ats_translated);
    if (status != ACS_STATUS_PASS)
    {
      result = ACS_STATUS_FAIL;
      goto cleanup;
    }

    if (ats_translated != ats_new_pa)
    {
      val_print(ACS_PRINT_ERR,
                " RLMFLX: stale ATC translation 0x%llx after CONFIG_UNLOCKED",
                ats_translated);
      val_print(ACS_PRINT_ERR,
                " RLMFLX: expected remapped PA 0x%llx",
                ats_new_pa);
      result = ACS_STATUS_FAIL;
      goto cleanup;
    }

    val_print(ACS_PRINT_INFO, " RLMFLX: ATS remap observed after CONFIG_UNLOCKED", 0);
  }

  result = ACS_STATUS_PASS;

cleanup:
  val_memory_clear_el3_access_state();
  val_cxl_aer_clear(context->root_bdf, context->aer_offset);

  if (second_session_open != 0u)
  {
    if (second_ide_enabled != 0u)
    {
      if (val_cxl_ide_disable_link(context->root_index,
                                   context->endpoint_index,
                                   &spdm_ctx_second,
                                   second_session_id) == ACS_STATUS_PASS)
      {
        second_ide_enabled = 0u;
      }
      else
      {
        val_print(ACS_PRINT_WARN, " RLMFLX: second IDE cleanup failed", 0);
      }
    }

    if (val_tdisp_stop_if_needed(&spdm_ctx_second,
                                 second_session_id,
                                 &interface_id_second,
                                 0u) != ACS_STATUS_PASS)
    {
      val_print(ACS_PRINT_WARN, " RLMFLX: second TDISP cleanup failed", 0);
    }
  }

  if (session_open != 0u)
  {
    if (ide_enabled != 0u)
    {
      if (val_cxl_ide_disable_link(context->root_index,
                                   context->endpoint_index,
                                   &spdm_ctx,
                                   session_id) == ACS_STATUS_PASS)
      {
        ide_enabled = 0u;
      }
    }

    if (tdi_stopped != 0u)
      (void)val_spdm_session_close(&spdm_ctx, session_id);
    else
      (void)val_tdisp_stop_if_needed(&spdm_ctx, session_id, &interface_id, 0u);
  }

  if (realm_assigned != 0u)
  {
    if (val_cxl_exerciser_execute_cmd(context->endpoint_bdf,
                                      CXL_CMD_OP_DCM_SET_REALM_ASSIGNMENT,
                                      dcm_hpa,
                                      0u,
                                      NULL) != ACS_STATUS_PASS)
    {
      val_print(ACS_PRINT_WARN, " RLMFLX: failed to clear Realm DCM assignment", 0);
    }
  }

  if (old_dpt_set != 0u)
  {
    (void)val_dpt_add_entry(ats_old_pa,
                            ((((uint64_t)master.smmu_index) << 32) |
                             DPT_RDWR_ACCESS_ENTRY));
  }

  if (new_dpt_set != 0u)
  {
    (void)val_dpt_add_entry(ats_new_pa,
                            ((((uint64_t)master.smmu_index) << 32) |
                             DPT_RDWR_ACCESS_ENTRY));
  }

  if ((old_dpt_set != 0u) || (new_dpt_set != 0u))
    (void)val_dpt_invalidate_all(master.smmu_index);

  if (val_smmu_restore_dpt_coverage(&dpt_cfg_state) != ACS_STATUS_PASS)
    result = ACS_STATUS_ERR;

  if (pgt_desc_old.pgt_base != 0u)
    (void)val_add_gpt_entry_el3(pgt_desc_old.pgt_base, GPT_ANY);

  if (pgt_desc_new.pgt_base != 0u)
    (void)val_add_gpt_entry_el3(pgt_desc_new.pgt_base, GPT_ANY);

  if (old_pgt_created != 0u)
    val_rlm_pgt_destroy(&pgt_desc_old);

  if (new_pgt_created != 0u)
    val_rlm_pgt_destroy(&pgt_desc_new);

  if (smmu_active != 0u)
    (void)val_smmu_disable(master.smmu_index);

  if (old_gpt_set != 0u)
    (void)val_add_gpt_entry_el3(ats_old_pa, GPT_ANY);

  if (new_gpt_set != 0u)
    (void)val_add_gpt_entry_el3(ats_new_pa, GPT_ANY);

  if (ats_buffer != NULL)
    val_memory_free_pages(ats_buffer, 2u);

  val_memory_clear_el3_access_state();
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
    val_print(ACS_PRINT_INFO, " RLMFLX: no suitable CHI-C2C CDA context", 0);
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
    val_print(ACS_PRINT_ERR, " RLMFLX: platform cleanup failed", 0);
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
  val_print(ACS_PRINT_INFO, " RLMFLX: SPDM/TDISP support not enabled", 0);
  val_set_status(pe_index, "SKIP", 01);
}

#endif

uint32_t
cda_rlmflx_config_unlocked_invalidate_entry(uint32_t num_pe)
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
