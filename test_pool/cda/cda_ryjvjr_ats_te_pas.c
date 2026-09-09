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
#include "val/include/val_memory.h"
#include "val/include/val_pcie.h"
#include "val/include/val_pe.h"
#include "val/include/val_pgt.h"
#include "val/include/val_smmu.h"
#include "val/include/val_spdm.h"
#include "val/include/val_tdisp.h"

#define TEST_NAME "cda_ryjvjr_ats_te_pas"
#define TEST_DESC "ATS TE reports the translated PA space             "
#define TEST_RULE "RYJVJR"

#define SMMU_R_IDR0_ATS_MASK       (1u << 10)
#define SMMU_R_IDR3_XT_MASK        (1u << 17)
#define RMECDA_CTL1_TDISP_EN_MASK   0x1u
#define RMECDA_CTL1_LINK_LOCK_MASK  (1u << 1)
#if ENABLE_SPDM

typedef struct {
  uint32_t root_index;
  uint32_t endpoint_index;
  uint32_t root_bdf;
  uint32_t endpoint_bdf;
  uint32_t rmecda_cap_base;
} RYJVJR_DEVICE_CONTEXT;

typedef struct {
  val_spdm_context_t spdm_ctx;
  pci_tdisp_interface_id_t interface_id;
  uint32_t session_id;
  uint32_t session_active;
  uint32_t ide_active;
} RYJVJR_LINK_CONTEXT;

static uint32_t
find_device_context(RYJVJR_DEVICE_CONTEXT *context)
{
  CXL_COMPONENT_TABLE *table;

  if (context == NULL)
    return ACS_STATUS_ERR;

  val_memory_set(context, sizeof(*context), 0);
  context->root_index = CXL_COMPONENT_INVALID_INDEX;
  context->endpoint_index = CXL_COMPONENT_INVALID_INDEX;

  table = val_cxl_component_table_ptr();
  if ((table == NULL) || (table->num_entries == 0u))
    return ACS_STATUS_SKIP;

  /*
   * The stimulus must originate from a CHI-C2C endpoint below an RME-CDA
   * capable root port so that the Realm ATS request follows the CDA path.
   */
  for (uint32_t index = 0u; index < table->num_entries; ++index)
  {
    const CXL_COMPONENT_ENTRY *root_port = &table->component[index];
    const CXL_COMPONENT_ENTRY *endpoint;
    uint32_t capability_offset;
    uint32_t endpoint_bdf;
    uint32_t endpoint_index;

    if ((root_port->role != CXL_COMPONENT_ROLE_ROOT_PORT) ||
        (root_port->chi_c2c_supported == 0u))
      continue;

    if (val_pcie_find_cda_capability(root_port->bdf, &capability_offset)
        != PCIE_SUCCESS)
      continue;

    if (val_cda_find_downstream_chi_c2c_exerciser_endpoint(root_port->bdf,
                                                            &endpoint_bdf)
        != ACS_STATUS_PASS)
      continue;

    if (val_cxl_find_component_index_by_bdf(endpoint_bdf, &endpoint_index)
        != ACS_STATUS_PASS)
      continue;

    endpoint = &table->component[endpoint_index];
    if ((endpoint->role != CXL_COMPONENT_ROLE_ENDPOINT) ||
        (endpoint->chi_c2c_supported == 0u))
      continue;

    context->root_index = index;
    context->endpoint_index = endpoint_index;
    context->root_bdf = root_port->bdf;
    context->endpoint_bdf = endpoint_bdf;
    context->rmecda_cap_base = capability_offset;
    return ACS_STATUS_PASS;
  }

  return ACS_STATUS_SKIP;
}

static uint32_t
start_realm_link(const RYJVJR_DEVICE_CONTEXT *device,
                 RYJVJR_LINK_CONTEXT *link)
{
  uint32_t status;

  if ((device == NULL) || (link == NULL))
    return ACS_STATUS_ERR;

  val_memory_set(link, sizeof(*link), 0);

  /* A Realm ATS request is valid only after the TDI has entered RUN. */
  status = val_tdisp_establish_run(device->endpoint_bdf,
                                   &link->spdm_ctx,
                                   &link->session_id,
                                   &link->interface_id);
  if (status != ACS_STATUS_PASS)
    return status;
  link->session_active = 1u;

  /* Protect traffic on the link before issuing the Realm-tagged request. */
  status = val_cxl_ide_establish_link(device->root_index,
                                      device->endpoint_index,
                                      &link->spdm_ctx,
                                      link->session_id);
  if (status != ACS_STATUS_PASS)
    return status;

  link->ide_active = 1u;
  return ACS_STATUS_PASS;
}

static uint32_t
stop_realm_link(const RYJVJR_DEVICE_CONTEXT *device,
                RYJVJR_LINK_CONTEXT *link)
{
  uint32_t result;

  if ((device == NULL) || (link == NULL))
    return ACS_STATUS_ERR;

  result = ACS_STATUS_PASS;
  if (link->ide_active != 0u)
  {
    if (val_cxl_ide_disable_link(device->root_index,
                                 device->endpoint_index,
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

static uint32_t
prepare_smmu_master(uint32_t endpoint_bdf,
                    smmu_master_attributes_t *master)
{
  uint32_t device_id;
  uint32_t its_id;
  uint32_t smmu_index;

  if (master == NULL)
    return ACS_STATUS_ERR;

  val_memory_set(master, sizeof(*master), 0);
  master->smmu_index = ACS_INVALID_INDEX;

  /* Resolve the endpoint to the SMMU and StreamID used by its ATS request. */
  smmu_index = val_iovirt_get_rc_smmu_index(PCIE_EXTRACT_BDF_SEG(endpoint_bdf),
                                            PCIE_CREATE_BDF_PACKED(endpoint_bdf));
  if (smmu_index == ACS_INVALID_INDEX)
    return ACS_STATUS_SKIP;

  if (val_iovirt_get_smmu_info(SMMU_CTRL_ARCH_MAJOR_REV, smmu_index) != 3u)
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

  val_print(ACS_PRINT_DEBUG, " RYJVJR: SMMU index %u", (uint64_t)smmu_index);
  val_print(ACS_PRINT_DEBUG, " RYJVJR: StreamID 0x%x", (uint64_t)master->streamid);
  return ACS_STATUS_PASS;
}

static uint32_t
check_smmu_xt_support(uint32_t smmu_index)
{
  uint32_t idr0;
  uint32_t idr3;

  if ((val_smmu_read_realm_cfg(SMMUv3_IDR0, smmu_index, &idr0)
       != ACS_STATUS_PASS) ||
      (val_smmu_read_realm_cfg(SMMUv3_IDR3, smmu_index, &idr3)
       != ACS_STATUS_PASS))
    return ACS_STATUS_ERR;

  val_print(ACS_PRINT_INFO, " RYJVJR: SMMU_R_IDR0 0x%x", (uint64_t)idr0);
  val_print(ACS_PRINT_INFO, " RYJVJR: SMMU_R_IDR3 0x%x", (uint64_t)idr3);

  /* The test requires both Realm ATS translation and TE reporting support. */
  if ((idr0 & SMMU_R_IDR0_ATS_MASK) == 0u)
  {
    val_print(ACS_PRINT_ERR, " RYJVJR: Realm ATS is not advertised", 0);
    return ACS_STATUS_FAIL;
  }

  if ((idr3 & SMMU_R_IDR3_XT_MASK) == 0u)
  {
    val_print(ACS_PRINT_ERR, " RYJVJR: XT and TE are not advertised", 0);
    return ACS_STATUS_FAIL;
  }

  return ACS_STATUS_PASS;
}

static uint32_t
install_pas_mappings(const smmu_master_attributes_t *master,
                     uint64_t ns_iova,
                     uint64_t ns_pa,
                     uint64_t realm_iova,
                     uint64_t realm_pa,
                     uint64_t page_size,
                     pgt_descriptor_t *pgt_desc)
{
  memory_region_descriptor_t mem_desc[3];

  if ((master == NULL) || (pgt_desc == NULL))
    return ACS_STATUS_ERR;

  val_memory_set(mem_desc, sizeof(mem_desc), 0);
  val_memory_set(pgt_desc, sizeof(*pgt_desc), 0);

  /*
   * Use two Realm stage-2 descriptors whose output PA spaces differ. This
   * provides the two expected TE values without changing the ATS request.
   */
  mem_desc[0].virtual_address = ns_iova;
  mem_desc[0].physical_address = ns_pa;
  mem_desc[0].length = page_size;
  /* Realm stage-2 RME_NS selects Non-secure as the translated PA space. */
  mem_desc[0].attributes = PGT_STAGE2_AP_RW | PGT_STAGE2_RME_NS_MASK;
  mem_desc[1].virtual_address = realm_iova;
  mem_desc[1].physical_address = realm_pa;
  mem_desc[1].length = page_size;
  /* RME_NS clear retains Realm as the translated PA space. */
  mem_desc[1].attributes = PGT_STAGE2_AP_RW;

  pgt_desc->ias = (uint32_t)val_smmu_get_info(SMMU_IN_ADDR_SIZE,
                                               master->smmu_index);
  pgt_desc->oas = (uint32_t)val_smmu_get_info(SMMU_OUT_ADDR_SIZE,
                                               master->smmu_index);
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
  if (val_smmu_rlm_map_el3((smmu_master_attributes_t *)master, pgt_desc) != 0u)
  {
    val_rlm_pgt_destroy(pgt_desc);
    pgt_desc->pgt_base = 0u;
    return ACS_STATUS_ERR;
  }

  return ACS_STATUS_PASS;
}

static uint32_t
check_translation(uint32_t endpoint_bdf,
                  uint64_t iova,
                  uint64_t expected_pa,
                  uint32_t expected_te,
                  uint32_t page_size)
{
  VAL_ATS_TRANSLATION_RESULT response;
  uint32_t status;

  /*
   * T=1 and XT=0 selects an unconstrained Realm request. In particular,
   * expected_te is not used to construct the request; it is checked only
   * after the SMMU returns the Translation Completion.
   */
  status = val_exerciser_ats_translate_by_bdf(endpoint_bdf,
                                               iova,
                                               page_size,
                                               VAL_ATS_REQUEST_T,
                                               &response);
  if (status != ACS_STATUS_PASS)
    return status;

  val_print(ACS_PRINT_INFO, " RYJVJR: IOVA 0x%llx", iova);
  val_print(ACS_PRINT_INFO, " RYJVJR: translated PA 0x%llx", response.translated_pa);
  val_print(ACS_PRINT_INFO, " RYJVJR: ATS attributes 0x%x",
            (uint64_t)response.response_attributes);
  val_print(ACS_PRINT_INFO, " RYJVJR: TE %u", (uint64_t)response.te);

  if (response.completion_success == 0u)
  {
    val_print(ACS_PRINT_ERR, " RYJVJR: ATS completion was unsuccessful", 0);
    return ACS_STATUS_FAIL;
  }

  if (response.translated_pa != expected_pa)
  {
    val_print(ACS_PRINT_ERR, " RYJVJR: expected PA 0x%llx", expected_pa);
    return ACS_STATUS_FAIL;
  }

  if ((response.response_attributes & VAL_ATS_PERMISSION_MASK) == 0u)
  {
    val_print(ACS_PRINT_ERR, " RYJVJR: completion granted no access", 0);
    return ACS_STATUS_FAIL;
  }

  if (response.te != expected_te)
  {
    val_print(ACS_PRINT_ERR, " RYJVJR: expected TE %u", (uint64_t)expected_te);
    return ACS_STATUS_FAIL;
  }

  return ACS_STATUS_PASS;
}

static uint32_t
exercise_rule(const RYJVJR_DEVICE_CONTEXT *device)
{
  RYJVJR_LINK_CONTEXT link;
  VAL_SMMU_DPT_CFG_STATE dpt_cfg_state;
  smmu_master_attributes_t master;
  pgt_descriptor_t pgt_desc;
  uint8_t *buffer;
  uint64_t buffer_pa;
  uint64_t ns_pa;
  uint64_t realm_pa;
  uint64_t ns_iova;
  uint64_t realm_iova;
  uint64_t max_pa;
  uint64_t rmecda_cfg_va;
  uint32_t page_size;
  uint32_t ats_cap_base;
  uint32_t ats_ctrl_orig;
  uint32_t rmecda_ctl1_orig;
  uint32_t rmecda_ctl3_orig;
  uint32_t rmecda_ctl4_orig;
  uint32_t endpoint_rid;
  uint32_t ats_enabled;
  uint32_t root_cda_configured;
  uint32_t root_rid_saved;
  uint32_t smmu_enabled;
  uint32_t pgt_created;
  uint32_t ns_gpt_set;
  uint32_t realm_gpt_set;
  uint32_t ns_dpt_set;
  uint32_t realm_dpt_set;
  uint32_t result;
  uint32_t status;

  if (device == NULL)
    return ACS_STATUS_ERR;

  val_memory_set(&link, sizeof(link), 0);
  val_memory_set(&dpt_cfg_state, sizeof(dpt_cfg_state), 0);
  val_memory_set(&master, sizeof(master), 0);
  val_memory_set(&pgt_desc, sizeof(pgt_desc), 0);
  master.smmu_index = ACS_INVALID_INDEX;

  buffer = NULL;
  ats_enabled = 0u;
  root_cda_configured = 0u;
  root_rid_saved = 0u;
  smmu_enabled = 0u;
  pgt_created = 0u;
  ns_gpt_set = 0u;
  realm_gpt_set = 0u;
  ns_dpt_set = 0u;
  realm_dpt_set = 0u;
  result = ACS_STATUS_FAIL;

  page_size = val_memory_page_size();
  if (page_size == 0u)
    return ACS_STATUS_ERR;

  /* Discover the Realm SMMU context that services this endpoint. */
  status = prepare_smmu_master(device->endpoint_bdf, &master);
  if (status != ACS_STATUS_PASS)
    return status;
  smmu_enabled = 1u;

  status = check_smmu_xt_support(master.smmu_index);
  if (status != ACS_STATUS_PASS)
  {
    result = status;
    goto cleanup;
  }

  /* Save the endpoint ATS control so cleanup can restore platform state. */
  status = val_pcie_enable_ats(device->endpoint_bdf,
                               &ats_cap_base,
                               &ats_ctrl_orig);
  if (status != ACS_STATUS_PASS)
  {
    result = status;
    goto cleanup;
  }
  ats_enabled = 1u;

  if ((val_pcie_read_rmecda_ctl1(device->root_bdf, &rmecda_ctl1_orig) != PCIE_SUCCESS) ||
      (val_pcie_map_root_config(device->root_bdf, &rmecda_cfg_va) != ACS_STATUS_PASS))
  {
    result = ACS_STATUS_ERR;
    goto cleanup;
  }

  if ((val_memory_read_el3(rmecda_cfg_va + device->rmecda_cap_base +
                           RMECDA_CTL3_OFFSET,
                           &rmecda_ctl3_orig) != ACS_STATUS_PASS) ||
      (val_memory_read_el3(rmecda_cfg_va + device->rmecda_cap_base +
                           RMECDA_CTL4_OFFSET,
                           &rmecda_ctl4_orig) != ACS_STATUS_PASS))
  {
    result = ACS_STATUS_ERR;
    goto cleanup;
  }
  root_rid_saved = 1u;

  endpoint_rid = (uint32_t)PCIE_CREATE_BDF_PACKED(device->endpoint_bdf);

  /* Allow this endpoint RID to send Realm requests through the root port. */
  status = val_cda_program_rid_range(rmecda_cfg_va,
                                     device->rmecda_cap_base,
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

  /* Permit Realm device-to-host requests over the protected link. */
  if (val_cda_set_link_stream_lock(rmecda_cfg_va,
                                   device->rmecda_cap_base,
                                   rmecda_ctl1_orig | RMECDA_CTL1_TDISP_EN_MASK,
                                   1u) != ACS_STATUS_PASS)
  {
    result = ACS_STATUS_ERR;
    goto cleanup;
  }
  root_cda_configured = 1u;

  buffer = (uint8_t *)val_memory_alloc_pages(2u);
  if (buffer == NULL)
  {
    result = ACS_STATUS_SKIP;
    goto cleanup;
  }

  buffer_pa = (uint64_t)val_memory_virt_to_phys(buffer);
  if (buffer_pa == 0u)
  {
    result = ACS_STATUS_ERR;
    goto cleanup;
  }

  ns_pa = buffer_pa;
  realm_pa = buffer_pa + page_size;

  /* Keep input addresses distinct from both output pages. */
  ns_iova = buffer_pa + (4u * page_size);
  realm_iova = buffer_pa + (5u * page_size);
  max_pa = (ns_pa > realm_pa) ? ns_pa : realm_pa;

  /*
   * Keep GPC policy independent of this test. The stage-2 descriptors below,
   * rather than the GPT entries, select the translated PA space reported by TE.
   */
  if (val_add_gpt_entry_el3(ns_pa, GPT_ANY) != 0u)
  {
    result = ACS_STATUS_ERR;
    goto cleanup;
  }
  ns_gpt_set = 1u;

  if (val_add_gpt_entry_el3(realm_pa, GPT_ANY) != 0u)
  {
    result = ACS_STATUS_ERR;
    goto cleanup;
  }
  realm_gpt_set = 1u;

  /* Make the new PA-space assignments visible to subsequent SMMU walks. */
  if (val_smmu_gpt_invalidate_el3(&master) != 0u)
  {
    result = ACS_STATUS_ERR;
    goto cleanup;
  }

  status = val_smmu_configure_dpt_coverage(master.smmu_index,
                                           max_pa,
                                           &dpt_cfg_state);
  if (status != ACS_STATUS_PASS)
  {
    result = status;
    goto cleanup;
  }

  /* Permit the first Realm translation to resolve into Non-secure PAS. */
  if (val_dpt_add_entry(ns_pa,
                        (((uint64_t)master.smmu_index << 32) |
                         DPT_RDWR_NS_ACCESS_ENTRY)) != 0u)
  {
    result = ACS_STATUS_ERR;
    goto cleanup;
  }
  ns_dpt_set = 1u;

  if (val_dpt_invalidate_all(master.smmu_index) != 0u)
  {
    result = ACS_STATUS_ERR;
    goto cleanup;
  }

  /* Install both IOVA mappings into the endpoint's Realm stage-2 context. */
  status = install_pas_mappings(&master,
                                ns_iova,
                                ns_pa,
                                realm_iova,
                                realm_pa,
                                page_size,
                                &pgt_desc);
  if (status != ACS_STATUS_PASS)
  {
    result = status;
    goto cleanup;
  }
  pgt_created = 1u;

  /* Enter TDISP RUN and establish IDE before emitting Realm traffic. */
  status = start_realm_link(device, &link);
  if (status != ACS_STATUS_PASS)
  {
    result = status;
    goto cleanup;
  }

  /* A Realm stream resolving to Non-secure PA must return TE clear. */
  status = check_translation(device->endpoint_bdf,
                             ns_iova,
                             ns_pa,
                             0u,
                             page_size);
  if (status != ACS_STATUS_PASS)
  {
    result = status;
    goto cleanup;
  }

  /*
   * DPT mappings can cover more than one page. Reprogram the target region
   * between requests so this subcase does not depend on DPT granularity.
   */
  if ((val_dpt_add_entry(realm_pa,
                         (((uint64_t)master.smmu_index << 32) |
                          DPT_RDWR_ACCESS_ENTRY)) != 0u) ||
      (val_dpt_invalidate_all(master.smmu_index) != 0u))
  {
    result = ACS_STATUS_ERR;
    goto cleanup;
  }
  realm_dpt_set = 1u;

  /* The same Realm stream resolving to Realm PA must return TE set. */
  status = check_translation(device->endpoint_bdf,
                             realm_iova,
                             realm_pa,
                             1u,
                             page_size);
  if (status != ACS_STATUS_PASS)
  {
    result = status;
    goto cleanup;
  }

  result = ACS_STATUS_PASS;

cleanup:
  /* Do not leave Realm ATS attributes or a cached translation in the endpoint. */
  (void)val_exerciser_set_param_by_bdf(EXERCISER_ATS_REQUEST_ATTRIBUTES,
                                       0u,
                                       0u,
                                       device->endpoint_bdf);
  (void)val_exerciser_ops_by_bdf(ATS_INV_CACHE, 0u, device->endpoint_bdf);

  if (stop_realm_link(device, &link) != ACS_STATUS_PASS)
    result = ACS_STATUS_FAIL;

  /* Restore permissive DPT entries before returning ownership of the pages. */
  if ((ns_dpt_set != 0u) || (realm_dpt_set != 0u))
  {
    if (ns_dpt_set != 0u)
      (void)val_dpt_add_entry(ns_pa,
                              (((uint64_t)master.smmu_index << 32) |
                               DPT_RDWR_ACCESS_ENTRY));
    if (realm_dpt_set != 0u)
      (void)val_dpt_add_entry(realm_pa,
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

  if ((realm_gpt_set != 0u) && (val_add_gpt_entry_el3(realm_pa, GPT_ANY) != 0u))
    result = ACS_STATUS_FAIL;
  if ((ns_gpt_set != 0u) && (val_add_gpt_entry_el3(ns_pa, GPT_ANY) != 0u))
    result = ACS_STATUS_FAIL;

  if (buffer != NULL)
    val_memory_free_pages(buffer, 2u);

  if (ats_enabled != 0u)
    val_pcie_write_cfg(device->endpoint_bdf,
                       ats_cap_base + ATS_CTRL,
                       ats_ctrl_orig);

  /* Restore root-port CDA controls and the original permitted RID range. */
  if (root_cda_configured != 0u)
  {
    if (val_cda_set_link_stream_lock(
          rmecda_cfg_va,
          device->rmecda_cap_base,
          rmecda_ctl1_orig,
          (rmecda_ctl1_orig & RMECDA_CTL1_LINK_LOCK_MASK) != 0u) != ACS_STATUS_PASS)
      result = ACS_STATUS_FAIL;
  }

  if (root_rid_saved != 0u)
  {
    if (val_cda_program_rid_range(rmecda_cfg_va,
                                  device->rmecda_cap_base,
                                  rmecda_ctl3_orig,
                                  rmecda_ctl4_orig,
                                  (rmecda_ctl4_orig >> 8) & 0xFFFFu,
                                  (rmecda_ctl3_orig >> 8) & 0xFFFFu,
                                  rmecda_ctl4_orig & 0x1u) != ACS_STATUS_PASS)
      result = ACS_STATUS_FAIL;
  }

  return result;
}

static void
payload(void)
{
  RYJVJR_DEVICE_CONTEXT device;
  uint32_t pe_index;
  uint32_t status;

  pe_index = val_pe_get_index_mpid(val_pe_get_mpid());
  status = find_device_context(&device);
  if (status == ACS_STATUS_PASS)
    status = exercise_rule(&device);

  if (status == ACS_STATUS_PASS)
    val_set_status(pe_index, "PASS", 01);
  else if (status == ACS_STATUS_SKIP)
    val_set_status(pe_index, "SKIP", 01);
  else
    val_set_status(pe_index, "FAIL", 01);
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
cda_ryjvjr_ats_te_pas_entry(uint32_t num_pe)
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
