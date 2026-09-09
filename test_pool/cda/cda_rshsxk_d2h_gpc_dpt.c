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
#include "val/include/val_pcie_spec.h"
#include "val/include/val_pe.h"
#include "val/include/val_pgt.h"
#include "val/include/val_smmu.h"
#include "val/include/val_spdm.h"
#include "val/include/val_tdisp.h"

#define TEST_NAME "cda_rshsxk_d2h_gpc_dpt"
#define TEST_DESC "Host enforces GPC and DPT on Realm D2H requests"
#define TEST_RULE "RSHSXK"

#define RMECDA_CTL1_TDISP_EN_MASK  0x1u
#define RMECDA_CTL1_LINK_LOCK_MASK (1u << 1)

#define RSHSXK_SRC_PATTERN 0xA5u
#define RSHSXK_DST_PATTERN 0x5Au

#define SEC_SID_NONSECURE 0x0u
#define SEC_SID_REALM     0x2u

#if ENABLE_SPDM

/*
 * Test outline:
 *  1. Put a CHI-C2C TDI in RUN with IDE active and admit its RID at the RP.
 *  2. Allocate HCM pages outside DCM and establish identity SMMU mappings.
 *  3. Prove a permitted Realm device-to-host transfer completes.
 *  4. Change only the destination GPT entry and prove GPC blocks the write.
 *  5. Supply Realm SEC_SID, then change only DPT permission and prove DPT
 *     blocks the write. Sentinel data detects any partial or silent write.
 *
 * Each negative check first runs the corresponding permitted path. This
 * separates a policy denial from an unusable DMA or link configuration.
 */

typedef struct {
  uint32_t root_index;
  uint32_t endpoint_index;
  uint32_t root_bdf;
  uint32_t endpoint_bdf;
  uint32_t rmecda_cap_base;
} RSHSXK_DEVICE_CONTEXT;

typedef struct {
  val_spdm_context_t spdm_ctx;
  pci_tdisp_interface_id_t interface_id;
  uint32_t session_id;
  uint32_t session_active;
  uint32_t ide_active;
} RSHSXK_LINK_CONTEXT;

static uint32_t
find_device_context(RSHSXK_DEVICE_CONTEXT *context)
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
   * Select a complete CDA path, not merely a capable endpoint: the upstream
   * RP must expose RME-CDA and both ends must advertise CHI-C2C support.
   */
  for (uint32_t index = 0u; index < table->num_entries; ++index)
  {
    const CXL_COMPONENT_ENTRY *root_port = &table->component[index];
    const CXL_COMPONENT_ENTRY *endpoint;
    uint32_t endpoint_bdf;
    uint32_t endpoint_index;
    uint32_t capability_offset;

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
start_realm_link(const RSHSXK_DEVICE_CONTEXT *device,
                 RSHSXK_LINK_CONTEXT *link)
{
  uint32_t status;

  if ((device == NULL) || (link == NULL))
    return ACS_STATUS_ERR;

  val_memory_set(link, sizeof(*link), 0);

  /* TDISP RUN establishes the TDI security state used by D2H requests. */
  status = val_tdisp_establish_run(device->endpoint_bdf,
                                   &link->spdm_ctx,
                                   &link->session_id,
                                   &link->interface_id);
  if (status != ACS_STATUS_PASS)
    return status;
  link->session_active = 1u;

  /* The protected link must be active before Realm traffic is generated. */
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
stop_realm_link(const RSHSXK_DEVICE_CONTEXT *device,
                RSHSXK_LINK_CONTEXT *link)
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
verify_hcm_range(uint64_t base, uint64_t size)
{
  uint32_t host_count;

  host_count = (uint32_t)val_cxl_get_info(CXL_INFO_NUM_DEVICES, 0u);
  if (host_count == 0u)
    return ACS_STATUS_SKIP;

  /*
   * RSHSXK allows the host to omit these checks for the originating device's
   * DCM. Keep the target outside every advertised CFMWS so that exemption
   * cannot account for an accepted request.
   */
  for (uint32_t host = 0u; host < host_count; ++host)
  {
    uint32_t count = val_cxl_get_cfmws_count(host);

    for (uint32_t index = 0u; index < count; ++index)
    {
      uint64_t window_base;
      uint64_t window_size;

      if (val_cxl_get_cfmws(host, index, &window_base, &window_size) != 0u)
        return ACS_STATUS_ERR;

      if (range_overlaps(base, size, window_base, window_size) != 0u)
      {
        val_print(ACS_PRINT_INFO,
                  " RSHSXK: DMA buffer overlaps a DCM window",
                  0);
        return ACS_STATUS_SKIP;
      }
    }
  }

  return ACS_STATUS_PASS;
}

static uint32_t
configure_smmu_maps(uint32_t endpoint_bdf,
                    uint64_t buffer_pa,
                    uint32_t total_size,
                    smmu_master_attributes_t *master,
                    pgt_descriptor_t *ns_pgt,
                    pgt_descriptor_t *realm_pgt)
{
  memory_region_descriptor_t mem_desc[2];
  uint32_t device_id;
  uint32_t its_id;
  uint32_t smmu_index;

  if ((buffer_pa == 0u) || (total_size == 0u) || (master == NULL) ||
      (ns_pgt == NULL) || (realm_pgt == NULL))
    return ACS_STATUS_ERR;

  val_memory_set(master, sizeof(*master), 0);
  val_memory_set(ns_pgt, sizeof(*ns_pgt), 0);
  val_memory_set(realm_pgt, sizeof(*realm_pgt), 0);
  val_memory_set(mem_desc, sizeof(mem_desc), 0);
  master->smmu_index = ACS_INVALID_INDEX;

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

  master->smmu_index = smmu_index;
  if (val_smmu_enable(smmu_index) != 0u)
    return ACS_STATUS_ERR;

  /*
   * Use identity mappings so the PA programmed into the exerciser is also the
   * final output PA checked by GPC and DPT. The stage-1 context supports the
   * ordinary stream and the Realm stage-2 context supports Realm SEC_SID.
   */
  mem_desc[0].virtual_address = buffer_pa;
  mem_desc[0].physical_address = buffer_pa;
  mem_desc[0].length = total_size;

  ns_pgt->ias = (uint32_t)val_smmu_get_info(SMMU_IN_ADDR_SIZE, smmu_index);
  ns_pgt->oas = (uint32_t)val_smmu_get_info(SMMU_OUT_ADDR_SIZE, smmu_index);
  if ((ns_pgt->ias == 0u) || (ns_pgt->oas == 0u))
    return ACS_STATUS_SKIP;

  if (val_pe_reg_read_tcr(0u, &ns_pgt->tcr) != 0u)
    return ACS_STATUS_ERR;

  ns_pgt->mair = val_pe_reg_read(MAIR_ELx);
  ns_pgt->stage = PGT_STAGE1;
  mem_desc[0].attributes = PGT_STAGE1_AP_RW;
  if (val_pgt_create(mem_desc, ns_pgt) != 0u)
    return ACS_STATUS_ERR;

  master->stage2 = 0u;
  if (val_smmu_map(*master, *ns_pgt) != 0u)
    return ACS_STATUS_ERR;

  realm_pgt->ias = ns_pgt->ias;
  realm_pgt->oas = ns_pgt->oas;
  realm_pgt->stage = PGT_STAGE2;
  if (val_pe_get_vtcr(&realm_pgt->vtcr) != 0u)
    return ACS_STATUS_ERR;

  mem_desc[0].attributes = PGT_STAGE2_AP_RW;
  if ((val_memory_map_el3_data((uint64_t)mem_desc,
                               sizeof(mem_desc),
                               NONSECURE_PAS) != ACS_STATUS_PASS) ||
      (val_memory_map_el3_data((uint64_t)realm_pgt,
                               sizeof(*realm_pgt),
                               NONSECURE_PAS) != ACS_STATUS_PASS) ||
      (val_memory_map_el3_data((uint64_t)master,
                               sizeof(*master),
                               NONSECURE_PAS) != ACS_STATUS_PASS))
    return ACS_STATUS_ERR;

  if (val_rlm_pgt_create(mem_desc, realm_pgt) != 0u)
    return ACS_STATUS_ERR;

  val_pe_reg_write(VTTBR, realm_pgt->pgt_base);
  master->stage2 = 1u;
  if (val_smmu_rlm_map_el3(master, realm_pgt) != 0u)
    return ACS_STATUS_ERR;

  val_print(ACS_PRINT_DEBUG, " RSHSXK: SMMU index %u", (uint64_t)smmu_index);
  val_print(ACS_PRINT_DEBUG, " RSHSXK: StreamID 0x%x", master->streamid);
  return ACS_STATUS_PASS;
}

static uint32_t
set_dpt_access(uint64_t pa, uint32_t smmu_index, uint32_t access)
{
  /* VAL packs the target SMMU index above the DPT descriptor attributes. */
  if (val_dpt_add_entry(pa,
                        (((uint64_t)smmu_index << 32) | access)) != 0u)
    return ACS_STATUS_ERR;

  return (val_dpt_invalidate_all(smmu_index) == 0u) ?
         ACS_STATUS_PASS : ACS_STATUS_ERR;
}

static uint32_t
start_dma(uint32_t endpoint_bdf,
          uint64_t address,
          uint32_t length,
          uint32_t direction)
{
  uint32_t status;

  /*
   * The rule applies to requests that already specify a PA. Program this for
   * every DMA so each generated request carries the required address type.
   */
  if (val_exerciser_set_param_by_bdf(CFG_TXN_ATTRIBUTES,
                                     TXN_ADDR_TYPE,
                                     AT_TRANSLATED,
                                     endpoint_bdf) != 0u)
    return ACS_STATUS_ERR;

  if (val_exerciser_set_param_by_bdf(DMA_ATTRIBUTES,
                                     address,
                                     length,
                                     endpoint_bdf) != 0u)
    return ACS_STATUS_ERR;

  status = val_exerciser_ops_by_bdf(START_DMA, direction, endpoint_bdf);
  val_print(ACS_PRINT_DEBUG, " RSHSXK: DMA direction %u", (uint64_t)direction);
  val_print(ACS_PRINT_DEBUG, " RSHSXK: DMA status 0x%x", (uint64_t)status);
  return (status == 0u) ? ACS_STATUS_PASS : ACS_STATUS_FAIL;
}

static uint32_t
exercise_rule(const RSHSXK_DEVICE_CONTEXT *device)
{
  RSHSXK_LINK_CONTEXT link;
  VAL_SMMU_DPT_CFG_STATE dpt_state;
  smmu_master_attributes_t master;
  pgt_descriptor_t ns_pgt;
  pgt_descriptor_t realm_pgt;
  uint8_t *buffer;
  uint8_t *source;
  uint8_t *destination;
  uint64_t buffer_pa;
  uint64_t source_pa;
  uint64_t destination_pa;
  uint64_t rmecda_cfg_va;
  uint32_t rmecda_ctl1_orig;
  uint32_t rmecda_ctl3_orig;
  uint32_t rmecda_ctl4_orig;
  uint32_t endpoint_rid;
  uint32_t page_size;
  uint32_t total_size;
  uint32_t root_state_saved;
  uint32_t source_gpt_set;
  uint32_t destination_gpt_set;
  uint32_t dpt_entries_set;
  uint32_t sec_sid_programmed;
  uint32_t source_dma_status;
  uint32_t status;
  uint32_t dma_status;
  uint32_t result;

  if (device == NULL)
    return ACS_STATUS_ERR;

  val_memory_set(&link, sizeof(link), 0);
  val_memory_set(&dpt_state, sizeof(dpt_state), 0);
  val_memory_set(&master, sizeof(master), 0);
  val_memory_set(&ns_pgt, sizeof(ns_pgt), 0);
  val_memory_set(&realm_pgt, sizeof(realm_pgt), 0);
  master.smmu_index = ACS_INVALID_INDEX;
  buffer = NULL;
  source = NULL;
  destination = NULL;
  buffer_pa = 0u;
  source_pa = 0u;
  destination_pa = 0u;
  rmecda_cfg_va = 0u;
  root_state_saved = 0u;
  source_gpt_set = 0u;
  destination_gpt_set = 0u;
  dpt_entries_set = 0u;
  sec_sid_programmed = 0u;
  source_dma_status = ACS_STATUS_ERR;
  result = ACS_STATUS_FAIL;

  page_size = val_memory_page_size();
  if ((page_size == 0u) || (page_size > (0xFFFFFFFFu / 2u)))
    return ACS_STATUS_ERR;
  total_size = page_size * 2u;

  if (val_pcie_map_root_config(device->root_bdf, &rmecda_cfg_va)
      != ACS_STATUS_PASS)
    return ACS_STATUS_ERR;

  if ((val_memory_read_el3(rmecda_cfg_va + device->rmecda_cap_base +
                           RMECDA_CTL1_OFFSET,
                           &rmecda_ctl1_orig) != ACS_STATUS_PASS) ||
      (val_memory_read_el3(rmecda_cfg_va + device->rmecda_cap_base +
                           RMECDA_CTL3_OFFSET,
                           &rmecda_ctl3_orig) != ACS_STATUS_PASS) ||
      (val_memory_read_el3(rmecda_cfg_va + device->rmecda_cap_base +
                           RMECDA_CTL4_OFFSET,
                           &rmecda_ctl4_orig) != ACS_STATUS_PASS))
    return ACS_STATUS_ERR;
  root_state_saved = 1u;

  /*
   * Unlock before changing the RID range, admit only the selected endpoint,
   * then enable TDISP enforcement and lock the programmed stream policy.
   */
  if (val_cda_set_link_stream_lock(rmecda_cfg_va,
                                   device->rmecda_cap_base,
                                   rmecda_ctl1_orig,
                                   0u) != ACS_STATUS_PASS)
  {
    result = ACS_STATUS_ERR;
    goto cleanup;
  }

  endpoint_rid = (uint32_t)PCIE_CREATE_BDF_PACKED(device->endpoint_bdf);
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

  if (val_cda_set_link_stream_lock(rmecda_cfg_va,
                                   device->rmecda_cap_base,
                                   rmecda_ctl1_orig |
                                   RMECDA_CTL1_TDISP_EN_MASK,
                                   1u) != ACS_STATUS_PASS)
  {
    result = ACS_STATUS_ERR;
    goto cleanup;
  }

  status = start_realm_link(device, &link);
  if (status != ACS_STATUS_PASS)
  {
    result = status;
    goto cleanup;
  }
  /* Separate pages let the test detect a D2H write without using device RAM. */
  buffer = (uint8_t *)val_get_free_va(total_size);
  if ((buffer == NULL) || ((uint64_t)buffer == 1u))
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

  source = buffer;
  destination = buffer + page_size;
  source_pa = buffer_pa;
  destination_pa = buffer_pa + page_size;

  val_print(ACS_PRINT_INFO, " RSHSXK: CHI-C2C RP 0x%x",
            (uint64_t)device->root_bdf);
  val_print(ACS_PRINT_INFO, " RSHSXK: CHI-C2C EP 0x%x",
            (uint64_t)device->endpoint_bdf);
  val_print(ACS_PRINT_DEBUG, " RSHSXK: HCM source PA 0x%llx", source_pa);
  val_print(ACS_PRINT_DEBUG, " RSHSXK: HCM destination PA 0x%llx",
            destination_pa);

  status = verify_hcm_range(buffer_pa, total_size);
  if (status != ACS_STATUS_PASS)
  {
    result = status;
    goto cleanup;
  }

  status = configure_smmu_maps(device->endpoint_bdf,
                               buffer_pa,
                               total_size,
                               &master,
                               &ns_pgt,
                               &realm_pgt);
  if (status != ACS_STATUS_PASS)
  {
    result = status;
    goto cleanup;
  }

  /* Establish the fully permitted Realm baseline used by the first control. */
  if (val_add_gpt_entry_el3(source_pa, GPT_REALM) != 0u)
  {
    result = ACS_STATUS_ERR;
    goto cleanup;
  }
  source_gpt_set = 1u;

  if (val_add_gpt_entry_el3(destination_pa, GPT_REALM) != 0u)
  {
    result = ACS_STATUS_ERR;
    goto cleanup;
  }
  destination_gpt_set = 1u;

  if (val_smmu_gpt_invalidate_el3(&master) != 0u)
  {
    result = ACS_STATUS_ERR;
    goto cleanup;
  }

  /* Ensure the Realm DPT covers the selected HCM addresses before use. */
  status = val_smmu_configure_dpt_coverage(master.smmu_index,
                                           destination_pa,
                                           &dpt_state);
  if (status != ACS_STATUS_PASS)
  {
    result = status;
    goto cleanup;
  }

  if ((set_dpt_access(source_pa,
                      master.smmu_index,
                      DPT_RDWR_ACCESS_ENTRY) != ACS_STATUS_PASS) ||
      (set_dpt_access(destination_pa,
                      master.smmu_index,
                      DPT_RDWR_ACCESS_ENTRY) != ACS_STATUS_PASS))
  {
    result = ACS_STATUS_ERR;
    goto cleanup;
  }
  dpt_entries_set = 1u;

  if (val_memory_map_dma_buffers_el3(buffer,
                                     buffer_pa,
                                     page_size,
                                     REALM_PAS) != ACS_STATUS_PASS)
  {
    result = ACS_STATUS_ERR;
    goto cleanup;
  }

  /* Use the endpoint's natural RID, which the host port converts to StreamID. */
  if (val_exerciser_set_param_by_bdf(CFG_TXN_ATTRIBUTES,
                                     TXN_REQ_ID_VALID,
                                     RID_NOT_VALID,
                                     device->endpoint_bdf) != 0u)
  {
    result = ACS_STATUS_SKIP;
    goto cleanup;
  }

  /*
   * Load the exerciser through the generic source-buffer DMA contract. The
   * checks below observe only writes to HCM and do not depend on the
   * exerciser's internal storage implementation.
   */
  if (val_memory_prepare_dma_buffers_el3(source,
                                         destination,
                                         page_size,
                                         RSHSXK_SRC_PATTERN,
                                         RSHSXK_DST_PATTERN) != ACS_STATUS_PASS ||
      start_dma(device->endpoint_bdf,
                source_pa,
                page_size,
                EDMA_TO_DEVICE) != ACS_STATUS_PASS)
  {
    val_print(ACS_PRINT_ERR, " RSHSXK: source DMA failed", 0);
    result = ACS_STATUS_FAIL;
    goto cleanup;
  }

  /*
   * Positive control: copy the device-held source data back to HCM. A match
   * proves the link, SMMU mappings, GPT state, and DPT permissions are usable.
   */
  if (start_dma(device->endpoint_bdf,
                destination_pa,
                page_size,
                EDMA_FROM_DEVICE) != ACS_STATUS_PASS ||
      val_memory_compare_el3((uint64_t)source,
                             (uint64_t)destination,
                             page_size) != 0u)
  {
    val_print(ACS_PRINT_ERR, " RSHSXK: permitted Realm D2H DMA failed", 0);
    result = ACS_STATUS_FAIL;
    goto cleanup;
  }
  val_print(ACS_PRINT_INFO, " RSHSXK: permitted Realm D2H DMA completed", 0);

  /*
   * GPC negative: retain Realm translation and DPT permission, but classify
   * the destination PA as Non-secure in GPT. A Realm request must be blocked
   * and must not modify any byte of the destination sentinel.
   */
  if (val_memory_set_el3(destination, page_size, RSHSXK_DST_PATTERN) != 0u ||
      val_add_gpt_entry_el3(destination_pa, GPT_NONSECURE) != 0u ||
      val_smmu_gpt_invalidate_el3(&master) != 0u)
  {
    result = ACS_STATUS_ERR;
    goto cleanup;
  }

  dma_status = start_dma(device->endpoint_bdf,
                         destination_pa,
                         page_size,
                         EDMA_FROM_DEVICE);

  /* Restore Realm access before EL3 examines the protected destination. */
  if (val_add_gpt_entry_el3(destination_pa, GPT_REALM) != 0u ||
      val_smmu_gpt_invalidate_el3(&master) != 0u)
  {
    result = ACS_STATUS_ERR;
    goto cleanup;
  }

  if (dma_status == ACS_STATUS_ERR)
  {
    result = ACS_STATUS_ERR;
    goto cleanup;
  }

  status = val_memory_has_byte_pattern_el3((uint64_t)destination,
                                           page_size,
                                           RSHSXK_DST_PATTERN);
  if (status != ACS_STATUS_PASS)
  {
    val_print(ACS_PRINT_ERR, " RSHSXK: GPC-denied D2H DMA modified HCM", 0);
    result = (status == ACS_STATUS_ERR) ? ACS_STATUS_ERR : ACS_STATUS_FAIL;
    goto cleanup;
  }
  val_print(ACS_PRINT_INFO, " RSHSXK: GPC denied Realm D2H DMA, status %u",
            (uint64_t)dma_status);

  /*
   * DPT positive control: explicitly supply Realm SEC_SID. The translated
   * request resolves into Non-secure PA space, so GPT is Non-secure and DPT
   * AC selects Non-secure output. Reloading the device makes this phase
   * independent of the rejected GPC request above.
   */
  val_pcie_clear_device_status_error(device->endpoint_bdf);
  if ((set_dpt_access(source_pa,
                      master.smmu_index,
                      DPT_RDWR_NS_ACCESS_ENTRY) != ACS_STATUS_PASS) ||
      (set_dpt_access(destination_pa,
                      master.smmu_index,
                      DPT_RDWR_NS_ACCESS_ENTRY) != ACS_STATUS_PASS))
  {
    result = ACS_STATUS_ERR;
    goto cleanup;
  }

  if (val_exerciser_set_param_by_bdf(EXERCISER_SEC_SID,
                                     SEC_SID_REALM,
                                     0u,
                                     device->endpoint_bdf) != 0u)
  {
    result = ACS_STATUS_SKIP;
    goto cleanup;
  }
  sec_sid_programmed = 1u;

  if (val_memory_prepare_dma_buffers_el3(source,
                                         destination,
                                         page_size,
                                         RSHSXK_SRC_PATTERN,
                                         RSHSXK_DST_PATTERN) != ACS_STATUS_PASS ||
      val_add_gpt_entry_el3(source_pa, GPT_NONSECURE) != 0u ||
      val_add_gpt_entry_el3(destination_pa, GPT_NONSECURE) != 0u ||
      val_smmu_gpt_invalidate_el3(&master) != 0u)
  {
    result = ACS_STATUS_ERR;
    goto cleanup;
  }

  /* Both pages are permitted here; this must complete before permission deny. */
  source_dma_status = start_dma(device->endpoint_bdf,
                                source_pa,
                                page_size,
                                EDMA_TO_DEVICE);
  dma_status = start_dma(device->endpoint_bdf,
                         destination_pa,
                         page_size,
                         EDMA_FROM_DEVICE);

  /* EL3 compares the buffers only after restoring their Realm GPT ownership. */
  if (val_add_gpt_entry_el3(source_pa, GPT_REALM) != 0u ||
      val_add_gpt_entry_el3(destination_pa, GPT_REALM) != 0u ||
      val_smmu_gpt_invalidate_el3(&master) != 0u)
  {
    result = ACS_STATUS_ERR;
    goto cleanup;
  }

  if ((source_dma_status != ACS_STATUS_PASS) ||
      (dma_status != ACS_STATUS_PASS) ||
      (val_memory_compare_el3((uint64_t)source,
                              (uint64_t)destination,
                              page_size) != 0u))
  {
    val_print(ACS_PRINT_ERR, " RSHSXK: permitted Realm SEC_SID DMA failed", 0);
    result = ACS_STATUS_FAIL;
    goto cleanup;
  }
  val_print(ACS_PRINT_INFO, " RSHSXK: permitted Realm SEC_SID DMA completed", 0);

  /*
   * DPT negative: use the same matching Non-secure GPT state and remove only
   * the destination's DPT permission. The unchanged sentinel proves the host
   * DPT check suppressed the device-to-host write.
   */
  if (val_memory_set_el3(destination, page_size, RSHSXK_DST_PATTERN) != 0u ||
      val_add_gpt_entry_el3(destination_pa, GPT_NONSECURE) != 0u ||
      val_smmu_gpt_invalidate_el3(&master) != 0u ||
      set_dpt_access(destination_pa,
                     master.smmu_index,
                     DPT_NO_ACCESS_ENTRY) != ACS_STATUS_PASS)
  {
    result = ACS_STATUS_ERR;
    goto cleanup;
  }

  dma_status = start_dma(device->endpoint_bdf,
                         destination_pa,
                         page_size,
                         EDMA_FROM_DEVICE);

  /* Restore policy before observing data and before entering common cleanup. */
  if ((set_dpt_access(destination_pa,
                      master.smmu_index,
                      DPT_RDWR_ACCESS_ENTRY) != ACS_STATUS_PASS) ||
      (val_add_gpt_entry_el3(destination_pa, GPT_REALM) != 0u) ||
      (val_smmu_gpt_invalidate_el3(&master) != 0u))
  {
    result = ACS_STATUS_ERR;
    goto cleanup;
  }

  if (dma_status == ACS_STATUS_ERR)
  {
    result = ACS_STATUS_ERR;
    goto cleanup;
  }

  status = val_memory_has_byte_pattern_el3((uint64_t)destination,
                                           page_size,
                                           RSHSXK_DST_PATTERN);
  if (status != ACS_STATUS_PASS)
  {
    val_print(ACS_PRINT_ERR, " RSHSXK: DPT-denied D2H DMA modified HCM", 0);
    result = (status == ACS_STATUS_ERR) ? ACS_STATUS_ERR : ACS_STATUS_FAIL;
    goto cleanup;
  }
  val_print(ACS_PRINT_INFO, " RSHSXK: DPT denied Realm D2H DMA, status %u",
            (uint64_t)dma_status);
  result = ACS_STATUS_PASS;

cleanup:
  /*
   * Unwind in dependency order: request attributes and DPT/GPT policy first,
   * translation structures next, then the protected link and RP controls.
   * State flags make cleanup valid for every early-exit path above.
   */
  if ((sec_sid_programmed != 0u) &&
      (val_exerciser_set_param_by_bdf(EXERCISER_SEC_SID,
                                      SEC_SID_NONSECURE,
                                      0u,
                                      device->endpoint_bdf) != 0u))
    result = ACS_STATUS_FAIL;

  if ((dpt_entries_set != 0u) &&
      (master.smmu_index != ACS_INVALID_INDEX))
  {
    (void)val_dpt_add_entry(source_pa,
                            (((uint64_t)master.smmu_index << 32) |
                             DPT_RDWR_ACCESS_ENTRY));
    (void)val_dpt_add_entry(destination_pa,
                            (((uint64_t)master.smmu_index << 32) |
                             DPT_RDWR_ACCESS_ENTRY));
    (void)val_dpt_invalidate_all(master.smmu_index);
  }

  if (val_smmu_restore_dpt_coverage(&dpt_state) != ACS_STATUS_PASS)
    result = ACS_STATUS_FAIL;

  if ((source_gpt_set != 0u) && (val_add_gpt_entry_el3(source_pa, GPT_ANY) != 0u))
    result = ACS_STATUS_FAIL;
  if ((destination_gpt_set != 0u) &&
      (val_add_gpt_entry_el3(destination_pa, GPT_ANY) != 0u))
    result = ACS_STATUS_FAIL;

  if (ns_pgt.pgt_base != 0u)
    (void)val_add_gpt_entry_el3(ns_pgt.pgt_base, GPT_ANY);
  if (realm_pgt.pgt_base != 0u)
    (void)val_add_gpt_entry_el3(realm_pgt.pgt_base, GPT_ANY);

  if (realm_pgt.pgt_base != 0u)
    val_rlm_pgt_destroy(&realm_pgt);
  if (ns_pgt.pgt_base != 0u)
    val_pgt_destroy(ns_pgt);
  if (master.smmu_index != ACS_INVALID_INDEX)
    (void)val_smmu_disable(master.smmu_index);

  if (stop_realm_link(device, &link) != ACS_STATUS_PASS)
    result = ACS_STATUS_FAIL;

  if (root_state_saved != 0u)
  {
    if ((val_cda_set_link_stream_lock(rmecda_cfg_va,
                                      device->rmecda_cap_base,
                                      rmecda_ctl1_orig,
                                      0u) != ACS_STATUS_PASS) ||
        (val_cda_program_rid_range(rmecda_cfg_va,
                                   device->rmecda_cap_base,
                                   rmecda_ctl3_orig,
                                   rmecda_ctl4_orig,
                                   (rmecda_ctl4_orig >> 8) & 0xFFFFu,
                                   (rmecda_ctl3_orig >> 8) & 0xFFFFu,
                                   rmecda_ctl4_orig & 0x1u) != ACS_STATUS_PASS) ||
        (val_cda_set_link_stream_lock(
           rmecda_cfg_va,
           device->rmecda_cap_base,
           rmecda_ctl1_orig,
           (rmecda_ctl1_orig & RMECDA_CTL1_LINK_LOCK_MASK) != 0u)
         != ACS_STATUS_PASS))
      result = ACS_STATUS_FAIL;
  }

  return result;
}

static void
payload(void)
{
  RSHSXK_DEVICE_CONTEXT device;
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
cda_rshsxk_d2h_gpc_dpt_entry(uint32_t num_pe)
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
