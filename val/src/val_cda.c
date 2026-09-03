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

#include "include/val.h"
#include "include/val_common.h"
#include "include/val_interface.h"
#include "include/val_cda.h"
#include "include/val_cxl.h"
#include "include/val_cxl_spec.h"
#include "include/val_el32.h"
#include "include/val_exerciser.h"
#include "include/val_iovirt.h"
#include "include/val_memory.h"
#include "include/val_pcie.h"
#include "include/val_pcie_spec.h"
#include "include/val_pe.h"
#include "include/val_pgt.h"
#include "include/val_smmu.h"
#include "include/val_tdisp.h"

#define RMECDA_CTL1_LINK_STR_LOCK_MASK  (1u << 1)
#define RMECDA_CTL1_TDISP_EN_MASK       0x1u
#define RMECDA_CTL3_RID_LIMIT_SHIFT       8u
#define RMECDA_CTL3_RID_LIMIT_MASK        (0xFFFFu << RMECDA_CTL3_RID_LIMIT_SHIFT)
#define RMECDA_CTL4_RID_BASE_SHIFT        8u
#define RMECDA_CTL4_RID_BASE_MASK         (0xFFFFu << RMECDA_CTL4_RID_BASE_SHIFT)
#define RMECDA_CTL4_RID_RANGE_VALID_MASK  0x1u
#define PGT_STAGE2_RME_NS_MASK            (1ull << 55)

/**
  @brief  Attempt an attributed, permission-checked TDI snoop request.

  @param  endpoint_bdf  Endpoint BDF identifying the originating TDI.
  @param  target_hpa    Target host physical address.
  @param  access_pas    NONSECURE_PAS or REALM_PAS.
  @param  result        Result flags returned by the platform hook. An emitted
                        request may additionally report the observed host response.

  @return ACS_STATUS_PASS when a valid result was returned.
          ACS_STATUS_SKIP when the platform hook is unavailable.
          ACS_STATUS_ERR for invalid arguments or malformed hook output.
**/
uint32_t
val_cda_tdi_snoop_attempt(uint32_t endpoint_bdf,
                          uint64_t target_hpa,
                          uint32_t access_pas,
                          uint32_t *result)
{
  uint32_t host_response;
  uint32_t pas_realm;

  if (result == NULL)
    return ACS_STATUS_ERR;

  if (access_pas == NONSECURE_PAS)
    pas_realm = 0u;
  else if (access_pas == REALM_PAS)
    pas_realm = 1u;
  else
    return ACS_STATUS_ERR;

  *result = 0u;
  if (pal_cda_tdi_snoop_attempt(endpoint_bdf,
                                target_hpa,
                                pas_realm,
                                result) != 0u)
    return ACS_STATUS_SKIP;

  if (((*result & CXL_SNOOP_RESULT_VALID) == 0u) ||
      (((*result & CXL_SNOOP_RESULT_EMITTED) != 0u) ==
       ((*result & CXL_SNOOP_RESULT_BLOCKED) != 0u)))
    return ACS_STATUS_ERR;

  host_response = *result & (CXL_SNOOP_RESULT_HOST_ACCEPTED |
                             CXL_SNOOP_RESULT_HOST_REJECTED);
  if ((host_response == (CXL_SNOOP_RESULT_HOST_ACCEPTED |
                         CXL_SNOOP_RESULT_HOST_REJECTED)) ||
      (((*result & CXL_SNOOP_RESULT_BLOCKED) != 0u) && (host_response != 0u)))
    return ACS_STATUS_ERR;

  return ACS_STATUS_PASS;
}

/**
  @brief  Seed a Realm Location and establish a clean coherent cache line.

  @param  target_hpa   Host physical address of the target DCM Location.
  @param  realm_alias  Cacheable Realm mapping of target_hpa.
  @param  value        Value used to initialize the target Location.

  @return ACS_STATUS_PASS when initialization and cache population complete.
**/
uint32_t
val_cda_seed_realm_cache_line(uint64_t target_hpa,
                              volatile uint64_t *realm_alias,
                              uint64_t value)
{
  volatile uint64_t *seed_alias;
  uint64_t observed;
  uint32_t observed_high;
  uint32_t observed_low;

  if ((target_hpa == 0u) || (realm_alias == NULL))
    return ACS_STATUS_ERR;

  /* Initialize backing DCM without creating dirty cache state. */
  seed_alias = NULL;
  if (val_memory_map_realm_noncacheable_alias(target_hpa, &seed_alias) !=
      ACS_STATUS_PASS)
    return ACS_STATUS_ERR;

  if ((val_memory_write_el3((uint64_t)seed_alias,
                            (uint32_t)value) != ACS_STATUS_PASS) ||
      (val_memory_write_el3((uint64_t)seed_alias + sizeof(uint32_t),
                            (uint32_t)(value >> 32)) != ACS_STATUS_PASS) ||
      (val_memory_read_el3((uint64_t)seed_alias,
                           &observed_low) != ACS_STATUS_PASS) ||
      (val_memory_read_el3((uint64_t)seed_alias + sizeof(uint32_t),
                           &observed_high) != ACS_STATUS_PASS))
    return ACS_STATUS_ERR;

  observed = ((uint64_t)observed_high << 32) | observed_low;
  if (observed != value)
  {
    val_print(ACS_PRINT_ERR,
              " CDA: Realm backing seed readback 0x%llx",
              observed);
    val_print(ACS_PRINT_ERR,
              " CDA: expected Realm backing value 0x%llx",
              value);
    return ACS_STATUS_ERR;
  }

  /* Read through the cacheable alias to establish a clean coherent line. */
  if ((val_memory_read_el3((uint64_t)realm_alias,
                           &observed_low) != ACS_STATUS_PASS) ||
      (val_memory_read_el3((uint64_t)realm_alias + sizeof(uint32_t),
                           &observed_high) != ACS_STATUS_PASS))
    return ACS_STATUS_ERR;

  observed = ((uint64_t)observed_high << 32) | observed_low;
  if (observed != value)
  {
    val_print(ACS_PRINT_ERR,
              " CDA: Realm cache-line fill readback 0x%llx",
              observed);
    val_print(ACS_PRINT_ERR,
              " CDA: expected Realm cache-line value 0x%llx",
              value);
    return ACS_STATUS_ERR;
  }

  /* Remove only the PE copy; the coherent target retains the clean line. */
  if (val_data_cache_ops_by_va_el3((uint64_t)realm_alias,
                                   CLEAN_AND_INVALIDATE) != 0u)
    return ACS_STATUS_ERR;

  return ACS_STATUS_PASS;
}

/**
  @brief  Configure identity stage-2 mappings for Realm and Non-secure DMA.

  @param  endpoint_bdf  Endpoint BDF identifying the SMMU master.
  @param  realm_base    Base IOVA and PA of the Realm DCM range.
  @param  realm_length  Length of the Realm DCM range.
  @param  ns_pa         IOVA and PA of one Non-secure verification page.
  @param  page_size     Size of the Non-secure verification page.
  @param  master        Returns the configured SMMU master attributes.
  @param  pgt_desc      Returns the created Realm page-table descriptor.

  @return ACS_STATUS_PASS when the mapping was installed, ACS_STATUS_SKIP when
          no suitable SMMUv3 path exists, or ACS_STATUS_ERR on setup failure.
**/
uint32_t
val_cda_prepare_realm_dma_mapping(uint32_t endpoint_bdf,
                                  uint64_t realm_base,
                                  uint64_t realm_length,
                                  uint64_t ns_pa,
                                  uint64_t page_size,
                                  smmu_master_attributes_t *master,
                                  pgt_descriptor_t *pgt_desc)
{
  memory_region_descriptor_t mem_desc[3];
  uint32_t device_id;
  uint32_t its_id;
  uint32_t smmu_index;

  if ((realm_base == 0u) || (realm_length == 0u) || (ns_pa == 0u) ||
      (page_size == 0u) || (master == NULL) || (pgt_desc == NULL))
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
  mem_desc[0].virtual_address = realm_base;
  mem_desc[0].physical_address = realm_base;
  mem_desc[0].length = realm_length;
  mem_desc[0].attributes = PGT_STAGE2_AP_RW;
  mem_desc[1].virtual_address = ns_pa;
  mem_desc[1].physical_address = ns_pa;
  mem_desc[1].length = page_size;
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
val_cda_cache_ats_translation(uint32_t endpoint_bdf,
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
    val_print(ACS_PRINT_ERR, " CDA: ATS PA 0x%llx", response.translated_pa);
    val_print(ACS_PRINT_ERR, " CDA: ATS TE %u", (uint64_t)response.te);
    val_print(ACS_PRINT_ERR,
              " CDA: ATS attributes 0x%x",
              (uint64_t)response.response_attributes);
    return ACS_STATUS_FAIL;
  }

  return ACS_STATUS_PASS;
}

/**
  @brief  Populate a Realm DCM line through the device coherent path.

  @param  endpoint_bdf  Endpoint BDF identifying the requesting TDI.
  @param  realm_alias   Cacheable Realm mapping of dcm_hpa.
  @param  dcm_hpa       Host physical address of the DCM Location.
  @param  verify_va     Non-secure verification buffer virtual address.
  @param  verify_pa     Physical address corresponding to verify_va.
  @param  seed_value    Value used to initialize and verify the DCM Location.
  @param  page_size     Translation granule used for ATS requests.

  @return ACS_STATUS_PASS when the line was fetched and verified.
**/
uint32_t
val_cda_populate_realm_device_cache_line(uint32_t endpoint_bdf,
                                         volatile uint64_t *realm_alias,
                                         uint64_t dcm_hpa,
                                         uint8_t *verify_va,
                                         uint64_t verify_pa,
                                         uint64_t seed_value,
                                         uint32_t page_size)
{
  uint64_t observed;
  uint32_t dma_length;

  if ((realm_alias == NULL) || (dcm_hpa == 0u) || (verify_va == NULL) ||
      (verify_pa == 0u) || (page_size == 0u))
    return ACS_STATUS_ERR;

  dma_length = (uint32_t)sizeof(uint64_t);
  if (val_cda_seed_realm_cache_line(dcm_hpa,
                                    realm_alias,
                                    seed_value) != ACS_STATUS_PASS)
    return ACS_STATUS_FAIL;

  if ((val_memory_set_el3(verify_va, dma_length, 0u) != 0u) ||
      (val_memory_cache_clean_invalidate_range_el3((uint64_t)verify_va,
                                                    dma_length)
       != ACS_STATUS_PASS))
    return ACS_STATUS_ERR;

  /* Fetch the DCM Location with an ATS-derived Realm translation. */
  if ((val_cda_cache_ats_translation(endpoint_bdf,
                                     dcm_hpa,
                                     dcm_hpa,
                                     1u,
                                     page_size) != ACS_STATUS_PASS) ||
      (val_exerciser_dma_with_atc_by_bdf(endpoint_bdf,
                                         dcm_hpa,
                                         dma_length,
                                         EDMA_TO_DEVICE) != ACS_STATUS_PASS))
    return ACS_STATUS_FAIL;

  /* Copy the captured value to host memory without inspecting device state. */
  if ((val_cda_cache_ats_translation(endpoint_bdf,
                                     verify_pa,
                                     verify_pa,
                                     0u,
                                     page_size) != ACS_STATUS_PASS) ||
      (val_exerciser_dma_with_atc_by_bdf(endpoint_bdf,
                                         verify_pa,
                                         dma_length,
                                         EDMA_FROM_DEVICE) != ACS_STATUS_PASS) ||
      (val_memory_cache_invalidate_range_el3((uint64_t)verify_va,
                                             dma_length)
       != ACS_STATUS_PASS))
    return ACS_STATUS_FAIL;

  observed = *(volatile uint64_t *)verify_va;
  if (observed != seed_value)
  {
    val_print(ACS_PRINT_ERR,
              " CDA: device cache-fill readback 0x%llx",
              observed);
    val_print(ACS_PRINT_ERR,
              " CDA: expected device cache-fill value 0x%llx",
              seed_value);
    return ACS_STATUS_FAIL;
  }

  return ACS_STATUS_PASS;
}

static void
val_cda_init_dcm_window_context(uint32_t decoder_index,
                                VAL_CDA_DCM_WINDOW_CONTEXT *context)
{
  val_memory_set(context, sizeof(*context), 0);
  context->decoder_index = decoder_index;
  context->host_index = CXL_COMPONENT_INVALID_INDEX;
  context->root_index = CXL_COMPONENT_INVALID_INDEX;
  context->endpoint_index = CXL_COMPONENT_INVALID_INDEX;
}

/**
  @brief  Restore decoder and RME-CDA state saved for a DCM window.
**/
uint32_t
val_cda_restore_dcm_window(const VAL_CDA_DCM_WINDOW_CONTEXT *context)
{
  uint32_t restore_status;
  uint32_t readback;

  if (context == NULL)
    return ACS_STATUS_ERR;

  restore_status = ACS_STATUS_PASS;

  if ((context->rmecda_ctl1_valid != 0u) && (context->rmecda_cfg_va != 0u))
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
      restore_status = ACS_STATUS_ERR;
    }
  }

  if ((context->endpoint_decoder_valid != 0u) &&
      (((context->endpoint_decoder_size_orig == 0u) &&
        (val_cxl_disable_component_decoder(context->endpoint_index,
                                           context->decoder_index)
         != ACS_STATUS_PASS)) ||
       ((context->endpoint_decoder_size_orig != 0u) &&
        (val_cxl_program_component_decoder(context->endpoint_index,
                                           context->decoder_index,
                                           context->endpoint_decoder_base_orig,
                                           context->endpoint_decoder_size_orig)
         != ACS_STATUS_PASS))))
  {
    restore_status = ACS_STATUS_ERR;
  }

  if ((context->host_decoder_valid != 0u) &&
      (val_cxl_restore_host_decoder(context->host_index,
                                    context->decoder_index,
                                    context->host_decoder_base_orig,
                                    context->host_decoder_size_orig,
                                    1u,
                                    context->host_target_low_orig,
                                    context->host_target_high_orig)
       != ACS_STATUS_PASS))
  {
    restore_status = ACS_STATUS_ERR;
  }

  return restore_status;
}

/**
  @brief  Select a CHI-C2C CDA endpoint and prepare a host-visible DCM window.

  The helper saves the existing decoder and RME-CDA state, enables CXL.mem,
  routes one CFMWS window to the endpoint, and enables TDISP enforcement on
  the selected Root Port. The caller must invoke val_cda_restore_dcm_window().
**/
uint32_t
val_cda_prepare_dcm_window(uint32_t decoder_index,
                           VAL_CDA_DCM_WINDOW_CONTEXT *context)
{
  return val_cda_prepare_dcm_window_with_dev_props(decoder_index, 0u, context);
}

/**
  @brief  Prepare a DCM window for an endpoint with required device properties.

  Endpoints that do not advertise every bit in required_dev_properties are
  ignored before any decoder or RME-CDA state is changed.
**/
uint32_t
val_cda_prepare_dcm_window_with_dev_props(
                           uint32_t decoder_index,
                           uint32_t required_dev_properties,
                           VAL_CDA_DCM_WINDOW_CONTEXT *context)
{
  return val_cda_prepare_dcm_window_from_root_index(decoder_index,
                                                     required_dev_properties,
                                                     0u,
                                                     context);
}

/**
  @brief  Prepare a DCM window by scanning from a component-table root index.

  This permits a caller to continue discovery after an otherwise suitable
  endpoint cannot provide an optional test stimulus.
**/
static uint32_t
val_cda_prepare_dcm_window_internal(
                           uint32_t decoder_index,
                           uint32_t required_dev_properties,
                           uint32_t start_root_index,
                           uint32_t require_exerciser,
                           VAL_CDA_DCM_WINDOW_CONTEXT *context)
{
  CXL_COMPONENT_TABLE *table;

  if (context == NULL)
    return ACS_STATUS_ERR;

  val_cda_init_dcm_window_context(decoder_index, context);
  table = val_cxl_component_table_ptr();
  if ((table == NULL) || (start_root_index >= table->num_entries))
    return ACS_STATUS_SKIP;

  for (uint32_t root_idx = start_root_index;
       root_idx < table->num_entries;
       ++root_idx)
  {
    VAL_CDA_DCM_WINDOW_CONTEXT candidate;
    const CXL_COMPONENT_ENTRY *root_port;
    const CXL_COMPONENT_ENTRY *endpoint;
    uint32_t endpoint_bdf;
    uint32_t dev_properties;
    uint32_t ctl1_programmed;
    uint32_t ctl1_readback;

    val_cda_init_dcm_window_context(decoder_index, &candidate);
    root_port = &table->component[root_idx];

    if ((root_port->role != CXL_COMPONENT_ROLE_ROOT_PORT) ||
        (root_port->chi_c2c_supported == 0u))
      continue;

    if (((require_exerciser != 0u) &&
         (val_cda_find_downstream_chi_c2c_exerciser_endpoint(root_port->bdf,
                                                              &endpoint_bdf)
          != ACS_STATUS_PASS)) ||
        ((require_exerciser == 0u) &&
         (val_cda_find_downstream_chi_c2c_endpoint(root_port->bdf,
                                                    &endpoint_bdf)
          != ACS_STATUS_PASS)))
      continue;

    if (val_cxl_find_component_index_by_bdf(endpoint_bdf,
                                             &candidate.endpoint_index)
        != ACS_STATUS_PASS)
      continue;

    endpoint = &table->component[candidate.endpoint_index];
    if ((endpoint->role != CXL_COMPONENT_ROLE_ENDPOINT) ||
        (endpoint->chi_c2c_supported == 0u))
      continue;

    if (required_dev_properties != 0u)
    {
      if ((val_tdisp_get_device_properties(endpoint_bdf, &dev_properties)
           != ACS_STATUS_PASS) ||
          ((dev_properties & required_dev_properties) !=
           required_dev_properties))
        continue;
    }

    candidate.root_index = root_idx;
    candidate.root_bdf = root_port->bdf;
    candidate.endpoint_bdf = endpoint_bdf;
    candidate.host_index = root_port->host_bridge_index;
    if (candidate.host_index == CXL_COMPONENT_INVALID_INDEX)
      continue;

    if (val_pcie_find_cda_capability(candidate.root_bdf,
                                     &candidate.rmecda_cap_base)
        != PCIE_SUCCESS)
      continue;

    if (val_cxl_select_cfmws_window(candidate.host_index,
                                    &candidate.window_base,
                                    &candidate.window_size) != ACS_STATUS_PASS)
      continue;

    if ((val_cxl_get_decoder(candidate.host_index,
                             decoder_index,
                             &candidate.host_decoder_base_orig,
                             &candidate.host_decoder_size_orig) != 0u) ||
        (val_cxl_get_host_decoder_target(candidate.host_index,
                                         decoder_index,
                                         &candidate.host_target_low_orig,
                                         &candidate.host_target_high_orig) != 0u))
      continue;
    candidate.host_decoder_valid = 1u;

    if (val_cxl_get_component_decoder(candidate.endpoint_index,
                                      decoder_index,
                                      &candidate.endpoint_decoder_base_orig,
                                      &candidate.endpoint_decoder_size_orig) != 0u)
    {
      (void)val_cda_restore_dcm_window(&candidate);
      continue;
    }
    candidate.endpoint_decoder_valid = 1u;

    if ((val_pcie_read_cfg(candidate.root_bdf,
                           candidate.rmecda_cap_base + RMECDA_CTL1_OFFSET,
                           &candidate.rmecda_ctl1_orig) != PCIE_SUCCESS) ||
        ((candidate.rmecda_ctl1_orig &
          (RMECDA_CTL1_TDISP_EN_MASK | RMECDA_CTL1_LINK_STR_LOCK_MASK)) != 0u))
    {
      (void)val_cda_restore_dcm_window(&candidate);
      continue;
    }

    if (val_pcie_map_root_config(candidate.root_bdf,
                                 &candidate.rmecda_cfg_va) != ACS_STATUS_PASS)
    {
      (void)val_cda_restore_dcm_window(&candidate);
      continue;
    }

    if (val_memory_read_el3(candidate.rmecda_cfg_va +
                            candidate.rmecda_cap_base +
                            RMECDA_CTL1_OFFSET,
                            &candidate.rmecda_ctl1_orig) != ACS_STATUS_PASS)
    {
      (void)val_cda_restore_dcm_window(&candidate);
      continue;
    }
    candidate.rmecda_ctl1_valid = 1u;

    if (val_cxl_enable_mem(candidate.endpoint_bdf) != ACS_STATUS_PASS)
    {
      (void)val_cda_restore_dcm_window(&candidate);
      continue;
    }

    if ((val_cxl_program_host_decoder_for_root(candidate.root_bdf,
                                               candidate.host_index,
                                               decoder_index,
                                               candidate.window_base,
                                               candidate.window_size)
         != ACS_STATUS_PASS) ||
        (val_cxl_program_component_decoder(candidate.endpoint_index,
                                           decoder_index,
                                           candidate.window_base,
                                           candidate.window_size)
         != ACS_STATUS_PASS))
    {
      (void)val_cda_restore_dcm_window(&candidate);
      continue;
    }

    ctl1_programmed = candidate.rmecda_ctl1_orig |
                      RMECDA_CTL1_TDISP_EN_MASK |
                      RMECDA_CTL1_LINK_STR_LOCK_MASK;
    if ((val_memory_write_el3(candidate.rmecda_cfg_va +
                              candidate.rmecda_cap_base +
                              RMECDA_CTL1_OFFSET,
                              ctl1_programmed) != ACS_STATUS_PASS) ||
        (val_memory_read_el3(candidate.rmecda_cfg_va +
                             candidate.rmecda_cap_base +
                             RMECDA_CTL1_OFFSET,
                             &ctl1_readback) != ACS_STATUS_PASS) ||
        ((ctl1_readback &
          (RMECDA_CTL1_TDISP_EN_MASK | RMECDA_CTL1_LINK_STR_LOCK_MASK)) !=
         (RMECDA_CTL1_TDISP_EN_MASK | RMECDA_CTL1_LINK_STR_LOCK_MASK)))
    {
      (void)val_cda_restore_dcm_window(&candidate);
      continue;
    }

    *context = candidate;
    return ACS_STATUS_PASS;
  }

  return ACS_STATUS_SKIP;
}

uint32_t
val_cda_prepare_dcm_window_from_root_index(
                           uint32_t decoder_index,
                           uint32_t required_dev_properties,
                           uint32_t start_root_index,
                           VAL_CDA_DCM_WINDOW_CONTEXT *context)
{
  return val_cda_prepare_dcm_window_internal(decoder_index,
                                              required_dev_properties,
                                              start_root_index,
                                              1u,
                                              context);
}

/** Prepare a DCM window without requiring the endpoint to implement PAL exerciser hooks. */
uint32_t
val_cda_prepare_generic_dcm_window(
                           uint32_t decoder_index,
                           VAL_CDA_DCM_WINDOW_CONTEXT *context)
{
  return val_cda_prepare_generic_dcm_window_from_root_index(decoder_index,
                                                             0u,
                                                             context);
}

/** Continue generic CHI-C2C endpoint discovery from a component-table index. */
uint32_t
val_cda_prepare_generic_dcm_window_from_root_index(
                           uint32_t decoder_index,
                           uint32_t start_root_index,
                           VAL_CDA_DCM_WINDOW_CONTEXT *context)
{
  return val_cda_prepare_dcm_window_internal(decoder_index,
                                              0u,
                                              start_root_index,
                                              0u,
                                              context);
}

/**
  @brief  Find a CHI-C2C endpoint downstream of a root port.

  @param  root_bdf          Root port BDF.
  @param  endpoint_bdf_out  Output pointer for the endpoint BDF.

  @return ACS_STATUS_PASS if a usable endpoint was found.
          ACS_STATUS_SKIP if no matching endpoint is present.
          ACS_STATUS_ERR  if discovery data cannot be read.
**/
static uint32_t
val_cda_find_downstream_chi_c2c_endpoint_internal(uint32_t root_bdf,
                                                  uint32_t require_exerciser,
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

    if ((require_exerciser != 0u) &&
        (val_exerciser_init_by_bdf(candidate_bdf) != 0u))
      continue;

    *endpoint_bdf_out = candidate_bdf;
    return ACS_STATUS_PASS;
  }

  return ACS_STATUS_SKIP;
}

uint32_t
val_cda_find_downstream_chi_c2c_endpoint(uint32_t root_bdf,
                                         uint32_t *endpoint_bdf_out)
{
  return val_cda_find_downstream_chi_c2c_endpoint_internal(root_bdf,
                                                            0u,
                                                            endpoint_bdf_out);
}

uint32_t
val_cda_find_downstream_chi_c2c_exerciser_endpoint(uint32_t root_bdf,
                                                   uint32_t *endpoint_bdf_out)
{
  return val_cda_find_downstream_chi_c2c_endpoint_internal(root_bdf,
                                                            1u,
                                                            endpoint_bdf_out);
}

/**
  @brief  Check whether a CXL component is a CHI-C2C endpoint downstream of a
          root port bus window.

  @param  entry            CXL component entry to test.
  @param  root_bdf         Root port BDF used for segment matching.
  @param  secondary_bus    Root port secondary bus number.
  @param  subordinate_bus  Root port subordinate bus number.

  @return 1 if entry is a CHI-C2C endpoint in the downstream window,
          otherwise 0.
**/
uint32_t
val_cda_is_downstream_chi_c2c_endpoint(const CXL_COMPONENT_ENTRY *entry,
                                       uint32_t root_bdf,
                                       uint32_t secondary_bus,
                                       uint32_t subordinate_bus)
{
  if (entry == NULL)
    return 0u;

  if (entry->role != CXL_COMPONENT_ROLE_ENDPOINT)
    return 0u;

  if (entry->chi_c2c_supported == 0u)
    return 0u;

  return val_pcie_is_downstream_bdf(root_bdf,
                                    secondary_bus,
                                    subordinate_bus,
                                    entry->bdf);
}

/**
  @brief  Select a page within a DCM host-visible window for test stimulus.

  @param  window_base  DCM window base address.
  @param  window_size  DCM window size in bytes.
  @param  page_out     Output pointer for the selected page base.

  @return ACS_STATUS_PASS if a page is selected.
          ACS_STATUS_SKIP if the window cannot contain a complete page.
          ACS_STATUS_ERR  if the inputs are invalid.
**/
uint32_t
val_cda_select_dcm_page(uint64_t window_base,
                        uint64_t window_size,
                        uint64_t *page_out)
{
  uint64_t page_size;
  uint64_t window_end;
  uint64_t page_base;

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
   * Use the end of the window so the selected page does not collide with ACS
   * allocations that may come from low CFMWS-backed addresses.
   */
  page_base = (window_end - page_size) & ~(page_size - 1u);
  if ((page_base < window_base) || ((page_base + page_size) > window_end))
    return ACS_STATUS_SKIP;

  *page_out = page_base;
  return ACS_STATUS_PASS;
}

/**
  @brief  Set or clear RMECDA_CTL1.LINK_STR_LOCK and verify the readback.

  @param  cfg_va           Root-accessible VA for the root port config space.
  @param  rmecda_cap_base  RME-CDA DVSEC capability offset.
  @param  ctl1_template    Existing RMECDA_CTL1 value; non-lock fields are preserved.
  @param  lock             Nonzero to set LINK_STR_LOCK, zero to clear it.

  @return ACS_STATUS_PASS if the requested state was programmed and verified.
          ACS_STATUS_SKIP if the bit did not take the requested state.
          ACS_STATUS_ERR  if Root access failed.
**/
uint32_t
val_cda_set_link_stream_lock(uint64_t cfg_va,
                             uint32_t rmecda_cap_base,
                             uint32_t ctl1_template,
                             uint32_t lock)
{
  uint32_t value;
  uint32_t readback;

  if (cfg_va == 0u)
    return ACS_STATUS_ERR;

  value = ctl1_template;
  if (lock != 0u)
    value |= RMECDA_CTL1_LINK_STR_LOCK_MASK;
  else
    value &= ~RMECDA_CTL1_LINK_STR_LOCK_MASK;

  if (val_memory_write_el3(cfg_va + rmecda_cap_base + RMECDA_CTL1_OFFSET,
                           value) != ACS_STATUS_PASS)
    return ACS_STATUS_ERR;

  if (val_memory_read_el3(cfg_va + rmecda_cap_base + RMECDA_CTL1_OFFSET,
                          &readback) != ACS_STATUS_PASS)
    return ACS_STATUS_ERR;

  if (((readback & RMECDA_CTL1_LINK_STR_LOCK_MASK) != 0u) != (lock != 0u))
    return ACS_STATUS_SKIP;

  return ACS_STATUS_PASS;
}

/**
  @brief  Program the RMECDA_CTL3/CTL4 Requester ID range.

  @param  cfg_va           Root-accessible VA for the root port config space.
  @param  rmecda_cap_base  RME-CDA DVSEC capability offset.
  @param  ctl3_template    Existing RMECDA_CTL3 value; non-RID fields are preserved.
  @param  ctl4_template    Existing RMECDA_CTL4 value; non-RID fields are preserved.
  @param  rid_base         RID_BASE value to program.
  @param  rid_limit        RID_LIMIT value to program.
  @param  rid_range_valid  Nonzero to set RID_RANGE_VALID.

  @return ACS_STATUS_PASS if the fields were programmed and verified.
          ACS_STATUS_SKIP if the RID fields are not writable.
          ACS_STATUS_ERR  if Root access failed.
**/
uint32_t
val_cda_program_rid_range(uint64_t cfg_va,
                          uint32_t rmecda_cap_base,
                          uint32_t ctl3_template,
                          uint32_t ctl4_template,
                          uint32_t rid_base,
                          uint32_t rid_limit,
                          uint32_t rid_range_valid)
{
  uint32_t ctl3_program;
  uint32_t ctl4_program;
  uint32_t ctl3_readback;
  uint32_t ctl4_readback;

  if (cfg_va == 0u)
    return ACS_STATUS_ERR;

  ctl3_program = (ctl3_template & ~RMECDA_CTL3_RID_LIMIT_MASK) |
                 (((rid_limit & 0xFFFFu) << RMECDA_CTL3_RID_LIMIT_SHIFT) &
                  RMECDA_CTL3_RID_LIMIT_MASK);
  ctl4_program = ctl4_template &
                 ~(RMECDA_CTL4_RID_BASE_MASK |
                   RMECDA_CTL4_RID_RANGE_VALID_MASK);
  ctl4_program |= ((rid_base & 0xFFFFu) << RMECDA_CTL4_RID_BASE_SHIFT) &
                  RMECDA_CTL4_RID_BASE_MASK;
  if (rid_range_valid != 0u)
    ctl4_program |= RMECDA_CTL4_RID_RANGE_VALID_MASK;

  if (val_memory_write_el3(cfg_va + rmecda_cap_base + RMECDA_CTL3_OFFSET,
                           ctl3_program) != ACS_STATUS_PASS)
    return ACS_STATUS_ERR;

  if (val_memory_write_el3(cfg_va + rmecda_cap_base + RMECDA_CTL4_OFFSET,
                           ctl4_program) != ACS_STATUS_PASS)
    return ACS_STATUS_ERR;

  if ((val_memory_read_el3(cfg_va + rmecda_cap_base + RMECDA_CTL3_OFFSET,
                           &ctl3_readback) != ACS_STATUS_PASS) ||
      (val_memory_read_el3(cfg_va + rmecda_cap_base + RMECDA_CTL4_OFFSET,
                           &ctl4_readback) != ACS_STATUS_PASS))
    return ACS_STATUS_ERR;

  if (((ctl3_readback & RMECDA_CTL3_RID_LIMIT_MASK) !=
       (ctl3_program & RMECDA_CTL3_RID_LIMIT_MASK)) ||
      ((ctl4_readback & (RMECDA_CTL4_RID_BASE_MASK |
                         RMECDA_CTL4_RID_RANGE_VALID_MASK)) !=
       (ctl4_program & (RMECDA_CTL4_RID_BASE_MASK |
                        RMECDA_CTL4_RID_RANGE_VALID_MASK))))
    return ACS_STATUS_SKIP;

  return ACS_STATUS_PASS;
}

/**
  @brief   Execute all CDA compliance tests registered for the suite.

  @param  num_pe  Number of processing elements available for test execution. Unused.

  @return Consolidated status of the executed tests.
**/
uint32_t
val_rme_cda_execute_tests(uint32_t num_pe)
{
  uint32_t status = ACS_STATUS_SKIP;
  uint64_t num_smmus = val_smmu_get_info(SMMU_NUM_CTRL, 0);
  uint64_t *smmu_base_arr = NULL;
  uint64_t pgt_attr_el3;
  uint32_t smmu_cnt;

  g_curr_module = 1 << CDA_MODULE_ID;

  if ((num_smmus != 0u) && !g_rl_smmu_init)
  {
    smmu_base_arr = val_memory_alloc_pages(1);
    if (smmu_base_arr == NULL)
    {
      val_print(ACS_PRINT_ERR, " Failed to allocate CDA smmu_base_arr", 0);
      return ACS_STATUS_ERR;
    }

    smmu_cnt = 0u;
    while (smmu_cnt < num_smmus)
    {
      smmu_base_arr[smmu_cnt] = val_smmu_get_info(SMMU_CTRL_BASE, smmu_cnt);
      smmu_cnt++;
    }

    pgt_attr_el3 = LOWER_ATTRS(PGT_ENTRY_ACCESS |
                               SHAREABLE_ATTR(OUTER_SHAREABLE) |
                               PGT_ENTRY_AP_RW |
                               PAS_ATTR(NONSECURE_PAS));
    if (val_add_mmu_entry_el3((uint64_t)smmu_base_arr,
                              (uint64_t)val_memory_virt_to_phys(smmu_base_arr),
                              pgt_attr_el3))
    {
      val_print(ACS_PRINT_ERR, " MMU mapping failed for CDA smmu_base_arr", 0);
      val_memory_free_pages(smmu_base_arr, 1);
      return ACS_STATUS_ERR;
    }

    if (val_rlm_smmu_init(num_smmus, smmu_base_arr))
    {
      val_print(ACS_PRINT_ERR, " CDA SMMU REALM INIT failed", 0);
      val_memory_free_pages(smmu_base_arr, 1);
      return ACS_STATUS_ERR;
    }

    g_rl_smmu_init = 1u;
    val_memory_free_pages(smmu_base_arr, 1);
  }

  val_print(ACS_PRINT_ALWAYS, "\n\n*******************************************************\n", 0);
  status = val_execute_module_tests(CDA_MODULE_ID,
                                    CDA_MODULE_START,
                                    CDA_MODULE_END,
                                    num_pe,
                                    status);

  return status;
}
