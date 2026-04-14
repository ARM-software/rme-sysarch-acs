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
#include "val/include/val_cxl.h"
#include "val/include/val_cxl_spec.h"
#include "val/include/val_pcie.h"
#include "val/include/val_el32.h"
#include "val/include/val_memory.h"
#include "val/include/val_mec.h"
#include "val/include/val_pe.h"
#include "val/include/val_spdm.h"

#if ENABLE_SPDM
#include "industry_standard/cxl_tsp.h"
#endif

#define TEST_NAME "cxl_rhcqws_host_side_mpe"
#define TEST_DESC "Host-side MPE preserves data on partial writes"
#define TEST_RULE "RHCQWS"

#define DECODER_SLOT          0u
#define MAX_CACHE_LINE        1024u
#define PCIE_LNKCAP_OFFSET    0x0Cu
#define PCIE_LNKCAP_PN_SHIFT  24u
#define PCIE_LNKCAP_PN_MASK   0xFFu
#define RMECDA_CTL1_TDISP_EN_MASK 0x1u
#define RMECDA_CTL1_LINK_STR_LOCK_MASK (1u << 1)
#define CXL_MEM_LINE_SIZE   64u

typedef struct {
  uint32_t host_index;
  uint64_t window_base;
  uint64_t window_size;
  uint32_t root_index;
  uint32_t endpoint_index;
  uint64_t host_decoder_base_orig;
  uint64_t host_decoder_size_orig;
  uint64_t endpoint_decoder_base_orig;
  uint64_t endpoint_decoder_size_orig;
  uint32_t host_target_low_orig;
  uint32_t host_target_high_orig;
  uint32_t host_target_valid;
} CONTEXT;

#if ENABLE_SPDM
static uint32_t
map_window_alias(uint64_t phys,
                 uint32_t pas,
                 uint32_t attr_index,
                 volatile uint8_t **virt_out)
{
  uint64_t page_size = (uint64_t)val_memory_page_size();
  uint64_t va;
  uint32_t attr;

  if ((phys == 0u) || (virt_out == NULL))
    return ACS_STATUS_ERR;

  if (page_size == 0u)
    return ACS_STATUS_ERR;

  va = val_get_free_va(page_size);
  if (va == 0u)
    return ACS_STATUS_ERR;

  attr = LOWER_ATTRS(PGT_ENTRY_ACCESS |
                     SHAREABLE_ATTR(OUTER_SHAREABLE) |
                     GET_ATTR_INDEX(attr_index) |
                     PGT_ENTRY_AP_RW |
                     PAS_ATTR(pas));

  if (val_add_mmu_entry_el3(va, phys, attr))
    return ACS_STATUS_ERR;

  *virt_out = (volatile uint8_t *)va;
  return ACS_STATUS_PASS;
}

static uint32_t
mut_write_u32(uint64_t address, uint32_t value)
{
  /* Write a 32-bit value through MUT at EL3. */
  shared_data->num_access = 1;
  shared_data->shared_data_access[0].addr = address;
  shared_data->shared_data_access[0].data = value;
  shared_data->shared_data_access[0].access_type = WRITE_DATA;

  if (val_pe_access_mut_el3())
  {
    val_print(ACS_PRINT_ERR, " RHCQWS: MUT write failed VA 0x%llx", address);
    return ACS_STATUS_FAIL;
  }

  return ACS_STATUS_PASS;
}

static uint32_t
mut_read_u32(uint64_t address, uint32_t *value)
{
  /* Read a 32-bit value through MUT at EL3. */
  if (value == NULL)
    return ACS_STATUS_ERR;

  shared_data->num_access = 1;
  shared_data->shared_data_access[0].addr = address;
  shared_data->shared_data_access[0].access_type = READ_DATA;

  if (val_pe_access_mut_el3())
  {
    val_print(ACS_PRINT_ERR, " RHCQWS: MUT read failed VA 0x%llx", address);
    return ACS_STATUS_FAIL;
  }

  *value = (uint32_t)shared_data->shared_data_access[0].data;
  return ACS_STATUS_PASS;
}

static uint32_t
mut_write_u8(uint64_t address, uint8_t value)
{
  /* Write an 8-bit value through MUT at EL3. */
  shared_data->num_access = 1;
  shared_data->shared_data_access[0].addr = address;
  shared_data->shared_data_access[0].data = value;
  shared_data->shared_data_access[0].access_type = WRITE_DATA_BYTE;

  if (val_pe_access_mut_el3())
  {
    val_print(ACS_PRINT_ERR, " RHCQWS: MUT byte write failed VA 0x%llx",
              address);
    return ACS_STATUS_FAIL;
  }

  return ACS_STATUS_PASS;
}

static uint32_t
read_from_root(uint64_t address, uint32_t *value)
{
  if (value == NULL)
    return ACS_STATUS_ERR;

  shared_data->num_access = 1;
  shared_data->shared_data_access[0].addr = address;
  shared_data->shared_data_access[0].access_type = READ_DATA;

  if (val_pe_access_mut_el3())
  {
    val_print(ACS_PRINT_ERR, " RHCQWS: MUT read failed 0x%llx", address);
    return ACS_STATUS_ERR;
  }

  *value = (uint32_t)shared_data->shared_data_access[0].data;
  return ACS_STATUS_PASS;
}

static uint32_t
write_from_root(uint64_t address, uint32_t value)
{
  shared_data->num_access = 1;
  shared_data->shared_data_access[0].addr = address;
  shared_data->shared_data_access[0].data = value;
  shared_data->shared_data_access[0].access_type = WRITE_DATA;

  if (val_pe_access_mut_el3())
  {
    val_print(ACS_PRINT_ERR, " RHCQWS: MUT write failed 0x%llx", address);
    return ACS_STATUS_ERR;
  }

  return ACS_STATUS_PASS;
}

static void
restore_decoders(const CONTEXT *context)
{
  if (context == NULL)
    return;

  if ((context->host_index != CXL_COMPONENT_INVALID_INDEX) &&
      (context->host_decoder_size_orig != 0u))
  {
    (void)val_cxl_program_host_decoder(context->host_index,
                                       DECODER_SLOT,
                                       context->host_decoder_base_orig,
                                       context->host_decoder_size_orig);
    if (context->host_target_valid != 0u)
    {
      uint64_t comp_base;
      uint64_t cap_base;

      comp_base = val_cxl_get_info(CXL_INFO_COMPONENT_BASE, context->host_index);
      if ((comp_base != 0u) &&
          (val_cxl_find_capability(comp_base,
                                   CXL_CAPID_HDM_DECODER,
                                   &cap_base) == ACS_STATUS_PASS))
      {
        val_mmio_write(cap_base + CXL_HDM_DECODER_TARGET_LOW(DECODER_SLOT),
                       context->host_target_low_orig);
        val_mmio_write(cap_base + CXL_HDM_DECODER_TARGET_HIGH(DECODER_SLOT),
                       context->host_target_high_orig);
      }
    }
  }

  if ((context->endpoint_index != CXL_COMPONENT_INVALID_INDEX) &&
      (context->endpoint_decoder_size_orig != 0u))
    (void)val_cxl_program_component_decoder(context->endpoint_index,
                                            DECODER_SLOT,
                                            context->endpoint_decoder_base_orig,
                                            context->endpoint_decoder_size_orig);
}

static uint32_t
program_host_target_list(uint32_t bdf,
                          uint64_t comp_base,
                          uint32_t decoder_index,
                          CONTEXT *context)
{
  uint32_t pcie_cap_offset;
  uint32_t lnkcap;
  uint32_t port_id;
  uint64_t hdm_cap_base;
  uint32_t target_low;
  uint32_t target_high;

  if (context == NULL)
    return ACS_STATUS_ERR;

  if (val_pcie_find_capability(bdf,
                               PCIE_CAP,
                               CID_PCIECS,
                               &pcie_cap_offset) != 0u)
  {
    val_print(ACS_PRINT_ERR, " RHCQWS: PCIe cap not found", 0);
    return ACS_STATUS_ERR;
  }

  if (val_pcie_read_cfg(bdf,
                        pcie_cap_offset + PCIE_LNKCAP_OFFSET,
                        &lnkcap) != 0u)
  {
    val_print(ACS_PRINT_ERR, " RHCQWS: LNKCAP read failed", 0);
    return ACS_STATUS_ERR;
  }

  port_id = (lnkcap >> PCIE_LNKCAP_PN_SHIFT) & PCIE_LNKCAP_PN_MASK;

  if (val_cxl_find_capability(comp_base,
                              CXL_CAPID_HDM_DECODER,
                              &hdm_cap_base) != ACS_STATUS_PASS)
  {
    val_print(ACS_PRINT_ERR, " RHCQWS: Host HDM cap missing", 0);
    return ACS_STATUS_ERR;
  }

  target_low = val_mmio_read(hdm_cap_base +
                             CXL_HDM_DECODER_TARGET_LOW(decoder_index));
  target_high = val_mmio_read(hdm_cap_base +
                              CXL_HDM_DECODER_TARGET_HIGH(decoder_index));
  context->host_target_low_orig = target_low;
  context->host_target_high_orig = target_high;
  context->host_target_valid = 1u;

  val_mmio_write(hdm_cap_base + CXL_HDM_DECODER_TARGET_LOW(decoder_index),
                 port_id);
  val_mmio_write(hdm_cap_base + CXL_HDM_DECODER_TARGET_HIGH(decoder_index),
                 0u);

  return ACS_STATUS_PASS;
}

static uint32_t
read_tsp_dvsec_capable(uint32_t bdf, uint32_t *tsp_capable)
{
  uint32_t dvsec_offset;
  uint32_t hdr2;
  uint16_t cxl_cap;

  if (tsp_capable == NULL)
    return ACS_STATUS_ERR;

  if (val_pcie_find_vendor_dvsec(bdf,
                                 CXL_DVSEC_VENDOR_ID,
                                 CXL_DVSEC_ID_DEVICE,
                                 &dvsec_offset) != PCIE_SUCCESS)
    return ACS_STATUS_FAIL;

  if (val_pcie_read_cfg(bdf, dvsec_offset + CXL_DVSEC_HDR2_OFFSET, &hdr2))
    return ACS_STATUS_FAIL;

  cxl_cap = (uint16_t)((hdr2 >> CXL_DVSEC_CXL_CAPABILITY_SHIFT) &
                       CXL_DVSEC_CXL_CAPABILITY_MASK);
  *tsp_capable = ((cxl_cap & CXL_DVSEC_CXL_CAP_TSP_CAPABLE) != 0u) ? 1u : 0u;

  return ACS_STATUS_PASS;
}

static uint32_t
run_partial_write_test(const CONTEXT *context)
{
  /* Exercise a partial write and verify cache-line preservation. */
  uint32_t status;
  volatile uint8_t *non_cacheable = NULL;
  uint32_t word_expected;
  uint32_t word_observed;
  uint8_t byte_expected;
  uint32_t mec_enabled = 0u;
  uint32_t mecid = 1 ;

  /* Enable MEC and program a MECID for host-side encryption. */
  if (val_is_mec_supported() == 0u)
    return ACS_STATUS_SKIP;

  if (val_rlm_enable_mec())
    return ACS_STATUS_FAIL;
  mec_enabled = 1u;

  if (val_rlm_configure_mecid(mecid))
  {
    status = ACS_STATUS_FAIL;
    goto cleanup;
  }

  if ((context == NULL) || (context->window_size < CXL_MEM_LINE_SIZE))
  {
    status = ACS_STATUS_SKIP;
    goto cleanup;
  }

  /* Map a non-cacheable Realm PAS alias to seed and update the cache line. */
  status = map_window_alias(context->window_base,
                            REALM_PAS,
                            NON_CACHEABLE,
                            &non_cacheable);
  if (status != ACS_STATUS_PASS)
    goto cleanup;

  /* Write 4 bytes, update 1 byte, and verify the full 4-byte value. */
  word_expected = 0xA5B6C7D8u;
  val_print(ACS_PRINT_DEBUG, " RHCQWS: Write addr 0x%llx",
            (uint64_t)non_cacheable);
  val_print(ACS_PRINT_DEBUG, " RHCQWS: Write data 0x%llx",
            (uint64_t)word_expected);
  if (mut_write_u32((uint64_t)non_cacheable, word_expected) !=
      ACS_STATUS_PASS)
  {
    status = ACS_STATUS_FAIL;
    goto cleanup;
  }

  byte_expected = (uint8_t)(0x5Au ^ (uint8_t)(word_expected & 0xFFu));
  val_print(ACS_PRINT_DEBUG, " RHCQWS: Byte update addr 0x%llx",
            (uint64_t)non_cacheable);
  val_print(ACS_PRINT_DEBUG, " RHCQWS: Byte update data 0x%llx",
            (uint64_t)byte_expected);
  if (mut_write_u8((uint64_t)non_cacheable, byte_expected) !=
      ACS_STATUS_PASS)
  {
    status = ACS_STATUS_FAIL;
    goto cleanup;
  }

  if (mut_read_u32((uint64_t)non_cacheable, &word_observed) !=
      ACS_STATUS_PASS)
  {
    status = ACS_STATUS_FAIL;
    goto cleanup;
  }

  word_expected = (word_expected & ~0xFFu) | byte_expected;
  val_print(ACS_PRINT_DEBUG, " RHCQWS: Read addr 0x%llx",
            (uint64_t)non_cacheable);
  val_print(ACS_PRINT_DEBUG, " RHCQWS: Read data 0x%llx",
            (uint64_t)word_observed);

  if (word_observed != word_expected)
  {
    val_print(ACS_PRINT_ERR, " RHCQWS: 4-byte data mismatch", 0);
    val_print(ACS_PRINT_ERR, " RHCQWS: observed 0x%x",
              (uint64_t)word_observed);
    val_print(ACS_PRINT_ERR, " RHCQWS: expected 0x%x",
              (uint64_t)word_expected);
    status = ACS_STATUS_FAIL;
    goto cleanup;
  }

  status = ACS_STATUS_PASS;

cleanup:
  if (mec_enabled != 0u)
    (void)val_rlm_disable_mec();

  return status;
}

static uint32_t
exercise_root_port(const CXL_COMPONENT_TABLE *table,
                   uint32_t root_index,
                   uint32_t *type3_found,
                   uint32_t *candidate_found)
{
  /* Locate a Type-3 device that relies on host-side encryption. */
  const CXL_COMPONENT_ENTRY *root_port;
  const CXL_COMPONENT_ENTRY *endpoint;
  CONTEXT context;
  uint32_t host_index;
  uint64_t host_comp_base;
  uint32_t endpoint_index = CXL_COMPONENT_INVALID_INDEX;
  val_spdm_context_t ctx;
  uint32_t session_id = 0u;
  uint32_t session_active = 0u;
  libcxltsp_device_capabilities_t capabilities;
  uint32_t rmecda_cap_base = 0u;
  uint64_t cfg_addr = 0u;
  uint64_t cfg_va = 0u;
  uint64_t tg = 0u;
  uint32_t attr;
  uint32_t ctl1_original = 0u;
  uint32_t ctl1_programmed;
  uint32_t ctl1_readback;
  uint32_t ctl1_valid = 0u;
  uint32_t tsp_capable = 0u;
  uint32_t status;

  if ((table == NULL) || (type3_found == NULL) || (candidate_found == NULL))
    return ACS_STATUS_ERR;

  *type3_found = 0u;
  *candidate_found = 0u;

  root_port = &table->component[root_index];
  if (root_port->role != CXL_COMPONENT_ROLE_ROOT_PORT)
    return ACS_STATUS_SKIP;

  /* Find a downstream endpoint for the root port. */
  status = val_cxl_find_downstream_endpoint(root_index, &endpoint_index);
  if (status != ACS_STATUS_PASS)
    return ACS_STATUS_SKIP;

  endpoint = &table->component[endpoint_index];
  if (endpoint->device_type != CXL_DEVICE_TYPE_TYPE3)
    return ACS_STATUS_SKIP;

  /* Filter to configurations with host/endpoint HDM decoders. */
  *type3_found = 1u;

  host_index = root_port->host_bridge_index;
  if (host_index == CXL_COMPONENT_INVALID_INDEX)
    return ACS_STATUS_SKIP;

  if (host_index >= (uint32_t)val_cxl_get_info(CXL_INFO_NUM_DEVICES, 0))
    return ACS_STATUS_SKIP;

  host_comp_base = val_cxl_get_info(CXL_INFO_COMPONENT_BASE, host_index);
  if ((host_comp_base == 0u) ||
      (val_cxl_find_capability(host_comp_base,
                               CXL_CAPID_HDM_DECODER,
                               NULL) != ACS_STATUS_PASS))
    return ACS_STATUS_SKIP;

  if ((endpoint->component_reg_base == 0u) ||
      (val_cxl_find_capability(endpoint->component_reg_base,
                               CXL_CAPID_HDM_DECODER,
                               NULL) != ACS_STATUS_PASS))
    return ACS_STATUS_SKIP;

  /* Enable CXL.mem in the endpoint device control DVSEC. */
  status = val_cxl_enable_mem(endpoint->bdf);
  if (status != ACS_STATUS_PASS)
  {
    val_print(ACS_PRINT_ERR, " RHCQWS: CXL.mem enable failed", 0);
    return ACS_STATUS_FAIL;
  }

  /* Select a CFMWS window for CXL.mem access. */
  val_memory_set(&context, sizeof(context), 0);
  context.host_index = host_index;
  context.root_index = root_index;
  context.endpoint_index = endpoint_index;
  context.host_target_valid = 0u;

  status = val_cxl_select_cfmws_window(context.host_index,
                                       &context.window_base,
                                       &context.window_size);
  if (status != ACS_STATUS_PASS)
    return ACS_STATUS_SKIP;

  status = program_host_target_list(root_port->bdf,
                                    host_comp_base,
                                    DECODER_SLOT,
                                    &context);
  if (status != ACS_STATUS_PASS)
  {
    restore_decoders(&context);
    return (status == ACS_STATUS_SKIP) ? ACS_STATUS_SKIP : ACS_STATUS_FAIL;
  }

  /* Save and reprogram HDM decoders for the selected window. */
  if (val_cxl_get_decoder(context.host_index,
                          DECODER_SLOT,
                          &context.host_decoder_base_orig,
                          &context.host_decoder_size_orig) != 0u)
  {
    context.host_decoder_base_orig = 0u;
    context.host_decoder_size_orig = 0u;
  }

  if (val_cxl_get_component_decoder(context.endpoint_index,
                                    DECODER_SLOT,
                                    &context.endpoint_decoder_base_orig,
                                    &context.endpoint_decoder_size_orig) != 0u)
  {
    context.endpoint_decoder_base_orig = 0u;
    context.endpoint_decoder_size_orig = 0u;
  }

  status = val_cxl_program_host_decoder(context.host_index,
                                        DECODER_SLOT,
                                        context.window_base,
                                        context.window_size);
  if (status != ACS_STATUS_PASS)
  {
    restore_decoders(&context);
    return (status == ACS_STATUS_SKIP) ? ACS_STATUS_SKIP : ACS_STATUS_FAIL;
  }

  status = val_cxl_program_component_decoder(context.endpoint_index,
                                             DECODER_SLOT,
                                             context.window_base,
                                             context.window_size);
  if (status != ACS_STATUS_PASS)
  {
    restore_decoders(&context);
    return (status == ACS_STATUS_SKIP) ? ACS_STATUS_SKIP : ACS_STATUS_FAIL;
  }

  /* Open an SPDM session to query CXL-TSP capabilities. */
  status = val_spdm_session_open(endpoint->bdf, &ctx, &session_id);
  if (status == ACS_STATUS_SKIP)
  {
    restore_decoders(&context);
    return ACS_STATUS_SKIP;
  }

  if (status != ACS_STATUS_PASS)
  {
    restore_decoders(&context);
    return ACS_STATUS_FAIL;
  }

  session_active = 1u;

  /* Confirm target capabilities and absence of target-side encryption. */
  status = val_spdm_send_cxl_tsp_get_version(&ctx, session_id);
  if (status != ACS_STATUS_PASS)
  {
    restore_decoders(&context);
    (void)val_spdm_session_close(&ctx, session_id);
    return ACS_STATUS_FAIL;
  }

  val_memory_set(&capabilities, sizeof(capabilities), 0);
  status = val_spdm_send_cxl_tsp_get_capabilities(&ctx, session_id, &capabilities);
  if (status == ACS_STATUS_SKIP)
  {
    restore_decoders(&context);
    (void)val_spdm_session_close(&ctx, session_id);
    return ACS_STATUS_SKIP;
  }
  if (status != ACS_STATUS_PASS)
  {
    restore_decoders(&context);
    (void)val_spdm_session_close(&ctx, session_id);
    return ACS_STATUS_FAIL;
  }

  if ((capabilities.memory_encryption_features_supported &
       CXL_TSP_MEMORY_ENCRYPTION_FEATURES_SUPPORT_ENCRYPTION) != 0u)
  {
    restore_decoders(&context);
    (void)val_spdm_session_close(&ctx, session_id);
    return ACS_STATUS_SKIP;
  }

  *candidate_found = 1u;

  /*
   * CXL 3.1 section 11.5.4.2: TSP Capable indicates MemRdFill support,
   * required for partial writes with initiator-based encryption.
   */
  status = read_tsp_dvsec_capable(endpoint->bdf, &tsp_capable);
  if ((status != ACS_STATUS_PASS) || (tsp_capable == 0u))
  {
    val_print(ACS_PRINT_ERR, " RHCQWS: TSP Capable not set for BDF 0x%x",
              (uint64_t)endpoint->bdf);
    status = ACS_STATUS_FAIL;
    goto cleanup;
  }

  /* Enable TDISP and lock the link after decoder programming. */
  status = val_pcie_find_cda_capability(root_port->bdf, &rmecda_cap_base);
  if (status != ACS_STATUS_PASS)
  {
    val_print(ACS_PRINT_DEBUG,
              " RHCQWS: RME-CDA DVSEC missing for BDF 0x%x",
              (uint64_t)root_port->bdf);
    status = ACS_STATUS_SKIP;
    goto cleanup;
  }

  cfg_addr = val_pcie_get_bdf_config_addr(root_port->bdf);
  tg = val_get_min_tg();
  if ((cfg_addr == 0u) || (tg == 0u))
  {
    val_print(ACS_PRINT_ERR,
              " RHCQWS: Invalid config mapping for BDF 0x%x",
              (uint64_t)root_port->bdf);
    status = ACS_STATUS_FAIL;
    goto cleanup;
  }

  cfg_va = val_get_free_va(tg);
  if (cfg_va == 0u)
  {
    val_print(ACS_PRINT_ERR,
              " RHCQWS: Config VA allocation failed for BDF 0x%x",
              (uint64_t)root_port->bdf);
    status = ACS_STATUS_FAIL;
    goto cleanup;
  }

  attr = LOWER_ATTRS(PGT_ENTRY_ACCESS | SHAREABLE_ATTR(OUTER_SHAREABLE) |
                     GET_ATTR_INDEX(DEV_MEM_nGnRnE) | PGT_ENTRY_AP_RW |
                     PAS_ATTR(ROOT_PAS));
  if (val_add_mmu_entry_el3(cfg_va, cfg_addr, attr))
  {
    val_print(ACS_PRINT_ERR,
              " RHCQWS: Config map failed for BDF 0x%x",
              (uint64_t)root_port->bdf);
    status = ACS_STATUS_FAIL;
    goto cleanup;
  }

  if (read_from_root(cfg_va + rmecda_cap_base + RMECDA_CTL1_OFFSET,
                     &ctl1_original) != ACS_STATUS_PASS)
  {
    val_print(ACS_PRINT_ERR,
              " RHCQWS: RMECDA_CTL1 read failed for BDF 0x%x",
              (uint64_t)root_port->bdf);
    status = ACS_STATUS_FAIL;
    goto cleanup;
  }

  ctl1_programmed = ctl1_original |
                    RMECDA_CTL1_TDISP_EN_MASK |
                    RMECDA_CTL1_LINK_STR_LOCK_MASK;
  if (write_from_root(cfg_va + rmecda_cap_base + RMECDA_CTL1_OFFSET,
                      ctl1_programmed) != ACS_STATUS_PASS)
  {
    val_print(ACS_PRINT_ERR,
              " RHCQWS: RMECDA_CTL1 write failed for BDF 0x%x",
              (uint64_t)root_port->bdf);
    status = ACS_STATUS_FAIL;
    goto cleanup;
  }

  if (read_from_root(cfg_va + rmecda_cap_base + RMECDA_CTL1_OFFSET,
                     &ctl1_readback) != ACS_STATUS_PASS)
  {
    val_print(ACS_PRINT_ERR,
              " RHCQWS: RMECDA_CTL1 readback failed for BDF 0x%x",
              (uint64_t)root_port->bdf);
    status = ACS_STATUS_FAIL;
    goto cleanup;
  }

  if ((ctl1_readback &
       (RMECDA_CTL1_TDISP_EN_MASK | RMECDA_CTL1_LINK_STR_LOCK_MASK)) !=
      (RMECDA_CTL1_TDISP_EN_MASK | RMECDA_CTL1_LINK_STR_LOCK_MASK))
  {
    val_print(ACS_PRINT_ERR,
              " RHCQWS: RMECDA_CTL1 not set for BDF 0x%x",
              (uint64_t)root_port->bdf);
    status = ACS_STATUS_FAIL;
    goto cleanup;
  }
  ctl1_valid = 1u;

  status = run_partial_write_test(&context);

cleanup:
  if (ctl1_valid != 0u)
  {
    (void)write_from_root(cfg_va + rmecda_cap_base + RMECDA_CTL1_OFFSET,
                          ctl1_original);
  }

  /* Restore decoder programming and close the session. */
  restore_decoders(&context);
  if (session_active != 0u)
    (void)val_spdm_session_close(&ctx, session_id);

  return status;
}

static void
payload(void)
{
  /* Walk all CXL components and validate host-side MPE behavior. */
  uint32_t pe_index = val_pe_get_index_mpid(val_pe_get_mpid());
  CXL_COMPONENT_TABLE *table = val_cxl_component_table_ptr();
  uint32_t scanned = 0u;
  uint32_t candidates = 0u;
  uint32_t failures = 0u;
  uint32_t skipped = 0u;

  if ((table == NULL) || (table->num_entries == 0u))
  {
    val_print(ACS_PRINT_DEBUG, " RHCQWS: No CXL components discovered", 0);
    val_set_status(pe_index, "SKIP", 01);
    return;
  }

  /* Track which root ports expose Type-3 endpoints and host-side encryption. */
  for (uint32_t index = 0u; index < table->num_entries; ++index)
  {
    uint32_t type3_found = 0u;
    uint32_t candidate_found = 0u;
    uint32_t status;

    status = exercise_root_port(table, index, &type3_found, &candidate_found);
    if (type3_found != 0u)
      scanned++;
    if (candidate_found != 0u)
      candidates++;

    if (candidate_found == 0u)
      continue;

    if (status == ACS_STATUS_PASS)
      continue;
    if (status == ACS_STATUS_SKIP)
      skipped++;
    else
      failures++;
  }

  if (scanned == 0u)
  {
    val_print(ACS_PRINT_DEBUG, " RHCQWS: No Type-3 devices discovered", 0);
    val_set_status(pe_index, "SKIP", 02);
    return;
  }

  /* Skip if no initiator-based encryption devices are present. */
  if (candidates == 0u)
  {
    val_print(ACS_PRINT_DEBUG,
              " RHCQWS: No initiator-based encryption devices",
              0);
    val_set_status(pe_index, "SKIP", 03);
    return;
  }

  if (failures != 0u)
    val_set_status(pe_index, "FAIL", failures);
  else if (skipped == candidates)
    val_set_status(pe_index, "SKIP", 04);
  else
    val_set_status(pe_index, "PASS", 01);
}
#else
static void
payload(void)
{
  uint32_t pe_index = val_pe_get_index_mpid(val_pe_get_mpid());

  val_print(ACS_PRINT_WARN, " SPDM support disabled - skipping RHCQWS", 0);
  val_set_status(pe_index, "SKIP", 05);
}
#endif

uint32_t
cxl_rhcqws_host_side_mpe_entry(uint32_t num_pe)
{
  num_pe = 1;
  uint32_t status;

  status = val_initialize_test(TEST_NAME, TEST_DESC, num_pe, TEST_RULE);

  if (status != ACS_STATUS_SKIP)
    val_run_test_payload(num_pe, payload, 0);

  status = val_check_for_error(num_pe);

  val_report_status(0, "END");

  return status;
}
