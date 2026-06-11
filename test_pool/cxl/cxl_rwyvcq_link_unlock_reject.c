/** @file
 * Copyright (c) 2026, Arm Limited or its affiliates. All rights reserved.
 * SPDX-License-Identifier : Apache-2.0

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
#include "val/include/val_pcie_spec.h"
#include "val/include/val_memory.h"
#include "val/include/val_pe.h"
#include "val/include/val_el32.h"

#define TEST_NAME "cxl_rwyvcq_link_unlock_reject"
#define TEST_DESC "Unlocked CXL link rejects Realm PAS host requests    "
#define TEST_RULE "RWYVCQ"

#define DECODER_SLOT        0u
#define ALIGNMENT_MASK      ((1ULL << 28) - 1ULL)
#define AER_POISONED_TLP    (1u << 12)
#define PCIE_LNKCAP_OFFSET  0x0Cu
#define PCIE_LNKCAP_PN_SHIFT 24u
#define PCIE_LNKCAP_PN_MASK  0xFFu

typedef struct {
  uint32_t host_index;
  uint64_t window_base;
  uint64_t window_size;
  uint32_t root_index;
  uint32_t endpoint_index;
  uint32_t endpoint_bdf;
  uint64_t host_decoder_base_orig;
  uint64_t host_decoder_size_orig;
  uint64_t endpoint_decoder_base_orig;
  uint64_t endpoint_decoder_size_orig;
  uint32_t host_target_low_orig;
  uint32_t host_target_high_orig;
  uint32_t host_target_valid;
} CONTEXT;

/* Wrapper for Root/EL3 accesses to config space. */
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
    val_print(ACS_PRINT_ERR, " MUT read failed for 0x%llx", address);
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
    val_print(ACS_PRINT_ERR, " MUT write failed for 0x%llx", address);
    return ACS_STATUS_ERR;
  }

  return ACS_STATUS_PASS;
}

static uint32_t
find_configuration(CONTEXT *context)
{
  /* Locate a CXL root port with an aligned, non-empty CFMWS window. */
  uint32_t host_count;
  uint32_t component_count;
  uint64_t host_comp_base;

  if (context == NULL)
    return ACS_STATUS_ERR;

  val_memory_set(context, sizeof(*context), 0);
  context->host_index = CXL_COMPONENT_INVALID_INDEX;
  context->root_index = CXL_COMPONENT_INVALID_INDEX;
  context->endpoint_index = CXL_COMPONENT_INVALID_INDEX;
  context->endpoint_bdf = 0u;

  host_count = (uint32_t)val_cxl_get_info(CXL_INFO_NUM_DEVICES, 0);
  component_count =
    (uint32_t)val_cxl_get_component_info(CXL_COMPONENT_INFO_COUNT, 0);

  if ((host_count == 0u) || (component_count == 0u))
  {
    val_print(ACS_PRINT_DEBUG, " RWYVCQ: insufficient CXL discovery data", 0);
    return ACS_STATUS_SKIP;
  }

  for (uint32_t component_index = 0;
       component_index < component_count;
       ++component_index)
  {
    uint32_t role =
      (uint32_t)val_cxl_get_component_info(CXL_COMPONENT_INFO_ROLE,
                                           component_index);
    uint32_t endpoint_index;
    uint32_t host_index;
    uint32_t status;
    uint64_t endpoint_comp_base;

    if (role != CXL_COMPONENT_ROLE_ROOT_PORT)
      continue;

    status = val_cxl_find_downstream_endpoint(component_index, &endpoint_index);
    if (status != ACS_STATUS_PASS)
      continue;

    host_index =
      (uint32_t)val_cxl_get_component_info(CXL_COMPONENT_INFO_HOST_BRIDGE_INDEX,
                                           component_index);
    if (host_index >= host_count)
      continue;

    host_comp_base = val_cxl_get_info(CXL_INFO_COMPONENT_BASE, host_index);
    if ((host_comp_base == 0u) ||
      (val_cxl_find_capability(host_comp_base,
                               CXL_CAPID_HDM_DECODER,
                               NULL) != ACS_STATUS_PASS))
      continue;

    endpoint_comp_base = val_cxl_get_component_info(
      CXL_COMPONENT_INFO_COMPONENT_BASE, endpoint_index);
    if ((endpoint_comp_base == 0u) ||
        (val_cxl_find_capability(endpoint_comp_base,
                                 CXL_CAPID_HDM_DECODER,
                                 NULL) != ACS_STATUS_PASS))
      continue;

    status = val_cxl_select_cfmws_window(host_index,
                                         &context->window_base,
                                         &context->window_size);
    if (status != ACS_STATUS_PASS)
      continue;

    context->host_index = host_index;
    context->root_index = component_index;
    context->endpoint_index = endpoint_index;
    context->endpoint_bdf = (uint32_t)val_cxl_get_component_info(
      CXL_COMPONENT_INFO_BDF_INDEX, endpoint_index);
    return ACS_STATUS_PASS;
  }

  return ACS_STATUS_SKIP;
}

static uint32_t
map_window_alias(uint64_t phys,
                        uint32_t pas,
                        volatile uint64_t **virt_out)
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
                     GET_ATTR_INDEX(DEV_MEM_nGnRnE) |
                     PGT_ENTRY_AP_RW |
                     PAS_ATTR(pas));

  if (val_add_mmu_entry_el3(va, phys, attr))
    return ACS_STATUS_ERR;

  *virt_out = (volatile uint64_t *)va;
  return ACS_STATUS_PASS;
}

static void
restore_decoders(const CONTEXT *context)
{
  if (context == NULL)
    return;

  if ((context->host_index != CXL_COMPONENT_INVALID_INDEX) &&
      (context->host_decoder_size_orig != 0u))
    (void)val_cxl_program_host_decoder(context->host_index,
                                       DECODER_SLOT,
                                       context->host_decoder_base_orig,
                                       context->host_decoder_size_orig);
  if ((context->host_index != CXL_COMPONENT_INVALID_INDEX) &&
      (context->host_target_valid != 0u))
  {
    uint64_t host_comp_base = val_cxl_get_info(CXL_INFO_COMPONENT_BASE,
                                               context->host_index);
    uint64_t cap_base;

    if ((host_comp_base != 0u) &&
        (val_cxl_find_capability(host_comp_base,
                                 CXL_CAPID_HDM_DECODER,
                                 &cap_base) == ACS_STATUS_PASS))
    {
      val_mmio_write(cap_base +
                     CXL_HDM_DECODER_TARGET_LOW(DECODER_SLOT),
                     context->host_target_low_orig);
      val_mmio_write(cap_base +
                     CXL_HDM_DECODER_TARGET_HIGH(DECODER_SLOT),
                     context->host_target_high_orig);
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

  if (val_pcie_find_capability(bdf, PCIE_CAP, CID_PCIECS, &pcie_cap_offset) != 0u)
  {
    val_print(ACS_PRINT_ERR, " RWYVCQ: PCIe cap not found", 0);
    return ACS_STATUS_ERR;
  }

  if (val_pcie_read_cfg(bdf, pcie_cap_offset + PCIE_LNKCAP_OFFSET, &lnkcap) != 0u)
  {
    val_print(ACS_PRINT_ERR, " RWYVCQ: LNKCAP read failed", 0);
    return ACS_STATUS_ERR;
  }

  port_id = (lnkcap >> PCIE_LNKCAP_PN_SHIFT) & PCIE_LNKCAP_PN_MASK;

  if (val_cxl_find_capability(comp_base, CXL_CAPID_HDM_DECODER, &hdm_cap_base)
      != ACS_STATUS_PASS)
  {
    val_print(ACS_PRINT_ERR, " RWYVCQ: Host HDM cap missing", 0);
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

static void
payload(void)
{
  uint32_t pe_index = val_pe_get_index_mpid(val_pe_get_mpid());
  CONTEXT context;
  uint32_t status;
  uint32_t result = ACS_STATUS_FAIL;
  uint32_t root_bdf = 0;
  uint64_t cfg_addr = 0;
  uint64_t cfg_va = 0;
  uint32_t attr;
  uint64_t tg;
  uint32_t rmecda_cap_base = 0;
  uint32_t rmecda_ctl1_original = 0;
  uint32_t rmecda_ctl1_unlocked = 0;
  volatile uint64_t *realm_ptr = NULL;
  volatile uint64_t *ns_ptr = NULL;
  volatile uint32_t *ns_ptr32 = NULL;
  uint32_t baseline_value = 0;
  uint32_t realm_pattern = 0;
  uint32_t control_pattern = 0;
  uint32_t aer_offset = 0;
  uint32_t aer_uncorr = 0;
  uint32_t control_readback = 0;
  uint64_t endpoint_base = 0u;
  uint64_t endpoint_size = 0u;

  val_memory_set(&context, sizeof(context), 0);

  /* Discover a CXL host/root/endpoint with a suitable CFMWS window. */
  status = find_configuration(&context);
  if (status == ACS_STATUS_SKIP)
  {
    val_print(ACS_PRINT_TEST, " RWYVCQ: no suitable host/root/endpoint found", 0);
    val_set_status(pe_index, "SKIP", 01);
    return;
  }
  if (status != ACS_STATUS_PASS)
  {
    val_set_status(pe_index, "FAIL", 01);
    return;
  }

  /* locate RMECDA DVSEC and AER capability on the root port. */
  root_bdf =
    (uint32_t)val_cxl_get_component_info(CXL_COMPONENT_INFO_BDF_INDEX,
                                         context.root_index);
  if (root_bdf == 0u)
  {
    val_set_status(pe_index, "FAIL", 02);
    return;
  }

  if (val_pcie_find_vendor_dvsec(root_bdf,
                                 ARM_RME_VENDOR_ID,
                                 RMECDA_HEAD2_DVSEC_ID,
                                 &rmecda_cap_base) != PCIE_SUCCESS)
  {
    val_print(ACS_PRINT_TEST,
              " RWYVCQ: RMECDA DVSEC absent on RP 0x%x", root_bdf);
    val_set_status(pe_index, "SKIP", 02);
    return;
  }

  if (val_pcie_find_capability(root_bdf,
                               PCIE_ECAP,
                               ECID_AER,
                               &aer_offset) != PCIE_SUCCESS)
  {
    val_print(ACS_PRINT_TEST,
              " RWYVCQ: AER capability absent on RP 0x%x", root_bdf);
    val_set_status(pe_index, "SKIP", 03);
    return;
  }

  /* Capture current decoder state for cleanup. */
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

  /* Enable CXL.mem before programming HDM decoders. */
  if (val_cxl_enable_mem(context.endpoint_bdf) != ACS_STATUS_PASS)
  {
    val_print(ACS_PRINT_ERR, " RWYVCQ: Failed to enable CXL.mem", 0);
    val_set_status(pe_index, "FAIL", 03);
    goto restore;
  }

  /* Program host decoder to target the chosen CFMWS window. */
  status = val_cxl_program_host_decoder(context.host_index,
                                        DECODER_SLOT,
                                        context.window_base,
                                        context.window_size);
  if (status == ACS_STATUS_SKIP)
  {
    val_print(ACS_PRINT_TEST,
              " RWYVCQ: host decoder programming skipped", 0);
    val_set_status(pe_index, "SKIP", 04);
    return;
  }
  if (status != ACS_STATUS_PASS)
  {
    val_set_status(pe_index, "FAIL", 03);
    goto restore;
  }

  /* Program the host target list to include the root port. */
  if (program_host_target_list(root_bdf,
                               val_cxl_get_info(CXL_INFO_COMPONENT_BASE,
                                                context.host_index),
                               DECODER_SLOT,
                               &context) != ACS_STATUS_PASS)
  {
    val_set_status(pe_index, "FAIL", 03);
    goto restore;
  }

  endpoint_base = context.endpoint_decoder_base_orig;
  endpoint_size = context.endpoint_decoder_size_orig;
  if (endpoint_size == 0u)
    endpoint_size = context.window_size;

  if ((endpoint_base == 0u) || ((endpoint_base & ALIGNMENT_MASK) != 0u))
    endpoint_base = context.window_base;
  if (endpoint_size == 0u)
    endpoint_size = context.window_size;

  status = val_cxl_program_component_decoder(context.endpoint_index,
                                             DECODER_SLOT,
                                             endpoint_base,
                                             endpoint_size);
  if (status == ACS_STATUS_SKIP)
  {
    val_print(ACS_PRINT_TEST,
              " RWYVCQ: endpoint decoder programming skipped", 0);
    val_set_status(pe_index, "SKIP", 05);
    goto restore;
  }
  if (status != ACS_STATUS_PASS)
  {
    val_set_status(pe_index, "FAIL", 04);
    goto restore;
  }

  /* Map root port config space with Root PAS. */
  cfg_addr = val_pcie_get_bdf_config_addr(root_bdf);
  tg = val_get_min_tg();
  if ((cfg_addr == 0u) || (tg == 0u))
  {
    val_set_status(pe_index, "FAIL", 05);
    goto restore;
  }

  cfg_va = val_get_free_va(tg);
  if (cfg_va == 0u)
  {
    val_set_status(pe_index, "FAIL", 06);
    goto restore;
  }

  attr = LOWER_ATTRS(PGT_ENTRY_ACCESS | SHAREABLE_ATTR(OUTER_SHAREABLE) |
                     GET_ATTR_INDEX(DEV_MEM_nGnRnE) | PGT_ENTRY_AP_RW |
                     PAS_ATTR(ROOT_PAS));
  if (val_add_mmu_entry_el3(cfg_va, cfg_addr, attr))
  {
    val_set_status(pe_index, "FAIL", 07);
    goto restore;
  }

  /* Read RMECDA_CTL.LINK_STR_LOCK state before unlocking. */
  if (read_from_root(cfg_va + rmecda_cap_base + RMECDA_CTL1_OFFSET,
                     &rmecda_ctl1_original) != ACS_STATUS_PASS)
  {
    val_set_status(pe_index, "FAIL", 8);
    goto restore;
  }

  if (map_window_alias(context.window_base,
                              REALM_PAS,
                              &realm_ptr) != ACS_STATUS_PASS)
  {
    val_set_status(pe_index, "FAIL", 9);
    goto restore;
  }

  if (map_window_alias(context.window_base,
                              NONSECURE_PAS,
                              &ns_ptr) != ACS_STATUS_PASS)
  {
    val_set_status(pe_index, "FAIL", 10);
    goto restore;
  }

  /* Unlock the link in RMECDA_CTL2 and confirm the control bit clears. */
  ns_ptr32 = (volatile uint32_t *)ns_ptr;
  baseline_value = *ns_ptr32;
  realm_pattern = baseline_value ^ 0xA5A5A5A5UL;
  if (realm_pattern == baseline_value)
    realm_pattern ^= 0x1U;

  rmecda_ctl1_unlocked = rmecda_ctl1_original & ~(1u << 1);
  if (write_from_root(cfg_va + rmecda_cap_base + RMECDA_CTL1_OFFSET,
                      rmecda_ctl1_unlocked) != ACS_STATUS_PASS)
  {
    val_set_status(pe_index, "FAIL", 11);
    goto restore;
  }

  if (read_from_root(cfg_va + rmecda_cap_base + RMECDA_CTL1_OFFSET,
                     &control_readback) != ACS_STATUS_PASS ||
      ((control_readback & (1u << 1)) != 0u))
  {
    val_set_status(pe_index, "FAIL", 11);
    goto restore;
  }

  val_cxl_aer_clear(root_bdf, aer_offset);

  shared_data->exception_expected = CLEAR;
  shared_data->num_access = 1;
  shared_data->shared_data_access[0].addr = (uint64_t)realm_ptr;
  shared_data->shared_data_access[0].data = realm_pattern;
  shared_data->shared_data_access[0].access_type = WRITE_DATA;

  if (val_pe_access_mut_el3())
  {
    val_set_status(pe_index, "FAIL", 12);
    goto restore;
  }

  if (*ns_ptr32 != baseline_value)
  {
    val_print(ACS_PRINT_ERR,
              " RWYVCQ: Realm write propagated (value 0x%x)",
              *ns_ptr32);
    val_set_status(pe_index, "FAIL", 13);
    goto restore;
  }

  /* Attempt Realm read and confirm Poisoned TLP logged. */
  shared_data->exception_expected = CLEAR;
  shared_data->num_access = 1;
  shared_data->shared_data_access[0].addr = (uint64_t)realm_ptr;
  shared_data->shared_data_access[0].access_type = READ_DATA;

  if (val_pe_access_mut_el3())
  {
    val_set_status(pe_index, "FAIL", 14);
    goto restore;
  }

  val_cxl_aer_read_uncorr(root_bdf,
                          aer_offset,
                          &aer_uncorr);
  if ((aer_uncorr & AER_POISONED_TLP) == 0u)
  {
    val_print(ACS_PRINT_ERR,
              " RWYVCQ: Poisoned TLP not logged (uncorr 0x%llx)",
              (uint64_t)aer_uncorr);
    val_set_status(pe_index, "FAIL", 15);
    goto restore;
  }

  val_cxl_aer_clear(root_bdf, aer_offset);

  control_pattern = baseline_value ^ 0x5A5A5A5AUL;
  shared_data->exception_expected = CLEAR;
  shared_data->num_access = 2;
  shared_data->shared_data_access[0].addr = (uint64_t)ns_ptr;
  shared_data->shared_data_access[0].data = control_pattern;
  shared_data->shared_data_access[0].access_type = WRITE_DATA;
  shared_data->shared_data_access[1].addr = (uint64_t)ns_ptr;
  shared_data->shared_data_access[1].access_type = READ_DATA;

  if (val_pe_access_mut_el3())
  {
    val_set_status(pe_index, "FAIL", 16);
    goto restore;
  }

  if (shared_data->shared_data_access[1].data != control_pattern)
  {
    val_print(ACS_PRINT_ERR,
              " RWYVCQ: Non-secure write failed (read 0x%llx)",
              shared_data->shared_data_access[1].data);
    val_set_status(pe_index, "FAIL", 17);
    goto restore;
  }

  val_cxl_aer_read_uncorr(root_bdf,
                          aer_offset,
                          &aer_uncorr);
  if (aer_uncorr != 0u)
  {
    val_print(ACS_PRINT_ERR,
              " RWYVCQ: Unexpected AER errors after NS traffic (0x%llx)",
              (uint64_t)aer_uncorr);
    val_set_status(pe_index, "FAIL", 18);
    goto restore;
  }

  result = ACS_STATUS_PASS;

restore:
  (void)write_from_root(cfg_va + rmecda_cap_base + RMECDA_CTL1_OFFSET,
                        rmecda_ctl1_original);
  restore_decoders(&context);

  if (result == ACS_STATUS_PASS)
    val_set_status(pe_index, "PASS", 01);
}

uint32_t
cxl_rwyvcq_link_unlock_reject_entry(uint32_t num_pe)
{
  num_pe = 1;
  uint32_t status = ACS_STATUS_FAIL;

  status = val_initialize_test(TEST_NAME, TEST_DESC, num_pe, TEST_RULE);

  if (status != ACS_STATUS_SKIP)
    val_run_test_payload(num_pe, payload, 0);

  status = val_check_for_error(num_pe);

  val_report_status(0, "END");

  return status;
}
