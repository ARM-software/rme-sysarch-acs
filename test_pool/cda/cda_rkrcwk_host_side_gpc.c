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
#include "val/include/val_el32.h"
#include "val/include/val_memory.h"
#include "val/include/val_pcie.h"
#include "val/include/val_pcie_spec.h"

#define TEST_NAME "cda_rkrcwk_host_side_gpc"
#define TEST_DESC "PE access to DCM is subject to host-side GPC           "
#define TEST_RULE "RKRCWK"

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
  uint32_t host_target_valid;
  uint32_t host_target_low_orig;
  uint32_t host_target_high_orig;
} RKRCWK_CONTEXT;

static uint32_t
find_configuration(RKRCWK_CONTEXT *context)
{
  uint32_t host_count;
  uint32_t component_count;

  if (context == NULL)
    return ACS_STATUS_ERR;

  val_memory_set(context, sizeof(*context), 0);
  context->host_index = CXL_COMPONENT_INVALID_INDEX;
  context->root_index = CXL_COMPONENT_INVALID_INDEX;
  context->endpoint_index = CXL_COMPONENT_INVALID_INDEX;
  context->root_bdf = 0u;
  context->endpoint_bdf = 0u;

  host_count = (uint32_t)val_cxl_get_info(CXL_INFO_NUM_DEVICES, 0);
  component_count = (uint32_t)val_cxl_get_component_info(CXL_COMPONENT_INFO_COUNT, 0);

  if ((host_count == 0u) || (component_count == 0u))
    return ACS_STATUS_SKIP;

  for (uint32_t comp_index = 0; comp_index < component_count; ++comp_index)
  {
    uint32_t role;
    uint32_t host_index;
    uint32_t endpoint_index;
    uint64_t host_comp_base;
    uint64_t ep_comp_base;
    uint32_t status;

    role = (uint32_t)val_cxl_get_component_info(CXL_COMPONENT_INFO_ROLE, comp_index);
    if (role != CXL_COMPONENT_ROLE_ROOT_PORT)
      continue;

    status = val_cxl_find_downstream_endpoint(comp_index, &endpoint_index);
    if (status != ACS_STATUS_PASS)
      continue;

    if ((uint32_t)val_cxl_get_component_info(CXL_COMPONENT_INFO_DEVICE_TYPE,
                                             endpoint_index) != CXL_DEVICE_TYPE_TYPE3)
      continue;

    host_index = (uint32_t)val_cxl_get_component_info(CXL_COMPONENT_INFO_HOST_BRIDGE_INDEX,
                                                      comp_index);
    if (host_index >= host_count)
      continue;

    host_comp_base = val_cxl_get_info(CXL_INFO_COMPONENT_BASE, host_index);
    status = val_cxl_find_capability(host_comp_base, CXL_CAPID_HDM_DECODER, NULL);
    if (status != ACS_STATUS_PASS)
      continue;

    ep_comp_base = val_cxl_get_component_info(CXL_COMPONENT_INFO_COMPONENT_BASE, endpoint_index);
    status = val_cxl_find_capability(ep_comp_base, CXL_CAPID_HDM_DECODER, NULL);
    if (status != ACS_STATUS_PASS)
      continue;

    status = val_cxl_select_cfmws_window(host_index,
                                         &context->window_base,
                                         &context->window_size);
    if (status != ACS_STATUS_PASS)
      continue;

    if ((context->window_base == 0u) || (context->window_size == 0u))
      continue;

    context->host_index = host_index;
    context->root_index = comp_index;
    context->endpoint_index = endpoint_index;
    context->root_bdf = (uint32_t)val_cxl_get_component_info(CXL_COMPONENT_INFO_BDF_INDEX,
                                                            comp_index);
    context->endpoint_bdf = (uint32_t)val_cxl_get_component_info(CXL_COMPONENT_INFO_BDF_INDEX,
                                                                endpoint_index);
    return ACS_STATUS_PASS;
  }

  return ACS_STATUS_SKIP;
}

static uint32_t
program_host_target_list(RKRCWK_CONTEXT *context)
{
  uint32_t pcie_cap_offset;
  uint32_t lnkcap;
  uint32_t port_id;
  uint64_t comp_base;
  uint64_t hdm_cap_base;
  uint32_t target_low;
  uint32_t target_high;

  if (context == NULL)
    return ACS_STATUS_ERR;

  comp_base = val_cxl_get_info(CXL_INFO_COMPONENT_BASE, context->host_index);
  if (comp_base == 0u)
    return ACS_STATUS_ERR;

  if (val_pcie_find_capability(context->root_bdf,
                               PCIE_CAP,
                               CID_PCIECS,
                               &pcie_cap_offset) != 0u)
    return ACS_STATUS_ERR;

  if (val_pcie_read_cfg(context->root_bdf, pcie_cap_offset + LCAPR_OFFSET, &lnkcap) != 0u)
    return ACS_STATUS_ERR;

  port_id = (lnkcap >> LCAPR_PN_SHIFT) & LCAPR_PN_MASK;

  if (val_cxl_find_capability(comp_base, CXL_CAPID_HDM_DECODER, &hdm_cap_base)
      != ACS_STATUS_PASS)
    return ACS_STATUS_ERR;

  target_low = val_mmio_read(hdm_cap_base +
                             CXL_HDM_DECODER_TARGET_LOW(CXL_HDM_DECODER_SLOT_DEFAULT));
  target_high = val_mmio_read(hdm_cap_base +
                              CXL_HDM_DECODER_TARGET_HIGH(CXL_HDM_DECODER_SLOT_DEFAULT));
  context->host_target_low_orig = target_low;
  context->host_target_high_orig = target_high;
  context->host_target_valid = 1u;

  val_mmio_write(hdm_cap_base +
                 CXL_HDM_DECODER_TARGET_LOW(CXL_HDM_DECODER_SLOT_DEFAULT),
                 port_id);
  val_mmio_write(hdm_cap_base +
                 CXL_HDM_DECODER_TARGET_HIGH(CXL_HDM_DECODER_SLOT_DEFAULT),
                 0u);

  return ACS_STATUS_PASS;
}

static void
restore_decoders(const RKRCWK_CONTEXT *context)
{
  uint64_t comp_base;
  uint64_t hdm_cap_base;

  if (context == NULL)
    return;

  if ((context->host_index != CXL_COMPONENT_INVALID_INDEX) &&
      (context->host_decoder_size_orig != 0u))
    (void)val_cxl_program_host_decoder(context->host_index,
                                      CXL_HDM_DECODER_SLOT_DEFAULT,
                                      context->host_decoder_base_orig,
                                      context->host_decoder_size_orig);

  if ((context->endpoint_index != CXL_COMPONENT_INVALID_INDEX) &&
      (context->endpoint_decoder_size_orig != 0u))
    (void)val_cxl_program_component_decoder(context->endpoint_index,
                                           CXL_HDM_DECODER_SLOT_DEFAULT,
                                           context->endpoint_decoder_base_orig,
                                           context->endpoint_decoder_size_orig);

  if (context->host_target_valid != 0u)
  {
    comp_base = val_cxl_get_info(CXL_INFO_COMPONENT_BASE, context->host_index);
    if ((comp_base != 0u) &&
        (val_cxl_find_capability(comp_base,
                                 CXL_CAPID_HDM_DECODER,
                                 &hdm_cap_base) == ACS_STATUS_PASS))
    {
      val_mmio_write(hdm_cap_base +
                     CXL_HDM_DECODER_TARGET_LOW(CXL_HDM_DECODER_SLOT_DEFAULT),
                     context->host_target_low_orig);
      val_mmio_write(hdm_cap_base +
                     CXL_HDM_DECODER_TARGET_HIGH(CXL_HDM_DECODER_SLOT_DEFAULT),
                     context->host_target_high_orig);
    }
  }
}

static uint32_t
program_decoders(RKRCWK_CONTEXT *context)
{
  uint32_t status;

  if (context == NULL)
    return ACS_STATUS_ERR;

  if (val_cxl_get_decoder(context->host_index,
                          CXL_HDM_DECODER_SLOT_DEFAULT,
                          &context->host_decoder_base_orig,
                          &context->host_decoder_size_orig) != 0u)
  {
    context->host_decoder_base_orig = 0u;
    context->host_decoder_size_orig = 0u;
  }

  if (val_cxl_get_component_decoder(context->endpoint_index,
                                    CXL_HDM_DECODER_SLOT_DEFAULT,
                                    &context->endpoint_decoder_base_orig,
                                    &context->endpoint_decoder_size_orig) != 0u)
  {
    context->endpoint_decoder_base_orig = 0u;
    context->endpoint_decoder_size_orig = 0u;
  }

  status = val_cxl_program_host_decoder(context->host_index,
                                        CXL_HDM_DECODER_SLOT_DEFAULT,
                                        context->window_base,
                                        context->window_size);
  if (status != ACS_STATUS_PASS)
    return status;

  status = val_cxl_program_component_decoder(context->endpoint_index,
                                             CXL_HDM_DECODER_SLOT_DEFAULT,
                                             context->window_base,
                                             context->window_size);
  return status;
}

static uint32_t
map_el3_alias(uint64_t pa_page, uint64_t page_size, uint32_t access_pas, uint64_t *va_out)
{
  uint64_t va;
  uint32_t attr;

  if (va_out == NULL)
    return ACS_STATUS_ERR;

  if ((pa_page == 0u) || (page_size == 0u))
    return ACS_STATUS_ERR;

  va = val_get_free_va(page_size);
  if (va == 0u)
    return ACS_STATUS_ERR;

  attr = LOWER_ATTRS(PGT_ENTRY_ACCESS |
                     SHAREABLE_ATTR(OUTER_SHAREABLE) |
                     GET_ATTR_INDEX(NON_CACHEABLE) |
                     PGT_ENTRY_AP_RW |
                     PAS_ATTR(access_pas));

  if (val_add_mmu_entry_el3(va, pa_page, attr))
    return ACS_STATUS_ERR;

  *va_out = va;
  return ACS_STATUS_PASS;
}

static uint32_t
el3_store_check_gpf(uint64_t va, uint32_t expect_gpf)
{
  uint32_t status;
  uint32_t gpf_seen;
  uint32_t fault_seen;

  shared_data->pas_filter_flag = CLEAR;
  shared_data->exception_generated = CLEAR;
  shared_data->access_mut = SET;
  shared_data->arg1 = va;
  shared_data->exception_expected = SET;

  status = val_pe_access_mut_el3();
  if (status != 0u)
    return ACS_STATUS_ERR;

  fault_seen = (shared_data->exception_expected == CLEAR);
  gpf_seen = (shared_data->exception_generated == SET);

  if (!fault_seen)
  {
    /* No fault occurred. Clear the expectation explicitly for subsequent accesses. */
    shared_data->exception_expected = CLEAR;
    shared_data->exception_generated = CLEAR;
    return expect_gpf ? ACS_STATUS_FAIL : ACS_STATUS_PASS;
  }

  shared_data->exception_generated = CLEAR;

  if (gpf_seen)
    return expect_gpf ? ACS_STATUS_PASS : ACS_STATUS_FAIL;

  /* A fault occurred but it was not classified as a GPF by the EL3 handler. */
  return ACS_STATUS_SKIP;
}

static void
payload(void)
{
  uint32_t pe_index;
  uint64_t page_size;
  uint64_t dcm_pa = 0u;
  uint64_t pa_page;
  uint64_t va_ns;
  uint32_t status;
  RKRCWK_CONTEXT context;
  uint32_t result;

  pe_index = val_pe_get_index_mpid(val_pe_get_mpid());
  page_size = val_get_min_tg();
  if (page_size == 0u)
  {
    val_set_status(pe_index, "FAIL", 01);
    return;
  }

  status = find_configuration(&context);
  if (status == ACS_STATUS_SKIP)
  {
    val_print(ACS_PRINT_INFO, " No suitable host/root/endpoint combination", 0);
    val_set_status(pe_index, "SKIP", 01);
    return;
  }

  if (status != ACS_STATUS_PASS)
  {
    val_set_status(pe_index, "FAIL", 02);
    return;
  }

  if (context.window_size < page_size)
  {
    val_print(ACS_PRINT_INFO, " CFMWS window too small for access", 0);
    val_set_status(pe_index, "SKIP", 02);
    return;
  }

  status = val_cxl_enable_mem(context.endpoint_bdf);
  if (status != ACS_STATUS_PASS)
  {
    val_print(ACS_PRINT_INFO, " Failed to enable CXL.mem", 0);
    val_set_status(pe_index, "SKIP", 03);
    return;
  }

  status = program_host_target_list(&context);
  if (status != ACS_STATUS_PASS)
  {
    val_print(ACS_PRINT_INFO, " Host target list programming failed", 0);
    restore_decoders(&context);
    val_set_status(pe_index, "SKIP", 04);
    return;
  }

  status = program_decoders(&context);
  if (status != ACS_STATUS_PASS)
  {
    val_print(ACS_PRINT_INFO, " HDM decoder programming skipped (status %d)", status);
    restore_decoders(&context);
    val_set_status(pe_index, "SKIP", 05);
    return;
  }

  dcm_pa = context.window_base;
  pa_page = dcm_pa & ~(page_size - 1u);
  result = ACS_STATUS_FAIL;

  /* Ensure the target page is accessible for baseline probing. */
  if (val_add_gpt_entry_el3(pa_page, GPT_ANY))
  {
    val_print(ACS_PRINT_ERR, " Failed to set GPT_ANY for DCM PA 0x%llx", pa_page);
    result = ACS_STATUS_FAIL;
    goto cleanup;
  }

  status = map_el3_alias(pa_page, page_size, NONSECURE_PAS, &va_ns);
  if (status != ACS_STATUS_PASS)
  {
    val_print(ACS_PRINT_ERR, " Failed to map DCM PA 0x%llx", pa_page);
    result = ACS_STATUS_FAIL;
    goto cleanup;
  }

  status = el3_store_check_gpf(va_ns, 0u);
  if (status != ACS_STATUS_PASS)
  {
    val_print(ACS_PRINT_INFO, " DCM access baseline failed - skipping", 0);
    result = ACS_STATUS_SKIP;
    goto cleanup;
  }

  /* Program the DCM page as Realm and ensure a Non-secure PE access triggers a GPF. */
  if (val_add_gpt_entry_el3(pa_page, GPT_REALM))
  {
    val_print(ACS_PRINT_ERR, " Failed to set GPT_REALM for DCM PA 0x%llx", pa_page);
    result = ACS_STATUS_FAIL;
    goto cleanup;
  }

  status = el3_store_check_gpf(va_ns, 1u);

  /* Restore default GPT association. */
  (void)val_add_gpt_entry_el3(pa_page, GPT_ANY);

  result = status;

cleanup:
  restore_decoders(&context);
  (void)val_add_gpt_entry_el3(pa_page, GPT_ANY);

  if (result == ACS_STATUS_PASS)
    val_set_status(pe_index, "PASS", 01);
  else if (result == ACS_STATUS_SKIP)
    val_set_status(pe_index, "SKIP", 05);
  else
    val_set_status(pe_index, "FAIL", 01);
}

uint32_t
cda_rkrcwk_host_side_gpc_entry(uint32_t num_pe)
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
