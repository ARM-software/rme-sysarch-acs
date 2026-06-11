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
#include "val/include/val_memory.h"
#include "val/include/val_pe.h"
#include "val/include/val_pgt.h"
#include "val/include/val_el32.h"

#define TEST_NAME "cxl_rhmxtf_host_hdm_decoder"
#define TEST_DESC "Validate host HDM decoder coverage for HPA access     "
#define TEST_RULE "RHMXTF"

#define DECODER_SLOT 0u
#define ALIGNMENT_MASK ((1ULL << 28) - 1ULL)

/* XOR pattern used to perturb test data without losing original bits. */
#define TEST_DATA_PATTERN 0xA5A5A5A5A5A5A5A5ULL

typedef struct {
  uint32_t host_index;
  uint64_t base;
  uint64_t size;
  uint32_t root_index;
  uint32_t endpoint_index;
  uint32_t endpoint_bdf;
  uint64_t host_decoder_base_orig;
  uint64_t host_decoder_size_orig;
  uint64_t endpoint_decoder_base_orig;
  uint64_t endpoint_decoder_size_orig;
} CONTEXT;

static uint32_t
map_window(uint64_t base,
                  uint64_t length,
                  volatile uint64_t **virt_out)
{
  memory_region_descriptor_t mem_desc[2];
  pgt_descriptor_t pgt_desc;
  uint64_t page_size;
  uint64_t range_end;
  uint64_t aligned_base;
  uint64_t aligned_length;
  uint64_t aligned_va;
  uint64_t ttbr;

  /* Validate inputs and fetch page size. */
  if ((base == 0u) || (length == 0u) || (virt_out == NULL))
    return ACS_STATUS_ERR;

  page_size = (uint64_t)val_memory_page_size();
  if (page_size == 0u)
    return ACS_STATUS_ERR;

  range_end = base + length;
  if (range_end < base)
    return ACS_STATUS_ERR;

  /* Align the physical range to page boundaries. */
  aligned_base = base & ~(page_size - 1u);

  uint64_t aligned_end = range_end + page_size - 1u;
  if (aligned_end < range_end)
    return ACS_STATUS_ERR;

  aligned_length = (aligned_end & ~(page_size - 1u)) - aligned_base;

  val_memory_set(mem_desc, sizeof(mem_desc), 0);

  /* Reserve a virtual address range for mapping. */
  aligned_va = val_get_free_va(aligned_length);
  if (aligned_va == 0u)
    return ACS_STATUS_ERR;

  mem_desc[0].virtual_address  = aligned_va;
  mem_desc[0].physical_address = aligned_base;
  mem_desc[0].length           = aligned_length;
  mem_desc[0].attributes = LOWER_ATTRS(PGT_ENTRY_ACCESS | SHAREABLE_ATTR(NON_SHAREABLE)
                | GET_ATTR_INDEX(NON_CACHEABLE) | PGT_ENTRY_AP_RW);

  /* Populate translation tables for the mapping. */
  if (val_pe_reg_read_tcr(0, &pgt_desc.tcr))
    return ACS_STATUS_ERR;

  if (val_pe_reg_read_ttbr(0, &ttbr))
    return ACS_STATUS_ERR;

  pgt_desc.pgt_base = (ttbr & AARCH64_TTBR_ADDR_MASK);
  pgt_desc.mair     = val_pe_reg_read(MAIR_ELx);
  pgt_desc.stage    = PGT_STAGE1;
  pgt_desc.ias      = 48;
  pgt_desc.oas      = 48;

  if (val_pgt_create(mem_desc, &pgt_desc))
    return ACS_STATUS_ERR;

  /* Return the mapped virtual address. */
  *virt_out = (volatile uint64_t *)(aligned_va + (base - aligned_base));
  return ACS_STATUS_PASS;
}

static uint32_t
find_configuration(CONTEXT *context)
{
  uint32_t host_count;
  uint32_t component_count;

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
    val_print(ACS_PRINT_DEBUG, " RHMXTF skip: insufficient CXL discovery data", 0);
    return ACS_STATUS_SKIP;
  }

  for (uint32_t comp_index = 0; comp_index < component_count; ++comp_index)
  {
    uint32_t role = (uint32_t)val_cxl_get_component_info(
      CXL_COMPONENT_INFO_ROLE, comp_index);
    uint32_t endpoint_index;
    uint32_t host_index;
    uint32_t status;
    uint64_t host_comp_base;
    uint64_t ep_comp_base;

    if (role != CXL_COMPONENT_ROLE_ROOT_PORT)
      continue;

    status = val_cxl_find_downstream_endpoint(comp_index, &endpoint_index);
    if (status != ACS_STATUS_PASS)
      continue;

    host_index = (uint32_t)val_cxl_get_component_info(CXL_COMPONENT_INFO_HOST_BRIDGE_INDEX,
                                                                                 comp_index);
    if (host_index >= host_count)
      continue;

    host_comp_base = val_cxl_get_info(CXL_INFO_COMPONENT_BASE, host_index);
    status = val_cxl_find_capability(host_comp_base,
                                                CXL_CAPID_HDM_DECODER,
                                                NULL);
    if (status != ACS_STATUS_PASS)
    {
        val_print(ACS_PRINT_DEBUG, " Host does not support HDM decoder, Skipping", 0);
        continue;
    }

    ep_comp_base = val_cxl_get_component_info(CXL_COMPONENT_INFO_COMPONENT_BASE,
                                              endpoint_index);
    status = val_cxl_find_capability(ep_comp_base,
                                                CXL_CAPID_HDM_DECODER,
                                                NULL);
    if (status != ACS_STATUS_PASS)
    {
        val_print(ACS_PRINT_DEBUG, " Endpoint does not support HDM decoder, Skipping", 0);
        continue;
    }

    status = val_cxl_select_cfmws_window(host_index,
                                         &context->base,
                                         &context->size);
    if (status != ACS_STATUS_PASS)
      continue;

    context->host_index = host_index;
    context->root_index = comp_index;
    context->endpoint_index = endpoint_index;
    context->endpoint_bdf = (uint32_t)val_cxl_get_component_info(
      CXL_COMPONENT_INFO_BDF_INDEX, endpoint_index);
    return ACS_STATUS_PASS;
  }

  return ACS_STATUS_SKIP;
}

static void
payload(void)
{
  uint32_t pe_index = val_pe_get_index_mpid(val_pe_get_mpid());
  CONTEXT context;
  uint32_t status;
  uint32_t result = ACS_STATUS_FAIL;
  uint64_t endpoint_base = 0;
  uint64_t endpoint_size = 0;
  volatile uint64_t *mapped = NULL;
  uint64_t original;
  uint64_t pattern;
  uint64_t readback;

  /* Locate a valid host/root/endpoint configuration. */
  status = find_configuration(&context);
  if (status == ACS_STATUS_SKIP)
  {
    val_print(ACS_PRINT_TEST, " No suitable host/root/endpoint combination", 0);
    val_set_status(pe_index, "SKIP", 01);
    return;
  }

  if (status != ACS_STATUS_PASS)
  {
    val_set_status(pe_index, "FAIL", 01);
    return;
  }

  /* Report the selected configuration. */
  val_print(ACS_PRINT_INFO, " RHMXTF Host Index        : %u",
            context.host_index);
  val_print(ACS_PRINT_INFO, " RHMXTF Window Base       : 0x%llx",
            (uint64_t)context.base);
  val_print(ACS_PRINT_INFO, " RHMXTF Window Size       : 0x%llx",
            (uint64_t)context.size);
  val_print(ACS_PRINT_INFO, " RHMXTF RootPort Index    : %u",
            context.root_index);
  val_print(ACS_PRINT_INFO, " RHMXTF Endpoint Index    : %u",
            context.endpoint_index);

  /* Enable CXL.mem access on the selected endpoint. */
  status = val_cxl_enable_mem(context.endpoint_bdf);
  if (status != ACS_STATUS_PASS)
  {
    val_print(ACS_PRINT_ERR, " Failed to enable CXL.mem", 0);
    val_set_status(pe_index, "FAIL", 02);
    return;
  }

  /* Program the host decoder for the HDM window. */
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
                                        context.base,
                                        context.size);
  if (status == ACS_STATUS_SKIP)
  {
    val_print(ACS_PRINT_DEBUG, " RHMXTF skip: host decoder programming skipped",
              0);
    val_set_status(pe_index, "SKIP", 03);
    goto cleanup;
  }

  if (status != ACS_STATUS_PASS)
  {
    val_print(ACS_PRINT_ERR, " Failed to program host decoder", 0);
    val_set_status(pe_index, "FAIL", 03);
    goto cleanup;
  }

  endpoint_base = context.endpoint_decoder_base_orig;
  endpoint_size = context.endpoint_decoder_size_orig;
  if (endpoint_size == 0u)
    endpoint_size = context.size;

  if ((endpoint_base & ALIGNMENT_MASK) != 0u)
    endpoint_base = 0u;
  if (endpoint_size == 0u)
    endpoint_size = context.size;

  /* Program the endpoint decoder for access checks. */
  status = val_cxl_program_component_decoder(context.endpoint_index,
                                             DECODER_SLOT,
                                             endpoint_base,
                                             endpoint_size);

  if (status == ACS_STATUS_SKIP)
  {
    val_print(ACS_PRINT_DEBUG,
              " RHMXTF skip: endpoint decoder programming skipped", 0);
    val_set_status(pe_index, "SKIP", 05);
    goto cleanup;
  }

  if (status != ACS_STATUS_PASS)
  {
    val_print(ACS_PRINT_ERR, " Failed to program endpoint decoder", 0);
    val_set_status(pe_index, "FAIL", 05);
    goto cleanup;
  }

  /* Map the window and perform load/store validation. */
  status = map_window(context.base, 0x1000, &mapped);
  if ((status != ACS_STATUS_PASS) || (mapped == NULL))
  {
    val_print(ACS_PRINT_ERR, " Failed to map HPA 0x%llx", (uint64_t)context.base);
    val_set_status(pe_index, "FAIL", 06);
    goto cleanup;
  }

  original = *mapped;

  /* Ensure the test pattern changes all bits. */
  pattern = original ^ TEST_DATA_PATTERN;

  /* Guarantee at least one bit flip if XOR matches. */
  if (pattern == original)
    pattern ^= 0x1ULL;

  /* Write the pattern, read it back, then restore. */
  *mapped = pattern;
  readback = *mapped;
  *mapped = original;

  if (readback != pattern)
  {
    val_print(ACS_PRINT_ERR, " Load/store validation failed at 0x%llx", (uint64_t)context.base);
    val_set_status(pe_index, "FAIL", 07);
    goto cleanup;
  }

  result = ACS_STATUS_PASS;

cleanup:
  if (context.endpoint_decoder_size_orig != 0u)
    (void)val_cxl_program_component_decoder(context.endpoint_index,
                                            DECODER_SLOT,
                                            context.endpoint_decoder_base_orig,
                                            context.endpoint_decoder_size_orig);
  if (context.host_decoder_size_orig != 0u)
    (void)val_cxl_program_host_decoder(context.host_index,
                                       DECODER_SLOT,
                                       context.host_decoder_base_orig,
                                       context.host_decoder_size_orig);

  if (result == ACS_STATUS_PASS)
    val_set_status(pe_index, "PASS", 01);
}

uint32_t
cxl_rhmxtf_host_hdm_decoder_entry(uint32_t num_pe)
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
