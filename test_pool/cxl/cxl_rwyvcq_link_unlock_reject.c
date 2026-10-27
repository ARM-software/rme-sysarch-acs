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
#define REALM_BASELINE      0x5A5A5A5Au
#define TDISP_EN_MASK       (1u << 0)
#define LINK_STR_LOCK_MASK  (1u << 1)

typedef struct {
  uint32_t host_index;
  uint64_t window_base;
  uint64_t window_size;
  uint32_t root_index;
  uint32_t endpoint_index;
  uint32_t endpoint_bdf;
  CXL_DECODER_STATE host_decoder;
  CXL_DECODER_STATE endpoint_decoder;
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
  uint32_t rmecda_ctl1_saved = 0u;
  uint32_t rmecda_ctl1_unlocked = 0;
  volatile uint64_t *realm_ptr = NULL;
  volatile uint64_t *ns_ptr = NULL;
  uint32_t realm_observed_value = 0;
  uint32_t realm_pattern = ~REALM_BASELINE;
  uint32_t control_pattern = 0;
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

  /* Locate RMECDA DVSEC on the root port. */
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

  /* Snapshot both decoders and program the target list while the host is inactive. */
  status = val_cxl_prepare_decoders(context.host_index, context.endpoint_index,
                                     DECODER_SLOT, root_bdf, &context.host_decoder,
                                     &context.endpoint_decoder);
  if (status != ACS_STATUS_PASS)
  {
    val_print(ACS_PRINT_TEST, " RWYVCQ: decoder snapshot unavailable or locked", 0);
    val_set_status(pe_index, (status == ACS_STATUS_SKIP) ? "SKIP" : "FAIL", 03);
    return;
  }

  /* Enable CXL.mem before programming HDM decoders. */
  if (val_cxl_enable_mem(context.endpoint_bdf) != ACS_STATUS_PASS)
  {
    val_print(ACS_PRINT_ERR, " RWYVCQ: Failed to enable CXL.mem", 0);
    val_set_status(pe_index, "FAIL", 03);
    goto restore;
  }

  /* Program host decoder to target the chosen CFMWS window. */
  status = val_cxl_program_saved_decoder(&context.host_decoder,
                                         context.window_base,
                                         context.window_size);
  if (status == ACS_STATUS_SKIP)
  {
    val_print(ACS_PRINT_TEST,
              " RWYVCQ: host decoder programming skipped", 0);
    val_set_status(pe_index, "SKIP", 04);
    goto restore;
  }
  if (status != ACS_STATUS_PASS)
  {
    val_set_status(pe_index, "FAIL", 03);
    goto restore;
  }

  endpoint_base = ((uint64_t)context.endpoint_decoder.reg[1] << 32) |
                  (context.endpoint_decoder.reg[0] & 0xF0000000u);
  endpoint_size = ((uint64_t)context.endpoint_decoder.reg[3] << 32) |
                  (context.endpoint_decoder.reg[2] & 0xF0000000u);
  if (endpoint_size == 0u)
    endpoint_size = context.window_size;

  if ((endpoint_base == 0u) || ((endpoint_base & ALIGNMENT_MASK) != 0u))
    endpoint_base = context.window_base;
  if (endpoint_size == 0u)
    endpoint_size = context.window_size;

  status = val_cxl_program_saved_decoder(&context.endpoint_decoder,
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

  rmecda_ctl1_saved = 1u;

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

  /* Permit Realm accesses while establishing a known encryption context. */
  if (write_from_root(cfg_va + rmecda_cap_base + RMECDA_CTL1_OFFSET,
                      rmecda_ctl1_original | TDISP_EN_MASK | LINK_STR_LOCK_MASK) !=
      ACS_STATUS_PASS)
  {
    val_set_status(pe_index, "FAIL", 10);
    goto restore;
  }

  if (read_from_root(cfg_va + rmecda_cap_base + RMECDA_CTL1_OFFSET,
                     &control_readback) != ACS_STATUS_PASS ||
      ((control_readback & (TDISP_EN_MASK | LINK_STR_LOCK_MASK)) !=
       (TDISP_EN_MASK | LINK_STR_LOCK_MASK)))
  {
    val_set_status(pe_index, "FAIL", 10);
    goto restore;
  }

  /* Use the same Realm PAS and MECID for initialization and the rejected write.
   * This prevents earlier tests' encryption contexts from affecting the check.
   */
  if (write_from_root((uint64_t)realm_ptr, REALM_BASELINE) != ACS_STATUS_PASS ||
      read_from_root((uint64_t)realm_ptr, &control_readback) != ACS_STATUS_PASS ||
      control_readback != REALM_BASELINE)
  {
    val_print(ACS_PRINT_ERR, " RWYVCQ: Realm baseline initialization failed", 0);
    val_set_status(pe_index, "FAIL", 10);
    goto restore;
  }

  /* Enable TDISP and unlock the link to isolate RWYVCQ from RNYCLL. */
  rmecda_ctl1_unlocked = (rmecda_ctl1_original | TDISP_EN_MASK) & ~LINK_STR_LOCK_MASK;
  if (write_from_root(cfg_va + rmecda_cap_base + RMECDA_CTL1_OFFSET,
                      rmecda_ctl1_unlocked) != ACS_STATUS_PASS)
  {
    val_set_status(pe_index, "FAIL", 11);
    goto restore;
  }

  if (read_from_root(cfg_va + rmecda_cap_base + RMECDA_CTL1_OFFSET,
                     &control_readback) != ACS_STATUS_PASS ||
      ((control_readback & (TDISP_EN_MASK | LINK_STR_LOCK_MASK)) != TDISP_EN_MASK))
  {
    val_set_status(pe_index, "FAIL", 11);
    goto restore;
  }

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

  /* Reopen the Realm path to verify data using its original PAS and MECID. */
  if (write_from_root(cfg_va + rmecda_cap_base + RMECDA_CTL1_OFFSET,
                      rmecda_ctl1_unlocked | LINK_STR_LOCK_MASK) != ACS_STATUS_PASS)
  {
    val_set_status(pe_index, "FAIL", 13);
    goto restore;
  }

  if (read_from_root(cfg_va + rmecda_cap_base + RMECDA_CTL1_OFFSET,
                     &control_readback) != ACS_STATUS_PASS ||
      ((control_readback & (TDISP_EN_MASK | LINK_STR_LOCK_MASK)) !=
       (TDISP_EN_MASK | LINK_STR_LOCK_MASK)))
  {
    val_set_status(pe_index, "FAIL", 13);
    goto restore;
  }

  if (read_from_root((uint64_t)realm_ptr, &realm_observed_value) != ACS_STATUS_PASS)
  {
    val_set_status(pe_index, "FAIL", 13);
    goto restore;
  }

  if (realm_observed_value != REALM_BASELINE)
  {
    val_print(ACS_PRINT_ERR,
              " RWYVCQ: Realm write propagated (value 0x%x)",
              realm_observed_value);
    val_set_status(pe_index, "FAIL", 13);
    goto restore;
  }

  /* Unlock again for the rejected read and Non-secure control accesses. */
  if (write_from_root(cfg_va + rmecda_cap_base + RMECDA_CTL1_OFFSET,
                      rmecda_ctl1_unlocked) != ACS_STATUS_PASS)
  {
    val_set_status(pe_index, "FAIL", 14);
    goto restore;
  }

  if (read_from_root(cfg_va + rmecda_cap_base + RMECDA_CTL1_OFFSET,
                     &control_readback) != ACS_STATUS_PASS ||
      ((control_readback & (TDISP_EN_MASK | LINK_STR_LOCK_MASK)) != TDISP_EN_MASK))
  {
    val_set_status(pe_index, "FAIL", 14);
    goto restore;
  }

  /* Observe the rejected read through the platform's synchronous external abort. */
  shared_data->access_mut = CLEAR;
  shared_data->exception_generated = CLEAR;
  shared_data->exception_expected = SET;
  shared_data->esr_value = SEA_ESR_READ;
  shared_data->num_access = 1;
  shared_data->shared_data_access[0].addr = (uint64_t)realm_ptr;
  shared_data->shared_data_access[0].access_type = READ_DATA;

  status = val_pe_access_mut_el3();
  shared_data->exception_expected = CLEAR;
  shared_data->esr_value = 0u;
  if (status || shared_data->exception_generated != SET)
  {
    shared_data->exception_generated = CLEAR;
    val_print(ACS_PRINT_ERR, " RWYVCQ: expected external read abort not observed", 0);
    val_set_status(pe_index, "FAIL", 14);
    goto restore;
  }
  shared_data->exception_generated = CLEAR;

  control_pattern = REALM_BASELINE ^ 0x33333333u;
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

  result = ACS_STATUS_PASS;

restore:
  if (rmecda_ctl1_saved != 0u &&
      write_from_root(cfg_va + rmecda_cap_base + RMECDA_CTL1_OFFSET,
                       rmecda_ctl1_original) != ACS_STATUS_PASS)
  {
    val_print(ACS_PRINT_ERR, " RWYVCQ: failed to restore RMECDA_CTL1", 0);
    val_set_status(pe_index, "FAIL", 18);
    result = ACS_STATUS_FAIL;
  }
  /* Each restore disables the decoder before touching its configuration. */
  status = val_cxl_restore_decoders(&context.host_decoder, &context.endpoint_decoder);
  if (status != ACS_STATUS_PASS)
  {
    val_print(ACS_PRINT_ERR, " RWYVCQ: failed to restore decoder state", 0);
    val_set_status(pe_index, "FAIL", 19);
    result = ACS_STATUS_FAIL;
  }

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
