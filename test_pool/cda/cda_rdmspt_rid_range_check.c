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
#include "val/include/val_el32.h"
#include "val/include/val_exerciser.h"
#include "val/include/val_iovirt.h"
#include "val/include/val_memory.h"
#include "val/include/val_pcie.h"
#include "val/include/val_pcie_spec.h"
#include "val/include/val_pgt.h"
#include "val/include/val_smmu.h"

#define TEST_NAME "cda_rdmspt_rid_range_check"
#define TEST_DESC "D2H requests are checked against permitted RID range"
#define TEST_RULE "RDMSPT"

#define RDMSPT_DMA_PAGES 2u
#define RDMSPT_DMA_LENGTH 64u
#define RDMSPT_SRC_PATTERN 0x5Au
#define RDMSPT_DST_PATTERN 0x00u

typedef struct {
  uint32_t root_bdf;
  uint32_t endpoint_bdf;
  uint32_t rmecda_cap_base;
  uint32_t rmecda_ctl1_orig;
  uint32_t rmecda_ctl3_orig;
  uint32_t rmecda_ctl4_orig;
  uint32_t rmecda_regs_valid;
  uint64_t rmecda_cfg_va;
} RDMSPT_CONTEXT;

static uint32_t
restore_rmecda_registers(const RDMSPT_CONTEXT *context)
{
  if ((context == NULL) || (context->rmecda_cfg_va == 0u) ||
      (context->rmecda_regs_valid == 0u))
    return ACS_STATUS_PASS;

  (void)val_cda_set_link_stream_lock(context->rmecda_cfg_va,
                                     context->rmecda_cap_base,
                                     context->rmecda_ctl1_orig,
                                     0u);

  if (val_memory_write_el3(context->rmecda_cfg_va + context->rmecda_cap_base +
                           RMECDA_CTL3_OFFSET,
                           context->rmecda_ctl3_orig) != ACS_STATUS_PASS)
    return ACS_STATUS_ERR;

  if (val_memory_write_el3(context->rmecda_cfg_va + context->rmecda_cap_base +
                           RMECDA_CTL4_OFFSET,
                           context->rmecda_ctl4_orig) != ACS_STATUS_PASS)
    return ACS_STATUS_ERR;

  if (val_memory_write_el3(context->rmecda_cfg_va + context->rmecda_cap_base +
                           RMECDA_CTL1_OFFSET,
                           context->rmecda_ctl1_orig) != ACS_STATUS_PASS)
    return ACS_STATUS_ERR;

  return ACS_STATUS_PASS;
}

static uint32_t
read_rmecda_originals(RDMSPT_CONTEXT *context)
{
  if (context == NULL)
    return ACS_STATUS_ERR;

  if (val_pcie_read_cfg(context->root_bdf,
                        context->rmecda_cap_base + RMECDA_CTL1_OFFSET,
                        &context->rmecda_ctl1_orig) != PCIE_SUCCESS)
    return ACS_STATUS_ERR;

  if (val_pcie_read_cfg(context->root_bdf,
                        context->rmecda_cap_base + RMECDA_CTL3_OFFSET,
                        &context->rmecda_ctl3_orig) != PCIE_SUCCESS)
    return ACS_STATUS_ERR;

  if (val_pcie_read_cfg(context->root_bdf,
                        context->rmecda_cap_base + RMECDA_CTL4_OFFSET,
                        &context->rmecda_ctl4_orig) != PCIE_SUCCESS)
    return ACS_STATUS_ERR;

  context->rmecda_regs_valid = 1u;
  return ACS_STATUS_PASS;
}

static uint32_t
configure_smmu_identity_map(uint32_t endpoint_bdf,
                            uint64_t page_pa,
                            uint64_t map_len,
                            smmu_master_attributes_t *master_out,
                            pgt_descriptor_t *pgt_desc_out)
{
  memory_region_descriptor_t mem_desc[2];
  pgt_descriptor_t pgt_desc;
  uint32_t device_id = 0u;
  uint32_t its_id = 0u;
  uint32_t smmu_index;
  uint32_t ias;
  uint32_t oas;

  if ((master_out == NULL) || (pgt_desc_out == NULL) ||
      (page_pa == 0u) || (map_len == 0u))
    return ACS_STATUS_ERR;

  val_memory_set(master_out, sizeof(*master_out), 0);
  val_memory_set(pgt_desc_out, sizeof(*pgt_desc_out), 0);
  master_out->smmu_index = ACS_INVALID_INDEX;

  smmu_index = val_iovirt_get_rc_smmu_index(PCIE_EXTRACT_BDF_SEG(endpoint_bdf),
                                            PCIE_CREATE_BDF_PACKED(endpoint_bdf));
  if (smmu_index == ACS_INVALID_INDEX)
    return ACS_STATUS_SKIP;

  if (val_iovirt_get_smmu_info(SMMU_CTRL_ARCH_MAJOR_REV, smmu_index) != 3u)
    return ACS_STATUS_SKIP;

  if (val_iovirt_get_device_info(PCIE_CREATE_BDF_PACKED(endpoint_bdf),
                                 PCIE_EXTRACT_BDF_SEG(endpoint_bdf),
                                 &device_id,
                                 &master_out->streamid,
                                 &its_id))
    return ACS_STATUS_SKIP;

  ias = (uint32_t)val_smmu_get_info(SMMU_IN_ADDR_SIZE, smmu_index);
  oas = (uint32_t)val_smmu_get_info(SMMU_OUT_ADDR_SIZE, smmu_index);
  if ((ias == 0u) || (oas == 0u))
    return ACS_STATUS_SKIP;

  val_memory_set(mem_desc, sizeof(mem_desc), 0);
  mem_desc[0].virtual_address = page_pa;
  mem_desc[0].physical_address = page_pa;
  mem_desc[0].length = map_len;
  mem_desc[0].attributes =
    LOWER_ATTRS(PGT_ENTRY_ACCESS | SHAREABLE_ATTR(NON_SHAREABLE) |
                GET_ATTR_INDEX(NON_CACHEABLE) | PGT_ENTRY_AP_RW);
  mem_desc[1].length = 0u;

  val_memory_set(&pgt_desc, sizeof(pgt_desc), 0);
  pgt_desc.pgt_base = (uint64_t)NULL;
  pgt_desc.ias = ias;
  pgt_desc.oas = oas;
  pgt_desc.stage = PGT_STAGE1;

  if (val_pe_reg_read_tcr(0, &pgt_desc.tcr))
    return ACS_STATUS_ERR;

  if (val_smmu_enable(smmu_index))
    return ACS_STATUS_ERR;

  master_out->smmu_index = smmu_index;
  master_out->stage2 = 0u;

  if (val_pgt_create(mem_desc, &pgt_desc))
  {
    (void)val_smmu_disable(smmu_index);
    master_out->smmu_index = ACS_INVALID_INDEX;
    return ACS_STATUS_ERR;
  }

  if (val_smmu_map(*master_out, pgt_desc))
  {
    val_pgt_destroy(pgt_desc);
    (void)val_smmu_disable(smmu_index);
    master_out->smmu_index = ACS_INVALID_INDEX;
    return ACS_STATUS_ERR;
  }

  *pgt_desc_out = pgt_desc;
  return ACS_STATUS_PASS;
}

static uint32_t
run_d2h_dma_check(uint32_t endpoint_bdf,
                  uint8_t *buffer_src,
                  uint8_t *buffer_dst,
                  uint64_t buffer_src_pa,
                  uint64_t buffer_dst_pa,
                  uint32_t length,
                  uint32_t load_device,
                  uint32_t expect_match)
{
  uint32_t status;
  uint32_t match;

  if ((buffer_src == NULL) || (buffer_dst == NULL) ||
      (buffer_src_pa == 0u) || (buffer_dst_pa == 0u))
    return ACS_STATUS_ERR;

  if (load_device != 0u)
  {
    if (val_memory_prepare_dma_buffers_el3(buffer_src,
                                           buffer_dst,
                                           length,
                                           RDMSPT_SRC_PATTERN,
                                           RDMSPT_DST_PATTERN) != ACS_STATUS_PASS)
      return ACS_STATUS_ERR;

    /* Make the initialized buffers visible before the exerciser owns them. */
    if ((val_memory_cache_clean_invalidate_range_el3((uint64_t)buffer_src,
                                                      length) != ACS_STATUS_PASS) ||
        (val_memory_cache_clean_invalidate_range_el3((uint64_t)buffer_dst,
                                                      length) != ACS_STATUS_PASS))
      return ACS_STATUS_ERR;

    if (val_exerciser_set_param_by_bdf(DMA_ATTRIBUTES,
                                       buffer_src_pa,
                                       length,
                                       endpoint_bdf))
      return ACS_STATUS_ERR;

    status = val_exerciser_ops_by_bdf(START_DMA, EDMA_TO_DEVICE, endpoint_bdf);
    if (status != 0u)
    {
      val_print(ACS_PRINT_ERR, " RDMSPT: H2D DMA status 0x%x", status);
      return ACS_STATUS_FAIL;
    }
  }
  else
  {
    if (val_memory_set_el3(buffer_dst, length, RDMSPT_DST_PATTERN))
      return ACS_STATUS_ERR;

    if (val_memory_cache_clean_invalidate_range_el3((uint64_t)buffer_dst,
                                                     length) != ACS_STATUS_PASS)
      return ACS_STATUS_ERR;
  }

  val_pcie_clear_device_status_error(endpoint_bdf);

  if (val_exerciser_set_param_by_bdf(DMA_ATTRIBUTES,
                                     buffer_dst_pa,
                                     length,
                                     endpoint_bdf))
    return ACS_STATUS_ERR;

  status = val_exerciser_ops_by_bdf(START_DMA, EDMA_FROM_DEVICE, endpoint_bdf);
  if ((expect_match != 0u) && (status != 0u))
    return ACS_STATUS_FAIL;

  /* Discard any stale PE copy before examining data written by the device. */
  if (val_memory_cache_invalidate_range_el3((uint64_t)buffer_dst,
                                             length) != ACS_STATUS_PASS)
    return ACS_STATUS_ERR;

  status = val_memory_compare_el3((uint64_t)buffer_src,
                                  (uint64_t)buffer_dst,
                                  length);
  if (status == ACS_STATUS_ERR)
    return ACS_STATUS_ERR;

  match = (status == 0u) ? 1u : 0u;

  if (expect_match != 0u)
    return (match != 0u) ? ACS_STATUS_PASS : ACS_STATUS_FAIL;

  return (match == 0u) ? ACS_STATUS_PASS : ACS_STATUS_FAIL;
}

static uint32_t
program_rid_window_and_lock(const RDMSPT_CONTEXT *context,
                            uint32_t rid_base,
                            uint32_t rid_limit)
{
  uint32_t status;

  status = val_cda_set_link_stream_lock(context->rmecda_cfg_va,
                                        context->rmecda_cap_base,
                                        context->rmecda_ctl1_orig,
                                        0u);
  if (status != ACS_STATUS_PASS)
    return status;

  status = val_cda_program_rid_range(context->rmecda_cfg_va,
                                     context->rmecda_cap_base,
                                     context->rmecda_ctl3_orig,
                                     context->rmecda_ctl4_orig,
                                     rid_base,
                                     rid_limit,
                                     1u);
  if (status != ACS_STATUS_PASS)
    return status;

  return val_cda_set_link_stream_lock(context->rmecda_cfg_va,
                                      context->rmecda_cap_base,
                                      context->rmecda_ctl1_orig,
                                      1u);
}

static uint32_t
verify_root_port(uint32_t root_bdf, uint32_t rmecda_cap_base)
{
  RDMSPT_CONTEXT context;
  smmu_master_attributes_t master;
  pgt_descriptor_t pgt_desc;
  uint8_t *buffer = NULL;
  uint8_t *buffer_src = NULL;
  uint8_t *buffer_dst = NULL;
  uint64_t buffer_src_pa = 0u;
  uint64_t buffer_dst_pa = 0u;
  uint32_t page_size;
  uint32_t endpoint_rid;
  uint32_t rid_base;
  uint32_t rid_limit;
  uint32_t status;
  uint32_t result = ACS_STATUS_PASS;
  uint32_t smmu_active = 0u;
  uint32_t pgt_created = 0u;
  uint32_t src_gpt_set = 0u;
  uint32_t dst_gpt_set = 0u;

  val_memory_set(&context, sizeof(context), 0);
  val_memory_set(&master, sizeof(master), 0);
  val_memory_set(&pgt_desc, sizeof(pgt_desc), 0);
  master.smmu_index = ACS_INVALID_INDEX;
  context.root_bdf = root_bdf;
  context.rmecda_cap_base = rmecda_cap_base;
  context.endpoint_bdf = ACS_INVALID_INDEX;

  status = val_cda_find_downstream_chi_c2c_exerciser_endpoint(root_bdf,
                                                              &context.endpoint_bdf);
  if (status != ACS_STATUS_PASS)
    return status;

  if (val_cxl_enable_mem(context.endpoint_bdf) != ACS_STATUS_PASS)
    return ACS_STATUS_SKIP;

  if (read_rmecda_originals(&context) != ACS_STATUS_PASS)
  {
    result = ACS_STATUS_ERR;
    goto cleanup;
  }

  if (val_pcie_map_root_config(root_bdf, &context.rmecda_cfg_va) != ACS_STATUS_PASS)
    return ACS_STATUS_ERR;

  page_size = val_memory_page_size();
  if (page_size == 0u)
  {
    result = ACS_STATUS_ERR;
    goto cleanup;
  }

  buffer = (uint8_t *)val_memory_alloc_pages(RDMSPT_DMA_PAGES);
  if (buffer == NULL)
  {
    result = ACS_STATUS_ERR;
    goto cleanup;
  }

  buffer_src = buffer;
  buffer_dst = buffer + page_size;
  buffer_src_pa = (uint64_t)val_memory_virt_to_phys(buffer_src);
  buffer_dst_pa = (uint64_t)val_memory_virt_to_phys(buffer_dst);
  if ((buffer_src_pa == 0u) || (buffer_dst_pa == 0u))
  {
    result = ACS_STATUS_ERR;
    goto cleanup;
  }

  if (val_add_gpt_entry_el3(buffer_src_pa, GPT_NONSECURE))
  {
    result = ACS_STATUS_ERR;
    goto cleanup;
  }
  src_gpt_set = 1u;

  if (val_add_gpt_entry_el3(buffer_dst_pa, GPT_NONSECURE))
  {
    result = ACS_STATUS_ERR;
    goto cleanup;
  }
  dst_gpt_set = 1u;

  /*
   * The buffers are now NS-owned. Map both source and destination VAs in EL3 so
   * initialization and result comparison can use EL3 MUT helpers without EL3
   * taking a data abort on either NS buffer VA.
   */
  if (val_memory_map_dma_buffer_el3(buffer_src,
                                    buffer_src_pa,
                                    page_size,
                                    NONSECURE_PAS) != ACS_STATUS_PASS)
  {
    result = ACS_STATUS_ERR;
    goto cleanup;
  }

  if (val_memory_map_dma_buffer_el3(buffer_dst,
                                    buffer_dst_pa,
                                    page_size,
                                    NONSECURE_PAS) != ACS_STATUS_PASS)
  {
    result = ACS_STATUS_ERR;
    goto cleanup;
  }

  status = configure_smmu_identity_map(context.endpoint_bdf,
                                       buffer_src_pa,
                                       page_size * RDMSPT_DMA_PAGES,
                                       &master,
                                       &pgt_desc);
  if (status != ACS_STATUS_PASS)
  {
    result = status;
    goto cleanup;
  }
  smmu_active = 1u;
  pgt_created = 1u;

  if (val_exerciser_set_param_by_bdf(CFG_TXN_ATTRIBUTES,
                                     TXN_ADDR_TYPE,
                                     AT_TRANSLATED,
                                     context.endpoint_bdf))
  {
    result = ACS_STATUS_SKIP;
    goto cleanup;
  }

  /*
   * RDMSPT is checked using the endpoint's natural Requester ID.  Do not
   * spoof RID in the exerciser; instead, move the host-port permitted window.
   */
  (void)val_exerciser_set_param_by_bdf(CFG_TXN_ATTRIBUTES,
                                       TXN_REQ_ID_VALID,
                                       RID_NOT_VALID,
                                       context.endpoint_bdf);

  endpoint_rid = (uint32_t)PCIE_CREATE_BDF_PACKED(context.endpoint_bdf);
  val_print(ACS_PRINT_INFO, " RDMSPT: RP BDF 0x%x", root_bdf);
  val_print(ACS_PRINT_INFO, " RDMSPT: EP BDF 0x%x", context.endpoint_bdf);
  val_print(ACS_PRINT_INFO, " RDMSPT: EP RID 0x%x", endpoint_rid);

  status = program_rid_window_and_lock(&context, endpoint_rid, endpoint_rid);
  if (status != ACS_STATUS_PASS)
  {
    result = status;
    goto cleanup;
  }

  status = run_d2h_dma_check(context.endpoint_bdf,
                             buffer_src,
                             buffer_dst,
                             buffer_src_pa,
                             buffer_dst_pa,
                             RDMSPT_DMA_LENGTH,
                             1u,
                             1u);
  if (status != ACS_STATUS_PASS)
  {
    val_print(ACS_PRINT_ERR, " RDMSPT: in-range RID D2H DMA failed", 0);
    result = ACS_STATUS_FAIL;
    goto cleanup;
  }

  if ((endpoint_rid & 0xFFFFu) != 0xFFFFu)
  {
    rid_base = (endpoint_rid & 0xFFFFu) + 1u;
    rid_limit = 0xFFFFu;
  }
  else if ((endpoint_rid & 0xFFFFu) != 0u)
  {
    rid_base = 0u;
    rid_limit = (endpoint_rid & 0xFFFFu) - 1u;
  }
  else
  {
    result = ACS_STATUS_SKIP;
    goto cleanup;
  }

  status = program_rid_window_and_lock(&context, rid_base, rid_limit);
  if (status != ACS_STATUS_PASS)
  {
    result = status;
    goto cleanup;
  }

  status = run_d2h_dma_check(context.endpoint_bdf,
                             buffer_src,
                             buffer_dst,
                             buffer_src_pa,
                             buffer_dst_pa,
                             RDMSPT_DMA_LENGTH,
                             0u,
                             0u);
  if (status != ACS_STATUS_PASS)
  {
    val_print(ACS_PRINT_ERR, " RDMSPT: out-of-range RID D2H DMA accepted", 0);
    result = ACS_STATUS_FAIL;
    goto cleanup;
  }

  result = ACS_STATUS_PASS;

cleanup:
  if (context.endpoint_bdf != ACS_INVALID_INDEX)
    (void)val_exerciser_set_param_by_bdf(CFG_TXN_ATTRIBUTES,
                                         TXN_REQ_ID_VALID,
                                         RID_NOT_VALID,
                                         context.endpoint_bdf);

  if (restore_rmecda_registers(&context) != ACS_STATUS_PASS)
    result = ACS_STATUS_FAIL;

  if (pgt_created != 0u)
    val_pgt_destroy(pgt_desc);

  if (smmu_active != 0u)
    (void)val_smmu_disable(master.smmu_index);

  if (src_gpt_set != 0u)
    (void)val_add_gpt_entry_el3(buffer_src_pa, GPT_ANY);

  if (dst_gpt_set != 0u)
    (void)val_add_gpt_entry_el3(buffer_dst_pa, GPT_ANY);

  if (buffer != NULL)
    val_memory_free_pages(buffer, RDMSPT_DMA_PAGES);

  return result;
}

static void
payload(void)
{
  CXL_COMPONENT_TABLE *table;
  uint32_t pe_index;
  uint32_t executed = 0u;
  uint32_t skipped = 0u;
  uint32_t failures = 0u;

  pe_index = val_pe_get_index_mpid(val_pe_get_mpid());
  table = val_cxl_component_table_ptr();

  if ((table == NULL) || (table->num_entries == 0u))
  {
    val_print(ACS_PRINT_DEBUG, " RDMSPT: no CXL component table", 0);
    val_set_status(pe_index, "SKIP", 01);
    return;
  }

  if (val_cxl_exerciser_get_info(CXL_EXERCISER_NUM_CARDS) == 0u)
  {
    val_print(ACS_PRINT_DEBUG, " RDMSPT: no CXL exerciser endpoint", 0);
    val_set_status(pe_index, "SKIP", 02);
    return;
  }

  for (uint32_t idx = 0u; idx < table->num_entries; ++idx)
  {
    const CXL_COMPONENT_ENTRY *entry = &table->component[idx];
    uint32_t rmecda_cap_base;
    uint32_t status;

    if (entry->role != CXL_COMPONENT_ROLE_ROOT_PORT)
      continue;

    if (entry->chi_c2c_supported == 0u)
      continue;

    if (val_pcie_find_cda_capability(entry->bdf, &rmecda_cap_base) != PCIE_SUCCESS)
      continue;

    executed++;
    status = verify_root_port(entry->bdf, rmecda_cap_base);
    if (status == ACS_STATUS_PASS)
      continue;
    if (status == ACS_STATUS_SKIP)
      skipped++;
    else
      failures++;
  }

  if ((executed == 0u) || (executed == skipped))
    val_set_status(pe_index, "SKIP", 03);
  else if (failures != 0u)
    val_set_status(pe_index, "FAIL", failures);
  else
    val_set_status(pe_index, "PASS", 01);
}

uint32_t
cda_rdmspt_rid_range_check_entry(uint32_t num_pe)
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
