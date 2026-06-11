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
#include "val/include/val_pcie.h"
#include "val/include/val_cxl.h"
#include "val/include/val_cxl_spec.h"
#include "val/include/val_memory.h"
#include "val/include/val_exerciser.h"
#include "val/include/val_pcie_spec.h"
#include "val/include/val_pcie_enumeration.h"
#include "val/include/val_smmu.h"
#include "val/include/val_iovirt.h"
#include "val/include/val_pgt.h"
#include "val/include/val_el32.h"
#include "val/include/val_pe.h"

#define TEST_NAME "cxl_rbytyv_root_port_pas_behavior"
#define TEST_DESC "CXL RP enforces RBYTYV access behavior            "
#define TEST_RULE "RBYTYV"

#define DECODER_SLOT 0u

#define PCIE_LNKCAP_OFFSET 0x0Cu
#define PCIE_LNKCAP_PN_SHIFT 24u
#define PCIE_LNKCAP_PN_MASK 0xFFu

typedef struct {
  uint32_t host_index;
  uint32_t endpoint_index;
  uint64_t window_base;
  uint64_t window_size;
  uint64_t host_decoder_base_orig;
  uint64_t host_decoder_size_orig;
  uint64_t endpoint_decoder_base_orig;
  uint64_t endpoint_decoder_size_orig;
  uint32_t host_target_low_orig;
  uint32_t host_target_high_orig;
  uint32_t host_target_valid;
} RBYTYV_CONTEXT;

static uint32_t
find_component_index_by_bdf(const CXL_COMPONENT_TABLE *table,
                            uint32_t bdf,
                            uint32_t *index_out)
{
  if ((table == NULL) || (index_out == NULL))
    return ACS_STATUS_ERR;

  for (uint32_t idx = 0; idx < table->num_entries; ++idx)
  {
    if (table->component[idx].bdf == bdf)
    {
      *index_out = idx;
      return ACS_STATUS_PASS;
    }
  }

  return ACS_STATUS_FAIL;
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

static uint32_t
map_dma_buffers_el3(uint8_t *buffer_va,
                    uint64_t buffer_pa,
                    uint32_t length,
                    uint32_t pas)
{
  uint32_t attr;

  if ((buffer_va == NULL) || (buffer_pa == 0u))
    return ACS_STATUS_ERR;

  attr = LOWER_ATTRS(PGT_ENTRY_ACCESS |
                     SHAREABLE_ATTR(OUTER_SHAREABLE) |
                     GET_ATTR_INDEX(DEV_MEM_nGnRnE) |
                     PGT_ENTRY_AP_RW |
                     PAS_ATTR(pas));

  if (val_add_mmu_entry_el3((uint64_t)buffer_va, buffer_pa, attr))
    return ACS_STATUS_ERR;

  if (val_add_mmu_entry_el3((uint64_t)(buffer_va + length),
                            buffer_pa + length,
                            attr))
    return ACS_STATUS_ERR;

  return ACS_STATUS_PASS;
}

static uint32_t
compare_buffers_el3(uint64_t src_va, uint64_t dst_va, uint32_t size)
{
  uint64_t src_data;
  uint64_t dst_data;

  shared_data->num_access = 1;
  shared_data->shared_data_access[0].access_type = READ_DATA;

  while (size > 0u)
  {
    shared_data->shared_data_access[0].addr = src_va;
    if (val_pe_access_mut_el3())
    {
      val_print(ACS_PRINT_ERR, " RBYTYV: EL3 read failed for 0x%llx", src_va);
      return ACS_STATUS_ERR;
    }
    src_data = shared_data->shared_data_access[0].data;

    shared_data->shared_data_access[0].addr = dst_va;
    if (val_pe_access_mut_el3())
    {
      val_print(ACS_PRINT_ERR, " RBYTYV: EL3 read failed for 0x%llx", dst_va);
      return ACS_STATUS_ERR;
    }
    dst_data = shared_data->shared_data_access[0].data;

    if ((uint32_t)src_data != (uint32_t)dst_data)
      return 1u;

    src_va += sizeof(uint32_t);
    dst_va += sizeof(uint32_t);
    size -= sizeof(uint32_t);
  }

  return 0u;
}

static uint32_t
program_host_target_list(uint32_t bdf,
                         uint64_t comp_base,
                         uint32_t decoder_index,
                         RBYTYV_CONTEXT *context)
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
    return ACS_STATUS_ERR;

  if (val_pcie_read_cfg(bdf, pcie_cap_offset + PCIE_LNKCAP_OFFSET, &lnkcap) != 0u)
    return ACS_STATUS_ERR;

  port_id = (lnkcap >> PCIE_LNKCAP_PN_SHIFT) & PCIE_LNKCAP_PN_MASK;

  if (val_cxl_find_capability(comp_base, CXL_CAPID_HDM_DECODER, &hdm_cap_base)
      != ACS_STATUS_PASS)
    return ACS_STATUS_ERR;

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
restore_host_target_list(const RBYTYV_CONTEXT *context)
{
  uint64_t comp_base;
  uint64_t cap_base;

  if ((context == NULL) || (context->host_target_valid == 0u))
    return;

  comp_base = val_cxl_get_info(CXL_INFO_COMPONENT_BASE, context->host_index);
  if (comp_base == 0u)
    return;

  if (val_cxl_find_capability(comp_base, CXL_CAPID_HDM_DECODER, &cap_base)
      != ACS_STATUS_PASS)
    return;

  val_mmio_write(cap_base + CXL_HDM_DECODER_TARGET_LOW(DECODER_SLOT),
                 context->host_target_low_orig);
  val_mmio_write(cap_base + CXL_HDM_DECODER_TARGET_HIGH(DECODER_SLOT),
                 context->host_target_high_orig);
}

static void
restore_decoders(const RBYTYV_CONTEXT *context)
{
  if (context == NULL)
    return;

  if (context->host_index != CXL_COMPONENT_INVALID_INDEX)
  {
    if (context->host_decoder_size_orig != 0u)
    {
      (void)val_cxl_program_host_decoder(context->host_index,
                                         DECODER_SLOT,
                                         context->host_decoder_base_orig,
                                         context->host_decoder_size_orig);
    }
    restore_host_target_list(context);
  }

  if ((context->endpoint_index != CXL_COMPONENT_INVALID_INDEX) &&
      (context->endpoint_decoder_size_orig != 0u))
    (void)val_cxl_program_component_decoder(context->endpoint_index,
                                            DECODER_SLOT,
                                            context->endpoint_decoder_base_orig,
                                            context->endpoint_decoder_size_orig);
}

static uint32_t
read_device_media(uint32_t endpoint_bdf,
                   uint64_t phys,
                   uint64_t *value_out)
{
  uint64_t readback = 0u;

  if (value_out == NULL)
    return ACS_STATUS_ERR;

  if (val_exerciser_set_param_by_bdf(EXERCISER_CXL_CMD_OP,
                                     CXL_CMD_OP_BACKDOOR_READ64,
                                     0u,
                                     endpoint_bdf))
    return ACS_STATUS_FAIL;

  if (val_exerciser_set_param_by_bdf(EXERCISER_CXL_CMD_ADDR,
                                     phys,
                                     0u,
                                     endpoint_bdf))
    return ACS_STATUS_FAIL;

  if (val_exerciser_ops_by_bdf(CXL_CMD_START, 0u, endpoint_bdf))
    return ACS_STATUS_FAIL;

  if (val_exerciser_get_param_by_bdf(EXERCISER_CXL_CMD_DATA0,
                                     &readback,
                                     NULL,
                                     endpoint_bdf))
    return ACS_STATUS_FAIL;

  *value_out = readback;
  return ACS_STATUS_PASS;
}

static uint32_t
access_cxl_mem(uint32_t root_bdf,
               uint32_t endpoint_bdf,
               uint32_t aer_offset,
               uint64_t phys,
               uint32_t pas,
               uint32_t expect_reject)
{
  volatile uint64_t *mapped = NULL;
  uint64_t baseline = 0u;
  uint32_t pattern = 0xA5A5A5A5U;
  uint64_t observed = 0u;
  uint32_t aer_uncorr = 0u;

  /* Map a single page of CXL.mem into the requested PAS. */
  if (map_window_alias(phys, pas, &mapped) != ACS_STATUS_PASS)
    return ACS_STATUS_ERR;

  if (read_device_media(endpoint_bdf, phys, &baseline) != ACS_STATUS_PASS)
    return ACS_STATUS_ERR;

  val_print(ACS_PRINT_DEBUG,
            " RBYTYV: Media baseline 0x%llx",
            baseline);

  if (pattern == (uint32_t)baseline)
    pattern ^= 0x1u;

  if (aer_offset != 0u)
    val_cxl_aer_clear(root_bdf, aer_offset);

  /* Trigger a CXL.mem write/read to observe RP behavior. */
  shared_data->exception_generated = CLEAR;
  shared_data->exception_expected = CLEAR;
  shared_data->num_access = 2;
  shared_data->shared_data_access[0].addr = (uint64_t)mapped;
  shared_data->shared_data_access[0].data = (uint64_t)pattern;
  shared_data->shared_data_access[0].access_type = WRITE_DATA;
  shared_data->shared_data_access[1].addr = (uint64_t)mapped;
  shared_data->shared_data_access[1].access_type = READ_DATA;

  if (val_pe_access_mut_el3())
    return ACS_STATUS_ERR;

  if (read_device_media(endpoint_bdf, phys, &observed) != ACS_STATUS_PASS)
    return ACS_STATUS_ERR;

  val_print(ACS_PRINT_DEBUG,
            " RBYTYV: Media observed 0x%llx",
            observed);

  if (aer_offset != 0u)
    (void)val_cxl_aer_read_uncorr(root_bdf, aer_offset, &aer_uncorr);

  if (expect_reject != 0u)
  {
    if ((uint32_t)observed != (uint32_t)baseline)
      return ACS_STATUS_FAIL;
    if ((aer_offset != 0u) && (aer_uncorr == 0u))
      return ACS_STATUS_FAIL;
  }
  else
  {
    if ((uint32_t)observed != pattern)
      return ACS_STATUS_FAIL;
  }

  return ACS_STATUS_PASS;
}

static uint32_t
check_device_to_host_dma(uint32_t endpoint_bdf,
                         uint32_t length)
{
  smmu_master_attributes_t master;
  memory_region_descriptor_t mem_desc[2];
  pgt_descriptor_t pgt_desc_ns;
  pgt_descriptor_t pgt_desc_rlm;
  uint8_t *buffer_va;
  uint8_t *buffer_src;
  uint8_t *buffer_dst;
  uint64_t buffer_pa;
  uint64_t buffer_src_pa;
  uint64_t buffer_dst_pa;
  uint64_t total_len;
  uint32_t its_id = 0u;
  uint32_t device_id = 0u;
  uint32_t status;
  uint32_t smmu_index;
  uint32_t pgt_ns_created = 0u;
  uint32_t pgt_rlm_created = 0u;
  uint32_t smmu_ns_mapped = 0u;
  uint32_t smmu_rlm_mapped = 0u;
  uint32_t buffer_valid = 0u;
  uint32_t cmp_status;
  uint32_t result = ACS_STATUS_PASS;

  val_memory_set(&master, sizeof(master), 0);
  val_memory_set(mem_desc, sizeof(mem_desc), 0);
  val_memory_set(&pgt_desc_ns, sizeof(pgt_desc_ns), 0);
  val_memory_set(&pgt_desc_rlm, sizeof(pgt_desc_rlm), 0);

  buffer_va = val_memory_alloc_pages(2);
  if (buffer_va == NULL)
    return ACS_STATUS_SKIP;

  buffer_pa = (uint64_t)val_memory_virt_to_phys(buffer_va);
  if (buffer_pa == 0u)
  {
    val_memory_free_pages(buffer_va, 2);
    return ACS_STATUS_SKIP;
  }

  buffer_src = buffer_va;
  buffer_dst = buffer_va + length;
  buffer_src_pa = buffer_pa;
  buffer_dst_pa = buffer_pa + length;
  buffer_valid = 1u;
  total_len = (uint64_t)length * 2u;

  /* Initialize the exerciser if available for the endpoint BDF. */
  if (val_exerciser_init_by_bdf(endpoint_bdf))
  {
    result = ACS_STATUS_SKIP;
    goto cleanup;
  }

  /* Configure SMMU translation for the endpoint DMA. */
  smmu_index = val_iovirt_get_rc_smmu_index(PCIE_EXTRACT_BDF_SEG(endpoint_bdf),
                                            PCIE_CREATE_BDF_PACKED(endpoint_bdf));
  if (smmu_index == ACS_INVALID_INDEX)
  {
    result = ACS_STATUS_SKIP;
    goto cleanup;
  }

  master.smmu_index = smmu_index;
  if (val_smmu_enable(master.smmu_index))
  {
    val_print(ACS_PRINT_ERR, " RBYTYV: SMMU enable failed", 0);
    result = ACS_STATUS_ERR;
    goto cleanup;
  }

  status = val_iovirt_get_device_info(PCIE_CREATE_BDF_PACKED(endpoint_bdf),
                                      PCIE_EXTRACT_BDF_SEG(endpoint_bdf),
                                      &device_id,
                                      &master.streamid,
                                      &its_id);
  if (status != 0u)
  {
    result = ACS_STATUS_SKIP;
    goto cleanup;
  }

  val_print(ACS_PRINT_DEBUG, " RBYTYV: EP BDF 0x%x", (uint64_t)endpoint_bdf);
  val_print(ACS_PRINT_DEBUG, " RBYTYV: SMMU index %u", master.smmu_index);
  val_print(ACS_PRINT_DEBUG, " RBYTYV: StreamID 0x%lx", master.streamid);
  val_print(ACS_PRINT_DEBUG, " RBYTYV: DeviceID 0x%x", (uint64_t)device_id);
  val_print(ACS_PRINT_DEBUG, " RBYTYV: ITS ID 0x%x", (uint64_t)its_id);

  mem_desc[0].virtual_address = buffer_pa;
  mem_desc[0].physical_address = buffer_pa;
  mem_desc[0].length = (uint32_t)total_len;
  mem_desc[1].length = 0u;

  pgt_desc_ns.ias = val_smmu_get_info(SMMU_IN_ADDR_SIZE, master.smmu_index);
  pgt_desc_ns.oas = val_smmu_get_info(SMMU_OUT_ADDR_SIZE, master.smmu_index);
  if ((pgt_desc_ns.ias == 0u) || (pgt_desc_ns.oas == 0u))
  {
    val_print(ACS_PRINT_ERR, " RBYTYV: SMMU address size invalid", 0);
    result = ACS_STATUS_SKIP;
    goto cleanup;
  }

  /* Program a Non-secure STE for the positive control DMA. */
  if (val_pe_reg_read_tcr(0, &pgt_desc_ns.tcr))
  {
    val_print(ACS_PRINT_ERR, " RBYTYV: TCR read failed", 0);
    result = ACS_STATUS_ERR;
    goto cleanup;
  }

  pgt_desc_ns.mair = val_pe_reg_read(MAIR_ELx);
  pgt_desc_ns.stage = PGT_STAGE1;
  pgt_desc_ns.pgt_base = (uint64_t)NULL;
  mem_desc[0].attributes = PGT_STAGE1_AP_RW;

  if (val_pgt_create(mem_desc, &pgt_desc_ns))
  {
    val_print(ACS_PRINT_ERR, " RBYTYV: NS PGT create failed", 0);
    result = ACS_STATUS_ERR;
    goto cleanup;
  }
  pgt_ns_created = 1u;

  master.stage2 = 0;
  if (val_smmu_map(master, pgt_desc_ns))
  {
    val_print(ACS_PRINT_ERR, " RBYTYV: NS SMMU map failed", 0);
    result = ACS_STATUS_ERR;
    goto cleanup;
  }
  smmu_ns_mapped = 1u;

  /* Use VTCR settings for Realm stage-2 translation. */
  if (val_pe_get_vtcr(&pgt_desc_rlm.vtcr))
  {
    val_print(ACS_PRINT_ERR, " RBYTYV: VTCR read failed", 0);
    result = ACS_STATUS_ERR;
    goto cleanup;
  }

  pgt_desc_rlm.ias = pgt_desc_ns.ias;
  pgt_desc_rlm.oas = pgt_desc_ns.oas;
  pgt_desc_rlm.pgt_base = (uint64_t)NULL;
  mem_desc[0].attributes = PGT_STAGE2_AP_RW;

  if (val_rlm_pgt_create(mem_desc, &pgt_desc_rlm))
  {
    val_print(ACS_PRINT_ERR, " RBYTYV: Realm PGT create failed", 0);
    result = ACS_STATUS_ERR;
    goto cleanup;
  }
  pgt_rlm_created = 1u;

  /* Provide the stage-2 base for EL3 to program the STE. */
  val_pe_reg_write(VTTBR, pgt_desc_rlm.pgt_base);
  master.stage2 = 1;
  if (val_smmu_rlm_map_el3(&master, &pgt_desc_rlm))
  {
    val_print(ACS_PRINT_ERR, " RBYTYV: Realm SMMU map failed", 0);
    result = ACS_STATUS_ERR;
    goto cleanup;
  }
  smmu_rlm_mapped = 1u;

  /* Configure translated addressing for DMA transactions. */
  if (val_exerciser_set_param_by_bdf(CFG_TXN_ATTRIBUTES,
                                     TXN_ADDR_TYPE,
                                     AT_TRANSLATED,
                                     endpoint_bdf))
  {
    result = ACS_STATUS_SKIP;
    goto cleanup;
  }

  /* Program a DMA to non-secure memory as a positive control. */
  val_memory_set(buffer_src, length, 0xAB);
  val_memory_set(buffer_dst, length, 0x0);
  val_pe_cache_clean_invalidate_range((uint64_t)buffer_src, length);
  val_pe_cache_invalidate_range((uint64_t)buffer_dst, length);

  if (val_add_gpt_entry_el3(buffer_pa, GPT_NONSECURE))
  {
    result = ACS_STATUS_ERR;
    goto cleanup;
  }
  if (val_add_gpt_entry_el3(buffer_pa + length, GPT_NONSECURE))
  {
    result = ACS_STATUS_ERR;
    goto cleanup;
  }

  if (val_smmu_gpt_invalidate_el3(&master))
  {
    val_print(ACS_PRINT_ERR, " RBYTYV: SMMU invalidate failed", 0);
    result = ACS_STATUS_ERR;
    goto cleanup;
  }

  if (map_dma_buffers_el3(buffer_va,
                          buffer_pa,
                          length,
                          REALM_PAS) != ACS_STATUS_PASS)
  {
    val_print(ACS_PRINT_ERR, " RBYTYV: EL3 map failed", 0);
    result = ACS_STATUS_ERR;
    goto cleanup;
  }

  status = val_exerciser_set_param_by_bdf(DMA_ATTRIBUTES,
                                          buffer_src_pa,
                                          length,
                                          endpoint_bdf);
  if (status != 0u)
  {
    val_print(ACS_PRINT_ERR, " RBYTYV: DMA attributes set failed", 0);
    result = ACS_STATUS_SKIP;
    goto cleanup;
  }

  (void)val_exerciser_ops_by_bdf(START_DMA, EDMA_TO_DEVICE, endpoint_bdf);

  status = val_exerciser_set_param_by_bdf(DMA_ATTRIBUTES,
                                          buffer_dst_pa,
                                          length,
                                          endpoint_bdf);
  if (status != 0u)
  {
    val_print(ACS_PRINT_ERR, " RBYTYV: DMA attributes set failed", 0);
    result = ACS_STATUS_SKIP;
    goto cleanup;
  }

  (void)val_exerciser_ops_by_bdf(START_DMA, EDMA_FROM_DEVICE, endpoint_bdf);

  val_pe_cache_invalidate_range((uint64_t)buffer_dst, length);
  if (val_memory_compare(buffer_src, buffer_dst, length) != 0)
  {
    val_print(ACS_PRINT_ERR, " RBYTYV: NS DMA compare failed", 0);
    result = ACS_STATUS_FAIL;
    goto cleanup;
  }

  /* Program a DMA to Realm memory and expect rejection. */
  val_memory_set(buffer_dst, length, 0x0);
  val_pe_cache_clean_invalidate_range((uint64_t)buffer_src, length);
  val_pe_cache_clean_invalidate_range((uint64_t)buffer_dst, length);
  if (val_add_gpt_entry_el3(buffer_pa, GPT_REALM))
  {
    result = ACS_STATUS_ERR;
    goto cleanup;
  }
  if (val_add_gpt_entry_el3(buffer_pa + length, GPT_REALM))
  {
    result = ACS_STATUS_ERR;
    goto cleanup;
  }

  if (val_smmu_gpt_invalidate_el3(&master))
  {
    val_print(ACS_PRINT_ERR, " RBYTYV: SMMU invalidate failed", 0);
    result = ACS_STATUS_ERR;
    goto cleanup;
  }

  status = val_exerciser_set_param_by_bdf(DMA_ATTRIBUTES,
                                          buffer_dst_pa,
                                          length,
                                          endpoint_bdf);
  if (status != 0u)
  {
    val_print(ACS_PRINT_ERR, " RBYTYV: DMA attributes set failed", 0);
    result = ACS_STATUS_ERR;
    goto cleanup;
  }

  (void)val_exerciser_ops_by_bdf(START_DMA, EDMA_FROM_DEVICE, endpoint_bdf);

  cmp_status = compare_buffers_el3((uint64_t)buffer_src,
                                   (uint64_t)buffer_dst,
                                   length);
  if (cmp_status == ACS_STATUS_ERR)
  {
    val_print(ACS_PRINT_ERR, " RBYTYV: Realm EL3 compare failed", 0);
    result = ACS_STATUS_ERR;
  }
  else if (cmp_status == 0u)
  {
    val_print(ACS_PRINT_ERR, " RBYTYV: Realm DMA compare matched", 0);
    result = ACS_STATUS_FAIL;
  }

cleanup:
  if (buffer_valid != 0u)
  {
    if (val_add_gpt_entry_el3(buffer_pa, GPT_ANY))
      result = ACS_STATUS_ERR;
    if (val_add_gpt_entry_el3(buffer_pa + length, GPT_ANY))
      result = ACS_STATUS_ERR;
  }

  if (pgt_desc_ns.pgt_base != 0u)
  {
    if (val_add_gpt_entry_el3(pgt_desc_ns.pgt_base, GPT_ANY))
      result = ACS_STATUS_ERR;
  }
  if (pgt_desc_rlm.pgt_base != 0u)
  {
    if (val_add_gpt_entry_el3(pgt_desc_rlm.pgt_base, GPT_ANY))
      result = ACS_STATUS_ERR;
  }

  if (smmu_rlm_mapped != 0u)
    smmu_rlm_mapped = 0u;
  if (pgt_rlm_created != 0u)
    val_rlm_pgt_destroy(&pgt_desc_rlm);
  if (smmu_ns_mapped != 0u)
    smmu_ns_mapped = 0u;
  if (pgt_ns_created != 0u)
    val_pgt_destroy(pgt_desc_ns);
  if (master.smmu_index != ACS_INVALID_INDEX)
    val_smmu_disable(master.smmu_index);
  if (buffer_valid != 0u)
    val_memory_free_pages(buffer_va, 2);

  return result;
}

static uint32_t
verify_root_port(const CXL_COMPONENT_TABLE *table,
                 uint32_t root_index)
{
  const CXL_COMPONENT_ENTRY *root_port = &table->component[root_index];
  const CXL_COMPONENT_ENTRY *endpoint;
  RBYTYV_CONTEXT context;
  uint32_t host_index;
  uint64_t host_comp_base;
  uint64_t endpoint_comp_base;
  uint32_t status;
  uint64_t page_size;
  uint32_t endpoint_index = CXL_COMPONENT_INVALID_INDEX;
  uint32_t endpoint_bdf = 0u;
  uint32_t num_exercisers;
  uint32_t aer_offset = 0u;
  uint32_t restore_required = 0u;
  uint32_t result;

  /* Select a CXL exerciser downstream of this root port. */
  num_exercisers = val_cxl_exerciser_get_info(CXL_EXERCISER_NUM_CARDS);
  if (num_exercisers == 0u)
    return ACS_STATUS_SKIP;

  for (uint32_t ex_idx = 0u; ex_idx < num_exercisers; ++ex_idx)
  {
    uint32_t rp_bdf = 0u;

    endpoint_bdf = val_cxl_exerciser_get_bdf(ex_idx);
    if (endpoint_bdf == 0u)
      continue;

    if (val_cxl_find_upstream_root_port(endpoint_bdf, &rp_bdf) !=
        ACS_STATUS_PASS)
      continue;

    if (rp_bdf == root_port->bdf)
      break;

    endpoint_bdf = 0u;
  }

  if (endpoint_bdf == 0u)
    return ACS_STATUS_SKIP;

  status = find_component_index_by_bdf(table, endpoint_bdf, &endpoint_index);
  if (status != ACS_STATUS_PASS)
    return ACS_STATUS_SKIP;

  endpoint = &table->component[endpoint_index];

  val_print(ACS_PRINT_DEBUG, " RBYTYV: Selected RP BDF 0x%x",
            (uint64_t)root_port->bdf);
  val_print(ACS_PRINT_DEBUG, " RBYTYV: Selected EP BDF 0x%x",
            (uint64_t)endpoint->bdf);

  /* Only validate Type-2/Type-3 endpoints that expose CXL.mem access. */
  if ((endpoint->device_type != CXL_DEVICE_TYPE_TYPE2) &&
      (endpoint->device_type != CXL_DEVICE_TYPE_TYPE3))
  {
    val_print(ACS_PRINT_DEBUG, " RBYTYV: Endpoint type unsupported", 0);
    return ACS_STATUS_SKIP;
  }

  status = val_cxl_enable_mem(endpoint->bdf);
  if (status != ACS_STATUS_PASS)
  {
    val_print(ACS_PRINT_ERR, " RBYTYV: CXL.mem enable failed", 0);
    return (status == ACS_STATUS_SKIP) ? ACS_STATUS_SKIP : ACS_STATUS_FAIL;
  }

  host_index = root_port->host_bridge_index;
  if ((host_index == CXL_COMPONENT_INVALID_INDEX) ||
      (host_index >= (uint32_t)val_cxl_get_info(CXL_INFO_NUM_DEVICES, 0)))
  {
    val_print(ACS_PRINT_DEBUG, " RBYTYV: Host index invalid", 0);
    return ACS_STATUS_SKIP;
  }

  /* Ensure HDM decoder capabilities exist on host and endpoint. */
  host_comp_base = val_cxl_get_info(CXL_INFO_COMPONENT_BASE, host_index);
  endpoint_comp_base = endpoint->component_reg_base;
  if ((host_comp_base == 0u) || (endpoint_comp_base == 0u))
  {
    val_print(ACS_PRINT_DEBUG, " RBYTYV: Component base invalid", 0);
    return ACS_STATUS_SKIP;
  }

  if ((val_cxl_find_capability(host_comp_base, CXL_CAPID_HDM_DECODER, NULL)
       != ACS_STATUS_PASS) ||
      (val_cxl_find_capability(endpoint_comp_base, CXL_CAPID_HDM_DECODER, NULL)
       != ACS_STATUS_PASS))
  {
    val_print(ACS_PRINT_DEBUG, " RBYTYV: HDM decoder missing", 0);
    return ACS_STATUS_SKIP;
  }

  val_memory_set(&context, sizeof(context), 0);
  context.host_index = CXL_COMPONENT_INVALID_INDEX;
  context.endpoint_index = CXL_COMPONENT_INVALID_INDEX;
  context.host_index = host_index;
  context.endpoint_index = endpoint_index;

  status = program_host_target_list(root_port->bdf,
                                    host_comp_base,
                                    DECODER_SLOT,
                                    &context);
  if (status != ACS_STATUS_PASS)
  {
    val_print(ACS_PRINT_ERR, " RBYTYV: Target list program failed", 0);
    return ACS_STATUS_FAIL;
  }
  restore_required = 1u;

  /* Select and program a CFMWS window for CXL.mem access. */
  status = val_cxl_select_cfmws_window(host_index,
                                       &context.window_base,
                                       &context.window_size);
  if (status != ACS_STATUS_PASS)
  {
    result = ACS_STATUS_SKIP;
    goto cleanup;
  }

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
    val_print(ACS_PRINT_ERR, " RBYTYV: Host decoder program failed", 0);
    result = (status == ACS_STATUS_SKIP) ? ACS_STATUS_SKIP : ACS_STATUS_FAIL;
    goto cleanup;
  }

  status = val_cxl_program_component_decoder(context.endpoint_index,
                                             DECODER_SLOT,
                                             context.window_base,
                                             context.window_size);
  if (status != ACS_STATUS_PASS)
  {
    val_print(ACS_PRINT_ERR, " RBYTYV: Endpoint decoder program failed", 0);
    result = (status == ACS_STATUS_SKIP) ? ACS_STATUS_SKIP : ACS_STATUS_FAIL;
    goto cleanup;
  }

  if (val_pcie_find_capability(root_port->bdf,
                               PCIE_ECAP,
                               ECID_AER,
                               &aer_offset) != PCIE_SUCCESS)
    aer_offset = 0u;

  /* Step 1: Verify non-secure access succeeds for host-to-device requests. */
  status = access_cxl_mem(root_port->bdf,
                          endpoint->bdf,
                          aer_offset,
                          context.window_base,
                          NONSECURE_PAS,
                          0u);
  if (status != ACS_STATUS_PASS)
  {
    val_print(ACS_PRINT_ERR, " RBYTYV: NS host-to-device access failed", 0);
    result = ACS_STATUS_FAIL;
    goto cleanup;
  }

  /* Step 2: Verify Realm host-to-device requests are rejected. */
  status = access_cxl_mem(root_port->bdf,
                          endpoint->bdf,
                          aer_offset,
                          context.window_base,
                          REALM_PAS,
                          1u);
  if (status != ACS_STATUS_PASS)
  {
    val_print(ACS_PRINT_ERR, " RBYTYV: Realm host-to-device reject failed", 0);
    result = ACS_STATUS_FAIL;
    goto cleanup;
  }

  /* Step 3: Verify device-to-host traffic is forced to Non-secure. */
  page_size = (uint64_t)val_memory_page_size();
  if (page_size != 0u)
  {
    status = check_device_to_host_dma(endpoint->bdf, (uint32_t)page_size);
    if (status == ACS_STATUS_FAIL)
    {
      val_print(ACS_PRINT_ERR, " RBYTYV: Device-to-host reject failed", 0);
      result = ACS_STATUS_FAIL;
      goto cleanup;
    }
  }

  result = ACS_STATUS_PASS;

cleanup:
  if (restore_required != 0u)
    restore_decoders(&context);

  return result;
}

static void
payload(void)
{
  uint32_t pe_index = val_pe_get_index_mpid(val_pe_get_mpid());
  CXL_COMPONENT_TABLE *table = val_cxl_component_table_ptr();
  uint32_t tested = 0u;
  uint32_t failures = 0u;

  if ((table == NULL) || (table->num_entries == 0u))
  {
    val_print(ACS_PRINT_DEBUG, " RBYTYV: No CXL components", 0);
    val_set_status(pe_index, "SKIP", 01);
    return;
  }

  for (uint32_t idx = 0; idx < table->num_entries; ++idx)
  {
    const CXL_COMPONENT_ENTRY *component = &table->component[idx];
    uint32_t dvsec_offset;
    uint32_t status;

    if (component->role != CXL_COMPONENT_ROLE_ROOT_PORT)
      continue;

    val_print(ACS_PRINT_DEBUG, " RBYTYV: Considering RP BDF 0x%x",
              (uint64_t)component->bdf);

    /* Step 1: If RME-CDA DVSEC is present, RBYTYV is satisfied. */
    if (val_pcie_find_cda_capability(component->bdf, &dvsec_offset) == PCIE_SUCCESS)
    {
      tested++;
      continue;
    }

    /* Step 2: Locate a downstream endpoint for non-DVSEC root ports. */
    status = verify_root_port(table, idx);
    if (status == ACS_STATUS_SKIP)
    {
      val_print(ACS_PRINT_INFO,
                " RBYTYV: Skipping RP BDF 0x%x",
                (uint64_t)component->bdf);
      continue;
    }

    if (status != ACS_STATUS_PASS)
    {
      val_print(ACS_PRINT_ERR,
                " RBYTYV: RP BDF 0x%x failed",
                (uint64_t)component->bdf);
      failures++;
      continue;
    }

    tested++;
  }

  if ((tested == 0u) && (failures == 0u))
  {
    val_set_status(pe_index, "SKIP", 02);
    return;
  }

  if (failures != 0u)
    val_set_status(pe_index, "FAIL", failures);
  else
    val_set_status(pe_index, "PASS", 01);
}

uint32_t
cxl_rbytyv_root_port_pas_behavior_entry(uint32_t num_pe)
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
