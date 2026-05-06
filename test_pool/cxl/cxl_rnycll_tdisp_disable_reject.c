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

#define TEST_NAME "cxl_rnycll_tdisp_disable_reject"
#define TEST_DESC "TDISP disabled rejects Realm-tagged CXL requests"
#define TEST_RULE "RNYCLL"

#define DECODER_SLOT 0u

#define RMECDA_CTL1_TDISP_EN_MASK 0x1u

#define PCIE_LNKCAP_OFFSET 0x0Cu
#define PCIE_LNKCAP_PN_SHIFT 24u
#define PCIE_LNKCAP_PN_MASK 0xFFu
#define SEC_SID_NONSECURE 0x0u
#define SEC_SID_REALM 0x2u

typedef struct {
  uint32_t host_index;
  uint32_t root_index;
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
  uint32_t rmecda_ctl1_orig;
  uint32_t rmecda_ctl1_valid;
  uint32_t rmecda_cap_base;
  uint64_t rmecda_cfg_va;
} RNYCLL_CONTEXT;

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
find_downstream_chi_c2c_exerciser_endpoint(uint32_t root_bdf,
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

    if (val_exerciser_init_by_bdf(candidate_bdf) == 0u)
    {
      *endpoint_bdf_out = candidate_bdf;
      return ACS_STATUS_PASS;
    }
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
prepare_dma_buffers_el3(uint8_t *buffer_src,
                        uint8_t *buffer_dst,
                        uint32_t length)
{
  if ((buffer_src == NULL) || (buffer_dst == NULL))
    return ACS_STATUS_ERR;

  if (val_memory_set_el3(buffer_src, length, 0xABu))
    return ACS_STATUS_ERR;

  if (val_memory_set_el3(buffer_dst, length, 0x0u))
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
      val_print(ACS_PRINT_ERR, " RNYCLL: EL3 read failed for 0x%llx", src_va);
      return ACS_STATUS_ERR;
    }
    src_data = shared_data->shared_data_access[0].data;

    shared_data->shared_data_access[0].addr = dst_va;
    if (val_pe_access_mut_el3())
    {
      val_print(ACS_PRINT_ERR, " RNYCLL: EL3 read failed for 0x%llx", dst_va);
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
                         RNYCLL_CONTEXT *context)
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
restore_host_target_list(const RNYCLL_CONTEXT *context)
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
restore_decoders(const RNYCLL_CONTEXT *context)
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
            " RNYCLL: Media baseline 0x%llx",
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
            " RNYCLL: Media observed 0x%llx",
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
  uint8_t *buffer_ns_alias;
  uint8_t *buffer_src_ns_alias;
  uint8_t *buffer_dst_ns_alias;
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
  uint32_t result = ACS_STATUS_PASS;

  val_memory_set(&master, sizeof(master), 0);
  val_memory_set(mem_desc, sizeof(mem_desc), 0);
  val_memory_set(&pgt_desc_ns, sizeof(pgt_desc_ns), 0);
  val_memory_set(&pgt_desc_rlm, sizeof(pgt_desc_rlm), 0);

  total_len = (uint64_t)length * 2u;
  buffer_va = (uint8_t *)val_get_free_va(total_len);
  if (buffer_va == NULL)
    return ACS_STATUS_SKIP;

  buffer_pa = (uint64_t)val_memory_virt_to_phys(buffer_va);
  if (buffer_pa == 0u)
    return ACS_STATUS_SKIP;

  buffer_src = buffer_va;
  buffer_dst = buffer_va + length;
  buffer_src_pa = buffer_pa;
  buffer_dst_pa = buffer_pa + length;
  buffer_valid = 1u;
  buffer_ns_alias = (uint8_t *)val_get_free_va(total_len);
  if (buffer_ns_alias == NULL)
    return ACS_STATUS_SKIP;

  buffer_src_ns_alias = buffer_ns_alias;
  buffer_dst_ns_alias = buffer_ns_alias + length;

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
    val_print(ACS_PRINT_ERR, " RNYCLL: SMMU enable failed", 0);
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

  val_print(ACS_PRINT_DEBUG, " RNYCLL: EP BDF 0x%x", (uint64_t)endpoint_bdf);
  val_print(ACS_PRINT_DEBUG, " RNYCLL: SMMU index %u", master.smmu_index);
  val_print(ACS_PRINT_DEBUG, " RNYCLL: StreamID 0x%lx", master.streamid);
  val_print(ACS_PRINT_DEBUG, " RNYCLL: DeviceID 0x%x", (uint64_t)device_id);
  val_print(ACS_PRINT_DEBUG, " RNYCLL: ITS ID 0x%x", (uint64_t)its_id);

  mem_desc[0].virtual_address = buffer_pa;
  mem_desc[0].physical_address = buffer_pa;
  mem_desc[0].length = (uint32_t)total_len;
  mem_desc[1].length = 0u;

  pgt_desc_ns.ias = val_smmu_get_info(SMMU_IN_ADDR_SIZE, master.smmu_index);
  pgt_desc_ns.oas = val_smmu_get_info(SMMU_OUT_ADDR_SIZE, master.smmu_index);
  if ((pgt_desc_ns.ias == 0u) || (pgt_desc_ns.oas == 0u))
  {
    val_print(ACS_PRINT_ERR, " RNYCLL: SMMU address size invalid", 0);
    result = ACS_STATUS_SKIP;
    goto cleanup;
  }

  /* Program a Non-secure STE for the positive control DMA. */
  if (val_pe_reg_read_tcr(0, &pgt_desc_ns.tcr))
  {
    val_print(ACS_PRINT_ERR, " RNYCLL: TCR read failed", 0);
    result = ACS_STATUS_ERR;
    goto cleanup;
  }

  pgt_desc_ns.mair = val_pe_reg_read(MAIR_ELx);
  pgt_desc_ns.stage = PGT_STAGE1;
  pgt_desc_ns.pgt_base = (uint64_t)NULL;
  mem_desc[0].attributes = PGT_STAGE1_AP_RW;

  if (val_pgt_create(mem_desc, &pgt_desc_ns))
  {
    val_print(ACS_PRINT_ERR, " RNYCLL: NS PGT create failed", 0);
    result = ACS_STATUS_ERR;
    goto cleanup;
  }
  pgt_ns_created = 1u;

  master.stage2 = 0;
  if (val_smmu_map(master, pgt_desc_ns))
  {
    val_print(ACS_PRINT_ERR, " RNYCLL: NS SMMU map failed", 0);
    result = ACS_STATUS_ERR;
    goto cleanup;
  }
  smmu_ns_mapped = 1u;

  /* Use VTCR settings for Realm stage-2 translation. */
  if (val_pe_get_vtcr(&pgt_desc_rlm.vtcr))
  {
    val_print(ACS_PRINT_ERR, " RNYCLL: VTCR read failed", 0);
    result = ACS_STATUS_ERR;
    goto cleanup;
  }

  pgt_desc_rlm.ias = pgt_desc_ns.ias;
  pgt_desc_rlm.oas = pgt_desc_ns.oas;
  pgt_desc_rlm.pgt_base = (uint64_t)NULL;
  mem_desc[0].attributes = PGT_STAGE2_AP_RW;

  if (val_rlm_pgt_create(mem_desc, &pgt_desc_rlm))
  {
    val_print(ACS_PRINT_ERR, " RNYCLL: Realm PGT create failed", 0);
    result = ACS_STATUS_ERR;
    goto cleanup;
  }
  pgt_rlm_created = 1u;

  /* Provide the stage-2 base for EL3 to program the STE. */
  val_pe_reg_write(VTTBR, pgt_desc_rlm.pgt_base);
  master.stage2 = 1;
  if (val_smmu_rlm_map_el3(&master, &pgt_desc_rlm))
  {
    val_print(ACS_PRINT_ERR, " RNYCLL: Realm SMMU map failed", 0);
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
  if (val_exerciser_set_param_by_bdf(EXERCISER_SEC_SID,
                                     SEC_SID_NONSECURE,
                                     0u,
                                     endpoint_bdf))
  {
    val_print(ACS_PRINT_ERR, " RNYCLL: SEC_SID NS set failed", 0);
    result = ACS_STATUS_ERR;
    goto cleanup;
  }

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
    val_print(ACS_PRINT_ERR, " RNYCLL: SMMU invalidate failed", 0);
    result = ACS_STATUS_ERR;
    goto cleanup;
  }

  if (map_dma_buffers_el3(buffer_ns_alias,
                          buffer_pa,
                          length,
                          NONSECURE_PAS) != ACS_STATUS_PASS)
  {
    val_print(ACS_PRINT_ERR, " RNYCLL: EL3 NS map failed", 0);
    result = ACS_STATUS_ERR;
    goto cleanup;
  }

  status = val_exerciser_set_param_by_bdf(DMA_ATTRIBUTES,
                                          buffer_src_pa,
                                          length,
                                          endpoint_bdf);
  if (status != 0u)
  {
    val_print(ACS_PRINT_ERR, " RNYCLL: DMA attributes set failed", 0);
    result = ACS_STATUS_SKIP;
    goto cleanup;
  }

  /* Prepare NS source/destination buffers through EL3 to avoid NS cache aliasing. */
  if (prepare_dma_buffers_el3(buffer_src_ns_alias,
                              buffer_dst_ns_alias,
                              length) != ACS_STATUS_PASS)
  {
    val_print(ACS_PRINT_ERR, " RNYCLL: EL3 buffer init failed", 0);
    result = ACS_STATUS_ERR;
    goto cleanup;
  }

  (void)val_exerciser_ops_by_bdf(START_DMA, EDMA_TO_DEVICE, endpoint_bdf);

  status = val_exerciser_set_param_by_bdf(DMA_ATTRIBUTES,
                                          buffer_dst_pa,
                                          length,
                                          endpoint_bdf);
  if (status != 0u)
  {
    val_print(ACS_PRINT_ERR, " RNYCLL: DMA attributes set failed", 0);
    result = ACS_STATUS_SKIP;
    goto cleanup;
  }

  (void)val_exerciser_ops_by_bdf(START_DMA, EDMA_FROM_DEVICE, endpoint_bdf);

  status = compare_buffers_el3((uint64_t)buffer_src_ns_alias,
                               (uint64_t)buffer_dst_ns_alias,
                               length);
  if (status == ACS_STATUS_ERR)
  {
    val_print(ACS_PRINT_ERR, " RNYCLL: EL3 compare failed", 0);
    result = ACS_STATUS_ERR;
    goto cleanup;
  }
  if (status != 0u)
  {
    val_print(ACS_PRINT_ERR, " RNYCLL: NS DMA compare failed", 0);
    result = ACS_STATUS_FAIL;
    goto cleanup;
  }

  /* Program a DMA with SEC_SID==Realm to NS memory and expect rejection. */
  if (prepare_dma_buffers_el3(buffer_src_ns_alias,
                              buffer_dst_ns_alias,
                              length) != ACS_STATUS_PASS)
  {
    val_print(ACS_PRINT_ERR, " RNYCLL: EL3 buffer init failed", 0);
    result = ACS_STATUS_ERR;
    goto cleanup;
  }

  if (val_exerciser_set_param_by_bdf(EXERCISER_SEC_SID,
                                     SEC_SID_REALM,
                                     0u,
                                     endpoint_bdf))
  {
    val_print(ACS_PRINT_ERR, " RNYCLL: SEC_SID Realm set failed", 0);
    result = ACS_STATUS_ERR;
    goto cleanup;
  }

  status = val_exerciser_set_param_by_bdf(DMA_ATTRIBUTES,
                                          buffer_dst_pa,
                                          length,
                                          endpoint_bdf);
  if (status != 0u)
  {
    val_print(ACS_PRINT_ERR, " RNYCLL: DMA attributes set failed", 0);
    result = ACS_STATUS_ERR;
    goto cleanup;
  }

  (void)val_exerciser_ops_by_bdf(START_DMA, EDMA_FROM_DEVICE, endpoint_bdf);

  status = compare_buffers_el3((uint64_t)buffer_src_ns_alias,
                               (uint64_t)buffer_dst_ns_alias,
                               length);
  if (status == ACS_STATUS_ERR)
  {
    val_print(ACS_PRINT_ERR, " RNYCLL: EL3 compare failed", 0);
    result = ACS_STATUS_ERR;
    goto cleanup;
  }
  if (status == 0u)
  {
    val_print(ACS_PRINT_ERR, " RNYCLL: SEC_SID Realm DMA compare matched", 0);
    result = ACS_STATUS_FAIL;
    goto cleanup;
  }

  /* Program a DMA to Realm memory and expect rejection. */
  if (val_exerciser_set_param_by_bdf(EXERCISER_SEC_SID,
                                     SEC_SID_NONSECURE,
                                     0u,
                                     endpoint_bdf))
  {
    val_print(ACS_PRINT_ERR, " RNYCLL: SEC_SID NS set failed", 0);
    result = ACS_STATUS_ERR;
    goto cleanup;
  }

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
    val_print(ACS_PRINT_ERR, " RNYCLL: SMMU invalidate failed", 0);
    result = ACS_STATUS_ERR;
    goto cleanup;
  }

  if (map_dma_buffers_el3(buffer_va,
                          buffer_pa,
                          length,
                          REALM_PAS) != ACS_STATUS_PASS)
  {
    val_print(ACS_PRINT_ERR, " RNYCLL: EL3 map failed", 0);
    result = ACS_STATUS_ERR;
    goto cleanup;
  }

  /* Prepare Realm source/destination buffers through the Realm EL3 alias. */
  if (prepare_dma_buffers_el3(buffer_src, buffer_dst, length) != ACS_STATUS_PASS)
  {
    val_print(ACS_PRINT_ERR, " RNYCLL: Realm EL3 buffer init failed", 0);
    result = ACS_STATUS_ERR;
    goto cleanup;
  }

  status = val_exerciser_set_param_by_bdf(DMA_ATTRIBUTES,
                                          buffer_dst_pa,
                                          length,
                                          endpoint_bdf);
  if (status != 0u)
  {
    val_print(ACS_PRINT_ERR, " RNYCLL: DMA attributes set failed", 0);
    result = ACS_STATUS_ERR;
    goto cleanup;
  }

  (void)val_exerciser_ops_by_bdf(START_DMA, EDMA_FROM_DEVICE, endpoint_bdf);

  if (compare_buffers_el3((uint64_t)buffer_src,
                          (uint64_t)buffer_dst,
                          length) == 0u)
  {
    val_print(ACS_PRINT_ERR, " RNYCLL: Realm DMA compare matched", 0);
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

  return result;
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
    val_print(ACS_PRINT_ERR, " RNYCLL: MUT read failed for 0x%llx", address);
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
    val_print(ACS_PRINT_ERR, " RNYCLL: MUT write failed for 0x%llx", address);
    return ACS_STATUS_ERR;
  }

  return ACS_STATUS_PASS;
}

static uint32_t
disable_tdisp(const CXL_COMPONENT_ENTRY *root_port,
              RNYCLL_CONTEXT *context)
{
  uint32_t rmecda_cap_base;
  uint64_t cfg_addr;
  uint64_t tg;
  uint32_t attr;
  uint32_t rmecda_ctl1;

  if ((root_port == NULL) || (context == NULL))
    return ACS_STATUS_ERR;

  if (val_pcie_find_cda_capability(root_port->bdf, &rmecda_cap_base) !=
      PCIE_SUCCESS)
  {
    val_print(ACS_PRINT_INFO, " RNYCLL: RME-CDA DVSEC missing", 0);
    return ACS_STATUS_SKIP;
  }

  cfg_addr = val_pcie_get_bdf_config_addr(root_port->bdf);
  tg = val_get_min_tg();
  if ((cfg_addr == 0u) || (tg == 0u))
  {
    val_print(ACS_PRINT_ERR, " RNYCLL: Invalid config mapping", 0);
    return ACS_STATUS_FAIL;
  }

  context->rmecda_cfg_va = val_get_free_va(tg);
  if (context->rmecda_cfg_va == 0u)
  {
    val_print(ACS_PRINT_ERR, " RNYCLL: Config VA allocation failed", 0);
    return ACS_STATUS_FAIL;
  }

  attr = LOWER_ATTRS(PGT_ENTRY_ACCESS | SHAREABLE_ATTR(OUTER_SHAREABLE) |
                     GET_ATTR_INDEX(DEV_MEM_nGnRnE) | PGT_ENTRY_AP_RW |
                     PAS_ATTR(ROOT_PAS));
  if (val_add_mmu_entry_el3(context->rmecda_cfg_va, cfg_addr, attr))
  {
    val_print(ACS_PRINT_ERR, " RNYCLL: Config map failed", 0);
    return ACS_STATUS_FAIL;
  }

  context->rmecda_cap_base = rmecda_cap_base;
  if (read_from_root(context->rmecda_cfg_va + rmecda_cap_base +
                     RMECDA_CTL1_OFFSET,
                     &context->rmecda_ctl1_orig) != ACS_STATUS_PASS)
  {
    val_print(ACS_PRINT_ERR, " RNYCLL: RMECDA_CTL1 read failed", 0);
    return ACS_STATUS_FAIL;
  }

  rmecda_ctl1 = context->rmecda_ctl1_orig & ~RMECDA_CTL1_TDISP_EN_MASK;
  if (write_from_root(context->rmecda_cfg_va + rmecda_cap_base +
                      RMECDA_CTL1_OFFSET,
                      rmecda_ctl1) != ACS_STATUS_PASS)
  {
    val_print(ACS_PRINT_ERR, " RNYCLL: RMECDA_CTL1 write failed", 0);
    return ACS_STATUS_FAIL;
  }

  if (read_from_root(context->rmecda_cfg_va + rmecda_cap_base +
                     RMECDA_CTL1_OFFSET,
                     &rmecda_ctl1) != ACS_STATUS_PASS)
  {
    val_print(ACS_PRINT_ERR, " RNYCLL: RMECDA_CTL1 readback failed", 0);
    return ACS_STATUS_FAIL;
  }

  if ((rmecda_ctl1 & RMECDA_CTL1_TDISP_EN_MASK) != 0u)
  {
    val_print(ACS_PRINT_ERR, " RNYCLL: TDISP_EN still set", 0);
    return ACS_STATUS_FAIL;
  }

  context->rmecda_ctl1_valid = 1u;
  return ACS_STATUS_PASS;
}

static uint32_t
verify_root_port(const CXL_COMPONENT_TABLE *table,
                 uint32_t root_index)
{
  const CXL_COMPONENT_ENTRY *root_port = &table->component[root_index];
  const CXL_COMPONENT_ENTRY *endpoint;
  RNYCLL_CONTEXT context;
  uint32_t host_index;
  uint64_t host_comp_base;
  uint64_t endpoint_comp_base;
  uint32_t status;
  uint64_t page_size;
  uint32_t endpoint_index = CXL_COMPONENT_INVALID_INDEX;
  uint32_t endpoint_bdf = ACS_INVALID_INDEX;
  uint32_t aer_offset = 0u;
  uint32_t result;

  /* Select a downstream CHI C2C-capable exerciser endpoint for this root port. */
  status = find_downstream_chi_c2c_exerciser_endpoint(root_port->bdf, &endpoint_bdf);
  if (status != ACS_STATUS_PASS)
    return ACS_STATUS_SKIP;

  status = find_component_index_by_bdf(table, endpoint_bdf, &endpoint_index);
  if (status != ACS_STATUS_PASS)
    return ACS_STATUS_SKIP;

  endpoint = &table->component[endpoint_index];

  val_print(ACS_PRINT_DEBUG, " RNYCLL: Selected RP BDF 0x%x",
            (uint64_t)root_port->bdf);
  val_print(ACS_PRINT_DEBUG, " RNYCLL: Selected EP BDF 0x%x",
            (uint64_t)endpoint->bdf);

  /* Only validate Type-2/Type-3 endpoints that expose CXL.mem access. */
  if ((endpoint->device_type != CXL_DEVICE_TYPE_TYPE2) &&
      (endpoint->device_type != CXL_DEVICE_TYPE_TYPE3))
  {
    val_print(ACS_PRINT_DEBUG, " RNYCLL: Endpoint type unsupported", 0);
    return ACS_STATUS_SKIP;
  }

  status = val_cxl_enable_mem(endpoint->bdf);
  if (status != ACS_STATUS_PASS)
  {
    val_print(ACS_PRINT_ERR, " RNYCLL: CXL.mem enable failed", 0);
    return (status == ACS_STATUS_SKIP) ? ACS_STATUS_SKIP : ACS_STATUS_FAIL;
  }

  host_index = root_port->host_bridge_index;
  if ((host_index == CXL_COMPONENT_INVALID_INDEX) ||
      (host_index >= (uint32_t)val_cxl_get_info(CXL_INFO_NUM_DEVICES, 0)))
  {
    val_print(ACS_PRINT_DEBUG, " RNYCLL: Host index invalid", 0);
    return ACS_STATUS_SKIP;
  }

  /* Ensure HDM decoder capabilities exist on host and endpoint. */
  host_comp_base = val_cxl_get_info(CXL_INFO_COMPONENT_BASE, host_index);
  endpoint_comp_base = endpoint->component_reg_base;
  if ((host_comp_base == 0u) || (endpoint_comp_base == 0u))
  {
    val_print(ACS_PRINT_DEBUG, " RNYCLL: Component base invalid", 0);
    return ACS_STATUS_SKIP;
  }

  if ((val_cxl_find_capability(host_comp_base, CXL_CAPID_HDM_DECODER, NULL)
       != ACS_STATUS_PASS) ||
      (val_cxl_find_capability(endpoint_comp_base, CXL_CAPID_HDM_DECODER, NULL)
       != ACS_STATUS_PASS))
  {
    val_print(ACS_PRINT_DEBUG, " RNYCLL: HDM decoder missing", 0);
    return ACS_STATUS_SKIP;
  }

  val_memory_set(&context, sizeof(context), 0);
  context.host_index = host_index;
  context.root_index = root_index;
  context.endpoint_index = endpoint_index;

  status = program_host_target_list(root_port->bdf,
                                    host_comp_base,
                                    DECODER_SLOT,
                                    &context);
  if (status != ACS_STATUS_PASS)
  {
    val_print(ACS_PRINT_ERR, " RNYCLL: Target list program failed", 0);
    return ACS_STATUS_FAIL;
  }

  /* Select and program a CFMWS window for CXL.mem access. */
  status = val_cxl_select_cfmws_window(host_index,
                                       &context.window_base,
                                       &context.window_size);
  if (status != ACS_STATUS_PASS)
    return ACS_STATUS_SKIP;

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
    val_print(ACS_PRINT_ERR, " RNYCLL: Host decoder program failed", 0);
    result = (status == ACS_STATUS_SKIP) ? ACS_STATUS_SKIP : ACS_STATUS_FAIL;
    goto cleanup;
  }

  status = val_cxl_program_component_decoder(context.endpoint_index,
                                             DECODER_SLOT,
                                             context.window_base,
                                             context.window_size);
  if (status != ACS_STATUS_PASS)
  {
    val_print(ACS_PRINT_ERR, " RNYCLL: Endpoint decoder program failed", 0);
    result = (status == ACS_STATUS_SKIP) ? ACS_STATUS_SKIP : ACS_STATUS_FAIL;
    goto cleanup;
  }

  status = disable_tdisp(root_port, &context);
  if (status != ACS_STATUS_PASS)
  {
    result = status;
    goto cleanup;
  }

  if (val_pcie_find_capability(root_port->bdf,
                               PCIE_ECAP,
                               ECID_AER,
                               &aer_offset) != PCIE_SUCCESS)
    aer_offset = 0u;

  /* Step 1: Verify non-secure host-to-device access succeeds. */
  status = access_cxl_mem(root_port->bdf,
                          endpoint->bdf,
                          aer_offset,
                          context.window_base,
                          NONSECURE_PAS,
                          0u);
  if (status != ACS_STATUS_PASS)
  {
    val_print(ACS_PRINT_ERR, " RNYCLL: NS host-to-device access failed", 0);
    result = ACS_STATUS_FAIL;
    goto cleanup;
  }

  /* Step 2: Verify Realm host-to-device requests are rejected (PAS==Realm). */
  status = access_cxl_mem(root_port->bdf,
                          endpoint->bdf,
                          aer_offset,
                          context.window_base,
                          REALM_PAS,
                          1u);
  if (status != ACS_STATUS_PASS)
  {
    val_print(ACS_PRINT_ERR, " RNYCLL: Realm host-to-device reject failed", 0);
    result = ACS_STATUS_FAIL;
    goto cleanup;
  }

  /*
   * Step 3: Verify device-to-host DMA rejects Realm-tagged requests.
   * Check both SEC_SID==Realm (PAS==NS) and PAS==Realm (SEC_SID==NS).
   */
  page_size = (uint64_t)val_memory_page_size();
  if (page_size != 0u)
  {
    status = check_device_to_host_dma(endpoint->bdf, (uint32_t)page_size);
    if (status == ACS_STATUS_FAIL)
    {
      val_print(ACS_PRINT_ERR, " RNYCLL: Device-to-host reject failed", 0);
      result = ACS_STATUS_FAIL;
      goto cleanup;
    }
  }

  result = ACS_STATUS_PASS;

cleanup:
  restore_decoders(&context);
  if ((context.rmecda_ctl1_valid != 0u) && (context.rmecda_cfg_va != 0u))
    (void)write_from_root(context.rmecda_cfg_va + context.rmecda_cap_base +
                          RMECDA_CTL1_OFFSET,
                          context.rmecda_ctl1_orig);

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
    val_print(ACS_PRINT_DEBUG, " RNYCLL: No CXL components", 0);
    val_set_status(pe_index, "SKIP", 01);
    return;
  }

  for (uint32_t idx = 0; idx < table->num_entries; ++idx)
  {
    const CXL_COMPONENT_ENTRY *component = &table->component[idx];
    uint32_t status;

    if (component->role != CXL_COMPONENT_ROLE_ROOT_PORT)
      continue;
    if (component->chi_c2c_supported == 0u)
      continue;

    val_print(ACS_PRINT_DEBUG, " RNYCLL: Considering RP BDF 0x%x",
              (uint64_t)component->bdf);

    status = verify_root_port(table, idx);
    if (status == ACS_STATUS_SKIP)
    {
      val_print(ACS_PRINT_INFO,
                " RNYCLL: Skipping RP BDF 0x%x",
                (uint64_t)component->bdf);
      continue;
    }

    if (status != ACS_STATUS_PASS)
    {
      val_print(ACS_PRINT_ERR,
                " RNYCLL: RP BDF 0x%x failed",
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
cxl_rnycll_tdisp_disable_reject_entry(uint32_t num_pe)
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
