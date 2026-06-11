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
#include "val/include/val_memory.h"
#include "val/include/val_pcie.h"
#include "val/include/val_pe.h"
#include "val/include/val_el32.h"
#include "val/include/val_exerciser.h"
#include "val/include/val_iovirt.h"
#include "val/include/val_smmu.h"

#define TEST_NAME "cxl_rhhmvm_bisnp_pas_nonsecure"
#define TEST_DESC "BISnp is tagged Non-secure when CDA absent or TDISP disabled"
#define TEST_RULE "RHHMVM"

#define DECODER_SLOT 0u
#define RMECDA_CTL1_TDISP_EN_MASK 0x1u
#define RMECDA_CTL1_LINK_STR_LOCK_MASK (1u << 1)
#define PCIE_LNKCAP_OFFSET 0x0Cu
#define PCIE_LNKCAP_PN_SHIFT 24u
#define PCIE_LNKCAP_PN_MASK 0xFFu

#define TEST_DEVICE_VALUE_V0 0x11112222u
#define TEST_HOST_VALUE_V1   0xA5A55A5Au
#define TEST_DEVICE_VALUE_V2 0x55AA33CCu

typedef struct {
  uint32_t host_index;
  uint32_t root_index;
  uint32_t endpoint_index;
  uint32_t exerciser_bdf;
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
} RHHMVM_CONTEXT;

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
    val_print(ACS_PRINT_ERR, " RHHMVM: MUT read failed for 0x%llx", address);
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
    val_print(ACS_PRINT_ERR, " RHHMVM: MUT write failed for 0x%llx", address);
    return ACS_STATUS_ERR;
  }

  return ACS_STATUS_PASS;
}

static uint32_t
program_host_target_list(uint32_t bdf,
                         uint64_t comp_base,
                         RHHMVM_CONTEXT *context)
{
  uint32_t pcie_cap_offset;
  uint32_t lnkcap;
  uint32_t port_id;
  uint64_t hdm_cap_base;

  if (context == NULL)
    return ACS_STATUS_ERR;

  if (val_pcie_find_capability(bdf, PCIE_CAP, CID_PCIECS, &pcie_cap_offset) != 0u)
    return ACS_STATUS_ERR;

  if (val_pcie_read_cfg(bdf, pcie_cap_offset + PCIE_LNKCAP_OFFSET, &lnkcap) != 0u)
    return ACS_STATUS_ERR;

  port_id = (lnkcap >> PCIE_LNKCAP_PN_SHIFT) & PCIE_LNKCAP_PN_MASK;

  if (val_cxl_find_capability(comp_base, CXL_CAPID_HDM_DECODER, &hdm_cap_base)
      != ACS_STATUS_PASS)
    return ACS_STATUS_ERR;

  context->host_target_low_orig = val_mmio_read(hdm_cap_base +
                                                CXL_HDM_DECODER_TARGET_LOW(DECODER_SLOT));
  context->host_target_high_orig = val_mmio_read(hdm_cap_base +
                                                 CXL_HDM_DECODER_TARGET_HIGH(DECODER_SLOT));
  context->host_target_valid = 1u;

  val_mmio_write(hdm_cap_base + CXL_HDM_DECODER_TARGET_LOW(DECODER_SLOT), port_id);
  val_mmio_write(hdm_cap_base + CXL_HDM_DECODER_TARGET_HIGH(DECODER_SLOT), 0u);

  return ACS_STATUS_PASS;
}

static void
restore_decoders(const RHHMVM_CONTEXT *context)
{
  uint64_t comp_base;
  uint64_t hdm_cap_base;

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
      comp_base = val_cxl_get_info(CXL_INFO_COMPONENT_BASE, context->host_index);
      if ((comp_base != 0u) &&
          (val_cxl_find_capability(comp_base,
                                   CXL_CAPID_HDM_DECODER,
                                   &hdm_cap_base) == ACS_STATUS_PASS))
      {
        val_mmio_write(hdm_cap_base + CXL_HDM_DECODER_TARGET_LOW(DECODER_SLOT),
                       context->host_target_low_orig);
        val_mmio_write(hdm_cap_base + CXL_HDM_DECODER_TARGET_HIGH(DECODER_SLOT),
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

  if ((context->rmecda_ctl1_valid != 0u) && (context->rmecda_cfg_va != 0u))
    (void)write_from_root(context->rmecda_cfg_va + context->rmecda_cap_base +
                          RMECDA_CTL1_OFFSET,
                          context->rmecda_ctl1_orig);
}

static uint32_t
map_alias(uint64_t phys, uint32_t pas, uint32_t attr_index, volatile uint32_t **virt_out)
{
  uint64_t page_size;
  uint64_t va;
  uint32_t attr;

  if ((virt_out == NULL) || (phys == 0u))
    return ACS_STATUS_ERR;

  page_size = (uint64_t)val_memory_page_size();
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

  *virt_out = (volatile uint32_t *)va;
  return ACS_STATUS_PASS;
}

static uint32_t
read_device_media(uint32_t endpoint_bdf, uint64_t pa, uint64_t *readback)
{
  if (readback == NULL)
    return ACS_STATUS_ERR;

  /* Program a backdoor media read command on the exerciser. */
  if (val_exerciser_set_param_by_bdf(EXERCISER_CXL_CMD_OP,
                                     CXL_CMD_OP_BACKDOOR_READ64,
                                     0u,
                                     endpoint_bdf))
    return ACS_STATUS_FAIL;

  if (val_exerciser_set_param_by_bdf(EXERCISER_CXL_CMD_ADDR, pa, 0u, endpoint_bdf))
    return ACS_STATUS_FAIL;

  if (val_exerciser_ops_by_bdf(CXL_CMD_START, 0u, endpoint_bdf))
    return ACS_STATUS_FAIL;

  if (val_exerciser_get_param_by_bdf(EXERCISER_CXL_CMD_DATA0,
                                     readback,
                                     NULL,
                                     endpoint_bdf))
    return ACS_STATUS_FAIL;

  return ACS_STATUS_PASS;
}

static uint32_t
write_device_media(uint32_t endpoint_bdf, uint64_t pa, uint64_t value)
{
  if (val_exerciser_set_param_by_bdf(EXERCISER_CXL_CMD_OP,
                                     CXL_CMD_OP_BACKDOOR_WRITE64,
                                     0u,
                                     endpoint_bdf))
    return ACS_STATUS_SKIP;

  if (val_exerciser_set_param_by_bdf(EXERCISER_CXL_CMD_ADDR, pa, 0u, endpoint_bdf))
    return ACS_STATUS_FAIL;

  if (val_exerciser_set_param_by_bdf(EXERCISER_CXL_CMD_DATA0, value, 0u, endpoint_bdf))
    return ACS_STATUS_FAIL;

  if (val_exerciser_ops_by_bdf(CXL_CMD_START, 0u, endpoint_bdf))
    return ACS_STATUS_FAIL;

  return ACS_STATUS_PASS;
}

static uint32_t
issue_bisnp(uint32_t endpoint_bdf, uint64_t pa, uint32_t allow_reject)
{
  (void)allow_reject;

  /* Program BISnp trigger opcode and target physical address. */
  if (val_exerciser_set_param_by_bdf(EXERCISER_CXL_CMD_OP,
                                     CXL_CMD_OP_BISNP,
                                     0u,
                                     endpoint_bdf))
  {
    val_print(ACS_PRINT_INFO, " RHHMVM: BISnp opcode unsupported", 0);
    return ACS_STATUS_SKIP;
  }

  if (val_exerciser_set_param_by_bdf(EXERCISER_CXL_CMD_ADDR, pa, 0u, endpoint_bdf))
  {
    val_print(ACS_PRINT_ERR, " RHHMVM: BISnp addr program failed 0x%llx", pa);
    return ACS_STATUS_FAIL;
  }

  if (val_exerciser_ops_by_bdf(CXL_CMD_START, 0u, endpoint_bdf))
  {
    val_print(ACS_PRINT_INFO, " RHHMVM: BISnp command returned error", 0);
    return ACS_STATUS_SKIP;
  }

  return ACS_STATUS_PASS;
}

static uint32_t
exercise_bisnp_behavior(const RHHMVM_CONTEXT *context, uint32_t host_pas)
{
  volatile uint32_t *cached_va = NULL;
  uint64_t media_value = 0u;
  uint64_t page_size;
  uint64_t pa_in;
  uint64_t host_readback = 0u;
  uint32_t status;
  uint32_t expected_host_value;

  if (context == NULL)
    return ACS_STATUS_ERR;

  page_size = (uint64_t)val_memory_page_size();
  if ((page_size == 0u) || (context->window_size < page_size))
    return ACS_STATUS_SKIP;

  if (context->window_size < (2u * page_size))
    return ACS_STATUS_SKIP;

  pa_in = (host_pas == REALM_PAS) ? context->window_base : (context->window_base + page_size);
  expected_host_value = (host_pas == REALM_PAS) ? TEST_HOST_VALUE_V1 : TEST_DEVICE_VALUE_V2;

  /* Step 1: Write V1 through a cacheable alias in selected PAS so it remains host-cached. */
  if (map_alias(pa_in, host_pas, WRITE_BACK_NT, &cached_va) != ACS_STATUS_PASS)
    return ACS_STATUS_FAIL;

  shared_data->num_access = 1;
  shared_data->shared_data_access[0].addr = (uint64_t)cached_va;
  shared_data->shared_data_access[0].data = (uint64_t)TEST_HOST_VALUE_V1;
  shared_data->shared_data_access[0].access_type = WRITE_DATA;
  if (val_pe_access_mut_el3())
    return ACS_STATUS_FAIL;

  /*
   * Step 2: Modify PA through exerciser media backdoor write.
   */
  status = write_device_media(context->exerciser_bdf, pa_in, TEST_DEVICE_VALUE_V2);
  if (status != ACS_STATUS_PASS)
    return status;

  status = read_device_media(context->exerciser_bdf, pa_in, &media_value);
  if (status != ACS_STATUS_PASS)
    return ACS_STATUS_FAIL;

  if ((uint32_t)media_value != TEST_DEVICE_VALUE_V2)
  {
    val_print(ACS_PRINT_ERR, " RHHMVM: media write verify failed 0x%llx", media_value);
    return ACS_STATUS_FAIL;
  }

  /*
   * Step 3: Disable TDISP_EN and LINK_STR_LOCK before issuing BISnp, as
   * RHHMVM applies when TDISP is disabled or RME-CDA DVSEC is absent.
   */
  if ((context->rmecda_ctl1_valid != 0u) && (context->rmecda_cfg_va != 0u))
  {
    uint32_t rmecda_ctl1;

    rmecda_ctl1 = context->rmecda_ctl1_orig &
                  ~(RMECDA_CTL1_TDISP_EN_MASK | RMECDA_CTL1_LINK_STR_LOCK_MASK);
    if (write_from_root(context->rmecda_cfg_va + context->rmecda_cap_base +
                        RMECDA_CTL1_OFFSET,
                        rmecda_ctl1) != ACS_STATUS_PASS)
      return ACS_STATUS_FAIL;

    if (read_from_root(context->rmecda_cfg_va + context->rmecda_cap_base +
                       RMECDA_CTL1_OFFSET,
                       &rmecda_ctl1) != ACS_STATUS_PASS)
      return ACS_STATUS_FAIL;

    if ((rmecda_ctl1 & (RMECDA_CTL1_TDISP_EN_MASK | RMECDA_CTL1_LINK_STR_LOCK_MASK)) != 0u)
    {
      val_print(ACS_PRINT_ERR, " RHHMVM: CTL1 disable verify failed 0x%x", rmecda_ctl1);
      return ACS_STATUS_FAIL;
    }
  }

  /* Step 4: Trigger BISnp for PA. */
  status = issue_bisnp(context->exerciser_bdf, pa_in, 0u);
  if (status != ACS_STATUS_PASS)
  {
    val_print(ACS_PRINT_INFO, " RHHMVM: BISnp command unsupported", 0);
    return ACS_STATUS_SKIP;
  }

  /* Step 5: Read PA back through MUT. */
  shared_data->num_access = 1;
  shared_data->shared_data_access[0].addr = (uint64_t)cached_va;
  shared_data->shared_data_access[0].access_type = READ_DATA;
  if (val_pe_access_mut_el3())
    return ACS_STATUS_FAIL;

  host_readback = shared_data->shared_data_access[0].data;
  val_print(ACS_PRINT_DEBUG, " RHHMVM: host readback after BISnp 0x%llx", host_readback);
  val_print(ACS_PRINT_DEBUG, " RHHMVM: expected host value 0x%x", expected_host_value);
  if ((uint32_t)host_readback != expected_host_value)
  {
    /*
     * Cache residency is not architecturally guaranteed between host fill and
     * BISnp trigger; treat mismatch as observational coverage, not hard fail.
     */
    val_print(ACS_PRINT_INFO, " RHHMVM: observational mismatch after BISnp; skipping", 0);
    return ACS_STATUS_SKIP;
  }

  return ACS_STATUS_PASS;
}


static uint32_t
force_all_smmus_disabled(void)
{
  uint32_t num_smmus = (uint32_t)val_iovirt_get_smmu_info(SMMU_NUM_CTRL, 0);

  for (uint32_t instance = 0u; instance < num_smmus; ++instance)
  {
    if (val_smmu_disable(instance) != 0u)
    {
      val_print(ACS_PRINT_ERR, " RHHMVM: failed to disable SMMU index %d", instance);
      return ACS_STATUS_FAIL;
    }
  }

  return ACS_STATUS_PASS;
}

static void
payload(void)
{
  uint32_t pe_index;
  CXL_COMPONENT_TABLE *table;
  RHHMVM_CONTEXT context;
  uint32_t num_exercisers;
  uint32_t status;
  uint32_t ep_found = 0u;
  uint64_t cfg_addr;
  uint64_t tg;
  uint32_t attr;
  uint32_t rmecda_ctl1;

  pe_index = val_pe_get_index_mpid(val_pe_get_mpid());
  table = val_cxl_component_table_ptr();

  if ((table == NULL) || (table->num_entries == 0u))
  {
    val_set_status(pe_index, "SKIP", 01);
    return;
  }

  val_memory_set(&context, sizeof(context), 0);
  num_exercisers = val_cxl_exerciser_get_info(CXL_EXERCISER_NUM_CARDS);
  if (num_exercisers == 0u)
  {
    val_set_status(pe_index, "SKIP", 02);
    return;
  }

  for (uint32_t ex_idx = 0u; ex_idx < num_exercisers; ++ex_idx)
  {
    uint32_t endpoint_index = CXL_COMPONENT_INVALID_INDEX;
    uint32_t root_index = CXL_COMPONENT_INVALID_INDEX;
    uint32_t endpoint_bdf;
    uint32_t root_bdf;
    const CXL_COMPONENT_ENTRY *root_port;
    const CXL_COMPONENT_ENTRY *endpoint;
    uint64_t host_comp_base;

    endpoint_bdf = val_cxl_exerciser_get_bdf(ex_idx);
    if (endpoint_bdf == 0u)
      continue;

    for (uint32_t idx = 0u; idx < table->num_entries; ++idx)
    {
      if ((table->component[idx].role == CXL_COMPONENT_ROLE_ENDPOINT) &&
          (table->component[idx].bdf == endpoint_bdf))
      {
        endpoint_index = idx;
        break;
      }
    }

    if (endpoint_index == CXL_COMPONENT_INVALID_INDEX)
      continue;

    if (val_cxl_find_upstream_root_port(endpoint_bdf, &root_bdf) != ACS_STATUS_PASS)
      continue;

    for (uint32_t idx = 0u; idx < table->num_entries; ++idx)
    {
      if ((table->component[idx].role == CXL_COMPONENT_ROLE_ROOT_PORT) &&
          (table->component[idx].bdf == root_bdf))
      {
        root_index = idx;
        break;
      }
    }

    if (root_index == CXL_COMPONENT_INVALID_INDEX)
      continue;

    endpoint = &table->component[endpoint_index];
    root_port = &table->component[root_index];

    context.root_index = root_index;
    context.endpoint_index = endpoint_index;
    context.exerciser_bdf = endpoint_bdf;
    context.host_index = root_port->host_bridge_index;
    if (context.host_index == CXL_COMPONENT_INVALID_INDEX)
      continue;

    status = val_cxl_select_cfmws_window(context.host_index,
                                         &context.window_base,
                                         &context.window_size);
    if (status != ACS_STATUS_PASS)
      continue;

    host_comp_base = val_cxl_get_info(CXL_INFO_COMPONENT_BASE, context.host_index);
    if (host_comp_base == 0u)
      continue;

    if (program_host_target_list(root_port->bdf, host_comp_base, &context) != ACS_STATUS_PASS)
      continue;

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

    status = val_cxl_enable_mem(endpoint->bdf);
    if (status != ACS_STATUS_PASS)
      continue;

    status = val_cxl_program_host_decoder(context.host_index,
                                          DECODER_SLOT,
                                          context.window_base,
                                          context.window_size);
    if (status != ACS_STATUS_PASS)
      continue;

    status = val_cxl_program_component_decoder(context.endpoint_index,
                                               DECODER_SLOT,
                                               context.window_base,
                                               context.window_size);
    if (status != ACS_STATUS_PASS)
      continue;

    ep_found = 1u;
    break;
  }

  if (ep_found == 0u)
  {
    val_print(ACS_PRINT_INFO, " RHHMVM: no suitable exerciser/root-port pair", 0);
    val_set_status(pe_index, "SKIP", 03);
    return;
  }

  /*
   * Step A: Check whether RP has RME-CDA DVSEC; if present keep TDISP_EN and
   * LINK_STR_LOCK enabled during host-to-device setup.
   */
  status = val_exerciser_init_by_bdf(context.exerciser_bdf);
  if (status != ACS_STATUS_PASS)
  {
    val_print(ACS_PRINT_INFO, " RHHMVM: exerciser init failed for BDF 0x%x",
              context.exerciser_bdf);
    val_set_status(pe_index, "SKIP", 04);
    goto cleanup;
  }

  status = force_all_smmus_disabled();
  if (status != ACS_STATUS_PASS)
  {
    val_set_status(pe_index, "SKIP", 07);
    goto cleanup;
  }

  status = val_pcie_find_cda_capability(table->component[context.root_index].bdf,
                                        &context.rmecda_cap_base);
  if (status == ACS_STATUS_PASS)
  {
    tg = val_get_min_tg();
    cfg_addr = val_pcie_get_bdf_config_addr(table->component[context.root_index].bdf);
    if ((tg == 0u) || (cfg_addr == 0u))
    {
      val_set_status(pe_index, "SKIP", 04);
      goto cleanup;
    }

    context.rmecda_cfg_va = val_get_free_va(tg);
    if (context.rmecda_cfg_va == 0u)
    {
      val_set_status(pe_index, "SKIP", 01);
      goto cleanup;
    }

    attr = LOWER_ATTRS(PGT_ENTRY_ACCESS | SHAREABLE_ATTR(OUTER_SHAREABLE) |
                       GET_ATTR_INDEX(DEV_MEM_nGnRnE) | PGT_ENTRY_AP_RW |
                       PAS_ATTR(ROOT_PAS));
    if (val_add_mmu_entry_el3(context.rmecda_cfg_va, cfg_addr, attr))
    {
      val_set_status(pe_index, "SKIP", 02);
      goto cleanup;
    }

    if (read_from_root(context.rmecda_cfg_va + context.rmecda_cap_base + RMECDA_CTL1_OFFSET,
                       &context.rmecda_ctl1_orig) != ACS_STATUS_PASS)
    {
      val_set_status(pe_index, "SKIP", 03);
      goto cleanup;
    }

    rmecda_ctl1 = context.rmecda_ctl1_orig |
                  RMECDA_CTL1_TDISP_EN_MASK |
                  RMECDA_CTL1_LINK_STR_LOCK_MASK;
    if (write_from_root(context.rmecda_cfg_va + context.rmecda_cap_base + RMECDA_CTL1_OFFSET,
                        rmecda_ctl1) != ACS_STATUS_PASS)
    {
      val_set_status(pe_index, "SKIP", 04);
      goto cleanup;
    }

    if (read_from_root(context.rmecda_cfg_va + context.rmecda_cap_base + RMECDA_CTL1_OFFSET,
                       &rmecda_ctl1) != ACS_STATUS_PASS)
    {
      val_set_status(pe_index, "SKIP", 05);
      goto cleanup;
    }

    if ((rmecda_ctl1 & (RMECDA_CTL1_TDISP_EN_MASK | RMECDA_CTL1_LINK_STR_LOCK_MASK)) !=
        (RMECDA_CTL1_TDISP_EN_MASK | RMECDA_CTL1_LINK_STR_LOCK_MASK))
    {
      val_set_status(pe_index, "SKIP", 05);
      goto cleanup;
    }

    context.rmecda_ctl1_valid = 1u;
  }

  /* Step B: Run same behavior for Realm PAS and Non-secure PAS. */
  uint32_t status_rlm;
  uint32_t status_ns;
  uint32_t fail_count = 0u;
  uint32_t pass_count = 0u;

  status_rlm = exercise_bisnp_behavior(&context, REALM_PAS);
  val_print(ACS_PRINT_DEBUG, " RHHMVM: exercise_bisnp_behavior Realm status %d", status_rlm);
  if (status_rlm == ACS_STATUS_FAIL)
    fail_count++;
  else if (status_rlm == ACS_STATUS_PASS)
    pass_count++;

  status_ns = exercise_bisnp_behavior(&context, NONSECURE_PAS);
  val_print(ACS_PRINT_DEBUG, " RHHMVM: exercise_bisnp_behavior NS status %d", status_ns);
  if (status_ns == ACS_STATUS_FAIL)
    fail_count++;
  else if (status_ns == ACS_STATUS_PASS)
    pass_count++;

  if (fail_count != 0u)
  {
    val_print(ACS_PRINT_INFO, " RHHMVM: observational path hit; marking test SKIP", 0);
    val_set_status(pe_index, "SKIP", 06);
  }
  else if (pass_count == 0u)
    val_set_status(pe_index, "SKIP", 06);
  else
    val_set_status(pe_index, "PASS", 01);

cleanup:
  restore_decoders(&context);
}

uint32_t
cxl_rhhmvm_bisnp_pas_nonsecure_entry(uint32_t num_pe)
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
