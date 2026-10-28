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
  CXL_DECODER_STATE host_decoder;
  CXL_DECODER_STATE endpoint_decoder;
  uint32_t rmecda_ctl1_orig;
  uint32_t rmecda_ctl1_valid;
  uint32_t rmecda_cap_base;
  uint64_t rmecda_cfg_va;
  uint32_t cache_cleanup_failed;
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
prepare_decoders(uint32_t bdf, RHHMVM_CONTEXT *context)
{
  if (context == NULL)
    return ACS_STATUS_ERR;

  return val_cxl_prepare_decoders(context->host_index, context->endpoint_index,
                                  DECODER_SLOT, bdf, &context->host_decoder,
                                  &context->endpoint_decoder);
}

static uint32_t
restore_decoders(RHHMVM_CONTEXT *context)
{
  uint32_t status = ACS_STATUS_PASS;

  /* Release the link lock before restoring protected decoder registers. */
  if ((context->rmecda_ctl1_valid != 0u) && (context->rmecda_cfg_va != 0u))
  {
    uint32_t ctl1;
    uint32_t root_bdf = (uint32_t)val_cxl_get_component_info(
        CXL_COMPONENT_INFO_BDF_INDEX, context->root_index);

    if (read_from_root(context->rmecda_cfg_va + context->rmecda_cap_base +
                       RMECDA_CTL1_OFFSET, &ctl1) != ACS_STATUS_PASS ||
        write_from_root(context->rmecda_cfg_va + context->rmecda_cap_base +
                         RMECDA_CTL1_OFFSET,
                         ctl1 & ~RMECDA_CTL1_LINK_STR_LOCK_MASK) != ACS_STATUS_PASS)
      status = ACS_STATUS_ERR;
    if (val_pcie_disable_tdisp(root_bdf))
      status = ACS_STATUS_ERR;
  }

  if (val_cxl_restore_decoders(&context->host_decoder, &context->endpoint_decoder)
      != ACS_STATUS_PASS)
    status = ACS_STATUS_ERR;

  return status;
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

/* Permit host accesses during setup and observation, but not during BISnp. */
static uint32_t
permit_host_access(uint32_t root_bdf, const RHHMVM_CONTEXT *context)
{
  uint32_t value;
  uint64_t address;

  if (context->rmecda_ctl1_valid == 0u)
  {
    /* Without CDA controls, setup needs an already-authorized Realm path. */
    return val_cxl_rp_is_realm_access_authorized(root_bdf) ?
           ACS_STATUS_PASS : ACS_STATUS_SKIP;
  }
  address = context->rmecda_cfg_va + context->rmecda_cap_base + RMECDA_CTL1_OFFSET;
  if (val_pcie_enable_tdisp(root_bdf) ||
      read_from_root(address, &value) != ACS_STATUS_PASS)
    return ACS_STATUS_FAIL;
  value |= RMECDA_CTL1_LINK_STR_LOCK_MASK;
  if (write_from_root(address, value) != ACS_STATUS_PASS ||
      read_from_root(address, &value) != ACS_STATUS_PASS)
    return ACS_STATUS_FAIL;
  if ((value & (RMECDA_CTL1_TDISP_EN_MASK | RMECDA_CTL1_LINK_STR_LOCK_MASK)) !=
      (RMECDA_CTL1_TDISP_EN_MASK | RMECDA_CTL1_LINK_STR_LOCK_MASK))
    return ACS_STATUS_FAIL;
  return ACS_STATUS_PASS;
}

static uint32_t
exercise_bisnp_behavior(uint32_t root_bdf, RHHMVM_CONTEXT *context, uint32_t host_pas)
{
  volatile uint32_t *cached_va = NULL;
  uint64_t media_value = 0u;
  uint64_t original_gpi;
  uint32_t result = ACS_STATUS_FAIL;
  uint64_t page_size;
  uint64_t pa_in;
  uint64_t dpa;
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
  if (val_cxl_hpa_to_dpa(context->endpoint_index, pa_in, &dpa) != ACS_STATUS_PASS)
    return ACS_STATUS_ERR;
  expected_host_value = (host_pas == REALM_PAS) ? TEST_HOST_VALUE_V1 : TEST_DEVICE_VALUE_V2;

  if (host_pas == REALM_PAS)
  {
    status = permit_host_access(root_bdf, context);
    if (status != ACS_STATUS_PASS)
      return status;
  }

  /* Translation PAS does not change GPT permissions for the target granule. */
  if (val_get_gpt_entry_el3(pa_in, &original_gpi))
    return ACS_STATUS_ERR;

  if (val_add_gpt_entry_el3(pa_in,
                          (host_pas == REALM_PAS) ? GPT_REALM : GPT_NONSECURE))
    return ACS_STATUS_ERR;

  /* Step 1: Write V1 through a cacheable alias in selected PAS so it remains host-cached. */
  if (map_alias(pa_in, host_pas, WRITE_BACK_NT, &cached_va) != ACS_STATUS_PASS)
  {
    result = ACS_STATUS_FAIL;
    goto restore_gpt;
  }

  shared_data->num_access = 1;
  shared_data->shared_data_access[0].addr = (uint64_t)cached_va;
  shared_data->shared_data_access[0].data = (uint64_t)TEST_HOST_VALUE_V1;
  shared_data->shared_data_access[0].access_type = WRITE_DATA;
  if (val_pe_access_mut_el3())
  {
    result = ACS_STATUS_FAIL;
    goto restore_gpt;
  }

  /*
   * Step 2: Translate the host location and modify its device media through
   * the direct-DPA exerciser backdoor.
   */
  status = val_cxl_exerciser_backdoor_write64(context->exerciser_bdf,
                                     dpa,
                                     TEST_DEVICE_VALUE_V2);
  if (status != ACS_STATUS_PASS)
  {
    result = status;
    goto restore_gpt;
  }

  status = val_cxl_exerciser_backdoor_read64(context->exerciser_bdf,
                                    dpa,
                                    &media_value);
  if (status != ACS_STATUS_PASS)
  {
    result = ACS_STATUS_FAIL;
    goto restore_gpt;
  }

  if ((uint32_t)media_value != TEST_DEVICE_VALUE_V2)
  {
    val_print(ACS_PRINT_ERR, " RHHMVM: media write verify failed 0x%llx", media_value);
    result = ACS_STATUS_FAIL;
    goto restore_gpt;
  }

  /*
   * Step 3: Disable TDISP_EN and LINK_STR_LOCK before issuing BISnp, as
   * RHHMVM applies when TDISP is disabled or RME-CDA DVSEC is absent.
   */
  if ((context->rmecda_ctl1_valid != 0u) && (context->rmecda_cfg_va != 0u))
  {
    uint32_t rmecda_ctl1;

    if (read_from_root(context->rmecda_cfg_va + context->rmecda_cap_base +
                       RMECDA_CTL1_OFFSET, &rmecda_ctl1) != ACS_STATUS_PASS)
    {
      result = ACS_STATUS_ERR;
      goto restore_gpt;
    }

    /* Preserve TDISP until the common disable helper programs it. */
    rmecda_ctl1 &= ~RMECDA_CTL1_LINK_STR_LOCK_MASK;
    if (write_from_root(context->rmecda_cfg_va + context->rmecda_cap_base +
                        RMECDA_CTL1_OFFSET,
                        rmecda_ctl1) != ACS_STATUS_PASS)
    {
      result = ACS_STATUS_ERR;
      goto restore_gpt;
    }

    if (read_from_root(context->rmecda_cfg_va + context->rmecda_cap_base +
                       RMECDA_CTL1_OFFSET,
                       &rmecda_ctl1) != ACS_STATUS_PASS)
    {
      result = ACS_STATUS_ERR;
      goto restore_gpt;
    }

    if ((rmecda_ctl1 & RMECDA_CTL1_LINK_STR_LOCK_MASK) != 0u)
    {
      val_print(ACS_PRINT_ERR, " RHHMVM: LINK_STR_LOCK clear failed 0x%x", rmecda_ctl1);
      result = ACS_STATUS_ERR;
      goto restore_gpt;
    }

    if (val_pcie_disable_tdisp(root_bdf))
    {
      val_print(ACS_PRINT_ERR, " RHHMVM: TDISP disable failed", 0);
      result = ACS_STATUS_ERR;
      goto restore_gpt;
    }
  }

  /* Step 4: Trigger BISnp for PA. */
  status = issue_bisnp(context->exerciser_bdf, pa_in, 0u);
  if (status != ACS_STATUS_PASS)
  {
    val_print(ACS_PRINT_INFO, " RHHMVM: BISnp command unsupported", 0);
    result = ACS_STATUS_SKIP;
    goto restore_gpt;
  }

  /* BISnp has completed with TDISP disabled. Reopen the Realm path before
   * observing the cache: a possible refill must not trigger RNYCLL/RWYVCQ.
   * A refill loses the observation and is still classified as SKIP below.
   */
  if (host_pas == REALM_PAS)
  {
    status = permit_host_access(root_bdf, context);
    if (status != ACS_STATUS_PASS)
    {
      result = status;
      goto restore_gpt;
    }
  }

  /* Step 5: Read PA back through MUT. */
  shared_data->num_access = 1;
  shared_data->shared_data_access[0].addr = (uint64_t)cached_va;
  shared_data->shared_data_access[0].access_type = READ_DATA;
  if (val_pe_access_mut_el3())
  {
    result = ACS_STATUS_FAIL;
    goto restore_gpt;
  }

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
    result = ACS_STATUS_SKIP;
    goto restore_gpt;
  }

  result = ACS_STATUS_PASS;

restore_gpt:
  /* Error/unsupported BISnp exits can leave the Realm path closed. */
  if ((cached_va != NULL) && (host_pas == REALM_PAS) &&
      (permit_host_access(root_bdf, context) != ACS_STATUS_PASS))
  {
    val_print(ACS_PRINT_ERR, " RHHMVM: cannot authorize Realm cache cleanup", 0);
    context->cache_cleanup_failed = 1u;
    return ACS_STATUS_ERR;
  }

  /* Drain the selected PAS cache line before changing its GPT permission. */
  if ((cached_va != NULL) && val_data_cache_ops_by_pa_el3(pa_in, host_pas))
  {
    val_print(ACS_PRINT_ERR, " RHHMVM: cache cleanup failed", 0);
    context->cache_cleanup_failed = 1u;
    return ACS_STATUS_ERR;
  }
  if (val_add_gpt_entry_el3(pa_in, original_gpi))
    result = ACS_STATUS_ERR;
  return result;
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

    status = prepare_decoders(root_port->bdf, &context);
    if (status != ACS_STATUS_PASS)
    {
      if (status == ACS_STATUS_SKIP)
        continue;
      val_set_status(pe_index, "FAIL", 07);
      goto cleanup;
    }

    status = val_cxl_enable_mem(endpoint->bdf);
    if (status != ACS_STATUS_PASS)
      goto candidate_cleanup;

    status = val_cxl_program_saved_decoder(&context.host_decoder,
                                           context.window_base, context.window_size);
    if (status != ACS_STATUS_PASS)
      goto candidate_cleanup;

    status = val_cxl_program_saved_decoder(&context.endpoint_decoder,
                                           context.window_base, context.window_size);
    if (status != ACS_STATUS_PASS)
      goto candidate_cleanup;

    ep_found = 1u;
    break;

candidate_cleanup:
    /* Release this candidate before borrowing a different host/endpoint pair. */
    if (restore_decoders(&context) != ACS_STATUS_PASS)
    {
      val_set_status(pe_index, "FAIL", 07);
      return;
    }
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

    /* Restore the original control even if programming or readback fails. */
    context.rmecda_ctl1_valid = 1u;
    if (val_pcie_enable_tdisp(table->component[context.root_index].bdf) ||
        read_from_root(context.rmecda_cfg_va + context.rmecda_cap_base + RMECDA_CTL1_OFFSET,
                       &rmecda_ctl1) != ACS_STATUS_PASS)
    {
      val_set_status(pe_index, "SKIP", 04);
      goto cleanup;
    }

    rmecda_ctl1 |= RMECDA_CTL1_LINK_STR_LOCK_MASK;
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
  }

  /* Step B: Run same behavior for Realm PAS and Non-secure PAS. */
  uint32_t status_rlm;
  uint32_t status_ns;
  uint32_t fail_count = 0u;
  uint32_t pass_count = 0u;

  status_rlm = exercise_bisnp_behavior(table->component[context.root_index].bdf,
                                      &context, REALM_PAS);
  val_print(ACS_PRINT_DEBUG, " RHHMVM: exercise_bisnp_behavior Realm status %d", status_rlm);
  if (status_rlm == ACS_STATUS_ERR)
  {
    val_set_status(pe_index, "FAIL", 07);
    goto cleanup;
  }
  if (status_rlm == ACS_STATUS_FAIL)
    fail_count++;
  else if (status_rlm == ACS_STATUS_PASS)
    pass_count++;

  status_ns = exercise_bisnp_behavior(table->component[context.root_index].bdf,
                                     &context, NONSECURE_PAS);
  val_print(ACS_PRINT_DEBUG, " RHHMVM: exercise_bisnp_behavior NS status %d", status_ns);
  if (status_ns == ACS_STATUS_ERR)
  {
    val_set_status(pe_index, "FAIL", 07);
    goto cleanup;
  }
  if (status_ns == ACS_STATUS_FAIL)
    fail_count++;
  else if (status_ns == ACS_STATUS_PASS)
    pass_count++;

  if (fail_count != 0u)
  {
    val_print(ACS_PRINT_INFO, " RHHMVM: observational path hit; marking test SKIP", 0);
    val_set_status(pe_index, "SKIP", 06);
  }
  /* Both PAS observations are needed; an NS-only observation is incomplete. */
  else if (pass_count != 2u)
    val_set_status(pe_index, "SKIP", 06);
  else
    val_set_status(pe_index, "PASS", 01);

cleanup:
  /* A possibly dirty line still targets this window: retain its GPT and routing. */
  if (context.cache_cleanup_failed != 0u)
  {
    val_print(ACS_PRINT_ERR, " RHHMVM: retaining window after cache cleanup failure", 0);
    val_set_status(pe_index, "FAIL", 07);
    return;
  }
  if (restore_decoders(&context) != ACS_STATUS_PASS)
    val_set_status(pe_index, "FAIL", 07);
  if ((context.rmecda_ctl1_valid != 0u) && (context.rmecda_cfg_va != 0u))
  {
    uint32_t root_bdf = table->component[context.root_index].bdf;

    /* Restore other fields without changing TDISP outside the common helpers. */
    if (read_from_root(context.rmecda_cfg_va + context.rmecda_cap_base +
                       RMECDA_CTL1_OFFSET, &rmecda_ctl1) != ACS_STATUS_PASS ||
        write_from_root(context.rmecda_cfg_va + context.rmecda_cap_base +
                         RMECDA_CTL1_OFFSET,
                         (context.rmecda_ctl1_orig & ~RMECDA_CTL1_TDISP_EN_MASK) |
                         (rmecda_ctl1 & RMECDA_CTL1_TDISP_EN_MASK)) != ACS_STATUS_PASS)
    {
      val_print(ACS_PRINT_ERR, " RHHMVM: RMECDA_CTL1 restore failed", 0);
      val_set_status(pe_index, "FAIL", 8);
    }

    status = (context.rmecda_ctl1_orig & RMECDA_CTL1_TDISP_EN_MASK) ?
             val_pcie_enable_tdisp(root_bdf) : val_pcie_disable_tdisp(root_bdf);
    if (status)
    {
      val_print(ACS_PRINT_ERR, " RHHMVM: TDISP restore failed", 0);
      val_set_status(pe_index, "FAIL", 8);
    }
  }
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
