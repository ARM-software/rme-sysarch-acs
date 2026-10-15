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

#define TEST_NAME "cxl_rptggp_cmo_to_cxl_mem"
#define TEST_DESC "PoPA/PoE CMO reaches host-side caches for CXL.mem"
#define TEST_RULE "RPTGGP"

#define DECODER_SLOT 0u
#define RMECDA_CTL1_TDISP_EN_MASK 0x1u
#define RMECDA_CTL1_LINK_STR_LOCK_MASK (1u << 1)

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
} RPTGGP_CONTEXT;

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
    val_print(ACS_PRINT_ERR, " RPTGGP: MUT read failed for 0x%llx", address);
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
    val_print(ACS_PRINT_ERR, " RPTGGP: MUT write failed for 0x%llx", address);
    return ACS_STATUS_ERR;
  }

  return ACS_STATUS_PASS;
}

static uint32_t
restore_decoders(RPTGGP_CONTEXT *context)
{
  /* Restore both complete snapshots, including initially inactive decoders. */
  return val_cxl_restore_decoders(&context->host_decoder, &context->endpoint_decoder);
}

static uint32_t
prepare_decoders(uint32_t bdf, RPTGGP_CONTEXT *context)
{
  if (context == NULL)
    return ACS_STATUS_ERR;

  return val_cxl_prepare_decoders(context->host_index, context->endpoint_index,
                                  DECODER_SLOT, bdf, &context->host_decoder,
                                  &context->endpoint_decoder);
}

static uint32_t
verify_device_readback(const RPTGGP_CONTEXT *context,
                       uint64_t pa,
                       uint32_t expected)
{
  CXL_COMPONENT_TABLE *table = val_cxl_component_table_ptr();
  uint32_t instance;
  uint64_t readback = 0u;
  uint32_t readback32;

  if ((context == NULL) || (table == NULL))
  {
    val_print(ACS_PRINT_INFO, " RPTGGP: verify_device_readback invalid context", 0);
    return ACS_STATUS_SKIP;
  }

  if (context->endpoint_index == CXL_COMPONENT_INVALID_INDEX)
  {
    val_print(ACS_PRINT_INFO, " RPTGGP: invalid endpoint index", 0);
    return ACS_STATUS_SKIP;
  }

  if (context->exerciser_bdf == 0u)
  {
    val_print(ACS_PRINT_INFO, " RPTGGP: exerciser BDF invalid", 0);
    return ACS_STATUS_SKIP;
  }

  instance = context->exerciser_bdf;
  if (val_exerciser_init_by_bdf(instance))
    return ACS_STATUS_SKIP;

  val_print(ACS_PRINT_INFO, " RPTGGP: exerciser BDF 0x%x", instance);
  val_print(ACS_PRINT_INFO, " RPTGGP: backdoor read PA 0x%llx", pa);

  /* Program a CXL backdoor read command for the target PA. */
  if (val_exerciser_set_param_by_bdf(EXERCISER_CXL_CMD_OP,
                                     CXL_CMD_OP_BACKDOOR_READ64,
                                     0u,
                                     instance))
    return ACS_STATUS_FAIL;

  if (val_exerciser_set_param_by_bdf(EXERCISER_CXL_CMD_ADDR, pa, 0u, instance))
    return ACS_STATUS_FAIL;

  /* Trigger the command and wait for completion. */
  if (val_exerciser_ops_by_bdf(CXL_CMD_START, 0u, instance))
    return ACS_STATUS_FAIL;

  /* Fetch the device media value and compare with expected data. */
  if (val_exerciser_get_param_by_bdf(EXERCISER_CXL_CMD_DATA0,
                                     &readback,
                                     NULL,
                                     instance))
    return ACS_STATUS_FAIL;

  readback32 = (uint32_t)readback;
  val_print(ACS_PRINT_INFO, " RPTGGP: expected 0x%lx", expected);
  val_print(ACS_PRINT_INFO, " RPTGGP: readback 0x%lx", readback32);

  if (readback32 != expected)
  {
    val_print(ACS_PRINT_ERR, " RPTGGP: device readback mismatch", 0);
    val_print(ACS_PRINT_ERR, " RPTGGP: expected 0x%lx", expected);
    val_print(ACS_PRINT_ERR, " RPTGGP: actual 0x%lx", readback32);
    return ACS_STATUS_FAIL;
  }

  return ACS_STATUS_PASS;
}

static void
payload(void)
{
  uint32_t pe_index = val_pe_get_index_mpid(val_pe_get_mpid());
  CXL_COMPONENT_TABLE *table = val_cxl_component_table_ptr();
  RPTGGP_CONTEXT context;
  uint64_t buffer_pa = 0u;
  volatile uint32_t *buffer_va = NULL;
  uint32_t pattern = 0xA5A5A5A5U;
  uint32_t status;
  uint32_t result = ACS_STATUS_SKIP;
  uint32_t ep_found = 0u;
  uint32_t num_exercisers;
  uint64_t page_size;
  uint64_t va;
  uint32_t attr;
  uint64_t cfg_addr;
  uint32_t rmecda_cap_base;
  uint32_t rmecda_present = 0u;
  uint32_t rmecda_ctl1;
  uint64_t tg;

  /* Ensure CXL components are present. */
  if ((table == NULL) || (table->num_entries == 0u))
  {
    val_print(ACS_PRINT_DEBUG,
              " RPTGGP: No CXL components discovered - skipping",
              0);
    val_set_status(pe_index, "SKIP", 01);
    return;
  }

  val_memory_set(&context, sizeof(context), 0);
  context.exerciser_bdf = 0u;

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
    {
      val_print(ACS_PRINT_INFO, " RPTGGP: CXL exerciser BDF invalid", 0);
      continue;
    }

    val_print(ACS_PRINT_INFO, " RPTGGP: CXL exerciser BDF 0x%x", endpoint_bdf);

    /* Map the exerciser BDF to a CXL endpoint component. */
    for (uint32_t idx = 0u; idx < table->num_entries; ++idx)
    {
      if (table->component[idx].role != CXL_COMPONENT_ROLE_ENDPOINT)
        continue;
      if (table->component[idx].bdf != endpoint_bdf)
        continue;
      endpoint_index = idx;
      break;
    }

    if (endpoint_index == CXL_COMPONENT_INVALID_INDEX)
    {
      val_print(ACS_PRINT_INFO, " RPTGGP: no endpoint match for BDF 0x%x", endpoint_bdf);
      continue;
    }

    endpoint = &table->component[endpoint_index];
    val_print(ACS_PRINT_INFO, " RPTGGP: endpoint index %u", endpoint_index);

    /* Find the upstream root port for this endpoint. */
    if (val_cxl_find_upstream_root_port(endpoint_bdf, &root_bdf) != ACS_STATUS_PASS)
    {
      val_print(ACS_PRINT_INFO, " RPTGGP: upstream root not found for BDF 0x%x", endpoint_bdf);
      continue;
    }

    for (uint32_t idx = 0u; idx < table->num_entries; ++idx)
    {
      if (table->component[idx].role != CXL_COMPONENT_ROLE_ROOT_PORT)
        continue;
      if (table->component[idx].bdf != root_bdf)
        continue;
      root_index = idx;
      break;
    }

    if (root_index == CXL_COMPONENT_INVALID_INDEX)
    {
      val_print(ACS_PRINT_INFO, " RPTGGP: root index not found for BDF 0x%x", root_bdf);
      continue;
    }

    root_port = &table->component[root_index];

    /* Skip unauthorized ports before changing target lists or decoders. */
    rmecda_present = (val_pcie_find_cda_capability(root_port->bdf,
                                                   &rmecda_cap_base) == PCIE_SUCCESS);
    if ((rmecda_present == 0u) &&
        (val_cxl_rp_is_realm_access_authorized(root_port->bdf) == 0u))
    {
      val_print(ACS_PRINT_DEBUG,
                " RPTGGP: Skipping RP 0x%x: no RME-CDA or configured Realm authorization",
                (uint64_t)root_port->bdf);
      continue;
    }

    context.root_index = root_index;
    context.endpoint_index = endpoint_index;
    context.exerciser_bdf = 0u;
    context.host_index = root_port->host_bridge_index;
    if (context.host_index == CXL_COMPONENT_INVALID_INDEX)
    {
      val_print(ACS_PRINT_INFO, " RPTGGP: host bridge index invalid", 0);
      continue;
    }

    context.exerciser_bdf = endpoint_bdf;

    /* Select a CFMWS window that backs CXL.mem access for this host bridge. */
    status = val_cxl_select_cfmws_window(context.host_index,
                                         &context.window_base,
                                         &context.window_size);
    if (status != ACS_STATUS_PASS)
    {
      val_print(ACS_PRINT_INFO, " RPTGGP: no CFMWS window for host %u", context.host_index);
      continue;
    }

    host_comp_base = val_cxl_get_info(CXL_INFO_COMPONENT_BASE, context.host_index);
    if (host_comp_base == 0u)
    {
      val_print(ACS_PRINT_INFO, " RPTGGP: host component base invalid", 0);
      continue;
    }

    status = prepare_decoders(root_port->bdf, &context);
    if (status != ACS_STATUS_PASS)
    {
      if (status == ACS_STATUS_SKIP)
        continue;
      result = ACS_STATUS_FAIL;
      goto cleanup;
    }

    /* Enable CXL.mem for the endpoint before programming decoders. */
    status = val_cxl_enable_mem(endpoint->bdf);
    if (status != ACS_STATUS_PASS)
    {
      if (restore_decoders(&context) != ACS_STATUS_PASS)
      {
        result = ACS_STATUS_FAIL;
        goto cleanup;
      }
      continue;
    }

    /*
     * Program HDM decoders to cover the selected CXL.mem window so that
     * CPU accesses use the expected host/endpoint decoder pair.
     */
    status = val_cxl_program_saved_decoder(&context.host_decoder,
                                           context.window_base,
                                           context.window_size);
    if (status != ACS_STATUS_PASS)
    {
      val_print(ACS_PRINT_INFO, " RPTGGP: host decoder program skipped", 0);
      result = ACS_STATUS_SKIP;
      goto cleanup;
    }

    val_print(ACS_PRINT_INFO, " RPTGGP: endpoint comp base 0x%llx",
              endpoint->component_reg_base);
    if (val_cxl_find_capability(endpoint->component_reg_base,
                                CXL_CAPID_HDM_DECODER,
                                &host_comp_base) != ACS_STATUS_PASS)
    {
      val_print(ACS_PRINT_INFO, " RPTGGP: endpoint HDM cap missing", 0);
    }
    else
    {
      val_print(ACS_PRINT_INFO, " RPTGGP: endpoint HDM cap base 0x%llx",
                host_comp_base);
    }

    status = val_cxl_program_saved_decoder(&context.endpoint_decoder,
                                           context.window_base,
                                           context.window_size);
    if (status != ACS_STATUS_PASS)
    {
      val_print(ACS_PRINT_INFO, " RPTGGP: endpoint decoder program skipped", 0);
      val_print(ACS_PRINT_INFO, " RPTGGP: endpoint decoder status %d", status);
      result = ACS_STATUS_SKIP;
      goto cleanup;
    }

    ep_found = 1u;
    break;
  }

  if (ep_found == 0u)
  {
    val_set_status(pe_index, "SKIP", 02);
    return;
  }

  /*
   * RPTGGP does not require RME-CDA. Where implemented, enable TDISP and
   * lock the link to permit the Realm accesses used by this test.
   */
  if (rmecda_present != 0u)
  {
    cfg_addr = val_pcie_get_bdf_config_addr(table->component[context.root_index].bdf);
    tg = val_get_min_tg();
    if ((cfg_addr == 0u) || (tg == 0u))
    {
      result = ACS_STATUS_FAIL;
      goto cleanup;
    }

    context.rmecda_cfg_va = val_get_free_va(tg);
    if (context.rmecda_cfg_va == 0u)
    {
      result = ACS_STATUS_FAIL;
      goto cleanup;
    }

    attr = LOWER_ATTRS(PGT_ENTRY_ACCESS | SHAREABLE_ATTR(OUTER_SHAREABLE) |
                       GET_ATTR_INDEX(DEV_MEM_nGnRnE) | PGT_ENTRY_AP_RW |
                       PAS_ATTR(ROOT_PAS));
    if (val_add_mmu_entry_el3(context.rmecda_cfg_va, cfg_addr, attr))
    {
      result = ACS_STATUS_FAIL;
      goto cleanup;
    }

    context.rmecda_cap_base = rmecda_cap_base;
    if (read_from_root(context.rmecda_cfg_va + rmecda_cap_base + RMECDA_CTL1_OFFSET,
                       &context.rmecda_ctl1_orig) != ACS_STATUS_PASS)
    {
      result = ACS_STATUS_FAIL;
      goto cleanup;
    }

    /* Restore the original control even if programming or readback fails. */
    context.rmecda_ctl1_valid = 1u;
    if (val_pcie_enable_tdisp(table->component[context.root_index].bdf) ||
        read_from_root(context.rmecda_cfg_va + rmecda_cap_base + RMECDA_CTL1_OFFSET,
                       &rmecda_ctl1) != ACS_STATUS_PASS)
    {
      result = ACS_STATUS_FAIL;
      goto cleanup;
    }

    rmecda_ctl1 |= RMECDA_CTL1_LINK_STR_LOCK_MASK;
    if (write_from_root(context.rmecda_cfg_va + rmecda_cap_base + RMECDA_CTL1_OFFSET,
                        rmecda_ctl1) != ACS_STATUS_PASS)
    {
      result = ACS_STATUS_FAIL;
      goto cleanup;
    }

    if (read_from_root(context.rmecda_cfg_va + rmecda_cap_base + RMECDA_CTL1_OFFSET,
                       &rmecda_ctl1) != ACS_STATUS_PASS)
    {
      result = ACS_STATUS_FAIL;
      goto cleanup;
    }

    if ((rmecda_ctl1 & (RMECDA_CTL1_TDISP_EN_MASK |
                        RMECDA_CTL1_LINK_STR_LOCK_MASK)) !=
        (RMECDA_CTL1_TDISP_EN_MASK |
         RMECDA_CTL1_LINK_STR_LOCK_MASK))
    {
      result = ACS_STATUS_FAIL;
      goto cleanup;
    }
  }
  else
  {
    val_print(ACS_PRINT_DEBUG,
              " RPTGGP: RME-CDA absent; platform configuration confirms Realm authorization",
              0);
  }

  /*
   * Populate host cache with a known pattern in CXL.mem memory so that a
   * PoPA/PoE CMO must clean host-side caches before reaching the root port.
   */
  page_size = (uint64_t)val_memory_page_size();
  if ((page_size == 0u) || (context.window_size < page_size))
  {
    val_print(ACS_PRINT_INFO, " RPTGGP: window too small for page", 0);
    result = ACS_STATUS_SKIP;
    goto cleanup;
  }

  buffer_pa = context.window_base;
  if (buffer_pa == 0u)
  {
    val_print(ACS_PRINT_INFO, " RPTGGP: CXL.mem window base invalid", 0);
    result = ACS_STATUS_SKIP;
    goto cleanup;
  }

  /* Map a cacheable Realm alias for the selected CXL.mem window. */
  va = val_get_free_va(page_size);
  if (va == 0u)
  {
    result = ACS_STATUS_FAIL;
    goto cleanup;
  }

  attr = LOWER_ATTRS(PGT_ENTRY_ACCESS |
                     SHAREABLE_ATTR(OUTER_SHAREABLE) |
                     GET_ATTR_INDEX(WRITE_BACK_NT) |
                     PGT_ENTRY_AP_RW |
                     PAS_ATTR(REALM_PAS));

  if (val_add_mmu_entry_el3(va, buffer_pa, attr))
  {
    result = ACS_STATUS_FAIL;
    goto cleanup;
  }

  buffer_va = (volatile uint32_t *)va;

  /* Write a known pattern and leave it dirty in the host cache. */
  shared_data->num_access = 1;
  shared_data->shared_data_access[0].addr = (uint64_t)buffer_va;
  shared_data->shared_data_access[0].data = (uint64_t)pattern;
  shared_data->shared_data_access[0].access_type = WRITE_DATA;
  if (val_pe_access_mut_el3())
  {
    result = ACS_STATUS_FAIL;
    goto cleanup;
  }

  /*
   * Issue a PoPA CMO for the CXL.mem PA so the host cleans to the point
   * of physical aliasing before the root port.
   */
  if (val_data_cache_ops_by_pa_el3(buffer_pa, REALM_PAS))
  {
    result = ACS_STATUS_FAIL;
    goto cleanup;
  }

  /* Trigger a device-side read and compare against the pattern. */
  status = verify_device_readback(&context, buffer_pa, pattern);
  if (status == ACS_STATUS_FAIL)
  {
    result = ACS_STATUS_FAIL;
    goto cleanup;
  }
  if (status == ACS_STATUS_SKIP)
  {
    val_print(ACS_PRINT_INFO, " RPTGGP: device readback skipped (PoPA)", 0);
  }

  /*
   * Issue a PoE CMO for the same CXL.mem PA to validate PoE behavior
   * matches PoC expectations when back-invalidate snoops are enabled.
   */
  if (val_cmo_to_poe(buffer_pa))
  {
    result = ACS_STATUS_FAIL;
    goto cleanup;
  }

  /* Trigger a device-side read and compare against the pattern. */
  status = verify_device_readback(&context, buffer_pa, pattern);
  if (status == ACS_STATUS_FAIL)
  {
    result = ACS_STATUS_FAIL;
    goto cleanup;
  }
  if (status == ACS_STATUS_SKIP)
  {
    val_print(ACS_PRINT_INFO, " RPTGGP: device readback skipped (PoE)", 0);
  }

  result = ACS_STATUS_PASS;

cleanup:
  if ((context.rmecda_ctl1_valid != 0u) && (context.rmecda_cfg_va != 0u))
  {
    /* Unlock the link while preserving TDISP for the common disable helper. */
    if (read_from_root(context.rmecda_cfg_va + context.rmecda_cap_base +
                       RMECDA_CTL1_OFFSET, &rmecda_ctl1) != ACS_STATUS_PASS ||
        write_from_root(context.rmecda_cfg_va + context.rmecda_cap_base +
                         RMECDA_CTL1_OFFSET,
                         rmecda_ctl1 & ~RMECDA_CTL1_LINK_STR_LOCK_MASK) != ACS_STATUS_PASS ||
        read_from_root(context.rmecda_cfg_va + context.rmecda_cap_base +
                       RMECDA_CTL1_OFFSET, &rmecda_ctl1) != ACS_STATUS_PASS ||
        (rmecda_ctl1 & RMECDA_CTL1_LINK_STR_LOCK_MASK) != 0u)
    {
      val_print(ACS_PRINT_ERR, " RPTGGP: LINK_STR_LOCK clear failed", 0);
      result = ACS_STATUS_FAIL;
    }

    if (val_pcie_disable_tdisp(table->component[context.root_index].bdf))
    {
      val_print(ACS_PRINT_ERR, " RPTGGP: TDISP disable failed", 0);
      result = ACS_STATUS_FAIL;
    }
  }

  /* Restore HDM decoder programming before reporting status. */
  if (restore_decoders(&context) != ACS_STATUS_PASS)
    result = ACS_STATUS_FAIL;

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
      val_print(ACS_PRINT_ERR, " RPTGGP: RMECDA_CTL1 restore failed", 0);
      result = ACS_STATUS_FAIL;
    }

    status = (context.rmecda_ctl1_orig & RMECDA_CTL1_TDISP_EN_MASK) ?
             val_pcie_enable_tdisp(root_bdf) : val_pcie_disable_tdisp(root_bdf);
    if (status)
    {
      val_print(ACS_PRINT_ERR, " RPTGGP: TDISP restore failed", 0);
      result = ACS_STATUS_FAIL;
    }
  }

  if (result == ACS_STATUS_PASS)
    val_set_status(pe_index, "PASS", 01);
  else if (result == ACS_STATUS_FAIL)
    val_set_status(pe_index, "FAIL", 01);
  else
  {
    val_print(ACS_PRINT_INFO, " RPTGGP: result SKIP", 0);
    val_set_status(pe_index, "SKIP", 03);
  }
}

uint32_t
cxl_rptggp_cmo_to_cxl_mem_entry(uint32_t num_pe)
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
