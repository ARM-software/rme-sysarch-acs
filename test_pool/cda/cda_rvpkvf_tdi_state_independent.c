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
#include "val/include/val_cxl_spec.h"
#include "val/include/val_dpt.h"
#include "val/include/val_el32.h"
#include "val/include/val_exerciser.h"
#include "val/include/val_memory.h"
#include "val/include/val_pcie.h"
#include "val/include/val_pcie_spec.h"
#include "val/include/val_pe.h"
#include "val/include/val_pgt.h"
#include "val/include/val_smmu.h"
#include "val/include/val_spdm.h"
#include "val/include/val_tdisp.h"

#define TEST_NAME "cda_rvpkvf_tdi_state_independent"
#define TEST_DESC "Coherent operations remain available in TDI ERROR"
#define TEST_RULE "RVPKVF"

#define DECODER_SLOT 0u
#define TEST_PAGE_COUNT 3u

#define RUN_SNOOP_PAGE   0u
#define ERROR_SNOOP_PAGE 1u
#define REQUEST_PAGE     2u

#define RUN_SNOOP_VALUE   0x13579BDF2468ACE0ULL
#define ERROR_SNOOP_VALUE 0x02468ACE13579BDFULL
#define REQUEST_VALUE     0xA55A5AA55AA55AA5ULL

#if ENABLE_SPDM

typedef struct {
  val_spdm_context_t spdm_ctx;
  pci_tdisp_interface_id_t interface_id;
  PCIE_ENDPOINT_CFG endpoint_cfg;
  uint32_t session_id;
  uint32_t session_active;
  uint32_t ide_active;
  uint32_t tdi_in_error;
} RVPKVF_LINK_CONTEXT;

static uint32_t
unavailable_result(uint32_t baseline)
{
  return (baseline != 0u) ? ACS_STATUS_SKIP : ACS_STATUS_FAIL;
}

static uint32_t
start_realm_link(const VAL_CDA_DCM_WINDOW_CONTEXT *context,
                 RVPKVF_LINK_CONTEXT *link)
{
  uint32_t status;

  if ((context == NULL) || (link == NULL))
    return ACS_STATUS_ERR;

  val_memory_set(link, sizeof(*link), 0);
  status = val_pcie_save_endpoint_cfg(context->endpoint_bdf,
                                      &link->endpoint_cfg);
  if (status != ACS_STATUS_PASS)
    return status;

  status = val_tdisp_establish_run(context->endpoint_bdf,
                                   &link->spdm_ctx,
                                   &link->session_id,
                                   &link->interface_id);
  if (status != ACS_STATUS_PASS)
    return status;
  link->session_active = 1u;

  status = val_cxl_ide_establish_link(context->root_index,
                                      context->endpoint_index,
                                      &link->spdm_ctx,
                                      link->session_id);
  if (status != ACS_STATUS_PASS)
    return status;

  link->ide_active = 1u;
  return ACS_STATUS_PASS;
}

static uint32_t
enter_tdi_error(RVPKVF_LINK_CONTEXT *link)
{
  uint32_t status;

  if ((link == NULL) || (link->session_active == 0u))
    return ACS_STATUS_ERR;

  status = val_tdisp_close_session_to_error(&link->spdm_ctx,
                                             link->session_id);
  if (status != ACS_STATUS_PASS)
    return status;

  link->session_active = 0u;
  link->tdi_in_error = 1u;
  return ACS_STATUS_PASS;
}

static uint32_t
stop_realm_link(const VAL_CDA_DCM_WINDOW_CONTEXT *context,
                RVPKVF_LINK_CONTEXT *link)
{
  uint32_t result;

  if ((context == NULL) || (link == NULL))
    return ACS_STATUS_ERR;

  result = ACS_STATUS_PASS;
  if (link->tdi_in_error != 0u)
  {
    /* Reset is required because the SPDM session was intentionally closed. */
    if (val_cxl_unlock_tsp_best_effort(context->root_bdf,
                                       context->endpoint_bdf,
                                       &link->endpoint_cfg) != ACS_STATUS_PASS)
      result = ACS_STATUS_FAIL;
    link->tdi_in_error = 0u;
    link->ide_active = 0u;
    return result;
  }

  if (link->ide_active != 0u)
  {
    if (val_cxl_ide_disable_link(context->root_index,
                                 context->endpoint_index,
                                 &link->spdm_ctx,
                                 link->session_id) != ACS_STATUS_PASS)
      result = ACS_STATUS_FAIL;
    link->ide_active = 0u;
  }

  if (link->session_active != 0u)
  {
    if (val_tdisp_stop_if_needed(&link->spdm_ctx,
                                 link->session_id,
                                 &link->interface_id,
                                 0u) != ACS_STATUS_PASS)
      result = ACS_STATUS_FAIL;
    link->session_active = 0u;
  }

  return result;
}

static uint32_t
select_test_pages(const VAL_CDA_DCM_WINDOW_CONTEXT *context,
                  uint64_t page[TEST_PAGE_COUNT])
{
  uint64_t page_size;
  uint64_t top_page;
  uint32_t status;

  if ((context == NULL) || (page == NULL))
    return ACS_STATUS_ERR;

  page_size = (uint64_t)val_memory_page_size();
  if ((page_size == 0u) ||
      (context->window_size < (TEST_PAGE_COUNT * page_size)))
    return ACS_STATUS_SKIP;

  status = val_cda_select_dcm_page(context->window_base,
                                   context->window_size,
                                   &top_page);
  if (status != ACS_STATUS_PASS)
    return status;

  page[REQUEST_PAGE] = top_page;
  page[ERROR_SNOOP_PAGE] = top_page - page_size;
  page[RUN_SNOOP_PAGE] = top_page - (2u * page_size);
  if (page[RUN_SNOOP_PAGE] < context->window_base)
    return ACS_STATUS_SKIP;

  return ACS_STATUS_PASS;
}

/*
 * A demand read of a device-owned dirty line requires the coherent device to
 * participate in resolving the request. The exerciser monitors the incoming
 * coherent read at its own interface; no host-port observation hook is used.
 * In ERROR, consuming the response may fault because RQWNBN requires poison.
 * Poison validation remains the responsibility of the dedicated RQWNBN test.
 */
static uint32_t
check_host_to_device_snoop(uint32_t endpoint_bdf,
                           uint64_t target_hpa,
                           volatile uint64_t *target_alias,
                           uint64_t expected_value,
                           uint32_t baseline)
{
  uint64_t esr;
  uint64_t value;
  uint32_t fault_seen;
  uint32_t observed;
  uint32_t status;

  if (target_alias == NULL)
    return ACS_STATUS_ERR;

  status = val_exerciser_start_transaction_monitor_by_bdf(endpoint_bdf);
  if (status != ACS_STATUS_PASS)
    return (status == ACS_STATUS_SKIP) ? unavailable_result(baseline) : status;

  esr = 0u;
  value = 0u;
  fault_seen = 0u;
  status = val_memory_read64_el3_protected_with_esr(target_alias,
                                                     &value,
                                                     &fault_seen,
                                                     &esr);
  if (val_exerciser_stop_transaction_monitor_by_bdf(endpoint_bdf)
      != ACS_STATUS_PASS)
    return ACS_STATUS_ERR;
  if (status != ACS_STATUS_PASS)
    return ACS_STATUS_ERR;

  val_print(ACS_PRINT_DEBUG, " RVPKVF: host snoop read fault %u", fault_seen);
  val_print(ACS_PRINT_DEBUG, " RVPKVF: host snoop read ESR 0x%llx", esr);
  if ((baseline != 0u) && (fault_seen != 0u))
  {
    val_print(ACS_PRINT_ERR,
              " RVPKVF: RUN host read faulted for HPA 0x%llx",
              target_hpa);
    return ACS_STATUS_FAIL;
  }
  if ((baseline != 0u) && (value != expected_value))
  {
    val_print(ACS_PRINT_ERR,
              " RVPKVF: RUN host read returned 0x%llx",
              value);
    return ACS_STATUS_FAIL;
  }

  status = val_exerciser_find_transaction_by_bdf(
                                  endpoint_bdf,
                                  target_hpa,
                                  EXERCISER_TXN_ATTR_READ,
                                  &observed);
  if (status != ACS_STATUS_PASS)
    return status;
  if (observed == 0u)
  {
    val_print((baseline != 0u) ? ACS_PRINT_INFO : ACS_PRINT_ERR,
              " RVPKVF: coherent read did not reach HPA 0x%llx",
              target_hpa);
    return (baseline != 0u) ? ACS_STATUS_SKIP : ACS_STATUS_FAIL;
  }

  val_print(ACS_PRINT_INFO,
            " RVPKVF: coherent read reached HPA 0x%llx",
            target_hpa);

  return ACS_STATUS_PASS;
}

/* Verify that a TDI-attributed device-to-host snoop is emitted in this state. */
static uint32_t
check_device_to_host_snoop(uint32_t endpoint_bdf,
                           uint64_t target_hpa,
                           uint32_t baseline)
{
  uint32_t result;
  uint32_t status;

  status = val_cda_tdi_snoop_attempt(endpoint_bdf,
                                     target_hpa,
                                     REALM_PAS,
                                     &result);
  if (status != ACS_STATUS_PASS)
    return (status == ACS_STATUS_SKIP) ? unavailable_result(baseline) : status;

  val_print(ACS_PRINT_DEBUG, " RVPKVF: D2H SNP result 0x%x", result);
  if ((result & CXL_SNOOP_RESULT_EMITTED) == 0u)
  {
    val_print((baseline != 0u) ? ACS_PRINT_INFO : ACS_PRINT_ERR,
              " RVPKVF: TDI did not emit snoop for HPA 0x%llx",
              target_hpa);
    return (baseline != 0u) ? ACS_STATUS_SKIP : ACS_STATUS_FAIL;
  }

  val_print(ACS_PRINT_INFO,
            " RVPKVF: device-to-host SNP emitted for HPA 0x%llx",
            target_hpa);

  return ACS_STATUS_PASS;
}

/*
 * Force a host-to-device REQ by cleaning a dirty host cache line, then confirm
 * that the resulting coherent transaction reaches the device interface. A
 * cache writeback can be represented downstream as an ordinary write request,
 * so the architectural observation is the target HPA rather than an
 * implementation-specific transaction-attribute bit.
 */
static uint32_t
check_host_to_device_request(uint32_t endpoint_bdf,
                             uint64_t target_hpa,
                             volatile uint64_t *target_alias,
                             uint32_t baseline)
{
  uint32_t observed;
  uint32_t status;

  if (target_alias == NULL)
    return ACS_STATUS_ERR;

  status = val_exerciser_start_transaction_monitor_by_bdf(endpoint_bdf);
  if (status != ACS_STATUS_PASS)
    return (status == ACS_STATUS_SKIP) ? unavailable_result(baseline) : status;

  status = val_memory_cache_clean_invalidate_range_el3((uint64_t)target_alias,
                                                        sizeof(uint64_t));
  if (val_exerciser_stop_transaction_monitor_by_bdf(endpoint_bdf)
      != ACS_STATUS_PASS)
    return ACS_STATUS_ERR;
  if (status != ACS_STATUS_PASS)
    return ACS_STATUS_FAIL;

  status = val_exerciser_find_transaction_by_bdf(
                                  endpoint_bdf,
                                  target_hpa,
                                  0u,
                                  &observed);
  if (status != ACS_STATUS_PASS)
    return status;
  if (observed == 0u)
  {
    val_print((baseline != 0u) ? ACS_PRINT_INFO : ACS_PRINT_ERR,
              " RVPKVF: host request did not reach HPA 0x%llx",
              target_hpa);
    return (baseline != 0u) ? ACS_STATUS_SKIP : ACS_STATUS_FAIL;
  }

  val_print(ACS_PRINT_INFO,
            " RVPKVF: host-to-device request reached HPA 0x%llx",
            target_hpa);

  return ACS_STATUS_PASS;
}

/*
 * Leave a dirty Realm copy in the PE cache. The following cache clean and
 * invalidate must then issue a coherent request instead of completing as a
 * local cache miss.
 */
static uint32_t
prepare_host_request_line(volatile uint64_t *target_alias, uint64_t value)
{
  if (target_alias == NULL)
    return ACS_STATUS_ERR;

  if ((val_memory_write_el3((uint64_t)target_alias,
                            (uint32_t)value) != ACS_STATUS_PASS) ||
      (val_memory_write_el3((uint64_t)target_alias + sizeof(uint32_t),
                            (uint32_t)(value >> 32)) != ACS_STATUS_PASS))
    return ACS_STATUS_ERR;

  return ACS_STATUS_PASS;
}

static uint32_t
run_state_checks(uint32_t endpoint_bdf,
                 uint64_t snoop_hpa,
                 volatile uint64_t *snoop_alias,
                 uint64_t snoop_value,
                 uint64_t request_hpa,
                 volatile uint64_t *request_alias,
                 uint32_t baseline)
{
  uint32_t status;

  status = check_host_to_device_snoop(endpoint_bdf,
                                      snoop_hpa,
                                      snoop_alias,
                                      snoop_value,
                                      baseline);
  if (status != ACS_STATUS_PASS)
    return status;

  status = check_host_to_device_request(endpoint_bdf,
                                        request_hpa,
                                        request_alias,
                                        baseline);
  if (status != ACS_STATUS_PASS)
    return status;

  return check_device_to_host_snoop(endpoint_bdf,
                                    request_hpa,
                                    baseline);
}

static uint32_t
exercise_rule(VAL_CDA_DCM_WINDOW_CONTEXT *context)
{
  RVPKVF_LINK_CONTEXT link;
  VAL_SMMU_DPT_CFG_STATE dpt_cfg_state;
  smmu_master_attributes_t master;
  pgt_descriptor_t pgt_desc;
  volatile uint64_t *alias[TEST_PAGE_COUNT];
  uint8_t *verify_va;
  uint64_t max_pa;
  uint64_t page[TEST_PAGE_COUNT];
  uint64_t page_size;
  uint64_t verify_pa;
  uint32_t assigned_mask;
  uint32_t ats_cap_base;
  uint32_t ats_ctrl_orig;
  uint32_t ats_enabled;
  uint32_t dcm_dpt_mask;
  uint32_t dpt_coverage_configured;
  uint32_t gpt_mask;
  uint32_t pgt_created;
  uint32_t result;
  uint32_t rid_range_programmed;
  uint32_t rmecda_ctl3_orig;
  uint32_t rmecda_ctl4_orig;
  uint32_t smmu_enabled;
  uint32_t status;
  uint32_t verify_dpt_set;
  uint32_t verify_gpt_set;

  if (context == NULL)
    return ACS_STATUS_ERR;

  status = select_test_pages(context, page);
  if (status != ACS_STATUS_PASS)
    return status;

  page_size = (uint64_t)val_memory_page_size();
  if (page_size == 0u)
    return ACS_STATUS_ERR;

  val_memory_set(&link, sizeof(link), 0);
  val_memory_set(&dpt_cfg_state, sizeof(dpt_cfg_state), 0);
  val_memory_set(&master, sizeof(master), 0);
  val_memory_set(&pgt_desc, sizeof(pgt_desc), 0);
  val_memory_set(alias, sizeof(alias), 0);
  master.smmu_index = ACS_INVALID_INDEX;
  verify_va = NULL;
  verify_pa = 0u;
  assigned_mask = 0u;
  ats_cap_base = 0u;
  ats_ctrl_orig = 0u;
  ats_enabled = 0u;
  dcm_dpt_mask = 0u;
  dpt_coverage_configured = 0u;
  gpt_mask = 0u;
  pgt_created = 0u;
  rid_range_programmed = 0u;
  rmecda_ctl3_orig = 0u;
  rmecda_ctl4_orig = 0u;
  smmu_enabled = 0u;
  verify_dpt_set = 0u;
  verify_gpt_set = 0u;
  result = ACS_STATUS_FAIL;

  verify_va = (uint8_t *)val_memory_alloc_pages(1u);
  if (verify_va == NULL)
    return ACS_STATUS_SKIP;

  verify_pa = (uint64_t)val_memory_virt_to_phys(verify_va);
  if ((verify_pa == 0u) ||
      (val_memory_map_el3_data((uint64_t)verify_va,
                               page_size,
                               NONSECURE_PAS) != ACS_STATUS_PASS) ||
      (val_add_gpt_entry_el3(verify_pa, GPT_ANY) != 0u))
  {
    result = ACS_STATUS_ERR;
    goto cleanup;
  }
  verify_gpt_set = 1u;

  for (uint32_t index = 0u; index < TEST_PAGE_COUNT; ++index)
  {
    if (val_add_gpt_entry_el3(page[index], GPT_ANY) != 0u)
    {
      result = ACS_STATUS_ERR;
      goto cleanup;
    }
    gpt_mask |= (1u << index);

    if (val_memory_map_realm_cacheable_alias(page[index], &alias[index])
        != ACS_STATUS_PASS)
    {
      result = ACS_STATUS_ERR;
      goto cleanup;
    }
  }

  status = val_cda_prepare_realm_dma_mapping(context->endpoint_bdf,
                                              page[RUN_SNOOP_PAGE],
                                              TEST_PAGE_COUNT * page_size,
                                              verify_pa,
                                              page_size,
                                              &master,
                                              &pgt_desc);
  if (status != ACS_STATUS_PASS)
  {
    result = status;
    goto cleanup;
  }
  smmu_enabled = 1u;
  pgt_created = 1u;

  if (val_smmu_gpt_invalidate_el3(&master) != 0u)
  {
    result = ACS_STATUS_ERR;
    goto cleanup;
  }

  max_pa = (page[REQUEST_PAGE] > verify_pa) ? page[REQUEST_PAGE] : verify_pa;
  status = val_smmu_configure_dpt_coverage(master.smmu_index,
                                           max_pa,
                                           &dpt_cfg_state);
  if (status != ACS_STATUS_PASS)
  {
    result = status;
    goto cleanup;
  }
  dpt_coverage_configured = 1u;

  for (uint32_t index = 0u; index < TEST_PAGE_COUNT; ++index)
  {
    if (val_dpt_add_entry(page[index],
                          (((uint64_t)master.smmu_index << 32) |
                           DPT_RDWR_ACCESS_ENTRY)) != 0u)
    {
      result = ACS_STATUS_ERR;
      goto cleanup;
    }
    dcm_dpt_mask |= (1u << index);
  }

  if (val_dpt_add_entry(verify_pa,
                        (((uint64_t)master.smmu_index << 32) |
                         DPT_RDWR_NS_ACCESS_ENTRY)) != 0u)
  {
    result = ACS_STATUS_ERR;
    goto cleanup;
  }
  verify_dpt_set = 1u;

  if (val_dpt_invalidate_all(master.smmu_index) != 0u)
  {
    result = ACS_STATUS_ERR;
    goto cleanup;
  }

  status = val_pcie_enable_ats(context->endpoint_bdf,
                               &ats_cap_base,
                               &ats_ctrl_orig);
  if (status != ACS_STATUS_PASS)
  {
    result = status;
    goto cleanup;
  }
  ats_enabled = 1u;

  if ((val_memory_read_el3(context->rmecda_cfg_va + context->rmecda_cap_base +
                           RMECDA_CTL3_OFFSET,
                           &rmecda_ctl3_orig) != ACS_STATUS_PASS) ||
      (val_memory_read_el3(context->rmecda_cfg_va + context->rmecda_cap_base +
                           RMECDA_CTL4_OFFSET,
                           &rmecda_ctl4_orig) != ACS_STATUS_PASS))
  {
    result = ACS_STATUS_ERR;
    goto cleanup;
  }

  status = val_cda_program_rid_range(
             context->rmecda_cfg_va,
             context->rmecda_cap_base,
             rmecda_ctl3_orig,
             rmecda_ctl4_orig,
             (uint32_t)PCIE_CREATE_BDF_PACKED(context->endpoint_bdf),
             (uint32_t)PCIE_CREATE_BDF_PACKED(context->endpoint_bdf),
             1u);
  if (status != ACS_STATUS_PASS)
  {
    result = status;
    goto cleanup;
  }
  rid_range_programmed = 1u;

  for (uint32_t index = 0u; index < TEST_PAGE_COUNT; ++index)
  {
    if (val_cxl_exerciser_execute_cmd(
                                  context->endpoint_bdf,
                                  CXL_CMD_OP_DCM_SET_REALM_ASSIGNMENT,
                                  page[index],
                                  1u,
                                  NULL) != ACS_STATUS_PASS)
    {
      val_print(ACS_PRINT_INFO,
                " RVPKVF: Realm DCM association is unavailable",
                0);
      result = ACS_STATUS_SKIP;
      goto cleanup;
    }
    assigned_mask |= (1u << index);
  }

  status = start_realm_link(context, &link);
  if (status != ACS_STATUS_PASS)
  {
    result = status;
    goto cleanup;
  }

  /*
   * Fetch two equivalent lines through the TDI's Realm coherent path while it
   * is in RUN. Separate lines keep the RUN snoop from changing the line used
   * after the transition to ERROR.
   */
  if ((val_cda_populate_realm_device_cache_line(
                                   context->endpoint_bdf,
                                   alias[RUN_SNOOP_PAGE],
                                   page[RUN_SNOOP_PAGE],
                                   verify_va,
                                   verify_pa,
                                   RUN_SNOOP_VALUE,
                                   (uint32_t)page_size) != ACS_STATUS_PASS) ||
      (val_cda_populate_realm_device_cache_line(
                                   context->endpoint_bdf,
                                   alias[ERROR_SNOOP_PAGE],
                                   page[ERROR_SNOOP_PAGE],
                                   verify_va,
                                   verify_pa,
                                   ERROR_SNOOP_VALUE,
                                   (uint32_t)page_size) != ACS_STATUS_PASS) ||
      (val_cda_seed_realm_cache_line(page[REQUEST_PAGE],
                                      alias[REQUEST_PAGE],
                                      REQUEST_VALUE) != ACS_STATUS_PASS))
  {
    val_print(ACS_PRINT_ERR,
              " RVPKVF: coherent device cache-line setup failed",
              0);
    result = ACS_STATUS_FAIL;
    goto cleanup;
  }

  if ((val_cxl_exerciser_execute_cmd(context->endpoint_bdf,
                                      CXL_CMD_OP_DCM_CACHE_DIRTY,
                                      page[RUN_SNOOP_PAGE],
                                      0u,
                                      NULL) != ACS_STATUS_PASS) ||
      (val_cxl_exerciser_execute_cmd(context->endpoint_bdf,
                                      CXL_CMD_OP_DCM_CACHE_DIRTY,
                                      page[ERROR_SNOOP_PAGE],
                                      0u,
                                      NULL) != ACS_STATUS_PASS))
  {
    val_print(ACS_PRINT_INFO,
              " RVPKVF: device cache-line stimulus is unavailable",
              0);
    result = ACS_STATUS_SKIP;
    goto cleanup;
  }

  if (prepare_host_request_line(alias[REQUEST_PAGE], REQUEST_VALUE)
      != ACS_STATUS_PASS)
  {
    val_print(ACS_PRINT_ERR,
              " RVPKVF: RUN host request-line setup failed",
              0);
    result = ACS_STATUS_FAIL;
    goto cleanup;
  }

  val_print(ACS_PRINT_INFO, " RVPKVF: checking operations in TDI RUN", 0);
  status = run_state_checks(context->endpoint_bdf,
                            page[RUN_SNOOP_PAGE],
                            alias[RUN_SNOOP_PAGE],
                            RUN_SNOOP_VALUE,
                            page[REQUEST_PAGE],
                            alias[REQUEST_PAGE],
                            1u);
  if (status != ACS_STATUS_PASS)
  {
    result = status;
    goto cleanup;
  }

  /* Stage the ERROR-state request while Realm access is still permitted in RUN. */
  if (prepare_host_request_line(alias[REQUEST_PAGE], REQUEST_VALUE)
      != ACS_STATUS_PASS)
  {
    val_print(ACS_PRINT_ERR,
              " RVPKVF: ERROR host request-line setup failed",
              0);
    result = ACS_STATUS_FAIL;
    goto cleanup;
  }

  status = enter_tdi_error(&link);
  if (status != ACS_STATUS_PASS)
  {
    result = status;
    goto cleanup;
  }

  val_print(ACS_PRINT_INFO, " RVPKVF: checking operations in TDI ERROR", 0);
  status = run_state_checks(context->endpoint_bdf,
                            page[ERROR_SNOOP_PAGE],
                            alias[ERROR_SNOOP_PAGE],
                            ERROR_SNOOP_VALUE,
                            page[REQUEST_PAGE],
                            alias[REQUEST_PAGE],
                            0u);
  result = status;

cleanup:
  /* Recover the endpoint before using its exerciser control interface. */
  if (stop_realm_link(context, &link) != ACS_STATUS_PASS)
    result = ACS_STATUS_FAIL;

  (void)val_exerciser_set_param_by_bdf(CFG_TXN_ATTRIBUTES,
                                       TXN_ATC_ENTRY,
                                       ATC_ENTRY_DISABLE,
                                       context->endpoint_bdf);
  if (ats_enabled != 0u)
  {
    (void)val_exerciser_set_param_by_bdf(EXERCISER_ATS_REQUEST_ATTRIBUTES,
                                         0u,
                                         0u,
                                         context->endpoint_bdf);
    (void)val_exerciser_ops_by_bdf(ATS_INV_CACHE,
                                    0u,
                                    context->endpoint_bdf);
  }

  for (uint32_t index = 0u; index < TEST_PAGE_COUNT; ++index)
  {
    if ((assigned_mask & (1u << index)) != 0u)
    {
      if (val_cxl_exerciser_execute_cmd(
                                  context->endpoint_bdf,
                                  CXL_CMD_OP_DCM_SET_REALM_ASSIGNMENT,
                                  page[index],
                                  0u,
                                  NULL) != ACS_STATUS_PASS)
        result = ACS_STATUS_FAIL;
    }
  }

  if (rid_range_programmed != 0u)
  {
    if (val_cda_program_rid_range(context->rmecda_cfg_va,
                                  context->rmecda_cap_base,
                                  rmecda_ctl3_orig,
                                  rmecda_ctl4_orig,
                                  (rmecda_ctl4_orig >> 8) & 0xFFFFu,
                                  (rmecda_ctl3_orig >> 8) & 0xFFFFu,
                                  rmecda_ctl4_orig & 0x1u) != ACS_STATUS_PASS)
      result = ACS_STATUS_FAIL;
  }

  if ((smmu_enabled != 0u) &&
      ((dcm_dpt_mask != 0u) || (verify_dpt_set != 0u)))
  {
    for (uint32_t index = 0u; index < TEST_PAGE_COUNT; ++index)
    {
      if ((dcm_dpt_mask & (1u << index)) != 0u)
        (void)val_dpt_add_entry(page[index],
                                (((uint64_t)master.smmu_index << 32) |
                                 DPT_RDWR_ACCESS_ENTRY));
    }
    if (verify_dpt_set != 0u)
      (void)val_dpt_add_entry(verify_pa,
                              (((uint64_t)master.smmu_index << 32) |
                               DPT_RDWR_ACCESS_ENTRY));
    (void)val_dpt_invalidate_all(master.smmu_index);
  }

  if ((dpt_coverage_configured != 0u) &&
      (val_smmu_restore_dpt_coverage(&dpt_cfg_state) != ACS_STATUS_PASS))
    result = ACS_STATUS_FAIL;

  if (pgt_created != 0u)
    val_rlm_pgt_destroy(&pgt_desc);
  if (smmu_enabled != 0u)
    (void)val_smmu_disable(master.smmu_index);

  for (uint32_t index = 0u; index < TEST_PAGE_COUNT; ++index)
  {
    if (((gpt_mask & (1u << index)) != 0u) &&
        (val_add_gpt_entry_el3(page[index], GPT_ANY) != 0u))
      result = ACS_STATUS_FAIL;
  }

  if ((verify_gpt_set != 0u) &&
      (val_add_gpt_entry_el3(verify_pa, GPT_ANY) != 0u))
    result = ACS_STATUS_FAIL;

  if (ats_enabled != 0u)
    val_pcie_write_cfg(context->endpoint_bdf,
                       ats_cap_base + ATS_CTRL,
                       ats_ctrl_orig);

  if (verify_va != NULL)
    val_memory_free_pages(verify_va, 1u);

  return result;
}

static void
payload(void)
{
  CXL_COMPONENT_TABLE *table;
  VAL_CDA_DCM_WINDOW_CONTEXT context;
  uint32_t context_prepared;
  uint32_t next_root_index;
  uint32_t pe_index;
  uint32_t status;

  pe_index = val_pe_get_index_mpid(val_pe_get_mpid());
  table = val_cxl_component_table_ptr();
  next_root_index = 0u;
  status = ACS_STATUS_SKIP;

  /*
   * Cache controls are implementation-defined test stimuli, while incoming
   * coherent traffic is observed by the exerciser transaction monitor. If one
   * otherwise eligible endpoint cannot provide them, restore its state and
   * continue with the next CHI-C2C endpoint.
   */
  while ((table != NULL) && (next_root_index < table->num_entries))
  {
    context_prepared = 0u;
    status = val_cda_prepare_dcm_window_from_root_index(DECODER_SLOT,
                                                        0u,
                                                        next_root_index,
                                                        &context);
    if (status != ACS_STATUS_PASS)
      break;

    context_prepared = 1u;
    next_root_index = context.root_index + 1u;
    val_print(ACS_PRINT_INFO,
              " RVPKVF: testing CHI-C2C endpoint 0x%x",
              context.endpoint_bdf);
    status = exercise_rule(&context);

    if ((context_prepared != 0u) &&
        (val_cda_restore_dcm_window(&context) != ACS_STATUS_PASS))
    {
      val_print(ACS_PRINT_ERR,
                " RVPKVF: platform state restoration failed",
                0);
      status = ACS_STATUS_FAIL;
    }

    if (status != ACS_STATUS_SKIP)
      break;

    val_print(ACS_PRINT_INFO,
              " RVPKVF: stimulus unavailable for endpoint 0x%x; continuing",
              context.endpoint_bdf);
  }

  if (status == ACS_STATUS_PASS)
    val_set_status(pe_index, "PASS", 01);
  else if (status == ACS_STATUS_SKIP)
    val_set_status(pe_index, "SKIP", 02);
  else
    val_set_status(pe_index, "FAIL", 02);
}

#else

static void
payload(void)
{
  uint32_t pe_index;

  pe_index = val_pe_get_index_mpid(val_pe_get_mpid());
  val_print(ACS_PRINT_INFO, " RVPKVF: SPDM/TDISP support not enabled", 0);
  val_set_status(pe_index, "SKIP", 01);
}

#endif

uint32_t
cda_rvpkvf_tdi_state_independent_entry(uint32_t num_pe)
{
  uint32_t status;

  num_pe = 1u;
  status = val_initialize_test(TEST_NAME, TEST_DESC, num_pe, TEST_RULE);

  if (status != ACS_STATUS_SKIP)
    val_run_test_payload(num_pe, payload, 0);

  status = val_check_for_error(num_pe);
  val_report_status(0, "END");
  return status;
}
