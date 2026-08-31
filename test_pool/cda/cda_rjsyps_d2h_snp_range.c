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
#include "val/include/val_memory.h"
#include "val/include/val_pe.h"
#include "val/include/val_spdm.h"
#include "val/include/val_tdisp.h"

#define TEST_NAME "cda_rjsyps_d2h_snp_range"
#define TEST_DESC "Host validates D2H SNP address against DCM range"
#define TEST_RULE "RJSYPS"

#define DECODER_SLOT 0u

#if ENABLE_SPDM

typedef struct {
  val_spdm_context_t spdm_ctx;
  pci_tdisp_interface_id_t interface_id;
  uint32_t session_id;
  uint32_t session_active;
  uint32_t ide_active;
} RJSYPS_LINK_CONTEXT;

static uint32_t
start_realm_link(const VAL_CDA_DCM_WINDOW_CONTEXT *context,
                 RJSYPS_LINK_CONTEXT *link)
{
  uint32_t status;

  if ((context == NULL) || (link == NULL))
    return ACS_STATUS_ERR;

  val_memory_set(link, sizeof(*link), 0);
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
  {
    (void)val_tdisp_stop_if_needed(&link->spdm_ctx,
                                   link->session_id,
                                   &link->interface_id,
                                   0u);
    link->session_active = 0u;
    return status;
  }

  link->ide_active = 1u;
  return ACS_STATUS_PASS;
}

static uint32_t
stop_realm_link(const VAL_CDA_DCM_WINDOW_CONTEXT *context,
                RJSYPS_LINK_CONTEXT *link)
{
  uint32_t result;

  if ((context == NULL) || (link == NULL))
    return ACS_STATUS_ERR;

  result = ACS_STATUS_PASS;
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
set_realm_assignment(uint32_t endpoint_bdf, uint64_t target_hpa, uint32_t assigned)
{
  return val_cxl_exerciser_execute_cmd(endpoint_bdf,
                                       CXL_CMD_OP_DCM_SET_REALM_ASSIGNMENT,
                                       target_hpa,
                                       assigned,
                                       NULL);
}

static uint32_t
address_in_window(uint64_t address, uint64_t base, uint64_t size)
{
  return ((size != 0u) && (address >= base) &&
          ((address - base) < size)) ? 1u : 0u;
}

/*
 * Require the endpoint to emit the request before examining the completion.
 * This keeps endpoint-side permission enforcement separate from the host-port
 * behavior under test.
 */
static uint32_t
check_snoop_result(uint32_t endpoint_bdf,
                   uint64_t target_hpa,
                   uint32_t access_pas,
                   uint32_t expect_success)
{
  uint32_t host_response;
  uint32_t result;
  uint32_t status;

  status = val_cda_tdi_snoop_attempt(endpoint_bdf,
                                     target_hpa,
                                     access_pas,
                                     &result);
  if (status != ACS_STATUS_PASS)
    return status;

  val_print(ACS_PRINT_DEBUG, " RJSYPS: SNP result flags 0x%x", result);

  if ((result & CXL_SNOOP_RESULT_EMITTED) == 0u)
  {
    val_print(ACS_PRINT_INFO,
              " RJSYPS: endpoint did not emit SNP for PA 0x%llx",
              target_hpa);
    return ACS_STATUS_SKIP;
  }

  host_response = result & (CXL_SNOOP_RESULT_HOST_ACCEPTED |
                            CXL_SNOOP_RESULT_HOST_REJECTED);
  if (host_response == 0u)
  {
    val_print(ACS_PRINT_INFO,
              " RJSYPS: host response is not observable for PA 0x%llx",
              target_hpa);
    return ACS_STATUS_SKIP;
  }

  if (expect_success != 0u)
  {
    if ((host_response & CXL_SNOOP_RESULT_HOST_ACCEPTED) == 0u)
    {
      val_print(ACS_PRINT_ERR,
                " RJSYPS: host rejected in-range DCM SNP 0x%llx",
                target_hpa);
      return ACS_STATUS_FAIL;
    }
    val_print(ACS_PRINT_INFO,
              " RJSYPS: host accepted in-range Realm SNP 0x%llx",
              target_hpa);
  }
  else
  {
    if ((host_response & CXL_SNOOP_RESULT_HOST_REJECTED) == 0u)
    {
      val_print(ACS_PRINT_ERR,
                " RJSYPS: host accepted out-of-range SNP 0x%llx",
                target_hpa);
      return ACS_STATUS_FAIL;
    }
    val_print(ACS_PRINT_INFO,
              " RJSYPS: host rejected out-of-range SNP 0x%llx",
              target_hpa);
  }

  return ACS_STATUS_PASS;
}

static uint32_t
exercise_rule(VAL_CDA_DCM_WINDOW_CONTEXT *context, uint64_t outside_hpa)
{
  RJSYPS_LINK_CONTEXT link;
  uint64_t dcm_hpa;
  uint32_t dcm_gpt_set;
  uint32_t outside_gpt_set;
  uint32_t realm_assigned;
  uint32_t result;
  uint32_t status;

  if ((context == NULL) || (outside_hpa == 0u))
    return ACS_STATUS_ERR;

  if (address_in_window(outside_hpa,
                        context->window_base,
                        context->window_size) != 0u)
    return ACS_STATUS_SKIP;

  status = val_cda_select_dcm_page(context->window_base,
                                   context->window_size,
                                   &dcm_hpa);
  if (status != ACS_STATUS_PASS)
    return status;

  val_memory_set(&link, sizeof(link), 0);
  dcm_gpt_set = 0u;
  outside_gpt_set = 0u;
  realm_assigned = 0u;
  result = ACS_STATUS_FAIL;

  /*
   * Deliberately give the DCM page conflicting GPT state. The in-range Realm
   * SNP must use the host-port DCM and Access PAS checks without a GPC lookup.
   */
  if (val_add_gpt_entry_el3(dcm_hpa, GPT_NONSECURE) != 0u)
  {
    result = ACS_STATUS_ERR;
    goto cleanup;
  }
  dcm_gpt_set = 1u;

  if (val_add_gpt_entry_el3(outside_hpa, GPT_NONSECURE) != 0u)
  {
    result = ACS_STATUS_ERR;
    goto cleanup;
  }
  outside_gpt_set = 1u;

  status = start_realm_link(context, &link);
  if (status != ACS_STATUS_PASS)
  {
    result = status;
    goto cleanup;
  }

  if (set_realm_assignment(context->endpoint_bdf, dcm_hpa, 1u)
      != ACS_STATUS_PASS)
  {
    val_print(ACS_PRINT_INFO,
              " RJSYPS: DCM PAS-assignment control is unavailable",
              0);
    result = ACS_STATUS_SKIP;
    goto cleanup;
  }
  realm_assigned = 1u;

  val_print(ACS_PRINT_INFO, " RJSYPS: DCM HPA 0x%llx", dcm_hpa);
  val_print(ACS_PRINT_INFO, " RJSYPS: outside HPA 0x%llx", outside_hpa);

  /* A Realm SNP inside the attached DCM is permitted through the active link. */
  status = check_snoop_result(context->endpoint_bdf,
                              dcm_hpa,
                              REALM_PAS,
                              1u);
  if (status != ACS_STATUS_PASS)
  {
    result = status;
    goto cleanup;
  }

  /*
   * The ordinary host page has matching Non-secure GPC state, so accepting it
   * would show that the required DCM-range rejection was not applied.
   */
  status = check_snoop_result(context->endpoint_bdf,
                              outside_hpa,
                              NONSECURE_PAS,
                              0u);
  result = status;

cleanup:
  /* Restore the GPT entries changed for the two range checks. */
  if ((dcm_gpt_set != 0u) && (val_add_gpt_entry_el3(dcm_hpa, GPT_ANY) != 0u))
    result = ACS_STATUS_FAIL;

  if ((outside_gpt_set != 0u) &&
      (val_add_gpt_entry_el3(outside_hpa, GPT_ANY) != 0u))
    result = ACS_STATUS_FAIL;

  if ((realm_assigned != 0u) &&
      (set_realm_assignment(context->endpoint_bdf, dcm_hpa, 0u)
       != ACS_STATUS_PASS))
    result = ACS_STATUS_FAIL;

  if (stop_realm_link(context, &link) != ACS_STATUS_PASS)
    result = ACS_STATUS_FAIL;

  return result;
}

static void
payload(void)
{
  VAL_CDA_DCM_WINDOW_CONTEXT context;
  void *outside_page;
  uint64_t outside_hpa;
  uint32_t context_prepared;
  uint32_t pe_index;
  uint32_t status;

  pe_index = val_pe_get_index_mpid(val_pe_get_mpid());
  outside_page = val_memory_alloc_pages(1u);
  if (outside_page == NULL)
  {
    val_set_status(pe_index, "FAIL", 01);
    return;
  }
  outside_hpa = (uint64_t)val_memory_virt_to_phys(outside_page);
  if (outside_hpa == 0u)
  {
    val_memory_free_pages(outside_page, 1u);
    val_set_status(pe_index, "FAIL", 01);
    return;
  }

  context_prepared = 0u;
  status = val_cda_prepare_dcm_window(DECODER_SLOT, &context);
  if (status == ACS_STATUS_PASS)
  {
    context_prepared = 1u;
    status = exercise_rule(&context, outside_hpa);
  }

  if ((context_prepared != 0u) &&
      (val_cda_restore_dcm_window(&context) != ACS_STATUS_PASS))
  {
    val_print(ACS_PRINT_ERR, " RJSYPS: platform state restoration failed", 0);
    status = ACS_STATUS_FAIL;
  }

  val_memory_free_pages(outside_page, 1u);

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
  val_set_status(pe_index, "SKIP", 01);
}

#endif

uint32_t
cda_rjsyps_d2h_snp_range_entry(uint32_t num_pe)
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
