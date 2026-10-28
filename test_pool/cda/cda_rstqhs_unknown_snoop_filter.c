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

#define TEST_NAME "cda_rstqhs_unknown_snoop_filter"
#define TEST_DESC "Host does not snoop an unknown Realm location  "
#define TEST_RULE "RSTQHS"

#define DECODER_SLOT 0u
#if ENABLE_SPDM

typedef struct {
  val_spdm_context_t spdm_ctx;
  pci_tdisp_interface_id_t interface_id;
  uint32_t session_id;
  uint32_t session_active;
  uint32_t ide_active;
} RSTQHS_LINK_CONTEXT;

static uint32_t
start_realm_link(const VAL_CDA_DCM_WINDOW_CONTEXT *context,
                 RSTQHS_LINK_CONTEXT *link)
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
    return status;

  link->ide_active = 1u;
  return ACS_STATUS_PASS;
}

static uint32_t
stop_realm_link(const VAL_CDA_DCM_WINDOW_CONTEXT *context,
                RSTQHS_LINK_CONTEXT *link)
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

/*
 * Capture actual incoming snoops while the PAL initiates a candidate at the
 * host. Completion of the trigger includes the observation interval, so an
 * empty capture is meaningful. Memory reads and CMOs alone are not snoops.
 */
static uint32_t
capture_host_snoop(uint32_t endpoint_bdf,
                   uint64_t target_hpa,
                   uint32_t *observed)
{
  uint32_t status;

  if (observed == NULL)
    return ACS_STATUS_ERR;

  *observed = 0u;
  status = val_exerciser_start_transaction_monitor_by_bdf(endpoint_bdf);
  if (status != ACS_STATUS_PASS)
    return status;

  status = val_cda_host_snoop_trigger(endpoint_bdf, target_hpa);
  if (val_exerciser_stop_transaction_monitor_by_bdf(endpoint_bdf) != ACS_STATUS_PASS)
    return ACS_STATUS_ERR;

  if (status != ACS_STATUS_PASS)
    return status;

  return val_exerciser_find_transaction_by_bdf(
                                  endpoint_bdf,
                                  target_hpa,
                                  EXERCISER_TXN_ATTR_SNOOP,
                                  observed);
}

static uint32_t
exercise_rule(VAL_CDA_DCM_WINDOW_CONTEXT *context)
{
  RSTQHS_LINK_CONTEXT link;
  uint64_t permitted_hpa;
  uint64_t unknown_hpa;
  uint64_t page_size;
  uint32_t permitted_gpt_set;
  uint32_t unknown_gpt_set;
  uint32_t host_setup_attempted;
  uint32_t snoop_observed;
  uint32_t result;
  uint32_t status;

  if (context == NULL)
    return ACS_STATUS_ERR;

  status = val_cda_select_dcm_page(context->window_base,
                                   context->window_size,
                                   &permitted_hpa);
  if (status != ACS_STATUS_PASS)
    return status;

  page_size = (uint64_t)val_memory_page_size();
  if ((page_size == 0u) || (context->window_size < (2u * page_size)) ||
      (permitted_hpa < (context->window_base + page_size)))
    return ACS_STATUS_SKIP;
  unknown_hpa = permitted_hpa - page_size;

  val_memory_set(&link, sizeof(link), 0);
  permitted_gpt_set = 0u;
  unknown_gpt_set = 0u;
  host_setup_attempted = 0u;
  result = ACS_STATUS_FAIL;

  /* Both observations use Realm PAS so Non-secure PAS cannot authorize them. */
  if (val_add_gpt_entry_el3(permitted_hpa, GPT_REALM) != 0u)
  {
    result = ACS_STATUS_ERR;
    goto cleanup;
  }
  permitted_gpt_set = 1u;

  if (val_add_gpt_entry_el3(unknown_hpa, GPT_REALM) != 0u)
  {
    result = ACS_STATUS_ERR;
    goto cleanup;
  }
  unknown_gpt_set = 1u;

  status = start_realm_link(context, &link);
  if (status != ACS_STATUS_PASS)
  {
    result = status;
    goto cleanup;
  }

  /*
   * Eligibility is host state, not the endpoint's Realm assignment table.
   * Require the platform to verify the positive case and exclude every
   * forwarding condition for the unknown target, including permitted MECIDs.
   */
  host_setup_attempted = 1u;
  status = val_cda_host_snoop_prepare(context->root_bdf, context->endpoint_bdf,
                                       permitted_hpa, unknown_hpa);
  if (status != ACS_STATUS_PASS)
  {
    val_print((status == ACS_STATUS_SKIP) ? ACS_PRINT_INFO : ACS_PRINT_ERR,
              " RSTQHS: verified host snoop setup unavailable, status 0x%x", status);
    result = status;
    goto cleanup;
  }

  val_print(ACS_PRINT_INFO,
            " RSTQHS: permitted Realm HPA 0x%llx",
            permitted_hpa);
  status = capture_host_snoop(context->endpoint_bdf,
                              permitted_hpa,
                              &snoop_observed);
  if (status != ACS_STATUS_PASS)
  {
    result = status;
    goto cleanup;
  }

  if (snoop_observed == 0u)
  {
    val_print(ACS_PRINT_INFO,
              " RSTQHS: host-to-device snoop monitor calibration unavailable",
              0);
    result = ACS_STATUS_SKIP;
    goto cleanup;
  }

  /*
   * The PAL has verified that none of the forwarding conditions applies to
   * this Realm candidate. Only a received snoop can fail this observation;
   * unrelated memory requests are ignored by the transaction matcher.
   */
  val_print(ACS_PRINT_INFO,
            " RSTQHS: unknown Realm HPA 0x%llx",
            unknown_hpa);
  status = capture_host_snoop(context->endpoint_bdf,
                              unknown_hpa,
                              &snoop_observed);
  if (status != ACS_STATUS_PASS)
  {
    result = status;
    goto cleanup;
  }

  if (snoop_observed != 0u)
  {
    val_print(ACS_PRINT_ERR,
              " RSTQHS: host forwarded snoop for unknown HPA 0x%llx",
              unknown_hpa);
    result = ACS_STATUS_FAIL;
    goto cleanup;
  }

  result = ACS_STATUS_PASS;

cleanup:
  if ((host_setup_attempted != 0u) &&
      (val_cda_host_snoop_restore(context->endpoint_bdf) != ACS_STATUS_PASS))
  {
    val_print(ACS_PRINT_ERR, " RSTQHS: host snoop state restoration failed", 0);
    result = ACS_STATUS_FAIL;
  }

  if (stop_realm_link(context, &link) != ACS_STATUS_PASS)
    result = ACS_STATUS_FAIL;

  if ((permitted_gpt_set != 0u) &&
      (val_add_gpt_entry_el3(permitted_hpa, GPT_ANY) != 0u))
    result = ACS_STATUS_FAIL;

  if ((unknown_gpt_set != 0u) &&
      (val_add_gpt_entry_el3(unknown_hpa, GPT_ANY) != 0u))
    result = ACS_STATUS_FAIL;

  return result;
}

static void
payload(void)
{
  VAL_CDA_DCM_WINDOW_CONTEXT context;
  uint32_t context_prepared;
  uint32_t pe_index;
  uint32_t status;

  pe_index = val_pe_get_index_mpid(val_pe_get_mpid());
  context_prepared = 0u;

  status = val_cda_prepare_dcm_window(DECODER_SLOT, &context);
  if (status == ACS_STATUS_PASS)
  {
    context_prepared = 1u;
    status = exercise_rule(&context);
  }

  if ((context_prepared != 0u) &&
      (val_cda_restore_dcm_window(&context) != ACS_STATUS_PASS))
  {
    val_print(ACS_PRINT_ERR, " RSTQHS: platform state restoration failed", 0);
    status = ACS_STATUS_FAIL;
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
  val_print(ACS_PRINT_INFO, " RSTQHS: SPDM/TDISP support not enabled", 0);
  val_set_status(pe_index, "SKIP", 01);
}

#endif

uint32_t
cda_rstqhs_unknown_snoop_filter_entry(uint32_t num_pe)
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
