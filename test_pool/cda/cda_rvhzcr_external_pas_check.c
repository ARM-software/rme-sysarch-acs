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
#include "val/include/val_spdm.h"
#include "val/include/val_tdisp.h"

#define TEST_NAME "cda_rvhzcr_external_pas_check"
#define TEST_DESC "PAS_CHECK protects external access to DCM       "
#define TEST_RULE "RVHZCR"

#define DECODER_SLOT 0u

#define POSITIVE_VALUE 0x35CA6A95F00D1EAFULL
#define PROTECTED_VALUE 0xCA35956A0FF2E150ULL

#if ENABLE_SPDM

typedef struct {
  val_spdm_context_t spdm_ctx;
  pci_tdisp_interface_id_t interface_id;
  uint32_t session_id;
  uint32_t session_active;
  uint32_t ide_active;
} EXTERNAL_PATH_CONTEXT;

static uint32_t
seed_dcm_media(uint32_t endpoint_bdf,
               uint64_t dpa,
               uint64_t value)
{
  uint64_t observed;

  /* Direct media access is used only to arrange and verify test data. */
  if (val_cxl_exerciser_backdoor_write64(endpoint_bdf, dpa, value)
      != ACS_STATUS_PASS)
    return ACS_STATUS_SKIP;

  if (val_cxl_exerciser_backdoor_read64(endpoint_bdf, dpa, &observed)
      != ACS_STATUS_PASS)
    return ACS_STATUS_FAIL;

  return (observed == value) ? ACS_STATUS_PASS : ACS_STATUS_FAIL;
}

static uint32_t
start_external_path(const VAL_CDA_DCM_WINDOW_CONTEXT *context,
                    EXTERNAL_PATH_CONTEXT *path)
{
  uint32_t status;

  if ((context == NULL) || (path == NULL))
    return ACS_STATUS_ERR;

  val_memory_set(path, sizeof(*path), 0);
  status = val_tdisp_establish_run(context->endpoint_bdf,
                                   &path->spdm_ctx,
                                   &path->session_id,
                                   &path->interface_id);
  if (status != ACS_STATUS_PASS)
    return status;
  path->session_active = 1u;

  status = val_cxl_ide_establish_link(context->root_index,
                                      context->endpoint_index,
                                      &path->spdm_ctx,
                                      path->session_id);
  if (status != ACS_STATUS_PASS)
  {
    (void)val_tdisp_stop_if_needed(&path->spdm_ctx,
                                   path->session_id,
                                   &path->interface_id,
                                   0u);
    path->session_active = 0u;
    return status;
  }

  path->ide_active = 1u;
  return ACS_STATUS_PASS;
}

static uint32_t
stop_external_path(const VAL_CDA_DCM_WINDOW_CONTEXT *context,
                   EXTERNAL_PATH_CONTEXT *path)
{
  uint32_t result;

  if ((context == NULL) || (path == NULL))
    return ACS_STATUS_ERR;

  result = ACS_STATUS_PASS;
  if (path->ide_active != 0u)
  {
    if (val_cxl_ide_disable_link(context->root_index,
                                 context->endpoint_index,
                                 &path->spdm_ctx,
                                 path->session_id) != ACS_STATUS_PASS)
      result = ACS_STATUS_FAIL;
    path->ide_active = 0u;
  }

  if (path->session_active != 0u)
  {
    if (val_tdisp_stop_if_needed(&path->spdm_ctx,
                                 path->session_id,
                                 &path->interface_id,
                                 0u) != ACS_STATUS_PASS)
      result = ACS_STATUS_FAIL;
    path->session_active = 0u;
  }

  return result;
}

static uint32_t
exercise_rule(VAL_CDA_DCM_WINDOW_CONTEXT *context)
{
  EXTERNAL_PATH_CONTEXT path;
  volatile uint64_t *realm_alias;
  uint32_t properties;
  uint32_t realm_assigned;
  uint32_t gpt_realm;
  uint32_t fault_seen;
  uint32_t result;
  uint32_t status;
  uint64_t test_hpa;
  uint64_t test_dpa;
  uint64_t observed;

  if (context == NULL)
    return ACS_STATUS_ERR;

  status = val_tdisp_get_device_properties(context->endpoint_bdf, &properties);
  if (status != ACS_STATUS_PASS)
    return status;

  val_print(ACS_PRINT_INFO, " RVHZCR: TDISP properties 0x%x", properties);
  if ((properties & VAL_TDISP_DEV_PROP_PAS_CHECK) == 0u)
  {
    val_print(ACS_PRINT_INFO, " RVHZCR: PAS_CHECK is not implemented", 0);
    return ACS_STATUS_SKIP;
  }

  status = val_cda_select_dcm_page(context->window_base,
                                   context->window_size,
                                   &test_hpa);
  if (status != ACS_STATUS_PASS)
    return status;

  status = val_cxl_hpa_to_dpa(context->endpoint_index, test_hpa, &test_dpa);
  if (status != ACS_STATUS_PASS)
    return ACS_STATUS_SKIP;

  realm_alias = NULL;
  if (val_memory_map_realm_cacheable_alias(test_hpa, &realm_alias)
      != ACS_STATUS_PASS)
    return ACS_STATUS_ERR;

  val_print(ACS_PRINT_INFO, " RVHZCR: external-access HPA 0x%llx", test_hpa);

  val_memory_set(&path, sizeof(path), 0);
  realm_assigned = 0u;
  gpt_realm = 0u;
  result = ACS_STATUS_FAIL;

  /*
   * Keep the host-side GPT permissive for the Realm transaction throughout
   * both phases. The negative phase can then be attributed to the device-side
   * PAS protection rather than an earlier host GPC rejection.
   */
  if (val_add_gpt_entry_el3(test_hpa, GPT_REALM) != 0u)
  {
    result = ACS_STATUS_ERR;
    goto cleanup;
  }
  gpt_realm = 1u;

  status = val_cxl_exerciser_execute_cmd(context->endpoint_bdf,
                                         CXL_CMD_OP_DCM_SET_REALM_ASSIGNMENT,
                                         test_hpa,
                                         1u,
                                         NULL);
  if (status != ACS_STATUS_PASS)
  {
    val_print(ACS_PRINT_INFO,
              " RVHZCR: DCM PAS-assignment control is unavailable",
              0);
    result = ACS_STATUS_SKIP;
    goto cleanup;
  }
  realm_assigned = 1u;

  status = seed_dcm_media(context->endpoint_bdf, test_dpa, POSITIVE_VALUE);
  if (status != ACS_STATUS_PASS)
  {
    result = status;
    goto cleanup;
  }

  /* Positive control: a correctly associated external Realm read succeeds. */
  status = start_external_path(context, &path);
  if (status != ACS_STATUS_PASS)
  {
    result = status;
    goto cleanup;
  }

  fault_seen = 0u;
  observed = 0u;
  status = val_memory_read64_el3_protected(realm_alias,
                                           &observed,
                                           &fault_seen);
  if ((status != ACS_STATUS_PASS) || (fault_seen != 0u) ||
      (observed != POSITIVE_VALUE))
  {
    val_print(ACS_PRINT_ERR, " RVHZCR: read status %u", status);
    val_print(ACS_PRINT_ERR, " RVHZCR: fault seen %u", fault_seen);
    val_print(ACS_PRINT_ERR, " RVHZCR: observed 0x%llx", observed);
    val_print(ACS_PRINT_ERR, " RVHZCR: expected 0x%llx", POSITIVE_VALUE);
    val_print(ACS_PRINT_ERR,
              " RVHZCR: permitted external Realm read did not complete",
              0);
    goto cleanup;
  }

  /* Remove any cached copy before changing the DCM PAS association. */
  if (val_data_cache_ops_by_pa_el3(test_hpa, REALM_PAS) != 0u)
  {
    result = ACS_STATUS_ERR;
    goto cleanup;
  }

  if (stop_external_path(context, &path) != ACS_STATUS_PASS)
    goto cleanup;

  status = val_cxl_exerciser_execute_cmd(context->endpoint_bdf,
                                         CXL_CMD_OP_DCM_SET_REALM_ASSIGNMENT,
                                         test_hpa,
                                         0u,
                                         NULL);
  if (status != ACS_STATUS_PASS)
    goto cleanup;
  realm_assigned = 0u;

  status = seed_dcm_media(context->endpoint_bdf, test_dpa, PROTECTED_VALUE);
  if (status != ACS_STATUS_PASS)
  {
    result = status;
    goto cleanup;
  }

  status = start_external_path(context, &path);
  if (status != ACS_STATUS_PASS)
  {
    result = status;
    goto cleanup;
  }

  /*
   * The host still issues the same Realm-PAS HPA transaction, but the target
   * page is no longer associated with Realm at the device. Protection is
   * demonstrated by a recoverable fault or by data other than the protected
   * media value; exerciser command status is not used as the verdict.
   */
  fault_seen = 0u;
  observed = 0u;
  status = val_memory_read64_el3_protected(realm_alias,
                                           &observed,
                                           &fault_seen);
  if (status != ACS_STATUS_PASS)
    goto cleanup;

  if ((fault_seen == 0u) && (observed == PROTECTED_VALUE))
  {
    val_print(ACS_PRINT_ERR,
              " RVHZCR: device exposed DCM through a disallowed Realm access",
              0);
    goto cleanup;
  }

  val_print(ACS_PRINT_INFO,
            " RVHZCR: device-side PAS check blocked external DCM data",
            0);
  result = ACS_STATUS_PASS;

cleanup:
  if (stop_external_path(context, &path) != ACS_STATUS_PASS)
    result = ACS_STATUS_FAIL;

  if (realm_assigned != 0u)
  {
    if (val_cxl_exerciser_execute_cmd(context->endpoint_bdf,
                                      CXL_CMD_OP_DCM_SET_REALM_ASSIGNMENT,
                                      test_hpa,
                                      0u,
                                      NULL) != ACS_STATUS_PASS)
      result = ACS_STATUS_FAIL;
  }

  if ((gpt_realm != 0u) && (val_add_gpt_entry_el3(test_hpa, GPT_ANY) != 0u))
    result = ACS_STATUS_FAIL;

  return result;
}

static void
payload(void)
{
  VAL_CDA_DCM_WINDOW_CONTEXT context;
  uint32_t pe_index;
  uint32_t status;

  pe_index = val_pe_get_index_mpid(val_pe_get_mpid());
  status = val_cda_prepare_dcm_window_with_dev_props(
             DECODER_SLOT,
             VAL_TDISP_DEV_PROP_PAS_CHECK,
             &context);
  if (status == ACS_STATUS_SKIP)
  {
    val_print(ACS_PRINT_INFO, " RVHZCR: no suitable CHI-C2C CDA context", 0);
    val_set_status(pe_index, "SKIP", 01);
    return;
  }

  if (status != ACS_STATUS_PASS)
  {
    val_set_status(pe_index, "FAIL", 01);
    return;
  }

  status = exercise_rule(&context);
  if (val_cda_restore_dcm_window(&context) != ACS_STATUS_PASS)
  {
    val_print(ACS_PRINT_ERR, " RVHZCR: platform state restoration failed", 0);
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
  val_set_status(pe_index, "SKIP", 01);
}

#endif

uint32_t
cda_rvhzcr_external_pas_check_entry(uint32_t num_pe)
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
