/** @file
 * Copyright (c) 2026, Arm Limited or its affiliates. All rights reserved.
 * SPDX-License-Identifier : Apache-2.0

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
#include "val/include/val_spdm.h"

#define TEST_NAME "cxl_rphwmm_rme_cda_tsp"
#define TEST_DESC "RME-CDA Root Ports comply with CXL-TSP       "
#define TEST_RULE "RPHWMM"

#define REQ_CKIDS 513U

#if ENABLE_SPDM
static uint32_t
verify_root_port(const CXL_COMPONENT_TABLE *table,
                 uint32_t root_index)
{
  /* Validate a single root port by exercising IDE establish and TSP programming. */
  const CXL_COMPONENT_ENTRY *root_port = &table->component[root_index];
  val_spdm_context_t ctx;
  uint32_t session_id = 0;
  uint32_t status;
  uint32_t result = ACS_STATUS_FAIL;
  uint32_t endpoint_index = CXL_COMPONENT_INVALID_INDEX;
  const CXL_COMPONENT_ENTRY *endpoint = NULL;
  uint32_t session_active = 0u;
  const uint32_t requested_ckids = REQ_CKIDS;
  const uint16_t expected_features_enable =
      (uint16_t)(CXL_TSP_MEMORY_ENCRYPTION_FEATURES_ENABLE_ENCRYPTION |
                 CXL_TSP_MEMORY_ENCRYPTION_FEATURES_ENABLE_CKID_BASED_ENCRYPTION);
  uint32_t tsp_locked = 0u;

  /* Check if RP supports CXL IDE*/
  if ((root_port->component_reg_base == 0u) ||
      (val_cxl_find_capability(root_port->component_reg_base,
                               CXL_CAPID_IDE,
                               NULL) != ACS_STATUS_PASS)) {
    val_print(ACS_PRINT_ERR, " Root port missing CXL IDE capability (BDF 0x%x)",
              (uint64_t)root_port->bdf);
    return ACS_STATUS_FAIL;
  }

  /* Find corresponding endpoint for the RP*/
  status = val_cxl_find_downstream_endpoint(root_index, &endpoint_index);
  if (status == ACS_STATUS_SKIP) {
    val_print(ACS_PRINT_INFO,
              " No CXL endpoint downstream of RP BDF 0x%x - skipping",
              (uint64_t)root_port->bdf);
    return ACS_STATUS_SKIP;
  }

  if (status != ACS_STATUS_PASS) {
    val_print(ACS_PRINT_ERR,
              " Failed to locate downstream endpoint for RP BDF 0x%x",
              (uint64_t)root_port->bdf);
    return ACS_STATUS_FAIL;
  }

  endpoint = &table->component[endpoint_index];
  val_print(ACS_PRINT_INFO,
            " RP downstream endpoint BDF 0x%x",
            (uint64_t)endpoint->bdf);
  val_print(ACS_PRINT_INFO,
            " RP BDF 0x%x",
            (uint64_t)root_port->bdf);

  /* Establish an SPDM session with the endpoint so DOE-based flows can proceed. */
  status = val_spdm_session_open(endpoint->bdf, &ctx, &session_id);
  if (status == ACS_STATUS_SKIP) {
    val_print(ACS_PRINT_WARN,
              " DOE absent for endpoint BDF 0x%x - skipping",
              (uint64_t)endpoint->bdf);
    val_print(ACS_PRINT_WARN, " RP 0x%x", (uint64_t)root_port->bdf);
    return ACS_STATUS_SKIP;
  }

  if (status != ACS_STATUS_PASS) {
    val_print(ACS_PRINT_ERR,
              " SPDM session open failed (endpoint BDF 0x%x)",
              (uint64_t)endpoint->bdf);
    return ACS_STATUS_FAIL;
  }

  session_active = 1u;

  /* IDE enablement provides the secure channel needed before programming TSP. */
  status = val_cxl_ide_establish_link(root_index,
                                      endpoint_index,
                                      &ctx,
                                      session_id);
  if (status == ACS_STATUS_SKIP) {
    result = ACS_STATUS_SKIP;
    goto cleanup;
  }
  if (status != ACS_STATUS_PASS)
    goto cleanup;

  /* Configure memory encryption features and lock the TSP instance. */
  status = val_cxl_tsp_configure_and_lock(root_index,
                                          endpoint_index,
                                          &ctx,
                                          session_id,
                                          requested_ckids,
                                          expected_features_enable);
  if (status != ACS_STATUS_PASS)
    goto cleanup;

  tsp_locked = 1u;
  result = ACS_STATUS_PASS;

cleanup:
  if (session_active != 0u)
    (void)val_spdm_session_close(&ctx, session_id);
  if (tsp_locked != 0u)
  {
    status = val_cxl_unlock_tsp_best_effort(root_port->bdf, endpoint->bdf, NULL);
    if (status != ACS_STATUS_PASS)
      val_print(ACS_PRINT_WARN,
                " RPHWMM: Cleanup unlock failed for EP 0x%x",
                (uint64_t)endpoint->bdf);
  }
  return result;
}

static void
payload(void)
{
  uint32_t pe_index = val_pe_get_index_mpid(val_pe_get_mpid());
  CXL_COMPONENT_TABLE *table = val_cxl_component_table_ptr();
  uint32_t tested = 0;
  uint32_t failures = 0;
  uint32_t skipped = 0;

  if ((table == NULL) || (table->num_entries == 0u)) {
    val_print(ACS_PRINT_DEBUG, " No CXL components - skipping RPHWMM", 0);
    val_set_status(pe_index, "SKIP", 01);
    return;
  }

  for (uint32_t idx = 0; idx < table->num_entries; ++idx) {
    const CXL_COMPONENT_ENTRY *component = &table->component[idx];
    uint32_t dvsec_offset;
    uint32_t status;

    /* Only examine root ports that advertise the RME-CDA DVSEC capability. */
    if (component->role != CXL_COMPONENT_ROLE_ROOT_PORT)
      continue;

    status = val_pcie_find_cda_capability(component->bdf, &dvsec_offset);
    if (status != PCIE_SUCCESS)
      continue;

    tested++;

    status = verify_root_port(table, idx);
    if (status == ACS_STATUS_PASS)
      continue;
    if (status == ACS_STATUS_SKIP)
      skipped++;
    else
      failures++;
  }

  if (tested == 0u) {
    val_print(ACS_PRINT_DEBUG,
              " No root ports with RME-CDA DVSEC - skipping RPHWMM",
              0);
    val_set_status(pe_index, "SKIP", 02);
    return;
  }

  if (failures != 0u) {
    val_set_status(pe_index, "FAIL", failures);
  } else if (skipped == tested) {
    val_set_status(pe_index, "SKIP", 03);
  } else {
    val_set_status(pe_index, "PASS", 01);
  }
}
#else

static void
payload(void)
{
  uint32_t pe_index = val_pe_get_index_mpid(val_pe_get_mpid());

  val_print(ACS_PRINT_WARN,
            " SPDM support disabled - skipping RPHWMM",
            0);
  val_set_status(pe_index, "SKIP", 04);
}
#endif

uint32_t
cxl_rphwmm_rme_cda_tsp_entry(uint32_t num_pe)
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
