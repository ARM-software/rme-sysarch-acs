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
#include "val/include/val_da.h"
#include "val/include/val_pcie.h"
#include "val/include/val_pcie_spec.h"
#include "val/include/val_spdm.h"

#define TEST_NAME "cda_rjzqcp_reset_transition"
#define TEST_DESC "Reset/power transition clears IDE/TSP state             "
#define TEST_RULE "RJZQCP"

static uint32_t
query_tsp_state(uint32_t endpoint_bdf, uint8_t *tsp_state_out)
{
  val_spdm_context_t spdm_context;
  uint32_t session_id = 0u;
  uint32_t status;
  uint8_t tsp_state = 0xFFu;

  if (tsp_state_out == NULL)
    return ACS_STATUS_ERR;

  for (uint32_t attempt = 0; attempt < CXL_TSP_STATE_QUERY_RETRY_COUNT; ++attempt)
  {
    status = val_spdm_session_open(endpoint_bdf, &spdm_context, &session_id);
    if (status == ACS_STATUS_SKIP)
      return ACS_STATUS_SKIP;
    if (status != ACS_STATUS_PASS)
    {
      (void)val_time_delay_ms(CXL_TSP_STATE_QUERY_RETRY_DELAY_MS);
      continue;
    }

    status = val_spdm_send_cxl_tsp_get_configuration(&spdm_context,
                                                     session_id,
                                                     NULL,
                                                     &tsp_state);
    (void)val_spdm_session_close(&spdm_context, session_id);

    if (status == ACS_STATUS_SKIP)
      return ACS_STATUS_SKIP;

    if (status == ACS_STATUS_PASS)
    {
      *tsp_state_out = tsp_state;
      return ACS_STATUS_PASS;
    }

    (void)val_time_delay_ms(CXL_TSP_STATE_QUERY_RETRY_DELAY_MS);
  }

  return ACS_STATUS_ERR;
}

static uint32_t
check_link_streams_insecure(uint32_t rp_bdf, uint32_t num_link_streams)
{
  uint32_t status;
  uint32_t state;

  if (num_link_streams == 0u)
    return ACS_STATUS_SKIP;

  for (uint32_t link = 0; link < num_link_streams; ++link)
  {
    status = val_get_link_str_status(rp_bdf, link, &state);
    if (status)
      return ACS_STATUS_ERR;

    if (state != STREAM_STATE_INSECURE)
      return ACS_STATUS_FAIL;
  }

  return ACS_STATUS_PASS;
}

static
void
payload(void)
{
  uint32_t pe_index;
  uint64_t component_count;
  uint32_t tested;
  uint32_t exercised;
  uint32_t failures;
  uint32_t skipped_role;
  uint32_t skipped_invalid_bdf;
  uint32_t skipped_no_endpoint;
  uint32_t skipped_no_doe;
  uint32_t skipped_no_ide;
  uint32_t skipped_stream_setup;
  uint32_t skipped_lock_setup;
  uint32_t skipped_reset;

  pe_index = val_pe_get_index_mpid(val_pe_get_mpid());
  component_count = val_cxl_get_component_info(CXL_COMPONENT_INFO_COUNT, 0);

  if (component_count == 0u)
  {
    val_print(ACS_PRINT_INFO, " No CXL components found", 0);
    val_set_status(pe_index, "SKIP", 01);
    return;
  }

  tested = 0u;
  exercised = 0u;
  failures = 0u;
  skipped_role = 0u;
  skipped_invalid_bdf = 0u;
  skipped_no_endpoint = 0u;
  skipped_no_doe = 0u;
  skipped_no_ide = 0u;
  skipped_stream_setup = 0u;
  skipped_lock_setup = 0u;
  skipped_reset = 0u;

  for (uint32_t root_index = 0; root_index < component_count; ++root_index)
  {
    uint32_t role;
    uint32_t rp_bdf;
    uint32_t endpoint_index;
    uint32_t endpoint_bdf;
    uint32_t num_link_str;
    uint8_t tsp_state;
    uint32_t reset_status;
    uint32_t status;
    val_spdm_context_t spdm_context;
    uint32_t session_id = 0u;
    const uint32_t requested_ckids = CXL_TSP_REQUESTED_CKIDS_DEFAULT;
    const uint16_t feature_enable_mask = CXL_TSP_MEMORY_ENCRYPTION_FEATURES_ENABLE_MASK_DEFAULT;

    role = (uint32_t)val_cxl_get_component_info(CXL_COMPONENT_INFO_ROLE, root_index);
    if (role != CXL_COMPONENT_ROLE_ROOT_PORT)
    {
      skipped_role++;
      continue;
    }

    rp_bdf = (uint32_t)val_cxl_get_component_info(CXL_COMPONENT_INFO_BDF_INDEX, root_index);
    if (rp_bdf == CXL_COMPONENT_INVALID_INDEX)
    {
      skipped_invalid_bdf++;
      continue;
    }

    status = val_cxl_find_downstream_endpoint(root_index, &endpoint_index);
    if (status != ACS_STATUS_PASS)
    {
      skipped_no_endpoint++;
      continue;
    }

    endpoint_bdf = (uint32_t)val_cxl_get_component_info(CXL_COMPONENT_INFO_BDF_INDEX,
                                                        endpoint_index);
    if (endpoint_bdf == CXL_COMPONENT_INVALID_INDEX)
    {
      skipped_invalid_bdf++;
      continue;
    }

    status = val_get_num_link_str(rp_bdf, &num_link_str);
    if (status || (num_link_str == 0u))
    {
      skipped_no_ide++;
      continue;
    }

    tested = 1u;

    status = val_spdm_session_open(endpoint_bdf, &spdm_context, &session_id);
    if (status != ACS_STATUS_PASS)
    {
      val_print(ACS_PRINT_WARN, " SPDM session unavailable for EP 0x%x", endpoint_bdf);
      if (status == ACS_STATUS_SKIP)
        skipped_no_doe++;
      else
        skipped_stream_setup++;
      continue;
    }

    status = val_cxl_ide_establish_link(root_index,
                                        endpoint_index,
                                        &spdm_context,
                                        session_id);
    if (status != ACS_STATUS_PASS)
    {
      val_print(ACS_PRINT_WARN, " Failed to establish CXL IDE link for RP 0x%x", rp_bdf);
      skipped_stream_setup++;
      (void)val_spdm_session_close(&spdm_context, session_id);
      continue;
    }

    /* Lock the endpoint using CXL TSP. */
    status = val_cxl_tsp_configure_and_lock(root_index,
                                            endpoint_index,
                                            &spdm_context,
                                            session_id,
                                            requested_ckids,
                                            feature_enable_mask);
    (void)val_spdm_session_close(&spdm_context, session_id);
    if (status != ACS_STATUS_PASS)
    {
      val_print(ACS_PRINT_WARN, " Failed to lock TSP for EP 0x%x", endpoint_bdf);
      skipped_lock_setup++;
      continue;
    }

    /* Preserve endpoint BARs and command bits before performing a reset. */
    PCIE_ENDPOINT_CFG endpoint_cfg;
    status = val_pcie_save_endpoint_cfg(endpoint_bdf, &endpoint_cfg);
    if (status != ACS_STATUS_PASS)
    {
      val_print(ACS_PRINT_WARN, " Failed to snapshot endpoint cfg for EP 0x%x", endpoint_bdf);
      skipped_reset++;
      continue;
    }

    /* Trigger a reset/power transition (prefer FLR, fallback to Secondary Bus Reset). */
    reset_status = val_pcie_reset_endpoint(rp_bdf, endpoint_bdf);
    if (reset_status != ACS_STATUS_PASS)
    {
      if (reset_status == ACS_STATUS_FAIL)
      {
        val_print(ACS_PRINT_ERR, " EP not present after reset, BDF 0x%x", endpoint_bdf);
        failures++;
      }
      else
      {
        val_print(ACS_PRINT_WARN, " Failed to trigger reset for EP 0x%x", endpoint_bdf);
        skipped_reset++;
      }
      continue;
    }

    val_pcie_restore_endpoint_cfg(endpoint_bdf, &endpoint_cfg);

    exercised++;

    /* RJZQCP: IDE stream(s) transition to Insecure. */
    status = check_link_streams_insecure(rp_bdf, num_link_str);
    if ((status == ACS_STATUS_FAIL) || (status == ACS_STATUS_ERR))
    {
      val_print(ACS_PRINT_ERR, " Link IDE streams not Insecure for RP 0x%x", rp_bdf);
      failures++;
    }

    /* RJZQCP: TSP instance is not CONFIG_LOCKED (allowed: ERROR or CONFIG_UNLOCKED). */
    status = query_tsp_state(endpoint_bdf, &tsp_state);
    if (status != ACS_STATUS_PASS)
    {
      val_print(ACS_PRINT_ERR, " Failed to query TSP state for EP 0x%x", endpoint_bdf);
      failures++;
      continue;
    }

    if ((tsp_state != CXL_TSP_STATE_ERROR) &&
        (tsp_state != CXL_TSP_STATE_CONFIG_UNLOCKED))
    {
      val_print(ACS_PRINT_ERR, " Post-reset TSP state unexpected for EP 0x%x", endpoint_bdf);
      val_print(ACS_PRINT_ERR, " TSP state 0x%x", tsp_state);
      failures++;
    }
  }

  if (!tested || (exercised == 0u))
  {
    val_print(ACS_PRINT_INFO, " No eligible RJZQCP targets exercised", 0);
    val_print(ACS_PRINT_INFO, " Components scanned %u", (uint32_t)component_count);
    val_print(ACS_PRINT_INFO, " Skipped non-root %u", skipped_role);
    val_print(ACS_PRINT_INFO, " Skipped invalid BDF %u", skipped_invalid_bdf);
    val_print(ACS_PRINT_INFO, " Skipped no endpoint %u", skipped_no_endpoint);
    val_print(ACS_PRINT_INFO, " Skipped no DOE/SPDM %u", skipped_no_doe);
    val_print(ACS_PRINT_INFO, " Skipped no IDE %u", skipped_no_ide);
    val_print(ACS_PRINT_INFO, " Skipped stream setup %u", skipped_stream_setup);
    val_print(ACS_PRINT_INFO, " Skipped TSP config/lock %u", skipped_lock_setup);
    val_print(ACS_PRINT_INFO, " Skipped reset trigger %u", skipped_reset);
    val_set_status(pe_index, "SKIP", 01);
  } else if (failures)
    val_set_status(pe_index, "FAIL", failures);
  else
    val_set_status(pe_index, "PASS", 01);
}

uint32_t
cda_rjzqcp_reset_transition_entry(uint32_t num_pe)
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
