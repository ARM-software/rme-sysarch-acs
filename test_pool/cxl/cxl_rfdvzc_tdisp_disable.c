/** @file
 * Copyright (c) 2025-2026, Arm Limited or its affiliates. All rights reserved.
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

#include "val/include/val_el32.h"
#include "val/include/val_pcie.h"
#include "val/include/val_pcie_spec.h"
#include "val/include/val_memory.h"
#include "val/include/val_pcie_enumeration.h"
#include "val/include/val_exerciser.h"
#include "val/include/val_smmu.h"
#include "val/include/val_pe.h"
#include "val/include/val_da.h"
#include "val/include/val_cxl.h"
#include "val/include/val_cxl_spec.h"
#include "val/include/val_spdm.h"

#define TEST_NAME "cxl_rfdvzc_tdisp_disable"
#define TEST_DESC "TDISP disable returns all CXL IDE streams insecure"
#define TEST_RULE "RFDVZC"

static uint32_t
check_link_streams_insecure(uint32_t bdf, uint32_t num_link_streams)
{
  uint32_t status;
  uint32_t state;

  if (num_link_streams == 0u)
    /* Nothing to validate when the port exposes no link streams. */
    return ACS_STATUS_SKIP;

  for (uint32_t link = 0; link < num_link_streams; ++link)
  {
      status = val_get_link_str_status(bdf, link, &state);
      if (status)
      {
          val_print(ACS_PRINT_ERR, " Failed to read Link IDE stream %d", link);
          val_print(ACS_PRINT_ERR, " BDF: 0x%x", bdf);
          return ACS_STATUS_ERR;
      }

      if (state != STREAM_STATE_INSECURE)
      {
          val_print(ACS_PRINT_ERR, " Link IDE stream %d not Insecure", link);
          val_print(ACS_PRINT_ERR, " BDF: 0x%x", bdf);
          return ACS_STATUS_FAIL;
      }
  }

  return ACS_STATUS_PASS;
}

static uint32_t
check_cxl_link_streams_insecure(uint32_t component_index)
{
  uint32_t status;
  uint32_t ide_status;
  uint32_t rx_state;
  uint32_t tx_state;
  uint64_t component_base;

  component_base =
    val_cxl_get_component_info(CXL_COMPONENT_INFO_COMPONENT_BASE, component_index);

  if ((component_base == 0u) ||
      (val_cxl_find_capability(component_base, CXL_CAPID_IDE, NULL) != ACS_STATUS_PASS))
    /* Skip components without the CXL IDE capability. */
    return ACS_STATUS_SKIP;

  status = val_cxl_ide_get_status(component_index, &ide_status);
  if (status != ACS_STATUS_PASS)
    return status;

  rx_state = ide_status & CXL_IDE_STATUS_FIELD_MASK;
  tx_state = (ide_status >> CXL_IDE_STATUS_TX_SHIFT) & CXL_IDE_STATUS_FIELD_MASK;

  if ((rx_state != CXL_IDE_STATE_INSECURE) || (tx_state != CXL_IDE_STATE_INSECURE))
  {
      val_print(ACS_PRINT_ERR, " CXL line IDE RX state 0x%x", rx_state);
      val_print(ACS_PRINT_ERR, " CXL line IDE TX state 0x%x", tx_state);
      val_print(ACS_PRINT_ERR, " Component index %u", component_index);
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
  uint32_t tested_ports;
  uint32_t failure_count;
  uint32_t skipped_role;
  uint32_t skipped_invalid_bdf;
  uint32_t skipped_no_cda;

  pe_index = val_pe_get_index_mpid(val_pe_get_mpid());
  component_count = val_cxl_get_component_info(CXL_COMPONENT_INFO_COUNT, 0);

  if (component_count == 0u)
  {
      val_print(ACS_PRINT_INFO, " No CXL components found", 0);
      val_set_status(pe_index, "SKIP", 01);
      return;
  }

  tested_ports = 0u;
  failure_count = 0u;
  skipped_role = 0u;
  skipped_invalid_bdf = 0u;
  skipped_no_cda = 0u;

  for (uint32_t comp = 0; comp < component_count; ++comp)
  {
      uint32_t role;
      uint32_t bdf;
      uint32_t cda_cap_base;
      uint32_t endpoint_index;
      uint32_t endpoint_bdf;
      uint32_t session_id;
      uint32_t num_sel_str;
      uint32_t num_link_str;
      uint32_t reg_value;
      uint32_t status;
      uint32_t sel_index = 0u;
      uint32_t link_checked = 0u;
      uint32_t session_active = 0u;
      val_spdm_context_t spdm_context;

      role = (uint32_t)val_cxl_get_component_info(CXL_COMPONENT_INFO_ROLE, comp);
      if (role != CXL_COMPONENT_ROLE_ROOT_PORT)
      {
          skipped_role++;
          continue;
      }

      bdf = (uint32_t)val_cxl_get_component_info(CXL_COMPONENT_INFO_BDF_INDEX, comp);
      if (bdf == CXL_COMPONENT_INVALID_INDEX)
      {
          skipped_invalid_bdf++;
          continue;
      }

      if (val_pcie_find_cda_capability(bdf, &cda_cap_base) != PCIE_SUCCESS)
      {
          skipped_no_cda++;
          continue;
      }

      status = val_ide_get_num_sel_str(bdf, &num_sel_str);
      if (status)
      {
          val_print(ACS_PRINT_ERR,
                    " Failed to get number of selective streams for BDF: 0x%x",
                    bdf);
          failure_count++;
          tested_ports = 1u;
          continue;
      }

      status = val_get_num_link_str(bdf, &num_link_str);
      if (status)
      {
          val_print(ACS_PRINT_ERR,
                    " Failed to get number of link streams for BDF: 0x%x",
                    bdf);
          failure_count++;
          tested_ports = 1u;
          continue;
      }

      tested_ports = 1u;

      /* Establish the CXL IDE link before enabling TDISP protection. */
      status = val_cxl_find_downstream_endpoint(comp, &endpoint_index);
      if (status == ACS_STATUS_PASS)
      {
          endpoint_bdf = (uint32_t)val_cxl_get_component_info(
            CXL_COMPONENT_INFO_BDF_INDEX, endpoint_index);
          if (endpoint_bdf != CXL_COMPONENT_INVALID_INDEX)
          {
              status = val_spdm_session_open(endpoint_bdf, &spdm_context, &session_id);
              if (status == ACS_STATUS_SKIP)
              {
                  val_print(ACS_PRINT_WARN,
                            " SPDM session unavailable for endpoint BDF: 0x%x",
                            endpoint_bdf);
              }
              else if (status != ACS_STATUS_PASS)
              {
                  val_print(ACS_PRINT_ERR,
                            " SPDM session open failed for endpoint BDF: 0x%x",
                            endpoint_bdf);
                  failure_count++;
              }
              else
              {
                  session_active = 1u;
                  status = val_cxl_ide_establish_link(comp, endpoint_index,
                                                      &spdm_context, session_id);
                  if (status == ACS_STATUS_SKIP)
                  {
                      val_print(ACS_PRINT_WARN,
                                " IDE link establish skipped for endpoint BDF: 0x%x",
                                endpoint_bdf);
                  }
                  else if (status != ACS_STATUS_PASS)
                  {
                      val_print(ACS_PRINT_ERR,
                                " IDE link establish failed for endpoint BDF: 0x%x",
                                endpoint_bdf);
                      failure_count++;
                  }
              }
          }
      }
      else if (status != ACS_STATUS_SKIP)
      {
          val_print(ACS_PRINT_ERR,
                    " Failed to locate downstream endpoint for BDF: 0x%x",
                    bdf);
          failure_count++;
      }

      while (sel_index++ < num_sel_str)
      {
          /* Program the selective IDE stream before TDISP enforces write protection. */
          status = val_ide_establish_stream(bdf, sel_index, val_generate_stream_id(),
                                            PCIE_CREATE_BDF_PACKED(bdf));
          if (status)
          {
              val_print(ACS_PRINT_ERR,
                        " Failed to establish stream %u",
                        sel_index);
              val_print(ACS_PRINT_ERR, " BDF: 0x%x", bdf);
              failure_count++;
              continue;
          }

          status = val_pcie_enable_tdisp(bdf);
          if (status)
          {
              val_print(ACS_PRINT_ERR,
                        " Unable to enable TDISP for BDF: 0x%x",
                        bdf);
              failure_count++;
              status = val_ide_set_sel_stream(bdf, sel_index, 0);
              if (status)
              {
                  val_print(ACS_PRINT_ERR,
                            " Failed to disable selective stream %u",
                            sel_index);
                  val_print(ACS_PRINT_ERR, " BDF: 0x%x", bdf);
              }
              val_ide_program_rid_base_limit_valid(bdf, sel_index, 0, 0, 0);
              continue;
          }

          status = val_pcie_disable_tdisp(bdf);
          if (status)
          {
              val_print(ACS_PRINT_WARN,
                        " Failed to disable TDISP for BDF: 0x%x",
                        bdf);
              failure_count++;
          }

          if (!link_checked)
          {
              /* Verify the one-time link status after the first disable. */
              uint32_t link_status = check_link_streams_insecure(bdf, num_link_str);
              if ((link_status == ACS_STATUS_FAIL) || (link_status == ACS_STATUS_ERR))
                  failure_count++;

              uint32_t cxl_status = check_cxl_link_streams_insecure(comp);
              if ((cxl_status == ACS_STATUS_FAIL) || (cxl_status == ACS_STATUS_ERR))
                  failure_count++;

              link_checked = 1u;
          }

          status = val_get_sel_str_status(bdf, sel_index, &reg_value);
          if (status)
          {
              val_print(ACS_PRINT_ERR,
                        " Failed to get selective stream state for BDF: 0x%x",
                        bdf);
              failure_count++;
          }
          else if (reg_value != STREAM_STATE_INSECURE)
          {
              val_print(ACS_PRINT_ERR, " Selective stream %u not Insecure", sel_index);
              val_print(ACS_PRINT_ERR, " BDF: 0x%x", bdf);
              failure_count++;
          }

          status = val_ide_set_sel_stream(bdf, sel_index, 0);
          if (status)
          {
              val_print(ACS_PRINT_ERR, " Failed to disable selective stream %u", sel_index);
              val_print(ACS_PRINT_ERR, " BDF: 0x%x", bdf);
              failure_count++;
          }

          /* Drop RID programming so subsequent iterations start from a clean slate. */
          val_ide_program_rid_base_limit_valid(bdf, sel_index, 0, 0, 0);
      }

      (void)val_pcie_disable_tdisp(bdf);
      if (session_active != 0u)
          (void)val_spdm_session_close(&spdm_context, session_id);
  }

  if (!tested_ports)
  {
      val_print(ACS_PRINT_INFO, " No eligible root ports found", 0);
      val_print(ACS_PRINT_INFO, " Components scanned %u", (uint32_t)component_count);
      val_print(ACS_PRINT_INFO, " Skipped non-root %u", skipped_role);
      val_print(ACS_PRINT_INFO, " Skipped invalid BDF %u", skipped_invalid_bdf);
      val_print(ACS_PRINT_INFO, " Skipped no CDA cap %u", skipped_no_cda);
      val_set_status(pe_index, "SKIP", 02);
  }
  else if (failure_count)
      val_set_status(pe_index, "FAIL", failure_count);
  else
      val_set_status(pe_index, "PASS", 01);
}

uint32_t
cxl_rfdvzc_tdisp_disable_entry(uint32_t num_pe)
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
