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
#include "val/include/val_pcie.h"
#include "val/include/val_spdm.h"
#include "val/include/val_tdisp.h"
#include "val/include/val_cxl.h"

#define TEST_NAME "tdisp_rpxlfy_get_version_req"
#define TEST_DESC "Validate GET_VERSION_REQ semantics"
#define TEST_RULE "RPXLFY"

static uint32_t
tdisp_rpxlfy_validate_get_version_success_rsp(uint32_t bdf,
                                              const uint8_t *response,
                                              uint32_t response_size)
{
  uint8_t rsp_msg_type;
  uint8_t rsp_reg_id;
  uint8_t rsp_vendor_len;
  uint16_t rsp_vendor_id;
  uint8_t rsp_arm_type;
  uint32_t offset;

  rsp_msg_type = 0;
  rsp_reg_id = 0;
  rsp_vendor_len = 0;
  rsp_vendor_id = 0;
  rsp_arm_type = 0;
  offset = 0;

  /* Validate the response envelope and that the Arm message is GET_VERSION_RESP. */
  if (response_size < VAL_TDISP_ARM_VDM_BASE_SIZE)
  {
    val_print(ACS_PRINT_ERR, " TDISP response too small for 0x%x", bdf);
    return ACS_STATUS_FAIL;
  }

  rsp_msg_type = response[VAL_TDISP_HDR_MSG_TYPE_OFF];
  if (rsp_msg_type != PCI_TDISP_VDM_RSP)
  {
    val_print(ACS_PRINT_ERR, " Expected VDM_RSP for 0x%x", bdf);
    return ACS_STATUS_FAIL;
  }

  /* Validate Arm VDM header (registry id, vendor id length, Arm vendor id). */
  offset = VAL_TDISP_VDM_HDR_OFF;
  rsp_reg_id = response[offset + VAL_TDISP_VDM_HDR_REG_OFF];
  rsp_vendor_len = response[offset + VAL_TDISP_VDM_HDR_LEN_OFF];
  rsp_vendor_id =
    (uint16_t)response[offset + VAL_TDISP_VDM_HDR_VENDOR_OFF] |
    ((uint16_t)response[offset + VAL_TDISP_VDM_HDR_VENDOR_OFF + 1u] << 8);

  if ((rsp_reg_id != VAL_TDISP_ARM_VDM_REGISTRY_ID_PCISIG) ||
      (rsp_vendor_len != VAL_TDISP_ARM_VDM_VENDOR_ID_LEN) ||
      (rsp_vendor_id != VAL_TDISP_ARM_VDM_VENDOR_ID))
  {
    val_print(ACS_PRINT_ERR, " ARM VDM header mismatch for 0x%x", bdf);
    return ACS_STATUS_FAIL;
  }

  /* Validate the Arm message type within the VDM payload. */
  offset = VAL_TDISP_REQ_RESP_HDR_OFF;
  rsp_arm_type = response[offset + VAL_TDISP_REQ_RESP_TYPE_OFF];
  if (rsp_arm_type != VAL_TDISP_ARM_MSG_GET_VERSION_RESP)
  {
    val_print(ACS_PRINT_ERR, " GET_VERSION_RESP type mismatch for 0x%x", bdf);
    return ACS_STATUS_FAIL;
  }

  return ACS_STATUS_PASS;
}

static uint32_t
tdisp_rpxlfy_send_get_version_with_interface_id(uint32_t bdf,
                                                val_spdm_context_t *spdm_context,
                                                uint32_t session_id,
                                                const pci_tdisp_interface_id_t *interface_id)
{
  uint32_t status;
  uint8_t response[VAL_TDISP_ARM_VDM_MAX_RSP_SIZE];
  uint32_t response_size;

  status = ACS_STATUS_FAIL;
  response_size = (uint32_t)sizeof(response);

  /* Send Arm VDM GET_VERSION over SPDM and validate we get a success response. */
  status = val_tdisp_vdm_get_version(spdm_context,
                                     session_id,
                                     interface_id,
                                     response,
                                     &response_size);
  if (status != ACS_STATUS_PASS)
    return status;

  return tdisp_rpxlfy_validate_get_version_success_rsp(bdf, response, response_size);
}

static
void
payload(void)
{
  uint32_t pe_index;
  CXL_COMPONENT_TABLE *cxl_tbl_ptr;
  const CXL_COMPONENT_ENTRY *root_port;
  const CXL_COMPONENT_ENTRY *endpoint;
  uint32_t root_index;
  uint32_t endpoint_index;
  uint32_t bdf;
  uint32_t rp_bdf;
  uint32_t cda_cap_base;
  uint32_t status;
  uint32_t session_id;
  uint32_t test_fail;
  uint32_t test_skip;
  uint32_t session_open;
  uint32_t tdisp_enabled;
  val_spdm_context_t spdm_context;
  pci_tdisp_interface_id_t interface_id_valid;
  pci_tdisp_interface_id_t interface_id_ignored;

  pe_index = val_pe_get_index_mpid(val_pe_get_mpid());
  cxl_tbl_ptr = val_cxl_component_table_ptr();
  test_fail = 0;
  test_skip = 1;

  if ((cxl_tbl_ptr == NULL) || (cxl_tbl_ptr->num_entries == 0u))
  {
    val_set_status(pe_index, "SKIP", 01);
    return;
  }

  /* Rule applies only to CHI-C2C root ports (same filtering as existing TDISP test). */
  for (root_index = 0u; root_index < cxl_tbl_ptr->num_entries; ++root_index)
  {
    root_port = &cxl_tbl_ptr->component[root_index];

    if (root_port->role != CXL_COMPONENT_ROLE_ROOT_PORT)
      continue;
    if (root_port->chi_c2c_supported == 0u)
      continue;

    rp_bdf = root_port->bdf;

    /* Identify a downstream endpoint to target for SPDM + TDISP VDM requests. */
    endpoint_index = CXL_COMPONENT_INVALID_INDEX;
    status = val_cxl_find_downstream_endpoint(root_index, &endpoint_index);
    if (status != ACS_STATUS_PASS)
      continue;

    endpoint = &cxl_tbl_ptr->component[endpoint_index];
    bdf = endpoint->bdf;
    if (bdf == CXL_COMPONENT_INVALID_INDEX)
      continue;

    if (val_pcie_find_cda_capability(rp_bdf, &cda_cap_base) != PCIE_SUCCESS)
      continue;

    tdisp_enabled = 0;
    session_open = 0;

    /* TDISP enable is controlled on the root port (RME-CDA DVSEC). */
    if (val_pcie_enable_tdisp(rp_bdf))
    {
      val_print(ACS_PRINT_ERR, " Failed to enable TDISP for RP 0x%x", rp_bdf);
      test_fail++;
      continue;
    }
    tdisp_enabled = 1;

    /* VDM messages are tunneled over SPDM; open a session to the endpoint. */
    status = val_spdm_session_open(bdf, &spdm_context, &session_id);
    if (status == ACS_STATUS_SKIP)
      goto cleanup;
    if (status != ACS_STATUS_PASS)
    {
      test_fail++;
      goto cleanup;
    }
    session_open = 1;
    test_skip = 0;

    /* Use a "valid-looking" INTERFACE_ID derived from the endpoint BDF. */
    interface_id_valid.function_id = (uint32_t)PCIE_CREATE_BDF_PACKED(bdf);
    interface_id_valid.reserved = 0ull;

    /* Use a benign alternate INTERFACE_ID (rule requires the field be ignored). */
    interface_id_ignored.function_id = 0u;
    interface_id_ignored.reserved = 0ull;

    /* Baseline: confirm the device accepts GET_VERSION with a valid interface id. */
    status = tdisp_rpxlfy_send_get_version_with_interface_id(bdf,
                                                             &spdm_context,
                                                             session_id,
                                                             &interface_id_valid);
    if (status == ACS_STATUS_SKIP)
      goto cleanup;
    if (status != ACS_STATUS_PASS)
    {
      test_fail++;
      goto cleanup;
    }

    /*
     * Rule RPXLFY: GET_VERSION_REQ does not apply to a specific INTERFACE_ID and
     * the field is ignored by the device. Verify the request still succeeds when
     * INTERFACE_ID is changed to a benign alternate value.
     */
    status = tdisp_rpxlfy_send_get_version_with_interface_id(bdf,
                                                             &spdm_context,
                                                             session_id,
                                                             &interface_id_ignored);
    if (status == ACS_STATUS_SKIP)
      goto cleanup;
    if (status != ACS_STATUS_PASS)
      test_fail++;

  cleanup:
    /* Always close session and disable TDISP before moving to next root port. */
    if (session_open)
      (void)val_spdm_session_close(&spdm_context, session_id);
    if (tdisp_enabled)
      val_pcie_disable_tdisp(rp_bdf);
  }

  if (test_skip)
    val_set_status(pe_index, "SKIP", 01);
  else if (test_fail)
    val_set_status(pe_index, "FAIL", 01);
  else
    val_set_status(pe_index, "PASS", 01);
}

uint32_t
tdisp_rpxlfy_get_version_req_entry(uint32_t num_pe)
{
  uint32_t status;

  num_pe = 1;
  status = ACS_STATUS_FAIL;

  status = val_initialize_test(TEST_NAME, TEST_DESC, num_pe, TEST_RULE);

  if (status != ACS_STATUS_SKIP)
    val_run_test_payload(num_pe, payload, 0);

  status = val_check_for_error(num_pe);
  val_report_status(0, "END");

  return status;
}
