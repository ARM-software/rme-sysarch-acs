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
#include "val/include/val_pcie_enumeration.h"
#include "val/include/val_spdm.h"
#include "val/include/val_tdisp.h"
#include "val/include/val_cxl.h"

#define TEST_NAME "tdisp_rfpymv_vdm_response_check"
#define TEST_DESC "Validate Arm VDM responses and errors"
#define TEST_RULE "RFPYMV"

/* Validate the common fields in an Arm VDM success response. */
static uint32_t
tdisp_rfpymv_validate_vdm_success_rsp(uint32_t bdf,
                                     const uint8_t *response,
                                     uint32_t response_size,
                                     uint8_t expected_arm_type)
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

  /* Need at least the TDISP header to read MessageType. */
  if (response_size < VAL_TDISP_HDR_SIZE)
  {
    val_print(ACS_PRINT_ERR, " TDISP response too small for 0x%x", bdf);
    return ACS_STATUS_FAIL;
  }

  /* For these success-path checks, TDISP_ERROR is unexpected. */
  rsp_msg_type = response[VAL_TDISP_HDR_MSG_TYPE_OFF];
  if (rsp_msg_type == PCI_TDISP_ERROR)
  {
    val_print(ACS_PRINT_ERR, " Unexpected TDISP_ERROR for 0x%x", bdf);
    return ACS_STATUS_FAIL;
  }

  /* Arm VDM responses must use TDISP VDM response MessageType. */
  if (rsp_msg_type != PCI_TDISP_VDM_RSP)
  {
    val_print(ACS_PRINT_ERR, " ARM VDM response type mismatch for 0x%x", bdf);
    return ACS_STATUS_FAIL;
  }

  /* Must include Arm VDM header + request/response header. */
  if (response_size < VAL_TDISP_ARM_VDM_BASE_SIZE)
  {
    val_print(ACS_PRINT_ERR, " ARM VDM response too small for 0x%x", bdf);
    return ACS_STATUS_FAIL;
  }

  /* Validate the Arm VDM header (registry id + vendor id fields). */
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

  /* Validate the Arm message type in the request/response header. */
  offset = VAL_TDISP_REQ_RESP_HDR_OFF;
  rsp_arm_type = response[offset + VAL_TDISP_REQ_RESP_TYPE_OFF];
  if (rsp_arm_type != expected_arm_type)
  {
    val_print(ACS_PRINT_ERR, " ARM VDM msg type mismatch for 0x%x", bdf);
    return ACS_STATUS_FAIL;
  }

  return ACS_STATUS_PASS;
}

/* Send Arm VDM GET_VERSION and validate the success response framing. */
static uint32_t
tdisp_rfpymv_do_get_version(uint32_t bdf,
                            val_spdm_context_t *spdm_context,
                            uint32_t session_id,
                            const pci_tdisp_interface_id_t *interface_id,
                            uint8_t *response,
                            uint32_t response_buf_size,
                            uint32_t *response_size)
{
  uint32_t status;

  status = ACS_STATUS_FAIL;
  /* Response is bounded by caller-provided buffer size. */
  *response_size = response_buf_size;

  /* Arm VDM GET_VERSION request. */
  status = val_tdisp_vdm_get_version(spdm_context,
                                     session_id,
                                     interface_id,
                                     response,
                                     response_size);
  if (status != ACS_STATUS_PASS)
  {
    val_print(ACS_PRINT_ERR, " ARM VDM GET_VERSION failed for 0x%x", bdf);
    return status;
  }

  /* Common Arm VDM response checks + expected message type. */
  return tdisp_rfpymv_validate_vdm_success_rsp(
    bdf,
    response,
    *response_size,
    VAL_TDISP_ARM_MSG_GET_VERSION_RESP);
}

/* Send Arm VDM GET_DEV_PROP and validate the success response framing. */
static uint32_t
tdisp_rfpymv_do_get_dev_prop(uint32_t bdf,
                             val_spdm_context_t *spdm_context,
                             uint32_t session_id,
                             const pci_tdisp_interface_id_t *interface_id,
                             uint8_t *response,
                             uint32_t response_buf_size,
                             uint32_t *response_size)
{
  uint32_t status;

  status = ACS_STATUS_FAIL;
  /* Response is bounded by caller-provided buffer size. */
  *response_size = response_buf_size;

  /* Arm VDM GET_DEV_PROP request. */
  status = val_tdisp_vdm_get_dev_prop(spdm_context,
                                      session_id,
                                      interface_id,
                                      response,
                                      response_size);
  if (status != ACS_STATUS_PASS)
  {
    val_print(ACS_PRINT_ERR, " ARM VDM GET_DEV_PROP failed for 0x%x", bdf);
    return status;
  }

  /* Common Arm VDM response checks + expected message type. */
  return tdisp_rfpymv_validate_vdm_success_rsp(
    bdf,
    response,
    *response_size,
    VAL_TDISP_ARM_MSG_GET_DEV_PROP_RESP);
}

/*
 * SET_INTERFACE is only meaningful when the device reports CONFIG_UNLOCKED.
 * If GET_INTERFACE_STATE isn't supported or reports a different state, skip
 * SET_INTERFACE without failing this rule.
 */
static uint32_t
tdisp_rfpymv_set_interface_if_config_unlocked(
  uint32_t bdf,
  val_spdm_context_t *spdm_context,
  uint32_t session_id,
  const pci_tdisp_interface_id_t *interface_id,
  uint8_t *response,
  uint32_t response_buf_size,
  uint32_t *response_size)
{
  uint32_t status;
  uint8_t tdi_state;
  uint16_t pmecid;

  status = ACS_STATUS_FAIL;
  tdi_state = 0;
  pmecid = 0;

  status = val_tdisp_get_interface_state(spdm_context,
                                         session_id,
                                         interface_id,
                                         &tdi_state);
  /* If the interface state isn't available, don't fail this test. */
  if (status != ACS_STATUS_PASS)
    return ACS_STATUS_PASS;

  /* Only send SET_INTERFACE when the device is in CONFIG_UNLOCKED. */
  if (tdi_state != PCI_TDISP_INTERFACE_STATE_CONFIG_UNLOCKED)
    return ACS_STATUS_PASS;

  *response_size = response_buf_size;
  /* pmecid=0: this test validates VDM framing; it does not bind to a MEC. */
  status = val_tdisp_vdm_set_interface(spdm_context,
                                       session_id,
                                       interface_id,
                                       pmecid,
                                       response,
                                       response_size);
  if (status != ACS_STATUS_PASS)
  {
    val_print(ACS_PRINT_ERR, " ARM VDM SET_INTERFACE failed for 0x%x", bdf);
    return status;
  }

  return tdisp_rfpymv_validate_vdm_success_rsp(
    bdf,
    response,
    *response_size,
    VAL_TDISP_ARM_MSG_SET_INTERFACE_RESP);
}

/* Send a malformed Arm VDM request and expect a TDISP_ERROR response. */
static uint32_t
tdisp_rfpymv_do_malformed_request_expect_error(
  uint32_t bdf,
  val_spdm_context_t *spdm_context,
  uint32_t session_id,
  const pci_tdisp_interface_id_t *interface_id,
  uint8_t *response,
  uint32_t response_buf_size,
  uint32_t *response_size)
{
  uint32_t status;
  uint8_t malformed[VAL_TDISP_ARM_VDM_BASE_SIZE];
  uint8_t rsp_msg_type;
  uint32_t offset;

  status = ACS_STATUS_FAIL;
  rsp_msg_type = 0;
  offset = 0;

  /* Build a minimal Arm VDM request with an invalid Arm message type. */
  val_memory_set(malformed, sizeof(malformed), 0);
  malformed[VAL_TDISP_HDR_VERSION_OFF] = PCI_TDISP_MESSAGE_VERSION;
  malformed[VAL_TDISP_HDR_MSG_TYPE_OFF] = PCI_TDISP_VDM_REQ;
  val_tdisp_write_u16_le(malformed, VAL_TDISP_HDR_RESERVED_OFF, 0);
  val_tdisp_write_u32_le(malformed, VAL_TDISP_HDR_INTERFACE_OFF,
                         interface_id->function_id);
  val_tdisp_write_u64_le(malformed, VAL_TDISP_HDR_INTERFACE_OFF + 4u,
                         interface_id->reserved);

  offset = VAL_TDISP_VDM_HDR_OFF;
  malformed[offset + VAL_TDISP_VDM_HDR_REG_OFF] =
    VAL_TDISP_ARM_VDM_REGISTRY_ID_PCISIG;
  malformed[offset + VAL_TDISP_VDM_HDR_LEN_OFF] =
    VAL_TDISP_ARM_VDM_VENDOR_ID_LEN;
  val_tdisp_write_u16_le(malformed,
                         offset + VAL_TDISP_VDM_HDR_VENDOR_OFF,
                         VAL_TDISP_ARM_VDM_VENDOR_ID);

  offset = VAL_TDISP_REQ_RESP_HDR_OFF;
  malformed[offset + VAL_TDISP_REQ_RESP_VER_OFF] = VAL_TDISP_ARM_VDM_VERSION;
  /* Invalid type to trigger a TDISP_ERROR response. */
  malformed[offset + VAL_TDISP_REQ_RESP_TYPE_OFF] = 0xFFu;
  val_tdisp_write_u16_le(malformed,
                         offset + VAL_TDISP_REQ_RESP_RSV_OFF,
                         0);

  /* Send raw request and expect the device to reject it. */
  *response_size = response_buf_size;
  status = val_tdisp_vdm_send_raw_request(spdm_context,
                                          session_id,
                                          malformed,
                                          (uint32_t)sizeof(malformed),
                                          response,
                                          response_size);
  if (status != ACS_STATUS_PASS)
  {
    val_print(ACS_PRINT_ERR, " ARM VDM malformed request failed 0x%x", bdf);
    return status;
  }

  /* Need at least the TDISP header to read MessageType. */
  if (*response_size < VAL_TDISP_HDR_SIZE)
  {
    val_print(ACS_PRINT_ERR, " TDISP response too small for 0x%x", bdf);
    return ACS_STATUS_FAIL;
  }

  /* For this negative test, the expected response is TDISP_ERROR. */
  rsp_msg_type = response[VAL_TDISP_HDR_MSG_TYPE_OFF];
  if (rsp_msg_type != PCI_TDISP_ERROR)
  {
    val_print(ACS_PRINT_ERR, " Expected TDISP_ERROR for 0x%x", bdf);
    return ACS_STATUS_FAIL;
  }

  return ACS_STATUS_PASS;
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
  uint32_t tdisp_enabled;
  uint32_t cda_cap_base;
  uint32_t status;
  uint32_t session_id;
  uint32_t test_fail;
  uint32_t test_skip;
  uint32_t session_open;
  uint8_t response[VAL_TDISP_ARM_VDM_MAX_RSP_SIZE];
  uint32_t response_size;
  val_spdm_context_t spdm_context;
  pci_tdisp_interface_id_t interface_id;
  uint32_t vdm_status;

  pe_index = val_pe_get_index_mpid(val_pe_get_mpid());
  cxl_tbl_ptr = val_cxl_component_table_ptr();
  test_fail = 0;
  test_skip = 1;
  vdm_status = ACS_STATUS_FAIL;

  if ((cxl_tbl_ptr == NULL) || (cxl_tbl_ptr->num_entries == 0u))
  {
    val_print(ACS_PRINT_DEBUG, " No component table entries", 0);
    val_set_status(pe_index, "SKIP", 01);
    return;
  }

  for (root_index = 0u; root_index < cxl_tbl_ptr->num_entries; ++root_index)
  {
    root_port = &cxl_tbl_ptr->component[root_index];

    /*
     * Per review feedback, scope TDISP VDM checks to CHI-C2C-capable root ports.
     * The component table entry's BDF is the root port BDF.
     */
    if (root_port->role != CXL_COMPONENT_ROLE_ROOT_PORT)
      continue;
    if (root_port->chi_c2c_supported == 0u)
      continue;

    rp_bdf = root_port->bdf;
    val_print(ACS_PRINT_TEST, " Checking RP BDF: 0x%x", rp_bdf);

    endpoint_index = CXL_COMPONENT_INVALID_INDEX;
    status = val_cxl_find_downstream_endpoint(root_index, &endpoint_index);
    if (status != ACS_STATUS_PASS)
    {
      val_print(ACS_PRINT_DEBUG, " No downstream EP for RP 0x%x", rp_bdf);
      continue;
    }

    endpoint = &cxl_tbl_ptr->component[endpoint_index];
    bdf = endpoint->bdf;
    if (bdf == CXL_COMPONENT_INVALID_INDEX)
    {
      val_print(ACS_PRINT_DEBUG, " Invalid EP BDF for RP 0x%x", rp_bdf);
      continue;
    }

    val_print(ACS_PRINT_TEST, " Checking EP BDF: 0x%x", bdf);

    /* Skip if RP does not implement RMECDA (no TDISP enable path). */
    if (val_pcie_find_cda_capability(rp_bdf, &cda_cap_base) != PCIE_SUCCESS)
    {
      val_print(ACS_PRINT_DEBUG, " CDA cap not found for RP 0x%x", rp_bdf);
      continue;
    }

    tdisp_enabled = 0;
    session_open = 0;

    /* Enable TDISP on the RP before starting SPDM/TDISP exchanges with the EP. */
    if (val_pcie_enable_tdisp(rp_bdf))
    {
      val_print(ACS_PRINT_ERR, " Failed to enable TDISP for RP 0x%x", rp_bdf);
      test_fail++;
      continue;
    }
    tdisp_enabled = 1;

    /* Open SPDM session to the endpoint to carry TDISP VDM messages. */
    status = val_spdm_session_open(bdf, &spdm_context, &session_id);
    if (status == ACS_STATUS_SKIP)
    {
      val_print(ACS_PRINT_WARN, " SPDM session not available for 0x%x", bdf);
      goto cleanup;
    }
    if (status != ACS_STATUS_PASS)
    {
      val_print(ACS_PRINT_ERR, " SPDM session open failed for 0x%x", bdf);
      test_fail++;
      goto cleanup;
    }
    session_open = 1;
    test_skip = 0;

    /* Use EP BDF as InterfaceId FunctionId for the Arm VDM payload. */
    interface_id.function_id = (uint32_t)PCIE_CREATE_BDF_PACKED(bdf);
    interface_id.reserved = 0ull;

    /* Arm VDM: GET_VERSION (validate success response). */
    vdm_status = tdisp_rfpymv_do_get_version(bdf,
                                             &spdm_context,
                                             session_id,
                                             &interface_id,
                                             response,
                                             (uint32_t)sizeof(response),
                                             &response_size);
    if (vdm_status != ACS_STATUS_PASS)
    {
      test_fail++;
      goto cleanup;
    }

    /* Arm VDM: GET_DEV_PROP (validate success response). */
    vdm_status = tdisp_rfpymv_do_get_dev_prop(bdf,
                                              &spdm_context,
                                              session_id,
                                              &interface_id,
                                              response,
                                              (uint32_t)sizeof(response),
                                              &response_size);
    if (vdm_status != ACS_STATUS_PASS)
    {
      test_fail++;
      goto cleanup;
    }

    /* If CONFIG_UNLOCKED, send SET_INTERFACE (depends on GET_INTERFACE_STATE). */
    vdm_status = tdisp_rfpymv_set_interface_if_config_unlocked(bdf,
                                                               &spdm_context,
                                                               session_id,
                                                               &interface_id,
                                                               response,
                                                               (uint32_t)sizeof(response),
                                                               &response_size);
    if (vdm_status != ACS_STATUS_PASS)
    {
      test_fail++;
      goto cleanup;
    }

    /* Arm VDM negative: malformed request must return TDISP_ERROR. */
    vdm_status = tdisp_rfpymv_do_malformed_request_expect_error(bdf,
                                                                &spdm_context,
                                                                session_id,
                                                                &interface_id,
                                                                response,
                                                                (uint32_t)sizeof(response),
                                                                &response_size);
    if (vdm_status != ACS_STATUS_PASS)
      test_fail++;

cleanup:
    /* Cleanup: close SPDM session (if open) and disable TDISP on the RP. */
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
tdisp_rfpymv_vdm_response_check_entry(uint32_t num_pe)
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
