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

#define TEST_NAME "tdisp_rwfpxr_tdisp_error_allowed"
#define TEST_DESC "Validate device can return TDISP_ERROR for Arm VDM"
#define TEST_RULE "RWFPXR"

static uint32_t
tdisp_rwfpxr_send_malformed_arm_vdm_request(uint32_t bdf,
                                           val_spdm_context_t *spdm_context,
                                           uint32_t session_id,
                                           const pci_tdisp_interface_id_t *interface_id)
{
  uint32_t status;
  uint8_t malformed[VAL_TDISP_ARM_VDM_BASE_SIZE];
  uint8_t response[VAL_TDISP_ARM_VDM_MAX_RSP_SIZE];
  uint32_t response_size;
  uint8_t rsp_msg_type;
  uint32_t offset;

  status = ACS_STATUS_FAIL;
  response_size = (uint32_t)sizeof(response);
  rsp_msg_type = 0;
  offset = 0;

  /* Build a minimal Arm VDM request with an invalid Arm message type. */
  /* This is expected to trigger a PCI_TDISP_ERROR response. */
  val_memory_set(malformed, sizeof(malformed), 0);
  malformed[VAL_TDISP_HDR_VERSION_OFF] = PCI_TDISP_MESSAGE_VERSION;
  malformed[VAL_TDISP_HDR_MSG_TYPE_OFF] = PCI_TDISP_VDM_REQ;
  val_tdisp_write_u16_le(malformed, VAL_TDISP_HDR_RESERVED_OFF, 0);
  val_tdisp_write_u32_le(malformed, VAL_TDISP_HDR_INTERFACE_OFF, interface_id->function_id);
  val_tdisp_write_u64_le(malformed, VAL_TDISP_HDR_INTERFACE_OFF + 4u, interface_id->reserved);

  offset = VAL_TDISP_VDM_HDR_OFF;
  malformed[offset + VAL_TDISP_VDM_HDR_REG_OFF] = VAL_TDISP_ARM_VDM_REGISTRY_ID_PCISIG;
  malformed[offset + VAL_TDISP_VDM_HDR_LEN_OFF] = VAL_TDISP_ARM_VDM_VENDOR_ID_LEN;
  val_tdisp_write_u16_le(malformed,
                         offset + VAL_TDISP_VDM_HDR_VENDOR_OFF,
                         VAL_TDISP_ARM_VDM_VENDOR_ID);

  offset = VAL_TDISP_REQ_RESP_HDR_OFF;
  malformed[offset + VAL_TDISP_REQ_RESP_VER_OFF] = VAL_TDISP_ARM_VDM_VERSION;
  /* Invalid type to trigger a TDISP_ERROR response. */
  malformed[offset + VAL_TDISP_REQ_RESP_TYPE_OFF] = 0xFFu;
  /* Keep the request otherwise well-formed to isolate the invalid type check. */
  val_tdisp_write_u16_le(malformed, offset + VAL_TDISP_REQ_RESP_RSV_OFF, 0);

  status = val_tdisp_vdm_send_raw_request(spdm_context,
                                          session_id,
                                          malformed,
                                          (uint32_t)sizeof(malformed),
                                          response,
                                          &response_size);
  if (status != ACS_STATUS_PASS)
  {
    val_print(ACS_PRINT_ERR, " ARM VDM malformed request send/recv failed 0x%x", bdf);
    return status;
  }

  /* Need at least the TDISP header to read MessageType. */
  if (response_size < VAL_TDISP_HDR_SIZE)
  {
    val_print(ACS_PRINT_ERR, " TDISP response too small for 0x%x", bdf);
    return ACS_STATUS_FAIL;
  }

  rsp_msg_type = response[VAL_TDISP_HDR_MSG_TYPE_OFF];
  /* Expect PCI_TDISP_ERROR for malformed request. */
  if (rsp_msg_type != PCI_TDISP_ERROR)
  {
    /* For a malformed request, any success-path VDM response is unexpected here. */
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
  uint32_t cda_cap_base;
  uint32_t status;
  uint32_t session_id;
  uint32_t test_fail;
  uint32_t test_skip;
  uint32_t session_open;
  uint32_t tdisp_enabled;
  val_spdm_context_t spdm_context;
  pci_tdisp_interface_id_t interface_id;

  pe_index = val_pe_get_index_mpid(val_pe_get_mpid());
  cxl_tbl_ptr = val_cxl_component_table_ptr();
  test_fail = 0;
  test_skip = 1;

  if ((cxl_tbl_ptr == NULL) || (cxl_tbl_ptr->num_entries == 0u))
  {
    val_set_status(pe_index, "SKIP", 01);
    return;
  }

  /* Rule applies only to CHI-C2C root ports (same filtering as existing TDISP tests). */
  for (root_index = 0u; root_index < cxl_tbl_ptr->num_entries; ++root_index)
  {
    root_port = &cxl_tbl_ptr->component[root_index];

    if (root_port->role != CXL_COMPONENT_ROLE_ROOT_PORT)
      continue;
    if (root_port->chi_c2c_supported == 0u)
      continue;

    rp_bdf = root_port->bdf;

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

    /* Use INTERFACE_ID derived from endpoint BDF. */
    interface_id.function_id = (uint32_t)PCIE_CREATE_BDF_PACKED(bdf);
    interface_id.reserved = 0ull;

    status = tdisp_rwfpxr_send_malformed_arm_vdm_request(bdf,
                                                         &spdm_context,
                                                         session_id,
                                                         &interface_id);
    if (status == ACS_STATUS_SKIP)
      goto cleanup;
    if (status != ACS_STATUS_PASS)
      test_fail++;

  cleanup:
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
tdisp_rwfpxr_tdisp_error_allowed_entry(void)
{
  uint32_t num_pe;
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

