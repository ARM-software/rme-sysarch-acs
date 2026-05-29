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

#define TEST_NAME "tdisp_rxdkdt_set_interface_req_semantics"
#define TEST_DESC "Validate SET_INTERFACE_REQ applies to INTERFACE_ID"
#define TEST_RULE "RXDKDT"

static uint32_t
tdisp_rxdkdt_read_u32_le(const uint8_t *buf, uint32_t offset)
{
  uint32_t v;

  v = 0;
  v |= (uint32_t)buf[offset + 0u];
  v |= (uint32_t)buf[offset + 1u] << 8;
  v |= (uint32_t)buf[offset + 2u] << 16;
  v |= (uint32_t)buf[offset + 3u] << 24;

  return v;
}

/*
 * Query GET_DEV_PROP and pick a benign PMECID value for SET_INTERFACE.
 *
 * Note: This test does not validate PMECID enforcement; PMECID is set to 0
 * to keep the request within any advertised MECID width.
 */
static uint32_t
tdisp_rxdkdt_get_pmecid_for_device(uint32_t bdf,
                                  val_spdm_context_t *spdm_context,
                                  uint32_t session_id,
                                  const pci_tdisp_interface_id_t *interface_id,
                                  uint16_t *pmecid)
{
  uint32_t status;
  uint8_t response[VAL_TDISP_ARM_VDM_MAX_RSP_SIZE];
  uint32_t response_size;
  uint32_t properties;
  uint32_t mec_supported;
  uint32_t mecid_bitwidth;

  status = ACS_STATUS_FAIL;
  response_size = (uint32_t)sizeof(response);
  properties = 0;
  mec_supported = 0;
  mecid_bitwidth = 0;

  /*
   * Query GET_DEV_PROP_RESP first so we know whether MEC is supported and what
   * MECID width the device advertises. This test currently focuses on the
   * INTERFACE_ID semantics of SET_INTERFACE, not on validating MECID handling.
   *
   * On some platforms/models, the device may not expose externally observable
   * behavior tied to PMECID, so we conservatively use PMECID=0 (always within
   * any advertised MECID width) and call this out explicitly.
   */
  status = val_tdisp_vdm_get_dev_prop(spdm_context,
                                      session_id,
                                      interface_id,
                                      response,
                                      &response_size);
  if (status != ACS_STATUS_PASS)
  {
    val_print(ACS_PRINT_WARN, " GET_DEV_PROP failed; using PMECID=0 for 0x%x", bdf);
    *pmecid = 0;
    return ACS_STATUS_PASS;
  }

  if (response_size < (VAL_TDISP_ARM_VDM_BASE_SIZE + 4u))
  {
    val_print(ACS_PRINT_WARN, " GET_DEV_PROP_RESP too small; using PMECID=0 for 0x%x", bdf);
    *pmecid = 0;
    return ACS_STATUS_PASS;
  }

  if (response[VAL_TDISP_HDR_MSG_TYPE_OFF] != PCI_TDISP_VDM_RSP)
  {
    val_print(ACS_PRINT_WARN, " GET_DEV_PROP not VDM_RSP; using PMECID=0 for 0x%x", bdf);
    *pmecid = 0;
    return ACS_STATUS_PASS;
  }

  if (response[VAL_TDISP_REQ_RESP_HDR_OFF + VAL_TDISP_REQ_RESP_TYPE_OFF] !=
      VAL_TDISP_ARM_MSG_GET_DEV_PROP_RESP)
  {
    val_print(ACS_PRINT_WARN, " GET_DEV_PROP_RESP type mismatch; using PMECID=0 for 0x%x", bdf);
    *pmecid = 0;
    return ACS_STATUS_PASS;
  }

  /* GET_DEV_PROP_RESP encodes PROPERTIES as little-endian DWORD. */
  properties = tdisp_rxdkdt_read_u32_le(response, VAL_TDISP_ARM_VDM_BASE_SIZE);
  mec_supported = (properties & VAL_TDISP_DEV_PROP_MEC) ? 1u : 0u;
  mecid_bitwidth = (properties & VAL_TDISP_DEV_PROP_MECID_MASK) >>
                   VAL_TDISP_DEV_PROP_MECID_SHIFT;

  if (!mec_supported)
  {
    val_print(ACS_PRINT_INFO, " MEC not supported; using PMECID=0 for 0x%x", bdf);
    *pmecid = 0;
    return ACS_STATUS_PASS;
  }

  if (mecid_bitwidth == 0u)
  {
    val_print(ACS_PRINT_WARN, " MECID width 0; using PMECID=0 for 0x%x", bdf);
    *pmecid = 0;
    return ACS_STATUS_PASS;
  }

  val_print(ACS_PRINT_INFO, " MEC supported; MECID width=%d", mecid_bitwidth);
  val_print(ACS_PRINT_INFO, " Using PMECID=0 for 0x%x", bdf);
  *pmecid = 0;
  return ACS_STATUS_PASS;
}

static uint32_t
tdisp_rxdkdt_validate_set_interface_success_rsp(uint32_t bdf,
                                                const uint8_t *response,
                                                uint32_t response_size)
{
  /* Validate the response envelope and that the Arm message is SET_INTERFACE_RESP. */
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

  /* Need at least the Arm VDM header + request/response header. */
  if (response_size < VAL_TDISP_ARM_VDM_BASE_SIZE)
  {
    val_print(ACS_PRINT_WARN, " SET_INTERFACE_RESP too small for 0x%x", bdf);
    return ACS_STATUS_FAIL;
  }

  rsp_msg_type = response[VAL_TDISP_HDR_MSG_TYPE_OFF];
  /* SET_INTERFACE success-path responses must use VDM_RSP MessageType. */
  if (rsp_msg_type != PCI_TDISP_VDM_RSP)
    return ACS_STATUS_FAIL;

  offset = VAL_TDISP_VDM_HDR_OFF;
  /* Validate Arm VDM header (registry id, vendor id length, Arm vendor id). */
  rsp_reg_id = response[offset + VAL_TDISP_VDM_HDR_REG_OFF];
  rsp_vendor_len = response[offset + VAL_TDISP_VDM_HDR_LEN_OFF];
  rsp_vendor_id =
    (uint16_t)response[offset + VAL_TDISP_VDM_HDR_VENDOR_OFF] |
    ((uint16_t)response[offset + VAL_TDISP_VDM_HDR_VENDOR_OFF + 1u] << 8);

  if ((rsp_reg_id != VAL_TDISP_ARM_VDM_REGISTRY_ID_PCISIG) ||
      (rsp_vendor_len != VAL_TDISP_ARM_VDM_VENDOR_ID_LEN) ||
      (rsp_vendor_id != VAL_TDISP_ARM_VDM_VENDOR_ID))
  {
    return ACS_STATUS_FAIL;
  }

  offset = VAL_TDISP_REQ_RESP_HDR_OFF;
  /* Validate the Arm message type within the VDM payload. */
  rsp_arm_type = response[offset + VAL_TDISP_REQ_RESP_TYPE_OFF];
  if (rsp_arm_type != VAL_TDISP_ARM_MSG_SET_INTERFACE_RESP)
    return ACS_STATUS_FAIL;

  return ACS_STATUS_PASS;
}

static uint32_t
tdisp_rxdkdt_set_interface_and_get_success(uint32_t bdf,
                                          val_spdm_context_t *spdm_context,
                                          uint32_t session_id,
                                          const pci_tdisp_interface_id_t *interface_id,
                                          uint16_t pmecid,
                                          uint32_t *success)
{
  uint32_t status;
  uint8_t response[VAL_TDISP_ARM_VDM_MAX_RSP_SIZE];
  uint32_t response_size;

  *success = 0;
  response_size = (uint32_t)sizeof(response);

  status = val_tdisp_vdm_set_interface(spdm_context,
                                       session_id,
                                       interface_id,
                                       pmecid,
                                       response,
                                       &response_size);
  if (status != ACS_STATUS_PASS)
    return status;

  /*
   * For the negative path we intentionally treat malformed/short replies as
   * 'not success' so the payload can evaluate INTERFACE_ID semantics.
   */
  /* Treat TDISP_ERROR or invalid response as "not a success response". */
  if (tdisp_rxdkdt_validate_set_interface_success_rsp(bdf, response, response_size) ==
      ACS_STATUS_PASS)
  {
    *success = 1;
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
  pci_tdisp_interface_id_t interface_id_valid;
  pci_tdisp_interface_id_t interface_id_other;
  uint8_t tdi_state;
  uint32_t valid_success;
  uint32_t other_success;
  uint16_t pmecid;

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
    tdi_state = 0;
    valid_success = 0;
    other_success = 0;

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

    /* Use INTERFACE_ID derived from the endpoint BDF. */
    interface_id_valid.function_id = (uint32_t)PCIE_CREATE_BDF_PACKED(bdf);
    interface_id_valid.reserved = 0ull;

    /* Use a different INTERFACE_ID for the negative check (avoid endpoint BDF). */
    interface_id_other.function_id = 0u;
    interface_id_other.reserved = 0ull;

    /* SET_INTERFACE_REQ is only permitted in CONFIG_UNLOCKED. */
    status = val_tdisp_get_interface_state(&spdm_context,
                                          session_id,
                                          &interface_id_valid,
                                          &tdi_state);
    if (status != ACS_STATUS_PASS)
      goto cleanup;
    if (tdi_state != PCI_TDISP_INTERFACE_STATE_CONFIG_UNLOCKED)
      goto cleanup;

    pmecid = 0;
    /* Use a benign PMECID (see helper comment above). */
    status = tdisp_rxdkdt_get_pmecid_for_device(bdf,
                                                &spdm_context,
                                                session_id,
                                                &interface_id_valid,
                                                &pmecid);
    if (status != ACS_STATUS_PASS)
    {
      test_fail++;
      goto cleanup;
    }

    /* Baseline: SET_INTERFACE with the correct INTERFACE_ID must succeed. */
    status = tdisp_rxdkdt_set_interface_and_get_success(bdf,
                                                        &spdm_context,
                                                        session_id,
                                                        &interface_id_valid,
                                                        pmecid,
                                                        &valid_success);
    if (status == ACS_STATUS_SKIP)
      goto cleanup;
    if (status != ACS_STATUS_PASS)
    {
      test_fail++;
      goto cleanup;
    }

    /*
     * If the device doesn't return a success response for the valid interface id,
     * we can't evaluate whether INTERFACE_ID is being ignored.
     */
    if (!valid_success)
      goto cleanup;

    test_skip = 0;

    /* test_skip is cleared only after the baseline succeeds on an endpoint. */

    /* Negative: SET_INTERFACE with a different INTERFACE_ID must not succeed. */
    status = tdisp_rxdkdt_set_interface_and_get_success(bdf,
                                                        &spdm_context,
                                                        session_id,
                                                        &interface_id_other,
                                                        pmecid,
                                                        &other_success);
    if (status == ACS_STATUS_SKIP)
      goto cleanup;
    if (status != ACS_STATUS_PASS)
    {
      test_fail++;
      goto cleanup;
    }

    if (other_success)
    {
      val_print(ACS_PRINT_ERR, " SET_INTERFACE succeeded for alternate INTERFACE_ID 0x%x", bdf);
      test_fail++;
    }

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
tdisp_rxdkdt_set_interface_req_semantics_entry(void)
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
