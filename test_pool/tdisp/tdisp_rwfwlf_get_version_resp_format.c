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

#define TEST_NAME "tdisp_rwfwlf_get_version_resp_format"
#define TEST_DESC "Validate GET_VERSION_RESP format"
#define TEST_RULE "RWFWLF"

static uint32_t
tdisp_rwfwlf_validate_get_version_resp(uint32_t bdf,
                                       const uint8_t *response,
                                       uint32_t response_size)
{
  uint32_t offset;
  uint8_t version_count;
  const uint8_t *versions;
  uint32_t idx;
  uint8_t prev;
  uint8_t curr;
  uint8_t prev_major;
  uint8_t prev_minor;
  uint8_t curr_major;
  uint8_t curr_minor;

  offset = 0;
  version_count = 0;
  versions = NULL;
  idx = 0;
  prev = 0;
  curr = 0;
  prev_major = 0;
  prev_minor = 0;
  curr_major = 0;
  curr_minor = 0;

  /* Validate minimum size for header + VERSION_COUNT field. */
  if (response_size < (VAL_TDISP_ARM_VDM_BASE_SIZE + 1u))
  {
    val_print(ACS_PRINT_ERR, " GET_VERSION_RESP too small for 0x%x", bdf);
    return ACS_STATUS_FAIL;
  }

  /* Validate we received an Arm VDM response of type GET_VERSION_RESP. */
  if (response[VAL_TDISP_HDR_MSG_TYPE_OFF] != PCI_TDISP_VDM_RSP)
  {
    val_print(ACS_PRINT_ERR, " Expected VDM_RSP for 0x%x", bdf);
    return ACS_STATUS_FAIL;
  }

  /* The Arm request/response header precedes the Arm-specific payload. */
  if (response[VAL_TDISP_REQ_RESP_HDR_OFF + VAL_TDISP_REQ_RESP_TYPE_OFF] !=
      VAL_TDISP_ARM_MSG_GET_VERSION_RESP)
  {
    val_print(ACS_PRINT_ERR, " GET_VERSION_RESP type mismatch for 0x%x", bdf);
    return ACS_STATUS_FAIL;
  }

  /* Arm VDM payload starts at VAL_TDISP_ARM_VDM_BASE_SIZE. */
  offset = VAL_TDISP_ARM_VDM_BASE_SIZE;
  version_count = response[offset];

  /*
   * VERSION_COUNT bounds the version list length. Ensure the message contains
   * all advertised version entries.
   */
  if (response_size < (VAL_TDISP_ARM_VDM_BASE_SIZE + 1u + (uint32_t)version_count))
  {
    val_print(ACS_PRINT_ERR, " GET_VERSION_RESP truncated for 0x%x", bdf);
    return ACS_STATUS_FAIL;
  }

  /* Version entries are 1 byte each: {major[7:4], minor[3:0]}. */
  versions = &response[offset + 1u];
  for (idx = 1u; idx < (uint32_t)version_count; ++idx)
  {
    prev = versions[idx - 1u];
    curr = versions[idx];
    prev_major = (uint8_t)((prev >> 4) & 0xFu);
    prev_minor = (uint8_t)(prev & 0xFu);
    curr_major = (uint8_t)((curr >> 4) & 0xFu);
    curr_minor = (uint8_t)(curr & 0xFu);

    /* Rule RWFWLF: versions must be listed in ascending order. */
    if ((curr_major < prev_major) ||
        ((curr_major == prev_major) && (curr_minor < prev_minor)))
    {
      val_print(ACS_PRINT_ERR, " Version list not ascending for 0x%x", bdf);
      return ACS_STATUS_FAIL;
    }
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
  uint8_t response[VAL_TDISP_ARM_VDM_MAX_RSP_SIZE];
  uint32_t response_size;

  pe_index = val_pe_get_index_mpid(val_pe_get_mpid());
  cxl_tbl_ptr = val_cxl_component_table_ptr();
  test_fail = 0;
  /* Keep the test SKIP unless at least one eligible CHI-C2C link is exercised. */
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

    /* Ensure RME-CDA DVSEC exists on the root port before enabling TDISP. */
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

    /* INTERFACE_ID is not used for response-format validation; use endpoint BDF. */
    interface_id.function_id = (uint32_t)PCIE_CREATE_BDF_PACKED(bdf);
    interface_id.reserved = 0ull;

    response_size = (uint32_t)sizeof(response);
    /* Send GET_VERSION to collect GET_VERSION_RESP for format validation. */
    status = val_tdisp_vdm_get_version(&spdm_context,
                                       session_id,
                                       &interface_id,
                                       response,
                                       &response_size);
    if (status == ACS_STATUS_SKIP)
      goto cleanup;
    if (status != ACS_STATUS_PASS)
    {
      test_fail++;
      goto cleanup;
    }

    /* Validate VERSION_COUNT and version ordering per rule RWFWLF. */
    status = tdisp_rwfwlf_validate_get_version_resp(bdf, response, response_size);
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
tdisp_rwfwlf_get_version_resp_format_entry(uint32_t num_pe)
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
