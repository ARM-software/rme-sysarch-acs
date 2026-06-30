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

#define TEST_NAME "tdisp_rghdcb_get_dev_prop_resp_format"
#define TEST_DESC "Validate GET_DEV_PROP_RESP format"
#define TEST_RULE "RGHDCB"

static uint32_t
tdisp_rghdcb_read_u32_le(const uint8_t *buf, uint32_t offset)
{
  uint32_t v;

  v = 0;
  /* GET_DEV_PROP_RESP encodes PROPERTIES as little-endian DWORD. */
  v |= (uint32_t)buf[offset + 0u];
  v |= (uint32_t)buf[offset + 1u] << 8;
  v |= (uint32_t)buf[offset + 2u] << 16;
  v |= (uint32_t)buf[offset + 3u] << 24;

  return v;
}

static uint32_t
tdisp_rghdcb_validate_get_dev_prop_resp(uint32_t bdf,
                                        const uint8_t *response,
                                        uint32_t response_size)
{
  uint32_t properties;
  uint32_t mec_supported;
  uint32_t pas_check;
  uint32_t mecid_bitwidth;
  uint32_t res0;

  properties = 0;
  mec_supported = 0;
  pas_check = 0;
  mecid_bitwidth = 0;
  res0 = 0;

  /* Validate minimum size for header + PROPERTIES field. */
  if (response_size < (VAL_TDISP_ARM_VDM_BASE_SIZE + 4u))
  {
    val_print(ACS_PRINT_ERR, " GET_DEV_PROP_RESP too small for 0x%x", bdf);
    return ACS_STATUS_FAIL;
  }

  /* Validate we received an Arm VDM response of type GET_DEV_PROP_RESP. */
  if (response[VAL_TDISP_HDR_MSG_TYPE_OFF] != PCI_TDISP_VDM_RSP)
  {
    val_print(ACS_PRINT_ERR, " Expected VDM_RSP for 0x%x", bdf);
    return ACS_STATUS_FAIL;
  }

  if (response[VAL_TDISP_REQ_RESP_HDR_OFF + VAL_TDISP_REQ_RESP_TYPE_OFF] !=
      VAL_TDISP_ARM_MSG_GET_DEV_PROP_RESP)
  {
      val_print(ACS_PRINT_ERR, " GET_DEV_PROP_RESP type mismatch for 0x%x", bdf);
      return ACS_STATUS_FAIL;
    }

  /*
   * Rule RGHDCB validates the PROPERTIES encoding. The register list that may
   * follow is implementation-defined, so do not enforce its content here.
   */
  properties = tdisp_rghdcb_read_u32_le(response, VAL_TDISP_ARM_VDM_BASE_SIZE);
  /*
   * PROPERTIES bit definitions (Arm TDISP VDM):
   * - bit[0]    PAS_CHECK
   * - bit[1]    MEC
   * - bit[12:2] MECID_BITWIDTH
   * - bit[31:13] RES0
   */
  pas_check = properties & 0x1u;
  mec_supported = (properties >> 1) & 0x1u;
  mecid_bitwidth = (properties & VAL_TDISP_DEV_PROP_MECID_MASK) >>
                   VAL_TDISP_DEV_PROP_MECID_SHIFT;
  res0 = properties >> 13;

  if (res0 != 0u)
  {
    val_print(ACS_PRINT_ERR, " Reserved bits set for 0x%x", bdf);
    return ACS_STATUS_FAIL;
  }

  /* PAS_CHECK is a single-bit field: 0 or 1. */
  if (pas_check > 1u)
  {
    val_print(ACS_PRINT_ERR, " Invalid PAS_CHECK for 0x%x", bdf);
    return ACS_STATUS_FAIL;
  }

  /* MEC is a single-bit field: 0 or 1. */
  if (mec_supported > 1u)
  {
    val_print(ACS_PRINT_ERR, " Invalid MEC bit for 0x%x", bdf);
    return ACS_STATUS_FAIL;
  }

  /* When MEC==1, MECID_BITWIDTH must be non-zero. */
  if (mec_supported && (mecid_bitwidth == 0u))
  {
    val_print(ACS_PRINT_ERR, " MECID width is 0 for 0x%x", bdf);
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
    /* Send GET_DEV_PROP to collect GET_DEV_PROP_RESP for format validation. */
    status = val_tdisp_vdm_get_dev_prop(&spdm_context,
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

    /* Validate PROPERTIES fields per rule RGHDCB. */
    status = tdisp_rghdcb_validate_get_dev_prop_resp(bdf, response, response_size);
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
tdisp_rghdcb_get_dev_prop_resp_format_entry(uint32_t num_pe)
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
