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
#include "val/include/val_pcie.h"
#include "val/include/val_cxl.h"
#include "val/include/val_da.h"

#define TEST_DESC "Coherent ports implement RME-CDA DVSEC           "
#define TEST_NAME "cxl_rplykv_rdfwkw_rme_cda_dvsec"
#define TEST_RULE "RPLYKV RDFWKW"

static
void
payload(void)
{
  uint32_t pe_index = val_pe_get_index_mpid(val_pe_get_mpid());
  CXL_COMPONENT_TABLE *comp_tbl = val_cxl_component_table_ptr();
  uint32_t tested_ports = 0;
  uint32_t failures = 0;

  if ((comp_tbl == NULL) || (comp_tbl->num_entries == 0))
  {
    val_print(ACS_PRINT_DEBUG, " No CXL components discovered - skipping", 0);
    val_set_status(pe_index, "SKIP", 01);
    return;
  }

  /* The scenario only applies when the platform advertises coherent DA capability. */
  if (val_is_coherent_da_supported() == 0u)
  {
    val_print(ACS_PRINT_DEBUG,
      " Platform lacks coherent DA support - skipping",
      0);
    val_set_status(pe_index, "SKIP", 03);
    return;
  }

  for (uint32_t idx = 0; idx < comp_tbl->num_entries; ++idx)
  {
    const CXL_COMPONENT_ENTRY *component = &comp_tbl->component[idx];
    uint32_t status;
    uint32_t dvsec_offset;

    if (component->role != CXL_COMPONENT_ROLE_ROOT_PORT)
      continue;

    tested_ports++;

    /* All host ports in a system that supports Coherent RME-DA implement the RME-CDA DVSEC */
    status = val_pcie_find_cda_capability(component->bdf, &dvsec_offset);
    if (status != PCIE_SUCCESS)
    {
      val_print(ACS_PRINT_ERR,
          " RME-CDA DVSEC missing on coherent DA root port BDF 0x%x",
          component->bdf);
      failures++;
    }
  }

  if (tested_ports == 0u)
  {
    val_print(ACS_PRINT_DEBUG,
      " No CXL root ports discovered for coherent DA check - skipping",
      0);
    val_set_status(pe_index, "SKIP", 02);
  }
  else if (failures != 0u)
  {
    val_set_status(pe_index, "FAIL", failures);
  }
  else
  {
    val_set_status(pe_index, "PASS", 01);
  }
}

uint32_t
cxl_rplykv_rdfwkw_rme_cda_dvsec_entry(uint32_t num_pe)
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
