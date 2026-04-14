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
#include "val/include/val_cxl.h"
#include "val/include/val_pcie.h"

#define TEST_NAME "cxl_rgbgqx_ctc_link_ide"
#define TEST_DESC "Exposed coherent links must advertise CXL IDE     "
#define TEST_RULE "RGBGQX"

static void
payload(void)
{
  uint32_t pe_index = val_pe_get_index_mpid(val_pe_get_mpid());
  CXL_COMPONENT_TABLE *comp_tbl = val_cxl_component_table_ptr();
  uint32_t examined_links = 0;
  uint32_t exposed_links = 0;
  uint32_t skipped_links = 0;
  uint32_t failures = 0;
  uint64_t comp_base;

  /* SKip if no CXL components discovered */
  if ((comp_tbl == NULL) || (comp_tbl->num_entries == 0u))
  {
    val_print(ACS_PRINT_DEBUG, " No CXL components discovered - skipping RGBGQX", 0);
    val_set_status(pe_index, "SKIP", 01);
    return;
  }

  /* Iterate over CXL Root Ports*/
  for (uint32_t idx = 0; idx < comp_tbl->num_entries; ++idx)
  {
    const CXL_COMPONENT_ENTRY *component = &comp_tbl->component[idx];
    uint32_t exposed = 0u;

    if (component->role != CXL_COMPONENT_ROLE_ROOT_PORT)
      continue;

    examined_links++;

    /* Get Platfrom defined info on Link Exposure*/
    if (val_pcie_get_link_exposure(component->bdf, &exposed) != ACS_STATUS_PASS)
    {
      val_print(ACS_PRINT_ERR,
                " RGBGQX: exposure query failed for root port BDF 0x%x",
                component->bdf);
      failures++;
      continue;
    }

    /* Skip the instance if the platform info reports that the link
       is not exposed to physical attacks */
    if (exposed == 0u)
    {
      skipped_links++;
      continue;
    }

    exposed_links++;

    /* If the link is exposed, Check that the rootport supports CXL IDE*/
    comp_base = val_cxl_get_component_info(CXL_COMPONENT_INFO_COMPONENT_BASE, idx);
    if (val_cxl_find_capability(comp_base, CXL_CAPID_IDE, NULL) != ACS_STATUS_PASS)
    {
      val_print(ACS_PRINT_ERR,
                " Root Port 0x%x missing CXL IDE capability - skip",
                (uint64_t)component->bdf);
      failures++;
    }
  }

  if (examined_links == 0u)
  {
    val_print(ACS_PRINT_DEBUG,
              " RGBGQX: no CXL root ports were discovered - skipping",
              0);
    val_set_status(pe_index, "SKIP", 02);
  }
  else if (exposed_links == 0u)
  {
    val_print(ACS_PRINT_DEBUG,
              " RGBGQX: all discovered root ports are marked not exposed (skip count %u)",
              skipped_links);
    val_set_status(pe_index, "SKIP", 03);
  }
  else if (failures != 0u)
  {
    val_set_status(pe_index, "FAIL", failures);
  }
  else
  {
    val_set_status(pe_index, "PASS", exposed_links);
  }
}

uint32_t
cxl_rgbgqx_ctc_link_ide_entry(uint32_t num_pe)
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
