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

#define TEST_NAME "cxl_rxwjnn_type3_link_ide"
#define TEST_DESC "Exposed Type-3 links must advertise CXL IDE         "
#define TEST_RULE "RXWJNN"

static void
payload(void)
{
  uint32_t pe_index = val_pe_get_index_mpid(val_pe_get_mpid());
  CXL_COMPONENT_TABLE *comp_tbl = val_cxl_component_table_ptr();
  uint32_t type3_devices = 0;
  uint32_t exposed_links = 0;
  uint32_t skipped_links = 0;
  uint32_t unresolved_links = 0;
  uint32_t failures = 0;

  /* Skip if there are no CXL components discovered*/
  if ((comp_tbl == NULL) || (comp_tbl->num_entries == 0u))
  {
    val_print(ACS_PRINT_DEBUG, " No CXL components discovered - skipping RXWJNN", 0);
    val_set_status(pe_index, "SKIP", 01);
    return;
  }

  /* Iterate over CXL componets and find CXL T3 <-> RP pairs */
  for (uint32_t idx = 0; idx < comp_tbl->num_entries; ++idx)
  {
    const CXL_COMPONENT_ENTRY *component = &comp_tbl->component[idx];
    uint32_t rp_bdf = 0u;
    uint32_t exposed = 0u;
    uint32_t rp_status;
    uint64_t comp_base;

    if (component->device_type != CXL_DEVICE_TYPE_TYPE3)
      continue;

    type3_devices++;

    /* For each type 3 device discovered, find its Root Port*/
    rp_status = val_cxl_find_upstream_root_port(component->bdf, &rp_bdf);
    if (rp_status != ACS_STATUS_PASS)
    {
      val_print(ACS_PRINT_DEBUG,
                " RXWJNN: unable to resolve upstream root port for BDF 0x%x",
                component->bdf);
      unresolved_links++;
      continue;
    }

    /* Get Platfrom defined info on Link Exposure*/
    if (val_pcie_get_link_exposure(rp_bdf, &exposed) != ACS_STATUS_PASS)
    {
      val_print(ACS_PRINT_ERR,
                " RXWJNN: exposure query failed for root port BDF 0x%x",
                rp_bdf);
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
      val_print(ACS_PRINT_INFO,
                " Root Port 0x%x missing CXL IDE capability - skip",
                (uint64_t)rp_bdf);
      continue;
    }
  }

  /* Skip if no Type 3 devices found */
  if (type3_devices == 0u)
  {
    val_print(ACS_PRINT_DEBUG,
              " RXWJNN: no CXL Type-3 components discovered - skipping",
              0);
    val_set_status(pe_index, "SKIP", 02);
  }

  /* Skip if no exposed links found or fails to find corresponding Root Port*/
  else if ((exposed_links == 0u) && (failures == 0u))
  {
    val_print(ACS_PRINT_DEBUG,
              " RXWJNN: Type-3 links marked internal count %u",
              skipped_links);
    val_print(ACS_PRINT_DEBUG,
              " RXWJNN: Type-3 links unresolved count %u",
              unresolved_links);
    val_set_status(pe_index, "SKIP", 03);
  }

  /* Fail the test if exposed links dont support IDE*/
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
cxl_rxwjnn_type3_link_ide_entry(uint32_t num_pe)
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
