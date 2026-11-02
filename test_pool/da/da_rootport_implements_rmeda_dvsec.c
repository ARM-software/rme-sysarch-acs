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

#include "val/include/val_pcie.h"
#include "val/include/val_da.h"

#define TEST_DESC "To check all Root Ports implement RME-DA DVSEC        "
#define TEST_NAME "da_rootport_implements_rmeda_dvsec"
#define TEST_RULE "RNWSJB"

static
void
payload()
{
  uint32_t bdf;
  uint32_t da_cap_base;
  uint32_t dp_type;
  uint32_t pe_index = val_pe_get_index_mpid(val_pe_get_mpid());
  uint32_t tbl_index = 0;
  uint32_t test_fails = 0;
  uint32_t test_skip = 1;
  pcie_device_bdf_table *bdf_tbl_ptr;

  bdf_tbl_ptr = val_pcie_bdf_table_ptr();
  if ((bdf_tbl_ptr == NULL) || (bdf_tbl_ptr->num_entries == 0))
  {
      val_print(ACS_PRINT_WARN, " No PCIe BDF entries discovered", 0);
      val_set_status(pe_index, "SKIP", 01);
      return;
  }

  while (tbl_index < bdf_tbl_ptr->num_entries)
  {
      bdf = bdf_tbl_ptr->device[tbl_index++].bdf;
      dp_type = val_pcie_device_port_type(bdf);

      if (dp_type != RP)
          continue;

      test_skip = 0;
      val_print(ACS_PRINT_TEST, " Checking Root Port BDF: 0x%x", bdf);

      if (val_pcie_find_da_capability(bdf, &da_cap_base) != PCIE_SUCCESS)
      {
          val_print(ACS_PRINT_ERR,
                    " RME-DA DVSEC capability not present for RP BDF: 0x%x", bdf);
          test_fails++;
      }
  }

  if (test_skip)
      val_set_status(pe_index, "SKIP", 01);
  else if (test_fails)
      val_set_status(pe_index, "FAIL", test_fails);
  else
      val_set_status(pe_index, "PASS", 01);
}

uint32_t
da_rootport_implements_rmeda_dvsec_entry(uint32_t num_pe)
{
  uint32_t status = ACS_STATUS_FAIL;

  num_pe = 1;
  status = val_initialize_test(TEST_NAME, TEST_DESC, num_pe, TEST_RULE);

  if (status != ACS_STATUS_SKIP)
      val_run_test_payload(num_pe, payload, 0);

  status = val_check_for_error(num_pe);

  val_report_status(0, "END");

  return status;
}
