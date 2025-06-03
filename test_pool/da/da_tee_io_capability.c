/** @file
 * Copyright (c) 2024-2025, Arm Limited or its affiliates. All rights reserved.
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

#include "val/include/rme_acs_val.h"
#include "val/include/val_interface.h"

#include "val/include/rme_acs_el32.h"
#include "val/include/rme_acs_pcie.h"
#include "val/include/rme_acs_memory.h"
#include "val/include/rme_acs_pcie_enumeration.h"
#include "val/include/rme_acs_exerciser.h"
#include "val/include/rme_acs_smmu.h"
#include "val/include/rme_acs_pe.h"

#define TEST_NAME "da_tee_io_capability"
#define TEST_DESC "Check TEE IO capability                                "
#define TEST_RULE "RLGXBX"

static
void
payload(void)
{
  uint32_t pe_index;
  pcie_device_bdf_table *bdf_tbl_ptr;
  uint32_t tbl_index;
  uint32_t test_fails = 0;
  uint32_t test_skip = 1;
  uint32_t dp_type;
  uint32_t bdf;
  uint32_t tee_io;
  uint32_t cap_base;
  uint32_t reg_value;

  tbl_index = 0;
  pe_index = val_pe_get_index_mpid(val_pe_get_mpid());
  bdf_tbl_ptr = val_pcie_bdf_table_ptr();
  while (tbl_index < bdf_tbl_ptr->num_entries)
  {
      bdf = bdf_tbl_ptr->device[tbl_index++].bdf;
      dp_type = val_pcie_device_port_type(bdf);

      if (dp_type == RP)
      {
          test_skip = 0;

          if (val_pcie_find_capability(bdf, PCIE_CAP, CID_PCIECS, &cap_base) != PCIE_SUCCESS)
          {
              val_print(ACS_PRINT_ERR, " PCIe Express Capability not present ", 0);
              test_fails++;
              continue;
          }

          val_pcie_read_cfg(bdf, cap_base + DCAPR_OFFSET, &reg_value);
          tee_io = (reg_value >> DCAPR_TEE_SHIFT) & DCAPR_TEE_MASK;

          if (tee_io != 1)
          {
              val_print(ACS_PRINT_ERR, " TEE-I/O Capability not present for BDF: %x", bdf);
              test_fails++;
          }

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
da_tee_io_capability_entry(void)
{

  uint32_t num_pe = 1;
  uint32_t status = ACS_STATUS_FAIL;  //default value

  status = val_initialize_test(TEST_NAME, TEST_DESC, num_pe, TEST_RULE);

  /* This check is when user is forcing us to skip this test */
  if (status != ACS_STATUS_SKIP)
      val_run_test_payload(num_pe, payload, 0);

  /* get the result from all PE and check for failure */
  status = val_check_for_error(num_pe);

  val_report_status(0, "END");

  return status;
}
