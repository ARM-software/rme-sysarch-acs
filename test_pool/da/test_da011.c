/** @file
 * Copyright (c) 2024-2025, Arm Limited or its affiliates. All rights reserved.
 * SPDX-License-Identifier : Apache-2.0

 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use
 * this file except in compliance with the License.
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
#include "val/include/rme_acs_da.h"

#define TEST_NUM (ACS_RME_DA_TEST_NUM_BASE  +  11)
#define TEST_DESC "Check TDISP from 1 to 0 transitions to Insecure state  "
#define TEST_RULE "RHCMWC"

static
void
payload(void)
{
  uint32_t pe_index;
  pcie_device_bdf_table *bdf_tbl_ptr;
  uint32_t tbl_index;
  uint32_t dp_type;
  uint32_t bdf;
  uint32_t da_cap_base;
  uint32_t reg_value;
  uint32_t test_fail = 0;
  uint32_t test_skip = 1;
  uint32_t num_sel_str;
  uint32_t count;
  uint32_t status;

  tbl_index = 0;
  pe_index = val_pe_get_index_mpid(val_pe_get_mpid());
  bdf_tbl_ptr = val_pcie_bdf_table_ptr();

  while (tbl_index < bdf_tbl_ptr->num_entries)
  {
      bdf = bdf_tbl_ptr->device[tbl_index++].bdf;
      dp_type = val_pcie_device_port_type(bdf);

      if (dp_type != RP)
          continue;

      test_skip = 0;

      /* Get the PCIE DVSEC Capability register */
      if (val_pcie_find_da_capability(bdf, &da_cap_base) != PCIE_SUCCESS)
      {
          val_print(ACS_PRINT_ERR,
                          "\n       PCIe DA DVSEC capability not present,bdf 0x%x", bdf);
          test_fail++;
          continue;
      }

      status = val_ide_get_num_sel_str(bdf, &num_sel_str);
      if (status)
      {
          val_print(ACS_PRINT_ERR, "\n       Failed to get num of Sel stream for BDF: 0x%x", bdf);
          test_fail++;
          continue;
      }

      /* Find the DA DVSEC_CTL register and enable TDISP */
      if (val_pcie_enable_tdisp(bdf))
      {
          val_print(ACS_PRINT_ERR, "\n        Unable to set tdisp_en for BDF: 0x%x", bdf);
          test_fail++;
          continue;
      }

      count = 0;
      while (count++ < num_sel_str)
      {
          status = val_ide_establish_stream(bdf, count, val_generate_stream_id(),
                                     PCIE_CREATE_BDF_PACKED(bdf));
          if (status)
          {
              val_print(ACS_PRINT_ERR, "\n       Failed to establish stream for bdf: 0x%x", bdf);
              test_fail++;
              continue;
          }

          /* Disable the TDISP */
          val_pcie_disable_tdisp(bdf);

          status = val_get_sel_str_status(bdf, count, &reg_value);
          if (status)
          {
              val_print(ACS_PRINT_ERR, "\n       Fail to get Sel Stream state for BDF: 0x%x", bdf);
              test_fail++;
              continue;
          }

          if (reg_value != STREAM_STATE_INSECURE)
          {
              val_print(ACS_PRINT_ERR, "\n       Sel Stream is not in Insecure for BDF: 0x%x", bdf);
              test_fail++;
              continue;
           }

          status = val_ide_set_sel_stream(bdf, count, 0);
          if (status)
          {
              val_print(ACS_PRINT_ERR, "\n       Failed to disable Sel Stream for BDF: 0x%x", bdf);
              test_fail++;
              continue;
          }

          val_ide_program_rid_base_limit_valid(bdf, count, 0, 0, 0);
      }

      /* Disable the TDISP before moving to next RP */
      val_pcie_disable_tdisp(bdf);

  }

  if (test_skip)
      val_set_status(pe_index, RESULT_SKIP(TEST_NUM, 01));
  else if (test_fail)
      val_set_status(pe_index, RESULT_FAIL(TEST_NUM, 01));
  else
      val_set_status(pe_index, RESULT_PASS(TEST_NUM, 01));

  return;
}

uint32_t
da011_entry(void)
{

  uint32_t num_pe = 1;
  uint32_t status = ACS_STATUS_FAIL;  //default value

  status = val_initialize_test(TEST_NUM, TEST_DESC, num_pe, TEST_RULE);

  /* This check is when user is forcing us to skip this test */
  if (status != ACS_STATUS_SKIP)
      val_run_test_payload(TEST_NUM, num_pe, payload, 0);

  /* get the result from all PE and check for failure */
  status = val_check_for_error(TEST_NUM, num_pe, TEST_RULE);

  val_report_status(0, RME_ACS_END(TEST_NUM), TEST_RULE);

  return status;
}
