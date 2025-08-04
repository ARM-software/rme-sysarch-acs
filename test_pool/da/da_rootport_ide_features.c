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

#define TEST_NAME "da_rootport_ide_features"
#define TEST_DESC "Check RP IDE features                                  "
#define TEST_RULE "RGRCKL"

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
  uint32_t sel_ide_str_supported;
  uint32_t num_tc_supp;
  uint32_t num_addr_asso_block;
  uint32_t tee_limited_stream_supp;
  uint32_t num_sel_ide_stream_supp;
  uint32_t count;
  uint32_t cap_base;
  uint32_t reg_value;
  uint32_t current_base_offset;

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

          val_print(ACS_PRINT_TEST, " Checking BDF: 0x%x", bdf);

          /* Get the PCIE IDE Extended Capability register */
          if (val_pcie_find_capability(bdf, PCIE_ECAP, ECID_IDE, &cap_base) != PCIE_SUCCESS)
          {
              val_print(ACS_PRINT_ERR, " PCIe IDE Capability not present ", 0);
              test_fails++;
              continue;
          }

          /* Check if Selective IDE stream is supported. If it is supported, then it
           * means at lease one Selective IDE stream will be supported such that 0=1 Stream
           */
          val_pcie_read_cfg(bdf, cap_base + IDE_CAP_REG, &reg_value);
          sel_ide_str_supported = (reg_value & SEL_IDE_STR_MASK) >> SEL_IDE_STR_SHIFT;
          if (sel_ide_str_supported != 0x1)
          {
              val_print(ACS_PRINT_ERR, " Selective IDE str not supported for BDF: %x", bdf);
              test_fails++;
              continue;
          }

          /* Check if TEE-Limited Stream control mechanism is supported */
          tee_limited_stream_supp = (reg_value & TEE_LIM_STR_SUPP_MASK) >> TEE_LIM_STR_SUPP_SHIFT;
          if (tee_limited_stream_supp != 1)
          {
              val_print(ACS_PRINT_ERR, " TEE limited str not supported for BDF: %x", bdf);
              test_fails++;
          }

          /* Get the number of Selective IDE Streams */
          num_sel_ide_stream_supp = (reg_value & NUM_SEL_STR_MASK) >> NUM_SEL_STR_SHIFT;

          /* Get the number of TCs supported for Link IDE */
          num_tc_supp = (reg_value & NUM_TC_SUPP_MASK) >> NUM_TC_SUPP_SHIFT;
          count = 0;

          current_base_offset = cap_base;

          /* Base offset of Link IDE Register Block */
          current_base_offset = current_base_offset + IDE_CAP_REG_SIZE;

          while (count <= num_sel_ide_stream_supp)
          {
              /* Base offset of Selective IDE Stream Block */
              current_base_offset = current_base_offset + ((num_tc_supp + 1) * LINK_IDE_BLK_SIZE);

              /* Get the number of Address Associaltion Register Blocks */
              val_pcie_read_cfg(bdf, current_base_offset, &reg_value);
              num_addr_asso_block = (reg_value & NUM_ADDR_ASSO_REG_MASK) >> NUM_ADDR_ASSO_REG_SHIFT;
              count++;

              /* Base offset of IDE RID Association Register 1 */
              current_base_offset = current_base_offset + SEL_IDE_CAP_REG_SIZE;

              /* Base offset of IDE RID Association Register 2 */
              current_base_offset = current_base_offset + RID_ADDR_REG1_SIZE;

              /* Base offset of IDE Address Association Register Block */
              current_base_offset = current_base_offset + RID_ADDR_REG2_SIZE;

              /*Check if at least 3 Address Association registers for each Selective IDE Stream */
              if (num_addr_asso_block < 3)
              {
                  val_print(ACS_PRINT_ERR, " Addr asso reg blk is < 3 for BDF: %x", bdf);
                  test_fails++;
                  continue;
              }

              /* Base offset of next Selective IDE Stream Register Block */
              current_base_offset +=  (num_addr_asso_block * IDE_ADDR_REG_BLK_SIZE);
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
da_rootport_ide_features_entry(void)
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
