/** @file
 * Copyright (c) 2024-2026, Arm Limited or its affiliates. All rights reserved.
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

#include "val/include/val_smmu.h"
#include "val/include/val_pcie.h"
#include "val/include/val_el32.h"
#include "val/include/val_da.h"

#define TEST_NAME "da_ctl_regs_rmsd_write_protect_property"
#define TEST_DESC  "Check that RMEDA_CTL registers are RMSD write-protect  "
#define TEST_RULE  "RNPGJV"

#define WRITE_DATA_CTL1 0x1
#define WRITE_DATA_CTL1_REV 0x0
#define WRITE_DATA_CTL2 0xFFFFFFFF

static
void
payload()
{

  uint32_t reg_value, reg_ctl1, reg_ctl2, write_val;
  uint32_t pe_index = val_pe_get_index_mpid(val_pe_get_mpid());
  uint32_t tbl_index;
  uint32_t bdf;
  uint32_t dp_type;
  uint32_t da_cap_base, ide_cap_base;
  uint32_t num_sel_ide_stream_supp;
  uint32_t test_skip = 1;
  uint32_t test_fails = 0;
  pcie_device_bdf_table *bdf_tbl_ptr;

  tbl_index = 0;
  bdf_tbl_ptr = val_pcie_bdf_table_ptr();
  while (tbl_index < bdf_tbl_ptr->num_entries)
  {
      bdf = bdf_tbl_ptr->device[tbl_index++].bdf;
      dp_type = val_pcie_device_port_type(bdf);

      test_skip = 0;

      if (dp_type == RP)
      {
          val_print(ACS_PRINT_TEST, " Checking BDF: 0x%x", bdf);

          /* Get the PCIE DVSEC Capability register */
          if (val_pcie_find_da_capability(bdf, &da_cap_base) != PCIE_SUCCESS)
          {
              val_print(ACS_PRINT_ERR,
                              " PCIe DA DVSEC capability not present,bdf 0x%x", bdf);
              test_fails++;
              continue;
          }

          /* Get the PCIE IDE Extended Capability register */
          if (val_pcie_find_capability(bdf, PCIE_ECAP, ECID_IDE, &ide_cap_base) != PCIE_SUCCESS)
          {
              val_print(ACS_PRINT_ERR,
                              " PCIe IDE Capability not present for BDF: 0x%x", bdf);
              test_fails++;
              continue;
          }

          /* Read the RMEDA_CTL registers */
          val_pcie_read_cfg(bdf, da_cap_base + RMEDA_CTL1, &reg_ctl1);
          val_pcie_read_cfg(bdf, da_cap_base + RMEDA_CTL2, &reg_ctl2);

          /* Chooose the data to be written on the registers */
          if (reg_ctl1 == WRITE_DATA_CTL1)
              write_val = WRITE_DATA_CTL1_REV;
          else
              write_val = WRITE_DATA_CTL1;

          uint64_t cfg_addr = val_pcie_get_bdf_config_addr(bdf);

          /* Check for the control register1 */
          val_pcie_write_cfg(bdf, da_cap_base + RMEDA_CTL1, WRITE_DATA_CTL1);
          if (val_rmsd_write_protect_check(cfg_addr + da_cap_base + RMEDA_CTL1,
                                           write_val,
                                           reg_ctl1))
          {
            val_print(ACS_PRINT_ERR, " RMSD fail for RMEDA_CTL1 of RP-BDF, 0x%x", bdf);
            test_fails++;
          }

          /* Read the IDE Capability Register to get the NUM_SEL_STR supported */
          val_pcie_read_cfg(bdf, ide_cap_base + IDE_CAP_REG, &reg_value);

          num_sel_ide_stream_supp = (reg_value & NUM_SEL_STR_MASK) >> NUM_SEL_STR_SHIFT;
          num_sel_ide_stream_supp += 1;

          /* If NUM_SEL_STR < 32, SEL_STR_LOCK[31:NUM_SEL_STR] is/are Res0/RsvdP */
          if (num_sel_ide_stream_supp < 32)
          {
              write_val = SEL_STR_LOCK_VALID_MASK(num_sel_ide_stream_supp) & SEL_STR_LOCK_VALID_MAX;

              if (reg_ctl2 == write_val)
                  write_val = ~write_val & SEL_STR_LOCK_VALID_MASK(num_sel_ide_stream_supp);

          } else {
              /* If NUM_SEL_STR => 32, SEL_STR_LOCK[31:0] are valid bits and RW */
              write_val = WRITE_DATA_CTL2;
          }

          if (reg_ctl2 == write_val)
              write_val = ~write_val;

          /* Check for the control regoster2 */
          if (val_rmsd_write_protect_check(cfg_addr + da_cap_base + RMEDA_CTL2,
                                           write_val,
                                           reg_ctl2))
          {
            val_print(ACS_PRINT_ERR, " RMSD fail for RMEDA_CTL2 of RP-BDF, 0x%x", bdf);
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
da_ctl_regs_rmsd_write_protect_property_entry(uint32_t num_pe)
{

  num_pe = 1;
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
