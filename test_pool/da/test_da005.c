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

#include "val/include/rme_acs_pcie.h"
#include "val/include/rme_acs_el32.h"
#include "val/include/rme_acs_da.h"

#define TEST_NUM (ACS_RME_DA_TEST_NUM_BASE  +  5)
#define TEST_DESC "To Check the attribute of RMEDA_CTL registers          "
#define TEST_RULE "RDVJRV"

void
write_from_root(uint64_t addr, uint32_t data)
{

  shared_data->num_access = 1;
  shared_data->shared_data_access[0].addr = addr;
  shared_data->shared_data_access[0].data = data;
  shared_data->shared_data_access[0].access_type = WRITE_DATA;

  val_pe_access_mut_el3();
}

static
void
payload()
{

  uint32_t reg_value, write_val, ide_reg_value;
  uint32_t original_reg_val;
  uint64_t va;
  uint32_t cfg_addr;
  uint32_t pgt_attr_el3;
  uint32_t pe_index = val_pe_get_index_mpid(val_pe_get_mpid());
  uint32_t test_fails = 0;
  uint32_t test_skip = 1;
  uint32_t tbl_index;
  uint32_t bdf;
  uint32_t dp_type;
  uint32_t da_cap_base, ide_cap_base;
  uint32_t num_sel_ide_stream_supp;
  pcie_device_bdf_table *bdf_tbl_ptr;

  tbl_index = 0;
  bdf_tbl_ptr = val_pcie_bdf_table_ptr();

  while (tbl_index < bdf_tbl_ptr->num_entries)
  {
      bdf = bdf_tbl_ptr->device[tbl_index++].bdf;
      dp_type = val_pcie_device_port_type(bdf);

      if (dp_type == RP)
      {
          test_skip = 0;

          /* Get the PCIE DVSEC Capability register */
          if (val_pcie_find_da_capability(bdf, &da_cap_base) != PCIE_SUCCESS)
          {
              val_print(ACS_PRINT_ERR,
                              "\n       PCIe DA DVSEC capability not present,bdf 0x%x", bdf);
              test_fails++;
              continue;
          }

          /* Get the PCIE IDE Extended Capability register */
          if (val_pcie_find_capability(bdf, PCIE_ECAP, ECID_IDE, &ide_cap_base) != PCIE_SUCCESS)
          {
              val_print(ACS_PRINT_ERR,
                              "\n       PCIe IDE Capability not present for BDF: 0x%x", bdf);
              test_fails++;
              continue;
          }

          /* Map the configuration address before writing from root as ROOT PAS */
          va = val_get_free_va(val_get_min_tg());
          cfg_addr = val_pcie_get_bdf_config_addr(bdf);
          pgt_attr_el3 = LOWER_ATTRS(PGT_ENTRY_ACCESS | SHAREABLE_ATTR(OUTER_SHAREABLE)
                          | GET_ATTR_INDEX(DEV_MEM_nGnRnE) | PGT_ENTRY_AP_RW | PAS_ATTR(ROOT_PAS));
          val_add_mmu_entry_el3(va, cfg_addr, pgt_attr_el3);

          /* Write to RMEDA_CTL1 register in Root to check it's RW attr */
          val_pcie_read_cfg(bdf, da_cap_base + RMEDA_CTL1, &original_reg_val);
          reg_value = original_reg_val;

          write_val = (reg_value == 0x1) ? 0x0 : 0x1;
          write_from_root(va + da_cap_base + RMEDA_CTL1, write_val);
          val_pcie_read_cfg(bdf, da_cap_base + RMEDA_CTL1, &reg_value);

          if (reg_value != write_val)
          {
              val_print(ACS_PRINT_ERR, "\n      TDISP_EN bit is not updated for RP bdf, 0x%x", bdf);
              test_fails++;
          }

          /* Restore the register */
          write_from_root(va + da_cap_base + RMEDA_CTL1, original_reg_val);

          /* Write to RMEDA_CTL2 register in ROOT to check if it's attr */
          val_pcie_read_cfg(bdf, da_cap_base + RMEDA_CTL2, &original_reg_val);
          reg_value = original_reg_val;
          val_pcie_read_cfg(bdf, ide_cap_base + IDE_CAP_REG, &ide_reg_value);
          val_print(ACS_PRINT_DEBUG, "IDE_REG value = 0x%lx\n", ide_reg_value);

          num_sel_ide_stream_supp = (ide_reg_value & NUM_SEL_STR_MASK) >> NUM_SEL_STR_SHIFT;
          num_sel_ide_stream_supp += 1;

          /* If NUM_SEL_STR < 32, SEL_STR_LOCK[31:NUM_SEL_STR] is/are Res0/RsvdP */
          if (num_sel_ide_stream_supp < 32)
          {
              /* Check for Res0/RsvdP */
              write_val = reg_value;
              write_from_root(va + da_cap_base + RMEDA_CTL2, write_val);
              reg_value = (reg_value >> num_sel_ide_stream_supp);

              if (reg_value != 0)
              {
                  val_print(ACS_PRINT_ERR,
                  "\n      RMEDA_CTL2 SEL_STR_LOC[31:NUM_SEL_STR] not RsvdP for RP bdf, 0x%x", bdf);
                  test_fails++;
              }

              /* Now for SEL_STR_LOCK[NUM_SEL_STR - 1: 0] which should be RW */
              write_val = reg_value ^ (REG_MASK(num_sel_ide_stream_supp - 1, 0) << 0);
              write_from_root(va + da_cap_base + RMEDA_CTL2, write_val);
              val_pcie_read_cfg(bdf, da_cap_base + RMEDA_CTL2, &reg_value);

              if (reg_value != write_val)
              {
                  val_print(ACS_PRINT_ERR,
                  "\n       RMEDA_CTL2 RW bits not updated for RP bdf, 0x%x", bdf);
                  test_fails++;
              }

              /* Restore the resgister */
              write_from_root(va + da_cap_base + RMEDA_CTL2, original_reg_val);
          } else {
              write_val = ~reg_value;
              write_from_root(va + da_cap_base + RMEDA_CTL2, write_val);

              if (reg_value != write_val)
              {
                  val_print(ACS_PRINT_ERR,
                  "\n       RMEDA_CTL2 RW bits not updated for RP bdf, 0x%x", bdf);
                  test_fails++;
              }

              /* Restore the resgister */
              write_from_root(va + da_cap_base + RMEDA_CTL2, original_reg_val);
          }
      }
  }

  if (test_skip)
      val_set_status(pe_index, RESULT_SKIP(TEST_NUM, 01));
  else if (test_fails)
      val_set_status(pe_index, RESULT_FAIL(TEST_NUM, test_fails));
  else
      val_set_status(pe_index, RESULT_PASS(TEST_NUM, 01));
}

uint32_t
da005_entry(void)
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
