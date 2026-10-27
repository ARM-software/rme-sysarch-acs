/** @file
 * Copyright (c) 2025, 2026, Arm Limited or its affiliates. All rights reserved.
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
#include "val/include/val_pcie_spec.h"
#include "val/include/val_cxl.h"
#include "val/include/val_cxl_spec.h"
#include "val/include/val_el32.h"
#include "val/include/val_da.h"

#define TEST_NAME "cxl_rwpgjb_rmsd_write_protect_property"
#define TEST_DESC "Check RMECDA_CTL registers are RMSD write-protect      "
#define TEST_RULE "RWPGJB"

#define TDISP_EN_MASK 0x1u
#define ALL_STREAM_LOCKS_MASK 0xFFFFFFFFu

static
void
payload()
{

  uint32_t reg_value, reg_ctl1, reg_ctl2, write_val;
  uint32_t pe_index = val_pe_get_index_mpid(val_pe_get_mpid());
  uint64_t component_count;
  uint32_t bdf;
  uint32_t rmecda_cap_base, ide_cap_base;
  uint32_t num_sel_ide_stream_supp, lock_mask;
  uint32_t test_skip = 1;
  uint32_t test_fails = 0;

  component_count = val_cxl_get_component_info(CXL_COMPONENT_INFO_COUNT, 0);

  if (component_count == 0u)
  {
      val_set_status(pe_index, "SKIP", 01);
      return;
  }

  for (uint32_t comp = 0; comp < component_count; ++comp)
  {
      uint32_t role;

      role = (uint32_t)val_cxl_get_component_info(CXL_COMPONENT_INFO_ROLE, comp);
      if (role != CXL_COMPONENT_ROLE_ROOT_PORT)
          continue;

      bdf = (uint32_t)val_cxl_get_component_info(CXL_COMPONENT_INFO_BDF_INDEX, comp);
      if (bdf == CXL_COMPONENT_INVALID_INDEX)
          continue;

      test_skip = 0;
      val_print(ACS_PRINT_TEST, " Checking BDF: 0x%x", bdf);

      if (val_pcie_find_cda_capability(bdf, &rmecda_cap_base) != ACS_STATUS_PASS)
      {
          val_print(ACS_PRINT_ERR,
                            " RMECDA DVSEC capability not present,bdf 0x%x", bdf);
          test_fails++;
          continue;
      }

      if (val_pcie_find_capability(bdf, PCIE_ECAP, ECID_IDE, &ide_cap_base) != PCIE_SUCCESS)
      {
          val_print(ACS_PRINT_ERR,
                            " PCIe IDE Capability not present for BDF: 0x%x", bdf);
          test_fails++;
          continue;
      }

      if (val_pcie_read_cfg(bdf, rmecda_cap_base + RMECDA_CTL1_OFFSET, &reg_ctl1) !=
              PCIE_SUCCESS || reg_ctl1 == PCIE_UNKNOWN_RESPONSE ||
          val_pcie_read_cfg(bdf, rmecda_cap_base + RMECDA_CTL2_OFFSET, &reg_ctl2) !=
              PCIE_SUCCESS ||
          val_pcie_read_cfg(bdf, ide_cap_base + IDE_CAP_REG, &reg_value) != PCIE_SUCCESS ||
          reg_value == PCIE_UNKNOWN_RESPONSE)
      {
          val_print(ACS_PRINT_ERR, " Unable to read RMECDA/IDE registers, BDF 0x%x", bdf);
          test_fails++;
          continue;
      }
      /* RMECDA_CTL3/4 are reserved for CXL ports. */

      uint64_t cfg_addr = val_pcie_get_bdf_config_addr(bdf);

      if (!cfg_addr || (cfg_addr & (PCIE_CFG_SIZE - 1u)))
      {
          val_print(ACS_PRINT_ERR, " Invalid configuration address for BDF 0x%x", bdf);
          test_fails++;
          continue;
      }

      /* Toggle TDISP_EN without changing the other CTL1 fields. */
      write_val = reg_ctl1 ^ TDISP_EN_MASK;
      if (val_rmsd_write_protect_check_masked(
              cfg_addr + rmecda_cap_base + RMECDA_CTL1_OFFSET,
              write_val, reg_ctl1, TDISP_EN_MASK))
      {
          val_print(ACS_PRINT_ERR, " RMSD fail for RMECDA_CTL1 of RP-BDF, 0x%x", bdf);
          test_fails++;
          continue;
      }

      num_sel_ide_stream_supp = (reg_value & NUM_SEL_STR_MASK) >> NUM_SEL_STR_SHIFT;
      num_sel_ide_stream_supp += 1;

      if (num_sel_ide_stream_supp < 32)
          lock_mask = SEL_STR_LOCK_VALID_MASK(num_sel_ide_stream_supp);
      else
          lock_mask = ALL_STREAM_LOCKS_MASK;

      /* Exercise every implemented lock bit and preserve reserved bits. */
      write_val = reg_ctl2 ^ lock_mask;
      if (val_rmsd_write_protect_check_masked(
              cfg_addr + rmecda_cap_base + RMECDA_CTL2_OFFSET,
              write_val, reg_ctl2, lock_mask))
      {
        val_print(ACS_PRINT_ERR, " RMSD fail for RMECDA_CTL2 of RP-BDF, 0x%x", bdf);
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
cxl_rwpgjb_rmsd_write_protect_property_entry(uint32_t num_pe)
{

  num_pe = 1;
  uint32_t status = ACS_STATUS_FAIL;

  status = val_initialize_test(TEST_NAME, TEST_DESC, num_pe, TEST_RULE);

  if (status != ACS_STATUS_SKIP)
      val_run_test_payload(num_pe, payload, 0);

  status = val_check_for_error(num_pe);

  val_report_status(0, "END");

  return status;
}
