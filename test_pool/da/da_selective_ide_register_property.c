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

#define TEST_NAME "da_selective_ide_register_property"
#define TEST_DESC "Check Selective IDE Streams are Locked/Unlocked        "
#define TEST_RULE "RYHQQL"

static
int
write_from_root(uint64_t addr, uint32_t data)
{

  shared_data->num_access = 1;
  shared_data->shared_data_access[0].addr = addr;
  shared_data->shared_data_access[0].data = data;
  shared_data->shared_data_access[0].access_type = WRITE_DATA;

  if (val_pe_access_mut_el3())
  {
    val_print(ACS_PRINT_ERR, " MUT Access failed for VA: 0x%llx", addr);
    return 1;
  }
  return 0;
}

static
void
payload(void)
{
  uint32_t pe_index;
  pcie_device_bdf_table *bdf_tbl_ptr;
  uint32_t tbl_index;
  uint32_t dp_type;
  uint32_t bdf;
  uint32_t reg_value;
  uint32_t test_fail = 0;
  uint32_t test_skip = 1;
  uint32_t count;
  uint32_t status;
  uint32_t pgt_attr_el3;
  uint32_t sel_str_lock_bit;
  uint64_t va;
  uint32_t cfg_addr;
  uint32_t da_cap_base;
  uint32_t stream_id;
  uint32_t str_index;
  uint32_t num_sel_str;

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
                          " PCIe DA DVSEC capability not present,bdf 0x%x", bdf);
          test_fail++;
          continue;
      }

      /* Map the configuration address before writing from root as ROOT PAS */
      va = val_get_free_va(val_get_min_tg());
      cfg_addr = val_pcie_get_bdf_config_addr(bdf);
      pgt_attr_el3 = LOWER_ATTRS(PGT_ENTRY_ACCESS | SHAREABLE_ATTR(OUTER_SHAREABLE)
                          | GET_ATTR_INDEX(DEV_MEM_nGnRnE) | PGT_ENTRY_AP_RW | PAS_ATTR(ROOT_PAS));
      val_add_mmu_entry_el3(va, cfg_addr, pgt_attr_el3);

      status = val_ide_get_num_sel_str(bdf, &num_sel_str);
      if (status)
      {
          val_print(ACS_PRINT_ERR, " Failed to get num of Sel stream for BDF: 0x%x", bdf);
          test_fail++;
          continue;
      }

      if (val_pcie_enable_tdisp(bdf))
      {
          val_print(ACS_PRINT_ERR, " Unable to set tdisp_en for BDF: 0x%x", bdf);
          test_fail++;
          continue;
      }

      count = 0;
      while (count++ < num_sel_str)
      {
          stream_id = val_generate_stream_id();

          status = val_ide_establish_stream(bdf, count, val_generate_stream_id(),
                                     PCIE_CREATE_BDF_PACKED(bdf));
          if (status)
          {
              val_print(ACS_PRINT_ERR, " Failed to establish stream for bdf: 0x%x", bdf);
              test_fail++;
              continue;
          }

          val_pcie_read_cfg(bdf, da_cap_base + RMEDA_CTL2, &reg_value);
          /* Lock the corresponding Selective IDE register block in RMEDA_CTL2 register */
          str_index = count - 1;
          sel_str_lock_bit = 1 << (str_index % 32);
          if (write_from_root(va + da_cap_base + RMEDA_CTL2, sel_str_lock_bit))
          {
            test_fail++;
            continue;
          }
          val_pcie_read_cfg(bdf, da_cap_base + RMEDA_CTL2, &reg_value);

          /* Reprogramming the Selective IDE registers should transition the Stream to Insecure */
          stream_id = val_generate_stream_id();
          status = val_ide_program_stream_id(bdf, count, stream_id);
          if (status)
          {
              val_print(ACS_PRINT_ERR, " Failed to re-set Stream ID for BDF: 0x%x", bdf);
              test_fail++;
              continue;
          }

          status = val_get_sel_str_status(bdf, count, &reg_value);
          if (status)
          {
              val_print(ACS_PRINT_ERR, " Fail to get Sel Stream state for BDF: 0x%x", bdf);
              test_fail++;
              continue;
          }

          if (reg_value != STREAM_STATE_INSECURE)
          {
              val_print(ACS_PRINT_ERR, " Sel Stream is not in InSecure for BDF: 0x%x", bdf);
              test_fail++;
              continue;
          }
      }

      /* Disable the TDISP for RP */
      val_pcie_enable_tdisp(bdf);

  }

  if (test_skip)
      val_set_status(pe_index, "SKIP", 01);
  else if (test_fail)
      val_set_status(pe_index, "FAIL", 01);
  else
      val_set_status(pe_index, "PASS", 01);

  return;
}

uint32_t
da_selective_ide_register_property_entry(void)
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
