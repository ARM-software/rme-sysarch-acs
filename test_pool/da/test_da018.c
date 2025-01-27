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
#include "val/include/rme_acs_pe.h"
#include "val/include/rme_acs_da.h"

#include "test_da018_data.h"

#define TEST_NUM (ACS_RME_DA_TEST_NUM_BASE  +  18)
#define TEST_DESC "Check for RMSD write-detect                            "
#define TEST_RULE "RPCRFM, RGSTJC"

static
void
payload(void)
{
  uint32_t pe_index;
  pcie_device_bdf_table *bdf_tbl_ptr;
  uint32_t tbl_index;
  uint32_t bdf, dp_type;
  uint32_t reg_value;
  uint32_t ide_cap_base;
  uint32_t sel_ide_str_supported;
  uint32_t test_fail = 0;
  uint32_t test_skip = 1;
  uint32_t stream_id;
  uint32_t count;
  uint32_t status;
  uint32_t table_entries;
  uint32_t rp_bdf, ep_index, ep_bdf, index;
  pcie_cfgreg_bitfield_entry *bf_entry;

  tbl_index = 0;
  pe_index = val_pe_get_index_mpid(val_pe_get_mpid());
  bdf_tbl_ptr = val_pcie_bdf_table_ptr();

  table_entries = sizeof(bf_info_table18)/sizeof(bf_info_table18[0]);
  ep_index = 0;

  while (tbl_index < bdf_tbl_ptr->num_entries)
  {
      bdf = bdf_tbl_ptr->device[tbl_index++].bdf;
      dp_type = val_pcie_device_port_type(bdf);

      if (dp_type != RP)
          continue;


      /* Check IDE Extended Capability register is present */
      if (val_pcie_find_capability(bdf, PCIE_ECAP, ECID_IDE, &ide_cap_base) != PCIE_SUCCESS)
      {
          val_print(ACS_PRINT_ERR,
                        "\n       PCIe IDE Capability not present for RP BDF: 0x%x", bdf);
          test_fail++;
          continue;
      }

      /* Check if Selective IDE Stream is supported */
      val_pcie_read_cfg(bdf, ide_cap_base + IDE_CAP_REG, &reg_value);
      sel_ide_str_supported = (reg_value & SEL_IDE_STR_MASK) >> SEL_IDE_STR_SHIFT;
      if (!sel_ide_str_supported)
      {
          val_print(ACS_PRINT_ERR, "\n       Selective IDE str not supported for BDF: %x", bdf);
          test_fail++;
          continue;
      }

      ep_index = 0;
      while (ep_index < bdf_tbl_ptr->num_entries)
      {
          ep_bdf = bdf_tbl_ptr->device[ep_index++].bdf;
          dp_type = val_pcie_device_port_type(ep_bdf);
          if (dp_type != EP)
              continue;

          val_pcie_get_rootport(ep_bdf, &rp_bdf);
          if (bdf == rp_bdf)
              break;
      }

      /* Check IDE Extended Capability register is present */
      if (val_pcie_find_capability(ep_bdf, PCIE_ECAP, ECID_IDE, &ide_cap_base) != PCIE_SUCCESS)
      {
          val_print(ACS_PRINT_ERR,
                        "\n       PCIe IDE Capability not present for BDF: 0x%x", ep_bdf);
          test_fail++;
          continue;
      }

      test_skip = 0;
      count = 1;
      stream_id = val_generate_stream_id();
      val_pcie_enable_tdisp(rp_bdf);

      for (index = 0; index < table_entries; index++)
      {
          bf_entry = (pcie_cfgreg_bitfield_entry *)&(bf_info_table18[index]);

          status = val_ide_establish_stream(ep_bdf, count, stream_id,
                                     PCIE_CREATE_BDF_PACKED(ep_bdf));
          if (status)
          {
              val_print(ACS_PRINT_ERR, "\n       Failed to establish stream for bdf: 0x%x", bdf);
              test_fail++;
              continue;
          }

          status = val_ide_establish_stream(rp_bdf, count, stream_id,
                                     PCIE_CREATE_BDF_PACKED(ep_bdf));
          if (status)
          {
              val_print(ACS_PRINT_ERR, "\n       Failed to establish stream for RP bdf: 0x%x", bdf);
              test_fail++;
              continue;
          }

          status = val_device_lock(ep_bdf);
          if (status)
          {
              val_print(ACS_PRINT_ERR, "\n       TDISP RUN state fail for bdf: 0x%x", bdf);
              test_fail++;
              continue;
          }

          status = val_pcie_write_detect_bitfield_check(rp_bdf, (void *)bf_entry, count);
          if (status && (status != PCIE_CAP_NOT_FOUND))
          {
              val_print(ACS_PRINT_ERR, "\n       Write detect failed for BDF: 0x%x", bdf);
              test_fail++;
              continue;
          }
      }
      /* Put the device back to unlocked state and disable TDISP in RP */
      val_pcie_disable_tdisp(rp_bdf);
      val_device_unlock(ep_bdf);
  }

  if (test_skip)
      val_set_status(pe_index, RESULT_SKIP(TEST_NUM, 01));
  else if (test_fail++)
      val_set_status(pe_index, RESULT_FAIL(TEST_NUM, 01));
  else
      val_set_status(pe_index, RESULT_PASS(TEST_NUM, 01));

  return;

}

uint32_t
da018_entry(void)
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
