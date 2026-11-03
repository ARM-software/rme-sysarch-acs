/** @file
 * Copyright (c) 2024-2025, 2026, Arm Limited or its affiliates. All rights reserved.
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

#include "val/include/val.h"
#include "val/include/val_interface.h"

#include "val/include/val_el32.h"
#include "val/include/val_pcie.h"
#include "val/include/val_memory.h"
#include "val/include/val_pcie_enumeration.h"
#include "val/include/val_exerciser.h"
#include "val/include/val_pe.h"
#include "val/include/val_da.h"

#include "da_rmsd_write_detect_property.h"

#define TEST_NAME "da_rmsd_write_detect_property"
#define TEST_DESC "Check for RMSD write-detect                            "
#define TEST_RULE "RPCRFM, RGSTJC"

static
void
payload(void)
{
  uint32_t pe_index;
  uint32_t instance, num_exercisers;
  uint32_t reg_value;
  uint32_t da_cap_base;
  uint32_t ide_cap_base;
  uint32_t cap_base, cap_id;
  uint32_t sel_ide_str_supported;
  uint32_t test_fail = 0;
  uint32_t test_skip = 1;
  uint32_t ide_unsupported = 0;
  uint32_t stream_id;
  uint32_t count;
  uint32_t status;
  uint32_t table_entries;
  uint32_t rp_bdf, ep_bdf, index;
  pcie_cfgreg_bitfield_entry *bf_entry;
  uint32_t ep_locked = 0;

  pe_index = val_pe_get_index_mpid(val_pe_get_mpid());
  num_exercisers = val_exerciser_get_info(EXERCISER_NUM_CARDS);
  if (num_exercisers == 0)
  {
      val_print(ACS_PRINT_WARN, " No exerciser cards discovered", 0);
      val_set_status(pe_index, "SKIP", 01);
      return;
  }

  table_entries = sizeof(bf_info_table18)/sizeof(bf_info_table18[0]);
  for (instance = 0; instance < num_exercisers; ++instance)
  {
      if (val_exerciser_init(instance))
          continue;

      ep_bdf = val_exerciser_get_bdf(instance);
      if (val_pcie_get_rootport(ep_bdf, &rp_bdf))
          continue;

      val_print(ACS_PRINT_TEST, " Exerciser BDF: 0x%x", ep_bdf);
      val_print(ACS_PRINT_TEST, " Checking RP BDF: 0x%x", rp_bdf);

      /* Get the PCIE DVSEC Capability register */
      if (val_pcie_find_da_capability(rp_bdf, &da_cap_base) != PCIE_SUCCESS)
      {
           val_print(ACS_PRINT_ERR,
                           " PCIe DA DVSEC capability not present,bdf 0x%x", rp_bdf);
           continue;
      }

      /* Check IDE Extended Capability register is present */
      if (val_pcie_find_capability(rp_bdf, PCIE_ECAP, ECID_IDE, &ide_cap_base) != PCIE_SUCCESS)
      {
          val_print(ACS_PRINT_ERR,
                        " PCIe IDE Capability not present for RP BDF: 0x%x", rp_bdf);
          continue;
      }

      /* Check if Selective IDE Stream is supported */
      val_pcie_read_cfg(rp_bdf, ide_cap_base + IDE_CAP_REG, &reg_value);
      sel_ide_str_supported = (reg_value & SEL_IDE_STR_MASK) >> SEL_IDE_STR_SHIFT;
      if (!sel_ide_str_supported)
      {
          val_print(ACS_PRINT_ERR, " Selective IDE str not supported for BDF: %x", rp_bdf);
          continue;
      }

      test_skip = 0;

      /* Check IDE Extended Capability register is present */
      if (val_pcie_find_capability(ep_bdf, PCIE_ECAP, ECID_IDE, &ide_cap_base) != PCIE_SUCCESS)
      {
          val_print(ACS_PRINT_ERR,
                        " PCIe IDE Capability not present for BDF: 0x%x", ep_bdf);
          test_fail++;
          continue;
      }

      count = 1;
      stream_id = val_generate_stream_id();

      if (val_pcie_enable_tdisp(rp_bdf))
      {
          val_print(ACS_PRINT_ERR, " Unable to set tdisp_en for BDF: 0x%x", rp_bdf);
          test_fail++;
          continue;
      }

      for (index = 0; index < table_entries; index++)
      {
          bf_entry = (pcie_cfgreg_bitfield_entry *)&(bf_info_table18[index]);
          val_print(ACS_PRINT_TEST, " Write-detect table entry: %d", index);

          /* Skip absent capabilities before establishing IDE and locking the TDI. */
          if (bf_entry->reg_type == PCIE_CAP || bf_entry->reg_type == PCIE_ECAP)
          {
              cap_id = (bf_entry->reg_type == PCIE_CAP) ? bf_entry->cap_id :
                                                        bf_entry->ecap_id;
              if (bf_entry->reg_type == PCIE_ECAP && cap_id == ECID_DVSEC)
                  status = val_pcie_find_da_capability(rp_bdf, &cap_base);
              else
                  status = val_pcie_find_capability(rp_bdf, bf_entry->reg_type,
                                                    cap_id, &cap_base);
              if (status == PCIE_CAP_NOT_FOUND)
              {
                  val_print(ACS_PRINT_WARN, " Skipping absent PCIe capability 0x%x", cap_id);
                  continue;
              }
              if (status != PCIE_SUCCESS)
              {
                  val_print(ACS_PRINT_ERR, " Capability lookup failed for BDF: 0x%x", rp_bdf);
                  test_fail++;
                  continue;
              }
          }

          /* Establish SPDM and matching EP/RP keys before enabling IDE. */
          status = val_pcie_ide_establish(ep_bdf, rp_bdf, count, stream_id,
                                          PCIE_CREATE_BDF_PACKED(ep_bdf));
          if (status == ACS_STATUS_SKIP)
          {
              ide_unsupported = 1;
              break;
          }
          if (status)
          {
              val_print(ACS_PRINT_ERR, " Failed to establish stream for bdf: 0x%x", rp_bdf);
              test_fail++;
              continue;
          }

          status = val_device_lock(ep_bdf);
          if (status)
          {
              val_print(ACS_PRINT_ERR, " TDISP RUN state fail for bdf: 0x%x", rp_bdf);
              test_fail++;
              if (val_ide_set_sel_stream(rp_bdf, count, 0))
                  test_fail++;
              if (val_ide_set_sel_stream(ep_bdf, count, 0))
                  test_fail++;
              continue;
          }

          ep_locked = 1;

          status = val_pcie_write_detect_bitfield_check(rp_bdf, (void *)bf_entry, count);
          if (status && (status != PCIE_CAP_NOT_FOUND))
          {
              val_print(ACS_PRINT_ERR, " Write detect failed for BDF: 0x%x", rp_bdf);
              test_fail++;
              /* Fall through to unlock before next iteration */
          }

          /* Unlock only if we actually locked */
          if (ep_locked) {
              if (val_device_unlock(ep_bdf) != ACS_STATUS_PASS)
                  test_fail++;
              ep_locked = 0;
          }
      }

      /* Disable TDISP in RP; ensure endpoint is not left locked */
      if (ep_locked) {
          if (val_device_unlock(ep_bdf) != ACS_STATUS_PASS)
              test_fail++;
          ep_locked = 0;
      }
      if (val_pcie_disable_tdisp(rp_bdf))
          test_fail++;
  }

  if (ide_unsupported && !test_fail)
      val_set_status(pe_index, "SKIP", 01);
  else if (test_skip)
      val_set_status(pe_index, "SKIP", 01);
  else if (test_fail++)
      val_set_status(pe_index, "FAIL", 01);
  else
      val_set_status(pe_index, "PASS", 01);

  return;

}

uint32_t
da_rmsd_write_detect_property_entry(uint32_t num_pe)
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
