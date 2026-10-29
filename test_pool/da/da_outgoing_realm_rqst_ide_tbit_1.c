/** @file
 * Copyright (c) 2025-2026, Arm Limited or its affiliates. All rights reserved.
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

#include "val/include/val_el32.h"
#include "val/include/val_pcie.h"
#include "val/include/val_memory.h"
#include "val/include/val_pcie_enumeration.h"
#include "val/include/val_exerciser.h"
#include "val/include/val_smmu.h"
#include "val/include/val_pe.h"
#include "val/include/val_pgt.h"
#include "val/include/val_iovirt.h"
#include "val/include/val_mem_interface.h"
#include "val/include/val_da.h"

#define TEST_NAME  "da_outgoing_realm_rqst_ide_tbit_1"
#define TEST_DESC  "Checking IDE-Tbit ==1 for outgoing Realm request       "
#define TEST_RULE  "RCFQBW, RGBVTS"

#define TEST_DATA  0xABCD

static
void
payload(void)
{
  uint32_t pe_index;
  uint32_t instance, num_exercisers;
  uint32_t bdf, rp_bdf;
  uint32_t da_cap_base;
  uint64_t bar_base, bar_size, original_gpi;
  uint32_t bar_index;
  uint32_t pgt_attr_el3;
  uint32_t data;
  uint64_t va;
  uint32_t test_fail = 0;
  uint32_t test_skip = 1;
  uint32_t stream_id;
  uint32_t count, status;
  uint32_t tdisp_enabled, address_configured, rp_lock_attempted;
  uint32_t gpt_modified;

  pe_index = val_pe_get_index_mpid(val_pe_get_mpid());
  num_exercisers = val_exerciser_get_info(EXERCISER_NUM_CARDS);
  if (num_exercisers == 0)
  {
      val_print(ACS_PRINT_WARN, " No exerciser cards discovered", 0);
      val_set_status(pe_index, "SKIP", 01);
      return;
  }

  for (instance = 0; instance < num_exercisers; ++instance)
  {
      if (val_exerciser_init(instance))
          continue;

      bdf = val_exerciser_get_bdf(instance);

      tdisp_enabled = 0;
      address_configured = 0;
      rp_lock_attempted = 0;
      gpt_modified = 0;

      /* Get the BAR of the Endpoint */
      val_pcie_get_mmio_bar(bdf, &bar_base);

      /* Skip this function if it doesn't have mmio BAR */
      if (!bar_base)
         continue;

      /* Get the Root Port for the exerciser. */
      if (val_pcie_get_rootport(bdf, &rp_bdf))
         continue;

      val_print(ACS_PRINT_TEST, " Checking BDF: 0x%x", bdf);

      /* Get the PCIE DVSEC Capability register */
      if (val_pcie_find_da_capability(rp_bdf, &da_cap_base) != PCIE_SUCCESS)
      {
          val_print(ACS_PRINT_ERR,
                          " PCIe DA DVSEC capability not present,bdf 0x%x", rp_bdf);
          test_fail++;
          continue;
      }

      count = 1;

      /* Enable the TDISP_EN bit in the RME-DA DVSEC register */
      if (val_pcie_enable_tdisp(rp_bdf))
      {
          val_print(ACS_PRINT_ERR, " Unable to set tdisp_en for BDF: 0x%x", bdf);
          test_fail++;
          goto ide_cleanup;
      }
      tdisp_enabled = 1;

      /* Allow Realm access to the BAR granule and preserve its original GPI. */
      if (val_get_gpt_entry_el3(bar_base, &original_gpi) ||
          val_add_gpt_entry_el3(bar_base, GPT_REALM))
      {
          val_print(ACS_PRINT_ERR, " Unable to configure BAR GPT permission: 0x%lx", bar_base);
          test_fail++;
          goto ide_cleanup;
      }
      gpt_modified = 1;

      /* Map the Bar address to realm PAS */
      va = val_get_free_va(val_get_min_tg());
      pgt_attr_el3 = LOWER_ATTRS(PGT_ENTRY_ACCESS | SHAREABLE_ATTR(OUTER_SHAREABLE)
                      | GET_ATTR_INDEX(DEV_MEM_nGnRnE) | PGT_ENTRY_AP_RW | PAS_ATTR(REALM_PAS));
      if (val_add_mmu_entry_el3(va, bar_base, pgt_attr_el3))
      {
          test_fail++;
          goto ide_cleanup;
      }

      stream_id = val_generate_stream_id();

      /* Address-routed Realm traffic needs a valid RP BAR association.
       * Program it while the stream is disabled, before IDE and TDISP lock.
       */
      if (val_pcie_get_bar_index(bdf, bar_base, &bar_index) ||
          val_pcie_get_memory_bar_size(bdf, bar_index, &bar_size) ||
          !bar_size || bar_base > ~(uint64_t)0 - (bar_size - 1u) ||
          val_ide_set_sel_stream(rp_bdf, count, 0))
      {
          val_print(ACS_PRINT_ERR, " Unable to prepare RP BAR association: 0x%x", rp_bdf);
          test_fail++;
          goto ide_cleanup;
      }
      /* Track partial programming so cleanup also invalidates it on failure. */
      address_configured = 1;
      if (val_ide_program_address_range(rp_bdf, count, bar_base,
                                        bar_base + bar_size - 1u, 1))
      {
          val_print(ACS_PRINT_ERR, " Unable to program RP BAR association: 0x%x", rp_bdf);
          test_fail++;
          goto ide_cleanup;
      }

      /* Establish IDE Stream between RootPort and Endpoint*/
      /* Establish SPDM and matching EP/RP keys before enabling IDE. */
      status = val_pcie_ide_establish(bdf, rp_bdf, count, stream_id,
                                      PCIE_CREATE_BDF_PACKED(bdf));
      if (status == ACS_STATUS_SKIP)
      {
          goto ide_cleanup;
      }
      if (status != ACS_STATUS_PASS)
      {
          val_print(ACS_PRINT_ERR, " Failed to establish stream for bdf: 0x%x", bdf);
          test_fail++;
          goto ide_cleanup;
      }

      /* RDVKPF requires the matching RP stream to be Locked and Secure. */
      rp_lock_attempted = 1;
      if (val_ide_set_sel_stream_lock(rp_bdf, count, 1))
      {
          val_print(ACS_PRINT_ERR, " Unable to lock RP IDE stream: 0x%x", rp_bdf);
          test_fail++;
          goto ide_cleanup;
      }

      /* Transition the Endpoint to TDISP RUN state */
      if (val_device_lock(bdf))
      {
          val_print(ACS_PRINT_ERR, " Failed to lock the device: 0x%lx", bdf);
          test_fail++;
          goto ide_cleanup;
      }

      test_skip = 0;
      data = 0;

      /* Write and read the BAR using the Realm PAS mapping at EL3. */
      shared_data->num_access = 2;
      shared_data->shared_data_access[0].addr = va;
      shared_data->shared_data_access[0].access_type = WRITE_DATA;
      shared_data->shared_data_access[0].data = TEST_DATA;
      shared_data->shared_data_access[1].addr = va;
      shared_data->shared_data_access[1].access_type = READ_DATA;
      if (val_pe_access_mut_el3())
      {
        val_print(ACS_PRINT_ERR, " MUT Access failed for va: 0x%lx", va);
        test_fail++;
      }
      data = shared_data->shared_data_access[1].data;

      /* The Request should be accepted by the RP */
      if (data != TEST_DATA)
      {
          val_print(ACS_PRINT_ERR, " Request rejected by RP BDF: %x", bdf);
          test_fail++;
      }

ide_cleanup:
      /* Unlock before shared teardown writes the RP stream registers. */
      if (rp_lock_attempted && val_ide_set_sel_stream_lock(rp_bdf, count, 0))
      {
          val_print(ACS_PRINT_ERR, " Unable to unlock RP IDE stream: 0x%x", rp_bdf);
          test_fail++;
      }
      /* Shared cleanup stops TDISP and IDE keys, then closes SPDM. */
      if (val_device_unlock(bdf) != ACS_STATUS_PASS)
          test_fail++;
      if (address_configured)
      {
          /* Shared teardown disables the stream; also handle partial setup. */
          if (val_ide_set_sel_stream(rp_bdf, count, 0) ||
              val_ide_program_address_range(rp_bdf, count, 0, 0, 0))
          {
              val_print(ACS_PRINT_ERR, " Unable to clear RP BAR association: 0x%x", rp_bdf);
              test_fail++;
          }
      }
      if (tdisp_enabled)
      {
          if (val_pcie_disable_tdisp(rp_bdf))
              test_fail++;
          tdisp_enabled = 0;
      }
      if (gpt_modified && val_add_gpt_entry_el3(bar_base, original_gpi))
      {
          val_print(ACS_PRINT_ERR, " Unable to restore BAR GPT permission: 0x%lx", bar_base);
          test_fail++;
      }
  }

  if (test_fail)
      val_set_status(pe_index, "FAIL", test_fail);
  else if (test_skip)
      val_set_status(pe_index, "SKIP", 01);
  else
      val_set_status(pe_index, "PASS", 01);
}

uint32_t
da_outgoing_realm_rqst_ide_tbit_1_entry(uint32_t num_pe)
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
