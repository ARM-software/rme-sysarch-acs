/** @file
 * Copyright (c) 2026, Arm Limited or its affiliates. All rights reserved.
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
#include "val/include/val_exerciser.h"
#include "val/include/val_smmu.h"
#include "val/include/val_pe.h"
#include "val/include/val_pgt.h"
#include "val/include/val_iovirt.h"
#include "val/include/val_mem_interface.h"

#define TEST_NAME  "da_rciep_ide_tbit_from_pas"
#define TEST_DESC  "Check RCiEP extracts IDE-Tbit from request PAS        "
#define TEST_RULE  "RGBVTS"

#define TEST_DATA  0xABCD

static
uint32_t
access_rciep_bar_from_pas(uint32_t bdf, uint64_t bar_base, uint64_t pas)
{
  uint32_t pgt_attr_el3;
  uint32_t data;
  uint32_t write_data;
  uint64_t va, size, original_gpi;
  uint32_t status, result = ACS_STATUS_FAIL;

  size = val_get_min_tg();
  if (!size || (size & (size - 1u)) || (bar_base & 3u))
      return ACS_STATUS_FAIL;
  va = val_get_free_va(size);
  if (!va || (va & (size - 1u)))
      return ACS_STATUS_FAIL;

  /* Test PAS handling without an unrelated GPT permission fault. */
  if (val_get_gpt_entry_el3(bar_base, &original_gpi))
      return ACS_STATUS_FAIL;
  if (val_add_gpt_entry_el3(bar_base, GPT_ANY))
      goto cleanup;
  pgt_attr_el3 = LOWER_ATTRS(PGT_ENTRY_ACCESS | SHAREABLE_ATTR(OUTER_SHAREABLE)
                  | GET_ATTR_INDEX(DEV_MEM_nGnRnE) | PGT_ENTRY_AP_RW | PAS_ATTR(pas));
  if (val_add_mmu_entry_el3(va, bar_base & ~(size - 1u), pgt_attr_el3))
  {
      val_print(ACS_PRINT_ERR, " Failed to add MMU entry for Bar address: 0x%lx", bar_base);
      goto cleanup;
  }

  va += bar_base & (size - 1u);
  write_data = TEST_DATA | ((uint32_t)pas << 16);

  shared_data->access_mut = CLEAR;
  shared_data->pas_filter_flag = CLEAR;
  shared_data->num_access = 2;
  shared_data->shared_data_access[0].addr = va;
  shared_data->shared_data_access[0].access_type = WRITE_DATA;
  shared_data->shared_data_access[0].data = write_data;
  shared_data->shared_data_access[1].addr = va;
  shared_data->shared_data_access[1].access_type = READ_DATA;
  shared_data->shared_data_access[1].data = 0;
  status = val_pe_access_mut_el3();
  shared_data->access_mut = CLEAR;
  if (status)
  {
      val_print(ACS_PRINT_ERR, " RCiEP BAR access failed, BDF: 0x%x", bdf);
      val_print(ACS_PRINT_ERR, " PAS: 0x%llx", pas);
      val_print(ACS_PRINT_ERR, " BAR address: 0x%llx", bar_base);
      val_print(ACS_PRINT_ERR, " Access status: 0x%x", status);
      goto cleanup;
  }

  data = shared_data->shared_data_access[1].data;
  if (data != write_data)
  {
      val_print(ACS_PRINT_ERR, " RCiEP BAR readback mismatch, BDF: 0x%x", bdf);
      val_print(ACS_PRINT_ERR, " PAS: 0x%llx", pas);
      val_print(ACS_PRINT_ERR, " Expected data: 0x%x", write_data);
      val_print(ACS_PRINT_ERR, " Observed data: 0x%x", data);
      goto cleanup;
  }

  result = ACS_STATUS_PASS;

cleanup:
  status = val_add_gpt_entry_el3(bar_base, original_gpi);
  if (status)
  {
      val_print(ACS_PRINT_ERR, " RCiEP GPT restoration failed, BDF: 0x%x", bdf);
      val_print(ACS_PRINT_ERR, " PAS: 0x%llx", pas);
      val_print(ACS_PRINT_ERR, " BAR address: 0x%llx", bar_base);
      val_print(ACS_PRINT_ERR, " Original GPI: 0x%llx", original_gpi);
      val_print(ACS_PRINT_ERR, " Restoration status: 0x%x", status);
      result = ACS_STATUS_FAIL;
  }
  return result;
}

/*
 * @brief  The test exercises RGBVTS through RCiEP Memory Requests using
 *         Non-secure/Secure PAS, which require T=0, and Root/Realm PAS,
 *         which require T=1 or the corresponding internal indication.
 * 1. Run on one PE, iterate and initialize PCIe exercisers, and select each
 *    RCiEP exerciser with an MMIO BAR.
 * 2. For each PAS, save the BAR granule's GPT entry and mark it All Access
 *    Permitted so GPT permissions do not reject the test access.
 * 3. Map the BAR with Device memory attributes and the selected PAS,
 *    preserving the BAR's offset within the translation granule.
 * 4. Write a PAS-specific pattern through the EL3 mapping and read it back.
 *    Require both accesses to succeed and the returned data to match.
 * 5. Restore the original GPT entry after each case, including failure paths.
 * 6. Repeat for Non-secure, Secure, Root, and Realm PAS on each selected RCiEP.
 * 7. Report FAIL for setup, access, comparison, or GPT restoration errors.
 *    Report SKIP if no applicable RCiEP BAR is tested; otherwise report PASS
 *    if every executed case succeeds.
 *
 * Note: This test provides best-effort software-visible PAS coverage. An RCiEP
 * may use an internal T-equivalent indication without a PCIe IDE stream, so
 * the test does not require RP IDE setup or an RME-DA DVSEC on the RCiEP.
 * Successful readback does not directly prove the internal T-bit derivation.
 * RGBVTS itself does not require that acceptance.
 * RCiEP type and BAR discovery do not verify TDISP applicability or this access
 * contract.
 */
static
void
payload(void)
{
  uint32_t pe_index;
  uint32_t instance, num_exercisers;
  uint32_t bdf;
  uint64_t bar_base;
  uint32_t test_fail = 0;
  uint32_t tests_executed = 0;
  uint32_t dp_type;
  uint32_t pas_index;
  uint64_t pas_list[] = {
      NONSECURE_PAS,
      SECURE_PAS,
      ROOT_PAS,
      REALM_PAS
  };

  pe_index = val_pe_get_index_mpid(val_pe_get_mpid());
  if (shared_data == NULL)
  {
      val_set_status(pe_index, "FAIL", 01);
      return;
  }
  num_exercisers = val_exerciser_get_info(EXERCISER_NUM_CARDS);
  if (num_exercisers == 0)
  {
      val_print(ACS_PRINT_WARN, " No PCIe exercisers discovered", 0);
      val_set_status(pe_index, "SKIP", 01);
      return;
  }

  if (num_exercisers > MAX_EXERCISER_CARDS)
  {
      val_set_status(pe_index, "FAIL", 01);
      return;
  }

  for (instance = 0; instance < num_exercisers; ++instance)
  {
      if (val_exerciser_init(instance))
          continue;
      bdf = val_exerciser_get_bdf(instance);
      dp_type = val_pcie_device_port_type(bdf);

      if (dp_type == RCiEP)
      {
          bar_base = 0;
          val_pcie_get_mmio_bar(bdf, &bar_base);
          if (!bar_base)
             continue;

          val_print(ACS_PRINT_TEST, " Checking RCiEP BDF: 0x%x", bdf);

          for (pas_index = 0;
               pas_index < (sizeof(pas_list) / sizeof(pas_list[0]));
               pas_index++)
          {
              /*
               * RGBVTS requires the RCiEP or Root Complex to derive the
               * T or T-equivalent indication from the request PAS:
               * Non-secure/Secure -> T = 0; Root/Realm -> T = 1.
               * Generic ACS cannot directly observe this internal indication,
               * so this test provides PAS-matrix MMIO coverage only.
               */
              if (access_rciep_bar_from_pas(bdf, bar_base, pas_list[pas_index]))
              {
                  val_print(ACS_PRINT_ERR, " RCiEP test case failed for PAS: 0x%llx",
                            pas_list[pas_index]);
                  test_fail++;
              } else
              {
                  tests_executed++;
              }
          }
      }
  }

  if (test_fail)
      val_set_status(pe_index, "FAIL", test_fail);
  else if (tests_executed == 0)
      val_set_status(pe_index, "SKIP", 01);
  else
      val_set_status(pe_index, "PASS", 01);
}

uint32_t
da_rciep_ide_tbit_from_pas_entry(uint32_t num_pe)
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
