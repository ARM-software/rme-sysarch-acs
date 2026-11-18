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

#define TEST_NAME "da_rp_ide_tbit_from_pas"
#define TEST_DESC  "Check RP derives IDE-Tbit from outgoing request PAS     "
#define TEST_RULE  "RCFQBW"

#define TEST_DATA  0xABCD

/* Exercise one Memory Request PAS using the current IDE/SPDM lifecycle. */
static
uint32_t
perform_bar_access_from_pas(uint32_t bdf, uint32_t rp_bdf, uint64_t bar_base,
                            uint64_t pas)
{
  uint32_t attr, bar_index, status, write_data;
  uint32_t address_configured = 0, lock_attempted = 0, ide_attempted = 0;
  uint32_t result = ACS_STATUS_FAIL;
  uint64_t size, va, bar_size, original_gpi;
  const uint32_t stream = 1;

  size = val_get_min_tg();
  if (!size || (size & (size - 1u)) || (bar_base & 3u))
      return ACS_STATUS_FAIL;
  va = val_get_free_va(size);
  if (!va || (va & (size - 1u)))
      return ACS_STATUS_FAIL;

  /* Permit each PAS without making GPT rejection the test's outcome. */
  if (val_get_gpt_entry_el3(bar_base, &original_gpi))
      return ACS_STATUS_FAIL;
  if (val_add_gpt_entry_el3(bar_base, GPT_ANY))
      goto cleanup;

  attr = LOWER_ATTRS(PGT_ENTRY_ACCESS | SHAREABLE_ATTR(OUTER_SHAREABLE)
                    | GET_ATTR_INDEX(DEV_MEM_nGnRnE) | PGT_ENTRY_AP_RW | PAS_ATTR(pas));
  if (val_add_mmu_entry_el3(va, bar_base & ~(size - 1u), attr))
      goto cleanup;
  va += bar_base & (size - 1u);

  if (pas == ROOT_PAS || pas == REALM_PAS)
  {
      /* Bind address-routed BAR traffic before enabling and locking IDE. */
      if (val_pcie_get_bar_index(bdf, bar_base, &bar_index) ||
          val_pcie_get_memory_bar_size(bdf, bar_index, &bar_size) ||
          !bar_size || bar_base > ~(uint64_t)0 - (bar_size - 1u) ||
          val_ide_set_sel_stream(rp_bdf, stream, 0))
          goto cleanup;

      /* Include partial programming in cleanup. */
      address_configured = 1;
      if (val_ide_program_address_range(rp_bdf, stream, bar_base,
                                        bar_base + bar_size - 1u, 1))
          goto cleanup;

      /* The current helper provisions matching keys and takes a packed RID. */
      ide_attempted = 1;
      status = val_pcie_ide_establish(bdf, rp_bdf, stream, val_generate_stream_id(),
                                      PCIE_CREATE_BDF_PACKED(bdf));
      if (status == ACS_STATUS_SKIP)
      {
          result = ACS_STATUS_SKIP;
          goto cleanup;
      }
      if (status != ACS_STATUS_PASS)
          goto cleanup;

      lock_attempted = 1;
      if (val_ide_set_sel_stream_lock(rp_bdf, stream, 1) || val_device_lock(bdf))
          goto cleanup;
  }

  /* Access success is indirect evidence; the IDE T-bit is not observable here. */
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
  if (status || shared_data->shared_data_access[1].data != write_data)
      goto cleanup;
  result = ACS_STATUS_PASS;

cleanup:
  /* Unlock before shared teardown disables streams and closes the SPDM session. */
  if (lock_attempted && val_ide_set_sel_stream_lock(rp_bdf, stream, 0))
      result = ACS_STATUS_FAIL;
  if (ide_attempted && val_device_unlock(bdf) != ACS_STATUS_PASS)
      result = ACS_STATUS_FAIL;
  if (address_configured)
  {
      if (val_ide_set_sel_stream(rp_bdf, stream, 0))
          result = ACS_STATUS_FAIL;
      if (val_ide_program_address_range(rp_bdf, stream, 0, 0, 0))
          result = ACS_STATUS_FAIL;
  }
  if (val_add_gpt_entry_el3(bar_base, original_gpi))
      result = ACS_STATUS_FAIL;
  return result;
}

/*
 * @brief  The test exercises RCFQBW through outgoing Memory Requests using
 *         Non-secure/Secure PAS, which require IDE-Tbit 0, and Root/Realm PAS,
 *         which require IDE-Tbit 1.
 * 1. Run on one PE and select an initialized PCIe exerciser Endpoint with an
 *    MMIO BAR and an associated Root Port.
 * 2. Verify the Root Port implements the RME-DA DVSEC and enable TDISP_EN.
 * 3. For each PAS, save the BAR granule's GPT entry, mark it All Access
 *    Permitted, and map the BAR with Device memory attributes and that PAS.
 * 4. For Root/Realm PAS, associate the full BAR range with the RP Selective
 *    IDE stream and provision matching EP/RP keys through the shared helper.
 *    Lock the RP stream and transition the Endpoint to TDISP RUN state.
 * 5. Write a PAS-specific pattern through the EL3 mapping and read it back.
 *    Require both accesses to succeed and the returned data to match.
 * 6. For protected cases, clear the RP stream lock, tear down IDE/TDISP and
 *    the SPDM session, and invalidate the BAR address association.
 *    Restore the original GPT entry after every PAS case.
 * 7. Repeat for Non-secure, Secure, Root, and Realm PAS, then disable TDISP_EN.
 *    Report FAIL for setup, access, comparison, or cleanup errors.
 * 8. Skip protected cases when the IDE helper reports an unsupported backend.
 *    Report SKIP if any required PAS case skips or no case executes. Report
 *    PASS only when all required PAS cases succeed, with FAIL taking precedence.
 *
 * Note: This test provides best-effort software-visible Memory Request coverage.
 * It does not directly observe the transmitted IDE-Tbit or cover Configuration
 * Requests. Completing all PAS cases still provides only functional coverage.
 */
static
void
payload(void)
{
  uint32_t pe_index = val_pe_get_index_mpid(val_pe_get_mpid());
  uint32_t instance, num_exercisers, bdf, rp_bdf, da_cap_base;
  uint32_t case_index, status;
  uint32_t test_fail = 0, tests_executed = 0, test_skip = 0;
  uint64_t bar_base;
  const uint64_t pas_list[] = {NONSECURE_PAS, SECURE_PAS, ROOT_PAS, REALM_PAS};

  if (shared_data == NULL)
  {
      val_set_status(pe_index, "FAIL", 01);
      return;
  }

  num_exercisers = val_exerciser_get_info(EXERCISER_NUM_CARDS);
  for (instance = 0; instance < num_exercisers; ++instance)
  {
      if (val_exerciser_init(instance))
          continue;
      bdf = val_exerciser_get_bdf(instance);
      if (val_pcie_device_port_type(bdf) != EP)
          continue;
      bar_base = 0;
      val_pcie_get_mmio_bar(bdf, &bar_base);
      if (!bar_base || val_pcie_get_rootport(bdf, &rp_bdf))
          continue;

      val_print(ACS_PRINT_TEST, " Checking BDF: 0x%x", bdf);
      if (val_pcie_find_da_capability(rp_bdf, &da_cap_base) != PCIE_SUCCESS)
      {
          val_print(ACS_PRINT_ERR, " PCIe DA DVSEC capability not present: 0x%x", rp_bdf);
          test_fail++;
          continue;
      }
      if (val_pcie_enable_tdisp(rp_bdf))
      {
          test_fail++;
          goto cleanup_tdisp;
      }

      for (case_index = 0; case_index < sizeof(pas_list) / sizeof(pas_list[0]); ++case_index)
      {
          status = perform_bar_access_from_pas(bdf, rp_bdf, bar_base, pas_list[case_index]);
          if (status == ACS_STATUS_SKIP)
          {
              test_skip = 1;
              val_print(ACS_PRINT_WARN, " IDE backend unavailable for PAS: 0x%llx",
                        pas_list[case_index]);
          } else if (status != ACS_STATUS_PASS)
          {
              val_print(ACS_PRINT_ERR, " BAR access or cleanup failed for PAS: 0x%llx",
                        pas_list[case_index]);
              test_fail++;
              break;
          } else
              tests_executed++;
      }

cleanup_tdisp:
      if (val_pcie_disable_tdisp(rp_bdf))
          test_fail++;
      if (test_fail)
          break;
  }

  if (test_fail)
      val_set_status(pe_index, "FAIL", test_fail);
  else if (test_skip || tests_executed == 0)
      val_set_status(pe_index, "SKIP", 01);
  else
      val_set_status(pe_index, "PASS", 01);
}

uint32_t
da_rp_ide_tbit_from_pas_entry(uint32_t num_pe)
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
