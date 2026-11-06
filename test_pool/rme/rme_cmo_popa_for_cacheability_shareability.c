/** @file
 * Copyright (c) 2023-2026, Arm Limited or its affiliates. All rights reserved.
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
#include "val/include/val_pe.h"
#include "val/include/val_common.h"
#include "val/include/val_test_entry.h"
#include "val/include/val_interface.h"
#include "val/include/val_el32.h"
#include "val/include/val_mem_interface.h"
#include "val/include/val_memory.h"

#define TEST_NAME  "rme_cmo_popa_for_cacheability_shareability"
#define TEST_DESC  "PoPA CMO applies to caches before PoPA              "
#define TEST_RULE  "RFXQCD"

/*
 * @brief  Check software-visible Secure data preservation after a PoPA CMO.
 * 1. PA1 is marked as All Access Permitted.
 * 2. VA1 is mapped to PA1 as Secure PAS with Write-Back cacheable attributes.
 * 3. VA2 is mapped to PA1 as Non-secure PAS with non-cacheable attributes.
 * 4. Issue CMO to PoPA for PA1 Non-secure PAS and wait for completion.
 * 5. Read VA1 to capture data1.
 * 6. Read VA2 to capture data2.
 * 7. Store data3 through VA1.
 * 8. Issue the Secure PoPA CMO, then read VA1 and verify it still holds data3.
 * 9. Issue the Non-secure PoPA CMO, then read VA2. At the end, require its value
 *    to differ from data1, data2 and data3, and the Secure readback to equal data3.
 */
static
void payload(void)
{

  uint32_t index = val_pe_get_index_mpid(val_pe_get_mpid());
  uint32_t attr_sec, attr_ns, access_status;
  uint32_t gpt_ready = CLEAR, gpt_restore_needed = CLEAR;
  uint64_t PA, VA_S, VA_NS, size;
  uint64_t data1, data2, data3, data4;
  uint64_t data_s_after_cmo, original_gpi;

  if (!shared_data) {
      val_print(ACS_PRINT_ERR, " Shared data is unavailable", 0);
      val_set_status(index, "FAIL", 13);
      return;
  }
  val_memory_clear_el3_access_state();

  size = val_get_min_tg();
  PA = val_get_free_pa(size, size);
  VA_S = val_get_free_va(size);
  VA_NS = val_get_free_va(size);
  /* PA allocation returns 1 on failure; VA allocation returns 0. */
  if (PA == 1 || !VA_S || !VA_NS || (PA & (size - 1)) ||
      (VA_S & (size - 1)) || (VA_NS & (size - 1)) || VA_S == VA_NS) {
      val_print(ACS_PRINT_ERR, " Failed to allocate distinct aligned test mappings", 0);
      val_set_status(index, "FAIL", 14);
      return;
  }
  data3 = RANDOM_DATA_2;

  if (val_get_gpt_entry_el3(PA, &original_gpi)) {
      val_print(ACS_PRINT_ERR, " Failed to read original GPT entry", 0);
      val_set_status(index, "FAIL", 15);
      return;
  }

  attr_sec = LOWER_ATTRS(PGT_ENTRY_ACCESS | SHAREABLE_ATTR(OUTER_SHAREABLE)
                         | GET_ATTR_INDEX(WRITE_BACK_NT) | PGT_ENTRY_AP_RW
                         | PAS_ATTR(SECURE_PAS));
  attr_ns = LOWER_ATTRS(PGT_ENTRY_ACCESS | SHAREABLE_ATTR(OUTER_SHAREABLE)
                        | GET_ATTR_INDEX(NON_CACHEABLE) | PGT_ENTRY_AP_RW
                        | PAS_ATTR(NONSECURE_PAS));

  /* GPT_ANY allows both Secure and Non-secure aliases to target the same PA. */
  /* Arm restoration before the call: an error need not mean no state changed. */
  gpt_restore_needed = (original_gpi != GPT_ANY);
  if (val_add_gpt_entry_el3(PA, GPT_ANY)) {
      val_print(ACS_PRINT_ERR, " Failed to add GPT entry for PA 0x%lx", PA);
      val_set_status(index, "FAIL", 01);
      goto cleanup;
  }

  gpt_ready = SET;

  if (val_add_mmu_entry_el3(VA_S, PA, attr_sec)) {
      val_print(ACS_PRINT_ERR, " Failed to add Secure MMU entry for VA 0x%lx", VA_S);
      val_set_status(index, "FAIL", 02);
      goto cleanup;
  }

  if (val_add_mmu_entry_el3(VA_NS, PA, attr_ns)) {
      val_print(ACS_PRINT_ERR, " Failed to add Non-secure MMU entry for VA 0x%lx", VA_NS);
      val_set_status(index, "FAIL", 03);
      goto cleanup;
  }

  /*
   * Clear any existing Non-secure state for the PA before capturing the known
   * Secure and Non-secure views used by the final comparison.
   */
  val_print(ACS_PRINT_TEST, " Issuing CMO to PoPA for Non-secure PAS", 0);
  if (val_data_cache_ops_by_pa_el3(PA, NONSECURE_PAS)) {
      val_print(ACS_PRINT_ERR, " Failed to issue Non-secure CMO for PA 0x%lx", PA);
      val_set_status(index, "FAIL", 04);
      goto cleanup;
  }

  val_print(ACS_PRINT_TEST, " Reading Secure and Non-secure views", 0);
  val_memory_clear_el3_access_state();
  shared_data->num_access = 2;
  shared_data->shared_data_access[0].addr = VA_S;
  shared_data->shared_data_access[0].data = INIT_DATA;
  shared_data->shared_data_access[0].access_type = READ_DATA;
  shared_data->shared_data_access[1].addr = VA_NS;
  shared_data->shared_data_access[1].data = INIT_DATA;
  shared_data->shared_data_access[1].access_type = READ_DATA;

  access_status = val_pe_access_mut_el3();
  val_memory_clear_el3_access_state();
  if (access_status) {
      val_print(ACS_PRINT_ERR, " Failed to read Secure/Non-secure aliases", 0);
      val_set_status(index, "FAIL", 05);
      goto cleanup;
  }

  data1 = shared_data->shared_data_access[0].data;
  data2 = shared_data->shared_data_access[1].data;

  val_print(ACS_PRINT_TEST, " Writing data through Secure PAS", 0);
  val_memory_clear_el3_access_state();
  shared_data->num_access = 1;
  shared_data->shared_data_access[0].addr = VA_S;
  shared_data->shared_data_access[0].data = data3;
  shared_data->shared_data_access[0].access_type = WRITE_DATA;

  access_status = val_pe_access_mut_el3();
  val_memory_clear_el3_access_state();
  if (access_status) {
      val_print(ACS_PRINT_ERR, " Failed to write Secure VA 0x%lx", VA_S);
      val_set_status(index, "FAIL", 06);
      goto cleanup;
  }

  /* Verify Secure data preservation before observing the Non-secure view. */
  val_print(ACS_PRINT_TEST, " Issuing CMO to PoPA for Secure PAS", 0);
  if (val_data_cache_ops_by_pa_el3(PA, SECURE_PAS)) {
      val_print(ACS_PRINT_ERR, " Failed to issue Secure CMO for PA 0x%lx", PA);
      val_set_status(index, "FAIL", 07);
      goto cleanup;
  }

  /* Read through the same PAS before any further cache maintenance. */
  val_print(ACS_PRINT_TEST, " Reading Secure view after Secure CMO", 0);
  val_memory_clear_el3_access_state();
  shared_data->num_access = 1;
  shared_data->shared_data_access[0].addr = VA_S;
  shared_data->shared_data_access[0].data = ~data3;
  shared_data->shared_data_access[0].access_type = READ_DATA;

  access_status = val_pe_access_mut_el3();
  val_memory_clear_el3_access_state();
  if (access_status) {
      val_print(ACS_PRINT_ERR, " Failed to read Secure VA 0x%lx", VA_S);
      val_set_status(index, "FAIL", 12);
      goto cleanup;
  }

  data_s_after_cmo = shared_data->shared_data_access[0].data;

  val_print(ACS_PRINT_TEST, " Issuing CMO to PoPA for Non-secure PAS", 0);
  if (val_data_cache_ops_by_pa_el3(PA, NONSECURE_PAS)) {
      val_print(ACS_PRINT_ERR, " Failed to issue Non-secure CMO for PA 0x%lx", PA);
      val_set_status(index, "FAIL", 8);
      goto cleanup;
  }

  val_print(ACS_PRINT_TEST, " Reading Non-secure view after Secure update", 0);
  val_memory_clear_el3_access_state();
  shared_data->num_access = 1;
  shared_data->shared_data_access[0].addr = VA_NS;
  shared_data->shared_data_access[0].data = data2;
  shared_data->shared_data_access[0].access_type = READ_DATA;

  access_status = val_pe_access_mut_el3();
  val_memory_clear_el3_access_state();
  if (access_status) {
      val_print(ACS_PRINT_ERR, " Failed to read Non-secure VA 0x%lx", VA_NS);
      val_set_status(index, "FAIL", 9);
      goto cleanup;
  }

  data4 = shared_data->shared_data_access[0].data;
  val_print(ACS_PRINT_DEBUG, " Initial Secure data = 0x%lx", data1);
  val_print(ACS_PRINT_DEBUG, " Initial Non-secure data = 0x%lx", data2);
  val_print(ACS_PRINT_DEBUG, " Secure write data = 0x%lx", data3);
  val_print(ACS_PRINT_DEBUG, " Secure data after CMO to PoPA = 0x%lx", data_s_after_cmo);
  val_print(ACS_PRINT_DEBUG, " Non-secure data after CMO to PoPA = 0x%lx", data4);

  //Compare the data and set the test result accordingly
  if (data4 != data2 && data4 != data3 && data4 != data1 && data_s_after_cmo == data3)
      val_set_status(index, "PASS", 01);
  else
      val_set_status(index, "FAIL", 11);

cleanup:
  val_memory_clear_el3_access_state();
  /* Remove cached test data before restoring the original protection. */
  if (gpt_ready == SET) {
      if (val_data_cache_ops_by_pa_el3(PA, SECURE_PAS)) {
          val_print(ACS_PRINT_ERR, " Failed to clean Secure test state", 0);
          val_set_status(index, "FAIL", 16);
      }
      if (val_data_cache_ops_by_pa_el3(PA, NONSECURE_PAS)) {
          val_print(ACS_PRINT_ERR, " Failed to clean Non-secure test state", 0);
          val_set_status(index, "FAIL", 17);
      }
  }
  if (gpt_restore_needed && val_add_gpt_entry_el3(PA, original_gpi)) {
      val_print(ACS_PRINT_ERR, " Failed to restore original GPT entry", 0);
      val_set_status(index, "FAIL", 18);
  }

  return;

}

uint32_t
rme_cmo_popa_for_cacheability_shareability_entry(uint32_t num_pe)
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
