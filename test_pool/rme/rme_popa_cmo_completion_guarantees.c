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
#include "val/include/val_pe.h"
#include "val/include/val_common.h"

#include "val/include/val_test_entry.h"
#include "val/include/val_interface.h"
#include "val/include/val_el32.h"
#include "val/include/val_mem_interface.h"

#define TEST_NAME  "rme_popa_cmo_completion_guarantees"
#define TEST_DESC  "Check PoPA CMO clean and invalidation completion behavior "
#define TEST_RULE  "RLCXDB"

/*
 * @brief  The test validates software-visible PoPA CMO completion behavior.
 * 1. PA1 is marked as All Access Permitted.
 * 2. VA1 is mapped to PA1 as Secure PAS with cacheable attributes.
 * 3. VA2 is mapped to PA1 as Non-secure PAS with cacheable attributes.
 * 4. Write a known initial value through VA2, issue CMO to PoPA for PA1
 *    Non-secure PAS and wait for completion.
 * 5. Read VA1 to capture the Secure view of PA1.
 * 6. Read VA2 and verify that it matches the known initial value.
 * 7. Store data3 in VA1.
 * 8. Issue CMO to PoPA for PA1 Secure PAS, followed by Non-secure PAS, and
 *    wait for completion of each operation.
 * 9. Read VA2 and verify that it returns data4, where data4 != data2.
 * 10. Store data5 in VA2, distinct from data4 and data3.
 * 11. Issue CMO to PoPA for PA1 Non-secure PAS and wait for completion.
 * 12. Read VA1, without issuing another Secure CMO, and verify that it returns
 *     data6, where data6 != data3. Do not read VA1 between the Secure CMO
 *     and this observation, as that could repopulate the Secure cache.
 * 13. Read VA2 and verify that it returns data5 after the Non-secure CMO.
 *
 * Note: This test provides best-effort software-visible validation of the PoPA
 * CMO clean and invalidation guarantees. Cross-PAS observations rely on the
 * platform's memory-encryption behavior. Direct observation of internal
 * cached/transient state before and after PoPA requires implementation-level
 * visibility.
 */
static
uint32_t run_popa_completion_cross_pas_check(void)
{
  uint32_t attr_sec, attr_ns;
  uint64_t data1, data2, data3, data4, data5, data6;
  const uint64_t initial_ns_data = RANDOM_DATA_1;
  uint64_t ns_readback;
  uint64_t PA, VA_S, VA_NS, size;

  size = val_get_min_tg();
  PA = val_get_free_pa(size, size);
  VA_S = val_get_free_va(size);
  VA_NS = val_get_free_va(size);
  data3 = RANDOM_DATA_2;

  attr_sec = LOWER_ATTRS(PGT_ENTRY_ACCESS | SHAREABLE_ATTR(INNER_SHAREABLE)
                         | GET_ATTR_INDEX(WRITE_BACK_NT) | PGT_ENTRY_AP_RW
                         | PAS_ATTR(SECURE_PAS));
  attr_ns = LOWER_ATTRS(PGT_ENTRY_ACCESS | SHAREABLE_ATTR(INNER_SHAREABLE)
                        | GET_ATTR_INDEX(WRITE_BACK_NT) | PGT_ENTRY_AP_RW
                        | PAS_ATTR(NONSECURE_PAS));

  if (val_add_gpt_entry_el3(PA, GPT_ANY)) {
      val_print(ACS_PRINT_ERR, "\n       Failed to add GPT entry for PA 0x%lx", PA);
      return 1;
  }

  if (val_add_mmu_entry_el3(VA_S, PA, attr_sec))
  {
      val_print(ACS_PRINT_ERR, "\n  Failed to add MMU entry for VA1 0x%lx", VA_S);
      return 2;
  }

  if (val_add_mmu_entry_el3(VA_NS, PA, attr_ns))
  {
      val_print(ACS_PRINT_ERR, "\n  Failed to add MMU entry for VA2 0x%lx", VA_NS);
      return 3;
  }

  val_print(ACS_PRINT_TEST, " Initializing Non-secure data = 0x%lx", initial_ns_data);
  shared_data->num_access = 1;
  shared_data->shared_data_access[0].addr = VA_NS;
  shared_data->shared_data_access[0].data = initial_ns_data;
  shared_data->shared_data_access[0].access_type = WRITE_DATA;

  if (val_pe_access_mut_el3()) {
      val_print(ACS_PRINT_ERR, " Failed to initialize Non-secure VA = 0x%lx", VA_NS);
      return 16;
  }

  val_print(ACS_PRINT_TEST, " Issuing CMO to PoPA for Non-secure PAS", 0);
  if (val_data_cache_ops_by_pa_el3(PA, NONSECURE_PAS)) {
      val_print(ACS_PRINT_ERR, " Failed to issue Non-secure CMO for PA 0x%llx", PA);
      return 4;
  }

  val_print(ACS_PRINT_TEST, " Reading Secure and Non-secure views", 0);
  shared_data->num_access = 2;
  shared_data->shared_data_access[0].addr = VA_S;
  shared_data->shared_data_access[0].access_type = READ_DATA;
  shared_data->shared_data_access[1].addr = VA_NS;
  shared_data->shared_data_access[1].data = initial_ns_data ^ 1;
  shared_data->shared_data_access[1].access_type = READ_DATA;

  if (val_pe_access_mut_el3())
  {
      val_print(ACS_PRINT_ERR, " Failed to read Secure/Non-secure aliases", 0);
      return 5;
  }

  data1 = shared_data->shared_data_access[0].data;
  data2 = shared_data->shared_data_access[1].data;
  if (data2 != initial_ns_data) {
      val_print(ACS_PRINT_ERR, " Initial Non-secure readback mismatch", 0);
      val_print(ACS_PRINT_DEBUG, " Expected data = 0x%lx", initial_ns_data);
      val_print(ACS_PRINT_DEBUG, " Observed data = 0x%lx", data2);
      return 17;
  }

  val_print(ACS_PRINT_TEST, " Writing data through Secure PAS", 0);
  shared_data->num_access = 1;
  shared_data->shared_data_access[0].addr = VA_S;
  shared_data->shared_data_access[0].data = data3;
  shared_data->shared_data_access[0].access_type = WRITE_DATA;

  if (val_pe_access_mut_el3()) {
      val_print(ACS_PRINT_ERR, " Failed to write Secure VA = 0x%lx", VA_S);
      return 6;
  }

  val_print(ACS_PRINT_TEST, " Issuing CMO to PoPA for Secure PAS", 0);
  if (val_data_cache_ops_by_pa_el3(PA, SECURE_PAS)) {
      val_print(ACS_PRINT_ERR, " Failed to issue Secure CMO for PA 0x%llx", PA);
      return 7;
  }

  val_print(ACS_PRINT_TEST, " Issuing CMO to PoPA for Non-secure PAS", 0);
  if (val_data_cache_ops_by_pa_el3(PA, NONSECURE_PAS)) {
      val_print(ACS_PRINT_ERR, " Failed to issue Non-secure CMO for PA 0x%llx", PA);
      return 8;
  }

  val_print(ACS_PRINT_TEST, " Reading Non-secure view after Secure update", 0);
  shared_data->num_access = 1;
  shared_data->shared_data_access[0].addr = VA_NS;
  shared_data->shared_data_access[0].access_type = READ_DATA;

  if (val_pe_access_mut_el3())
  {
      val_print(ACS_PRINT_ERR, " Failed to read Non-secure VA = 0x%lx", VA_NS);
      return 9;
  }

  data4 = shared_data->shared_data_access[0].data;
  if (data4 == data2) {
      val_print(ACS_PRINT_ERR, " Non-secure view did not change after CMO sequence", 0);
      return 10;
  }

  if (data4 == data3) {
      val_print(ACS_PRINT_ERR, " Non-secure view returned Secure plaintext", 0);
      return 11;
  }

  data5 = RANDOM_DATA_3;
  if ((data5 == data4) || (data5 == data3))
      data5 = RANDOM_DATA_4;

  val_print(ACS_PRINT_TEST, " Writing new data through Non-secure PAS", 0);
  shared_data->num_access = 1;
  shared_data->shared_data_access[0].addr = VA_NS;
  shared_data->shared_data_access[0].data = data5;
  shared_data->shared_data_access[0].access_type = WRITE_DATA;

  if (val_pe_access_mut_el3())
  {
      val_print(ACS_PRINT_ERR, " Failed to write Non-secure VA = 0x%lx", VA_NS);
      return 12;
  }

  val_print(ACS_PRINT_TEST, " Issuing CMO to PoPA for Non-secure PAS", 0);
  if (val_data_cache_ops_by_pa_el3(PA, NONSECURE_PAS)) {
      val_print(ACS_PRINT_ERR, " Failed to issue Non-secure CMO for PA 0x%llx", PA);
      return 13;
  }

  /*
   * Observe the earlier Secure CMO's invalidation before any additional
   * readback. An intervening Secure read could refill the line with data3;
   * the Non-secure CMO is not required to invalidate that Secure copy.
   */
  val_print(ACS_PRINT_TEST, " Reading Secure view after Non-secure update", 0);
  shared_data->num_access = 1;
  shared_data->shared_data_access[0].addr = VA_S;
  shared_data->shared_data_access[0].access_type = READ_DATA;

  if (val_pe_access_mut_el3())
  {
      val_print(ACS_PRINT_ERR, " Failed to read Secure VA = 0x%lx", VA_S);
      return 14;
  }

  data6 = shared_data->shared_data_access[0].data;
  val_print(ACS_PRINT_DEBUG, " Initial Secure data = 0x%lx", data1);
  val_print(ACS_PRINT_DEBUG, " Initial Non-secure data = 0x%lx", data2);
  val_print(ACS_PRINT_DEBUG, " Secure write data = 0x%lx", data3);
  val_print(ACS_PRINT_DEBUG, " Non-secure data after Secure CMO = 0x%lx", data4);
  val_print(ACS_PRINT_DEBUG, " Non-secure write data = 0x%lx", data5);
  val_print(ACS_PRINT_DEBUG, " Secure data after Non-secure CMO = 0x%lx", data6);

  if (data6 == data3) {
      val_print(ACS_PRINT_ERR, " Secure view still returns the earlier Secure data", 0);
      return 15;
  }

  val_print(ACS_PRINT_TEST, " Verifying Non-secure data after CMO", 0);
  shared_data->num_access = 1;
  shared_data->shared_data_access[0].addr = VA_NS;
  shared_data->shared_data_access[0].data = data5 ^ 1;
  shared_data->shared_data_access[0].access_type = READ_DATA;

  if (val_pe_access_mut_el3()) {
      val_print(ACS_PRINT_ERR, " Failed to read Non-secure VA = 0x%lx", VA_NS);
      return 18;
  }

  ns_readback = shared_data->shared_data_access[0].data;
  if (ns_readback != data5) {
      val_print(ACS_PRINT_ERR, " Final Non-secure readback mismatch", 0);
      val_print(ACS_PRINT_DEBUG, " Expected data = 0x%lx", data5);
      val_print(ACS_PRINT_DEBUG, " Observed data = 0x%lx", ns_readback);
      return 19;
  }

  return ACS_STATUS_PASS;
}

static
void payload(void)
{
  uint32_t index = val_pe_get_index_mpid(val_pe_get_mpid());
  uint32_t status;

  status = run_popa_completion_cross_pas_check();
  if (status != ACS_STATUS_PASS) {
      val_set_status(index, "FAIL", status);
      return;
  }

  val_set_status(index, "PASS", 01);
}

uint32_t
rme_popa_cmo_completion_guarantees_entry(uint32_t num_pe)
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
