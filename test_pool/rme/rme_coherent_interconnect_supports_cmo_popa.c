/** @file
 * Copyright (c) 2022-2026, Arm Limited or its affiliates. All rights reserved.
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

#define TEST_NAME  "rme_coherent_interconnect_supports_cmo_popa"
#define TEST_DESC  "To check if coherent interconnect supports CMO to PoPA "
#define TEST_RULE  "RXTSXB"

/*
 * @brief  The test validates that coherent interconnect supports CMO to PoPA.
 * 1. PA1 is marked as All Access Permitted.
 * 2. VA1 is mapped to PA1 as Secure PAS with cacheable attributes.
 * 3. VA2 is mapped to PA1 as Non-secure PAS with cacheable attributes.
 * 4. Data is seeded through VA2, then CMO to PoPA is issued for PA1
 *    Non-secure PAS.
 * 5. Read VA1 to capture the Secure view of PA1.
 * 6. Read VA2 to capture the Non-secure cached view of PA1.
 * 7. Store new data through VA1.
 * 8. Issue CMO to PoPA for PA1 Secure PAS, followed by Non-secure PAS, and
 *    wait for completion of each operation.
 * 9. Read VA2 again. The value must differ from the previous VA2 read,
 *    providing a software-visible indication that the CMO sequence affected the
 *    Non-secure view of the PA.
 */
static
uint32_t run_cmo_popa_cross_pas_check(void)
{
  uint32_t attr_sec, attr_ns;
  uint64_t pa, va_sec, va_ns, rd_data_sec, rd_data_ns;
  uint64_t ns_data_popa, size, wt_data_ns, wt_data_sec;

  size = val_get_min_tg();
  pa = val_get_free_pa(size, size);
  va_sec = val_get_free_va(size);
  va_ns = val_get_free_va(size);
  wt_data_ns = RANDOM_DATA_1;
  wt_data_sec = RANDOM_DATA_2;

  attr_sec = LOWER_ATTRS(PGT_ENTRY_ACCESS | SHAREABLE_ATTR(INNER_SHAREABLE)
                         | GET_ATTR_INDEX(WRITE_BACK_NT) | PGT_ENTRY_AP_RW
                         | PAS_ATTR(SECURE_PAS));
  attr_ns = LOWER_ATTRS(PGT_ENTRY_ACCESS | SHAREABLE_ATTR(INNER_SHAREABLE)
                        | GET_ATTR_INDEX(WRITE_BACK_NT) | PGT_ENTRY_AP_RW
                        | PAS_ATTR(NONSECURE_PAS));

  if (val_add_gpt_entry_el3(pa, GPT_ANY)) {
      val_print(ACS_PRINT_ERR, "\n       Failed to add GPT entry for PA 0x%lx", pa);
      return 1;
  }

  if (val_add_mmu_entry_el3(va_sec, pa, attr_sec))
  {
      val_print(ACS_PRINT_ERR, "\n  Failed to add MMU entry for VA 0x%lx", va_sec);
      return 2;
  }

  if (val_add_mmu_entry_el3(va_ns, pa, attr_ns))
  {
      val_print(ACS_PRINT_ERR, "\n  Failed to add MMU entry for VA 0x%lx", va_ns);
      return 3;
  }

  /*
   * Seed an initial Non-secure value. The first Non-secure CMO makes this
   * value observable through VA2 before the Secure update.
   */
  val_print(ACS_PRINT_TEST, " Creating initial Non-secure value for PA 0x%lx", pa);
  shared_data->num_access = 1;
  shared_data->shared_data_access[0].addr = va_ns;
  shared_data->shared_data_access[0].data = wt_data_ns;
  shared_data->shared_data_access[0].access_type = WRITE_DATA;

  if (val_pe_access_mut_el3()) {
      val_print(ACS_PRINT_ERR, " Failed to write Non-secure VA = 0x%lx", va_ns);
      return 4;
  }

  val_print(ACS_PRINT_TEST, " Issuing CMO to PoPA for Non-secure PAS", 0);
  if (val_data_cache_ops_by_pa_el3(pa, NONSECURE_PAS)) {
      val_print(ACS_PRINT_ERR, " Failed to issue CMO for PA 0x%llx", pa);
      return 5;
  }

  val_print(ACS_PRINT_TEST, " Reading Secure and Non-secure views before update", 0);
  shared_data->num_access = 2;
  shared_data->shared_data_access[0].addr = va_sec;
  shared_data->shared_data_access[0].access_type = READ_DATA;
  shared_data->shared_data_access[1].addr = va_ns;
  shared_data->shared_data_access[1].access_type = READ_DATA;

  if (val_pe_access_mut_el3()) {
      val_print(ACS_PRINT_ERR, " Failed to read Secure/Non-secure aliases", 0);
      return 6;
  }

  rd_data_sec = shared_data->shared_data_access[0].data;
  rd_data_ns = shared_data->shared_data_access[1].data;
  if (rd_data_ns != wt_data_ns) {
      val_print(ACS_PRINT_ERR, " Unexpected initial Non-secure data", 0);
      val_print(ACS_PRINT_DEBUG, " Expected data = 0x%lx", wt_data_ns);
      val_print(ACS_PRINT_DEBUG, " Observed data = 0x%lx", rd_data_ns);
      return 7;
  }

  val_print(ACS_PRINT_TEST, " Writing new data through Secure PAS", 0);
  shared_data->num_access = 1;
  shared_data->shared_data_access[0].addr = va_sec;
  shared_data->shared_data_access[0].data = wt_data_sec;
  shared_data->shared_data_access[0].access_type = WRITE_DATA;

  if (val_pe_access_mut_el3()) {
      val_print(ACS_PRINT_ERR, " Failed to write Secure VA = 0x%lx", va_sec);
      return 8;
  }

  val_print(ACS_PRINT_TEST, " Issuing CMO to PoPA for Secure PAS", 0);
  if (val_data_cache_ops_by_pa_el3(pa, SECURE_PAS)) {
      val_print(ACS_PRINT_ERR, " Failed to issue Secure CMO for PA 0x%llx", pa);
      return 9;
  }

  val_print(ACS_PRINT_TEST, " Issuing CMO to PoPA for Non-secure PAS", 0);
  if (val_data_cache_ops_by_pa_el3(pa, NONSECURE_PAS)) {
      val_print(ACS_PRINT_ERR, " Failed to issue Non-secure CMO for PA 0x%llx", pa);
      return 10;
  }

  val_print(ACS_PRINT_TEST, " Reading Non-secure view after CMO sequence", 0);
  shared_data->num_access = 1;
  shared_data->shared_data_access[0].addr = va_ns;
  shared_data->shared_data_access[0].access_type = READ_DATA;

  if (val_pe_access_mut_el3()) {
      val_print(ACS_PRINT_ERR, " Failed to read Non-secure VA = 0x%lx", va_ns);
      return 11;
  }

  ns_data_popa = shared_data->shared_data_access[0].data;
  val_print(ACS_PRINT_DEBUG, " Secure data before update = 0x%lx", rd_data_sec);
  val_print(ACS_PRINT_DEBUG, " Non-secure data before update = 0x%lx", rd_data_ns);
  val_print(ACS_PRINT_DEBUG, " Data stored in Secure VA = 0x%lx", wt_data_sec);
  val_print(ACS_PRINT_DEBUG, " Non-secure data after CMO to PoPA = 0x%lx", ns_data_popa);

  if (ns_data_popa == rd_data_ns) {
      val_print(ACS_PRINT_ERR, " Non-secure view did not change after CMO sequence", 0);
      return 12;
  }

  /*
   * Cross-PAS encryption means data written through Secure PAS is expected to
   * be observed as a different ciphertext value through Non-secure PAS.
   */
  if (ns_data_popa == wt_data_sec) {
      val_print(ACS_PRINT_ERR, " Non-secure view returned Secure plaintext", 0);
      return 13;
  }

  return ACS_STATUS_PASS;
}

static
void payload(void)
{

  uint32_t index = val_pe_get_index_mpid(val_pe_get_mpid());
  uint32_t status;

  status = run_cmo_popa_cross_pas_check();
  if (status != ACS_STATUS_PASS) {
      val_set_status(index, "FAIL", status);
      return;
  }

  val_set_status(index, "PASS", 01);
  return;

}

uint32_t
rme_coherent_interconnect_supports_cmo_popa_entry(uint32_t num_pe)
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
