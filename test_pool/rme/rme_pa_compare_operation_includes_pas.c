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

#define TEST_NAME  "rme_pa_compare_operation_includes_pas"
#define TEST_DESC  "PA compare operation includes PAS                    "
#define TEST_RULE  "RFRMJJ"

#define DATA_1  0xAD
#define DATA_2  0xBC

static uint64_t snoop_pa;
static uint64_t snoop_size;

/**
 * @brief  The test validates that PA compare operations include PAS.
 * 1. Mark PA1 as all-access permitted in GPT.
 * 2. Map PA1 with cacheable Non-secure, Root, Realm and Secure PAS aliases.
 * 3. Store data through the Non-secure alias without cleaning it to PoPA.
 * 4. Verify Root, Realm and Secure aliases do not observe the Non-secure
 *    cached data.
 * 5. Mark PA2 as all-access permitted in GPT.
 * 6. On PE0, map PA2 as cacheable/shareable Root PAS and cache a new value.
 * 7. On PE1, map PA2 as cacheable/shareable Realm PAS and verify it does not
 *    observe PE0's Root PAS cached update through snoop.
 *
 * Note: The snoop check assumes that only the test PA is mapped cacheable.
 * Other regions such as .code, .data and .bss must remain non-cacheable or
 * otherwise isolated from the test PA, so unrelated cacheable traffic does not
 * affect the observed result.
**/
static uint32_t
run_same_pe_pa_compare_check(void)
{
  uint32_t index = val_pe_get_index_mpid(val_pe_get_mpid());
  uint64_t pa, va_ns, va_rt, va_rl, va_s, size, attr;
  uint64_t wt_data_ns, data_rt, data_rl, data_s;

  size = val_get_min_tg();
  pa = val_get_free_pa(size, size);
  /* The PA allocator reports mapping failures with address 1. */
  if (pa == 1)
  {
      val_print(ACS_PRINT_ERR, " Failed to allocate PA for same-PE comparison", 0);
      val_set_status(index, "FAIL", 21);
      return ACS_STATUS_FAIL;
  }

  va_ns = val_get_free_va(size);
  va_rt = val_get_free_va(size);
  va_rl = val_get_free_va(size);
  va_s = val_get_free_va(size);
  if (!va_ns || !va_rt || !va_rl || !va_s)
  {
      val_print(ACS_PRINT_ERR, " Failed to allocate PAS aliases for same-PE comparison", 0);
      val_set_status(index, "FAIL", 22);
      return ACS_STATUS_FAIL;
  }

  attr = LOWER_ATTRS(PGT_ENTRY_ACCESS | SHAREABLE_ATTR(INNER_SHAREABLE)
                     | GET_ATTR_INDEX(WRITE_BACK_NT) | PGT_ENTRY_AP_RW);

  if (val_add_gpt_entry_el3(pa, GPT_ANY))
  {
      val_print(ACS_PRINT_ERR, " Failed to add GPT entry for PA 0x%lx", pa);
      val_set_status(index, "FAIL", 01);
      return ACS_STATUS_FAIL;
  }

  if (val_add_mmu_entry_el3(va_ns, pa, (attr | LOWER_ATTRS(PAS_ATTR(NONSECURE_PAS)))))
  {
      val_print(ACS_PRINT_ERR, " Failed to add MMU entry for VA_NS 0x%lx", va_ns);
      val_set_status(index, "FAIL", 02);
      return ACS_STATUS_FAIL;
  }

  if (val_add_mmu_entry_el3(va_rt, pa, (attr | LOWER_ATTRS(PAS_ATTR(ROOT_PAS)))))
  {
      val_print(ACS_PRINT_ERR, " Failed to add MMU entry for VA_RT 0x%lx", va_rt);
      val_set_status(index, "FAIL", 03);
      return ACS_STATUS_FAIL;
  }

  if (val_add_mmu_entry_el3(va_rl, pa, (attr | LOWER_ATTRS(PAS_ATTR(REALM_PAS)))))
  {
      val_print(ACS_PRINT_ERR, " Failed to add MMU entry for VA_RL 0x%lx", va_rl);
      val_set_status(index, "FAIL", 04);
      return ACS_STATUS_FAIL;
  }

  if (val_add_mmu_entry_el3(va_s, pa, (attr | LOWER_ATTRS(PAS_ATTR(SECURE_PAS)))))
  {
      val_print(ACS_PRINT_ERR, " Failed to add MMU entry for VA_S 0x%lx", va_s);
      val_set_status(index, "FAIL", 05);
      return ACS_STATUS_FAIL;
  }

  val_print(ACS_PRINT_TEST, " Initialising PA from Non-secure PAS", 0);
  shared_data->num_access = 1;
  shared_data->shared_data_access[0].addr = va_ns;
  shared_data->shared_data_access[0].data = INIT_DATA;
  shared_data->shared_data_access[0].access_type = WRITE_DATA;
  if (val_pe_access_mut_el3())
  {
      val_print(ACS_PRINT_ERR, " Failed to access VA_NS = 0x%lx", va_ns);
      val_set_status(index, "FAIL", 06);
      return ACS_STATUS_FAIL;
  }

  if (val_data_cache_ops_by_pa_el3(pa, NONSECURE_PAS))
  {
      val_print(ACS_PRINT_ERR, " Failed to issue CMO for PA 0x%lx", pa);
      val_set_status(index, "FAIL", 07);
      return ACS_STATUS_FAIL;
  }

  wt_data_ns = RANDOM_DATA_1;
  val_print(ACS_PRINT_TEST, " Checking PA compare from other PAS aliases", 0);
  shared_data->num_access = 4;
  shared_data->shared_data_access[0].addr = va_ns;
  shared_data->shared_data_access[0].data = wt_data_ns;
  shared_data->shared_data_access[0].access_type = WRITE_DATA;

  shared_data->shared_data_access[1].addr = va_rt;
  shared_data->shared_data_access[1].access_type = READ_DATA;

  shared_data->shared_data_access[2].addr = va_rl;
  shared_data->shared_data_access[2].access_type = READ_DATA;

  shared_data->shared_data_access[3].addr = va_s;
  shared_data->shared_data_access[3].access_type = READ_DATA;

  if (val_pe_access_mut_el3())
  {
      val_print(ACS_PRINT_ERR, " Failed to access VA_NS, VA_RT, VA_RL and VA_S", 0);
      val_set_status(index, "FAIL", 8);
      return ACS_STATUS_FAIL;
  }

  data_rt = shared_data->shared_data_access[1].data;
  data_rl = shared_data->shared_data_access[2].data;
  data_s = shared_data->shared_data_access[3].data;

  val_print(ACS_PRINT_DEBUG, " The data stored in VA_NS = 0x%lx", wt_data_ns);
  val_print(ACS_PRINT_DEBUG, " The data read from VA_RT = 0x%lx", data_rt);
  val_print(ACS_PRINT_DEBUG, " The data read from VA_RL = 0x%lx", data_rl);
  val_print(ACS_PRINT_DEBUG, " The data read from VA_S = 0x%lx", data_s);

  if (data_rt != wt_data_ns && data_rl != wt_data_ns && data_s != wt_data_ns)
      return ACS_STATUS_PASS;

  val_set_status(index, "FAIL", 9);
  return ACS_STATUS_FAIL;
}

static
void
snoop_filter_payload2(void)
{
  uint32_t index = val_pe_get_index_mpid(val_pe_get_mpid());
  uint64_t va2, pe2_data, attr;

  va2 = val_get_free_va(snoop_size);
  if (!va2)
  {
    val_print(ACS_PRINT_ERR, " Failed to allocate Realm VA for snoop comparison", 0);
    val_set_status(index, "FAIL", 23);
    return;
  }

  attr = LOWER_ATTRS(PGT_ENTRY_ACCESS | SHAREABLE_ATTR(INNER_SHAREABLE)
                     | GET_ATTR_INDEX(WRITE_BACK_NT) | PGT_ENTRY_AP_RW
                     | PAS_ATTR(REALM_PAS));
  if (val_add_mmu_entry_el3(va2, snoop_pa, attr))
  {
    val_set_status(index, "FAIL", 10);
    return;
  }

  shared_data->num_access = 1;
  shared_data->shared_data_access[0].addr = va2;
  shared_data->shared_data_access[0].access_type = READ_DATA;

  if (val_pe_access_mut_el3())
  {
    val_set_status(index, "FAIL", 11);
    return;
  }

  pe2_data = shared_data->shared_data_access[0].data;
  if (pe2_data == DATA_2)
  {
    val_set_test_data(index, pe2_data, 0);
    val_set_status(index, "FAIL", 12);
    return;
  }

  val_set_status(index, "PASS", 01);
}

static uint32_t
run_snoop_pa_compare_check(void)
{
  uint32_t my_index = val_pe_get_index_mpid(val_pe_get_mpid());
  uint32_t timeout, sec_index = 1;
  uint64_t pe2_data, pe2_data_aux, attr, va1;

  snoop_size = val_get_min_tg();
  snoop_pa = val_get_free_pa(snoop_size, snoop_size);
  if (snoop_pa == 1)
  {
    val_print(ACS_PRINT_ERR, " Failed to allocate PA for snoop comparison", 0);
    val_set_status(my_index, "FAIL", 24);
    return ACS_STATUS_FAIL;
  }

  va1 = val_get_free_va(snoop_size);
  if (!va1)
  {
    val_print(ACS_PRINT_ERR, " Failed to allocate Root VA for snoop comparison", 0);
    val_set_status(my_index, "FAIL", 25);
    return ACS_STATUS_FAIL;
  }

  if (val_add_gpt_entry_el3(snoop_pa, GPT_ANY))
  {
    val_set_status(my_index, "FAIL", 13);
    return ACS_STATUS_FAIL;
  }

  attr = LOWER_ATTRS(PGT_ENTRY_ACCESS | SHAREABLE_ATTR(INNER_SHAREABLE)
                     | GET_ATTR_INDEX(WRITE_BACK_NT) | PGT_ENTRY_AP_RW
                     | PAS_ATTR(ROOT_PAS));
  if (val_add_mmu_entry_el3(va1, snoop_pa, attr))
  {
    val_set_status(my_index, "FAIL", 14);
    return ACS_STATUS_FAIL;
  }

  shared_data->num_access = 1;
  shared_data->shared_data_access[0].addr = va1;
  shared_data->shared_data_access[0].data = DATA_1;
  shared_data->shared_data_access[0].access_type = WRITE_DATA;
  if (val_pe_access_mut_el3())
  {
    val_set_status(my_index, "FAIL", 15);
    return ACS_STATUS_FAIL;
  }

  if (val_data_cache_ops_by_pa_el3(snoop_pa, ROOT_PAS))
  {
    val_set_status(my_index, "FAIL", 16);
    return ACS_STATUS_FAIL;
  }

  shared_data->num_access = 2;
  shared_data->shared_data_access[0].addr = va1;
  shared_data->shared_data_access[0].access_type = READ_DATA;
  shared_data->shared_data_access[1].addr = va1;
  shared_data->shared_data_access[1].data = DATA_2;
  shared_data->shared_data_access[1].access_type = WRITE_DATA;
  if (val_pe_access_mut_el3())
  {
    val_set_status(my_index, "FAIL", 17);
    return ACS_STATUS_FAIL;
  }

  timeout = TIMEOUT_MEDIUM;
  val_execute_on_pe(sec_index, snoop_filter_payload2, 0);
  while ((--timeout) && (IS_RESULT_PENDING(val_get_status(sec_index)))) {
  }

  if (!timeout)
  {
    val_print(ACS_PRINT_ERR, " **Timed out** for PE index = %d", sec_index);
    val_set_status(sec_index, "FAIL", 18);
    return ACS_STATUS_FAIL;
  }

  if (IS_TEST_FAIL(val_get_status(sec_index)))
  {
    val_get_test_data(sec_index, &pe2_data, &pe2_data_aux);
    val_print(ACS_PRINT_ERR, " The data read in PE2 is 0x%x", pe2_data);
    val_print(ACS_PRINT_ERR, " which is same as the data stored in PE1, ", 0);
    val_print(ACS_PRINT_ERR, " 0x%x", DATA_2);
    val_set_status(my_index, "FAIL", 19);
    return ACS_STATUS_FAIL;
  }

  return ACS_STATUS_PASS;
}

static
void
payload(void)
{
  uint32_t index = val_pe_get_index_mpid(val_pe_get_mpid());

  if (run_same_pe_pa_compare_check() != ACS_STATUS_PASS)
      return;

  if (run_snoop_pa_compare_check() != ACS_STATUS_PASS)
      return;

  val_set_status(index, "PASS", 01);
}

uint32_t
rme_pa_compare_operation_includes_pas_entry(uint32_t num_pe)
{
  uint32_t index = val_pe_get_index_mpid(val_pe_get_mpid());
  uint32_t status = ACS_STATUS_FAIL;
  uint32_t timeout;

  if (num_pe < 2) {
      status = val_initialize_test(TEST_NAME, TEST_DESC, num_pe, TEST_RULE);
      if (status != ACS_STATUS_SKIP)
          val_print(ACS_PRINT_WARN, " Skipping the test as Number of PEs is less than required", 0);
      val_set_status(val_get_primary_pe_index(), "SKIP", 01);
      status = ACS_STATUS_SKIP;
  } else {
      num_pe = 2;
      status = val_initialize_test(TEST_NAME, TEST_DESC, num_pe, TEST_RULE);

      if (status != ACS_STATUS_SKIP) {
          if (index == 0) {
              payload();
          } else {
              val_execute_on_pe(0, payload, 0);
              timeout = TIMEOUT_LARGE;
              while ((--timeout) && IS_RESULT_PENDING(val_get_status(0))) {
              }

              if (!timeout) {
                  val_print(ACS_PRINT_ERR, " Timed out waiting for PE0", 0);
                  val_set_status(0, "FAIL", 20);
              }
          }
      }
  }

  status = val_check_for_error(num_pe);

  val_report_status(0, "END");

  return status;
}
