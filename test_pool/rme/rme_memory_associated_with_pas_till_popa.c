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

#define TEST_NAME  "rme_memory_associated_with_pas_till_popa"
#define TEST_DESC  "Cacheable memory/PA is associated with PAS until POPA  "
#define TEST_RULE  "RWFQKD"

#define NUM_PAS 4
/**
 * @brief  Check cacheable data isolation for each source PAS before PoPA.
 * 1. For each source PAS, allocate a fresh PA and mark it GPT_ANY.
 * 2. Map the PA with cacheable Root, Realm, Non-secure and Secure aliases.
 * 3. Initialize through the source PAS and clean/invalidate it to PoPA.
 * 4. Read through the source PAS to populate its cache, then write new data.
 * 5. Without another CMO, read through the other three PAS aliases.
 * 6. Each of those reads must differ from the source PAS's new data.
 * This checks software-visible isolation, not internal PAS tags along the path.
**/
static
void payload(void)
{
  uint32_t index = val_pe_get_index_mpid(val_pe_get_mpid());
  uint32_t src, dst, access_idx;
  uint64_t PA, VA[NUM_PAS], size, attr, wt_data, rd_data;
  const uint64_t pas_list[NUM_PAS] = {ROOT_PAS, REALM_PAS, NONSECURE_PAS, SECURE_PAS};

  /* Normal SMC services must reach the firmware dispatcher, not the probe handler. */
  shared_data->exception_expected = CLEAR;
  shared_data->exception_generated = CLEAR;
  shared_data->access_mut = CLEAR;
  shared_data->pas_filter_flag = CLEAR;

  size = val_get_min_tg();
  attr = LOWER_ATTRS(PGT_ENTRY_ACCESS | SHAREABLE_ATTR(INNER_SHAREABLE)
                     | GET_ATTR_INDEX(WRITE_BACK_NT) | PGT_ENTRY_AP_RW);

  for (src = 0; src < NUM_PAS; src++) {
      /* Keep earlier source-PAS iterations from leaving cached aliases of this PA. */
      PA = val_get_free_pa(size, size);
      if (PA == 0) {
          val_print(ACS_PRINT_ERR, " Failed to allocate test PA", 0);
          val_set_status(index, "FAIL", 01);
          return;
      }

      if (val_add_gpt_entry_el3(PA, GPT_ANY)) {
          val_print(ACS_PRINT_ERR, " Failed to add GPT entry for PA 0x%lx", PA);
          val_set_status(index, "FAIL", 02);
          return;
      }

      for (dst = 0; dst < NUM_PAS; dst++) {
          VA[dst] = val_get_free_va(size);
          if (VA[dst] == 0) {
              val_print(ACS_PRINT_ERR, " Failed to allocate test VA", 0);
              val_set_status(index, "FAIL", 03);
              return;
          }
          if (val_add_mmu_entry_el3(VA[dst], PA,
                                   attr | LOWER_ATTRS(PAS_ATTR(pas_list[dst])))) {
              val_print(ACS_PRINT_ERR, " Failed to add MMU entry for VA 0x%lx", VA[dst]);
              val_set_status(index, "FAIL", 04);
              return;
          }
      }

      val_print(ACS_PRINT_TEST, " Initialising PA from source PAS: 0x%lx", pas_list[src]);
      shared_data->num_access = 1;
      shared_data->shared_data_access[0].addr = VA[src];
      shared_data->shared_data_access[0].data = INIT_DATA;
      shared_data->shared_data_access[0].access_type = WRITE_DATA;
      shared_data->exception_expected = CLEAR;
      shared_data->exception_generated = CLEAR;
      shared_data->access_mut = CLEAR;
      shared_data->pas_filter_flag = CLEAR;
      if (val_pe_access_mut_el3()) {
          val_print(ACS_PRINT_ERR, " Failed to initialize source VA 0x%lx", VA[src]);
          val_set_status(index, "FAIL", 05);
          return;
      }

      val_print(ACS_PRINT_TEST, " Issuing initial CMO to PoPA for source PAS: 0x%lx",
                pas_list[src]);
      if (val_data_cache_ops_by_pa_el3(PA, pas_list[src])) {
          val_print(ACS_PRINT_ERR, " Failed to issue CMO for PA 0x%lx", PA);
          val_set_status(index, "FAIL", 06);
          return;
      }

      /* Preserve main's load-before-store sequence to populate the source cache. */
      shared_data->num_access = 1;
      shared_data->shared_data_access[0].addr = VA[src];
      shared_data->shared_data_access[0].access_type = READ_DATA;
      shared_data->exception_expected = CLEAR;
      shared_data->exception_generated = CLEAR;
      shared_data->access_mut = CLEAR;
      shared_data->pas_filter_flag = CLEAR;
      if (val_pe_access_mut_el3()) {
          val_print(ACS_PRINT_ERR, " Failed to read source VA 0x%lx", VA[src]);
          val_set_status(index, "FAIL", 07);
          return;
      }

      wt_data = (uint32_t)RANDOM_DATA_1;
      shared_data->num_access = NUM_PAS;
      shared_data->shared_data_access[0].addr = VA[src];
      shared_data->shared_data_access[0].data = wt_data;
      shared_data->shared_data_access[0].access_type = WRITE_DATA;
      access_idx = 1;
      for (dst = 0; dst < NUM_PAS; dst++) {
          if (dst == src)
              continue;
          shared_data->shared_data_access[access_idx].addr = VA[dst];
          /* An unchanged result slot must not satisfy the inequality check. */
          shared_data->shared_data_access[access_idx].data = wt_data;
          shared_data->shared_data_access[access_idx].access_type = READ_DATA;
          access_idx++;
      }
      shared_data->exception_expected = CLEAR;
      shared_data->exception_generated = CLEAR;
      /* SET would bypass this batch and probe arg1 without updating these slots. */
      shared_data->access_mut = CLEAR;
      shared_data->pas_filter_flag = CLEAR;
      if (val_pe_access_mut_el3()) {
          val_print(ACS_PRINT_ERR, " Failed source write or other-PAS reads", 0);
          val_set_status(index, "FAIL", 8);
          return;
      }

      access_idx = 1;
      for (dst = 0; dst < NUM_PAS; dst++) {
          if (dst == src)
              continue;
          rd_data = shared_data->shared_data_access[access_idx++].data;
          val_print(ACS_PRINT_TEST, " Comparing source PAS against read PAS: 0x%lx",
                    pas_list[dst]);
          val_print(ACS_PRINT_DEBUG, " Source write data = 0x%lx", wt_data);
          val_print(ACS_PRINT_DEBUG, " Other-PAS read data = 0x%lx", rd_data);
          if (rd_data == wt_data) {
              val_print(ACS_PRINT_ERR, " Source PAS = 0x%lx", pas_list[src]);
              val_print(ACS_PRINT_ERR, " Read PAS = 0x%lx", pas_list[dst]);
              val_print(ACS_PRINT_ERR, " Other-PAS read matches source data: 0x%lx", rd_data);
              val_set_status(index, "FAIL", 9);
              return;
          }
      }
  }

  val_set_status(index, "PASS", 01);
}

uint32_t
rme_memory_associated_with_pas_till_popa_entry(uint32_t num_pe)
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
