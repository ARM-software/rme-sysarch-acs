/** @file
 * Copyright (c) 2022-2023, Arm Limited or its affiliates. All rights reserved.
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

#include "val/include/rme_acs_val.h"
#include "val/include/rme_acs_pe.h"
#include "val/include/rme_acs_common.h"

#include "val/include/rme_test_entry.h"
#include "val/include/val_interface.h"
#include "val/include/rme_acs_el32.h"
#include "val/include/mem_interface.h"

#define TEST_NUM   (ACS_RME_TEST_NUM_BASE  +  05)
#define TEST_DESC  "To check if coherent interconnect supports CMO to PoPA"
#define TEST_RULE  "PE_08"

/*
 * @brief  The test validates that coherent interconnect supports CMO to PoPA.
 * 1. Mark PA as ALL_ACCESS and initialise it  with INIT_DATA
 * 2. VA_NS and VA_S are mapped to the PA with Non-Secure and Secure access PAS respectively.
 * 3. Access VA_NS and VA_S returns rd_data_ns and rd_data_s respectively.
 * 4. Store wt_data_s in VA_S and then issue CMO to PoPA for PA with secure and non-secure PASs.
 * 5. Access VA_NS and expect a data, ns_data_popa, that is different from rd_data_ns.
 */
static
void payload(void)
{

  uint32_t index = val_pe_get_index_mpid(val_pe_get_mpid());
  uint64_t rd_data_s, rd_data_ns, wt_data_s, ns_data_popa, PA;
  uint64_t VA_S, VA_NS, size;

  size = val_get_min_tg();
  PA = val_get_free_pa(size, size);
  VA_S = val_get_free_va(size);
  VA_NS = val_get_free_va(size);

  val_add_gpt_entry_el3(PA, GPT_ANY);

  /*PA is initialized with the initial DATA*/
  *(uint64_t *)PA = (uint64_t) INIT_DATA;

  val_add_mmu_entry_el3(VA_S/* VA1 */, PA, SECURE_PAS);

  val_add_mmu_entry_el3(VA_NS/* VA2 */, PA, NONSECURE_PAS);

  /* Read VA1 and VA2 and Write Random data in VA1*/
  wt_data_s = RANDOM_DATA_2;
  shared_data->num_access = 3;
  shared_data->shared_data_access[0].addr = VA_S;
  shared_data->shared_data_access[0].access_type = READ_DATA;

  shared_data->shared_data_access[1].addr = VA_NS;
  shared_data->shared_data_access[1].access_type = READ_DATA;

  shared_data->shared_data_access[2].addr = VA_S;
  shared_data->shared_data_access[2].data = wt_data_s;
  shared_data->shared_data_access[2].access_type = WRITE_DATA;

  val_pe_access_mut_el3();
  rd_data_s = shared_data->shared_data_access[0].data;
  rd_data_ns = shared_data->shared_data_access[1].data;

  /* CMO to PoPA for PA1 at secure PAS */
  val_data_cache_ops_by_pa_el3(PA, SECURE_PAS);

  /* CMO to PoPA for PA1 at non-secure PAS */
  val_data_cache_ops_by_pa_el3(PA, NONSECURE_PAS);

  /* Access the data stored in VA2 */
  shared_data->num_access = 1;
  shared_data->shared_data_access[0].addr = VA_NS;
  shared_data->shared_data_access[0].access_type = READ_DATA;

  val_pe_access_mut_el3();
  ns_data_popa = shared_data->shared_data_access[0].data;

  val_print(ACS_PRINT_DEBUG, "\n  Secure data before CMO to PoPA = 0x%lx", rd_data_s);
  val_print(ACS_PRINT_DEBUG, "\n  Non-Secure data before CMO to PoPA = 0x%lx", rd_data_ns);
  val_print(ACS_PRINT_DEBUG, "\n  Data stored in Secure VA before CMO to PoPA = 0x%lx", wt_data_s);
  val_print(ACS_PRINT_DEBUG, "\n  Non-Secure data after CMO to PoPA = 0x%lx", ns_data_popa);
  val_print(ACS_PRINT_DEBUG, "\n  The test expects all data to be unique", 0);

  if (ns_data_popa != rd_data_ns && ns_data_popa != wt_data_s && ns_data_popa != rd_data_s)
      val_set_status(index, RESULT_PASS(TEST_NUM, 01));

  else
      val_set_status(index, RESULT_FAIL(TEST_NUM, 01));
  return;

}

uint32_t
rme005_entry(void)
{

  uint32_t num_pe = 1;
  uint32_t status = ACS_STATUS_FAIL;

  status = val_initialize_test(TEST_NUM, TEST_DESC, num_pe, TEST_RULE);

  if (status != ACS_STATUS_SKIP)
      val_run_test_payload(TEST_NUM, num_pe, payload, 0);

  status = val_check_for_error(TEST_NUM, num_pe, TEST_RULE);

  val_report_status(0, RME_ACS_END(TEST_NUM), TEST_RULE);

  return status;
}

