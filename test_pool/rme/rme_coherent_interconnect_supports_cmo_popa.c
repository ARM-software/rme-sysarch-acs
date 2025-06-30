/** @file
 * Copyright (c) 2022-2024, 2025, Arm Limited or its affiliates. All rights reserved.
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

#define TEST_NAME  "rme_coherent_interconnect_supports_cmo_popa"
#define TEST_DESC  "To check if coherent interconnect supports CMO to PoPA "
#define TEST_RULE  "RXTSXB/RLCXDB"

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

  uint32_t index = val_pe_get_index_mpid(val_pe_get_mpid()), attr;
  uint64_t rd_data_s, rd_data_ns, wt_data_s, ns_data_popa, PA;
  uint64_t VA_S, VA_NS, size;

  size = val_get_min_tg();
  PA = val_get_free_pa(size, size);
  VA_S = val_get_free_va(size);
  VA_NS = val_get_free_va(size);
  attr = LOWER_ATTRS(PGT_ENTRY_ACCESS | SHAREABLE_ATTR(NON_SHAREABLE) | PGT_ENTRY_AP_RW);

  if (val_add_gpt_entry_el3(PA, GPT_ANY)) {
      val_print(ACS_PRINT_ERR, "\n       Failed to add GPT entry for PA 0x%lx", PA);
      val_set_status(index, "FAIL", 01);
      return;
  }

  /*PA is initialized with the initial DATA*/
  *(uint64_t *)PA = (uint64_t) INIT_DATA;

  if (val_add_mmu_entry_el3(VA_S/* VA1 */, PA, (attr | LOWER_ATTRS(PAS_ATTR(SECURE_PAS)))))
  {
      val_print(ACS_PRINT_ERR, "\n  Failed to add MMU entry for VA1 0x%lx", VA_S);
      val_set_status(index, "FAIL", 02);
      return;
  }

  if (val_add_mmu_entry_el3(VA_NS/* VA2 */, PA, (attr | LOWER_ATTRS(PAS_ATTR(NONSECURE_PAS)))))
  {
      val_print(ACS_PRINT_ERR, "\n  Failed to add MMU entry for VA2 0x%lx", VA_NS);
      val_set_status(index, "FAIL", 03);
      return;
  }

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

  if (val_pe_access_mut_el3()) {
      val_print(ACS_PRINT_ERR, " Failed to access VA_S and VA_NS", 0);
      val_set_status(index, "FAIL", 04);
      return;
  }
  rd_data_s = shared_data->shared_data_access[0].data;
  rd_data_ns = shared_data->shared_data_access[1].data;

  /* CMO to PoPA for PA1 at secure PAS */
  if (val_data_cache_ops_by_pa_el3(PA, SECURE_PAS)) {
      val_print(ACS_PRINT_ERR, " Failed to issue CMO for PA 0x%llx", PA);
      val_set_status(index, "FAIL", 05);
      return;
  }

  /* CMO to PoPA for PA1 at non-secure PAS */
  if (val_data_cache_ops_by_pa_el3(PA, NONSECURE_PAS)) {
      val_print(ACS_PRINT_ERR, " Failed to issue CMO for PA 0x%llx", PA);
      val_set_status(index, "FAIL", 06);
      return;
  }

  /* Access the data stored in VA2 */
  shared_data->num_access = 1;
  shared_data->shared_data_access[0].addr = VA_NS;
  shared_data->shared_data_access[0].access_type = READ_DATA;

  if (val_pe_access_mut_el3())
  {
      val_print(ACS_PRINT_ERR, " Failed to access VA_NS = 0x%lx", VA_NS);
      val_set_status(index, "FAIL", 07);
      return;
  }

  ns_data_popa = shared_data->shared_data_access[0].data;

  val_print(ACS_PRINT_DEBUG, " Secure data before CMO to PoPA = 0x%lx", rd_data_s);
  val_print(ACS_PRINT_DEBUG, " Non-Secure data before CMO to PoPA = 0x%lx", rd_data_ns);
  val_print(ACS_PRINT_DEBUG, " Data stored in Secure VA before CMO to PoPA = 0x%lx", wt_data_s);
  val_print(ACS_PRINT_DEBUG, " Non-Secure data after CMO to PoPA = 0x%lx", ns_data_popa);
  val_print(ACS_PRINT_DEBUG, " The test expects all data to be unique", 0);

  if (ns_data_popa != rd_data_ns && ns_data_popa != wt_data_s && ns_data_popa != rd_data_s)
      val_set_status(index, "PASS", 01);

  else
      val_set_status(index, "FAIL", 8);
  return;

}

uint32_t
rme_coherent_interconnect_supports_cmo_popa_entry(void)
{

  uint32_t num_pe = 1;
  uint32_t status = ACS_STATUS_FAIL;

  status = val_initialize_test(TEST_NAME, TEST_DESC, num_pe, TEST_RULE);

  if (status != ACS_STATUS_SKIP)
      val_run_test_payload(num_pe, payload, 0);

  status = val_check_for_error(num_pe);

  val_report_status(0, "END");

  return status;
}

