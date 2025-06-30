/** @file
 * Copyright (c) 2023-2024, 2025, Arm Limited or its affiliates. All rights reserved.
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

#define TEST_NAME  "rme_memory_associated_with_pas_till_popa"
#define TEST_DESC  "Cacheable memory/PA is associated with PAS until POPA  "
#define TEST_RULE  "RWFQKD/RFRMJJ"

/*
 * @brief  The test validates that memory that can be cached is associated with PAS until PoPA..
 * 1. PA is marked as ALL_ACCESS permitted in GPT.
 * 2. PA is mapped with VA_S, VA_NS, VA_RT and VA_RL as mentioned PAS.
 * 3. Cacheable Store wt_data_ns in VA_NS.
 * 4. Access the PA with other PASs i.e., VA_S, VA_RT and VA_RL.
 * 5. All the data should be different from wt_data_ns.
 */
static
void payload(void)
{

  uint32_t index = val_pe_get_index_mpid(val_pe_get_mpid());
  uint64_t wt_data_ns, data_rt, data_rl, data_s, PA;
  uint64_t VA_NS, VA_RT, VA_RL, VA_S, size;
  uint64_t attr_s, attr_ns, attr_rl, attr_rt;

  /* Get free VAs and PAs and set the respective attributes */
  size = val_get_min_tg();
  PA = val_get_free_pa(size, size);
  VA_NS = val_get_free_va(size);
  attr_ns = LOWER_ATTRS(PGT_ENTRY_ACCESS  | SHAREABLE_ATTR(INNER_SHAREABLE) | PGT_ENTRY_AP_RW
                        | GET_ATTR_INDEX(WRITE_BACK_NT) | PAS_ATTR(NONSECURE_PAS));

  VA_RT = val_get_free_va(size);
  attr_rt = LOWER_ATTRS(PGT_ENTRY_ACCESS | SHAREABLE_ATTR(INNER_SHAREABLE)
                        | GET_ATTR_INDEX(WRITE_BACK_NT) | PGT_ENTRY_AP_RW | PAS_ATTR(ROOT_PAS));

  VA_RL = val_get_free_va(size);
  attr_rl = LOWER_ATTRS(PGT_ENTRY_ACCESS | SHAREABLE_ATTR(INNER_SHAREABLE)
                        | GET_ATTR_INDEX(WRITE_BACK_NT) | PGT_ENTRY_AP_RW | PAS_ATTR(REALM_PAS));

  VA_S = val_get_free_va(size);
  attr_s = LOWER_ATTRS(PGT_ENTRY_ACCESS | SHAREABLE_ATTR(INNER_SHAREABLE)
                       | GET_ATTR_INDEX(WRITE_BACK_NT) | PGT_ENTRY_AP_RW | PAS_ATTR(SECURE_PAS));

  /* Map PA as all access permitted */
  if (val_add_gpt_entry_el3(PA /* PA */, GPT_ANY /* GPI */))
  {
      val_print(ACS_PRINT_ERR, " Failed to add GPT entry for PA 0x%lx", PA);
      val_set_status(index, "FAIL", 01);
      return;
  }

  /* PA is mapped as VA1_S, VA2_RL, VA3_RT, VA4_NS with Cacheable attribute */
  if (val_add_mmu_entry_el3(VA_NS /* VA1 */, PA, attr_ns))
  {
      val_print(ACS_PRINT_ERR, " Failed to add MMU entry for VA1 0x%lx", VA_NS);
      val_set_status(index, "FAIL", 02);
      return;
  }

  if (val_add_mmu_entry_el3(VA_RT /* VA2 */, PA, attr_rt))
  {
      val_print(ACS_PRINT_ERR, " Failed to add MMU entry for VA2 0x%lx", VA_RT);
      val_set_status(index, "FAIL", 03);
      return;
  }

  if (val_add_mmu_entry_el3(VA_RL /* VA3 */, PA, attr_rl))
  {
      val_print(ACS_PRINT_ERR, " Failed to add MMU entry for VA3 0x%lx", VA_RL);
      val_set_status(index, "FAIL", 04);
      return;
  }

  if (val_add_mmu_entry_el3(VA_S /* VA4 */, PA, attr_s))
  {
      val_print(ACS_PRINT_ERR, " Failed to add MMU entry for VA4 0x%lx", VA_S);
      val_set_status(index, "FAIL", 05);
      return;
  }

  /* Load VA_NS first to ensure the data is brought to cache level and then,
   * Store Random data in VA_NS and access from the rest of the PASs */
  shared_data->num_access = 1;
  shared_data->shared_data_access[0].addr = VA_NS;
  shared_data->shared_data_access[0].data = INIT_DATA;
  shared_data->shared_data_access[0].access_type = WRITE_DATA;
  if (val_pe_access_mut_el3())
  {
      val_print(ACS_PRINT_ERR, " Failed to access VA_NS = 0x%lx", VA_NS);
      val_set_status(index, "FAIL", 06);
      return;
  }

  //CMO to PoPA for PA_NS
  if (val_data_cache_ops_by_pa_el3(PA, NONSECURE_PAS))
  {
      val_print(ACS_PRINT_ERR, " Failed to issue CMO for PA 0x%lx", PA);
      val_set_status(index, "FAIL", 07);
      return;
  }

  shared_data->num_access = 1;
  shared_data->shared_data_access[0].addr = VA_NS;
  shared_data->shared_data_access[0].access_type = READ_DATA;
  if (val_pe_access_mut_el3())
  {
      val_print(ACS_PRINT_ERR, " Failed to access VA_NS = 0x%lx", VA_NS);
      val_set_status(index, "FAIL", 8);
      return;
  }

  wt_data_ns = RANDOM_DATA_1;
  shared_data->num_access = 4;
  shared_data->shared_data_access[0].addr = VA_NS;
  shared_data->shared_data_access[0].data = wt_data_ns;
  shared_data->shared_data_access[0].access_type = WRITE_DATA;

  shared_data->shared_data_access[1].addr = VA_RT;
  shared_data->shared_data_access[1].access_type = READ_DATA;

  shared_data->shared_data_access[2].addr = VA_RL;
  shared_data->shared_data_access[2].access_type = READ_DATA;

  shared_data->shared_data_access[3].addr = VA_S;
  shared_data->shared_data_access[3].access_type = READ_DATA;

  if (val_pe_access_mut_el3())
  {
      val_print(ACS_PRINT_ERR, " Failed to access VA_NS, VA_RT, VA_RL and VA_S", 0);
      val_set_status(index, "FAIL", 9);
      return;
  }
  data_rt = shared_data->shared_data_access[1].data;
  data_rl = shared_data->shared_data_access[2].data;
  data_s = shared_data->shared_data_access[3].data;

  val_print(ACS_PRINT_DEBUG, " The data stored in VA_NS = 0x%lx", wt_data_ns);
  val_print(ACS_PRINT_DEBUG, " The data read from VA_RT = 0x%lx", data_rt);
  val_print(ACS_PRINT_DEBUG, " The data read from VA_RL = 0x%lx", data_rl);
  val_print(ACS_PRINT_DEBUG, " The data read from VA_S = 0x%lx", data_s);
  val_print(ACS_PRINT_DEBUG, " The test expects all tha data to be unique", 0);

  /* Reads of VA1_S, VA3_RL, VA4_RT must be Not Equal to data stored in VA4_NS */
  if (data_rt != wt_data_ns && data_rl != wt_data_ns && data_s != wt_data_ns)
      val_set_status(index, "PASS", 01);

  else
      val_set_status(index, "FAIL", 10);
  return;

}

uint32_t
rme_memory_associated_with_pas_till_popa_entry(void)
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

