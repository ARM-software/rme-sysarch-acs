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

#define TEST_NUM   (ACS_RME_TEST_NUM_BASE  +  10)
#define TEST_DESC  "Encryption enable check for all PAS except Non-Secure  "
#define TEST_RULE  "PE_11"

/*
 * @brief  The test validates the encryption feature for all the access PASs except for Non-secure.
 * 1. PA is marked as ALL_ACCESS permitted in GPT.
 * 2. PA is mapped with VA_S, VA_NS, VA_RT and VA_RL as mentioned PAS.
 * 3. Store wt_data_ns in VA_NS.
 * 4. Access the PA with other PASs i.e., VA_S, VA_RT and VA_RL.
 * 5. All the data should be different i.e., unique.
 */
static
void payload(void)
{

  uint32_t index = val_pe_get_index_mpid(val_pe_get_mpid());
  uint64_t wt_data_ns, data_rt, data_rl, data_s, PA;
  uint64_t VA_NS, VA_RT, VA_RL, VA_S, size;

  size = val_get_min_tg();
  PA = val_get_free_pa(size, size);
  VA_NS = val_get_free_va(size);
  VA_RT = val_get_free_va(size);
  VA_RL = val_get_free_va(size);
  VA_S = val_get_free_va(size);

  /* Map PA as all access permitted */
  val_add_gpt_entry_el3(PA /* PA */, GPT_ANY /* GPI */);

  /* PA is mapped as VA1_S, VA2_RL, VA3_RT, VA4_NS */

  val_add_mmu_entry_el3(VA_NS /* VA1 */, PA, NONSECURE_PAS);

  val_add_mmu_entry_el3(VA_RT /* VA2 */, PA, ROOT_PAS);

  val_add_mmu_entry_el3(VA_RL /* VA3 */, PA, REALM_PAS);

  val_add_mmu_entry_el3(VA_S /* VA4 */, PA, SECURE_PAS);

  /* Store Random data in VA_NS and access the rest of the VAs */
  wt_data_ns = RANDOM_DATA_1;
  shared_data->num_access = 1;
  shared_data->shared_data_access[0].addr = VA_NS;
  shared_data->shared_data_access[0].data = wt_data_ns;
  shared_data->shared_data_access[0].access_type = WRITE_DATA;

  val_pe_access_mut_el3();

  val_data_cache_ops_by_va_el3(VA_NS, CLEAN_AND_INVALIDATE);

  shared_data->num_access = 3;
  shared_data->shared_data_access[0].addr = VA_RT;
  shared_data->shared_data_access[0].access_type = READ_DATA;

  shared_data->shared_data_access[1].addr = VA_RL;
  shared_data->shared_data_access[1].access_type = READ_DATA;

  shared_data->shared_data_access[2].addr = VA_S;
  shared_data->shared_data_access[2].access_type = READ_DATA;

  val_pe_access_mut_el3();
  data_rt = shared_data->shared_data_access[0].data;
  data_rl = shared_data->shared_data_access[1].data;
  data_s = shared_data->shared_data_access[2].data;

  val_print(ACS_PRINT_DEBUG, "\n  The data stored in VA_NS = 0x%lx", wt_data_ns);
  val_print(ACS_PRINT_DEBUG, "\n  The data read from VA_RT = 0x%lx", data_rt);
  val_print(ACS_PRINT_DEBUG, "\n  The data read from VA_RL = 0x%lx", data_rl);
  val_print(ACS_PRINT_DEBUG, "\n  The data read from VA_S = 0x%lx", data_s);
  val_print(ACS_PRINT_DEBUG, "\n  The test expects all tha data to be unique", 0);

  /* Reads of VA1_S, VA3_RL, VA4_RT msut be unique values and Not Equal to data stored in VA4_NS */
  if (data_rt != wt_data_ns && data_rt != data_rl && data_rt != data_s
      && data_rl != wt_data_ns && data_rl != data_s && data_s != wt_data_ns)
      val_set_status(index, RESULT_PASS(TEST_NUM, 01));

  else
      val_set_status(index, RESULT_FAIL(TEST_NUM, 01));
  return;

}

uint32_t
rme010_entry(void)
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

