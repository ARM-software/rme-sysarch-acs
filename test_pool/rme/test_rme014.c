/** @file
 * Copyright (c) 2023-2024, Arm Limited or its affiliates. All rights reserved.
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
#include "val/include/sys_config.h"
#include "val/include/mem_interface.h"

#define TEST_NUM   (ACS_RME_TEST_NUM_BASE  +  14)
#define TEST_DESC  "Check data encryption beyond PoPA in mem/shared cache  "
#define TEST_RULE  "PE_03"

/**
 * @brief  The test checks the different encryption nature for each PAS beyond PoPA of
 *         external memory or any shared cache
 * 1. Store the data in Root memory
 * 2. Perform CMO to PoPA until for all PAS
 * 3. Read the data from Secure, Realm and NonSecure PAS
 * 4. Observe that each data is unique
 */
static
void payload(void)
{
  uint32_t index = val_pe_get_index_mpid(val_pe_get_mpid()), attr;
  uint64_t data_wt_rt, data_rd_rl, data_rd_s, data_rd_ns, PA;
  uint64_t VA_RL, VA_RT, VA_S, VA_NS, size;

  size = val_get_min_tg();
  PA = val_get_free_pa(size, size);
  VA_RL = val_get_free_va(size);
  VA_RT = val_get_free_va(size);
  VA_S = val_get_free_va(size);
  VA_NS = val_get_free_va(size);
  attr = LOWER_ATTRS(PGT_ENTRY_ACCESS | SHAREABLE_ATTR(NON_SHAREABLE) | PGT_ENTRY_AP_RW);

  val_add_gpt_entry_el3(PA, GPT_ANY);
  val_add_mmu_entry_el3(VA_RL, PA, (attr | LOWER_ATTRS(PAS_ATTR(REALM_PAS))));
  val_add_mmu_entry_el3(VA_RT, PA, (attr | LOWER_ATTRS(PAS_ATTR(ROOT_PAS))));
  val_add_mmu_entry_el3(VA_S, PA, (attr | LOWER_ATTRS(PAS_ATTR(SECURE_PAS))));
  val_add_mmu_entry_el3(VA_NS, PA, (attr | LOWER_ATTRS(PAS_ATTR(NONSECURE_PAS))));

  /* Store RANDOM_DATA_1 in PA_RT*/
  data_wt_rt = RANDOM_DATA_1;
  shared_data->num_access = 1;
  shared_data->shared_data_access[0].addr = VA_RT;
  shared_data->shared_data_access[0].data = data_wt_rt;
  shared_data->shared_data_access[0].access_type = WRITE_DATA;
  val_pe_access_mut_el3();

  val_print(ACS_PRINT_DEBUG, "  Data stored in Root = 0x%lx\n", data_wt_rt);
  /* CMO to PoPA for all PA of all pas */
  val_data_cache_ops_by_pa_el3(PA, SECURE_PAS);
  val_data_cache_ops_by_pa_el3(PA, NONSECURE_PAS);
  val_data_cache_ops_by_pa_el3(PA, REALM_PAS);
  val_data_cache_ops_by_pa_el3(PA, ROOT_PAS);

  /* Read the data from PA_RL, PA_S, PA_NS */
  shared_data->num_access = 3;
  shared_data->shared_data_access[0].addr = VA_RL;
  shared_data->shared_data_access[0].access_type = READ_DATA;

  shared_data->shared_data_access[1].addr = VA_S;
  shared_data->shared_data_access[1].access_type = READ_DATA;

  shared_data->shared_data_access[2].addr = VA_NS;
  shared_data->shared_data_access[2].access_type = READ_DATA;
  val_pe_access_mut_el3();

  data_rd_rl = shared_data->shared_data_access[0].data;
  data_rd_s = shared_data->shared_data_access[1].data;
  data_rd_ns = shared_data->shared_data_access[2].data;

  val_print(ACS_PRINT_DEBUG, "  Data returned from Realm Address = 0x%lx\n", data_rd_rl);
  val_print(ACS_PRINT_DEBUG, "  Data returned from Secure Address = 0x%lx\n", data_rd_s);
  val_print(ACS_PRINT_DEBUG, "  Data returned from Nonsecure Address = 0x%lx\n", data_rd_ns);
  val_print(ACS_PRINT_DEBUG, "  The test expects all data to be unique\n", 0);

  //Compare the data from Realm, Secure and Nonsecure addresses with the root data
  if (data_rd_rl != data_wt_rt && data_rd_rl != data_rd_s && data_rd_rl != data_rd_ns) {
          if (data_rd_s != data_wt_rt && data_rd_s != data_rd_ns) {
                  if (data_rd_ns != data_wt_rt)
                          val_set_status(index, RESULT_PASS(TEST_NUM, 01));
          }
  } else
      val_set_status(index, RESULT_FAIL(TEST_NUM, 01));
  return;

}

uint32_t
rme014_entry(void)
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
