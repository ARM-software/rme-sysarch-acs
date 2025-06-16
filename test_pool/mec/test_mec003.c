/** @file
 * Copyright (c) 2024-2025, Arm Limited or its affiliates. All rights reserved.
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
#include "val/include/val_interface.h"
#include "val/include/rme_acs_el32.h"
#include "val/include/rme_acs_pe.h"
#include "val/include/rme_acs_mec.h"

#define TEST_NUM  (ACS_RME_MEC_TEST_NUM_BASE  +  3)
#define TEST_DESC  "Check effect of PoPA CMO                               "
#define TEST_RULE  "RQBNJF"

#define MECID1 0x1
#define MECID2 0x2

static
void
payload(void)
{
  uint32_t pe_index = val_pe_get_index_mpid(val_pe_get_mpid());
  uint64_t data_wt_rl, data_rd_rl, VA_RL, PA, size;
  uint32_t attr;

  size = val_get_min_tg();
  PA = val_get_free_pa(size, size);
  VA_RL = val_get_free_va(size);

  /* Map VA to PA at EL3 */
  attr = LOWER_ATTRS(PGT_ENTRY_ACCESS | SHAREABLE_ATTR(NON_SHAREABLE) | PGT_ENTRY_AP_RW);
  val_add_gpt_entry_el3(PA, GPT_ANY);
  val_add_mmu_entry_el3(VA_RL, PA, (attr | LOWER_ATTRS(PAS_ATTR(REALM_PAS))));

  val_rlm_enable_mec();

  val_rlm_configure_mecid(MECID1);

  /* Store RANDOM_DATA_1 in VA_RL*/
  data_wt_rl = RANDOM_DATA_1;
  shared_data->num_access = 1;
  shared_data->shared_data_access[0].addr = VA_RL;
  shared_data->shared_data_access[0].data = data_wt_rl;
  shared_data->shared_data_access[0].access_type = WRITE_DATA;

  val_pe_access_mut_el3();

  /* Issue CMO with MECID = MECID2 */
  val_rlm_configure_mecid(MECID2);
  val_data_cache_ops_by_pa_el3(PA, REALM_PAS);

  /* Mark memory as Non cacheable to be able read directly from main memory */
  attr = LOWER_ATTRS(PGT_ENTRY_ACCESS | SHAREABLE_ATTR(NON_SHAREABLE)
                               | PGT_ENTRY_AP_RW | GET_ATTR_INDEX(NON_CACHEABLE));
  val_add_mmu_entry_el3(VA_RL, PA, (attr | LOWER_ATTRS(PAS_ATTR(REALM_PAS))));

  /* Restore MECID to MECID1 when reading directly from main memory */
  val_rlm_configure_mecid(MECID1);

  shared_data->num_access = 1;
  shared_data->shared_data_access[0].addr = VA_RL;
  shared_data->shared_data_access[0].access_type = READ_DATA;
  val_pe_access_mut_el3();

  data_rd_rl = shared_data->shared_data_access[0].data;

  /* Reading VA_RL should read RANDOM_DATA_1 indicating cache was cleaned with correct MECID*/
  if (data_rd_rl != data_wt_rl)
  {
      val_print(ACS_PRINT_ERR, "Incorrect MECID used while cleaning cache\n", 0);
      val_set_status(pe_index, RESULT_FAIL(TEST_NUM, 01));
      return;
  }

  /* Write RANDOM_DATA_2 directly to main memory */
  data_wt_rl = RANDOM_DATA_2;
  shared_data->num_access = 1;
  shared_data->shared_data_access[0].addr = VA_RL;
  shared_data->shared_data_access[0].data = data_wt_rl;
  shared_data->shared_data_access[0].access_type = WRITE_DATA;

  val_pe_access_mut_el3();

  /* Restore the memory as cacheable */
  attr = LOWER_ATTRS(PGT_ENTRY_ACCESS | SHAREABLE_ATTR(NON_SHAREABLE) | PGT_ENTRY_AP_RW);
  val_add_mmu_entry_el3(VA_RL, PA, (attr | LOWER_ATTRS(PAS_ATTR(REALM_PAS))));

  shared_data->num_access = 1;
  shared_data->shared_data_access[0].addr = VA_RL;
  shared_data->shared_data_access[0].access_type = READ_DATA;
  val_pe_access_mut_el3();

  /* Reading VA_RL should return RANDOM_DATA_2, indicating cache was invalidated*/
  data_rd_rl = shared_data->shared_data_access[0].data;
  if (data_rd_rl != data_wt_rl)
  {
      val_print(ACS_PRINT_ERR, "CMO did not clean the cache\n", 0);
      val_set_status(pe_index, RESULT_FAIL(TEST_NUM, 02));
      return;
  }

  /* Restore MECID to GMECID */
  val_rlm_configure_mecid(VAL_GMECID);
  val_rlm_disable_mec();

  val_set_status(pe_index, RESULT_PASS(TEST_NUM, 01));
  return;

}


uint32_t
mec003_entry(void)
{

  uint32_t num_pe = 1;
  uint32_t status = ACS_STATUS_FAIL;  //default value

  status = val_initialize_test(TEST_NUM, TEST_DESC, num_pe, TEST_RULE);

  /* This check is when user is forcing us to skip this test */
  if (status != ACS_STATUS_SKIP)
      val_run_test_payload(TEST_NUM, num_pe, payload, 0);

  /* get the result from all PE and check for failure */
  status = val_check_for_error(TEST_NUM, num_pe, TEST_RULE);

  val_report_status(0, RME_ACS_END(TEST_NUM), TEST_RULE);

  return status;
}
