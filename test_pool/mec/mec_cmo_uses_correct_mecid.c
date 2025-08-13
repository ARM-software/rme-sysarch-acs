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

#define TEST_NAME  "mec_cmo_uses_correct_mecid"
#define TEST_DESC  "Check CMO uses correct MECID                           "
#define TEST_RULE  "RKMNQX"

#define MECID1 0x1
#define MECID2 0x2

uint64_t data_wt_rl, data_rd_rl, VA_RL, PA_RL, tg_size;
uint32_t mem_attr;

static
void
payload1(void)
{
  uint32_t pe_index = val_pe_get_index_mpid(val_pe_get_mpid());

  if (pe_index == 0)
  {
      tg_size = val_get_min_tg();
      PA_RL = val_get_free_pa(tg_size, tg_size);
      VA_RL = val_get_free_va(tg_size);
      mem_attr = LOWER_ATTRS(PGT_ENTRY_ACCESS | SHAREABLE_ATTR(NON_SHAREABLE) | PGT_ENTRY_AP_RW);

      val_data_cache_ops_by_va((addr_t)&PA_RL, CLEAN_AND_INVALIDATE);
      val_data_cache_ops_by_va((addr_t)&VA_RL, CLEAN_AND_INVALIDATE);
      val_data_cache_ops_by_va((addr_t)&mem_attr, CLEAN_AND_INVALIDATE);

      if (val_add_gpt_entry_el3(PA_RL, GPT_ANY))
      {
        val_set_status(pe_index, "FAIL", 01);
        return;
      }

      if (val_add_mmu_entry_el3(VA_RL, PA_RL, (mem_attr | LOWER_ATTRS(PAS_ATTR(REALM_PAS)))))
      {
        val_set_status(pe_index, "FAIL", 02);
        return;
      }

      if (val_rlm_enable_mec())
      {
        val_set_status(pe_index, "FAIL", 03);
        return;
      }

      if (val_rlm_configure_mecid(MECID1))
      {
        val_set_status(pe_index, "FAIL", 04);
        return;
      }

      /* Store RANDOM_DATA_1 in PA_RT*/
      data_wt_rl = RANDOM_DATA_1;
      shared_data->num_access = 1;
      shared_data->shared_data_access[0].addr = VA_RL;
      shared_data->shared_data_access[0].data = data_wt_rl;
      shared_data->shared_data_access[0].access_type = WRITE_DATA;

      if (val_pe_access_mut_el3())
      {
        val_set_status(pe_index, "FAIL", 05);
        return;
      }

      if (val_rlm_configure_mecid(MECID2))
      {
        val_set_status(pe_index, "FAIL", 06);
        return;
      }

      if (val_data_cache_ops_by_va_el3(VA_RL, CLEAN_AND_INVALIDATE))
      {
        val_set_status(pe_index, "FAIL", 07);
        return;
      }

      val_set_status(pe_index, "PASS", 01);
      return;
  }

  if (pe_index == 1)
  {
      if (val_add_gpt_entry_el3(PA_RL, GPT_ANY))
      {
        val_set_status(pe_index, "FAIL", 01);
        return;
      }
      if (val_add_mmu_entry_el3(VA_RL, PA_RL, (mem_attr | LOWER_ATTRS(PAS_ATTR(REALM_PAS)))))
      {
        val_set_status(pe_index, "FAIL", 02);
        return;
      }

      if (val_rlm_enable_mec())
      {
        val_set_status(pe_index, "FAIL", 03);
        return;
      }

      if (val_rlm_configure_mecid(MECID1))
      {
        val_set_status(pe_index, "FAIL", 04);
        return;
      }

      shared_data->num_access = 1;
      shared_data->shared_data_access[0].addr = VA_RL;
      shared_data->shared_data_access[0].access_type = READ_DATA;
      val_data_cache_ops_by_va((addr_t)&shared_data->num_access, CLEAN_AND_INVALIDATE);
      val_data_cache_ops_by_va((addr_t)&shared_data->shared_data_access[0].access_type,
                                                                 CLEAN_AND_INVALIDATE);
      val_data_cache_ops_by_va((addr_t)&shared_data->shared_data_access[0].addr,
                                                                 CLEAN_AND_INVALIDATE);

      if (val_pe_access_mut_el3())
      {
          val_set_status(pe_index, "FAIL", 05);
          return;
      }

      if (val_rlm_disable_mec())
      {
          val_set_status(pe_index, "FAIL", 06);
          return;
      }

      data_rd_rl = shared_data->shared_data_access[0].data;
      if (data_rd_rl != RANDOM_DATA_1)
      {
          val_set_status(pe_index, "FAIL", 07);
          return;
      }

  /* Restore MECID to GMECID */
  if (val_rlm_configure_mecid(VAL_GMECID))
  {
      val_set_status(pe_index, "FAIL", 8);
      return;
  }

  if (val_rlm_disable_mec())
  {
      val_set_status(pe_index, "FAIL", 9);
      return;
  }

      val_set_status(pe_index, "PASS", 01);
      return;
  }
}

static
void
payload2(void)
{
  uint32_t pe_index = val_pe_get_index_mpid(val_pe_get_mpid());

  if (pe_index == 0)
  {

      if (val_rlm_enable_mec())
      {
          val_set_status(pe_index, "FAIL", 8);
          return;
      }

      if (val_rlm_configure_mecid(MECID1))
      {
          val_set_status(pe_index, "FAIL", 9);
          return;
      }

      /* Store RANDOM_DATA_2 in VA_RL*/
      data_wt_rl = RANDOM_DATA_2;
      shared_data->num_access = 1;
      shared_data->shared_data_access[0].addr = VA_RL;
      shared_data->shared_data_access[0].data = data_wt_rl;
      shared_data->shared_data_access[0].access_type = WRITE_DATA;

      if (val_pe_access_mut_el3())
      {
          val_set_status(pe_index, "FAIL", 10);
          return;
      }

      val_set_status(pe_index, "PASS", 01);
      return;
  }

  if (pe_index == 1)
  {
      if (val_rlm_enable_mec())
      {
          val_set_status(pe_index, "FAIL", 9);
          return;
      }

      if (val_rlm_configure_mecid(MECID2))
      {
          val_set_status(pe_index, "FAIL", 10);
          return;
      }

      if (val_data_cache_ops_by_va_el3(VA_RL, CLEAN_AND_INVALIDATE))
      {
          val_set_status(pe_index, "FAIL", 11);
          return;
      }

      if (val_rlm_configure_mecid(MECID1))
      {
          val_set_status(pe_index, "FAIL", 12);
          return;
      }

      shared_data->num_access = 1;
      shared_data->shared_data_access[0].addr = VA_RL;
      shared_data->shared_data_access[0].access_type = READ_DATA;
      val_data_cache_ops_by_va((addr_t)&shared_data->num_access, CLEAN_AND_INVALIDATE);
      val_data_cache_ops_by_va((addr_t)&shared_data->shared_data_access[0].access_type,
                                                                 CLEAN_AND_INVALIDATE);
      val_data_cache_ops_by_va((addr_t)&shared_data->shared_data_access[0].addr,
                                                                 CLEAN_AND_INVALIDATE);

      if (val_pe_access_mut_el3())
      {
          val_set_status(pe_index, "FAIL", 13);
          return;
      }

      if (val_rlm_disable_mec())
      {
          val_set_status(pe_index, "FAIL", 14);
          return;
      }

      data_rd_rl = shared_data->shared_data_access[0].data;
      if (data_rd_rl != RANDOM_DATA_2)
      {
          val_set_status(pe_index, "FAIL", 15);
          return;
      }
  }

  /* Restore MECID to GMECID */
  if (val_rlm_configure_mecid(VAL_GMECID))
  {
      val_set_status(pe_index, "FAIL", 16);
      return;
  }

  if (val_rlm_disable_mec())
  {
      val_set_status(pe_index, "FAIL", 17);
      return;
  }

  val_set_status(pe_index, "PASS", 01);
  return;
}

static
void
payload4(uint32_t PoX)
{
  uint32_t pe_index = val_pe_get_index_mpid(val_pe_get_mpid());

  if (val_add_gpt_entry_el3(PA_RL, GPT_ANY))
  {
      val_set_status(pe_index, "FAIL", 11);
      return;
  }

  if (val_add_mmu_entry_el3(VA_RL, PA_RL, (mem_attr | LOWER_ATTRS(PAS_ATTR(REALM_PAS)))))
  {
      val_set_status(pe_index, "FAIL", 12);
      return;
  }

  if (val_rlm_enable_mec())
  {
      val_set_status(pe_index, "FAIL", 13);
      return;
  }

  if (val_rlm_configure_mecid(MECID1))
  {
      val_set_status(pe_index, "FAIL", 14);
      return;
  }

  /* Store RANDOM_DATA_1 in PA_RT*/
  data_wt_rl = RANDOM_DATA_3;
  shared_data->num_access = 1;
  shared_data->shared_data_access[0].addr = VA_RL;
  shared_data->shared_data_access[0].data = data_wt_rl;
  shared_data->shared_data_access[0].access_type = WRITE_DATA;

  if (val_pe_access_mut_el3())
  {
      val_set_status(pe_index, "FAIL", 15);
      return;
  }

  if (val_rlm_configure_mecid(MECID2))
  {
      val_set_status(pe_index, "FAIL", 16);
      return;
  }

  if (PoX == PoPA) {
      if (val_data_cache_ops_by_pa_el3(PA_RL, REALM_PAS))
      {
          val_set_status(pe_index, "FAIL", 17);
          return;
      }
  }

  else if (PoX == PoE)
  {
      if (val_cmo_to_poe(PA_RL))
      {
          val_set_status(pe_index, "FAIL", 18);
          return;
      }
  }
  else if (PoX == PoC)
  {
      if (val_data_cache_ops_by_va_el3(VA_RL, CLEAN_AND_INVALIDATE))
      {
          val_set_status(pe_index, "FAIL", 19);
          return;
      }
  }

  if (val_rlm_configure_mecid(MECID1))
  {
      val_set_status(pe_index, "FAIL", 20);
      return;
  }

  shared_data->num_access = 1;
  shared_data->shared_data_access[0].addr = VA_RL;
  shared_data->shared_data_access[0].access_type = READ_DATA;
  if (val_pe_access_mut_el3())
  {
      val_set_status(pe_index, "FAIL", 21);
      return;
  }

  data_rd_rl = shared_data->shared_data_access[0].data;

  if (data_rd_rl != data_wt_rl)
  {
      val_set_status(pe_index, "FAIL", 22);
      return;
  }

   /* Restore MECID to GMECID */
  if (val_rlm_configure_mecid(VAL_GMECID))
  {
      val_set_status(pe_index, "FAIL", 23);
      return;
  }

  if (val_rlm_disable_mec())
  {
      val_set_status(pe_index, "FAIL", 24);
      return;
  }

  val_set_status(pe_index, "PASS", 25);
  return;
}

static
void
payload3(void)
{
  payload4(PoPA);

  payload4(PoE);

  payload4(PoC);

}

uint32_t
mec_cmo_uses_correct_mecid_entry(uint32_t num_pe)
{

  uint32_t status = ACS_STATUS_FAIL, i;  //default value
  char8_t *test_status = NULL;

  status = val_initialize_test(TEST_NAME, TEST_DESC, num_pe, TEST_RULE);

  /* This check is when user is forcing us to skip this test */
  if (status != ACS_STATUS_SKIP)
  {
      val_run_test_payload(num_pe, payload1, 0);

      for (i = 0; i < num_pe; i++)
      {
          test_status = val_get_status(i);
          if (IS_TEST_FAIL(test_status))
              break;
      }

      if (IS_TEST_PASS(test_status))
          val_run_test_payload(num_pe, payload2, 0);

      for (i = 0; i < num_pe; i++)
      {
          test_status = val_get_status(i);
          if (IS_TEST_FAIL(test_status))
              break;
      }

      if (IS_TEST_PASS(test_status))
      {
          num_pe = 1;
          val_run_test_payload(num_pe, payload3, 0);
      }
  }

  /* get the result from all PE and check for failure */
  status = val_check_for_error(num_pe);

  val_report_status(0, "END");

  return status;
}
