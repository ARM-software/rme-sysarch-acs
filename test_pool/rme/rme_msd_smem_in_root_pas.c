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

#include "val/include/val.h"
#include "val/include/val_pe.h"
#include "val/include/val_common.h"

#include "val/include/val_interface.h"
#include "val/include/val_test_entry.h"
#include "val/include/val_el32.h"

#define NUM_PAS 4
#define NUM_SMEM_REGN 2

#define TEST_NAME  "rme_msd_smem_in_root_pas"
#define TEST_DESC  "Verify that MSD SMEM is in ROOT PAS only               "
#define TEST_RULE  "RNXJLB/RCSSDG"

/**
 * @brief  The test validates that the Root SMEM can always be accessed through ROOT access PAS only
 * 1. Access the Root SMEM using all access PAS
 * 2. Observe that only Root access PAS is successful
**/
static
void payload(void)
{
  uint8_t status_fail_cnt = 0;
  uint32_t index = val_pe_get_index_mpid(val_pe_get_mpid()), security_state, attr;
  uint64_t pas_list[4] = {ROOT_PAS, REALM_PAS, NONSECURE_PAS, SECURE_PAS};
  uint64_t VA, PA, VA_Top, size, rd_data1, rd_data2;
  uint64_t root_smem_available = val_get_root_smem_base();

  shared_data->shared_data_access[0].data = INIT_DATA;
  size = val_get_min_tg();

  if (root_smem_available)
    PA = root_smem_available;
  else {
    PA = val_get_free_pa(size, size);
    val_add_gpt_entry_el3(PA, GPT_ROOT);
  }

  VA = val_get_free_va(NUM_PAS * NUM_SMEM_REGN * size);
  VA_Top = VA + size - 8;
  security_state = ROOT_PAS;
  attr = LOWER_ATTRS(PGT_ENTRY_ACCESS | SHAREABLE_ATTR(NON_SHAREABLE) | PGT_ENTRY_AP_RW);

  for (int pas_cnt = 0; pas_cnt < 4; ++pas_cnt)
  {
      val_print(ACS_PRINT_TEST, " Accessing the Root SMEM from PAS: %lld", pas_list[pas_cnt]);
      if (val_add_mmu_entry_el3(VA, PA, (attr | LOWER_ATTRS(PAS_ATTR(pas_list[pas_cnt])))))
      {
        val_print(ACS_PRINT_ERR, " Failed to add MMU entry for VA 0x%llx", VA);
        status_fail_cnt++;
        continue;
      }

      if (security_state == pas_list[pas_cnt]) {

        shared_data->exception_expected = CLEAR;
        shared_data->access_mut = SET;
        shared_data->arg1 = VA;
        if (val_pe_access_mut_el3())
        {
          val_print(ACS_PRINT_ERR, " Failed to access VA = 0x%lx", VA);
          status_fail_cnt++;
        }

        if (shared_data->exception_generated == SET)
        {
          val_print(ACS_PRINT_ERR, "  The exception is generated when Resource PAS \
                          and Access PAS are same", 0);
          status_fail_cnt++;
        }

        /* Also test for Top address within the minimum TG size to make sure
         * SMEM region is compliant with the page size supported
         **/
        shared_data->exception_expected = CLEAR;
        shared_data->access_mut = SET;
        VA_Top = VA + size - 8;
        shared_data->arg1 = VA_Top;
        if (val_pe_access_mut_el3())
        {
          val_print(ACS_PRINT_ERR, " Failed to access VA_Top = 0x%lx", VA_Top);
          status_fail_cnt++;
        }

        if (shared_data->exception_generated == SET)
        {
          val_print(ACS_PRINT_ERR, "  The exception is generated when Resource PAS \
                          and Access PAS are same", 0);
          status_fail_cnt++;
        }

      } else {
        shared_data->exception_expected = SET;
        shared_data->access_mut = SET;
        shared_data->pas_filter_flag = SET;
        shared_data->arg1 = VA;
        if (val_pe_access_mut_el3())
        {
          val_print(ACS_PRINT_ERR, " Failed to access VA = 0x%lx", VA);
          status_fail_cnt++;
        }
        rd_data1 = shared_data->shared_data_access[0].data;
        shared_data->pas_filter_flag = CLEAR;

        val_print(ACS_PRINT_DEBUG, " The data read when res pas != acc pas is 0x%lx", rd_data1);
        /* If fault is not generated, check that the load of the address must not be updated */
        if (shared_data->exception_generated == CLEAR)
        {
          if (rd_data1 != INIT_DATA) {
            val_print(ACS_PRINT_ERR, "  The exception is not generated when Resource PAS \
                            and Access PAS are different", 0);
            status_fail_cnt++;
          }
        }
        shared_data->exception_generated = CLEAR;

        /* Also test for Top address within the minimum TG size to make sure
         * SMEM region is compliant with the page size supported
         **/
        VA_Top = VA + size - 8;
        shared_data->exception_expected = SET;
        shared_data->access_mut = SET;
        shared_data->pas_filter_flag = SET;
        shared_data->arg1 = VA_Top;
        if (val_pe_access_mut_el3())
        {
          val_print(ACS_PRINT_ERR, " Failed to access VA_Top = 0x%lx", VA_Top);
          status_fail_cnt++;
        }
        rd_data2 = shared_data->shared_data_access[0].data;
        shared_data->pas_filter_flag = CLEAR;

        val_print(ACS_PRINT_DEBUG, " The data read when res pas != acc pas is 0x%lx", rd_data2);
        /* If fault is not generated, check that the load of the address must not be updated */
        if (shared_data->exception_generated == CLEAR)
        {
          if (rd_data2 != INIT_DATA) {
            val_print(ACS_PRINT_ERR, "  Unexpected successful access when resource pas \
                            is not same as access pas", 0);
            status_fail_cnt++;
          }
        }
        shared_data->exception_generated = CLEAR;
      }
      VA += size;

  }
  val_print(ACS_PRINT_DEBUG, " The accesses did not go as expected for %d times",
                  status_fail_cnt);
  val_print(ACS_PRINT_DEBUG, " The test expects zero status_fail_cnt", 0);
  if (status_fail_cnt >= 1)
  {
    val_set_status(index, "FAIL", 01);
  }
  else
    val_set_status(index, "PASS", 01);
  return;

}

uint32_t
rme_msd_smem_in_root_pas_entry(void)
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


