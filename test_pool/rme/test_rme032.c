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

#include "val/include/mem_interface.h"
#include "val/include/val_interface.h"
#include "val/include/rme_test_entry.h"
#include "val/include/rme_acs_el32.h"
#include "val/include/sys_config.h"

#define NUM_PAS 4
#define NUM_SMEM_REGN 2

#define TEST_NUM   (ACS_RME_TEST_NUM_BASE  +  32)
#define TEST_DESC  "Verify that MSD SMEM is in ROOT PAS after reset        "
#define TEST_RULE  "SYS_RST_01"

/**
 * @brief  The test validates that the Root SMEM can always be accessed through
 *         ROOT access PAS after reset.
 * 1. Apply system reset.
 * 2. Access the Root SMEM using all access PAS
 * 3. Observe that only Root access PAS is successful
**/
static
void payload(void)
{
  if (val_read_reset_status() == RESET_TST32_FLAG)
          goto reset_done;

  val_write_reset_status(RESET_TST32_FLAG);
  val_save_global_test_data();
  val_system_reset();

reset_done:
  val_restore_global_test_data();
  val_print(ACS_PRINT_DEBUG, "\n  After system reset", 0);
  uint8_t status_fail_cnt = 0;
  uint32_t index = val_pe_get_index_mpid(val_pe_get_mpid()), security_state, attr;
  uint64_t pas_list[4] = {ROOT_PAS, REALM_PAS, NONSECURE_PAS, SECURE_PAS};
  uint64_t VA, PA, VA_Top, size, rd_data1, rd_data2;

  shared_data->shared_data_access[0].data = INIT_DATA;
  size = val_get_min_tg();
  PA = ROOT_SMEM_BASE;
  VA = val_get_free_va(NUM_PAS * NUM_SMEM_REGN * size);
  VA_Top = VA + size - 8;
  security_state = ROOT_PAS;
  attr = LOWER_ATTRS(PGT_ENTRY_ACCESS | SHAREABLE_ATTR(NON_SHAREABLE) | PGT_ENTRY_AP_RW);

  for (int pas_cnt = 0; pas_cnt < 4; ++pas_cnt)
  {
      val_print(ACS_PRINT_DEBUG, "\n  Access PAS = 0x%llx", pas_list[pas_cnt]);
      val_add_mmu_entry_el3(VA, PA, (attr | LOWER_ATTRS(PAS_ATTR(pas_list[pas_cnt]))));

      if (security_state == pas_list[pas_cnt]) {

        shared_data->exception_expected = CLEAR;
        shared_data->access_mut = SET;
        shared_data->arg1 = VA;
        val_pe_access_mut_el3();    //Accessing MUT

        if (shared_data->exception_generated == SET)
        {
          val_print(ACS_PRINT_ERR, "\n  The exception is generated when Resource PAS \
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
        val_pe_access_mut_el3();    //Accessing MUT

        if (shared_data->exception_generated == SET)
        {
          val_print(ACS_PRINT_ERR, "\n  The exception is generated when Resource PAS \
                          and Access PAS are same", 0);
          status_fail_cnt++;
        }

      } else {
        shared_data->exception_expected = SET;
        shared_data->access_mut = SET;
        shared_data->pas_filter_flag = SET;
        shared_data->arg1 = VA;
        val_pe_access_mut_el3();    //Accessing MUT
        rd_data1 = shared_data->shared_data_access[0].data;
        shared_data->pas_filter_flag = CLEAR;

        val_print(ACS_PRINT_DEBUG, "\n  The data read when res pas != acc pas is 0x%lx", rd_data1);
        /* If fault is not generated, check that the load of the address must not be updated */
        if (shared_data->exception_generated == CLEAR)
        {
          if (rd_data1 != INIT_DATA) {
            val_print(ACS_PRINT_ERR, "\n  The exception is not generated when Resource PAS \
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
        val_pe_access_mut_el3();    //Accessing MUT
        rd_data2 = shared_data->shared_data_access[0].data;
        shared_data->pas_filter_flag = CLEAR;

        val_print(ACS_PRINT_DEBUG, "\n  The data read when res pas != acc pas is 0x%lx", rd_data2);
        /* If fault is not generated, check that the load of the address must not be updated */
        if (shared_data->exception_generated == CLEAR)
        {
          if (rd_data2 != INIT_DATA) {
            val_print(ACS_PRINT_ERR, "\n  Unexpected successful access when resource pas \
                            is not same as access pas", 0);
            status_fail_cnt++;
          }
        }
        shared_data->exception_generated = CLEAR;
      }
      VA += size;

  }
  val_print(ACS_PRINT_DEBUG, "\n  The accesses did not go as expected for %d times",
                  status_fail_cnt);
  val_print(ACS_PRINT_DEBUG, "\n  The test expects zero status_fail_cnt", 0);
  if (status_fail_cnt >= 1)
  {
    val_set_status(index, RESULT_FAIL(TEST_NUM, 01));
  }
  else
    val_set_status(index, RESULT_PASS(TEST_NUM, 01));
  return;

}

uint32_t
rme032_entry(void)
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


