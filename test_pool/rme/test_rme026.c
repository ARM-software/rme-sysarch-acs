/** @file
 * Copyright (c) 2023, Arm Limited or its affiliates. All rights reserved.
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

#include "val/include/val_interface.h"
#include "val/include/rme_test_entry.h"
#include "val/include/rme_acs_el32.h"
#include "val/include/sys_config.h"

#define NUM_PAS 4

#define TEST_NUM   (ACS_RME_TEST_NUM_BASE  +  26)
#define TEST_DESC  "RNVS prog functions can only be accessed from Root PAS "
#define TEST_RULE  "PE_17"

/**
 * @brief  The test validates that RNVS programming functions can be accessed from
 *         ROOT access PAS only
 * 1. Access the RNVS mailbox memory, RME_RNVS_MAILBOX_MEM using all the access PASs.
 * 2. Observe that only Root access PAS is successful.
**/
static
void payload(void)
{
  uint8_t status_fail_cnt = 0;
  uint32_t index = val_pe_get_index_mpid(val_pe_get_mpid()), security_state;
  uint64_t pas_list[4] = {ROOT_PAS, REALM_PAS, NONSECURE_PAS, SECURE_PAS};
  uint64_t VA, PA, size, rd_data;

  shared_data->shared_data_access[0].data = INIT_DATA;
  size = val_get_min_tg();
  PA = RME_RNVS_MAILBOX_MEM;
  VA = val_get_free_va(NUM_PAS * size);
  security_state = ROOT_PAS;

  for (int pas_cnt = 0; pas_cnt < 4; ++pas_cnt)
  {
      val_add_mmu_entry_el3(VA, PA, pas_list[pas_cnt]);

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

      } else {
        shared_data->exception_expected = SET;
        shared_data->access_mut = SET;
        shared_data->pas_filter_flag = SET;
        shared_data->arg1 = VA;
        val_pe_access_mut_el3();    //Accessing MUT
        rd_data = shared_data->shared_data_access[0].data;
        shared_data->pas_filter_flag = CLEAR;

        val_print(ACS_PRINT_DEBUG, "\n  The data read when res pas != acc pas is 0x%lx", rd_data);
        /* If fault is not generated, check that the load of the address must not be updated */
        if (shared_data->exception_generated == CLEAR)
        {
          if (rd_data != INIT_DATA) {
            val_print(ACS_PRINT_ERR, "\n  The exception is not generated when Resource PAS \
                            and Access PAS are different", 0);
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
rme026_entry(void)
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

