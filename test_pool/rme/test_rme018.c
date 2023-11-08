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
#include "val/include/mem_interface.h"

#define TEST_NUM   (ACS_RME_TEST_NUM_BASE  +  18)
#define TEST_DESC  "To validate that snoop filter considers PAS"
#define TEST_RULE  "PE_02_B"

#define Data1 0xAD
#define Data2 0xBC

uint64_t PA, size, VA1;

static
void payload2(void)
{
  uint32_t index = val_pe_get_index_mpid(val_pe_get_mpid());
  uint64_t VA2, rd_data, attr;

  VA2 = val_get_free_va(size);
  attr = (CACHEABLE_ATTR(WRITE_BACK_NT) | SHAREABLE_ATTR(INNER_SHAREABLE) | REALM_PAS);
  val_add_mmu_entry_el3(VA2, PA, attr);

  /* Access VA2 from this PE */
  shared_data->num_access = 1;
  shared_data->shared_data_access[0].addr = VA2;
  shared_data->shared_data_access[0].access_type = READ_DATA;

  val_pe_access_mut_el3();
  rd_data = shared_data->shared_data_access[0].data;

  if (rd_data == Data2)
  {
    val_set_test_data(index, rd_data, 0);
    val_set_status(index, RESULT_FAIL(TEST_NUM, 01));
  }
  else
    val_set_status(index, RESULT_PASS(TEST_NUM, 01));

  return;
}

/**
 * @brief  The test validates that snoop filter considers PAS.
 * 1. Map the VA1 to PA in PE1 with Write Back Shareablity attribute and ROOT PAS.
 * 2. Store Data1 in VA1 and perform CMO to PoPA.
 * 3. Start executing in the secondary PE, PE2 while PE1 is being halt.
 * 4. Map the VA2 to PA in PE2 with Write Back Shareablity attribute and REALM PAS.
 * 5. Access VA2 and update the status of the PE2.
 * 6. Read the status form PE2 in PE1 and set the result status.
**/
static
void payload1(uint32_t num_pe)
{
  uint32_t my_index = val_pe_get_index_mpid(val_pe_get_mpid());
  uint32_t timeout, sec_index;
  uint64_t pe2_data, attr;

  size = val_get_min_tg();
  PA = val_get_free_pa(size, size);
  attr = (CACHEABLE_ATTR(WRITE_BACK_NT) | SHAREABLE_ATTR(INNER_SHAREABLE) | ROOT_PAS);
  VA1 = val_get_free_va(size);
  val_add_mmu_entry_el3(VA1, PA, attr);

  /* Store Data1 and Data2 in the PA_RT address */
  shared_data->num_access = 1;
  shared_data->shared_data_access[0].addr = VA1;
  shared_data->shared_data_access[0].data = Data1;
  shared_data->shared_data_access[0].access_type = WRITE_DATA;
  val_pe_access_mut_el3();

  /* Perform CIPAPA to ensure Data1 is flushed */
  val_data_cache_ops_by_pa_el3(PA, ROOT_PAS);

  shared_data->num_access = 2;
  shared_data->shared_data_access[0].addr = VA1;
  shared_data->shared_data_access[0].access_type = READ_DATA;
  shared_data->shared_data_access[1].addr = VA1;
  shared_data->shared_data_access[1].data = Data2;
  shared_data->shared_data_access[1].access_type = WRITE_DATA;
  val_pe_access_mut_el3();

  //Moving to the next PE index to execute payload2
  if ((my_index + 1) >= val_pe_get_num())
      sec_index = my_index-1;
  else
      sec_index = my_index+1;
  timeout = TIMEOUT_MEDIUM;
  val_execute_on_pe(sec_index, payload2, 0);
  while  ((--timeout) && (IS_RESULT_PENDING(val_get_status(sec_index))))
	  ;
  if (!timeout)
  {
    val_print(ACS_PRINT_ERR, "\n       **Timed out** for PE index = %d", sec_index);
    val_set_status(sec_index, RESULT_FAIL(TEST_NUM, 02));
    return;
  }

  if (IS_TEST_FAIL(val_get_status(sec_index)))
  {
    val_get_test_data(sec_index, &pe2_data, 0);
    val_print(ACS_PRINT_ERR, "\n  The data read in PE2 is 0x%x", pe2_data);
    val_print(ACS_PRINT_ERR, " which is same as the data stored in PE1, ", 0);
    val_print(ACS_PRINT_ERR, " 0x%x", Data2);
    val_set_status(sec_index, RESULT_FAIL(TEST_NUM, 01));
  }
  else
    val_set_status(my_index, RESULT_PASS(TEST_NUM, 01));
  return;

}

uint32_t
rme018_entry(uint32_t num_pe)
{

  if (num_pe < 2) {
      val_print(ACS_PRINT_DEBUG, "\n  Skipping the test as Number of PEs is less than required", 0);
      return ACS_STATUS_SKIP;
  }

  uint32_t status = ACS_STATUS_FAIL;

  status = val_initialize_test(TEST_NUM, TEST_DESC, num_pe, TEST_RULE);

  if (status != ACS_STATUS_SKIP)
      payload1(num_pe);

  status = val_check_for_error(TEST_NUM, num_pe, TEST_RULE);

  val_report_status(0, RME_ACS_END(TEST_NUM), TEST_RULE);

  return status;
}


