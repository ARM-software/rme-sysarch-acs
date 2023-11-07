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

#include "val/include/rme_test_entry.h"
#include "val/include/val_interface.h"
#include "val/include/rme_acs_el32.h"
#include "val/include/sys_config.h"
#include "val/include/mem_interface.h"

#define TEST_NUM   (ACS_RME_TEST_NUM_BASE + 12)
#define TEST_DESC  "To Verify Realm SMEM does not reveal old data after system reset"
#define TEST_RULE  "SYS_RST_02"

/*
 * @brief  The test validates that Realm SMEM does not reveal old data after the reset.
 * 1. Store the data, wt_data in the address of the Realm SMEM.
 * 2. Execute reset
 * 3. Read the same address and see that the data read, rd_data is different than wt_data.
 */
static
void payload(void)
{

  struct_sh_data *shared_data = (struct_sh_data *) SHARED_ADDRESS;
  uint32_t index = val_pe_get_index_mpid(val_pe_get_mpid());
  uint64_t wt_data, rd_data, PA_RLM = REALM_SMEM_BASE;

  wt_data = RANDOM_DATA_1;
  if (val_read_reset_status() == RESET_TST12_FLAG)
          goto reset_done;

  /* Store DATA1 to PA of Realm SMEM and read the PA from realm SMEM after reset.*/
  val_add_mmu_entry_el3(PA_RLM, PA_RLM, REALM_PAS);//Flat-mapping
  shared_data->num_access = 1;
  shared_data->shared_data_access[0].addr = PA_RLM;
  shared_data->shared_data_access[0].data = wt_data;
  shared_data->shared_data_access[0].access_type = WRITE_DATA;
  val_pe_access_mut_el3();

  val_write_reset_status(RESET_TST12_FLAG);
  val_save_global_test_data();
  val_system_reset();

reset_done:
  val_print(ACS_PRINT_INFO, "\n  After system reset", 0);
  val_restore_global_test_data();
  val_add_mmu_entry_el3(PA_RLM, PA_RLM, REALM_PAS);
  /* Read the PA from realm SMEM after reset */
  shared_data->num_access = 1;
  shared_data->shared_data_access[0].addr = PA_RLM;
  shared_data->shared_data_access[0].access_type = READ_DATA;
  val_pe_access_mut_el3();
  rd_data = shared_data->shared_data_access[0].data;

  val_print(ACS_PRINT_DEBUG, "\n  The data stored is 0x%lx", wt_data);
  val_print(ACS_PRINT_DEBUG, " and the data read after the reset is 0x%lx", rd_data);
  val_print(ACS_PRINT_DEBUG, "\n  The test expects the data to be not same", 0);
  if (wt_data == rd_data)
    val_set_status(index, RESULT_FAIL(TEST_NUM, 01));

  else
    val_set_status(index, RESULT_PASS(TEST_NUM, 01));

  return;
}

uint32_t
rme012_entry(void)
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

