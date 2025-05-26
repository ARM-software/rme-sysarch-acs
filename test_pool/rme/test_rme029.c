/** @file
 * Copyright (c) 2023-2025, Arm Limited or its affiliates. All rights reserved.
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
#include "val/include/rme_acs_memory.h"
#include "val/include/rme_acs_el32.h"

#define NUM_PAS 4

#define TEST_NUM   (ACS_RME_TEST_NUM_BASE  +  29)
#define TEST_DESC  "Pas filter in In-Active mode doesn't service requests  "
#define TEST_RULE  "PAS_FLTR_01"

/*
 * @brief  The test validates the PAS filter doesn't service request in Non-Active mode.
 * 1. Change the mode of PAS_FILTER to In-active.
 * 2. Loop through every PAS_FILTER protected regions, and try to access the same
 *    using the VAs mapped in MMU with the access pas same as correspoding resource pas.
 * 3. If any access results in a rd_data that is different from the INIT_DATA,
 *    then the test FAILs, otherwise PASSes.
 */
static
void payload(void)
{
  uint8_t status_fail_cnt = 0;
  uint32_t index = val_pe_get_index_mpid(val_pe_get_mpid()), security_state, num_regn, attr;
  uint64_t VA, rd_data, size;
  MEM_REGN_INFO_TABLE *mem_region_pas_filter_cfg;

  mem_region_pas_filter_cfg = val_mem_pas_info_table();
  num_regn = mem_region_pas_filter_cfg->header.num_of_regn_gpc;

  if (!val_is_pas_filter_mode_programmable()) {
    val_print(ACS_PRINT_ERR, "\n       The pas filter mode is not programmable in this system", 0);
    val_set_status(index, RESULT_SKIP(TEST_NUM, 01));
    return;
  }
  //Change the Active mode of the PAS filter
  val_pas_filter_active_mode_el3(CLEAR);
  shared_data->shared_data_access[0].data = INIT_DATA;
  size = val_get_min_tg();
  VA = val_get_free_va(num_regn * size);
  attr = LOWER_ATTRS(PGT_ENTRY_ACCESS | SHAREABLE_ATTR(NON_SHAREABLE) | PGT_ENTRY_AP_RW);

  for (uint32_t regn_cnt = 0; regn_cnt < num_regn; ++regn_cnt)
  {

    shared_data->arg0 = mem_region_pas_filter_cfg->regn_info[regn_cnt].base_addr;
    security_state = mem_region_pas_filter_cfg->regn_info[regn_cnt].resourse_pas;
    val_add_mmu_entry_el3(VA, shared_data->arg0, (attr | LOWER_ATTRS(PAS_ATTR(security_state))));

    shared_data->exception_expected = CLEAR;
    shared_data->access_mut = SET;
    shared_data->pas_filter_flag = SET;
    shared_data->arg1 = VA;
    val_pe_access_mut_el3();    //Accessing MUT
    rd_data = shared_data->shared_data_access[0].data;
    shared_data->pas_filter_flag = CLEAR;

    val_print(ACS_PRINT_DEBUG, "\n  The data read when pas is in-active is 0x%lx", rd_data);
    if (rd_data != INIT_DATA) {
      val_print(ACS_PRINT_ERR, "\n  The data is updated even though the PAS_FILTER is InActive", 0);
      status_fail_cnt++;
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
rme029_entry(void)
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

