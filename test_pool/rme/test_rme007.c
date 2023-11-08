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

#include "val/include/val_interface.h"
#include "val/include/rme_acs_el32.h"
#include "val/include/sys_config.h"

#define TEST_NUM   (ACS_RME_TEST_NUM_BASE  +  07)
#define TEST_DESC  "To check if the address range of resources is not physically aliased"
#define TEST_RULE  "PE_21"

/*
 * @brief  The test validates that the address range of resources is not physically aliased.
 * 1. The base addresses of each resource with their respective size are checked against
 *    each other.
 * 2. The test expects that the addresses along their sizes are not overlapped with one another.
 */
static
void payload(void)
{

  uint32_t index = val_pe_get_index_mpid(val_pe_get_mpid()), num_regn;
  uint8_t status_fail_cnt;
  uint64_t region_size, Top_Addr, Base_Addr, Top_Addr_cmpr, Base_Addr_cmpr, region_size_cmpr;

  num_regn = mem_region_cfg.header.num_of_regn_gpc;
  status_fail_cnt = 0;

  for (int regn_cnt = 0; regn_cnt < num_regn; ++regn_cnt) {

    Base_Addr = mem_region_cfg.regn_info[regn_cnt].base_addr;
    region_size = mem_region_cfg.regn_info[regn_cnt].regn_size;
    Top_Addr = Base_Addr + region_size - 1;

    for (int cmpr_regn_cnt = regn_cnt + 1; cmpr_regn_cnt < num_regn; ++cmpr_regn_cnt)
    {

      Base_Addr_cmpr = mem_region_cfg.regn_info[cmpr_regn_cnt].base_addr;
      region_size_cmpr = mem_region_cfg.regn_info[cmpr_regn_cnt].regn_size;
      Top_Addr_cmpr = Base_Addr_cmpr + region_size_cmpr - 1;
      if (Top_Addr < Base_Addr_cmpr)
        continue;

      else if (Base_Addr > Top_Addr_cmpr)
        continue;

      else {
        val_print(ACS_PRINT_ERR, "    Overlapping found between 0x%lx and ", Base_Addr);
	val_print(ACS_PRINT_ERR, "0x%lx \n", Base_Addr_cmpr);
        status_fail_cnt++;
      }

    }
  }

  val_print(ACS_PRINT_DEBUG, "\n  The Addresses were found to be overlapped for %d times",
                  status_fail_cnt);
  val_print(ACS_PRINT_DEBUG, "\n  The test expects zero status_fail_cnt", 0);

  if (status_fail_cnt >= 1)
    val_set_status(index, RESULT_FAIL(TEST_NUM, 01));
  else
    val_set_status(index, RESULT_PASS(TEST_NUM, 01));
  return;
}

uint32_t
rme007_entry(void)
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

