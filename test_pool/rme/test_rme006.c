/** @file
 * Copyright (c) 2022-2025, Arm Limited or its affiliates. All rights reserved.
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

#define TEST_NUM   (ACS_RME_TEST_NUM_BASE  +  06)
#define TEST_DESC  "To check if resources are aligned to page granularity  "
#define TEST_RULE  "PE_22"

/*
 * @brief  The test validates that the address range of resources arealigned to the page
 *         granularity supported by the system.
 * 1. The alignment of the base addresses of the resources are checked against the
 *    page granularity of the system.
 * 2. The test expects the addresses to be aligned to the page granularity (4KB in this case).
 */
static
void payload(void)
{

  uint32_t index = val_pe_get_index_mpid(val_pe_get_mpid()), num_regn;
  uint8_t status_fail_cnt, pgs, p[3] = {12 /*4KB*/, 16 /*64KB*/, 14 /*16KB*/};
  uint64_t PA;

  num_regn = mem_region_cfg.header.num_of_regn_gpc;
  status_fail_cnt = 0;

  for (uint32_t regn_cnt = 0; regn_cnt < num_regn; ++regn_cnt)
  {

    PA = mem_region_cfg.regn_info[regn_cnt].base_addr;
    /* The page granularity is always assumed to be 4KB for the current resources*/
    pgs = p[0];

    val_print(ACS_PRINT_DEBUG, "\n  The PA is 0x%lx", PA);
    val_print(ACS_PRINT_DEBUG, "\n  The test expects Adress to be aligned to the", 0);
    val_print(ACS_PRINT_DEBUG, "\n  page granularity, 4KB by default", 0);
    if ((PA & ((0x1ull << pgs) - 1)))
    {
      val_print(ACS_PRINT_ERR, "\n  The address 0x%llx is not aligned to the page granularity", PA);
      status_fail_cnt++;
    }

  }
  if (status_fail_cnt >= 1)
    val_set_status(index, RESULT_FAIL(TEST_NUM, 01));
  else
    val_set_status(index, RESULT_PASS(TEST_NUM, 01));
  return;
}


uint32_t
rme006_entry(void)
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

