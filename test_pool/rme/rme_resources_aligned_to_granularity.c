/** @file
 * Copyright (c) 2022-2026, Arm Limited or its affiliates. All rights reserved.
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
#include "val/include/val_el32.h"

#define TEST_NAME  "rme_resources_aligned_to_granularity"
#define TEST_DESC  "Check resources are page aligned and not aliased      "
#define TEST_RULE  "RKGDVK"

/*
 * @brief  The test validates GPT Resource requirements for RKGDVK.
 * 1. The base address, size and range end of each GPC protected Resource are
 *    checked against the page granularity of the system.
 * 2. The address range of each Resource is checked against every other
 *    Resource to ensure there is no physical aliasing/overlap.
 */
static
void payload(void)
{

  uint32_t index = val_pe_get_index_mpid(val_pe_get_mpid()), num_regn;
  uint32_t regn_cnt, cmpr_regn_cnt, status_fail_cnt;
  uint8_t pgs, p[3] = {12 /*4KB*/, 16 /*64KB*/, 14 /*16KB*/};
  uint64_t base_addr, top_addr, region_size;
  uint64_t base_addr_cmpr, top_addr_cmpr, region_size_cmpr;
  MEM_REGN_INFO_TABLE *mem_region_cfg;

  mem_region_cfg = val_mem_gpc_info_table();
  num_regn = mem_region_cfg->header.num_of_regn_gpc;
  status_fail_cnt = 0;
  if (num_regn == 0) {
    val_print(ACS_PRINT_WARN, " No GPC protected regions provided by the platform", 0);
    val_set_status(index, "SKIP", 01);
    return;
  }

  for (regn_cnt = 0; regn_cnt < num_regn; ++regn_cnt)
  {

    base_addr = mem_region_cfg->regn_info[regn_cnt].base_addr;
    region_size = mem_region_cfg->regn_info[regn_cnt].regn_size;
    val_print(ACS_PRINT_TEST, " Checking Resource range 0x%llx", base_addr);

    /* The page granularity is always assumed to be 4KB for the current resources*/
    pgs = p[0];

    val_print(ACS_PRINT_DEBUG, " The PA is 0x%lx", base_addr);
    val_print(ACS_PRINT_DEBUG, " The test expects address to be aligned to the", 0);
    val_print(ACS_PRINT_DEBUG, " page granularity, 4KB by default", 0);
    if ((base_addr & ((0x1ull << pgs) - 1)))
    {
      val_print(ACS_PRINT_ERR, " The address 0x%llx is not aligned to the page granularity",
                base_addr);
      status_fail_cnt++;
    }

    if (region_size == 0)
    {
      val_print(ACS_PRINT_ERR, " The resource at 0x%llx has zero size", base_addr);
      status_fail_cnt++;
      continue;
    }

    if ((region_size & ((0x1ull << pgs) - 1)))
    {
      val_print(ACS_PRINT_ERR, " The resource size 0x%llx is not page granular",
                region_size);
      status_fail_cnt++;
    }

    if ((region_size - 1) > (~0ULL - base_addr))
    {
      val_print(ACS_PRINT_ERR, " Resource range overflows physical address space", 0);
      status_fail_cnt++;
      continue;
    }

    top_addr = base_addr + region_size - 1;
    if (((top_addr & ((0x1ull << pgs) - 1)) != ((0x1ull << pgs) - 1)))
    {
      val_print(ACS_PRINT_ERR, " The resource end 0x%llx is not page granular",
                top_addr);
      status_fail_cnt++;
    }

    for (cmpr_regn_cnt = regn_cnt + 1; cmpr_regn_cnt < num_regn; ++cmpr_regn_cnt)
    {
      base_addr_cmpr = mem_region_cfg->regn_info[cmpr_regn_cnt].base_addr;
      region_size_cmpr = mem_region_cfg->regn_info[cmpr_regn_cnt].regn_size;
      if (region_size_cmpr == 0)
        continue;

      /* The outer loop reports invalid comparison ranges on their own iteration. */
      if ((region_size_cmpr - 1) > (~0ULL - base_addr_cmpr))
        continue;

      top_addr_cmpr = base_addr_cmpr + region_size_cmpr - 1;

      if ((top_addr < base_addr_cmpr) || (base_addr > top_addr_cmpr))
        continue;

      val_print(ACS_PRINT_ERR, " Overlap found between 0x%lx and ", base_addr);
      val_print(ACS_PRINT_ERR, "0x%lx ", base_addr_cmpr);
      status_fail_cnt++;
    }

  }
  if (status_fail_cnt >= 1)
    val_set_status(index, "FAIL", 01);
  else
    val_set_status(index, "PASS", 01);
  return;
}


uint32_t
rme_resources_aligned_to_granularity_entry(uint32_t num_pe)
{

  num_pe = 1;
  uint32_t status = ACS_STATUS_FAIL;

  status = val_initialize_test(TEST_NAME, TEST_DESC, num_pe, TEST_RULE);

  if (status != ACS_STATUS_SKIP)
      val_run_test_payload(num_pe, payload, 0);

  status = val_check_for_error(num_pe);

  val_report_status(0, "END");

  return status;
}
