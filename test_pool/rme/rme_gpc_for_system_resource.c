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
#include "val/include/rme_test_entry.h"
#include "val/include/rme_acs_el32.h"

#define NUM_PAS 4

#define TEST_NAME  "rme_gpc_for_system_resource"
#define TEST_DESC  "To Check if resources are protected by GPC             "
#define TEST_RULE  "PE_01"

/*
 * @brief  The test validates that the resources are protected by GPC as per system requirement.
 * 1. The base addresses of the resources are mapped to different access PASs using Free VA.
 * 2. Access with the same PAS as that of resources' will be successful.
 * 3. While the access with the different access PAS than that of resources' will generate fault.
 * 4. ACK handler takes care of the GPF and sends the handle back to the test safely.
 */
static
void payload(void)
{
  uint8_t status_fail_cnt = 0;
  MEM_REGN_INFO_TABLE *mem_region_cfg;
  uint32_t index = val_pe_get_index_mpid(val_pe_get_mpid()), security_state, num_regn, attr;
  uint64_t pas_list[4] = {REALM_PAS, NONSECURE_PAS, SECURE_PAS, ROOT_PAS}, VA, size;

  size = val_get_min_tg();

  mem_region_cfg = val_mem_gpc_info_table();
  num_regn = mem_region_cfg->header.num_of_regn_gpc;
  VA = val_get_free_va(num_regn * NUM_PAS * size);
  attr = LOWER_ATTRS(PGT_ENTRY_ACCESS | SHAREABLE_ATTR(NON_SHAREABLE) | PGT_ENTRY_AP_RW);

  for (uint32_t regn_cnt = 0; regn_cnt < num_regn; ++regn_cnt)
  {

    shared_data->arg0 = mem_region_cfg->regn_info[regn_cnt].base_addr;
    security_state = mem_region_cfg->regn_info[regn_cnt].resourse_pas;
    val_print(ACS_PRINT_TEST, " Checking GPC for resource 0x%llx", shared_data->arg0);

    for (int pas_cnt = 0; pas_cnt < 4; ++pas_cnt)
    {
      shared_data->arg1 = pas_list[pas_cnt];/* GPI */
      if (val_add_mmu_entry_el3(VA, shared_data->arg0,
                                attr | LOWER_ATTRS(PAS_ATTR(shared_data->arg1))))
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
          val_print(ACS_PRINT_ERR, " Failed to access VA = 0x%llx", VA);
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
        shared_data->arg1 = VA;
        if (val_pe_access_mut_el3())
        {
          val_print(ACS_PRINT_ERR, " Failed to access VA = 0x%llx", VA);
          status_fail_cnt++;
        }

        if (shared_data->exception_generated == CLEAR)
        {
          val_print(ACS_PRINT_ERR, " The exception is not generated when Resource PAS \
                          and Access PAS are different", 0);
          status_fail_cnt++;
        }
        shared_data->exception_generated = CLEAR;
      }
      VA += size;
    }
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
rme_gpc_for_system_resource_entry(void)
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

