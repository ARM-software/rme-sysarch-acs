/** @file
 * Copyright (c) 2023-2026, Arm Limited or its affiliates. All rights reserved.
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

#include "val/include/val_test_entry.h"
#include "val/include/val_interface.h"
#include "val/include/val_memory.h"
#include "val/include/val_el32.h"

#define NUM_PAS 4

#define TEST_NAME  "rme_pas_filter_in_inactive_mode"
#define TEST_DESC  "Pas filter in In-Active mode doesn't service requests  "
#define TEST_RULE  "RDQTSG"

/*
 * @brief  The test validates the PAS filter doesn't service request in Non-Active mode.
 * 1. Change the mode of PAS_FILTER to In-active.
 * 2. Loop through every PAS_FILTER protected regions, and try to access the same
 *    using the VAs mapped in MMU with the access pas same as correspoding resource pas.
 * 3. Require a platform-validated denial exception for each access.
 */
static
void payload(void)
{
  uint32_t status_fail_cnt = 0;
  uint32_t status;
  uint32_t index = val_pe_get_index_mpid(val_pe_get_mpid()), security_state, num_regn, attr;
  uint64_t VA, size;
  MEM_REGN_INFO_TABLE *mem_region_pas_filter_cfg;

  mem_region_pas_filter_cfg = val_mem_pas_info_table();
  num_regn = mem_region_pas_filter_cfg->header.num_of_regn_pas_filter;
  if (num_regn == 0) {
    val_print(ACS_PRINT_WARN, " No PAS filter regions provided by the platform", 0);
    val_set_status(index, "SKIP", 01);
    return;
  }

  if (!val_is_pas_filter_mode_programmable()) {
    val_print(ACS_PRINT_ERR, " The pas filter mode is not programmable in this system", 0);
    val_set_status(index, "SKIP", 01);
    return;
  }

  //Change the Active mode of the PAS filter
  val_print(ACS_PRINT_TEST, " Changing the Active mode of the PAS filter to In-Active", 0);
  status = val_pas_filter_active_mode_el3(CLEAR);
  if (status == NOT_IMPLEMENTED)
  {
    val_print(ACS_PRINT_ERR,
              " PAS filter mode is programmable but the PAL mode-switch API is not implemented", 0);
    val_set_status(index, "FAIL", 02);
    return;
  }
  if (status)
  {
    val_print(ACS_PRINT_ERR, " Active mode of the PAS filter couldn't be programmed", 0);
    val_set_status(index, "FAIL", 01);
    return;
  }
  size = val_get_min_tg();
  VA = val_get_free_va(num_regn * size);
  attr = LOWER_ATTRS(PGT_ENTRY_ACCESS | SHAREABLE_ATTR(NON_SHAREABLE) | PGT_ENTRY_AP_RW);

  for (uint32_t regn_cnt = 0; regn_cnt < num_regn; ++regn_cnt)
  {

    shared_data->arg0 = mem_region_pas_filter_cfg->regn_info[regn_cnt].base_addr;
    security_state = mem_region_pas_filter_cfg->regn_info[regn_cnt].resourse_pas;
    val_print(ACS_PRINT_TEST, " Checking the PAS filtering for the resource: 0x%llx",
              shared_data->arg0);
    /* Allow every PAS through GPT so this access tests the PAS filter. */
    if (val_add_gpt_entry_el3(shared_data->arg0, GPT_ANY))
    {
      val_print(ACS_PRINT_ERR, " Failed to add GPT entry for PA 0x%llx", shared_data->arg0);
      status_fail_cnt++;
      continue;
    }

    if (val_add_mmu_entry_el3(VA, shared_data->arg0,
        (attr | LOWER_ATTRS(PAS_ATTR(security_state)))))
    {
      val_print(ACS_PRINT_ERR, " Failed to add MMU entry for VA 0x%llx", VA);
      status_fail_cnt++;
      continue;
    }

    shared_data->exception_generated = CLEAR;
    shared_data->esr_value = 0;
    shared_data->exception_expected = SET;
    shared_data->access_mut = SET;
    shared_data->pas_filter_flag = SET;
    /* Select platform-specific denial verification in the EL3 handler. */
    shared_data->generic_flag = PAS_FILTER_INACTIVE_PROBE;
    shared_data->arg1 = VA;
    if (val_pe_access_mut_el3())
    {
      val_print(ACS_PRINT_ERR, " Failed to access VA = 0x%lx", VA);
      status_fail_cnt++;
    }
    shared_data->exception_expected = CLEAR;
    shared_data->access_mut = CLEAR;
    shared_data->pas_filter_flag = CLEAR;
    shared_data->generic_flag = CLEAR;

    if (shared_data->exception_generated != SET) {
      val_print(ACS_PRINT_ERR, " Expected PAS filter denial was not observed, ESR: 0x%llx",
                shared_data->esr_value);
      status_fail_cnt++;
    }
    shared_data->exception_generated = CLEAR;
    VA += size;

  }

  /* Restore Active mode before reporting the result, including probe failures. */
  status = val_pas_filter_active_mode_el3(SET);
  if (status)
  {
    val_print(ACS_PRINT_ERR, " Failed to restore PAS filter to Active mode", 0);
    status_fail_cnt++;
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
rme_pas_filter_in_inactive_mode_entry(uint32_t num_pe)
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

