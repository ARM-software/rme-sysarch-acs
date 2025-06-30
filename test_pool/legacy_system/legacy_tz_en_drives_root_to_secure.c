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
#include "val/include/val_interface.h"

#include "val/include/rme_acs_pe.h"
#include "val/include/rme_acs_smmu.h"
#include "val/include/rme_acs_pcie.h"
#include "val/include/rme_acs_el32.h"

#define TEST_NAME "legacy_tz_en_drives_root_to_secure"
#define TEST_DESC  "Check if LEGACY_TZ_EN=1, root PAS is driven to sec PAS "
#define TEST_RULE  "RHCGZN"

/*
 * @brief  The test validates that the root pas is driven to secure pas if LEGACY_TZ=1.
 * 1. Get the registers that are accessible only by root access PAS.
 * 2. Modify the access PAS by mapping the Register addresses with VAs as secure acc_pas.
 * 3. Access the VAs.
 * 4. Observe that it raises the fault or the data read is not updated, making the test
 *    PASS, otherwise FAIL.
 * Note: The test assumes that LEGACY_TZ_EN is already enabled in the first test.
 */
static
void
payload()
{

  uint64_t rd_data;
  uint32_t index = val_pe_get_index_mpid(val_pe_get_mpid());
  uint32_t status_fail_cnt, attr;
  uint64_t VA, PA, size, num_reg;
  ROOT_REGSTR_TABLE *root_registers_cfg;

  size = val_get_min_tg();

  //Get the registers content
  root_registers_cfg = val_root_reg_info_table();
  num_reg = root_registers_cfg->num_reg;
  attr = LOWER_ATTRS(PGT_ENTRY_ACCESS | SHAREABLE_ATTR(NON_SHAREABLE) | PGT_ENTRY_AP_RW);
  for (uint64_t reg_cnt = 0; reg_cnt < num_reg; ++reg_cnt) {

    VA = val_get_free_va(size);
    PA = root_registers_cfg->rt_reg_info[reg_cnt].rt_reg_base_addr;
    /* Use the register addresses as PAs to map them with secure access PAS */
    if (val_add_mmu_entry_el3(VA, PA, (attr | LOWER_ATTRS(PAS_ATTR(SECURE_PAS)))))
    {
      val_print(ACS_PRINT_ERR, "\n  Failed to add MMU entry for register 0x%llx", PA);
      status_fail_cnt++;
      continue;
    }

    shared_data->shared_data_access[0].data = 0xdeadc0de;
    shared_data->arg1 = VA;
    shared_data->access_mut = SET;
    shared_data->exception_expected = CLEAR;
    //Accessing MUT
    if (val_pe_access_mut_el3())
    {
      val_print(ACS_PRINT_ERR, " Failed to access the root register from secure PAS", 0);
      status_fail_cnt++;
      continue;
    }

    rd_data = shared_data->shared_data_access[0].data;
    if (shared_data->exception_generated == SET || rd_data == 0xdeadc0de)
    {
      val_print(ACS_PRINT_ERR, "  The exception was generated for accessing the root\
                      register from secure PAS after LEGACY_TZ_EN is True", 0);
      status_fail_cnt++;
      shared_data->exception_generated = CLEAR;
    }
  }

  if (status_fail_cnt > 0) {
      val_print(ACS_PRINT_ERR, " The accesses did not go as expected for %d times",
                  status_fail_cnt);
      val_set_status(index, "FAIL", 01);
  }
  /* PASS Otherwise*/
  else
      val_set_status(index, "PASS", 01);
  return;

}

uint32_t
legacy_tz_en_drives_root_to_secure_entry(uint32_t num_pe)
{
  num_pe = 1;
  uint32_t  status = ACS_STATUS_FAIL;

  status = val_initialize_test(TEST_NAME, TEST_DESC, num_pe, TEST_RULE);

  if (status != ACS_STATUS_SKIP)
      val_run_test_payload(num_pe, payload, 0);

  /*get the result from all PE and check for failure */
  status = val_check_for_error(num_pe);
  val_report_status(0, "END");

  return  status;
}


