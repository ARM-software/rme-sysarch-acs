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

#include "val/include/rme_test_entry.h"
#include "val/include/val_interface.h"
#include "val/include/rme_acs_el32.h"
#include "val/include/sys_config.h"

#define NUM_PAS 4
#define NUM_MTE_RGN 3

#define TEST_NUM   (ACS_RME_TEST_NUM_BASE  +  9)
#define TEST_DESC  "To check if MTE carve-out region has Root access only  "
#define TEST_RULE  "PE_13"

/*
 * @brief  The test validates that the MTE carve-out region can be accessed only from Root PAS.
 * 1. Divide the MTE region for three addresses as BASE, END and MID.
 * 2. Access from the root access PAS to the three addresses of MTE region will be successful.
 * 2. While the accesses with different PASs as that of the MTE region's will generate fault.
 */
static
void payload(void)
{
  struct_sh_data *shared_data = (struct_sh_data *) SHARED_ADDRESS;
  uint32_t index = val_pe_get_index_mpid(val_pe_get_mpid());
  uint64_t pas_list[4] = {REALM_PAS, NONSECURE_PAS, SECURE_PAS, ROOT_PAS}, VA, size;
  uint8_t status_fail_cnt;

  size = val_get_min_tg();
  VA = val_get_free_va(NUM_MTE_RGN * NUM_PAS * size);

  for (int pas_cnt = 0; pas_cnt < 4; ++pas_cnt)
  {
    /* MTE carve-out region: Base Address */
    val_add_mmu_entry_el3(VA, MTE_PROTECTED_REGION_BASE, pas_list[pas_cnt]);

    if (pas_list[pas_cnt] == ROOT_PAS) {
        shared_data->exception_expected = CLEAR;
        shared_data->access_mut = SET;
        shared_data->arg1 = VA;
        val_pe_access_mut_el3();    //Accessing MUT

        if (shared_data->exception_generated == SET)
        {
          val_print(ACS_PRINT_ERR, "\n  The exception was generated for 0x%lx pas",
                          pas_list[pas_cnt]);
          status_fail_cnt++;
        }
    } else {
        shared_data->exception_expected = SET;
        shared_data->access_mut = SET;
        shared_data->arg1 = VA;
        val_pe_access_mut_el3();    //Accessing MUT

        if (shared_data->exception_generated == CLEAR)
        {
          val_print(ACS_PRINT_ERR, "\n  The exception wasn't generated for 0x%lx pas",
                          pas_list[pas_cnt]);
          status_fail_cnt++;
        }
        shared_data->exception_generated = CLEAR;
    }
    VA += size;

    /* MTE carve-out region: Middle Address */
    val_add_mmu_entry_el3(VA, MTE_PROTECTED_REGION_MID, pas_list[pas_cnt]);

    if (pas_list[pas_cnt] == ROOT_PAS) {
        shared_data->exception_expected = CLEAR;
        shared_data->access_mut = SET;
        shared_data->arg1 = VA;
        val_pe_access_mut_el3();    //Accessing MUT

        if (shared_data->exception_generated == SET)
        {
          val_print(ACS_PRINT_ERR, "\n  The exception was generated for 0x%lx pas",
                          pas_list[pas_cnt]);
          status_fail_cnt++;
        }
    } else {
        shared_data->exception_expected = SET;
        shared_data->access_mut = SET;
        shared_data->arg1 = VA;
        val_pe_access_mut_el3();    //Accessing MUT

        if (shared_data->exception_generated == CLEAR)
        {
          val_print(ACS_PRINT_ERR, "\n  The exception wasn't generated for 0x%lx pas",
                          pas_list[pas_cnt]);
          status_fail_cnt++;
        }
        shared_data->exception_generated = CLEAR;
    }
    VA += size;

    /* MTE carve-out region: End Address */
    val_add_mmu_entry_el3(VA, MTE_PROTECTED_REGION_END, pas_list[pas_cnt]);

    if (pas_list[pas_cnt] == ROOT_PAS) {
        shared_data->exception_expected = CLEAR;
        shared_data->access_mut = SET;
        shared_data->arg1 = VA;
        val_pe_access_mut_el3();    //Accessing MUT

        if (shared_data->exception_generated == SET)
        {
          val_print(ACS_PRINT_ERR, "\n  The exception was generated for 0x%lx pas",
                          pas_list[pas_cnt]);
          status_fail_cnt++;
        }
    } else {
        shared_data->exception_expected = SET;
        shared_data->access_mut = SET;
        shared_data->arg1 = VA;
        val_pe_access_mut_el3();    //Accessing MUT

        if (shared_data->exception_generated == CLEAR)
        {
          val_print(ACS_PRINT_ERR, "\n  The exception wasn't generated for 0x%lx pas",
                          pas_list[pas_cnt]);
          status_fail_cnt++;
        }
        shared_data->exception_generated = CLEAR;
    }
    VA += size;
  }
  val_print(ACS_PRINT_DEBUG, "\n  Test expects any accesses other than root \
                  to cause an exception", 0);
  if (status_fail_cnt > 0)
    val_set_status(index, RESULT_FAIL(TEST_NUM, 01));
  else
    val_set_status(index, RESULT_PASS(TEST_NUM, 01));
  return;
}

uint32_t
rme009_entry(void)
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

