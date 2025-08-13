/** @file
 * Copyright (c) 2023-2024, 2025, Arm Limited or its affiliates. All rights reserved.
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
#include "val/include/mem_interface.h"

#define TEST_NAME  "rme_interconnect_supports_tlbi_pa"
#define TEST_DESC  "Check if Interconnect supports TLBI PA operation       "
#define TEST_RULE  "RJRJSQ"

/*
 * @brief  The test validates that interconnect supports TLBI PA operation by changing
 *         the GPT entry
 * 1. Map VA to PA in MMU as secure access PAS and PA in GPT as Secure resource PAS.
 * 2. Access VA without generating GPF.
 * 3. Now change the GPT mapping to Non-secure resource PAS and issue TLBI PA.
 * 4. Observe that accessing VA generates GPF which sets the test result to PASS otherwise FAIL.
 */
static
void payload(void)
{

  uint32_t index = val_pe_get_index_mpid(val_pe_get_mpid()), attr;
  uint64_t PA, VA, size;

  size = val_get_min_tg();
  PA = val_get_free_pa(size, size);
  VA = val_get_free_va(size);
  attr = LOWER_ATTRS(PGT_ENTRY_ACCESS | SHAREABLE_ATTR(NON_SHAREABLE) | PGT_ENTRY_AP_RW);

  val_print(ACS_PRINT_TEST, " Accessing the PA of Secure resource PAS from Secure PAS", 0);
  /* Map VA to PA as secure access PAS in MMU and PA to secure resource PAS in GPT */
  if (val_add_gpt_entry_el3(PA, GPT_SECURE))
  {
    val_print(ACS_PRINT_ERR, " Failed to add GPT entry for PA 0x%llx", PA);
    val_set_status(index, "FAIL", 01);
    return;
  }
  if (val_add_mmu_entry_el3(VA, PA, (attr | LOWER_ATTRS(PAS_ATTR(SECURE_PAS)))))
  {
    val_print(ACS_PRINT_ERR, " Failed to add MMU entry for VA 0x%llx", VA);
    val_set_status(index, "FAIL", 02);
    return;
  }

  //Access VA
  shared_data->num_access = 1;
  shared_data->shared_data_access[0].addr = VA;
  shared_data->shared_data_access[0].access_type = READ_DATA;

  if (val_pe_access_mut_el3())
  {
    val_print(ACS_PRINT_ERR, " Failed to access VA = 0x%llx", VA);
    val_set_status(index, "FAIL", 03);
    return;
  }

  //Change the Resource PAS from Secure to Non-secure
  if (val_add_gpt_entry_el3(PA, GPT_NONSECURE))
  {
    val_print(ACS_PRINT_ERR, " Failed to change GPT entry for PA 0x%llx", PA);
    val_set_status(index, "FAIL", 04);
    return;
  }
  //Access VA after the GPT change
  val_print(ACS_PRINT_TEST, " Accessing the PA of Non resource PAS from Secure PAS", 0);
  shared_data->exception_expected = SET;
  shared_data->access_mut = SET;
  shared_data->arg1 = VA;
  if (val_pe_access_mut_el3())
  {
    val_print(ACS_PRINT_ERR, " Failed to access VA = 0x%llx", VA);
    val_set_status(index, "FAIL", 05);
    return;
  }

  if (shared_data->exception_generated == CLEAR)
  {
    val_print(ACS_PRINT_ERR, "  Unexpected successful access when resource pas \
                            is not same as access pas", 0);
    val_set_status(index, "FAIL", 06);
  }
  else {
    val_set_status(index, "PASS", 01);
    shared_data->exception_generated = CLEAR;
  }
  return;
}


uint32_t
rme_interconnect_supports_tlbi_pa_entry(void)
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

