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

#include "val/include/val.h"
#include "val/include/val_pe.h"
#include "val/include/val_common.h"

#include "val/include/val_test_entry.h"
#include "val/include/val_interface.h"
#include "val/include/val_el32.h"
#include "val/include/val_mem_interface.h"

#define TEST_NAME  "rme_realm_smem_behaviour_after_reset"
#define TEST_DESC  "Realm SMEM does not reveal old data after system reset "
#define TEST_RULE  "RZQQSQ"

/*
 * @brief  The test validates that Realm SMEM does not reveal old data after the reset.
 * 1. Store the data, wt_data in the address of the Realm SMEM.
 * 2. Execute reset
 * 3. Read the same address and see that the data read, rd_data is different than wt_data.
 */
static
void payload(void)
{

  uint32_t index = val_pe_get_index_mpid(val_pe_get_mpid()), attr;
  uint64_t wt_data, rd_data, PA_RLM, size;
  uint64_t realm_smem_available = val_get_realm_smem_base();

  wt_data = RANDOM_DATA_1;
  size = val_get_min_tg();

  if (realm_smem_available)
    PA_RLM = realm_smem_available;
  else {
    /* Map the PA as REALM in GPT table */
    PA_RLM = val_get_free_pa(size, size);
    if (val_add_gpt_entry_el3(PA_RLM, GPT_REALM))
    {
      val_print(ACS_PRINT_ERR, " Failed to add GPT entry for PA 0x%llx", PA_RLM);
      val_set_status(index, "FAIL", 01);
      return;
    }
  }

  if (val_read_reset_status() == RESET_TST12_FLAG)
          goto reset_done;

  /* Store DATA1 to PA of Realm SMEM and read the PA from realm SMEM after reset.*/
  attr = LOWER_ATTRS(PGT_ENTRY_ACCESS | SHAREABLE_ATTR(NON_SHAREABLE) | PGT_ENTRY_AP_RW);
  if (val_add_mmu_entry_el3(PA_RLM, PA_RLM, (attr | LOWER_ATTRS(PAS_ATTR(REALM_PAS)))))
  {
    val_print(ACS_PRINT_ERR, " Failed to add MMU entry for PA 0x%llx", PA_RLM);
    val_set_status(index, "FAIL", 02);
    return;
  }
  val_print(ACS_PRINT_TEST, " Writing a data to PA from Realm state", 0);
  shared_data->num_access = 1;
  shared_data->shared_data_access[0].addr = PA_RLM;
  shared_data->shared_data_access[0].data = wt_data;
  shared_data->shared_data_access[0].access_type = WRITE_DATA;
  if (val_pe_access_mut_el3())
  {
    val_print(ACS_PRINT_ERR, " Failed to access PA = 0x%lx", PA_RLM);
    val_set_status(index, "FAIL", 03);
    return;
  }

  val_print(ACS_PRINT_TEST, " Going to system reset", 0);
  val_write_reset_status(RESET_TST12_FLAG);
  val_save_global_test_data();
  val_system_reset();

reset_done:
  val_print(ACS_PRINT_TEST, " After system reset", 0);
  val_restore_global_test_data();
  attr = LOWER_ATTRS(PGT_ENTRY_ACCESS | SHAREABLE_ATTR(NON_SHAREABLE) | PGT_ENTRY_AP_RW);
  if (val_add_mmu_entry_el3(PA_RLM, PA_RLM, (attr | LOWER_ATTRS(PAS_ATTR(REALM_PAS)))))
  {
    val_print(ACS_PRINT_ERR, " Failed to add MMU entry for PA 0x%llx", PA_RLM);
    val_set_status(index, "FAIL", 04);
    return;
  }
  /* Read the PA from realm SMEM after reset */
  val_print(ACS_PRINT_TEST, " Reading the data from PA after reset", 0);
  shared_data->num_access = 1;
  shared_data->shared_data_access[0].addr = PA_RLM;
  shared_data->shared_data_access[0].access_type = READ_DATA;
  if (val_pe_access_mut_el3())
  {
    val_print(ACS_PRINT_ERR, " Failed to access PA = 0x%lx", PA_RLM);
    val_set_status(index, "FAIL", 05);
    return;
  }
  rd_data = shared_data->shared_data_access[0].data;

  val_print(ACS_PRINT_DEBUG, " The data stored is 0x%lx", wt_data);
  val_print(ACS_PRINT_DEBUG, " and the data read after the reset is 0x%lx", rd_data);
  val_print(ACS_PRINT_DEBUG, " The test expects the data to be not same", 0);
  if (wt_data == rd_data)
    val_set_status(index, "FAIL", 06);

  else
    val_set_status(index, "PASS", 01);

  return;
}

uint32_t
rme_realm_smem_behaviour_after_reset_entry(void)
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

