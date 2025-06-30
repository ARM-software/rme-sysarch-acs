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

#define TEST_NAME  "rme_data_encryption_with_different_tweak"
#define TEST_DESC  "Data encryption with different tweak in each data block"
#define TEST_RULE  "RMLFBL"

/*
 * @brief  The test validates the encryption nature of an external memory/shared cache with a
 *         different tweak in each 128-bit block
 * 1. Store the data in PA_Secure and (PA_Secure + 16)
 * 2. Perform CMO to PoPA for PA_Secure and PA_Nonsecure
 * 3. Read the data from PA_Nonsecure and (PA_Nonsecure + 16)
 * 4. Observe that both the data are different
 */
static
void payload(void)
{
  uint32_t index = val_pe_get_index_mpid(val_pe_get_mpid()), attr;
  uint64_t data_rd_ns, data_rd_ns_nxt_blk, PA, PA_NXT_BLK;
  uint64_t VA_S, VA_S_NXT_BLK, VA_NS, VA_NS_NXT_BLK, size;

  size = val_get_min_tg();
  PA = val_get_free_pa(size, size);
  VA_S = val_get_free_va(size);
  VA_S_NXT_BLK = val_get_free_va(size);
  VA_NS = val_get_free_va(size);
  VA_NS_NXT_BLK = val_get_free_va(size);
  attr = LOWER_ATTRS(PGT_ENTRY_ACCESS | SHAREABLE_ATTR(NON_SHAREABLE) | PGT_ENTRY_AP_RW);

  PA_NXT_BLK = PA + 16;
  if (val_add_mmu_entry_el3(VA_S, PA, (attr | LOWER_ATTRS(PAS_ATTR(SECURE_PAS)))))
  {
      val_print(ACS_PRINT_ERR, "\n  Failed to add MMU entry for VA_S 0x%llx", VA_S);
      val_set_status(index, "FAIL", 01);
      return;
  }
  if (val_add_mmu_entry_el3(VA_S_NXT_BLK, PA_NXT_BLK,
                           (attr | LOWER_ATTRS(PAS_ATTR(SECURE_PAS)))))
  {
      val_print(ACS_PRINT_ERR,
        "\n  Failed to add MMU entry for VA_S_NXT_BLK 0x%llx", VA_S_NXT_BLK);
      val_set_status(index, "FAIL", 02);
      return;
  }
  if (val_add_mmu_entry_el3(VA_NS, PA, (attr | LOWER_ATTRS(PAS_ATTR(NONSECURE_PAS)))))
  {
      val_print(ACS_PRINT_ERR, "\n  Failed to add MMU entry for VA_NS 0x%llx", VA_NS);
      val_set_status(index, "FAIL", 03);
      return;
  }
  if (val_add_mmu_entry_el3(VA_NS_NXT_BLK, PA_NXT_BLK,
                            (attr | LOWER_ATTRS(PAS_ATTR(NONSECURE_PAS)))))
  {
      val_print(ACS_PRINT_ERR,
        "\n  Failed to add MMU entry for VA_NS_NXT_BLK 0x%llx", VA_NS_NXT_BLK);
      val_set_status(index, "FAIL", 04);
      return;
  }

  /* Store RANDOM_DATA_1 in PA_S and (PA_S + 16)*/
  shared_data->num_access = 1;
  shared_data->shared_data_access[0].addr = VA_S;
  shared_data->shared_data_access[0].data = RANDOM_DATA_1;
  shared_data->shared_data_access[0].access_type = WRITE_DATA;
  if (val_pe_access_mut_el3())
  {
      val_print(ACS_PRINT_ERR, " Failed to access VA_S = 0x%llx", VA_S);
      val_set_status(index, "FAIL", 05);
      return;
  }

  shared_data->num_access = 1;
  shared_data->shared_data_access[0].addr = VA_S_NXT_BLK;
  shared_data->shared_data_access[0].data = RANDOM_DATA_1;
  shared_data->shared_data_access[0].access_type = WRITE_DATA;
  if (val_pe_access_mut_el3())
  {
      val_print(ACS_PRINT_ERR, " Failed to access VA_S_NXT_BLK = 0x%llx", VA_S_NXT_BLK);
      val_set_status(index, "FAIL", 06);
      return;
  }

  /* CMO to PoPA for all PA of all pas */
  if (val_data_cache_ops_by_pa_el3(PA, SECURE_PAS))
  {
      val_print(ACS_PRINT_ERR, " Failed to issue CMO for PA 0x%llx", PA);
      val_set_status(index, "FAIL", 07);
      return;
  }
  if (val_data_cache_ops_by_pa_el3(PA_NXT_BLK, SECURE_PAS))
  {
      val_print(ACS_PRINT_ERR, " Failed to issue CMO for PA_NXT_BLK 0x%llx", PA_NXT_BLK);
      val_set_status(index, "FAIL", 8);
      return;
  }
  if (val_data_cache_ops_by_pa_el3(PA, NONSECURE_PAS))
  {
      val_print(ACS_PRINT_ERR, " Failed to issue CMO for PA 0x%llx", PA);
      val_set_status(index, "FAIL", 9);
      return;
  }
  if (val_data_cache_ops_by_pa_el3(PA_NXT_BLK, NONSECURE_PAS))
  {
      val_print(ACS_PRINT_ERR, " Failed to issue CMO for PA_NXT_BLK 0x%llx", PA_NXT_BLK);
      val_set_status(index, "FAIL", 10);
      return;
  }

  /* Read the data from PA_NS and (PA_NS + 16) */
  shared_data->num_access = 2;
  shared_data->shared_data_access[0].addr = VA_NS;
  shared_data->shared_data_access[0].access_type = READ_DATA;

  shared_data->shared_data_access[1].addr = VA_NS_NXT_BLK;
  shared_data->shared_data_access[1].access_type = READ_DATA;

  if (val_pe_access_mut_el3())
  {
      val_print(ACS_PRINT_ERR, " Failed to access VA_NS and VA_NS_NXT_BLK", 0);
      val_set_status(index, "FAIL", 11);
      return;
  }

  data_rd_ns = shared_data->shared_data_access[0].data;
  data_rd_ns_nxt_blk = shared_data->shared_data_access[1].data;

  val_print(ACS_PRINT_DEBUG, " Data returned from Nonsecure Address = 0x%lx", data_rd_ns);
  val_print(ACS_PRINT_DEBUG, " Data returned from next(128-bit) block Address = 0x%lx",
                  data_rd_ns_nxt_blk);
  val_print(ACS_PRINT_DEBUG, " The test expects both the data to be unique", 0);

  if (data_rd_ns_nxt_blk != data_rd_ns)
      val_set_status(index, "PASS", 01);
  else
      val_set_status(index, "FAIL", 12);
  return;

}

uint32_t
rme_data_encryption_with_different_tweak_entry(void)
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

