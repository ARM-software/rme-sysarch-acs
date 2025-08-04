/** @file
 * Copyright (c) 2025, Arm Limited or its affiliates. All rights reserved.
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

#include "include/rme_acs_val.h"
#include "include/rme_acs_common.h"
#include "include/rme_acs_mec.h"
#include "include/rme_acs_iovirt.h"
#include "include/rme_acs_el32.h"
#include "include/mem_interface.h"
#include "include/val_interface.h"
#include "include/rme_acs_pe.h"

/**
  @brief   This API will execute all RME MEC tests designated for a given compliance level
           1. Caller       -  Application layer.
           2. Prerequisite -  val_pe_create_info_table, val_allocate_shared_mem
  @param   num_pe - the number of PE to run these tests on.
  @return  Consolidated status of all the tests run.
**/

uint32_t
val_rme_mec_execute_tests(uint32_t num_pe)
{
  uint32_t status, i, reset_status, smmu_cnt;
  uint64_t num_smmus = val_smmu_get_info(SMMU_NUM_CTRL, 0);
  uint64_t smmu_base_arr[num_smmus], pgt_attr_el3;

  for (i = 0 ; i < g_num_skip ; i++) {
      if (val_memory_compare((char8_t *)g_skip_test_str[i], MEC_MODULE,
                             val_strnlen(g_skip_test_str[i])) == 0)
      {
          val_print(ACS_PRINT_ALWAYS, "\n USER Override - Skipping all RME-MEC tests \n", 0);
          return ACS_STATUS_SKIP;
      }
  }

  /* Check if there are any tests to be executed in current module with user override options*/
  status = val_check_skip_module(MEC_MODULE);
  if (status) {
    val_print(ACS_PRINT_ALWAYS, "\n USER Override - Skipping all RME-MEC tests \n", 0);
    return ACS_STATUS_SKIP;
  }

  if (!val_is_mec_supported())
  {
      val_print(ACS_PRINT_ALWAYS, "\n Platform does not support MEC \
                       - Skipping all RME-MEC tests \n", 0);
      return ACS_STATUS_SKIP;
  }

  if (!g_rl_smmu_init)
  {
      smmu_cnt = 0;

      while (smmu_cnt < num_smmus)
      {
        smmu_base_arr[smmu_cnt] = val_smmu_get_info(SMMU_CTRL_BASE, smmu_cnt);
        smmu_cnt++;
      }
      /* Map the Pointer in EL3 as NS Access PAS so that EL3 can access this struct pointers */
      pgt_attr_el3 = LOWER_ATTRS(PGT_ENTRY_ACCESS | SHAREABLE_ATTR(OUTER_SHAREABLE) |
                                 PGT_ENTRY_AP_RW | PAS_ATTR(NONSECURE_PAS));
      if (val_add_mmu_entry_el3((uint64_t)(smmu_base_arr), (uint64_t)(smmu_base_arr), pgt_attr_el3))
      {
        val_print(ACS_PRINT_ERR, " MMU mapping failed for smmu_base_arr", 0);
        return ACS_STATUS_ERR;
      }
      if (val_rlm_smmu_init(num_smmus, smmu_base_arr))
      {
        val_print(ACS_PRINT_ERR, " SMMU REALM INIT failed", 0);
        return ACS_STATUS_ERR;
      }

      g_rl_smmu_init = 1;
  }

  reset_status = val_read_reset_status();

  if (reset_status != RESET_TST12_FLAG &&
      reset_status != RESET_TST31_FLAG &&
      reset_status != RESET_TST2_FLAG &&
      reset_status != RESET_LS_DISBL_FLAG &&
      reset_status != RESET_LS_TEST3_FLAG)
  {
    val_print(ACS_PRINT_ALWAYS, "\n\n*******************************************************\n", 0);
    status = mec_support_mecid_and_mecid_width_entry(num_pe);
    status |= mec_mecid_assosiation_and_encryption_entry();
    status |= mec_effect_of_popa_cmo_entry();
    status |= mec_cmo_uses_correct_mecid_entry(2);
  }

  return status;

}

/**
 * @brief Extracts the MEC support field from the AA64MMFR3_EL1 register.
 *
 * Reads the ID_AA64MMFR3_EL1 system register and returns the value of bits 28-31,
 * indicating whether MEC is supported.
 *
 * @return An unsigned integer containing the extracted MEC support bits.
 */
uint32_t val_is_mec_supported(void)
{
    return VAL_EXTRACT_BITS(val_pe_reg_read(ID_AA64MMFR3_EL1), 28, 31);
}

/**
 * @brief Validates memory encryption configuration between two MECIDs.
 *
 * Configures a test memory region, writes a random value under the first MECID,
 * performs appropriate cache/memory operations (PoPA or PoE), then reconfigures
 * to the second MECID and reads back the value.
 *
 * @param mecid1 The first MECID used for the write access.
 * @param mecid2 The second MECID used for the read access.
 * @param PoX    Operation to perform after write: PoPA or PoE.
 *
 * @return 1 (TRUE) if the read value differs from the written value, indicating
 *         MECID validation failure; 0 (FALSE) otherwise.
 */
uint32_t val_mec_validate_mecid(uint32_t mecid1, uint32_t mecid2, uint8_t PoX)
{
  uint64_t data_wt_rl, data_rd_rl, VA_RL, PA, size;
  uint32_t attr;

  size = val_get_min_tg();
  PA = val_get_free_pa(size, size);
  VA_RL = val_get_free_va(size);

  attr = LOWER_ATTRS(PGT_ENTRY_ACCESS | SHAREABLE_ATTR(NON_SHAREABLE) | PGT_ENTRY_AP_RW);

  if (val_add_gpt_entry_el3(PA, GPT_ANY))
  {
    val_print(ACS_PRINT_ERR, " GPT mapping failed for PA: 0x%llx", PA);
    return ACS_STATUS_ERR;
  }
  if (val_add_mmu_entry_el3(VA_RL, PA, (attr | LOWER_ATTRS(PAS_ATTR(REALM_PAS)))))
  {
    val_print(ACS_PRINT_ERR, " MMU mapping failed for VA: 0x%llx", VA_RL);
    return ACS_STATUS_ERR;
  }

  if (val_rlm_configure_mecid(mecid1))
  {
    val_print(ACS_PRINT_ERR, " MEC configure failure for mecid: 0x%lx", mecid1);
    return ACS_STATUS_ERR;
  }

  /* Store RANDOM_DATA_1 in PA_RT*/
  data_wt_rl = RANDOM_DATA_4;
  shared_data->num_access = 1;
  shared_data->shared_data_access[0].addr = VA_RL;
  shared_data->shared_data_access[0].data = data_wt_rl;
  shared_data->shared_data_access[0].access_type = WRITE_DATA;

  if (val_pe_access_mut_el3())
  {
    val_print(ACS_PRINT_ERR, " Access MUT failure for VA: 0x%llx", VA_RL);
    return ACS_STATUS_ERR;
  }

  if (PoX == PoPA) {
    if (val_data_cache_ops_by_pa_el3(PA, REALM_PAS))
    {
      val_print(ACS_STATUS_ERR, " CMO till PoPA failed for PA: 0x%llx", PA);
      return ACS_STATUS_ERR;
    }
  }
  else if (PoX == PoE) {
    if (val_cmo_to_poe(PA))
    {
      val_print(ACS_PRINT_ERR, " CMO till POE failed for PA: 0x%llx", PA);
    }
  }

  if (val_rlm_configure_mecid(mecid2))
  {
    val_print(ACS_PRINT_ERR, " MECID Configuration failed for mecid: 0x%lx", mecid2);
    return ACS_STATUS_ERR;
  }

  shared_data->num_access = 1;
  shared_data->shared_data_access[0].addr = VA_RL;
  shared_data->shared_data_access[0].access_type = READ_DATA;
  if (val_pe_access_mut_el3())
  {
    val_print(ACS_PRINT_ERR, " MUT Access failed for VA: 0x%llx after CMO", VA_RL);
    return ACS_STATUS_ERR;
  }

  data_rd_rl = shared_data->shared_data_access[0].data;

  if (data_rd_rl != data_wt_rl)
    return TRUE;
  else
    return FALSE;
}
