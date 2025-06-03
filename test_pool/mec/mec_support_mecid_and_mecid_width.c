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

#include "val/include/rme_acs_val.h"
#include "val/include/val_interface.h"

#include "val/include/rme_acs_iovirt.h"
#include "val/include/rme_acs_smmu.h"
#include "val/include/rme_acs_mec.h"
#include "val/include/rme_acs_pe.h"
#include "val/include/rme_acs_el32.h"
#include "val/include/rme_acs_memory.h"

#define TEST_NAME  "mec_support_mecid_and_mecid_width"
#define TEST_DESC  "Check MECID Support and MECID width of requesters      "
#define TEST_RULE  "RBJVZS"

#define INVALID_MECIDW 0xFFFFFFFF

uint32_t *pe_mecidw;

static
void
payload1(void)
{
  uint32_t pe_index = val_pe_get_index_mpid(val_pe_get_mpid());

  /* All PEs must support FEAT_MEC */
  if (!val_is_mec_supported())
  {
      val_set_status(pe_index, "FAIL", 01);
      return;
  }

  /* Get MECID width supported by each PE */
  pe_mecidw[pe_index] = VAL_EXTRACT_BITS(val_pe_reg_read(MECIDR_EL2), 0, 3) + 1;
  val_data_cache_ops_by_va((addr_t)&(pe_mecidw[pe_index]), CLEAN_AND_INVALIDATE);

  val_set_status(pe_index, "PASS", 01);
  return;
}

static
void
payload2(void)
{
  uint32_t num_smmu, smmu_base, *smmu_mecidw;
  uint32_t pe_index = val_pe_get_index_mpid(val_pe_get_mpid());
  uint32_t i, common_mecidw = INVALID_MECIDW, max_mecid;
  uint32_t test_fail = 0;

  val_rlm_enable_mec();

  num_smmu = val_smmu_get_info(SMMU_NUM_CTRL, 0);

  smmu_mecidw = val_memory_alloc(num_smmu * sizeof(uint32_t));
  if (num_smmu == 0) {
      val_print(ACS_PRINT_ERR, "No SMMU Controllers are discovered ", 0);
      val_set_status(pe_index, "FAIL", 02);
      return;
  }

  for (i = 0; i < num_smmu; i++) {
    smmu_base = val_smmu_get_info(SMMU_CTRL_BASE, i);

    /* Check if SMMU supports MEC */
    val_smmu_rlm_check_mec_impl(smmu_base);
    if (shared_data->shared_data_access[0].data == 0)
    {
      val_print(ACS_PRINT_ERR, "SMMU %d does not support MEC ", i);
      test_fail++;
      continue;
    }

    /* Get MECID width supported by each SMMU */
    val_smmu_rlm_get_mecidw(smmu_base);
    smmu_mecidw[i] = shared_data->shared_data_access[0].data + 1;

    if (smmu_mecidw[i] < common_mecidw)
        common_mecidw = smmu_mecidw[i];
  }

  if (test_fail)
  {
      val_set_status(pe_index, "FAIL", 03);
      return;
  }

  /* Establish a common SMMU from All PEs and SMMUs */
  for (i = 0; i < val_pe_get_num(); i++) {
      if (pe_mecidw[i] < common_mecidw)
          common_mecidw = pe_mecidw[i];
  }

  if (common_mecidw == INVALID_MECIDW) {
      val_print(ACS_PRINT_ERR, " Failed to determine common MECID width", 0);
      val_set_status(pe_index, "FAIL", 04);
      return;
  }

  /* Calculate MAX_MECID from the common MECIDwidth */
  max_mecid = (1 << common_mecidw) - 1;

  /* Validate MECIDs */
  if (!val_mec_validate_mecid(max_mecid, max_mecid - 1, PoE))
  {
      val_print(ACS_PRINT_ERR, " Invalid MECID behaviour", 0);
      val_set_status(pe_index, "FAIL", 05);
      return;
  }

  if (!val_mec_validate_mecid(max_mecid, max_mecid - 1, PoPA))
  {
      val_print(ACS_PRINT_ERR, " Invalid MECID behaviour", 0);
      val_set_status(pe_index, "FAIL", 06);
      return;
  }

  /* Restore MECID to GMECID */
  val_rlm_configure_mecid(VAL_GMECID);

  val_set_status(pe_index, "PASS", 01);
  return;
}

uint32_t
mec_support_mecid_and_mecid_width_entry(uint32_t num_pe)
{

  uint32_t status = ACS_STATUS_FAIL, i;
  uint32_t pe_index = val_pe_get_index_mpid(val_pe_get_mpid());

  status = val_initialize_test(TEST_NAME, TEST_DESC, num_pe, TEST_RULE);

  pe_mecidw = val_memory_alloc(num_pe * sizeof(uint32_t));
  if (!pe_mecidw) {
      val_print(ACS_PRINT_ERR, " Failed to allocate shared memory", 0);
      val_report_status(pe_index, "FAIL");
      val_report_status(0, "END");
      return ACS_STATUS_FAIL;
  }

  val_data_cache_ops_by_va((addr_t)&pe_mecidw, CLEAN_AND_INVALIDATE);
  /* This check is when user is forcing us to skip this test */
  if (status != ACS_STATUS_SKIP)
  {
      val_run_test_payload(num_pe, payload1, 0);

      for (i = 0; i < num_pe; i++)
      {
          if (IS_TEST_FAIL(val_get_status(i)))
              break;
      }
      if (IS_TEST_PASS(val_get_status(--i)))
      {
          num_pe = 1;
          val_run_test_payload(num_pe, payload2, 0);
      }
  }

  val_rlm_disable_mec();

  /*get the result from all PE and check for failure */
  status = val_check_for_error(num_pe);

  val_report_status(0, "END");

  return  status;
}

