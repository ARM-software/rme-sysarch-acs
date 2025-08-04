/** @file
 * Copyright (c) 2024-2025, Arm Limited or its affiliates. All rights reserved.
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

#include "val/include/rme_acs_smmu.h"
#include "val/include/rme_acs_iovirt.h"
#include "val/include/rme_acs_pcie.h"
#include "val/include/rme_acs_el32.h"

#define TEST_NAME  "da_smmu_implementation"
#define TEST_DESC  "Check if SMMU implements DA                            "
#define TEST_RULE  "RNJRPC"

static
void
payload()
{

  uint64_t rme_impl_smmu, root_impl_smmu;
  uint32_t num_smmu;
  uint64_t smmu_base;
  uint32_t index = val_pe_get_index_mpid(val_pe_get_mpid());

  num_smmu = val_smmu_get_info(SMMU_NUM_CTRL, 0);

  if (num_smmu == 0) {
      val_print(ACS_PRINT_ERR, "No SMMU Controllers are discovered ", 0);
      val_set_status(index, "SKIP", 01);
      return;
  }

  while (num_smmu--) {
      val_print(ACS_PRINT_TEST, " Checking SMMU Controller: %d", num_smmu);
      if (val_smmu_get_info(SMMU_CTRL_ARCH_MAJOR_REV, num_smmu) == 2) {
          val_print(ACS_PRINT_WARN, "Not valid for SMMU v2           ", 0);
          val_set_status(index, "SKIP", 02);
          return;
      }

      /* Check the SMMU_ROOT_IDR0 register for the feature implementations */
      smmu_base = val_smmu_get_info(SMMU_CTRL_BASE, num_smmu);
      if (val_smmu_check_rmeda_el3(smmu_base))
      {
        val_print(ACS_PRINT_ERR, " SMMU DA implmnt check failure", 0);
        val_set_status(index, "FAIL", 01);
        return;
      }
      root_impl_smmu = VAL_EXTRACT_BITS(shared_data->shared_data_access[0].data, 0, 0);

      /* Check If SMMU__ROOT_IDR0.RME_IMPL[3] && SMMU_ROOT_IDR0.ROOT_IMPL[0] == 0b1 */

      if (!root_impl_smmu) {
          val_print(ACS_PRINT_ERR,
            " The SMMU 0x%x doesn't indicate the support for ROOT registers", num_smmu);
          val_set_status(index, "FAIL", 02);
          return;
      }

      rme_impl_smmu = VAL_EXTRACT_BITS(shared_data->shared_data_access[0].data, 3, 3);
      if (!rme_impl_smmu) {
          val_print(ACS_PRINT_ERR,
            " The RME_IMPL bit of SMMUv3_IDR0 is not set for %d smmu controller", num_smmu);
          val_set_status(index, "FAIL", 03);
          return;
      }
  }
  val_set_status(index, "PASS", 01);
}

uint32_t
da_smmu_implementation_entry(void)
{
  uint32_t num_pe = 1;
  uint32_t  status = ACS_STATUS_FAIL;

  status = val_initialize_test(TEST_NAME, TEST_DESC, num_pe, TEST_RULE);

  if (status != ACS_STATUS_SKIP)
      val_run_test_payload(num_pe, payload, 0);

  /*get the result from all PE and check for failure */
  status = val_check_for_error(num_pe);
  val_report_status(0, "END");

  return  status;
}
