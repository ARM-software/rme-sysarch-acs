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
#include "val/include/rme_acs_iovirt.h"
#include "val/include/rme_acs_pcie.h"
#include "val/include/rme_acs_el32.h"
#include "val/include/mem_interface.h"

#define TEST_NAME "legacy_tz_enable_before_reset"
#define TEST_DESC  "Check that LEGACY_TZ_EN takes effect only after reset  "
#define TEST_RULE  "RKQLKN"

#define BIT_30 30
#define BIT_55 55
#define BIT_52 52

/*
 * @brief  The test validates that the LEGACY_TZ_EN takes effect only after reset.
 * 1. The bit[52:55] of ID_AA64PFR0_EL1 register is checked for PE's RME implementation.
 * 2. The bit[30] of SMMU_IDR0 register is checked for SMMU's RME implementation.
 * 3. These bits are expected to be RES0 once LEGACY_TZ_EN is enabled.
 */
static
void
payload()
{

  uint64_t rme_impl_smmu, rme_impl_pe;
  uint32_t num_smmu, smmu_index;
  uint32_t index = val_pe_get_index_mpid(val_pe_get_mpid());

  if (val_read_reset_status() == RESET_LS_TEST3_FLAG)
          goto reset_done;

  //Enable the Legacy_TZ_EN tie-off in the system
  val_print(ACS_PRINT_TEST, " Enabling LEGACY_TZ_EN", 0);
  if (val_prog_legacy_tz(SET))
  {
    val_print(ACS_PRINT_ERR, "\n  Programming LEGACY_TZ_EN failed", 0);
    val_set_status(index, "FAIL", 01);
    return;
  }

  val_print(ACS_PRINT_TEST, " Going to reset", 0);
  val_write_reset_status(RESET_LS_TEST3_FLAG);
  val_system_reset();

reset_done:
  num_smmu = val_smmu_get_info(SMMU_NUM_CTRL, 0);

  if (num_smmu == 0) {
      val_print(ACS_PRINT_ERR, "No SMMU Controllers are discovered ", 0);
      val_set_status(index, "SKIP", 01);
      return;
  }

  smmu_index = 0;
  if (val_smmu_get_info(SMMU_CTRL_ARCH_MAJOR_REV, smmu_index) == 2) {
      val_print(ACS_PRINT_WARN, "Not valid for SMMU v2           ", 0);
      val_set_status(index, "SKIP", 02);
      return;
  }

  /* VAL_EXTRACT_BITS(data, start_bit, end_bit) */
  val_print(ACS_PRINT_TEST, " Checking RME implementation bits after reset", 0);
  rme_impl_smmu = VAL_EXTRACT_BITS(val_smmu_read_cfg(SMMUv3_IDR0, smmu_index), BIT_30, BIT_30);
  val_print(ACS_PRINT_DEBUG, " The RME implementation bit of SMMUv3_IDR0 = %lx", rme_impl_smmu);

  rme_impl_pe = VAL_EXTRACT_BITS(val_pe_reg_read(ID_AA64PFR0_EL1), BIT_52, BIT_55);
  val_print(ACS_PRINT_DEBUG, " The RME implementation bit of ID_AA64PFR0_EL1 = %lx", rme_impl_pe);

  /*Check If SMMU_IDR0.RME_IMPL[30] == 0b1 and ID_AA64PFR0_EL1.RME_IMPL[52:55] == 0b0001*/
  if (rme_impl_smmu || rme_impl_pe) {

    if (rme_impl_pe)
      val_print(ACS_PRINT_ERR, "  The RME implementation bit of PE is set\
                      even after enabling LEGACY_TZ_EN", 0);
    if (rme_impl_smmu)
      val_print(ACS_PRINT_ERR, "  The RME implementation bit of SMMU is set\
                      even after enabling LEGACY_TZ_EN", 0);
    val_set_status(index, "FAIL", 01);
    return;
  }
  val_set_status(index, "PASS", 01);

}

uint32_t
legacy_tz_enable_before_resetv_entry(uint32_t num_pe)
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

