/** @file
 * Copyright (c) 2022-2023, 2025, Arm Limited or its affiliates. All rights reserved.
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
#include "val/include/val_interface.h"

#define TEST_NAME  "rme_all_pe_has_feat_rng_or_rng_trap"
#define TEST_DESC  "Check if all PEs implement FEAT_RNG or FEAT_RNG_TRAP   "
#define TEST_RULE  "RQYRGG"

#define RNG_SHIFT      60
#define RNG_MASK       (0xFULL << RNG_SHIFT)

#define RNG_TRAP_SHIFT 28
#define RNG_TRAP_MASK  (0xFULL << RNG_TRAP_SHIFT)

/*
 * @brief  The test validates that all PEs implement FEAT_RNG or FEAT_RNG_TRAP.
 * 1. The bit[63:60] of ID_AA64ISAR0_EL1 and bits[31:28] of ID_AA64PFR0_EL1 are checked
 *    against 0x1.
 * 2. If either of them is implemented, the test is expected to PASS.
 */
static
void
payload(void)
{
  uint64_t feat_rng = 0, feat_rng_trap = 0;
  uint32_t index = val_pe_get_index_mpid(val_pe_get_mpid());

  feat_rng = val_pe_reg_read(ID_AA64ISAR0_EL1);
  feat_rng = (feat_rng & RNG_MASK) >> RNG_SHIFT;
  feat_rng_trap = val_pe_reg_read(ID_AA64PFR0_EL1);
  feat_rng_trap = (feat_rng_trap & RNG_TRAP_MASK) >> RNG_TRAP_SHIFT;

  if (feat_rng == 0x1 || feat_rng_trap == 0x1)
        val_set_status(index, "PASS", 01);
  else
        val_set_status(index, "FAIL", 01);

  return;

}

uint32_t
rme_all_pe_has_feat_rng_or_rng_trap_entry(uint32_t num_pe)
{

  uint32_t status = ACS_STATUS_FAIL;

  status = val_initialize_test(TEST_NAME, TEST_DESC, num_pe, TEST_RULE);

  if (status != ACS_STATUS_SKIP)
      val_run_test_payload(num_pe, payload, 0);

  status = val_check_for_error(num_pe);

  val_report_status(0, "END");

  return status;
}

