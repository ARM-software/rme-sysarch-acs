/** @file
 * Copyright (c) 2023, 2025-2026, Arm Limited or its affiliates. All rights reserved.
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

#include "pal_el3.h"

/**
 * @brief Attempt to disable Non-secure encryption in a platform-specific manner.
 *
 * Partner must attempt the platform control write; the boot decision must remain
 * unchanged. An empty hook does not establish immutability.
 *
 * @return 0 if a disable attempt was performed, nonzero if unsupported or failed.
 *         A write rejected by the boot lock is a completed attempt, not failure.
 */
uint32_t pal_el3_disable_ns_encryption(void)
{
  //Partner shall implement their own IMPLEMNTATION_DEFINED
  //register for attempting to disable NS encryption
  return 1;
}

/**
 * @brief Program Legacy TZ enable state.
 *
 * @param enable  Non-zero to enable, zero to disable.
 *
 * Partner must implement IMPLEMNTATION_DEFINED register programming to control legacy TZ.
 * @return 0 after programming the requested state, PAL_EL3_NOT_IMPLEMENTED if the
 *         operation is unimplemented, or another nonzero value on failure.
 */
uint32_t pal_el3_prog_legacy_tz(int enable)
{
  //Partner shall implement their own IMPLEMNTATION_DEFINED
  //register for enabling the LEGACY_TZ_EN feature
  (void)enable;
  return PAL_EL3_NOT_IMPLEMENTED;
}

/**
 * @brief Set PAS filter to Active/Inactive mode.
 *
 * @param enable  Non-zero to set Active mode, zero for Inactive.
 *
 * Partner must implement IMPLEMNTATION_DEFINED method to change PAS filter mode.
 * @return 0 after the requested mode is established, PAL_EL3_NOT_IMPLEMENTED if the
 *         operation is unimplemented, or another nonzero value on failure.
 */
uint32_t pal_el3_pas_filter_active_mode(int enable)
{
  //Partner shall implement their own IMPLEMNTATION_DEFINED
  //way for changing the Active mode of pas filter
  (void)enable;
  return PAL_EL3_NOT_IMPLEMENTED;
}

/**
 * @brief Verify that a captured exception is an inactive PAS filter read denial.
 *
 * @param esr      ESR_EL3 captured by the ACS exception handler.
 * @param far      FAR_EL3 captured by the ACS exception handler.
 * @param address  Untagged virtual address of the load being tested.
 *
 * Implement the platform's documented denial-syndrome checks. Accept only a
 * synchronous read denial with a valid FAR matching address. Reject GPF,
 * translation and permission faults, and unrelated errors. If the syndrome
 * alone cannot identify the PAS filter as the source, also check the platform's
 * filter error status. Do not accept an arbitrary Data Abort as a denial.
 *
 * This hook only verifies the exception; ACS EL3 code performs recovery.
 * @return true for a verified denial; false for an unexpected or unverifiable
 *         exception, including when this hook is not implemented.
 */
bool pal_el3_pas_filter_check_exception(uint64_t esr, uint64_t far, uint64_t address)
{
  (void)esr;
  (void)far;
  (void)address;
  return false;
}
