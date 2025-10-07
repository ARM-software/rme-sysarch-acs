/** @file
 * Copyright (c) 2023,2025, Arm Limited or its affiliates. All rights reserved.
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
 * @brief Enable Non-secure encryption in platform-specific manner.
 *
 * Partner must implement IMPLEMNTATION_DEFINED mechanism to enable NS encryption.
 */
void pal_el3_enable_ns_encryption(void)
{
  //Partner shall implement their own IMPLEMNTATION_DEFINED
  //register for enabling and disabling the NS_Encryption
  return;
}

/**
 * @brief Disable Non-secure encryption in platform-specific manner.
 *
 * Partner must implement IMPLEMNTATION_DEFINED mechanism to disable NS encryption.
 */
void pal_el3_disable_ns_encryption(void)
{
  //Partner shall implement their own IMPLEMNTATION_DEFINED
  //register for enabling and disabling the NS_Encryption
  return;
}

/**
 * @brief Program Legacy TZ enable state.
 *
 * @param enable  Non-zero to enable, zero to disable.
 *
 * Partner must implement IMPLEMNTATION_DEFINED register programming to control legacy TZ.
 */
void pal_el3_prog_legacy_tz(int enable)
{
  //Partner shall implement their own IMPLEMNTATION_DEFINED
  //register for enabling the LEGACY_TZ_EN feature
  return;
}

/**
 * @brief Set PAS filter to Active/Inactive mode.
 *
 * @param enable  Non-zero to set Active mode, zero for Inactive.
 *
 * Partner must implement IMPLEMNTATION_DEFINED method to change PAS filter mode.
 */
void pal_el3_pas_filter_active_mode(int enable)
{
  //Partner shall implement their own IMPLEMNTATION_DEFINED
  //way for changing the Active mode of pas filter
  return;
}
