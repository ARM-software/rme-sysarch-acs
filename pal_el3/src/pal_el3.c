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

void pal_enable_ns_encryption(void)
{
  //Partner shall implement their own IMPLEMNTATION_DEFINED
  //register for enabling and disabling the NS_Encryption
  return;
}

void pal_disable_ns_encryption(void)
{
  //Partner shall implement their own IMPLEMNTATION_DEFINED
  //register for enabling and disabling the NS_Encryption
  return;
}

void pal_prog_legacy_tz(int enable)
{
  //Partner shall implement their own IMPLEMNTATION_DEFINED
  //register for enabling the LEGACY_TZ_EN feature
  return;
}

void pal_pas_filter_active_mode(int enable)
{
  //Partner shall implement their own IMPLEMNTATION_DEFINED
  //way for changing the Active mode of pas filter
  return;
}
