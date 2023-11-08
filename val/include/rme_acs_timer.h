/** @file
 * Copyright (c) 2022, Arm Limited or its affiliates. All rights reserved.
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

#ifndef __RME_ACS_TIMER_H__
#define __RME_ACS_TIMER_H__

#define ARM_ARCH_TIMER_ENABLE           (1 << 0)
#define ARM_ARCH_TIMER_IMASK            (1 << 1)
#define ARM_ARCH_TIMER_ISTATUS          (1 << 2)

uint32_t t001_entry(uint32_t num_pe);
uint32_t t002_entry(uint32_t num_pe);
uint32_t t003_entry(uint32_t num_pe);
uint32_t t004_entry(uint32_t num_pe);
uint32_t t005_entry(uint32_t num_pe);
uint32_t t006_entry(uint32_t num_pe);
uint32_t t007_entry(uint32_t num_pe);
uint32_t t008_entry(uint32_t num_pe);
#endif // __RME_ACS_TIMER_H__
