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

#ifndef __RME_ACS_MEC_H__
#define __RME_ACS_MEC_H__

#define PoPA 0x0
#define PoE  0x1
#define PoC  0x2

uint32_t
mec001_entry(uint32_t num_pe);
uint32_t
mec002_entry(void);
uint32_t
mec003_entry(void);
uint32_t
mec004_entry(uint32_t num_pe);

uint32_t val_is_mec_supported(void);
uint32_t val_mec_validate_mecid(uint32_t mecid1, uint32_t mecid2, uint8_t PoX);
#endif
