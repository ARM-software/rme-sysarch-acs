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

#ifndef __RME_ACS_DPT_H__
#define __RME_ACS_DPT_H__

#define DPT_NO_ACCESS_ENTRY        0
#define DPT_READ_ONLY_ACCESS_ENTRY 1
#define DPT_RDWR_ACCESS_ENTRY      17

uint32_t
dpt001_entry(void);

uint32_t
dpt002_entry(void);

uint32_t
dpt003_entry(void);

uint32_t
dpt004_entry(void);

uint32_t
dpt005_entry(void);

uint32_t
dpt006_entry(void);

uint32_t
dpt007_entry(void);
#endif
