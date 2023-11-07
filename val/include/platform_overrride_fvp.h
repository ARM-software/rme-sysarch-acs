/** @file
 * Copyright (c) 2023, Arm Limited or its affiliates. All rights reserved.
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

#define PAS_SECURE 0x0
#define PAS_NON_SECURE 0x1
#define PAS_ROOT 0x2
#define PAS_REALM 0x3


#define IS_LEGACY_TZ_ENABLED 0x0

#define IS_NS_ENCRYPTION_PROGRAMMABLE 0x0

#define IS_PAS_FILTER_MODE_PROGRAMMABLE 0x0


#define GPC_PROTECTED_REGION_CNT 0x4

#define GPC_PROTECTED_REGION_0_START_ADDR 0xFC400000
#define GPC_PROTECTED_REGION_0_SIZE 0x1E00000
#define GPC_PROTECTED_REGION_0_PAS 0x2

#define GPC_PROTECTED_REGION_1_START_ADDR 0XF9E00000
#define GPC_PROTECTED_REGION_1_SIZE 0x2600000
#define GPC_PROTECTED_REGION_1_PAS 0x3

#define GPC_PROTECTED_REGION_2_START_ADDR 0XF9000000
#define GPC_PROTECTED_REGION_2_SIZE 0xDFF000
#define GPC_PROTECTED_REGION_2_PAS 0x0

#define GPC_PROTECTED_REGION_3_START_ADDR 0X80000000
#define GPC_PROTECTED_REGION_3_SIZE 0x7900000
#define GPC_PROTECTED_REGION_3_PAS 0x1


#define PAS_PROTECTED_REGION_CNT 0x4

#define PAS_PROTECTED_REGION_0_START_ADDR 0x2A940000
#define PAS_PROTECTED_REGION_0_SIZE 0x20000
#define PAS_PROTECTED_REGION_0_PAS 0x2

#define PAS_PROTECTED_REGION_1_START_ADDR 0x2AB60000
#define PAS_PROTECTED_REGION_1_SIZE 0x20000
#define PAS_PROTECTED_REGION_1_PAS 0x3

#define PAS_PROTECTED_REGION_2_START_ADDR 0x2B100000
#define PAS_PROTECTED_REGION_2_SIZE 0x30000
#define PAS_PROTECTED_REGION_2_PAS 0x0

#define PAS_PROTECTED_REGION_3_START_ADDR 0x2A830000
#define PAS_PROTECTED_REGION_3_SIZE 0x10000
#define PAS_PROTECTED_REGION_3_PAS 0x1


#define RT_REG_CNT 0x4

#define RT_REG_0_START_ADDR 0x2A430000
#define RT_REG_0_SIZE 0x1000

#define RT_REG_1_START_ADDR 0x2A430000
#define RT_REG_1_SIZE 0x1000

#define RT_REG_2_START_ADDR 0x2A430000
#define RT_REG_2_SIZE 0x1000

#define RT_REG_3_START_ADDR 0x2A430000
#define RT_REG_3_SIZE 0x1000


