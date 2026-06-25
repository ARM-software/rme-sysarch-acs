/** @file
  * Copyright (c) 2025-2026, Arm Limited or its affiliates. All rights reserved.
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

/**
 * EL3 local configuration header for RD-V3.
**/

#ifndef VAL_EL3_CONFIG_H
#define VAL_EL3_CONFIG_H

#define SMMUV3_ROOT_REG_OFFSET  (0xA0000)

#define PLAT_FREE_MEM_START     0x8080000000ULL

#define PLAT_SHARED_ADDRESS     0xE0000000ULL

#define PLAT_FREE_MEM_SMMU      0x8080400000ULL
#define PLAT_MEMORY_POOL_SIZE   (2 * 1024 * 1024)

#define PLATFORM_OVERRIDE_SMMU_STRTAB_BITS 20U

#endif /* VAL_EL3_CONFIG_H */
