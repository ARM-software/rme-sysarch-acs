/** @file
  * Copyright (c) 2022-2024, Arm Limited or its affiliates. All rights reserved.
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

#include "platform_overrride_fvp.h"

#if PLATFORM_BASEFVP

#define MTE_PROTECTED_REGION_BASE      0xFFC00000ULL
#define MTE_PROTECTED_REGION_SIZE      0x300000   //3 MB
#define MTE_PROTECTED_REGION_END       (MTE_PROTECTED_REGION_BASE + MTE_PROTECTED_REGION_SIZE - 1)
#define MTE_PROTECTED_REGION_MID       (MTE_PROTECTED_REGION_END - (MTE_PROTECTED_REGION_SIZE / 2))

/* Defines related to System memory */
#define ROOT_SMEM_BASE  0xFFC00000ULL
#define REALM_SMEM_BASE 0XFDC00000ULL

#define REALM_MEM_ADDRES 0XFDC00000ULL

#define MSD_SAVE_RESTORE_MEM 0xFFC00000ULL

#define RME_RNVS_MAILBOX_MEM 0xFFC00000ULL

/* Root watchdog defines */
#define WD_IIDR_OFFSET 0xFCC

#define RT_WDOG_CTRL 0x2A490000 // 0x2A460000
#define RT_WDOG_REFRESH 0x2A470000
#define RT_WDOG_INT_ID 0x72

#define CNTR_FREQ 0x5F5E100

/* SMMU_V3 ROOT register defines */
#define ROOT_IOVIRT_SMMUV3_BASE (0x2b400000)
#define SMMUV3_ROOT_REG_OFFSET  (0x20000)
#define SMMU_ROOT_CR0           (SMMUV3_ROOT_REG_OFFSET + 0x0020)
#define SMMU_ROOT_IDRO          (SMMUV3_ROOT_REG_OFFSET + 0x0000)

/**
 * FREE_MEM_START is the start address of 2MB region which is flat-mapped in EL3 MMU. This
 * region is used for descriptor mappings.
 * FREE_PA_TEST is the base address for free PA which is used in test(EL2).
 * This free PA does not require to be flat-mapped.
 * FREE_VA_TEST is the base VA of 512MB size used in test as free VA.
 **/
#define FREE_MEM_START   0x880000000ULL
#define FREE_VA_TEST     0x880200000ULL
#define FREE_PA_TEST     0x880300000ULL
#define SHARED_ADDRESS 0xE0000000ULL

#else

#define MTE_PROTECTED_REGION_BASE      0x2A460000ULL
#define MTE_PROTECTED_REGION_SIZE      0x20000
#define MTE_PROTECTED_REGION_END       (MTE_PROTECTED_REGION_BASE + MTE_PROTECTED_REGION_SIZE - 1)
#define MTE_PROTECTED_REGION_MID       (MTE_PROTECTED_REGION_END - (MTE_PROTECTED_REGION_SIZE / 2))

/* Defines related to System memory */
#define ROOT_SMEM_BASE  0x2A460000ULL
#define REALM_SMEM_BASE 0x2A420000ULL

#define REALM_MEM_ADDRES 0x2A420000ULL

#define MSD_SAVE_RESTORE_MEM 0x2A460000ULL

#define RME_RNVS_MAILBOX_MEM 0x2A460000ULL

/* Root watchdog defines */
#define WD_IIDR_OFFSET 0xFCC

#define RT_WDOG_CTRL 0x2A460000
#define RT_WDOG_REFRESH 0x2A470000
#define RT_WDOG_INT_ID 0x72

#define CNTR_FREQ 0x5F5E100

/* SMMU_V3 ROOT register defines */
#define ROOT_IOVIRT_SMMUV3_BASE (0x288000000)
#define SMMUV3_ROOT_REG_OFFSET  (0xA0000)
#define SMMU_ROOT_CR0           (SMMUV3_ROOT_REG_OFFSET + 0x0020)
#define SMMU_ROOT_IDRO          (SMMUV3_ROOT_REG_OFFSET + 0x0000)

/**
 * FREE_MEM_START is the start address of 2MB region which is flat-mapped in EL3 MMU. This
 * region is used for descriptor mappings.
 * FREE_PA_TEST is the base address for free PA which is used in test(EL2).
 * This free PA does not require to be flat-mapped.
 * FREE_VA_TEST is the base VA of 512MB size used in test as free VA.
 **/
#define FREE_MEM_START   0x8080000000ULL
#define FREE_VA_TEST     0x8080200000ULL
#define FREE_PA_TEST     0x8080300000ULL
#define SHARED_ADDRESS 0xE0000000ULL

#endif

#ifndef __ASSEMBLER__
/**
 * @brief structure instance for ROOT registers
 */
typedef struct {
  uint64_t rt_reg_base_addr;
  uint64_t rt_reg_size;
} RT_REG_INFO_ENTRY;

typedef struct {
  uint32_t num_reg;
  RT_REG_INFO_ENTRY rt_reg_info[];
} ROOT_REGSTR_TABLE;

/**
  @brief  structure instance for region types
**/
typedef struct {
  uint32_t num_of_regn_gpc;
  uint32_t num_of_regn_pas_filter;
} MEM_REGN_INFO_HDR;

/**
  @brief  structure instance for Region details
**/
typedef struct {
  uint32_t   base_addr;
  uint32_t   regn_size;
  uint64_t   resourse_pas;
} MEM_REGN_INFO_ENTRY;

typedef struct {
  MEM_REGN_INFO_HDR    header;
  MEM_REGN_INFO_ENTRY  regn_info[];
} MEM_REGN_INFO_TABLE;

extern MEM_REGN_INFO_TABLE mem_region_cfg;
extern MEM_REGN_INFO_TABLE mem_region_pas_filter_cfg;
extern ROOT_REGSTR_TABLE root_registers_cfg;

#endif //__ASSEMBLER__
