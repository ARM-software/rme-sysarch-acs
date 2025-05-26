/** @file
 * Copyright (c) 2016-2018, 2022, 2025, Arm Limited or its affiliates. All rights reserved.
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


/* THESE values are provided as a HOOK to
     1. Override a value which is read from ACPI tables
     2. Fill-in a value which is not provided by any ACPI Table
 */

#define PLATFORM_GENERIC_UART_BASE       0
#define PLATFORM_GENERIC_UART_INTID      0

/* Change OVERRIDE to 1 and define the Timer values to be used */
#define PLATFORM_OVERRIDE_PLATFORM_TIMER 0
#define PLATFORM_OVERRIDE_CNTCTL_BASE    0x2a810000
#define PLATFORM_OVERRIDE_CNTREAD_BASE   0x2a800000
#define PLATFORM_OVERRIDE_CNTBASE_N      0x2a830000
#define PLATFORM_OVERRIDE_PLATFORM_TIMER_GSIV 58

/* Change OVERRIDE to 1 and define the Timeout values to be used */
#define PLATFORM_OVERRIDE_TIMEOUT        0
#define PLATFORM_OVERRIDE_TIMEOUT_LARGE  0x10000
#define PLATFORM_OVERRIDE_TIMEOUT_MEDIUM 0x1000
#define PLATFORM_OVERRIDE_TIMEOUT_SMALL  0x10

#define PLATFORM_OVERRIDE_EL2_VIR_TIMER_GSIV  28


/* Change OVERRIDE_WD to 1 and define the WD values to be used */
#define PLATFORM_OVERRIDE_WD               0
#define PLATFORM_OVERRIDE_WD_REFRESH_BASE  0x2A450000
#define PLATFORM_OVERRIDE_WD_CTRL_BASE     0x2A440000
#define PLATFORM_OVERRIDE_WD_GSIV          93

#define PLATFORM_OVERRIDE_TIMER_CNTFRQ         0x0

/* To use a different value from the MCFG Table, change this to Non-Zero */
#define PLATFORM_OVERRIDE_PCIE_ECAM_BASE       0x0 //0x40000000
#define PLATFORM_OVERRIDE_PCIE_START_BUS_NUM   0x0

#define PLATFORM_OVERRIDE_MAX_BDF           0
#define PLATFORM_OVERRIDE_PCIE_MAX_BUS      256
#define PLATFORM_OVERRIDE_PCIE_MAX_DEV      32
#define PLATFORM_OVERRIDE_PCIE_MAX_FUNC     8

/* Change OVERRIDE_SMMU_BASE to non-zero value for this to take effect */
#define PLATFORM_OVERRIDE_SMMU_BASE        0x0 //0x2B400000
#define PLATFORM_OVERRIDE_SMMU_ARCH_MAJOR  3

/* Platform Specifc details and system configurations */

#define PLATFORM_BASEFVP 0

#define IS_LEGACY_TZ_ENABLED 0x0

#define IS_NS_ENCRYPTION_PROGRAMMABLE 0x0

#define IS_PAS_FILTER_MODE_PROGRAMMABLE 0x0

#if PLATFORM_BASEFVP

#define GPC_PROTECTED_REGION_CNT 0x4

#define GPC_PROTECTED_REGION_0_START_ADDR 0xFFC00000
#define GPC_PROTECTED_REGION_0_SIZE 0x300000
#define GPC_PROTECTED_REGION_0_PAS 0x2

#define GPC_PROTECTED_REGION_1_START_ADDR 0XFDC00000
#define GPC_PROTECTED_REGION_1_SIZE 0x2000000
#define GPC_PROTECTED_REGION_1_PAS 0x3

#define GPC_PROTECTED_REGION_2_START_ADDR 0XFC000000
#define GPC_PROTECTED_REGION_2_SIZE 0x1C00000
#define GPC_PROTECTED_REGION_2_PAS 0x0

#define GPC_PROTECTED_REGION_3_START_ADDR 0X80000000
#define GPC_PROTECTED_REGION_3_SIZE 0x7C000000
#define GPC_PROTECTED_REGION_3_PAS 0x1

#define PAS_PROTECTED_REGION_CNT 0x4

#define PAS_PROTECTED_REGION_0_START_ADDR 0xFFC00000
#define PAS_PROTECTED_REGION_0_SIZE 0x3000000
#define PAS_PROTECTED_REGION_0_PAS 0x2

#define PAS_PROTECTED_REGION_1_START_ADDR 0XFDC00000
#define PAS_PROTECTED_REGION_1_SIZE 0x2000000
#define PAS_PROTECTED_REGION_1_PAS 0x3

#define PAS_PROTECTED_REGION_2_START_ADDR 0XFC000000
#define PAS_PROTECTED_REGION_2_SIZE 0x1C00000
#define PAS_PROTECTED_REGION_2_PAS 0x0

#define PAS_PROTECTED_REGION_3_START_ADDR 0X80000000
#define PAS_PROTECTED_REGION_3_SIZE 0x7C00000
#define PAS_PROTECTED_REGION_3_PAS 0x1

#define RT_REG_CNT 0x4

#define RT_REG_0_START_ADDR 0xAA430000
#define RT_REG_0_SIZE 0x1000

#define RT_REG_1_START_ADDR 0xAA430000
#define RT_REG_1_SIZE 0x1000

#define RT_REG_2_START_ADDR 0xAA430000
#define RT_REG_2_SIZE 0x1000

#define RT_REG_3_START_ADDR 0xAA430000
#define RT_REG_3_SIZE 0x1000

#define PLAT_MTE_PROTECTED_REGION_BASE      0xFFC00000ULL
#define PLAT_MTE_PROTECTED_REGION_SIZE      0x300000   //3 MB

/* SMMUv3 Root Regoster Offset */
#define SMMUV3_ROOT_REG_OFFSET  (0x20000)

/* Defines related to System memory */
#define PLAT_ROOT_SMEM_BASE  0
#define PLAT_REALM_SMEM_BASE 0

#define PLAT_MSD_SAVE_RESTORE_MEM 0

#define PLAT_RME_RNVS_MAILBOX_MEM 0

/* Root watchdog defines */
#define PLAT_RT_WDOG_CTRL 0x2A490000 // 0x2A460000
#define PLAT_RT_WDOG_INT_ID 0x72

/* Non-Volatile Memory */
#define PLAT_RME_ACS_NVM_MEM         0x82800000

/**
 * FREE_MEM_START is the start address of 2MB region which is flat-mapped in EL3 MMU. This
 * region is used for descriptor mappings.
 * FREE_PA_TEST is the base address for free PA which is used in test(EL2).
 * This free PA does not require to be flat-mapped.
 * FREE_VA_TEST is the base VA of 512MB size used in test as free VA.
 * PLAT_FREE_MEM_SMMU is the base free memory to be used in EL3 for Realm SMMU tables which
 * is flat-mapped as REALM PAS (currently using 2 MB)
 **/
#define PLAT_FREE_MEM_START   0x880000000ULL
#define PLAT_FREE_VA_TEST     0x880200000ULL
#define PLAT_FREE_PA_TEST     0x880300000ULL
#define PLAT_SHARED_ADDRESS   0xE0000000ULL
#define PLAT_FREE_MEM_SMMU    0x880400000ULL

#define PLAT_MEMORY_POOL_SIZE (2 * 1024 * 1024)

#else


#define GPC_PROTECTED_REGION_CNT 0x4

#define GPC_PROTECTED_REGION_0_START_ADDR 0x2A460000
#define GPC_PROTECTED_REGION_0_SIZE 0x20000
#define GPC_PROTECTED_REGION_0_PAS 0x2

#define GPC_PROTECTED_REGION_1_START_ADDR 0x2A420000
#define GPC_PROTECTED_REGION_1_SIZE 0x10000
#define GPC_PROTECTED_REGION_1_PAS 0x3

#define GPC_PROTECTED_REGION_2_START_ADDR 0x28000000
#define GPC_PROTECTED_REGION_2_SIZE 0x1000000
#define GPC_PROTECTED_REGION_2_PAS 0x0

#define GPC_PROTECTED_REGION_3_START_ADDR 0x2A400000
#define GPC_PROTECTED_REGION_3_SIZE 0x10000
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

#define PLAT_MTE_PROTECTED_REGION_BASE      0x2A460000ULL
#define PLAT_MTE_PROTECTED_REGION_SIZE      0x20000

/* Defines related to System memory */
#define PLAT_ROOT_SMEM_BASE  0
#define PLAT_REALM_SMEM_BASE 0

#define PLAT_MSD_SAVE_RESTORE_MEM 0

#define PLAT_RME_RNVS_MAILBOX_MEM 0

/* SMMUv3 Root Regoster Offset */
#define SMMUV3_ROOT_REG_OFFSET  (0xA0000)

/* Root watchdog defines */
#define PLAT_RT_WDOG_CTRL 0x2A460000
#define PLAT_RT_WDOG_INT_ID 0x72

#define PLAT_RME_ACS_NVM_MEM  0x82800000

/**
 * FREE_MEM_START is the start address of 2MB region which is flat-mapped in EL3 MMU. This
 * region is used for descriptor mappings.
 * FREE_PA_TEST is the base address for free PA which is used in test(EL2).
 * This free PA does not require to be flat-mapped.
 * FREE_VA_TEST is the base VA of 512MB size used in test as free VA.
 **/
#define PLAT_FREE_MEM_START   0x8080000000ULL
#define PLAT_FREE_VA_TEST     0x8080200000ULL
#define PLAT_FREE_PA_TEST     0x8080300000ULL
#define PLAT_SHARED_ADDRESS   0xE0000000ULL
#define PLAT_FREE_MEM_SMMU    0x8080400000ULL

#define PLAT_MEMORY_POOL_SIZE (2 * 1024 * 1024)

#endif


/* ------------ Expansion Macros ------------ */
#define EXPAND_PROTECTED_MEM_REGION(base, size, pas) \
    { .base_addr = base, .regn_size = size, .resourse_pas = pas },

#define GPC_PROTECTED_REGION_ENTRIES(_)                      \
    _(GPC_PROTECTED_REGION_0_START_ADDR, GPC_PROTECTED_REGION_0_SIZE, GPC_PROTECTED_REGION_0_PAS) \
    _(GPC_PROTECTED_REGION_1_START_ADDR, GPC_PROTECTED_REGION_1_SIZE, GPC_PROTECTED_REGION_1_PAS) \
    _(GPC_PROTECTED_REGION_2_START_ADDR, GPC_PROTECTED_REGION_2_SIZE, GPC_PROTECTED_REGION_2_PAS) \
    _(GPC_PROTECTED_REGION_3_START_ADDR, GPC_PROTECTED_REGION_3_SIZE, GPC_PROTECTED_REGION_3_PAS)

#define PAS_PROTECTED_REGION_ENTRIES(_)                      \
    _(PAS_PROTECTED_REGION_0_START_ADDR, PAS_PROTECTED_REGION_0_SIZE, PAS_PROTECTED_REGION_0_PAS) \
    _(PAS_PROTECTED_REGION_1_START_ADDR, PAS_PROTECTED_REGION_1_SIZE, PAS_PROTECTED_REGION_1_PAS) \
    _(PAS_PROTECTED_REGION_2_START_ADDR, PAS_PROTECTED_REGION_2_SIZE, PAS_PROTECTED_REGION_2_PAS) \
    _(PAS_PROTECTED_REGION_3_START_ADDR, PAS_PROTECTED_REGION_3_SIZE, PAS_PROTECTED_REGION_3_PAS)

#define EXPAND_RT_REG(base, size) \
    { .rt_reg_base_addr = base, .rt_reg_size = size },

#define RT_REGISTER_ENTRIES(_) \
    _(RT_REG_0_START_ADDR, RT_REG_0_SIZE) \
    _(RT_REG_1_START_ADDR, RT_REG_1_SIZE) \
    _(RT_REG_2_START_ADDR, RT_REG_2_SIZE) \
    _(RT_REG_3_START_ADDR, RT_REG_3_SIZE)

#define EXPAND_REGISTER_INFO(type, bdf, addr, prop) \
    { .type = type, .bdf = bdf, .address = addr, .property = prop },

#define REGISTER_INFO_TABLE_ENTRIES(_)
/* Example to override:
#define REGISTER_INFO_TABLE_ENTRIES(_) \
    _(PCIE_RP, 0x100, 0x880200000, RMSD_WRITE_PROTECT) \
    _(INTERCONNECT, 0x000, 0x880201000, RMSD_PROTECT)
*/

#define PLATFORM_OVERRIDE_RP_REG_NUM_ENTRIES  0
