/** @file
 * Copyright (c) 2023-2024, Arm Limited or its affiliates. All rights reserved.
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

/* Defines related to User SMC Call services */
#define RME_INSTALL_HANDLER 0x1
#define RME_ADD_GPT_ENTRY 0x2
#define RME_ADD_MMU_ENTRY 0x3
#define RME_MAP_SHARED_MEM 0x4
#define RME_CMO_POPA 0x5
#define RME_ACCESS_MUT 0x6
#define RME_MEM_SET 0x7
#define RME_DATA_CACHE_OPS 0x8
#define RME_NS_ENCRYPTION 0x9
#define RME_READ_AND_CMPR_REG_MSD 0xA
#define LEGACY_TZ_ENABLE 0xB
#define ROOT_WATCHDOG 0xC
#define PAS_FILTER_SERVICE 0xD
#define SMMU_ROOT_SERVICE 0xE
#define SEC_STATE_CHANGE 0xF
#define SMMU_ROOT_REG_CHK 0x10

/* General Defines used by tests */
#define INIT_DATA   0x11
#define RANDOM_DATA_1 0x99
#define RANDOM_DATA_2 0x77
#define RANDOM_DATA_3 0x55
#define RANDOM_DATA_4 0x33
#define READ_DATA 0
#define WRITE_DATA 1
#define CLEAN_AND_INVALIDATE 0x1
#define CLEAN 0x2
#define INVALIDATE 0x3
#define SET   1
#define CLEAR 0

/* smmu root register configuration */
#define SMMU_ROOT_RME_IMPL_CHK 0x1

/* Defines related to PGT attrinutes of an address */
#define MAIR_REG_VAL_EL3  0x00000000004404ff

#define GPT_SECURE 0x8
#define GPT_NONSECURE 0x9
#define GPT_ROOT 0xA
#define GPT_REALM 0xB
#define GPT_ANY 0xF
#define GPT_NOACCESS 0x0
#define SECURE_PAS     0x0
#define NONSECURE_PAS  0x1
#define ROOT_PAS       0x2
#define REALM_PAS      0x3
#define SECURE_STATE    0x0
#define NONSECURE_STATE 0x1
#define ROOT_STATE      0x2
#define REALM_STATE     0x3

#define NSE_SHIFT 9
#define NS_SHIFT  3
#define PGT_SHAREABLITY_SHIFT 6
#define PGT_ENTRY_ACCESS    (0x1 << 8)
#define PGT_ENTRY_AP_RW     (0x1ull << 4)
#define INNER_SHAREABLE  0x3ULL
#define OUTER_SHAREABLE  0x2ULL
#define NON_SHAREABLE    0x0ULL
#define WRITE_BACK_NT    0xFFULL
#define WRITE_THROUGH_NT 0xBBULL
#define WRITE_BACK_TRSNT 0x77ULL
#define NON_CACHEABLE    0x44ULL
#define DEV_MEM_nGnRnE   0x00ULL
#define EXTRACT_ATTR_IND(x) ((MAIR_REG_VAL_EL3 >> (x*8)) & 0xFF)
#define GET_ATTR_INDEX(x)   ({                                                       \
                              int index;                                             \
                              for (int i = 0; i < 8; ++i) {                          \
                                  if (EXTRACT_ATTR_IND(i) == x) {                    \
                                      index = i;                                     \
                                      break;                                         \
                                  }                                                  \
                              }                                                      \
                              index;                                                 \
                            })

#define NSE_SET(x)    ((x == SECURE_PAS || x == NONSECURE_PAS) ? 0 : 1)
#define NS_SET(x)     ((x == ROOT_PAS || x == SECURE_PAS) ? 0 : 1)
#define SHAREABLE_ATTR(x) (x << PGT_SHAREABLITY_SHIFT)
#define PAS_ATTR(x) ((NSE_SET(x) << NSE_SHIFT) | (NS_SET(x) << NS_SHIFT))

#define LOWER_ATTRS(x)			(((x) & (0xFFF)) << 2)

/* Shared data structure instances */
typedef struct shared_data_access {
  uint64_t access_type;
  uint64_t addr;
  uint64_t data;
} SHARED_DATA_ACCESS;

#define MAX_NUM_REGISTERS_MSD 10

typedef struct{
    uint32_t reg_name;
    uint64_t saved_reg_value;
} reg_details_msd;

typedef struct{
    uint32_t num_regs;
    reg_details_msd reg_list[MAX_NUM_REGISTERS_MSD];
} reg_info_msd;

typedef struct shared_data_el32 {
  uint64_t access_data;           //0x0
  uint64_t elr_el3;               //0x8
  uint64_t spsr_el3;              //0x10
  uint64_t exception_expected;
  uint64_t exception_generated;
  uint64_t access_mut;
  uint64_t esr_value;
  uint64_t arg0;
  uint64_t arg1;
  uint64_t num_access;
  uint64_t pas_filter_flag;
  uint64_t generic_flag;
  reg_info_msd reg_info;
  SHARED_DATA_ACCESS shared_data_access[];
} struct_sh_data;

extern struct_sh_data *shared_data;

/* Structure instance for MSD registers */
typedef enum {
  GPCCR_EL3_MSD = 1,
  GPTBR_EL3_MSD,
  TCR_EL3_MSD,
  TTBR_EL3_MSD,
  SCR_EL3_MSD,
  SCTLR_EL2_MSD,
  SCTLR_EL3_MSD
} RME_ACS_REGS_MSD;

