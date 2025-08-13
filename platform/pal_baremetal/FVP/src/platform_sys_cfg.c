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

#include "include/platform_override_struct.h"

/**
 * @brief Platform-specific register and memory region table definitions.
 *
 * This file defines the structures and initialization routines for:
 * 1. REGISTER_INFO_TABLE      - placeholder (currently unused)
 * 2. ROOT_REGSTR_TABLE        - root register entries using RT macros
 * 3. MEM_REGN_INFO_TABLE (GPC) - memory region entries for GPC
 * 4. MEM_REGN_INFO_TABLE (PAS) - memory region entries for PAS filters
 *
 * All data is populated using macros from platform_override_fvp.h to ensure consistency
 * and maintainability. Tables are populated statically and copied into user-provided
 * buffers through dedicated pal_*_create_info_table() functions.
 */

REGISTER_INFO_TABLE rp_regs[PLATFORM_OVERRIDE_RP_REG_NUM_ENTRIES] = {
    REGISTER_INFO_TABLE_ENTRIES(EXPAND_REGISTER_INFO)
};

void
pal_register_create_info_table(REGISTER_INFO_TABLE *registerInfoTable)
{
  if (registerInfoTable == NULL)
      return;

  // Just copy the entire structure block from pre-expanded rp_regs[]
  for (int32_t index = 0; index < PLATFORM_OVERRIDE_RP_REG_NUM_ENTRIES; index++)
  {
      registerInfoTable[index] = rp_regs[index];
  }
}

uint32_t
pal_register_get_num_entries(void)
{
  return PLATFORM_OVERRIDE_RP_REG_NUM_ENTRIES;
}

RT_REG_INFO_ENTRY rt_regs[RT_REG_CNT] = {
    RT_REGISTER_ENTRIES(EXPAND_RT_REG)
};

void
pal_root_register_create_info_table(ROOT_REGSTR_TABLE *rootRegTable)
{
    if (!rootRegTable)
        return;

    rootRegTable->num_reg = RT_REG_CNT;

    for (uint32_t i = 0; i < RT_REG_CNT; i++) {
        rootRegTable->rt_reg_info[i] = rt_regs[i];
    }
}

MEM_REGN_INFO_ENTRY gpc_regs[GPC_PROTECTED_REGION_CNT] = {
    GPC_PROTECTED_REGION_ENTRIES(EXPAND_PROTECTED_MEM_REGION)
};

MEM_REGN_INFO_ENTRY pas_regs[PAS_PROTECTED_REGION_CNT] = {
    PAS_PROTECTED_REGION_ENTRIES(EXPAND_PROTECTED_MEM_REGION)
};

void
pal_mem_region_create_info_table(MEM_REGN_INFO_TABLE *gpc_table,
                                 MEM_REGN_INFO_TABLE *pas_table)
{
    if (!gpc_table || !pas_table)
        return;

    // Populate GPC-specific entries
    gpc_table->header.num_of_regn_gpc = GPC_PROTECTED_REGION_CNT;
    for (uint32_t i = 0; i < GPC_PROTECTED_REGION_CNT; i++) {
        gpc_table->regn_info[i] = gpc_regs[i];
    }

    // Populate PAS filter-specific entries
    pas_table->header.num_of_regn_pas_filter = PAS_PROTECTED_REGION_CNT;
    for (uint32_t i = 0; i < PAS_PROTECTED_REGION_CNT; i++) {
        pas_table->regn_info[i] = pas_regs[i];
    }
}

uint32_t
pal_is_legacy_tz_enabled(void)
{
    return IS_LEGACY_TZ_ENABLED;
}

uint32_t
pal_is_ns_encryption_programmable(void)
{
    return IS_NS_ENCRYPTION_PROGRAMMABLE;
}

uint32_t
pal_is_pas_filter_mode_programmable(void)
{
    return IS_PAS_FILTER_MODE_PROGRAMMABLE;
}
