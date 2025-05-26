/** @file
 * Copyright (c) 2022-2025, Arm Limited or its affiliates. All rights reserved.
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

#include  <Library/ShellCEntryLib.h>
#include  <Library/UefiBootServicesTableLib.h>
#include  <Library/UefiLib.h>
#include  <Library/ShellLib.h>
#include  <Library/PrintLib.h>
#include  <include/pal_uefi.h>

REGISTER_INFO_TABLE pal_rp_regs[PLATFORM_OVERRIDE_RP_REG_NUM_ENTRIES] = {
    REGISTER_INFO_TABLE_ENTRIES(EXPAND_REGISTER_INFO)
};

VOID
pal_register_create_info_table(REGISTER_INFO_TABLE *registerInfoTable)
{
  if (registerInfoTable == NULL)
  {
      rme_print(ACS_PRINT_ERR, L"\nInput Register Table Pointer is NULL", 0);
      return;
  }

  // Just copy the entire structure block from pre-expanded rp_regs[]
  for (UINT32 index = 0; index < PLATFORM_OVERRIDE_RP_REG_NUM_ENTRIES; index++)
  {
      registerInfoTable[index] = pal_rp_regs[index];
  }
}

UINT32
pal_register_get_num_entries(void)
{
  return PLATFORM_OVERRIDE_RP_REG_NUM_ENTRIES;
}

RT_REG_INFO_ENTRY rt_regs[RT_REG_CNT] = {
    RT_REGISTER_ENTRIES(EXPAND_RT_REG)
};

VOID
pal_root_register_create_info_table(ROOT_REGSTR_TABLE *rootRegTable)
{
    if (!rootRegTable)
        return;

    rootRegTable->num_reg = RT_REG_CNT;

    for (UINT32 i = 0; i < RT_REG_CNT; i++) {
        rootRegTable->rt_reg_info[i] = rt_regs[i];
    }
}

MEM_REGN_INFO_ENTRY pal_gpc_regs[GPC_PROTECTED_REGION_CNT] = {
    GPC_PROTECTED_REGION_ENTRIES(EXPAND_PROTECTED_MEM_REGION)
};

MEM_REGN_INFO_ENTRY pal_pas_regs[PAS_PROTECTED_REGION_CNT] = {
    PAS_PROTECTED_REGION_ENTRIES(EXPAND_PROTECTED_MEM_REGION)
};

VOID
pal_mem_region_create_info_table(MEM_REGN_INFO_TABLE *gpc_table,
                                 MEM_REGN_INFO_TABLE *pas_table)
{
    if (!gpc_table || !pas_table)
        return;

    // Populate GPC-specific entries
    gpc_table->header.num_of_regn_gpc = GPC_PROTECTED_REGION_CNT;
    for (UINT32 i = 0; i < GPC_PROTECTED_REGION_CNT; i++) {
        gpc_table->regn_info[i] = pal_gpc_regs[i];
    }

    // Populate PAS filter-specific entries
    pas_table->header.num_of_regn_pas_filter = PAS_PROTECTED_REGION_CNT;
    for (UINT32 i = 0; i < PAS_PROTECTED_REGION_CNT; i++) {
        pas_table->regn_info[i] = pal_pas_regs[i];
    }
}

UINT32
pal_is_legacy_tz_enabled(void)
{
    return IS_LEGACY_TZ_ENABLED;
}

UINT32
pal_is_ns_encryption_programmable(void)
{
    return IS_NS_ENCRYPTION_PROGRAMMABLE;
}

UINT32
pal_is_pas_filter_mode_programmable(void)
{
    return IS_PAS_FILTER_MODE_PROGRAMMABLE;
}
