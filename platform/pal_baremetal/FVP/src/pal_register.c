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

REGISTER_INFO_TABLE rp_regs[PLATFORM_OVERRIDE_RP_REG_NUM_ENTRIES] = {
  /* Sample values
  {PCIE_RP, 0x100, 0x880200000, RMSD_WRITE_PROTECT},
  {PCIE_RP, 0x200, 0x880200000, RMSD_FULL_PROTECT},
  {INTERCONNECT, 0x0, 0x880201000, RMSD_PROTECT}
  */
};

void
pal_register_create_info_table(REGISTER_INFO_TABLE *registerInfoTable)
{
  int32_t index = 0;

  if (registerInfoTable == NULL)
      return;

  for (index = 0; index < PLATFORM_OVERRIDE_RP_REG_NUM_ENTRIES; index++)
  {
      registerInfoTable[index].type = rp_regs[index].type;
      registerInfoTable[index].bdf = rp_regs[index].bdf;
      registerInfoTable[index].address = rp_regs[index].address;
      registerInfoTable[index].property = rp_regs[index].property;
  }
}

uint32_t
pal_register_get_num_entries(void)
{
  return PLATFORM_OVERRIDE_RP_REG_NUM_ENTRIES;
}
