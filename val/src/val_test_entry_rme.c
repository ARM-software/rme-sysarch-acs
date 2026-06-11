/** @file
 * Copyright (c) 2022-2026, Arm Limited or its affiliates. All rights reserved.
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

#include "include/val.h"
#include "include/val_common.h"
#include "include/val_test_entry.h"
#include "include/val_exerciser.h"
#include "include/val_iovirt.h"
#include "include/val_smmu.h"
#include "include/val_pcie.h"

#include "include/val_interface.h"
#include "include/val_el32.h"
#include "include/val_mem_interface.h"

MEM_REGN_INFO_TABLE *g_mem_region_cfg;
MEM_REGN_INFO_TABLE *g_mem_region_pas_filter_cfg;

static uint32_t
rme_run_if_selected(uint32_t num_pe, uint32_t status, uint32_t reset_status)
{

  if (reset_status == RESET_TST12_FLAG)
          goto reset_done_12;

  else if (reset_status == RESET_TST31_FLAG)
          goto reset_done_31;

  else if (reset_status == RESET_TST32_FLAG)
          goto reset_done_32;

  else if (reset_status == RESET_TST2_FLAG)
          goto reset_done_2;

  else if (reset_status == RESET_LS_DISBL_FLAG || reset_status == RESET_LS_TEST3_FLAG)
          goto reset_done_ls;

  val_execute_module_tests(RME_MODULE_ID,
                           RME_ENTRY_RME_SUPPORT_IN_PE_ENTRY - 1,
                           RME_ENTRY_RME_GPRS_SCRUBBED_AFTER_RESET_ENTRY + 1,
                           num_pe,
                           status);
  reset_done_2:
  val_execute_module_tests(RME_MODULE_ID,
                           RME_ENTRY_RME_GPRS_SCRUBBED_AFTER_RESET_ENTRY - 1,
                           RME_ENTRY_RME_REALM_SMEM_BEHAVIOUR_AFTER_RESET_ENTRY + 1,
                           num_pe,
                           status);
  reset_done_12:
  val_execute_module_tests(RME_MODULE_ID,
                           RME_ENTRY_RME_REALM_SMEM_BEHAVIOUR_AFTER_RESET_ENTRY - 1,
                           RME_ENTRY_RME_SYSTEM_RESET_PROPAGATION_TO_ALL_PE_ENTRY + 1,
                           num_pe,
                           status);
  reset_done_31:
  val_execute_module_tests(RME_MODULE_ID,
                           RME_ENTRY_RME_SYSTEM_RESET_PROPAGATION_TO_ALL_PE_ENTRY - 1,
                           RME_ENTRY_RME_MSD_SMEM_IN_ROOT_AFTER_RESET_ENTRY + 1,
                           num_pe,
                           status);
  reset_done_32:
  val_execute_module_tests(RME_MODULE_ID,
                           RME_ENTRY_RME_MSD_SMEM_IN_ROOT_AFTER_RESET_ENTRY - 1,
                           RME_ENTRY_RME_MSD_SMEM_IN_ROOT_AFTER_RESET_ENTRY + 1,
                           num_pe,
                           status);
  reset_done_ls:
  return status;
}

/**
  @brief   This API will execute all RME tests designated for a given compliance level
           1. Caller       -  Application layer.
           2. Prerequisite -  val_pe_create_info_table, val_allocate_shared_mem
  @param   num_pe - the number of PE to run these tests on.
  @return  Consolidated status of all the tests run.
**/
uint32_t
val_rme_execute_tests(uint32_t num_pe)
{
  uint32_t status = ACS_STATUS_SKIP, reset_status;

  reset_status = val_read_reset_status();
  val_print(ACS_PRINT_DEBUG, " reset_status = %lx\n", reset_status);

  g_curr_module = 1 << RME_MODULE_ID;

  /* RME-ACS tests */
  val_print(ACS_PRINT_ALWAYS, "\n\n******************************************************* \n", 0);
  status = rme_run_if_selected(num_pe, status, reset_status);
  return status;

}

void
val_mem_region_create_info_table(uint64_t *mem_gpc_region_table, uint64_t *mem_pas_region_table)
{
  g_mem_region_cfg = (MEM_REGN_INFO_TABLE *)mem_gpc_region_table;
  g_mem_region_pas_filter_cfg = (MEM_REGN_INFO_TABLE *)mem_pas_region_table;

  pal_mem_region_create_info_table(g_mem_region_cfg, g_mem_region_pas_filter_cfg);
}

MEM_REGN_INFO_TABLE *
val_mem_gpc_info_table(void)
{
  return g_mem_region_cfg;
}

MEM_REGN_INFO_TABLE *
val_mem_pas_info_table(void)
{
  return g_mem_region_pas_filter_cfg;
}
