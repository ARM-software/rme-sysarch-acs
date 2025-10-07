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

#include "val/include/val_interface.h"
#include "val/include/val_pe.h"
#include "val/include/val.h"
#include "val/include/val_memory.h"
#include "RmeAcs.h"

uint32_t  g_enable_pcie_tests;
uint32_t  g_print_level;
uint32_t  g_print_in_test_context;
uint32_t  g_print_test_check_id;
uint32_t  g_print_mmio;
uint32_t  g_curr_module;
uint32_t  g_enable_module;
uint32_t  g_rme_tests_total;
uint32_t  g_rme_tests_pass;
uint32_t  g_rme_tests_fail;
uint64_t  g_stack_pointer;
uint64_t  g_exception_ret_addr;
uint64_t  g_ret_addr;
uint32_t  g_rl_smmu_init;

char8_t **g_execute_tests_str;
char8_t **g_execute_modules_str;
char8_t **g_skip_test_str;

extern char8_t *g_skip_array[];
extern uint32_t g_num_skip;
extern char8_t *g_test_array[];
extern uint32_t g_num_tests;
extern char8_t *g_module_array[];
extern uint32_t g_num_modules;

uint32_t
createPeInfoTable(
)
{

  uint32_t Status;
  uint64_t *PeInfoTable;

  PeInfoTable = val_aligned_alloc(SIZE_4K, sizeof(PE_INFO_TABLE) +
                                (PLATFORM_OVERRIDE_PE_CNT * sizeof(PE_INFO_ENTRY)));

  Status = val_pe_create_info_table(PeInfoTable);

  return Status;

}

uint32_t
createGicInfoTable(
)
{
  uint32_t Status;
  uint64_t *GicInfoTable;
  uint32_t gic_info_end_index = 1; //Additional index for mem alloc to store the end value(0xff)

  GicInfoTable = val_aligned_alloc(SIZE_4K, sizeof(GIC_INFO_TABLE)
                  + ((PLATFORM_OVERRIDE_GICITS_COUNT
                  + PLATFORM_OVERRIDE_GICRD_COUNT + PLATFORM_OVERRIDE_GICC_COUNT
                  + PLATFORM_OVERRIDE_GICD_COUNT + gic_info_end_index) * sizeof(GIC_INFO_ENTRY)));

  Status = val_gic_create_info_table(GicInfoTable);

  return Status;

}

void
createMemCfgInfoTable (
)
{
  uint64_t     *GPCInfoTable;
  uint64_t     *PASInfoTable;
  uint64_t     *RootRegInfoTable;

  GPCInfoTable = val_aligned_alloc(SIZE_4K, sizeof(MEM_REGN_INFO_TABLE)
                                   + GPC_PROTECTED_REGION_CNT * sizeof(MEM_REGN_INFO_TABLE));

  PASInfoTable = val_aligned_alloc(SIZE_4K, sizeof(MEM_REGN_INFO_TABLE)
                                   + PAS_PROTECTED_REGION_CNT * sizeof(MEM_REGN_INFO_TABLE));

  val_mem_region_create_info_table(GPCInfoTable, PASInfoTable);

  RootRegInfoTable = val_aligned_alloc(SIZE_4K, sizeof(ROOT_REGSTR_TABLE)
                                       + RT_REG_CNT * sizeof(ROOT_REGSTR_TABLE));

  val_root_register_create_info_table(RootRegInfoTable);

}

uint32_t
configureGicIts(
)
{
  uint32_t Status;
  Status = val_gic_its_configure();
  return Status;
}

void
createTimerInfoTable(
)
{
  uint64_t   *TimerInfoTable;

  TimerInfoTable = val_aligned_alloc(SIZE_4K, sizeof(TIMER_INFO_TABLE)
                   + (PLATFORM_OVERRIDE_TIMER_COUNT * sizeof(TIMER_INFO_GTBLOCK)));

  val_timer_create_info_table(TimerInfoTable);
}

void
createPcieVirtInfoTable(
)
{
  uint64_t   *PcieInfoTable;
  uint64_t   *IoVirtInfoTable;
  uint64_t   *RegisterInfoTable;

  PcieInfoTable = val_aligned_alloc(SIZE_4K, sizeof(PCIE_INFO_TABLE)
                  + (PLATFORM_OVERRIDE_NUM_ECAM * sizeof(PCIE_INFO_BLOCK)));

  val_pcie_create_info_table(PcieInfoTable);

  RegisterInfoTable = val_aligned_alloc(SIZE_4K, sizeof(REGISTER_INFO_TABLE)
                  + (PLATFORM_OVERRIDE_RP_REG_NUM_ENTRIES * sizeof(REGISTER_INFO_TABLE)));

  val_register_create_info_table(RegisterInfoTable);

  IoVirtInfoTable = val_aligned_alloc(SIZE_4K, sizeof(IOVIRT_INFO_TABLE)
                    + ((NUM_ITS_COUNT + IOVIRT_SMMUV3_COUNT + IOVIRT_RC_COUNT
                    + IOVIRT_SMMUV2_COUNT + IOVIRT_NAMED_COMPONENT_COUNT + IOVIRT_PMCG_COUNT)
                    * sizeof(IOVIRT_BLOCK)) + (IOVIRT_MAX_NUM_MAP * sizeof(ID_MAP)));

  val_iovirt_create_info_table(IoVirtInfoTable);
}

void
createPeripheralInfoTable(
)
{
  uint64_t   *PeripheralInfoTable;

  PeripheralInfoTable = val_aligned_alloc(SIZE_4K, sizeof(PERIPHERAL_INFO_TABLE)
                        + (PLATFORM_OVERRIDE_PERIPHERAL_COUNT * sizeof(PERIPHERAL_INFO_BLOCK)));
  val_peripheral_create_info_table(PeripheralInfoTable);
}

void
freeRmeAcsMem()
{

  val_pe_free_info_table();
  val_gic_free_info_table();
  val_timer_free_info_table();
  val_pcie_free_info_table();
  val_iovirt_free_info_table();
  val_peripheral_free_info_table();
  val_free_shared_mem();
}

/***
  RME Compliance Suite Entry Point.

  Call the Entry points of individual modules.

  @retval  0         The application exited normally.
  @retval  Other     An error occurred.
***/
int32_t
ShellAppMainrme(
  )
{

  uint32_t             Status;
  void                 *branch_label;

  g_print_level = PLATFORM_OVERRIDE_PRINT_LEVEL;
  if (g_print_level < ACS_PRINT_INFO)
  {
      val_print(ACS_PRINT_ERR, "Print Level %d is not supported.", g_print_level);
      val_print(ACS_PRINT_ERR, "Setting Print level to %d", ACS_PRINT_INFO);
      g_print_level = ACS_PRINT_INFO;
  } else if (g_print_level > ACS_PRINT_ERR) {
      val_print(ACS_PRINT_ERR, "Print Level %d is not supported.", g_print_level);
      val_print(ACS_PRINT_ERR, "Setting Print level to %d", ACS_PRINT_ERR);
      g_print_level = ACS_PRINT_ERR;
  }

#ifdef TARGET_BM_BOOT
  /* Write page tables */
  if (val_setup_mmu())
      return ACS_STATUS_FAIL;

  /* Enable Stage-1 MMU */
  if (val_enable_mmu())
      return ACS_STATUS_FAIL;
#endif

  g_print_mmio = FALSE;
  g_enable_pcie_tests = 1;

  //
  // Initialize global counters
  //
  g_print_in_test_context = 0;
  g_print_test_check_id = 0;
  g_rme_tests_total = 0;
  g_rme_tests_pass  = 0;
  g_rme_tests_fail  = 0;

  val_print(ACS_PRINT_ALWAYS, "\n\n RME Architecture Compliance Suite \n", 0);
  val_print(ACS_PRINT_ALWAYS, " Version: Issue B.a ACS EAC   \n", 0);

  val_print(ACS_PRINT_ALWAYS, " (Print level is %2d)\n\n", g_print_level);
  /* Initialize runtime-dependent globals (free mem, shared data, NVM). */
  val_init_runtime_params();

  g_skip_test_str = g_skip_array;

  /* Check if there is a user override to run specific tests*/
  if (g_num_tests) {
      g_execute_tests_str   = g_test_array;
  }

  /* Check if there is a user override to run specific modules*/
  if (g_num_modules) {
      g_execute_modules_str = g_module_array;
  }

  val_print(ACS_PRINT_ALWAYS, " Creating Platform Information Tables \n", 0);
  Status = createPeInfoTable();
  if (Status)
    return Status;
  Status = createGicInfoTable();
  if (Status)
    return Status;
 createTimerInfoTable();
 createPeripheralInfoTable();
 createPcieVirtInfoTable();

 val_allocate_shared_mem();

  /* Initialise exception vector, so any unexpected exception gets handled
   *  by default RME exception handler.
   */
  branch_label = &&print_test_status;
  val_pe_context_save(AA64ReadSp(), (uint64_t)branch_label);
  val_pe_initialize_default_exception_handler(val_pe_default_esr);

  /*
   * Configure Gic Redistributor and ITS to support
   * Generation of LPIs.
  */
  configureGicIts();

  /* Create the platform config tables for the RME Issue A tests */
  createMemCfgInfoTable();

  /* Configure SMMUs, PCIe and Exerciser tables required for the ACS */
  Status = val_configure_acs();
  if (Status)
    return Status;

  Status |= val_rme_execute_tests(val_pe_get_num());

  Status |= val_legacy_execute_tests(val_pe_get_num());

  Status |= val_gic_execute_tests(val_pe_get_num());

  Status |= val_smmu_execute_tests(val_pe_get_num());

  Status |= val_rme_da_execute_tests(val_pe_get_num());

  Status |= val_rme_dpt_execute_tests(val_pe_get_num());

  Status |= val_rme_mec_execute_tests(val_pe_get_num());

print_test_status:
  val_print(ACS_PRINT_ALWAYS, "\n ------------------------------------------------------- \n", 0);
  val_print(ACS_PRINT_ALWAYS, " Total Tests run  = %4d;", g_rme_tests_total);
  val_print(ACS_PRINT_ALWAYS, " Tests Passed  = %4d", g_rme_tests_pass);
  val_print(ACS_PRINT_ALWAYS, " Tests Failed = %4d\n", g_rme_tests_fail);
  val_print(ACS_PRINT_ALWAYS, " --------------------------------------------------------- \n", 0);

  freeRmeAcsMem();

  val_print(ACS_PRINT_ALWAYS, "\n********* RME tests complete. Reset the system *********\n\n", 0);

  val_pe_context_restore(AA64WriteSp(g_stack_pointer));
  while (1);

  return 0;
}
