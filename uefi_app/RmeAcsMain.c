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

#include  <Uefi.h>
#include  <Library/UefiLib.h>
#include  <Library/ShellCEntryLib.h>
#include  <Library/ShellLib.h>
#include  <Library/UefiBootServicesTableLib.h>
#include  <Library/CacheMaintenanceLib.h>
#include  <Protocol/LoadedImage.h>

#include "val/include/val_interface.h"
#include "val/include/rme_acs_pe.h"
#include "val/include/rme_acs_val.h"
#include "val/include/sys_config.h"

#include "RmeAcs.h"

UINT32 g_pcie_p2p;
UINT32 g_pcie_cache_present;

UINT32  g_print_level;
UINT32 g_print_mmio;
UINT32 g_curr_module;
UINT32 g_enable_module;
UINT32  g_skip_test_num[MAX_TEST_SKIP_NUM] = { 10000, 10000, 10000, 10000, 10000,
                                               10000, 10000, 10000, 10000, 10000 };
UINT32  g_single_test = SINGLE_TEST_SENTINEL;
UINT32  g_single_module = SINGLE_MODULE_SENTINEL;
UINT32  g_rme_tests_total;
UINT32  g_rme_tests_pass;
UINT32  g_rme_tests_fail;
UINT64  g_stack_pointer;
UINT64  g_exception_ret_addr;
UINT64  g_ret_addr;
UINT32  g_wakeup_timeout;
UINT32  g_rl_smmu_init;
SHELL_FILE_HANDLE g_rme_log_file_handle;

STATIC VOID FlushImage (VOID)
{
  EFI_LOADED_IMAGE_PROTOCOL   *ImageInfo;
  EFI_STATUS Status;
  Status = gBS->HandleProtocol (gImageHandle, &gEfiLoadedImageProtocolGuid, (VOID **)&ImageInfo);
  if(EFI_ERROR (Status))
  {
    return;
  }

  val_pe_cache_clean_range((UINT64)ImageInfo->ImageBase, (UINT64)ImageInfo->ImageSize);

}

EFI_STATUS
createPeInfoTable (
)
{

  EFI_STATUS Status;

  UINT64   *PeInfoTable;

/* allowing room for growth, at present each entry is 16 bytes, so we can support upto 511 PEs with 8192 bytes*/
  Status = gBS->AllocatePool ( EfiBootServicesData,
                               PE_INFO_TBL_SZ,
                               (VOID **) &PeInfoTable );

  if (EFI_ERROR(Status))
  {
    Print(L"Allocate Pool failed %x \n", Status);
    return Status;
  }

  Status = val_pe_create_info_table(PeInfoTable);

  return Status;

}

EFI_STATUS
createGicInfoTable (
)
{
  EFI_STATUS Status;
  UINT64     *GicInfoTable;

  Status = gBS->AllocatePool (EfiBootServicesData,
                               GIC_INFO_TBL_SZ,
                               (VOID **) &GicInfoTable);

  if (EFI_ERROR(Status))
  {
    Print(L"Allocate Pool failed %x \n", Status);
    return Status;
  }

  Status = val_gic_create_info_table(GicInfoTable);

  return Status;

}

EFI_STATUS
configureGicIts (
)
{
  EFI_STATUS Status;

  Status = val_gic_its_configure();

  return Status;
}

EFI_STATUS
createTimerInfoTable(
)
{
  UINT64   *TimerInfoTable;
  EFI_STATUS Status;

  Status = gBS->AllocatePool (EfiBootServicesData,
                              TIMER_INFO_TBL_SZ,
                              (VOID **) &TimerInfoTable);

  if (EFI_ERROR(Status))
  {
    Print(L"Allocate Pool failed %x \n", Status);
    return Status;
  }
  val_timer_create_info_table(TimerInfoTable);

  return Status;
}

EFI_STATUS
createPcieVirtInfoTable(
)
{
  UINT64   *PcieInfoTable;
  UINT64   *IoVirtInfoTable;
  UINT64   *RegisterInfoTable;

  EFI_STATUS Status;

  Status = gBS->AllocatePool (EfiBootServicesData,
                              PCIE_INFO_TBL_SZ,
                              (VOID **) &PcieInfoTable);

  if (EFI_ERROR(Status))
  {
    Print(L"Allocate Pool failed %x \n", Status);
    return Status;
  }
  val_pcie_create_info_table(PcieInfoTable);

  Status = gBS->AllocatePool (EfiBootServicesData,
                              REGISTER_INFO_TBL_SZ,
                              (VOID **) &RegisterInfoTable);

  if (EFI_ERROR(Status))
  {
    Print(L"Allocate Pool failed %x \n", Status);
    return Status;
  }

  val_register_create_info_table(RegisterInfoTable);


  Status = gBS->AllocatePool (EfiBootServicesData,
                              IOVIRT_INFO_TBL_SZ,
                              (VOID **) &IoVirtInfoTable);

  if (EFI_ERROR(Status))
  {
    Print(L"Allocate Pool failed %x \n", Status);
    return Status;
  }
  val_iovirt_create_info_table(IoVirtInfoTable);

  return Status;
}

EFI_STATUS
createPeripheralInfoTable(
)
{
  UINT64   *PeripheralInfoTable;

  EFI_STATUS Status;

  Status = gBS->AllocatePool (EfiBootServicesData,
                              PERIPHERAL_INFO_TBL_SZ,
                              (VOID **) &PeripheralInfoTable);

  if (EFI_ERROR(Status))
  {
    Print(L"Allocate Pool failed %x \n", Status);
    return Status;
  }
  val_peripheral_create_info_table(PeripheralInfoTable);

  return Status;
}

VOID
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

VOID
HelpMsg (
  VOID
  )
{
  Print (L"\nUsage: Rme.efi [-v <n>] | [-l <n>] | [-f <filename>] | [-skip <n>] | [-p <n>] | [-t <n>] | [-m <n>]\n"
         "[-skip <n>] | [-p <n>]\n"
         "Options:\n"
         "-v      Verbosity of the Prints\n"
         "        1 shows all prints, 5 shows Errors\n"
         "        Note: pal_mmio prints can be enabled for specific modules by passing\n"
         "              module numbers along with global verbosity level 1\n"
         "              Module numbers are PE 0, GIC 1,  ...\n"
         "              E.g., To enable mmio prints for PE and TIMER pass -v 102 \n"
         "-mmio   Pass this flag to enable pal_mmio_read/write prints, use with -v 1\n"
         "-l      Level of compliance to be tested for\n"
         "        As per RME spec, 3 to 6\n"
         "-f      Name of the log file to record the test results in\n"
         "-skip   Test(s) to be skipped\n"
         "        Refer to section 4 of RME_ACS_User_Guide\n"
         "        To skip a module, use Model_ID as mentioned in user guide\n"
         "        To skip a particular test within a module, use the exact testcase number\n"
         "-p      Enable/disable PCIe RME 6.0 (RCiEP) compliance tests\n"
         "        1 - enables PCIe tests, 0 - disables PCIe tests\n"
         "-t      If set, will only run the specified test, all others will be skipped.\n"
         "-m      If set, will only run the specified module, all others will be skipped.\n"
         "-p2p    Pass this flag to indicate that PCIe Hierarchy Supports Peer-to-Peer\n"
         "-cache  Pass this flag to indicate that if the test system supports PCIe address translation cache\n"
         "-timeout  Set timeout multiple for wakeup tests\n"
         "        1 - min value  5 - max value\n"
  );
}

STATIC CONST SHELL_PARAM_ITEM ParamList[] = {
  {L"-v"    , TypeValue},    // -v    # Verbosity of the Prints. 1 shows all prints, 5 shows Errors
  {L"-l"    , TypeValue},    // -l    # Level of compliance to be tested for.
  {L"-f"    , TypeValue},    // -f    # Name of the log file to record the test results in.
  {L"-skip" , TypeValue},    // -skip # test(s) to skip execution
  {L"-help" , TypeFlag},     // -help # help : info about commands
  {L"-h"    , TypeFlag},     // -h    # help : info about commands
  {L"-p"    , TypeValue},    // -p    # Enable/disable PCIe RME 6.0 (RCiEP) compliance tests.
  {L"-mmio" , TypeFlag},     // -mmio # Enable pal_mmio prints
  {L"-t"    , TypeValue},    // -t    # Test to be run
  {L"-m"    , TypeValue},    // -m    # Module to be run
  {L"-p2p", TypeFlag},       // -p2p  # Peer-to-Peer is supported
  {L"-cache", TypeFlag},     // -cache# PCIe address translation cache is supported
  {L"-timeout" , TypeValue}, // -timeout # Set timeout multiple for wakeup tests
  {NULL     , TypeMax}
  };

/***
  RME Compliance Suite Entry Point.

  Call the Entry points of individual modules.

  @retval  0         The application exited normally.
  @retval  Other     An error occurred.
***/
INTN
EFIAPI
ShellAppMainrme (
  IN UINTN Argc,
  IN CHAR16 **Argv
  )
{

  LIST_ENTRY         *ParamPackage;
  CONST CHAR16       *CmdLineArg;
  CHAR16             *ProbParam;
  UINT32             Status;
  UINT32             ReadVerbosity;
  UINT32             i,j=0;
  VOID               *branch_label;


  //
  // Process Command Line arguments
  //
  Status = ShellInitialize();
  Status = ShellCommandLineParse (ParamList, &ParamPackage, &ProbParam, TRUE);
  if (Status) {
    Print(L"Shell command line parse error %x\n", Status);
    Print(L"Unrecognized option %s passed\n", ProbParam);
    HelpMsg();
    return SHELL_INVALID_PARAMETER;
  }

  // Options with Values
  if (ShellCommandLineGetFlag (ParamPackage, L"-skip")) {
      CmdLineArg  = ShellCommandLineGetValue (ParamPackage, L"-skip");
      for (i=0 ; i < StrLen(CmdLineArg) ; i++){
        g_skip_test_num[0] = StrDecimalToUintn((CONST CHAR16 *)(CmdLineArg+0));
          if(*(CmdLineArg+i) == L','){
              g_skip_test_num[++j] = StrDecimalToUintn((CONST CHAR16 *)(CmdLineArg+i+1));
          }
      }
  }


    // Options with Values
  CmdLineArg  = ShellCommandLineGetValue (ParamPackage, L"-v");
  if (CmdLineArg == NULL) {
    g_print_level = G_PRINT_LEVEL;
  } else {
    ReadVerbosity = StrDecimalToUintn(CmdLineArg);
    while (ReadVerbosity/10) {
      g_enable_module |= (1 << ReadVerbosity%10);
      ReadVerbosity /= 10;
    }
    g_print_level = ReadVerbosity;
    if (g_print_level > 5) {
      g_print_level = G_PRINT_LEVEL;
    }
  }

  // Options with Values
  CmdLineArg  = ShellCommandLineGetValue (ParamPackage, L"-timeout");
  if (CmdLineArg == NULL) {
    g_wakeup_timeout = 1;
  } else {
    g_wakeup_timeout = StrDecimalToUintn(CmdLineArg);
    Print(L"Wakeup timeout multiple %d.\n", g_wakeup_timeout);
    if (g_wakeup_timeout > 5)
        g_wakeup_timeout = 5;
    }

    // Options with Values
  CmdLineArg  = ShellCommandLineGetValue (ParamPackage, L"-f");
  if (CmdLineArg == NULL) {
    g_rme_log_file_handle = NULL;
  } else {
    Status = ShellOpenFileByName(CmdLineArg, &g_rme_log_file_handle,
             EFI_FILE_MODE_WRITE | EFI_FILE_MODE_READ | EFI_FILE_MODE_CREATE, 0x0);
    if(EFI_ERROR(Status)) {
         Print(L"Failed to open log file %s\n", CmdLineArg);
         g_rme_log_file_handle = NULL;
    }
  }


  // Options with Flags
  if ((ShellCommandLineGetFlag (ParamPackage, L"-help")) || (ShellCommandLineGetFlag (ParamPackage, L"-h"))){
     HelpMsg();
     return 0;
  }

  if (ShellCommandLineGetFlag (ParamPackage, L"-mmio")) {
    g_print_mmio = TRUE;
  } else {
    g_print_mmio = FALSE;
  }

  if (ShellCommandLineGetFlag (ParamPackage, L"-p2p")) {
    g_pcie_p2p = TRUE;
  } else {
    g_pcie_p2p = FALSE;
  }

  if (ShellCommandLineGetFlag (ParamPackage, L"-cache")) {
    g_pcie_cache_present = TRUE;
  } else {
    g_pcie_cache_present = FALSE;
  }


  // Options with Values
  CmdLineArg  = ShellCommandLineGetValue (ParamPackage, L"-t");
  if (CmdLineArg != NULL) {
    g_single_test = StrDecimalToUintn(CmdLineArg);
  }

  // Options with Values
  CmdLineArg  = ShellCommandLineGetValue (ParamPackage, L"-m");
  if (CmdLineArg != NULL) {
    g_single_module = StrDecimalToUintn(CmdLineArg);
  }

  //
  // Initialize global counters
  //
  g_rme_tests_total = 0;
  g_rme_tests_pass  = 0;
  g_rme_tests_fail  = 0;

  Print(L"\n\n RME Architecture Compliance Suite \n");
  Print(L"    Version: Issue B.a ACS EAC   \n");

  Print(L"\n Starting tests for (Print level is %2d)\n\n", g_print_level);


  Print(L" Creating Platform Information Tables \n");
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

  // Initialise exception vector, so any unexpected exception gets handled by default RME exception handler
  branch_label = &&print_test_status;
  val_pe_context_save(AA64ReadSp(), (uint64_t)branch_label);
  val_pe_initialize_default_exception_handler(val_pe_default_esr);
  FlushImage();
  /*
   * Configure Gic Redistributor and ITS to support
   * Generation of LPIs.
  */
  configureGicIts();

  /* Configure SMMUs, PCIe and Exerciser tables required for the ACS */
  Status = val_configure_acs();
  if (Status)
    return Status;

  Print(L"\n      *** Starting RME tests ***  \n");
  Status |= val_rme_execute_tests(val_pe_get_num());

  Print(L"\n      *** Starting Legacy System tests ***  \n");
  Status |= val_legacy_execute_tests(val_pe_get_num());

  Print(L"\n      *** Starting GIC test ***  \n");
  Status |= val_gic_execute_tests(val_pe_get_num());

  Print(L"\n      *** Starting IO Virtualization tests ***  \n");
  Status |= val_smmu_execute_tests(val_pe_get_num());

  Print(L"\n      *** Starting RME DA tests ***  \n");
  Status |= val_rme_da_execute_tests(val_pe_get_num());

  Print(L"\n      *** Starting RME DPT tests ***  \n");
  Status |= val_rme_dpt_execute_tests(val_pe_get_num());

  Print(L"\n      *** Starting RME MEC tests ***  \n");
  Status |= val_rme_mec_execute_tests(val_pe_get_num());


print_test_status:
  val_print(ACS_PRINT_TEST, "\n     ------------------------------------------------------- \n", 0);
  val_print(ACS_PRINT_TEST, "     Total Tests run  = %4d;", g_rme_tests_total);
  val_print(ACS_PRINT_TEST, "  Tests Passed  = %4d", g_rme_tests_pass);
  val_print(ACS_PRINT_TEST, "  Tests Failed = %4d\n", g_rme_tests_fail);
  val_print(ACS_PRINT_TEST, "     --------------------------------------------------------- \n", 0);

  freeRmeAcsMem();

  if(g_rme_log_file_handle) {
    ShellCloseFile(&g_rme_log_file_handle);
  }

  Print(L"\n      *** RME tests complete. Reset the system. *** \n\n");

  val_pe_context_restore(AA64WriteSp(g_stack_pointer));

  return(0);
}

/***
  RME Compliance Suite Entry Point. This function is to
  support compilation of RME changes in edk2

  Call the Entry points of individual modules.

  @retval  0         The application exited normally.
  @retval  Other     An error occurred.
***/
INTN
EFIAPI
ShellAppMain(
  IN UINTN Argc,
  IN CHAR16 **Argv
  )
{
 return ShellAppMainrme(Argc, Argv);
}
