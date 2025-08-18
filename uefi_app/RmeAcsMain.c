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
#include  <Library/BaseLib.h>
#include  <Library/MemoryAllocationLib.h>
#include  <Protocol/LoadedImage.h>

#include "val/include/val_interface.h"
#include "val/include/val_pe.h"
#include "val/include/val.h"

#include "RmeAcs.h"

UINT32 g_pcie_p2p;
UINT32 g_pcie_cache_present;

UINT32 g_print_level;
UINT32 g_print_in_test_context;
UINT32 g_print_test_check_id;
UINT32 g_print_mmio;
UINT32 g_curr_module;
UINT32 g_enable_module;
CHAR8 **g_skip_test_str;
CHAR8 **g_execute_tests_str;
CHAR8 **g_execute_modules_str;
UINT32 g_num_skip = 0;
UINT32 g_num_tests = 0;
UINT32 g_num_modules = 0;
UINT32 g_rme_tests_total;
UINT32 g_rme_tests_pass;
UINT32 g_rme_tests_fail;
UINT64 g_stack_pointer;
UINT64 g_exception_ret_addr;
UINT64 g_ret_addr;
UINT32 g_wakeup_timeout;
UINT32 g_rl_smmu_init;
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
    Print(L"\nAllocate Pool failed %x ", Status);
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
    Print(L"\nAllocate Pool failed %x ", Status);
    return Status;
  }

  Status = val_gic_create_info_table(GicInfoTable);

  return Status;

}

EFI_STATUS
createMemCfgInfoTable (
)
{
  EFI_STATUS Status;
  UINT64     *GPCInfoTable;
  UINT64     *PASInfoTable;
  UINT64     *RootRegInfoTable;

  Status = gBS->AllocatePool (EfiBootServicesData,
                               MEM_GPC_REGION_TBL_SZ,
                               (VOID **) &GPCInfoTable);

  Status = gBS->AllocatePool (EfiBootServicesData,
                               MEM_PAS_REGION_TBL_SZ,
                               (VOID **) &PASInfoTable);

  if (EFI_ERROR(Status))
  {
    Print(L"Allocate Pool failed %x \n", Status);
    return Status;
  }

  val_mem_region_create_info_table(GPCInfoTable, PASInfoTable);

  Status = gBS->AllocatePool (EfiBootServicesData,
                               ROOT_REG_TBL_SZ,
                               (VOID **) &RootRegInfoTable);

  if (EFI_ERROR(Status))
  {
    Print(L"Allocate Pool failed %x \n", Status);
    return Status;
  }

  val_root_register_create_info_table(RootRegInfoTable);

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
    Print(L"\nAllocate Pool failed %x ", Status);
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
    Print(L"\nAllocate Pool failed %x ", Status);
    return Status;
  }
  val_pcie_create_info_table(PcieInfoTable);

  Status = gBS->AllocatePool (EfiBootServicesData,
                              REGISTER_INFO_TBL_SZ,
                              (VOID **) &RegisterInfoTable);

  if (EFI_ERROR(Status))
  {
    Print(L"\nAllocate Pool failed %x ", Status);
    return Status;
  }

  val_register_create_info_table(RegisterInfoTable);


  Status = gBS->AllocatePool (EfiBootServicesData,
                              IOVIRT_INFO_TBL_SZ,
                              (VOID **) &IoVirtInfoTable);

  if (EFI_ERROR(Status))
  {
    Print(L"\nAllocate Pool failed %x ", Status);
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
    Print(L"\nAllocate Pool failed %x ", Status);
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
         "              module id along with global verbosity level 1\n"
         "              Module ids are rme, gic,  ...\n"
         "              E.g., To enable mmio prints for RME and DA pass -v 1,rme,da \n"
         "-mmio   Pass this flag to enable pal_mmio_read/write and tdisp prints, use with -v 1\n"
         "-f      Name of the log file to record the test results in\n"
         "-skip   Test(s) to be skipped\n"
         "        Refer to section 2.3 of RME_ACS_Platform_Porting_Guide\n"
         "        To skip a module, use Model_ID as mentioned in user guide\n"
         "        To skip a particular test within a module, use the exact testcase name\n"
         "-t      If set, will only run the specified tests, all others will be skipped.\n"
         "-m      If set, will only run the specified modules, all others will be skipped.\n"
         "-p2p    Pass this flag to indicate that PCIe Hierarchy Supports Peer-to-Peer\n"
         "-cache  Pass this flag to indicate that if the test system supports PCIe address translation cache\n"
  );
}

STATIC CONST SHELL_PARAM_ITEM ParamList[] = {
  {L"-v"    , TypeValue},    // -v    # Verbosity of the Prints. 1 shows all prints, 5 shows Errors
  {L"-f"    , TypeValue},    // -f    # Name of the log file to record the test results in.
  {L"-skip" , TypeValue},    // -skip # test(s) to skip execution
  {L"-help" , TypeFlag},     // -help # help : info about commands
  {L"-h"    , TypeFlag},     // -h    # help : info about commands
  {L"-mmio" , TypeFlag},     // -mmio # Enable pal_mmio prints
  {L"-t"    , TypeValue},    // -t    # Test to be run
  {L"-m"    , TypeValue},    // -m    # Module to be run
  {L"-p2p", TypeFlag},       // -p2p  # Peer-to-Peer is supported
  {L"-cache", TypeFlag},     // -cache# PCIe address translation cache is supported
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
  VOID               *branch_label;


  //
  // Process Command Line arguments
  //
  Status = ShellInitialize();
  Status = ShellCommandLineParse (ParamList, &ParamPackage, &ProbParam, TRUE);
  if (Status) {
    Print(L"\nShell command line parse error %x", Status);
    Print(L"\nUnrecognized option %s passed", ProbParam);
    HelpMsg();
    return SHELL_INVALID_PARAMETER;
  }

  // Options with Values
  if (ShellCommandLineGetFlag(ParamPackage, L"-skip")) {
      CmdLineArg = ShellCommandLineGetValue(ParamPackage, L"-skip");

      if (CmdLineArg != NULL) {
          UINTN str_len = StrLen(CmdLineArg);
          EFI_STATUS Status;
          Status = gBS->AllocatePool(EfiBootServicesData,
                                     str_len * sizeof(CHAR8 *),
                                     (VOID **)&g_skip_test_str);
          if (EFI_ERROR(Status)) {
              Print(L"\nError: Unable to allocate memory for skip string array");
              return SHELL_OUT_OF_RESOURCES;
          }
          CHAR16 *WorkingStr = AllocateCopyPool(StrSize(CmdLineArg), CmdLineArg);
          if (WorkingStr == NULL) {
              Print(L"\nError: Unable to allocate memory for skip string");
              return SHELL_OUT_OF_RESOURCES;
          }

          CHAR16 *Token = WorkingStr;

          while (*Token != L'\0' && g_num_skip < str_len) {
              CHAR16 *Next = StrStr(Token, L",");
              if (Next != NULL)
                  *Next = L'\0';

              // Trim leading spaces
              while (*Token == L' ') Token++;

              // Trim trailing spaces
              CHAR16 *End = Token + StrLen(Token) - 1;
              while (End > Token && *End == L' ') {
                  *End = L'\0';
                  End--;
              }
              UINTN Len = StrLen(Token);
              g_skip_test_str[g_num_skip] = AllocateZeroPool(Len + 1);
              if (g_skip_test_str[g_num_skip]) {
                  UnicodeStrToAsciiStrS(Token, g_skip_test_str[g_num_skip], Len + 1);
                  g_num_skip++;
              }
              if (Next != NULL)
                  Token = Next + 1;
              else
                  break;
          }
      }
  }

  // Options with Values
  CmdLineArg  = ShellCommandLineGetValue (ParamPackage, L"-v");
  if (CmdLineArg != NULL) {
    CHAR16 *token;
    CHAR16 *next = (CHAR16 *)CmdLineArg;

    g_print_level = 1;  // Default to verbose

      while ((token = StrStr(next, L",")) != NULL) {
        *token = L'\0'; // Null-terminate current token

        if (StrCmp(next, L"rme") == 0)         g_enable_module |= (1 << 0);
        else if (StrCmp(next, L"gic") == 0)    g_enable_module |= (1 << 1);
        else if (StrCmp(next, L"smmu") == 0)   g_enable_module |= (1 << 2);
        else if (StrCmp(next, L"da") == 0)     g_enable_module |= (1 << 3);
        else if (StrCmp(next, L"dpt") == 0)    g_enable_module |= (1 << 4);
        else if (StrCmp(next, L"mec") == 0)    g_enable_module |= (1 << 5);
        else if (StrCmp(next, L"ls") == 0)     g_enable_module |= (1 << 6);

        next = token + 1; // Move past the comma
      }

      // Handle the last (or only) token
      if (*next != L'\0') {
        if (StrCmp(next, L"rme") == 0)         g_enable_module |= (1 << 0);
        else if (StrCmp(next, L"gic") == 0)    g_enable_module |= (1 << 1);
        else if (StrCmp(next, L"smmu") == 0)   g_enable_module |= (1 << 2);
        else if (StrCmp(next, L"da") == 0)     g_enable_module |= (1 << 3);
        else if (StrCmp(next, L"dpt") == 0)    g_enable_module |= (1 << 4);
        else if (StrCmp(next, L"mec") == 0)    g_enable_module |= (1 << 5);
        else if (StrCmp(next, L"ls") == 0)     g_enable_module |= (1 << 6);
      }
  } else {
    g_print_level = G_PRINT_LEVEL;
  }

  // Options with Values
  CmdLineArg  = ShellCommandLineGetValue (ParamPackage, L"-timeout");
  if (CmdLineArg == NULL) {
    g_wakeup_timeout = 1;
  } else {
    g_wakeup_timeout = StrDecimalToUintn(CmdLineArg);
    Print(L"\nWakeup timeout multiple %d.", g_wakeup_timeout);
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
         Print(L"\nFailed to open log file %s", CmdLineArg);
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
CmdLineArg = ShellCommandLineGetValue(ParamPackage, L"-t");
if (CmdLineArg != NULL) {
    UINTN str_len = StrLen(CmdLineArg);
    EFI_STATUS Status;
    Status = gBS->AllocatePool(EfiBootServicesData,
                               str_len * sizeof(CHAR8 *),
                               (VOID **)&g_execute_tests_str);
    if (EFI_ERROR(Status)) {
        Print(L"\nError: Unable to allocate memory for execute test string array");
        return SHELL_OUT_OF_RESOURCES;
    }

    CHAR16 *WorkingStr = AllocateCopyPool(StrSize(CmdLineArg), CmdLineArg);
    if (WorkingStr == NULL) {
        Print(L"\nError: Unable to allocate memory for test string");
        return SHELL_OUT_OF_RESOURCES;
    }

    CHAR16 *Token = WorkingStr;
    UINTN j = 0;

    while (*Token != L'\0' && j < str_len) {
        CHAR16 *Next = StrStr(Token, L",");
        if (Next != NULL)
            *Next = L'\0';

        // Trim leading spaces
        while (*Token == L' ') Token++;

        // Trim trailing spaces
        CHAR16 *End = Token + StrLen(Token) - 1;
        while (End > Token && *End == L' ') {
            *End = L'\0';
            End--;
        }

        UINTN Len = StrLen(Token);
        g_execute_tests_str[g_num_tests] = AllocateZeroPool(Len + 1);
        if (g_execute_tests_str[g_num_tests]) {
            UnicodeStrToAsciiStrS(Token, g_execute_tests_str[g_num_tests], Len + 1);
            g_num_tests++;
        }
        if (Next != NULL)
            Token = Next + 1;
        else
            break;
        j++;
    }
}

  // Options with Values
CmdLineArg = ShellCommandLineGetValue(ParamPackage, L"-m");
if (CmdLineArg != NULL) {
    UINTN str_len = StrLen(CmdLineArg);
    EFI_STATUS Status;
    Status = gBS->AllocatePool(EfiBootServicesData,
                               str_len * sizeof(CHAR8 *),
                               (VOID **)&g_execute_modules_str);
    if (EFI_ERROR(Status)) {
        Print(L"\nError: Unable to allocate memory for execute module string array");
        return SHELL_OUT_OF_RESOURCES;
    }

    CHAR16 *WorkingStr = AllocateCopyPool(StrSize(CmdLineArg), CmdLineArg);
    if (WorkingStr == NULL) {
        Print(L"\nError: Unable to allocate memory for module string");
        return SHELL_OUT_OF_RESOURCES;
    }

    CHAR16 *Token = WorkingStr;
    UINTN j = 0;

    while (*Token != L'\0' && j < str_len) {
        CHAR16 *Next = StrStr(Token, L",");
        if (Next != NULL)
            *Next = L'\0';

        // Trim leading spaces
        while (*Token == L' ') Token++;

        // Trim trailing spaces
        CHAR16 *End = Token + StrLen(Token) - 1;
        while (End > Token && *End == L' ') {
            *End = L'\0';
            End--;
        }

        UINTN Len = StrLen(Token);
        g_execute_modules_str[g_num_modules] = AllocateZeroPool(Len + 1);
        if (g_execute_modules_str[g_num_modules]) {
            UnicodeStrToAsciiStrS(Token, g_execute_modules_str[g_num_modules], Len + 1);
            g_num_modules++;
        }
        if (Next != NULL)
            Token = Next + 1;
        else
            break;
        j++;
    }
}

  //
  // Initialize global counters
  //
  g_print_in_test_context = 0;
  g_print_test_check_id = 0;
  g_rme_tests_total = 0;
  g_rme_tests_pass  = 0;
  g_rme_tests_fail  = 0;

  Print(L"\n\n RME Architecture Compliance Suite \n");
  Print(L"    Version: Issue B.a ACS EAC   \n");

  Print(L"\n Starting tests for (Print level is %2d)\n\n", g_print_level);


  Print(L" Creating Platform Information Tables ");
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
  val_print(ACS_PRINT_ALWAYS, "\n------------------------------------------------------- \n", 0);
  val_print(ACS_PRINT_ALWAYS, " Total Tests run  = %4d;", g_rme_tests_total);
  val_print(ACS_PRINT_ALWAYS, " Tests Passed  = %4d", g_rme_tests_pass);
  val_print(ACS_PRINT_ALWAYS, " Tests Failed = %4d\n", g_rme_tests_fail);
  val_print(ACS_PRINT_ALWAYS, "--------------------------------------------------------- \n", 0);

  freeRmeAcsMem();

  if(g_rme_log_file_handle) {
    ShellCloseFile(&g_rme_log_file_handle);
  }

  Print(L"\n********* RME tests complete. Reset the system *********\n\n");

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
