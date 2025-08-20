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
#include  <Library/BaseMemoryLib.h>
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
CHAR8** g_skip_test_str;
CHAR8** g_execute_tests_str;
CHAR8** g_execute_modules_str;
UINT32 g_num_skip    = 0;
UINT32 g_num_tests   = 0;
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

/* When -cfg is passed, parse the INI and set globals accordingly.
 * Also pass the same INI path to the platform runtime config so
 * PLATFORM_CONFIG_* _RT macros pull values from that file.
 */
VOID RmeCfgInit(VOID);
VOID RmeCfgSetIniPath(CONST CHAR16* NewPath);
VOID pal_dump_platform_config(VOID);
UINT64 RmeCfgGetU64(CONST CHAR16* Key, UINT64 DefaultVal);
CONST CHAR16* RmeCfgGetStr(CONST CHAR16* Key, CONST CHAR16* DefaultVal);

STATIC VOID TrimInPlace(CHAR16* s)
{
  if (!s)
    return;
  while (*s == L' ' || *s == L'\t')
  {
    CopyMem(s, s + 1, StrLen(s) * sizeof(CHAR16));
  }
  UINTN n = StrLen(s);
  while (n && (s[n - 1] == L' ' || s[n - 1] == L'\t' || s[n - 1] == L'\r' || s[n - 1] == L'\n'))
    s[--n] = 0;
}

STATIC EFI_STATUS ReadAsciiFileToWide(CONST CHAR16* Path, CHAR16** OutWide, UINTN* OutBytes)
{
  if (OutWide)
    *OutWide = NULL;
  if (OutBytes)
    *OutBytes = 0;

  SHELL_FILE_HANDLE File;
  EFI_STATUS Status = ShellOpenFileByName(Path, &File, EFI_FILE_MODE_READ, 0);
  if (EFI_ERROR(Status))
    return Status;

  UINT64 fsz = 0;
  Status     = ShellGetFileSize(File, &fsz);
  if (EFI_ERROR(Status))
  {
    ShellCloseFile(&File);
    return Status;
  }

  if (fsz == 0)
  {
    ShellCloseFile(&File);
    return EFI_NOT_FOUND;
  }

  UINTN read = (UINTN)fsz;
  CHAR8* buf = AllocateZeroPool(read + 2);
  if (!buf)
  {
    ShellCloseFile(&File);
    return EFI_OUT_OF_RESOURCES;
  }
  Status = ShellReadFile(File, &read, buf);
  ShellCloseFile(&File);
  if (EFI_ERROR(Status))
  {
    FreePool(buf);
    return Status;
  }

  CHAR16* wide = AllocateZeroPool((read + 1) * sizeof(CHAR16));
  if (!wide)
  {
    FreePool(buf);
    return EFI_OUT_OF_RESOURCES;
  }
  for (UINTN i = 0; i < read; i++)
    wide[i] = buf[i];
  if (OutWide)
    *OutWide = wide;
  if (OutBytes)
    *OutBytes = read;
  FreePool(buf);
  return EFI_SUCCESS;
}

STATIC VOID ParseCsvToAsciiArray(CONST CHAR16* Csv, CHAR8*** OutArr, UINT32* OutCount)
{
  if (OutArr)
    *OutArr = NULL;
  if (OutCount)
    *OutCount = 0;
  if (!Csv || !OutArr || !OutCount)
    return;

  UINTN len = StrLen(Csv);
  if (!len)
    return;

  EFI_STATUS St = gBS->AllocatePool(EfiBootServicesData, len * sizeof(CHAR8*), (VOID**)OutArr);
  if (EFI_ERROR(St) || !*OutArr)
    return;

  CHAR16* Working = AllocateCopyPool(StrSize(Csv), Csv);
  if (!Working)
  {
    FreePool(*OutArr);
    *OutArr   = NULL;
    *OutCount = 0;
    return;
  }
  CHAR16* token = Working;
  while (*token != L'\0' && *OutCount < len)
  {
    CHAR16* next = StrStr(token, L",");
    if (next)
      *next = L'\0';
    while (*token == L' ')
      token++;
    CHAR16* end = token + StrLen(token);
    while (end > token && (end[-1] == L' '))
      *--end = 0;

    UINTN tlen           = StrLen(token);
    (*OutArr)[*OutCount] = AllocateZeroPool(tlen + 1);
    if ((*OutArr)[*OutCount])
    {
      UnicodeStrToAsciiStrS(token, (*OutArr)[*OutCount], tlen + 1);
      (*OutCount)++;
    }
    if (!next)
      break;
    token = next + 1;
  }
  FreePool(Working);
}

STATIC VOID FreeAsciiArray(CHAR8*** Arr, UINT32* Count)
{
  if (!Arr || !*Arr || !Count)
    return;
  for (UINT32 i = 0; i < *Count; i++)
  {
    if ((*Arr)[i])
      FreePool((*Arr)[i]);
  }
  FreePool(*Arr);
  *Arr   = NULL;
  *Count = 0;
}

STATIC VOID ReplaceCsvArray(CONST CHAR16* Csv, CHAR8*** Arr, UINT32* Count)
{
  // Free previous content, then (re)parse Csv if provided
  if (Arr && Count && *Arr)
    FreeAsciiArray(Arr, Count);
  if (Csv && Arr && Count)
  {
    if (*Arr || *Count)
      FreeAsciiArray(Arr, Count);
    ParseCsvToAsciiArray(Csv, Arr, Count);
  }
}

STATIC VOID ApplyIniRmeConfig(CONST CHAR16* IniText)
{
  if (!IniText)
    return;

  BOOLEAN InRme = FALSE;
  for (CONST CHAR16* p = IniText; *p;)
  {
    CONST CHAR16* line = p;
    while (*p && *p != L'\n' && *p != L'\r')
      p++;
    CHAR16 save   = *p;
    *((CHAR16*)p) = 0;

    // Work on a trimmed copy to avoid altering IniText
    CHAR16* work = AllocateCopyPool(StrSize(line), line);
    if (work)
    {
      TrimInPlace(work);
      if (work[0] && work[0] != L'#' && work[0] != L';')
      {
        if (work[0] == L'[')
        {
          InRme = (StrCmp(work, L"[RME_COMMAND_CONFIG]") == 0);
        }
        else if (InRme)
        {
          CHAR16* eq = StrStr(work, L"=");
          if (eq)
          {
            *eq         = 0;
            CHAR16* key = work;
            CHAR16* val = eq + 1;
            TrimInPlace(key);
            TrimInPlace(val);
            if (StrCmp(key, L"RME_PRINT_LEVEL") == 0)
            {
              g_print_level = (UINT32)StrDecimalToUintn(val);
            }
            else if (StrCmp(key, L"RME_LOG_FILE") == 0)
            {
              if (g_rme_log_file_handle)
                ShellCloseFile(&g_rme_log_file_handle);
              EFI_STATUS S = ShellOpenFileByName(
                  val, &g_rme_log_file_handle,
                  EFI_FILE_MODE_WRITE | EFI_FILE_MODE_READ | EFI_FILE_MODE_CREATE, 0x0);
              if (EFI_ERROR(S))
              {
                g_rme_log_file_handle = NULL;
              }
            }
            else if (StrCmp(key, L"RME_EXEC_TESTS") == 0)
            {
              ReplaceCsvArray(val, &g_execute_tests_str, &g_num_tests);
            }
            else if (StrCmp(key, L"RME_EXEC_MODULES") == 0)
            {
              ReplaceCsvArray(val, &g_execute_modules_str, &g_num_modules);
            }
            else if (StrCmp(key, L"RME_SKIP_TESTS") == 0)
            {
              ReplaceCsvArray(val, &g_skip_test_str, &g_num_skip);
            }
            else if (StrCmp(key, L"RME_MMIO") == 0)
            {
              // Optional non-standard key to enable mmio prints
              if (val[0] == L'1' || StrCmp(val, L"true") == 0 || StrCmp(val, L"TRUE") == 0)
                g_print_mmio = TRUE;
            }
          }
        }
      }
      FreePool(work);
    }
    *((CHAR16*)p) = save;
    if (*p == L'\r' && *(p + 1) == L'\n')
      p += 2;
    else if (*p)
      p++;
  }
}

STATIC VOID FlushImage(VOID)
{
  EFI_LOADED_IMAGE_PROTOCOL* ImageInfo;
  EFI_STATUS Status;
  Status = gBS->HandleProtocol(gImageHandle, &gEfiLoadedImageProtocolGuid, (VOID**)&ImageInfo);
  if (EFI_ERROR(Status))
  {
    return;
  }

  val_pe_cache_clean_range((UINT64)ImageInfo->ImageBase, (UINT64)ImageInfo->ImageSize);
}

EFI_STATUS
createPeInfoTable()
{

  EFI_STATUS Status;

  UINT64* PeInfoTable;

  /* allowing room for growth, at present each entry is 16 bytes, so we can support upto 511 PEs
   * with 8192 bytes*/
  Status = gBS->AllocatePool(EfiBootServicesData, PE_INFO_TBL_SZ, (VOID**)&PeInfoTable);

  if (EFI_ERROR(Status))
  {
    Print(L"\nAllocate Pool failed %x ", Status);
    return Status;
  }

  Status = val_pe_create_info_table(PeInfoTable);

  return Status;
}

EFI_STATUS
createGicInfoTable()
{
  EFI_STATUS Status;
  UINT64* GicInfoTable;

  Status = gBS->AllocatePool(EfiBootServicesData, GIC_INFO_TBL_SZ, (VOID**)&GicInfoTable);

  if (EFI_ERROR(Status))
  {
    Print(L"\nAllocate Pool failed %x ", Status);
    return Status;
  }

  Status = val_gic_create_info_table(GicInfoTable);

  return Status;
}

EFI_STATUS
createMemCfgInfoTable()
{
  EFI_STATUS Status;
  UINT64* GPCInfoTable;
  UINT64* PASInfoTable;
  UINT64* RootRegInfoTable;

  Status = gBS->AllocatePool(EfiBootServicesData, MEM_GPC_REGION_TBL_SZ, (VOID**)&GPCInfoTable);

  Status = gBS->AllocatePool(EfiBootServicesData, MEM_PAS_REGION_TBL_SZ, (VOID**)&PASInfoTable);

  if (EFI_ERROR(Status))
  {
    Print(L"Allocate Pool failed %x \n", Status);
    return Status;
  }

  val_mem_region_create_info_table(GPCInfoTable, PASInfoTable);

  Status = gBS->AllocatePool(EfiBootServicesData, ROOT_REG_TBL_SZ, (VOID**)&RootRegInfoTable);

  if (EFI_ERROR(Status))
  {
    Print(L"Allocate Pool failed %x \n", Status);
    return Status;
  }

  val_root_register_create_info_table(RootRegInfoTable);

  return Status;
}

EFI_STATUS
configureGicIts()
{
  EFI_STATUS Status;

  Status = val_gic_its_configure();

  return Status;
}

EFI_STATUS
createTimerInfoTable()
{
  UINT64* TimerInfoTable;
  EFI_STATUS Status;

  Status = gBS->AllocatePool(EfiBootServicesData, TIMER_INFO_TBL_SZ, (VOID**)&TimerInfoTable);

  if (EFI_ERROR(Status))
  {
    Print(L"\nAllocate Pool failed %x ", Status);
    return Status;
  }
  val_timer_create_info_table(TimerInfoTable);

  return Status;
}

EFI_STATUS
createPcieVirtInfoTable()
{
  UINT64* PcieInfoTable;
  UINT64* IoVirtInfoTable;
  UINT64* RegisterInfoTable;

  EFI_STATUS Status;

  Status = gBS->AllocatePool(EfiBootServicesData, PCIE_INFO_TBL_SZ, (VOID**)&PcieInfoTable);

  if (EFI_ERROR(Status))
  {
    Print(L"\nAllocate Pool failed %x ", Status);
    return Status;
  }
  val_pcie_create_info_table(PcieInfoTable);

  Status = gBS->AllocatePool(EfiBootServicesData, REGISTER_INFO_TBL_SZ, (VOID**)&RegisterInfoTable);

  if (EFI_ERROR(Status))
  {
    Print(L"\nAllocate Pool failed %x ", Status);
    return Status;
  }

  val_register_create_info_table(RegisterInfoTable);

  Status = gBS->AllocatePool(EfiBootServicesData, IOVIRT_INFO_TBL_SZ, (VOID**)&IoVirtInfoTable);

  if (EFI_ERROR(Status))
  {
    Print(L"\nAllocate Pool failed %x ", Status);
    return Status;
  }
  val_iovirt_create_info_table(IoVirtInfoTable);

  return Status;
}

EFI_STATUS
createPeripheralInfoTable()
{
  UINT64* PeripheralInfoTable;

  EFI_STATUS Status;

  Status = gBS->AllocatePool(EfiBootServicesData, PERIPHERAL_INFO_TBL_SZ,
                             (VOID**)&PeripheralInfoTable);

  if (EFI_ERROR(Status))
  {
    Print(L"\nAllocate Pool failed %x ", Status);
    return Status;
  }
  val_peripheral_create_info_table(PeripheralInfoTable);

  return Status;
}

VOID freeRmeAcsMem()
{

  val_pe_free_info_table();
  val_gic_free_info_table();
  val_timer_free_info_table();
  val_pcie_free_info_table();
  val_iovirt_free_info_table();
  val_peripheral_free_info_table();
  val_free_shared_mem();
}

VOID HelpMsg(VOID)
{
  Print(L"\nUsage: Rme.efi [-v <n>] | [-l <n>] | [-f <filename>] | [-skip <n>] | [-p <n>] | [-t "
        L"<n>] | [-m <n>]\n"
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
        "-cache  Pass this flag to indicate that if the test system supports PCIe address "
        "translation cache\n"
        "-cfg    Provide an INI path to run using [RME_COMMAND_CONFIG] and [PLATFORM_CONFIG]\n"
        "        from the file. When -cfg is present, legacy flags (-v/-t/-m/-skip/-f/etc.)\n"
        "        are ignored and the INI is authoritative.\n");
}

STATIC CONST SHELL_PARAM_ITEM ParamList[]
    = {{L"-v", TypeValue},    // -v    # Verbosity of the Prints. 1 shows all prints, 5 shows Errors
       {L"-f", TypeValue},    // -f    # Name of the log file to record the test results in.
       {L"-skip", TypeValue}, // -skip # test(s) to skip execution
       {L"-help", TypeFlag},  // -help # help : info about commands
       {L"-h", TypeFlag},     // -h    # help : info about commands
       {L"-mmio", TypeFlag},  // -mmio # Enable pal_mmio prints
       {L"-t", TypeValue},    // -t    # Test to be run
       {L"-m", TypeValue},    // -m    # Module to be run
       {L"-p2p", TypeFlag},   // -p2p  # Peer-to-Peer is supported
       {L"-cache", TypeFlag}, // -cache# PCIe address translation cache is supported
       {L"-cfg", TypeValue},  // -cfg  # Override INI path (e.g., \config\acs_run_rdv3_config.ini)
       {NULL, TypeMax}};

/***
  RME Compliance Suite Entry Point.

  Call the Entry points of individual modules.

  @retval  0         The application exited normally.
  @retval  Other     An error occurred.
***/
INTN EFIAPI ShellAppMainrme(IN UINTN Argc, IN CHAR16** Argv)
{

  /* When -cfg is used, we will read INI and set globals from it. */

  LIST_ENTRY* ParamPackage;
  CONST CHAR16* CmdLineArg;
  CHAR16* ProbParam;
  UINT32 Status;
  VOID* branch_label;

  //
  // Process Command Line arguments
  //
  Status = ShellInitialize();
  Status = ShellCommandLineParse(ParamList, &ParamPackage, &ProbParam, TRUE);
  if (Status)
  {
    Print(L"\nShell command line parse error %x", Status);
    Print(L"\nUnrecognized option %s passed", ProbParam);
    HelpMsg();
    return SHELL_INVALID_PARAMETER;
  }

  // Options with Values
  if (ShellCommandLineGetFlag(ParamPackage, L"-skip"))
  {
    CmdLineArg = ShellCommandLineGetValue(ParamPackage, L"-skip");

    if (CmdLineArg != NULL)
    {
      UINTN str_len = StrLen(CmdLineArg);
      EFI_STATUS Status;
      Status = gBS->AllocatePool(EfiBootServicesData, str_len * sizeof(CHAR8*),
                                 (VOID**)&g_skip_test_str);
      if (EFI_ERROR(Status))
      {
        Print(L"\nError: Unable to allocate memory for skip string array");
        return SHELL_OUT_OF_RESOURCES;
      }
      CHAR16* WorkingStr = AllocateCopyPool(StrSize(CmdLineArg), CmdLineArg);
      if (WorkingStr == NULL)
      {
        Print(L"\nError: Unable to allocate memory for skip string");
        return SHELL_OUT_OF_RESOURCES;
      }

      CHAR16* Token = WorkingStr;

      while (*Token != L'\0' && g_num_skip < str_len)
      {
        CHAR16* Next = StrStr(Token, L",");
        if (Next != NULL)
          *Next = L'\0';

        // Trim leading spaces
        while (*Token == L' ')
          Token++;

        // Trim trailing spaces
        CHAR16* End = Token + StrLen(Token) - 1;
        while (End > Token && *End == L' ')
        {
          *End = L'\0';
          End--;
        }
        UINTN Len                   = StrLen(Token);
        g_skip_test_str[g_num_skip] = AllocateZeroPool(Len + 1);
        if (g_skip_test_str[g_num_skip])
        {
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

  // Check early if -cfg is provided; if so, set override path for platform
  // runtime getters, load INI and apply, skipping
  // individual CLI options below.
  // Ensure a reasonable default before overrides
  g_print_level = G_PRINT_LEVEL;
  BOOLEAN used_cfg = FALSE;

  CmdLineArg = ShellCommandLineGetValue(ParamPackage, L"-cfg");
  if (CmdLineArg != NULL)
  {
    // Make platform runtime getters use the same INI file
    RmeCfgSetIniPath(CmdLineArg);
    RmeCfgInit();
    used_cfg = TRUE;
    // Reset previously parsed CLI/INI selections to ensure INI fully overrides
    if (g_execute_tests_str || g_num_tests)
      FreeAsciiArray(&g_execute_tests_str, &g_num_tests);
    if (g_execute_modules_str || g_num_modules)
      FreeAsciiArray(&g_execute_modules_str, &g_num_modules);
    if (g_skip_test_str || g_num_skip)
      FreeAsciiArray(&g_skip_test_str, &g_num_skip);
    if (g_rme_log_file_handle)
    {
      ShellCloseFile(&g_rme_log_file_handle);
      g_rme_log_file_handle = NULL;
    }
    g_print_level = G_PRINT_LEVEL; // reset to default before applying INI
    g_print_mmio  = FALSE;
    CHAR16* iniText = NULL;
    UINTN iniBytes  = 0;
    EFI_STATUS S    = ReadAsciiFileToWide(CmdLineArg, &iniText, &iniBytes);
    if (EFI_ERROR(S) || !iniText)
    {
      Print(L"\nError: failed to read INI file %s (%r)\n", CmdLineArg, S);
      return SHELL_NOT_FOUND;
    }
    ApplyIniRmeConfig(iniText);
    FreePool(iniText);

    // All required variables should now be updated by ApplyIniRmeConfig.
  }
  else
  {
    // Legacy path: parse shell options as before
    // Options with Values
    CmdLineArg = ShellCommandLineGetValue(ParamPackage, L"-v");
    if (CmdLineArg != NULL)
    {
      CHAR16* token;
      CHAR16* next = (CHAR16*)CmdLineArg;

      g_print_level = 1; // Default to verbose

      while ((token = StrStr(next, L",")) != NULL)
      {
        *token = L'\0'; // Null-terminate current token

        if (StrCmp(next, L"rme") == 0)
          g_enable_module |= (1 << 0);
        else if (StrCmp(next, L"gic") == 0)
          g_enable_module |= (1 << 1);
        else if (StrCmp(next, L"smmu") == 0)
          g_enable_module |= (1 << 2);
        else if (StrCmp(next, L"da") == 0)
          g_enable_module |= (1 << 3);
        else if (StrCmp(next, L"dpt") == 0)
          g_enable_module |= (1 << 4);
        else if (StrCmp(next, L"mec") == 0)
          g_enable_module |= (1 << 5);
        else if (StrCmp(next, L"ls") == 0)
          g_enable_module |= (1 << 6);

        next = token + 1; // Move past the comma
      }

      // Handle the last (or only) token
      if (*next != L'\0')
      {
        if (StrCmp(next, L"rme") == 0)
          g_enable_module |= (1 << 0);
        else if (StrCmp(next, L"gic") == 0)
          g_enable_module |= (1 << 1);
        else if (StrCmp(next, L"smmu") == 0)
          g_enable_module |= (1 << 2);
        else if (StrCmp(next, L"da") == 0)
          g_enable_module |= (1 << 3);
        else if (StrCmp(next, L"dpt") == 0)
          g_enable_module |= (1 << 4);
        else if (StrCmp(next, L"mec") == 0)
          g_enable_module |= (1 << 5);
        else if (StrCmp(next, L"ls") == 0)
          g_enable_module |= (1 << 6);
      }
    }
    else
    {
      g_print_level = G_PRINT_LEVEL;
    }

    // Options with Values
    CmdLineArg = ShellCommandLineGetValue(ParamPackage, L"-timeout");
    if (CmdLineArg == NULL)
    {
      g_wakeup_timeout = 1;
    }
    else
    {
      g_wakeup_timeout = StrDecimalToUintn(CmdLineArg);
      Print(L"\nWakeup timeout multiple %d.", g_wakeup_timeout);
      if (g_wakeup_timeout > 5)
        g_wakeup_timeout = 5;
    }

    // Options with Values
    CmdLineArg = ShellCommandLineGetValue(ParamPackage, L"-f");
    if (CmdLineArg == NULL)
    {
      g_rme_log_file_handle = NULL;
    }
    else
    {
      Status = ShellOpenFileByName(CmdLineArg, &g_rme_log_file_handle,
                                   EFI_FILE_MODE_WRITE | EFI_FILE_MODE_READ | EFI_FILE_MODE_CREATE,
                                   0x0);
      if (EFI_ERROR(Status))
      {
        Print(L"\nFailed to open log file %s", CmdLineArg);
        g_rme_log_file_handle = NULL;
      }
    }

    // Options with Flags
    if ((ShellCommandLineGetFlag(ParamPackage, L"-help"))
        || (ShellCommandLineGetFlag(ParamPackage, L"-h")))
    {
      HelpMsg();
      return 0;
    }
  }
  if (!used_cfg)
  {
    if (ShellCommandLineGetFlag(ParamPackage, L"-mmio"))
      g_print_mmio = TRUE;
    else
      g_print_mmio = FALSE;

    if (ShellCommandLineGetFlag(ParamPackage, L"-p2p"))
      g_pcie_p2p = TRUE;
    else
      g_pcie_p2p = FALSE;

    if (ShellCommandLineGetFlag(ParamPackage, L"-cache"))
      g_pcie_cache_present = TRUE;
    else
      g_pcie_cache_present = FALSE;
  }

  // Options with Values
  CmdLineArg = ShellCommandLineGetValue(ParamPackage, L"-t");
  if (CmdLineArg != NULL && !used_cfg)
  {
    UINTN str_len = StrLen(CmdLineArg);
    EFI_STATUS Status;
    Status = gBS->AllocatePool(EfiBootServicesData, str_len * sizeof(CHAR8*),
                               (VOID**)&g_execute_tests_str);
    if (EFI_ERROR(Status))
    {
      Print(L"\nError: Unable to allocate memory for execute test string array");
      return SHELL_OUT_OF_RESOURCES;
    }

    CHAR16* WorkingStr = AllocateCopyPool(StrSize(CmdLineArg), CmdLineArg);
    if (WorkingStr == NULL)
    {
      Print(L"\nError: Unable to allocate memory for test string");
      return SHELL_OUT_OF_RESOURCES;
    }

    CHAR16* Token = WorkingStr;
    UINTN j       = 0;

    while (*Token != L'\0' && j < str_len)
    {
      CHAR16* Next = StrStr(Token, L",");
      if (Next != NULL)
        *Next = L'\0';

      // Trim leading spaces
      while (*Token == L' ')
        Token++;

      // Trim trailing spaces
      CHAR16* End = Token + StrLen(Token) - 1;
      while (End > Token && *End == L' ')
      {
        *End = L'\0';
        End--;
      }

      UINTN Len                        = StrLen(Token);
      g_execute_tests_str[g_num_tests] = AllocateZeroPool(Len + 1);
      if (g_execute_tests_str[g_num_tests])
      {
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
  if (CmdLineArg != NULL && !used_cfg)
  {
    UINTN str_len = StrLen(CmdLineArg);
    EFI_STATUS Status;
    Status = gBS->AllocatePool(EfiBootServicesData, str_len * sizeof(CHAR8*),
                               (VOID**)&g_execute_modules_str);
    if (EFI_ERROR(Status))
    {
      Print(L"\nError: Unable to allocate memory for execute module string array");
      return SHELL_OUT_OF_RESOURCES;
    }

    CHAR16* WorkingStr = AllocateCopyPool(StrSize(CmdLineArg), CmdLineArg);
    if (WorkingStr == NULL)
    {
      Print(L"\nError: Unable to allocate memory for module string");
      return SHELL_OUT_OF_RESOURCES;
    }

    CHAR16* Token = WorkingStr;
    UINTN j       = 0;

    while (*Token != L'\0' && j < str_len)
    {
      CHAR16* Next = StrStr(Token, L",");
      if (Next != NULL)
        *Next = L'\0';

      // Trim leading spaces
      while (*Token == L' ')
        Token++;

      // Trim trailing spaces
      CHAR16* End = Token + StrLen(Token) - 1;
      while (End > Token && *End == L' ')
      {
        *End = L'\0';
        End--;
      }

      UINTN Len                            = StrLen(Token);
      g_execute_modules_str[g_num_modules] = AllocateZeroPool(Len + 1);
      if (g_execute_modules_str[g_num_modules])
      {
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
  g_print_test_check_id   = 0;
  g_rme_tests_total       = 0;
  g_rme_tests_pass        = 0;
  g_rme_tests_fail        = 0;

  Print(L"\n\n RME Architecture Compliance Suite \n");
  Print(L"    Version: Issue B.a ACS EAC   \n");

  Print(L"\n Starting tests for (Print level is %2d)\n\n", g_print_level);
  // Show effective selection from INI/CLI to aid debugging
  {
    Print(L"Modules(%u): ", g_num_modules);
    if (g_num_modules == 0) Print(L"<all>");
    for (UINT32 i = 0; i < g_num_modules; i++)
    {
      if (i) Print(L",");
      Print(L"%a", g_execute_modules_str[i] ? g_execute_modules_str[i] : (CHAR8*)"?");
    }
    Print(L"\nTests(%u): ", g_num_tests);
    if (g_num_tests == 0) Print(L"<all>");
    for (UINT32 i = 0; i < g_num_tests; i++)
    {
      if (i) Print(L",");
      Print(L"%a", g_execute_tests_str[i] ? g_execute_tests_str[i] : (CHAR8*)"?");
    }
    Print(L"\nSkips(%u): ", g_num_skip);
    for (UINT32 i = 0; i < g_num_skip; i++)
    {
      if (i) Print(L",");
      Print(L"%a", g_skip_test_str[i] ? g_skip_test_str[i] : (CHAR8*)"?");
    }
    Print(L"\n");
  }
  // Ensure runtime-dependent VAL globals and EL3-shared cfg are initialized first
  val_init_runtime_params();
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

  // Initialise exception vector, so any unexpected exception gets handled by default RME exception
  // handler
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

  if (g_rme_log_file_handle)
  {
    ShellCloseFile(&g_rme_log_file_handle);
  }

  Print(L"\n********* RME tests complete. Reset the system *********\n\n");

  val_pe_context_restore(AA64WriteSp(g_stack_pointer));

  return (0);
}

/***
  RME Compliance Suite Entry Point. This function is to
  support compilation of RME changes in edk2

  Call the Entry points of individual modules.

  @retval  0         The application exited normally.
  @retval  Other     An error occurred.
***/
INTN EFIAPI ShellAppMain(IN UINTN Argc, IN CHAR16** Argv)
{
  return ShellAppMainrme(Argc, Argv);
}
