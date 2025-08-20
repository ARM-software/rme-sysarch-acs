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

#include <Guid/FileInfo.h>
#include <Library/BaseLib.h>       // CompareGuid, Str* helpers
#include <Library/BaseMemoryLib.h> // CopyMem, CompareMem
#include <Library/MemoryAllocationLib.h>
#include <Library/PrintLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiLib.h>
#include <Library/ShellLib.h>
#include <Protocol/SimpleFileSystem.h>
#include <Uefi.h>
#include <include/pal_uefi.h>
#include <stdint.h>

// Forward declarations for config accessors used before their definitions
UINT64 RmeCfgGetU64(CONST CHAR16* Key, UINT64 DefaultVal);
CONST CHAR16* RmeCfgGetStr(CONST CHAR16* Key, CONST CHAR16* DefaultVal);

/**
  Platform config access for RME ACS (UEFI).
  - First try runtime configuration table (installed by Parser.efi)
  - If absent, fall back to reading \acs_run_base-revc_config.ini (or platform variant)
**/
#ifndef MIN
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#endif

/* ---- shared GUID/format (keep in sync with Parser) ---- */
STATIC EFI_GUID gArmRmeAcsConfigGuid
    = (EFI_GUID){0xb171e1f3, 0x1a7a, 0x4a84, {0x9f, 0x6b, 0x12, 0x36, 0x58, 0x6a, 0xca, 0x21}};

typedef struct
{
  UINT32 NumEntries;
  UINT8 Data[1];
} ARM_RME_ACS_CONFIG;
typedef enum
{
  RME_CFG_U64 = 1,
  RME_CFG_STR = 2
} RME_CFG_TYPE;

// Default INI path; can be overridden at runtime via RmeCfgSetIniPath()
#define CONFIG_REL_PATH_DEFAULT L"\\acs_run_base-revc_config.ini"

/* ---- local cache ---- */
STATIC ARM_RME_ACS_CONFIG* mCfg = NULL;
STATIC BOOLEAN mInit            = FALSE;
STATIC CHAR16* gIniOverridePath = NULL; // heap copy if set via RmeCfgSetIniPath()

VOID RmeCfgSetIniPath(CONST CHAR16* NewPath)
{
  if (!NewPath || !*NewPath)
    return;
  UINTN sz     = (StrLen(NewPath) + 1) * sizeof(CHAR16);
  CHAR16* copy = AllocateZeroPool(sz);
  if (!copy)
    return;
  CopyMem(copy, NewPath, sz);
  if (gIniOverridePath)
    FreePool(gIniOverridePath);
  gIniOverridePath = copy;
}

STATIC
VOID RmeCfgDebugDump(ARM_RME_ACS_CONFIG* Cfg, UINTN MaxToShow)
{
  if (!Cfg)
  {
    Print(L"[RME CFG] Cfg=NULL\n");
    return;
  }
  Print(L"[RME CFG] Blob @%p, NumEntries=%u\n", Cfg, Cfg->NumEntries);
  UINT8* p = Cfg->Data;
  for (UINTN i = 0; i < Cfg->NumEntries && i < MaxToShow; i++)
  {
    UINT16 klen = 0, type = 0;
    UINT32 vlen = 0;
    CopyMem(&klen, p, 2);
    p += 2;
    CHAR16* kstr = (CHAR16*)p;
    p += klen * sizeof(CHAR16);
    CopyMem(&type, p, 2);
    p += 2;
    p += 2; // rsv
    CopyMem(&vlen, p, 4);
    p += 4;
    Print(L"  [%u] key=\"%.*s\" type=%u vlen=%u\n", (UINT32)i, (INT32)klen, kstr, (UINT32)type,
          (UINT32)vlen);
    p += vlen;
  }
}

STATIC
BOOLEAN RmeCfgValidate(ARM_RME_ACS_CONFIG* Cfg)
{
  if (!Cfg)
    return FALSE;

  // Put a generous cap so we never run wild if NumEntries is corrupt
  const UINTN HARD_CAP_BYTES = 256 * 1024; // 256KB scan cap
  UINT8* base                = (UINT8*)Cfg;
  UINT8* p                   = Cfg->Data;

  for (UINT32 i = 0; i < Cfg->NumEntries; i++)
  {
    // Bounds check before every read
    if ((p + 2) > base + HARD_CAP_BYTES)
      return FALSE;
    UINT16 klen = 0;
    CopyMem(&klen, p, 2);
    p += 2;

    // key must be "small" and 16-bit chars
    if (klen == 0 || klen > 512)
      return FALSE;
    if ((p + klen * sizeof(CHAR16)) > base + HARD_CAP_BYTES)
      return FALSE;
    p += klen * sizeof(CHAR16);

    if ((p + 2 + 2 + 4) > base + HARD_CAP_BYTES)
      return FALSE;
    UINT16 type = 0;
    CopyMem(&type, p, 2);
    p += 2;
    p += 2; // rsv
    UINT32 vlen = 0;
    CopyMem(&vlen, p, 4);
    p += 4;

    // type/value sanity
    if (type != 1 && type != 2)
      return FALSE;
    if (type == 1 && vlen != sizeof(UINT64))
      return FALSE; // U64
    if (type == 2 && (vlen < sizeof(CHAR16) || (vlen % sizeof(CHAR16)) != 0))
      return FALSE; // UTF-16 string

    if ((p + vlen) > base + HARD_CAP_BYTES)
      return FALSE;
    p += vlen;
  }
  return TRUE;
}

/* ---------- tiny file helpers ---------- */
STATIC
EFI_STATUS ReadAll(EFI_FILE_PROTOCOL* File, VOID** Data, UINTN* SizeBytes)
{
  EFI_STATUS Status;
  EFI_FILE_INFO* Info;
  UINTN InfoSize = 0;
  Status         = File->GetInfo(File, &gEfiFileInfoGuid, &InfoSize, NULL);
  if (Status != EFI_BUFFER_TOO_SMALL)
    return Status;
  Info = AllocateZeroPool(InfoSize);
  if (!Info)
    return EFI_OUT_OF_RESOURCES;
  Status = File->GetInfo(File, &gEfiFileInfoGuid, &InfoSize, Info);
  if (EFI_ERROR(Status))
  {
    FreePool(Info);
    return Status;
  }
  UINTN Size = (UINTN)Info->FileSize;
  FreePool(Info);

  VOID* Buf = AllocateZeroPool(Size + 2);
  if (!Buf)
    return EFI_OUT_OF_RESOURCES;
  Status = File->Read(File, &Size, Buf);
  if (EFI_ERROR(Status))
  {
    FreePool(Buf);
    return Status;
  }
  *Data      = Buf;
  *SizeBytes = Size;
  return EFI_SUCCESS;
}

STATIC
EFI_STATUS OpenFsWithIni(CONST CHAR16* RelPath, EFI_FILE_PROTOCOL** OutRoot)
{
  EFI_STATUS s;
  EFI_HANDLE* H = NULL;
  UINTN N       = 0;
  s = gBS->LocateHandleBuffer(ByProtocol, &gEfiSimpleFileSystemProtocolGuid, NULL, &N, &H);
  if (EFI_ERROR(s))
    return s;
  for (UINTN i = 0; i < N; i++)
  {
    EFI_SIMPLE_FILE_SYSTEM_PROTOCOL* Fs = NULL;
    if (EFI_ERROR(gBS->HandleProtocol(H[i], &gEfiSimpleFileSystemProtocolGuid, (VOID**)&Fs)) || !Fs)
      continue;
    EFI_FILE_PROTOCOL* R = NULL;
    if (EFI_ERROR(Fs->OpenVolume(Fs, &R)) || !R)
      continue;
    EFI_FILE_PROTOCOL* F = NULL;
    if (!EFI_ERROR(R->Open(R, &F, (CHAR16*)RelPath, EFI_FILE_MODE_READ, 0)))
    {
      F->Close(F);
      *OutRoot = R;
      FreePool(H);
      return EFI_SUCCESS;
    }
    R->Close(R);
  }
  FreePool(H);
  return EFI_NOT_FOUND;
}

/* ---------- INI -> runtime blob (same wire format as Parser) ---------- */
STATIC
VOID TrimInPlace(CHAR16* s)
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

STATIC
ARM_RME_ACS_CONFIG* BuildCfgFromIni(CHAR16* IniText)
{
  typedef struct
  {
    CONST CHAR16* Key;
    UINT16 Type;
    UINT64 U64;
    CONST CHAR16* Str;
  } KV;
  KV items[256];
  UINTN n = 0;

  for (CHAR16* p = IniText; *p;)
  {
    CHAR16* line = p;
    while (*p && *p != L'\n' && *p != L'\r')
      p++;
    CHAR16 save = *p;
    *p          = 0;
    TrimInPlace(line);
    if (line[0] && line[0] != L'#' && line[0] != L';' && line[0] != L'[')
    {
      CHAR16* eq = StrStr(line, L"=");
      if (eq && n < ARRAY_SIZE(items))
      {
        *eq         = 0;
        CHAR16* key = line;
        CHAR16* val = eq + 1;
        TrimInPlace(key);
        TrimInPlace(val);
        if (val[0])
        {
          BOOLEAN isNum = ((val[0] >= L'0' && val[0] <= L'9')
                           || (val[0] == L'0' && (val[1] == L'x' || val[1] == L'X')));
          if (isNum)
          {
            UINT64 u   = (val[0] == L'0' && (val[1] == L'x' || val[1] == L'X'))
                             ? StrHexToUint64(val)
                             : StrDecimalToUint64(val);
            items[n++] = (KV){key, RME_CFG_U64, u, NULL};
          }
          else
          {
            items[n++] = (KV){key, RME_CFG_STR, 0, val};
          }
        }
      }
    }
    *p = save;
    if (*p == L'\r' && *(p + 1) == L'\n')
      p += 2;
    else if (*p)
      p++;
  }
  if (n == 0)
    return NULL;

  UINTN size = sizeof(ARM_RME_ACS_CONFIG);
  for (UINTN i = 0; i < n; i++)
  {
    UINTN klen = StrLen(items[i].Key);
    UINTN vlen = (items[i].Type == RME_CFG_U64) ? sizeof(UINT64)
                                                : (StrLen(items[i].Str) + 1) * sizeof(CHAR16);
    size += 2 + klen * sizeof(CHAR16) + 2 + 2 + 4 + vlen;
  }
  ARM_RME_ACS_CONFIG* cfg = AllocateZeroPool(size);
  if (!cfg)
    return NULL;
  cfg->NumEntries = (UINT32)n;
  UINT8* p        = (UINT8*)cfg->Data;
  for (UINTN i = 0; i < n; i++)
  {
    UINT16 klen = (UINT16)StrLen(items[i].Key);
    CopyMem(p, &klen, 2);
    p += 2;
    CopyMem(p, items[i].Key, klen * sizeof(CHAR16));
    p += klen * sizeof(CHAR16);
    CopyMem(p, &items[i].Type, 2);
    p += 2;
    UINT16 rsv = 0;
    CopyMem(p, &rsv, 2);
    p += 2;
    if (items[i].Type == RME_CFG_U64)
    {
      UINT32 vlen = sizeof(UINT64);
      CopyMem(p, &vlen, 4);
      p += 4;
      CopyMem(p, &items[i].U64, sizeof(UINT64));
      p += sizeof(UINT64);
    }
    else
    {
      UINT32 vlen = (UINT32)((StrLen(items[i].Str) + 1) * sizeof(CHAR16));
      CopyMem(p, &vlen, 4);
      p += 4;
      CopyMem(p, items[i].Str, vlen);
      p += vlen;
    }
  }
  return cfg;
}

/* ---------- key lookup over runtime blob ---------- */
STATIC
BOOLEAN RmeCfgFind(ARM_RME_ACS_CONFIG* Cfg, CONST CHAR16* Key, UINT16* OutType, VOID** OutVal,
                   UINT32* OutBytes)
{
  if (!Cfg || !Key)
    return FALSE;
  UINT8* p = Cfg->Data;
  for (UINT32 i = 0; i < Cfg->NumEntries; i++)
  {
    UINT16 klen = 0;
    CopyMem(&klen, p, 2);
    p += 2;
    CHAR16* kstr = (CHAR16*)p;
    p += klen * sizeof(CHAR16);
    UINT16 type = 0;
    CopyMem(&type, p, 2);
    p += 2;
    p += 2; // reserved
    UINT32 vlen = 0;
    CopyMem(&vlen, p, 4);
    p += 4;
    VOID* val = p;
    p += vlen;

    if ((StrLen(Key) == klen) && (CompareMem(kstr, Key, klen * sizeof(CHAR16)) == 0))
    {
      if (OutType)
        *OutType = type;
      if (OutVal)
        *OutVal = val;
      if (OutBytes)
        *OutBytes = vlen;
      return TRUE;
    }
  }
  return FALSE;
}

/* ---------- public getters (plus init with fallback) ---------- */
VOID RmeCfgInit(VOID)
{
  if (mInit)
    return;
  mInit = TRUE;

  // If an explicit override path was provided (via -cfg), prefer INI first.
  if (gIniOverridePath)
  {
    Print(L"[RME CFG] Trying INI override first: %s\n", gIniOverridePath);
    // If the override path looks like a Shell mapping (e.g., fs2:...), use ShellLib
    if (StrStr(gIniOverridePath, L":") != NULL) {
      SHELL_FILE_HANDLE ShFile;
      EFI_STATUS S = ShellOpenFileByName(gIniOverridePath, &ShFile, EFI_FILE_MODE_READ, 0);
      if (!EFI_ERROR(S)) {
        UINT64 fsz = 0;
        S = ShellGetFileSize(ShFile, &fsz);
        if (!EFI_ERROR(S) && fsz > 0) {
          UINTN read = (UINTN)fsz;
          CHAR8* buf = AllocateZeroPool(read + 2);
          if (buf) {
            S = ShellReadFile(ShFile, &read, buf);
            if (!EFI_ERROR(S)) {
              CHAR16* Wide = AllocateZeroPool((read + 1) * sizeof(CHAR16));
              if (Wide) {
                for (UINTN i = 0; i < read; i++)
                  Wide[i] = buf[i];
                ARM_RME_ACS_CONFIG* built = BuildCfgFromIni(Wide);
                if (built && RmeCfgValidate(built)) {
                  mCfg = built;
                  Print(L"[RME CFG] Using INI override.\n");
                  RmeCfgDebugDump(mCfg, 16);
                  FreePool(Wide);
                  FreePool(buf);
                  ShellCloseFile(&ShFile);
                  return;
                }
                FreePool(Wide);
              }
              FreePool(buf);
            }
          }
        }
        ShellCloseFile(&ShFile);
      }
    } else {
      // Fallback: try existing SimpleFileSystem enumeration for plain relative paths
      EFI_FILE_PROTOCOL* Root = NULL;
      CONST CHAR16* RelPath   = gIniOverridePath;
      EFI_STATUS fsSt         = OpenFsWithIni(RelPath, &Root);
      if (!EFI_ERROR(fsSt) && Root) {
        EFI_FILE_PROTOCOL* F = NULL;
        VOID* Data           = NULL;
        UINTN Size           = 0;
        if (!EFI_ERROR(Root->Open(Root, &F, (CHAR16*)RelPath, EFI_FILE_MODE_READ, 0)) && F) {
          if (!EFI_ERROR(ReadAll(F, &Data, &Size)) && Data) {
            CHAR16* Wide = AllocateZeroPool((Size + 1) * sizeof(CHAR16));
            if (Wide) {
              for (UINTN i = 0; i < Size; i++)
                Wide[i] = ((CHAR8*)Data)[i];
              ARM_RME_ACS_CONFIG* built = BuildCfgFromIni(Wide);
              if (built && RmeCfgValidate(built)) {
                mCfg = built;
                Print(L"[RME CFG] Using INI override.\n");
                RmeCfgDebugDump(mCfg, 16);
                FreePool(Wide);
                FreePool(Data);
                F->Close(F);
                Root->Close(Root);
                return;
              }
              FreePool(Wide);
            }
            FreePool(Data);
          }
          F->Close(F);
        }
        Root->Close(Root);
      }
    }
    Print(L"[RME CFG] INI override failed; will try runtime CT then fallback.\n");
  }

  // 1) Try runtime configuration table
  if (gST)
  {
    for (UINTN i = 0; i < gST->NumberOfTableEntries; i++)
    {
      if (CompareGuid(&gST->ConfigurationTable[i].VendorGuid, &gArmRmeAcsConfigGuid))
      {
        ARM_RME_ACS_CONFIG* cand = (ARM_RME_ACS_CONFIG*)gST->ConfigurationTable[i].VendorTable;
        if (cand)
        {
          // Validate before accepting
          if (RmeCfgValidate(cand))
          {
            mCfg = cand;
            Print(L"[RME CFG] Using runtime configuration table.\n");
            RmeCfgDebugDump(mCfg, 16); // show more entries to aid debugging
            return;
          }
          else
          {
            Print(L"[RME CFG] Found CT but it failed validation; ignoring.\n");
          }
        }
      }
    }
  }

  // 2) Fall back to INI file
  Print(L"[RME CFG] No runtime table; falling back to INI.\n");
  EFI_FILE_PROTOCOL* Root = NULL;
  CONST CHAR16* RelPath   = gIniOverridePath ? gIniOverridePath : CONFIG_REL_PATH_DEFAULT;
  EFI_STATUS fsSt         = OpenFsWithIni(RelPath, &Root);
  if (EFI_ERROR(fsSt))
  {
    // Try platform-specific names at root
    if (EFI_ERROR(fsSt) && !gIniOverridePath)
    {
      CONST CHAR16* cands[] = {L"\\acs_run_rdv3_config.ini", L"\\acs_run_base-revc_config.ini"};
      for (UINTN i = 0; i < sizeof(cands) / sizeof(cands[0]); i++)
      {
        fsSt = OpenFsWithIni(cands[i], &Root);
        if (!EFI_ERROR(fsSt))
        {
          RelPath = cands[i];
          break;
        }
      }
    }
  }
  if (!EFI_ERROR(fsSt) && Root)
  {
    EFI_FILE_PROTOCOL* F = NULL;
    VOID* Data           = NULL;
    UINTN Size           = 0;
    if (!EFI_ERROR(Root->Open(Root, &F, (CHAR16*)RelPath, EFI_FILE_MODE_READ, 0)) && F)
    {
      if (!EFI_ERROR(ReadAll(F, &Data, &Size)) && Data)
      {
        CHAR16* Wide = AllocateZeroPool((Size + 1) * sizeof(CHAR16));
        if (Wide)
        {
          for (UINTN i = 0; i < Size; i++)
            Wide[i] = ((CHAR8*)Data)[i];
          ARM_RME_ACS_CONFIG* built = BuildCfgFromIni(Wide);
          if (built && RmeCfgValidate(built))
          {
            mCfg = built;
            Print(L"[RME CFG] Using INI fallback.\n");
            RmeCfgDebugDump(mCfg, 16);
          }
          else
          {
            Print(L"[RME CFG] INI fallback invalid; using built-in defaults only.\n");
          }
          FreePool(Wide);
        }
        FreePool(Data);
      }
      F->Close(F);
    }
    Root->Close(Root);
  }
}

/* Public getter: SMMU root register page offset */
UINT64 pal_get_smmu_root_reg_offset(void)
{
  // Prefer runtime/INI value; fall back to compiled default for UEFI CT
  UINT64 off = RmeCfgGetU64(L"SMMUV3_ROOT_REG_OFFSET", SMMUV3_ROOT_REG_OFFSET_CT);
  return off;
}

UINT64
RmeCfgGetU64(CONST CHAR16* Key, UINT64 DefaultVal)
{
  RmeCfgInit();
  if (!mCfg)
    return DefaultVal;

  UINT16 type;
  VOID* val;
  UINT32 len;
  if (!RmeCfgFind(mCfg, Key, &type, &val, &len))
    return DefaultVal;
  if (type != RME_CFG_U64 || len < sizeof(UINT64))
    return DefaultVal;

  UINT64 out = 0;
  CopyMem(&out, val, sizeof(UINT64));
  return out;
}

CONST CHAR16* RmeCfgGetStr(CONST CHAR16* Key, CONST CHAR16* DefaultVal)
{
  RmeCfgInit();
  if (!mCfg)
    return DefaultVal;

  UINT16 type;
  VOID* val;
  UINT32 len;
  if (!RmeCfgFind(mCfg, Key, &type, &val, &len))
    return DefaultVal;
  if (type != RME_CFG_STR || len < sizeof(CHAR16))
    return DefaultVal;

  return (CONST CHAR16*)val; // guaranteed NUL-terminated by builders
}

/* ---------- existing table construction code (unchanged) ---------- */

REGISTER_INFO_TABLE pal_rp_regs[PLATFORM_OVERRIDE_RP_REG_NUM_ENTRIES]
    = {REGISTER_INFO_TABLE_ENTRIES(EXPAND_REGISTER_INFO)};

VOID pal_register_create_info_table(REGISTER_INFO_TABLE* registerInfoTable)
{
  if (!registerInfoTable)
  {
    rme_print(ACS_PRINT_ERR, L"\nInput Register Table Pointer is NULL", 0);
    return;
  }
  for (UINT32 index = 0; index < PLATFORM_OVERRIDE_RP_REG_NUM_ENTRIES; index++)
    registerInfoTable[index] = pal_rp_regs[index];
}

UINT32 pal_register_get_num_entries(void)
{
  return PLATFORM_OVERRIDE_RP_REG_NUM_ENTRIES;
}

RT_REG_INFO_ENTRY rt_regs[RT_REG_CAP] = {RT_REGISTER_ENTRIES(EXPAND_RT_REG)};

VOID pal_root_register_create_info_table(ROOT_REGSTR_TABLE* rootRegTable)
{
  if (!rootRegTable)
    return;
  UINT32 rt_cnt         = (UINT32)RmeCfgGetU64(L"RT_REG_CNT", RT_REG_CNT_CT);
  rt_cnt                = MIN(rt_cnt, (UINT32)RT_REG_CAP);
  rootRegTable->num_reg = rt_cnt;

  // Override defaults with runtime config for each RT register
  for (UINT32 i = 0; i < rt_cnt; i++)
  {
    UINT64 def_base = 0, def_size = 0;
    switch (i)
    {
      case 0:
        def_base = RT_REG_0_START_ADDR_CT;
        def_size = RT_REG_0_SIZE_CT;
        break;
      case 1:
        def_base = RT_REG_1_START_ADDR_CT;
        def_size = RT_REG_1_SIZE_CT;
        break;
      case 2:
        def_base = RT_REG_2_START_ADDR_CT;
        def_size = RT_REG_2_SIZE_CT;
        break;
      case 3:
        def_base = RT_REG_3_START_ADDR_CT;
        def_size = RT_REG_3_SIZE_CT;
        break;
      default:
        def_base = 0;
        def_size = 0;
        break;
    }

    CHAR16 key[64];
    UnicodeSPrint(key, sizeof(key), L"RT_REG_%u_START_ADDR", i);
    UINT64 base = RmeCfgGetU64(key, def_base);
    UnicodeSPrint(key, sizeof(key), L"RT_REG_%u_SIZE", i);
    UINT64 size = RmeCfgGetU64(key, def_size);

    rt_regs[i].rt_reg_base_addr  = base;
    rt_regs[i].rt_reg_size       = size;
    rootRegTable->rt_reg_info[i] = rt_regs[i];
  }
}

MEM_REGN_INFO_ENTRY pal_gpc_regs[GPC_PROTECTED_REGION_CAP]
    = {GPC_PROTECTED_REGION_ENTRIES(EXPAND_PROTECTED_MEM_REGION)};

MEM_REGN_INFO_ENTRY pal_pas_regs[PAS_PROTECTED_REGION_CAP]
    = {PAS_PROTECTED_REGION_ENTRIES(EXPAND_PROTECTED_MEM_REGION)};

VOID pal_mem_region_create_info_table(MEM_REGN_INFO_TABLE* gpc_table,
                                      MEM_REGN_INFO_TABLE* pas_table)
{
  if (!gpc_table || !pas_table)
    return;

  UINT32 gpc_cnt = (UINT32)RmeCfgGetU64(L"GPC_PROTECTED_REGION_CNT", GPC_PROTECTED_REGION_CNT_CT);
  UINT32 pas_cnt = (UINT32)RmeCfgGetU64(L"PAS_PROTECTED_REGION_CNT", PAS_PROTECTED_REGION_CNT_CT);
  gpc_cnt        = MIN(gpc_cnt, (UINT32)GPC_PROTECTED_REGION_CAP);
  pas_cnt        = MIN(pas_cnt, (UINT32)PAS_PROTECTED_REGION_CAP);

  // Override defaults with runtime configuration values for each region
  gpc_table->header.num_of_regn_gpc = gpc_cnt;
  for (UINT32 i = 0; i < gpc_cnt; i++)
  {
    UINT64 def_base = 0, def_size = 0, def_pas = 0;
    switch (i)
    {
      case 0:
        def_base = GPC_PROTECTED_REGION_0_START_ADDR_CT;
        def_size = GPC_PROTECTED_REGION_0_SIZE_CT;
        def_pas  = GPC_PROTECTED_REGION_0_PAS_CT;
        break;
      case 1:
        def_base = GPC_PROTECTED_REGION_1_START_ADDR_CT;
        def_size = GPC_PROTECTED_REGION_1_SIZE_CT;
        def_pas  = GPC_PROTECTED_REGION_1_PAS_CT;
        break;
      case 2:
        def_base = GPC_PROTECTED_REGION_2_START_ADDR_CT;
        def_size = GPC_PROTECTED_REGION_2_SIZE_CT;
        def_pas  = GPC_PROTECTED_REGION_2_PAS_CT;
        break;
      case 3:
        def_base = GPC_PROTECTED_REGION_3_START_ADDR_CT;
        def_size = GPC_PROTECTED_REGION_3_SIZE_CT;
        def_pas  = GPC_PROTECTED_REGION_3_PAS_CT;
        break;
      default:
        def_base = 0;
        def_size = 0;
        def_pas  = 0;
        break;
    }
    CHAR16 key[64];
    UnicodeSPrint(key, sizeof(key), L"GPC_PROTECTED_REGION_%u_START_ADDR", i);
    UINT64 base = RmeCfgGetU64(key, def_base);
    UnicodeSPrint(key, sizeof(key), L"GPC_PROTECTED_REGION_%u_SIZE", i);
    UINT64 size = RmeCfgGetU64(key, def_size);
    UnicodeSPrint(key, sizeof(key), L"GPC_PROTECTED_REGION_%u_PAS", i);
    UINT64 pas                   = RmeCfgGetU64(key, def_pas);
    pal_gpc_regs[i].base_addr    = (UINT32)base;
    pal_gpc_regs[i].regn_size    = (UINT32)size;
    pal_gpc_regs[i].resourse_pas = pas;
    gpc_table->regn_info[i]      = pal_gpc_regs[i];
  }

  pas_table->header.num_of_regn_pas_filter = pas_cnt;
  for (UINT32 i = 0; i < pas_cnt; i++)
  {
    UINT64 def_base = 0, def_size = 0, def_pas = 0;
    switch (i)
    {
      case 0:
        def_base = PAS_PROTECTED_REGION_0_START_ADDR_CT;
        def_size = PAS_PROTECTED_REGION_0_SIZE_CT;
        def_pas  = PAS_PROTECTED_REGION_0_PAS_CT;
        break;
      case 1:
        def_base = PAS_PROTECTED_REGION_1_START_ADDR_CT;
        def_size = PAS_PROTECTED_REGION_1_SIZE_CT;
        def_pas  = PAS_PROTECTED_REGION_1_PAS_CT;
        break;
      case 2:
        def_base = PAS_PROTECTED_REGION_2_START_ADDR_CT;
        def_size = PAS_PROTECTED_REGION_2_SIZE_CT;
        def_pas  = PAS_PROTECTED_REGION_2_PAS_CT;
        break;
      case 3:
        def_base = PAS_PROTECTED_REGION_3_START_ADDR_CT;
        def_size = PAS_PROTECTED_REGION_3_SIZE_CT;
        def_pas  = PAS_PROTECTED_REGION_3_PAS_CT;
        break;
      default:
        def_base = 0;
        def_size = 0;
        def_pas  = 0;
        break;
    }
    CHAR16 key[64];
    UnicodeSPrint(key, sizeof(key), L"PAS_PROTECTED_REGION_%u_START_ADDR", i);
    UINT64 base = RmeCfgGetU64(key, def_base);
    UnicodeSPrint(key, sizeof(key), L"PAS_PROTECTED_REGION_%u_SIZE", i);
    UINT64 size = RmeCfgGetU64(key, def_size);
    UnicodeSPrint(key, sizeof(key), L"PAS_PROTECTED_REGION_%u_PAS", i);
    UINT64 pas                   = RmeCfgGetU64(key, def_pas);
    pal_pas_regs[i].base_addr    = (UINT32)base;
    pal_pas_regs[i].regn_size    = (UINT32)size;
    pal_pas_regs[i].resourse_pas = pas;
    pas_table->regn_info[i]      = pal_pas_regs[i];
  }
}

UINT32 pal_is_legacy_tz_enabled(void)
{
  return (UINT32)RmeCfgGetU64(L"IS_LEGACY_TZ_ENABLED", IS_LEGACY_TZ_ENABLED_CT);
}
UINT32 pal_is_ns_encryption_programmable(void)
{
  return (UINT32)RmeCfgGetU64(L"IS_NS_ENCRYPTION_PROGRAMMABLE", IS_NS_ENCRYPTION_PROGRAMMABLE_CT);
}
UINT32 pal_is_pas_filter_mode_programmable(void)
{
  return (UINT32)RmeCfgGetU64(L"IS_PAS_FILTER_MODE_PROGRAMMABLE",
                              IS_PAS_FILTER_MODE_PROGRAMMABLE_CT);
}

/* --------- Simple getters for single-value PLATFORM_CONFIG keys --------- */
uint64_t pal_get_root_smem_base(void)
{
  return RmeCfgGetU64(L"PLAT_ROOT_SMEM_BASE", PLAT_ROOT_SMEM_BASE_CT);
}
uint64_t pal_get_realm_smem_base(void)
{
  return RmeCfgGetU64(L"PLAT_REALM_SMEM_BASE", PLAT_REALM_SMEM_BASE_CT);
}
uint64_t pal_get_mte_protected_region_base(void)
{
  return RmeCfgGetU64(L"PLAT_MTE_PROTECTED_REGION_BASE", PLAT_MTE_PROTECTED_REGION_BASE_CT);
}
uint64_t pal_get_mte_protected_region_size(void)
{
  return RmeCfgGetU64(L"PLAT_MTE_PROTECTED_REGION_SIZE", PLAT_MTE_PROTECTED_REGION_SIZE_CT);
}
uint64_t pal_get_msd_save_restore_mem(void)
{
  return RmeCfgGetU64(L"PLAT_MSD_SAVE_RESTORE_MEM", PLAT_MSD_SAVE_RESTORE_MEM_CT);
}
uint64_t pal_get_rme_rnvs_mailbox_mem(void)
{
  return RmeCfgGetU64(L"PLAT_RME_RNVS_MAILBOX_MEM", PLAT_RME_RNVS_MAILBOX_MEM_CT);
}
uint64_t pal_get_rt_wdog_ctrl(void)
{
  return RmeCfgGetU64(L"PLAT_RT_WDOG_CTRL", PLAT_RT_WDOG_CTRL_CT);
}
uint64_t pal_get_rt_wdog_int_id(void)
{
  return RmeCfgGetU64(L"PLAT_RT_WDOG_INT_ID", PLAT_RT_WDOG_INT_ID_CT);
}
uint64_t pal_get_rme_acs_nvm_mem(void)
{
  return RmeCfgGetU64(L"PLAT_RME_ACS_NVM_MEM", PLAT_RME_ACS_NVM_MEM_CT);
}
uint64_t pal_get_free_mem_start(void)
{
  return RmeCfgGetU64(L"PLAT_FREE_MEM_START", PLAT_FREE_MEM_START_CT);
}
uint64_t pal_get_free_va_test(void)
{
  return RmeCfgGetU64(L"PLAT_FREE_VA_TEST", PLAT_FREE_VA_TEST_CT);
}
uint64_t pal_get_free_pa_test(void)
{
  return RmeCfgGetU64(L"PLAT_FREE_PA_TEST", PLAT_FREE_PA_TEST_CT);
}
uint64_t pal_get_free_mem_smmu(void)
{
  return RmeCfgGetU64(L"PLAT_FREE_MEM_SMMU", PLAT_FREE_MEM_SMMU_CT);
}
uint64_t pal_get_memory_pool_size(void)
{
  return PLAT_MEMORY_POOL_SIZE;
}

/*
 * Print a concise summary of applied PLATFORM_CONFIG values. Values are read
 * from the runtime configuration if present, otherwise fall back to _CT defaults.
 */
VOID pal_dump_platform_config(void)
{
  UINT64 uart_base  = RmeCfgGetU64(L"PLATFORM_GENERIC_UART_BASE", PLATFORM_GENERIC_UART_BASE_CT);
  UINT64 uart_intid = RmeCfgGetU64(L"PLATFORM_GENERIC_UART_INTID", PLATFORM_GENERIC_UART_INTID_CT);
  UINT64 cntctl = RmeCfgGetU64(L"PLATFORM_OVERRIDE_CNTCTL_BASE", PLATFORM_OVERRIDE_CNTCTL_BASE_CT);
  UINT64 cntread
      = RmeCfgGetU64(L"PLATFORM_OVERRIDE_CNTREAD_BASE", PLATFORM_OVERRIDE_CNTREAD_BASE_CT);
  UINT64 cntbase_n = RmeCfgGetU64(L"PLATFORM_OVERRIDE_CNTBASE_N", PLATFORM_OVERRIDE_CNTBASE_N_CT);
  UINT64 pt_gsiv   = RmeCfgGetU64(L"PLATFORM_OVERRIDE_PLATFORM_TIMER_GSIV",
                                  PLATFORM_OVERRIDE_PLATFORM_TIMER_GSIV_CT);
  UINT64 tout_l
      = RmeCfgGetU64(L"PLATFORM_OVERRIDE_TIMEOUT_LARGE", PLATFORM_OVERRIDE_TIMEOUT_LARGE_CT);
  UINT64 tout_m
      = RmeCfgGetU64(L"PLATFORM_OVERRIDE_TIMEOUT_MEDIUM", PLATFORM_OVERRIDE_TIMEOUT_MEDIUM_CT);
  UINT64 tout_s
      = RmeCfgGetU64(L"PLATFORM_OVERRIDE_TIMEOUT_SMALL", PLATFORM_OVERRIDE_TIMEOUT_SMALL_CT);
  UINT64 el2_gsiv = RmeCfgGetU64(L"PLATFORM_OVERRIDE_EL2_VIR_TIMER_GSIV",
                                 PLATFORM_OVERRIDE_EL2_VIR_TIMER_GSIV_CT);
  UINT64 wd_ref
      = RmeCfgGetU64(L"PLATFORM_OVERRIDE_WD_REFRESH_BASE", PLATFORM_OVERRIDE_WD_REFRESH_BASE_CT);
  UINT64 wd_ctrl
      = RmeCfgGetU64(L"PLATFORM_OVERRIDE_WD_CTRL_BASE", PLATFORM_OVERRIDE_WD_CTRL_BASE_CT);
  UINT64 wd_gsiv = RmeCfgGetU64(L"PLATFORM_OVERRIDE_WD_GSIV", PLATFORM_OVERRIDE_WD_GSIV_CT);
  UINT64 ecam
      = RmeCfgGetU64(L"PLATFORM_OVERRIDE_PCIE_ECAM_BASE", PLATFORM_OVERRIDE_PCIE_ECAM_BASE_CT);
  UINT64 sbus = RmeCfgGetU64(L"PLATFORM_OVERRIDE_PCIE_START_BUS_NUM",
                             PLATFORM_OVERRIDE_PCIE_START_BUS_NUM_CT);
  UINT64 mbus = RmeCfgGetU64(L"PLATFORM_OVERRIDE_PCIE_MAX_BUS", PLATFORM_OVERRIDE_PCIE_MAX_BUS_CT);
  UINT64 mdev = RmeCfgGetU64(L"PLATFORM_OVERRIDE_PCIE_MAX_DEV", PLATFORM_OVERRIDE_PCIE_MAX_DEV_CT);
  UINT64 mfunc
      = RmeCfgGetU64(L"PLATFORM_OVERRIDE_PCIE_MAX_FUNC", PLATFORM_OVERRIDE_PCIE_MAX_FUNC_CT);
  UINT64 smmu_base = RmeCfgGetU64(L"PLATFORM_OVERRIDE_SMMU_BASE", PLATFORM_OVERRIDE_SMMU_BASE_CT);
  UINT64 smmu_arch
      = RmeCfgGetU64(L"PLATFORM_OVERRIDE_SMMU_ARCH_MAJOR", PLATFORM_OVERRIDE_SMMU_ARCH_MAJOR_CT);
  UINT64 rt_cnt  = RmeCfgGetU64(L"RT_REG_CNT", RT_REG_CNT_CT);
  UINT64 gpc_cnt = RmeCfgGetU64(L"GPC_PROTECTED_REGION_CNT", GPC_PROTECTED_REGION_CNT_CT);
  UINT64 pas_cnt = RmeCfgGetU64(L"PAS_PROTECTED_REGION_CNT", PAS_PROTECTED_REGION_CNT_CT);
  UINT64 s3_off  = RmeCfgGetU64(L"SMMUV3_ROOT_REG_OFFSET", SMMUV3_ROOT_REG_OFFSET_CT);

  rme_print(ACS_PRINT_INFO, L"\n[CFG] UART_BASE=0x%lx INTID=%lu\n", uart_base, uart_intid);
  rme_print(ACS_PRINT_INFO, L"[CFG] TIMER: CNTCTL=0x%lx CNTREAD=0x%lx CNTBASE_N=0x%lx GSIV=%lu\n",
            cntctl, cntread, cntbase_n, pt_gsiv);
  rme_print(ACS_PRINT_INFO, L"[CFG] TIMEOUTS: L=0x%lx M=0x%lx S=0x%lx EL2_VIR_GSIV=%lu\n", tout_l,
            tout_m, tout_s, el2_gsiv);
  rme_print(ACS_PRINT_INFO, L"[CFG] WD: REFRESH=0x%lx CTRL=0x%lx GSIV=%lu\n", wd_ref, wd_ctrl,
            wd_gsiv);
  rme_print(ACS_PRINT_INFO,
            L"[CFG] PCIe: ECAM=0x%lx START_BUS=%lu MAX_BUS=%lu MAX_DEV=%lu MAX_FUNC=%lu\n", ecam,
            sbus, mbus, mdev, mfunc);
  rme_print(ACS_PRINT_INFO, L"[CFG] SMMU: BASE=0x%lx ARCH_MAJOR=%lu ROOT_REG_OFF=0x%lx\n",
            smmu_base, smmu_arch, s3_off);
  rme_print(ACS_PRINT_INFO, L"[CFG] RT_REG_CNT=%lu, GPC_CNT=%lu, PAS_CNT=%lu\n", rt_cnt, gpc_cnt,
            pas_cnt);

  // Also show key single-value memory parameters
  rme_print(ACS_PRINT_INFO,
            L"[CFG] MEM: FREE_START=0x%lx VA_TEST=0x%lx PA_TEST=0x%lx SMMU=0x%lx "
            L"NVM=0x%lx\n",
            pal_get_free_mem_start(), pal_get_free_va_test(), pal_get_free_pa_test(),
            pal_get_free_mem_smmu(), pal_get_rme_acs_nvm_mem());

  // Print a few entries from RT/GPC/PAS for quick verification (limit to 4 each)
  for (UINT32 i = 0; i < (UINT32)MIN(rt_cnt, 4); i++)
  {
    CHAR16 k[64];
    UnicodeSPrint(k, sizeof(k), L"RT_REG_%u_START_ADDR", i);
    UINT64 base = RmeCfgGetU64(k, (i == 0)   ? RT_REG_0_START_ADDR_CT
                                  : (i == 1) ? RT_REG_1_START_ADDR_CT
                                  : (i == 2) ? RT_REG_2_START_ADDR_CT
                                             : RT_REG_3_START_ADDR_CT);
    UnicodeSPrint(k, sizeof(k), L"RT_REG_%u_SIZE", i);
    UINT64 size = RmeCfgGetU64(k, (i == 0)   ? RT_REG_0_SIZE_CT
                                  : (i == 1) ? RT_REG_1_SIZE_CT
                                  : (i == 2) ? RT_REG_2_SIZE_CT
                                             : RT_REG_3_SIZE_CT);
    rme_print(ACS_PRINT_INFO, L"[CFG]   RT[%u]: BASE=0x%lx SIZE=0x%lx\n", i, base, size);
  }
  for (UINT32 i = 0; i < (UINT32)MIN(gpc_cnt, 4); i++)
  {
    CHAR16 k[64];
    UnicodeSPrint(k, sizeof(k), L"GPC_PROTECTED_REGION_%u_START_ADDR", i);
    UINT64 base = RmeCfgGetU64(k, (i == 0)   ? GPC_PROTECTED_REGION_0_START_ADDR_CT
                                  : (i == 1) ? GPC_PROTECTED_REGION_1_START_ADDR_CT
                                  : (i == 2) ? GPC_PROTECTED_REGION_2_START_ADDR_CT
                                             : GPC_PROTECTED_REGION_3_START_ADDR_CT);
    UnicodeSPrint(k, sizeof(k), L"GPC_PROTECTED_REGION_%u_SIZE", i);
    UINT64 size = RmeCfgGetU64(k, (i == 0)   ? GPC_PROTECTED_REGION_0_SIZE_CT
                                  : (i == 1) ? GPC_PROTECTED_REGION_1_SIZE_CT
                                  : (i == 2) ? GPC_PROTECTED_REGION_2_SIZE_CT
                                             : GPC_PROTECTED_REGION_3_SIZE_CT);
    UnicodeSPrint(k, sizeof(k), L"GPC_PROTECTED_REGION_%u_PAS", i);
    UINT64 pas = RmeCfgGetU64(k, (i == 0)   ? GPC_PROTECTED_REGION_0_PAS_CT
                                 : (i == 1) ? GPC_PROTECTED_REGION_1_PAS_CT
                                 : (i == 2) ? GPC_PROTECTED_REGION_2_PAS_CT
                                            : GPC_PROTECTED_REGION_3_PAS_CT);
    rme_print(ACS_PRINT_INFO, L"[CFG]   GPC[%u]: BASE=0x%lx SIZE=0x%lx PAS=%lu\n", i, base, size,
              pas);
  }
  for (UINT32 i = 0; i < (UINT32)MIN(pas_cnt, 4); i++)
  {
    CHAR16 k[64];
    UnicodeSPrint(k, sizeof(k), L"PAS_PROTECTED_REGION_%u_START_ADDR", i);
    UINT64 base = RmeCfgGetU64(k, (i == 0)   ? PAS_PROTECTED_REGION_0_START_ADDR_CT
                                  : (i == 1) ? PAS_PROTECTED_REGION_1_START_ADDR_CT
                                  : (i == 2) ? PAS_PROTECTED_REGION_2_START_ADDR_CT
                                             : PAS_PROTECTED_REGION_3_START_ADDR_CT);
    UnicodeSPrint(k, sizeof(k), L"PAS_PROTECTED_REGION_%u_SIZE", i);
    UINT64 size = RmeCfgGetU64(k, (i == 0)   ? PAS_PROTECTED_REGION_0_SIZE_CT
                                  : (i == 1) ? PAS_PROTECTED_REGION_1_SIZE_CT
                                  : (i == 2) ? PAS_PROTECTED_REGION_2_SIZE_CT
                                             : PAS_PROTECTED_REGION_3_SIZE_CT);
    UnicodeSPrint(k, sizeof(k), L"PAS_PROTECTED_REGION_%u_PAS", i);
    UINT64 pas = RmeCfgGetU64(k, (i == 0)   ? PAS_PROTECTED_REGION_0_PAS_CT
                                 : (i == 1) ? PAS_PROTECTED_REGION_1_PAS_CT
                                 : (i == 2) ? PAS_PROTECTED_REGION_2_PAS_CT
                                            : PAS_PROTECTED_REGION_3_PAS_CT);
    rme_print(ACS_PRINT_INFO, L"[CFG]   PAS[%u]: BASE=0x%lx SIZE=0x%lx PAS=%lu\n", i, base, size,
              pas);
  }
}
