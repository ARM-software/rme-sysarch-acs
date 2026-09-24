/** @file
 * Copyright (c) 2025-2026, Arm Limited or its affiliates. All rights reserved.
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

#include <Uefi.h>
#include <Library/BaseMemoryLib.h>
#include <Library/PrintLib.h>
#include <Library/UefiLib.h>

#include "Include/IndustryStandard/Acpi64.h"

#include "include/pal_uefi.h"
#include "include/pal_pcie_enum.h"
#include "include/pal_exerciser.h"

#define CXL_COMPONENT_RCRB     0x1
#define CXL_COMPONENT_HDM      0x4
#define CXL_COMPONENT_MAILBOX  0x8
#define CXL_CACHEMEM_PRIMARY_OFFSET 0x1000
#define CXL_RP_IDE_KM_BAR0_OFFSET        0x20000ULL
#define CXL_RP_IDE_KM_REG_SIGNATURE      0x000
#define CXL_RP_IDE_KM_REG_CONTROL        0x004
#define CXL_RP_IDE_KM_REG_STREAM_SLOT    0x008
#define CXL_RP_IDE_KM_REG_STATE          0x00C
#define CXL_RP_IDE_KM_REG_RX_KEY_BASE    0x100
#define CXL_RP_IDE_KM_REG_TX_KEY_BASE    0x140

#define CXL_RP_IDE_KM_SIGNATURE_VALUE      0x4D4B4549u
#define CXL_RP_IDE_KM_CTRL_KEY_PROG        (1u << 0)
#define CXL_RP_IDE_KM_CTRL_K_SET_GO        (1u << 1)
#define CXL_RP_IDE_KM_CTRL_K_SET_STOP      (1u << 2)
#define CXL_RP_IDE_KM_STATE_KEY_PROGRAMMED (1u << 0)
#define CXL_RP_IDE_KM_STATE_ACTIVE         (1u << 1)

UINT64 pal_get_cedt_ptr(void);
UINT64 RmeCfgGetU64(CONST CHAR16* Key, UINT64 DefaultVal);

UINT32
pal_cxl_rp_is_not_subject_to_host_gpc(UINT32 rp_bdf)
{
  UINT32 count
      = (UINT32)RmeCfgGetU64(L"CXL_RP_NOT_SUBJECT_TO_HOST_GPC_CNT", 0u);

  /* Cap the loop to prevent untrusted config blobs from stalling execution. */
  if (count > 256u)
    count = 256u;

  for (UINT32 idx = 0u; idx < count; ++idx)
  {
    CHAR16 key[64];
    UnicodeSPrint(key,
                  sizeof(key),
                  L"CXL_RP_NOT_SUBJECT_TO_HOST_GPC_%u_BDF",
                  idx);

    UINT64 cfg_bdf = RmeCfgGetU64(key, ~0ULL);
    if ((UINT32)cfg_bdf == rp_bdf)
      return 1u;
  }

  return 0u;
}

UINT32
pal_cxl_rp_is_realm_access_authorized(UINT32 rp_bdf)
{
  UINT64 count = RmeCfgGetU64(L"CXL_RP_REALM_ACCESS_AUTHORIZED_CNT", 0u);

  /* Missing or invalid configuration does not confirm authorization. */
  if (count > 256u)
    return 0u;

  for (UINT32 idx = 0u; idx < count; ++idx)
  {
    CHAR16 key[64];
    UnicodeSPrint(key,
                  sizeof(key),
                  L"CXL_RP_REALM_ACCESS_AUTHORIZED_%u_BDF",
                  idx);

    UINT64 cfg_bdf = RmeCfgGetU64(key, ~0ULL);
    if (cfg_bdf == (UINT64)rp_bdf)
      return 1u;
  }

  return 0u;
}

UINT32
pal_cxl_is_chi_c2c_supported(UINT32 bdf)
{
  UINT32 count
      = (UINT32)RmeCfgGetU64(L"CXL_CHI_C2C_SUPPORTED_CNT", 0u);

  /* Cap the loop to prevent untrusted config blobs from stalling execution. */
  if (count > 256u)
    count = 256u;

  for (UINT32 idx = 0u; idx < count; ++idx)
  {
    CHAR16 key[64];
    UnicodeSPrint(key,
                  sizeof(key),
                  L"CXL_CHI_C2C_SUPPORTED_%u_BDF",
                  idx);

    UINT64 cfg_bdf = RmeCfgGetU64(key, ~0ULL);
    if ((UINT32)cfg_bdf == bdf)
      return 1u;
  }

  return 0u;
}

/**
  @brief   Incorporate CFMWS records into the CXL info table.

  @param  Cfmws     Pointer to a CXL fixed memory window structure.
  @param  CxlTable  CXL info table to update.
**/
static VOID
pal_cxl_apply_cfmws(const EFI_ACPI_6_4_CEDT_CXL_FIXED_MEMORY_WINDOW_STRUCTURE *Cfmws,
                    CXL_INFO_TABLE                                          *CxlTable)
{
  if ((Cfmws == NULL) || (CxlTable == NULL)) {
    return;
  }

  if (CxlTable->num_entries == 0) {
    return;
  }

  UINT16 record_length = Cfmws->RecordLength;
  UINT32 header_length = sizeof(*Cfmws);

  if (record_length < header_length) {
    return;
  }

  UINT32 target_count = (record_length - header_length) / sizeof(UINT32);

  for (UINT32 target_index = 0; target_index < target_count; target_index++) {
    UINT32 target_uid = Cfmws->InterleaveTargetList[target_index];

    for (UINT32 entry_index = 0; entry_index < CxlTable->num_entries; entry_index++) {
      CXL_INFO_BLOCK *entry = &CxlTable->device[entry_index];

      if (entry->uid != target_uid) {
        continue;
      }

      UINT32 window_slot = entry->cfmws_count;
      UINT32 max_windows = (UINT32)(sizeof(entry->cfmws_base) /
                                    sizeof(entry->cfmws_base[0]));
      if (window_slot < max_windows) {
        entry->cfmws_base[window_slot]   = Cfmws->BaseHpa;
        entry->cfmws_length[window_slot] = Cfmws->WindowSize;
        entry->cfmws_count++;
      }
    }
  }
}

/**
  @brief   Build the platform CXL info table from ACPI CEDT data.

  @param  CxlTable  Caller-provided buffer to populate.
**/
VOID
pal_cxl_create_info_table(CXL_INFO_TABLE *CxlTable)
{
  EFI_ACPI_DESCRIPTION_HEADER *Cedt;
  UINT8                        *ptr;
  UINT8                        *end;
  UINT32                        host_count;
  UINT64                        cedt_address;

  if (CxlTable == NULL) {
    rme_print(ACS_PRINT_ERR, L" Input CXL Table Pointer is NULL. Cannot create CXL INFO ");
    return;
  }

  CxlTable->num_entries = 0;

  cedt_address = pal_get_cedt_ptr();
  if (cedt_address == 0) {
    rme_print(ACS_PRINT_DEBUG, L" ACPI - CEDT Table not found. ");
    return;
  }

  Cedt       = (EFI_ACPI_DESCRIPTION_HEADER *)(UINTN)cedt_address;
  ptr        = (UINT8 *)(Cedt + 1);
  end        = ((UINT8 *)Cedt) + Cedt->Length;
  host_count = 0;

  while ((ptr + sizeof(UINT8) + sizeof(UINT16)) <= end) {
    EFI_ACPI_6_4_CEDT_CXL_HOST_BRIDGE_STRUCTURE *Host =
      (EFI_ACPI_6_4_CEDT_CXL_HOST_BRIDGE_STRUCTURE *)ptr;

    if (Host->RecordLength == 0) {
      rme_print(ACS_PRINT_WARN, L" CEDT record length is zero. Aborting parse. ");
      return;
    }

    if ((ptr + Host->RecordLength) > end) {
      rme_print(ACS_PRINT_WARN, L" CEDT record overruns table length. Stopping parse. ");
      break;
    }

    if ((Host->Type == EFI_ACPI_6_4_CEDT_STRUCTURE_TYPE_CXL_HOST_BRIDGE_STRUCTURE) &&
        (Host->RecordLength >= sizeof(EFI_ACPI_6_4_CEDT_CXL_HOST_BRIDGE_STRUCTURE))) {
      CXL_INFO_BLOCK *entry = &CxlTable->device[host_count];
      ZeroMem(entry, sizeof(*entry));

      entry->uid                 = Host->Uid;
      entry->component_reg_type  = CXL_COMPONENT_RCRB;
      entry->component_reg_base  = Host->Base + CXL_CACHEMEM_PRIMARY_OFFSET;
      entry->component_reg_length = Host->Length;
      entry->hdm_decoder_count   = 0;

      host_count++;
    }

    ptr += Host->RecordLength;
  }

  CxlTable->num_entries = host_count;

  if (host_count == 0) {
    return;
  }

  ptr = (UINT8 *)(Cedt + 1);
  while ((ptr + sizeof(UINT8) + sizeof(UINT16)) <= end) {
    UINT8  type = ptr[0];
    UINT16 len  = *(UINT16 *)(ptr + 2);

    if (len == 0) {
      rme_print(ACS_PRINT_WARN, L" CEDT record length is zero. Aborting parse. ");
      return;
    }

    if ((ptr + len) > end) {
      rme_print(ACS_PRINT_WARN, L" CEDT record overruns table length. Stopping parse. ");
      break;
    }

    if ((type == EFI_ACPI_6_4_CEDT_STRUCTURE_TYPE_CXL_FIXED_MEMORY_WINDOW_STRUCTURE) &&
        (len >= sizeof(EFI_ACPI_6_4_CEDT_CXL_FIXED_MEMORY_WINDOW_STRUCTURE))) {
      pal_cxl_apply_cfmws((const EFI_ACPI_6_4_CEDT_CXL_FIXED_MEMORY_WINDOW_STRUCTURE *)ptr,
                          CxlTable);
    }

    ptr += len;
  }
}

/**
  @brief   Return the CEDT host bridge UID for the given root port BDF.

  @param  bdf  Root port Bus/Device/Function identifier.
  @param  uid  Output pointer for the host bridge UID.

  @return 0 on success, non-zero when mapping is unavailable.
**/
UINT32
pal_cxl_get_host_bridge_uid(UINT32 bdf, UINT32 *uid)
{
  UINT16 segment;
  UINT8 bus;

  /* Map root port BDF to the root bridge UID for CEDT lookup. */
  if (uid == NULL) {
    rme_print(ACS_PRINT_ERR, L" pal_cxl_get_host_bridge_uid UID pointer NULL ");
    return 1u;
  }

  segment = (UINT16)PCIE_EXTRACT_BDF_SEG(bdf);
  bus = (UINT8)PCIE_EXTRACT_BDF_BUS(bdf);

  return pal_acpi_get_root_bridge_uid(segment, bus, uid);
}
