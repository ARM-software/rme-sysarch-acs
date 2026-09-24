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

#include "include/pal_common_support.h"
#include "include/pal_pcie_enum.h"
#include "FVP/include/pal_override_struct.h"

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
#define CXL_COMPONENT_RCRB                 0x1
#define CXL_CACHEMEM_PRIMARY_OFFSET        0x1000ULL

/* List of CXL Root Ports that are not subject to host-side GPC (RKJYPB). */
#define EXPAND_CXL_RP_BDF_ENTRY(bdf) bdf,
static const uint32_t g_cxl_rp_not_subject_to_host_gpc_bdfs[CXL_RP_NOT_SUBJECT_TO_HOST_GPC_CNT] =
  {CXL_RP_NOT_SUBJECT_TO_HOST_GPC_BDF_ENTRIES(EXPAND_CXL_RP_BDF_ENTRY)};
#undef EXPAND_CXL_RP_BDF_ENTRY

#ifndef CXL_RP_REALM_ACCESS_AUTHORIZED_CNT
#define CXL_RP_REALM_ACCESS_AUTHORIZED_CNT 0u
#endif
#ifndef CXL_RP_REALM_ACCESS_AUTHORIZED_BDF_ENTRIES
#define CXL_RP_REALM_ACCESS_AUTHORIZED_BDF_ENTRIES(_)
#endif

#if CXL_RP_REALM_ACCESS_AUTHORIZED_CNT != 0u
/* User-confirmed Root Ports with the RBYTYV Realm access exception enabled. */
#define EXPAND_CXL_RP_BDF_ENTRY(bdf) bdf,
static const uint32_t g_cxl_rp_realm_access_authorized_bdfs[] =
  {CXL_RP_REALM_ACCESS_AUTHORIZED_BDF_ENTRIES(EXPAND_CXL_RP_BDF_ENTRY)};
#undef EXPAND_CXL_RP_BDF_ENTRY
#endif

#ifndef CXL_CHI_C2C_SUPPORTED_CNT
#define CXL_CHI_C2C_SUPPORTED_CNT 0u
#endif
#ifndef CXL_CHI_C2C_SUPPORTED_BDF_ENTRIES
#define CXL_CHI_C2C_SUPPORTED_BDF_ENTRIES(_)
#endif

#if CXL_CHI_C2C_SUPPORTED_CNT != 0u
/* List of CXL components that support CHI-C2C. */
#define EXPAND_CXL_CHI_C2C_BDF_ENTRY(bdf) bdf,
static const uint32_t g_cxl_chi_c2c_supported_bdfs[CXL_CHI_C2C_SUPPORTED_CNT] =
  {CXL_CHI_C2C_SUPPORTED_BDF_ENTRIES(EXPAND_CXL_CHI_C2C_BDF_ENTRY)};
#undef EXPAND_CXL_CHI_C2C_BDF_ENTRY
#endif

extern PLATFORM_OVERRIDE_CXL_INFO_TABLE platform_cxl_cfg;

uint32_t
pal_cxl_rp_is_not_subject_to_host_gpc(uint32_t rp_bdf)
{
  for (uint32_t idx = 0u; idx < CXL_RP_NOT_SUBJECT_TO_HOST_GPC_CNT; ++idx)
  {
    if (g_cxl_rp_not_subject_to_host_gpc_bdfs[idx] == rp_bdf)
      return 1u;
  }

  return 0u;
}

uint32_t
pal_cxl_rp_is_realm_access_authorized(uint32_t rp_bdf)
{
#if CXL_RP_REALM_ACCESS_AUTHORIZED_CNT == 0u
  (void)rp_bdf;
  return 0u;
#else
  uint32_t count = (uint32_t)(sizeof(g_cxl_rp_realm_access_authorized_bdfs) /
                             sizeof(g_cxl_rp_realm_access_authorized_bdfs[0]));

  /* A mismatched count/list must not authorize an unintended port. */
  if (count != CXL_RP_REALM_ACCESS_AUTHORIZED_CNT)
    return 0u;

  for (uint32_t idx = 0u; idx < count; ++idx)
  {
    if (g_cxl_rp_realm_access_authorized_bdfs[idx] == rp_bdf)
      return 1u;
  }

  return 0u;
#endif
}

uint32_t
pal_cxl_is_chi_c2c_supported(uint32_t bdf)
{
#if CXL_CHI_C2C_SUPPORTED_CNT == 0u
  (void)bdf;
  return 0u;
#else
  for (uint32_t idx = 0u; idx < CXL_CHI_C2C_SUPPORTED_CNT; ++idx)
  {
    if (g_cxl_chi_c2c_supported_bdfs[idx] == bdf)
      return 1u;
  }

  return 0u;
#endif
}

/**
  @brief   Populate the bare-metal CXL info table structure for the platform.

  @param  CxlTable  Pointer to the caller-provided table to initialise.
**/
void
pal_cxl_create_info_table(CXL_INFO_TABLE *CxlTable)
{
  uint32_t host_count, host_idx, window_idx, max_windows;

  if (CxlTable == NULL) {
    print(ACS_PRINT_ERR, "Input CXL Table Pointer is NULL. Cannot create CXL INFO ");
    return;
  }

  CxlTable->num_entries = 0;

  host_count = platform_cxl_cfg.num_entries;
  if (host_count == 0u)
    return;

  max_windows = (uint32_t)(sizeof(CxlTable->device[0].cfmws_base) /
                           sizeof(CxlTable->device[0].cfmws_base[0]));

  for (host_idx = 0u; host_idx < host_count; ++host_idx) {
    CXL_INFO_BLOCK *dst = &CxlTable->device[host_idx];
    PLATFORM_OVERRIDE_CXL_INFO_BLOCK *src = &platform_cxl_cfg.device[host_idx];

    pal_mem_set(dst, sizeof(*dst), 0);
    dst->uid = src->uid;
    dst->component_reg_type = CXL_COMPONENT_RCRB;
    dst->component_reg_base = src->component_reg_base + CXL_CACHEMEM_PRIMARY_OFFSET;
    dst->component_reg_length = src->component_reg_length;

    dst->cfmws_count = src->cfmws_count;
    if (dst->cfmws_count > max_windows)
      dst->cfmws_count = max_windows;

    for (window_idx = 0u; window_idx < dst->cfmws_count; ++window_idx) {
      dst->cfmws_base[window_idx] = src->cfmws_base[window_idx];
      dst->cfmws_length[window_idx] = src->cfmws_length[window_idx];
    }

    dst->hdm_decoder_count = 0;
  }

  CxlTable->num_entries = host_count;
}

/**
  @brief   Return the CEDT host bridge UID for the given root port BDF.

  @param  bdf  Root port Bus/Device/Function identifier.
  @param  uid  Output pointer for the host bridge UID.

  @return 0 on success, non-zero when mapping is unavailable.
**/
uint32_t
pal_cxl_get_host_bridge_uid(uint32_t bdf, uint32_t *uid)
{
  if (uid == NULL) {
    print(ACS_PRINT_ERR, " pal_cxl_get_host_bridge_uid UID pointer NULL ");
    return 1u;
  }

  for (uint32_t idx = 0u; idx < platform_cxl_cfg.num_entries; ++idx) {
    PLATFORM_OVERRIDE_CXL_INFO_BLOCK *host_bridge = &platform_cxl_cfg.device[idx];
    uint32_t rp_count = host_bridge->rp_count;

    if (rp_count > PLATFORM_OVERRIDE_CXL_MAX_ROOT_PORTS)
      rp_count = PLATFORM_OVERRIDE_CXL_MAX_ROOT_PORTS;

    for (uint32_t rp_idx = 0u; rp_idx < rp_count; ++rp_idx) {
      if (host_bridge->rp_bdf[rp_idx] == bdf) {
        *uid = host_bridge->uid;
        return 0u;
      }
    }
  }

  return 1u;
}
