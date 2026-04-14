/** @file
 * Copyright (c) 2025-2026, Arm Limited or its affiliates. All rights reserved.
 * SPDX-License-Identifier : Apache-2.0
 *
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
#include "include/val_pcie.h"
#include "include/val_cxl_spec.h"
#include "include/val_cxl.h"
#include "include/val_pgt.h"
#include "include/val_pe.h"
#include "include/val_el32.h"
#include "include/val_memory.h"
#include "include/val_iovirt.h"

#define VAL_CXL_TSP_MAX_IB_ENTRIES 8u
#define CXL_HDM_ALIGNMENT_SHIFT     28u
#define CXL_HDM_ALIGNMENT_MASK      ((1ULL << CXL_HDM_ALIGNMENT_SHIFT) - 1ULL)
#define CXL_HDM_ERROR_BIT           (1u << 11)

static CXL_INFO_TABLE *g_cxl_info_table;
static CXL_COMPONENT_TABLE *g_cxl_component_table;

static uint32_t
val_cxl_find_host_index_by_uid(uint32_t uid, uint32_t *index_out)
{
  if ((g_cxl_info_table == NULL) || (index_out == NULL))
    return ACS_STATUS_ERR;

  for (uint32_t idx = 0; idx < g_cxl_info_table->num_entries; idx++) {
    if (g_cxl_info_table->device[idx].uid == uid) {
      *index_out = idx;
      return ACS_STATUS_PASS;
    }
  }

  return ACS_STATUS_SKIP;
}

static void
val_cxl_assign_host_bridge_indices(void)
{
  if ((g_cxl_info_table == NULL) || (g_cxl_component_table == NULL))
    return;

  for (uint32_t comp_index = 0; comp_index < g_cxl_component_table->num_entries;
       comp_index++) {
    CXL_COMPONENT_ENTRY *entry = &g_cxl_component_table->component[comp_index];
    uint32_t uid;
    uint32_t host_index;

    if (entry->role != CXL_COMPONENT_ROLE_ROOT_PORT)
      continue;

    if (entry->host_bridge_index != CXL_COMPONENT_INVALID_INDEX)
      continue;

    if (pal_cxl_get_host_bridge_uid(entry->bdf, &uid) != 0u) {
      continue;
    }

    if (val_cxl_find_host_index_by_uid(uid, &host_index) != ACS_STATUS_PASS) {
      continue;
    }

    entry->host_bridge_index = host_index;
  }
}

uint32_t
val_cxl_rp_is_not_subject_to_host_gpc(uint32_t rp_bdf)
{
  return pal_cxl_rp_is_not_subject_to_host_gpc(rp_bdf);
}

static int  val_cxl_dev_cap_hdr_read(uint64_t arr_base,
                                     uint32_t index,
                                     uint16_t *id_out,
                                     uint8_t *ver_out,
                                     uint32_t *off_out);

static inline uint64_t
val_align_down(uint64_t value, uint64_t align)
{
  return value & ~(align - 1u);
}

static inline uint64_t
val_align_up(uint64_t value, uint64_t align)
{
  return (value + align - 1u) & ~(align - 1u);
}

static uint32_t
val_cxl_map_component_window(uint64_t base, uint64_t length)
{
  memory_region_descriptor_t mem_desc_array[2];
  pgt_descriptor_t pgt_desc;
  uint64_t page_size;
  uint64_t aligned_base;
  uint64_t aligned_length;
  uint64_t ttbr;

  if ((base == 0u) || (length == 0u))
    return ACS_STATUS_PASS;

  page_size = val_memory_page_size();
  if (page_size == 0u)
    return ACS_STATUS_ERR;

  aligned_base = val_align_down(base, page_size);
  aligned_length = val_align_up(base + length, page_size) - aligned_base;

  val_memory_set(mem_desc_array, sizeof(mem_desc_array), 0);

  mem_desc_array[0].virtual_address  = aligned_base;
  mem_desc_array[0].physical_address = aligned_base;
  mem_desc_array[0].length           = aligned_length;
  mem_desc_array[0].attributes =
    LOWER_ATTRS(PGT_ENTRY_ACCESS | SHAREABLE_ATTR(NON_SHAREABLE) |
                GET_ATTR_INDEX(NON_CACHEABLE) | PGT_ENTRY_AP_RW);

  if (val_pe_reg_read_tcr(0, &pgt_desc.tcr))
    return ACS_STATUS_ERR;

  if (val_pe_reg_read_ttbr(0, &ttbr))
    return ACS_STATUS_ERR;

  pgt_desc.pgt_base = (ttbr & AARCH64_TTBR_ADDR_MASK);
  pgt_desc.mair     = val_pe_reg_read(MAIR_ELx);
  pgt_desc.stage    = PGT_STAGE1;
  pgt_desc.ias      = 48;
  pgt_desc.oas      = 48;

  if (val_pgt_create(mem_desc_array, &pgt_desc))
    return ACS_STATUS_ERR;

  return ACS_STATUS_PASS;
}

uint32_t
val_cxl_select_cfmws_window(uint32_t host_index,
                            uint64_t *base,
                            uint64_t *size)
{
  uint32_t window_count;

  if ((base == NULL) || (size == NULL))
    return ACS_STATUS_ERR;

  window_count = val_cxl_get_cfmws_count(host_index);
  if (window_count == 0u)
    return ACS_STATUS_SKIP;

  for (uint32_t idx = 0; idx < window_count; ++idx)
  {
    uint64_t candidate_base = 0u;
    uint64_t candidate_size = 0u;

    if (val_cxl_get_cfmws(host_index, idx, &candidate_base, &candidate_size) != 0u)
      continue;

    if ((candidate_base == 0u) || (candidate_size == 0u))
      continue;

    if (((candidate_base | candidate_size) & CXL_HDM_ALIGNMENT_MASK) != 0u)
      continue;

    *base = candidate_base;
    *size = candidate_size;
    return ACS_STATUS_PASS;
  }

  return ACS_STATUS_SKIP;
}

uint32_t
val_cxl_aer_clear(uint32_t bdf, uint32_t aer_offset)
{
  val_pcie_write_cfg(bdf,
                     aer_offset + AER_UNCORR_STATUS_OFFSET,
                     AER_ERROR_MASK);
  val_pcie_write_cfg(bdf,
                     aer_offset + AER_CORR_STATUS_OFFSET,
                     AER_ERROR_MASK);
  return ACS_STATUS_PASS;
}

uint32_t
val_cxl_aer_read_uncorr(uint32_t bdf,
                        uint32_t aer_offset,
                        uint32_t *status_out)
{
  if (status_out == NULL)
    return ACS_STATUS_ERR;

  val_pcie_read_cfg(bdf,
                    aer_offset + AER_UNCORR_STATUS_OFFSET,
                    status_out);
  return ACS_STATUS_PASS;
}

/**
  @brief   Retrieve a pointer to a component table entry.

  @param  component_index  Index of the component within the component table.

  @return Pointer to the component entry on success; NULL on error.
**/
static CXL_COMPONENT_ENTRY *
val_cxl_get_component_entry(uint32_t component_index)
{
  if (g_cxl_component_table == NULL) {
    val_print(ACS_PRINT_ERR, " CXL: component table not initialised", 0);
    return NULL;
  }

  if (component_index >= g_cxl_component_table->num_entries) {
    val_print(ACS_PRINT_ERR, " CXL: invalid component index %u", component_index);
    return NULL;
  }

  return &g_cxl_component_table->component[component_index];
}

/**
  @brief   Convert a component role enumeration value to a printable label.

  @param  role  CXL component role value.

  @return Pointer to a static string describing the role.
**/
static const char *
val_cxl_role_name(uint32_t role)
{
  switch (role) {
  case CXL_COMPONENT_ROLE_ROOT_PORT:        return "Root Port";
  case CXL_COMPONENT_ROLE_SWITCH_UPSTREAM:  return "Switch Upstream";
  case CXL_COMPONENT_ROLE_SWITCH_DOWNSTREAM:return "Switch Downstream";
  case CXL_COMPONENT_ROLE_ENDPOINT:         return "Endpoint";
  default:                                  return "Unknown";
  }
}

/**
  @brief   Convert a CXL device type value to a printable label.

  @param  type  Enumerated device type value.

  @return Pointer to a static string describing the device type.
**/
static const char *
val_cxl_device_type_name(uint32_t type)
{
  switch (type) {
  case CXL_DEVICE_TYPE_TYPE1: return "Type1";
  case CXL_DEVICE_TYPE_TYPE2: return "Type2";
  case CXL_DEVICE_TYPE_TYPE3: return "Type3";
  default:                    return "Unknown";
  }
}

/**
  @brief   Retrieve or allocate a component entry for the given PCIe function.

  @param  bdf  PCIe identifier of the device to look up.

  @return Pointer to the component entry or NULL if no slot is available.
**/
static CXL_COMPONENT_ENTRY *
val_cxl_get_or_create_component(uint32_t bdf)
{
  uint32_t idx;
  CXL_COMPONENT_ENTRY *entry;

  if (g_cxl_component_table == NULL)
    return NULL;

  for (idx = 0; idx < g_cxl_component_table->num_entries; idx++) {
    entry = &g_cxl_component_table->component[idx];
    if (entry->bdf == bdf)
      return entry;
  }

  if (g_cxl_component_table->num_entries >= CXL_COMPONENT_TABLE_MAX_ENTRIES)
    return NULL;

  entry = &g_cxl_component_table->component[g_cxl_component_table->num_entries++];

  entry->component_reg_base   = 0;
  entry->component_reg_length = 0;
  entry->device_reg_base      = 0;
  entry->bdf                  = bdf;
  entry->role                 = CXL_COMPONENT_ROLE_UNKNOWN;
  entry->device_type          = CXL_DEVICE_TYPE_UNKNOWN;
  entry->host_bridge_index    = CXL_COMPONENT_INVALID_INDEX;
  entry->device_reg_length    = 0;
  entry->hdm_decoder_count    = 0;
  entry->chi_c2c_supported    = 0;
  entry->chi_c2c_dvsec_offset = 0;

  return entry;
}

/**
  @brief   Locate a capability structure within a component register block.

  @param  component_base  Base address of the component register space.
  @param  cap_id          Capability identifier to locate.
  @param  cap_base_out    Optional pointer that receives the capability base address.

  @return ACS_STATUS_PASS if found; ACS_STATUS_SKIP when absent; ACS_STATUS_ERR on error.
**/
uint32_t
val_cxl_find_capability(uint64_t component_base,
                        uint16_t cap_id,
                        uint64_t *cap_base_out)
{
  uint32_t arr_hdr;
  uint32_t entries;

  if (component_base == 0u)
    return ACS_STATUS_ERR;

  arr_hdr = val_mmio_read(component_base + CXL_COMPONENT_CAP_ARRAY_OFFSET);
  entries = CXL_CAP_ARRAY_ENTRIES(arr_hdr);

  for (uint32_t idx = 1; idx <= entries; ++idx) {
    uint32_t cap_hdr =
      val_mmio_read(component_base + (uint64_t)idx * CXL_CAP_HDR_SIZE);

    if ((cap_hdr == 0u) || (cap_hdr == PCIE_UNKNOWN_RESPONSE))
      continue;

    if (CXL_CAP_HDR_CAPID(cap_hdr) != cap_id)
      continue;

    uint32_t pointer = CXL_CAP_HDR_POINTER(cap_hdr);
    if (pointer == 0u)
      return ACS_STATUS_ERR;

    if (cap_base_out != NULL)
      *cap_base_out = component_base + (uint64_t)pointer;

    return ACS_STATUS_PASS;
  }

  if (cap_base_out != NULL)
    *cap_base_out = 0u;

  return ACS_STATUS_SKIP;
}

/**
  @brief   Assign a component role based on the PCIe device/port type.

  @param  component  Pointer to component entry to update.
  @param  dp_type    PCIe device/port type value.

  @return  None.
**/
static void
val_cxl_assign_component_role(CXL_COMPONENT_ENTRY *component, uint32_t dp_type)
{
  if (component == NULL)
    return;
  switch (dp_type) {
  case RP:
  case iEP_RP:
    component->role = CXL_COMPONENT_ROLE_ROOT_PORT;
    break;
  case UP:
    component->role = CXL_COMPONENT_ROLE_SWITCH_UPSTREAM;
    break;
  case DP:
    component->role = CXL_COMPONENT_ROLE_SWITCH_DOWNSTREAM;
    break;
  case EP:
  case iEP_EP:
  case RCiEP:
    component->role = CXL_COMPONENT_ROLE_ENDPOINT;
    break;
  default:
    component->role = CXL_COMPONENT_ROLE_UNKNOWN;
    break;
  }
}

/**
  @brief   Allocate and initialise the global CXL component table.

  @return ACS_STATUS_PASS on success, ACS_STATUS_ERR otherwise.
**/
uint32_t
val_cxl_create_component_table(void)
{
  uint32_t idx;
  uint64_t i;

  if (g_cxl_component_table != NULL)
    return ACS_STATUS_PASS;

  g_cxl_component_table =
    (CXL_COMPONENT_TABLE *)pal_mem_alloc(CXL_COMPONENT_TABLE_SZ);
  if (g_cxl_component_table == NULL)
    return ACS_STATUS_ERR;

  for (i = 0; i < CXL_COMPONENT_TABLE_SZ; i++)
    ((uint8_t *)g_cxl_component_table)[i] = 0;

  g_cxl_component_table->num_entries = 0;

  for (idx = 0; idx < CXL_COMPONENT_TABLE_MAX_ENTRIES; idx++) {
    g_cxl_component_table->component[idx].host_bridge_index = CXL_COMPONENT_INVALID_INDEX;
    g_cxl_component_table->component[idx].role              = CXL_COMPONENT_ROLE_UNKNOWN;
    g_cxl_component_table->component[idx].device_type       = CXL_DEVICE_TYPE_UNKNOWN;
  }

  return ACS_STATUS_PASS;
}

/**
  @brief   Reset component discovery bookkeeping for subsequent scans.
**/
void
val_cxl_free_component_table(void)
{
  if (g_cxl_component_table != NULL) {
    pal_mem_free(g_cxl_component_table);
    g_cxl_component_table = NULL;
  }
}

/**
  @brief   Request EL3 to program IDE keys on a root port and report status.

  BAR0 is derived from the root port BDF in NS world. Key buffers are mapped to
  EL3 as NS memory, then EL3 service programs IDE_KM through EL3 PAL.

  @param  rp_bdf    Bus/Device/Function tuple of the CXL root port.
  @param  stream_id IDE stream identifier that should be armed.
  @param  key_slot  Key slot index to populate with the provided keys.
  @param  rx_key    Pointer to the RX key material for the stream.
  @param  tx_key    Pointer to the TX key material for the stream.

  @retval ACS_STATUS_PASS PAL reported successful IDE programming.
  @retval ACS_STATUS_FAIL PAL returned 0 indicating IDE was not configured.
**/
uint32_t
val_cxl_root_port_ide_program_and_enable(uint32_t rp_bdf,
                                         uint8_t stream_id,
                                         uint8_t key_slot,
                                         const CXL_IDE_KEY_BUFFER *rx_key,
                                         const CXL_IDE_KEY_BUFFER *tx_key)
{
  uint64_t bar0_base;
  uint64_t ide_km_base;
  uint64_t ide_km_pgt_attr_el3;
  uint64_t tg;
  uint64_t key_pgt_attr_el3;
  uint64_t rx_key_va_page;
  uint64_t rx_key_pa_page;
  uint64_t rx_key_end_va_page;
  uint64_t rx_key_end_pa_page;
  uint64_t tx_key_va_page;
  uint64_t tx_key_pa_page;
  uint64_t tx_key_end_va_page;
  uint64_t tx_key_end_pa_page;
  uint32_t el3_status;

  if ((rx_key == NULL) || (tx_key == NULL))
    return ACS_STATUS_FAIL;

  val_pcie_get_mmio_bar(rp_bdf, &bar0_base);
  if (bar0_base == 0u)
    return ACS_STATUS_FAIL;
  val_print(ACS_PRINT_DEBUG, " CXL IDE_KM RP BDF: 0x%x", rp_bdf);
  val_print(ACS_PRINT_DEBUG, " CXL IDE_KM BAR0 base: 0x%llx", bar0_base);

  if (val_cxl_root_port_ide_get_base_el3(bar0_base, &ide_km_base))
    return ACS_STATUS_FAIL;
  val_print(ACS_PRINT_DEBUG, " CXL IDE_KM base: 0x%llx", ide_km_base);

  if (val_add_gpt_entry_el3(ide_km_base, GPT_ANY))
  {
    val_print(ACS_PRINT_ERR, " EL3 IDE_KM GPT mapping failed for BDF 0x%x", rp_bdf);
    return ACS_STATUS_FAIL;
  }

  ide_km_pgt_attr_el3 = LOWER_ATTRS(PGT_ENTRY_ACCESS | SHAREABLE_ATTR(OUTER_SHAREABLE) |
                                    GET_ATTR_INDEX(DEV_MEM_nGnRnE) | PGT_ENTRY_AP_RW |
                                    PAS_ATTR(ROOT_PAS));

  /* IDE_KM register space is 4KB. Single EL3 mapping is sufficient. */
  if (val_add_mmu_entry_el3(ide_km_base, ide_km_base, ide_km_pgt_attr_el3))
  {
    val_print(ACS_PRINT_ERR, " EL3 IDE_KM MMU mapping failed for BDF 0x%x", rp_bdf);
    return ACS_STATUS_FAIL;
  }

  tg = val_get_min_tg();
  key_pgt_attr_el3 = LOWER_ATTRS(PGT_ENTRY_ACCESS | SHAREABLE_ATTR(OUTER_SHAREABLE) |
                                 PGT_ENTRY_AP_RW | PAS_ATTR(NONSECURE_PAS));

  rx_key_va_page = (uint64_t)rx_key & ~(tg - 1u);
  rx_key_pa_page = (uint64_t)val_memory_virt_to_phys((void *)rx_key_va_page) & ~(tg - 1u);
  rx_key_end_va_page = ((uint64_t)rx_key + sizeof(CXL_IDE_KEY_BUFFER) - 1u) & ~(tg - 1u);
  rx_key_end_pa_page = (uint64_t)val_memory_virt_to_phys((void *)rx_key_end_va_page) &
                       ~(tg - 1u);

  tx_key_va_page = (uint64_t)tx_key & ~(tg - 1u);
  tx_key_pa_page = (uint64_t)val_memory_virt_to_phys((void *)tx_key_va_page) & ~(tg - 1u);
  tx_key_end_va_page = ((uint64_t)tx_key + sizeof(CXL_IDE_KEY_BUFFER) - 1u) & ~(tg - 1u);
  tx_key_end_pa_page = (uint64_t)val_memory_virt_to_phys((void *)tx_key_end_va_page) &
                       ~(tg - 1u);

  if (val_add_gpt_entry_el3(rx_key_pa_page, GPT_ANY) ||
      val_add_mmu_entry_el3(rx_key_va_page, rx_key_pa_page, key_pgt_attr_el3))
  {
    val_print(ACS_PRINT_ERR, " EL3 RX key mapping failed for RP BDF 0x%x", rp_bdf);
    return ACS_STATUS_FAIL;
  }

  if ((rx_key_end_va_page != rx_key_va_page) &&
      (val_add_gpt_entry_el3(rx_key_end_pa_page, GPT_ANY) ||
       val_add_mmu_entry_el3(rx_key_end_va_page, rx_key_end_pa_page, key_pgt_attr_el3)))
  {
    val_print(ACS_PRINT_ERR, " EL3 RX key end-page mapping failed for BDF 0x%x", rp_bdf);
    return ACS_STATUS_FAIL;
  }

  if ((tx_key_va_page != rx_key_va_page) && (tx_key_va_page != rx_key_end_va_page) &&
      (val_add_gpt_entry_el3(tx_key_pa_page, GPT_ANY) ||
       val_add_mmu_entry_el3(tx_key_va_page, tx_key_pa_page, key_pgt_attr_el3)))
  {
    val_print(ACS_PRINT_ERR, " EL3 TX key mapping failed for RP BDF 0x%x", rp_bdf);
    return ACS_STATUS_FAIL;
  }

  if ((tx_key_end_va_page != tx_key_va_page) &&
      (tx_key_end_va_page != rx_key_va_page) &&
      (tx_key_end_va_page != rx_key_end_va_page) &&
      (val_add_gpt_entry_el3(tx_key_end_pa_page, GPT_ANY) ||
       val_add_mmu_entry_el3(tx_key_end_va_page, tx_key_end_pa_page, key_pgt_attr_el3)))
  {
    val_print(ACS_PRINT_ERR, " EL3 TX key end-page mapping failed for BDF 0x%x", rp_bdf);
    return ACS_STATUS_FAIL;
  }

  el3_status = val_cxl_root_port_ide_program_and_enable_el3(bar0_base,
                                                             stream_id,
                                                             key_slot,
                                                             rx_key,
                                                             tx_key);

  if (el3_status == 0U) {
    return ACS_STATUS_PASS;
  }

  return ACS_STATUS_FAIL;
}

uint32_t
val_cxl_ide_disable_link(uint32_t root_index,
                         uint32_t endpoint_index,
                         val_spdm_context_t *context,
                         uint32_t session_id)
{
#if ENABLE_SPDM
  const CXL_COMPONENT_ENTRY *root_port;
  const CXL_COMPONENT_ENTRY *endpoint;
  uint32_t status;
  uint32_t el3_status;
  uint64_t bar0_base;
  uint64_t ide_km_base;
  uint64_t ide_km_pgt_attr_el3;
  uint32_t endpoint_ide_status;
  uint32_t root_ide_status;
  uint32_t rx_state;
  uint32_t tx_state;

  if ((context == NULL) || (session_id == 0u))
    return ACS_STATUS_ERR;

  root_port = val_cxl_get_component_entry(root_index);
  endpoint = val_cxl_get_component_entry(endpoint_index);
  if ((root_port == NULL) || (endpoint == NULL))
    return ACS_STATUS_ERR;

  status = val_spdm_send_cxl_ide_km_key_set_stop(context,
                                                  session_id,
                                                  0u,
                                                  CXL_IDE_KM_KEY_DIRECTION_RX |
                                                  CXL_IDE_KM_KEY_SUB_STREAM_CXL,
                                                  0u);
  if (status != ACS_STATUS_PASS)
    return status;

  status = val_spdm_send_cxl_ide_km_key_set_stop(context,
                                                  session_id,
                                                  0u,
                                                  CXL_IDE_KM_KEY_DIRECTION_TX |
                                                  CXL_IDE_KM_KEY_SUB_STREAM_CXL,
                                                  0u);
  if (status != ACS_STATUS_PASS)
    return status;

  val_pcie_get_mmio_bar(root_port->bdf, &bar0_base);
  if (bar0_base == 0u)
    return ACS_STATUS_FAIL;
  val_print(ACS_PRINT_DEBUG, " CXL IDE_KM RP BDF: 0x%x", root_port->bdf);
  val_print(ACS_PRINT_DEBUG, " CXL IDE_KM BAR0 base: 0x%llx", bar0_base);

  if (val_cxl_root_port_ide_get_base_el3(bar0_base, &ide_km_base))
    return ACS_STATUS_FAIL;
  val_print(ACS_PRINT_DEBUG, " CXL IDE_KM base: 0x%llx", ide_km_base);

  if (val_add_gpt_entry_el3(ide_km_base, GPT_ANY))
    return ACS_STATUS_FAIL;

  ide_km_pgt_attr_el3 = LOWER_ATTRS(PGT_ENTRY_ACCESS | SHAREABLE_ATTR(OUTER_SHAREABLE) |
                                    GET_ATTR_INDEX(DEV_MEM_nGnRnE) | PGT_ENTRY_AP_RW |
                                    PAS_ATTR(ROOT_PAS));

  if (val_add_mmu_entry_el3(ide_km_base, ide_km_base, ide_km_pgt_attr_el3))
  {
    val_print(ACS_PRINT_ERR, " EL3 IDE_KM MMU mapping failed for BDF 0x%x", root_port->bdf);
    return ACS_STATUS_FAIL;
  }

  el3_status = val_cxl_root_port_ide_disable_el3(bar0_base, 0u, 0u);
  if (el3_status != 0u)
    return ACS_STATUS_FAIL;

  status = val_cxl_ide_get_status(endpoint_index, &endpoint_ide_status);
  if (status != ACS_STATUS_PASS)
    return status;

  rx_state = endpoint_ide_status & CXL_IDE_STATUS_FIELD_MASK;
  tx_state = (endpoint_ide_status >> CXL_IDE_STATUS_TX_SHIFT) & CXL_IDE_STATUS_FIELD_MASK;
  if ((rx_state != CXL_IDE_STATE_INSECURE) || (tx_state != CXL_IDE_STATE_INSECURE))
  {
    val_print(ACS_PRINT_ERR, " CXL: EP IDE status after stop 0x%x",
              (uint64_t)endpoint_ide_status);
    val_print(ACS_PRINT_ERR, " CXL: EP BDF 0x%x", (uint64_t)endpoint->bdf);
    return ACS_STATUS_FAIL;
  }

  status = val_cxl_ide_get_status(root_index, &root_ide_status);
  if (status != ACS_STATUS_PASS)
    return status;

  rx_state = root_ide_status & CXL_IDE_STATUS_FIELD_MASK;
  tx_state = (root_ide_status >> CXL_IDE_STATUS_TX_SHIFT) & CXL_IDE_STATUS_FIELD_MASK;
  if ((rx_state != CXL_IDE_STATE_INSECURE) || (tx_state != CXL_IDE_STATE_INSECURE))
  {
    val_print(ACS_PRINT_ERR, " CXL: RP IDE status after stop 0x%x",
              (uint64_t)root_ide_status);
    val_print(ACS_PRINT_ERR, " CXL: RP BDF 0x%x", (uint64_t)root_port->bdf);
    return ACS_STATUS_FAIL;
  }

  return ACS_STATUS_PASS;
#else
  (void)root_index;
  (void)endpoint_index;
  (void)context;
  (void)session_id;

  val_print(ACS_PRINT_WARN,
            " SPDM support disabled - skipping IDE disable",
            0);
  return ACS_STATUS_SKIP;
#endif
}

/**
  @brief   Return the active CXL component table pointer, if any.

  @return Pointer to the global component table, or NULL if not created.
**/
CXL_COMPONENT_TABLE *
val_cxl_component_table_ptr(void)
{
  return g_cxl_component_table;
}

/**
  @brief   Query a property from the discovered CXL component table.

  @param  type   Selector describing which field to return.
  @param  index  Component index when the selector is per-entry.

  @return Requested value or 0 on error.
**/
uint64_t
val_cxl_get_component_info(CXL_COMPONENT_INFO_e type, uint32_t index)
{
  if (g_cxl_component_table == NULL) {
    val_print(ACS_PRINT_ERR, " GET_CXL_COMPONENT_INFO: component table not created", 0);
    return 0;
  }

  if (type == CXL_COMPONENT_INFO_COUNT)
    return g_cxl_component_table->num_entries;

  if (index >= g_cxl_component_table->num_entries) {
    val_print(ACS_PRINT_ERR, " GET_CXL_COMPONENT_INFO: Invalid index %u", index);
    return 0;
  }

  const CXL_COMPONENT_ENTRY *entry = &g_cxl_component_table->component[index];

  switch (type) {
  case CXL_COMPONENT_INFO_ROLE:
    return entry->role;
  case CXL_COMPONENT_INFO_DEVICE_TYPE:
    return entry->device_type;
  case CXL_COMPONENT_INFO_HOST_BRIDGE_INDEX:
    return entry->host_bridge_index;
  case CXL_COMPONENT_INFO_BDF_INDEX:
    return entry->bdf;
  case CXL_COMPONENT_INFO_COMPONENT_BASE:
    return entry->component_reg_base;
  case CXL_COMPONENT_INFO_COMPONENT_LENGTH:
    return entry->component_reg_length;
  case CXL_COMPONENT_INFO_HDM_COUNT:
    return entry->hdm_decoder_count;
  case CXL_COMPONENT_INFO_CHI_C2C_SUPPORTED:
    return entry->chi_c2c_supported;
  case CXL_COMPONENT_INFO_CHI_C2C_DVSEC_OFFSET:
    return entry->chi_c2c_dvsec_offset;
  default:
    val_print(ACS_PRINT_ERR, " GET_CXL_COMPONENT_INFO: Unsupported type %u", type);
    break;
  }

  return 0;
}


/**
  @brief   Resolve the base address of the CXL Security Capability for a component.

  @param  component_index  Index of the component within the component table.
  @param  base_out         Output pointer that receives the capability base address.

  @return ACS_STATUS_PASS on success.
          ACS_STATUS_SKIP if capability absent.
          ACS_STATUS_ERR otherwise.
**/
static uint32_t
val_cxl_security_capability_base(uint32_t component_index, uint64_t *base_out)
{
  const CXL_COMPONENT_ENTRY *entry = val_cxl_get_component_entry(component_index);

  if ((entry == NULL) || (entry->component_reg_base == 0u) || (base_out == NULL))
    return ACS_STATUS_ERR;

  return val_cxl_find_capability(entry->component_reg_base,
                                 CXL_CAPID_SECURITY,
                                 base_out);
}

/**
  @brief   Resolve the base address of the CXL Extended Security Capability.

  @param  component_index  Index of the component within the component table.
  @param  base_out         Output pointer that receives the capability base address.

  @return ACS_STATUS_PASS on success.
          ACS_STATUS_SKIP if capability absent.
          ACS_STATUS_ERR otherwise.
**/
static uint32_t
val_cxl_ext_security_capability_base(uint32_t component_index, uint64_t *base_out)
{
  const CXL_COMPONENT_ENTRY *entry = val_cxl_get_component_entry(component_index);

  if ((entry == NULL) || (entry->component_reg_base == 0u) || (base_out == NULL))
    return ACS_STATUS_ERR;

  return val_cxl_find_capability(entry->component_reg_base,
                                 CXL_CAPID_EXT_SECURITY,
                                 base_out);
}

/**
  @brief   Resolve the base address of the CXL IDE Capability.

  @param  component_index  Index of the component within the component table.
  @param  base_out         Output pointer that receives the capability base address.

  @return ACS_STATUS_PASS on success.
          ACS_STATUS_SKIP if capability absent.
          ACS_STATUS_ERR otherwise.
**/
static uint32_t
val_cxl_ide_capability_base(uint32_t component_index, uint64_t *base_out)
{
  const CXL_COMPONENT_ENTRY *entry = val_cxl_get_component_entry(component_index);

  if ((entry == NULL) || (entry->component_reg_base == 0u) || (base_out == NULL))
    return ACS_STATUS_ERR;

  return val_cxl_find_capability(entry->component_reg_base,
                                 CXL_CAPID_IDE,
                                 base_out);
}

/**
  @brief   Read the CXL Security Policy register for a component.

  @param  component_index  Index of the component within the component table.
  @param  policy           Output pointer that receives the Security Policy register contents.

  @return ACS_STATUS_PASS on success.
          ACS_STATUS_SKIP if capability absent.
          ACS_STATUS_ERR otherwise.
**/
uint32_t
val_cxl_security_get_policy(uint32_t component_index, uint32_t *policy)
{
  uint64_t cap_base;
  uint32_t status;

  if (policy == NULL)
    return ACS_STATUS_ERR;

  status = val_cxl_security_capability_base(component_index, &cap_base);
  if (status != ACS_STATUS_PASS)
    return status;

  *policy = val_mmio_read(cap_base + CXL_SECURITY_POLICY_OFFSET);
  return ACS_STATUS_PASS;
}

/**
  @brief   Extract the Device Trust Level field from the Security Policy register.

  @param  component_index  Index of the component within the component table.
  @param  trust_level      Output pointer that receives the decoded trust level value.

  @return ACS_STATUS_PASS on success.
          ACS_STATUS_SKIP if capability absent.
          ACS_STATUS_ERR otherwise.
**/
uint32_t
val_cxl_security_get_device_trust_level(uint32_t component_index, uint32_t *trust_level)
{
  uint32_t policy;
  uint32_t status;

  if (trust_level == NULL)
    return ACS_STATUS_ERR;

  status = val_cxl_security_get_policy(component_index, &policy);
  if (status != ACS_STATUS_PASS)
    return status;

  *trust_level = (policy >> CXL_SECURITY_POLICY_TRUST_LEVEL_SHIFT) &
                 CXL_SECURITY_POLICY_TRUST_LEVEL_MASK;
  return ACS_STATUS_PASS;
}

/**
  @brief   Obtain the Extended Security entry count for a component.

  @param  component_index  Index of the component within the component table.
  @param  count            Output pointer that receives the number of table entries.

  @return ACS_STATUS_PASS on success.
          ACS_STATUS_SKIP if capability absent.
          ACS_STATUS_ERR otherwise.
**/
uint32_t
val_cxl_ext_security_get_count(uint32_t component_index, uint32_t *count)
{
  uint64_t cap_base;
  uint32_t status;

  if (count == NULL)
    return ACS_STATUS_ERR;

  status = val_cxl_ext_security_capability_base(component_index, &cap_base);
  if (status != ACS_STATUS_PASS)
    return status;

  *count = val_mmio_read(cap_base + CXL_EXT_SECURITY_COUNT_OFFSET) &
           CXL_EXT_SECURITY_COUNT_MASK;
  return ACS_STATUS_PASS;
}

/**
  @brief   Read a Root Port security policy entry from the Extended Security table.

  @param  component_index  Index of the component within the component table.
  @param  entry_index      Entry slot to read (0-based).
  @param  policy           Output pointer that receives the policy DWORD for the entry.

  @return ACS_STATUS_PASS on success.
          ACS_STATUS_SKIP if capability absent.
          ACS_STATUS_ERR on error.
          ACS_STATUS_FAIL when entry_index is out of range.
**/
uint32_t
val_cxl_ext_security_get_policy(uint32_t component_index,
                                uint32_t entry_index,
                                uint32_t *policy)
{
  uint64_t cap_base;
  uint32_t status;
  uint32_t count;

  if (policy == NULL)
    return ACS_STATUS_ERR;

  status = val_cxl_ext_security_get_count(component_index, &count);
  if (status != ACS_STATUS_PASS)
    return status;

  if (entry_index >= count)
    return ACS_STATUS_FAIL;

  status = val_cxl_ext_security_capability_base(component_index, &cap_base);
  if (status != ACS_STATUS_PASS)
    return status;

  *policy = val_mmio_read(cap_base + CXL_EXT_SECURITY_POLICY_BASE +
                          entry_index * CXL_EXT_SECURITY_ENTRY_STRIDE);
  return ACS_STATUS_PASS;
}

/**
  @brief   Read the Root Port identifier associated with a security policy entry.

  @param  component_index  Index of the component within the component table.
  @param  entry_index      Entry slot to read (0-based).
  @param  port_id          Output pointer that receives the Root Port ID.

  @return ACS_STATUS_PASS on success.
          ACS_STATUS_SKIP if capability absent.
          ACS_STATUS_ERR on error.
          ACS_STATUS_FAIL when entry_index is out of range.
**/
uint32_t
val_cxl_ext_security_get_port_id(uint32_t component_index,
                                 uint32_t entry_index,
                                 uint32_t *port_id)
{
  uint64_t cap_base;
  uint32_t status;
  uint32_t count;

  if (port_id == NULL)
    return ACS_STATUS_ERR;

  status = val_cxl_ext_security_get_count(component_index, &count);
  if (status != ACS_STATUS_PASS)
    return status;

  if (entry_index >= count)
    return ACS_STATUS_FAIL;

  status = val_cxl_ext_security_capability_base(component_index, &cap_base);
  if (status != ACS_STATUS_PASS)
    return status;

  *port_id = val_mmio_read(cap_base + CXL_EXT_SECURITY_PORT_ID_BASE +
                           entry_index * CXL_EXT_SECURITY_ENTRY_STRIDE) &
             CXL_EXT_SECURITY_PORT_ID_MASK;
  return ACS_STATUS_PASS;
}

/**
  @brief   Find the security policy word that corresponds to a given Root Port ID.

  @param  component_index  Index of the component within the component table.
  @param  port_id          Root Port identifier to match.
  @param  policy           Output pointer that receives the matching policy DWORD.

  @return ACS_STATUS_PASS when a matching entry is found.
          ACS_STATUS_SKIP if no matching entry exists.
          ACS_STATUS_ERR on error.
**/
uint32_t
val_cxl_ext_security_find_policy_by_port(uint32_t component_index,
                                         uint32_t port_id,
                                         uint32_t *policy)
{
  uint32_t count;
  uint32_t idx;
  uint32_t current_port;
  uint32_t status;

  if (policy == NULL)
    return ACS_STATUS_ERR;

  status = val_cxl_ext_security_get_count(component_index, &count);
  if (status != ACS_STATUS_PASS)
    return status;

  for (idx = 0; idx < count; ++idx) {
    status = val_cxl_ext_security_get_port_id(component_index, idx, &current_port);
    if (status != ACS_STATUS_PASS)
      return status;

    if (current_port == port_id)
      return val_cxl_ext_security_get_policy(component_index, idx, policy);
  }

  return ACS_STATUS_SKIP;
}

/**
  @brief   Find the security policy word and register address that correspond to a given RP ID.

  @param  cap_base        Base address of the CXL Extended Security Capability.
  @param  port_id         Root Port identifier to match.
  @param  policy_out      Output pointer that receives the matching policy DWORD.
  @param  policy_pa_out   Output pointer that receives the policy register address.

  @return ACS_STATUS_PASS when a matching entry is found.
          ACS_STATUS_SKIP if no matching entry exists.
          ACS_STATUS_ERR on error.
**/
uint32_t
val_cxl_find_ext_security_policy(uint64_t cap_base,
                                 uint32_t port_id,
                                 uint32_t *policy_out,
                                 uint64_t *policy_pa_out)
{
  uint32_t count;

  if ((policy_out == NULL) || (policy_pa_out == NULL) || (cap_base == 0u))
    return ACS_STATUS_ERR;

  count = val_mmio_read(cap_base + CXL_EXT_SECURITY_COUNT_OFFSET) &
          CXL_EXT_SECURITY_COUNT_MASK;
  if (count == 0u)
    return ACS_STATUS_SKIP;

  for (uint32_t idx = 0u; idx < count; ++idx)
  {
    uint32_t entry_port =
      val_mmio_read(cap_base + CXL_EXT_SECURITY_PORT_ID_BASE +
                    idx * CXL_EXT_SECURITY_ENTRY_STRIDE) &
      CXL_EXT_SECURITY_PORT_ID_MASK;

    if (entry_port != port_id)
      continue;

    *policy_pa_out = cap_base + CXL_EXT_SECURITY_POLICY_BASE +
                     idx * CXL_EXT_SECURITY_ENTRY_STRIDE;
    *policy_out = val_mmio_read(*policy_pa_out);
    return ACS_STATUS_PASS;
  }

  return ACS_STATUS_SKIP;
}

/**
  @brief   Read the CXL IDE Capability register for a component.

  @param  component_index  Index of the component within the component table.
  @param  capability       Output pointer that receives the capability register contents.

  @return ACS_STATUS_PASS on success.
          ACS_STATUS_SKIP if capability absent.
          ACS_STATUS_ERR otherwise.
**/
uint32_t
val_cxl_ide_get_capability(uint32_t component_index, uint32_t *capability)
{
  uint64_t cap_base;
  uint32_t status;

  if (capability == NULL)
    return ACS_STATUS_ERR;

  status = val_cxl_ide_capability_base(component_index, &cap_base);
  if (status != ACS_STATUS_PASS)
    return status;

  *capability = val_mmio_read(cap_base + CXL_IDE_REG_CAPABILITY);
  return ACS_STATUS_PASS;
}

/**
  @brief   Read the CXL IDE Control register for a component.

  @param  component_index  Index of the component within the component table.
  @param  control          Output pointer that receives the control register contents.

  @return ACS_STATUS_PASS on success.
          ACS_STATUS_SKIP if capability absent.
          ACS_STATUS_ERR otherwise.
**/
uint32_t
val_cxl_ide_get_control(uint32_t component_index, uint32_t *control)
{
  uint64_t cap_base;
  uint32_t status;

  if (control == NULL)
    return ACS_STATUS_ERR;

  status = val_cxl_ide_capability_base(component_index, &cap_base);
  if (status != ACS_STATUS_PASS)
    return status;

  *control = val_mmio_read(cap_base + CXL_IDE_REG_CONTROL);
  return ACS_STATUS_PASS;
}

/**
  @brief   Read the CXL IDE Status register for a component.

  @param  component_index  Index of the component within the component table.
  @param  status_out       Output pointer that receives the status register contents.

  @return ACS_STATUS_PASS on success.
          ACS_STATUS_SKIP if capability absent.
          ACS_STATUS_ERR otherwise.
**/
uint32_t
val_cxl_ide_get_status(uint32_t component_index, uint32_t *status_out)
{
  uint64_t cap_base;
  uint32_t status;

  if (status_out == NULL)
    return ACS_STATUS_ERR;

  status = val_cxl_ide_capability_base(component_index, &cap_base);
  if (status != ACS_STATUS_PASS)
    return status;

  *status_out = val_mmio_read(cap_base + CXL_IDE_REG_STATUS);
  return ACS_STATUS_PASS;
}

/**
  @brief   Read the CXL IDE Error Status register for a component.

  @param  component_index  Index of the component within the component table.
  @param  error_status     Output pointer that receives the error status register contents.

  @return ACS_STATUS_PASS on success.
          ACS_STATUS_SKIP if capability absent.
          ACS_STATUS_ERR otherwise.
**/
uint32_t
val_cxl_ide_get_error_status(uint32_t component_index, uint32_t *error_status)
{
  uint64_t cap_base;
  uint32_t status;

  if (error_status == NULL)
    return ACS_STATUS_ERR;

  status = val_cxl_ide_capability_base(component_index, &cap_base);
  if (status != ACS_STATUS_PASS)
    return status;

  *error_status = val_mmio_read(cap_base + CXL_IDE_REG_ERROR_STATUS);
  return ACS_STATUS_PASS;
}

uint32_t
val_cxl_find_upstream_root_port(uint32_t endpoint_bdf,
                                uint32_t *root_bdf_out)
{
    uint32_t reg_value;
    uint32_t secondary_bus;
    uint32_t subordinate_bus;
    uint32_t segment;
    uint32_t idx;

    if (root_bdf_out == NULL)
        return ACS_STATUS_ERR;

    *root_bdf_out = 0u;

    if (g_cxl_component_table == NULL)
        return ACS_STATUS_ERR;

    segment = PCIE_EXTRACT_BDF_SEG(endpoint_bdf);

    for (idx = 0; idx < g_cxl_component_table->num_entries; ++idx) {
        const CXL_COMPONENT_ENTRY *entry = &g_cxl_component_table->component[idx];

        if (entry->role != CXL_COMPONENT_ROLE_ROOT_PORT)
            continue;

        if (val_pcie_read_cfg(entry->bdf, TYPE1_PBN, &reg_value) != PCIE_SUCCESS)
            continue;

        secondary_bus = (reg_value >> SECBN_SHIFT) & SECBN_MASK;
        subordinate_bus = (reg_value >> SUBBN_SHIFT) & SUBBN_MASK;

        if ((secondary_bus == 0u) && (subordinate_bus == 0u))
            continue;

        if (PCIE_EXTRACT_BDF_SEG(entry->bdf) != segment)
            continue;

        if ((PCIE_EXTRACT_BDF_BUS(endpoint_bdf) < secondary_bus) ||
            (PCIE_EXTRACT_BDF_BUS(endpoint_bdf) > subordinate_bus))
            continue;

        *root_bdf_out = entry->bdf;
        return ACS_STATUS_PASS;
    }

    return ACS_STATUS_SKIP;
}

uint32_t
val_cxl_find_downstream_endpoint(uint32_t root_index,
                                 uint32_t *endpoint_index_out)
{
  const CXL_COMPONENT_ENTRY *root_port;
  uint32_t reg_value;
  uint32_t secondary_bus;
  uint32_t subordinate_bus;
  uint32_t segment;
  uint32_t idx;

  if (endpoint_index_out == NULL)
    return ACS_STATUS_ERR;

  *endpoint_index_out = CXL_COMPONENT_INVALID_INDEX;

  if (g_cxl_component_table == NULL)
    return ACS_STATUS_ERR;

  root_port = val_cxl_get_component_entry(root_index);
  if (root_port == NULL)
    return ACS_STATUS_ERR;

  if (val_pcie_read_cfg(root_port->bdf, TYPE1_PBN, &reg_value) != PCIE_SUCCESS)
    return ACS_STATUS_ERR;

  secondary_bus = (reg_value >> SECBN_SHIFT) & SECBN_MASK;
  subordinate_bus = (reg_value >> SUBBN_SHIFT) & SUBBN_MASK;
  segment = PCIE_EXTRACT_BDF_SEG(root_port->bdf);

  if ((secondary_bus == 0u) && (subordinate_bus == 0u))
    return ACS_STATUS_SKIP;

  for (idx = 0; idx < g_cxl_component_table->num_entries; ++idx) {
    const CXL_COMPONENT_ENTRY *candidate = &g_cxl_component_table->component[idx];
    uint32_t candidate_bus;

    if (idx == root_index)
      continue;

    if (candidate->role != CXL_COMPONENT_ROLE_ENDPOINT)
      continue;

    if (PCIE_EXTRACT_BDF_SEG(candidate->bdf) != segment)
      continue;

    candidate_bus = PCIE_EXTRACT_BDF_BUS(candidate->bdf);
    if ((candidate_bus < secondary_bus) || (candidate_bus > subordinate_bus))
      continue;

    *endpoint_index_out = idx;
    return ACS_STATUS_PASS;
  }

  return ACS_STATUS_SKIP;
}

#if ENABLE_SPDM
uint32_t
val_cxl_ide_establish_link(uint32_t root_index,
                           uint32_t endpoint_index,
                           val_spdm_context_t *context,
                           uint32_t session_id)
{
  const uint32_t stream_id = 0u;
  const CXL_COMPONENT_ENTRY *root_port;
  const CXL_COMPONENT_ENTRY *endpoint;
  uint32_t endpoint_bdf;
  uint32_t status;
  uint8_t caps;
  cxl_ide_km_aes_256_gcm_key_buffer_t rx_key;
  cxl_ide_km_aes_256_gcm_key_buffer_t tx_key;
  cxl_ide_km_query_resp_t query_info;
  uint8_t kp_ack_status;
  uint8_t iv_type;
  uint8_t key_mode_flag = CXL_IDE_KM_KEY_MODE_SKID;
  uint32_t endpoint_ide_status;
  uint32_t endpoint_err_status;
  uint32_t root_ide_status;
  uint32_t root_err_status;
  uint32_t endpoint_ide_regs[CXL_IDE_KM_IDE_CAP_REG_BLOCK_MAX_COUNT];
  uint32_t endpoint_ide_reg_count = CXL_IDE_KM_IDE_CAP_REG_BLOCK_MAX_COUNT;
  uint32_t endpoint_capability = 0u;

  if ((context == NULL) || (session_id == 0u))
    return ACS_STATUS_ERR;

  root_port = val_cxl_get_component_entry(root_index);
  endpoint = val_cxl_get_component_entry(endpoint_index);
  if ((root_port == NULL) || (endpoint == NULL))
    return ACS_STATUS_ERR;

  endpoint_bdf = endpoint->bdf;

  val_memory_set(&query_info, sizeof(query_info), 0);
  val_memory_set(endpoint_ide_regs, (uint32_t)sizeof(endpoint_ide_regs), 0);
  status = val_spdm_send_cxl_ide_km_query(context,
                                          session_id,
                                          (uint8_t)stream_id,
                                          &query_info,
                                          endpoint_ide_regs,
                                          &endpoint_ide_reg_count);
  if (status != ACS_STATUS_PASS) {
    val_print(ACS_PRINT_ERR, " IDE_KM query failed (status 0x%x)", (uint64_t)status);
    val_print(ACS_PRINT_ERR, " EP BDF 0x%x", (uint64_t)endpoint_bdf);
    return status;
  }

  caps = query_info.caps;

  if ((caps & CXL_IDE_KM_QUERY_RESP_CAP_VERSION_MASK) != CXL_IDE_KM_QUERY_RESP_CAP_VERSION_1) {
    val_print(ACS_PRINT_ERR,
              " IDE_KM version unsupported (caps 0x%x)",
              (uint64_t)caps);
    val_print(ACS_PRINT_ERR, " EP BDF 0x%x", (uint64_t)endpoint_bdf);
    return ACS_STATUS_FAIL;
  }

  val_memory_set(&rx_key, sizeof(rx_key), 0);
  val_memory_set(&tx_key, sizeof(tx_key), 0);

  if ((caps & CXL_IDE_KM_QUERY_RESP_KEY_GEN_CAP) != 0u) {
    status = val_spdm_send_cxl_ide_km_get_key(context,
                                              session_id,
                                              (uint8_t)stream_id,
                                              CXL_IDE_KM_KEY_SUB_STREAM_CXL,
                                              0,
                                              &rx_key);
    if (status != ACS_STATUS_PASS) {
      val_print(ACS_PRINT_ERR,
                " IDE_KM GET_KEY failed (status 0x%x)",
                (uint64_t)status);
      val_print(ACS_PRINT_ERR, " EP BDF 0x%x", (uint64_t)endpoint_bdf);
      return status;
    }

    tx_key = rx_key;
  } else {
    status = val_spdm_get_random(sizeof(rx_key.key),
                                 (uint8_t *)rx_key.key);
    if (status != ACS_STATUS_PASS) {
      val_print(ACS_PRINT_ERR, " RNG failure for IDE key (EP BDF 0x%x)",
                (uint64_t)endpoint_bdf);
      return status;
    }

    rx_key.iv[0] = 0x80000000u;
    rx_key.iv[1] = 0u;
    rx_key.iv[2] = 1u;

    status = val_spdm_get_random(sizeof(tx_key.key),
                                 (uint8_t *)tx_key.key);
    if (status != ACS_STATUS_PASS) {
      val_print(ACS_PRINT_ERR, " RNG failure for IDE key (EP BDF 0x%x)",
                (uint64_t)endpoint_bdf);
      return status;
    }

    tx_key.iv[0] = 0x80000000u;
    tx_key.iv[1] = 0u;
    tx_key.iv[2] = 1u;
  }

  iv_type = ((caps & CXL_IDE_KM_QUERY_RESP_IV_GEN_CAP) == 0u) ?
            CXL_IDE_KM_KEY_IV_DEFAULT :
            CXL_IDE_KM_KEY_IV_INITIAL;

  if (endpoint_ide_reg_count == 0u) {
    val_print(ACS_PRINT_ERR, " Endpoint IDE capability absent in query", 0);
    return ACS_STATUS_FAIL;
  }

  {
    uint32_t capability_index = CXL_IDE_REG_CAPABILITY / (uint32_t)sizeof(uint32_t);
    if (capability_index >= endpoint_ide_reg_count) {
      val_print(ACS_PRINT_ERR, " Endpoint IDE capability index out of range", 0);
      return ACS_STATUS_FAIL;
    }

    endpoint_capability = endpoint_ide_regs[capability_index];
  }

  if ((endpoint_capability & CXL_IDE_CAP_MODE_CONTAINMENT) != 0u)
    key_mode_flag = CXL_IDE_KM_KEY_MODE_CONTAINMENT;

  if (key_mode_flag == CXL_IDE_KM_KEY_MODE_CONTAINMENT)
    val_print(ACS_PRINT_DEBUG, " Using IDE key mode containment", 0);
  else
    val_print(ACS_PRINT_DEBUG, " Using IDE key mode SKID", 0);

  status = val_spdm_send_cxl_ide_km_key_prog(context,
                                             session_id,
                                             (uint8_t)stream_id,
                                             (uint8_t)(CXL_IDE_KM_KEY_DIRECTION_RX |
                                                       iv_type |
                                                       CXL_IDE_KM_KEY_SUB_STREAM_CXL),
                                             0,
                                             &rx_key,
                                             &kp_ack_status);
  if ((status != ACS_STATUS_PASS) ||
      (kp_ack_status != CXL_IDE_KM_KP_ACK_STATUS_SUCCESS)) {
    val_print(ACS_PRINT_ERR,
              " IDE_KM KEY_PROG RX failed (status 0x%x)",
              (uint64_t)status);
    val_print(ACS_PRINT_ERR, " ack 0x%x", (uint64_t)kp_ack_status);
    val_print(ACS_PRINT_ERR, " EP BDF 0x%x", (uint64_t)endpoint_bdf);
    return (status == ACS_STATUS_PASS) ? ACS_STATUS_FAIL : status;
  }

  status = val_spdm_send_cxl_ide_km_key_prog(context,
                                             session_id,
                                             (uint8_t)stream_id,
                                             (uint8_t)(CXL_IDE_KM_KEY_DIRECTION_TX |
                                                       iv_type |
                                                       CXL_IDE_KM_KEY_SUB_STREAM_CXL),
                                             0,
                                             &tx_key,
                                             &kp_ack_status);
  if ((status != ACS_STATUS_PASS) ||
      (kp_ack_status != CXL_IDE_KM_KP_ACK_STATUS_SUCCESS)) {
    val_print(ACS_PRINT_ERR,
              " IDE_KM KEY_PROG TX failed (status 0x%x)",
              (uint64_t)status);
    val_print(ACS_PRINT_ERR, " ack 0x%x", (uint64_t)kp_ack_status);
    val_print(ACS_PRINT_ERR, " EP BDF 0x%x", (uint64_t)endpoint_bdf);
    return (status == ACS_STATUS_PASS) ? ACS_STATUS_FAIL : status;
  }

  status = val_cxl_root_port_ide_program_and_enable(root_port->bdf,
                                                     (uint8_t)stream_id,
                                                     0,
                                                     (const CXL_IDE_KEY_BUFFER *)&rx_key,
                                                     (const CXL_IDE_KEY_BUFFER *)&tx_key);
  if (status != ACS_STATUS_PASS) {
    val_print(ACS_PRINT_ERR,
              " RP IDE_KM programming failed (RP BDF 0x%x)",
              (uint64_t)root_port->bdf);
    return status;
  }

  status = val_spdm_send_cxl_ide_km_key_set_go(context,
                                               session_id,
                                               (uint8_t)stream_id,
                                               (uint8_t)(CXL_IDE_KM_KEY_DIRECTION_RX |
                                                         key_mode_flag |
                                                         CXL_IDE_KM_KEY_SUB_STREAM_CXL),
                                               0);
  if (status != ACS_STATUS_PASS) {
    val_print(ACS_PRINT_ERR, " IDE_KM KEY_SET_GO RX failed (0x%x)", (uint64_t)status);
    val_print(ACS_PRINT_ERR, " EP BDF 0x%x", (uint64_t)endpoint_bdf);
    return status;
  }

  status = val_spdm_send_cxl_ide_km_key_set_go(context,
                                               session_id,
                                               (uint8_t)stream_id,
                                               (uint8_t)(CXL_IDE_KM_KEY_DIRECTION_TX |
                                                         key_mode_flag |
                                                         CXL_IDE_KM_KEY_SUB_STREAM_CXL),
                                               0);
  if (status != ACS_STATUS_PASS) {
    val_print(ACS_PRINT_ERR, " IDE_KM KEY_SET_GO TX failed (0x%x)", (uint64_t)status);
    val_print(ACS_PRINT_ERR, " EP BDF 0x%x", (uint64_t)endpoint_bdf);
    return status;
  }

  status = val_cxl_ide_get_status(endpoint_index, &endpoint_ide_status);
  if (status == ACS_STATUS_SKIP) {
    val_print(ACS_PRINT_DEBUG,
              " Endpoint lacks IDE capability - skipping status check (BDF 0x%x)",
              (uint64_t)endpoint_bdf);
    return ACS_STATUS_PASS;
  }
  if (status != ACS_STATUS_PASS) {
    val_print(ACS_PRINT_ERR,
              " IDE status read failed for endpoint BDF 0x%x",
              (uint64_t)endpoint_bdf);
    return status;
  }
  val_print(ACS_PRINT_DEBUG,
            " Endpoint IDE status 0x%x",
            (uint64_t)endpoint_ide_status);
  val_print(ACS_PRINT_DEBUG,
            " EP BDF 0x%x",
            (uint64_t)endpoint_bdf);

  status = val_cxl_ide_get_error_status(endpoint_index, &endpoint_err_status);
  if (status != ACS_STATUS_PASS) {
    val_print(ACS_PRINT_ERR,
              " IDE error status read failed for endpoint BDF 0x%x",
              (uint64_t)endpoint_bdf);
    return status;
  }
  if (endpoint_err_status != 0u) {
    val_print(ACS_PRINT_ERR,
              " Endpoint IDE error status non-zero (0x%x)",
              (uint64_t)endpoint_err_status);
    val_print(ACS_PRINT_ERR, " EP BDF 0x%x", (uint64_t)endpoint_bdf);
    return ACS_STATUS_FAIL;
  }

  status = val_cxl_ide_get_status(root_index, &root_ide_status);
  if (status == ACS_STATUS_SKIP) {
    val_print(ACS_PRINT_DEBUG,
              " Root port lacks IDE capability - skipping status check (BDF 0x%x)",
              (uint64_t)root_port->bdf);
    return ACS_STATUS_PASS;
  }
  if (status != ACS_STATUS_PASS) {
    val_print(ACS_PRINT_ERR,
              " IDE status read failed for root port BDF 0x%x",
              (uint64_t)root_port->bdf);
    return status;
  }
  val_print(ACS_PRINT_DEBUG,
            " Root port IDE status 0x%x",
            (uint64_t)root_ide_status);
  val_print(ACS_PRINT_DEBUG,
            " RP BDF 0x%x",
            (uint64_t)root_port->bdf);

  status = val_cxl_ide_get_error_status(root_index, &root_err_status);
  if (status != ACS_STATUS_PASS) {
    val_print(ACS_PRINT_ERR,
              " IDE error status read failed for root port BDF 0x%x",
              (uint64_t)root_port->bdf);
    return status;
  }
  if (root_err_status != 0u) {
    val_print(ACS_PRINT_ERR,
              " Root port IDE error status non-zero (0x%x)",
              (uint64_t)root_err_status);
    val_print(ACS_PRINT_ERR, " RP BDF 0x%x", (uint64_t)root_port->bdf);
    return ACS_STATUS_FAIL;
  }

  return ACS_STATUS_PASS;
}
#else
uint32_t
val_cxl_ide_establish_link(uint32_t root_index,
                           uint32_t endpoint_index,
                           val_spdm_context_t *context,
                           uint32_t session_id)
{
  (void)root_index;
  (void)endpoint_index;
  (void)context;
  (void)session_id;

  val_print(ACS_PRINT_WARN,
            " SPDM support disabled - skipping IDE establish",
            0);
  return ACS_STATUS_SKIP;
}
#endif

#if ENABLE_SPDM
uint32_t
val_cxl_tsp_configure_and_lock(uint32_t root_index,
                               uint32_t endpoint_index,
                               val_spdm_context_t *context,
                               uint32_t session_id,
                               uint32_t requested_ckids,
                               uint16_t feature_enable_mask)
{
  const CXL_COMPONENT_ENTRY *root_port;
  const CXL_COMPONENT_ENTRY *endpoint;
  uint32_t rp_bdf;
  uint32_t endpoint_bdf;
  libcxltsp_device_capabilities_t capabilities;
  libcxltsp_device_configuration_t config;
  libcxltsp_device_configuration_t current_cfg;
  libcxltsp_device_2nd_session_info_t secondary_info;
  uint8_t tsp_state;
  uint32_t status;
  uint16_t effective_features;

  if ((context == NULL) || (session_id == 0u))
    return ACS_STATUS_ERR;

  root_port = val_cxl_get_component_entry(root_index);
  endpoint = val_cxl_get_component_entry(endpoint_index);
  if ((root_port == NULL) || (endpoint == NULL))
    return ACS_STATUS_ERR;

  rp_bdf = root_port->bdf;
  endpoint_bdf = endpoint->bdf;

  val_memory_set(&capabilities, sizeof(capabilities), 0);
  val_memory_set(&config, sizeof(config), 0);
  val_memory_set(&current_cfg, sizeof(current_cfg), 0);
  val_memory_set(&secondary_info, sizeof(secondary_info), 0);

  status = val_spdm_send_cxl_tsp_get_version(context, session_id);
  if (status != ACS_STATUS_PASS) {
    val_print(ACS_PRINT_ERR, " TSP GET_VERSION failed (status 0x%x)",
              (uint64_t)status);
    val_print(ACS_PRINT_ERR, " EP BDF 0x%x", (uint64_t)endpoint_bdf);
    return status;
  }

  status = val_spdm_send_cxl_tsp_get_capabilities(context,
                                                  session_id,
                                                  &capabilities);
  if (status != ACS_STATUS_PASS) {
    val_print(ACS_PRINT_ERR, " TSP GET_CAPABILITIES failed (status 0x%x)",
              (uint64_t)status);
    val_print(ACS_PRINT_ERR, " EP BDF 0x%x", (uint64_t)endpoint_bdf);
    return status;
  }

  effective_features = feature_enable_mask;
  if ((capabilities.memory_encryption_features_supported &
       CXL_TSP_MEMORY_ENCRYPTION_FEATURES_SUPPORT_ENCRYPTION) == 0u)
    effective_features = 0u;
  else if ((capabilities.memory_encryption_features_supported &
            CXL_TSP_MEMORY_ENCRYPTION_FEATURES_SUPPORT_CKID_BASED_ENCRYPTION) != 0u)
  {
    if ((capabilities.memory_encryption_features_supported &
         CXL_TSP_MEMORY_ENCRYPTION_FEATURES_SUPPORT_CKID_BASED_REQUIRED) != 0u)
      effective_features = (uint16_t)(CXL_TSP_MEMORY_ENCRYPTION_FEATURES_ENABLE_ENCRYPTION |
                            CXL_TSP_MEMORY_ENCRYPTION_FEATURES_ENABLE_CKID_BASED_ENCRYPTION |
                            CXL_TSP_MEMORY_ENCRYPTION_FEATURES_ENABLE_CKID_BASED_REQUIRED);
    else
      effective_features = CXL_TSP_MEMORY_ENCRYPTION_FEATURES_ENABLE_ENCRYPTION;
  }
  else
  {
    effective_features = CXL_TSP_MEMORY_ENCRYPTION_FEATURES_ENABLE_ENCRYPTION;
  }

  config.memory_encryption_features_enable = effective_features;

  if (effective_features == 0u)
  {
    config.memory_encryption_algorithm_select = 0u;
  }
  else if ((capabilities.memory_encryption_algorithms_supported &
            CXL_TSP_MEMORY_ENCRYPTION_ALGORITHMS_AES_XTS_256) != 0u)
  {
    config.memory_encryption_algorithm_select =
        CXL_TSP_MEMORY_ENCRYPTION_ALGORITHMS_AES_XTS_256;
  }
  else if (capabilities.memory_encryption_algorithms_supported != 0u)
  {
    config.memory_encryption_algorithm_select =
        capabilities.memory_encryption_algorithms_supported;
  }
  else
  {
    config.memory_encryption_algorithm_select = 0u;
  }

  config.te_state_change_and_access_control_features_enable = 0u;
  config.explicit_oob_te_state_granularity = 0u;
  config.configuration_features_enable = 0u;
  config.ckid_base = 0u;
  if ((effective_features &
       CXL_TSP_MEMORY_ENCRYPTION_FEATURES_ENABLE_CKID_BASED_ENCRYPTION) != 0u)
    config.number_of_ckids = requested_ckids;
  else
    config.number_of_ckids = 0u;
  config.explicit_ib_te_state_granularity_entry[0].te_state_granularity = 0u;
  config.explicit_ib_te_state_granularity_entry[0].length_index = 0u;
  for (uint32_t idx = 1; idx < VAL_CXL_TSP_MAX_IB_ENTRIES; ++idx)
    config.explicit_ib_te_state_granularity_entry[idx].length_index = 0xFF;

  status = val_spdm_send_cxl_tsp_set_configuration(context,
                                                   session_id,
                                                   &config,
                                                   &secondary_info);
  if (status != ACS_STATUS_PASS) {
    val_print(ACS_PRINT_ERR, " TSP SET_CONFIGURATION failed (0x%x)",
              (uint64_t)status);
    val_print(ACS_PRINT_ERR, " EP BDF 0x%x", (uint64_t)endpoint_bdf);
    return status;
  }

  tsp_state = CXL_TSP_STATE_CONFIG_UNLOCKED;
  status = val_spdm_send_cxl_tsp_get_configuration(context,
                                                   session_id,
                                                   &current_cfg,
                                                   &tsp_state);
  if (status != ACS_STATUS_PASS) {
    val_print(ACS_PRINT_ERR, " TSP GET_CONFIGURATION failed (0x%x)",
              (uint64_t)status);
    val_print(ACS_PRINT_ERR, " EP BDF 0x%x", (uint64_t)endpoint_bdf);
    return status;
  }

  if ((tsp_state != CXL_TSP_STATE_CONFIG_UNLOCKED) &&
      (tsp_state != CXL_TSP_STATE_CONFIG_LOCKED)) {
    val_print(ACS_PRINT_ERR, " Unexpected TSP state 0x%x", (uint64_t)tsp_state);
    val_print(ACS_PRINT_ERR, " RP BDF 0x%x", (uint64_t)rp_bdf);
    return ACS_STATUS_FAIL;
  }

  if (effective_features != 0u)
  {
    if ((current_cfg.memory_encryption_features_enable & effective_features) !=
        effective_features) {
      val_print(ACS_PRINT_ERR,
                " Target configuration missing required features (RP BDF 0x%x)",
                (uint64_t)rp_bdf);
      return ACS_STATUS_FAIL;
    }

    if (current_cfg.memory_encryption_algorithm_select !=
        config.memory_encryption_algorithm_select) {
      val_print(ACS_PRINT_ERR,
                " Target configuration algorithm mismatch (RP BDF 0x%x)",
                (uint64_t)rp_bdf);
      return ACS_STATUS_FAIL;
    }

    if ((effective_features &
         CXL_TSP_MEMORY_ENCRYPTION_FEATURES_ENABLE_CKID_BASED_ENCRYPTION) != 0u)
    {
      if (current_cfg.ckid_base != config.ckid_base) {
        val_print(ACS_PRINT_ERR,
                  " Target configuration CKID base mismatch (RP BDF 0x%x)",
                  (uint64_t)rp_bdf);
        return ACS_STATUS_FAIL;
      }

      if (current_cfg.number_of_ckids < requested_ckids) {
        val_print(ACS_PRINT_ERR,
                  " Target configuration reports insufficient CKIDs (0x%x)",
                  (uint64_t)current_cfg.number_of_ckids);
        val_print(ACS_PRINT_ERR,
                  " RP BDF 0x%x",
                  (uint64_t)rp_bdf);
        return ACS_STATUS_FAIL;
      }
    }
  }

  status = val_spdm_send_cxl_tsp_lock_configuration(context, session_id);
  if (status != ACS_STATUS_PASS) {
    val_print(ACS_PRINT_ERR, " TSP LOCK_CONFIGURATION failed (0x%x)",
              (uint64_t)status);
    val_print(ACS_PRINT_ERR, " EP BDF 0x%x", (uint64_t)endpoint_bdf);
    return status;
  }

  tsp_state = CXL_TSP_STATE_CONFIG_UNLOCKED;
  status = val_spdm_send_cxl_tsp_get_configuration(context,
                                                   session_id,
                                                   NULL,
                                                   &tsp_state);
  if (status != ACS_STATUS_PASS) {
    val_print(ACS_PRINT_ERR, " TSP state query failed (0x%x)", (uint64_t)status);
    val_print(ACS_PRINT_ERR, " EP BDF 0x%x", (uint64_t)endpoint_bdf);
    return status;
  }

  if (tsp_state != CXL_TSP_STATE_CONFIG_LOCKED) {
    val_print(ACS_PRINT_ERR,
              " TSP state not locked (0x%x)",
              (uint64_t)tsp_state);
    val_print(ACS_PRINT_ERR,
              " RP BDF 0x%x",
              (uint64_t)rp_bdf);
    return ACS_STATUS_FAIL;
  }

  return ACS_STATUS_PASS;
}
#else
uint32_t
val_cxl_tsp_configure_and_lock(uint32_t root_index,
                               uint32_t endpoint_index,
                               val_spdm_context_t *context,
                               uint32_t session_id,
                               uint32_t requested_ckids,
                               uint16_t feature_enable_mask)
{
  (void)root_index;
  (void)endpoint_index;
  (void)context;
  (void)session_id;
  (void)requested_ckids;
  (void)feature_enable_mask;

  val_print(ACS_PRINT_WARN,
            " SPDM support disabled - skipping TSP configuration",
            0);
  return ACS_STATUS_SKIP;
}
#endif

/**
  @brief   Decode the HDM decoder count field from the capability register.

  @param  field  Raw field extracted from the HDM capability register.

  @return Number of HDM decoders reported, or 0 when encoding is reserved.
**/
static uint32_t
val_cxl_decode_hdm_count(uint32_t field)
{
  switch (field & CXL_HDM_DECODER_COUNT_MASK) {
  case 0x0: return 1;
  case 0x1: return 2;
  case 0x2: return 4;
  case 0x3: return 6;
  case 0x4: return 8;
  case 0x5: return 10;
  case 0x6: return 12;
  case 0x7: return 14;
  case 0x8: return 16;
  case 0x9: return 20;
  case 0xA: return 24;
  case 0xB: return 28;
  case 0xC: return 32;
  default:  return 0;
  }
}

/**
  @brief   Reconstruct a 52-bit value from paired low and high HDM registers.

  @param  low   Lower 32 bits read from the register.
  @param  high  Upper 32 bits read from the register.

  @return Combined 52-bit value aligned per CXL HDM encoding rules.
**/
static uint64_t
val_cxl_decode_hdm_value(uint32_t low, uint32_t high)
{
  uint64_t value;

  value  = ((uint64_t)(low >> 28) & 0xFULL) << 28;
  value |= ((uint64_t)high << 32);
  return value;
}

static void
val_cxl_host_parse_hdm_capability(CXL_INFO_BLOCK *entry, uint64_t cap_base)
{
  if ((entry == NULL) || (cap_base == 0u))
    return;

  uint32_t cap_reg = val_mmio_read(cap_base + CXL_HDM_CAP_REG_OFFSET);
  uint32_t count_encoded =
    (cap_reg >> CXL_HDM_DECODER_COUNT_SHIFT) & CXL_HDM_DECODER_COUNT_MASK;
  entry->hdm_decoder_count = val_cxl_decode_hdm_count(count_encoded);
}

static void
val_cxl_host_parse_component_capabilities(CXL_INFO_BLOCK *entry)
{
  uint64_t base;
  uint32_t arr_hdr;
  uint32_t entries;

  if ((entry == NULL) || (entry->component_reg_base == 0u))
    return;

  entry->hdm_decoder_count = 0;

  base = entry->component_reg_base;
  arr_hdr = val_mmio_read(base + CXL_COMPONENT_CAP_ARRAY_OFFSET);
  entries = CXL_CAP_ARRAY_ENTRIES(arr_hdr);

  val_print(ACS_PRINT_DEBUG,
            " CXL_INFO: UID 0x%x",
            entry->uid);
  val_print(ACS_PRINT_DEBUG,
            "  component base 0x%llx",
            base);
  val_print(ACS_PRINT_DEBUG,
            "  component length 0x%llx",
            entry->component_reg_length);
  val_print(ACS_PRINT_DEBUG,
            "  capability array header 0x%x",
            arr_hdr);
  val_print(ACS_PRINT_DEBUG,
            "  capability entries %u",
            entries);

  for (uint32_t idx = 1; idx <= entries; ++idx) {
    uint32_t cap_hdr =
      val_mmio_read(base + (uint64_t)idx * CXL_CAP_HDR_SIZE);

    val_print(ACS_PRINT_DEBUG,
              "   Cap index %u",
              idx);
    val_print(ACS_PRINT_DEBUG,
              "   Cap header 0x%x",
              cap_hdr);

    if ((cap_hdr == 0u) || (cap_hdr == PCIE_UNKNOWN_RESPONSE))
      continue;

    if (CXL_CAP_HDR_CAPID(cap_hdr) != CXL_CAPID_HDM_DECODER)
      continue;

    uint32_t pointer = CXL_CAP_HDR_POINTER(cap_hdr);
    val_print(ACS_PRINT_DEBUG,
              " CXL_INFO: HDM decoder pointer 0x%x",
              pointer);
    if (pointer == 0u)
      continue;

    if ((entry->component_reg_length != 0u) &&
        (pointer >= entry->component_reg_length))
      continue;

    val_cxl_host_parse_hdm_capability(entry, base + pointer);
    val_print(ACS_PRINT_DEBUG,
              "   HDM decoders discovered %u",
              entry->hdm_decoder_count);
    break;
  }

  if (entry->hdm_decoder_count == 0u) {
    val_print(ACS_PRINT_DEBUG,
              " CXL_INFO: UID 0x%x exposes no HDM decoder capability",
              entry->uid);
  }
}

static uint32_t
val_cxl_host_discover_capabilities(CXL_INFO_BLOCK *entry)
{
  if (entry == NULL)
    return ACS_STATUS_ERR;

  if ((entry->component_reg_base == 0u) || (entry->component_reg_length == 0u)) {
    entry->hdm_decoder_count = 0;
    return ACS_STATUS_PASS;
  }

  if (val_cxl_map_component_window(entry->component_reg_base,
                                   entry->component_reg_length) != ACS_STATUS_PASS)
    return ACS_STATUS_ERR;

  val_cxl_host_parse_component_capabilities(entry);
  return ACS_STATUS_PASS;
}

static uint32_t
val_cxl_encode_hdm_value(uint64_t value, uint32_t *low, uint32_t *high)
{
  if ((value & CXL_HDM_ALIGNMENT_MASK) != 0u)
    return ACS_STATUS_ERR;

  if (low != NULL)
    *low = (uint32_t)(((value >> CXL_HDM_ALIGNMENT_SHIFT) & 0xFULL) << 28);

  if (high != NULL)
    *high = (uint32_t)(value >> 32);

  return ACS_STATUS_PASS;
}

/**
  @brief   Populate decoder metadata for a component from its HDM capability.

  @param  component  Component entry to update.
  @param  cap_base   Base address of the HDM capability structure.
**/
static void
val_cxl_parse_hdm_capability(CXL_COMPONENT_ENTRY *component,
                             uint64_t cap_base)
{
  uint32_t cap_reg;
  uint32_t dec_count_encoded;
  uint32_t decoder_count;

  if ((component == NULL) || (cap_base == 0))
    return;

  cap_reg = val_mmio_read(cap_base + CXL_HDM_CAP_REG_OFFSET);
  dec_count_encoded = (cap_reg >> CXL_HDM_DECODER_COUNT_SHIFT) & CXL_HDM_DECODER_COUNT_MASK;
  decoder_count = val_cxl_decode_hdm_count(dec_count_encoded);

  component->hdm_decoder_count = decoder_count;
}

/**
  @brief   Program an HDM decoder window at the specified capability base.

  @param  cap_base       Base address of the HDM capability.
  @param  decoder_index  Decoder slot to program.
  @param  base           HPA/DPA base aligned to 256MB.
  @param  size           Window size aligned to 256MB.

  @return ACS_STATUS_PASS on success, ACS_STATUS_FAIL on commit failure, ACS_STATUS_ERR on error.
**/
static uint32_t
val_cxl_program_decoder_common(uint64_t cap_base,
                               uint32_t decoder_index,
                               uint64_t base,
                               uint64_t size)
{
  uint32_t cap_reg;
  uint32_t dec_count_encoded;
  uint32_t decoder_count;
  uint32_t base_low;
  uint32_t base_high;
  uint32_t size_low;
  uint32_t size_high;
  uint64_t base_low_addr;
  uint64_t base_high_addr;
  uint64_t size_low_addr;
  uint64_t size_high_addr;
  uint64_t ctrl_addr;
  uint32_t ctrl;
  uint32_t attempt;

  if ((cap_base == 0) || (size == 0)) {
    val_print(ACS_PRINT_ERR, " CXL_HDM: invalid parameters for decoder prog", 0);
    val_print(ACS_PRINT_ERR, " CXL_HDM: cap base 0x%llx", cap_base);
    val_print(ACS_PRINT_ERR, " CXL_HDM: window size 0x%llx", size);
    return ACS_STATUS_ERR;
  }

  cap_reg = val_mmio_read(cap_base + CXL_HDM_CAP_REG_OFFSET);
  dec_count_encoded = (cap_reg >> CXL_HDM_DECODER_COUNT_SHIFT) & CXL_HDM_DECODER_COUNT_MASK;
  decoder_count = val_cxl_decode_hdm_count(dec_count_encoded);

  if ((decoder_count == 0u) || (decoder_index >= decoder_count)) {
    val_print(ACS_PRINT_ERR, " CXL_HDM: decoder index %u out of range", decoder_index);
    val_print(ACS_PRINT_ERR, " CXL_HDM: decoders available %u", decoder_count);
    return ACS_STATUS_ERR;
  }

  if (decoder_index >= CXL_MAX_DECODER_SLOTS) {
    val_print(ACS_PRINT_ERR,
              " CXL_HDM: decoder index %u exceeds max slots",
              decoder_index);
    return ACS_STATUS_ERR;
  }

  if (val_cxl_encode_hdm_value(base, &base_low, &base_high) != ACS_STATUS_PASS) {
    val_print(ACS_PRINT_ERR, " CXL_HDM: base encoding failed 0x%llx", base);
    return ACS_STATUS_ERR;
  }

  if (val_cxl_encode_hdm_value(size, &size_low, &size_high) != ACS_STATUS_PASS) {
    val_print(ACS_PRINT_ERR, " CXL_HDM: size encoding failed 0x%llx", size);
    return ACS_STATUS_ERR;
  }

  base_low_addr = cap_base + CXL_HDM_DECODER_BASE_LOW(decoder_index);
  base_high_addr = cap_base + CXL_HDM_DECODER_BASE_HIGH(decoder_index);
  size_low_addr = cap_base + CXL_HDM_DECODER_SIZE_LOW(decoder_index);
  size_high_addr = cap_base + CXL_HDM_DECODER_SIZE_HIGH(decoder_index);
  ctrl_addr = cap_base + CXL_HDM_DECODER_CTRL(decoder_index);

  ctrl = val_mmio_read(ctrl_addr);

  if ((ctrl & CXL_HDM_COMMIT_BIT) != 0u) {
    uint32_t cleared = ctrl & ~CXL_HDM_COMMIT_BIT;
    val_mmio_write(ctrl_addr, cleared);
    for (attempt = 0; attempt < CXL_HDM_COMMIT_TIMEOUT_MS; ++attempt) {
      uint32_t status = val_mmio_read(ctrl_addr);
      if ((status & CXL_HDM_COMMITTED_BIT) == 0u)
        break;
      (void)val_time_delay_ms(1);
    }

    ctrl = val_mmio_read(ctrl_addr);
    if ((ctrl & CXL_HDM_COMMITTED_BIT) != 0u) {
      val_print(ACS_PRINT_ERR,
                " CXL_HDM: commit bit stuck for decoder %u",
                decoder_index);
      return ACS_STATUS_ERR;
    }
  }

  val_mmio_write(base_low_addr, base_low);
  val_mmio_write(base_high_addr, base_high);
  val_mmio_write(size_low_addr, size_low);
  val_mmio_write(size_high_addr, size_high);

  ctrl |= CXL_HDM_COMMIT_BIT;
  val_mmio_write(ctrl_addr, ctrl);

  for (attempt = 0; attempt < CXL_HDM_COMMIT_TIMEOUT_MS; ++attempt) {
    uint32_t status = val_mmio_read(ctrl_addr);

    if ((status & CXL_HDM_ERROR_BIT) != 0u) {
      uint32_t cleared = status & ~CXL_HDM_COMMIT_BIT;
      val_mmio_write(ctrl_addr, cleared);
      val_print(ACS_PRINT_ERR,
                " CXL_HDM: commit error for decoder %u",
                decoder_index);
      return ACS_STATUS_FAIL;
    }

    if ((status & CXL_HDM_COMMITTED_BIT) != 0u) {
      val_print(ACS_PRINT_DEBUG,
                " CXL_HDM: decoder %u programmed",
                decoder_index);
      return ACS_STATUS_PASS;
    }

    (void)val_time_delay_ms(1);
  }

  val_print(ACS_PRINT_ERR,
            " CXL_HDM: commit timed out for decoder %u",
            decoder_index);
  return ACS_STATUS_FAIL;
}

/**
  @brief   Get host physical address for a given PCIe BAR on a CXL device.

  @param bdf           - Segment/Bus/Device/Function identifier.
  @param bir           - BAR indicator (BAR number) from CXL Register Locator.
  @param bar_base_out  - Output pointer for resolved BAR base host PA.
  @param bar_is64      - Output flag set to 1 if BAR is 64-bit, else 0.

  @return  VAL_CXL_BAR_SUCCESS on success; specific error code otherwise.
**/
static int val_cxl_get_mmio_bar_host_pa(uint32_t bdf, uint8_t bir,
                                        uint64_t *bar_base_out, uint32_t *bar_is64)
{
    uint32_t off, lo, hi = 0, header_type, mit, mdt;
    uint64_t bar_base64;
    uint32_t bar_is64_local = 0;

    if (!bar_base_out)
        return VAL_CXL_BAR_ERR_CFG_READ;

    /* Guard BAR index against header type limits */
    header_type = val_pcie_function_header_type(bdf);
    if ((header_type == TYPE0_HEADER && bir >= TYPE0_MAX_BARS) ||
        (header_type == TYPE1_HEADER && bir >= TYPE1_MAX_BARS)) {
        *bar_base_out = 0;
        if (bar_is64) *bar_is64 = 0;
        return VAL_CXL_BAR_ERR_INVALID_INDEX;
    }

    off = TYPE01_BAR + (bir * 4);
    if (val_pcie_read_cfg(bdf, off, &lo))
        return VAL_CXL_BAR_ERR_CFG_READ;

    mit = (lo >> BAR_MIT_SHIFT) & BAR_MIT_MASK;
    if (mit != MMIO)
        return VAL_CXL_BAR_ERR_NOT_MMIO;

    mdt = (lo >> BAR_MDT_SHIFT) & BAR_MDT_MASK;
    if (mdt == BITS_64) {
        if (val_pcie_read_cfg(bdf, off + 4, &hi))
            return VAL_CXL_BAR_ERR_CFG_READ;
        /* Reconstruct base using BAR field macros to avoid magic masks */
        bar_base64 = (((uint64_t)hi) << 32) |
                     (((uint64_t)((lo >> BAR_BASE_SHIFT) & BAR_BASE_MASK)) << BAR_BASE_SHIFT);
        bar_is64_local = 1;
    } else {
        bar_base64 = ((uint64_t)((lo >> BAR_BASE_SHIFT) & BAR_BASE_MASK)) << BAR_BASE_SHIFT;
        bar_is64_local = 0;
    }

    /* Enable Bus Master Enable and Memory Space Access */
    val_pcie_enable_bme(bdf);
    val_pcie_enable_msa(bdf);

    *bar_base_out = bar_base64;
    if (bar_is64) *bar_is64 = bar_is64_local;
    return (*bar_base_out) ? PCIE_SUCCESS : VAL_CXL_BAR_ERR_ZERO;
}

/**
  @brief   Locate the primary CXL component register block for a PCIe function.

  @param  bdf              Segment/Bus/Device/Function identifier.
  @param  component_base   Output pointer updated with the component base address.

  @return ACS_STATUS_PASS on success.
          ACS_STATUS_SKIP when no component block is advertised.
          ACS_STATUS_ERR on config space or BAR resolution failures.
**/
uint32_t
val_cxl_find_component_register_base(uint32_t bdf, uint64_t *component_base)
{
  uint32_t rl_offset;
  uint32_t status;
  uint32_t hdr1;
  uint32_t dvsec_len;
  uint32_t entries;
  uint32_t entry_base;

  if (component_base == NULL)
    return ACS_STATUS_ERR;

  status = val_pcie_find_vendor_dvsec(bdf,
                                      CXL_DVSEC_VENDOR_ID,
                                      CXL_DVSEC_ID_REGISTER_LOCATOR,
                                      &rl_offset);
  if (status != ACS_STATUS_PASS)
    return status;

  if (val_pcie_read_cfg(bdf, rl_offset + CXL_DVSEC_HDR1_OFFSET, &hdr1))
    return ACS_STATUS_ERR;

  dvsec_len = (hdr1 >> CXL_DVSEC_HDR1_LEN_SHIFT) & CXL_DVSEC_HDR1_LEN_MASK;
  if (dvsec_len < CXL_RL_HDR_OFFSET_ENTRIES)
    return ACS_STATUS_ERR;

  entries = (dvsec_len - CXL_RL_HDR_OFFSET_ENTRIES) / CXL_RL_ENTRY_SIZE;
  entry_base = rl_offset + CXL_RL_HDR_OFFSET_ENTRIES;

  for (uint32_t idx = 0; idx < entries; ++idx) {
    uint32_t entry_offset = entry_base + (idx * CXL_RL_ENTRY_SIZE);
    uint32_t dw0;
    uint32_t reg_off;
    uint8_t bar_num;
    uint16_t block_id;
    uint64_t bar_pa;

    if (val_pcie_read_cfg(bdf, entry_offset + CXL_RL_ENTRY_DW0_OFF, &dw0))
      continue;
    if (val_pcie_read_cfg(bdf, entry_offset + CXL_RL_ENTRY_REG_OFF, &reg_off))
      continue;

    bar_num = (uint8_t)CXL_RL_BAR_NUM(dw0);
    block_id = (uint16_t)((dw0 >> CXL_RL_ENTRY_BLOCKID_SHIFT) & CXL_RL_ENTRY_BLOCKID_MASK);

    if (val_cxl_get_mmio_bar_host_pa(bdf, bar_num, &bar_pa, NULL) != PCIE_SUCCESS)
      continue;

    if (block_id == CXL_REG_BLOCK_COMPONENT) {
      *component_base = bar_pa + (uint64_t)reg_off + CXL_CACHEMEM_PRIMARY_OFFSET;
      return ACS_STATUS_PASS;
    }
  }

  return ACS_STATUS_SKIP;
}

/**
  @brief   Return a human-readable name for a CXL component capability ID.

  @param id    - CXL component capability ID.

  @return  Pointer to a static string describing the capability.
**/
static const char *val_cxl_cap_name(uint16_t id)
{
    switch (id) {
    case CXL_CAPID_COMPONENT_CAP: return "CXL Capability";
    case CXL_CAPID_RAS:           return "CXL RAS Capability";
    case CXL_CAPID_SECURITY:      return "CXL Security Capability";
    case CXL_CAPID_LINK:          return "CXL Link Capability";
    case CXL_CAPID_HDM_DECODER:   return "CXL HDM Decoder Capability";
    case CXL_CAPID_EXT_SECURITY:  return "CXL Extended Security Capability";
    case CXL_CAPID_IDE:           return "CXL IDE Capability";
    case CXL_CAPID_SNOOP_FILTER:  return "CXL Snoop Filter Capability";
    /* Device Register Cap IDs overlap numerically with Component Cap IDs.
       Avoid duplicate case values; treat others as unknown here. */
    default: return "Unknown CXL Capability";
    }
}

/**
  @brief   Return a human-readable name for a CXL device register capability ID.

  @param id    - CXL device capability ID.

  @return  Pointer to a static string describing the device capability.
**/
static const char *val_cxl_dev_cap_name(uint16_t id)
{
    switch (id) {
    case CXL_DEVCAPID_DEVICE_STATUS:     return "Device Status Registers";
    case CXL_DEVCAPID_MAILBOX:           return "Primary Mailbox Registers";
    case CXL_DEVCAPID_MEMORY_DEVICE_STS: return "Memory Device Status Registers";
    default: return "Unknown CXL Device Capability";
    }
}

/* Read one Device Capability header element from the Device Register block
   array (8.2.8.2.1). Each element is 16 bytes, but ID/Version/Offset are
   contained in the first 64-bit word:
     - w0[15:0]  = Capability ID
     - w0[23:16] = Version
     - w0[63:32] = Offset from start of Device Register block
   Returns 0 on success, non-zero on invalid/terminator element. */
/**
  @brief   Read one capability header from a CXL Device Capabilities array.

  @param arr_base  - Base address of the Device Capabilities array (MMIO).
  @param index     - Element index within the array to read.
  @param id_out    - Output pointer for the capability ID.
  @param ver_out   - Output pointer for the capability version.
  @param off_out   - Output pointer for the capability offset from block base.

  @return  0 on success; non-zero if the entry is invalid or terminator.
**/
static int val_cxl_dev_cap_hdr_read(uint64_t arr_base, uint32_t index,
                                    uint16_t *id_out, uint8_t *ver_out, uint32_t *off_out)
{
    uint64_t w0 = val_mmio_read64(arr_base + (uint64_t)index * CXL_DEV_CAP_ELEM_SIZE);
    uint32_t w0_lo = (uint32_t)(w0 & CXL_DEV_CAP_ELEM_W0_OFF_MASK);

    if (w0_lo == 0 || w0_lo == (uint32_t)PCIE_UNKNOWN_RESPONSE)
        return PCIE_CAP_NOT_FOUND;
    if (id_out)  *id_out  = (uint16_t)(w0_lo & CXL_DEV_CAP_ELEM_W0_ID_MASK);
    if (ver_out) *ver_out = (uint8_t)((w0_lo >> CXL_DEV_CAP_ELEM_W0_VER_SHIFT)
                            & CXL_DEV_CAP_ELEM_W0_VER_MASK);
    if (off_out) *off_out = (uint32_t)((w0 >> CXL_DEV_CAP_ELEM_W0_OFF_SHIFT)
                            & CXL_DEV_CAP_ELEM_W0_OFF_MASK);
    return PCIE_SUCCESS;
}



/* Walk a CXL register block (Component or Device), printing all caps it contains. */
/**
  @brief   Walk a CXL register block and print discovered capabilities.

  @param base_pa     - Base physical address of the register block.
  @param block_len   - Length of the block in bytes (0 if unknown/unbounded).
  @param block_id    - CXL Register Block ID (e.g., Component or Device).

  @return  None.
**/
static void val_cxl_walk_reg_block(uint64_t base_pa,
                                   uint32_t block_len,
                                   uint16_t block_id,
                                   CXL_COMPONENT_ENTRY *component)
{
    uint16_t id;
    uint8_t  ver;
    const char *hdr_fmt;
    uint64_t hdr64;
    uint32_t hdr_cnt;
    uint64_t hdr_base;
    const uint32_t elem_sz = CXL_DEV_CAP_ELEM_SIZE; /* bytes per element */
    uint32_t max_cnt_by_len;
    uint32_t i;
    uint16_t id_local;
    uint8_t  ver_local;
    uint32_t cap_off;
    uint32_t arr_hdr;
    uint16_t cap_id;
    uint8_t  cap_ver;
    uint8_t  cachemem_ver;
    uint8_t  arr_sz;
    uint32_t idx;
    uint32_t cap_hdr;

    /* Per CXL 3.1 Table 8-21, Component registers reside in the
       CXL.cachemem Primary range: BAR base + 4KB. Adjust here so that
       the capability walk lands in the correct window. */
    if (block_id == CXL_REG_BLOCK_COMPONENT)
        base_pa += CXL_CACHEMEM_PRIMARY_OFFSET;

    if (block_id == CXL_REG_BLOCK_COMPONENT)
        hdr_fmt = " \t\t\t[CXL Component Registers] base=0x%lx";
    else if (block_id == CXL_REG_BLOCK_DEVICE)
        hdr_fmt = " \t\t\t[CXL Device Registers] base=0x%lx";
    else
        hdr_fmt = " \t\t\t[CXL Register Block] base=0x%lx";
    val_print(ACS_PRINT_INFO, (char8_t *)hdr_fmt, base_pa);

    if (block_len && block_len < CXL_CAP_HDR_SIZE) {
        val_print(ACS_PRINT_INFO, " ERROR in CXL Summary :: Block length too small\n", 0);
        return;
    }

    if (block_id == CXL_REG_BLOCK_DEVICE) {
        /* Device Register Block: starts with Device Capabilities Array (8.2.8) */
        hdr64 = val_mmio_read64(base_pa + CXL_DEV_CAP_ARR_HDR_OFFSET);
        hdr_cnt = (uint32_t)((hdr64 >> CXL_DEV_CAP_ARR_COUNT_SHIFT) & CXL_DEV_CAP_ARR_COUNT_MASK);
        hdr_base = base_pa + CXL_DEV_CAP_ARR_BASE_OFFSET;
        max_cnt_by_len = (block_len > CXL_DEV_CAP_ARR_HDR_SIZE) ?
                         ((block_len - CXL_DEV_CAP_ARR_HDR_SIZE) / elem_sz) : 0;
        if (block_len == 0) {
            if (hdr_cnt > CXL_DEV_CAP_MAX_GUARD) hdr_cnt = CXL_DEV_CAP_MAX_GUARD; /* guard */
        } else if (hdr_cnt > max_cnt_by_len) {
            hdr_cnt = max_cnt_by_len;
        }

        val_print(ACS_PRINT_INFO, "   \t\t\tDevCap Array count=%ld", (uint64_t)hdr_cnt);
        for (i = 0; i < hdr_cnt; ++i) {
        if (val_cxl_dev_cap_hdr_read(hdr_base, i, &id_local, &ver_local, &cap_off))
                break;
            id = id_local; ver = ver_local;
            val_print(ACS_PRINT_INFO, "   \t\t\tDevCap[%ld]: ", (uint64_t)i);
            val_print(ACS_PRINT_INFO, "    \t\t\tID=0x%x ", (uint64_t)id);
            val_print(ACS_PRINT_INFO, "    \t\t\t(%a) ", (uint64_t)val_cxl_dev_cap_name(id));
            val_print(ACS_PRINT_INFO, "    \t\t\t\tVer=%d ", (uint64_t)ver);
            val_print(ACS_PRINT_INFO, "    \t\t\t\tOff=0x%x", (uint64_t)cap_off);
            /* Bounds check for capability structure */
            if (block_len && cap_off >= block_len) {
                val_print(ACS_PRINT_INFO, " ERROR in CXL Summary:: -> Cap offset out of range", 0);
            }
            /* Optional: read capability-specific header at base_pa + cap_off if needed */
            /* Example (do not print raw here unless required):
               uint32_t cap_hdr0 = mmio_read32(base_pa + cap_off);
            */
        }
        return;
    }

    /* Component Register Block (8.2.4): capability array within 4KB primary region */
    arr_hdr     = val_mmio_read(base_pa + CXL_COMPONENT_CAP_ARRAY_OFFSET);
    cap_id       = CXL_CAP_HDR_CAPID(arr_hdr);
    cap_ver      = CXL_CAP_HDR_VER(arr_hdr);
    cachemem_ver = CXL_CAP_HDR_CACHEMEM_VER(arr_hdr);
    arr_sz       = CXL_CAP_ARRAY_ENTRIES(arr_hdr);

    val_print(ACS_PRINT_INFO,  "   \t\t\t\tCXL_Capability_Header: ID=0x%x", (uint64_t)cap_id);
    val_print(ACS_PRINT_INFO,  "   \t\t\t\tPrimary Array: CXL.cachemem v%ld",
                (uint64_t)cachemem_ver);
    val_print(ACS_PRINT_INFO,  "   \t\t\t\tCXL Cap v%ld", (uint64_t)cap_ver);
    val_print(ACS_PRINT_INFO,  "   \t\t\t\tentries=%ld", (uint64_t)arr_sz);

    for (idx = 1; idx <= arr_sz; ++idx) {
        cap_hdr = val_mmio_read(base_pa + (uint64_t)idx * CXL_CAP_HDR_SIZE);
        if (cap_hdr == PCIE_UNKNOWN_RESPONSE || cap_hdr == 0x00000000)
            continue;

        id  = CXL_CAP_HDR_CAPID(cap_hdr);
        ver = CXL_CAP_HDR_VER(cap_hdr);
        uint32_t cap_ptr = CXL_CAP_HDR_POINTER(cap_hdr);
        uint64_t cap_base = base_pa + (uint64_t)cap_ptr;

        val_print(ACS_PRINT_INFO, "   \t\t\tCapID=0x%x ", (uint64_t)id);
        val_print(ACS_PRINT_INFO, "    \t\t\t(%a) ", (uint64_t)val_cxl_cap_name(id));
        val_print(ACS_PRINT_INFO, "    \t\t\t\tVer=%d ", (uint64_t)ver);
        val_print(ACS_PRINT_INFO, "    \t\t\t\t@+0x%lx", (uint64_t)(idx * CXL_CAP_HDR_SIZE));

        if ((component != NULL) && (block_id == CXL_REG_BLOCK_COMPONENT) &&
            (id == CXL_CAPID_HDM_DECODER))
            val_cxl_parse_hdm_capability(component, cap_base);

        /* Optional: read capability-specific header at base_pa + idx*4 if needed */
        /* Example (do not print raw here unless required):
           uint32_t cap_hdr0 = mmio_read32(base_pa + idx*4);
        */
    }
}

/* Consume a Register Locator DVSEC and walk the blocks it exposes */
/**
  @brief   Parse a CXL Register Locator DVSEC and walk exposed register blocks.

  @param bdf        - BDF of the device.
  @param ecap_off   - Offset to the Register Locator DVSEC in config space.

  @return  None.
**/
static void val_cxl_parse_register_locator(uint32_t bdf,
                                           uint32_t ecap_off,
                                           uint32_t dp_type)
{
    uint32_t dvsec_hdr1;
    uint16_t dvsec_vendor;
    uint32_t dvsec_rev, dvsec_len, num_entries, ent_off_cfg, i;
    uint32_t reg0, off;
    uint16_t block_id;
    uint8_t  bir;
    uint8_t  bar_num;
    uint32_t bar_st;
    uint64_t reg_off = 0ull, bar_base, block_pa;
    uint32_t      bar_is64;
    const char *blkname;
    CXL_COMPONENT_ENTRY *component;

    component = val_cxl_get_or_create_component(bdf);

    if (component)
        val_cxl_assign_component_role(component, dp_type);

    if (val_pcie_read_cfg(bdf, ecap_off + CXL_DVSEC_HDR1_OFFSET, &dvsec_hdr1)) {
        val_print(ACS_PRINT_INFO, " ERROR in CXL Summary :: DVSEC Header1 read failed", 0);
        return;
    }

    dvsec_vendor = (uint16_t)(dvsec_hdr1 & CXL_DVSEC_HDR1_VENDOR_ID_MASK);
    dvsec_rev    = (dvsec_hdr1 >> CXL_DVSEC_HDR1_REV_SHIFT) & CXL_DVSEC_HDR1_REV_MASK;
    dvsec_len    = (dvsec_hdr1 >> CXL_DVSEC_HDR1_LEN_SHIFT) & CXL_DVSEC_HDR1_LEN_MASK;

    val_print(ACS_PRINT_INFO, " \tDVSEC Header 1 : 0x%lx", (uint64_t)dvsec_hdr1);
    val_print(ACS_PRINT_INFO, "    \tVendor ID    : 0x%lx", (uint64_t)dvsec_vendor);
    val_print(ACS_PRINT_INFO, "    \tRevision     : 0x%lx", (uint64_t)dvsec_rev);
    val_print(ACS_PRINT_INFO, "    \tLength (B)   : 0x%lx", (uint64_t)dvsec_len);

    if (dvsec_len < CXL_RL_HDR_OFFSET_ENTRIES ||
        ((dvsec_len - CXL_RL_HDR_OFFSET_ENTRIES) % CXL_RL_ENTRY_SIZE) != 0) {
        val_print(ACS_PRINT_INFO, " ERROR in CXL Summary :: RL: Bad DVSEC Length 0x%lx",
                  (uint64_t)dvsec_len);
        return;
    }

    num_entries = (dvsec_len - CXL_RL_HDR_OFFSET_ENTRIES) / CXL_RL_ENTRY_SIZE;
    val_print(ACS_PRINT_INFO, " \t\tRegister Locator: %ld entries", (uint64_t)num_entries);


    ent_off_cfg = ecap_off + CXL_RL_HDR_OFFSET_ENTRIES;
    for (i = 0; i < num_entries; i++, ent_off_cfg += CXL_RL_ENTRY_SIZE) {
        if (val_pcie_read_cfg(bdf, ent_off_cfg + CXL_RL_ENTRY_DW0_OFF, &reg0) ||
            val_pcie_read_cfg(bdf, ent_off_cfg + CXL_RL_ENTRY_REG_OFF, &off)) {
            val_print(ACS_PRINT_INFO, " ERROR in CXL Summary :: RL[%ld]: entry read failed",
                        (uint64_t)i);
            continue;
        }

        /* DW0: [7:0]=BIR, [15:8]=BlockID, [31:16]=RSVD */
        bir      = (uint8_t)((reg0 >> CXL_RL_ENTRY_BIR_SHIFT)    & CXL_RL_ENTRY_BIR_MASK);
        block_id = (uint8_t)((reg0 >> CXL_RL_ENTRY_BLOCKID_SHIFT) & CXL_RL_ENTRY_BLOCKID_MASK);
        bar_num = (uint8_t)CXL_RL_BAR_NUM(bir);
        reg_off = (uint64_t)off; /* RL entry is 8B: 32b offset */
        {
            bar_st = val_cxl_get_mmio_bar_host_pa(bdf, bar_num, &bar_base, &bar_is64);
            if (bar_st != PCIE_SUCCESS) {
                val_print(ACS_PRINT_INFO, " ERROR in CXL Summary :: RL[%ld]: ", (uint64_t)i);
                val_print(ACS_PRINT_INFO, " ERROR in CXL Summary :: BAR%ld not usable ",
                            (uint64_t)bar_num);
                switch (bar_st) {
                case VAL_CXL_BAR_ERR_INVALID_INDEX:
                    val_print(ACS_PRINT_INFO, " ERROR in CXL Summary :: -> Invalid BAR index", 0);
                    break;
                case VAL_CXL_BAR_ERR_CFG_READ:
                    val_print(ACS_PRINT_INFO, " ERROR in CXL Summary :: -> CFG read failed", 0);
                    break;
                case VAL_CXL_BAR_ERR_NOT_MMIO:
                    val_print(ACS_PRINT_INFO, " ERROR in CXL Summary :: -> BAR not MMIO type", 0);
                    break;
                case VAL_CXL_BAR_ERR_ZERO:
                    val_print(ACS_PRINT_INFO, " ERROR in CXL Summary :: -> BAR is zero", 0);
                    break;
                default:
                    break;
                }
                continue;
            }
        }
        block_pa = bar_base + reg_off;
        val_print(ACS_PRINT_INFO, "  \tRL reg0=0x%lx ", (uint64_t)reg0);
        val_print(ACS_PRINT_INFO, "  \toff=0x%lx", (uint64_t)off);
        val_print(ACS_PRINT_INFO, "  \tBlockID=0x%x ", (uint64_t)block_id);
        val_print(ACS_PRINT_INFO, "  \tBIR=%d", (uint64_t)CXL_RL_BAR_NUM(bir));

        blkname =
            (block_id == CXL_REG_BLOCK_COMPONENT) ? "CXL Component Registers" :
            (block_id == CXL_REG_BLOCK_DEVICE)    ? "CXL Device Registers" :
            (block_id == CXL_REG_BLOCK_VENDOR_SPECIFIC) ? "Vendor-Specific Reg Block" :
                                                    "CXL Register Block";

        val_print(ACS_PRINT_INFO, "  \tRL[%ld]: ", (uint64_t)i);
        val_print(ACS_PRINT_INFO, "  \t\tBlockID=0x%x ", (uint64_t)block_id);
        val_print(ACS_PRINT_INFO, "  \t\t(%a) ", (uint64_t)blkname);
        val_print(ACS_PRINT_INFO, "  \t\tBIR=%ld ", (uint64_t)CXL_RL_BAR_NUM(bir));
        val_print(ACS_PRINT_INFO, "  \t\toff=0x%lx ", (uint64_t)reg_off);

        if (component && block_id == CXL_REG_BLOCK_COMPONENT) {
            component->component_reg_base   = block_pa + CXL_CACHEMEM_PRIMARY_OFFSET;
            component->component_reg_length = CXL_CACHEMEM_PRIMARY_SIZE;
        } else if (component && block_id == CXL_REG_BLOCK_DEVICE) {
            component->device_reg_base    = block_pa;
            component->device_reg_length  = CXL_CACHEMEM_PRIMARY_SIZE;
        }

        /* Walk capabilities; length unknown in RL entry, pass 0 */
        val_cxl_walk_reg_block(block_pa, 0, block_id, component);
    }
}

/**
  @brief   Parse the PCIe DVSEC for CXL Devices and update component flags.

  @param bdf        - BDF of the device exposing the DVSEC.
  @param ecap_off   - Offset to the DVSEC in PCIe config space.
  @param dp_type    - PCIe device/port type.

  @return  None.
**/
static void val_cxl_parse_device_dvsec(uint32_t bdf,
                                       uint32_t ecap_off,
                                       uint32_t dp_type)
{
    CXL_COMPONENT_ENTRY *component;
    uint32_t hdr2;
    uint16_t cxl_cap;
    uint32_t cache_capable;
    uint32_t io_capable;
    uint32_t mem_capable;

    component = val_cxl_get_or_create_component(bdf);
    if (component == NULL)
        return;

    val_cxl_assign_component_role(component, dp_type);

    if (val_pcie_read_cfg(bdf, ecap_off + CXL_DVSEC_HDR2_OFFSET, &hdr2))
        return;

    cxl_cap = (uint16_t)((hdr2 >> CXL_DVSEC_CXL_CAPABILITY_SHIFT) &
                         CXL_DVSEC_CXL_CAPABILITY_MASK);

    cache_capable = ((cxl_cap & CXL_DVSEC_CXL_CAP_CACHE_CAPABLE) != 0u) ? 1u : 0u;
    io_capable = ((cxl_cap & CXL_DVSEC_CXL_CAP_IO_CAPABLE) != 0u) ? 1u : 0u;
    mem_capable = ((cxl_cap & CXL_DVSEC_CXL_CAP_MEM_CAPABLE) != 0u) ? 1u : 0u;

    if (io_capable != 0u) {
        if (cache_capable != 0u) {
            if (mem_capable != 0u)
                component->device_type = CXL_DEVICE_TYPE_TYPE2;
            else
                component->device_type = CXL_DEVICE_TYPE_TYPE1;
        } else if (mem_capable != 0u) {
            component->device_type = CXL_DEVICE_TYPE_TYPE3;
        }
    }
}

/**
  @brief   Enable CXL.mem in the CXL Device DVSEC control register.

  @param  bdf  PCIe identifier of the device to program.

  @return ACS_STATUS_PASS when enabled or already set.
          ACS_STATUS_FAIL when enable is not set after programming.
          ACS_STATUS_ERR on config space access failures.
**/
uint32_t
val_cxl_enable_mem(uint32_t bdf)
{
  uint32_t dvsec_offset;
  uint32_t ctrl;
  uint32_t status;

  /* Locate the CXL Device DVSEC to enable CXL.mem. */
  status = val_pcie_find_vendor_dvsec(bdf,
                                      CXL_DVSEC_VENDOR_ID,
                                      CXL_DVSEC_ID_DEVICE,
                                      &dvsec_offset);
  if (status != ACS_STATUS_PASS) {
    val_print(ACS_PRINT_ERR, " CXL: CXL Device DVSEC missing", 0);
    return status;
  }

  /* Read the CXL DVSEC control register. */
  if (val_pcie_read_cfg(bdf, dvsec_offset + CXL_DVSEC_CTRL_OFFSET, &ctrl)) {
    val_print(ACS_PRINT_ERR, " CXL: DVSEC control read failed", 0);
    return ACS_STATUS_ERR;
  }

  /* Set the CXL.mem enable bit if needed. */
  if ((ctrl & CXL_DVSEC_MEM_ENABLE) == 0u) {
    ctrl |= CXL_DVSEC_MEM_ENABLE;
    val_pcie_write_cfg(bdf, dvsec_offset + CXL_DVSEC_CTRL_OFFSET, ctrl);

    if (val_pcie_read_cfg(bdf, dvsec_offset + CXL_DVSEC_CTRL_OFFSET, &ctrl)) {
      val_print(ACS_PRINT_ERR, " CXL: DVSEC control verify failed", 0);
      return ACS_STATUS_ERR;
    }

    if ((ctrl & CXL_DVSEC_MEM_ENABLE) == 0u) {
      val_print(ACS_PRINT_ERR, " CXL: CXL.mem enable not set", 0);
      return ACS_STATUS_FAIL;
    }
  }

  return ACS_STATUS_PASS;
}

/**
  @brief   Best-effort reset to clear CXL TSP configuration lock state.

  The helper resets the endpoint (preferring FLR, falling back to Secondary Bus
  Reset) and restores PCIe configuration (BARs + command bits) so subsequent
  tests can continue to access device MMIO.

  @param  rp_bdf       Root port BDF used for Secondary Bus Reset fallback.
  @param  endpoint_bdf Endpoint BDF to reset and restore.
  @param  cfg          Optional endpoint config snapshot to restore. When NULL or
                       invalid, the helper snapshots config space before resetting.

  @return ACS_STATUS_PASS on success.
          ACS_STATUS_FAIL when config space does not respond after reset.
          ACS_STATUS_ERR on failures to snapshot or trigger the reset.
**/
uint32_t
val_cxl_unlock_tsp_best_effort(uint32_t rp_bdf,
                               uint32_t endpoint_bdf,
                               const struct pcie_endpoint_cfg *cfg)
{
  PCIE_ENDPOINT_CFG snapshot;
  const PCIE_ENDPOINT_CFG *restore_cfg = cfg;
  uint32_t status;

  if ((restore_cfg == NULL) || (restore_cfg->valid == 0u)) {
    status = val_pcie_save_endpoint_cfg(endpoint_bdf, &snapshot);
    if (status != ACS_STATUS_PASS)
      return ACS_STATUS_ERR;
    restore_cfg = &snapshot;
  }

  status = val_pcie_reset_endpoint(rp_bdf, endpoint_bdf);
  if (status != ACS_STATUS_PASS)
    return status;

  val_pcie_restore_endpoint_cfg(endpoint_bdf, restore_cfg);
  return ACS_STATUS_PASS;
}

/**
  @brief   Quickly determine whether a PCIe function advertises any CXL DVSECs.

  @param  bdf  PCIe identifier of the device to probe.

  @return ACS_STATUS_PASS when a CXL DVSEC is present.
          ACS_STATUS_SKIP when none are found.
          ACS_STATUS_ERR on config space access failures.
**/
uint32_t
val_cxl_device_is_cxl(uint32_t bdf)
{
  uint32_t next_cap_offset = PCIE_ECAP_START;
  uint32_t prev_off = PCIE_UNKNOWN_RESPONSE;
  uint32_t hdr0;

  while (next_cap_offset) {
    if (next_cap_offset == prev_off)
      break;

    prev_off = next_cap_offset;

    if (val_pcie_read_cfg(bdf, next_cap_offset, &hdr0))
      return ACS_STATUS_ERR;

    if ((hdr0 == 0u) || (hdr0 == PCIE_UNKNOWN_RESPONSE))
      break;

    if ((hdr0 & PCIE_ECAP_CIDR_MASK) == ECID_DVSEC) {
      uint32_t hdr1;

      if (val_pcie_read_cfg(bdf, next_cap_offset + CXL_DVSEC_HDR1_OFFSET, &hdr1))
        return ACS_STATUS_ERR;

      if ((hdr1 & CXL_DVSEC_HDR1_VENDOR_ID_MASK) == CXL_DVSEC_VENDOR_ID)
        return ACS_STATUS_PASS;
    }

    next_cap_offset = (hdr0 >> PCIE_ECAP_NCPR_SHIFT) & PCIE_ECAP_NCPR_MASK;
  }

  return ACS_STATUS_SKIP;
}

/**
  @brief   Populate the global CXL component table for a discovered CXL function.

  @param  bdf  PCIe identifier of the device to register.

  @return ACS_STATUS_PASS when the component entry is created/populated.
          ACS_STATUS_SKIP when no CXL capabilities are detected.
          ACS_STATUS_ERR on allocation or config space errors.
**/
uint32_t
val_cxl_component_add(uint32_t bdf)
{
  uint32_t status;
  uint32_t next_cap_offset;
  uint32_t prev_off;
  uint32_t hdr0;
  uint32_t dp_type;
  uint32_t found = 0;

  status = val_cxl_create_component_table();
  if (status != ACS_STATUS_PASS)
    return ACS_STATUS_ERR;

  next_cap_offset = PCIE_ECAP_START;
  prev_off = PCIE_UNKNOWN_RESPONSE;
  dp_type = val_pcie_device_port_type(bdf);

  while (next_cap_offset) {
    uint32_t hdr1;
    uint32_t hdr2;
    uint32_t next_ptr;
    uint16_t dvsec_id;

    if (next_cap_offset == prev_off)
      break;

    prev_off = next_cap_offset;

    if (val_pcie_read_cfg(bdf, next_cap_offset, &hdr0))
      return ACS_STATUS_ERR;

    next_ptr = (hdr0 >> PCIE_ECAP_NCPR_SHIFT) & PCIE_ECAP_NCPR_MASK;

    if ((hdr0 == 0u) || (hdr0 == PCIE_UNKNOWN_RESPONSE)) {
      next_cap_offset = next_ptr;
      continue;
    }

    if ((hdr0 & PCIE_ECAP_CIDR_MASK) != ECID_DVSEC) {
      next_cap_offset = next_ptr;
      continue;
    }

    if (val_pcie_read_cfg(bdf, next_cap_offset + CXL_DVSEC_HDR1_OFFSET, &hdr1))
      return ACS_STATUS_ERR;

    if ((hdr1 & CXL_DVSEC_HDR1_VENDOR_ID_MASK) != CXL_DVSEC_VENDOR_ID) {
      next_cap_offset = next_ptr;
      continue;
    }

    if (val_pcie_read_cfg(bdf, next_cap_offset + CXL_DVSEC_HDR2_OFFSET, &hdr2))
      return ACS_STATUS_ERR;

    dvsec_id = (uint16_t)(hdr2 & CXL_DVSEC_HDR2_ID_MASK);
    found = 1;

    if (val_cxl_get_or_create_component(bdf) == NULL)
      return ACS_STATUS_ERR;

    val_print(ACS_PRINT_INFO, " BDF: 0x%lx  :: ", (uint64_t)bdf);
    val_print(ACS_PRINT_INFO, " Device type : 0x%lx", (uint64_t)dp_type);
    val_print(ACS_PRINT_INFO, " \tFound CXL DVSEC (ID=0x%x)", (uint64_t)dvsec_id);

    switch (dvsec_id) {
    case CXL_DVSEC_ID_DEVICE:
      val_cxl_parse_device_dvsec(bdf, next_cap_offset, dp_type);
      break;
    case CXL_DVSEC_ID_REGISTER_LOCATOR:
      val_cxl_parse_register_locator(bdf, next_cap_offset, dp_type);
      break;
    default:
      break;
    }

    next_cap_offset = next_ptr;
  }

  if (!found)
    return ACS_STATUS_SKIP;

  if (pal_cxl_is_chi_c2c_supported(bdf) != 0u) {
    CXL_COMPONENT_ENTRY *component = val_cxl_get_or_create_component(bdf);
    if (component == NULL)
      return ACS_STATUS_ERR;

    component->chi_c2c_supported = 1u;
    val_cxl_assign_component_role(component, dp_type);
  }

  if (g_cxl_info_table != NULL)
    val_cxl_assign_host_bridge_indices();

  return ACS_STATUS_PASS;
}

/**
  @brief   Print a diagnostic summary of the discovered CXL components.
**/
void
val_cxl_print_component_summary(void)
{
  if (g_cxl_component_table == NULL) {
    val_print(ACS_PRINT_INFO, " CXL_COMPONENT: Discovered 0 components", 0);
    return;
  }

  uint32_t total            = g_cxl_component_table->num_entries;
  uint32_t role_root_port   = 0;
  uint32_t role_endpoint    = 0;
  uint32_t type_unknown     = 0;
  uint32_t type1_devices    = 0;
  uint32_t type2_devices    = 0;
  uint32_t type3_devices    = 0;
  uint32_t chi_c2c_count    = 0;

  for (uint32_t idx = 0; idx < total; idx++) {
    const CXL_COMPONENT_ENTRY *entry = &g_cxl_component_table->component[idx];

    if (entry->chi_c2c_supported != 0u)
      chi_c2c_count++;

    switch (entry->role) {
    case CXL_COMPONENT_ROLE_ROOT_PORT:
      role_root_port++;
      break;
    case CXL_COMPONENT_ROLE_ENDPOINT:
      role_endpoint++;
      break;
    default:
      break;
    }

    switch (entry->device_type) {
    case CXL_DEVICE_TYPE_TYPE1:
      type1_devices++;
      break;
    case CXL_DEVICE_TYPE_TYPE2:
      type2_devices++;
      break;
    case CXL_DEVICE_TYPE_TYPE3:
      type3_devices++;
      break;
    default:
      type_unknown++;
      break;
    }
  }

  val_print(ACS_PRINT_ALWAYS,
            "\n CXL_INFO: Number of components       : %4u\n", (uint64_t)total);
  val_print(ACS_PRINT_ALWAYS,
            " CXL_INFO: Root Ports                 : %4u\n", (uint64_t)role_root_port);
  val_print(ACS_PRINT_ALWAYS,
            " CXL_INFO: Devices (Endpoints)        : %4u\n", (uint64_t)role_endpoint);
  val_print(ACS_PRINT_ALWAYS,
            " CXL_INFO: CHI-C2C Capable Components : %4u\n", (uint64_t)chi_c2c_count);
  val_print(ACS_PRINT_ALWAYS,
            " CXL_INFO: Type1 Devices              : %4u\n", (uint64_t)type1_devices);
  val_print(ACS_PRINT_ALWAYS,
            " CXL_INFO: Type2 Devices              : %4u\n", (uint64_t)type2_devices);
  val_print(ACS_PRINT_ALWAYS,
            " CXL_INFO: Type3 Devices              : %4u", (uint64_t)type3_devices);

  val_print(ACS_PRINT_INFO,
            " CXL_COMPONENT: Discovered %u components",
            (uint64_t)total);

  for (uint32_t idx = 0; idx < g_cxl_component_table->num_entries; idx++) {
    const CXL_COMPONENT_ENTRY *entry = &g_cxl_component_table->component[idx];
    const char *role_str = val_cxl_role_name(entry->role);
    const char *dtype_str = val_cxl_device_type_name(entry->device_type);

    val_print(ACS_PRINT_INFO, "   Component Index : %u", (uint64_t)idx);
    val_print(ACS_PRINT_INFO, "     BDF           : 0x%x", (uint64_t)entry->bdf);
    val_print(ACS_PRINT_INFO, "     Role          : %a", (uint64_t)role_str);
    val_print(ACS_PRINT_INFO, "     Device Type   : %a", (uint64_t)dtype_str);

    if (entry->component_reg_base) {
      val_print(ACS_PRINT_INFO, "     CompReg Base  : 0x%llx",
                entry->component_reg_base);
      val_print(ACS_PRINT_INFO, "     CompReg Len   : 0x%llx",
                entry->component_reg_length);
    }

    val_print(ACS_PRINT_INFO, "   HDM Decoder Count  : %u", entry->hdm_decoder_count);
  }
}


/**
  @brief   Create the VAL CXL info table by delegating to the platform PAL.

  @param  cxl_info_table  Caller-provided buffer to populate.
**/
void
val_cxl_create_info_table(uint64_t *cxl_info_table)
{
  if (cxl_info_table == NULL) {
    val_print(ACS_PRINT_ERR, " CXL_INFO: Input table pointer is NULL ", 0);
    return;
  }

  g_cxl_info_table = (CXL_INFO_TABLE *)cxl_info_table;
  pal_cxl_create_info_table(g_cxl_info_table);

  /* Print parsed informationi*/
  uint32_t num_entries = g_cxl_info_table->num_entries;

  val_print(ACS_PRINT_ALWAYS,
            " CXL_INFO: Number of CXL host bridges : %4u\n",
            num_entries);

  if (num_entries == 0) {
    val_print(ACS_PRINT_WARN, " CXL_INFO: No CXL host bridges found\n", 0);
    return;
  }

  for (uint32_t index = 0; index < num_entries; index++) {
    CXL_INFO_BLOCK *entry = &g_cxl_info_table->device[index];

    if (val_cxl_host_discover_capabilities(entry) != ACS_STATUS_PASS) {
      val_print(ACS_PRINT_ERR,
                " CXL_INFO: Failed to map host bridge component window (UID 0x%x)",
                entry->uid);
    }

    val_print(ACS_PRINT_INFO, " CXL_INFO: Host Bridge[%u]", index);
    val_print(ACS_PRINT_INFO, "   UID                : 0x%x", entry->uid);
    val_print(ACS_PRINT_INFO, "   Component Type     : 0x%x", entry->component_reg_type);
    val_print(ACS_PRINT_INFO, "   Component Base     : 0x%llx", entry->component_reg_base);
    val_print(ACS_PRINT_INFO, "   Component Length   : 0x%llx", entry->component_reg_length);
    val_print(ACS_PRINT_INFO, "   CFMWS Count        : %u", entry->cfmws_count);

    for (uint32_t window = 0;
         window < entry->cfmws_count && window < CXL_MAX_CFMWS_WINDOWS;
         window++) {
      val_print(ACS_PRINT_INFO, "     CFMWS Index       : %u", window);
      val_print(ACS_PRINT_INFO, "       Base            : 0x%llx",
                entry->cfmws_base[window]);
      val_print(ACS_PRINT_INFO, "       Length          : 0x%llx",
                entry->cfmws_length[window]);
    }

    val_print(ACS_PRINT_INFO, "   HDM Decoder Count  : %u", entry->hdm_decoder_count);
  }
}

/**
  @brief   Release VAL-side state associated with the CXL info table.
**/
void
val_cxl_free_info_table(void)
{
  g_cxl_info_table = NULL;
  val_cxl_free_component_table();
}

/**
  @brief   Fetch a value from the cached CXL info table.

  @param  type   Selector from CXL_INFO_e.
  @param  index  Host bridge index for per-entry selectors.

  @return Requested value or 0 on failure.
**/
uint64_t
val_cxl_get_info(CXL_INFO_e type, uint32_t index)
{
  if (g_cxl_info_table == NULL) {
    val_print(ACS_PRINT_ERR, " GET_CXL_INFO: CXL info table is not created ", 0);
    return 0;
  }

  if ((type != CXL_INFO_NUM_DEVICES) && (index >= g_cxl_info_table->num_entries)) {
    val_print(ACS_PRINT_ERR, " GET_CXL_INFO: Invalid index %d ", index);
    return 0;
  }

  switch (type) {
  case CXL_INFO_NUM_DEVICES:
    return g_cxl_info_table->num_entries;
  case CXL_INFO_COMPONENT_BASE:
    return g_cxl_info_table->device[index].component_reg_base;
  case CXL_INFO_COMPONENT_LENGTH:
    return g_cxl_info_table->device[index].component_reg_length;
  case CXL_INFO_COMPONENT_TYPE:
    return g_cxl_info_table->device[index].component_reg_type;
  case CXL_INFO_HDM_COUNT:
    return g_cxl_info_table->device[index].hdm_decoder_count;
  case CXL_INFO_UID:
    return g_cxl_info_table->device[index].uid;
  default:
    val_print(ACS_PRINT_ERR, " GET_CXL_INFO: Unsupported info type %d ", type);
    break;
  }

  return 0;
}

/**
  @brief   Retrieve HDM decoder base and length for a given host bridge.

  @param  index          Host bridge index within the info table.
  @param  decoder_index  Decoder slot to query.
  @param  base           Output pointer for decoder base address.
  @param  length         Output pointer for decoder region length.

  @return 0 on success, non-zero on failure.
**/
uint32_t
val_cxl_get_decoder(uint32_t index,
                    uint32_t decoder_index,
                    uint64_t *base,
                    uint64_t *length)
{
  uint64_t cap_base;
  uint32_t base_low;
  uint32_t base_high;
  uint32_t size_low;
  uint32_t size_high;
  CXL_INFO_BLOCK *entry;
  uint32_t status;

  if (base != NULL)
    *base = 0u;
  if (length != NULL)
    *length = 0u;

  if ((g_cxl_info_table == NULL) || (base == NULL) || (length == NULL))
    return 1;

  if (index >= g_cxl_info_table->num_entries)
    return 1;

  entry = &g_cxl_info_table->device[index];

  if ((entry->component_reg_base == 0) ||
      (decoder_index >= entry->hdm_decoder_count))
    return 1;

  status = val_cxl_find_capability(entry->component_reg_base,
                                   CXL_CAPID_HDM_DECODER,
                                   &cap_base);
  if (status != ACS_STATUS_PASS)
    return 1;

  base_low = val_mmio_read(cap_base + CXL_HDM_DECODER_BASE_LOW(decoder_index));
  base_high = val_mmio_read(cap_base + CXL_HDM_DECODER_BASE_HIGH(decoder_index));
  size_low = val_mmio_read(cap_base + CXL_HDM_DECODER_SIZE_LOW(decoder_index));
  size_high = val_mmio_read(cap_base + CXL_HDM_DECODER_SIZE_HIGH(decoder_index));

  *base = val_cxl_decode_hdm_value(base_low, base_high);
  *length = val_cxl_decode_hdm_value(size_low, size_high);
  return 0;
}

/**
  @brief  Fetch a component HDM decoder range.

  @param  component_index  Index within the CXL component table.
  @param  decoder_index    Decoder slot to query.
  @param  base             Pointer to receive the decoded base.
  @param  length           Pointer to receive the decoded length.

  @return 0 on success, non-zero on failure.
**/
uint32_t
val_cxl_get_component_decoder(uint32_t component_index,
                              uint32_t decoder_index,
                              uint64_t *base,
                              uint64_t *length)
{
  const CXL_COMPONENT_ENTRY *component;
  uint64_t cap_base;
  uint32_t base_low;
  uint32_t base_high;
  uint32_t size_low;
  uint32_t size_high;
  uint32_t status;

  if (base != NULL)
    *base = 0u;
  if (length != NULL)
    *length = 0u;

  if ((base == NULL) || (length == NULL))
    return 1;

  component = val_cxl_get_component_entry(component_index);
  if ((component == NULL) || (component->component_reg_base == 0))
    return 1;

  if (decoder_index >= component->hdm_decoder_count)
    return 1;

  status = val_cxl_find_capability(component->component_reg_base,
                                   CXL_CAPID_HDM_DECODER,
                                   &cap_base);
  if (status != ACS_STATUS_PASS)
    return 1;

  base_low = val_mmio_read(cap_base + CXL_HDM_DECODER_BASE_LOW(decoder_index));
  base_high = val_mmio_read(cap_base + CXL_HDM_DECODER_BASE_HIGH(decoder_index));
  size_low = val_mmio_read(cap_base + CXL_HDM_DECODER_SIZE_LOW(decoder_index));
  size_high = val_mmio_read(cap_base + CXL_HDM_DECODER_SIZE_HIGH(decoder_index));

  *base = val_cxl_decode_hdm_value(base_low, base_high);
  *length = val_cxl_decode_hdm_value(size_low, size_high);
  return 0;
}

/**
  @brief  Return the number of CFMWS windows for a host.

  @param  index  Index within the firmware CXL info table.

  @return Count of CFMWS windows, or 0 on error.
**/
uint32_t
val_cxl_get_cfmws_count(uint32_t index)
{
  if (g_cxl_info_table == NULL)
    return 0;

  if (index >= g_cxl_info_table->num_entries)
    return 0;

  CXL_INFO_BLOCK *entry = &g_cxl_info_table->device[index];
  uint32_t count = entry->cfmws_count;
  uint32_t max_windows = (uint32_t)(sizeof(entry->cfmws_base) /
                                    sizeof(entry->cfmws_base[0]));

  if (count > max_windows)
    count = max_windows;

  return count;
}

/**
  @brief  Fetch a CFMWS window base/length pair for a host.

  @param  index         Index within the firmware CXL info table.
  @param  window_index  Window slot to query.
  @param  base          Pointer to receive the window base.
  @param  length        Pointer to receive the window length.

  @return 0 on success, non-zero on failure.
**/
uint32_t
val_cxl_get_cfmws(uint32_t index,
                  uint32_t window_index,
                  uint64_t *base,
                  uint64_t *length)
{
  if ((g_cxl_info_table == NULL) || (base == NULL) || (length == NULL))
    return 1;

  if (index >= g_cxl_info_table->num_entries)
    return 1;

  CXL_INFO_BLOCK *entry = &g_cxl_info_table->device[index];

  if (window_index >= entry->cfmws_count)
    return 1;

  if (window_index >= (uint32_t)(sizeof(entry->cfmws_base) /
                                 sizeof(entry->cfmws_base[0])))
    return 1;

  *base   = entry->cfmws_base[window_index];
  *length = entry->cfmws_length[window_index];
  return 0;
}

/**
  @brief   Program an HDM decoder for a host bridge CHBCR window.

  @param  host_index     Index within the firmware CXL info table.
  @param  decoder_index  Decoder slot to configure.
  @param  base           HPA base aligned to 256MB.
  @param  size           Window length aligned to 256MB.

  @return Status code propagated from the programming helper.
**/
uint32_t
val_cxl_program_host_decoder(uint32_t host_index,
                             uint32_t decoder_index,
                             uint64_t base,
                             uint64_t size)
{
  uint64_t cap_base;
  CXL_INFO_BLOCK *entry;
  uint32_t status;

  if (g_cxl_info_table == NULL) {
    val_print(ACS_PRINT_ERR, " CXL_HDM: info table not initialised", 0);
    return ACS_STATUS_ERR;
  }

  if (host_index >= g_cxl_info_table->num_entries) {
    val_print(ACS_PRINT_ERR, " CXL_HDM: invalid host index %u", host_index);
    return ACS_STATUS_ERR;
  }

  entry = &g_cxl_info_table->device[host_index];
  if (entry->component_reg_base == 0) {
    val_print(ACS_PRINT_ERR,
              " CXL_HDM: component base missing for host %u",
              host_index);
    return ACS_STATUS_ERR;
  }

  status = val_cxl_find_capability(entry->component_reg_base,
                                   CXL_CAPID_HDM_DECODER,
                                   &cap_base);
  if (status != ACS_STATUS_PASS) {
    val_print(ACS_PRINT_ERR,
              " CXL_HDM: HDM capability lookup failed for host %u",
              host_index);
    return status;
  }

  status = val_cxl_program_decoder_common(cap_base, decoder_index, base, size);
  if (status != ACS_STATUS_PASS) {
    val_print(ACS_PRINT_ERR,
              " CXL_HDM: decoder programming failed for host %u",
              host_index);
    val_print(ACS_PRINT_ERR,
              " CXL_HDM: decoder index %u",
              decoder_index);
    val_print(ACS_PRINT_ERR,
              " CXL_HDM: helper returned status %d",
              status);
  }

  if ((status == ACS_STATUS_PASS) &&
      (entry->hdm_decoder_count <= decoder_index))
    entry->hdm_decoder_count = decoder_index + 1u;

  return status;
}

/**
  @brief   Program an HDM decoder for a discovered CXL component.

  @param  component_index  Index within the component table.
  @param  decoder_index    Decoder slot to configure.
  @param  base             Base address aligned to 256MB.
  @param  size             Length aligned to 256MB.

  @return Status code propagated from the programming helper.
**/
uint32_t
val_cxl_program_component_decoder(uint32_t component_index,
                                  uint32_t decoder_index,
                                  uint64_t base,
                                  uint64_t size)
{
  uint64_t cap_base;
  uint32_t status;
  CXL_COMPONENT_ENTRY *component;

  component = val_cxl_get_component_entry(component_index);
  if (component == NULL)
    return ACS_STATUS_ERR;

  status = val_cxl_find_capability(component->component_reg_base,
                                   CXL_CAPID_HDM_DECODER,
                                   &cap_base);
  if (status != ACS_STATUS_PASS)
    return status;

  status = val_cxl_program_decoder_common(cap_base, decoder_index, base, size);

  if ((status == ACS_STATUS_PASS) && (component->hdm_decoder_count <= decoder_index))
    component->hdm_decoder_count = decoder_index + 1u;

  return status;
}

/**
  @brief   Execute all CXL compliance tests registered for the suite.

  @param  num_pe  Number of processing elements available for test execution. Unused.

  @return Consolidated status of the executed tests.
**/
uint32_t
val_rme_cxl_execute_tests(uint32_t num_pe)
{
  uint32_t status = ACS_STATUS_SKIP;
  uint64_t num_smmus = val_smmu_get_info(SMMU_NUM_CTRL, 0);
  uint64_t *smmu_base_arr = NULL;
  uint64_t pgt_attr_el3;
  uint32_t smmu_cnt;

  g_curr_module = 1 << CXL_MODULE_ID;

  if (!g_rl_smmu_init)
  {
    smmu_base_arr = val_memory_alloc_pages(1);
    if (smmu_base_arr == NULL)
    {
      val_print(ACS_PRINT_ERR, " Failed to allocate smmu_base_arr", 0);
      return ACS_STATUS_ERR;
    }

    smmu_cnt = 0;

    while (smmu_cnt < num_smmus)
    {
      smmu_base_arr[smmu_cnt] = val_smmu_get_info(SMMU_CTRL_BASE, smmu_cnt);
      smmu_cnt++;
    }
    /* Map the pointer in EL3 as NS access PAS so that EL3 can access it. */
    pgt_attr_el3 = LOWER_ATTRS(PGT_ENTRY_ACCESS | SHAREABLE_ATTR(OUTER_SHAREABLE) |
                               PGT_ENTRY_AP_RW | PAS_ATTR(NONSECURE_PAS));
    if (val_add_mmu_entry_el3((uint64_t)(smmu_base_arr),
                              (uint64_t)val_memory_virt_to_phys(smmu_base_arr),
                              pgt_attr_el3))
    {
      val_print(ACS_PRINT_ERR, " MMU mapping failed for smmu_base_arr", 0);
      val_memory_free_pages(smmu_base_arr, 1);
      return ACS_STATUS_ERR;
    }
    if (val_rlm_smmu_init(num_smmus, smmu_base_arr))
    {
      val_print(ACS_PRINT_ERR, " SMMU REALM INIT failed", 0);
      val_memory_free_pages(smmu_base_arr, 1);
      return ACS_STATUS_ERR;
    }

    g_rl_smmu_init = 1;
    val_memory_free_pages(smmu_base_arr, 1);
  }

  val_print(ACS_PRINT_ALWAYS, "\n\n*******************************************************\n", 0);
  status = val_execute_module_tests(CXL_MODULE_ID,
                                    CXL_MODULE_START,
                                    CXL_MODULE_END,
                                    num_pe,
                                    status);

  return status;
}
