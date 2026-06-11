/** @file
 * Copyright (c) 2024-2026, Arm Limited or its affiliates. All rights reserved.
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
#include "include/val_pcie.h"
#include "include/val_da.h"
#include "include/val_spdm.h"
#if ENABLE_SPDM
#include "industry_standard/pci_tdisp.h"
#endif

#include "include/val_memory.h"
#include "include/val_iovirt.h"
#include "include/val_mem_interface.h"
#include "include/val_el32.h"
#include "include/val_mem_interface.h"
#include "include/pal_interface.h"

#define TEST_DATA_1 0xabababab
#define TEST_DATA_2 0xcdcdcdcd

REGISTER_INFO_TABLE  *g_register_info_table;

#if ENABLE_SPDM

/* Maintain a small registry of active SPDM sessions keyed by BDF. */
typedef struct {
  uint32_t             in_use;
  uint32_t             bdf;
  uint32_t             session_id;
  val_spdm_context_t   ctx;
} spdm_session_slot_t;

#ifndef MAX_SPDM_SESSION_SLOTS
#define MAX_SPDM_SESSION_SLOTS 8
#endif

static spdm_session_slot_t g_spdm_sessions[MAX_SPDM_SESSION_SLOTS];

static spdm_session_slot_t *spdm_find_slot(uint32_t bdf)
{
  for (uint32_t i = 0; i < MAX_SPDM_SESSION_SLOTS; ++i) {
    if (g_spdm_sessions[i].in_use && (g_spdm_sessions[i].bdf == bdf))
      return &g_spdm_sessions[i];
  }
  return NULL;
}

static spdm_session_slot_t *spdm_alloc_slot(uint32_t bdf)
{
  spdm_session_slot_t *s = spdm_find_slot(bdf);
  if (s)
    return s;
  for (uint32_t i = 0; i < MAX_SPDM_SESSION_SLOTS; ++i) {
    if (!g_spdm_sessions[i].in_use) {
      g_spdm_sessions[i].in_use = 1u;
      g_spdm_sessions[i].bdf = bdf;
      g_spdm_sessions[i].session_id = 0u;
      /* ctx will be initialised when session is opened. */
      return &g_spdm_sessions[i];
    }
  }
  return NULL;
}

static void spdm_free_slot(spdm_session_slot_t *slot)
{
  if (!slot)
    return;
  slot->in_use = 0u;
  slot->bdf = 0u;
  slot->session_id = 0u;
  /* ctx is left zeroed by deinit path */
}
#endif

/**
  @brief  Exercise Realm Management Secure Domain write-protect behaviour for a register.

          The helper maps the target register into EL3 with each permitted PAS, attempts a
          write of the provided value, checks whether the update is accepted or blocked, and
          finally restores the original contents. Realm and Root PAS writes must succeed
          while Non-secure and Secure PAS writes must be ignored.

  @param  pa             Physical address of the register to be validated.
  @param  new_value      Value to attempt writing during the check.
  @param  original_value Known-good value used to restore the register and as reference.

  @retval 0             All PAS checks behaved as expected.
  @retval >0            Number of PAS contexts that violated the expected behaviour.
**/
uint32_t
val_rmsd_write_protect_check(uint64_t pa,
                             uint32_t new_value,
                             uint32_t original_value)
{
  static const uint64_t pas_list[] = {ROOT_PAS, REALM_PAS, NONSECURE_PAS, SECURE_PAS};
  uint32_t failures = 0u;
  uint64_t attr;
  uint64_t tg;
  uint64_t pa_page;
  uint64_t offset;

  tg = val_get_min_tg();
  pa_page = pa & ~(tg - 1u);
  offset = pa - pa_page;
  attr = LOWER_ATTRS(PGT_ENTRY_ACCESS | SHAREABLE_ATTR(OUTER_SHAREABLE) |
                     GET_ATTR_INDEX(DEV_MEM_nGnRnE) | PGT_ENTRY_AP_RW);

  for (uint32_t index = 0; index < (sizeof(pas_list) / sizeof(pas_list[0])); ++index)
  {
    uint64_t pas = pas_list[index];
    uint64_t va = val_get_free_va(tg);

    if (val_add_gpt_entry_el3(pa_page, GPT_ANY))
    {
      val_print(ACS_PRINT_ERR,
                " Failed to add GPT entry for 0x%llx ",
                pa_page);
      failures++;
      continue;
    }

    if (val_add_mmu_entry_el3(va, pa_page, attr | LOWER_ATTRS(PAS_ATTR(pas))))
    {
      val_print(ACS_PRINT_ERR,
                " Failed to add MMU entry for 0x%llx ",
                pa_page);
      val_print(ACS_PRINT_ERR,
                " with PAS 0x%llx",
                pas);
      failures++;
      continue;
    }

    shared_data->num_access = 1;
    shared_data->shared_data_access[0].addr = va + offset;
    shared_data->shared_data_access[0].access_type = WRITE_DATA;
    shared_data->shared_data_access[0].data = new_value;
    if (val_pe_access_mut_el3())
    {
      val_print(ACS_PRINT_ERR,
                " Failed to write register 0x%llx ",
                pa);
      val_print(ACS_PRINT_ERR,
                " with PAS 0x%llx",
                pas);
      failures++;
      continue;
    }

    shared_data->num_access = 1;
    shared_data->shared_data_access[0].addr = va + offset;
    shared_data->shared_data_access[0].access_type = READ_DATA;
    if (val_pe_access_mut_el3())
    {
      val_print(ACS_PRINT_ERR,
                " Failed to read register 0x%llx ",
                pa);
      val_print(ACS_PRINT_ERR,
                " with PAS 0x%llx",
                pas);
      failures++;
      continue;
    }

    uint32_t read_value = shared_data->shared_data_access[0].data;

    if ((pas == REALM_PAS) || (pas == ROOT_PAS))
    {
      if (read_value == original_value)
      {
        val_print(ACS_PRINT_ERR,
                  " Register 0x%llx not updated for RMSD write ",
                  pa);
        val_print(ACS_PRINT_ERR,
                  " with PAS 0x%llx",
                  pas);
        failures++;
      }
    }
    else
    {
      if (read_value != original_value)
      {
        val_print(ACS_PRINT_ERR,
                  " Register 0x%llx updated for non-RMSD write ",
                  pa);
        val_print(ACS_PRINT_ERR,
                  " with PAS 0x%llx",
                  pas);
        failures++;
      }
    }

    shared_data->num_access = 1;
    shared_data->shared_data_access[0].addr = va + offset;
    shared_data->shared_data_access[0].access_type = WRITE_DATA;
    shared_data->shared_data_access[0].data = original_value;
    if (val_pe_access_mut_el3())
    {
      val_print(ACS_PRINT_ERR,
                " Failed to restore register 0x%llx ",
                pa);
      val_print(ACS_PRINT_ERR,
                " with PAS 0x%llx",
                pas);
      failures++;
    }
  }

  return failures;
}

/**
  @brief  Query whether the platform reports coherent DA support.

  @return Non-zero when coherent DA is supported, otherwise 0.
**/
uint32_t
val_is_coherent_da_supported(void)
{
  return pal_is_coherent_da_supported();
}

/**
  @brief   This API will execute all RME DA tests designated for a given compliance level
           1. Caller       -  Application layer.
           2. Prerequisite -  val_pe_create_info_table, val_allocate_shared_mem
  @param   num_pe - the number of PE to run these tests on.
  @return  Consolidated status of all the tests run.
**/
uint32_t
val_rme_da_execute_tests(uint32_t num_pe)
{
  uint32_t status = ACS_STATUS_SKIP, reset_status, smmu_cnt;
  uint64_t num_smmus = val_smmu_get_info(SMMU_NUM_CTRL, 0);
  uint64_t smmu_base_arr[num_smmus], pgt_attr_el3;

  g_curr_module = 1 << DA_MODULE_ID;

  if (!g_rl_smmu_init)
  {
      smmu_cnt = 0;

      while (smmu_cnt < num_smmus)
      {
        smmu_base_arr[smmu_cnt] = val_smmu_get_info(SMMU_CTRL_BASE, smmu_cnt);
        smmu_cnt++;
      }
      /* Map the Pointer in EL3 as NS Access PAS so that EL3 can access this struct pointers */
      pgt_attr_el3 = LOWER_ATTRS(PGT_ENTRY_ACCESS | SHAREABLE_ATTR(OUTER_SHAREABLE) |
                                 PGT_ENTRY_AP_RW | PAS_ATTR(NONSECURE_PAS));
      if (val_add_mmu_entry_el3((uint64_t)(smmu_base_arr), (uint64_t)(smmu_base_arr), pgt_attr_el3))
      {
        val_print(ACS_PRINT_ERR, " MMU mapping failed for smmu_base_arr", 0);
        return ACS_STATUS_ERR;
      }
      if (val_rlm_smmu_init(num_smmus, smmu_base_arr))
      {
        val_print(ACS_PRINT_ERR, " SMMU REALM INIT failed", 0);
        return ACS_STATUS_ERR;
      }

      g_rl_smmu_init = 1;
  }

  val_print(ACS_PRINT_DEBUG, "\n RME-DA : Starting tests \n", 0);
  reset_status = val_read_reset_status();
  val_print(ACS_PRINT_DEBUG, "\n Reset status : %x \n", reset_status);

  if (reset_status != RESET_TST12_FLAG &&
      reset_status != RESET_TST31_FLAG &&
      reset_status != RESET_TST2_FLAG &&
      reset_status != RESET_LS_DISBL_FLAG &&
      reset_status != RESET_LS_TEST3_FLAG)
  {
      /* DA-ACS tests */
      val_print(ACS_PRINT_ALWAYS,
                "\n\n*******************************************************\n", 0);
      status = val_execute_module_tests(DA_MODULE_ID,
                                        DA_MODULE_START,
                                        DA_MODULE_END,
                                        num_pe,
                                        status);

  }

  return status;

}

void
val_register_create_info_table(uint64_t *register_info_table)
{
  g_register_info_table = (REGISTER_INFO_TABLE *)register_info_table;

  pal_register_create_info_table(g_register_info_table);
}

void *
val_register_table_ptr(void)
{
  return g_register_info_table;
}

uint32_t
val_register_get_num_entries(void)
{
  return pal_register_get_num_entries();
}

void
val_da_get_addr_asso_block_base(uint32_t *num_sel_ide_stream_supp,
                         uint32_t *num_tc_supp,
                         uint32_t *current_base_offset,
                         uint32_t bdf,
                         uint32_t *num_addr_asso_block,
                         uint32_t *rid_limit,
                         uint32_t *rid_base,
                         uint32_t reg_value)
{

  /* Get the number of Selective IDE Streams */
  *num_sel_ide_stream_supp = (reg_value & NUM_SEL_STR_MASK) >> NUM_SEL_STR_SHIFT;
  /* Get the number of TCs supported for Link IDE */
  *num_tc_supp = (reg_value & NUM_TC_SUPP_MASK) >> NUM_TC_SUPP_SHIFT;

  /* Base offset of Link IDE Register Block */
  *current_base_offset = *current_base_offset + IDE_CAP_REG_SIZE; //IDE Reg size

  /* Base offset of Selective IDE Stream Block */
  *current_base_offset = *current_base_offset + ((*num_tc_supp + 1) * LINK_IDE_BLK_SIZE);

  /* Get the number of Address Associaltion Register Blocks */
  val_pcie_read_cfg(bdf, *current_base_offset, &reg_value);
  *num_addr_asso_block = (reg_value & NUM_ADDR_ASSO_REG_MASK) >> NUM_ADDR_ASSO_REG_SHIFT;

  /* Base offset of IDE RID Association Register 1 */
  *current_base_offset = *current_base_offset + SEL_IDE_CAP_REG_SIZE;

  /* Get the RID Limit from IDE RID Association Register 1 */
  *rid_limit = VAL_EXTRACT_BITS(val_pcie_read_cfg(bdf, *current_base_offset, rid_limit), 8, 23);
  val_print(ACS_PRINT_INFO, " RID Limit: %x", *rid_limit);

  /* Base offset of IDE RID Association Register 2 */
  *current_base_offset = *current_base_offset + RID_ADDR_REG1_SIZE;

  /* Get the RID Limit from IDE RID Association Register 2 */
  *rid_base = VAL_EXTRACT_BITS(val_pcie_read_cfg(bdf, *current_base_offset, rid_base), 8, 23);
  val_print(ACS_PRINT_INFO, " RID Base: %x", *rid_base);

  /* Base offset of IDE Address Association Register Block */
  *current_base_offset = *current_base_offset + RID_ADDR_REG2_SIZE; // Addr ass base
}

void
val_da_get_next_rid_values(uint32_t *current_base_offset,
                    uint32_t *num_addr_asso_block,
                    uint32_t bdf,
                    uint32_t *next_rid_limit,
                    uint32_t *next_rid_base)
{
  uint32_t reg_value;

  /* Base offset of next Selective IDE Stream Register Block */
  *current_base_offset = *current_base_offset + (*num_addr_asso_block * IDE_ADDR_REG_BLK_SIZE);

  /* Get the number of Address Associaltion Register Blocks */
  val_pcie_read_cfg(bdf, *current_base_offset, &reg_value);
  *num_addr_asso_block = (reg_value & NUM_ADDR_ASSO_REG_MASK) >> NUM_ADDR_ASSO_REG_SHIFT;

  /* Base offset of IDE RID Association Register 1 */
  *current_base_offset = *current_base_offset + SEL_IDE_CAP_REG_SIZE;

  /* Get the RID Limit from IDE RID Association Register 1 */
  *next_rid_limit = VAL_EXTRACT_BITS(
                    val_pcie_read_cfg(bdf, *current_base_offset, next_rid_limit),
                    8, 23);
  val_print(ACS_PRINT_INFO, " RID Limit: %x", *next_rid_limit);

  /* Base offset of IDE RID Association Register 2 */
  *current_base_offset = *current_base_offset + RID_ADDR_REG1_SIZE;

  /* Get the RID Limit from IDE RID Association Register 2 */
  *next_rid_base = VAL_EXTRACT_BITS(
                   val_pcie_read_cfg(bdf, *current_base_offset, next_rid_base),
                   8, 23);
  val_print(ACS_PRINT_INFO, " RID Base: %x", *next_rid_base);
}

uint32_t
val_device_lock(uint32_t bdf)
{
#if ENABLE_SPDM
  spdm_session_slot_t                 *slot;
  val_spdm_context_t                  *ctx;
  uint32_t                             session_id = 0;
  pci_tdisp_interface_id_t             interface_id;
  pci_tdisp_requester_capabilities_t   req_caps;
  pci_tdisp_responder_capabilities_t   rsp_caps;
  pci_tdisp_lock_interface_param_t     lock_param;
  uint8_t                              nonce[PCI_TDISP_START_INTERFACE_NONCE_SIZE];
  uint32_t                             status;
  uint8_t                              tdi_state;

  /* Build interface ID from endpoint BDF */
  interface_id.function_id = (uint32_t)PCIE_CREATE_BDF_PACKED(bdf);
  interface_id.reserved    = 0ull;

  slot = spdm_alloc_slot(bdf);
  if (slot == NULL) {
    val_print(ACS_PRINT_ERR, " SPDM: No free session slot for BDF: 0x%x", bdf);
    return ACS_STATUS_ERR;
  }

  ctx = &slot->ctx;

  status = val_spdm_session_open(bdf, ctx, &session_id);
  if (status == ACS_STATUS_PASS) {
    val_print(ACS_PRINT_INFO, " SPDM session_open PASS 0x%x", status);
  } else if (status == ACS_STATUS_SKIP) {
    val_print(ACS_PRINT_WARN, " SPDM session_open SKIP 0x%x", status);
    return ACS_STATUS_ERR;
  } else {
    val_print(ACS_PRINT_ERR, " SPDM session_open ERR 0x%x", status);
    return ACS_STATUS_ERR;
  }

  val_memory_set(&req_caps, sizeof(req_caps), 0);
  val_memory_set(&rsp_caps, sizeof(rsp_caps), 0);
  val_memory_set(&lock_param, sizeof(lock_param), 0);
  val_memory_set(nonce, sizeof(nonce), 0);

  status = val_spdm_send_pci_tdisp_get_version(ctx,
                                               session_id,
                                               &interface_id);
  if (status == ACS_STATUS_PASS)
    val_print(ACS_PRINT_INFO, " TDISP GET_VERSION PASS 0x%x", status);
  else if (status == ACS_STATUS_SKIP) {
    val_print(ACS_PRINT_WARN, " TDISP GET_VERSION SKIP 0x%x", status);
    goto fallback_close;
  } else {
    val_print(ACS_PRINT_ERR, " TDISP GET_VERSION ERR 0x%x", status);
    goto fallback_close;
  }

  status = val_spdm_send_pci_tdisp_get_capabilities(ctx,
                                                   session_id,
                                                   &interface_id,
                                                   &req_caps,
                                                   &rsp_caps);
  if (status == ACS_STATUS_PASS)
    val_print(ACS_PRINT_INFO, " TDISP GET_CAPS PASS 0x%x", status);
  else if (status == ACS_STATUS_SKIP) {
    val_print(ACS_PRINT_WARN, " TDISP GET_CAPS SKIP 0x%x", status);
    goto fallback_close;
  } else {
    val_print(ACS_PRINT_ERR, " TDISP GET_CAPS ERR 0x%x", status);
    goto fallback_close;
  }

  /* flags, reporting offset and P2P mask are zero */
  lock_param.flags                 = 0;
  lock_param.default_stream_id     = 0;
  lock_param.reserved              = 0;
  lock_param.mmio_reporting_offset = 0ull;
  lock_param.bind_p2p_address_mask = 0ull;

  status = val_spdm_send_pci_tdisp_lock_interface(ctx,
                                                 session_id,
                                                 &interface_id,
                                                 &lock_param,
                                                 nonce);
  if (status == ACS_STATUS_PASS)
    val_print(ACS_PRINT_INFO, " TDISP LOCK_IF PASS 0x%x", status);
  else if (status == ACS_STATUS_SKIP) {
    val_print(ACS_PRINT_WARN, " TDISP LOCK_IF SKIP 0x%x", status);
    goto fallback_close;
  } else {
    val_print(ACS_PRINT_ERR, " TDISP LOCK_IF ERR 0x%x", status);
    goto fallback_close;
  }

  /* Verify CONFIG_LOCKED then transition to RUN. */
  status = val_spdm_send_pci_tdisp_get_interface_state(ctx,
                                                      session_id,
                                                      &interface_id,
                                                      &tdi_state);
  if (status == ACS_STATUS_PASS)
    val_print(ACS_PRINT_INFO, " TDISP GET_STATE PASS 0x%x", status);
  else if (status == ACS_STATUS_SKIP) {
    val_print(ACS_PRINT_WARN, " TDISP GET_STATE SKIP 0x%x", status);
    goto fallback_close;
  } else {
    val_print(ACS_PRINT_ERR, " TDISP GET_STATE ERR 0x%x", status);
    goto fallback_close;
  }

  if (tdi_state != PCI_TDISP_INTERFACE_STATE_CONFIG_LOCKED)
  {
    val_print(ACS_PRINT_ERR, " TDISP state !CONFIG_LOCKED 0x%x", tdi_state);
    goto fallback_close;
  }

  status = val_spdm_send_pci_tdisp_start_interface(ctx,
                                                  session_id,
                                                  &interface_id,
                                                  nonce);
  if (status == ACS_STATUS_PASS)
    val_print(ACS_PRINT_INFO, " TDISP START_IF PASS 0x%x", status);
  else if (status == ACS_STATUS_SKIP) {
    val_print(ACS_PRINT_WARN, " TDISP START_IF SKIP 0x%x", status);
    goto fallback_close;
  } else {
    val_print(ACS_PRINT_ERR, " TDISP START_IF ERR 0x%x", status);
    goto fallback_close;
  }

  status = val_spdm_send_pci_tdisp_get_interface_state(ctx,
                                                      session_id,
                                                      &interface_id,
                                                      &tdi_state);
  if (status == ACS_STATUS_PASS)
    val_print(ACS_PRINT_INFO, " TDISP GET_STATE PASS 0x%x", status);
  else if (status == ACS_STATUS_SKIP) {
    val_print(ACS_PRINT_WARN, " TDISP GET_STATE SKIP 0x%x", status);
    goto fallback_close;
  } else {
    val_print(ACS_PRINT_ERR, " TDISP GET_STATE ERR 0x%x", status);
    goto fallback_close;
  }

  if (tdi_state != PCI_TDISP_INTERFACE_STATE_RUN)
  {
    val_print(ACS_PRINT_ERR, " TDISP state !RUN 0x%x", tdi_state);
    goto fallback_close;
  }

  /* Keep the SPDM session open until val_device_unlock(); remember handle. */
  slot->session_id = session_id;
  return ACS_STATUS_PASS;

fallback_close:
  status = val_spdm_session_close(ctx, session_id);
  if (status == ACS_STATUS_PASS)
    val_print(ACS_PRINT_INFO, " SPDM session_close PASS 0x%x", status);
  else if (status == ACS_STATUS_SKIP)
    val_print(ACS_PRINT_WARN, " SPDM session_close SKIP 0x%x", status);
  else
    val_print(ACS_PRINT_ERR, " SPDM session_close ERR 0x%x", status);

  if (ctx)
    val_spdm_context_deinit(ctx);

  spdm_free_slot(slot);

  return ACS_STATUS_ERR;
#else
  return pal_device_lock(bdf);
#endif
}

uint32_t
val_device_unlock(uint32_t bdf)
{
#if ENABLE_SPDM
  pci_tdisp_interface_id_t interface_id;
  spdm_session_slot_t *slot = spdm_find_slot(bdf);
  uint32_t status;

  interface_id.function_id = (uint32_t)PCIE_CREATE_BDF_PACKED(bdf);
  interface_id.reserved    = 0ull;

  /* unlock: if no active session for this BDF, treat as success. */
  if (slot == NULL)
    return ACS_STATUS_PASS;

  status = val_spdm_send_pci_tdisp_stop_interface(&slot->ctx,
                                                  slot->session_id,
                                                  &interface_id);
  if (status == ACS_STATUS_PASS)
    val_print(ACS_PRINT_INFO, " TDISP STOP_IF PASS 0x%x", status);
  else if (status == ACS_STATUS_SKIP)
    val_print(ACS_PRINT_WARN, " TDISP STOP_IF SKIP 0x%x", status);
  else
    val_print(ACS_PRINT_ERR,  " TDISP STOP_IF ERR 0x%x", status);

  status = val_spdm_session_close(&slot->ctx, slot->session_id);
  if (status == ACS_STATUS_PASS)
    val_print(ACS_PRINT_INFO, " SPDM session_close PASS 0x%x", status);
  else if (status == ACS_STATUS_SKIP)
    val_print(ACS_PRINT_WARN, " SPDM session_close SKIP 0x%x", status);
  else
    val_print(ACS_PRINT_ERR,  " SPDM session_close ERR 0x%x", status);

  val_spdm_context_deinit(&slot->ctx);
  spdm_free_slot(slot);
  return ACS_STATUS_PASS;
#else
  return pal_device_unlock(bdf);
#endif
}

uint32_t val_ide_set_sel_stream(uint32_t bdf, uint32_t str_cnt, uint32_t enable)
{
  uint32_t reg_value;
  uint32_t ide_cap_base;
  uint32_t num_tc_supp;
  uint32_t num_sel_ide_stream_supp;
  uint32_t sel_ide_str_supported;
  uint32_t current_base_offset;
  uint32_t num_addr_asso_block;
  uint32_t count;

  /* Check IDE Extended Capability register is present */
  if (val_pcie_find_capability(bdf, PCIE_ECAP, ECID_IDE, &ide_cap_base) != PCIE_SUCCESS)
  {
      val_print(ACS_PRINT_ERR,
                    " PCIe IDE Capability not present for BDF: 0x%x", bdf);
      return 1;
  }

  /* Check if Selective IDE Stream is supported */
  val_pcie_read_cfg(bdf, ide_cap_base + IDE_CAP_REG, &reg_value);
  sel_ide_str_supported = (reg_value & SEL_IDE_STR_MASK) >> SEL_IDE_STR_SHIFT;
  if (!sel_ide_str_supported)
  {
      val_print(ACS_PRINT_ERR, " Selective IDE str not supported for BDF: %x", bdf);
      return 1;
  }

  /* Get the number of Selective IDE stream */
  num_sel_ide_stream_supp = (reg_value & NUM_SEL_STR_MASK) >> NUM_SEL_STR_SHIFT;

  /* Skip past the Link IDE register block */
  num_tc_supp = (reg_value & NUM_TC_SUPP_MASK) >> NUM_TC_SUPP_SHIFT;
  current_base_offset = ide_cap_base + IDE_CAP_REG_SIZE;
  current_base_offset = current_base_offset + ((num_tc_supp + 1) * LINK_IDE_BLK_SIZE);

  count = 0;
  while (count++ <= num_sel_ide_stream_supp)
  {
      val_pcie_read_cfg(bdf, current_base_offset, &reg_value);
      num_addr_asso_block = (reg_value & NUM_ADDR_ASSO_REG_MASK) >> NUM_ADDR_ASSO_REG_SHIFT;

      /* Set/Unset the Selective IDE Stream enable bit */
      if (count == str_cnt)
      {
          val_pcie_read_cfg(bdf, current_base_offset + SEL_IDE_CAP_CNTRL_REG, &reg_value);
          if (enable)
              val_pcie_write_cfg(bdf, current_base_offset + SEL_IDE_CAP_CNTRL_REG, reg_value | 1);
          else
              val_pcie_write_cfg(bdf, current_base_offset + SEL_IDE_CAP_CNTRL_REG, 0);

          return 0;
      }

      /* Base offset of IDE RID Association Register 1 */
      current_base_offset = current_base_offset + SEL_IDE_CAP_REG_SIZE;

      /* Base offset of IDE RID Association Register 2 */
      current_base_offset = current_base_offset + RID_ADDR_REG1_SIZE;

      /* Base offset of IDE Address Association Register Block */
      current_base_offset = current_base_offset + RID_ADDR_REG2_SIZE;

      /* Base offset of next Selective IDE Stream Register Block */
      current_base_offset +=  (num_addr_asso_block * IDE_ADDR_REG_BLK_SIZE);
  }

  /* If the Stream doesn't match the required selective stream, return failure */
  return 1;
}


uint32_t val_ide_program_stream_id(uint32_t bdf, uint32_t str_cnt, uint32_t stream_id)
{
  uint32_t reg_value;
  uint32_t ide_cap_base;
  uint32_t num_tc_supp;
  uint32_t num_sel_ide_stream_supp;
  uint32_t sel_ide_str_supported;
  uint32_t current_base_offset;
  uint32_t num_addr_asso_block;
  uint32_t count;

  /* Check IDE Extended Capability register is present */
  if (val_pcie_find_capability(bdf, PCIE_ECAP, ECID_IDE, &ide_cap_base) != PCIE_SUCCESS)
  {
      val_print(ACS_PRINT_ERR,
                    " PCIe IDE Capability not present for BDF: 0x%x", bdf);
      return 1;
  }

  /* Check if Selective IDE Stream is supported */
  val_pcie_read_cfg(bdf, ide_cap_base + IDE_CAP_REG, &reg_value);
  sel_ide_str_supported = (reg_value & SEL_IDE_STR_MASK) >> SEL_IDE_STR_SHIFT;
  if (!sel_ide_str_supported)
  {
      val_print(ACS_PRINT_ERR, " Selective IDE str not supported for BDF: %x", bdf);
      return 1;
  }

  /* Get the number of Selective IDE stream */
  num_sel_ide_stream_supp = (reg_value & NUM_SEL_STR_MASK) >> NUM_SEL_STR_SHIFT;

  /* Skip past the Link IDE register block */
  num_tc_supp = (reg_value & NUM_TC_SUPP_MASK) >> NUM_TC_SUPP_SHIFT;
  current_base_offset = ide_cap_base + IDE_CAP_REG_SIZE;
  current_base_offset = current_base_offset + ((num_tc_supp + 1) * LINK_IDE_BLK_SIZE);

  count = 0;
  while (count++ <= num_sel_ide_stream_supp)
  {
      val_pcie_read_cfg(bdf, current_base_offset, &reg_value);
      num_addr_asso_block = (reg_value & NUM_ADDR_ASSO_REG_MASK) >> NUM_ADDR_ASSO_REG_SHIFT;

      /* Write the given Stream ID in the Selective IDE Stream control Register Bit[31:24] */
      if (count == str_cnt)
      {
          val_pcie_write_cfg(bdf, current_base_offset + SEL_IDE_CAP_CNTRL_REG,
                            (stream_id << 24) & 0xFF000000);
          return 0;
      }

      /* Base offset of IDE RID Association Register 1 */
      current_base_offset = current_base_offset + SEL_IDE_CAP_REG_SIZE;

      /* Base offset of IDE RID Association Register 2 */
      current_base_offset = current_base_offset + RID_ADDR_REG1_SIZE;

      /* Base offset of IDE Address Association Register Block */
      current_base_offset = current_base_offset + RID_ADDR_REG2_SIZE;

      /* Base offset of next Selective IDE Stream Register Block */
      current_base_offset +=  (num_addr_asso_block * IDE_ADDR_REG_BLK_SIZE);
    }

  /* If the Stream doesn't match the required selective stream, return failure */
  return 1;
}

uint32_t val_ide_program_rid_base_limit_valid(uint32_t bdf, uint32_t str_cnt,
                               uint32_t base, uint32_t limit, uint32_t valid)
{
  uint32_t reg_value;
  uint32_t ide_cap_base;
  uint32_t num_tc_supp;
  uint32_t num_sel_ide_stream_supp;
  uint32_t sel_ide_str_supported;
  uint32_t current_base_offset;
  uint32_t num_addr_asso_block;
  uint32_t rid_asso_reg_1;
  uint32_t rid_asso_reg_2;
  uint32_t count;

  /* Check IDE Extended Capability register is present */
  if (val_pcie_find_capability(bdf, PCIE_ECAP, ECID_IDE, &ide_cap_base) != PCIE_SUCCESS)
  {
      val_print(ACS_PRINT_ERR,
                    " PCIe IDE Capability not present for BDF: 0x%x", bdf);
      return 1;
  }

  /* Check if Selective IDE Stream is supported */
  val_pcie_read_cfg(bdf, ide_cap_base + IDE_CAP_REG, &reg_value);
  sel_ide_str_supported = (reg_value & SEL_IDE_STR_MASK) >> SEL_IDE_STR_SHIFT;
  if (!sel_ide_str_supported)
  {
      val_print(ACS_PRINT_ERR, " Selective IDE str not supported for BDF: %x", bdf);
      return 1;
  }

  /* Get the number of Selective IDE stream */
  num_sel_ide_stream_supp = (reg_value & NUM_SEL_STR_MASK) >> NUM_SEL_STR_SHIFT;

  /* Skip past the Link IDE register block */
  num_tc_supp = (reg_value & NUM_TC_SUPP_MASK) >> NUM_TC_SUPP_SHIFT;
  current_base_offset = ide_cap_base + IDE_CAP_REG_SIZE;
  current_base_offset = current_base_offset + ((num_tc_supp + 1) * LINK_IDE_BLK_SIZE);

  count = 0;
  while (count++ <= num_sel_ide_stream_supp)
  {
      val_pcie_read_cfg(bdf, current_base_offset, &reg_value);
      num_addr_asso_block = (reg_value & NUM_ADDR_ASSO_REG_MASK) >> NUM_ADDR_ASSO_REG_SHIFT;

      /* Base offset of IDE RID Association Register 1 */
      current_base_offset = current_base_offset + SEL_IDE_CAP_REG_SIZE;
      rid_asso_reg_1 = current_base_offset;

      /* Base offset of IDE RID Association Register 2 */
      current_base_offset = current_base_offset + RID_ADDR_REG1_SIZE;
      rid_asso_reg_2 = current_base_offset;

      if (count == str_cnt)
      {
          /* Write RID Limit value in the RID Assosiation Register 1 */
          val_pcie_write_cfg(bdf, rid_asso_reg_1, (limit << 8) & 0xFFFF00);
          /* Write RID Base value in the RID Assosiation Register 2 */
          val_pcie_write_cfg(bdf, rid_asso_reg_2, (base << 8) & 0xFFFF00);
          /* Enable the valid bit in the RID Assosiation Register 2 */
          val_pcie_write_cfg(bdf, rid_asso_reg_2, valid);

          return 0;
      }

      /* Base offset of IDE Address Association Register Block */
      current_base_offset = current_base_offset + RID_ADDR_REG2_SIZE;

      /* Base offset of next Selective IDE Stream Register Block */
      current_base_offset +=  (num_addr_asso_block * IDE_ADDR_REG_BLK_SIZE);
  }

  /* If the Stream doesn't match the required selective stream, return failure */
  return 1;
}

uint32_t val_ide_get_num_sel_str(uint32_t bdf, uint32_t *num_sel_str)
{
  uint32_t reg_value;
  uint32_t ide_cap_base;
  uint32_t sel_ide_str_supported;

  /* Check IDE Extended Capability register is present */
  if (val_pcie_find_capability(bdf, PCIE_ECAP, ECID_IDE, &ide_cap_base) != PCIE_SUCCESS)
  {
      val_print(ACS_PRINT_ERR,
                    " PCIe IDE Capability not present for BDF: 0x%x", bdf);
      return 1;
  }

  /* Check if Selective IDE Stream is supported */
  val_pcie_read_cfg(bdf, ide_cap_base + IDE_CAP_REG, &reg_value);
  sel_ide_str_supported = (reg_value & SEL_IDE_STR_MASK) >> SEL_IDE_STR_SHIFT;
  if (!sel_ide_str_supported)
  {
      val_print(ACS_PRINT_ERR, " Selective IDE str not supported for BDF: %x", bdf);
      return 1;
  }

  /* Get the number of Selective IDE stream */
  *num_sel_str = ((reg_value & NUM_SEL_STR_MASK) >> NUM_SEL_STR_SHIFT) + 1;

  return 0;
}

/**
  @brief  Derive the number of IDE link streams advertised by a root port.

          The helper locates the PCIe IDE extended capability, reads the capability register,
          and returns the link stream count encoded in NUM_TC_SUPP.

  @param  bdf                Segment/Bus/Device/Function identifier of the port.
  @param  num_link_streams   Output parameter updated with the number of link streams.

  @retval 0  Capability present and the count was returned successfully.
  @retval 1  Capability missing, invalid arguments, or configuration read failure.
**/
uint32_t
val_get_num_link_str(uint32_t bdf, uint32_t *num_link_streams)
{
  uint32_t ide_cap_base;
  uint32_t reg_value;

  if (num_link_streams == NULL)
      return 1;

  if (val_pcie_find_capability(bdf, PCIE_ECAP, ECID_IDE, &ide_cap_base) != PCIE_SUCCESS)
  {
      val_print(ACS_PRINT_ERR,
                    " PCIe IDE Capability not present for BDF: 0x%x", bdf);
      return 1;
  }

  val_pcie_read_cfg(bdf, ide_cap_base + IDE_CAP_REG, &reg_value);

  *num_link_streams = ((reg_value & NUM_TC_SUPP_MASK) >> NUM_TC_SUPP_SHIFT) + 1;

  return 0;
}

/**
  @brief  Report the current state of a specific IDE link stream.

          The function validates the requested index against the advertised link stream count,
          walks to the stream's status register, and returns the STREAM_STATE_* field.

  @param  bdf         Segment/Bus/Device/Function identifier of the port.
  @param  link_index  Zero-based IDE link stream index to query.
  @param  str_status  Output parameter receiving the current stream state value.

  @retval 0  Stream state retrieved successfully.
  @retval 1  Capability missing, index out of range, or configuration access error.
**/
uint32_t
val_get_link_str_status(uint32_t bdf, uint32_t link_index, uint32_t *str_status)
{
  uint32_t ide_cap_base;
  uint32_t reg_value;
  uint32_t num_link_streams;

  if (str_status == NULL)
      return 1;

  if (val_pcie_find_capability(bdf, PCIE_ECAP, ECID_IDE, &ide_cap_base) != PCIE_SUCCESS)
  {
      val_print(ACS_PRINT_ERR,
                    " PCIe IDE Capability not present for BDF: 0x%x", bdf);
      return 1;
  }

  val_pcie_read_cfg(bdf, ide_cap_base + IDE_CAP_REG, &reg_value);
  num_link_streams = ((reg_value & NUM_TC_SUPP_MASK) >> NUM_TC_SUPP_SHIFT) + 1;

  if (link_index >= num_link_streams)
  {
      val_print(ACS_PRINT_ERR, " Invalid Link IDE stream index %d", link_index);
      val_print(ACS_PRINT_ERR, " BDF: 0x%x", bdf);
      return 1;
  }

  ide_cap_base += IDE_CAP_REG_SIZE;
  ide_cap_base += (link_index * LINK_IDE_BLK_SIZE);

  val_pcie_read_cfg(bdf, ide_cap_base + LINK_IDE_STATUS_REG, &reg_value);

  *str_status = reg_value & LINK_IDE_STATE_MASK;

  return 0;
}

uint32_t val_get_sel_str_status(uint32_t bdf, uint32_t str_cnt, uint32_t *str_status)
{
  uint32_t reg_value;
  uint32_t ide_cap_base;
  uint32_t num_tc_supp;
  uint32_t num_sel_ide_stream_supp;
  uint32_t sel_ide_str_supported;
  uint32_t current_base_offset;
  uint32_t num_addr_asso_block;
  uint32_t count;

  /* Check IDE Extended Capability register is present */
  if (val_pcie_find_capability(bdf, PCIE_ECAP, ECID_IDE, &ide_cap_base) != PCIE_SUCCESS)
  {
      val_print(ACS_PRINT_ERR,
                    " PCIe IDE Capability not present for BDF: 0x%x", bdf);
      return 1;
  }

  /* Check if Selective IDE Stream is supported */
  val_pcie_read_cfg(bdf, ide_cap_base + IDE_CAP_REG, &reg_value);
  sel_ide_str_supported = (reg_value & SEL_IDE_STR_MASK) >> SEL_IDE_STR_SHIFT;
  if (!sel_ide_str_supported)
  {
      val_print(ACS_PRINT_ERR, " Selective IDE str not supported for BDF: %x", bdf);
      return 1;
  }

  /* Get the number of Selective IDE stream */
  num_sel_ide_stream_supp = (reg_value & NUM_SEL_STR_MASK) >> NUM_SEL_STR_SHIFT;

  /* Skip past the Link IDE register block */
  num_tc_supp = (reg_value & NUM_TC_SUPP_MASK) >> NUM_TC_SUPP_SHIFT;
  current_base_offset = ide_cap_base + IDE_CAP_REG_SIZE;
  current_base_offset = current_base_offset + ((num_tc_supp + 1) * LINK_IDE_BLK_SIZE);

  count = 0;
  while (count++ <= num_sel_ide_stream_supp)
  {
      val_pcie_read_cfg(bdf, current_base_offset, &reg_value);
      num_addr_asso_block = (reg_value & NUM_ADDR_ASSO_REG_MASK) >> NUM_ADDR_ASSO_REG_SHIFT;

      /* Get the Status of Selective IDE Stream state */
      if (count == str_cnt)
      {
          val_pcie_read_cfg(bdf, current_base_offset + SEL_IDE_CAP_STATUS_REG, &reg_value);
          *str_status = reg_value & SEL_IDE_STATE_MASK;
          return 0;
      }

      /* Base offset of IDE RID Association Register 1 */
      current_base_offset = current_base_offset + SEL_IDE_CAP_REG_SIZE;

      /* Base offset of IDE RID Association Register 2 */
      current_base_offset = current_base_offset + RID_ADDR_REG1_SIZE;

      /* Base offset of IDE Address Association Register Block */
      current_base_offset = current_base_offset + RID_ADDR_REG2_SIZE;

      /* Base offset of next Selective IDE Stream Register Block */
      current_base_offset +=  (num_addr_asso_block * IDE_ADDR_REG_BLK_SIZE);
  }

  /* If the Stream doesn't match the required selective stream, return failure */
  return 1;
}

uint32_t
val_ide_establish_stream(uint32_t bdf, uint32_t count, uint32_t stream_id, uint32_t base_limit)
{
  uint32_t status, reg_value;

  status = val_ide_program_rid_base_limit_valid(bdf, count,
             PCIE_CREATE_BDF_PACKED(base_limit), PCIE_CREATE_BDF_PACKED(base_limit), 1);
  if (status)
  {
      val_print(ACS_PRINT_ERR, " Failed to set RID values for BDF: 0x%x", bdf);
      return 1;
  }

  status = val_ide_program_stream_id(bdf, count, stream_id);
  if (status)
  {
      val_print(ACS_PRINT_ERR, " Failed to set Stream ID for BDF: 0x%x", bdf);
      return 1;
  }

  status = val_ide_set_sel_stream(bdf, count, 1);
  if (status)
  {
      val_print(ACS_PRINT_ERR, " Failed to enable Sel Stream for BDF: 0x%x", bdf);
      return 1;
  }

  status = val_get_sel_str_status(bdf, count, &reg_value);
  if (status)
  {
      val_print(ACS_PRINT_ERR, " Fail to get Sel Stream state for BDF: 0x%x", bdf);
      return 1;
  }

  if (reg_value != STREAM_STATE_SECURE)
  {
      val_print(ACS_PRINT_ERR, " Sel Stream is not in Secure for BDF: 0x%x", bdf);
      return 1;
  }

  return 0;
}

uint32_t val_intercnt_sec_prpty_check(uint64_t *register_entry_info)
{
  REGISTER_INFO_TABLE *register_entry;
  uint32_t rd_data = 0;
  uint32_t data_rt, data_ns, org_data;

  register_entry = (REGISTER_INFO_TABLE *)register_entry_info;

  if (register_entry->type != INTERCONNECT)
      return 0;

  val_print(ACS_PRINT_DEBUG, " Address: 0x%x", register_entry->bdf);
  val_print(ACS_PRINT_ALWAYS, " Property: %d", register_entry->property);

  data_rt = TEST_DATA_1;
  data_ns = TEST_DATA_2;

  switch (register_entry->property)
  {
     case RMSD_PROTECT:
          /* Store the original data */
          shared_data->num_access = 1;
          shared_data->shared_data_access[0].addr = register_entry->address;
          shared_data->shared_data_access[0].access_type = READ_DATA;
          if (val_pe_access_mut_el3())
          {
            val_print(ACS_PRINT_ERR, " MUT access failed for 0x%llx", register_entry->address);
            return 1;
          }
          org_data = shared_data->shared_data_access[0].data;

          /* Write the data_rt from ROOT */
          shared_data->num_access = 1;
          shared_data->shared_data_access[0].addr = register_entry->address;
          shared_data->shared_data_access[0].access_type = WRITE_DATA;
          shared_data->shared_data_access[0].data = data_rt;

          /* Read the data from NS */
          rd_data = val_mmio_read(register_entry->address);

          /* Fail if the NS read is successfull */
          if (rd_data == data_rt)
          {
              val_print(ACS_PRINT_ERR, " Read success from NS for addr: 0x%lx",
                        register_entry->address);
              return 1;
          }

          /* Write the data_ns from NS */
          val_mmio_write(register_entry->address, data_ns);
          rd_data = val_mmio_read(register_entry->address);

          /* Fail if the NS write is successfull */
          if (rd_data == data_ns)
          {
              val_print(ACS_PRINT_ERR, " Write from NS is successfull for address: 0x%x",
                        register_entry->address);
              return 1;
          }

          /* Restore the original data */
          shared_data->num_access = 1;
          shared_data->shared_data_access[0].addr = register_entry->address;
          shared_data->shared_data_access[0].access_type = WRITE_DATA;
          shared_data->shared_data_access[0].data = org_data;
          if (val_pe_access_mut_el3())
          {
            val_print(ACS_PRINT_ERR, " MUT access failed for 0x%llx", register_entry->address);
            return 1;
          }

          rd_data = 0;
          break;

    default:
      val_print(ACS_PRINT_ERR, " Invalid Security Property: %d", register_entry->property);
      return 1;
  }

  return 0;
}
