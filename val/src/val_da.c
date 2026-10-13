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
#include "include/val_ide_km.h"
#if ENABLE_SPDM
#include "industry_standard/pci_tdisp.h"
#include "library/spdm_return_status.h"
#include "library/pci_ide_km_requester_lib.h"
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
  uint32_t             tdi_locked;
  uint32_t             ide_configured;
  uint32_t             rp_bdf;
  uint32_t             ep_count;
  uint32_t             rp_count;
  uint32_t             rp_key_cleanup_required;
  uint8_t              stream_id;
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
      g_spdm_sessions[i].tdi_locked = 0u;
      g_spdm_sessions[i].ide_configured = 0u;
      g_spdm_sessions[i].rp_key_cleanup_required = 0u;
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
          This API requires a change for Root/Realm writes; use the masked variant
          to verify the requested value in every known writable bit.
          Restoration uses Root PAS and is verified before continuing.

  @param  pa             Physical address of the register to be validated.
  @param  new_value      Value to attempt writing during the check.
  @param  original_value Known-good value used to restore the register and as reference.

  @retval 0             All PAS checks behaved as expected.
  @retval >0            One or more setup, access, validation or restoration failures.
**/
uint32_t
val_rmsd_write_protect_check(uint64_t pa,
                             uint32_t new_value,
                             uint32_t original_value)
{
  /* Preserve the comparison used by callers with read-only or self-clearing fields. */
  return val_rmsd_write_protect_check_masked(pa, new_value, original_value, 0u);
}

/**
  @brief  Check RMSD write protection and readback of known writable bits.

          Root and Realm writes must change the register and match new_value in
          every bit selected by write_mask. Non-secure and Secure writes must
          leave the entire register unchanged. A zero mask checks only that
          Root and Realm writes change the register, as in the existing API.
          After each write attempt, restore through Root PAS and verify the
          original value, including after an access error. Stop on failure.

  @param  pa             Physical address of the register to be validated.
  @param  new_value      Value to attempt writing during the check.
  @param  original_value Known-good register value used for comparison and restoration.
  @param  write_mask     Writable bits whose readback must match new_value.

  @retval 0             All PAS checks behaved as expected.
  @retval >0            One or more setup, access, validation or restoration failures.
**/
uint32_t
val_rmsd_write_protect_check_masked(uint64_t pa,
                                    uint32_t new_value,
                                    uint32_t original_value,
                                    uint32_t write_mask)
{
  static const uint64_t pas_list[] = {ROOT_PAS, REALM_PAS, NONSECURE_PAS, SECURE_PAS};
  uint32_t failures = 0u;
  uint32_t read_value;
  uint64_t attr;
  uint64_t tg;
  uint64_t pa_page;
  uint64_t offset;
  uint64_t root_va;

  tg = val_get_min_tg();
  if (!tg || (tg & (tg - 1u)))
    return 1u;
  pa_page = pa & ~(tg - 1u);
  offset = pa - pa_page;
  attr = LOWER_ATTRS(PGT_ENTRY_ACCESS | SHAREABLE_ATTR(OUTER_SHAREABLE) |
                     GET_ATTR_INDEX(DEV_MEM_nGnRnE) | PGT_ENTRY_AP_RW);

  /* Establish the restore path before any register write can take effect. */
  root_va = val_get_free_va(tg);
  if (!root_va || (root_va & (tg - 1u)))
  {
    val_print(ACS_PRINT_ERR, " Invalid Root VA for register 0x%llx", pa);
    return 1u;
  }

  if (val_add_gpt_entry_el3(pa_page, GPT_ANY))
  {
    val_print(ACS_PRINT_ERR, " Failed to add GPT entry for 0x%llx", pa_page);
    return 1u;
  }

  if (val_add_mmu_entry_el3(root_va, pa_page, attr | LOWER_ATTRS(PAS_ATTR(ROOT_PAS))))
  {
    val_print(ACS_PRINT_ERR, " Failed to add Root MMU entry for 0x%llx", pa_page);
    return 1u;
  }

  for (uint32_t index = 0; index < (sizeof(pas_list) / sizeof(pas_list[0])); ++index)
  {
    uint64_t pas = pas_list[index];
    uint64_t va = root_va;

    if (pas != ROOT_PAS)
    {
      va = val_get_free_va(tg);
      if (!va || (va & (tg - 1u)) ||
          val_add_mmu_entry_el3(va, pa_page, attr | LOWER_ATTRS(PAS_ATTR(pas))))
      {
        val_print(ACS_PRINT_ERR, " Failed to map register 0x%llx", pa);
        val_print(ACS_PRINT_ERR, " with PAS 0x%llx", pas);
        failures++;
        break;
      }
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
      goto restore_register;
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
      goto restore_register;
    }

    read_value = shared_data->shared_data_access[0].data;

    if ((pas == REALM_PAS) || (pas == ROOT_PAS))
    {
      if (read_value == original_value ||
          ((read_value ^ new_value) & write_mask) != 0u)
      {
        val_print(ACS_PRINT_ERR,
                  " Register 0x%llx has unexpected RMSD write readback ",
                  pa);
        val_print(ACS_PRINT_ERR,
                  " with PAS 0x%llx",
                  pas);
        val_print(ACS_PRINT_ERR, " Write value 0x%x", new_value);
        val_print(ACS_PRINT_ERR, " Read value 0x%x", read_value);
        val_print(ACS_PRINT_ERR, " Readback mask 0x%x", write_mask);
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

restore_register:
    shared_data->num_access = 1;
    shared_data->shared_data_access[0].addr = root_va + offset;
    shared_data->shared_data_access[0].access_type = WRITE_DATA;
    shared_data->shared_data_access[0].data = original_value;
    if (val_pe_access_mut_el3())
    {
      val_print(ACS_PRINT_ERR,
                " Failed to restore register 0x%llx ",
                pa);
      val_print(ACS_PRINT_ERR,
                " with PAS 0x%llx",
                (uint64_t)ROOT_PAS);
      failures++;
    }

    /* Verify even after a restore error: the write may still have taken effect. */
    shared_data->num_access = 1;
    shared_data->shared_data_access[0].addr = root_va + offset;
    shared_data->shared_data_access[0].access_type = READ_DATA;
    if (val_pe_access_mut_el3())
    {
      val_print(ACS_PRINT_ERR, " Failed to verify restoration of register 0x%llx", pa);
      failures++;
    }
    else if ((uint32_t)shared_data->shared_data_access[0].data != original_value)
    {
      val_print(ACS_PRINT_ERR, " Register 0x%llx not restored through Root PAS", pa);
      failures++;
    }

    if (failures)
      break;
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
  if (reg_value & LINK_IDE_STR_MASK)
      *current_base_offset += (*num_tc_supp + 1) * LINK_IDE_BLK_SIZE;

  /* Get the number of Address Associaltion Register Blocks */
  val_pcie_read_cfg(bdf, *current_base_offset, &reg_value);
  *num_addr_asso_block = (reg_value & NUM_ADDR_ASSO_REG_MASK) >> NUM_ADDR_ASSO_REG_SHIFT;

  /* Base offset of IDE RID Association Register 1 */
  *current_base_offset = *current_base_offset + SEL_IDE_CAP_REG_SIZE;

  /* Get the RID Limit from IDE RID Association Register 1 */
  val_pcie_read_cfg(bdf, *current_base_offset, &reg_value);
  *rid_limit = VAL_EXTRACT_BITS(reg_value, 8, 23);
  val_print(ACS_PRINT_INFO, " RID Limit: %x", *rid_limit);

  /* Base offset of IDE RID Association Register 2 */
  *current_base_offset = *current_base_offset + RID_ADDR_REG1_SIZE;

  /* Get the RID Base from IDE RID Association Register 2 */
  val_pcie_read_cfg(bdf, *current_base_offset, &reg_value);
  *rid_base = VAL_EXTRACT_BITS(reg_value, 8, 23);
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
  val_pcie_read_cfg(bdf, *current_base_offset, &reg_value);
  *next_rid_limit = VAL_EXTRACT_BITS(reg_value, 8, 23);
  val_print(ACS_PRINT_INFO, " RID Limit: %x", *next_rid_limit);

  /* Base offset of IDE RID Association Register 2 */
  *current_base_offset = *current_base_offset + RID_ADDR_REG1_SIZE;

  /* Get the RID Base from IDE RID Association Register 2 */
  val_pcie_read_cfg(bdf, *current_base_offset, &reg_value);
  *next_rid_base = VAL_EXTRACT_BITS(reg_value, 8, 23);
  val_print(ACS_PRINT_INFO, " RID Base: %x", *next_rid_base);

  /* Base offset of IDE Address Association Register Block for the next iteration */
  *current_base_offset += RID_ADDR_REG2_SIZE;
}


/**
 * @brief Open or reuse a secured SPDM session for an endpoint.
 *
 * @param bdf Endpoint BDF identifying the session.
 * @return ACS_STATUS_PASS on success, or ACS_STATUS_ERR on failure.
 */
uint32_t
val_device_session_open(uint32_t bdf)
{
#if ENABLE_SPDM
  spdm_session_slot_t *slot = spdm_alloc_slot(bdf);
  uint32_t status;

  if (slot == NULL)
    return ACS_STATUS_ERR;

  if (slot->session_id != 0u)
    return ACS_STATUS_PASS;

  status = val_spdm_session_open(bdf, &slot->ctx, &slot->session_id);
  if (status != ACS_STATUS_PASS) {
    val_spdm_context_deinit(&slot->ctx);
    spdm_free_slot(slot);
    return ACS_STATUS_ERR;
  }

  return ACS_STATUS_PASS;
#else
  (void)bdf;
  val_print(ACS_PRINT_ERR, " PCIe IDE setup requires ENABLE_SPDM", 0);
  return ACS_STATUS_ERR;
#endif
}

/**
 * @brief Establish a Secure PCIe IDE stream with matching endpoint and RP keys.
 *
 * @param bdf Endpoint BDF.
 * @param rp_bdf Root Port BDF.
 * @param ep_count Endpoint Selective IDE block number, starting at 1.
 * @param rp_count Root Port Selective IDE block number, starting at 1.
 * @param stream_id Eight-bit Stream ID used at both ports.
 * @param rid Packed Requester ID used for the RID associations.
 * @return ACS_STATUS_PASS when both ports are Secure, ACS_STATUS_SKIP when the
 *         RP backend is unsupported, or ACS_STATUS_ERR on setup failure.
 */
uint32_t
val_pcie_ide_establish_streams(uint32_t bdf, uint32_t rp_bdf,
                               uint32_t ep_count, uint32_t rp_count,
                               uint32_t stream_id, uint32_t rid)
{
#if ENABLE_SPDM
  spdm_session_slot_t *slot;
  PCIE_IDE_SELECTOR selector = {0};
  PCIE_IDE_KEY rp_key;
  pci_ide_km_aes_256_gcm_key_buffer_t ep_rx, ep_tx;
  uint32_t regs[PCIE_CFG_SIZE / sizeof(uint32_t)];
  uint32_t reg_count = PCIE_CFG_SIZE / sizeof(uint32_t);
  uint32_t i, j, state_ep, state_rp, result = ACS_STATUS_ERR;
  uint8_t dev_func, bus, segment, max_port, ack, sub;
  libspdm_return_t status = ACS_STATUS_ERR;
  char8_t *stage = " PCIe IDE setup: configure stream associations";

  /* Open SPDM session with EP */
  if (stream_id > 255u || val_device_session_open(bdf) != ACS_STATUS_PASS)
    return ACS_STATUS_ERR;

  /* Record RP and Stream ID in the EP session slot for setup and cleanup */
  slot = spdm_find_slot(bdf);
  slot->rp_bdf = rp_bdf;
  slot->ep_count = ep_count;
  slot->rp_count = rp_count;
  slot->stream_id = (uint8_t)stream_id;
  selector.stream_id = (uint8_t)stream_id;

  /* Disable the selected stream at both ports, then program RID and Stream ID */
  for (i = 0; i < 2; ++i) {
    uint32_t port = i ? rp_bdf : bdf;
    uint32_t count = i ? rp_count : ep_count;

    stage = i ? " PCIe IDE setup: RP stream configuration" :
                " PCIe IDE setup: EP stream configuration";
    status = val_ide_set_sel_stream(port, count, 0);
    if (status != ACS_STATUS_PASS)
      goto cleanup;

    status = val_ide_program_rid_base_limit_valid(port, count, rid, rid, 1);
    if (status != ACS_STATUS_PASS)
      goto cleanup;

    status = val_ide_program_stream_id(port, count, stream_id);
    if (status != ACS_STATUS_PASS)
      goto cleanup;
  }

  /* Query EP IDE-KM capabilities and configuration over the SPDM session */
  stage = " PCIe IDE setup: EP IDE_KM QUERY";
  status = pci_ide_km_query(NULL, slot->ctx.spdm_context, &slot->session_id, 0,
                &dev_func, &bus, &segment, &max_port, regs, &reg_count);
  if (LIBSPDM_STATUS_IS_ERROR(status)) {
    val_print(ACS_PRINT_ERR, " PCIe IDE_KM QUERY failed: 0x%x", (uint64_t)status);
    goto cleanup;
  }

  /* Confirm the responder identifies the EP function selected by the test */
  if (bus != PCIE_EXTRACT_BDF_BUS(bdf) ||
      dev_func != ((PCIE_EXTRACT_BDF_DEV(bdf) << 3) | PCIE_EXTRACT_BDF_FUNC(bdf)) ||
      segment != PCIE_EXTRACT_BDF_SEG(bdf)) {
    status = ACS_STATUS_ERR;
    stage = " PCIe IDE setup: EP QUERY identity validation";
    val_print(ACS_PRINT_ERR, " PCIe IDE_KM QUERY identity mismatch for EP: 0x%x", bdf);
    goto cleanup;
  }

  /* Independent keys/IVs for PR/NPR/Cpl in both directions, using key set K0. */

  /* Track IDE setup so cleanup also stops keys after a partial failure */
  slot->ide_configured = 1u;
  for (i = 0; i < 3; ++i) {

    /* Encode PR/NPR/Completion in the EP request; zero selects key set K0 */
    sub = (uint8_t)(i << 4);

    /* Generate separate RX and TX keys for this substream */
    val_memory_set(&ep_rx, sizeof(ep_rx), 0);
    val_memory_set(&ep_tx, sizeof(ep_tx), 0);
    stage = " PCIe IDE setup: generate keys";
    status = val_spdm_get_random(sizeof(ep_rx.key), (uint8_t *)ep_rx.key);
    if (status != ACS_STATUS_PASS)
      goto cleanup;

    status = val_spdm_get_random(sizeof(ep_tx.key), (uint8_t *)ep_tx.key);
    if (status != ACS_STATUS_PASS)
      goto cleanup;

    /* Initial invocation field for AES-GCM; the key material is fresh. */
    ep_rx.iv[0] = ep_tx.iv[0] = 1u;

    /* Program the EP receive key and check transport status and KP_ACK */
    stage = " PCIe IDE setup: EP RX KEY_PROG";
    ack = 0xff;
    status = pci_ide_km_key_prog(NULL, slot->ctx.spdm_context, &slot->session_id,
                 (uint8_t)stream_id, sub | PCI_IDE_KM_KEY_DIRECTION_RX, 0, &ep_rx, &ack);
    if (LIBSPDM_STATUS_IS_ERROR(status) || ack != PCI_IDE_KM_KP_ACK_STATUS_SUCCESS) {
      val_print(ACS_PRINT_ERR, " EP KEY_PROG ACK status: 0x%x", ack);
      goto cleanup;
    }

    /* Program the EP transmit key over the same secured SPDM session */
    stage = " PCIe IDE setup: EP TX KEY_PROG";
    ack = 0xff;
    status = pci_ide_km_key_prog(NULL, slot->ctx.spdm_context, &slot->session_id,
                 (uint8_t)stream_id, sub | PCI_IDE_KM_KEY_DIRECTION_TX, 0, &ep_tx, &ack);
    if (LIBSPDM_STATUS_IS_ERROR(status) || ack != PCI_IDE_KM_KP_ACK_STATUS_SUCCESS) {
      val_print(ACS_PRINT_ERR, " EP KEY_PROG ACK status: 0x%x", ack);
      goto cleanup;
    }

    /* Program RP RX through EL3 using the matching EP TX key and IFV */
    selector.sub_stream = (uint8_t)i;
    selector.direction = PCIE_IDE_RX;

    for (j = 0; j < 8; ++j)
      rp_key.key[j] = ep_tx.key[j];

    rp_key.initial_ifv = (uint64_t)ep_tx.iv[0] | ((uint64_t)ep_tx.iv[1] << 32);
    stage = " PCIe IDE setup: RP RX KEY_PROG";
    /* PROGRAM can fail after staging keys, so cleanup is required on any attempt. */
    slot->rp_key_cleanup_required = 1u;
    status = val_pcie_rp_ide_key_program(rp_bdf, &selector, &rp_key);
    if (status != ACS_STATUS_PASS)
      goto cleanup;

    /* Program RP TX through EL3 using the matching EP RX key and IFV */
    selector.direction = PCIE_IDE_TX;

    for (j = 0; j < 8; ++j)
      rp_key.key[j] = ep_rx.key[j];

    rp_key.initial_ifv = (uint64_t)ep_rx.iv[0] | ((uint64_t)ep_rx.iv[1] << 32);
    stage = " PCIe IDE setup: RP TX KEY_PROG";
    status = val_pcie_rp_ide_key_program(rp_bdf, &selector, &rp_key);
    if (status != ACS_STATUS_PASS)
      goto cleanup;

    /* Erase the temporary RP key copy after programming this substream */
    val_memory_set(&rp_key, sizeof(rp_key), 0);
  }

  /* Enable the selected EP and RP streams after all keys have been programmed */
  stage = " PCIe IDE setup: EP stream enable";
  status = val_ide_set_sel_stream(bdf, ep_count, 1);
  if (status != ACS_STATUS_PASS)
    goto cleanup;

  stage = " PCIe IDE setup: RP stream enable";
  status = val_ide_set_sel_stream(rp_bdf, rp_count, 1);
  if (status != ACS_STATUS_PASS)
    goto cleanup;

  /* Enable receivers at BOTH ports before enabling any transmitter. */
  for (j = 0; j < 2; ++j) {
    selector.direction = j ? PCIE_IDE_TX : PCIE_IDE_RX;
    for (i = 0; i < 3; ++i) {
      sub = (uint8_t)((i << 4) | (j ? PCI_IDE_KM_KEY_DIRECTION_TX :
                                                     PCI_IDE_KM_KEY_DIRECTION_RX));

      /* Activate the EP key set through IDE-KM */
      stage = j ? " PCIe IDE setup: EP TX KEY_GO" : " PCIe IDE setup: EP RX KEY_GO";
      status = pci_ide_km_key_set_go(NULL, slot->ctx.spdm_context, &slot->session_id,
                                                  (uint8_t)stream_id, sub, 0);
      if (LIBSPDM_STATUS_IS_ERROR(status))
        goto cleanup;

      /* Select the matching RP key set through EL3 */
      selector.sub_stream = (uint8_t)i;
      stage = j ? " PCIe IDE setup: RP TX KEY_GO" : " PCIe IDE setup: RP RX KEY_GO";
      status = val_pcie_rp_ide_key_go(rp_bdf, &selector);
      if (status != ACS_STATUS_PASS)
        goto cleanup;
    }

    /* ACK permits another request; allow receiver readiness before TX starts. */
    (void)val_time_delay_ms(10);
  }

  /* Poll both ports; enabling the streams alone does not establish Secure */
  for (i = 0; i <= 10; ++i) {
    stage = " PCIe IDE setup: read EP/RP stream state";
    status = val_get_sel_str_status(bdf, ep_count, &state_ep);
    if (status != ACS_STATUS_PASS)
      goto cleanup;

    status = val_get_sel_str_status(rp_bdf, rp_count, &state_rp);
    if (status != ACS_STATUS_PASS)
      goto cleanup;

    if (state_ep == STREAM_STATE_SECURE && state_rp == STREAM_STATE_SECURE) {
      val_print(ACS_PRINT_INFO, " PCIe IDE Secure at both ports, stream 0x%x", stream_id);
      result = ACS_STATUS_PASS;
      break;
    }
    (void)val_time_delay_ms(1);
  }

  /* Report the last observed states if the both-port Secure check timed out */
  if (result != ACS_STATUS_PASS) {
    stage = " PCIe IDE setup: timeout waiting for EP/RP Secure";
    status = ACS_STATUS_ERR;
    val_print(ACS_PRINT_ERR, " EP stream state: 0x%x", state_ep);
    val_print(ACS_PRINT_ERR, " RP stream state: 0x%x", state_rp);
  }
cleanup:


  /* Erase temporary key material on both success and failure */
  val_memory_set(&ep_rx, sizeof(ep_rx), 0);
  val_memory_set(&ep_tx, sizeof(ep_tx), 0);
  val_memory_set(&rp_key, sizeof(rp_key), 0);
  if (result != ACS_STATUS_PASS) {

    /* Report the failing stage, stop setup state and disable both streams */
    val_print(status == ACS_STATUS_SKIP ? ACS_PRINT_WARN : ACS_PRINT_ERR, stage, 0);
    val_print(status == ACS_STATUS_SKIP ? ACS_PRINT_WARN : ACS_PRINT_ERR,
              " Setup status: 0x%x", status);
    val_print(ACS_PRINT_ERR, " EP BDF: 0x%x", bdf);
    val_print(ACS_PRINT_ERR, " RP BDF: 0x%x", rp_bdf);
    (void)val_device_unlock(bdf);
  }
  if (result != ACS_STATUS_PASS && status == ACS_STATUS_SKIP)
    return ACS_STATUS_SKIP;

  return result;
#else
  (void)bdf;
  (void)rp_bdf;
  (void)ep_count;
  (void)rp_count;
  (void)stream_id;
  (void)rid;
  val_print(ACS_PRINT_ERR, " PCIe IDE setup requires ENABLE_SPDM", 0);
  return ACS_STATUS_ERR;
#endif
}

/**
 * @brief Establish PCIe IDE using the same block number at both ports.
 *
 * @param bdf Endpoint BDF.
 * @param rp_bdf Root Port BDF.
 * @param count Selectively addressed IDE block number, starting at 1.
 * @param stream_id Eight-bit Stream ID used at both ports.
 * @param rid Packed Requester ID used for the RID associations.
 * @return Status returned by val_pcie_ide_establish_streams().
 */
uint32_t
val_pcie_ide_establish(uint32_t bdf, uint32_t rp_bdf, uint32_t count,
                       uint32_t stream_id, uint32_t rid)
{
  return val_pcie_ide_establish_streams(bdf, rp_bdf, count, count, stream_id, rid);
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

  if (val_device_session_open(bdf) != ACS_STATUS_PASS)
    return ACS_STATUS_ERR;
  slot = spdm_find_slot(bdf);
  ctx = &slot->ctx;
  session_id = slot->session_id;

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
  lock_param.default_stream_id     = slot->ide_configured ? slot->stream_id : 0;
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

  slot->tdi_locked = 1u;

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
  /* Shared cleanup stops TDISP and IDE before closing the secured session. */
  (void)val_device_unlock(bdf);
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

  uint32_t cleanup_failed = 0u;

  /* Stop TDISP while the secured SPDM session and IDE keys remain available. */
  if (slot->tdi_locked) {
    uint8_t tdi_state;

    status = val_spdm_send_pci_tdisp_stop_interface(&slot->ctx, slot->session_id,
                                                  &interface_id);
    if (status != ACS_STATUS_PASS)
      cleanup_failed = 1u;
    else {
      status = val_spdm_send_pci_tdisp_get_interface_state(&slot->ctx, slot->session_id,
                                                          &interface_id, &tdi_state);
      if (status != ACS_STATUS_PASS || tdi_state != PCI_TDISP_INTERFACE_STATE_CONFIG_UNLOCKED)
        cleanup_failed = 1u;
      else
        slot->tdi_locked = 0u;
    }
  }
  if (slot->ide_configured) {
    PCIE_IDE_SELECTOR selector = {0};

    /* Follow TF-RMM teardown: EP TX, RP TX, EP RX, then RP RX.
     * Complete all three substreams at one port before moving to its partner.
     * Preserve the first failure while attempting the remaining cleanup.
     */
    selector.stream_id = slot->stream_id;
    for (uint32_t pass = 0; pass < 2; ++pass) {
      selector.direction = pass == 0u ? PCIE_IDE_TX : PCIE_IDE_RX;
      for (uint32_t sub = 0; sub < 3; ++sub) {
        uint8_t key_sub_stream = (uint8_t)((sub << 4) | (selector.direction << 1));

        if (LIBSPDM_STATUS_IS_ERROR(pci_ide_km_key_set_stop(NULL, slot->ctx.spdm_context,
              &slot->session_id, slot->stream_id, key_sub_stream, 0)))
          cleanup_failed = 1u;
      }
      if (slot->rp_key_cleanup_required) {
        for (uint32_t sub = 0; sub < 3; ++sub) {
          selector.sub_stream = (uint8_t)sub;
          if (val_pcie_rp_ide_key_stop(slot->rp_bdf, &selector) != ACS_STATUS_PASS)
            cleanup_failed = 1u;
        }
      }
    }

    /* ACS also leaves both stream blocks disabled for the next test. */
    if (val_ide_set_sel_stream(bdf, slot->ep_count, 0) != ACS_STATUS_PASS)
      cleanup_failed = 1u;
    if (val_ide_set_sel_stream(slot->rp_bdf, slot->rp_count, 0) != ACS_STATUS_PASS)
      cleanup_failed = 1u;
  }

  status = val_spdm_session_close(&slot->ctx, slot->session_id);
  if (status == ACS_STATUS_PASS)
    val_print(ACS_PRINT_INFO, " SPDM session_close PASS 0x%x", status);
  else if (status == ACS_STATUS_SKIP)
    val_print(ACS_PRINT_WARN, " SPDM session_close SKIP 0x%x", status);
  else
    val_print(ACS_PRINT_ERR,  " SPDM session_close ERR 0x%x", status);

  if (status != ACS_STATUS_PASS)
    cleanup_failed = 1u;
  val_spdm_context_deinit(&slot->ctx);
  spdm_free_slot(slot);
  return cleanup_failed ? ACS_STATUS_ERR : ACS_STATUS_PASS;
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
  if (val_pcie_read_cfg(bdf, ide_cap_base + IDE_CAP_REG, &reg_value) != PCIE_SUCCESS)
      return 1;
  sel_ide_str_supported = (reg_value & SEL_IDE_STR_MASK) >> SEL_IDE_STR_SHIFT;
  if (!sel_ide_str_supported)
  {
      val_print(ACS_PRINT_ERR, " Selective IDE str not supported for BDF: %x", bdf);
      return 1;
  }

  /* Get the number of Selective IDE stream */
  num_sel_ide_stream_supp = (reg_value & NUM_SEL_STR_MASK) >> NUM_SEL_STR_SHIFT;
  if (str_cnt == 0 || str_cnt > num_sel_ide_stream_supp + 1)
      return 1;

  /* Skip Link IDE register blocks only when Link IDE is supported. */
  num_tc_supp = (reg_value & NUM_TC_SUPP_MASK) >> NUM_TC_SUPP_SHIFT;
  current_base_offset = ide_cap_base + IDE_CAP_REG_SIZE;
  if (reg_value & LINK_IDE_STR_MASK)
      current_base_offset += (num_tc_supp + 1) * LINK_IDE_BLK_SIZE;

  count = 0;
  while (count++ <= num_sel_ide_stream_supp)
  {
      if (current_base_offset + SEL_IDE_CAP_REG_SIZE + RID_ADDR_REG1_SIZE +
          RID_ADDR_REG2_SIZE > PCIE_CFG_SIZE ||
          val_pcie_read_cfg(bdf, current_base_offset, &reg_value) != PCIE_SUCCESS)
          return 1;
      num_addr_asso_block = (reg_value & NUM_ADDR_ASSO_REG_MASK) >> NUM_ADDR_ASSO_REG_SHIFT;
      if (current_base_offset + SEL_IDE_CAP_REG_SIZE + RID_ADDR_REG1_SIZE +
          RID_ADDR_REG2_SIZE + num_addr_asso_block * IDE_ADDR_REG_BLK_SIZE >
          PCIE_CFG_SIZE)
          return 1;

      /* Set/Unset the Selective IDE Stream enable bit */
      if (count == str_cnt)
      {
          if (val_pcie_read_cfg(bdf, current_base_offset + SEL_IDE_CAP_CNTRL_REG,
                               &reg_value) != PCIE_SUCCESS)
              return 1;
          if (enable)
              val_pcie_write_cfg(bdf, current_base_offset + SEL_IDE_CAP_CNTRL_REG, reg_value | 1);
          else
              /* Preserve Stream ID so RP KEY_STOP can resolve the key context. */
              val_pcie_write_cfg(bdf, current_base_offset + SEL_IDE_CAP_CNTRL_REG,
                                 reg_value & ~1u);

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


/**
 * @brief Program the first address association of a disabled Selective IDE stream.
 *
 * @param bdf Port BDF.
 * @param str_cnt Selective IDE block number, starting at 1.
 * @param base Inclusive base address; encoded at 1 MiB granularity.
 * @param limit Inclusive limit address; encoded at 1 MiB granularity.
 * @param valid One to enable the association, zero to invalidate it.
 * @note PCIe 6.2 section 7.9.26.5.5 defines 1 MiB address granularity.
 * @return ACS_STATUS_PASS on success, or ACS_STATUS_ERR for an invalid request,
 *         enabled stream, absent address block, or configuration access failure.
 */
uint32_t
val_ide_program_address_range(uint32_t bdf, uint32_t str_cnt,
                              uint64_t base, uint64_t limit, uint32_t valid)
{
  uint32_t offset, capability, streams, blocks, control, value;
  const uint32_t stream_header_size = SEL_IDE_CAP_REG_SIZE +
                                      RID_ADDR_REG1_SIZE + RID_ADDR_REG2_SIZE;

  if (valid > 1u || base > limit || val_pcie_find_capability(bdf, PCIE_ECAP, ECID_IDE, &offset))
    return ACS_STATUS_ERR;

  if (val_pcie_read_cfg(bdf, offset + IDE_CAP_REG, &capability) ||
      !(capability & SEL_IDE_STR_MASK))
    return ACS_STATUS_ERR;

  /* Decode the supported Selective IDE stream count. */
  streams = ((capability & NUM_SEL_STR_MASK) >> NUM_SEL_STR_SHIFT) + 1u;
  if (!str_cnt || str_cnt > streams)
    return ACS_STATUS_ERR;

  /* Skip the capability header and any Link IDE stream blocks. */
  offset += IDE_CAP_REG_SIZE;
  if (capability & LINK_IDE_STR_MASK)
    offset += (((capability & NUM_TC_SUPP_MASK) >> NUM_TC_SUPP_SHIFT) + 1u) *
              LINK_IDE_BLK_SIZE;

  /* Locate the requested stream using each block's address count. */
  for (uint32_t stream = 1; stream <= str_cnt; ++stream) {
    if (offset > PCIE_CFG_SIZE - stream_header_size || val_pcie_read_cfg(bdf, offset, &value))
      return ACS_STATUS_ERR;

    blocks = (value & NUM_ADDR_ASSO_REG_MASK) >> NUM_ADDR_ASSO_REG_SHIFT;
    if (blocks > (PCIE_CFG_SIZE - offset - stream_header_size) / IDE_ADDR_REG_BLK_SIZE)
      return ACS_STATUS_ERR;

    if (stream != str_cnt) {
      offset += stream_header_size + blocks * IDE_ADDR_REG_BLK_SIZE;
      continue;
    }

    /* Require an address block and a disabled stream before writing. */
    if (!blocks || val_pcie_read_cfg(bdf, offset + SEL_IDE_CAP_CNTRL_REG, &control) ||
        (control & SEL_IDE_STR_EN_MASK))
      return ACS_STATUS_ERR;

    offset += stream_header_size;

    /* Remove stale associations before publishing the new valid range. */
    for (uint32_t block = 0; block < blocks; ++block) {
      uint32_t address = offset + block * IDE_ADDR_REG_BLK_SIZE;
      if (val_pcie_read_cfg(bdf, address, &value))
        return ACS_STATUS_ERR;

      val_pcie_write_cfg(bdf, address, value & ~1u);
    }

    if (val_pcie_read_cfg(bdf, offset, &control))
      return ACS_STATUS_ERR;

    /* Write the upper addresses, then publish the range and Valid bit. */
    val_pcie_write_cfg(bdf, offset + 4u, (uint32_t)(limit >> 32));
    val_pcie_write_cfg(bdf, offset + 8u, (uint32_t)(base >> 32));
    value = (control & 0xfeu) | (((uint32_t)(base >> 20) & 0xfffu) << 8) |
            (((uint32_t)(limit >> 20) & 0xfffu) << 20) | valid;
    val_pcie_write_cfg(bdf, offset, value);

    /* Verify the programmed association before reporting success. */
    if (val_pcie_read_cfg(bdf, offset, &control) || control != value)
      return ACS_STATUS_ERR;

    return ACS_STATUS_PASS;
  }

  return ACS_STATUS_ERR;
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
  if (val_pcie_read_cfg(bdf, ide_cap_base + IDE_CAP_REG, &reg_value) != PCIE_SUCCESS)
      return 1;
  sel_ide_str_supported = (reg_value & SEL_IDE_STR_MASK) >> SEL_IDE_STR_SHIFT;
  if (!sel_ide_str_supported)
  {
      val_print(ACS_PRINT_ERR, " Selective IDE str not supported for BDF: %x", bdf);
      return 1;
  }

  /* Get the number of Selective IDE stream */
  num_sel_ide_stream_supp = (reg_value & NUM_SEL_STR_MASK) >> NUM_SEL_STR_SHIFT;
  if (str_cnt == 0 || str_cnt > num_sel_ide_stream_supp + 1)
      return 1;

  /* Skip Link IDE register blocks only when Link IDE is supported. */
  num_tc_supp = (reg_value & NUM_TC_SUPP_MASK) >> NUM_TC_SUPP_SHIFT;
  current_base_offset = ide_cap_base + IDE_CAP_REG_SIZE;
  if (reg_value & LINK_IDE_STR_MASK)
      current_base_offset += (num_tc_supp + 1) * LINK_IDE_BLK_SIZE;

  count = 0;
  while (count++ <= num_sel_ide_stream_supp)
  {
      if (current_base_offset + SEL_IDE_CAP_REG_SIZE + RID_ADDR_REG1_SIZE +
          RID_ADDR_REG2_SIZE > PCIE_CFG_SIZE ||
          val_pcie_read_cfg(bdf, current_base_offset, &reg_value) != PCIE_SUCCESS)
          return 1;
      num_addr_asso_block = (reg_value & NUM_ADDR_ASSO_REG_MASK) >> NUM_ADDR_ASSO_REG_SHIFT;
      if (current_base_offset + SEL_IDE_CAP_REG_SIZE + RID_ADDR_REG1_SIZE +
          RID_ADDR_REG2_SIZE + num_addr_asso_block * IDE_ADDR_REG_BLK_SIZE >
          PCIE_CFG_SIZE)
          return 1;

      /* Write the given Stream ID in the Selective IDE Stream control Register Bit[31:24] */
      if (count == str_cnt)
      {
          if (val_pcie_read_cfg(bdf, current_base_offset + SEL_IDE_CAP_CNTRL_REG,
                               &reg_value) != PCIE_SUCCESS)
              return 1;

          /* Preserve Stream Enable and every control field other than Stream ID. */
          reg_value = (reg_value & ~SEL_IDE_STR_ID_MASK) |
                      ((stream_id << SEL_IDE_STR_ID_SHIFT) & SEL_IDE_STR_ID_MASK);
          val_pcie_write_cfg(bdf, current_base_offset + SEL_IDE_CAP_CNTRL_REG, reg_value);
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
  if (val_pcie_read_cfg(bdf, ide_cap_base + IDE_CAP_REG, &reg_value) != PCIE_SUCCESS)
      return 1;
  sel_ide_str_supported = (reg_value & SEL_IDE_STR_MASK) >> SEL_IDE_STR_SHIFT;
  if (!sel_ide_str_supported)
  {
      val_print(ACS_PRINT_ERR, " Selective IDE str not supported for BDF: %x", bdf);
      return 1;
  }

  /* Get the number of Selective IDE stream */
  num_sel_ide_stream_supp = (reg_value & NUM_SEL_STR_MASK) >> NUM_SEL_STR_SHIFT;
  if (str_cnt == 0 || str_cnt > num_sel_ide_stream_supp + 1)
      return 1;

  /* Skip Link IDE register blocks only when Link IDE is supported. */
  num_tc_supp = (reg_value & NUM_TC_SUPP_MASK) >> NUM_TC_SUPP_SHIFT;
  current_base_offset = ide_cap_base + IDE_CAP_REG_SIZE;
  if (reg_value & LINK_IDE_STR_MASK)
      current_base_offset += (num_tc_supp + 1) * LINK_IDE_BLK_SIZE;

  count = 0;
  while (count++ <= num_sel_ide_stream_supp)
  {
      if (current_base_offset + SEL_IDE_CAP_REG_SIZE + RID_ADDR_REG1_SIZE +
          RID_ADDR_REG2_SIZE > PCIE_CFG_SIZE ||
          val_pcie_read_cfg(bdf, current_base_offset, &reg_value) != PCIE_SUCCESS)
          return 1;
      num_addr_asso_block = (reg_value & NUM_ADDR_ASSO_REG_MASK) >> NUM_ADDR_ASSO_REG_SHIFT;
      if (current_base_offset + SEL_IDE_CAP_REG_SIZE + RID_ADDR_REG1_SIZE +
          RID_ADDR_REG2_SIZE + num_addr_asso_block * IDE_ADDR_REG_BLK_SIZE >
          PCIE_CFG_SIZE)
          return 1;

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
          /* Write RID Base and Valid together in RID Association Register 2. */
          val_pcie_write_cfg(bdf, rid_asso_reg_2,
                            ((base << 8) & 0xFFFF00) | (valid & 0x1));

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

  if (num_sel_str == NULL)
      return 1;

  /* Check IDE Extended Capability register is present */
  if (val_pcie_find_capability(bdf, PCIE_ECAP, ECID_IDE, &ide_cap_base) != PCIE_SUCCESS)
  {
      val_print(ACS_PRINT_ERR,
                    " PCIe IDE Capability not present for BDF: 0x%x", bdf);
      return 1;
  }

  /* Check if Selective IDE Stream is supported */
  if (val_pcie_read_cfg(bdf, ide_cap_base + IDE_CAP_REG, &reg_value) != PCIE_SUCCESS)
      return 1;
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
          and returns the link stream count encoded in NUM_TC_SUPP when Link IDE is supported.
          The count is zero when Link IDE is not supported.

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

  if (val_pcie_read_cfg(bdf, ide_cap_base + IDE_CAP_REG, &reg_value) != PCIE_SUCCESS)
      return 1;

  *num_link_streams = 0;
  if (reg_value & LINK_IDE_STR_MASK)
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
  @retval 1  Capability missing, Link IDE unsupported, index out of range,
             or configuration access error.
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

  if (val_pcie_read_cfg(bdf, ide_cap_base + IDE_CAP_REG, &reg_value) != PCIE_SUCCESS)
      return 1;

  if (!(reg_value & LINK_IDE_STR_MASK))
  {
      val_print(ACS_PRINT_ERR, " Link IDE not supported for BDF: 0x%x", bdf);
      return 1;
  }

  num_link_streams = ((reg_value & NUM_TC_SUPP_MASK) >> NUM_TC_SUPP_SHIFT) + 1;

  if (link_index >= num_link_streams)
  {
      val_print(ACS_PRINT_ERR, " Invalid Link IDE stream index %d", link_index);
      val_print(ACS_PRINT_ERR, " BDF: 0x%x", bdf);
      return 1;
  }

  ide_cap_base += IDE_CAP_REG_SIZE;
  ide_cap_base += (link_index * LINK_IDE_BLK_SIZE);

  if (val_pcie_read_cfg(bdf, ide_cap_base + LINK_IDE_STATUS_REG, &reg_value) != PCIE_SUCCESS)
      return 1;

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

  if (str_status == NULL)
      return 1;

  /* Check IDE Extended Capability register is present */
  if (val_pcie_find_capability(bdf, PCIE_ECAP, ECID_IDE, &ide_cap_base) != PCIE_SUCCESS)
  {
      val_print(ACS_PRINT_ERR,
                    " PCIe IDE Capability not present for BDF: 0x%x", bdf);
      return 1;
  }

  /* Check if Selective IDE Stream is supported */
  if (val_pcie_read_cfg(bdf, ide_cap_base + IDE_CAP_REG, &reg_value) != PCIE_SUCCESS)
      return 1;
  sel_ide_str_supported = (reg_value & SEL_IDE_STR_MASK) >> SEL_IDE_STR_SHIFT;
  if (!sel_ide_str_supported)
  {
      val_print(ACS_PRINT_ERR, " Selective IDE str not supported for BDF: %x", bdf);
      return 1;
  }

  /* Get the number of Selective IDE stream */
  num_sel_ide_stream_supp = (reg_value & NUM_SEL_STR_MASK) >> NUM_SEL_STR_SHIFT;
  if (str_cnt == 0 || str_cnt > num_sel_ide_stream_supp + 1)
      return 1;

  /* Skip Link IDE register blocks only when Link IDE is supported. */
  num_tc_supp = (reg_value & NUM_TC_SUPP_MASK) >> NUM_TC_SUPP_SHIFT;
  current_base_offset = ide_cap_base + IDE_CAP_REG_SIZE;
  if (reg_value & LINK_IDE_STR_MASK)
      current_base_offset += (num_tc_supp + 1) * LINK_IDE_BLK_SIZE;

  count = 0;
  while (count++ <= num_sel_ide_stream_supp)
  {
      if (current_base_offset + SEL_IDE_CAP_REG_SIZE + RID_ADDR_REG1_SIZE +
          RID_ADDR_REG2_SIZE > PCIE_CFG_SIZE ||
          val_pcie_read_cfg(bdf, current_base_offset, &reg_value) != PCIE_SUCCESS)
          return 1;
      num_addr_asso_block = (reg_value & NUM_ADDR_ASSO_REG_MASK) >> NUM_ADDR_ASSO_REG_SHIFT;
      if (current_base_offset + SEL_IDE_CAP_REG_SIZE + RID_ADDR_REG1_SIZE +
          RID_ADDR_REG2_SIZE + num_addr_asso_block * IDE_ADDR_REG_BLK_SIZE >
          PCIE_CFG_SIZE)
          return 1;

      /* Get the Status of Selective IDE Stream state */
      if (count == str_cnt)
      {
          if (val_pcie_read_cfg(bdf, current_base_offset + SEL_IDE_CAP_STATUS_REG,
                               &reg_value) != PCIE_SUCCESS)
              return 1;
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

  /* Stream ID programming preserves Enable; disable explicitly before reconfiguration. */
  status = val_ide_set_sel_stream(bdf, count, 0);
  if (status)
  {
      val_print(ACS_PRINT_ERR, " Failed to disable Sel Stream for BDF: 0x%x", bdf);
      return 1;
  }

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
