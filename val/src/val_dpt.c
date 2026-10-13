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

#include "include/val.h"
#include "include/val_common.h"
#include "include/val_pcie.h"
#include "include/val_da.h"
#include "include/val_dpt.h"
#include "include/val_smmu.h"
#include "include/val_iovirt.h"

#include "include/val_memory.h"
#include "include/val_mem_interface.h"
#include "include/val_el32.h"
#include "include/val_mem_interface.h"
#include "include/val_interface.h"

/**
  @brief   This API will execute all RME DPT tests designated for a given compliance level
           1. Caller       -  Application layer.
           2. Prerequisite -  val_pe_create_info_table, val_allocate_shared_mem
  @param   num_pe - the number of PE to run these tests on.
  @return  Consolidated status of all the tests run.
**/

uint32_t
val_rme_dpt_execute_tests(uint32_t num_pe)
{
  uint32_t status = ACS_STATUS_SKIP, reset_status, smmu_cnt;
  uint64_t num_smmus = val_smmu_get_info(SMMU_NUM_CTRL, 0);
  uint64_t smmu_base_arr[num_smmus], pgt_attr_el3;

  g_curr_module = 1 << DPT_MODULE_ID;

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

  reset_status = val_read_reset_status();

  if (reset_status != RESET_TST12_FLAG &&
      reset_status != RESET_TST31_FLAG &&
      reset_status != RESET_LS_DISBL_FLAG &&
      reset_status != RESET_LS_TEST3_FLAG)
  {
    val_print(ACS_PRINT_ALWAYS, "\n\n*******************************************************\n", 0);
    status = val_execute_module_tests(DPT_MODULE_ID,
                                      DPT_MODULE_START,
                                      DPT_MODULE_END,
                                      num_pe,
                                      status);
  }

  return status;

}


uint32_t
val_dpt_ide_stop(uint32_t ep_bdf, uint32_t rp_bdf, uint32_t ep_count,
                   uint32_t count)
{
  uint32_t status = ACS_STATUS_PASS;

  if (!count)
    return status;
  /* Unlock the RP block, then use shared TDISP/IDE/session teardown. */
  if (val_ide_set_sel_stream_lock(rp_bdf, count, 0))
    status = ACS_STATUS_ERR;
  if (val_device_unlock(ep_bdf) != ACS_STATUS_PASS)
    status = ACS_STATUS_ERR;
  if (val_ide_program_address_range(rp_bdf, count, 0, 0, 0))
    status = ACS_STATUS_ERR;
  /* A failed TDISP lock may already have closed the session. Ensure both
   * streams are disabled, and continue cleanup after a teardown error.
   */
  if (val_ide_set_sel_stream(ep_bdf, ep_count, 0))
    status = ACS_STATUS_ERR;
  if (val_ide_set_sel_stream(rp_bdf, count, 0))
    status = ACS_STATUS_ERR;
  else if (val_ide_program_address_range(rp_bdf, count, 0, 0, 0))
    status = ACS_STATUS_ERR;
  return status;
}

uint32_t
val_dpt_ide_setup_target(uint32_t ep_bdf, uint32_t rp_bdf, uint32_t req_rp_bdf,
                      uint64_t bar, uint64_t size, uint32_t *active_count)
{
  uint32_t ep_streams, rp_streams, status, ep_state, rp_state, retry;
  uint32_t count = rp_bdf == req_rp_bdf ? 2u : 1u;

  if (active_count == NULL)
    return ACS_STATUS_ERR;
  *active_count = 0;
  if (!size || bar > ~(uint64_t)0 - (size - 1u) ||
      val_ide_get_num_sel_str(ep_bdf, &ep_streams) || ep_streams < 1u ||
      val_ide_get_num_sel_str(rp_bdf, &rp_streams) || rp_streams < count)
    return ACS_STATUS_ERR;

  /* Provision target keys in a separate RP block when the RP is shared. */
  status = val_pcie_ide_establish_streams(ep_bdf, rp_bdf, 1u, count,
                    val_generate_stream_id(), PCIE_CREATE_BDF_PACKED(ep_bdf));
  if (status != ACS_STATUS_PASS)
    return status;
  *active_count = count;

  /* Address-routed traffic selects the target stream through its BAR range. */
  if (val_ide_set_sel_stream(rp_bdf, count, 0) ||
      val_ide_program_address_range(rp_bdf, count, bar, bar + size - 1u, 1) ||
      val_ide_set_sel_stream(rp_bdf, count, 1))
    return ACS_STATUS_ERR;
  /* Recheck both ends after changing the address association and re-enabling. */
  for (retry = 0; retry <= 10u; ++retry) {
    if (val_get_sel_str_status(ep_bdf, 1u, &ep_state) ||
        val_get_sel_str_status(rp_bdf, count, &rp_state))
      return ACS_STATUS_ERR;
    if (ep_state == STREAM_STATE_SECURE && rp_state == STREAM_STATE_SECURE)
      break;
    if (retry < 10u)
      (void)val_time_delay_ms(1);
  }
  if (ep_state != STREAM_STATE_SECURE || rp_state != STREAM_STATE_SECURE ||
      val_ide_set_sel_stream_lock(rp_bdf, count, 1) || val_device_lock(ep_bdf))
    return ACS_STATUS_ERR;
  return ACS_STATUS_PASS;
}
