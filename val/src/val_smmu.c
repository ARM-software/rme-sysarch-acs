/** @file
 * Copyright (c) 2022-2026, Arm Limited or its affiliates. All rights reserved.
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

#include "include/val_smmu.h"
#include "include/val_iovirt.h"
#include "include/val_el32.h"
#include "include/val_memory.h"

/*
 * The VAL SMMU base passed to these helpers is the start of the SMMU register
 * frame. Root Page 0 registers are addressed directly from that base.
 */
#define SMMU_R_PAGE_0_OFFSET       0u
#define SMMU_R_CR0_OFFSET          (SMMU_R_PAGE_0_OFFSET + 0x020u)
#define SMMU_R_CR0ACK_OFFSET       (SMMU_R_PAGE_0_OFFSET + 0x024u)
#define SMMU_R_DPT_BASE_CFG_OFFSET (SMMU_R_PAGE_0_OFFSET + 0x208u)
#define SMMU_R_DPT_WALK_EN_MASK    (1u << 10)
#define SMMU_DPT_CFG_SYNC_RETRIES  10000u

/**
  @brief  This API reads 32-bit data from a register of an SMMU controller
          specified by index
  @param offset   32-bit register offset
  @param index    when multiple SMMU controllers are present in the system.
                  '0' based index to uniquely identify them

  @return  32-bit data value
**/
uint32_t
val_smmu_read_cfg(uint32_t offset, uint32_t index)
{

  uint64_t ctrl_base = val_smmu_get_info(SMMU_CTRL_BASE, index);

  if (ctrl_base == 0)
      return 0;

  return val_mmio_read(ctrl_base + offset);
}

/**
  @brief  Read SMMU_R_DPT_BASE_CFG using EL3 access.
  @param  smmu_base  SMMU controller base address
  @param  cfg        On return, DPT base config value
  @return ACS_STATUS_PASS/ERR
**/
uint32_t
val_smmu_read_dpt_base_cfg(uint64_t smmu_base, uint32_t *cfg)
{
  if ((smmu_base == 0u) || (cfg == NULL))
    return ACS_STATUS_ERR;

  return val_memory_read_el3(smmu_base + SMMU_R_DPT_BASE_CFG_OFFSET, cfg);
}

/**
  @brief  Write SMMU_R_CR0 and wait until SMMU_R_CR0ACK reflects the value.
  @param  smmu_base  SMMU controller base address
  @param  value      Value to write to SMMU_R_CR0
  @return ACS_STATUS_PASS/ERR
**/
uint32_t
val_smmu_write_root_cr0_sync(uint64_t smmu_base, uint32_t value)
{
  uint32_t ack;

  if (smmu_base == 0u)
    return ACS_STATUS_ERR;

  if (val_memory_write_el3(smmu_base + SMMU_R_CR0_OFFSET, value) != ACS_STATUS_PASS)
    return ACS_STATUS_ERR;

  for (uint32_t retry = 0u; retry < SMMU_DPT_CFG_SYNC_RETRIES; ++retry)
  {
    if (val_memory_read_el3(smmu_base + SMMU_R_CR0ACK_OFFSET, &ack) != ACS_STATUS_PASS)
      return ACS_STATUS_ERR;

    if (ack == value)
      return ACS_STATUS_PASS;
  }

  val_print(ACS_PRINT_ERR, " SMMU_R_CR0ACK sync timed out", 0);
  return ACS_STATUS_ERR;
}

/**
  @brief  Write SMMU_R_DPT_BASE_CFG while preserving DPT walk enable state.
  @param  smmu_base  SMMU controller base address
  @param  cfg        DPT base config value to program
  @return ACS_STATUS_PASS/ERR
**/
uint32_t
val_smmu_write_dpt_base_cfg(uint64_t smmu_base, uint32_t cfg)
{
  uint32_t cr0;
  uint32_t readback;

  if (smmu_base == 0u)
    return ACS_STATUS_ERR;

  if (val_memory_read_el3(smmu_base + SMMU_R_CR0_OFFSET, &cr0) != ACS_STATUS_PASS)
    return ACS_STATUS_ERR;

  if ((cr0 & SMMU_R_DPT_WALK_EN_MASK) != 0u)
  {
    if (val_smmu_write_root_cr0_sync(smmu_base, cr0 & ~SMMU_R_DPT_WALK_EN_MASK)
        != ACS_STATUS_PASS)
    {
      return ACS_STATUS_ERR;
    }
  }

  if (val_memory_write_el3(smmu_base + SMMU_R_DPT_BASE_CFG_OFFSET, cfg)
      != ACS_STATUS_PASS)
    return ACS_STATUS_ERR;

  if (val_memory_read_el3(smmu_base + SMMU_R_DPT_BASE_CFG_OFFSET, &readback)
      != ACS_STATUS_PASS)
    return ACS_STATUS_ERR;

  if (readback != cfg)
  {
    val_print(ACS_PRINT_ERR, " SMMU_R_DPT_BASE_CFG readback 0x%x",
              (uint64_t)readback);
    return ACS_STATUS_ERR;
  }

  if ((cr0 & SMMU_R_DPT_WALK_EN_MASK) != 0u)
  {
    if (val_smmu_write_root_cr0_sync(smmu_base, cr0) != ACS_STATUS_PASS)
      return ACS_STATUS_ERR;
  }

  return ACS_STATUS_PASS;
}

/**
  @brief  Convert an SMMU DPTPS encoding to the corresponding PA width.
  @param  encoding  DPTPS field encoding
  @return PA width in bits, or zero for an unsupported encoding
**/
uint32_t
val_smmu_dptps_bits_from_encoding(uint32_t encoding)
{
  switch (encoding & SMMU_DPT_BASE_CFG_DPTPS_MASK)
  {
  case 0u: return 32u;
  case 1u: return 36u;
  case 2u: return 40u;
  case 3u: return 42u;
  case 4u: return 44u;
  case 5u: return 48u;
  case 6u: return 52u;
  default: return 0u;
  }
}

/**
  @brief  Select DPTPS and L0DPTSZ encodings that cover the input address.
  @param  address            Physical address that must be covered by DPT walks
  @param  dptps_encoding    On return, selected DPTPS encoding
  @param  l0dptsz_encoding  On return, selected L0DPTSZ encoding
  @return ACS_STATUS_PASS/SKIP/ERR
**/
uint32_t
val_smmu_select_dptps_encoding(uint64_t address,
                               uint32_t *dptps_encoding,
                               uint32_t *l0dptsz_encoding)
{
  if ((dptps_encoding == NULL) || (l0dptsz_encoding == NULL))
    return ACS_STATUS_ERR;

  if (address < (1ull << 32))
  {
    *dptps_encoding = 0u;
    *l0dptsz_encoding = 0u;
  }
  else if (address < (1ull << 36))
  {
    *dptps_encoding = 1u;
    *l0dptsz_encoding = 4u;
  }
  else if (address < (1ull << 40))
  {
    *dptps_encoding = 2u;
    *l0dptsz_encoding = 6u;
  }
  else if (address < (1ull << 42))
  {
    *dptps_encoding = 3u;
    *l0dptsz_encoding = 6u;
  }
  else if (address < (1ull << 44))
  {
    *dptps_encoding = 4u;
    *l0dptsz_encoding = 6u;
  }
  else if (address < (1ull << 48))
  {
    *dptps_encoding = 5u;
    *l0dptsz_encoding = 9u;
  }
  else
  {
    return ACS_STATUS_SKIP;
  }

  return ACS_STATUS_PASS;
}

/**
  @brief  Ensure the SMMU DPT base configuration can cover a translated PA.

  @param  smmu_index       SMMU controller index.
  @param  translated_addr  Physical address that DPT walks must be able to cover.
  @param  state            Caller-owned restore state for this programming.

  @return ACS_STATUS_PASS/SKIP/ERR.
**/
uint32_t
val_smmu_configure_dpt_coverage(uint32_t smmu_index,
                                uint64_t translated_addr,
                                VAL_SMMU_DPT_CFG_STATE *state)
{
  uint32_t dpt_cfg;
  uint32_t current_dptps_bits;
  uint32_t desired_dptps_encoding;
  uint32_t desired_l0dptsz_encoding;
  uint32_t desired_cfg;
  uint64_t smmu_base;

  if ((translated_addr == 0u) || (state == NULL))
    return ACS_STATUS_ERR;

  val_memory_set(state, sizeof(*state), 0);

  smmu_base = val_smmu_get_info(SMMU_CTRL_BASE, smmu_index);
  if (smmu_base == 0u)
    return ACS_STATUS_SKIP;

  state->smmu_base = smmu_base;
  if (val_smmu_read_dpt_base_cfg(smmu_base, &dpt_cfg) != ACS_STATUS_PASS)
    return ACS_STATUS_ERR;

  state->original_cfg = dpt_cfg;
  state->valid = 1u;
  current_dptps_bits =
    val_smmu_dptps_bits_from_encoding(
      (dpt_cfg >> SMMU_DPT_BASE_CFG_DPTPS_SHIFT) &
      SMMU_DPT_BASE_CFG_DPTPS_MASK);

  if ((current_dptps_bits != 0u) &&
      ((current_dptps_bits >= 64u) ||
       (translated_addr < (1ull << current_dptps_bits))))
  {
    return ACS_STATUS_PASS;
  }

  if (val_smmu_select_dptps_encoding(translated_addr,
                                     &desired_dptps_encoding,
                                     &desired_l0dptsz_encoding) != ACS_STATUS_PASS)
  {
    return ACS_STATUS_SKIP;
  }

  desired_cfg = dpt_cfg;
  desired_cfg &= ~(SMMU_DPT_BASE_CFG_DPTPS_MASK <<
                   SMMU_DPT_BASE_CFG_DPTPS_SHIFT);
  desired_cfg &= ~(SMMU_DPT_BASE_CFG_L0DPTSZ_MASK <<
                   SMMU_DPT_BASE_CFG_L0DPTSZ_SHIFT);
  desired_cfg |= (desired_dptps_encoding & SMMU_DPT_BASE_CFG_DPTPS_MASK) <<
                 SMMU_DPT_BASE_CFG_DPTPS_SHIFT;
  desired_cfg |= (desired_l0dptsz_encoding & SMMU_DPT_BASE_CFG_L0DPTSZ_MASK) <<
                 SMMU_DPT_BASE_CFG_L0DPTSZ_SHIFT;

  if (val_smmu_write_dpt_base_cfg(smmu_base, desired_cfg) != ACS_STATUS_PASS)
    return ACS_STATUS_ERR;

  state->updated = 1u;
  return ACS_STATUS_PASS;
}

/**
  @brief  Restore DPT base configuration saved by val_smmu_configure_dpt_coverage.

  @param  state  Restore state returned by val_smmu_configure_dpt_coverage.

  @return ACS_STATUS_PASS/ERR.
**/
uint32_t
val_smmu_restore_dpt_coverage(const VAL_SMMU_DPT_CFG_STATE *state)
{
  if ((state == NULL) || (state->valid == 0u) || (state->updated == 0u))
    return ACS_STATUS_PASS;

  return val_smmu_write_dpt_base_cfg(state->smmu_base, state->original_cfg);
}

/**
  @brief   This API executes all the SMMU tests sequentially
           1. Caller       -  Application layer.
           2. Prerequisite -  val_smmu_create_info_table()
  @param   num_pe - the number of PE to run these tests on.
  @return  Consolidated status of all the tests run.
**/
uint32_t
val_smmu_execute_tests(uint32_t num_pe)
{
  uint32_t status = ACS_STATUS_SKIP;
  uint32_t num_smmu;

  num_smmu = val_iovirt_get_smmu_info(SMMU_NUM_CTRL, 0);
  if (num_smmu == 0) {
    val_print(ACS_PRINT_WARN, " No SMMU Controller Found, Skipping SMMU tests...", 0);
    return ACS_STATUS_SKIP;
  }

  g_curr_module = 1 << SMMU_MODULE_ID;

  val_print(ACS_PRINT_ALWAYS, "\n\n******************************************************* \n", 0);
  status = val_execute_module_tests(SMMU_MODULE_ID,
                                    SMMU_MODULE_START,
                                    SMMU_MODULE_END,
                                    num_pe,
                                    status);

  return status;
}
