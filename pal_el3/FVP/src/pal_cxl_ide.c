/** @file
 * Copyright (c) 2026, Arm Limited or its affiliates. All rights reserved.
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

#include "pal_el3.h"

/* FVP synthetic CXL IDE register interface. */
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

static uint32_t
cxl_ide_validate_registers(const CXL_IDE_RP_REGISTERS *registers,
                           const CXL_IDE_SELECTOR *selector)
{
  if ((registers == 0) || (selector == 0) ||
      (registers->aes == 0u) || (registers->cm_host != registers->aes))
    return CXL_IDE_ERROR;

  if (*(volatile uint32_t *)(uintptr_t)(registers->aes + CXL_RP_IDE_KM_REG_SIGNATURE) !=
      CXL_RP_IDE_KM_SIGNATURE_VALUE)
    return CXL_IDE_ERROR;

  return CXL_IDE_SUCCESS;
}

/* PCI configuration BAR0 is at 0x10; bit 2 selects a 64-bit memory BAR. */
#define CXL_RP_BAR0_OFFSET 0x10u
#define CXL_RP_BAR_MEMORY_TYPE_MASK 0x6u
#define CXL_RP_BAR_MEMORY_TYPE_64 0x4u

uint32_t
pal_cxl_rp_ide_cfg_address(uint64_t ecam_base, uint32_t rp_id, uint64_t *config)
{
  uint64_t offset = (uint64_t)rp_id << 12;

  if (config == 0 || ecam_base == 0u || (ecam_base & 0xfffu) != 0u ||
      rp_id > 0xffffu || ecam_base > UINT64_MAX - offset)
    return CXL_IDE_ERROR;
  *config = ecam_base + offset;
  return CXL_IDE_SUCCESS;
}

/* EL3 maps configuration space before PAL reads BAR0. */
uint32_t
pal_cxl_rp_ide_km_address(uint64_t config, CXL_IDE_RP_REGISTERS *registers)
{
  uint32_t bar;
  uint64_t bar0_base;

  if (config == 0u || registers == 0)
    return CXL_IDE_ERROR;
  bar = *(volatile uint32_t *)(uintptr_t)(config + CXL_RP_BAR0_OFFSET);
  if ((bar & 1u) != 0u)
    return CXL_IDE_ERROR;
  bar0_base = bar & ~0xfULL;
  if ((bar & CXL_RP_BAR_MEMORY_TYPE_MASK) == CXL_RP_BAR_MEMORY_TYPE_64)
    bar0_base |= (uint64_t)*(volatile uint32_t *)(uintptr_t)
                             (config + CXL_RP_BAR0_OFFSET + sizeof(uint32_t)) << 32;
  if (bar0_base == 0u || bar0_base > UINT64_MAX - CXL_RP_IDE_KM_BAR0_OFFSET)
    return CXL_IDE_ERROR;
  registers->aes = bar0_base + CXL_RP_IDE_KM_BAR0_OFFSET;
  registers->cm_host = registers->aes;
  return CXL_IDE_SUCCESS;
}

/** Program both RP directions into the selected bank without activating IDE. */
uint32_t
pal_cxl_rp_ide_key_program(const CXL_IDE_RP_REGISTERS *registers,
                            const CXL_IDE_SELECTOR *selector,
                            const CXL_IDE_KEY_BUFFER *rx_key,
                            const CXL_IDE_KEY_BUFFER *tx_key)
{
  uint64_t aes_base;
  uint32_t state;

  if ((rx_key == 0) || (tx_key == 0) ||
      cxl_ide_validate_registers(registers, selector) != CXL_IDE_SUCCESS)
    return CXL_IDE_ERROR;

  aes_base = registers->aes;
  *(volatile uint32_t *)(uintptr_t)(aes_base + CXL_RP_IDE_KM_REG_STREAM_SLOT) =
      (uint32_t)selector->stream_id | ((uint32_t)selector->key_slot << 8);

  /* This synthetic interface implements key words only, with no IV registers. */
  for (uint32_t idx = 0; idx < 8u; idx++) {
    *(volatile uint32_t *)(uintptr_t)(aes_base + CXL_RP_IDE_KM_REG_RX_KEY_BASE +
                                      (idx * sizeof(uint32_t))) = rx_key->key[idx];
    *(volatile uint32_t *)(uintptr_t)(aes_base + CXL_RP_IDE_KM_REG_TX_KEY_BASE +
                                      (idx * sizeof(uint32_t))) = tx_key->key[idx];
  }

  *(volatile uint32_t *)(uintptr_t)(registers->cm_host + CXL_RP_IDE_KM_REG_CONTROL) =
      CXL_RP_IDE_KM_CTRL_KEY_PROG;
  state = *(volatile uint32_t *)(uintptr_t)(registers->cm_host + CXL_RP_IDE_KM_REG_STATE);
  return (state & CXL_RP_IDE_KM_STATE_KEY_PROGRAMMED) != 0u ?
      CXL_IDE_SUCCESS : CXL_IDE_ERROR;
}

/** Activate the selected RP bank after both endpoint KEY_SET_GO operations. */
uint32_t
pal_cxl_rp_ide_key_go(const CXL_IDE_RP_REGISTERS *registers,
                       const CXL_IDE_SELECTOR *selector, uint8_t mode)
{
  uint32_t state;

  /* The existing synthetic interface has no mode-selection register. */
  (void)mode;

  if (cxl_ide_validate_registers(registers, selector) != CXL_IDE_SUCCESS)
    return CXL_IDE_ERROR;

  *(volatile uint32_t *)(uintptr_t)(registers->aes + CXL_RP_IDE_KM_REG_STREAM_SLOT) =
      (uint32_t)selector->stream_id | ((uint32_t)selector->key_slot << 8);
  *(volatile uint32_t *)(uintptr_t)(registers->cm_host + CXL_RP_IDE_KM_REG_CONTROL) =
      CXL_RP_IDE_KM_CTRL_K_SET_GO;
  state = *(volatile uint32_t *)(uintptr_t)(registers->cm_host + CXL_RP_IDE_KM_REG_STATE);
  return (state & CXL_RP_IDE_KM_STATE_ACTIVE) != 0u ? CXL_IDE_SUCCESS : CXL_IDE_ERROR;
}

/** Stop the selected RP stream/slot and verify completion. */
uint32_t
pal_cxl_rp_ide_key_stop(const CXL_IDE_RP_REGISTERS *registers,
                         const CXL_IDE_SELECTOR *selector)
{
  uint32_t state;

  if (cxl_ide_validate_registers(registers, selector) != CXL_IDE_SUCCESS)
    return CXL_IDE_ERROR;

  *(volatile uint32_t *)(uintptr_t)(registers->aes + CXL_RP_IDE_KM_REG_STREAM_SLOT) =
      (uint32_t)selector->stream_id | ((uint32_t)selector->key_slot << 8);
  *(volatile uint32_t *)(uintptr_t)(registers->cm_host + CXL_RP_IDE_KM_REG_CONTROL) =
      CXL_RP_IDE_KM_CTRL_K_SET_STOP;
  state = *(volatile uint32_t *)(uintptr_t)(registers->cm_host + CXL_RP_IDE_KM_REG_STATE);
  return (state & CXL_RP_IDE_KM_STATE_ACTIVE) == 0u ? CXL_IDE_SUCCESS : CXL_IDE_ERROR;
}
