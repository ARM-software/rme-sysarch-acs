/** @file
 * Copyright (c) 2023, 2025-2026, Arm Limited or its affiliates. All rights reserved.
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

/**
 * @brief Enable Non-secure encryption in platform-specific manner.
 *
 * Partner must implement IMPLEMNTATION_DEFINED mechanism to enable NS encryption.
 */
void pal_el3_enable_ns_encryption(void)
{
  //Partner shall implement their own IMPLEMNTATION_DEFINED
  //register for enabling and disabling the NS_Encryption
  return;
}

/**
 * @brief Disable Non-secure encryption in platform-specific manner.
 *
 * Partner must implement IMPLEMNTATION_DEFINED mechanism to disable NS encryption.
 */
void pal_el3_disable_ns_encryption(void)
{
  //Partner shall implement their own IMPLEMNTATION_DEFINED
  //register for enabling and disabling the NS_Encryption
  return;
}

/**
 * @brief Program Legacy TZ enable state.
 *
 * @param enable  Non-zero to enable, zero to disable.
 *
 * Partner must implement IMPLEMNTATION_DEFINED register programming to control legacy TZ.
 */
void pal_el3_prog_legacy_tz(int enable)
{
  //Partner shall implement their own IMPLEMNTATION_DEFINED
  //register for enabling the LEGACY_TZ_EN feature
  return;
}

/**
 * @brief Set PAS filter to Active/Inactive mode.
 *
 * @param enable  Non-zero to set Active mode, zero for Inactive.
 *
 * Partner must implement IMPLEMNTATION_DEFINED method to change PAS filter mode.
 */
void pal_el3_pas_filter_active_mode(int enable)
{
  //Partner shall implement their own IMPLEMNTATION_DEFINED
  //way for changing the Active mode of pas filter
  return;
}

uint32_t
pal_cxl_root_port_ide_program_and_enable(uint64_t bar0_base,
                                         uint8_t stream_id,
                                         uint8_t key_slot,
                                         const CXL_IDE_KEY_BUFFER *rx_key,
                                         const CXL_IDE_KEY_BUFFER *tx_key)
{
  uint64_t ide_km_base;
  uint32_t state;
  uint32_t idx;

  if ((bar0_base == 0u) || (rx_key == 0) || (tx_key == 0))
    return 1;

  ide_km_base = (bar0_base & ~0xFULL) + CXL_RP_IDE_KM_BAR0_OFFSET;
  if (*(volatile uint32_t *)(uintptr_t)(ide_km_base + CXL_RP_IDE_KM_REG_SIGNATURE) !=
      CXL_RP_IDE_KM_SIGNATURE_VALUE)
    return 1;

  *(volatile uint32_t *)(uintptr_t)(ide_km_base + CXL_RP_IDE_KM_REG_STREAM_SLOT) =
      (uint32_t)stream_id | ((uint32_t)key_slot << 8);

  for (idx = 0; idx < 8u; idx++) {
    *(volatile uint32_t *)(uintptr_t)(ide_km_base + CXL_RP_IDE_KM_REG_RX_KEY_BASE +
                                      (idx * sizeof(uint32_t))) = rx_key->key[idx];
  }

  for (idx = 0; idx < 8u; idx++) {
    *(volatile uint32_t *)(uintptr_t)(ide_km_base + CXL_RP_IDE_KM_REG_TX_KEY_BASE +
                                      (idx * sizeof(uint32_t))) = tx_key->key[idx];
  }

  *(volatile uint32_t *)(uintptr_t)(ide_km_base + CXL_RP_IDE_KM_REG_CONTROL) =
      CXL_RP_IDE_KM_CTRL_KEY_PROG;
  state = *(volatile uint32_t *)(uintptr_t)(ide_km_base + CXL_RP_IDE_KM_REG_STATE);
  if ((state & CXL_RP_IDE_KM_STATE_KEY_PROGRAMMED) == 0u)
    return 1;

  *(volatile uint32_t *)(uintptr_t)(ide_km_base + CXL_RP_IDE_KM_REG_CONTROL) =
      CXL_RP_IDE_KM_CTRL_K_SET_GO;
  state = *(volatile uint32_t *)(uintptr_t)(ide_km_base + CXL_RP_IDE_KM_REG_STATE);
  if ((state & CXL_RP_IDE_KM_STATE_ACTIVE) == 0u)
    return 1;

  return 0;
}

uint32_t
pal_cxl_root_port_ide_disable(uint64_t bar0_base,
                              uint8_t stream_id,
                              uint8_t key_slot)
{
  uint64_t ide_km_base;
  uint32_t state;

  (void)stream_id;
  (void)key_slot;

  if (bar0_base == 0u)
    return 1;

  ide_km_base = (bar0_base & ~0xFULL) + CXL_RP_IDE_KM_BAR0_OFFSET;
  if (*(volatile uint32_t *)(uintptr_t)(ide_km_base + CXL_RP_IDE_KM_REG_SIGNATURE) !=
      CXL_RP_IDE_KM_SIGNATURE_VALUE)
    return 1;

  *(volatile uint32_t *)(uintptr_t)(ide_km_base + CXL_RP_IDE_KM_REG_CONTROL) =
      CXL_RP_IDE_KM_CTRL_K_SET_STOP;
  state = *(volatile uint32_t *)(uintptr_t)(ide_km_base + CXL_RP_IDE_KM_REG_STATE);
  if ((state & CXL_RP_IDE_KM_STATE_ACTIVE) != 0u)
    return 1;

  return 0;
}

uint32_t
pal_cxl_root_port_ide_get_km_base(uint64_t bar0_base,
                                  uint64_t *ide_km_base)
{
  if ((bar0_base == 0u) || (ide_km_base == 0))
    return 1;

  *ide_km_base = (bar0_base & ~0xFULL) + CXL_RP_IDE_KM_BAR0_OFFSET;
  return 0;
}
