/** @file
  * Copyright (c) 2025, 2026, Arm Limited or its affiliates. All rights reserved.
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
#include <val_el3_debug.h>
#include <val_el3_security.h>

/**
 * @brief Attempt to disable Non-secure encryption at EL3 via PAL.
 * @return 0 if the attempt completed, nonzero if unsupported or failed.
 */
uint32_t val_el3_disable_ns_encryption(void)
{
  return pal_el3_disable_ns_encryption();
}

/**
 * @brief Program Legacy TZ enable state at EL3 via PAL.
 *
 * @param enable  Non-zero to enable, zero to disable.
 */
void val_el3_prog_legacy_tz(int enable)
{
  return pal_el3_prog_legacy_tz(enable);
}

/**
 * @brief Change EL3 security state by updating SCR_EL3.NSE and SCR_EL3.NS.
 *
 * @param attr_nse_ns  Encoded NSE/NS bits (macros NSE_SET/NS_SET extract fields).
 */
void val_el3_security_state_change(uint64_t attr_nse_ns)
{
  uint64_t scr_data, nse_bit, ns_bit;

  nse_bit = NSE_SET(attr_nse_ns);
  ns_bit = NS_SET(attr_nse_ns);
  scr_data = val_el3_read_scr_el3();
  //The SCR_EL3.NSE and SCR_EL3.NS bits decides the security state
  scr_data &= (~SCR_NSE_MASK & ~SCR_NS_MASK);
  scr_data |= ((nse_bit << SCR_NSE_SHIFT) | (ns_bit << SCR_NS_SHIFT));
  val_el3_write_scr_el3(scr_data);
}

/**
 * @brief Set PAS filter to Active/Inactive mode at EL3 via PAL.
 *
 * @param enable  Non-zero to set Active mode, zero for Inactive.
 */
void val_el3_pas_filter_active_mode(int enable)
{
  //Change the mode to Active from In-active
  pal_el3_pas_filter_active_mode(enable);
}

uint32_t
val_el3_ide_km_program_and_enable(uint64_t bar0_base,
                                  uint8_t stream_id,
                                  uint8_t key_slot,
                                  const CXL_IDE_KEY_BUFFER *rx_key,
                                  const CXL_IDE_KEY_BUFFER *tx_key)
{
  return pal_cxl_root_port_ide_program_and_enable(bar0_base,
                                                   stream_id,
                                                   key_slot,
                                                   rx_key,
                                                   tx_key);
}

uint32_t
val_el3_ide_km_disable(uint64_t bar0_base,
                       uint8_t stream_id,
                       uint8_t key_slot)
{
  return pal_cxl_root_port_ide_disable(bar0_base, stream_id, key_slot);
}

uint32_t
val_el3_ide_km_get_base(uint64_t bar0_base,
                        uint64_t *ide_km_base)
{
  return pal_cxl_root_port_ide_get_km_base(bar0_base, ide_km_base);
}
