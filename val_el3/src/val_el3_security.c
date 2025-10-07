/** @file
  * Copyright (c) 2025, Arm Limited or its affiliates. All rights reserved.
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
 * @brief Enable Non-secure encryption at EL3 via PAL.
 */
void val_el3_enable_ns_encryption(void)
{
  pal_el3_enable_ns_encryption();
}

/**
 * @brief Disable Non-secure encryption at EL3 via PAL.
 */
void val_el3_disable_ns_encryption(void)
{
  pal_el3_disable_ns_encryption();
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
