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
#include <val_el3_cxl_ide.h>
#include <val_el3_debug.h>
#include <val_el3_security.h>
#include <val_el3_pgt.h>

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

/* Discover and map Root-only configuration, AES and CXL.CM register pages. */
static uint32_t
cxl_ide_map_mmio(uint64_t address)
{
  uint64_t attributes = LOWER_ATTRS(PGT_ENTRY_ACCESS |
                                   SHAREABLE_ATTR(OUTER_SHAREABLE) |
                                   GET_ATTR_INDEX(DEV_MEM_nGnRnE) |
                                   PGT_ENTRY_AP_RW | PAS_ATTR(ROOT_PAS));

  if (address == 0u)
    return CXL_IDE_SUCCESS;
  val_el3_add_gpt_entry(address, GPT_ANY);
  return val_el3_add_mmu_entry(address, address, attributes);
}

static uint32_t
cxl_ide_get_mapped_backend(uint64_t ecam_base, uint32_t rp_id,
                            CXL_IDE_RP_REGISTERS *registers)
{
  uint64_t config;
  uint32_t status = pal_cxl_rp_ide_cfg_address(ecam_base, rp_id, &config);

  if (status != CXL_IDE_SUCCESS)
    return status;
  if (cxl_ide_map_mmio(config) != CXL_IDE_SUCCESS)
    return CXL_IDE_ERROR;

  status = pal_cxl_rp_ide_km_address(config, registers);
  if (status != CXL_IDE_SUCCESS)
    return status;
  if (cxl_ide_map_mmio(registers->aes) != CXL_IDE_SUCCESS)
    return CXL_IDE_ERROR;
  if (registers->cm_host != registers->aes)
    return cxl_ide_map_mmio(registers->cm_host);
  return CXL_IDE_SUCCESS;
}

uint32_t
val_el3_ide_km_program(uint64_t ecam_base, uint32_t rp_id,
                                  uint8_t stream_id,
                                  uint8_t key_slot,
                                  const CXL_IDE_KEY_BUFFER *rx_key,
                                  const CXL_IDE_KEY_BUFFER *tx_key)
{
  CXL_IDE_RP_REGISTERS registers;
  CXL_IDE_SELECTOR selector = {stream_id, key_slot};
  uint32_t status;

  status = cxl_ide_get_mapped_backend(ecam_base, rp_id, &registers);
  if (status != CXL_IDE_SUCCESS)
    return status;

  return pal_cxl_rp_ide_key_program(&registers, &selector, rx_key, tx_key);
}

uint32_t
val_el3_ide_km_go(uint64_t ecam_base, uint32_t rp_id, uint8_t stream_id,
                        uint8_t key_slot, uint8_t mode)
{
  CXL_IDE_RP_REGISTERS registers;
  CXL_IDE_SELECTOR selector = {stream_id, key_slot};
  uint32_t status = cxl_ide_get_mapped_backend(ecam_base, rp_id, &registers);

  if (status != CXL_IDE_SUCCESS)
    return status;
  return pal_cxl_rp_ide_key_go(&registers, &selector, mode);
}

uint32_t
val_el3_ide_km_stop(uint64_t ecam_base, uint32_t rp_id,
                       uint8_t stream_id,
                       uint8_t key_slot)
{
  CXL_IDE_RP_REGISTERS registers;
  CXL_IDE_SELECTOR selector = {stream_id, key_slot};
  uint32_t status = cxl_ide_get_mapped_backend(ecam_base, rp_id, &registers);

  if (status != CXL_IDE_SUCCESS)
    return status;
  return pal_cxl_rp_ide_key_stop(&registers, &selector);
}
