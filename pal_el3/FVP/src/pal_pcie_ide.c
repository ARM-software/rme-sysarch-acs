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

/* FVP placeholders return success without programming RP keys.
 * Use with impdefv1_ide_km_supported=false in the PCIe hierarchy.
 * Real RP key programming must be supplied by the platform.
 */
/**
 * @brief Return the RP configuration address required by the platform.
 *
 * @param ecam_base PCIe segment ECAM base.
 * @param rp_id Packed PCI Requester ID.
 * @param config Output configuration address.
 * @note This placeholder performs no RP register accesses.
 * @return PCIE_IDE_SUCCESS for valid arguments, or PCIE_IDE_ERROR otherwise.
 */
uint32_t
pal_pcie_rp_ide_cfg_address(uint64_t ecam_base, uint32_t rp_id, uint64_t *config)
{
  uint64_t offset = (uint64_t)rp_id << 12;

  if (config == 0 || ecam_base == 0u || (ecam_base & 0xfffu) != 0u ||
      rp_id > 0xffffu || ecam_base > UINT64_MAX - offset)
    return PCIE_IDE_ERROR;

  /* No configuration-space access is required by the stub backend. */
  *config = 0u;
  return PCIE_IDE_SUCCESS;
}

/**
 * @brief Discover the RP IDE key-management register regions.
 *
 * @param config RP configuration address.
 * @param registers Output register regions.
 * @note This placeholder performs no RP register accesses.
 * @return PCIE_IDE_SUCCESS for valid arguments, or PCIE_IDE_ERROR otherwise.
 */
uint32_t
pal_pcie_rp_ide_km_address(uint64_t config, PCIE_IDE_RP_REGISTERS *registers)
{
  (void)config;
  if (registers == 0)
    return PCIE_IDE_ERROR;

  registers->config = 0u;
  registers->keys = 0u;
  registers->control = 0u;
  return PCIE_IDE_SUCCESS;
}

/**
 * @brief Program a selected RP IDE key.
 *
 * @param registers RP register regions.
 * @param selector Stream, direction, key set and substream.
 * @param key Key material and initial invocation field.
 * @note This placeholder performs no RP register accesses.
 * @return PCIE_IDE_SUCCESS for valid arguments, or PCIE_IDE_ERROR otherwise.
 */
uint32_t
pal_pcie_rp_ide_key_program(const PCIE_IDE_RP_REGISTERS *registers,
                            const PCIE_IDE_SELECTOR *selector, const PCIE_IDE_KEY *key)
{
  if (registers == 0 || selector == 0 || key == 0)
    return PCIE_IDE_ERROR;

  return PCIE_IDE_SUCCESS;
}

/**
 * @brief Activate the selected RP IDE key set.
 *
 * @param registers RP register regions.
 * @param selector Stream, direction, key set and substream.
 * @note This placeholder performs no RP register accesses.
 * @return PCIE_IDE_SUCCESS for valid arguments, or PCIE_IDE_ERROR otherwise.
 */
uint32_t
pal_pcie_rp_ide_key_go(const PCIE_IDE_RP_REGISTERS *registers,
                       const PCIE_IDE_SELECTOR *selector)
{
  if (registers == 0 || selector == 0)
    return PCIE_IDE_ERROR;

  return PCIE_IDE_SUCCESS;
}

/**
 * @brief Stop the selected RP IDE key set.
 *
 * @param registers RP register regions.
 * @param selector Stream, direction, key set and substream.
 * @note This placeholder performs no RP register accesses.
 * @return PCIE_IDE_SUCCESS for valid arguments, or PCIE_IDE_ERROR otherwise.
 */
uint32_t
pal_pcie_rp_ide_key_stop(const PCIE_IDE_RP_REGISTERS *registers,
                         const PCIE_IDE_SELECTOR *selector)
{
  if (registers == 0 || selector == 0)
    return PCIE_IDE_ERROR;

  return PCIE_IDE_SUCCESS;
}
