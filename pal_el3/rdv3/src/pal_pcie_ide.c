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

/* PCIe IDE key programming requires an RDV3-specific backend. */
/**
 * @brief Return the RP configuration address required by the platform.
 *
 * @param ecam_base PCIe segment ECAM base.
 * @param rp_id Packed PCI Requester ID.
 * @param cfg Output configuration address.
 * @return PCIE_IDE_UNSUPPORTED until the platform backend is implemented.
 */
uint32_t
pal_pcie_rp_ide_cfg_address(uint64_t ecam_base, uint32_t rp_id, uint64_t *cfg)
{
  (void)ecam_base;
  (void)rp_id;
  (void)cfg;
  return PCIE_IDE_UNSUPPORTED;
}

/**
 * @brief Discover the RP IDE key-management register regions.
 *
 * @param cfg RP configuration address.
 * @param registers Output register regions.
 * @return PCIE_IDE_UNSUPPORTED until the platform backend is implemented.
 */
uint32_t
pal_pcie_rp_ide_km_address(uint64_t cfg, PCIE_IDE_RP_REGISTERS *registers)
{
  (void)cfg;
  (void)registers;
  return PCIE_IDE_UNSUPPORTED;
}

/**
 * @brief Program a selected RP IDE key.
 *
 * @param registers RP register regions.
 * @param selector Stream, direction, key set and substream.
 * @param key Key material and initial invocation field.
 * @return PCIE_IDE_UNSUPPORTED until the platform backend is implemented.
 */
uint32_t
pal_pcie_rp_ide_key_program(const PCIE_IDE_RP_REGISTERS *registers,
                           const PCIE_IDE_SELECTOR *selector,
                           const PCIE_IDE_KEY *key)
{
  (void)registers;
  (void)selector;
  (void)key;
  return PCIE_IDE_UNSUPPORTED;
}

/**
 * @brief Activate the selected RP IDE key set.
 *
 * @param registers RP register regions.
 * @param selector Stream, direction, key set and substream.
 * @return PCIE_IDE_UNSUPPORTED until the platform backend is implemented.
 */
uint32_t
pal_pcie_rp_ide_key_go(const PCIE_IDE_RP_REGISTERS *registers, const PCIE_IDE_SELECTOR *selector)
{
  (void)registers;
  (void)selector;
  return PCIE_IDE_UNSUPPORTED;
}

/**
 * @brief Stop the selected RP IDE key set.
 *
 * @param registers RP register regions.
 * @param selector Stream, direction, key set and substream.
 * @return PCIE_IDE_UNSUPPORTED until the platform backend is implemented.
 */
uint32_t
pal_pcie_rp_ide_key_stop(const PCIE_IDE_RP_REGISTERS *registers, const PCIE_IDE_SELECTOR *selector)
{
  (void)registers;
  (void)selector;
  return PCIE_IDE_UNSUPPORTED;
}
