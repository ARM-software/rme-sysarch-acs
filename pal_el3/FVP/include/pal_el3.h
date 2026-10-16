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

#ifndef PAL_EL3_H
#define PAL_EL3_H

#include <stdint.h>
#include <stdbool.h>
#include <pal_el3_pcie_ide.h>
#include <pal_el3_cxl_ide.h>

/* Shared ACS status value; propagated unchanged through EL3. */
#define PAL_EL3_NOT_IMPLEMENTED 0x4B1D

uint32_t pal_el3_disable_ns_encryption(void);
/* Return 0 on success, PAL_EL3_NOT_IMPLEMENTED for a stub, or another nonzero error. */
uint32_t pal_el3_prog_legacy_tz(int enable);
/* Return 0 on success, PAL_EL3_NOT_IMPLEMENTED for a stub, or another nonzero error. */
uint32_t pal_el3_pas_filter_active_mode(int enable);
/* True only for a synchronous read denial caused by the inactive PAS filter.
 * Validate the syndrome, FAR validity and its match to the untagged probe VA.
 * GPF, translation and permission faults must not satisfy this check.
 */
bool pal_el3_pas_filter_check_exception(uint64_t esr, uint64_t far, uint64_t address);

/* Platform PAL owns CXL.cachemem register discovery and key-bank selection. */
uint32_t pal_cxl_rp_ide_cfg_address(uint64_t ecam_base, uint32_t rp_id, uint64_t *config);
uint32_t pal_cxl_rp_ide_km_address(uint64_t config, CXL_IDE_RP_REGISTERS *registers);
uint32_t pal_cxl_rp_ide_key_program(const CXL_IDE_RP_REGISTERS *registers,
                                    const CXL_IDE_SELECTOR *selector,
                                    const CXL_IDE_KEY_BUFFER *rx_key,
                                    const CXL_IDE_KEY_BUFFER *tx_key);
uint32_t pal_cxl_rp_ide_key_go(const CXL_IDE_RP_REGISTERS *registers,
                               const CXL_IDE_SELECTOR *selector, uint8_t mode);
uint32_t pal_cxl_rp_ide_key_stop(const CXL_IDE_RP_REGISTERS *registers,
                                 const CXL_IDE_SELECTOR *selector);

/* Platform PAL owns the RP configuration and key register layout. */
uint32_t pal_pcie_rp_ide_cfg_address(uint64_t ecam_base, uint32_t rp_id, uint64_t *cfg);
uint32_t pal_pcie_rp_ide_km_address(uint64_t cfg, PCIE_IDE_RP_REGISTERS *registers);
uint32_t pal_pcie_rp_ide_key_program(PCIE_IDE_RP_REGISTERS const *registers,
                                    PCIE_IDE_SELECTOR const *selector,
                                    PCIE_IDE_KEY const *key);
uint32_t pal_pcie_rp_ide_key_go(PCIE_IDE_RP_REGISTERS const *registers,
                               PCIE_IDE_SELECTOR const *selector);
uint32_t pal_pcie_rp_ide_key_stop(PCIE_IDE_RP_REGISTERS const *registers,
                               PCIE_IDE_SELECTOR const *selector);

#endif /* PAL_EL3_H */
