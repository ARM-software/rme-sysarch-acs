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

/* CXL IDE key management requires an RD-V3-specific backend.
 * These placeholders perform no register access or output writes.
 */

/** Resolve the Root Port configuration aperture. */
uint32_t
pal_cxl_rp_ide_cfg_address(uint64_t ecam_base, uint32_t rp_id, uint64_t *config)
{
  (void)ecam_base;
  (void)rp_id;
  (void)config;
  return CXL_IDE_UNSUPPORTED;
}

/** @return CXL_IDE_UNSUPPORTED until the platform backend is implemented. */
uint32_t
pal_cxl_rp_ide_km_address(uint64_t config, CXL_IDE_RP_REGISTERS *registers)
{
  (void)config;
  (void)registers;
  return CXL_IDE_UNSUPPORTED;
}

/** @return CXL_IDE_UNSUPPORTED until the platform backend is implemented. */
uint32_t
pal_cxl_rp_ide_key_program(const CXL_IDE_RP_REGISTERS *registers,
                            const CXL_IDE_SELECTOR *selector,
                            const CXL_IDE_KEY_BUFFER *rx_key,
                            const CXL_IDE_KEY_BUFFER *tx_key)
{
  (void)registers;
  (void)selector;
  (void)rx_key;
  (void)tx_key;
  return CXL_IDE_UNSUPPORTED;
}

/** @return CXL_IDE_UNSUPPORTED until the platform backend is implemented. */
uint32_t
pal_cxl_rp_ide_key_go(const CXL_IDE_RP_REGISTERS *registers,
                       const CXL_IDE_SELECTOR *selector, uint8_t mode)
{
  (void)registers;
  (void)selector;
  (void)mode;
  return CXL_IDE_UNSUPPORTED;
}

/** @return CXL_IDE_UNSUPPORTED until the platform backend is implemented. */
uint32_t
pal_cxl_rp_ide_key_stop(const CXL_IDE_RP_REGISTERS *registers,
                         const CXL_IDE_SELECTOR *selector)
{
  (void)registers;
  (void)selector;
  return CXL_IDE_UNSUPPORTED;
}
