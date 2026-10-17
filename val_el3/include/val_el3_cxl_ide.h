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

#ifndef VAL_EL3_CXL_IDE_H
#define VAL_EL3_CXL_IDE_H

#ifndef __ASSEMBLER__
#include <stdint.h>
#include <pal_el3_cxl_ide.h>

uint32_t val_el3_ide_km_program(uint64_t ecam_base, uint32_t rp_id,
                                           uint8_t stream_id,
                                           uint8_t key_slot,
                                           const CXL_IDE_KEY_BUFFER *rx_key,
                                           const CXL_IDE_KEY_BUFFER *tx_key);
uint32_t val_el3_ide_km_go(uint64_t ecam_base, uint32_t rp_id, uint8_t stream_id,
                        uint8_t key_slot, uint8_t mode);
uint32_t val_el3_ide_km_stop(uint64_t ecam_base, uint32_t rp_id,
                              uint8_t stream_id, uint8_t key_slot);
#endif /* __ASSEMBLER__ */

#endif /* VAL_EL3_CXL_IDE_H */
