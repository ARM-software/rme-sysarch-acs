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

void pal_el3_enable_ns_encryption(void);
void pal_el3_disable_ns_encryption(void);
void pal_el3_prog_legacy_tz(int enable);
void pal_el3_pas_filter_active_mode(int enable);

typedef struct {
  uint32_t key[8];
  uint32_t iv[3];
} CXL_IDE_KEY_BUFFER;

uint32_t pal_cxl_root_port_ide_program_and_enable(uint64_t bar0_base,
                                                   uint8_t stream_id,
                                                   uint8_t key_slot,
                                                   const CXL_IDE_KEY_BUFFER *rx_key,
                                                   const CXL_IDE_KEY_BUFFER *tx_key);
uint32_t pal_cxl_root_port_ide_disable(uint64_t bar0_base,
                                        uint8_t stream_id,
                                        uint8_t key_slot);
uint32_t pal_cxl_root_port_ide_get_km_base(uint64_t bar0_base,
                                            uint64_t *ide_km_base);

#endif /* PAL_EL3_H */
