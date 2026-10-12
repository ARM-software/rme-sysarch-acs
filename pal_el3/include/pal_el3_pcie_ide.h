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
#ifndef PAL_EL3_PCIE_IDE_H
#define PAL_EL3_PCIE_IDE_H

/* The including environment supplies the fixed-width integer types. */

/* PCIe-only contract. Direction is relative to the Root Port. */
#define PCIE_IDE_SUCCESS 0u
#define PCIE_IDE_ERROR   1u

#define PCIE_IDE_RX 0u
#define PCIE_IDE_TX 1u
#define PCIE_IDE_UNSUPPORTED 2u
#define PCIE_IDE_BUSY 3u

typedef struct {
  uint8_t stream_id;
  uint8_t key_set;
  uint8_t sub_stream;
  uint8_t direction;
} PCIE_IDE_SELECTOR;

typedef struct {
  uint32_t key[8];
  uint64_t initial_ifv;
} PCIE_IDE_KEY;

/* Platform-discovered register regions, used only by EL3 and PAL.
 * PAL discovery uses zero addresses to request no MMIO mapping, including
 * the configuration address returned by pal_pcie_rp_ide_cfg_address().
 * A backend that needs no register accesses may return all zeros.
 */
typedef struct {
  uint64_t config;
  uint64_t keys;
  uint64_t control;
} PCIE_IDE_RP_REGISTERS;

#endif /* PAL_EL3_PCIE_IDE_H */
