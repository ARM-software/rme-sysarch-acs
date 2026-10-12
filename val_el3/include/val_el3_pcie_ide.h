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
#ifndef VAL_EL3_PCIE_IDE_H
#define VAL_EL3_PCIE_IDE_H

/* Include the execution environment's fixed-width integer types before this header.
 * EL3 uses stdint.h; UEFI uses the PAL integer types. */

#include "pal_el3_pcie_ide.h"

typedef struct {
  uint64_t ecam_base;
  uint32_t rp_id; /* PCI RID: bus[15:8], device[7:3], function[2:0]. */
  uint32_t reserved;
  PCIE_IDE_SELECTOR selector;
  uint32_t reserved2;
  PCIE_IDE_KEY key;
} PCIE_IDE_REQUEST;

/* EL3 entry point; Host VAL uses the SMC service. */
uint32_t val_el3_pcie_ide_km_handle(uint32_t operation, uint64_t address);

#endif
