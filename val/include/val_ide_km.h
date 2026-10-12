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
#ifndef RME_ACS_IDE_KM_H
#define RME_ACS_IDE_KM_H

#include "val_el3_pcie_ide.h"

uint32_t val_pcie_rp_ide_key_program(uint32_t rp_bdf,
                                    PCIE_IDE_SELECTOR const *selector,
                                    PCIE_IDE_KEY const *key);
uint32_t val_pcie_rp_ide_key_go(uint32_t rp_bdf, PCIE_IDE_SELECTOR const *selector);
uint32_t val_pcie_rp_ide_key_stop(uint32_t rp_bdf, PCIE_IDE_SELECTOR const *selector);

#endif
