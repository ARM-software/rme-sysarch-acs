/** @file
 * Copyright (c) 2025, Arm Limited or its affiliates. All rights reserved.
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

#ifndef VAL_EL3_MEC_H
#define VAL_EL3_MEC_H

#include <val_el3_helpers.h>

#ifndef __ASSEMBLER__
unsigned int val_is_mec_supported(void);
void val_mec_service(uint64_t arg0, uint64_t arg1, uint64_t arg2);
void val_enable_mec(void);
void val_disable_mec(void);
uint32_t val_is_mec_enabled(void);
void val_write_mecid(uint32_t mecid);
#endif /* __ASSEMBLER__ */

#endif /* VAL_EL3_MEC_H */
