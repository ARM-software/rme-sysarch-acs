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

#ifndef VAL_EL3_EXCEPTION_H
#define VAL_EL3_EXCEPTION_H

#include <val_el3_helpers.h>

#define ALLEXCPTNS_MASK 0x7ULL
#define ALLEXCPTNS_MASK_BIT 6

#define GPF_ESR_READ    0x96000028ULL
#define GPF_ESR_WRITE   0x96000068ULL

#ifndef __ASSEMBLER__
void val_el3_asm_eret_smc(void);
void val_el3_update_elr_el3(uint64_t reg_value);
void val_el3_update_spsr_el3(uint64_t reg_value);
void val_el3_exception_handler_user(void);
void val_el3_rme_install_handler(void);
void val_el3_ack_handler(void);
void val_el3_save_vbar_el3(uint64_t *el3_handler);
void val_el3_program_vbar_el3(void (*)(void));
void val_el3_asm_eret(void);
void val_el3_set_daif(void);
#endif /* __ASSEMBLER__ */

#endif /* VAL_EL3_EXCEPTION_H */
