/** @file
 * Copyright (c) 2022, Arm Limited or its affiliates. All rights reserved.
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

#include "include/rme_acs_val.h"
#include "include/rme_acs_common.h"

#define NUM_ARM_MAX_INTERRUPT 16384
#define ICC_IAR1_EL1    S3_0_C12_C12_0
#define ICC_EOIR1_EL1   S3_0_C12_C12_1

void rme_gic_set_el2_vector_table(void);
uint32_t rme_gic_update_elr(uint64_t elr_value);
uint32_t rme_gic_get_elr(void);
uint32_t rme_gic_get_far(void);
uint32_t rme_gic_get_esr(void);
uint32_t rme_gic_ack_intr(void);
void rme_gic_end_intr(uint32_t interrupt_id);
void rme_gic_vector_table_init(void);
uint32_t common_exception_handler(uint32_t exception_type);

void val_gic_rme_install_esr(uint32_t exception_type, void (*esr)(uint64_t, void *));
uint32_t val_gic_rme_install_isr(uint32_t interrupt_id, void (*isr)(void));


