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

#ifndef VAL_EL3_WD_H
#define VAL_EL3_WD_H

#include <val_el3_helpers.h>

/* Prototypes moved from ack_common.c */
#ifndef __ASSEMBLER__
void val_el3_wd_enable(uint64_t wdog_ctrl_base);
void val_el3_wd_disable(uint64_t wdog_ctrl_base);
void val_el3_wd_set_ws0(uint64_t VA_RT_WDOG, uint32_t timeout, uint64_t counter_freq);
#endif /* __ASSEMBLER__ */

#endif /* VAL_EL3_WD_H */
