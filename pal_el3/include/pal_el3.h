/** @file
 * Copyright (c) 2023,2025, Arm Limited or its affiliates. All rights reserved.
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

void pal_enable_ns_encryption(void);
void pal_disable_ns_encryption(void);
void pal_prog_legacy_tz(int enable);
void pal_pas_filter_active_mode(int enable);

#endif /* PAL_EL3_H */