/** @file
 * Copyright (c) 2022-2023, 2025, Arm Limited or its affiliates. All rights reserved.
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
#include "include/rme_acs_timer_support.h"
#include "include/rme_acs_timer.h"
#include "include/rme_acs_wd.h"
#include "include/rme_acs_common.h"

/**
  @brief   This API is to get counter frequency
  @param   None
  @return  counter frequency
 **/
uint64_t
val_get_counter_frequency(void)
{
  return val_timer_get_info(TIMER_INFO_CNTFREQ, 0);
}
