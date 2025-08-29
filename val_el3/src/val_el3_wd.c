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
#include <val_el3_debug.h>
#include <val_el3_wd.h>

void
val_wd_enable(uint64_t wdog_ctrl_base)
{
    if (shared_data->generic_flag) {
      shared_data->exception_expected = SET;
      shared_data->access_mut = CLEAR;
    }
    *(uint64_t *)(wdog_ctrl_base + 0) = SET;
}

void
val_wd_disable(uint64_t wdog_ctrl_base)
{
    *(uint64_t *)(wdog_ctrl_base + 0) = CLEAR;
}

void val_wd_set_ws0_el3(uint64_t VA_RT_WDOG, uint32_t timeout, uint64_t counter_freq)
{
  uint32_t wor_l;
  uint32_t wor_h = 0;
  uint64_t ctrl_base;
  uint32_t data;

  ctrl_base = VA_RT_WDOG;
  if (!timeout) {
      INFO("Disabling the Root watchdog\n");
      val_wd_disable(ctrl_base);
      return;
  }

  data = VAL_EXTRACT_BITS(*(uint64_t *)(ctrl_base + WD_IIDR_OFFSET), 16, 19);

  /* Option to override system counter frequency value */
  /* Check if the timeout value exceeds */
  if (data == 0)
  {
      if ((counter_freq * timeout) >> 32)
      {
          ERROR("Counter frequency value exceeded\n");
      }
  }

  wor_l = (uint32_t)(counter_freq * timeout);
  wor_h = (uint32_t)((counter_freq * timeout) >> 32);

  if (shared_data->generic_flag) {
    shared_data->exception_expected = SET;
    shared_data->access_mut = CLEAR;
  }
  *(uint64_t *)(ctrl_base + 8) =  wor_l;

  /* Upper bits are applicable only for WDog Version 1 */
  if (data == 1) {
      if (shared_data->generic_flag) {
        shared_data->exception_expected = SET;
        shared_data->access_mut = CLEAR;
      }
      *(uint64_t *)(ctrl_base + 12) = wor_h;
  }

  INFO("Enabling the Root watchdog\n");
  val_wd_enable(ctrl_base);

}
