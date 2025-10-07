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
#include <val_el3_pe.h>

/**
 * @brief Read and save a platform-defined list of EL3 registers.
 *
 * Saves values into shared_data->reg_info.reg_list[].saved_reg_value.
 */
void val_el3_pe_reg_read_msd(void)
{
  int num_regs;

  num_regs = shared_data->reg_info.num_regs;
  for (int i = 0; i < num_regs; i++) {
    shared_data->reg_info.reg_list[i].saved_reg_value =
            val_el3_pe_reg_read(shared_data->reg_info.reg_list[i].reg_name);
  }
}

/**
 * @brief Compare previously saved EL3 registers with current values.
 *
 * Sets shared_data->generic_flag on mismatch and populates error fields.
 */
void val_el3_pe_reg_list_cmp_msd(void)
{
  uint64_t reg_val;
  int cmp_fail;
  int num_regs;

  num_regs = shared_data->reg_info.num_regs;
  reg_val = 0;
  cmp_fail = 0;
  for (int i = 0; i < num_regs; i++) {
    reg_val = val_el3_pe_reg_read(shared_data->reg_info.reg_list[i].reg_name);
    if (shared_data->reg_info.reg_list[i].saved_reg_value != reg_val) {
        ERROR("The register has not retained it's original value \n");
        cmp_fail++;
    }
    reg_val = 0;
  }
  //If the comparision is failed at any time, SET the shared generic flag
  if (cmp_fail > 0)
  {
    shared_data->generic_flag = SET;
    shared_data->status_code = 1;
    const char *msg = "EL3: Register comparision failed";
    int i = 0; while (msg[i] && i < sizeof(shared_data->error_msg) - 1) {
        shared_data->error_msg[i] = msg[i]; i++;
    }
    shared_data->error_msg[i] = '\0';
  } else {
    INFO("Register comparision passed\n");
  }

}

/**
 * @brief Read a single EL3 register by abstract register id.
 *
 * @param reg_id  Register identifier (GPCCR_EL3_MSD, GPTBR_EL3_MSD, etc.).
 * @return Current 64-bit value of the requested register.
 */
uint64_t
val_el3_pe_reg_read(uint32_t reg_id)
{

  switch (reg_id)
  {
      case GPCCR_EL3_MSD:
          return val_el3_read_gpccr_el3();
      case GPTBR_EL3_MSD:
          return val_el3_read_gptbr_el3();
      case TCR_EL3_MSD:
          return val_el3_read_tcr_el3();
      case TTBR_EL3_MSD:
          return val_el3_read_ttbr_el3();
      case SCR_EL3_MSD:
          return val_el3_read_scr_el3();
      case SCTLR_EL3_MSD:
          return val_el3_read_sctlr_el3();
      case SCTLR_EL2_MSD:
          return val_el3_read_sctlr_el2();
      default:
          ERROR("Specify the correct register index\n");
          return 0;
  }
}
