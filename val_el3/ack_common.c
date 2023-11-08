/** @file
  * Copyright (c) 2023, Arm Limited or its affiliates. All rights reserved.
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

#include <val_el3/ack_include.h>

/**
 *  @brief  Clean and Invalidate the Data cache line containing
 *          the input physical address to the point of physical
 *          aliasing at EL3
 *          1. Caller       -  Test Suite
 *          2. Prerequisite -  The address should be mapped successfully
 *  @param  PA - Physical address needed for the cache maintenance
 *  @param  acc_pas - Access PAS that speciies the target PAS of the given PA
 *  @return None
**/
void val_data_cache_ops_by_va_el3(uint64_t VA, uint32_t type)
{

  switch (type)
  {
    case CLEAN_AND_INVALIDATE:
      cln_and_invldt_cache((uint64_t *)VA);
      break;
    case CLEAN:
      clean_cache((uint64_t *)VA);
      break;
    case INVALIDATE:
      invalidate_cache((uint64_t *)VA);
      break;
    default:
      ERROR("Invalid cache operation\n");
      break;
  }
}

/**
 *  @brief  This API is used to enable the NS_Encryption
 *          1. Caller       -  Test Suite
 *  @param  None
 *  @return None
**/
void val_enable_ns_encryption(void)
{
  pal_enable_ns_encryption();
}

/**
 *  @brief  This API is used to enable the NS_Encryption
 *          1. Caller       -  Test Suite
 *          2. Prerequisite -  val_enable_ns_encryption
 *  @param  None
 *  @return None
**/
void val_disable_ns_encryption(void)
{
  pal_disable_ns_encryption();
}

/**
 *  @brief  This API is used to program the LEGACY_TZ input for enabling/disabling
 *  it in the system.
 *          1. Caller       -  Test Suite
 *          2. Prerequisite -  val_enable_ns_encryption
 *  @param  enable - Enable if 1
 *  @return None
**/
void val_prog_legacy_tz(int enable)
{
  return pal_prog_legacy_tz(enable);
}

/**
  @brief   This API saves the contents fof the registers specified in the structure
           before an event.
           1. Caller       -  Test Suite
           2. Prerequisite -  None
  @param   None
  @return  None
**/
void val_pe_reg_read_msd(void)
{
  int num_regs;

  num_regs = shared_data->reg_info.num_regs;
  for (int i = 0; i < num_regs; i++) {
    shared_data->reg_info.reg_list[i].saved_reg_value =
            val_pe_reg_read(shared_data->reg_info.reg_list[i].reg_name);
  }
}

/**
  @brief   This API provides a comparison between the saved registers and the present value
           after an event.
           1. Caller       -  Test Suite
           2. Prerequisite -  val_reg_read_msd
  @param   None
  @return  None
**/
void val_pe_reg_list_cmp_msd(void)
{
  uint64_t reg_val;
  int cmp_fail;
  int num_regs;

  num_regs = shared_data->reg_info.num_regs;
  reg_val = 0;
  cmp_fail = 0;
  for (int i = 0; i < num_regs; i++) {
    reg_val = val_pe_reg_read(shared_data->reg_info.reg_list[i].reg_name);
    if (shared_data->reg_info.reg_list[i].saved_reg_value != reg_val) {
        ERROR("The register has not retained it's original value \n");
        cmp_fail++;
    }
    reg_val = 0;
  }
  //If the comparision is failed at any time, SET the shared generic flag
  if (cmp_fail > 0)
      shared_data->generic_flag = SET;

}

/**
  @brief   This API provides a 'C' interface to call System register reads
           1. Caller       -  Test Suite
           2. Prerequisite -  None
  @param   reg_id  - the system register index for which data is returned
  @return  the value read from the system register.
**/
uint64_t
val_pe_reg_read(uint32_t reg_id)
{

  switch (reg_id)
  {
      case GPCCR_EL3_MSD:
          return read_gpccr_el3();
      case GPTBR_EL3_MSD:
          return read_gptbr_el3();
      case TCR_EL3_MSD:
          return read_tcr_el3();
      case TTBR_EL3_MSD:
          return read_ttbr_el3();
      case SCR_EL3_MSD:
          return read_scr_el3();
      case SCTLR_EL3_MSD:
          return read_sctlr_el3();
      case SCTLR_EL2_MSD:
          return read_sctlr_el2();
      default:
          ERROR("Specify the correct register index\n");
          return 0;
  }
}

/**
 *  @brief  This API is used to set the given memory with the required data
 *          with the specified size
 *          1. Caller       -  Test Suite
 *  @param  address - The address buffer that needs to be set
 *  @param  size - Size of the buffer upto which the test needs to fill in the data
 *  @param  value - Data needed to set the buffer with
 *  @return None
**/
void val_memory_set_el3(void *address, uint32_t size, uint8_t value)
{
  uint32_t index;

  for (index = 0; index < size; index++)
    *((char *)address + index) = value;

}

/**
 *  @brief  This API is used to set/clear the active mode of PAS_FILTER
 *          present in the system.
 *          1. Caller	- Test suite
 *  @param  enable - Bit to enable the active mode: SET to Active mode,
 *                   CLEAR to In-Active
 *  @return None
**/
void val_pas_filter_active_mode(int enable)
{
  //Change the mode to Active from In-active
  pal_pas_filter_active_mode(enable);
}
/**
  @brief   This API Enables root watchdog by writing to Control Base register
  @param   wdog_ctrl_base - Watchdog control base register
  @return  None
 **/
void
val_wd_enable(uint64_t wdog_ctrl_base)
{
    *(uint64_t *)(wdog_ctrl_base + 0) = SET;
}

/**
  @brief   This API Disbles root watchdog by writing to Control Base register
  @param   wdog_ctrl_base - Watchdog control base register
  @return  None
 **/
void
val_wd_disable(uint64_t wdog_ctrl_base)
{
    *(uint64_t *)(wdog_ctrl_base + 0) = CLEAR;
}

/**
  @brief   This API arms the Root watchdog by writing to Control Base register.
  @param   VA_RT_WDOG - VA of Root watchdog control base register that is mapped
                        to PA, Root watchdog control base register.
  @param   timeout - ticks to generation of ws0 interrupt.
  @param   counter_freq - System counter frequency.
  @return  None
 **/
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

  *(uint64_t *)(ctrl_base + 8) =  wor_l;

  /* Upper bits are applicable only for WDog Version 1 */
  if (data == 1)
      *(uint64_t *)(ctrl_base + 12) = wor_h;

  INFO("Enabling the Root watchdog\n");
  val_wd_enable(ctrl_base);

}

/**
  @brief   This API Disbles accesses from the SMMU and client devices
           by writing to ACCESSEN bit of SMMU_ROOT_CR0 register.
  @return  None
 **/
void val_smmu_access_disable(void)
{
  *(uint32_t *)(ROOT_IOVIRT_SMMUV3_BASE + SMMU_ROOT_CR0) = CLEAR;
}

/**
 *  @brief  This API is used to change the security state of EL2 and lower levels by writing
 *          to the SCR_EL3 register.
 *  @return None
 */
void val_security_state_change(uint64_t attr_nse_ns)
{
  uint64_t scr_data, nse_bit, ns_bit;

  nse_bit = NSE_SET(attr_nse_ns);
  ns_bit = NS_SET(attr_nse_ns);
  scr_data = read_scr_el3();
  //The SCR_EL3.NSE and SCR_EL3.NS bits decides the security state
  scr_data &= (~SCR_NSE_MASK & ~SCR_NS_MASK);
  scr_data |= ((nse_bit << SCR_NSE_SHIFT) | (ns_bit << SCR_NS_SHIFT));
  write_scr_el3(scr_data);

}
