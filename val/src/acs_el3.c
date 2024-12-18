/** @file
 * Copyright (c) 2023-2024, Arm Limited or its affiliates. All rights reserved.
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
#include "include/val_interface.h"
#include "include/rme_acs_el32.h"

/**
 *  @brief  This API is used to set the given memory with the required data
 *          with the specified size
 *          1. Caller       -  Test Suite
 *  @param  address - The address buffer that needs to be set
 *  @param  size - Size of the buffer upto which the test needs to fill in the data
 *  @param  value - Data needed to set the buffer with
 *  @return None
**/
void
val_memory_set_el3(void *address, uint32_t size, uint8_t value)
{
  UserCallSMC(ARM_ACS_SMC_FID, RME_MEM_SET, (uint64_t)address, size, value);
}

/**
 *  @brief  Clean and Invalidate the Data cache line containing
 *          the input virtual address tag at EL3
 *          1. Caller       -  Test Suite
 *  @param  address - Virtual address needed for the CMO
 *  @param  type - Type of CMO required for the mentioned VA
 *  @return None

**/
void
val_data_cache_ops_by_va_el3(uint64_t address, uint32_t type)
{
  UserCallSMC(ARM_ACS_SMC_FID, RME_DATA_CACHE_OPS, address, type, 0);
}

/**
 *  @brief   This API maps a passed Virtual Address to the mentioned
 *           Physical Address with the Access PAS at EL3
 *           1. Caller       -  Test Suite
 *  @param   VA - Virtual Address needed for the MMU mapping
 *  @param   PA - Physical Address needed to be mapped to the Virtual Address
 *  @param   acc_pas - Access PAS for the corresponding mapping if specified or NS PAS by default
 *  @return  None
**/
void
val_add_mmu_entry_el3(uint64_t VA, uint64_t PA, uint64_t attr)
{
  UserCallSMC(ARM_ACS_SMC_FID, RME_ADD_MMU_ENTRY, VA, PA, attr);
}

/**
 *  @brief   This API maps a given Physical Address into the GPT table
 *           with the specified GPI at EL3
 *           1. Caller       -  Test Suite
 *  @param   PA - Physical Address needed to be mapped into the GPT table
 *  @param   gpi - GPI encoding required for the corresponding Physical Address
 *  @return  None
**/
void
val_add_gpt_entry_el3(uint64_t PA, uint64_t gpi)
{
  UserCallSMC(ARM_ACS_SMC_FID, RME_ADD_GPT_ENTRY, PA, gpi, 0);
}

/**
 *  @brief   This API provides access to MUT at EL3 to write on or read from
 *           1. Caller       -  Test Suite
 *  @return  NOne
**/
void
val_pe_access_mut_el3(void)
{
  UserCallSMC(ARM_ACS_SMC_FID, RME_ACCESS_MUT, 0, 0, 0);
}

/**
 *  @brief  Clean and Invalidate the Data cache line containing
 *          the input physical address to the point of physical
 *          aliasing at EL3
 *          1. Caller       -  Test Suite
 *  @param  PA - Physical address needed for the cache maintenance
 *  @param  acc_pas - Access PAS that speciies the target PAS of the given PA
 *  @return None
**/
void
val_data_cache_ops_by_pa_el3(uint64_t PA, uint64_t acc_pas)
{
  UserCallSMC(ARM_ACS_SMC_FID, RME_CMO_POPA, PA, acc_pas, 0);
}

/**
 *  @brief  This API is called to install the ack handler for exceptions at EL3
 *          1. Caller       -  Test Suite
 *  @return None
**/
void
val_rme_install_handler_el3(void)
{
  UserCallSMC(ARM_ACS_SMC_FID, RME_INSTALL_HANDLER, 0, 0, 0);
}

/**
 *  @brief  This API is called to Enable NS_Encryption at EL3
 *          1. Caller       -  Test Suite
 *  @return None
**/
void
val_enable_ns_encryption(void)
{
  UserCallSMC(ARM_ACS_SMC_FID, RME_NS_ENCRYPTION, SET, 0, 0);
}

/**
 *  @brief  This API is called to Diable NS_Encryption at EL3
 *          1. Caller       -  Test Suite
 *  @return None
**/
void
val_disable_ns_encryption(void)
{
  UserCallSMC(ARM_ACS_SMC_FID, RME_NS_ENCRYPTION, CLEAR, 0, 0);
}

/**
 *  @brief  This API is called to store the register values before entering into
 *          the low power state.
 *          1. Caller       -  Test Suite
 *  @return None
**/
void
val_read_pe_regs_bfr_low_pwr_el3(void)
{
  UserCallSMC(ARM_ACS_SMC_FID, RME_READ_AND_CMPR_REG_MSD, CLEAR, 0, 0);
}

/**
 *  @brief  This API is called to read and compare the register values after an
 *          exit from the low power state.
 *          1. Caller       -  Test Suite
 *  @return None
**/
void
val_cmpr_pe_regs_aftr_low_pwr_el3(void)
{
  UserCallSMC(ARM_ACS_SMC_FID, RME_READ_AND_CMPR_REG_MSD, SET, 0, 0);
}
/**
 *  @brief  This API is called to enable/disable the legacy tie-off input in EL3
 *          1. Caller       -  Test Suite
 *  @return None
**/
void
val_prog_legacy_tz(int enable)
{
  UserCallSMC(ARM_ACS_SMC_FID, LEGACY_TZ_ENABLE, SET, 0, 0);
}

/**
 *  @brief  This API is called to enable/disable the Root watchdog in EL3
 *          1. Caller       -  Test Suite
 *  @return None
**/
void
val_wd_set_ws0_el3(uint64_t VA_RT_WDOG, uint32_t timeout, uint64_t counter_freq)
{
  UserCallSMC(ARM_ACS_SMC_FID, ROOT_WATCHDOG, VA_RT_WDOG, timeout, counter_freq);
}

/**
 *  @brief  This API is called to enable/disable the Active mode of PAS filter in EL3
 *          1. Caller       -  Test Suite
 *  @return None
**/
void val_pas_filter_active_mode_el3(int enable)
{
  UserCallSMC(ARM_ACS_SMC_FID, PAS_FILTER_SERVICE, enable, 0, 0);
}

/**
 *  @brief  This API is called to disable the SMMU in EL3 writing to SMMU_ROOT_CR0 offset of
 *          SMMU_ROOT register.
 *          1. Caller       -  Test Suite
 *  @return None
**/
void val_smmu_access_disable(void)
{
  UserCallSMC(ARM_ACS_SMC_FID, SMMU_ROOT_SERVICE, 0, 0, 0);
}

/**
 *  @brief  This API is used to change the security state of EL2 and lower levels by writing
 *          to the SCR_EL3 register in EL3.
 *          1. Caller       -  Test Suite
 *  @return None
 */
void val_change_security_state_el3(int sec_state)
{
  UserCallSMC(ARM_ACS_SMC_FID, SEC_STATE_CHANGE, sec_state, 0, 0);
}

/**
 *  @brief  This API is used to check the RME_IMPL && ROOT_IMPL feature of the SMMU.
 *          1. Caller       -  Test suite
 *  @return None
 */
void val_smmu_check_rmeda_el3(void)
{
  UserCallSMC(ARM_ACS_SMC_FID, SMMU_ROOT_REG_CHK, SMMU_ROOT_RME_IMPL_CHK, 0, 0);
}
