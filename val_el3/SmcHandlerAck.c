/** @file
  * Copyright (c) 2022-2023, Arm Limited or its affiliates. All rights reserved.
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

#define TEST_DATA 0x999

struct_sh_data *shared_data = (struct_sh_data *) SHARED_ADDRESS;

void map_shared_mem(void)
{
        INFO(" Function not implemented\n");
}

uint64_t *armtf_handler = (uint64_t *)(ARM_TF_SHARED_ADDRESS);

/**
 *  @brief  This API is called to install the ack handler for exceptions at EL3
 *          1. Caller       -  Test Suite
 *  @return None
**/
void rme_install_handler(void)
{
  save_vbar_el3(armtf_handler);
  INFO("armtf_handler= 0x%lx\n", *(armtf_handler));
  program_vbar_el3(&exception_handler_user);
}

/**
 *  @brief  This API is called for the exceptions caused in and are/is taken to EL3
 *          so that it is handled appropriately as expected from the test
 *          1. Caller       -  Any EL3 Excpetion
 *          2. Prerequisite -  rme_install_handler()
 *  @return None
**/
void ack_handler_el3(void)
{

  uint64_t *elr_ptr;
  uint64_t *spsr_ptr;

  elr_ptr = (uint64_t *) SHARED_OFFSET_ELR;
  spsr_ptr = (uint64_t *) SHARED_OFFSET_SPSR;
  INFO("Inside EL3 ACK Handler\n");

  if (shared_data->exception_expected == SET && shared_data->access_mut == CLEAR) {
    INFO("The Fault is encountered\n");
    if (read_esr_el3() == GPF_ESR_READ || read_esr_el3() == GPF_ESR_WRITE) {
        INFO("The GPF was expected, encountered and handled\n");
        shared_data->exception_generated = SET;
        shared_data->exception_expected = CLEAR;
        VERBOSE("Saved elr = %lx\n", *(elr_ptr));
        VERBOSE("Saved spsr = %lx\n", *(spsr_ptr));
        VERBOSE("Current elr = %lx\n", read_elr_el3());
        VERBOSE("Current spsr = %lx\n", read_spsr_el3());
        asm_eret();
    } else {
        VERBOSE("The fault is not GPF, ESR_EL3 = 0x%lx\n", read_esr_el3());
        VERBOSE("FAR_EL3 = 0x%lx\n", read_far());
        VERBOSE("Saved elr = %lx\n", *(elr_ptr));
        VERBOSE("Saved spsr = %lx\n", *(spsr_ptr));
        VERBOSE("Current elr = %lx\n", read_elr_el3());
        VERBOSE("Current spsr = %lx\n", read_spsr_el3());
	shared_data->exception_expected = CLEAR;
        asm_eret();
    }
    //Save other parameters as per test requirement
  } else if (shared_data->access_mut == SET) {
    uint64_t data = TEST_DATA;

    // The access_mut flag is unset as the purpose is served in this section
    shared_data->access_mut = CLEAR;
    INFO("Argument 1: 0x%lx\n", shared_data->arg1);
    //Store the elr_el3 and spsr_el3 to restore it later
    shared_data->elr_el3 = read_elr_el3();
    shared_data->spsr_el3 = read_spsr_el3();
    if (shared_data->pas_filter_flag == SET) {
        set_daif();
        acs_ldr_pas_filter((uint64_t *)shared_data->arg1,
                        shared_data->shared_data_access[0].data);
    } else if (shared_data->exception_expected == SET) {
        VERBOSE("Exception Expected\n");
        VERBOSE("Saved elr = %lx\n", *(elr_ptr));
        VERBOSE("Saved spsr = %lx\n", *(spsr_ptr));
        acs_str((uint64_t *)shared_data->arg1, data);
    } else
        data = *(uint64_t *)shared_data->arg1;
    //Now restore the contents of the registers to be used in eret
    update_elr_el3(shared_data->elr_el3);
    update_spsr_el3(shared_data->spsr_el3);
    asm_eret_smc();

  } else {
    INFO("Branch to arm-tf handler\n");
    branch_asm(*(armtf_handler + 1));
  }
}

/**
  @brief   This function helps to read or write the address in EL3
           1. Caller       -  Test Suite
           2. Prerequisite -  Address needs to be mapped without any faults expected
  @param   address - Address that needs to be read on or written on
  @param   data    - The data which is written on the address
  @return  None
**/
void access_mut(void)
{
  uint8_t type, num = shared_data->num_access;
  uint64_t data;

  for (int acc_cnt = 0; acc_cnt < num; ++acc_cnt)
  {

    type = shared_data->shared_data_access[acc_cnt].access_type;
    switch (type)
    {
        case READ_DATA:
          data = *(uint64_t *) shared_data->shared_data_access[acc_cnt].addr;
          VERBOSE("The data returned from the address, 0x%lx is 0x%lx\n",
               shared_data->shared_data_access[acc_cnt].addr, data);
          shared_data->shared_data_access[acc_cnt].data = data;
          break;
        case WRITE_DATA:
          data = shared_data->shared_data_access[acc_cnt].data;
          *(uint64_t *)shared_data->shared_data_access[acc_cnt].addr = data;
          VERBOSE("Data stored in VA, 0x%lx is 0x%lx\n",
                shared_data->shared_data_access[acc_cnt].addr,
                *(uint64_t *)shared_data->shared_data_access[acc_cnt].addr);
          break;
        default:
          ERROR("INVALID TYPE OF ACCESS");
          break;
    }
  }
}

/**
 *  @brief  This API is used to branch out to all the different functions in EL3
 *          1. Caller       -  Test Suite
 *  @param  services -  The type of service to carry out the EL3 operation
 *  @param  arg0     -  The argument is specific to the test requirement
 *  @param  arg1     -  The argument is specific to the test requirement
 *  @param  arg2     -  The argument is specific to the test requirement
 *  @return None
**/
void UserSmcCall(uint64_t services, uint64_t arg0, uint64_t arg1, uint64_t arg2)
{

  INFO("UserSMCCall call started for service = 0x%lx arg0 = 0x%lx arg1 = 0x%lx arg2 = 0x%lx \n", services, arg0, arg1, arg2);

  switch (services)
  {
    case RME_INSTALL_HANDLER:
      INFO("RME Handler Installing service \n");
      rme_install_handler();
      break;
    case RME_ADD_GPT_ENTRY:
      add_gpt_entry(arg0, arg1);
      tlbi_paallos();
      break;
    case RME_ADD_MMU_ENTRY:
      INFO("RME MMU mapping service \n");
      add_mmu_entry(arg0, arg1, arg2);
      tlbi_vae3(arg0);
      break;
    case RME_MAP_SHARED_MEM:
      map_shared_mem();
      break;
    case RME_CMO_POPA:
      INFO("RME CMO to PoPA service \n");
      modify_desc(arg0, CIPOPA_NS_BIT, NSE_SET(arg1), 1);
      modify_desc(arg0, CIPOPA_NSE_BIT, NS_SET(arg1), 1);
      cmo_cipapa(arg0);
      break;
    case RME_ACCESS_MUT:
      INFO("RME MEMORY ACCESS SERVICE\n");
      access_mut();
      break;
    case RME_DATA_CACHE_OPS:
      INFO("RME data cache maintenance operation service \n");
      val_data_cache_ops_by_va_el3(arg0, arg1);
      break;
    case RME_MEM_SET:
      INFO("RME memory write service\n");
      val_memory_set_el3((uint64_t *)arg0, arg1, arg2);
      break;
    case RME_NS_ENCRYPTION:
      INFO("RME Non-secure Encryption Enable/Disable service\n");
      if (arg0 == SET)
        val_enable_ns_encryption();
      else
        val_disable_ns_encryption();
      break;
    case RME_READ_AND_CMPR_REG_MSD:
      INFO("RME Registers Read and Compare service\n");
      if (arg0 == SET) {
        val_pe_reg_list_cmp_msd();
        INFO("Register comparision\n");
      } else {
        val_pe_reg_read_msd();
        INFO("Register read\n");
      }
      break;
    case LEGACY_TZ_ENABLE:
      INFO("Legacy System Service\n");
      val_prog_legacy_tz(arg0);
      break;
    case ROOT_WATCHDOG:
      INFO("Root watchdog service \n");
      if (shared_data->generic_flag) {
        set_daif();
        shared_data->generic_flag = CLEAR;
        shared_data->exception_expected = SET;
        shared_data->access_mut = CLEAR;
      }
      val_wd_set_ws0_el3(arg0, arg1, arg2);
      break;
    case PAS_FILTER_SERVICE:
      INFO("PAS filter mode service \n");
      val_pas_filter_active_mode(arg0);
      break;
    case SMMU_ROOT_SERVICE:
      INFO("ROOT SMMU service \n");
      val_smmu_access_disable();
      break;
    case SEC_STATE_CHANGE:
      INFO("Security STte change service \n");
      val_security_state_change(arg0);
      break;
    default:
      INFO(" Service not present\n");
      break;
  }
}
