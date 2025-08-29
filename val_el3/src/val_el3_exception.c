/** @file
  * Copyright (c) 2022-2025, Arm Limited or its affiliates. All rights reserved.
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
#include <val_el3_exception.h>
#include <val_el3_memory.h>
#include <val_el3_pe.h>

#define TEST_DATA 0x999

uint64_t *armtf_handler = (uint64_t *)(ARM_TF_SHARED_ADDRESS);

/**
 *  @brief  This API is called to install the ack handler for exceptions at EL3
 *          1. Caller       -  Test Suite
 *  @return None
**/
void rme_install_handler(void)
{
  save_vbar_el3(armtf_handler);
  INFO("armtf_handler: 0x%lx\n", *(armtf_handler));
  INFO("armtf_handler address: 0x%llx\n", ARM_TF_SHARED_ADDRESS);
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
