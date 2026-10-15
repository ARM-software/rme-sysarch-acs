/** @file
  * Copyright (c) 2022-2026, Arm Limited or its affiliates. All rights reserved.
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
#include <pal_el3.h>

#define TEST_DATA 0x999

uint64_t *armtf_handler = (uint64_t *)(ARM_TF_SHARED_ADDRESS);

/**
 *  @brief  This API is called to install the ack handler for exceptions at EL3
 *          1. Caller       -  Test Suite
 *  @return None
**/
void val_el3_rme_install_handler(void)
{
  val_el3_save_vbar_el3(armtf_handler);
  INFO("armtf_handler: 0x%lx\n", *(armtf_handler));
  INFO("armtf_handler address: 0x%llx\n", ARM_TF_SHARED_ADDRESS);
  val_el3_program_vbar_el3(&val_el3_exception_handler_user);
}

/**
 *  @brief  This API is called for the exceptions caused in and are/is taken to EL3
 *          so that it is handled appropriately as expected from the test
 *          1. Caller       -  Any EL3 Excpetion
 *          2. Prerequisite -  rme_install_handler()
 *  @return None
**/
void val_el3_ack_handler(void)
{
  uint64_t *elr_ptr;
  uint64_t *spsr_ptr;

  elr_ptr = (uint64_t *) SHARED_OFFSET_ELR;
  spsr_ptr = (uint64_t *) SHARED_OFFSET_SPSR;

  INFO("Inside EL3 ACK Handler\n");

  /* The access branch clears access_mut before issuing the probe. A fault then
   * re-enters with exception_expected SET, selecting recovery here.
   */
  if (shared_data->exception_expected == SET && shared_data->access_mut == CLEAR) {
    /* These markers identify a fault from the inactive PAS-filter load.
     * Let PAL verify its platform-specific denial syndrome before accepting it.
     */
    if (shared_data->pas_filter_flag == SET &&
        shared_data->generic_flag == PAS_FILTER_INACTIVE_PROBE) {
        uint64_t esr = val_el3_read_esr_el3();
        uint64_t far = val_el3_read_far();

        shared_data->esr_value = esr;
        shared_data->exception_generated =
            pal_el3_pas_filter_check_exception(esr, far, shared_data->arg1) ? SET : CLEAR;

        INFO("PAS filter probe: ESR_EL3=0x%lx FAR_EL3=0x%lx\n", esr, far);

        shared_data->exception_expected = CLEAR;
        val_el3_asm_eret();
        return;
    }

    /* A caller may arm a specific external read abort. Do not consume other faults. */
    if (shared_data->esr_value == SEA_ESR_READ) {
        uint64_t esr = val_el3_read_esr_el3();
        if (((esr >> 26) == 0x25u) && ((esr & 0x3fu) == 0x10u) &&
            ((esr & ((1u << 6) | (1u << 10))) == 0u) &&
            (val_el3_read_elr_el3() == (uint64_t)&val_el3_mmio_read_load) &&
            (val_el3_read_far() == shared_data->shared_data_access[0].addr)) {
            shared_data->exception_generated = SET;
            shared_data->exception_expected = CLEAR;
            INFO("Expected external read abort observed\n");
            val_el3_asm_eret();
        } else {
            val_el3_branch_asm(*(armtf_handler + 1));
        }
        return;
    }
    INFO("The Fault is encountered\n");

    /* Other probes retain the existing GPF checks. Record a matching read/write
     * GPF, then resume after the faulting instruction.
     */
    if (val_el3_read_esr_el3() == GPF_ESR_READ || val_el3_read_esr_el3() == GPF_ESR_WRITE) {
        INFO("The GPF was expected, encountered and handled\n");
        shared_data->exception_generated = SET;
        shared_data->exception_expected = CLEAR;

        VERBOSE("Saved elr = %lx\n", *(elr_ptr));
        VERBOSE("Saved spsr = %lx\n", *(spsr_ptr));
        VERBOSE("Current elr = %lx\n", val_el3_read_elr_el3());
        VERBOSE("Current spsr = %lx\n", val_el3_read_spsr_el3());
        val_el3_asm_eret();
    } else {
        /* The syndrome does not match the expected GPF. Resume after the faulting
         * instruction without setting exception_generated, so the test can check it.
         */
        VERBOSE("The fault is not GPF, ESR_EL3 = 0x%lx\n", val_el3_read_esr_el3());
        VERBOSE("FAR_EL3 = 0x%lx\n", val_el3_read_far());
        VERBOSE("Saved elr = %lx\n", *(elr_ptr));
        VERBOSE("Saved spsr = %lx\n", *(spsr_ptr));
        VERBOSE("Current elr = %lx\n", val_el3_read_elr_el3());
        VERBOSE("Current spsr = %lx\n", val_el3_read_spsr_el3());
        shared_data->exception_expected = CLEAR;
        val_el3_asm_eret();
    }
    //Save other parameters as per test requirement
  } else if (shared_data->access_mut == SET) {
    /* The initial SMC arrives with access_mut SET. Save its return state and
     * issue the requested probe; any expected fault takes the recovery path above.
     */
    uint64_t data = TEST_DATA;

    /* A probe fault must enter the recovery path rather than issue another access. */
    shared_data->access_mut = CLEAR;

    INFO("Argument 1: 0x%lx\n", shared_data->arg1);

    /* Store the elr_el3 and spsr_el3 to restore it later */
    shared_data->elr_el3 = val_el3_read_elr_el3();
    shared_data->spsr_el3 = val_el3_read_spsr_el3();

    if (shared_data->pas_filter_flag == SET) {
        /* The helper releases the ACK frame before LDR so a fault can reuse it.
         * After completion or fault recovery, it ERETs directly to the test.
         */
        val_el3_set_daif();
        val_el3_acs_ldr_pas_filter((uint64_t *)shared_data->arg1,
                        shared_data->shared_data_access[0].data);
    } else if (shared_data->exception_expected == SET) {
        /* Issue the store probe with access_mut already CLEAR. If it faults,
         * re-entry selects expected-fault recovery rather than another access.
         */
        VERBOSE("Exception Expected\n");
        VERBOSE("Saved elr = %lx\n", *(elr_ptr));
        VERBOSE("Saved spsr = %lx\n", *(spsr_ptr));
        if (shared_data->shared_data_access[0].access_type == READ_DATA_GPF)
            val_el3_acs_ldr32((uint32_t *)shared_data->arg1);
        else if (shared_data->shared_data_access[0].access_type == WRITE_DATA_GPF)
            val_el3_acs_str32((uint32_t *)shared_data->arg1,
                              (uint32_t)shared_data->shared_data_access[0].data);
        else
            val_el3_acs_str((uint64_t *)shared_data->arg1, data);
    } else
        /* No fault is expected for this ordinary read request. */
        data = *(uint64_t *)shared_data->arg1;

    //Now restore the contents of the registers to be used in eret
    val_el3_update_elr_el3(shared_data->elr_el3);
    val_el3_update_spsr_el3(shared_data->spsr_el3);
    val_el3_asm_eret_smc();
  } else {
    /* Neither ACS access handling nor expected-fault recovery applies.
     * Restore the entry context and forward this exception to firmware.
     */
    INFO("Branch to arm-tf handler\n");
    val_el3_branch_asm(*(armtf_handler + 1));
  }
}
