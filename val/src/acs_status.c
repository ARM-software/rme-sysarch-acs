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
#include "include/rme_acs_common.h"
#include "include/rme_acs_cfg.h"
#include "include/rme_acs_pe.h"

/**
  @brief  Print the appropriate information to console based on string state
          1. Caller       - Application layer
          2. Prerequisite - None
  @param  index     - index of the PE who is reporting this status.
  @param  state     - pointer to the state string ("PASS", "FAIL", etc).
  @return  none
 **/
void
val_report_status(uint32_t index, char8_t *state)
{
  volatile VAL_SHARED_MEM_t *pe_mem;
  pe_mem = (VAL_SHARED_MEM_t *)pal_mem_get_shared_addr();
  pe_mem = pe_mem + index;

  if (val_memory_compare("FAIL", state, sizeof("FAIL")) == 0) {
      val_print(ACS_PRINT_ALWAYS, "\nFailed on PE - %4d ", index);
  }

  if (val_memory_compare("SKIP", state, sizeof("SKIP")) == 0) {
      val_print(ACS_PRINT_ALWAYS, "\nSkipped on PE - %4d", index);
  }

  if (val_memory_compare("PASS", state, sizeof("PASS")) == 0)
  {
    val_print(ACS_PRINT_ALWAYS, "\nResult: PASS \n", 0);
  }

  else
    if (val_memory_compare("FAIL", state, sizeof("FAIL")) == 0) {
        val_print(ACS_PRINT_ALWAYS, " Checkpoint -- %2d", (uint64_t)pe_mem->checkpoint);
        val_print(ACS_PRINT_ALWAYS, "\nResult: FAIL \n", 0);
    }
    else
      if (val_memory_compare("SKIP", state, sizeof("SKIP")) == 0) {
        val_print(ACS_PRINT_ALWAYS, " Checkpoint -- %2d", (uint64_t)pe_mem->checkpoint);
        val_print(ACS_PRINT_ALWAYS, "\nResult: SKIPPED \n", 0);
      }
      else
        if (val_memory_compare("END", state, sizeof("END")) == 0) {
          g_print_in_test_context = 0;
          g_print_test_check_id = 0;
          val_print(ACS_PRINT_ALWAYS,
            "\n******************************************************* \n", 0);
        }
        else {
            val_print(ACS_PRINT_ALWAYS, "\nResult=", 0);
            val_print(ACS_PRINT_ALWAYS, state, 0);
            val_print(ACS_PRINT_ALWAYS, " \n", 0);
            return;
        }
}

/**
  @brief  Record the string-based state, test name, and checkpoint for the test
          1. Caller       - Test Suite
          2. Prerequisite - val_allocate_shared_mem
  @param  index      - index of the PE who is reporting this status.
  @param  state      - string result status ("PASS", "FAIL", "SKIP", etc.)
  @param  checkpoint - checkpoint identifier to tag result
  @return none
**/
void
val_set_status(uint32_t index, char8_t *state, uint32_t checkpoint)
{
  volatile VAL_SHARED_MEM_t *mem;

  mem = (VAL_SHARED_MEM_t *) pal_mem_get_shared_addr();
  mem = mem + index;

  val_memcpy((void *)mem->state, state, sizeof(mem->state) - 1);
  mem->state[sizeof(mem->state) - 1] = '\0';

  mem->checkpoint = checkpoint;

  val_pe_cache_invalidate_range((addr_t)mem->state, sizeof(mem->state));
  val_data_cache_ops_by_va((addr_t)&mem->checkpoint, CLEAN_AND_INVALIDATE);
}

/**
  @brief  Return the state and status for the  input PE index
          1. Caller       - Test Suite
          2. Prerequisite - val_allocate_shared_mem
  @param  index  - index of the PE who is reporting this status.
  @return 32-bit value concatenated from state, level, error value
**/
char8_t *
val_get_status(uint32_t index)
{
  volatile VAL_SHARED_MEM_t *mem;

  mem = (VAL_SHARED_MEM_t *) pal_mem_get_shared_addr();
  mem = mem + index;

  val_data_cache_ops_by_va((addr_t)mem->state, INVALIDATE);

  return (char8_t *)(mem->state);
}
