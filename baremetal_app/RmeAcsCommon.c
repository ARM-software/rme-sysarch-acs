/** @file
 * Copyright (c) 2023-2026, Arm Limited or its affiliates. All rights reserved.
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


#include "val/include/val_interface.h"
#include "val/include/val_pe.h"
#include "val/include/val.h"
#include "val/include/val_memory.h"
#include "val/include/acs_el3_param.h"
#include "RmeAcs.h"
#include <stdbool.h>

extern uint64_t  g_el3_param_magic;
extern uint64_t  g_el3_param_addr;
extern uint32_t *g_execute_tests;
extern uint32_t  g_num_tests;
extern char8_t **g_execute_modules_str;
extern uint32_t  g_num_modules;
extern char8_t **g_skip_modules;
/* Maximum number of tests that can be skipped via EL3 params */
#define MAX_TEST_SKIP_NUM 100

uint32_t  g_skip_test_num[MAX_TEST_SKIP_NUM];
extern uint32_t  g_num_skip;

/* === Build-time module list support (ACS_ENABLED_MODULE_LIST) === */
#if ACS_HAS_ENABLED_MODULE_LIST
static const char8_t *acs_build_module_array[] = { ACS_ENABLED_MODULE_LIST };
static const uint32_t acs_build_module_count =
    sizeof(acs_build_module_array) / sizeof(acs_build_module_array[0]);
#endif

void
acs_apply_el3_params(void)
{
  acs_el3_params *params;

  /* If magic doesn't match, ignore X20 completely */
  if (g_el3_param_magic != ACS_EL3_PARAM_MAGIC)
    return;

  if (!g_el3_param_addr) {
    val_print(ACS_PRINT_WARN,
              "EL3 param magic set but param address is 0, ignoring\n", 0);
    return;
  }

  params = (acs_el3_params *)(uintptr_t)g_el3_param_addr;

  /* Optional: version check (kept minimal, versioned for future proofing) */
  if ((params->version < 0x1) || (params->version > ACS_EL3_PARAM_VERSION)) {
    val_print(ACS_PRINT_WARN,
              "Unsupported EL3 param version %ld, ignoring\n", params->version);
    return;
  }

  val_print(ACS_PRINT_DEBUG, "EL3 params: tests=0x%lx", params->test_array_addr);
  val_print(ACS_PRINT_DEBUG, " (%ld),", params->test_array_count);
  val_print(ACS_PRINT_DEBUG, " modules=0x%lx", params->module_array_addr);
  val_print(ACS_PRINT_DEBUG, " (%ld),", params->module_array_count);
  val_print(ACS_PRINT_DEBUG, " skip modules=0x%lx", params->skip_module_array_addr);
  val_print(ACS_PRINT_DEBUG, " (%ld)\n", params->skip_module_array_count);

  /* Override tests if provided */
  if (params->test_array_addr && params->test_array_count) {
    g_execute_tests_str = (char8_t **)(uintptr_t)params->test_array_addr;
    g_num_tests     = (uint32_t)params->test_array_count;
  }

  /* Override modules if provided */
  if (params->module_array_addr && params->module_array_count) {
    g_execute_modules_str = (char8_t **)(uintptr_t)params->module_array_addr;
    g_num_modules     = (uint32_t)params->module_array_count;
  }

  /* Override skip list if provided (only valid from version 0x2) */
  if ((params->version >= 0x2) &&
        params->skip_test_array_addr && params->skip_test_array_count) {
    g_num_skip      = params->skip_test_array_count;

    g_skip_test_str  = (char8_t **)(uintptr_t)params->skip_test_array_addr;
  }

}

void acs_apply_compile_params(void)
{
#if ACS_HAS_ENABLED_MODULE_LIST
  g_execute_modules_str = (char8_t **)acs_build_module_array;
  g_num_modules = acs_build_module_count;
#endif
  return;
}
