/** @file
 * Copyright (c) 2022,2025, Arm Limited or its affiliates. All rights reserved.
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

#ifndef __RME_ACS_CFG_H__
#define __RME_ACS_CFG_H__

#ifndef TARGET_LINUX
#define MAX_TEST_SKIP_NUM  10
#else
#define MAX_TEST_SKIP_NUM  3
#endif

extern uint32_t g_print_level;
extern uint32_t g_execute_secure;
extern uint32_t g_skip_test_num[MAX_TEST_SKIP_NUM];
extern uint32_t g_rme_tests_total;
extern uint32_t g_rme_tests_pass;
extern uint32_t g_rme_tests_fail;
extern uint64_t g_stack_pointer;
extern uint64_t g_exception_ret_addr;
extern uint64_t g_ret_addr;
extern uint32_t g_curr_module;
extern uint32_t g_single_test;
extern uint32_t g_single_module;
extern uint32_t g_rl_smmu_init;

#endif
