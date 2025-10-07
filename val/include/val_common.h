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


/** This file is common to all test cases and Val layer of the Suite */


#ifndef __RME_ACS_COMMON_H__
#define __RME_ACS_COMMON_H__

#include "val_memory.h"

#define DA_MODULE        "da"
#define DPT_MODULE       "dpt"
#define GIC_MODULE       "gic"
#define LEGACY_MODULE    "legacy"
#define MEC_MODULE       "mec"
#define RME_MODULE       "rme"
#define SMMU_MODULE      "smmu"

#define CPU_NUM_BIT  32
#define CPU_NUM_MASK 0xFFFFFFFF

#define LEVEL_BIT    24
#define LEVEL_MASK  0xF

#define IS_TEST_END(status)        (val_memory_compare("END", status, sizeof("END")) == 0)
#define IS_RESULT_PENDING(status)  (val_memory_compare("PENDING", status, sizeof("PENDING")) == 0)
#define IS_TEST_PASS(status)       (val_memory_compare("PASS", status, sizeof("PASS")) == 0)
#define IS_TEST_FAIL(status)       (val_memory_compare("FAIL", status, sizeof("FAIL")) == 0)
#define IS_TEST_SKIP(status)       (val_memory_compare("SKIP", status, sizeof("SKIP")) == 0)
#define IS_TEST_FAIL_SKIP(status)  (IS_TEST_FAIL(status) || IS_TEST_SKIP(status))

uint8_t
val_mmio_read8(addr_t addr);

uint16_t
val_mmio_read16(addr_t addr);

uint32_t
val_mmio_read(addr_t addr);

uint64_t
val_mmio_read64(addr_t addr);

void
val_mmio_write8(addr_t addr, uint8_t data);

void
val_mmio_write16(addr_t addr, uint16_t data);

void
val_mmio_write(addr_t addr, uint32_t data);

void
val_mmio_write64(addr_t addr, uint64_t data);

uint32_t
val_check_skip_module(char8_t *module_id);

uint32_t
val_initialize_test(char8_t *testname, char8_t *desc, uint32_t num_pe, char8_t *ruleid);

uint32_t
val_check_for_error(uint32_t num_pe);

void
val_run_test_payload(uint32_t num_pe, void (*payload)(void), uint64_t test_input);


void
val_data_cache_ops_by_va(addr_t addr, uint32_t type);

/* Module specific print APIs */

typedef enum {
    RME_MODULE_ID,
    GIC_MODULE_ID,
    SMMU_MODULE_ID,
    DA_MODULE_ID,
    DPT_MODULE_ID,
    MEC_MODULE_ID,
    LEGACY_MODULE_ID
} MODULE_ID_e;

#endif
