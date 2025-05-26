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

#ifndef __RME_ACS_VAL_H__
#define __RME_ACS_VAL_H__

#include "val_interface.h"
#include "pal_interface.h"
#include "rme_acs_cfg.h"
#include "rme_acs_common.h"

typedef struct {
  uint64_t    data0;
  uint64_t    data1;
  uint32_t    status;
} VAL_SHARED_MEM_t;

uint64_t
val_pe_reg_read(uint32_t reg_id);

void
val_pe_reg_write(uint32_t reg_id, uint64_t write_data);

uint32_t
val_pe_reg_read_tcr(uint32_t ttbr1, PE_TCR_BF *tcr);

uint32_t
val_pe_reg_read_ttbr(uint32_t ttbr1, uint64_t *ttbr_ptr);

uint8_t
val_is_el3_enabled(void);

uint8_t
val_is_el2_enabled(void);

void
val_report_status(uint32_t id, uint32_t status, char8_t *ruleid);

void
val_set_status(uint32_t index, uint32_t status);

uint32_t
val_get_status(uint32_t id);

uint32_t
val_read_reset_status(void);

void
val_write_reset_status(uint32_t data);

uint64_t
val_get_free_pa(uint64_t size, uint64_t alignment);

uint64_t
val_get_free_va(uint64_t size);

uint64_t
val_get_min_tg(void);

void
val_reg_update_shared_struct_msd(uint32_t reg_name, uint32_t reg_indx);

void
val_restore_global_test_data(void);

void
val_save_global_test_data(void);

uint32_t
val_pe_get_vtcr(VTCR_EL2_INFO *vtcr);

uint32_t
val_pe_get_vtbr(uint64_t *ttbr_ptr);

void
val_mem_region_create_info_table(uint64_t *mem_gpc_region_table,
                                 uint64_t *mem_pas_region_table);

MEM_REGN_INFO_TABLE *
val_mem_gpc_info_table(void);

MEM_REGN_INFO_TABLE *
val_mem_pas_info_table(void);

#endif

