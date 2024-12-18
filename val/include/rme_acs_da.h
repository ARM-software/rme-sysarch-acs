/** @file
 * Copyright (c) 2024, Arm Limited or its affiliates. All rights reserved.
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

#ifndef __RME_ACS_DA_H__
#define __RME_ACS_DA_H__

void val_da_get_addr_asso_block_base(uint32_t *num_sel_ide_stream_supp,
                         uint32_t *num_tc_supp,
                         uint32_t *current_base_offset,
                         uint32_t bdf,
                         uint32_t *num_addr_asso_block,
                         uint32_t *rid_limit,
                         uint32_t *rid_base,
                         uint32_t reg_value);

void val_da_get_next_rid_values(uint32_t *current_base_offset,
                    uint32_t *num_addr_asso_block,
                    uint32_t bdf,
                    uint32_t *next_rid_limit,
                    uint32_t *next_rid_base);

uint32_t
val_device_lock(uint32_t bdf);

uint32_t
val_device_unlock(uint32_t bdf);

uint32_t
val_get_sel_str_status(uint32_t bdf, uint32_t str_cnt, uint32_t *str_status);

uint32_t
val_get_sel_str_status(uint32_t bdf, uint32_t str_cnt, uint32_t *str_status);

uint32_t
val_ide_program_rid_base_limit_valid(uint32_t bdf, uint32_t str_cnt,
                                     uint32_t base, uint32_t limit, uint32_t valid);

uint32_t
val_ide_program_stream_id(uint32_t bdf, uint32_t str_cnt, uint32_t stream_id);

uint32_t
val_ide_set_sel_stream(uint32_t bdf, uint32_t str_cnt, uint32_t enable);

uint32_t
val_ide_get_num_sel_str(uint32_t bdf, uint32_t *num_sel_str);

uint32_t
val_ide_establish_stream(uint32_t bdf, uint32_t count, uint32_t stream_id, uint32_t base_limit);

uint32_t da001_entry(void);
uint32_t da002_entry(void);
uint32_t da003_entry(void);
uint32_t da004_entry(void);
uint32_t da005_entry(void);
uint32_t da006_entry(void);
uint32_t da007_entry(void);
uint32_t da008_entry(void);
uint32_t da009_entry(void);
uint32_t da010_entry(void);
uint32_t da011_entry(void);
uint32_t da012_entry(void);
uint32_t da013_entry(void);
uint32_t da014_entry(void);
uint32_t da015_entry(void);

#endif
