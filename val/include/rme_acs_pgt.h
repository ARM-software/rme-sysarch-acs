/** @file
 * Copyright (c) 2022, 2025, Arm Limited or its affiliates. All rights reserved.
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

#ifndef __RME_ACS_PGT_H__
#define __RME_ACS_PGT_H__

#define PGT_STAGE1 1
#define PGT_STAGE2 2

#define PGT_IAS     40
#define PAGT_OAS    40
#define PGT_ENTRY_TABLE_MASK (0x1 << 1)
#define PGT_ENTRY_VALID_MASK  0x1
#define PGT_ENTRY_PAGE_MASK  (0x1 << 1)
#define PGT_ENTRY_BLOCK_MASK (0x0 << 1)
#define PGT_ENTRY_ACCESS_SET (0x1 << 10)

#define IS_PGT_ENTRY_PAGE(val) (val & 0x2)
#define IS_PGT_ENTRY_BLOCK(val) !(val & 0x2)

#define PGT_DESC_SIZE 8
#define PGT_DESC_ATTR_UPPER_MASK (((0x1ull << 12) - 1) << 52)
#define PGT_DESC_ATTR_LOWER_MASK (((0x1ull << 10) - 1) << 2)
#define PGT_DESC_ATTRIBUTES_MASK (PGT_DESC_ATTR_UPPER_MASK | PGT_DESC_ATTR_LOWER_MASK)
#define PGT_DESC_ATTRIBUTES(val) (val & PGT_DESC_ATTRIBUTES_MASK)

#define PGT_STAGE1_AP_RO (0x3ull << 6)
#define PGT_STAGE1_AP_RW (0x1ull << 6)
#define PGT_STAGE2_AP_RO (0x1ull << 6)
#define PGT_STAGE2_AP_RW (0x3ull << 6)

#define PGT_LEVEL_0   0
#define PGT_LEVEL_1   1
#define PGT_LEVEL_2   2
#define PGT_LEVEL_3   3

#define MAX_ENTRIES_4K      512L
#define MAX_ENTRIES_16K     2048L
#define MAX_ENTRIES_64K     8192L

#define PAGE_SIZE_4K        0x1000
#define PAGE_SIZE_16K       (4 * 0x1000)
#define PAGE_SIZE_64K       (16 * 0x1000)

uint32_t val_pgt_create(memory_region_descriptor_t *mem_desc, pgt_descriptor_t *pgt_desc);
void val_pgt_destroy(pgt_descriptor_t pgt_desc);
uint64_t val_pgt_get_attributes(pgt_descriptor_t pgt_desc,
		                uint64_t virtual_address, uint64_t *attributes);
uint32_t val_pe_mmu_map_add(memory_region_descriptor_t *mem_desc);
uint32_t val_pe_mmu_map_rmv(memory_region_descriptor_t *mem_desc);
uint64_t modify_desc(uint64_t table_desc, uint8_t bit_to_set, uint64_t value_to_set);
uint32_t val_realm_pgt_create(memory_region_descriptor_t *mem_desc, pgt_descriptor_t *pgt_desc);

#endif
