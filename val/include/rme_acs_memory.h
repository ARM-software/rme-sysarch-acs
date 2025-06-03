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

#ifndef __RME_ACS_MEMORY_H__
#define __RME_ACS_MEMORY_H__

#define MEM_MAP_SUCCESS  0x0
#define MEM_MAP_NO_MEM   0x1
#define MEM_MAP_FAILURE  0x2

extern uint64_t tt_l0_base[];

void val_memory_unmap(void *ptr);
void *val_memory_alloc(uint32_t size);
void *val_memory_calloc(uint32_t num, uint32_t size);
void *val_memory_alloc_cacheable(uint32_t bdf, uint32_t size, void **pa);
void val_memory_free(void *addr);
int val_memory_compare(void *src, void *dest, uint32_t len);
void val_memory_set(void *buf, uint32_t size, uint8_t value);
void val_memory_free_cacheable(uint32_t bdf, uint32_t size, void *va, void *pa);
void *val_memory_virt_to_phys(void *va);
void *val_memory_phys_to_virt(uint64_t pa);
uint32_t val_memory_page_size(void);
void *val_memory_alloc_pages(uint32_t num_pages);
void val_memory_free_pages(void *page_base, uint32_t num_pages);
void *val_aligned_alloc(uint32_t alignment, uint32_t size);
void val_memory_free_aligned(void *addr);
uint32_t val_memory_compare_src_el3(uint32_t *src, uint32_t *dest, uint32_t size);
uint32_t val_strnlen(const char8_t *str);
// NSEL2 MMU mem map APIs
uint32_t val_setup_mmu(void);
uint32_t val_enable_mmu(void);
void val_mmu_add_mmap(void);
void *val_mmu_get_mmap_list(void);
uint32_t val_mmu_get_mapping_count(void);

extern void val_mair_write(uint64_t value, uint64_t el_num);
extern void val_tcr_write(uint64_t value, uint64_t el_num);
extern void val_ttbr0_write(uint64_t value, uint64_t el_num);
extern void val_sctlr_write(uint64_t value, uint64_t el_num);
extern uint64_t val_sctlr_read(uint64_t el_num);
extern uint64_t val_ttbr0_read(uint64_t el_num);
extern uint64_t val_read_current_el(void);

uint32_t val_is_ns_encryption_programmable(void);
uint32_t val_is_pas_filter_mode_programmable(void);

#endif // __RME_ACS_MEMORY_H__
