/** @file
 * Copyright (c) 2025, Arm Limited or its affiliates. All rights reserved.
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

#ifndef VAL_EL3_MEMORY_H
#define VAL_EL3_MEMORY_H

#include <val_el3_helpers.h>

/* Shared memory layout constants are provided by val_el3_helpers.h */
#define ARM_TF_SHARED_ADDRESS (PLAT_SHARED_ADDRESS + SIZE_4KB - 0x20)
#define SHARED_OFFSET_ELR     (PLAT_SHARED_ADDRESS + 0x8)
#define SHARED_OFFSET_SPSR    (PLAT_SHARED_ADDRESS + 0x10)
#define SHARED_OFFSET_EXC_EXP (PLAT_SHARED_ADDRESS + 0x18)
#define SHARED_OFFSET_EXC_GEN (PLAT_SHARED_ADDRESS + 0x20)
#define SHARED_OFFSET_ACC_MUT (PLAT_SHARED_ADDRESS + 0x28)
#define SHARED_OFFSET_ESR_VAL (PLAT_SHARED_ADDRESS + 0x30)
#define SHARED_OFFSET_ARG0    (PLAT_SHARED_ADDRESS + 0x38)
#define SHARED_OFFSET_ARG1    (PLAT_SHARED_ADDRESS + 0x40)
#define ACS_EL3_STACK (PLAT_SHARED_ADDRESS + SIZE_4KB - 0x100)
#define ACS_EL3_HANDLER_SAVED_POINTER (PLAT_SHARED_ADDRESS + 0x800)

#define CIPOPA_NS_BIT           63
#define CIPOPA_NSE_BIT          62
#define CIPAE_NS_BIT           63
#define CIPAE_NSE_BIT          62


#ifndef __ASSEMBLER__
typedef struct BlockHeader {
    size_t size;                // Size of the block
    int is_free;                // Block free status
    struct BlockHeader *next;   // Pointer to the next block
} BlockHeader;

typedef struct {
    uint8_t *base;              // Base address of the memory pool
    size_t size;                // Total size of the pool
    BlockHeader *free_list;     // Head of the free list
} MemoryPool;


/* Prototypes moved from ack_common.c */
void val_data_cache_ops_by_va_el3(uint64_t address, uint32_t type);
void val_memory_set_el3(void *address, uint32_t size, uint8_t value);
void memory_pool_init(void);
void split_block(BlockHeader *block, size_t size);
void *val_memory_virt_to_phys_el3(void *va);
void *val_memory_phys_to_virt(uint64_t pa);
void *val_memory_alloc_el3(size_t size, size_t alignment);
void val_memory_free_el3(void *ptr);
void *val_memory_calloc_el3(size_t num, size_t size, size_t alignment);
void cmo_cipapa(uint64_t PA);
void tlbi_paallos(void);
void cln_and_invldt_cache(uint64_t *desc_addr);
void clean_cache(uint64_t *address);
void invalidate_cache(uint64_t *address);
void val_mmio_write_el3(uintptr_t addr, uint32_t val);
uint32_t val_mmio_read_el3(uintptr_t addr);
uint32_t val_mmio_read64_el3(uintptr_t addr);
void val_mmio_write64_el3(uintptr_t addr, uint64_t val);
void mem_barrier(void);
void cmo_cipae(uint64_t PA);
void acs_str(uint64_t *address, uint64_t data);
void tlbi_vae3(uint64_t VA);
void tlbi_alle3is(void);
void isb(void);
void map_shared_mem(void);
void access_mut(void);
void acs_ldr_pas_filter(uint64_t *address, uint64_t data);

#endif /* __ASSEMBLER__ */

#endif /* VAL_EL3_MEMORY_H */
