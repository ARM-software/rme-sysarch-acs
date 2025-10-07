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

#include <val_el3_debug.h>
#include <val_el3_memory.h>
#include <val_el3_mec.h>
#include <val_el3_pe.h>
#include <val_el3_pgt.h>

struct_sh_data *shared_data = (struct_sh_data *) PLAT_SHARED_ADDRESS;

static MemoryPool mem_pool = {
    .base = (uint8_t *)PLAT_FREE_MEM_SMMU, // Hardcoded address
    .size = PLAT_MEMORY_POOL_SIZE,
    .free_list = NULL,
};

/**
 * @brief  Returns the sligned address with the given size
 *
 * @param  size        Size in bytes to align
 * @param  alignment   alignment required
 * @return address aligned to the specified alignment till the 'size'
 */
static size_t align_size(size_t size, size_t alignment)
{
    return (size + (alignment - 1)) & ~(alignment - 1);
}

/**
 *  @brief  This API is called to Map the shared buffer into EL3 page tables with NS RW attributes,
 *          then populate EL3-local configuration so NS world can consume it immediately.
 *          1. Caller       -  VAL
 *  @param  shared_addr     -  The address of the shared memory buffer in EL3 to be read by NS
 *  @return None
**/
void val_el3_map_shared_mem(uint64_t shared_addr)
{
  uint64_t pgt_attr_el3;

  pgt_attr_el3 = LOWER_ATTRS(PGT_ENTRY_ACCESS | SHAREABLE_ATTR(OUTER_SHAREABLE)
                                      | PGT_ENTRY_AP_RW | PAS_ATTR(NONSECURE_PAS));

  // Store base address in shared_addr pointer which will be used by NS world
  val_el3_add_mmu_entry((uint64_t)shared_data, (uint64_t)shared_data, pgt_attr_el3);

  // Store base address in shared_addr pointer which will be used by NS world
  val_el3_add_mmu_entry(shared_addr, shared_addr, pgt_attr_el3);
  *(uint64_t *)shared_addr = (uint64_t)shared_data;

  struct_sh_data *sd = (struct_sh_data *)shared_data;
  /* EL3 cfg populated for NS consumption */
  sd->cfg_free_mem_start       = PLAT_FREE_MEM_START;
  sd->cfg_free_mem_smmu        = PLAT_FREE_MEM_SMMU;
  sd->cfg_memory_pool_size     = PLAT_MEMORY_POOL_SIZE;
  sd->cfg_smmu_root_reg_offset = SMMUV3_ROOT_REG_OFFSET;

}

/**
 * @brief Perform data cache maintenance by VA at EL3.
 *
 * @param VA    Virtual address for cache operation.
 * @param type  Operation type (CLEAN, INVALIDATE, CLEAN_AND_INVALIDATE).
 */
void val_el3_data_cache_ops_by_va(uint64_t VA, uint32_t type)
{

  switch (type)
  {
    case CLEAN_AND_INVALIDATE:
      val_el3_cln_and_invldt_cache((uint64_t *)VA);
      break;
    case CLEAN:
      val_el3_clean_cache((uint64_t *)VA);
      break;
    case INVALIDATE:
      val_el3_invalidate_cache((uint64_t *)VA);
      break;
    default:
      shared_data->status_code = 1;
      shared_data->error_code = 0;
      const char *msg = "EL3: Invalid cache operation";
      ERROR("\n %s", msg);
      int i = 0; while (msg[i] && i < sizeof(shared_data->error_msg) - 1) {
          shared_data->error_msg[i] = msg[i]; i++;
      }
      shared_data->error_msg[i] = '\0';
      break;
  }
}

/**
 * @brief Set memory to a byte value at EL3.
 *
 * @param address  Buffer base.
 * @param size     Number of bytes to set.
 * @param value    Byte value to write.
 */
void val_el3_memory_set(void *address, uint32_t size, uint8_t value)
{
  memset(address, value, size);
}

/**
 * @brief Free memory previously allocated from EL3 pool.
 *
 * @param ptr  Pointer returned by val_el3_memory_alloc/calloc.
 */
void val_el3_memory_free(void *ptr)
{
    uint32_t mecid = 0;

    if (!ptr) return;

   /* If MEC is enabled, the memory pool structures need to be accessed with
       VAL_GMECID */
    if (val_el3_is_mec_enabled())
    {
        mecid = val_el3_read_mecid_rl_a_el3();
        val_el3_write_mecid(VAL_GMECID);
    }


    BlockHeader *block = (BlockHeader *)((uint8_t *)ptr - sizeof(BlockHeader));
    block->is_free = 1;

    // Coalesce adjacent free blocks
    BlockHeader *current = mem_pool.free_list;
    while (current) {
        if (current->is_free && current->next && current->next->is_free) {
            current->size += current->next->size + sizeof(BlockHeader);
            current->next = current->next->next;
        }
        current = current->next;
    }

    /* Restore MECID */
    if (val_el3_is_mec_enabled())
        val_el3_write_mecid(mecid);
}

/**
 * @brief Initialize EL3 memory pool metadata.
 */
void val_el3_memory_pool_init(void)
{
    mem_pool.free_list = (BlockHeader *)mem_pool.base;
    mem_pool.free_list->size = mem_pool.size - sizeof(BlockHeader);
    mem_pool.free_list->is_free = 1;
    mem_pool.free_list->next = NULL;
}

/**
 * @brief Split a free block into an allocated block and remainder.
 *
 * @param block  Free block to split.
 * @param size   Size (bytes) for the allocated portion.
 */
void val_el3_split_block(BlockHeader *block, size_t size)
{
    BlockHeader *new_block = (BlockHeader *)((uint8_t *)block + sizeof(BlockHeader) + size);
    new_block->size = block->size - size - sizeof(BlockHeader);
    new_block->is_free = 1;
    new_block->next = block->next;

    block->size = size;
    block->next = new_block;
}

/**
  @brief   This function helps to read or write the address in EL3
           1. Caller       -  Test Suite
           2. Prerequisite -  Address needs to be mapped without any faults expected
  @param   address - Address that needs to be read on or written on
  @param   data    - The data which is written on the address
  @return  None
**/
/**
 * @brief Perform read/write accesses to MUT addresses as per shared_data.
 *
 * Iterates shared_data->shared_data_access and executes requested operations.
 */
void val_el3_access_mut(void)
{
  uint8_t type, num = shared_data->num_access;
  uint64_t data;

  for (int acc_cnt = 0; acc_cnt < num; ++acc_cnt)
  {

    type = shared_data->shared_data_access[acc_cnt].access_type;
    switch (type)
    {
        case READ_DATA:
          data = *(volatile uint32_t *) shared_data->shared_data_access[acc_cnt].addr;
          VERBOSE("The data returned from the address, 0x%lx is 0x%x\n",
               shared_data->shared_data_access[acc_cnt].addr, (uint32_t)data);
          shared_data->shared_data_access[acc_cnt].data = data;
          break;
        case WRITE_DATA:
          data = shared_data->shared_data_access[acc_cnt].data;
          *(volatile uint32_t *)shared_data->shared_data_access[acc_cnt].addr = data;
          VERBOSE("Data stored in VA, 0x%lx is 0x%x\n",
                shared_data->shared_data_access[acc_cnt].addr,
                *(uint32_t *)shared_data->shared_data_access[acc_cnt].addr);
          break;
        default:
          ERROR("INVALID TYPE OF ACCESS");
          break;
    }
  }
}

/**
 * @brief  Allocates requested buffer size in bytes with zeros in a contiguous memory
 *         and returns the base address of the range.
 *
 * @param  size         allocation size in bytes
 * @param  num          Requested number of (buffer * size)
 * @retval ptr          pointer to allocated memory
 */
void *val_el3_memory_calloc(size_t num, size_t size, size_t alignment)
{
    size_t total_size = num * size;
    void *ptr = val_el3_memory_alloc(total_size, alignment);
    if (ptr) {
        memset(ptr, 0, total_size);
    }
    return ptr;
}

/**
 * @brief  Returns the physical address of the requested Virtual address
 *
 * @param  Va  Virtual address
 * @return Va  Returns the VA because of the 1:1 memory mapping
 */
void *val_el3_memory_virt_to_phys(void *va)
{
  return va;
}

/**
 * @brief  Returns the virtual address of the requested physical address
 *
 * @param  pa  Physical address
 * @return pa  Returns the PA because of the 1:1 memory mapping
 */
void *val_el3_memory_phys_to_virt(uint64_t pa)
{
  return (void *)pa;
}

/**
 * @brief  Allocates requested buffer size in bytes in a contiguous memory
 *         and returns the base address of the range.
 *
 * @param  Size         allocation size in bytes
 * @param  alignment    Required alignment for the buffer
 * @retval if SUCCESS   pointer to allocated memory
 * @retval if FAILURE   NULL
 */
void *val_el3_memory_alloc(size_t size, size_t alignment)
{
    uint32_t mecid = 0;

    if (!mem_pool.free_list)
    {
        val_el3_memory_pool_init(); // Initialize pool on first call
    }

    /* If MEC is enabled, the memory pool structures need to be accessed with
       VAL_GMECID */
    if (val_el3_is_mec_enabled())
    {
        mecid = val_el3_read_mecid_rl_a_el3();
        val_el3_write_mecid(VAL_GMECID);
    }

    size = align_size(size, alignment); // Align the requested size
    BlockHeader *current = mem_pool.free_list;

    while (current) {
        // Align the starting address of the block
        uintptr_t block_start = (uintptr_t)current + sizeof(BlockHeader);
        uintptr_t aligned_start = align_size(block_start, alignment);
        size_t alignment_padding = aligned_start - block_start;

        if (current->is_free && current->size >= size + alignment_padding) {
            if (current->size > size + alignment_padding + sizeof(BlockHeader)) {
                val_el3_split_block(current, size + alignment_padding);
            }
            current->is_free = 0;
            /* Restore MECID */
            if (val_el3_is_mec_enabled())
                val_el3_write_mecid(mecid);
            return (void *)aligned_start;
        }
        current = current->next;
    }

    /* Restore MECID */
    if (val_el3_is_mec_enabled())
        val_el3_write_mecid(mecid);

    return NULL;
}
