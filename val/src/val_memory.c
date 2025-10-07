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

#include "include/val.h"
#include "include/val_peripherals.h"
#include "include/val_common.h"
#include "include/val_memory.h"
#include "include/val_pgt.h"
#include "include/val_interface.h"
#include "include/val_el32.h"

void *
val_memory_alloc(uint32_t size)
{
  return pal_mem_alloc(size);
}

void *
val_memory_calloc(uint32_t num, uint32_t size)
{
  return pal_mem_calloc(num, size);
}

void *
val_memory_alloc_cacheable(uint32_t bdf, uint32_t size, void **pa)
{
  return pal_mem_alloc_cacheable(bdf, size, pa);
}

void
val_memory_free(void *addr)
{
  pal_mem_free(addr);
}

int
val_memory_compare(void *src, void *dest, uint32_t len)
{
  return pal_mem_compare(src, dest, len);
}

void
val_memory_set(void *buf, uint32_t size, uint8_t value)
{
  pal_mem_set(buf, size, value);
}

void
val_memory_free_cacheable(uint32_t bdf, uint32_t size, void *va, void *pa)
{
  pal_mem_free_cacheable(bdf, size, va, pa);
}

void *
val_memory_virt_to_phys(void *va)
{
  return pal_mem_virt_to_phys(va);
}

void *
val_memory_phys_to_virt(uint64_t pa)
{
  return pal_mem_phys_to_virt(pa);
}

/**
  @brief  Return the address of unpopulated memory of requested
          instance from the GCD memory map.

  @param  addr      - Address of the unpopulated memory
          instance  - Instance of memory

  @return 0 - SUCCESS
          1 - No unpopulated memory present
          2 - FAILURE
**/

uint32_t val_memory_page_size(void)
{
    return pal_mem_page_size();
}

void *
val_memory_alloc_pages(uint32_t num_pages)
{
    return pal_mem_alloc_pages(num_pages);
}

void
val_memory_free_pages(void *addr, uint32_t num_pages)
{
    pal_mem_free_pages(addr, num_pages);
}

/**
  @brief  Allocates memory with the given alignment.

  @param  Alignment   Specifies the alignment.
  @param  Size        Requested memory allocation size.

  @return Pointer to the allocated memory with requested alignment.
**/
void
*val_aligned_alloc(uint32_t alignment, uint32_t size)
{
  return pal_aligned_alloc(alignment, size);
}

/**
 * @brief Check if non-secure memory encryption is programmable on this platform.
 *
 * @return 1 if programmable, 0 otherwise.
 */
uint32_t val_is_ns_encryption_programmable(void)
{
    return pal_is_ns_encryption_programmable();
}

/**
 * @brief Check if PAS filter mode is programmable on this platform.
 *
 * @return 1 if programmable, 0 otherwise.
 */
uint32_t val_is_pas_filter_mode_programmable(void)
{
    return pal_is_pas_filter_mode_programmable();
}

#ifdef TARGET_BM_BOOT
/**
 *   @brief    Add regions assigned to host into its translation table data structure.
 *   @param    void
 *   @return   void
**/
void val_mmu_add_mmap(void)
{
    return pal_mmu_add_mmap();
}

/**
 *   @brief    Get the list of mem regions.
 *   @param    void
 *   @return   Pointer of the list.
**/
void *val_mmu_get_mmap_list(void)
{
    return pal_mmu_get_mmap_list();
}

/**
 *   @brief    Get the total number of mem map regions.
 *   @param    void
 *   @return   Count of mem map regions.
**/
uint32_t val_mmu_get_mapping_count(void)
{
    return pal_mmu_get_mapping_count();
}

/**
 * @brief Setup page table for image regions and device regions
 * @param void
 * @return status
**/
uint32_t val_setup_mmu(void)
{
    memory_region_descriptor_t mem_desc_array[2], *mem_desc;
    memory_region_descriptor_t *mmap_region_list;
    pgt_descriptor_t pgt_desc;
    uint8_t i = 0;
    uint32_t map_count;

    // Memory map the image regions
    val_mmu_add_mmap();

    pgt_desc.ias = MMU_PGT_IAS;
    pgt_desc.oas = MMU_PGT_OAS;

    pgt_desc.pgt_base = (uint64_t) tt_l0_base;
    pgt_desc.stage = PGT_STAGE1;

    val_print(ACS_PRINT_DEBUG, " mmu: ias=%d", pgt_desc.ias);
    val_print(ACS_PRINT_DEBUG, " mmu: oas=%d", pgt_desc.oas);

    /* Map regions */

    val_memory_set(mem_desc_array, sizeof(mem_desc_array), 0);
    mem_desc = &mem_desc_array[0];
    mmap_region_list = (memory_region_descriptor_t *) val_mmu_get_mmap_list();
    map_count = val_mmu_get_mapping_count();

    while (i < map_count)
    {
        mem_desc->virtual_address = mmap_region_list[i].virtual_address;
        mem_desc->physical_address = mmap_region_list[i].physical_address;
        mem_desc->length = mmap_region_list[i].length;
        mem_desc->attributes = mmap_region_list[i].attributes;

        val_print(ACS_PRINT_ALWAYS, "\n Creating page table for region  : 0x%lx",
                                                                        mem_desc->virtual_address);
        val_print(ACS_PRINT_ALWAYS, "- 0x%lx\n",
          (mem_desc->virtual_address + mem_desc->length) - 1);

        if (val_pgt_create(mem_desc, &pgt_desc))
        {
            return ACS_STATUS_ERR;
        }
        i++;
    }

    return ACS_STATUS_PASS;
}

/**
 * @brief Enable mmu through configuring mmu registers
 * @param void
 * @return status
**/
uint32_t val_enable_mmu(void)
{
    uint64_t tcr;
    uint32_t currentEL;
    currentEL = (val_read_current_el() & 0xc) >> 2;

    /*
     * Setup Memory Attribute Indirection Register
     * Attr0 = b01000100 = Normal, Inner/Outer Non-Cacheable
     * Attr1 = b11111111 = Normal, Inner/Outer WB/WA/RA
     * Attr2 = b00000000 = Device-nGnRnE
     */
    val_mair_write(0x00FF44, currentEL);

    /* Setup ttbr0 */
    val_ttbr0_write((uint64_t)tt_l0_base, currentEL);

    if (currentEL == 0x02)
    {
        tcr = ((1ull << 20)    |           /* TBI, top byte ignored. */
               (5ull << 16)    |           /* Physical Address Size - 48 Bits*/
               (TCR_TG0 << 14) |           /* TG0, granule size */
               (3ull << 12)    |           /* SH0, inner shareable. */
               (1ull << 10)    |           /* ORGN0, normal mem, WB RA WA Cacheable */
               (1ull << 8)     |           /* IRGN0, normal mem, WB RA WA Cacheable */
               (64 - MMU_PGT_IAS));        /* T0SZ, input address is 2^40 bytes. */
    }

    val_tcr_write(tcr, currentEL);

    val_print(ACS_PRINT_DEBUG, " val_setup_mmu: TG0=0x%x", TCR_TG0);
    val_print(ACS_PRINT_DEBUG, " val_setup_mmu: tcr=0x%lx", tcr);

/* Enable MMU */
    val_sctlr_write((1 << 0) |  // M=1 Enable the stage 1 MMU
                    (1 << 2) |  // C=1 Enable data and unified caches
                    (1 << 12) | // I=1 Enable instruction caches
                    val_sctlr_read(currentEL),
                    currentEL);

    val_print(ACS_PRINT_DEBUG, " val_enable_mmu: successful", 0);
    val_print(ACS_PRINT_DEBUG, " System Control EL2 is %llx", val_sctlr_read(currentEL));

    return ACS_STATUS_PASS;
}
#endif  // TARGET_BM_BOOT

/**
 * @brief Compare two memory regions word-by-word with source bffer read from EL3.
 *
 * This function reads 32-bit words from a secure source buffer at EL3 and
 * compares them against words in a non-secure (NS) destination buffer.
 * The EL3 read is performed via platform-specific routines, while the destination
 * buffer is accessed normally from the Non-Secure world.
 *
 * @param[in] src   Pointer to the source buffer;
 * @param[in] dest  Pointer to the destination buffer.
 * @param[in] size  Size of memory comparision;
 *
 * @retval 0 All words matched successfully.
 * @retval 1 A mismatch was detected between EL3-read data and NS buffer data.
 */
uint32_t val_memory_compare_src_el3(uint32_t *src, uint32_t *dest, uint32_t size)
{
  /* Configure Read Access */
  shared_data->num_access = 1;
  shared_data->shared_data_access[0].access_type = READ_DATA;

  while (size > 0)
  {
      /* Read source buffer from EL3*/
      shared_data->shared_data_access[0].addr = (uint64_t)src;
      if (val_pe_access_mut_el3())
      {
        val_print(ACS_PRINT_ERR, " Access MUT failure for VA: 0x%llx", (uint64_t)src);
        return ACS_STATUS_ERR;
      }

      if (shared_data->shared_data_access[0].data != *dest)
          return 1;

      src++;
      dest++;
      size -= sizeof(uint32_t);
  }

  return 0;
}

/**
  @brief  Return the length of a null-terminated string

  @param  str   The pointer to a Null-terminated ASCII string.

  @return The number of characters in the string (not including null terminator)
**/
uint32_t
val_strnlen(const char8_t *str)
{
  uint32_t len = 0;
  while (str[len] != '\0')
    len++;
  return len;
}

