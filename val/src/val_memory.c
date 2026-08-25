/** @file
 * Copyright (c) 2022-2023, 2025-2026, Arm Limited or its affiliates. All rights reserved.
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
#include "include/val_common.h"
#include "include/val_memory.h"
#include "include/val_pgt.h"
#include "include/val_interface.h"
#include "include/val_pe.h"
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

    tcr = 0;
    currentEL = (val_read_current_el() & 0xc) >> 2;
    tcr = val_pe_reg_read(TCR_ELx);

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

void
val_memory_clear_el3_access_state(void)
{
  shared_data->exception_expected = CLEAR;
  shared_data->exception_generated = CLEAR;
  shared_data->access_mut = CLEAR;
  shared_data->esr_value = 0u;
  shared_data->pas_filter_flag = CLEAR;
  shared_data->arg1 = 0u;
  shared_data->num_access = 0u;
}

/**
  @brief  Read a 32-bit value through the EL3 MUT access path.

  @param  address  Address to read.
  @param  value    Output pointer that receives the read value.

  @return ACS_STATUS_PASS on success, ACS_STATUS_ERR on failure.
**/
uint32_t
val_memory_read_el3(uint64_t address, uint32_t *value)
{
  if (value == NULL)
    return ACS_STATUS_ERR;

  val_memory_clear_el3_access_state();
  shared_data->num_access = 1;
  shared_data->shared_data_access[0].addr = address;
  shared_data->shared_data_access[0].access_type = READ_DATA;

  if (val_pe_access_mut_el3())
  {
    val_memory_clear_el3_access_state();
    val_print(ACS_PRINT_ERR, " EL3: MUT read failed for 0x%llx", address);
    return ACS_STATUS_ERR;
  }

  *value = (uint32_t)shared_data->shared_data_access[0].data;
  val_memory_clear_el3_access_state();
  return ACS_STATUS_PASS;
}

/**
  @brief  Write a 32-bit value through the EL3 MUT access path.

  @param  address  Address to write.
  @param  value    Value to write.

  @return ACS_STATUS_PASS on success, ACS_STATUS_ERR on failure.
**/
uint32_t
val_memory_write_el3(uint64_t address, uint32_t value)
{
  val_memory_clear_el3_access_state();
  shared_data->num_access = 1;
  shared_data->shared_data_access[0].addr = address;
  shared_data->shared_data_access[0].data = value;
  shared_data->shared_data_access[0].access_type = WRITE_DATA;

  if (val_pe_access_mut_el3())
  {
    val_memory_clear_el3_access_state();
    val_print(ACS_PRINT_ERR, " EL3: MUT write failed for 0x%llx", address);
    return ACS_STATUS_ERR;
  }

  val_memory_clear_el3_access_state();
  return ACS_STATUS_PASS;
}

/**
  @brief  Map a physical address with the requested Realm PAS memory type.

  @param  phys      Physical address to map.
  @param  memory_type  Translation-table memory attribute index.
  @param  virt_out  Output pointer that receives the virtual alias.

  @return ACS_STATUS_PASS on success, ACS_STATUS_ERR on failure.
**/
static uint32_t
val_memory_map_realm_alias(uint64_t phys,
                           uint64_t memory_type,
                           volatile uint64_t **virt_out)
{
  uint64_t page_size;
  uint64_t va;
  uint32_t attr;

  if ((phys == 0u) || (virt_out == NULL))
    return ACS_STATUS_ERR;

  page_size = (uint64_t)val_memory_page_size();
  if (page_size == 0u)
    return ACS_STATUS_ERR;

  va = val_get_free_va(page_size);
  if (va == 0u)
    return ACS_STATUS_ERR;

  attr = LOWER_ATTRS(PGT_ENTRY_ACCESS |
                     SHAREABLE_ATTR(OUTER_SHAREABLE) |
                     GET_ATTR_INDEX(memory_type) |
                     PGT_ENTRY_AP_RW |
                     PAS_ATTR(REALM_PAS));

  if (val_add_mmu_entry_el3(va, phys, attr))
    return ACS_STATUS_ERR;

  *virt_out = (volatile uint64_t *)va;
  return ACS_STATUS_PASS;
}

uint32_t
val_memory_map_realm_cacheable_alias(uint64_t phys, volatile uint64_t **virt_out)
{
  return val_memory_map_realm_alias(phys, WRITE_BACK_NT, virt_out);
}

/**
  @brief  Map a physical address as a non-cacheable Realm PAS alias.
**/
uint32_t
val_memory_map_realm_noncacheable_alias(uint64_t phys,
                                         volatile uint64_t **virt_out)
{
  return val_memory_map_realm_alias(phys, NON_CACHEABLE, virt_out);
}

/**
  @brief  Map a physical address as a device-memory alias for EL3 access.

  @param  phys      Physical address to map.
  @param  pas       PAS_ATTR value to use for the EL3 mapping.
  @param  virt_out  Output pointer that receives the virtual alias.

  @return ACS_STATUS_PASS on success, ACS_STATUS_ERR on failure.
**/
uint32_t
val_memory_map_device_alias(uint64_t phys, uint32_t pas,
                            volatile uint64_t **virt_out)
{
  uint64_t page_size;
  uint64_t va;
  uint32_t attr;

  if ((phys == 0u) || (virt_out == NULL))
    return ACS_STATUS_ERR;

  page_size = (uint64_t)val_memory_page_size();
  if (page_size == 0u)
    return ACS_STATUS_ERR;

  va = val_get_free_va(page_size);
  if (va == 0u)
    return ACS_STATUS_ERR;

  attr = LOWER_ATTRS(PGT_ENTRY_ACCESS |
                     SHAREABLE_ATTR(OUTER_SHAREABLE) |
                     GET_ATTR_INDEX(DEV_MEM_nGnRnE) |
                     PGT_ENTRY_AP_RW |
                     PAS_ATTR(pas));

  if (val_add_mmu_entry_el3(va, phys, attr))
    return ACS_STATUS_ERR;

  *virt_out = (volatile uint64_t *)va;
  return ACS_STATUS_PASS;
}

/**
  @brief  Perform a protected EL3 64-bit read that can recover from a fault.

  @param  address         Address to read.
  @param  value_out       Output pointer that receives read data if the access completes.
  @param  fault_seen_out  Optional output flag set when EL3 recovered from a fault.
  @param  esr_out         Optional output containing ESR_EL3 for a recovered fault.

  @return ACS_STATUS_PASS when the protected access path ran, ACS_STATUS_ERR on setup failure.
**/
uint32_t
val_memory_read64_el3_protected_with_esr(volatile uint64_t *address,
                                         uint64_t *value_out,
                                         uint32_t *fault_seen_out,
                                         uint64_t *esr_out)
{
  uint32_t fault_seen;
  uint64_t esr;

  if ((address == NULL) || (value_out == NULL))
    return ACS_STATUS_ERR;

  /*
   * Use the pas_filter protected-load path instead of READ_DATA. READ_DATA is a
   * 32-bit generic MUT operation; this path performs a 64-bit load and lets EL3
   * recover when the access is expected to fault.
   */
  val_memory_clear_el3_access_state();
  shared_data->access_mut = SET;
  shared_data->pas_filter_flag = SET;
  shared_data->arg1 = (uint64_t)address;
  shared_data->shared_data_access[0].data = 0u;
  shared_data->exception_expected = SET;
  shared_data->exception_generated = CLEAR;

  if (val_pe_access_mut_el3())
  {
    val_memory_clear_el3_access_state();
    return ACS_STATUS_ERR;
  }

  fault_seen = (shared_data->exception_generated == SET);
  esr = shared_data->esr_value;
  *value_out = shared_data->shared_data_access[0].data;
  if (fault_seen_out != NULL)
    *fault_seen_out = fault_seen;
  if (esr_out != NULL)
    *esr_out = esr;

  val_memory_clear_el3_access_state();
  return ACS_STATUS_PASS;
}

uint32_t
val_memory_read64_el3_protected(volatile uint64_t *address,
                                uint64_t *value_out,
                                uint32_t *fault_seen_out)
{
  return val_memory_read64_el3_protected_with_esr(address,
                                                   value_out,
                                                   fault_seen_out,
                                                   NULL);
}

/**
  @brief  Map a small data structure for EL3 access under the requested PAS.

  @param  va    Virtual address of the structure.
  @param  size  Size of the structure in bytes.
  @param  pas   PAS_ATTR value to use for the EL3 mapping.

  @return ACS_STATUS_PASS on success, ACS_STATUS_ERR on failure.
**/
uint32_t
val_memory_map_el3_data(uint64_t va, uint32_t size, uint32_t pas)
{
  uint32_t attr;
  uint64_t pa;
  uint64_t page_size;
  uint64_t page_mask;
  uint64_t map_va;
  uint64_t end_va;

  if ((va == 0u) || (size == 0u))
    return ACS_STATUS_ERR;

  page_size = val_memory_page_size();
  if ((page_size == 0u) || ((page_size & (page_size - 1u)) != 0u))
    return ACS_STATUS_ERR;

  page_mask = ~(page_size - 1u);
  attr = LOWER_ATTRS(PGT_ENTRY_ACCESS |
                     SHAREABLE_ATTR(OUTER_SHAREABLE) |
                     PGT_ENTRY_AP_RW |
                     PAS_ATTR(pas));

  map_va = va & page_mask;
  end_va = (va + size - 1u) & page_mask;
  while (map_va <= end_va)
  {
    pa = (uint64_t)val_memory_virt_to_phys((void *)map_va);
    if (pa == 0u)
      return ACS_STATUS_ERR;

    if (val_add_mmu_entry_el3(map_va, pa & page_mask, attr))
      return ACS_STATUS_ERR;

    map_va += page_size;
  }

  return ACS_STATUS_PASS;
}

/**
  @brief  Map a DMA buffer for EL3 access.

  @param  buffer_va  VA of the buffer.
  @param  buffer_pa  PA of the buffer.
  @param  length     Size of the buffer in bytes.
  @param  pas        PAS_ATTR value to use for the mapping.

  @return ACS_STATUS_PASS on success, ACS_STATUS_ERR on failure.
**/
uint32_t
val_memory_map_dma_buffer_el3(void *buffer_va,
                              uint64_t buffer_pa,
                              uint32_t length,
                              uint32_t pas)
{
  uint32_t attr;

  if ((buffer_va == NULL) || (buffer_pa == 0u) || (length == 0u))
    return ACS_STATUS_ERR;

  attr = LOWER_ATTRS(PGT_ENTRY_ACCESS |
                     SHAREABLE_ATTR(OUTER_SHAREABLE) |
                     GET_ATTR_INDEX(DEV_MEM_nGnRnE) |
                     PGT_ENTRY_AP_RW |
                     PAS_ATTR(pas));

  if (val_add_mmu_entry_el3((uint64_t)buffer_va, buffer_pa, attr))
    return ACS_STATUS_ERR;

  return ACS_STATUS_PASS;
}

/**
  @brief  Map adjacent source/destination DMA buffers for EL3 access.

  @param  buffer_va  VA of the first buffer.
  @param  buffer_pa  PA of the first buffer.
  @param  length     Size of each buffer in bytes.
  @param  pas        PAS_ATTR value to use for both mappings.

  @return ACS_STATUS_PASS on success, ACS_STATUS_ERR on failure.
**/
uint32_t
val_memory_map_dma_buffers_el3(void *buffer_va,
                               uint64_t buffer_pa,
                               uint32_t length,
                               uint32_t pas)
{
  if (val_memory_map_dma_buffer_el3(buffer_va, buffer_pa, length, pas)
      != ACS_STATUS_PASS)
    return ACS_STATUS_ERR;

  return val_memory_map_dma_buffer_el3((void *)((uint8_t *)buffer_va + length),
                                       buffer_pa + length,
                                       length,
                                       pas);
}

/**
  @brief  Initialize source and destination DMA buffers through EL3.

  @param  buffer_src   Source buffer VA.
  @param  buffer_dst   Destination buffer VA.
  @param  length       Size of each buffer in bytes.
  @param  src_pattern  Byte pattern for the source buffer.
  @param  dst_pattern  Byte pattern for the destination buffer.

  @return ACS_STATUS_PASS on success, ACS_STATUS_ERR on failure.
**/
uint32_t
val_memory_prepare_dma_buffers_el3(void *buffer_src,
                                   void *buffer_dst,
                                   uint32_t length,
                                   uint32_t src_pattern,
                                   uint32_t dst_pattern)
{
  if ((buffer_src == NULL) || (buffer_dst == NULL) || (length == 0u))
    return ACS_STATUS_ERR;

  if (val_memory_set_el3(buffer_src, length, (uint8_t)src_pattern))
    return ACS_STATUS_ERR;

  if (val_memory_set_el3(buffer_dst, length, (uint8_t)dst_pattern))
    return ACS_STATUS_ERR;

  return ACS_STATUS_PASS;
}

/**
  @brief  Clean and invalidate every EL3 data-cache line in an address range.

  @param  address  Start virtual address.
  @param  length   Number of bytes covered by the operation.

  @return ACS_STATUS_PASS on success, ACS_STATUS_ERR on invalid input or CMO failure.
**/
static uint32_t
val_memory_cache_maint_range_el3(uint64_t address,
                                 uint32_t length,
                                 uint32_t operation)
{
  uint64_t aligned_address;
  uint64_t end_address;
  uint64_t line_length;

  if ((address == 0u) || (length == 0u) ||
      (address > (~0ull - (uint64_t)length)))
    return ACS_STATUS_ERR;

  line_length = 2ull << ((val_pe_reg_read(CTR_EL0) >> 16) & 0xFu);
  aligned_address = address & ~(line_length - 1u);
  end_address = address + length;

  while (aligned_address < end_address)
  {
    if (val_data_cache_ops_by_va_el3(aligned_address, operation) != 0u)
      return ACS_STATUS_ERR;
    aligned_address += line_length;
  }

  return ACS_STATUS_PASS;
}

uint32_t
val_memory_cache_clean_invalidate_range_el3(uint64_t address, uint32_t length)
{
  return val_memory_cache_maint_range_el3(address,
                                          length,
                                          CLEAN_AND_INVALIDATE);
}

uint32_t
val_memory_cache_invalidate_range_el3(uint64_t address, uint32_t length)
{
  return val_memory_cache_maint_range_el3(address, length, INVALIDATE);
}

/**
  @brief  Compare two buffers through EL3 MUT reads.

  @param  src_va  Source buffer VA.
  @param  dst_va  Destination buffer VA.
  @param  size    Number of bytes to compare. Must be 32-bit aligned.

  @return 0 if the buffers match, 1 if they differ, ACS_STATUS_ERR on access
          failure.
**/
uint32_t
val_memory_compare_el3(uint64_t src_va, uint64_t dst_va, uint32_t size)
{
  uint32_t src_data;
  uint32_t dst_data;

  if ((src_va == 0u) || (dst_va == 0u) || ((size % sizeof(uint32_t)) != 0u))
    return ACS_STATUS_ERR;

  while (size > 0u)
  {
    if (val_memory_read_el3(src_va, &src_data) != ACS_STATUS_PASS)
      return ACS_STATUS_ERR;

    if (val_memory_read_el3(dst_va, &dst_data) != ACS_STATUS_PASS)
      return ACS_STATUS_ERR;

    if (src_data != dst_data)
      return 1u;

    src_va += sizeof(uint32_t);
    dst_va += sizeof(uint32_t);
    size -= sizeof(uint32_t);
  }

  return 0u;
}

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
