/** @file:
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

#include <stdint.h>
#include <stdarg.h>
#include <stddef.h>
#include "include/pal_pcie_enum.h"
#include "include/pal_common_support.h"
#include "pal_image_def.h"
#include "pal_pl011_uart.h"

#define __ADDR_ALIGN_MASK(a, mask)    (((a) + (mask)) & ~(mask))
#define ADDR_ALIGN(a, b)              __ADDR_ALIGN_MASK(a, (typeof(a))(b) - 1)

void *mem_alloc(size_t alignment, size_t size);
void mem_free(void *ptr);
void mem_alloc_init(void);

#define get_num_va_args(_args, _lcount)             \
    (((_lcount) > 1)  ? va_arg(_args, long long int) :  \
    (((_lcount) == 1) ? va_arg(_args, long int) :       \
                va_arg(_args, int)))

#define get_unum_va_args(_args, _lcount)                \
    (((_lcount) > 1)  ? va_arg(_args, unsigned long long int) : \
    (((_lcount) == 1) ? va_arg(_args, unsigned long int) :      \
                va_arg(_args, unsigned int)))


typedef struct {
    uint64_t base;
    uint64_t size;
} val_host_alloc_region_ts;

static uint64_t heap_base;
static uint64_t heap_top;
static uint64_t heap_init_done = 0;

/* Header magic to detect invalid frees/overwrites. */
#define HEAP_HDR_MAGIC 0x48454150u

typedef struct heap_hdr {
  size_t size;
  uint32_t magic;
  uint32_t rsvd;
} heap_hdr_t;

typedef struct heap_free_node {
  size_t size;
  struct heap_free_node *next;
} heap_free_node_t;

static heap_free_node_t *heap_free_list;
extern void* g_rme_log_file_handle;
uint8_t   *gSharedMemory;

#ifdef ENABLE_OOB
/* Below code is not applicable for Bare-metal
 * Only for FVP OOB experience
 */

#include  <Library/ShellCEntryLib.h>
#include  <Library/UefiBootServicesTableLib.h>
#include  <Library/UefiLib.h>
#include  <Library/ShellLib.h>
#include  <Library/PrintLib.h>
#include  <Library/BaseMemoryLib.h>
#include  <Protocol/Cpu.h>

#endif
/**
  @brief  Provides a single point of abstraction to read from all
          Memory Mapped IO address

  @param  addr 64-bit address

  @return 8-bit data read from the input address
**/
uint8_t
pal_mmio_read8(uint64_t addr)
{
  uint8_t data;

  data = (*(volatile uint8_t *)addr);
  if (g_print_mmio || (g_curr_module & g_enable_module))
      print(ACS_PRINT_INFO, " pal_mmio_read8 Address = %llx  Data = %lx ", addr, data);

  return data;
}

/**
  @brief  Provides a single point of abstraction to read from all
          Memory Mapped IO address

  @param  addr 64-bit address

  @return 16-bit data read from the input address
**/
uint16_t
pal_mmio_read16(uint64_t addr)
{
  uint16_t data;

  data = (*(volatile uint16_t *)addr);
  if (g_print_mmio || (g_curr_module & g_enable_module))
      print(ACS_PRINT_INFO, " pal_mmio_read16 Address = %llx  Data = %lx ", addr, data);

  return data;
}

/**
  @brief  Provides a single point of abstraction to read from all
          Memory Mapped IO address

  @param  addr 64-bit address

  @return 64-bit data read from the input address
**/
uint64_t
pal_mmio_read64(uint64_t addr)
{
  uint64_t data;

  data = (*(volatile uint64_t *)addr);
  if (g_print_mmio || (g_curr_module & g_enable_module))
      print(ACS_PRINT_INFO, " pal_mmio_read64 Address = %llx  Data = %llx ", addr, data);

  return data;
}

/**
  @brief  Provides a single point of abstraction to read from all
          Memory Mapped IO address

  @param  addr 64-bit address

  @return 32-bit data read from the input address
**/
uint32_t
pal_mmio_read(uint64_t addr)
{
  uint32_t data;

  data = (*(volatile uint32_t *)addr);

  if (g_print_mmio || (g_curr_module & g_enable_module))
      print(ACS_PRINT_INFO, " pal_mmio_read Address = %llx  Data = %x ", addr, data);

  return data;

}

/**
  @brief  Provides a single point of abstraction to write to all
          Memory Mapped IO address

  @param  addr  64-bit address
  @param  data  8-bit data to write to address

  @return None
**/
void
pal_mmio_write8(uint64_t addr, uint8_t data)
{
  if (g_print_mmio || (g_curr_module & g_enable_module))
      print(ACS_PRINT_INFO, " pal_mmio_write8 Address = %llx  Data = %lx ", addr, data);

  *(volatile uint8_t *)addr = data;
}

/**
  @brief  Provides a single point of abstraction to write to all
          Memory Mapped IO address

  @param  addr  64-bit address
  @param  data  16-bit data to write to address

  @return None
**/
void
pal_mmio_write16(uint64_t addr, uint16_t data)
{
  if (g_print_mmio || (g_curr_module & g_enable_module))
      print(ACS_PRINT_INFO, " pal_mmio_write16 Address = %llx  Data = %lx ", addr, data);

  *(volatile uint16_t *)addr = data;
}

/**
  @brief  Provides a single point of abstraction to write to all
          Memory Mapped IO address

  @param  addr  64-bit address
  @param  data  64-bit data to write to address

  @return None
**/
void
pal_mmio_write64(uint64_t addr, uint64_t data)
{
  if (g_print_mmio || (g_curr_module & g_enable_module))
      print(ACS_PRINT_INFO, " pal_mmio_write64 Address = %llx  Data = %llx ", addr, data);

  *(volatile uint64_t *)addr = data;
}

/**
  @brief  Provides a single point of abstraction to write to all
          Memory Mapped IO address

  @param  addr  64-bit address
  @param  data  32-bit data to write to address

  @return None
**/
void
pal_mmio_write(uint64_t addr, uint32_t data)
{

  if (addr & 0x3) {
      print(ACS_PRINT_WARN, "  Error-Input address is not aligned. Masking the last 2 bits ");
      addr = addr & ~(0x3);  //make sure addr is aligned to 4 bytes
  }

  if (g_print_mmio || (g_curr_module & g_enable_module))
      print(ACS_PRINT_INFO, " pal_mmio_write Address = %8x  Data = %x ", addr, data);

    *(volatile uint32_t *)addr = data;
}

/**
  @brief  Sends a string to the output console without using Baremetal print function
          This function will get COMM port address and directly writes to the addr char-by-char

  @param  string  An ASCII string
  @param  data    data for the formatted output

  @return None
**/
void
pal_print_raw(uint64_t addr, char *string, uint64_t data)
{
    uint8_t j, buffer[16];
    uint8_t  i=0;
    for(;*string!='\0';++string){
        if(*string == '%'){
            ++string;
            if(*string == 'd'){
                while(data != 0){
                    j = data%10;
                    data = data/10;
                    buffer[i]= j + 48 ;
                    i = i+1;
                }
            } else if(*string == 'x' || *string == 'X'){
                while(data != 0){
                    j = data & 0xf;
                    data = data >> 4;
                    buffer[i]= j + ((j > 9) ? 55 : 48) ;
                    i = i+1;
                }
            }
            if(i>0) {
                while(i!=0)
                    *(volatile uint8_t *)addr = buffer[--i];
            } else
                *(volatile uint8_t *)addr = 48;

        } else
            *(volatile uint8_t *)addr = *string;
    }
}

/**
  @brief  Free the memory allocated by UEFI Framework APIs
  @param  Buffer the base address of the memory range to be freed

  @return None
**/
void
pal_mem_free(void *Buffer)
{
#ifndef TARGET_BM_BOOT
  free(Buffer);
#else
  pal_mem_free_aligned(Buffer);
#endif
}

/**
  @brief  Retrieve the base address of the shared memory buffer used between PEs.

  @return Base address of the shared memory region.
**/
uint64_t
pal_mem_get_shared_addr()
{
  return (uint64_t)(gSharedMemory);
}

/**
  @brief  Free the shared memory region allocated above

  @param  None

  @return  None
**/
void
pal_mem_free_shared()
{
#ifndef TARGET_BM_BOOT
  free ((void *)gSharedMemory);
#else
  /* Shared region is a fixed reserved window; nothing to free in BM. */
  gSharedMemory = 0;
#endif
}

/**
  @brief  Allocates requested buffer size in bytes in a contiguous memory
          and returns the base address of the range.

  @param  Size         allocation size in bytes
  @retval if SUCCESS   pointer to allocated memory
  @retval if FAILURE   NULL
**/
void *
pal_mem_alloc(uint32_t Size)
{

#ifndef TARGET_BM_BOOT
  return malloc(Size);
#else
  uint32_t alignment = 0x08;
  return (void *)mem_alloc(alignment, Size);
#endif
}

/**
  @brief  Allocates requested buffer size in bytes with zeros in a contiguous memory
          and returns the base address of the range.

  @param  Size         allocation size in bytes
  @retval if SUCCESS   pointer to allocated memory
  @retval if FAILURE   NULL
**/
void *
pal_mem_calloc(uint32_t num, uint32_t Size)
{

#ifndef TARGET_BM_BOOT
  return calloc(num, Size);
#else
  void* ptr;
  uint32_t alignment = 0x08;

  ptr = mem_alloc(alignment, num * Size);

  if (ptr != NULL)
  {
    pal_mem_set(ptr, num * Size, 0);
  }
  return ptr;
#endif

}


/**
  @brief  Allocate memory which is to be used to share data across PEs

  @param  num_pe      - Number of PEs in the system
  @param  sizeofentry - Size of memory region allocated to each PE

  @return None
**/
void
pal_mem_allocate_shared(uint32_t num_pe, uint32_t sizeofentry)
{
   uint64_t size;
   uint64_t base;
   uint64_t aligned;

   gSharedMemory = 0;
#ifndef TARGET_BM_BOOT
   gSharedMemory = pal_mem_alloc(num_pe * sizeofentry);
   pal_pe_data_cache_ops_by_va((uint64_t)&gSharedMemory, CLEAN_AND_INVALIDATE);
#else
   /* Place shared data in the shared region so all PEs can access it. */
   size = (uint64_t)num_pe * (uint64_t)sizeofentry;
   base = (uint64_t)PLATFORM_SHARED_REGION_BASE;
   aligned = (base + 63u) & ~63u;
   if ((aligned + size) > ((uint64_t)PLATFORM_SHARED_REGION_BASE +
                           (uint64_t)PLATFORM_SHARED_REGION_SIZE)) {
     return;
   }
   gSharedMemory = (uint8_t *)aligned;
   pal_pe_data_cache_ops_by_va((uint64_t)&gSharedMemory, CLEAN_AND_INVALIDATE);
#endif
}

/**
  @brief  Allocates memory of the requested size.

  @param  Bdf:  BDF of the requesting PCIe device
  @param  Size: size of the memory region to be allocated
  @param  Pa:   physical address of the allocated memory
**/
void *
pal_mem_alloc_cacheable(uint32_t Bdf, uint32_t Size, void **Pa)
{
  #ifdef ENABLE_OOB
  /* Below code is not applicable for Bare-metal
   * Only for FVP OOB experience
   */

  EFI_PHYSICAL_ADDRESS      Address;
  EFI_CPU_ARCH_PROTOCOL     *Cpu;
  EFI_STATUS                Status;

  Status = gBS->AllocatePages (AllocateAnyPages,
                               EfiBootServicesData,
                               EFI_SIZE_TO_PAGES(Size),
                               &Address);
  if (EFI_ERROR(Status)) {
    print(ACS_PRINT_ERR, "Allocate Pool failed %x ", Status);
    return NULL;
  }

  /* Check Whether Cpu architectural protocol is installed */
  Status = gBS->LocateProtocol ( &gEfiCpuArchProtocolGuid, NULL, (VOID **)&Cpu);
  if (EFI_ERROR(Status)) {
    print(ACS_PRINT_ERR, "Could not get Cpu Arch Protocol %x ", Status);
    return NULL;
  }

  /* Set Memory Attributes */
  Status = Cpu->SetMemoryAttributes (Cpu,
                                     Address,
                                     Size,
                                     EFI_MEMORY_WB);
  if (EFI_ERROR (Status)) {
    print(ACS_PRINT_ERR, "Could not Set Memory Attribute %x ", Status);
    return NULL;
  }

  *Pa = (VOID *)Address;
  return (VOID *)Address;
#elif defined (TARGET_BM_BOOT)
  void *address;
  uint32_t alignment = 0x08;
  (void) Bdf;
  address = (void *)mem_alloc(alignment, Size);
  *Pa = (void *)address;
  return (void *)address;
#endif
  return 0;
}

/**
  @brief  Frees the memory allocated

  @param  Bdf:  BDF of the requesting PCIe device
  @param  Size: size of the memory region to be freed
  @param  Va:   virtual address of the memory to be freed
  @param  Pa:   physical address of the memory to be freed
**/
void
pal_mem_free_cacheable(uint32_t Bdf, uint32_t Size, void *Va, void *Pa)
{

#ifdef ENABLE_OOB
 /* Below code is not applicable for Bare-metal
  * Only for FVP OOB experience
  */

  gBS->FreePages((EFI_PHYSICAL_ADDRESS)(UINTN)Va, EFI_SIZE_TO_PAGES(Size));
#else
  (void) Bdf;
  (void) Size;
  (void) Va;
  (void) Pa;
#endif

}

/**
  @brief  Returns the physical address of the input virtual address.

  @param Va virtual address of the memory to be converted

  Returns the physical address.
**/
void *
pal_mem_virt_to_phys(void *Va)
{
  /* Place holder function. Need to be
   * implemented if needed in later releases
   */
  return Va;
}

/**
  @brief  Returns the virtual address of the input physical address.

  @param Pa physical address of the memory to be converted

  Returns the virtual address.
**/
void *
pal_mem_phys_to_virt (
  uint64_t Pa
  )
{
  /* Place holder function*/
  return (void*)Pa;
}

/**
  Stalls the CPU for the number of microseconds specified by MicroSeconds.

  @param  MicroSeconds  The minimum number of microseconds to delay.

  @return 1 - Success, 0 -Failure

**/
uint64_t
pal_time_delay_ms(uint64_t MicroSeconds)
{
  #ifdef ENABLE_OOB
  /* Below code is not applicable for Bare-metal
   * Only for FVP OOB experience
   */
  gBS->Stall(MicroSeconds);
  #endif
  (void) MicroSeconds;
  return 0;
}

/**
  @brief  page size being used in current translation regime.

  @return page size being used
**/
uint32_t
pal_mem_page_size()
{
  #ifdef ENABLE_OOB
   /* Below code is not applicable for Bare-metal
    * Only for FVP OOB experience
    */
   return EFI_PAGE_SIZE;
  #endif
   return PLATFORM_PAGE_SIZE;;
}

/**
  @brief  allocates contiguous numpages of size
          returned by pal_mem_page_size()

  @return Start address of base page
**/
void *
pal_mem_alloc_pages (uint32_t NumPages)
{
  #ifdef ENABLE_OOB
  EFI_STATUS Status;
  EFI_PHYSICAL_ADDRESS PageBase;

  Status = gBS->AllocatePages (AllocateAnyPages,
                               EfiBootServicesData,
                               NumPages,
                               &PageBase);
  if (EFI_ERROR(Status))
  {
    print(ACS_PRINT_ERR, " Allocate Pages failed %x ", Status);
    return NULL;
  }

  return (VOID*)(UINTN)PageBase;
#else
  return (void *)mem_alloc(MEM_ALIGN_4K, NumPages * PLATFORM_PAGE_SIZE);
#endif
}

/**
  @brief  frees continguous numpages starting from page
          at address PageBase

**/
void
pal_mem_free_pages(void *PageBase, uint32_t NumPages)
{
  #ifdef ENABLE_OOB
  /* Below code is not applicable for Bare-metal
   * Only for FVP OOB experience
   */

  gBS->FreePages((EFI_PHYSICAL_ADDRESS)(UINTN)PageBase, NumPages);
  #endif
  (void) PageBase;
  (void) NumPages;
}

/**
  @brief  Allocates memory with the given alignement.

  @param  Alignment   Specifies the alignment.
  @param  Size        Requested memory allocation size.

  @return Pointer to the allocated memory with requested alignment.
**/
void
*pal_aligned_alloc( uint32_t alignment, uint32_t size )
{
  #ifdef ENABLE_OOB
  VOID *Mem = NULL;
  VOID **Aligned_Ptr = NULL;

  /* Generate mask for the Alignment parameter*/
  UINT64 Mask = ~(UINT64)(alignment - 1);

  /* Allocate memory with extra bytes, so we can return an aligned address*/
  Mem = (VOID *)pal_mem_alloc(size + alignment);

  if( Mem == NULL)
    return 0;

  /* Add the alignment to allocated memory address and align it to target alignment*/
  Aligned_Ptr = (VOID **)(((UINT64) Mem + alignment - 1) & Mask);

  /* Using a double pointer to store the address of allocated
     memory location so that it can be used to free the memory later*/
  Aligned_Ptr[-1] = Mem;

  return Aligned_Ptr;
  #else
  return (void *)mem_alloc(alignment, size);
  #endif
}

/**
  @brief  Release memory previously returned by pal_aligned_alloc().

  @param  Buffer   Aligned pointer received from pal_aligned_alloc().
**/
void
pal_mem_free_aligned (void *Buffer)
{
#ifdef ENABLE_OOB
    free(((VOID **)Buffer)[-1]);
    return;
#else
    mem_free(Buffer);
    return;
#endif
}

/**
  @brief   Checks if System information is passed using Baremetal (BM)
           This api is also used to check if GIC/Interrupt Init ACS Code
           is used or not. In case of BM, ACS Code is used for INIT

  @param  None

  @return True/False
*/
uint32_t
pal_target_is_bm()
{
  return 1;
}

/**
  Copies a source buffer to a destination buffer, and returns the destination buffer.

  @param  DestinationBuffer   The pointer to the destination buffer of the memory copy.
  @param  SourceBuffer        The pointer to the source buffer of the memory copy.
  @param  Length              The number of bytes to copy from SourceBuffer to DestinationBuffer.

  @return DestinationBuffer.

**/
void *
pal_memcpy(void *DestinationBuffer, const void *SourceBuffer, uint32_t Length)
{

    uint32_t i;
    const char *s = (char *)SourceBuffer;
    char *d = (char *) DestinationBuffer;

    for(i = 0; i < Length; i++)
    {
        d[i] = s[i];
    }

    return d;
}

/**
  @brief  Compare two strings up to a maximum length.

  @param  str1  First string.
  @param  str2  Second string.
  @param  len   Maximum characters to compare.

  @return 0 when equal, non-zero difference otherwise.
**/
uint32_t pal_strncmp(const char8_t *str1, const char8_t *str2, uint32_t len)
{
    while ( len && *str1 && ( *str1 == *str2 ) )
    {
        ++str1;
        ++str2;
        --len;
    }
    if ( len == 0 )
    {
        return 0;
    }
    else
    {
        return ( *(unsigned char *)str1 - *(unsigned char *)str2 );
    }
}

/**
  @brief  Compare two memory buffers.

  @param  Src  Pointer to the first buffer.
  @param  Dest Pointer to the second buffer.
  @param  Len  Number of bytes to compare.

  @return 0 if buffers are identical, otherwise the signed difference.
**/
int32_t
pal_mem_compare(void *Src, void *Dest, uint32_t Len)
{
  if (Len != 0) {
    register const unsigned char *p1 = Dest, *p2 = Src;

    do {
      if (*p1++ != *p2++)
        return (*--p1 - *--p2);
    } while (--Len != 0);
  }
  return (0);
}

/**
  @brief  Fill a buffer with the requested byte value.

  @param  buf   Pointer to the buffer to fill.
  @param  size  Number of bytes to update.
  @param  value Byte value to store.
**/
void
pal_mem_set(void *buf, uint32_t size, uint8_t value)
{
    uintptr_t addr;
    uint8_t *ptr8;

    if (buf == NULL || size == 0)
        return;

    addr = (uintptr_t)buf;
    ptr8 = (uint8_t *)buf;

    // Align to 8 bytes
    while (size && (addr & (sizeof(uint64_t) - 1u)))
    {
        *ptr8++ = value;
        addr++;
        size--;
    }

    // Prepare 64-bit writes
    if (size >= sizeof(uint64_t)) {
        uint64_t *ptr64 = (uint64_t *)ptr8;

        if (value == 0) {
            while (size >= sizeof(uint64_t)) {
                *ptr64++ = 0;
                size -= sizeof(uint64_t);
            }
        } else {
            uint64_t pattern = value;
            pattern |= pattern << 8;
            pattern |= pattern << 16;
            pattern |= pattern << 32;

            while (size >= sizeof(uint64_t)) {
                *ptr64++ = pattern;
                size -= sizeof(uint64_t);
            }
        }

        ptr8 = (uint8_t *)ptr64;
    }

    // Remaining bytes
    while (size--)
    {
        *ptr8++ = value;
    }

    /* Ensure writes are observed before proceeding */
    __asm__ volatile ("dsb sy" ::: "memory");
}
/**
 @brief Writes the reset status on Non-Volatile memory.

 @param rme_nvm_mem Address of Non-Volatile memory
 @param status          Status to be saved on the memory.

 @return None
**/
void
pal_write_reset_status(
  uint64_t rme_nvm_mem,
  uint32_t status
  )
{
  *(uint32_t *)rme_nvm_mem = status;
}

/**
 @brief Reads the reset status from Non-Volatile memory.

 @param rme_nvm_mem Address of Non-Volatile memory
 @param status          Status to be saved on the memory.

 @return None
**/
uint32_t
pal_read_reset_status(
  uint64_t rme_nvm_mem
  )
{
  return (*(uint32_t *)rme_nvm_mem);
}

/**
  @brief Saves the test status, i.e., total tests, tests
         passed and tests failed before any system reset
         on Non-Volatile Memory.
  @param rme_nvm_mem Address for Non-Volatile memory
  @param rme_tests_total Total rme tests
  @param rme_tests_pass  Tests PASSED
  @param rme_tests_fail  Tests FAILED

  @return None
**/
void
pal_save_global_test_data(
  uint64_t rme_nvm_mem,
  uint32_t rme_tests_total,
  uint32_t rme_tests_pass,
  uint32_t rme_tests_fail
  )
{

  uint32_t *addr;

  addr = (uint32_t *)(rme_nvm_mem + 0x10);
  *addr = rme_tests_total;
  *(addr + 1) = rme_tests_pass;
  *(addr + 2) = rme_tests_fail;
}

/**
  @brief Restores the tests status i.e., total tests, tests
         passed and tests failed from Non-Volatile Memory
         after a system reset.
  @param rme_nvm_mem Address for Non-Volatile memory
  @param rme_tests_total Total rme tests
  @param rme_tests_pass  Tests PASSED
  @param rme_tests_fail  Tests FAILED

  @return None
**/
void
pal_restore_global_test_data(
  uint64_t rme_nvm_mem,
  uint32_t *rme_tests_total,
  uint32_t *rme_tests_pass,
  uint32_t *rme_tests_fail
  )
{
  uint32_t *addr;

  addr = (uint32_t *)(rme_nvm_mem + 0x10);
  *rme_tests_total = *addr;
  *rme_tests_pass = *(addr + 1);
  *rme_tests_fail = *(addr + 2);
}

/* Functions implemented below are used to allocate memory from heap. Baremetal implementation
   of memory allocation.
*/

/**
  @brief  Helper to check whether the supplied value is a power of two.

  @param  n  Value to test.

  @return 1 when n is a power of two, else 0.
**/
static int is_power_of_2(uint32_t n)
{
    return n && !(n & (n - 1));
}

/**
 * @brief Allocates contiguous memory with the requested size and alignment.
 * @param alignment - alignment for the address. It must be in power of 2.
 * @param Size - Size of the region. It must not be zero.
 * @return - Returns allocated memory base address if allocation is successful.
 *           Otherwise returns NULL.
 * @note   Limitations: no split/merge; free list search is linear.
 **/
void *heap_alloc(size_t alignment, size_t size)
{
    heap_free_node_t *node;
    heap_free_node_t *prev;
    uintptr_t raw;
    heap_hdr_t *hdr;
    size_t total;
    uintptr_t block_start;

    if (heap_init_done != 1)
        mem_alloc_init();

    if (alignment < sizeof(void *))
        alignment = sizeof(void *);

    if (size == 0)
        return NULL;

    if (!is_power_of_2((uint32_t)alignment))
        return NULL;

    /* Scan the free list for the first block that can fit this request. */
    prev = NULL;
    for (node = heap_free_list; node != NULL; node = node->next) {
        block_start = (uintptr_t)node;
        raw = (uintptr_t)ADDR_ALIGN(block_start + sizeof(heap_hdr_t),
                                    alignment);
        hdr = (heap_hdr_t *)(raw - sizeof(heap_hdr_t));
        /* Skip blocks where alignment would move the header. */
        if ((uintptr_t)hdr != block_start)
            continue;

        total = (size_t)(raw + size - block_start);
        /* Skip blocks that cannot fit the request. */
        if (total > node->size)
            continue;

        /* Remove the chosen block from the free list. */
        if (prev != NULL)
            prev->next = node->next;
        else
            heap_free_list = node->next;

        hdr->size = node->size;
        hdr->magic = HEAP_HDR_MAGIC;
        hdr->rsvd = 0;
        return (void *)raw;
    }

    /* No free block fit: allocate from the heap top. */
    raw = (uintptr_t)ADDR_ALIGN(heap_base + sizeof(heap_hdr_t), alignment);
    hdr = (heap_hdr_t *)(raw - sizeof(heap_hdr_t));
    total = (size_t)(raw + size - (uintptr_t)hdr);
    if (((uintptr_t)hdr + total) > heap_top)
        return NULL;

    hdr->size = total;
    hdr->magic = HEAP_HDR_MAGIC;
    hdr->rsvd = 0;
    heap_base = (uint64_t)((uintptr_t)hdr + total);
    return (void *)raw;
}

/**
 * @brief  Initialisation of allocation data structure
 * @param  void
 * @return Void
 **/
void mem_alloc_init(void)
{
    uintptr_t base;

    heap_base = PLATFORM_HEAP_REGION_BASE;
    heap_top = PLATFORM_HEAP_REGION_BASE + PLATFORM_HEAP_REGION_SIZE;
    heap_init_done = 1;

    base = (uintptr_t)ADDR_ALIGN(heap_base, sizeof(void *));
    if (base + sizeof(heap_hdr_t) + sizeof(void *) > heap_top) {
        heap_free_list = NULL;
        return;
    }
    heap_free_list = NULL;
}

/**
 * @brief Allocates contiguous memory of requested size(no_of_bytes) and alignment.
 * @param alignment - alignment for the address. It must be in power of 2.
 * @param Size - Size of the region. It must not be zero.
 * @return - Returns allocated memory base address if allocation is successful.
 *           Otherwise returns NULL.
 **/
void *mem_alloc(size_t alignment, size_t size)
{
  void *addr = NULL;

  if (heap_init_done != 1)
    mem_alloc_init();

  if (size == 0)
    return NULL;

  if (!is_power_of_2((uint32_t)alignment))
    return NULL;

  addr = heap_alloc(alignment, size);
  return addr;
}

/**
  @brief  Release a heap allocation.

  @param  ptr  Pointer returned by mem_alloc().

  @note   Validates header magic and pushes the block to the free list.
          Blocks are not merged.

**/
void mem_free(void *ptr)
{
  heap_hdr_t *hdr;
  heap_free_node_t *node;

  if (ptr == NULL)
    return;

  hdr = (heap_hdr_t *)((uint8_t *)ptr - sizeof(heap_hdr_t));
  if (hdr->magic != HEAP_HDR_MAGIC)
    return;

  node = (heap_free_node_t *)hdr;
  node->size = hdr->size;
  node->next = heap_free_list;
  heap_free_list = node;
}

/* The functions implemented below are to enable console prints via UART driver */

typedef int (*pal_emit_fn)(char ch, void *ctx);

typedef struct {
    pal_emit_fn emit;
    void *ctx;
} format_output;

struct snprintf_ctx {
    char *buf;
    size_t size;
    size_t length;
};

/**
  @brief  Emit a character to the platform UART.

  @param  ch   Character to transmit.
  @param  ctx  Unused context pointer.

  @return 0 on success.
**/
static int uart_emit_char(char ch, void *ctx)
{
    (void)ctx;
    (void)pal_uart_putc(ch);
    return 0;
}

/**
  @brief  Emit a character into an in-memory string buffer.

  @param  ch   Character to append.
  @param  ctx  Pointer to snprintf context state.

  @return 0 once the character is handled.
**/
static int buffer_emit_char(char ch, void *ctx)
{
    struct snprintf_ctx *out = (struct snprintf_ctx *)ctx;

    if ((out->size > 0U) && ((out->length + 1U) < out->size)) {
        out->buf[out->length++] = ch;
    }
    return 0;
}

/**
  @brief  Write a NUL-terminated string using the provided formatter.

  @param  out Formatter target.
  @param  str String to emit.

  @return Number of characters written or -1 on failure.
**/
static int format_string(format_output *out, const char *str)
{
    int count = 0;

    if (str == NULL) {
        str = "(null)";
    }

    while (*str != '\0') {
        if (out->emit(*str, out->ctx) != 0) {
            return -1;
        }
        str++;
        count++;
    }

    return count;
}

/**
  @brief  Format an unsigned integer in the requested radix.

  @param  out    Formatter target.
  @param  unum   Value to print.
  @param  radix  Base to use (>=2).
  @param  padc   Padding character (or '\0' for space).
  @param  padn   Minimum field width.

  @return Number of characters written or -1 on failure.
**/
static int format_unsigned(format_output *out, unsigned long long int unum,
                           unsigned int radix, char padc, int padn)
{
    char num_buf[20];
    int i = 0;
    int count = 0;
    unsigned int rem;

    if (radix < 2U) {
        return 0;
    }

    do {
        rem = (unsigned int)(unum % radix);
        if (rem < 0xaU) {
            num_buf[i] = (char)('0' + rem);
        } else {
            num_buf[i] = (char)('a' + (rem - 0xaU));
        }
        i++;
        unum /= radix;
    } while ((unum > 0U) && (i < (int)sizeof(num_buf)));

    while (i < padn) {
        char ch = (padc != '\0') ? padc : ' ';
        if (out->emit(ch, out->ctx) != 0) {
            return -1;
        }
        count++;
        padn--;
    }

    while (--i >= 0) {
        if (out->emit(num_buf[i], out->ctx) != 0) {
            return -1;
        }
        count++;
    }

    return count;
}

/**
  @brief  Core printf-style formatter shared by UART and buffer backends.

  @param  out    Formatter target.
  @param  fmt    Format string.
  @param  args   Argument list.
  @param  add_cr Automatically insert CR after LF when non-zero.

  @return Number of characters written or -1 on failure.
**/
static int format_engine(format_output *out, const char *fmt, va_list args, int add_cr)
{
    int count = 0;

    while (*fmt != '\0') {
        int l_count = 0;
        int padn = 0;
        char padc = '\0';

        if (*fmt == '%') {
            fmt++;
parse:
            switch (*fmt) {
            case '%':
                if (out->emit('%', out->ctx) != 0) {
                    return -1;
                }
                count++;
                break;
            case 'i':
            case 'd':
            {
                long long int num = get_num_va_args(args, l_count);
                unsigned long long int unum;

                if (num < 0) {
                    if (out->emit('-', out->ctx) != 0) {
                        return -1;
                    }
                    count++;
                    unum = (unsigned long long int)(-num);
                    padn--;
                } else {
                    unum = (unsigned long long int)num;
                }

                int printed = format_unsigned(out, unum, 10U, padc, padn);
                if (printed < 0) {
                    return -1;
                }
                count += printed;
                break;
            }
            case 's':
            {
                char *str = va_arg(args, char *);
                int printed = format_string(out, str);
                if (printed < 0) {
                    return -1;
                }
                count += printed;
                break;
            }
            case 'p':
            {
                unsigned long long int unum = (uintptr_t)va_arg(args, void *);
                if (unum > 0U) {
                    if ((out->emit('0', out->ctx) != 0) ||
                        (out->emit('x', out->ctx) != 0)) {
                        return -1;
                    }
                    count += 2;
                    padn -= 2;
                }

                int printed = format_unsigned(out, unum, 16U, padc, padn);
                if (printed < 0) {
                    return -1;
                }
                count += printed;
                break;
            }
            case 'x':
            {
                unsigned long long int unum = get_unum_va_args(args, l_count);
                int printed = format_unsigned(out, unum, 16U, padc, padn);
                if (printed < 0) {
                    return -1;
                }
                count += printed;
                break;
            }
            case 'z':
                if (sizeof(size_t) == 8U) {
                    l_count = 2;
                }
                fmt++;
                goto parse;
            case 'l':
                l_count++;
                fmt++;
                goto parse;
            case 'u':
            {
                unsigned long long int unum = get_unum_va_args(args, l_count);
                int printed = format_unsigned(out, unum, 10U, padc, padn);
                if (printed < 0) {
                    return -1;
                }
                count += printed;
                break;
            }
            case '0': case '1': case '2': case '3': case '4':
            case '5': case '6': case '7': case '8': case '9':
            {
                if ((*fmt == '0') && (padn == 0) && (padc == '\0')) {
                    padc = '0';
                }
                padn = 0;
                while ((*fmt >= '0') && (*fmt <= '9')) {
                    padn = (padn * 10) + (*fmt - '0');
                    fmt++;
                }
                goto parse;
            }
            default:
                return -1;
            }

            fmt++;
            continue;
        }

        if (out->emit(*fmt, out->ctx) != 0) {
            return -1;
        }
        count++;

        if (add_cr && (*fmt == '\n')) {
            (void)out->emit('\r', out->ctx);
        }

        fmt++;
    }

    return count;
}

/**
  @brief  Format and transmit a message via the platform UART.

  @param  fmt   Format string.
  @param  args  Argument list.

  @return Number of characters emitted, or negative on error.
**/
int vprintf(const char *fmt, va_list args)
{
    format_output out = { uart_emit_char, NULL };
    va_list args_copy;
    int ret;

    va_copy(args_copy, args);
    ret = format_engine(&out, fmt, args_copy, 1);
    va_end(args_copy);

    return ret;
}

/*
 * Minimal printf shim for BM builds. Routes to PAL's vprintf which ultimately
 * emits over UART. Kept in pal_misc.c alongside the UART/vprintf plumbing for
 * easier maintenance and single-point removal when debugging is complete.
 */
int printf(const char *fmt, ...)
{
    va_list args;
    int ret;

    va_start(args, fmt);
    ret = vprintf(fmt, args);
    va_end(args);
    return ret;
}

/* newlib's assert calls this symbol. Provide a minimal handler that prints and halts. */
void __assert_func(const char *file, int line, const char *func, const char *failedexpr)
{
    (void)func;
    printf("ASSERT: %s:%d: %s\n",
           (file != NULL) ? file : "?",
           line,
           (failedexpr != NULL) ? failedexpr : "");
    /* Spin to allow debugger/console capture. */
    while (1) {
        /* no-op */
    }
}

/**
  @brief  Format text into a caller-provided buffer using a varargs list.

  @param  str   Destination buffer.
  @param  size  Buffer capacity in bytes.
  @param  fmt   Format string.
  @param  args  Argument list.

  @return Number of characters that would have been written (excluding terminator).
**/
int vsnprintf(char *str, size_t size, const char *fmt, va_list args)
{
    struct snprintf_ctx ctx = { str, size, 0 };
    format_output out = { buffer_emit_char, &ctx };
    va_list args_copy;
    int ret;

    va_copy(args_copy, args);
    ret = format_engine(&out, fmt, args_copy, 0);
    va_end(args_copy);

    if (ctx.size > 0U) {
        size_t term = (ctx.length < ctx.size) ? ctx.length : (ctx.size - 1U);
        ctx.buf[term] = '\0';
    }

    return ret;
}

/**
  @brief  snprintf front-end that wraps vsnprintf().

  @param  str   Destination buffer.
  @param  size  Buffer capacity in bytes.
  @param  fmt   Format string.
  @param  ...   Variable argument list.

  @return Number of characters that would have been written.
**/
int snprintf(char *str, size_t size, const char *fmt, ...)
{
    va_list args;
    int ret;

    va_start(args, fmt);
    ret = vsnprintf(str, size, fmt, args);
    va_end(args);

    return ret;
}

static const char *prefix_str[] = {
        "", "", "", "", ""};

/**
  @brief  Retrieve the log prefix string for a given verbosity level.

  @param  log_level  ACS logging level.

  @return NUL-terminated prefix string.
**/
const char *log_get_prefix(int log_level)
{
        int level;

        if (log_level > ACS_PRINT_ERR) {
                level = ACS_PRINT_ERR;
        } else if (log_level < ACS_PRINT_INFO) {
                level = ACS_PRINT_TEST;
        } else {
                level = log_level;
        }

        return prefix_str[level - 1];
}

/**
  @brief  Print a formatted message to the UART with level-specific prefixing.

  @param  log  ACS logging level.
  @param  fmt  Format string.
  @param  ...  Variable argument list.
**/
void pal_uart_print(int log, const char *fmt, ...)
{
        va_list args;
        const char *prefix_str;

        prefix_str = log_get_prefix(log);

        while (*prefix_str != '\0') {
                pal_uart_putc(*prefix_str);
                prefix_str++;
        }

        va_start(args, fmt);
        (void)vprintf(fmt, args);
        va_end(args);
        (void) log;
}

/**
  @brief  mbedTLS-compatible calloc shim backed by PAL allocators.

  @param  count  Number of elements.
  @param  size   Size of each element.

  @return Pointer to zeroed memory or NULL on failure/overflow.
**/
void *
pal_mbedtls_calloc(size_t count, size_t size)
{
  uint32_t total;
  void *ptr;

  if ((count == 0u) || (size == 0u))
    return NULL;

  /* Basic overflow check. */
  if (size != 0u && (count > (UINT32_MAX / size)))
    return NULL;

  total = (uint32_t)(count * size);

  ptr = pal_mem_alloc(total);
  if (ptr != NULL)
    pal_mem_set(ptr, total, 0);
  return ptr;
}

/**
  @brief  Sends a formatted string to the output console

  @param  string  An ASCII string
  @param  data    data for the formatted output

  @return None
**/
void
pal_print(char8_t *string, ...)
{
  va_list args;

  va_start(args, string);
  pal_platform_print(string, args);
  va_end(args);
}
