/** @file:
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

#include <stdint.h>
#include <stdarg.h>
#include "include/pal_pcie_enum.h"
#include "include/pal_common_support.h"
#include "platform_image_def.h"
#include "pal_pl011_uart.h"

#define __ADDR_ALIGN_MASK(a, mask)    (((a) + (mask)) & ~(mask))
#define ADDR_ALIGN(a, b)              __ADDR_ALIGN_MASK(a, (typeof(a))(b) - 1)

void *mem_alloc(size_t alignment, size_t size);
void mem_free(void *ptr);

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
      print(ACS_PRINT_INFO, " pal_mmio_read8 Address = %llx  Data = %lx \n", addr, data);

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
      print(ACS_PRINT_INFO, " pal_mmio_read16 Address = %llx  Data = %lx \n", addr, data);

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
      print(ACS_PRINT_INFO, " pal_mmio_read64 Address = %llx  Data = %llx \n", addr, data);

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
      print(ACS_PRINT_INFO, " pal_mmio_read Address = %llx  Data = %x \n", addr, data);

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
      print(ACS_PRINT_INFO, " pal_mmio_write8 Address = %llx  Data = %lx \n", addr, data);

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
      print(ACS_PRINT_INFO, " pal_mmio_write16 Address = %llx  Data = %lx \n", addr, data);

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
      print(ACS_PRINT_INFO, " pal_mmio_write64 Address = %llx  Data = %llx \n", addr, data);

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
      print(ACS_PRINT_WARN, "\n  Error-Input address is not aligned. Masking the last 2 bits \n");
      addr = addr & ~(0x3);  //make sure addr is aligned to 4 bytes
  }

  if (g_print_mmio || (g_curr_module & g_enable_module))
      print(ACS_PRINT_INFO, " pal_mmio_write Address = %8x  Data = %x \n", addr, data);

    *(volatile uint32_t *)addr = data;
}

/**
  @brief  Sends a formatted string to the output console

  @param  string  An ASCII string
  @param  data    data for the formatted output

  @return None
**/
void
pal_print(char *string, uint64_t data)
{
  #ifdef ENABLE_OOB
  /* Below code is not applicable for Bare-metal
   * Only for FVP OOB experience
   */
    AsciiPrint(string, data);
  #endif
  (void) string;
  (void) data;
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
  pal_mem_free_aligned((void *)gSharedMemory);
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
   gSharedMemory = 0;
   gSharedMemory = pal_mem_alloc(num_pe * sizeofentry);
   pal_pe_data_cache_ops_by_va((uint64_t)&gSharedMemory, CLEAN_AND_INVALIDATE);
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
    print(ACS_PRINT_ERR, "Allocate Pool failed %x \n", Status);
    return NULL;
  }

  /* Check Whether Cpu architectural protocol is installed */
  Status = gBS->LocateProtocol ( &gEfiCpuArchProtocolGuid, NULL, (VOID **)&Cpu);
  if (EFI_ERROR(Status)) {
    print(ACS_PRINT_ERR, "Could not get Cpu Arch Protocol %x \n", Status);
    return NULL;
  }

  /* Set Memory Attributes */
  Status = Cpu->SetMemoryAttributes (Cpu,
                                     Address,
                                     Size,
                                     EFI_MEMORY_WB);
  if (EFI_ERROR (Status)) {
    print(ACS_PRINT_ERR, "Could not Set Memory Attribute %x \n", Status);
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
    print(ACS_PRINT_ERR, " Allocate Pages failed %x \n", Status);
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

void *pal_strncpy(void *DestinationStr, const void *SourceStr, uint32_t Length)
{
  const char *s = SourceStr;
  char *d = DestinationStr;

  if (d == NULL) {
      return NULL;
  }

  char* ptr = d;

  while (*s && Length--)
  {
      *d = *s;
      d++;
      s++;
  }
  *d = '\0';

  return ptr;
}

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

void
pal_mem_set(void *buf, uint32_t size, uint8_t value)
{
    unsigned char *ptr = buf;

    while (size--)
    {
        *ptr++ = (unsigned char)value;
    }

    return (void) buf;
}

/**
 @brief Writes the reset status on Non-Volatile memory.

 @param RME_ACS_NVM_MEM Address of Non-Volatile memory
 @param status          Status to be saved on the memory.

 @return None
**/
void
pal_write_reset_status(
  uint64_t RME_ACS_NVM_MEM,
  uint32_t status
  )
{
  *(uint32_t *)RME_ACS_NVM_MEM = status;
}

/**
 @brief Reads the reset status from Non-Volatile memory.

 @param RME_ACS_NVM_MEM Address of Non-Volatile memory
 @param status          Status to be saved on the memory.

 @return None
**/
uint32_t
pal_read_reset_status(
  uint64_t RME_ACS_NVM_MEM
  )
{
  return (*(uint32_t *)RME_ACS_NVM_MEM);
}

/**
  @brief Saves the test status, i.e., total tests, tests
         passed and tests failed before any system reset
         on Non-Volatile Memory.
  @param RME_ACS_NVM_MEM Address for Non-Volatile memory
  @param rme_tests_total Total rme tests
  @param rme_tests_pass  Tests PASSED
  @param rme_tests_fail  Tests FAILED

  @return None
**/
void
pal_save_global_test_data(
  uint64_t RME_ACS_NVM_MEM,
  uint32_t rme_tests_total,
  uint32_t rme_tests_pass,
  uint32_t rme_tests_fail
  )
{

  uint32_t *addr;

  addr = (uint32_t *)(RME_ACS_NVM_MEM + 0x10);
  *addr = rme_tests_total;
  *(addr + 1) = rme_tests_pass;
  *(addr + 2) = rme_tests_fail;
}

/**
  @brief Restores the tests status i.e., total tests, tests
         passed and tests failed from Non-Volatile Memory
         after a system reset.
  @param RME_ACS_NVM_MEM Address for Non-Volatile memory
  @param rme_tests_total Total rme tests
  @param rme_tests_pass  Tests PASSED
  @param rme_tests_fail  Tests FAILED

  @return None
**/
void
pal_restore_global_test_data(
  uint64_t RME_ACS_NVM_MEM,
  uint32_t *rme_tests_total,
  uint32_t *rme_tests_pass,
  uint32_t *rme_tests_fail
  )
{
  uint32_t *addr;

  addr = (uint32_t *)(RME_ACS_NVM_MEM + 0x10);
  *rme_tests_total = *addr;
  *rme_tests_pass = *(addr + 1);
  *rme_tests_fail = *(addr + 2);
}

/* Functions implemented below are used to allocate memory from heap. Baremetal implementation
   of memory allocation.
*/

static int is_power_of_2(uint32_t n)
{
    return n && !(n & (n - 1));
}

/**
 * @brief Allocates contiguous memory of requested size(no_of_bytes) and alignment.
 * @param alignment - alignment for the address. It must be in power of 2.
 * @param Size - Size of the region. It must not be zero.
 * @return - Returns allocated memory base address if allocation is successful.
 *           Otherwise returns NULL.
 **/
void *heap_alloc(size_t alignment, size_t size)
{
    uint64_t addr;

    addr = ADDR_ALIGN(heap_base, alignment);
    size += addr - heap_base;

    if ((heap_top - heap_base) < size)
    {
       return NULL;
    }

    heap_base += size;

    return (void *)addr;
}

/**
 * @brief  Initialisation of allocation data structure
 * @param  void
 * @return Void
 **/
void mem_alloc_init(void)
{
    heap_base = PLATFORM_HEAP_REGION_BASE;
    heap_top = PLATFORM_HEAP_REGION_BASE + PLATFORM_HEAP_REGION_SIZE;
    heap_init_done = 1;
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

  if(heap_init_done != 1)
    mem_alloc_init();

  if (size <= 0)
  {
    return NULL;
  }

  if (!is_power_of_2((uint32_t)alignment))
  {
    return NULL;
  }

  size += alignment - 1;
  addr = heap_alloc(alignment, size);

  return addr;
}

/**
 * TODO: Free the memory for given memory address
 * Currently acs code is initialisazing from base for every test,
 * the regions data structure is internal and below code only setting to zero
 * not actually freeing memory.
 * If require can revisit in future.
 **/
void mem_free(void *ptr)
{
  if (!ptr)
    return;

  return;
}

/* The functions implemented below are to enable console prints via UART driver */

static int string_print(const char *str)
{
    int count = 0;

    for ( ; *str != '\0'; str++) {
        (void)pal_uart_putc(*str);
        count++;
    }

    return count;
}

static int unsigned_num_print(unsigned long long int unum, unsigned int radix,
                  char padc, int padn)
{
    /* Just need enough space to store 64 bit decimal integer */
    char num_buf[20];
    int i = 0, count = 0;
    unsigned int rem;

    /* num_buf is only large enough for radix >= 10 */
    if (radix < 10) {
        return 0;
    }

    do {
        rem = unum % radix;
        if (rem < 0xa)
            num_buf[i] = '0' + rem;
        else
            num_buf[i] = 'a' + (rem - 0xa);
        i++;
        unum /= radix;
    } while (unum > 0U);

    if (padn > 0) {
        while (i < padn) {
            (void)pal_uart_putc(padc);
            count++;
            padn--;
        }
    }

    while (--i >= 0) {
        (void)pal_uart_putc(num_buf[i]);
        count++;
    }

    return count;
}

int vprintf(const char *fmt, va_list args)
{
    int l_count;
    long long int num;
    unsigned long long int unum;
    char *str;
    char padc = '\0'; /* Padding character */
    int padn;         /* Number of characters to pad */
    int count = 0;    /* Number of printed characters */

    while (*fmt != '\0') {
        l_count = 0;
        padn = 0;

        if (*fmt == '%') {
            fmt++;
            /* Check the format specifier */
loop:
            switch (*fmt) {
            case '%':
                (void)pal_uart_putc('%');
                break;
            case 'i': /* Fall through to next one */
            case 'd':
                num = get_num_va_args(args, l_count);
                if (num < 0) {
                    (void)pal_uart_putc('-');
                    unum = (unsigned long long int)-num;
                    padn--;
                } else
                    unum = (unsigned long long int)num;

                count += unsigned_num_print(unum, 10,
                                padc, padn);
                break;
            case 's':
                str = va_arg(args, char *);
                count += string_print(str);
                break;
            case 'p':
                unum = (uintptr_t)va_arg(args, void *);
                if (unum > 0U) {
                    count += string_print("0x");
                    padn -= 2;
                }

                count += unsigned_num_print(unum, 16,
                                padc, padn);
                break;
            case 'x':
                unum = get_unum_va_args(args, l_count);
                count += unsigned_num_print(unum, 16,
                                padc, padn);
                break;
            case 'z':
                if (sizeof(size_t) == 8U)
                    l_count = 2;

                fmt++;
                goto loop;
            case 'l':
                l_count++;
                fmt++;
                goto loop;
            case 'u':
                unum = get_unum_va_args(args, l_count);
                count += unsigned_num_print(unum, 10,
                                padc, padn);
                break;
            case '1':
            case '2':
            case '3':
            case '4':
            case '5':
            case '6':
            case '7':
            case '8':
            case '9':
            case '0':
                padc = '0';
                padn = 0;
                fmt++;

                for (;;) {
                    char ch = *fmt;
                    if ((ch < '0') || (ch > '9')) {
                        goto loop;
                    }
                    padn = (padn * 10) + (ch - '0');
                    fmt++;
                }

            default:
                /* Exit on any other format specifier */
                return -1;
            }

            fmt++;
            continue;
        }
        else
        {
            (void)pal_uart_putc(*fmt);
            if (*fmt == '\n')
            {
                (void)pal_uart_putc('\r');
            }
        }

        fmt++;
        count++;
    }

    return count;
}

static const char *prefix_str[] = {
        "", "", "", "", ""};

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
