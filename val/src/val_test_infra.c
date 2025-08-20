/** @file
 * Copyright (c) 2022-2025, Arm Limited or its affiliates. All rights reserved.
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
#include "include/val_pe.h"
#include "include/val_common.h"
#include "include/val_interface.h"
#include "include/val_iovirt.h"
#include "include/val_mem_interface.h"
#include "include/val_el32.h"
#include "include/val_exerciser.h"
#include "include/val_smmu.h"
#include "include/val_pgt.h"

uint64_t free_mem_var_pa;
uint64_t free_mem_var_va;
uint64_t rme_nvm_mem;

struct_sh_data *shared_data;

/**
  @brief  This API calls PAL layer to print a formatted string
          to the output console.
          1. Caller       - Application layer
          2. Prerequisite - None.

  @param level   The print verbosity (1 to 5)
  @param string  Formatted ASCII string
  @param data    64-bit data. Set to 0 if no data is to be sent to console.
  @param file    File name from which the print was invoked (typically __FILE__)
  @param line    Line number from which the print was invoked (typically __LINE__)

  @return        None
 **/
void val_log_context(uint32_t level, char8_t *string, uint64_t data, const char *file, int line)
{
#ifndef TARGET_BM_BOOT
  if (level >= g_print_level)
  {
    if (level == ACS_PRINT_DEBUG)
    {
      if (g_print_in_test_context)
        pal_print("\n\t\tDBG : ", 0);
      else
        pal_print("\n\tDBG : ", 0);
    } else if (level == ACS_PRINT_ERR)
    {
      if (g_print_in_test_context)
        pal_print("\n\t\tERR : ", 0);
      else
        pal_print("\n\tERR : ", 0);
    } else if (level == ACS_PRINT_INFO)
    {
      if (g_print_in_test_context)
        pal_print("\n\t\tINFO: ", 0);
      else
        pal_print("\n\tINFO: ", 0);
    } else if (level == ACS_PRINT_WARN)
    {
      if (g_print_in_test_context)
        pal_print("\n\t\tWARN: ", 0);
      else
        pal_print("\n\tWARN: ", 0);
    } else if (level == ACS_PRINT_ALWAYS)
    {
      // Do not print prefix or newline
      pal_print(string, data);
      return;
    } else
    {
      if (g_print_test_check_id == 0)
        pal_print("  Check %d : ", ++g_print_test_check_id);
      else
        pal_print("\n  Check %d : ", ++g_print_test_check_id);
    }
    pal_print(string, data);
    /* Print file name and line number for ERR and WARN */
    if (level == ACS_PRINT_ERR || level == ACS_PRINT_WARN)
    {
      pal_print("[FILE: %a]", (uint64_t)file);
      pal_print("  [LINE: %d]", line);
    }
  }
#else
  if (level >= g_print_level) {
    if (level == ACS_PRINT_DEBUG)
    {
      if (g_print_in_test_context)
        pal_uart_print(level, "\n\t\tDBG: ", 0);
      else
        pal_uart_print(level, "\n\tDBG: ", 0);
    } else if (level == ACS_PRINT_ERR)
    {
      if (g_print_in_test_context)
        pal_uart_print(level, "\n\t\tERR: ", 0);
      else
        pal_uart_print(level, "\n\tERR: ", 0);
    } else if (level == ACS_PRINT_INFO)
    {
      if (g_print_in_test_context)
        pal_uart_print(level, "\n\t\tINFO: ", 0);
      else
        pal_uart_print(level, "\n\tINFO", 0);
    } else if (level == ACS_PRINT_WARN)
    {
      if (g_print_in_test_context)
        pal_uart_print(level, "\n\t\tWARN: ", 0);
      else
        pal_uart_print(level, "\n\tWARN: ", 0);
    } else if (level == ACS_PRINT_ALWAYS)
    {
      // Do not print prefix or newline
      pal_uart_print(level, string, data);
      return;
    } else
    {
      pal_uart_print(level, "\n  Check %d : ", ++g_print_test_check_id);
    }
    pal_uart_print(level, string, data);
    /* Print file name and line number for ERR and WARN */
    if (level == ACS_PRINT_ERR || level == ACS_PRINT_WARN)
    {
      pal_uart_print(level, "  [FILE: %a]", (uint64_t)file);
      pal_uart_print(level, "  [LINE: %d]", line);
    }
  }
#endif
}

/**
  @brief  This API calls PAL layer to print a string to the output console.
          1. Caller       - Application layer
          2. Prerequisite - None.

  @param uart_address address of uart to be used
  @param level   the print verbosity (1 to 5)
  @param string  formatted ASCII string
  @param data    64-bit data. set to 0 if no data is to sent to console.

  @return        None
 **/
void val_print_raw(uint64_t uart_address, uint32_t level, char8_t *string, uint64_t data)
{

  if (level >= g_print_level)
    pal_print_raw(uart_address, string, data);
}

/**
  @brief  This API calls PAL layer to read from a Memory address
          and return 8-bit data.
          1. Caller       - Test Suite
          2. Prerequisite - None.

  @param addr   64-bit address

  @return       8-bits of data
 **/
uint8_t val_mmio_read8(addr_t addr)
{
  return pal_mmio_read8(addr);
}

/**
  @brief  This API calls PAL layer to read from a Memory address
          and return 16-bit data.
          1. Caller       - Test Suite
          2. Prerequisite - None.

  @param addr   64-bit address

  @return       16-bits of data
 **/
uint16_t val_mmio_read16(addr_t addr)
{
  return pal_mmio_read16(addr);
}

/**
  @brief  This API calls PAL layer to read from a Memory address
          and return 32-bit data.
          1. Caller       - Test Suite
          2. Prerequisite - None.

  @param addr   64-bit address

  @return       32-bits of data
 **/
uint32_t val_mmio_read(addr_t addr)
{
  return pal_mmio_read(addr);
}

/**
  @brief  This API calls PAL layer to read from a Memory address
          and return 64-bit data.
          1. Caller       - Test Suite
          2. Prerequisite - None.

  @param addr   64-bit address

  @return       64-bits of data
 **/
uint64_t val_mmio_read64(addr_t addr)
{
  return pal_mmio_read64(addr);
}

/**
  @brief  This function will call PAL layer to write 8-bit data to
          a Memory address.
        1. Caller       - Test Suite
        2. Prerequisite - None.

  @param addr   64-bit address
  @param data   8-bit data

  @return       None
 **/
void val_mmio_write8(addr_t addr, uint8_t data)
{

  pal_mmio_write8(addr, data);
}

/**
  @brief  This function will call PAL layer to write 16-bit data to
          a Memory address.
        1. Caller       - Test Suite
        2. Prerequisite - None.

  @param addr   64-bit address
  @param data   16-bit data

  @return       None
 **/
void val_mmio_write16(addr_t addr, uint16_t data)
{

  pal_mmio_write16(addr, data);
}

/**
  @brief  This function will call PAL layer to write 32-bit data to
          a Memory address.
        1. Caller       - Test Suite
        2. Prerequisite - None.

  @param addr   64-bit address
  @param data   32-bit data

  @return       None
 **/
void val_mmio_write(addr_t addr, uint32_t data)
{

  pal_mmio_write(addr, data);
}
/**
  @brief  This function will call PAL layer to write 64-bit data to
          a Memory address.
        1. Caller       - Test Suite
        2. Prerequisite - None.

  @param addr   64-bit address
  @param data   64-bit data

  @return       None
 **/
void val_mmio_write64(addr_t addr, uint64_t data)
{

  pal_mmio_write64(addr, data);
}

void print_suite_from_testname(char8_t *testname)
{
  char8_t suite[32];
  uint32_t i = 0;

  // Extract characters until first '_' or end of string
  while (testname[i] != '_' && testname[i] != '\0' && i < sizeof(suite) - 1)
  {
    suite[i] = testname[i];
    i++;
  }
  suite[i] = '\0'; // Null-terminate the suite name

  val_print(ACS_PRINT_ALWAYS, "Suite: ", 0), val_print(ACS_PRINT_ALWAYS, suite, 0);
}

/**
  @brief  This API checks if all the tests in the current module needs to be skipped.
          Skip if no tests are to be executed with user override options.
          1. Caller       - Test suite
          2. Prerequisite - None.

  @param module_id Name of the module

  @return         ACS_STATUS_SKIP - if the user override has no tests to run in the current module
                  ACS_STATUS_PASS - if tests are to be run in the current module
 **/
uint32_t val_check_skip_module(char8_t *module_id)
{
  uint32_t i, dont_skip = 0;

  /* Case 1 - Don't skip the module if the module number is mentioned in -m option parameters */
  for (i = 0; i < g_num_modules; i++)
  {
    if (val_memory_compare(g_execute_modules_str[i], module_id,
                           val_strnlen(g_execute_modules_str[i]))
        == 0)
      dont_skip++;
  }

  /* Case 2 - Don't skip the module if any of module's tests are in -t option parameters  */
  for (i = 0; i < g_num_tests; i++)
  {
    if (val_memory_compare(module_id, g_execute_tests_str[i], val_strnlen(module_id)) == 0)
    {
      dont_skip++;
    }
  }

  /* Skip the module if neither of above 2 cases are true */
  if ((!dont_skip) && (g_num_tests || g_num_modules))
  {
    return ACS_STATUS_SKIP;
  }

  return ACS_STATUS_PASS;
}

/**
  @brief  This API prints the test name, description and
          sets the test status to pending for the input number of PEs.
          1. Caller       - Application layer
          2. Prerequisite - val_allocate_shared_mem

  @param testname pointer to the test name string
  @param desc     brief description of the test
  @param num_pe   the number of PE to execute this test on.
  @param ruleid   Pointer to the TEST_RULE string.
  @return         Skip - if the user has overridden to skip the test.
 **/
uint32_t val_initialize_test(char8_t *testname, char8_t *desc, uint32_t num_pe, char8_t *ruleid)
{
  uint32_t i;
  uint32_t index     = val_pe_get_index_mpid(val_pe_get_mpid());
  uint32_t dont_skip = 0;

  g_print_in_test_context = 1;
  val_print(ACS_PRINT_ALWAYS, "\n", 0);
  print_suite_from_testname(testname);
  val_print(ACS_PRINT_ALWAYS, ", Test: ", 0), val_print(ACS_PRINT_ALWAYS, testname, 0);
  val_print(ACS_PRINT_ALWAYS, "\nRule: ", 0), val_print(ACS_PRINT_ALWAYS, ruleid, 0);
  val_print(ACS_PRINT_ALWAYS, "\nDesc: ", 0), val_print(ACS_PRINT_ALWAYS, desc, 0);
  val_print(ACS_PRINT_ALWAYS, "\n", 0);
  val_pe_initialize_default_exception_handler(val_pe_default_esr);

  for (i = 0; i < num_pe; i++)
    val_set_status(i, "PENDING", 0);

  /* Skip the test if it one of the -skip option parameters */
  for (i = 0; i < g_num_skip; i++)
  {
    if (val_memory_compare(g_skip_test_str[i], testname, val_strnlen(g_skip_test_str[i])) == 0)
    {
      val_print(ACS_PRINT_ALWAYS, "\n USER OVERRIDE  - Skip Test        ", 0);
      val_set_status(index, "SKIP", 0);
      return ACS_STATUS_SKIP;
    }
  }

  /* Don't skip if the test belongs to one of the modules in -m option parameters */
  for (i = 0; i < g_num_modules; i++)
  {
    if (val_memory_compare(g_execute_modules_str[i], testname,
                           val_strnlen(g_execute_modules_str[i]))
        == 0)
      dont_skip++;
  }

  /* Don't skip if test_num is one of the -t option parameters */
  for (i = 0; i < g_num_tests; i++)
  {
    if (val_memory_compare(testname, g_execute_tests_str[i], val_strnlen(testname)) == 0)
    {
      dont_skip++;
    }
  }

  if ((!dont_skip) && (g_num_tests || g_num_modules))
  {
    val_set_status(index, "SKIP", 0);
    val_print(ACS_PRINT_ALWAYS, "\n USER OVERRIDE  - Skip Test        ", 0);
    return ACS_STATUS_SKIP;
  }

  dont_skip = 1;
  g_rme_tests_total++;

  return ACS_STATUS_PASS;
}

/**
  @brief  Allocate memory which is to be shared across PEs

  @param  None

  @result None
**/
void val_allocate_shared_mem(void)
{

  pal_mem_allocate_shared(val_pe_get_num(), sizeof(VAL_SHARED_MEM_t));
}

/**
  @brief  Free the memory which was allocated by allocate_shared_mem
        1. Caller       - Application Layer
        2. Prerequisite - val_allocate_shared_mem

  @param  None

  @result None
**/
void val_free_shared_mem(void)
{

  pal_mem_free_shared();
}

/**
  @brief  This function sets the address of the test entry and the test
          argument to the shared address space which is picked up by the
          secondary PE identified by index.
          1. Caller       - VAL
          2. Prerequisite - val_allocate_shared_mem

  @param index     the PE Index
  @param addr      Address of the test payload which needs to be executed by PE
  @param test_data 64-bit data to be passed as a parameter to test payload

  @return        None
 **/
void val_set_test_data(uint32_t index, uint64_t addr, uint64_t test_data)
{
  volatile VAL_SHARED_MEM_t *mem;

  if (index > val_pe_get_num())
  {
    val_print(ACS_PRINT_ERR, " Incorrect PE index = %d", index);
    return;
  }

  mem = (VAL_SHARED_MEM_t *)pal_mem_get_shared_addr();
  mem = mem + index;

  mem->data0 = addr;
  mem->data1 = test_data;

  val_data_cache_ops_by_va((addr_t)&mem->data0, CLEAN_AND_INVALIDATE);
  val_data_cache_ops_by_va((addr_t)&mem->data1, CLEAN_AND_INVALIDATE);
}

/**
  @brief  This API returns the optional data parameter between PEs
          to the output console.
          1. Caller       - Test Suite
          2. Prerequisite - val_set_test_data

  @param index   PE index whose data parameter has to be returned.

  @return    64-bit data
 **/

void val_get_test_data(uint32_t index, uint64_t *data0, uint64_t *data1)
{

  volatile VAL_SHARED_MEM_t *mem;

  if (index > val_pe_get_num())
  {
    val_print(ACS_PRINT_ERR, " Incorrect PE index = %d", index);
    return;
  }

  mem = (VAL_SHARED_MEM_t *)pal_mem_get_shared_addr();
  mem = mem + index;

  val_data_cache_ops_by_va((addr_t)&mem->data0, INVALIDATE);
  val_data_cache_ops_by_va((addr_t)&mem->data1, INVALIDATE);

  *data0 = mem->data0;
  *data1 = mem->data1;
}

/**
  @brief  This function will wait for all PEs to report their status
          or we timeout and set a failure for the PE which timed-out
          1. Caller       - Application layer
          2. Prerequisite - val_set_status

  @param num_pe    Number of PE who are executing this test
  @param timeout   integer value ob expiry the API will timeout and return

  @return        None
 **/

void val_wait_for_test_completion(uint32_t num_pe, uint32_t timeout)
{
  uint32_t i = 0, j = 0;

  // For single PE tests, there is no need to wait for the results
  if (num_pe == 1)
    return;

  while (--timeout)
  {
    j = 0;
    for (i = 0; i < num_pe; i++)
    {
      if (val_memory_compare(val_get_status(i), "PENDING", val_strnlen(val_get_status(i))) == 0)
        j = i + 1;
    }
    // If None of the PE have the status as Pending, return
    if (!j)
      return;
  }
  // We are here if we timed-out, set the last index PE as failed
  val_set_status(j - 1, "FAIL", 0xF);
}

/**
  @brief  This API Executes the payload function on secondary PEs
          1. Caller       - Application layer
          2. Prerequisite - val_pe_create_info_table

  @param num_pe     The number of PEs to run this test on
  @param payload    Function pointer of the test entry function
  @param test_input optional parameter for the test payload

  @return        None
 **/
void val_run_test_payload(uint32_t num_pe, void (*payload)(void), uint64_t test_input)
{
  uint32_t my_index = val_pe_get_index_mpid(val_pe_get_mpid());
  uint32_t i;

  payload(); // this is test run separately on present PE
  if (num_pe == 1)
    return;

  // Now run the test on all other PE
  for (i = 0; i < num_pe; i++)
  {
    if (i != my_index)
      val_execute_on_pe(i, payload, test_input);
  }

  val_wait_for_test_completion(num_pe, TIMEOUT_LARGE);
}

/**
  @brief  Checks and reports the status of a completed test
          1. Caller       - Test Suite
          2. Prerequisite - val_set_status

  @param num_pe     The number of PEs to query for status
  @return           ACS_STATUS_PASS if all PEs passed,
                    ACS_STATUS_FAIL if any PE failed,
                    ACS_STATUS_SKIP if all were skipped
 **/
uint32_t val_check_for_error(uint32_t num_pe)
{
  uint32_t i;
  char8_t *status     = 0;
  uint32_t error_flag = 0;
  uint32_t my_index   = val_pe_get_index_mpid(val_pe_get_mpid());

  /* this special case is needed when the Main PE is not the first entry
     of pe_info_table but num_pe is 1 for SOC tests */
  if (num_pe == 1)
  {
    status = val_get_status(my_index);
    val_report_status(my_index, status);
    if (val_memory_compare(status, "PASS", val_strnlen(status)) == 0)
    {
      g_rme_tests_pass++;
      return ACS_STATUS_PASS;
    }
    if (val_memory_compare(status, "SKIP", val_strnlen(status)) == 0)
      return ACS_STATUS_SKIP;

    g_rme_tests_fail++;
    return ACS_STATUS_FAIL;
  }

  for (i = 0; i < num_pe; i++)
  {
    status = val_get_status(i);
    if ((val_memory_compare(status, "FAIL", val_strnlen(status)) == 0)
        || (val_memory_compare(status, "SKIP", val_strnlen(status)) == 0))
    {
      val_report_status(i, status);
      error_flag += 1;
      break;
    }
  }

  if (!error_flag)
    val_report_status(my_index, status);

  if (val_memory_compare(status, "PASS", val_strnlen(status)) == 0)
  {
    g_rme_tests_pass++;
    return ACS_STATUS_PASS;
  }
  if (val_memory_compare(status, "SKIP", val_strnlen(status)) == 0)
    return ACS_STATUS_SKIP;

  g_rme_tests_fail++;
  return ACS_STATUS_FAIL;
}

/**
  @brief  Clean and Invalidate the Data cache line containing
          the input address tag
**/
void val_data_cache_ops_by_va(addr_t addr, uint32_t type)
{
  pal_pe_data_cache_ops_by_va(addr, type);
}

/**
  @brief  Update ELR based on the offset provided
**/
void val_pe_update_elr(void *context, uint64_t offset)
{
  pal_pe_update_elr(context, offset);
}

/**
  @brief  Get ESR from exception context
**/
uint64_t val_pe_get_esr(void *context)
{
  return pal_pe_get_esr(context);
}

/**
  @brief  Get ELR from exception context
**/
uint64_t val_pe_get_elr(void *context)
{
  return pal_pe_get_elr(context);
}

/**
  @brief  Get FAR from exception context
**/
uint64_t val_pe_get_far(void *context)
{
  return pal_pe_get_far(context);
}

/**
  @brief  Write to an address, meant for debugging purpose
**/
void val_debug_brk(uint32_t data)
{
  addr_t address    = 0x9000F000; // address = pal_get_debug_address();
  *(addr_t *)address = data;
}

/**
  @brief  Compares two strings

  @param  str1  The pointer to a Null-terminated ASCII string.
  @param  str2  The pointer to a Null-terminated ASCII string.
  @param  len   The maximum number of ASCII characters for compare.

  @return Zero if strings are identical, else non-zero value
**/
uint32_t val_strncmp(char8_t *str1, char8_t *str2, uint32_t len)
{
  return pal_strncmp(str1, str2, len);
}

/**
  Copies a source buffer to a destination buffer, and returns the destination buffer.

  @param  DestinationBuffer   The pointer to the destination buffer of the memory copy.
  @param  SourceBuffer        The pointer to the source buffer of the memory copy.
  @param  Length              The number of bytes to copy from SourceBuffer to DestinationBuffer.

  @return DestinationBuffer.

**/
void *val_memcpy(void *dst_buffer, void *src_buffer, uint32_t len)
{
  return pal_memcpy(dst_buffer, src_buffer, len);
}

/**
  Stalls the CPU for the number of microseconds specified by MicroSeconds.

  @param  MicroSeconds  The minimum number of microseconds to delay.

  @return The value of MicroSeconds inputted.

**/
uint64_t val_time_delay_ms(uint64_t timer_ms)
{
  return pal_time_delay_ms(timer_ms);
}

void val_write_reset_status(uint32_t status)
{
  pal_write_reset_status(rme_nvm_mem, status);
}

uint32_t val_read_reset_status(void)
{
  return pal_read_reset_status(rme_nvm_mem);
}

static int Aarch64VaIsMappedForWrite(const void *Va)
{
  uint64_t par;

  __asm__ volatile("at     s1e2w, %1\n"
                   "isb\n"
                   "mrs    %0, par_el1\n"
                   : "=r"(par) // <-- changed to write-only output
                   : "r"(Va)   // <-- input: address to check
                   : "memory");

  return ((par & 1ULL) == 0);
}

uint64_t val_get_free_pa(uint64_t size, uint64_t alignment)
{
  uint64_t mem_base;
  if (!Aarch64VaIsMappedForWrite((void *)free_mem_var_pa))
  {
    memory_region_descriptor_t mem_desc_array[2], *mem_desc;
    pgt_descriptor_t pgt_desc;
    uint64_t ttbr;

    val_print(ACS_PRINT_ERR, "The PA is not mapped for write", 0);

    /* Get translation attributes via TCR and translation table base via TTBR */
    if (val_pe_reg_read_tcr(0 /*for TTBR0*/, &pgt_desc.tcr))
    {
      val_print(ACS_PRINT_ERR, " TCR read failure", 0);
      return 1;
    }

    if (val_pe_reg_read_ttbr(0 /*for TTBR0*/, &ttbr))
    {
      val_print(ACS_PRINT_ERR, " TTBR0 read failure", 0);
      return 1;
    }

    val_memory_set(mem_desc_array, sizeof(mem_desc_array), 0);
    mem_desc = &mem_desc_array[0];

    pgt_desc.pgt_base = (ttbr & AARCH64_TTBR_ADDR_MASK);
    pgt_desc.mair     = val_pe_reg_read(MAIR_ELx);
    pgt_desc.stage    = PGT_STAGE1;

    pgt_desc.ias               = 48;
    pgt_desc.oas               = 48;
    mem_desc->virtual_address  = free_mem_var_pa;
    mem_desc->physical_address = free_mem_var_pa;
    mem_desc->length           = size;
    mem_desc->attributes |= (PGT_STAGE1_AP_RW);

    if (val_pgt_create(mem_desc, &pgt_desc))
    {
      val_print(ACS_PRINT_ERR, " Unable to create page table with given attributes", 0);
      return 1;
    }
  }

  if (!Aarch64VaIsMappedForWrite((void *)free_mem_var_pa))
  {
    val_print(ACS_PRINT_ERR, "The PA is still not mapped for write", 0);
    return 1;
  }
  mem_base = free_mem_var_pa & ~(alignment - 1);

  if (alignment < size)
    free_mem_var_pa = mem_base + size;
  else
    free_mem_var_pa = mem_base + alignment;

  val_print(ACS_PRINT_DEBUG, "The PA allocated = 0x%lx", mem_base);
  return mem_base;
}

uint64_t val_get_free_va(uint64_t size)
{
  uint64_t mem_base;

  if (!Aarch64VaIsMappedForWrite((void *)free_mem_var_va))
  {
    memory_region_descriptor_t mem_desc_array[2], *mem_desc;
    pgt_descriptor_t pgt_desc;
    uint64_t ttbr;

    val_print(ACS_PRINT_ERR, "The VA is not mapped for write", 0);

    /* Get translation attributes via TCR and translation table base via TTBR */
    if (val_pe_reg_read_tcr(0 /*for TTBR0*/, &pgt_desc.tcr))
    {
      val_print(ACS_PRINT_ERR, " TCR read failure", 0);
      return 1;
    }

    if (val_pe_reg_read_ttbr(0 /*for TTBR0*/, &ttbr))
    {
      val_print(ACS_PRINT_ERR, " TTBR0 read failure", 0);
      return 1;
    }

    val_memory_set(mem_desc_array, sizeof(mem_desc_array), 0);
    mem_desc = &mem_desc_array[0];

    pgt_desc.pgt_base = (ttbr & AARCH64_TTBR_ADDR_MASK);
    pgt_desc.mair     = val_pe_reg_read(MAIR_ELx);
    pgt_desc.stage    = PGT_STAGE1;

    pgt_desc.ias               = 48;
    pgt_desc.oas               = 48;
    mem_desc->virtual_address  = free_mem_var_va;
    mem_desc->physical_address = free_mem_var_va;
    mem_desc->length           = size;
    mem_desc->attributes |= (PGT_STAGE1_AP_RW);

    if (val_pgt_create(mem_desc, &pgt_desc))
    {
      val_print(ACS_PRINT_ERR, " Unable to create page table with given attributes", 0);
      return 1;
    }
  }
  if (!Aarch64VaIsMappedForWrite((void *)free_mem_var_va))
  {
    val_print(ACS_PRINT_ERR, "The VA is still not mapped for write", 0);
    return 1;
  }
  mem_base = free_mem_var_va;
  free_mem_var_va += size;
  // val_print(ACS_PRINT_DEBUG, "The VA allocated = 0x%lx\n", mem_base);
  return mem_base;
}

uint64_t val_get_min_tg(void)
{
  uint64_t val, tg;

  val = val_pe_reg_read(ID_AA64MMFR0_EL1);
  tg  = (val & RME_MIN_TG4_MASK) >> RME_MIN_TG4_SHIFT;
  if (tg == 0)
    return SIZE_4K;
  else
  {
    tg = (val & RME_MIN_TG16_MASK) >> RME_MIN_TG16_SHIFT;
    if (tg == 0)
      return SIZE_16K;
    else
      return SIZE_64K;
  }
}

void val_reg_update_shared_struct_msd(uint32_t reg_name, uint32_t reg_indx)
{
  shared_data->reg_info.reg_list[reg_indx].reg_name        = reg_name;
  shared_data->reg_info.reg_list[reg_indx].saved_reg_value = 0x0;
}

void val_save_global_test_data(void)
{

  pal_save_global_test_data(rme_nvm_mem, g_rme_tests_total, g_rme_tests_pass, g_rme_tests_fail);
}

void val_restore_global_test_data(void)
{

  pal_restore_global_test_data(rme_nvm_mem, &g_rme_tests_total, &g_rme_tests_pass,
                               &g_rme_tests_fail);
}

uint32_t val_configure_acs(void)
{
  uint64_t sp_val, smmu_root_page, smmu_base;
  uint64_t smmu_rlm_page0, smmu_rlm_page1;
  uint32_t num_smmus, attr;

  sp_val = AA64ReadSP_EL0();

  /* Base EL3 mapping attributes for subsequent mappings */
  attr = LOWER_ATTRS(PGT_ENTRY_ACCESS | SHAREABLE_ATTR(OUTER_SHAREABLE) | PGT_ENTRY_AP_RW);

  if (val_add_mmu_entry_el3(sp_val, sp_val, (attr | LOWER_ATTRS(PAS_ATTR(NONSECURE_PAS)))))
  {
    val_print(ACS_PRINT_ERR, " MMU mapping failed for SP address: 0x%llx", sp_val);
    return 1;
  }

  /* Map the SMMU root, NS and realm pages as ROOT PAS */
  smmu_base = val_iovirt_get_smmu_info(SMMU_CTRL_BASE, 0);
  {
    uint64_t s3_off = val_get_smmu_root_reg_offset();

    if (!s3_off)
      s3_off = shared_data->cfg_smmu_root_reg_offset;
    smmu_root_page = smmu_base + s3_off;
  }
  smmu_rlm_page0 = smmu_base + SMMU_R_PAGE_0_OFFSET;
  smmu_rlm_page1 = smmu_base + SMMU_R_PAGE_1_OFFSET;
  attr |= LOWER_ATTRS(GET_ATTR_INDEX(DEV_MEM_nGnRnE));
  if (val_add_mmu_entry_el3(smmu_base, smmu_base, attr | LOWER_ATTRS(PAS_ATTR(ROOT_PAS))))
  {
    val_print(ACS_PRINT_ERR, " MMU mapping failed for SMMU_BASE address: 0x%llx", smmu_base);
    return 1;
  }
  if (val_add_mmu_entry_el3(smmu_root_page, smmu_root_page, attr | LOWER_ATTRS(PAS_ATTR(ROOT_PAS))))
  {
    val_print(ACS_PRINT_ERR, " MMU mapping failed for SMMU_ROOT_BASE address: 0x%llx",
              smmu_root_page);
    return 1;
  }
  if (val_add_mmu_entry_el3(smmu_rlm_page0, smmu_rlm_page0, attr | LOWER_ATTRS(PAS_ATTR(ROOT_PAS))))
  {
    val_print(ACS_PRINT_ERR, " MMU mapping failed for SMMU_REALM0_BASE address: 0x%llx",
              smmu_rlm_page0);
    return 1;
  }
  if (val_add_mmu_entry_el3(smmu_rlm_page1, smmu_rlm_page1, attr | LOWER_ATTRS(PAS_ATTR(ROOT_PAS))))
  {
    val_print(ACS_PRINT_ERR, " MMU mapping failed for SMMU_REALM1_BASE address: 0x%llx",
              smmu_rlm_page1);
    return 1;
  }
  if (val_rme_install_handler_el3())
  {
    val_print(ACS_PRINT_ERR, " Failed to install the RME handler in EL3", 0);
    return 1;
  }

  /* Create the list of valid Pcie Device Functions, Exerciser table
   * and initialise smmu for the tests that require exerciser and smmu required
   **/
  if (val_pcie_create_device_bdf_table())
  {
    val_print(ACS_PRINT_WARN, " Create BDF Table Failed \n", 0);
    return ACS_STATUS_SKIP;
  }

  val_exerciser_create_info_table();
  val_smmu_init();

  num_smmus = val_iovirt_get_smmu_info(SMMU_NUM_CTRL, 0);

  /* Disable all SMMUs */
  for (uint32_t instance = 0; instance < num_smmus; ++instance)
    val_smmu_disable(instance);

  return 0;
}

uint32_t val_generate_stream_id(void)
{
  /* Starting from 1 */
  static uint32_t unique_stream_id = 1;

  /* Increment the unique Stream ID */
  unique_stream_id++;

  /* If the number exceeds 255, reset to 1 */
  if (unique_stream_id > 255)
  {
    unique_stream_id = 1;
  }

  return unique_stream_id;
}

void val_init_runtime_params(void)
{
  uint64_t shared_addr;
  uint64_t sva, spa;

  rme_nvm_mem = val_get_rme_acs_nvm_mem();

  /* First, request EL3 to publish its local configuration into shared_data & map the shared_addr */
  val_print(ACS_PRINT_DEBUG,
            " Requesting EL3 to map shared memory & publish its local configuration", 0);

  val_map_shared_mem_el3((uint64_t)&shared_addr);
  val_print(ACS_PRINT_DEBUG, " Shared memory address = 0x%lx\n", (uint64_t)shared_addr);
  shared_data = (struct_sh_data *)shared_addr;
  /* Prefer EL3-provided free memory hints; fall back to platform getters. */
  {
    sva = val_get_free_va_test();
    spa = val_get_free_pa_test();

    if ((!sva || !spa) && shared_data)
    {
      if (!sva)
        sva = shared_data->cfg_free_mem_start + 0x200000;
      if (!spa)
        spa = shared_data->cfg_free_mem_start + 0x300000;
    }

    free_mem_var_va = sva;
    free_mem_var_pa = spa;
  }
}
