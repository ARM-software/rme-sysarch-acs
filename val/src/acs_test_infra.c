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

#include "include/rme_acs_val.h"
#include "include/rme_acs_pe.h"
#include "include/rme_acs_common.h"
#include "include/val_interface.h"
#include "include/rme_acs_iovirt.h"
#include "include/mem_interface.h"
#include "include/rme_acs_el32.h"
#include "include/rme_acs_exerciser.h"
#include "include/rme_acs_smmu.h"

uint64_t free_mem_var_pa = PLAT_FREE_PA_TEST;
uint64_t free_mem_var_va = PLAT_FREE_VA_TEST;
uint64_t rme_nvm_mem = PLAT_RME_ACS_NVM_MEM;

struct_sh_data *shared_data = (struct_sh_data *) PLAT_SHARED_ADDRESS;

/**
  @brief  This API calls PAL layer to print a formatted string
          to the output console.
          1. Caller       - Application layer
          2. Prerequisite - None.

  @param level   the print verbosity (1 to 5)
  @param string  formatted ASCII string
  @param data    64-bit data. set to 0 if no data is to sent to console.

  @return        None
 **/
void
val_print(uint32_t level, char8_t *string, uint64_t data)
{
#ifndef TARGET_BM_BOOT
  if (level >= g_print_level)
    pal_print(string, data);
#else
  if (level >= g_print_level) {
      pal_uart_print(level, string, data);
  }
#endif
}

void
val_print_test_end(uint32_t status, char8_t *string)
{
  val_print(ACS_PRINT_TEST, "\n      ", 0);

  if (status != ACS_STATUS_PASS) {
      val_print(ACS_PRINT_TEST, "One or more ", 0);
      val_print(ACS_PRINT_TEST, string, 0);
      val_print(ACS_PRINT_TEST, " tests failed or were skipped.", 0);
  } else {
      val_print(ACS_PRINT_TEST, "All ", 0);
      val_print(ACS_PRINT_TEST, string, 0);
      val_print(ACS_PRINT_TEST, " tests passed.", 0);
  }

  val_print(ACS_PRINT_TEST, "\n", 0);
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
void
val_print_raw(uint64_t uart_address, uint32_t level, char8_t *string,
                                                                uint64_t data)
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
uint8_t
val_mmio_read8(addr_t addr)
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
uint16_t
val_mmio_read16(addr_t addr)
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
uint32_t
val_mmio_read(addr_t addr)
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
uint64_t
val_mmio_read64(addr_t addr)
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
void
val_mmio_write8(addr_t addr, uint8_t data)
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
void
val_mmio_write16(addr_t addr, uint16_t data)
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
void
val_mmio_write(addr_t addr, uint32_t data)
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
void
val_mmio_write64(addr_t addr, uint64_t data)
{

  pal_mmio_write64(addr, data);
}

/**
  @brief  This API prints the test number, description and
          sets the test status to pending for the input number of PEs.
          1. Caller       - Application layer
          2. Prerequisite - val_allocate_shared_mem

  @param test_num unique number identifying this test
  @param desc     brief description of the test
  @param num_pe   the number of PE to execute this test on.
  @param ruleid   Pointer to the TEST_RULE string.
  @return         Skip - if the user has overridden to skip the test.
 **/
uint32_t
val_initialize_test(uint32_t test_num, char8_t *desc, uint32_t num_pe, char8_t *ruleid)
{
  uint32_t i;
  uint32_t index = val_pe_get_index_mpid(val_pe_get_mpid());

  val_print(ACS_PRINT_ERR, "%4d : ", test_num); //Always print this
  val_print(ACS_PRINT_TEST, desc, 0);
  val_report_status(0, RME_ACS_START(test_num), ruleid);
  val_pe_initialize_default_exception_handler(val_pe_default_esr);

  g_rme_tests_total++;

  for (i = 0; i < num_pe; i++)
      val_set_status(i, RESULT_PENDING(test_num));

  for (i = 0 ; i < MAX_TEST_SKIP_NUM ; i++) {
      if (g_skip_test_num[i] == test_num) {
          val_print(ACS_PRINT_TEST, "\n       USER OVERRIDE  - Skip Test        ", 0);
          val_set_status(index, RESULT_SKIP(test_num, 0));
          return ACS_STATUS_SKIP;
      }
  }

  if ((g_single_test != SINGLE_TEST_SENTINEL && test_num != g_single_test) &&
        (g_single_module == SINGLE_MODULE_SENTINEL ||
          (test_num - g_single_module >= 100 ||
           test_num - g_single_module <= 0))) {
    val_print(ACS_PRINT_TEST, "\n       USER OVERRIDE VIA SINGLE TEST - Skip Test        ", 0);
    val_set_status(index, RESULT_SKIP(test_num, 0));
    return ACS_STATUS_SKIP;
  }

  return ACS_STATUS_PASS;
}

/**
  @brief  Allocate memory which is to be shared across PEs

  @param  None

  @result None
**/
void
val_allocate_shared_mem()
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
void
val_free_shared_mem()
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
void
val_set_test_data(uint32_t index, uint64_t addr, uint64_t test_data)
{
  volatile VAL_SHARED_MEM_t *mem;

  if (index > val_pe_get_num())
  {
      val_print(ACS_PRINT_ERR, "\n Incorrect PE index = %d", index);
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

void
val_get_test_data(uint32_t index, uint64_t *data0, uint64_t *data1)
{

  volatile VAL_SHARED_MEM_t *mem;

  if (index > val_pe_get_num())
  {
      val_print(ACS_PRINT_ERR, "\n Incorrect PE index = %d", index);
      return;
  }

  mem = (VAL_SHARED_MEM_t *) pal_mem_get_shared_addr();
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

  @param test_num  Unique test number
  @param num_pe    Number of PE who are executing this test
  @param timeout   integer value ob expiry the API will timeout and return

  @return        None
 **/

void
val_wait_for_test_completion(uint32_t test_num, uint32_t num_pe, uint32_t timeout)
{

  uint32_t i = 0, j = 0;

  //For single PE tests, there is no need to wait for the results
  if (num_pe == 1)
      return;

  while (--timeout)
  {
      j = 0;
      for (i = 0; i < num_pe; i++)
      {
          if (IS_RESULT_PENDING(val_get_status(i)))
              j = i+1;
      }
      //If None of the PE have the status as Pending, return
      if (!j)
          return;
  }
  //We are here if we timed-out, set the last index PE as failed
  val_set_status(j-1, RESULT_FAIL(test_num, 0xF));
}

/**
  @brief  This API Executes the payload function on secondary PEs
          1. Caller       - Application layer
          2. Prerequisite - val_pe_create_info_table

  @param test_num   unique test number
  @param num_pe     The number of PEs to run this test on
  @param payload    Function pointer of the test entry function
  @param test_input optional parameter for the test payload

  @return        None
 **/
void
val_run_test_payload(uint32_t test_num, uint32_t num_pe, void (*payload)(void), uint64_t test_input)
{

  uint32_t my_index = val_pe_get_index_mpid(val_pe_get_mpid());
  uint32_t i;

  payload();  //this is test run separately on present PE
  if (num_pe == 1)
      return;

  //Now run the test on all other PE
  for (i = 0; i < num_pe; i++) {
      if (i != my_index)
          val_execute_on_pe(i, payload, test_input);
  }

  val_wait_for_test_completion(test_num, num_pe, TIMEOUT_LARGE);
}

/**
  @brief  Prints the status of the completed test
          1. Caller       - Test Suite
          2. Prerequisite - val_set_status

  @param test_num   unique test number
  @param num_pe     The number of PEs to query for status
  @oaram *ruleid    The pointer to TEST_RULE string.
  @return     Success or on failure - status of the last failed PE
 **/
uint32_t
val_check_for_error(uint32_t test_num, uint32_t num_pe, char8_t *ruleid)
{
  uint32_t i;
  uint32_t status = 0;
  uint32_t error_flag = 0;
  uint32_t my_index = val_pe_get_index_mpid(val_pe_get_mpid());
  (void) test_num;

  /* this special case is needed when the Main PE is not the first entry
     of pe_info_table but num_pe is 1 for SOC tests */
  if (num_pe == 1) {
      status = val_get_status(my_index);
      val_report_status(my_index, status, ruleid);
      if (IS_TEST_PASS(status)) {
          g_rme_tests_pass++;
          return ACS_STATUS_PASS;
      }
      if (IS_TEST_SKIP(status))
          return ACS_STATUS_SKIP;

      g_rme_tests_fail++;
      return ACS_STATUS_FAIL;
  }

  for (i = 0; i < num_pe; i++) {
      status = val_get_status(i);
      //val_print(ACS_PRINT_ERR, "Status %4x \n", status);
      if (IS_TEST_FAIL_SKIP(status)) {
          val_report_status(i, status, ruleid);
          error_flag += 1;
          break;
      }
  }

  if (!error_flag)
      val_report_status(my_index, status, ruleid);

  if (IS_TEST_PASS(status)) {
      g_rme_tests_pass++;
      return ACS_STATUS_PASS;
  }
  if (IS_TEST_SKIP(status))
      return ACS_STATUS_SKIP;

  g_rme_tests_fail++;
  return ACS_STATUS_FAIL;
}

/**
  @brief  Clean and Invalidate the Data cache line containing
          the input address tag
**/
void
val_data_cache_ops_by_va(addr_t addr, uint32_t type)
{
  pal_pe_data_cache_ops_by_va(addr, type);

}

/**
  @brief  Update ELR based on the offset provided
**/
void
val_pe_update_elr(void *context, uint64_t offset)
{
    pal_pe_update_elr(context, offset);
}

/**
  @brief  Get ESR from exception context
**/
uint64_t
val_pe_get_esr(void *context)
{
    return pal_pe_get_esr(context);
}

/**
  @brief  Get ELR from exception context
**/
uint64_t
val_pe_get_elr(void *context)
{
    return pal_pe_get_elr(context);
}

/**
  @brief  Get FAR from exception context
**/
uint64_t
val_pe_get_far(void *context)
{
    return pal_pe_get_far(context);
}

/**
  @brief  Write to an address, meant for debugging purpose
**/
void
val_debug_brk(uint32_t data)
{
   addr_t address = 0x9000F000; // address = pal_get_debug_address();
   *(addr_t *)address = data;
}

/**
  @brief  Compares two strings

  @param  str1  The pointer to a Null-terminated ASCII string.
  @param  str2  The pointer to a Null-terminated ASCII string.
  @param  len   The maximum number of ASCII characters for compare.

  @return Zero if strings are identical, else non-zero value
**/
uint32_t
val_strncmp(char8_t *str1, char8_t *str2, uint32_t len)
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
void*
val_memcpy(void *dst_buffer, void *src_buffer, uint32_t len)
{
  return pal_memcpy(dst_buffer, src_buffer, len);
}

/**
  Stalls the CPU for the number of microseconds specified by MicroSeconds.

  @param  MicroSeconds  The minimum number of microseconds to delay.

  @return The value of MicroSeconds inputted.

**/
uint64_t
val_time_delay_ms(uint64_t timer_ms)
{
  return pal_time_delay_ms(timer_ms);
}

void
val_write_reset_status(uint32_t status)
{
  pal_write_reset_status(rme_nvm_mem, status);
}

uint32_t
val_read_reset_status()
{
  return pal_read_reset_status(rme_nvm_mem);
}

uint64_t
val_get_free_pa(uint64_t size, uint64_t alignment)
{
  uint64_t mem_base;

  mem_base = free_mem_var_pa & ~(alignment - 1);

  if (alignment < size)
    free_mem_var_pa = mem_base + size;
  else
    free_mem_var_pa = mem_base + alignment;

  val_print(ACS_PRINT_DEBUG, "The PA allocated = 0x%lx\n", mem_base);
  return mem_base;
}

uint64_t
val_get_free_va(uint64_t size)
{
  uint64_t mem_base;

  mem_base = free_mem_var_va;
  free_mem_var_va += size;
  //val_print(ACS_PRINT_DEBUG, "The VA allocated = 0x%lx\n", mem_base);
  return mem_base;
}

uint64_t
val_get_min_tg()
{
  uint64_t val, tg;

  val = val_pe_reg_read(ID_AA64MMFR0_EL1);
  tg = (val & RME_MIN_TG4_MASK) >> RME_MIN_TG4_SHIFT;
  if (tg == 0)
      return SIZE_4K;
  else {
      tg = (val & RME_MIN_TG16_MASK) >> RME_MIN_TG16_SHIFT;
      if (tg == 0)
          return SIZE_16K;
      else
          return SIZE_64K;
  }
}

void
val_reg_update_shared_struct_msd(uint32_t reg_name, uint32_t reg_indx)
{
  shared_data->reg_info.reg_list[reg_indx].reg_name = reg_name;
  shared_data->reg_info.reg_list[reg_indx].saved_reg_value = 0x0;
}

void
val_save_global_test_data()
{

  pal_save_global_test_data(rme_nvm_mem, g_rme_tests_total,
                            g_rme_tests_pass, g_rme_tests_fail);
}

void
val_restore_global_test_data()
{

  pal_restore_global_test_data(rme_nvm_mem, &g_rme_tests_total,
                               &g_rme_tests_pass, &g_rme_tests_fail);
}

uint32_t val_configure_acs(void)
{
  uint64_t sp_val, smmu_root_page, smmu_base;
  uint64_t smmu_rlm_page0, smmu_rlm_page1;
  uint32_t num_smmus, attr;
  uint64_t shared_address;

  sp_val = AA64ReadSP_EL0();
  shared_address = PLAT_SHARED_ADDRESS;
  val_print(ACS_PRINT_INFO, "\n SHARED_ADDRESS = 0x%llx", shared_address);

  /* Map the SHARED_ADDRESS and the sp_el0 as NS in EL3 */
  attr = LOWER_ATTRS(PGT_ENTRY_ACCESS | SHAREABLE_ATTR(OUTER_SHAREABLE) | PGT_ENTRY_AP_RW);
  val_add_mmu_entry_el3(shared_address, shared_address,
                  (attr | LOWER_ATTRS(PAS_ATTR(NONSECURE_PAS))));
  val_add_mmu_entry_el3(sp_val, sp_val, (attr | LOWER_ATTRS(PAS_ATTR(NONSECURE_PAS))));

  /* Map the SMMU root, NS and realm pages as ROOT PAS */
  smmu_base = val_iovirt_get_smmu_info(SMMU_CTRL_BASE, 0);
  smmu_root_page = smmu_base + SMMUV3_ROOT_REG_OFFSET;
  smmu_rlm_page0 = smmu_base + SMMU_R_PAGE_0_OFFSET;
  smmu_rlm_page1 = smmu_base + SMMU_R_PAGE_1_OFFSET;
  attr |= LOWER_ATTRS(GET_ATTR_INDEX(DEV_MEM_nGnRnE));
  val_add_mmu_entry_el3(smmu_base, smmu_base, attr | LOWER_ATTRS(PAS_ATTR(ROOT_PAS)));
  val_add_mmu_entry_el3(smmu_root_page, smmu_root_page, attr | LOWER_ATTRS(PAS_ATTR(ROOT_PAS)));
  val_add_mmu_entry_el3(smmu_rlm_page0, smmu_rlm_page0, attr | LOWER_ATTRS(PAS_ATTR(ROOT_PAS)));
  val_add_mmu_entry_el3(smmu_rlm_page1, smmu_rlm_page1, attr | LOWER_ATTRS(PAS_ATTR(ROOT_PAS)));
  val_rme_install_handler_el3();

  /* Create the list of valid Pcie Device Functions, Exerciser table
   * and initialise smmu for the tests that require exerciser and smmu required
   **/
  if (val_pcie_create_device_bdf_table()) {
      val_print(ACS_PRINT_WARN, "\n     Create BDF Table Failed \n", 0);
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
