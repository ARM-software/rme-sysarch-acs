/** @file
 * Copyright (c) 2023-2024, 2025, Arm Limited or its affiliates. All rights reserved.
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

#include "val/include/rme_acs_val.h"
#include "val/include/rme_acs_pe.h"
#include "val/include/rme_acs_common.h"
#include "val/include/rme_acs_memory.h"
#include "val/include/rme_acs_pgt.h"
#include "val/include/rme_test_entry.h"
#include "val/include/val_interface.h"
#include "val/include/rme_acs_el32.h"
#include "val/include/mem_interface.h"

#define TEST_NAME  "rme_cmo_popa_for_cacheability_shareability"
#define TEST_DESC  "CMO to PoPA true for all cacheability and shareability "
#define TEST_RULE  "RFXQCD/RQBNJF"

/*
 *  @brief  The test validates that coherent interconnect supports CMO to PoPA.
 * 1. Mark PA as ALL_ACCESS and initialise it  with INIT_DATA
 * 2. VA_NS and VA_S are mapped to the PA with Non-Secure and Secure access PAS respectively
 *    as Non-Cacheable.
 * 3. Access VA_NS and VA_S returns rd_data_ns and rd_data_s respectively.
 * 4. Store wt_data_s in VA_S and then issue CMO to PoPA for PA with secure and non-secure PASs.
 * 5. Access VA_NS and expect a data, ns_data_popa, that is different from rd_data_ns.
 */
static
void payload(void)
{

  uint32_t index = val_pe_get_index_mpid(val_pe_get_mpid());
  uint64_t rd_data_s, rd_data_ns, wt_data_s, ns_data_popa, PA;
  uint64_t VA_S, VA_NS, size, attr_ns, attr_sec;
  memory_region_descriptor_t mem_desc_array[2], *mem_desc;
  pgt_descriptor_t pgt_desc;
  uint64_t ttbr;

  size = val_get_min_tg();
  PA = val_get_free_pa(size, size);
  VA_S = val_get_free_va(size);
  VA_NS = val_get_free_va(size);

  if (val_add_gpt_entry_el3(PA, GPT_ANY)) {
      val_print(ACS_PRINT_ERR, " Failed to add GPT entry for PA 0x%lx", PA);
      val_set_status(index, "FAIL", 01);
      return;
  }

  /* Get translation attributes via TCR and translation table base via TTBR */
    if (val_pe_reg_read_tcr(0 /*for TTBR0*/,
                            &pgt_desc.tcr)) {
      val_print(ACS_PRINT_ERR, " TCR read failure", 0);
      val_set_status(index, "FAIL", 02);
      return;
    }

  if (val_pe_reg_read_ttbr(0 /*for TTBR0*/,
                             &ttbr)) {
      val_print(ACS_PRINT_ERR, " TTBR0 read failure", 0);
      val_set_status(index, "FAIL", 03);
      return;
    }

  val_memory_set(mem_desc_array, sizeof(mem_desc_array), 0);
  mem_desc = &mem_desc_array[0];

  pgt_desc.pgt_base = (ttbr & AARCH64_TTBR_ADDR_MASK);
  pgt_desc.mair = val_pe_reg_read(MAIR_ELx);
  pgt_desc.stage = PGT_STAGE1;

  pgt_desc.ias = 48;
  pgt_desc.oas = 48;
  mem_desc->virtual_address = PA;
  mem_desc->physical_address = PA;
  mem_desc->length = size;
  mem_desc->attributes |= (PGT_STAGE1_AP_RW);

  if (val_pgt_create(mem_desc, &pgt_desc)) {
        val_print(ACS_PRINT_ERR,
                      " Unable to create page table with given attributes", 0);
      val_set_status(index, "FAIL", 04);
      return;
  }

  /*PA is initialized with the initial DATA*/
  val_print(ACS_PRINT_TEST, " Initializing PA 0x%lx of GPI_ANY with INIT_DATA", PA);
  *(uint64_t *)PA = (uint64_t) INIT_DATA;

  /* Map the PA with VA_Secure and VA_Non-Secure with Non-Cacheable attribute */
  attr_sec = LOWER_ATTRS(PGT_ENTRY_ACCESS | SHAREABLE_ATTR(OUTER_SHAREABLE)
                         | GET_ATTR_INDEX(NON_CACHEABLE) | PGT_ENTRY_AP_RW | PAS_ATTR(SECURE_PAS));
  attr_ns = LOWER_ATTRS(PGT_ENTRY_ACCESS  | SHAREABLE_ATTR(OUTER_SHAREABLE) | PGT_ENTRY_AP_RW
                        | GET_ATTR_INDEX(NON_CACHEABLE) | PAS_ATTR(NONSECURE_PAS));

  if (val_add_mmu_entry_el3(VA_S/* VA1 */, PA, attr_sec)) {
      val_print(ACS_PRINT_ERR, " Failed to add MMU entry for VA_S 0x%lx", VA_S);
      val_set_status(index, "FAIL", 05);
      return;
  }

  if (val_add_mmu_entry_el3(VA_NS/* VA2 */, PA, attr_ns)) {
      val_print(ACS_PRINT_ERR, " Failed to add MMU entry for VA_NS 0x%lx", VA_NS);
      val_set_status(index, "FAIL", 06);
      return;
  }

  /* Read VA1 and VA2 and Write Random data in VA1*/
  val_print(ACS_PRINT_TEST, " Accessing PA with Secure and NonSecure PAS", 0);
  wt_data_s = RANDOM_DATA_1;
  shared_data->num_access = 3;
  shared_data->shared_data_access[0].addr = VA_S;
  shared_data->shared_data_access[0].access_type = READ_DATA;

  shared_data->shared_data_access[1].addr = VA_NS;
  shared_data->shared_data_access[1].access_type = READ_DATA;

  shared_data->shared_data_access[2].addr = VA_S;
  shared_data->shared_data_access[2].data = wt_data_s;
  shared_data->shared_data_access[2].access_type = WRITE_DATA;

  if (val_pe_access_mut_el3()) {
      val_print(ACS_PRINT_ERR, " Failed to access VA_S and VA_NS", 0);
      val_set_status(index, "FAIL", 07);
      return;
  }
  rd_data_s = shared_data->shared_data_access[0].data;
  rd_data_ns = shared_data->shared_data_access[1].data;

  /* CMO to PoPA for PA1 at secure PAS */
  val_print(ACS_PRINT_TEST, " Issuing CMO to PoPA for PA 0x%lx at both the PASs", PA);
  if (val_data_cache_ops_by_pa_el3(PA, SECURE_PAS)) {
      val_print(ACS_PRINT_ERR, " Failed to issue CMO for PA 0x%lx", PA);
      val_set_status(index, "FAIL", 8);
      return;
  }

  /* CMO to PoPA for PA1 at non-secure PAS */
  if (val_data_cache_ops_by_pa_el3(PA, NONSECURE_PAS)) {
      val_print(ACS_PRINT_ERR, " Failed to issue CMO for PA 0x%lx", PA);
      val_set_status(index, "FAIL", 9);
      return;
  }

  /* Access the data stored in VA2 */
  val_print(ACS_PRINT_TEST, " Accessing PA from NS PAS after CMO to PoPA", 0);
  shared_data->num_access = 1;
  shared_data->shared_data_access[0].addr = VA_NS;
  shared_data->shared_data_access[0].access_type = READ_DATA;

  if (val_pe_access_mut_el3()) {
      val_print(ACS_PRINT_ERR, " Failed to access VA_NS = 0x%lx", VA_NS);
      val_set_status(index, "FAIL", 10);
      return;
  }
  ns_data_popa = shared_data->shared_data_access[0].data;

  val_print(ACS_PRINT_DEBUG, " Secure data before CMO to PoPA = 0x%lx", rd_data_s);
  val_print(ACS_PRINT_DEBUG, " Non-Secure data before CMO to PoPA = 0x%lx", rd_data_ns);
  val_print(ACS_PRINT_DEBUG, " Data stored in Secure VA before CMO to PoPA = 0x%lx", wt_data_s);
  val_print(ACS_PRINT_DEBUG, " Non-Secure data after CMO to PoPA = 0x%lx", ns_data_popa);
  val_print(ACS_PRINT_DEBUG, " The test expects all data to be unique", 0);

  //Compare the data and set the test result accordingly
  if (ns_data_popa != rd_data_ns && ns_data_popa != wt_data_s && ns_data_popa != rd_data_s)
      val_set_status(index, "PASS", 01);

  else
      val_set_status(index, "FAIL", 11);
  return;

}

uint32_t
rme_cmo_popa_for_cacheability_shareability_entry(void)
{
  uint32_t num_pe = 1;
  uint32_t status = ACS_STATUS_FAIL;

  status = val_initialize_test(TEST_NAME, TEST_DESC, num_pe, TEST_RULE);

  if (status != ACS_STATUS_SKIP)
      val_run_test_payload(num_pe, payload, 0);

  status = val_check_for_error(num_pe);

  val_report_status(0, "END");

  return status;
}
