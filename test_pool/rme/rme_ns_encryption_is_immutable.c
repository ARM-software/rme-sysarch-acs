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

#include "val/include/val.h"
#include "val/include/val_pe.h"
#include "val/include/val_common.h"

#include "val/include/val_test_entry.h"
#include "val/include/val_interface.h"
#include "val/include/val_memory.h"
#include "val/include/val_el32.h"
#include "val/include/val_mem_interface.h"

#define TEST_NAME  "rme_ns_encryption_is_immutable"
#define TEST_DESC  "Check that the NS_Encryption is immutable once set     "
#define TEST_RULE  "RVSMPS"

/*
 * @brief  The test validates that the NS_Encryption is immutabe once set
 * 1. Map VA to PA as Nonsecure access PAS in MMU.
 * 2. Store the data, wt_ns_data in PA.
 * 3. Issue CMO to PoPA for PA.
 * 4. Enable NS_Encryption and issue CMO to PoPA for PA again.
 * 5. Now read the data, 'rd_data_encrpt_enbl' from PA and observe it is different
 *    from wt_ns_data.
 * 6. Disable NS_Encryption and issue CMO to PoPA for PA again.
 * 7. Now read the data, 'rd_data_encrpt_disbl'.
 * 8. Set the test result to FAIL if both the data are different otherwise PASS.
 */
static
void payload(void)
{

  uint32_t index = val_pe_get_index_mpid(val_pe_get_mpid()), attr;
  uint64_t PA, VA_NS, size, wt_ns_data, rd_data_encrpt_enbl, rd_data_encrpt_disbl;

  if (!val_is_ns_encryption_programmable()) {
    val_print(ACS_PRINT_ERR, "  The test is Skipped as the NS_Enrypition is \
                    not programmable in this model", 0);
    val_set_status(index, "SKIP", 01);
    return;
  }

  size = val_get_min_tg();
  PA = val_get_free_pa(size, size);
  VA_NS = val_get_free_va(size);
  attr = LOWER_ATTRS(PGT_ENTRY_ACCESS | SHAREABLE_ATTR(NON_SHAREABLE) | PGT_ENTRY_AP_RW);

  //Map VA to PA as NS access pas in MMU
  if (val_add_mmu_entry_el3(VA_NS, PA, (attr | LOWER_ATTRS(PAS_ATTR(NONSECURE_PAS)))))
  {
      val_print(ACS_PRINT_ERR, " Failed to add MMU entry for VA_NS = 0x%llx", VA_NS);
      val_set_status(index, "FAIL", 01);
      return;
  }

  //Store the data in PA_NS
  val_print(ACS_PRINT_TEST, " Storing some data in PA_NS and Issuing CMO", 0);
  wt_ns_data = RANDOM_DATA_1;
  shared_data->num_access = 2;
  shared_data->shared_data_access[0].addr = VA_NS;
  shared_data->shared_data_access[0].data = wt_ns_data;
  shared_data->shared_data_access[0].access_type = WRITE_DATA;

  shared_data->shared_data_access[1].addr = VA_NS;
  shared_data->shared_data_access[1].access_type = READ_DATA;

  if (val_pe_access_mut_el3()) {
    val_print(ACS_PRINT_ERR, " Failed to access VA_NS = 0x%llx", VA_NS);
    val_set_status(index, "FAIL", 02);
    return;
  }

  //CMO to PoPA for PA
  if (val_data_cache_ops_by_pa_el3(PA, NONSECURE_PAS)) {
    val_print(ACS_PRINT_ERR, " Failed to issue CMO for PA = 0x%llx", PA);
    val_set_status(index, "FAIL", 03);
    return;
  }

  //Enable NS Encryption
  val_print(ACS_PRINT_TEST, " Enabling NS_Encryption and issuing CMO to PoPA for PA", 0);
  if (val_enable_ns_encryption()) {
    val_print(ACS_PRINT_ERR, " Failed to enable NS_Encryption", 0);
    val_set_status(index, "FAIL", 04);
    return;
  }

  //CMO to PoPA for PA
  if (val_data_cache_ops_by_pa_el3(PA, NONSECURE_PAS)) {
    val_print(ACS_PRINT_ERR, " Failed to issue CMO for PA = 0x%llx", PA);
    val_set_status(index, "FAIL", 05);
    return;
  }

  //Read VA_NS
  val_print(ACS_PRINT_TEST, " Reading PA_NS after enabling NS_Encryption", 0);
  shared_data->num_access = 1;
  shared_data->shared_data_access[0].addr = VA_NS;
  shared_data->shared_data_access[0].access_type = READ_DATA;

  if (val_pe_access_mut_el3())
  {
    val_print(ACS_PRINT_ERR, " Failed to access VA_NS = 0x%llx", VA_NS);
    val_set_status(index, "FAIL", 06);
    return;
  }
  rd_data_encrpt_enbl = shared_data->shared_data_access[0].data;

  //Disable NS Enryption
  val_print(ACS_PRINT_TEST, " Disabling NS_Encryption and issuing CMO to PoPA for PA", 0);
  if (val_disable_ns_encryption()) {
    val_print(ACS_PRINT_ERR, " Failed to disable NS_Encryption", 0);
    val_set_status(index, "FAIL", 07);
    return;
  }

  //CMO to PoPA for PA
  if (val_data_cache_ops_by_pa_el3(PA, NONSECURE_PAS)) {
    val_print(ACS_PRINT_ERR, " Failed to issue CMO for PA = 0x%llx", PA);
    val_set_status(index, "FAIL", 8);
    return;
  }

  //Read VA_NS
  val_print(ACS_PRINT_TEST, " Reading PA_NS after disabling NS_Encryption", 0);
  shared_data->num_access = 1;
  shared_data->shared_data_access[0].addr = VA_NS;
  shared_data->shared_data_access[0].access_type = READ_DATA;

  if (val_pe_access_mut_el3())
  {
    val_print(ACS_PRINT_ERR, " Failed to access VA_NS = 0x%llx", VA_NS);
    val_set_status(index, "FAIL", 9);
    return;
  }
  rd_data_encrpt_disbl = shared_data->shared_data_access[0].data;

  //If data read after enabling NSEncryption is expected to be
  //same as the one read after disbling it.
  val_print(ACS_PRINT_DEBUG, " The data written on VA_NS = 0x%lx", wt_ns_data);
  val_print(ACS_PRINT_DEBUG,
                  "  The data read after enabling NS_Encryption = 0x%lx", rd_data_encrpt_enbl);
  val_print(ACS_PRINT_DEBUG,
                  "  The data read after disabling NS_Encryption = 0x%lx", rd_data_encrpt_disbl);
  val_print(ACS_PRINT_DEBUG, " The test expectes both the read data to be the same", 0);
  if (wt_ns_data == rd_data_encrpt_enbl) {
    val_print(ACS_PRINT_ERR, " The Encryption is not enabled", 0);
    val_set_status(index, "FAIL", 10);
  }

  if (rd_data_encrpt_enbl != rd_data_encrpt_disbl) {
    val_print(ACS_PRINT_ERR, " Both the data read after enabling and \
                    disabling NS_Encryption are different", 0);
    val_set_status(index, "FAIL", 11);
  }
  else
    val_set_status(index, "PASS", 01);
  return;
}


uint32_t
rme_ns_encryption_is_immutable_entry(void)
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

