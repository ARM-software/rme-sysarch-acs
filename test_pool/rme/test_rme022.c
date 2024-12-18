/** @file
 * Copyright (c) 2023-2024, Arm Limited or its affiliates. All rights reserved.
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

#include "val/include/rme_test_entry.h"
#include "val/include/val_interface.h"
#include "val/include/rme_acs_el32.h"
#include "val/include/sys_config.h"
#include "val/include/mem_interface.h"

#define TEST_NUM   (ACS_RME_TEST_NUM_BASE  +  22)
#define TEST_DESC  "Check that the NS_Encryption is immutable once set     "
#define TEST_RULE  "PE_12"

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

  if (IS_NS_ENCRYPTION_PROGRAMMABLE == CLEAR) {
    val_print(ACS_PRINT_DEBUG, "\n  The test is Skipped as the NS_Enrypition is \
                    not programmable in this model", 0);
    val_set_status(index, RESULT_SKIP(TEST_NUM, 01));
    return;
  }

  size = val_get_min_tg();
  PA = val_get_free_pa(size, size);
  VA_NS = val_get_free_va(size);
  attr = LOWER_ATTRS(PGT_ENTRY_ACCESS | SHAREABLE_ATTR(NON_SHAREABLE) | PGT_ENTRY_AP_RW);

  //Map VA to PA as NS access pas in MMU
  val_add_mmu_entry_el3(VA_NS, PA, (attr | LOWER_ATTRS(PAS_ATTR(NONSECURE_PAS))));

  //Store the data in PA_NS
  wt_ns_data = RANDOM_DATA_1;
  shared_data->num_access = 2;
  shared_data->shared_data_access[0].addr = VA_NS;
  shared_data->shared_data_access[0].data = wt_ns_data;
  shared_data->shared_data_access[0].access_type = WRITE_DATA;

  shared_data->shared_data_access[1].addr = VA_NS;
  shared_data->shared_data_access[1].access_type = READ_DATA;

  val_pe_access_mut_el3();

  //CMO to PoPA for PA
  val_data_cache_ops_by_pa_el3(PA, NONSECURE_PAS);

  //Enable NS Encryption
  val_enable_ns_encryption();

  //CMO to PoPA for PA
  val_data_cache_ops_by_pa_el3(PA, NONSECURE_PAS);

  //Read VA_NS
  shared_data->num_access = 1;
  shared_data->shared_data_access[0].addr = VA_NS;
  shared_data->shared_data_access[0].access_type = READ_DATA;

  val_pe_access_mut_el3();
  rd_data_encrpt_enbl = shared_data->shared_data_access[0].data;

  //Disable NS Enryption
  val_disable_ns_encryption();

  //CMO to PoPA for PA
  val_data_cache_ops_by_pa_el3(PA, NONSECURE_PAS);

  //Read VA_NS
  shared_data->num_access = 1;
  shared_data->shared_data_access[0].addr = VA_NS;
  shared_data->shared_data_access[0].access_type = READ_DATA;

  val_pe_access_mut_el3();
  rd_data_encrpt_disbl = shared_data->shared_data_access[0].data;

  //If data read after enabling NSEncryption is expected to be
  //same as the one read after disbling it.
  val_print(ACS_PRINT_DEBUG, "\n  The data written on VA_NS = 0x%lx", wt_ns_data);
  val_print(ACS_PRINT_DEBUG,
                  "\n  The data read after enabling NS_Encryption = 0x%lx", rd_data_encrpt_enbl);
  val_print(ACS_PRINT_DEBUG,
                  "\n  The data read after disabling NS_Encryption = 0x%lx", rd_data_encrpt_disbl);
  val_print(ACS_PRINT_DEBUG, "\n  The test expectes both the read data to be the same", 0);
  if (wt_ns_data == rd_data_encrpt_enbl) {
    val_print(ACS_PRINT_ERR, "\n  The Encryption is not enabled", 0);
    val_set_status(index, RESULT_FAIL(TEST_NUM, 01));
  }

  if (rd_data_encrpt_enbl != rd_data_encrpt_disbl) {
    val_print(ACS_PRINT_ERR, "\n  Both the data read after enabling and \
                    disabling NS_Encryption are different", 0);
    val_set_status(index, RESULT_FAIL(TEST_NUM, 01));
  }
  else
    val_set_status(index, RESULT_PASS(TEST_NUM, 01));
  return;
}


uint32_t
rme022_entry(void)
{

  uint32_t num_pe = 1;
  uint32_t status = ACS_STATUS_FAIL;

  status = val_initialize_test(TEST_NUM, TEST_DESC, num_pe, TEST_RULE);

  if (status != ACS_STATUS_SKIP)
      val_run_test_payload(TEST_NUM, num_pe, payload, 0);

  status = val_check_for_error(TEST_NUM, num_pe, TEST_RULE);

  val_report_status(0, RME_ACS_END(TEST_NUM), TEST_RULE);

  return status;
}

