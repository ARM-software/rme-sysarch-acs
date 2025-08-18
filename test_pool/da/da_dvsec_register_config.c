/** @file
 * Copyright (c) 2024-2025, Arm Limited or its affiliates. All rights reserved.
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
#include "val/include/val_interface.h"

#include "da_dvsec_register_config.h"

#define TEST_NAME "da_dvsec_register_config"
#define TEST_DESC "To check PCIe DVSEC Register configuration             "
#define TEST_RULE "RDVJRV"

static
void
payload(void)
{

  uint32_t pe_index;
  uint32_t ret;
  uint32_t table_entries;

  pe_index = val_pe_get_index_mpid(val_pe_get_mpid());

  table_entries = sizeof(bf_info_table)/sizeof(bf_info_table[0]);
  ret = val_pcie_register_bitfields_check((void *)&bf_info_table, table_entries);

  if (ret)
      val_set_status(pe_index, "FAIL", 01);
  else
      val_set_status(pe_index, "PASS", 01);

}

uint32_t
da_dvsec_register_config_entry(void)
{

  uint32_t num_pe = 1;
  uint32_t status = ACS_STATUS_FAIL;  //default value

  status = val_initialize_test(TEST_NAME, TEST_DESC, num_pe, TEST_RULE);

  /* This check is when user is forcing us to skip this test */
  if (status != ACS_STATUS_SKIP)
      val_run_test_payload(num_pe, payload, 0);

  /* get the result from all PE and check for failure */
  status = val_check_for_error(num_pe);

  val_report_status(0, "END");

  return status;
}

