/** @file
 * Copyright (c) 2024-2025, Arm Limited or its affiliates. All rights reserved.
 * SPDX-License-Identifier : Apache-2.0

 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use
 * this file except in compliance with the License.
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
#include "val/include/val_interface.h"

#include "val/include/rme_acs_el32.h"
#include "val/include/rme_acs_pcie.h"
#include "val/include/rme_acs_memory.h"
#include "val/include/rme_acs_pcie_enumeration.h"
#include "val/include/rme_acs_exerciser.h"
#include "val/include/rme_acs_smmu.h"
#include "val/include/rme_acs_pe.h"

#define TEST_NAME "da_outgoing_request_with_ide_tbit"
#define TEST_DESC "Check outgoing request with IDE-Tbit = 1               "
#define TEST_RULE "RDVKPF"

static
void
payload(void)
{
  uint32_t pe_index;
  pcie_device_bdf_table *bdf_tbl_ptr;
  static uint32_t tbl_index;
  uint32_t bdf, dsf_bdf;
  uint32_t bar_base;
  uint32_t pgt_attr_el3;
  uint32_t data;
  uint64_t va;
  uint32_t test_fails = 0;
  uint32_t test_skip = 1;

  tbl_index = 0;
  pe_index = val_pe_get_index_mpid(val_pe_get_mpid());
  bdf_tbl_ptr = val_pcie_bdf_table_ptr();

  while (tbl_index < bdf_tbl_ptr->num_entries)
  {
      bdf = bdf_tbl_ptr->device[tbl_index++].bdf;

      /* If it is a RP, get the Endpoint BAR Base below it if it is available.
       * Otherwise use the RP's BAR address */
      if ((val_pcie_function_header_type(bdf) == TYPE1_HEADER) &&
           (!val_pcie_get_downstream_function(bdf, &dsf_bdf))) {
          val_pcie_get_mmio_bar(dsf_bdf, &bar_base);
      }
      else
          val_pcie_get_mmio_bar(bdf, &bar_base);

      /* Skip this function if it doesn't have mmio BAR */
      if (!bar_base)
         continue;

      /* Enable the TDISP_EN bit in the RME-DA DVSEC register */
      if (val_pcie_enable_tdisp(bdf))
         continue;

      test_skip = 0;

      /* Map the Bar address to Root PAS */
      va = val_get_free_va(val_get_min_tg());
      pgt_attr_el3 = LOWER_ATTRS(PGT_ENTRY_ACCESS | SHAREABLE_ATTR(OUTER_SHAREABLE)
                      | GET_ATTR_INDEX(DEV_MEM_nGnRnE) | PGT_ENTRY_AP_RW | PAS_ATTR(ROOT_PAS));
      val_add_mmu_entry_el3(va, bar_base, pgt_attr_el3);

      /* Read the data at Bar address from Root world */
      shared_data->num_access = 1;
      shared_data->shared_data_access[0].addr = va;
      shared_data->shared_data_access[0].access_type = READ_DATA;
      if (val_pe_access_mut_el3())
      {
            val_print(ACS_PRINT_ERR, " MUT Access failed for VA: 0x%llx", va);
            test_fails++;
      }
      data = shared_data->shared_data_access[0].data;

      /* Disable the TDISP */
      val_pcie_disable_tdisp(bdf);
      /* The Request should be rejected by the RP */
      if (data != PCIE_UNKNOWN_RESPONSE)
      {
          val_print(ACS_PRINT_ERR, " Request not rejected by RP BDF: %x", bdf);
          test_fails++;
      }
  }

  if (test_skip)
      val_set_status(pe_index, "SKIP", 01);
  else if (test_fails)
      val_set_status(pe_index, "FAIL", test_fails);
  else
      val_set_status(pe_index, "PASS", 01);
}

uint32_t
da_outgoing_request_with_ide_tbit_entry(void)
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
