/** @file
 * Copyright (c) 2025, Arm Limited or its affiliates. All rights reserved.
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
#include "val/include/val_interface.h"

#include "val/include/rme_acs_el32.h"
#include "val/include/rme_acs_pcie.h"
#include "val/include/rme_acs_memory.h"
#include "val/include/rme_acs_pcie_enumeration.h"
#include "val/include/rme_acs_exerciser.h"
#include "val/include/rme_acs_smmu.h"
#include "val/include/rme_acs_pe.h"
#include "val/include/rme_acs_pgt.h"
#include "val/include/rme_acs_iovirt.h"
#include "val/include/mem_interface.h"
#include "val/include/sys_config.h"
#include "val/include/rme_acs_da.h"

#define TEST_NUM  (ACS_RME_DA_TEST_NUM_BASE  +  16)
#define TEST_DESC  "Checking IDE-Tbit ==1 for outgoing Realm request        "
#define TEST_RULE  "RCFQBW, RGBVTS"

#define TEST_DATA  0xABCD

static
void
payload(void)
{
  uint32_t pe_index;
  pcie_device_bdf_table *bdf_tbl_ptr;
  static uint32_t tbl_index;
  uint32_t bdf, rp_bdf;
  uint32_t bar_base;
  uint32_t pgt_attr_el3;
  uint32_t data;
  uint64_t va;
  uint32_t test_fail = 0;
  uint32_t test_skip = 1;
  uint32_t stream_id;
  uint32_t count, dp_type, status;


  tbl_index = 0;
  pe_index = val_pe_get_index_mpid(val_pe_get_mpid());
  bdf_tbl_ptr = val_pcie_bdf_table_ptr();

  while (tbl_index < bdf_tbl_ptr->num_entries)
  {
      bdf = bdf_tbl_ptr->device[tbl_index++].bdf;
      dp_type = val_pcie_device_port_type(bdf);

      if (dp_type == EP)
      {
          /* Get the BAR of the Endpoint */
          val_pcie_get_mmio_bar(bdf, &bar_base);

          /* Skip this function if it doesn't have mmio BAR */
          if (!bar_base)
             continue;

          /* Get the RootPortfor the Endpoint */
          if (val_pcie_get_rootport(bdf, &rp_bdf))
             continue;

          /* Enable the TDISP_EN bit in the RME-DA DVSEC register */
          if (val_pcie_enable_tdisp(rp_bdf))
             continue;

          test_skip = 0;

          /* Map the Bar address to realm PAS */
          va = val_get_free_va(val_get_min_tg());
          pgt_attr_el3 = LOWER_ATTRS(PGT_ENTRY_ACCESS | SHAREABLE_ATTR(OUTER_SHAREABLE)
                          | GET_ATTR_INDEX(DEV_MEM_nGnRnE) | PGT_ENTRY_AP_RW | PAS_ATTR(REALM_PAS));
          val_add_mmu_entry_el3(va, bar_base, pgt_attr_el3);

          count = 1;
          stream_id = val_generate_stream_id();

          /* Establish IDE Stream between RootPort and Endpoint*/
          status = val_ide_establish_stream(bdf, count, stream_id,
                                         PCIE_CREATE_BDF_PACKED(bdf));
          if (status)
          {
              val_print(ACS_PRINT_ERR, "\n       Failed to establish stream for bdf: 0x%x", bdf);
              test_fail++;
              continue;
          }

          status = val_ide_establish_stream(rp_bdf, count, stream_id,
                                         PCIE_CREATE_BDF_PACKED(bdf));
          if (status)
          {
              val_print(ACS_PRINT_ERR, "\n       Failed to estab stream for RP bdf: 0x%x", rp_bdf);
              test_fail++;
              continue;
          }

          /* Transition the Endpoint to TDISP RUN state */
          if (val_device_lock(bdf))
          {
              val_print(ACS_PRINT_ERR, "\n       Failed to lock the device: 0x%lx", bdf);
              test_fail++;
              continue;
          }

          data = 0;

          /* Write and Read the data at Bar address from Root world */
          shared_data->num_access = 2;
          shared_data->shared_data_access[0].addr = va;
          shared_data->shared_data_access[0].access_type = WRITE_DATA;
          shared_data->shared_data_access[0].data = TEST_DATA;
          shared_data->shared_data_access[1].addr = va;
          shared_data->shared_data_access[1].access_type = READ_DATA;
          val_pe_access_mut_el3();
          data = shared_data->shared_data_access[0].data;

          /* The Request should be accepted by the RP */
          if (data != TEST_DATA)
          {
              val_print(ACS_PRINT_ERR, "\n      Request rejected by RP BDF: %x", bdf);
              test_fail++;
          }
      }
  }

  if (test_skip)
      val_set_status(pe_index, RESULT_SKIP(TEST_NUM, 01));
  else if (test_fail)
      val_set_status(pe_index, RESULT_FAIL(TEST_NUM, test_fail));
  else
      val_set_status(pe_index, RESULT_PASS(TEST_NUM, 01));
}

uint32_t
da016_entry(void)
{

  uint32_t num_pe = 1;
  uint32_t status = ACS_STATUS_FAIL;  //default value

  status = val_initialize_test(TEST_NUM, TEST_DESC, num_pe, TEST_RULE);

  /* This check is when user is forcing us to skip this test */
  if (status != ACS_STATUS_SKIP)
      val_run_test_payload(TEST_NUM, num_pe, payload, 0);

  /* get the result from all PE and check for failure */
  status = val_check_for_error(TEST_NUM, num_pe, TEST_RULE);

  val_report_status(0, RME_ACS_END(TEST_NUM), TEST_RULE);

  return status;
}
