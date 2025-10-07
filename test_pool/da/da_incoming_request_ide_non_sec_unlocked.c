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

#include "val/include/val.h"
#include "val/include/val_interface.h"

#include "val/include/val_el32.h"
#include "val/include/val_pcie.h"
#include "val/include/val_memory.h"
#include "val/include/val_pcie_enumeration.h"
#include "val/include/val_exerciser.h"
#include "val/include/val_smmu.h"
#include "val/include/val_pe.h"
#include "val/include/val_pgt.h"
#include "val/include/val_iovirt.h"
#include "val/include/val_mem_interface.h"
#include "val/include/val_da.h"

#define TEST_NAME "da_incoming_request_ide_non_sec_unlocked"
#define TEST_DESC  "RP reject incoming request if IDE is not secure & lock "
#define TEST_RULE  "RKZBHV, RZJJMZ"

#define TEST_DATA_NUM_PAGES 1
#define TEST_DATA 0xAB

static
void
payload(void)
{

  uint32_t pe_index;
  uint32_t instance, num_exercisers;
  uint32_t bdf, rp_bdf, da_cap_base;
  uint32_t dma_len, test_data_blk_size;
  void *dram_buf_in_virt, *dram_buf_in_virt2;
  uint32_t test_fail = 0, test_skip = 1;
  uint32_t page_size = val_memory_page_size();

  pe_index = val_pe_get_index_mpid(val_pe_get_mpid());

  test_data_blk_size = page_size * TEST_DATA_NUM_PAGES;
  dma_len = test_data_blk_size / 2;

  num_exercisers = val_exerciser_get_info(EXERCISER_NUM_CARDS);

  for (instance = 0; instance < num_exercisers; ++instance)
  {
      /* if init fail moves to next exerciser */
      if (val_exerciser_init(instance))
          continue;

      bdf = val_exerciser_get_bdf(instance);
      val_print(ACS_PRINT_TEST, " Exerciser BDF - 0x%x", bdf);

      /* Create a buffer of size TEST_DMA_SIZE in DRAM */
      dram_buf_in_virt = val_memory_alloc_pages(TEST_DATA_NUM_PAGES);

      /* Set the buffer to value 0 */
      val_memory_set(dram_buf_in_virt, dma_len, 0);
      dram_buf_in_virt2 = dram_buf_in_virt + dma_len;

      /* Initialise the input buffer with test data */
      val_memory_set(dram_buf_in_virt, dma_len, TEST_DATA);
      val_data_cache_ops_by_va((uint64_t)dram_buf_in_virt, CLEAN_AND_INVALIDATE);

      /* Get the RootPort for the Exerciser */
      if (val_pcie_get_rootport(bdf, &rp_bdf))
          continue;

      test_skip = 0;

      /* Check for DA Capability */
      if (val_pcie_find_da_capability(rp_bdf, &da_cap_base) != PCIE_SUCCESS)
      {
          val_print(ACS_PRINT_ERR,
                        " PCIe DA DVSEC capability not present,bdf 0x%x", bdf);
          test_fail++;
          continue;
      }

      /* Enable RMEDA_CTL1.TDISP_EN*/
      if (val_pcie_enable_tdisp(rp_bdf))
      {
          val_print(ACS_PRINT_ERR, " Unable to set tdisp_en for BDF: 0x%x", rp_bdf);
          test_fail++;
          continue;
      }

      /* Transition the device to TDISP RUN state without establishing a stream */
      if (val_device_lock(bdf))
      {
          val_print(ACS_PRINT_ERR, " Failed to lock the device: 0x%lx", bdf);
          test_fail++;
          continue;
      }

      /* Perform DMA using exerciser from source to target buffer */
      val_exerciser_set_param(DMA_ATTRIBUTES, (uint64_t)dram_buf_in_virt, dma_len, instance);
      if (val_exerciser_ops(START_DMA, EDMA_TO_DEVICE, instance))
      {
          val_print(ACS_PRINT_ERR, " DMA write failure to exerciser %4x", instance);
          test_fail++;
          continue;
      }

      val_exerciser_set_param(DMA_ATTRIBUTES, (uint64_t)dram_buf_in_virt2, dma_len, instance);
      if (val_exerciser_ops(START_DMA, EDMA_FROM_DEVICE, instance))
      {
          val_print(ACS_PRINT_ERR, " DMA write failure to exerciser %4x", instance);
          test_fail++;
          continue;
      }

      /* Check the src and dst buff values are not same indicating the request is rejected by RP */
      if (!(val_memory_compare(dram_buf_in_virt, dram_buf_in_virt2, dma_len)))
      {
          val_print(ACS_PRINT_ERR,
                    " Incoming rqst not rejected when Str is not sec & lck inst %4x", instance);
          test_fail++;
          continue;
      }

      val_memory_set(dram_buf_in_virt, dma_len * 2, 0);

      /* Return the buffer to the heap manager */
      val_memory_free_pages(dram_buf_in_virt, TEST_DATA_NUM_PAGES);
  }


  while (instance--)
  {
    bdf = val_exerciser_get_bdf(instance);
    if (val_pcie_get_rootport(bdf, &rp_bdf))
          continue;

    val_print(ACS_PRINT_DEBUG, " Disabling TDISP for RP: 0x%x", rp_bdf);
    val_pcie_disable_tdisp(rp_bdf);
    val_print(ACS_PRINT_DEBUG, " Putting the device into unlockes state for bdf: 0x%x", bdf);
    val_device_unlock(bdf);

  }

  if (test_skip)
      val_set_status(pe_index, "SKIP", 01);
  else if (test_fail)
      val_set_status(pe_index, "FAIL", 01);
  else
      val_set_status(pe_index, "PASS", 01);

  return;
}

uint32_t
da_incoming_request_ide_non_sec_unlocked_entry(void)
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
