/** @file
 * Copyright (c) 2024, Arm Limited or its affiliates. All rights reserved.
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

#define TEST_NUM (ACS_RME_DA_TEST_NUM_BASE  +  13)
#define TEST_DESC "RP rejects the request when RMEDA_CTL1.TDISP_EN==0     "
#define TEST_RULE "RRNQNM, RGKHSZ"

#define TEST_DATA_NUM_PAGES 1
#define TEST_DATA 0xAB


static
void
payload(void)
{

  uint32_t pe_index, pgt_attr_el3;
  uint32_t instance, num_exercisers;
  uint32_t e_bdf, rp_bdf, da_cap_base;
  uint32_t dma_len, test_data_blk_size;
  void *dram_buf_in_virt, *dram_buf_in_virt2;
  uint64_t Bar_Base;
  uint64_t rp_data, va;
  uint32_t test_fail = 0, test_skip = 1;
  uint32_t page_size = val_memory_page_size();
  uint32_t tbl_index;
  uint32_t dp_type;
  pcie_device_bdf_table *bdf_tbl_ptr;

  pe_index = val_pe_get_index_mpid(val_pe_get_mpid());

  test_data_blk_size = page_size * TEST_DATA_NUM_PAGES;
  dma_len = test_data_blk_size / 2;

  num_exercisers = val_exerciser_get_info(EXERCISER_NUM_CARDS, 0);

  for (instance = 0; instance < num_exercisers; ++instance)
  {
      /* if init fail moves to next exerciser */
      if (val_exerciser_init(instance))
          continue;

      e_bdf = val_exerciser_get_bdf(instance);
      val_print(ACS_PRINT_DEBUG, "\n       Exerciser BDF - 0x%x", e_bdf);

      /* Create a buffer of size TEST_DMA_SIZE in DRAM */
      dram_buf_in_virt = val_memory_alloc_pages(TEST_DATA_NUM_PAGES);

      /* Set the buffer to value 0 */
      val_memory_set(dram_buf_in_virt, dma_len, 0);
      dram_buf_in_virt2 = dram_buf_in_virt + dma_len;

      val_memory_set(dram_buf_in_virt, dma_len, TEST_DATA);

      if (val_pcie_get_rootport(e_bdf, &rp_bdf))
          continue;

      /* Check for DA Capability */
      if (val_pcie_find_da_capability(rp_bdf, &da_cap_base) != PCIE_SUCCESS)
      {
          val_print(ACS_PRINT_ERR,
                        "\n       PCIe DA DVSEC capability not present,bdf 0x%x", e_bdf);
          continue;
      }

      test_skip = 0;

      /* Disable RMEDA_CTL1.TDISP_EN*/
      val_pcie_disable_tdisp(rp_bdf);
      if (val_device_lock(e_bdf))
      {
          val_print(ACS_PRINT_ERR, "\n       Failed to lock the device: 0x%lx", e_bdf);
          test_fail++;
          continue;
      }

      val_exerciser_set_param(DMA_ATTRIBUTES, (uint64_t)dram_buf_in_virt, dma_len, instance);
      if (val_exerciser_ops(START_DMA, EDMA_TO_DEVICE, instance))
      {
          val_print(ACS_PRINT_ERR, "\n        DMA write failure to exerciser %4x", instance);
          test_fail++;
          continue;
      }

      val_exerciser_set_param(DMA_ATTRIBUTES, (uint64_t)dram_buf_in_virt2, dma_len, instance);
      if (val_exerciser_ops(START_DMA, EDMA_FROM_DEVICE, instance))
      {
          val_print(ACS_PRINT_ERR, "\n        DMA write failure to exerciser %4x", instance);
          test_fail++;
          continue;
      }

      if (!val_memory_compare(dram_buf_in_virt, dram_buf_in_virt2, dma_len))
      {
          val_print(ACS_PRINT_ERR,
                    "\n Incoming request is succesful when TDISP_EN=0 for instance %4x", instance);
          test_fail++;
          continue;
      }

      val_memory_set(dram_buf_in_virt, dma_len * 2, 0);
      /* Return the buffer to the heap manager */
      val_memory_free_pages(dram_buf_in_virt, TEST_DATA_NUM_PAGES);
  }

  tbl_index = 0;
  bdf_tbl_ptr = val_pcie_bdf_table_ptr();
  while (tbl_index < bdf_tbl_ptr->num_entries)
  {
      rp_bdf = bdf_tbl_ptr->device[tbl_index++].bdf;
      dp_type = val_pcie_device_port_type(rp_bdf);

      if (dp_type == RP)
      {
          /* Check for DA Capability */
          if (val_pcie_find_da_capability(rp_bdf, &da_cap_base) != PCIE_SUCCESS)
          {
              val_print(ACS_PRINT_ERR,
                        "\n       PCIe DA DVSEC capability not present,bdf 0x%x", e_bdf);
              continue;
          }

          val_pcie_disable_tdisp(rp_bdf);
          val_pcie_get_mmio_bar(rp_bdf, &Bar_Base);

          if (!Bar_Base)
              continue;

          test_skip = 0;
          va = val_get_free_va(val_get_min_tg());
          pgt_attr_el3 = LOWER_ATTRS(PGT_ENTRY_ACCESS | SHAREABLE_ATTR(OUTER_SHAREABLE)
                          | GET_ATTR_INDEX(DEV_MEM_nGnRnE) | PGT_ENTRY_AP_RW | PAS_ATTR(ROOT_PAS));
          val_add_mmu_entry_el3(va, Bar_Base, pgt_attr_el3);
          shared_data->num_access = 1;
          shared_data->shared_data_access[0].addr = va;
          shared_data->shared_data_access[0].access_type = READ_DATA;
          val_pe_access_mut_el3();
          rp_data = shared_data->shared_data_access[0].data;
          if (rp_data != PCIE_UNKNOWN_RESPONSE)
          {
              val_print(ACS_PRINT_ERR,
                    "\n Outgoing request is successful when TDISP_EN=0 for instance %4x", instance);
              test_fail++;
              continue;
          }
      }
  }

  if (test_skip)
      val_set_status(pe_index, RESULT_SKIP(TEST_NUM, 01));
  else if (test_fail)
      val_set_status(pe_index, RESULT_FAIL(TEST_NUM, 01));
  else
      val_set_status(pe_index, RESULT_PASS(TEST_NUM, 01));

  return;

}


uint32_t
da013_entry(void)
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

