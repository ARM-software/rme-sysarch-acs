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
#define _TEST_
#include "val/include/rme_acs_val.h"
#include "val/include/val_interface.h"

#include "val/include/rme_acs_el32.h"
#include "val/include/rme_acs_pcie.h"
#include "val/include/rme_acs_memory.h"
#include "val/include/rme_acs_pcie_enumeration.h"
#include "val/include/rme_acs_exerciser.h"
#include "val/include/rme_acs_smmu.h"
#include "val/include/rme_acs_pe.h"
#include "val/include/rme_acs_da.h"
#include "val/include/rme_acs_iovirt.h"
#include "val/include/rme_acs_gic.h"
#include "val/include/rme_acs_gic_support.h"
#include "val/sys_arch_src/gic/its/rme_gic_its.h"

#define TEST_NAME "da_p2p_btw_2_tdisp_devices"
#define TEST_DESC "P2P traffic between two TDISP devices                  "
#define TEST_RULE "RMDPKR"

uint32_t
get_target_exer_bdf(uint32_t req_rp_bdf, uint32_t *tgt_e_bdf,
                    uint32_t *tgt_rp_bdf, uint64_t *bar_base)
{

  uint32_t erp_bdf;
  uint32_t e_bdf;
  uint32_t instance;
  uint32_t req_rp_ecam_index;
  uint32_t erp_ecam_index;
  uint32_t status;

  instance = val_exerciser_get_info(EXERCISER_NUM_CARDS);

  while (instance-- != 0)
  {
      /* if init fail moves to next exerciser */
      if (val_exerciser_init(instance))
          continue;

      e_bdf = val_exerciser_get_bdf(instance);

      /* Read e_bdf BAR Register to get the Address to perform P2P */
      /* If No BAR Space, continue */
      val_pcie_get_mmio_bar(e_bdf, bar_base);
      if (*bar_base == 0)
          continue;

      /* Get RP of the exerciser */
      if (val_pcie_get_rootport(e_bdf, &erp_bdf))
          continue;

      if (req_rp_bdf != erp_bdf)
      {
          status = val_pcie_get_ecam_index(req_rp_bdf, &req_rp_ecam_index);
          if (status)
          {
             val_print(ACS_PRINT_ERR, " Error Ecam index for req RP BDF: 0x%x", req_rp_bdf);
             goto test_fail;
          }

          status = val_pcie_get_ecam_index(erp_bdf, &erp_ecam_index);
          if (status)
          {
             val_print(ACS_PRINT_ERR, " Error Ecam index for tgt RP BDF: 0x%x", erp_bdf);
             goto test_fail;
          }

          if (req_rp_ecam_index != erp_ecam_index)
              continue;

          *tgt_e_bdf = e_bdf;
          *tgt_rp_bdf = erp_bdf;

          /* Enable Bus Master Enable */
          val_pcie_enable_bme(e_bdf);
          /* Enable Memory Space Access */
          val_pcie_enable_msa(e_bdf);

          return ACS_STATUS_PASS;
      }
  }

test_fail:
  /* Return failure if No Such Exerciser Found */
  *tgt_e_bdf = 0;
  *tgt_rp_bdf = 0;
  *bar_base = 0;
  return ACS_STATUS_FAIL;
}

uint32_t
check_p2p_transaction(uint32_t req_instance, uint64_t bar_base)
{
  /* P2P transaction must fail */
  val_exerciser_set_param(DMA_ATTRIBUTES, (uint64_t)bar_base, 1, req_instance);
  val_exerciser_ops(START_DMA, EDMA_TO_DEVICE, req_instance);

  return ACS_STATUS_PASS;
}

static
void
payload(void)
{

  uint32_t status;
  uint32_t index;
  uint32_t req_e_bdf;
  uint32_t req_rp_bdf;
  uint32_t tgt_e_bdf;
  uint32_t tgt_rp_bdf;
  uint32_t instance;
  uint32_t test_skip;
  uint64_t bar_base;
  uint32_t test_fails;

  test_skip = 1;
  test_fails = 0;
  index = val_pe_get_index_mpid(val_pe_get_mpid());
  instance = val_exerciser_get_info(EXERCISER_NUM_CARDS);

  while (instance-- != 0)
  {

      /* if init fail moves to next exerciser */
      if (val_exerciser_init(instance))
          continue;

      req_e_bdf = val_exerciser_get_bdf(instance);
      val_print(ACS_PRINT_TEST, " Requester exerciser BDF - 0x%x", req_e_bdf);

      /* Get RP of the exerciser */
      if (val_pcie_get_rootport(req_e_bdf, &req_rp_bdf))
          continue;

      /* Find another exerciser on other rootport,
         Skip the current exerciser if no such exerciser if found */
      if (get_target_exer_bdf(req_rp_bdf, &tgt_e_bdf, &tgt_rp_bdf, &bar_base))
          continue;

      test_skip = 0;

      if (val_pcie_enable_tdisp(req_rp_bdf))
      {
          val_print(ACS_PRINT_ERR, " Unable to set tdisp_en for BDF: 0x%x", req_rp_bdf);
          test_fails++;
          continue;
      }

      if (val_pcie_enable_tdisp(tgt_rp_bdf))
      {
          val_print(ACS_PRINT_ERR, " Unable to set tdisp_en for BDF: 0x%x", tgt_rp_bdf);
          test_fails++;
          continue;
      }

      val_print(ACS_PRINT_TEST, " Target exerciser BDF - 0x%x", tgt_e_bdf);

      if (val_device_lock(req_e_bdf))
      {
          val_print(ACS_PRINT_ERR, " Failed to lock the device: 0x%lx", req_e_bdf);
          goto test_clean;
      }

      if (val_device_lock(tgt_e_bdf))
      {
          val_print(ACS_PRINT_ERR, " Failed to lock the device: 0x%lx", tgt_e_bdf);
          goto test_clean;
      }

      /* Check if P2P transaction causes any deadlock */
      status = check_p2p_transaction(instance, bar_base);
      if (status)
      {
          val_print(ACS_PRINT_DEBUG, " Putting the devices into unlocked state", 0);
          val_device_unlock(req_e_bdf);
          val_pcie_disable_tdisp(req_rp_bdf);
          val_device_unlock(tgt_e_bdf);
          val_pcie_disable_tdisp(tgt_rp_bdf);
          val_set_status(index, "FAIL", 1);
          return;
      }

test_clean:
      val_print(ACS_PRINT_DEBUG, " Putting the devices back into unlocked state", 0);
      val_device_unlock(req_e_bdf);
      val_device_unlock(tgt_e_bdf);
      val_pcie_disable_tdisp(req_rp_bdf);
      val_pcie_disable_tdisp(tgt_rp_bdf);
      /* Clear Error Status Bits */
      val_pcie_clear_device_status_error(req_rp_bdf);
      val_pcie_clear_sig_target_abort(req_rp_bdf);
  }

  if (test_skip)
    val_set_status(index, "SKIP", 02);
  else if (test_fails)
      val_set_status(index, "FAIL", test_fails);
  else
      val_set_status(index, "PASS", 01);

}

uint32_t
da_p2p_btw_2_tdisp_devices_entry(void)
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
