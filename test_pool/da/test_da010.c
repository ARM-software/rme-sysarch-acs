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

#include "val/include/rme_acs_val.h"
#include "val/include/val_interface.h"

#include "val/include/rme_acs_da.h"
#include "val/include/rme_acs_smmu.h"
#include "val/include/rme_acs_pcie.h"
#include "val/include/rme_acs_exerciser.h"
#include "val/include/rme_acs_el32.h"

#define TEST_NUM  (ACS_RME_DA_TEST_NUM_BASE + 10)
#define TEST_DESC  "Check IDE Stream state when RP has UNCORR_DL_ERROR     "
#define TEST_RULE  "RPJGJK"

static
uint32_t
inject_error(uint32_t e_bdf, uint32_t instance)
{
    uint32_t pciecs_base, reg_value;

    val_exerciser_set_param(ERROR_INJECT_TYPE, UNCORR_INT_ERR, 0, instance);
    val_exerciser_ops(INJECT_ERROR, UNCORR_INT_ERR, instance);

    /* Check if the appropriate status bit is set in Device status register */
    val_pcie_find_capability(e_bdf, PCIE_CAP, CID_PCIECS, &pciecs_base);
    val_pcie_read_cfg(e_bdf, pciecs_base + DCTLR_OFFSET, &reg_value);
    if (!((reg_value >> DSTS_SHIFT) & DS_UNCORR_MASK))
    {
        val_print(ACS_PRINT_ERR, "\n       Error is not detected", 0);
        return 1;
    }

    return 0;
}

static
void
payload()
{

  uint32_t pe_index = val_pe_get_index_mpid(val_pe_get_mpid());
  uint32_t instance;
  uint32_t e_bdf;
  uint32_t erp_bdf;
  uint32_t aer_offset;
  uint32_t rp_aer_offset;
  uint32_t da_cap_base, ide_cap_base;
  uint32_t reg_value;
  uint32_t num_sel_ide_stream_supp;
  uint32_t count;
  uint32_t test_fails = 0;
  uint32_t test_skip = 1;
  uint32_t status;

  instance = val_exerciser_get_info(EXERCISER_NUM_CARDS);

  while (instance-- != 0) {

    /* if init fail moves to next exerciser */
    if (val_exerciser_init(instance))
        continue;

    e_bdf = val_exerciser_get_bdf(instance);
    val_print(ACS_PRINT_DEBUG, "\n       Exerciser BDF - 0x%x", e_bdf);

    val_pcie_enable_eru(e_bdf);
    if (val_pcie_get_rootport(e_bdf, &erp_bdf))
        continue;

    val_pcie_enable_eru(erp_bdf);

    /*Check AER capability for exerciser and its RP */
    if (val_pcie_find_capability(e_bdf, PCIE_ECAP, ECID_AER, &aer_offset) != PCIE_SUCCESS) {
        val_print(ACS_PRINT_ERR, "\n       No AER Capability, Skipping for Bdf : 0x%x", e_bdf);
        continue;
    }

    if (val_pcie_find_capability(erp_bdf, PCIE_ECAP, ECID_AER, &rp_aer_offset) != PCIE_SUCCESS) {
        val_print(ACS_PRINT_ERR, "\n       AER Capability not supported for RP : 0x%x", erp_bdf);
        val_set_status(pe_index, RESULT_FAIL(TEST_NUM, 01));
        return;
    }

    test_skip = 0;
    /* Check for DA capability */
    if (val_pcie_find_da_capability(erp_bdf, &da_cap_base) != PCIE_SUCCESS)
    {
        val_print(ACS_PRINT_ERR,
                      "\n       PCIe DA DVSEC capability not present,bdf 0x%x", e_bdf);
        test_fails++;
        continue;
    }

    /* Get the PCIE IDE Extended Capability register for RP */
    if (val_pcie_find_capability(erp_bdf, PCIE_ECAP, ECID_IDE, &ide_cap_base) != PCIE_SUCCESS)
    {
        val_print(ACS_PRINT_ERR,
                      "\n       PCIe IDE Capability not present for BDF: 0x%x", e_bdf);
        test_fails++;
        continue;
    }

    /* Get the number of Selective IDE Streams */
    status = val_ide_get_num_sel_str(erp_bdf, &num_sel_ide_stream_supp);
    if (status)
    {
        val_print(ACS_PRINT_ERR, "\n       Failed to get num of Sel stream for BDF: 0x%x", e_bdf);
        test_fails++;
        continue;
    }

    /* Bring the RP to TDISP Locked state */
    if (val_pcie_enable_tdisp(erp_bdf))
    {
          val_print(ACS_PRINT_ERR, "\n        Unable to set tdisp_en for BDF: 0x%x", erp_bdf);
          test_fails++;
          continue;
    }

    count = 0;
    while (count++ < num_sel_ide_stream_supp)
    {
        status = val_ide_establish_stream(erp_bdf, count, val_generate_stream_id(),
                                     PCIE_CREATE_BDF_PACKED(erp_bdf));
        if (status)
        {
            val_print(ACS_PRINT_ERR, "\n       Failed to establish stream for bdf: 0x%x", erp_bdf);
            test_fails++;
            continue;
        }

        /* Inject the error into the device */
        if (inject_error(e_bdf, instance))
        {
            val_print(ACS_PRINT_ERR, "\n       Errror injection failed for BDF: 0x%x", e_bdf);
            test_fails++;
            continue;
        }

        status = val_get_sel_str_status(erp_bdf, count, &reg_value);
        if (status)
        {
            val_print(ACS_PRINT_ERR, "\n       Failed to get SEL_STR state for BDF: 0x%x", erp_bdf);
            test_fails++;
            continue;
        }

        if (reg_value != STREAM_STATE_INSECURE)
        {
            val_print(ACS_PRINT_ERR, "\n       SEL_STR is not in Insecure for BDF: 0x%x", erp_bdf);
            test_fails++;
            continue;
        }

        status = val_ide_set_sel_stream(erp_bdf, count, 0);
        if (status)
        {
            val_print(ACS_PRINT_ERR, "\n       Failed to disable SEL_STR for BDF: 0x%x", erp_bdf);
            test_fails++;
            continue;
        }

        val_ide_program_rid_base_limit_valid(erp_bdf, count, 0, 0, 0);

    }

    /* Disable the TDISP for RP */
    val_pcie_disable_tdisp(erp_bdf);

    /* Disable error reporting of Exerciser and upstream Root Port */
    val_pcie_disable_eru(e_bdf);
    val_pcie_disable_eru(erp_bdf);

    /*
     * Clear unsupported request detected bit in Exerciser upstream
     * Rootport's Device Status Register to clear any pending urd status.
     */
    val_pcie_clear_urd(erp_bdf);
  }

  if (test_skip)
      val_set_status(pe_index, RESULT_SKIP(TEST_NUM, 01));
  else if (test_fails)
      val_set_status(pe_index, RESULT_FAIL(TEST_NUM, 01));
  else
      val_set_status(pe_index, RESULT_PASS(TEST_NUM, 01));

  return;
}

uint32_t
da010_entry(void)
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
