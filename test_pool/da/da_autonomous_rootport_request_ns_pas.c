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

#define _TEST_
#include "val/include/val.h"
#include "val/include/val_interface.h"

#include "val/include/val_el32.h"
#include "val/include/val_pcie.h"
#include "val/include/val_memory.h"
#include "val/include/val_pcie_enumeration.h"
#include "val/include/val_exerciser.h"
#include "val/include/val_smmu.h"
#include "val/include/val_pe.h"
#include "val/include/val_da.h"
#include "val/include/val_iovirt.h"
#include "val/include/val_gic.h"
#include "val/include/val_gic_support.h"
#include "val/sys_arch_src/gic/its/val_gic_its.h"

#define TEST_NAME "da_autonomous_rootport_request_ns_pas"
#define TEST_DESC "Autonomously initiated by the RP over its host interface "
#define TEST_RULE "RMJNLW"

static uint32_t irq_pending;
static uint32_t lpi_int_id = 0x204c;

extern GIC_ITS_INFO    *g_gic_its_info;

static
void
intr_handler(void)
{
  /* Clear the interrupt pending state */
  irq_pending = 0;

  val_print(ACS_PRINT_INFO, " Received MSI interrupt %x       ", lpi_int_id);
  val_gic_end_of_interrupt(lpi_int_id);
  return;
}

static
void
inject_error(uint32_t instance)
{

    /* Set the interrupt trigger status to pending */
    irq_pending = 1;

    val_exerciser_set_param(ERROR_INJECT_TYPE, 0, 0, instance);
    val_exerciser_ops(INJECT_ERROR, 0, instance);

    return;
}

static
void
payload(void)
{
  uint32_t instance;
  uint32_t pe_index;
  uint32_t e_bdf;
  uint32_t erp_bdf;
  uint32_t test_skip = 1;
  uint32_t status;
  uint32_t device_id = 0;
  uint32_t stream_id = 0;
  uint32_t its_id = 0;
  uint32_t msi_index = 0;
  uint32_t msi_cap_offset = 0;
  uint64_t itt_base;
  uint32_t timeout, rp_aer_offset, value;

  pe_index = val_pe_get_index_mpid(val_pe_get_mpid());
  instance = val_exerciser_get_info(EXERCISER_NUM_CARDS);

  while (instance-- != 0) {

      /* if init fail moves to next exerciser */
      if (val_exerciser_init(instance))
          continue;

      e_bdf = val_exerciser_get_bdf(instance);
      val_print(ACS_PRINT_TEST, " Exerciser BDF - 0x%x", e_bdf);

      val_pcie_enable_eru(e_bdf);
      if (val_pcie_get_rootport(e_bdf, &erp_bdf))
          continue;

      val_pcie_enable_eru(erp_bdf);

      /* Search for MSI-X Capability */
      if (val_pcie_find_capability(e_bdf, PCIE_CAP, CID_MSIX, &msi_cap_offset)) {
          val_print(ACS_PRINT_ERR, " No MSI-X Capability, Skipping for Bdf 0x%x", e_bdf);
          continue;
      }

      if (val_pcie_find_capability(erp_bdf, PCIE_CAP, CID_MSIX, &msi_cap_offset)) {
          val_print(ACS_PRINT_ERR, " No MSI-X Capability for RP Bdf 0x%x", erp_bdf);
          val_set_status(pe_index, "FAIL", 01);
          return;
      }

      if (val_pcie_find_capability(erp_bdf, PCIE_ECAP, ECID_AER, &rp_aer_offset) != PCIE_SUCCESS) {
          val_print(ACS_PRINT_ERR, " AER Capability not supported for RP : 0x%x", erp_bdf);
          val_set_status(pe_index, "FAIL", 02);
          val_set_status(pe_index, "FAIL", 02);
          return;
      }

      /* Get DeviceID & ITS_ID for this device */
      status = val_iovirt_get_device_info(PCIE_CREATE_BDF_PACKED(erp_bdf),
                                        PCIE_EXTRACT_BDF_SEG(erp_bdf), &device_id,
                                        &stream_id, &its_id);

      if (status) {
          val_print(ACS_PRINT_ERR, " iovirt_get_device failed for bdf 0x%x", e_bdf);
          val_set_status(pe_index, "FAIL", 03);
          return;
      }

      test_skip = 0;
      //Enable the Error Reporting bits in the RP's AER ROOT_ERR_CMD register
      val_pcie_read_cfg(erp_bdf, rp_aer_offset + AER_ROOT_ERR_CMD_OFFSET, &value);
      val_pcie_write_cfg(erp_bdf, rp_aer_offset + AER_ROOT_ERR_CMD_OFFSET, (value | 0x7));

      // Program the ITT base as ROOT in GPT
      itt_base = g_gic_its_info->GicIts[its_id].ITTBase;
      if (val_add_gpt_entry_el3(itt_base, GPT_ROOT))
      {
            val_print(ACS_PRINT_ERR, " DPT Entry adding failed for the Address: 0x%llx", itt_base);
            val_set_status(pe_index, "FAIL", 04);
            return;
      }
      val_print(ACS_PRINT_INFO, " ITT base is mapped as Root in GPT ", 0);

      /* MSI assignment */
      status = val_gic_request_msi(erp_bdf, device_id, its_id, lpi_int_id + instance, msi_index);
      if (status) {
          val_print(ACS_PRINT_ERR, " MSI Assignment failed for bdf : 0x%x", erp_bdf);
          val_set_status(pe_index, "FAIL", 05);
          return;
      }

      status = val_gic_install_isr(lpi_int_id + instance, intr_handler);

      if (status) {
          val_print(ACS_PRINT_ERR, " Intr handler registration failed: 0x%x", lpi_int_id);
          val_set_status(pe_index, "FAIL", 06);
          return;
      }

      inject_error(instance);

      /* PE busy polls to check the completion of interrupt service routine */
      timeout = TIMEOUT_MEDIUM;
      while ((--timeout > 0) && irq_pending)
          {};

      /* Interrupt should not be generated */
      if (irq_pending == 0) {
          val_print(ACS_PRINT_ERR,
              " Interrupt triggered PE for bdf : 0x%x, ", e_bdf);
          val_set_status(pe_index, "FAIL", 7);
          val_gic_free_msi(e_bdf, device_id, its_id, lpi_int_id + instance, msi_index);
          return;
      }

      val_pcie_clear_urd(erp_bdf);
      val_gic_free_msi(erp_bdf, device_id, its_id, lpi_int_id + instance, msi_index);

      itt_base = g_gic_its_info->GicIts[its_id].ITTBase;
      if (val_add_gpt_entry_el3(itt_base, GPT_NONSECURE))
      {
            val_print(ACS_PRINT_ERR, " DPT Entry adding failed for the Address: 0x%llx", itt_base);
            val_set_status(pe_index, "FAIL", 8);
            return;
      }
      val_print(ACS_PRINT_INFO, " ITT base is mapped as Non-Secure in GPT ", 0);

      /* MSI assignment */
      status = val_gic_request_msi(erp_bdf, device_id, its_id, lpi_int_id + instance, msi_index);
      if (status) {
          val_print(ACS_PRINT_ERR, " MSI Assignment failed for bdf : 0x%x", erp_bdf);
          val_set_status(pe_index, "FAIL", 9);
          return;
      }

      status = val_gic_install_isr(lpi_int_id + instance, intr_handler);

      if (status) {
          val_print(ACS_PRINT_ERR, " Intr handler registration failed: 0x%x", lpi_int_id);
          val_set_status(pe_index, "FAIL", 10);
          return;
      }

      inject_error(instance);

      /* PE busy polls to check the completion of interrupt service routine */
      timeout = TIMEOUT_LARGE;
      while ((--timeout > 0) && irq_pending)
          {};

      if (timeout == 0) {
          val_print(ACS_PRINT_ERR, " Interrupt trigger failed for : 0x%x, ", lpi_int_id);
          val_print(ACS_PRINT_ERR, " BDF : 0x%x   ", e_bdf);
          val_set_status(pe_index, "FAIL", 11);
          val_gic_free_msi(e_bdf, device_id, its_id, lpi_int_id + instance, msi_index);
          return;
      }

      /*
       * Clear unsupported request detected bit in Exerciser upstream
       * Rootport's Device Status Register to clear any pending urd status.
       */
      val_pcie_clear_urd(erp_bdf);
      val_gic_free_msi(erp_bdf, device_id, its_id, lpi_int_id + instance, msi_index);


      /* Disable error reporting of Exerciser and upstream Root Port */
      val_pcie_disable_eru(e_bdf);
      val_pcie_disable_eru(erp_bdf);

    }

  if (test_skip == 1)
      val_set_status(pe_index, "SKIP", 01);
  else
      val_set_status(pe_index, "PASS", 01);

  return;

}

uint32_t
da_autonomous_rootport_request_ns_pas_entry(void)
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
