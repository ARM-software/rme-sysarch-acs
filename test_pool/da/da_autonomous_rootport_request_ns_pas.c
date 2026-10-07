/** @file
 * Copyright (c) 2024-2026, Arm Limited or its affiliates. All rights reserved.
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

/* Updated by the ISR while payload polls for delivery. */
static volatile uint32_t irq_pending;
static uint32_t lpi_int_id = 0x204c;
static uint32_t active_int_id;

extern GIC_ITS_INFO    *g_gic_its_info;

static
void
intr_handler(void)
{
  /* Clear the interrupt pending state */
  irq_pending = 0;

  val_print(ACS_PRINT_INFO, " Received MSI interrupt %x       ", active_int_id);
  val_gic_end_of_interrupt(active_int_id);
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
  uint32_t its_index;
  ITS_CACHE_STATE its_cache_state;
  uint32_t msi_index = 0;
  uint32_t msi_cap_offset = 0;
  uint32_t use_msix;
  uint64_t itt_base, itt_entry_pa, itt_entry_offset;
  uint32_t itt_size, itt_entry_size;
  uint32_t timeout, rp_aer_offset, value;

  pe_index = val_pe_get_index_mpid(val_pe_get_mpid());
  instance = val_exerciser_get_info(EXERCISER_NUM_CARDS);
  if (instance == 0)
  {
    val_print(ACS_PRINT_WARN, " No exerciser cards discovered", 0);
    val_set_status(pe_index, "SKIP", 1);
    return;
  }

  while (instance-- != 0) {

      /* if init fail moves to next exerciser */
      if (val_exerciser_init(instance))
          continue;

      e_bdf = val_exerciser_get_bdf(instance);
      val_print(ACS_PRINT_TEST, " Exerciser BDF - 0x%x", e_bdf);

      if (val_pcie_get_rootport(e_bdf, &erp_bdf))
          continue;

      /* The RP generates the interrupt; the EP only injects the error. */
      use_msix = (val_pcie_find_capability(erp_bdf, PCIE_CAP, CID_MSIX,
                                          &msi_cap_offset) == PCIE_SUCCESS);
      if (!use_msix &&
          val_pcie_find_capability(erp_bdf, PCIE_CAP, CID_MSI, &msi_cap_offset)) {
          val_print(ACS_PRINT_WARN, " No MSI/MSI-X Capability for RP Bdf 0x%x, skipping", erp_bdf);
          continue;
      }

      if (val_pcie_find_capability(erp_bdf, PCIE_ECAP, ECID_AER, &rp_aer_offset) != PCIE_SUCCESS) {
          val_print(ACS_PRINT_ERR, " AER Capability not supported for RP : 0x%x", erp_bdf);
          val_set_status(pe_index, "FAIL", 1);
          return;
      }

      /* Get DeviceID & ITS_ID for this device */
      status = val_iovirt_get_device_info(PCIE_CREATE_BDF_PACKED(erp_bdf),
                                        PCIE_EXTRACT_BDF_SEG(erp_bdf), &device_id,
                                        &stream_id, &its_id);

      if (status) {
          val_print(ACS_PRINT_ERR, " iovirt_get_device failed for bdf 0x%x", e_bdf);
          val_set_status(pe_index, "FAIL", 2);
          return;
      }

      its_index = val_gic_get_its_index(its_id);
      if (its_index == ACS_INVALID_INDEX) {
          val_print(ACS_PRINT_ERR, " Could not find ITS ID [%x]", its_id);
          val_set_status(pe_index, "FAIL", 3);
          return;
      }

      /* Check MSI addressability before protecting the ITT. */
      if (!use_msix) {
          val_pcie_read_cfg(erp_bdf, msi_cap_offset, &value);
          if (!(value & MSI_64BIT_ADDR_MASK) &&
              (val_gic_its_get_translater_addr(its_index) >> 32)) {
              val_print(ACS_PRINT_WARN,
                  " 32-bit MSI cannot address GITS_TRANSLATER for RP Bdf 0x%x, skipping", erp_bdf);
              continue;
          }
      }

      val_pcie_enable_eru(e_bdf);
      val_pcie_enable_eru(erp_bdf);
      active_int_id = lpi_int_id + instance;
      val_print(ACS_PRINT_TEST, " Root Port BDF - 0x%x", erp_bdf);
      val_print(ACS_PRINT_TEST, " LPI INTID - 0x%x", active_int_id);
      test_skip = 0;
      //Enable the Error Reporting bits in the RP's AER ROOT_ERR_CMD register
      val_pcie_read_cfg(erp_bdf, rp_aer_offset + AER_ROOT_ERR_CMD_OFFSET, &value);
      val_pcie_write_cfg(erp_bdf, rp_aer_offset + AER_ROOT_ERR_CMD_OFFSET, (value | 0x7));

      itt_entry_size = ARM_GITS_TYPER_ITTEntrySize(val_mmio_read64(
          g_gic_its_info->GicIts[its_index].Base + ARM_GITS_TYPER)) + 1;
      /* EventID indexes the ITT (IHI0069H.b, section 5.2.4). */
      itt_entry_offset = (uint64_t)(lpi_int_id + instance) * itt_entry_size;

      /* Protect the selected ITT entry before requesting the Root Port MSI. */
      status = val_gic_its_alloc_device_itt(its_index, device_id);
      if (status) {
          val_print(ACS_PRINT_ERR, " Could not allocate device ITT", 0);
          val_set_status(pe_index, "FAIL", 4);
          return;
      }

      itt_base = val_gic_its_get_itt_base(its_index, device_id);
      itt_size = val_gic_its_get_itt_size(its_index, device_id);
      if ((itt_base == 0) || (itt_size == 0)) {
          val_set_status(pe_index, "FAIL", 5);
          return;
      }
      if ((itt_entry_offset >= itt_size) ||
          (itt_entry_size > itt_size - itt_entry_offset)) {
          val_print(ACS_PRINT_ERR, " EventID entry exceeds allocated ITT", 0);
          val_set_status(pe_index, "FAIL", 6);
          return;
      }
      itt_entry_pa = itt_base + itt_entry_offset;
      if ((itt_entry_pa & (SIZE_4KB - 1)) + itt_entry_size > SIZE_4KB) {
          val_print(ACS_PRINT_WARN, " ITT entry crosses a 4KB page", 0);
          val_set_status(pe_index, "SKIP", 2);
          return;
      }
      status = val_gic_install_isr(lpi_int_id + instance, intr_handler);
      if (status) {
          val_set_status(pe_index, "FAIL", 7);
          return;
      }

      /* Complete ITS setup while the ITT is Non-secure, before protecting it. */
      status = val_gic_its_create_lpi_map(its_index, device_id,
                                       lpi_int_id + instance, LPI_PRIORITY1);
      if (status != ACS_STATUS_PASS) {
          val_set_status(pe_index, "FAIL", 8);
          return;
      }

      /* Keep ITS stopped across the PAS change to prevent cache refills. */
      status = val_gic_its_invalidate_cache_and_suspend(its_index, &its_cache_state);
      if (status != ACS_STATUS_PASS) {
          if (status == ACS_STATUS_SKIP) {
              if (val_gic_free_msi(erp_bdf, device_id, its_id,
                               lpi_int_id + instance, msi_index) != ACS_STATUS_PASS) {
                  val_set_status(pe_index, "FAIL", 9);
                  return;
              }
              val_set_status(pe_index, "SKIP", 3);
          } else {
              /* ITS may still reference the ITT; retain its allocation on error. */
              val_set_status(pe_index, "FAIL", 10);
          }
          return;
      }

      if (val_add_gpt_entry_el3(itt_entry_pa, GPT_ROOT))
      {
            val_print(ACS_PRINT_ERR, " DPT Entry adding failed for the Address: 0x%llx",
                      itt_entry_pa);
            val_set_status(pe_index, "FAIL", 11);

            /* Resume ITS before cleanup submits commands or releases the ITT. */
            if (val_gic_its_resume_after_pas_change(its_index, &its_cache_state) == ACS_STATUS_PASS)
              val_gic_free_msi(erp_bdf, device_id, its_id, lpi_int_id + instance, msi_index);
            return;
      }

      /* GPT maintenance is complete; resume without recreating the ITS mapping. */
      if (val_gic_its_resume_after_pas_change(its_index, &its_cache_state) != ACS_STATUS_PASS) {
          val_set_status(pe_index, "FAIL", 12);

          /* Restore PAS, but retain memory if ITS state could not be restored. */
          val_add_gpt_entry_el3(itt_entry_pa, GPT_NONSECURE);
          return;
      }

      val_print(ACS_PRINT_INFO, " Selected ITT entry is mapped as Root in GPT ", 0);

      status = val_gic_request_msi(erp_bdf, device_id, its_id, lpi_int_id + instance, msi_index);
      if (status) {
          val_print(ACS_PRINT_ERR, " MSI Assignment failed for bdf : 0x%x", erp_bdf);
          val_set_status(pe_index, "FAIL", 13);
          if (val_add_gpt_entry_el3(itt_entry_pa, GPT_NONSECURE))
              return;
          val_gic_free_msi(erp_bdf, device_id, its_id, lpi_int_id + instance, msi_index);
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
          val_set_status(pe_index, "FAIL", 14);
          if (val_add_gpt_entry_el3(itt_entry_pa, GPT_NONSECURE))
              return;
          val_gic_free_msi(erp_bdf, device_id, its_id, lpi_int_id + instance, msi_index);
          return;
      }

      val_pcie_clear_urd(erp_bdf);
      /* Restore the Root entry before discarding its mapping and ITT. */
      if (val_add_gpt_entry_el3(itt_entry_pa, GPT_NONSECURE))
      {
            val_print(ACS_PRINT_ERR, " DPT Entry adding failed for the Address: 0x%llx",
                      itt_entry_pa);
            val_set_status(pe_index, "FAIL", 15);
            return;
      }

      val_print(ACS_PRINT_INFO, " Selected ITT entry is mapped as Non-Secure in GPT ", 0);

      /* Start the positive phase with a fresh mapping, not a second MAPTI
       * for an already mapped DeviceID/EventID (IHI0069H.b, section 5.3.12).
       */
      /* Stop if teardown timed out; ITS still owns the retained mapping. */
      if (val_gic_free_msi(erp_bdf, device_id, its_id, lpi_int_id + instance, msi_index)
          != ACS_STATUS_PASS) {
          val_set_status(pe_index, "FAIL", 16);
          return;
      }
      status = val_gic_its_alloc_device_itt(its_index, device_id);
      if (status) {
          val_set_status(pe_index, "FAIL", 17);
          return;
      }
      itt_base = val_gic_its_get_itt_base(its_index, device_id);
      if (itt_base == 0) {
          val_set_status(pe_index, "FAIL", 18);
          return;
      }
      /* Entry size and offset are unchanged for this ITS and EventID. */
      itt_entry_pa = itt_base + itt_entry_offset;
      if (val_add_gpt_entry_el3(itt_entry_pa, GPT_NONSECURE)) {
          val_set_status(pe_index, "FAIL", 19);
          return;
      }

      status = val_gic_its_create_lpi_map(its_index, device_id,
                                       lpi_int_id + instance, LPI_PRIORITY1);
      if (status != ACS_STATUS_PASS) {
          val_set_status(pe_index, "FAIL", 20);
          return;
      }

      /* MSI assignment */
      status = val_gic_request_msi(erp_bdf, device_id, its_id, lpi_int_id + instance, msi_index);
      if (status) {
          val_print(ACS_PRINT_ERR, " MSI Assignment failed for bdf : 0x%x", erp_bdf);
          val_set_status(pe_index, "FAIL", 21);
          val_gic_free_msi(erp_bdf, device_id, its_id, lpi_int_id + instance, msi_index);
          return;
      }

      inject_error(instance);

      /* PE busy polls to check the completion of interrupt service routine */
      timeout = TIMEOUT_LARGE;
      while ((--timeout > 0) && irq_pending)
          {};

      if (timeout == 0) {
          val_print(ACS_PRINT_ERR, " Interrupt trigger failed for : 0x%x, ", active_int_id);
          val_print(ACS_PRINT_ERR, " BDF : 0x%x   ", e_bdf);
          val_set_status(pe_index, "FAIL", 22);
          val_gic_free_msi(erp_bdf, device_id, its_id, lpi_int_id + instance, msi_index);
          return;
      }

      /*
       * Clear unsupported request detected bit in Exerciser upstream
       * Rootport's Device Status Register to clear any pending urd status.
       */
      val_pcie_clear_urd(erp_bdf);
      /* Stop if teardown timed out; ITS still owns the retained mapping. */
      if (val_gic_free_msi(erp_bdf, device_id, its_id, lpi_int_id + instance, msi_index)
          != ACS_STATUS_PASS) {
          val_set_status(pe_index, "FAIL", 23);
          return;
      }


      /* Disable error reporting of Exerciser and upstream Root Port */
      val_pcie_disable_eru(e_bdf);
      val_pcie_disable_eru(erp_bdf);

    }

  /* No exerciser had a usable Root Port and MSI address configuration. */
  if (test_skip == 1)
      val_set_status(pe_index, "SKIP", 4);
  else
      val_set_status(pe_index, "PASS", 01);

  return;

}

uint32_t
da_autonomous_rootport_request_ns_pas_entry(uint32_t num_pe)
{

  num_pe = 1;
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
