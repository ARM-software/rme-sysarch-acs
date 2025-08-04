/** @file
 * Copyright (c) 2023-2024, 2025, Arm Limited or its affiliates. All rights reserved.
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

#include "val/include/rme_acs_pcie_enumeration.h"
#include "val/include/rme_acs_pcie.h"
#include "val/include/rme_acs_iovirt.h"
#include "val/include/rme_acs_smmu.h"
#include "val/include/rme_acs_memory.h"
#include "val/include/rme_acs_exerciser.h"
#include "val/include/rme_acs_gic.h"
#include "val/include/rme_acs_gic_support.h"
#include "val/include/rme_acs_exerciser.h"
#include "val/include/rme_acs_el32.h"
#include "val/sys_arch_src/gic/its/rme_gic_its.h"

#define TEST_NAME "gic_its_subjected_to_gpc_check"
#define TEST_DESC  "To check if GIC ITS mem accesses are only to NS memory "
#define TEST_RULE  "RNULL"

static uint32_t irq_pending;
static uint32_t lpi_int_id = 0x204c;

extern GIC_ITS_INFO    *g_gic_its_info;

static
void
intr_handler(void)
{
  /* Clear the interrupt pending state */
  irq_pending = 0;

  val_print(ACS_PRINT_INFO, " Received the interrupt %x       ", lpi_int_id);
  val_gic_end_of_interrupt(lpi_int_id);
  return;
}

/**
 * @brief The test validates that the ITS access is always Non-secure in nature.
 * 1. The Exerciser is initialised by setting command register for Memory Space Enable and
 *    Bus Master Enable.
 * 2. GIC ITS is configured by initialising ITS along with CommandQueue, Device and
 *    collection Tables by writing to the registers like, GITS_BASER<n>, GITS_CBASER, etc.,
 * 3. An exerciser BDF is selected based on the first instance, and ITS id, ITT base and
 *    table mapping for MSI are generated for this particular exerciser Instance.
 * 4. ISR for lpi_int_id is installed for this instance.
 * 5. Program ITT base address as Nonsecure PAS in GPT table.
 * 6. An LPI is generatedd successfully.
 * 7. The ITT base is now programmed as ROOT resource pas in GPT Table and
 *    the steps 3 and 4 are repeated.
 * 8. The LPI should not be generated, setting the test result to PASS otherwise FAIL.
 *
 * Note: Test assume that all GPC checks in the system are using same GPT tables.
 **/
static
void
payload(void)
{

    uint32_t index = val_pe_get_index_mpid(val_pe_get_mpid());
    uint32_t e_bdf = 0;
    uint32_t timeout;
    uint32_t status;
    uint32_t instance;
    uint32_t test_skip = 1;
    uint32_t msi_index = 0;
    uint32_t msi_cap_offset = 0;

    uint32_t device_id = 0;
    uint32_t stream_id = 0;
    uint32_t its_id = 0;
    uint64_t its_base = 0, itt_base;

    /* Create the list of valid Pcie Device Functions */
    if (val_pcie_create_device_bdf_table()) {
        val_print(ACS_PRINT_WARN, " Create BDF Table Failed...", 0);
        return;
    }

    if (val_gic_get_info(GIC_INFO_NUM_ITS) == 0) {
        val_print(ACS_PRINT_ERR, " No ITS, Skipping Test.", 0);
        val_set_status(index, "SKIP", 1);
        return;
    }

    val_exerciser_create_info_table();

    instance = 0;

    if (val_exerciser_init(instance))
        return;

    /* Get the exerciser BDF */
    e_bdf = val_exerciser_get_bdf(instance);

    /* Search for MSI-X Capability */
    if (val_pcie_find_capability(e_bdf, PCIE_CAP, CID_MSIX, &msi_cap_offset)) {
        val_print(ACS_PRINT_ERR, " No MSI-X Capability, Skipping for 0x%x", e_bdf);
        return;
    }

    test_skip = 0;

    /* Get DeviceID & ITS_ID for this device */
    status = val_iovirt_get_device_info(PCIE_CREATE_BDF_PACKED(e_bdf),
                                        PCIE_EXTRACT_BDF_SEG(e_bdf), &device_id,
                                        &stream_id, &its_id);

    val_print(ACS_PRINT_DEBUG, " device_id: 0x%lx", device_id);
    val_print(ACS_PRINT_DEBUG, " its_id: 0x%lx", its_id);
    if (status) {
        val_print(ACS_PRINT_ERR, " MSI Assignment failed for bdf : 0x%x", e_bdf);
        val_set_status(index, "FAIL", 01);
        return;
    }

    itt_base = g_gic_its_info->GicIts[its_id].ITTBase;
    val_print(ACS_PRINT_INFO, " itt_base: 0x%lx", itt_base);
    if (val_add_gpt_entry_el3(itt_base, GPT_NONSECURE))
    {
        val_print(ACS_PRINT_ERR, " Failed to add GPT entry for PA 0x%llx", itt_base);
        val_set_status(index, "FAIL", 2);
        return;
    }

    val_print(ACS_PRINT_INFO, " ITT base is mapped as Non-secure in GPT ", 0);
    status = val_gic_request_msi(e_bdf, device_id, its_id, lpi_int_id + instance, msi_index);
    if (status) {
        val_print(ACS_PRINT_ERR, " MSI Assignment failed for bdf : 0x%x", e_bdf);
        val_set_status(index, "FAIL", 3);
        return;
    }

    status = val_gic_install_isr(lpi_int_id + instance, intr_handler);

    if (status) {
        val_print(ACS_PRINT_ERR, " Intr handler registration failed for Interrupt : 0x%x",
                  lpi_int_id);
        val_set_status(index, "FAIL", 4);
        return;
    }

    /* Set the interrupt trigger status to pending */
    irq_pending = 1;

    /* Get ITS Base for current ITS */
    if (val_gic_its_get_base(its_id, &its_base)) {
        val_print(ACS_PRINT_ERR, " Could not find ITS Base for its_id : 0x%x", its_id);
        val_set_status(index, "FAIL", 5);
        return;
    }

    /* Part 1 : ITS_DEV_6 */
    /* Trigger the interrupt by writing to GITS_TRANSLATER from PE */
    val_mmio_write(its_base + GITS_TRANSLATER, lpi_int_id + instance);

    /* PE busy polls to check the completion of interrupt service routine */
    timeout = TIMEOUT_MEDIUM;
    while ((--timeout > 0) && irq_pending)
        {};

    /* Interrupt should not be generated */
    if (irq_pending == 0) {
        val_print(ACS_PRINT_ERR, " Interrupt triggered from PE for bdf : 0x%x, ", e_bdf);
        val_set_status(index, "FAIL", 6);
        val_gic_free_msi(e_bdf, device_id, its_id, lpi_int_id + instance, msi_index);
        return;
    }

    /* Part 2: PCI_MSI_2 */
    /* Trigger the interrupt for this Exerciser instance */
    val_print(ACS_PRINT_TEST, " Triggering interrupt for Non-Secure ITT ", 0);

    val_exerciser_ops(GENERATE_MSI, msi_index, instance);

    /* PE busy polls to check the completion of interrupt service routine */
    timeout = TIMEOUT_LARGE;
    while ((--timeout > 0) && irq_pending)
        {};

    if (timeout == 0) {
        val_print(ACS_PRINT_ERR, " Interrupt trigger failed for : 0x%x, ", lpi_int_id);
        val_print(ACS_PRINT_ERR, " BDF : 0x%x   ", e_bdf);
        val_set_status(index, "FAIL", 07);
        val_gic_free_msi(e_bdf, device_id, its_id, lpi_int_id + instance, msi_index);
        return;
    }

    /* Clear Interrupt and Mappings */
    val_gic_free_msi(e_bdf, device_id, its_id, lpi_int_id + instance, msi_index);

    status = val_gic_request_msi(e_bdf, device_id, its_id, lpi_int_id + instance, msi_index);
    if (status) {
        val_print(ACS_PRINT_ERR, " MSI Assignment failed for bdf : 0x%x", e_bdf);
        val_set_status(index, "FAIL", 8);
        return;
    }

    /**
     * Program one of the ITT bases with secure, Root or Realm PA
     * and expect a fault when GIC tries to access it
    **/
    itt_base = g_gic_its_info->GicIts[its_id].ITTBase;
    if (val_add_gpt_entry_el3(itt_base, GPT_ROOT))
    {
        val_print(ACS_PRINT_ERR, " Failed to add GPT entry for PA 0x%llx", itt_base);
        val_set_status(index, "FAIL", 9);
        return;
    }
    val_print(ACS_PRINT_INFO, " ITT base is mapped as Root PAS in GPT ", 0);

    status = val_gic_install_isr(lpi_int_id + instance, intr_handler);

    if (status) {
        val_print(ACS_PRINT_ERR, " Intr handler registration failed for Interrupt : 0x%x",
                  lpi_int_id);
        val_set_status(index, "FAIL", 10);
        return;
    }

    /* Set the interrupt trigger status to pending */
    irq_pending = 1;

    /* Part 1 : ITS_DEV_6 */
    /* Trigger the interrupt by writing to GITS_TRANSLATER from PE */
    val_mmio_write(its_base + GITS_TRANSLATER, lpi_int_id + instance);

    /* PE busy polls to check the completion of interrupt service routine */
    timeout = TIMEOUT_MEDIUM;
    while ((--timeout > 0) && irq_pending)
      {};

    /* Interrupt should not be generated */
    if (irq_pending == 0) {
        val_print(ACS_PRINT_ERR, " Interrupt triggered from PE for bdf : 0x%x, ", e_bdf);
        val_set_status(index, "FAIL", 11);
        val_add_gpt_entry_el3(itt_base, GPT_NONSECURE);
        val_gic_free_msi(e_bdf, device_id, its_id, lpi_int_id + instance, msi_index);
        return;
    }

    /* Part 2: PCI_MSI_2 */
    /* Trigger the interrupt for this Exerciser instance */
    val_print(ACS_PRINT_TEST, " Triggering interrupt for Root ITT ", 0);
    val_exerciser_ops(GENERATE_MSI, msi_index, instance);

    /* PE busy polls to check the completion of interrupt service routine */
    timeout = TIMEOUT_LARGE;
    while ((--timeout > 0) && irq_pending)
        {};

    if (irq_pending == 0) {
        val_print(ACS_PRINT_ERR, " Interrupt triggered for Root ITS access", 0);
        val_print(ACS_PRINT_ERR, " BDF : 0x%x ", e_bdf);
        val_set_status(index, "FAIL", 12);
        val_add_gpt_entry_el3(itt_base, GPT_NONSECURE);
        val_gic_free_msi(e_bdf, device_id, its_id, lpi_int_id + instance, msi_index);
        return;
    }

    /* Clear Interrupt and Mappings and revert back the ITT_BASE to it's original PA space */
    val_add_gpt_entry_el3(itt_base, GPT_NONSECURE);
    val_gic_free_msi(e_bdf, device_id, its_id, lpi_int_id + instance, msi_index);

    if (test_skip) {
      val_set_status(index, "SKIP", 2);
      return;
    }

    /* Pass Test */
    val_set_status(index, "PASS", 01);

}


uint32_t
gic_its_subjected_to_gpc_check_entry(uint32_t num_pe)
{

  num_pe = 1;
  uint32_t status = ACS_STATUS_FAIL;

  status = val_initialize_test(TEST_NAME, TEST_DESC, num_pe, TEST_RULE);

  if (status != ACS_STATUS_SKIP)
      val_run_test_payload(num_pe, payload, 0);

  status = val_check_for_error(num_pe);

  val_report_status(0, "END");

  return status;
}

