/** @file
 * Copyright (c) 2023-2024, 2026, Arm Limited or its affiliates. All rights reserved.
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
#include "val/include/val.h"
#include "val/include/val_interface.h"

#include "val/include/val_pcie_enumeration.h"
#include "val/include/val_pcie.h"
#include "val/include/val_iovirt.h"
#include "val/include/val_smmu.h"
#include "val/include/val_memory.h"
#include "val/include/val_exerciser.h"
#include "val/include/val_gic.h"
#include "val/include/val_gic_support.h"
#include "val/include/val_exerciser.h"
#include "val/include/val_el32.h"
#include "val/sys_arch_src/gic/its/val_gic_its.h"

#define TEST_NAME "gic_its_subjected_to_gpc_check"
#define TEST_DESC  "Check ITS table accesses are subject to PAS protection "
#define TEST_RULE  "RMZJXC"

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

  val_print(ACS_PRINT_INFO, " Received the interrupt %x       ", active_int_id);
  val_gic_end_of_interrupt(active_int_id);
  return;
}

/**
 * @brief Validate PAS protection for ITS table accesses (RMZJXC).
 * Allocate a device ITT and mark the selected EventID's ITT granule
 * Non-secure before requesting MSI. An endpoint MSI must deliver an LPI; a PE write to the
 * ITS TRANSLATER must not deliver that device's LPI.
 * Remove the mapping, allocate a fresh ITT, and mark the selected ITT granule
 * Non-secure while setting up a fresh ITS mapping, then mark the selected
 * ITT granule Root before programming and triggering MSI. Neither trigger may deliver an LPI.
 * Restore the selected granule to Non-secure before removing the mapping.
 *
 * The test assumes all GPC checks in the system use the same GPT tables.
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
    uint32_t num_exercisers;
    uint32_t test_skip = 1;
    uint32_t msi_index = 0;
    uint32_t msi_cap_offset = 0;

    uint32_t device_id = 0;
    uint32_t stream_id = 0;
    uint32_t its_id = 0;
    uint32_t its_index;
    ITS_CACHE_STATE its_cache_state;
    uint64_t its_base = 0, itt_base, itt_entry_pa, itt_entry_offset;
    uint32_t itt_size, itt_entry_size;

    if (val_pcie_get_info(PCIE_INFO_NUM_ECAM, 0) == 0) {
        val_print(ACS_PRINT_WARN, " No PCIe ECAM regions discovered", 0);
        val_set_status(index, "SKIP", 1);
        return;
    }

    /* Create the list of valid Pcie Device Functions */
    if (val_pcie_create_device_bdf_table()) {
        val_print(ACS_PRINT_WARN, "Create BDF Table Failed ", 0);
        val_set_status(index, "SKIP", 2);
        return;
    }

    if (val_gic_get_info(GIC_INFO_NUM_ITS) == 0) {
        val_print(ACS_PRINT_WARN, " No ITS, Skipping Test.", 0);
        val_set_status(index, "SKIP", 3);
        return;
    }

    val_exerciser_create_info_table();
    num_exercisers = val_exerciser_get_info(EXERCISER_NUM_CARDS);
    if (num_exercisers == 0) {
        val_print(ACS_PRINT_WARN, " No exerciser cards discovered", 0);
        val_set_status(index, "SKIP", 4);
        return;
    }

    for (instance = 0; instance < num_exercisers; ++instance) {
        if (val_exerciser_init(instance)) {
            val_print(ACS_PRINT_WARN, " Exerciser init failed for instance %d", instance);
            continue;
        }

        /* Get the exerciser BDF */
        e_bdf = val_exerciser_get_bdf(instance);

        /* Search for MSI-X Capability */
        if (val_pcie_find_capability(e_bdf, PCIE_CAP, CID_MSIX, &msi_cap_offset)) {
            val_print(ACS_PRINT_WARN, " No MSI-X Capability for BDF 0x%x", e_bdf);
            continue;
        }

        test_skip = 0;
        break;
    }

    if (test_skip) {
        val_print(ACS_PRINT_WARN, " No usable exerciser with MSI-X capability found", 0);
        val_set_status(index, "SKIP", 5);
        return;
    }

    /* Get DeviceID & ITS_ID for this device */
    status = val_iovirt_get_device_info(PCIE_CREATE_BDF_PACKED(e_bdf),
                                        PCIE_EXTRACT_BDF_SEG(e_bdf), &device_id,
                                        &stream_id, &its_id);

    val_print(ACS_PRINT_DEBUG, " device_id: 0x%lx", device_id);
    val_print(ACS_PRINT_DEBUG, " its_id: 0x%lx", its_id);
    if (status) {
        val_print(ACS_PRINT_ERR, " MSI Assignment failed for bdf : 0x%x", e_bdf);
        val_set_status(index, "FAIL", 1);
        return;
    }

    its_index = val_gic_get_its_index(its_id);
    if (its_index == ACS_INVALID_INDEX) {
        val_print(ACS_PRINT_ERR, " Could not find ITS ID [%x]", its_id);
        val_set_status(index, "FAIL", 2);
        return;
    }

    itt_entry_size = ARM_GITS_TYPER_ITTEntrySize(val_mmio_read64(
        g_gic_its_info->GicIts[its_index].Base + ARM_GITS_TYPER)) + 1;
    /* EventID indexes the ITT (IHI0069H.b, section 5.2.4). */
    itt_entry_offset = (uint64_t)(lpi_int_id + instance) * itt_entry_size;

    status = val_gic_its_alloc_device_itt(its_index, device_id);
    if (status) {
        val_print(ACS_PRINT_ERR, " Could not allocate device ITT", 0);
        val_set_status(index, "FAIL", 3);
        return;
    }

    itt_base = val_gic_its_get_itt_base(its_index, device_id);
    itt_size = val_gic_its_get_itt_size(its_index, device_id);
    if ((itt_base == 0) || (itt_size == 0)) {
        val_print(ACS_PRINT_ERR, " Could not find device ITT", 0);
        val_set_status(index, "FAIL", 4);
        return;
    }
    if ((itt_entry_offset >= itt_size) ||
        (itt_entry_size > itt_size - itt_entry_offset)) {
        val_print(ACS_PRINT_ERR, " EventID entry exceeds allocated ITT", 0);
        val_set_status(index, "FAIL", 5);
        return;
    }
    itt_entry_pa = itt_base + itt_entry_offset;
    if ((itt_entry_pa & (SIZE_4KB - 1)) + itt_entry_size > SIZE_4KB) {
        val_print(ACS_PRINT_WARN, " ITT entry crosses a 4KB page", 0);
        val_set_status(index, "SKIP", 6);
        return;
    }
    val_print(ACS_PRINT_INFO, " itt_base: 0x%lx", itt_base);
    if (val_add_gpt_entry_el3(itt_entry_pa, GPT_NONSECURE))
    {
        val_print(ACS_PRINT_ERR, " Failed to add GPT entry for PA 0x%llx", itt_entry_pa);
        val_set_status(index, "FAIL", 6);
        return;
    }


    val_print(ACS_PRINT_INFO, " Selected ITT entry is mapped as Non-secure in GPT ", 0);

    active_int_id = lpi_int_id + instance;
    status = val_gic_install_isr(active_int_id, intr_handler);

    if (status) {
        val_print(ACS_PRINT_ERR, " Intr handler registration failed for Interrupt : 0x%x",
                  lpi_int_id);
        val_set_status(index, "FAIL", 7);
        return;
    }

    status = val_gic_its_create_lpi_map(its_index, device_id,
                                     lpi_int_id + instance, LPI_PRIORITY1);
    if (status != ACS_STATUS_PASS) {
        val_print(ACS_PRINT_ERR, " ITS mapping setup failed for DeviceID 0x%x", device_id);
        val_set_status(index, "FAIL", 8);
        return;
    }

    status = val_gic_request_msi(e_bdf, device_id, its_id, lpi_int_id + instance, msi_index);
    if (status) {
        val_print(ACS_PRINT_ERR, " MSI Assignment failed for bdf : 0x%x", e_bdf);
        val_set_status(index, "FAIL", 9);
        val_gic_free_msi(e_bdf, device_id, its_id, lpi_int_id + instance, msi_index);
        return;
    }

    /* Set the interrupt trigger status to pending */
    irq_pending = 1;

    /* Get ITS Base for current ITS */
    if (val_gic_its_get_base(its_id, &its_base)) {
        val_print(ACS_PRINT_ERR, " Could not find ITS Base for its_id : 0x%x", its_id);
        val_set_status(index, "FAIL", 10);
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
        val_set_status(index, "FAIL", 11);
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
        val_set_status(index, "FAIL", 12);
        val_gic_free_msi(e_bdf, device_id, its_id, lpi_int_id + instance, msi_index);
        return;
    }

    /* Clear Interrupt and Mappings */
    /* Stop if teardown timed out; ITS still owns the retained mapping. */
    if (val_gic_free_msi(e_bdf, device_id, its_id, lpi_int_id + instance, msi_index)
        != ACS_STATUS_PASS) {
        val_set_status(index, "FAIL", 13);
        return;
    }

    status = val_gic_its_alloc_device_itt(its_index, device_id);
    if (status) {
        val_print(ACS_PRINT_ERR, " Could not allocate device ITT", 0);
        val_set_status(index, "FAIL", 14);
        return;
    }

    /* Use a fresh device ITT for the negative phase. Complete its mapping
     * while Non-secure so the Root check is exercised by the interrupt trigger.
     */
    itt_base = val_gic_its_get_itt_base(its_index, device_id);
    itt_size = val_gic_its_get_itt_size(its_index, device_id);
    if ((itt_base == 0) || (itt_size == 0)) {
        val_print(ACS_PRINT_ERR, " Could not find device ITT", 0);
        val_set_status(index, "FAIL", 15);
        return;
    }
    if ((itt_entry_offset >= itt_size) ||
        (itt_entry_size > itt_size - itt_entry_offset)) {
        val_print(ACS_PRINT_ERR, " EventID entry exceeds allocated ITT", 0);
        val_set_status(index, "FAIL", 16);
        return;
    }
    itt_entry_pa = itt_base + itt_entry_offset;
    if ((itt_entry_pa & (SIZE_4KB - 1)) + itt_entry_size > SIZE_4KB) {
        val_print(ACS_PRINT_WARN, " ITT entry crosses a 4KB page", 0);
        val_set_status(index, "SKIP", 7);
        return;
    }
    val_print(ACS_PRINT_TEST, " Setting up ITS mapping with Non-secure ITT ", 0);
    status = val_gic_its_create_lpi_map(its_index, device_id,
                                     lpi_int_id + instance, LPI_PRIORITY1);
    if (status != ACS_STATUS_PASS) {
        val_print(ACS_PRINT_ERR, " ITS mapping setup failed for DeviceID 0x%x", device_id);
        val_set_status(index, "FAIL", 17);
        return;
    }

    /* Keep ITS stopped across the PAS change to prevent cache refills. */
    status = val_gic_its_invalidate_cache_and_suspend(its_index, &its_cache_state);
    if (status != ACS_STATUS_PASS) {
        if (status == ACS_STATUS_SKIP) {
            if (val_gic_free_msi(e_bdf, device_id, its_id,
                             lpi_int_id + instance, msi_index) != ACS_STATUS_PASS) {
                val_set_status(index, "FAIL", 18);
                return;
            }
            val_set_status(index, "SKIP", 8);
        } else {
            /* ITS may still reference the ITT; retain its allocation on error. */
            val_set_status(index, "FAIL", 19);
        }
        return;
    }

    if (val_add_gpt_entry_el3(itt_entry_pa, GPT_ROOT))
    {
        val_print(ACS_PRINT_ERR, " Failed to add GPT entry for PA 0x%llx", itt_entry_pa);
        val_set_status(index, "FAIL", 20);

        /* Resume ITS before cleanup submits commands or releases the ITT. */
        if (val_gic_its_resume_after_pas_change(its_index, &its_cache_state) == ACS_STATUS_PASS)
            val_gic_free_msi(e_bdf, device_id, its_id, lpi_int_id + instance, msi_index);
        return;
    }

    /* GPT maintenance is complete; resume without recreating the ITS mapping. */
    if (val_gic_its_resume_after_pas_change(its_index, &its_cache_state) != ACS_STATUS_PASS) {
        val_set_status(index, "FAIL", 21);

        /* Restore PAS, but retain memory if ITS state could not be restored. */
        val_add_gpt_entry_el3(itt_entry_pa, GPT_NONSECURE);
        return;
    }

    val_print(ACS_PRINT_INFO, " Selected ITT entry is mapped as Root PAS in GPT ", 0);

    /* Program PCIe MSI without resubmitting ITS commands against the Root ITT. */
    status = val_gic_request_msi(e_bdf, device_id, its_id, lpi_int_id + instance, msi_index);
    if (status) {
        val_print(ACS_PRINT_ERR, " MSI Assignment failed for bdf : 0x%x", e_bdf);
        val_set_status(index, "FAIL", 22);
        if (val_add_gpt_entry_el3(itt_entry_pa, GPT_NONSECURE))
            return;
        val_gic_free_msi(e_bdf, device_id, its_id, lpi_int_id + instance, msi_index);
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
        val_set_status(index, "FAIL", 23);
        if (val_add_gpt_entry_el3(itt_entry_pa, GPT_NONSECURE))
            return;
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
        val_set_status(index, "FAIL", 24);
        if (val_add_gpt_entry_el3(itt_entry_pa, GPT_NONSECURE))
            return;
        val_gic_free_msi(e_bdf, device_id, its_id, lpi_int_id + instance, msi_index);
        return;
    }

    /* Restore the selected ITT granule before unmapping and releasing its memory. */
    if (val_add_gpt_entry_el3(itt_entry_pa, GPT_NONSECURE)) {
        val_set_status(index, "FAIL", 25);
        return;
    }
    /* Stop if teardown timed out; ITS still owns the retained mapping. */
    if (val_gic_free_msi(e_bdf, device_id, its_id, lpi_int_id + instance, msi_index)
        != ACS_STATUS_PASS) {
        val_set_status(index, "FAIL", 26);
        return;
    }

    if (test_skip) {
      val_set_status(index, "SKIP", 9);
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

