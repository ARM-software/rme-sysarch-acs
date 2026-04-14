/** @file
 * Copyright (c) 2026, Arm Limited or its affiliates. All rights reserved.
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
#include "val/include/val_pcie.h"
#include "val/include/val_pcie_spec.h"
#include "val/include/val_cxl.h"
#include "val/include/val_cxl_spec.h"
#include "val/include/val_el32.h"
#include "val/include/val_memory.h"
#include "val/include/val_pe.h"

#define TEST_NAME "cxl_rdhwnr_link_stream_lock"
#define TEST_DESC "Validate CXL IDE registers respect LINK_STR_LOCK     "
#define TEST_RULE "RDHNWR"

#define RMECDA_CTL1_LINK_STR_LOCK_MASK   (1u << 1)
#define CXL_IDE_CONTROL_PCRC_DISABLE_BIT (1u << 0)

/* Wrapper for Root/EL3 writes*/
static int
write_from_root(uint64_t address, uint32_t data)
{
  shared_data->num_access = 1;
  shared_data->shared_data_access[0].addr = address;
  shared_data->shared_data_access[0].data = data;
  shared_data->shared_data_access[0].access_type = WRITE_DATA;

  if (val_pe_access_mut_el3())
  {
    val_print(ACS_PRINT_ERR, " MUT Access failed for 0x%llx", address);
    return 1;
  }

  return 0;
}

static uint32_t
verify_link_lock(uint32_t component_index, uint64_t rmecda_cap_base, uint64_t ide_cap_base)
{
  uint32_t result = ACS_STATUS_PASS;
  uint32_t bdf;
  uint32_t ctl1_original = 0;
  uint32_t ctl1_unlocked = 0;
  uint32_t ctl1_locked = 0;
  uint32_t ctl1_readback;
  uint64_t cfg_addr;
  uint64_t cfg_va;
  uint64_t ide_control_addr = 0;
  uint32_t control_original = 0;
  uint32_t control_toggle = 0;
  uint32_t control_after;
  uint32_t attr;
  uint64_t tg;

  bdf = (uint32_t)val_cxl_get_component_info(CXL_COMPONENT_INFO_BDF_INDEX,
                                             component_index);


  /* Get configuration address for the BDF*/
  cfg_addr = val_pcie_get_bdf_config_addr(bdf);
  tg = val_get_min_tg();
  if (tg == 0u)
  {
    val_print(ACS_PRINT_ERR, " Invalid translation granule size", 0);
    return ACS_STATUS_ERR;
  }

  cfg_va = val_get_free_va(tg);
  if (cfg_va == 0u)
  {
    val_print(ACS_PRINT_ERR, " Failed to allocate VA for cfg space", 0);
    return ACS_STATUS_ERR;
  }

  /* Map the configuration region at EL3 */
  attr = LOWER_ATTRS(PGT_ENTRY_ACCESS | SHAREABLE_ATTR(OUTER_SHAREABLE) |
                     GET_ATTR_INDEX(DEV_MEM_nGnRnE) | PGT_ENTRY_AP_RW |
                     PAS_ATTR(ROOT_PAS));
  if (val_add_mmu_entry_el3(cfg_va, cfg_addr, attr))
  {
    val_print(ACS_PRINT_ERR, " MMU map failed for cfg_addr 0x%llx", cfg_addr);
    return ACS_STATUS_ERR;
  }

  /* Read the original value of RMECDA_CTL1*/
  if (val_pcie_read_cfg(bdf,
                        rmecda_cap_base + RMECDA_CTL1_OFFSET,
                        &ctl1_original))
  {
    val_print(ACS_PRINT_ERR,
              " Failed to read RMECDA_CTL1 for BDF 0x%x",
              (uint64_t)bdf);
    return ACS_STATUS_ERR;
  }

  /* Reset RMECDA_CTL1.LINK_STR_LOCK bit*/
  ctl1_unlocked = ctl1_original & ~RMECDA_CTL1_LINK_STR_LOCK_MASK;
  if (write_from_root(cfg_va + rmecda_cap_base + RMECDA_CTL1_OFFSET,
                      ctl1_unlocked))
  {
    val_print(ACS_PRINT_ERR,
              " Unable to clear LINK_STR_LOCK for BDF 0x%x",
              (uint64_t)bdf);
    result = ACS_STATUS_FAIL;
    goto restore_control;
  }

  /* Verify RMECDA_CTL1.LINK_STR_LOCK is cleared */
  if (val_pcie_read_cfg(bdf,
                        rmecda_cap_base + RMECDA_CTL1_OFFSET,
                        &ctl1_readback) ||
      ((ctl1_readback & RMECDA_CTL1_LINK_STR_LOCK_MASK) != 0u))
  {
    val_print(ACS_PRINT_ERR,
              " LINK_STR_LOCK not cleared for BDF 0x%x",
              (uint64_t)bdf);
    result = ACS_STATUS_FAIL;
    goto restore_control;
  }

  /* Validate IDE capability structure has no security porperty*/
  ide_control_addr = ide_cap_base + CXL_IDE_REG_CONTROL;
  control_original = val_mmio_read(ide_control_addr);
  control_toggle = control_original ^ CXL_IDE_CONTROL_PCRC_DISABLE_BIT;

  val_mmio_write(ide_control_addr, control_toggle);
  control_after = val_mmio_read(ide_control_addr);
  if (control_after != control_toggle)
  {
    val_print(ACS_PRINT_ERR,
              " IDE Control write ignored in unlocked state (BDF 0x%x)",
              (uint64_t)bdf);
    result = ACS_STATUS_FAIL;
    goto restore_control;
  }

  /* Restore original control value before locking */
  val_mmio_write(ide_control_addr, control_original);

  /* Set RMECDA_CTL1.LINK_STR_LOCK bit*/
  ctl1_locked = ctl1_unlocked | RMECDA_CTL1_LINK_STR_LOCK_MASK;
  if (write_from_root(cfg_va + rmecda_cap_base + RMECDA_CTL1_OFFSET,
                      ctl1_locked))
  {
    val_print(ACS_PRINT_ERR,
              " Unable to set LINK_STR_LOCK for BDF 0x%x",
              (uint64_t)bdf);
    result = ACS_STATUS_FAIL;
    goto restore_control;
  }

  /* Verify that RMECDA_CTL1.LINK_STR_LOCK is set */
  if (val_pcie_read_cfg(bdf,
                        rmecda_cap_base + RMECDA_CTL1_OFFSET,
                        &ctl1_readback) ||
      ((ctl1_readback & RMECDA_CTL1_LINK_STR_LOCK_MASK) == 0u))
  {
    val_print(ACS_PRINT_ERR,
              " LINK_STR_LOCK refused to set for BDF 0x%x",
              (uint64_t)bdf);
    result = ACS_STATUS_FAIL;
    goto restore_control;
  }

  /* Check that IDE configuaration registers are RMSD wirte protect */
  val_mmio_write(ide_control_addr, control_toggle);
  control_after = val_mmio_read(ide_control_addr);
  if (control_after != control_original)
  {
    val_print(ACS_PRINT_ERR,
              " IDE Control changed while locked (BDF 0x%x)",
              (uint64_t)bdf);
    result = ACS_STATUS_FAIL;
  }

restore_control:
  if (ide_control_addr != 0u)
    val_mmio_write(ide_control_addr, control_original);

  if (write_from_root(cfg_va + rmecda_cap_base + RMECDA_CTL1_OFFSET,
                      ctl1_original))
  {
    val_print(ACS_PRINT_WARN,
              " Failed to restore RMECDA_CTL1 for BDF 0x%x",
              (uint64_t)bdf);
  }

  return result;
}

static void
payload(void)
{
  uint32_t pe_index = val_pe_get_index_mpid(val_pe_get_mpid());
  CXL_COMPONENT_TABLE *table = val_cxl_component_table_ptr();
  uint64_t comp_base;
  uint32_t executed = 0;
  uint32_t failures = 0;
  uint32_t rmecda_cap_base;
  uint64_t ide_cap_base;

  /* Skip if no CXL components discovered*/
  if ((table == NULL) || (table->num_entries == 0u))
  {
    val_print(ACS_PRINT_DEBUG, " No CXL components discovered", 0);
    val_set_status(pe_index, "SKIP", 01);
    return;
  }

  /* Iterate through CXL root ports*/
  for (uint32_t idx = 0; idx < table->num_entries; ++idx)
  {
    uint32_t role = (uint32_t)val_cxl_get_component_info(CXL_COMPONENT_INFO_ROLE, idx);
    uint32_t bdf = (uint32_t)val_cxl_get_component_info(CXL_COMPONENT_INFO_BDF_INDEX, idx);

    if (role != CXL_COMPONENT_ROLE_ROOT_PORT)
      continue;

    /* Check if Root port supports CXL-IDE*/
    comp_base = val_cxl_get_component_info(CXL_COMPONENT_INFO_COMPONENT_BASE, idx);
    if (val_cxl_find_capability(comp_base, CXL_CAPID_IDE, &ide_cap_base) != ACS_STATUS_PASS)
    {
      val_print(ACS_PRINT_INFO,
                " Root Port 0x%x missing CXL IDE capability - skip",
                (uint64_t)bdf);
      continue;
    }

    /* Skip if the root port does not support RME-CDA DVSEC*/
    if (val_pcie_find_cda_capability(bdf, &rmecda_cap_base) != PCIE_SUCCESS)
    {
      val_print(ACS_PRINT_INFO,
              " Skipping BDF 0x%x - RME-CDA DVSEC absent", (uint64_t)bdf);
      continue;
    }

    executed++;
    val_print(ACS_PRINT_TEST, " Checking Root Port BDF: 0x%x", (uint64_t)bdf);

    /* Verify the RDHWNR Rule */
    if (verify_link_lock(idx, rmecda_cap_base, ide_cap_base) != ACS_STATUS_PASS)
      failures++;
  }

  if (executed == 0u)
    val_set_status(pe_index, "SKIP", 02);
  else if (failures != 0u)
    val_set_status(pe_index, "FAIL", failures);
  else
    val_set_status(pe_index, "PASS", 01);
}

uint32_t
cxl_rdhwnr_link_stream_lock_entry(uint32_t num_pe)
{
  num_pe = 1;
  uint32_t status;

  status = val_initialize_test(TEST_NAME, TEST_DESC, num_pe, TEST_RULE);

  if (status != ACS_STATUS_SKIP)
    val_run_test_payload(num_pe, payload, 0);

  status = val_check_for_error(num_pe);

  val_report_status(0, "END");

  return status;
}
