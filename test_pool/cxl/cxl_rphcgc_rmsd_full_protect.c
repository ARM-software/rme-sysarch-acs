/** @file
 * Copyright (c) 2026, Arm Limited or its affiliates. All rights reserved.
 * SPDX-License-Identifier : Apache-2.0
 *
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
#include "val/include/val_cxl.h"
#include "val/include/val_da.h"

#define TEST_NAME "cxl_rphcgc_rmsd_full_protect_property"
#define TEST_DESC "Check CXL RP RMSD full-protect registers            "
#define TEST_RULE "RPHCGC"

static
uint32_t
is_cxl_root_port(uint32_t bdf, uint32_t component_count)
{
  for (uint32_t index = 0; index < component_count; ++index)
  {
    uint32_t role = (uint32_t)val_cxl_get_component_info(
      CXL_COMPONENT_INFO_ROLE,
      index);
    uint32_t comp_bdf = (uint32_t)val_cxl_get_component_info(
      CXL_COMPONENT_INFO_BDF_INDEX,
      index);

    if ((role == CXL_COMPONENT_ROLE_ROOT_PORT) && (comp_bdf == bdf))
      return 1u;
  }

  return 0u;
}

static
void
payload(void)
{
  uint32_t pe_index = val_pe_get_index_mpid(val_pe_get_mpid());
  uint32_t table_entries;
  uint32_t component_count;
  uint32_t test_skip = 1;
  uint32_t test_fail = 0;
  REGISTER_INFO_TABLE *register_tbl_ptr;

  /* Skip when the platform does not advertise coherent DA support. */
  if (val_is_coherent_da_supported() == 0u)
  {
    val_print(ACS_PRINT_DEBUG,
              " Platform lacks coherent DA support - skipping",
              0);
    val_set_status(pe_index, "SKIP", 01);
    return;
  }

  /* Discover CXL root ports from the component table. */
  component_count = (uint32_t)val_cxl_get_component_info(
    CXL_COMPONENT_INFO_COUNT,
    0);
  if (component_count == 0u)
  {
    val_print(ACS_PRINT_DEBUG,
              " No CXL components discovered - skipping",
              0);
    val_set_status(pe_index, "SKIP", 02);
    return;
  }

  /* Enumerate platform-provided RMSD full-protect registers. */
  table_entries = val_register_get_num_entries();
  register_tbl_ptr = val_register_table_ptr();
  val_print(ACS_PRINT_TEST, " table entries: %d", table_entries);

  for (uint32_t index = 0; index < table_entries; index++)
  {
    REGISTER_INFO_TABLE *register_entry = register_tbl_ptr + index;

    if (register_entry->type != PCIE_RP)
      continue;

    if (register_entry->property != RMSD_FULL_PROTECT)
      continue;

    if (is_cxl_root_port(register_entry->bdf, component_count) == 0u)
      continue;

    test_skip = 0;
    val_print(ACS_PRINT_TEST,
              " Checking CXL RP BDF: 0x%x",
              register_entry->bdf);

    if (val_pcie_rp_sec_prpty_check((void *)register_entry))
      test_fail++;
  }

  /* Report per-PE result based on register checks. */
  if (test_skip)
    val_set_status(pe_index, "SKIP", 03);
  else if (test_fail)
    val_set_status(pe_index, "FAIL", test_fail);
  else
    val_set_status(pe_index, "PASS", 01);
}

uint32_t
cxl_rphcgc_rmsd_full_protect_entry(uint32_t num_pe)
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
