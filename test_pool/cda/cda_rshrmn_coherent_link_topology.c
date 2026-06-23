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

#include "val/include/val_cda.h"
#include "val/include/val_cxl.h"
#include "val/include/val_da.h"
#include "val/include/val_pcie.h"
#include "val/include/val_pcie_spec.h"
#include "val/include/val_pe.h"

#define TEST_NAME "cda_rshrmn_coherent_link_topology"
#define TEST_DESC "One coherent device per coherent link topology"
#define TEST_RULE "RSHRMN"

static uint32_t
coherent_device_key(uint32_t bdf)
{
  /*
   * RSHRMN permits a coherent device to include multiple requesters.  In the
   * PCIe/CXL representation used by ACS, those requesters can appear as
   * multiple functions under the same bus/device.  Ignore function number when
   * counting coherent devices attached to one coherent link.
   */
  return bdf & ~0xFFu;
}

static uint32_t
is_first_device_group(const CXL_COMPONENT_TABLE *table,
                      uint32_t candidate_index,
                      uint32_t root_bdf,
                      uint32_t secondary_bus,
                      uint32_t subordinate_bus)
{
  uint32_t candidate_key;

  if ((table == NULL) || (candidate_index >= table->num_entries))
    return 0u;

  candidate_key = coherent_device_key(table->component[candidate_index].bdf);

  for (uint32_t idx = 0u; idx < candidate_index; ++idx)
  {
    const CXL_COMPONENT_ENTRY *entry = &table->component[idx];

    if (val_cda_is_downstream_chi_c2c_endpoint(entry,
                                               root_bdf,
                                               secondary_bus,
                                               subordinate_bus) == 0u)
      continue;

    if (coherent_device_key(entry->bdf) == candidate_key)
      return 0u;
  }

  return 1u;
}

static uint32_t
count_group_functions(const CXL_COMPONENT_TABLE *table,
                      uint32_t root_bdf,
                      uint32_t secondary_bus,
                      uint32_t subordinate_bus,
                      uint32_t device_key)
{
  uint32_t function_count = 0u;

  if (table == NULL)
    return 0u;

  for (uint32_t idx = 0u; idx < table->num_entries; ++idx)
  {
    const CXL_COMPONENT_ENTRY *entry = &table->component[idx];

    if (val_cda_is_downstream_chi_c2c_endpoint(entry,
                                               root_bdf,
                                               secondary_bus,
                                               subordinate_bus) == 0u)
      continue;

    if (coherent_device_key(entry->bdf) == device_key)
      function_count++;
  }

  return function_count;
}

static uint32_t
check_root_port_topology(const CXL_COMPONENT_TABLE *table,
                         const CXL_COMPONENT_ENTRY *root_port)
{
  uint32_t pbn;
  uint32_t secondary_bus;
  uint32_t subordinate_bus;
  uint32_t device_group_count = 0u;
  uint32_t endpoint_function_count = 0u;

  if ((table == NULL) || (root_port == NULL))
    return ACS_STATUS_ERR;

  if (val_pcie_read_cfg(root_port->bdf, TYPE1_PBN, &pbn) != PCIE_SUCCESS)
  {
    val_print(ACS_PRINT_ERR,
              " RSHRMN: failed to read bus numbers for RP 0x%x",
              root_port->bdf);
    return ACS_STATUS_ERR;
  }

  secondary_bus = (pbn >> SECBN_SHIFT) & SECBN_MASK;
  subordinate_bus = (pbn >> SUBBN_SHIFT) & SUBBN_MASK;

  val_print(ACS_PRINT_INFO, " RSHRMN: checking CHI-C2C RP 0x%x",
            root_port->bdf);
  val_print(ACS_PRINT_DEBUG, " RSHRMN: secondary bus 0x%x", secondary_bus);
  val_print(ACS_PRINT_DEBUG, " RSHRMN: subordinate bus 0x%x", subordinate_bus);

  if ((secondary_bus == 0u) && (subordinate_bus == 0u))
  {
    val_print(ACS_PRINT_INFO, " RSHRMN: RP has no downstream bus window", 0);
    return ACS_STATUS_SKIP;
  }

  for (uint32_t idx = 0u; idx < table->num_entries; ++idx)
  {
    const CXL_COMPONENT_ENTRY *entry = &table->component[idx];
    uint32_t device_key;
    uint32_t function_count;

    if (val_cda_is_downstream_chi_c2c_endpoint(entry,
                                               root_port->bdf,
                                               secondary_bus,
                                               subordinate_bus) == 0u)
      continue;

    endpoint_function_count++;

    if (is_first_device_group(table,
                              idx,
                              root_port->bdf,
                              secondary_bus,
                              subordinate_bus) == 0u)
      continue;

    device_group_count++;
    device_key = coherent_device_key(entry->bdf);
    function_count = count_group_functions(table,
                                           root_port->bdf,
                                           secondary_bus,
                                           subordinate_bus,
                                           device_key);

    val_print(ACS_PRINT_INFO, " RSHRMN: coherent device BDF key 0x%x",
              device_key);
    val_print(ACS_PRINT_INFO, " RSHRMN: requester functions in group %u",
              function_count);
  }

  if (device_group_count == 0u)
  {
    val_print(ACS_PRINT_INFO,
              " RSHRMN: no downstream CHI-C2C coherent device for RP 0x%x",
              root_port->bdf);
    return ACS_STATUS_SKIP;
  }

  if (device_group_count > 1u)
  {
    val_print(ACS_PRINT_ERR,
              " RSHRMN: more than one coherent device on RP 0x%x",
              root_port->bdf);
    val_print(ACS_PRINT_ERR, " RSHRMN: coherent device groups %u",
              device_group_count);
    val_print(ACS_PRINT_ERR, " RSHRMN: endpoint functions %u",
              endpoint_function_count);
    return ACS_STATUS_FAIL;
  }

  val_print(ACS_PRINT_INFO, " RSHRMN: one coherent device on this link", 0);
  return ACS_STATUS_PASS;
}

static void
payload(void)
{
  CXL_COMPONENT_TABLE *table;
  uint32_t pe_index;
  uint32_t applicable_links = 0u;
  uint32_t checked_links = 0u;
  uint32_t skipped_links = 0u;
  uint32_t failures = 0u;

  pe_index = val_pe_get_index_mpid(val_pe_get_mpid());

  if (val_is_coherent_da_supported() == 0u)
  {
    val_print(ACS_PRINT_INFO,
              " RSHRMN: platform does not advertise coherent DA support",
              0);
    val_set_status(pe_index, "SKIP", 01);
    return;
  }

  table = val_cxl_component_table_ptr();
  if ((table == NULL) || (table->num_entries == 0u))
  {
    val_print(ACS_PRINT_INFO, " RSHRMN: no CXL component table", 0);
    val_set_status(pe_index, "SKIP", 02);
    return;
  }

  for (uint32_t idx = 0u; idx < table->num_entries; ++idx)
  {
    const CXL_COMPONENT_ENTRY *entry = &table->component[idx];
    uint32_t rmecda_cap_base;
    uint32_t status;

    if (entry->role != CXL_COMPONENT_ROLE_ROOT_PORT)
      continue;

    if (entry->chi_c2c_supported == 0u)
      continue;

    if (val_pcie_find_cda_capability(entry->bdf, &rmecda_cap_base) != PCIE_SUCCESS)
    {
      val_print(ACS_PRINT_DEBUG,
                " RSHRMN: skipping RP 0x%x without RME-CDA DVSEC",
                entry->bdf);
      continue;
    }

    applicable_links++;
    status = check_root_port_topology(table, entry);
    if (status == ACS_STATUS_PASS)
      checked_links++;
    else if (status == ACS_STATUS_SKIP)
      skipped_links++;
    else
      failures++;
  }

  if (applicable_links == 0u)
  {
    val_print(ACS_PRINT_INFO, " RSHRMN: no CHI-C2C RME-CDA links found", 0);
    val_set_status(pe_index, "SKIP", 03);
  }
  else if (failures != 0u)
  {
    val_set_status(pe_index, "FAIL", failures);
  }
  else if (checked_links == 0u)
  {
    val_print(ACS_PRINT_INFO, " RSHRMN: no populated CHI-C2C links checked", 0);
    val_print(ACS_PRINT_INFO, " RSHRMN: skipped links %u", skipped_links);
    val_set_status(pe_index, "SKIP", 04);
  }
  else
  {
    val_set_status(pe_index, "PASS", 01);
  }
}

uint32_t
cda_rshrmn_coherent_link_topology_entry(uint32_t num_pe)
{
  uint32_t status;

  num_pe = 1;
  status = val_initialize_test(TEST_NAME, TEST_DESC, num_pe, TEST_RULE);

  if (status != ACS_STATUS_SKIP)
    val_run_test_payload(num_pe, payload, 0);

  status = val_check_for_error(num_pe);

  val_report_status(0, "END");

  return status;
}
