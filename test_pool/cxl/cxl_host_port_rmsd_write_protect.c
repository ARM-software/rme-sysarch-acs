/** @file
 * Copyright (c) 2025-2026, Arm Limited or its affiliates. All rights reserved.
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
#include "val/include/val_da.h"

#define TEST_NAME "cxl_host_port_rmsd_write_protect"
#define TEST_DESC "Check coherent host port registers RMSD write-protect    "
#define TEST_RULE "RVSFPJ RDWRKS"

#define MAX_RVSFPJ_REG_PER_PORT 64U

typedef struct {
  uint64_t pa;
  uint32_t original;
  uint32_t new_value;
} RVSFPJ_REGISTER_DESC;

typedef struct {
  BITFIELD_REGISTER_TYPE reg_type;
  uint16_t cap_id;
  uint16_t ecap_id;
  uint16_t offset;
  uint8_t start_bit;
  uint8_t end_bit;
} RVSFPJ_PCIE_REGISTER_DESC;

/*
 * Register descriptors encoded as:
 *   {register_type, capability_id, extended_capability_id, byte_offset, start_bit, end_bit}
 */
static const RVSFPJ_PCIE_REGISTER_DESC g_pcie_registers[] = {
  {HEADER, 0, 0, TYPE01_CR, 1, 1},       /* Command register bit 1 (CR_MSE) */
  {HEADER, 0, 0, TYPE01_CR, 2, 2},       /* Command register bit 2 (CR_BME) */
  {HEADER, 0, 0, TYPE01_CLSR, 30, 30},   /* BIST register start bit */
  {HEADER, 0, 0, TYPE01_BAR, 0, 31},     /* BAR0 low dword */
  {HEADER, 0, 0, TYPE01_EXP_ROM, 0, 31}, /* Expansion ROM base address */
  {HEADER, 0, 0, TYPE1_PBN, 0, 7},       /* Primary bus number */
  {HEADER, 0, 0, TYPE1_PBN, 8, 15},      /* Secondary bus number */
  {HEADER, 0, 0, TYPE1_PBN, 16, 23},     /* Subordinate bus number */
  {HEADER, 0, 0, TYPE1_NP_MEM, 0, 31},   /* Non-prefetchable memory base/limit */
  {HEADER, 0, 0, TYPE1_P_MEM, 0, 31},    /* Prefetchable memory base/limit */
  {HEADER, 0, 0, TYPE1_P_MEM_BU, 0, 31}, /* Prefetchable memory base upper */
  {HEADER, 0, 0, TYPE1_P_MEM_LU, 0, 31}, /* Prefetchable memory limit upper */
  {PCIE_ECAP, 0, ECID_MC, 0x04u, 31, 31}, /* Multicast control bit 31 */
  {PCIE_ECAP, 0, ECID_RBAR, 0x08u, 8, 13}, /* Resizable BAR control bits 13:8 */
};

static uint32_t collect_rvsfpj_registers(uint32_t component_index,
                                         uint32_t bdf,
                                         RVSFPJ_REGISTER_DESC *registers,
                                         uint32_t *count);

static uint32_t
compute_toggled_value(uint32_t value, uint32_t mask)
{
  uint32_t toggled;

  if (mask == 0u)
    mask = 0x1u;

  /* Flip the selected bit(s) while leaving the rest of the value unchanged. */
  toggled = (value ^ mask) & mask;
  toggled |= (value & ~mask);

  if (toggled == value)
    /* Guarantee we test a distinct value even when the mask keeps the bit stable. */
    toggled ^= mask;

  return toggled;
}

static uint32_t
append_register(RVSFPJ_REGISTER_DESC *registers,
                uint32_t *count,
                uint64_t pa,
                uint32_t toggle_mask)
{
  uint32_t index;

  if ((registers == NULL) || (count == NULL))
    return ACS_STATUS_ERR;

  if (*count >= MAX_RVSFPJ_REG_PER_PORT)
    return ACS_STATUS_ERR;

  index = *count;
  registers[index].pa = pa;
  registers[index].original = val_mmio_read(pa);
  /* Test the write-protect behaviour by attempting to toggle only the tracked bits. */
  registers[index].new_value = compute_toggled_value(registers[index].original,
                                                     toggle_mask);
  *count = index + 1u;
  return ACS_STATUS_PASS;
}

static uint32_t
collect_hdm_registers(uint32_t host_index,
                      RVSFPJ_REGISTER_DESC *registers,
                      uint32_t *count)
{
  uint64_t cap_base;
  uint32_t status;
  uint64_t component_base = val_cxl_get_info(CXL_INFO_COMPONENT_BASE, host_index);

  if (component_base == 0u)
    return ACS_STATUS_PASS;

  status = val_cxl_find_capability(component_base,
                                   CXL_CAPID_HDM_DECODER,
                                   &cap_base);
  if (status != ACS_STATUS_PASS)
    return (status == ACS_STATUS_SKIP) ? ACS_STATUS_PASS : status;

  if (append_register(registers, count, cap_base + CXL_HDM_GLOBAL_CTRL_OFFSET, 0x1u))
    return ACS_STATUS_ERR;

  return ACS_STATUS_PASS;
}

static uint32_t
collect_bi_decoder_registers(uint64_t component_base,
                             RVSFPJ_REGISTER_DESC *registers,
                             uint32_t *count)
{
  uint64_t cap_base;
  uint32_t status;

  status = val_cxl_find_capability(component_base,
                                   CXL_CAPID_BI_DECODER,
                                   &cap_base);
  if (status != ACS_STATUS_PASS)
    return (status == ACS_STATUS_SKIP) ? ACS_STATUS_PASS : status;

  if (append_register(registers, count, cap_base + CXL_BI_DECODER_CTRL_OFFSET, 0x1u))
    return ACS_STATUS_ERR;

  return ACS_STATUS_PASS;
}

static uint32_t
collect_ext_security_registers(uint64_t component_base,
                               RVSFPJ_REGISTER_DESC *registers,
                               uint32_t *count)
{
  uint64_t cap_base;
  uint32_t status;
  uint32_t reg_value;
  uint32_t entry_count;

  status = val_cxl_find_capability(component_base,
                                   CXL_CAPID_EXT_SECURITY,
                                   &cap_base);
  if (status != ACS_STATUS_PASS)
    return (status == ACS_STATUS_SKIP) ? ACS_STATUS_PASS : status;

  reg_value = val_mmio_read(cap_base + CXL_EXT_SECURITY_COUNT_OFFSET);
  entry_count = reg_value & CXL_EXT_SECURITY_COUNT_MASK;
  if (entry_count == 0u)
    return ACS_STATUS_PASS;

  if (append_register(registers, count, cap_base + CXL_EXT_SECURITY_POLICY_BASE, 0x1u))
    return ACS_STATUS_ERR;

  return ACS_STATUS_PASS;
}

static uint32_t
collect_pcie_registers(uint32_t bdf,
                       RVSFPJ_REGISTER_DESC *registers,
                       uint32_t *count)
{
  uint64_t cfg_base;

  cfg_base = val_pcie_get_bdf_config_addr(bdf);
  if (cfg_base == 0u)
    return ACS_STATUS_ERR;

  for (uint32_t idx = 0; idx < (sizeof(g_pcie_registers) / sizeof(g_pcie_registers[0])); ++idx)
  {
    const RVSFPJ_PCIE_REGISTER_DESC *entry = &g_pcie_registers[idx];
    uint32_t cap_offset = 0u;
    uint32_t status = PCIE_SUCCESS;
    uint64_t register_pa;
    uint8_t start = entry->start_bit;
    uint8_t end = entry->end_bit;
    uint8_t bit_low;
    uint8_t bit_high;
    uint32_t mask;

    switch (entry->reg_type)
    {
      case HEADER:
        register_pa = cfg_base + entry->offset;
        break;
      case PCIE_CAP:
        status = val_pcie_find_capability(bdf, PCIE_CAP, entry->cap_id, &cap_offset);
        if (status != PCIE_SUCCESS)
          continue;
        register_pa = cfg_base + cap_offset + entry->offset;
        break;
      case PCIE_ECAP:
        status = val_pcie_find_capability(bdf, PCIE_ECAP, entry->ecap_id, &cap_offset);
        if (status != PCIE_SUCCESS)
          continue;
        register_pa = cfg_base + cap_offset + entry->offset;
        break;
      default:
        return ACS_STATUS_ERR;
    }

    if ((entry->offset == TYPE01_CLSR) && (start == 30u) && (end == 30u))
    {
      if ((val_mmio_read(register_pa) & (1u << 31)) == 0u)
        continue;
    }

    bit_low = (start < end) ? start : end;
    bit_high = (start > end) ? start : end;
    mask = REG_MASK(bit_high, bit_low) << bit_low;
  if (mask == 0u)
    continue;

  val_print(ACS_PRINT_DEBUG,
            " RVSFPJ: add reg 0x%llx\n",
            register_pa);

  /* Track the register location so the payload can exercise RMSD write protection. */
  if (append_register(registers, count, register_pa, mask))
    return ACS_STATUS_ERR;
  }

  return ACS_STATUS_PASS;
}

static uint32_t
collect_rvsfpj_registers(uint32_t component_index,
                         uint32_t bdf,
                         RVSFPJ_REGISTER_DESC *registers,
                         uint32_t *count)
{
  uint64_t component_base = 0u;
  uint32_t status;
  uint32_t host_index;

  if ((registers == NULL) || (count == NULL))
    return ACS_STATUS_ERR;

  *count = 0u;

  status = val_cxl_find_component_register_base(bdf, &component_base);
  if (status != ACS_STATUS_PASS)
    return status;

  host_index = (uint32_t)val_cxl_get_component_info(CXL_COMPONENT_INFO_HOST_BRIDGE_INDEX,
                                                    component_index);
  if (host_index != CXL_COMPONENT_INVALID_INDEX) {
    status = collect_hdm_registers(host_index, registers, count);
    if (status == ACS_STATUS_ERR)
      return status;
  }

  if (status == ACS_STATUS_ERR)
    return status;

  status = collect_bi_decoder_registers(component_base, registers, count);
  if (status == ACS_STATUS_ERR)
    return status;

  status = collect_ext_security_registers(component_base, registers, count);
  if (status == ACS_STATUS_ERR)
    return status;

  status = collect_pcie_registers(bdf, registers, count);
  if (status == ACS_STATUS_ERR)
    return status;

  if (*count == 0u)
    return ACS_STATUS_SKIP;

  return ACS_STATUS_PASS;
}

static
void
payload(void)
{
  uint32_t pe_index;
  uint64_t component_count;
  uint32_t tested_ports;
  uint32_t failure_count;

  pe_index = val_pe_get_index_mpid(val_pe_get_mpid());
  component_count = val_cxl_get_component_info(CXL_COMPONENT_INFO_COUNT, 0);

  if (component_count == 0u)
  {
    val_set_status(pe_index, "SKIP", 01);
    return;
  }

  tested_ports = 0u;
  failure_count = 0u;

  for (uint32_t comp = 0; comp < component_count; ++comp)
  {
    uint32_t role;
    uint32_t bdf;
    uint32_t status;
    RVSFPJ_REGISTER_DESC registers[MAX_RVSFPJ_REG_PER_PORT];
    uint32_t reg_count = 0u;

    role = (uint32_t)val_cxl_get_component_info(CXL_COMPONENT_INFO_ROLE, comp);
    if (role != CXL_COMPONENT_ROLE_ROOT_PORT)
      continue;

    bdf = (uint32_t)val_cxl_get_component_info(CXL_COMPONENT_INFO_BDF_INDEX, comp);
    if (bdf == CXL_COMPONENT_INVALID_INDEX)
      continue;

    uint32_t rmecda_offset;

    status = val_pcie_find_cda_capability(bdf, &rmecda_offset);
    if (status == ACS_STATUS_SKIP)
      continue;
    if (status != ACS_STATUS_PASS)
    {
      /* Host ports must implement the RME-CDA DVSEC before RMSD write protection is checked. */
      val_print(ACS_PRINT_ERR,
                " RMECDA DVSEC missing or inaccessible on BDF: 0x%x",
                bdf);
      failure_count++;
      tested_ports = 1u;
      continue;
    }

    if (val_pcie_enable_tdisp(bdf))
    {
      /* TDISP needs to be enabled so that RMSD registers accept programming attempts. */
      val_print(ACS_PRINT_ERR, " Failed to enable TDISP for BDF: 0x%x", bdf);
      failure_count++;
      tested_ports = 1u;
      continue;
    }

    status = collect_rvsfpj_registers(comp, bdf, registers, &reg_count);
    if (status == ACS_STATUS_ERR)
    {
      val_print(ACS_PRINT_ERR, " Unable to collect RVSFPJ registers for BDF: 0x%x", bdf);
      failure_count++;
      tested_ports = 1u;
      (void)val_pcie_disable_tdisp(bdf);
      continue;
    }

    if (status == ACS_STATUS_SKIP)
    {
      /* Some ports may have no applicable registers, but that is not a failure. */
      val_print(ACS_PRINT_INFO,
                " Skipping RVSFPJ check - no applicable registers on BDF: 0x%x",
                bdf);
      (void)val_pcie_disable_tdisp(bdf);
      continue;
    }

    tested_ports = 1u;

    for (uint32_t reg_idx = 0; reg_idx < reg_count; ++reg_idx)
    {
        /* Log the register index to aid RMSD debug visibility. */
        val_print(ACS_PRINT_INFO,
                  " RMSD write-protect check register index %d",
                  reg_idx);
        val_print(ACS_PRINT_INFO,
                  " RMSD write-protect check register index %llx",
                  registers[reg_idx].pa);

        if (val_rmsd_write_protect_check(registers[reg_idx].pa,
                                         registers[reg_idx].new_value,
                                         registers[reg_idx].original))
        {
            val_print(ACS_PRINT_ERR,
                      " RMSD write-protect failure for register 0x%llx",
                      registers[reg_idx].pa);
            failure_count++;
        }
    }

    if (val_pcie_disable_tdisp(bdf))
      val_print(ACS_PRINT_WARN, " Failed to disable TDISP for BDF: 0x%x", bdf);
  }

  if (!tested_ports)
    val_set_status(pe_index, "SKIP", 02);
  else if (failure_count)
    val_set_status(pe_index, "FAIL", failure_count);
  else
    val_set_status(pe_index, "PASS", 01);
}

uint32_t
cxl_host_port_rmsd_write_protect_entry(uint32_t num_pe)
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
