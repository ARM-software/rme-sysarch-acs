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
  uint8_t requires_link_lock;
  uint8_t access_width; /* 1 for Flex Bus Port controls; 4 for component registers */
} RVSFPJ_REGISTER_DESC;

/* CXL Flex Bus Port Control is 16-bit at DVSEC + 0x0c.  Its adjacent
 * Status register has RW1C bits, so NEVER write the surrounding DWORD.
 * CXL 3.1, 8.2.1.3 and 11.5.4.8.2.
 */
#define CXL_FLEX_CTRL_OFFSET           0x0cu
#define CXL_FLEX_CTRL2_OFFSET          0x18u
#define CXL_FLEX_CAP2_OFFSET           0x14u
#define CXL_FLEX_DVSEC_REV_1           1u
#define CXL_FLEX_DVSEC_REV_2           2u
#define CXL_FLEX_DVSEC_REV_2_LENGTH    0x20u
#define CXL_FLEX_CONTROL_LOW_CACHE     (1u << 0)
#define CXL_FLEX_CONTROL_LOW_MEM       (1u << 2)
#define CXL_FLEX_CONTROL_LOW_68B       (1u << 5)
#define CXL_FLEX_CONTROL_LOW_RCD       (1u << 7)
#define CXL_FLEX_CONTROL_HIGH_256B     (1u << 5)
#define CXL_FLEX_CONTROL_HIGH_PBR      (1u << 6)

static uint32_t collect_rvsfpj_registers(uint32_t bdf,
                                         RVSFPJ_REGISTER_DESC *registers,
                                         uint32_t *count);

/* Program RMECDA_CTL1 through Root PAS and verify the complete readback. */
static uint32_t
write_ctl1(uint32_t bdf, uint64_t address, uint32_t value)
{
  uint32_t readback;

  shared_data->num_access = 1;
  shared_data->shared_data_access[0].addr = address;
  shared_data->shared_data_access[0].access_type = WRITE_DATA;
  shared_data->shared_data_access[0].data = value;
  if (val_pe_access_mut_el3() ||
      val_pcie_read_rmecda_ctl1(bdf, &readback) || readback != value)
    return ACS_STATUS_ERR;
  return ACS_STATUS_PASS;
}

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
  registers[index].requires_link_lock = 0u;
  registers[index].access_width = 4u;
  *count = index + 1u;
  return ACS_STATUS_PASS;
}

static uint32_t
append_byte_register(RVSFPJ_REGISTER_DESC *registers,
                     uint32_t *count, uint64_t pa, uint32_t mask)
{
  uint32_t index;
  uint32_t word;
  uint32_t shift;

  if ((registers == NULL) || (count == NULL) || (*count >= MAX_RVSFPJ_REG_PER_PORT) ||
      (mask == 0u) || ((mask & ~0xffu) != 0u))
    return ACS_STATUS_ERR;

  /* Read a DWORD for discovery only.  Byte-sized writes in the VAL helper
   * cannot accidentally clear RW1C bits in the adjacent Status register. */
  word = val_mmio_read(pa & ~3ull);
  shift = (uint32_t)(pa & 3ull) * 8u;
  index = (*count)++;
  registers[index].pa = pa;
  registers[index].original = (word >> shift) & 0xffu;
  registers[index].new_value = compute_toggled_value(registers[index].original, mask);
  registers[index].requires_link_lock = 0u;
  registers[index].access_width = 1u;
  return ACS_STATUS_PASS;
}

static uint32_t
collect_flex_bus_registers(uint32_t bdf,
                           RVSFPJ_REGISTER_DESC *registers,
                           uint32_t *count)
{
  uint32_t dvsec_offset = 0u;
  uint32_t header1, header2, cap2;
  uint32_t revision, length, capability;
  uint32_t low_mask = 0u, high_mask = 0u;
  uint64_t cfg_base = val_pcie_get_bdf_config_addr(bdf);

  if (cfg_base == 0u ||
      val_pcie_find_vendor_dvsec(bdf, CXL_DVSEC_VENDOR_ID,
                                 CXL_DVSEC_ID_PCIE_FLEXBUS_PORT,
                                 &dvsec_offset) != PCIE_SUCCESS)
  {
    val_print(ACS_PRINT_ERR,
              " Missing CXL Flex Bus Port DVSEC on RP BDF: 0x%x", bdf);
    return ACS_STATUS_ERR;
  }

  if (val_pcie_read_cfg(bdf, dvsec_offset + CXL_DVSEC_HDR1_OFFSET, &header1) ||
      val_pcie_read_cfg(bdf, dvsec_offset + CXL_DVSEC_HDR2_OFFSET, &header2))
    return ACS_STATUS_ERR;

  val_print(ACS_PRINT_DEBUG, " Flex DVSEC offset 0x%x", dvsec_offset);
  val_print(ACS_PRINT_DEBUG, " Flex DVSEC Header 1 0x%x", header1);
  val_print(ACS_PRINT_DEBUG, " Flex DVSEC Header 2 0x%x", header2);

  revision = (header1 >> CXL_DVSEC_HDR1_REV_SHIFT) & CXL_DVSEC_HDR1_REV_MASK;
  length = (header1 >> CXL_DVSEC_HDR1_LEN_SHIFT) & CXL_DVSEC_HDR1_LEN_MASK;
  if (length < 0x10u)
    return ACS_STATUS_ERR;

  /* DVSEC Header 2 stores the CXL Capabilities in its upper 16 bits. */
  capability = (header2 >> 16) & 0xffffu;
  if (capability & CXL_DVSEC_CXL_CAP_CACHE_CAPABLE)
    low_mask |= CXL_FLEX_CONTROL_LOW_CACHE;
  if (capability & CXL_DVSEC_CXL_CAP_MEM_CAPABLE)
    low_mask |= CXL_FLEX_CONTROL_LOW_MEM;
  if (revision >= CXL_FLEX_DVSEC_REV_1)
  {
    if (capability & (1u << 5))
      low_mask |= CXL_FLEX_CONTROL_LOW_68B;
    low_mask |= CXL_FLEX_CONTROL_LOW_RCD;
  }

  /* At least one applicable CXL.cache/mem control must be testable. */
  if (low_mask == 0u)
    return ACS_STATUS_ERR;
  if (append_byte_register(registers, count,
                           cfg_base + dvsec_offset + CXL_FLEX_CTRL_OFFSET,
                           low_mask))
    return ACS_STATUS_ERR;

  if (revision >= CXL_FLEX_DVSEC_REV_2)
  {
    if (length < CXL_FLEX_DVSEC_REV_2_LENGTH)
      return ACS_STATUS_ERR;
    if (capability & (1u << 13))
      high_mask |= CXL_FLEX_CONTROL_HIGH_256B;
    if (capability & (1u << 14))
      high_mask |= CXL_FLEX_CONTROL_HIGH_PBR;
    if (high_mask && append_byte_register(registers, count,
                                          cfg_base + dvsec_offset + CXL_FLEX_CTRL_OFFSET + 1u,
                                          high_mask))
      return ACS_STATUS_ERR;

    if (val_pcie_read_cfg(bdf, dvsec_offset + CXL_FLEX_CAP2_OFFSET, &cap2))
      return ACS_STATUS_ERR;
    if ((cap2 & 0x1u) &&
        append_byte_register(registers, count,
                             cfg_base + dvsec_offset + CXL_FLEX_CTRL2_OFFSET, 0x1u))
      return ACS_STATUS_ERR;
  }

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
  if (status == ACS_STATUS_SKIP)
  {
    val_print(ACS_PRINT_WARN,
              " BI Decoder capability absent at 0x%llx; protection check omitted",
              component_base);
    return ACS_STATUS_PASS;
  }
  if (status != ACS_STATUS_PASS)
    return status;

  /* CXL 3.1 BI Decoder Control: Forward and BI Enable (bits 0 and 1). */
  uint32_t original = val_mmio_read(cap_base + CXL_BI_DECODER_CTRL_OFFSET);
  uint32_t controls = original & 0x3u;

  if (original == PCIE_UNKNOWN_RESPONSE)
    return ACS_STATUS_ERR;

  /* BI Forward=1 with BI Enable=1 is invalid (CXL 3.1, Tables 9-13/9-14). */
  if (controls == 0x3u)
  {
    val_print(ACS_PRINT_WARN,
              " BI Control has invalid Forward/Enable combination at 0x%llx; check omitted",
              cap_base + CXL_BI_DECODER_CTRL_OFFSET);
    return ACS_STATUS_PASS;
  }
  if (append_register(registers, count, cap_base + CXL_BI_DECODER_CTRL_OFFSET, 0x3u))
    return ACS_STATUS_ERR;
  registers[*count - 1u].new_value = (original & ~0x3u) |
                                      ((controls == 0x1u) ? 0x2u : 0x1u);

  /* From 00, exercise each writable bit separately without ever programming 11. */
  if (controls == 0u)
  {
    if (append_register(registers, count, cap_base + CXL_BI_DECODER_CTRL_OFFSET, 0x2u))
      return ACS_STATUS_ERR;
  }

  return ACS_STATUS_PASS;
}

static uint32_t
collect_rvsfpj_registers(uint32_t bdf,
                         RVSFPJ_REGISTER_DESC *registers,
                         uint32_t *count)
{
  uint64_t component_base = 0u;
  uint32_t status;

  if ((registers == NULL) || (count == NULL))
    return ACS_STATUS_ERR;

  *count = 0u;

  /* The CXL security rule does not unconditionally write-protect standard
   * PCIe RP Command/BAR/bus-number/window registers.  Those are checked
   * as write-detect under RPCRFM by the PCIe DA suite. */
  status = collect_flex_bus_registers(bdf, registers, count);
  val_print(ACS_PRINT_DEBUG, " Collection count after Flex Bus Port: %u", *count);
  if (status != ACS_STATUS_PASS)
  {
    val_print(ACS_PRINT_ERR, " RVSFPJ: Flex Bus Port DVSEC collection failed BDF 0x%x", bdf);
    val_print(ACS_PRINT_ERR, " Collection status 0x%x", status);
    return ACS_STATUS_ERR;
  }

  status = val_cxl_find_component_register_base(bdf, &component_base);
  if (status != ACS_STATUS_PASS)
  {
    /* Do not accidentally treat PCIE_CAP_NOT_FOUND as an ACS skip/pass. */
    val_print(ACS_PRINT_ERR,
              " Failed to discover CXL RP Component Register on BDF: 0x%x", bdf);
    return ACS_STATUS_ERR;
  }

  status = collect_bi_decoder_registers(component_base, registers, count);
  val_print(ACS_PRINT_DEBUG, " Collection count after BI Decoder: %u", *count);
  if (status != ACS_STATUS_PASS)
  {
    val_print(ACS_PRINT_ERR, " RVSFPJ: RP BI Decoder Control collection failed BDF 0x%x", bdf);
    val_print(ACS_PRINT_ERR, " Collection status 0x%x", status);
    return ACS_STATUS_ERR;
  }

  {
    uint64_t ide_base = 0u;
    uint32_t header = val_mmio_read(component_base + CXL_COMPONENT_CAP_ARRAY_OFFSET);
    uint32_t capability;
    uint32_t ide_status;
    uint32_t mask = 0x1u; /* PCRC Disable */

    val_print(ACS_PRINT_DEBUG, " RP Component base 0x%llx", component_base);
    val_print(ACS_PRINT_DEBUG, " RP Component header 0x%x", header);

    /* An unreadable capability array must not masquerade as optional IDE absence. */
    if ((header == PCIE_UNKNOWN_RESPONSE) ||
        (CXL_CAP_HDR_CAPID(header) != CXL_CAPID_COMPONENT_CAP))
    {
      val_print(ACS_PRINT_ERR, " Invalid RP Component header 0x%x", header);
      val_print(ACS_PRINT_ERR, " Header address 0x%llx", component_base);
      return ACS_STATUS_ERR;
    }

    status = val_cxl_find_capability(component_base, CXL_CAPID_IDE, &ide_base);
    if ((status != ACS_STATUS_PASS) && (status != ACS_STATUS_SKIP))
    {
      val_print(ACS_PRINT_ERR, " IDE capability lookup failed at 0x%llx", component_base);
      val_print(ACS_PRINT_ERR, " Lookup status 0x%x", status);
      return ACS_STATUS_ERR;
    }
    if (status == ACS_STATUS_SKIP)
      val_print(ACS_PRINT_WARN,
                " CXL IDE capability absent on BDF 0x%x; IDE Control check omitted", bdf);
    if (status == ACS_STATUS_PASS)
    {
      capability = val_mmio_read(ide_base + CXL_IDE_REG_CAPABILITY);
      val_print(ACS_PRINT_DEBUG, " IDE Capability address 0x%llx",
                ide_base + CXL_IDE_REG_CAPABILITY);
      val_print(ACS_PRINT_DEBUG, " IDE register value 0x%x", capability);
      if (capability == PCIE_UNKNOWN_RESPONSE)
      {
        val_print(ACS_PRINT_ERR, " IDE Capability unreadable at 0x%llx",
                  ide_base + CXL_IDE_REG_CAPABILITY);
        return ACS_STATUS_ERR;
      }
      if (capability & CXL_IDE_CAP_CAPABLE)
      {
        ide_status = val_mmio_read(ide_base + CXL_IDE_REG_STATUS);
        val_print(ACS_PRINT_DEBUG, " IDE Status address 0x%llx",
                  ide_base + CXL_IDE_REG_STATUS);
        val_print(ACS_PRINT_DEBUG, " IDE Status value 0x%x", ide_status);
        if (ide_status == PCIE_UNKNOWN_RESPONSE)
        {
          val_print(ACS_PRINT_ERR, " IDE Status unreadable at 0x%llx",
                    ide_base + CXL_IDE_REG_STATUS);
          return ACS_STATUS_ERR;
        }

        /* CXL 3.1 8.2.4.22.2: PCRC changes with active IDE are undefined.
         * Preserve a live link and omit only IDE Control from this port. */
        uint32_t rx = ide_status & CXL_IDE_STATUS_FIELD_MASK;
        uint32_t tx = (ide_status >> CXL_IDE_STATUS_TX_SHIFT) & CXL_IDE_STATUS_FIELD_MASK;
        if ((rx == 1u) || (rx == 2u) || (tx == 1u) || (tx == 2u))
        {
          val_print(ACS_PRINT_INFO,
                    " Omitting IDE Control check: CXL IDE is active on BDF: 0x%x", bdf);
          return (*count > 0u) ? ACS_STATUS_PASS : ACS_STATUS_SKIP;
        }
        if ((rx != CXL_IDE_STATE_INSECURE) || (tx != CXL_IDE_STATE_INSECURE))
        {
          val_print(ACS_PRINT_ERR, " Unexpected IDE state register at 0x%llx",
                    ide_base + CXL_IDE_REG_STATUS);
          val_print(ACS_PRINT_ERR, " IDE Status 0x%x", ide_status);
          val_print(ACS_PRINT_ERR, " IDE RX state 0x%x", rx);
          val_print(ACS_PRINT_ERR, " IDE TX state 0x%x", tx);
          return ACS_STATUS_ERR;
        }

        if (capability & CXL_IDE_CAP_IDE_STOP_CAPABLE)
          mask |= 0x2u; /* IDE.Stop Enable is writable only when advertised. */
        if (append_register(registers, count, ide_base + CXL_IDE_REG_CONTROL, mask))
          return ACS_STATUS_ERR;
        registers[*count - 1u].requires_link_lock = 1u;
      }
    }
  }

  return (*count > 0u) ? ACS_STATUS_PASS : ACS_STATUS_SKIP;
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
    uint32_t ctl1_original;
    uint32_t enabled_here = 0u;

    status = val_pcie_find_cda_capability(bdf, &rmecda_offset);
    if (status != PCIE_SUCCESS)
    {
      val_print(ACS_PRINT_ERR,
                " RMECDA DVSEC missing or inaccessible on BDF: 0x%x", bdf);
      failure_count++;
      tested_ports = 1u;
      continue;
    }

    if (val_pcie_read_rmecda_ctl1(bdf, &ctl1_original) != PCIE_SUCCESS)
    {
      failure_count++;
      tested_ports = 1u;
      continue;
    }

    if ((ctl1_original & 0x1u) == 0u)
    {
      if (val_pcie_enable_tdisp(bdf))
      {
        val_print(ACS_PRINT_ERR, " Failed to enable TDISP for BDF: 0x%x", bdf);
        failure_count++;
        tested_ports = 1u;
        continue;
      }
      enabled_here = 1u;
    }

    status = collect_rvsfpj_registers(bdf, registers, &reg_count);
    /* Show partial collection too: discovery failure must not hide coverage. */
    val_print(ACS_PRINT_DEBUG, " RVSFPJ inventory for BDF 0x%x", bdf);
    val_print(ACS_PRINT_DEBUG, " Collected register count %u", reg_count);
    for (uint32_t reg_idx = 0; reg_idx < reg_count; ++reg_idx)
    {
      val_print(ACS_PRINT_DEBUG, " Register index %u", reg_idx);
      val_print(ACS_PRINT_DEBUG, " Register PA 0x%llx", registers[reg_idx].pa);
      val_print(ACS_PRINT_DEBUG, " Access width in bytes %u", registers[reg_idx].access_width);
      val_print(ACS_PRINT_DEBUG, " Original value 0x%x", registers[reg_idx].original);
      val_print(ACS_PRINT_DEBUG, " Toggle mask 0x%x",
                registers[reg_idx].original ^ registers[reg_idx].new_value);
    }

    if ((status != ACS_STATUS_PASS) && (status != ACS_STATUS_SKIP))
    {
      val_print(ACS_PRINT_ERR, " Unable to collect RVSFPJ registers for BDF: 0x%x", bdf);
      failure_count++;
      tested_ports = 1u;
      if (enabled_here)
        (void)val_pcie_disable_tdisp(bdf);
      continue;
    }

    if (status == ACS_STATUS_SKIP)
    {
      /* No applicable registers, or active IDE prevents a safe PCRC stimulus. */
      val_print(ACS_PRINT_INFO,
                " Skipping RVSFPJ check - no safe register stimulus on BDF: 0x%x",
                bdf);
      if (enabled_here && val_pcie_disable_tdisp(bdf))
      {
        val_print(ACS_PRINT_ERR, " Failed to restore TDISP_EN for BDF: 0x%x", bdf);
        failure_count++;
        tested_ports = 1u;
      }
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

        uint32_t check_failures;
        uint64_t ctl1_va = 0u;
        uint32_t ctl1_before = 0u;
        uint32_t lock_changed = 0u;

        if (registers[reg_idx].requires_link_lock)
        {
          uint64_t tg = val_get_min_tg();
          uint64_t attr = LOWER_ATTRS(PGT_ENTRY_ACCESS | SHAREABLE_ATTR(OUTER_SHAREABLE) |
                           GET_ATTR_INDEX(DEV_MEM_nGnRnE) | PGT_ENTRY_AP_RW |
                           PAS_ATTR(ROOT_PAS));
          if (!tg || val_pcie_read_rmecda_ctl1(bdf, &ctl1_before))
          {
            failure_count++;
            continue;
          }
          uint64_t ctl1_pa = val_pcie_get_bdf_config_addr(bdf) +
                             rmecda_offset + RMECDA_CTL1_OFFSET;
          ctl1_va = val_get_free_va(tg);
          if (!ctl1_va || (ctl1_va & (tg - 1u)) ||
              val_add_mmu_entry_el3(ctl1_va, ctl1_pa & ~(tg - 1u), attr))
          {
            failure_count++;
            continue;
          }
          ctl1_va += ctl1_pa & (tg - 1u);
          /* RDHNWR protects IDE registers only while the link is locked. */
          lock_changed = (ctl1_before & 0x2u) == 0u;
          if (lock_changed && write_ctl1(bdf, ctl1_va, ctl1_before | 0x2u))
          {
            val_print(ACS_PRINT_ERR, " Failed to set LINK_STR_LOCK for BDF 0x%x", bdf);
            failure_count++;
            if (write_ctl1(bdf, ctl1_va, ctl1_before))
              failure_count++;
            break;
          }
        }
        if (registers[reg_idx].access_width == 1u)
          check_failures = val_rmsd_write_protect_check_byte(
                             registers[reg_idx].pa,
                             (uint8_t)registers[reg_idx].new_value,
                             (uint8_t)registers[reg_idx].original);
        else
          check_failures = val_rmsd_write_protect_check_masked(
                             registers[reg_idx].pa,
                             registers[reg_idx].new_value,
                             registers[reg_idx].original,
                             registers[reg_idx].original ^ registers[reg_idx].new_value);
        if (lock_changed && write_ctl1(bdf, ctl1_va, ctl1_before))
        {
          val_print(ACS_PRINT_ERR, " Failed to restore LINK_STR_LOCK for BDF 0x%x", bdf);
          failure_count++;
        }
        if (check_failures)
        {
            val_print(ACS_PRINT_ERR,
                      " RMSD write-protect failure for register 0x%llx",
                      registers[reg_idx].pa);
            failure_count++;
        }
    }

    /* Do not clear TDISP_EN when it was already enabled on entry. */
    if (enabled_here && val_pcie_disable_tdisp(bdf))
    {
      val_print(ACS_PRINT_ERR, " Failed to restore TDISP_EN for BDF: 0x%x", bdf);
      failure_count++;
    }
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
