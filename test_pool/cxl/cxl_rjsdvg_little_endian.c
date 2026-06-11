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

#define TEST_DESC "Verify RME DVSEC little-endian ordering        "
#define TEST_NAME "cxl_rjsdvg_little_endian"
#define TEST_RULE "RJSDVG"

#define RME_ARRAY_SIZE(_array) (sizeof(_array) / sizeof((_array)[0]))
#define RME_DVSEC_CTL1_OFFSET  RMEDA_CTL1
#define RME_DVSEC_CTL2_OFFSET  RMEDA_CTL2

typedef struct {
  const char8_t      *dvsec_name;
  const char8_t      *head1_label;
  const char8_t      *head2_label;
  const char8_t      *ctl1_label;
  const char8_t      *ctl2_label;
  uint32_t          (*finder)(uint32_t bdf, uint32_t *offset_out);
} RME_DVSEC_DESCRIPTOR;

static uint32_t verify_dvsec_le32(uint32_t bdf,
                                  uint64_t cfg_base,
                                  uint32_t reg_offset,
                                  const char8_t *reg_label);
static uint32_t process_dvsec(uint32_t bdf,
                              const RME_DVSEC_DESCRIPTOR *desc,
                              uint32_t dvsec_offset,
                              uint32_t *tested);

/* Lookup descriptors for Arm DVSECs exposed on coherent and non-coherent ports. */
static const RME_DVSEC_DESCRIPTOR g_rme_dvsecs[] = {
  {
    "RME-DA",
    "RME-DA HEAD1",
    "RME-DA HEAD2",
    "RME-DA CTL1",
    "RME-DA CTL2",
    val_pcie_find_da_capability
  },
  {
    "RME-CDA",
    "RME-CDA HEAD1",
    "RME-CDA HEAD2",
    "RME-CDA CTL1",
    "RME-CDA CTL2",
    val_pcie_find_cda_capability
  }
};

static
uint32_t
verify_dvsec_le32(uint32_t bdf,
                  uint64_t cfg_base,
                  uint32_t reg_offset,
                  const char8_t *reg_label)
{
  uint32_t cfg_value;
  uint32_t assembled = 0;

  if (val_pcie_read_cfg(bdf, reg_offset, &cfg_value))
  {
    val_print(ACS_PRINT_ERR, " Failed to read %a register", (uint64_t)reg_label);
    val_print(ACS_PRINT_ERR, "   BDF : 0x%x", bdf);
    return 1;
  }

  /* Assemble bytes straight from MMIO to validate little-endian ordering. */
  for (uint32_t byte = 0; byte < sizeof(uint32_t); ++byte)
  {
    assembled |= (uint32_t)val_mmio_read8(cfg_base + reg_offset + byte) << (8u * byte);
  }

  if (assembled != cfg_value)
  {
    val_print(ACS_PRINT_ERR, " %a register violates little-endian order", (uint64_t)reg_label);
    val_print(ACS_PRINT_ERR, "   BDF : 0x%x", bdf);
    val_print(ACS_PRINT_ERR, "   cfg : 0x%x", cfg_value);
    val_print(ACS_PRINT_ERR, "   mem : 0x%x", assembled);
    return 1;
  }

  return 0;
}

static
uint32_t
process_dvsec(uint32_t bdf,
              const RME_DVSEC_DESCRIPTOR *desc,
              uint32_t dvsec_offset,
              uint32_t *tested)
{
  uint32_t header1;
  uint32_t failures = 0;

  if (val_pcie_read_cfg(bdf, dvsec_offset + CXL_DVSEC_HDR1_OFFSET, &header1))
  {
    val_print(ACS_PRINT_ERR, " Failed to read DVSEC header1 for BDF 0x%x", bdf);
    val_print(ACS_PRINT_ERR, "   DVSEC : %a", (uint64_t)desc->dvsec_name);
    return 1;
  }

  /* Ignore unrelated DVSECs; only Arm vendor entries are relevant here. */
  if ((header1 & CXL_DVSEC_HDR1_VENDOR_ID_MASK) != ARM_RME_VENDOR_ID)
    return 0;

  if (tested != NULL)
    *tested = 1;

  uint64_t cfg_base = val_pcie_get_bdf_config_addr(bdf);

  /* Bail out if config space cannot be mapped for byte-addressable reads. */
  if (cfg_base == 0u)
  {
    val_print(ACS_PRINT_ERR, " Unable to resolve config base for BDF 0x%x", bdf);
    val_print(ACS_PRINT_ERR, "   DVSEC : %a", (uint64_t)desc->dvsec_name);
    return 1;
  }

  failures += verify_dvsec_le32(bdf, cfg_base,
                                dvsec_offset + CXL_DVSEC_HDR1_OFFSET,
                                desc->head1_label);

  failures += verify_dvsec_le32(bdf, cfg_base,
                                dvsec_offset + CXL_DVSEC_HDR2_OFFSET,
                                desc->head2_label);

  uint32_t dvsec_len = (header1 >> CXL_DVSEC_HDR1_LEN_SHIFT) & CXL_DVSEC_HDR1_LEN_MASK;

  /* Validate control registers only if the DVSEC advertises the fields. */
  if (dvsec_len >= (RME_DVSEC_CTL1_OFFSET + sizeof(uint32_t)))
  {
    failures += verify_dvsec_le32(bdf, cfg_base,
                                  dvsec_offset + RME_DVSEC_CTL1_OFFSET,
                                  desc->ctl1_label);
  }

  if (dvsec_len >= (RME_DVSEC_CTL2_OFFSET + sizeof(uint32_t)))
  {
    failures += verify_dvsec_le32(bdf, cfg_base,
                                  dvsec_offset + RME_DVSEC_CTL2_OFFSET,
                                  desc->ctl2_label);
  }
  /* TODO: RMECDA_CTL3/4 govern C2C host ports; add coverage once C2C support added. */

  return failures;
}

static
void
payload(void)
{
  uint32_t pe_index = val_pe_get_index_mpid(val_pe_get_mpid());
  pcie_device_bdf_table *bdf_tbl = val_pcie_bdf_table_ptr();
  uint32_t failures = 0;
  uint32_t test_skip = 1;

  if ((bdf_tbl == NULL) || (bdf_tbl->num_entries == 0))
  {
    val_print(ACS_PRINT_DEBUG, " PCIe device table absent - skipping RJSDVG", 0);
    val_set_status(pe_index, "SKIP", 01);
    return;
  }

  /* Scan the PCIe BDF table for RME-DA DVSECs exposed on non-coherent root ports. */
  for (uint32_t tbl_index = 0; tbl_index < bdf_tbl->num_entries; ++tbl_index)
  {
    uint32_t bdf = bdf_tbl->device[tbl_index].bdf;
    uint32_t port_type = val_pcie_device_port_type(bdf);
    uint32_t dvsec_offset = 0;
    uint32_t tested = 0;
    uint32_t status;

    /* Little-endian rule applies only to root ports that expose DVSECs. */
    if ((port_type != RP) && (port_type != iEP_RP))
      continue;

    status = g_rme_dvsecs[0].finder(bdf, &dvsec_offset);

    if (status == PCIE_CAP_NOT_FOUND)
      continue;

    if (status != PCIE_SUCCESS)
    {
      val_print(ACS_PRINT_ERR, " DVSEC discovery failed for BDF 0x%x", bdf);
      val_print(ACS_PRINT_ERR, "   DVSEC : %a", (uint64_t)g_rme_dvsecs[0].dvsec_name);
      failures++;
      continue;
    }

    failures += process_dvsec(bdf, &g_rme_dvsecs[0], dvsec_offset, &tested);

    if (tested)
      test_skip = 0;
  }

  /* Scan the discovered CXL component table for coherent root ports carrying RME-CDA DVSECs. */
  {
    CXL_COMPONENT_TABLE *comp_tbl = val_cxl_component_table_ptr();

    if ((comp_tbl != NULL) && (comp_tbl->num_entries != 0))
    {
      for (uint32_t idx = 0; idx < comp_tbl->num_entries; ++idx)
      {
        const CXL_COMPONENT_ENTRY *entry = &comp_tbl->component[idx];
        uint32_t dvsec_offset = 0;
        uint32_t tested = 0;
        uint32_t status;

        if (entry->role != CXL_COMPONENT_ROLE_ROOT_PORT)
          continue;

        status = g_rme_dvsecs[1].finder(entry->bdf, &dvsec_offset);

        if (status == PCIE_CAP_NOT_FOUND)
          continue;

        if (status != PCIE_SUCCESS)
        {
          val_print(ACS_PRINT_ERR, " DVSEC discovery failed for BDF 0x%x", entry->bdf);
          val_print(ACS_PRINT_ERR, "   DVSEC : %a", (uint64_t)g_rme_dvsecs[1].dvsec_name);
          failures++;
          continue;
        }

        failures += process_dvsec(entry->bdf, &g_rme_dvsecs[1], dvsec_offset, &tested);

        if (tested)
          test_skip = 0;
      }
    }
  }

  if (test_skip)
  {
    val_print(ACS_PRINT_DEBUG, " No RME DVSEC instances detected", 0);
    val_set_status(pe_index, "SKIP", 02);
  } else if (failures)
  {
    val_set_status(pe_index, "FAIL", failures);
  } else
  {
    val_set_status(pe_index, "PASS", 01);
  }
}

uint32_t
cxl_rjsdvg_little_endian_entry(uint32_t num_pe)
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
