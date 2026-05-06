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
#include "val/include/val_cxl.h"
#include "val/include/val_cxl_spec.h"
#include "val/include/val_da.h"
#include "val/include/val_pcie.h"
#include "val/include/val_spdm.h"
#include "val/include/val_el32.h"

#if ENABLE_SPDM
#include "industry_standard/pcidoe.h"
#endif

#define TEST_NAME "cxl_rcnslj_type3_no_tsp"
#define TEST_DESC "Validate RCNSLJ requirements for non-TSP Type-3    "
#define TEST_RULE "RCNSLJ"

#define MAX_DOE_PROTOCOLS 32u

#define CXL_DVSEC_CXL_CONTROL_OFFSET 0x0Cu
#define CXL_DVSEC_CXL_CONTROL_DIRECT_P2P_MEM_ENABLE (1u << 12)
#define CXL_BI_DECODER_CTRL_BI_ENABLE (1u << 1)

#if ENABLE_SPDM
static uint32_t
get_tsp_capable(uint32_t bdf, uint32_t *tsp_capable)
{
  uint32_t dvsec_offset;
  uint32_t hdr2;
  uint16_t cxl_cap;

  if (tsp_capable == NULL)
    return ACS_STATUS_ERR;

  if (val_pcie_find_vendor_dvsec(bdf,
                                 CXL_DVSEC_VENDOR_ID,
                                 CXL_DVSEC_ID_DEVICE,
                                 &dvsec_offset) != PCIE_SUCCESS)
    return ACS_STATUS_FAIL;

  if (val_pcie_read_cfg(bdf, dvsec_offset + CXL_DVSEC_HDR2_OFFSET, &hdr2))
    return ACS_STATUS_FAIL;

  cxl_cap = (uint16_t)((hdr2 >> CXL_DVSEC_CXL_CAPABILITY_SHIFT) &
                       CXL_DVSEC_CXL_CAPABILITY_MASK);
  *tsp_capable = ((cxl_cap & CXL_DVSEC_CXL_CAP_TSP_CAPABLE) != 0u) ? 1u : 0u;

  return ACS_STATUS_PASS;
}

static uint32_t
check_cma_support(uint32_t bdf, uint32_t *supported)
{
  val_pci_doe_protocol_t protocols[MAX_DOE_PROTOCOLS];
  uint32_t protocol_count = MAX_DOE_PROTOCOLS;
  uint32_t status;

  if (supported == NULL)
    return ACS_STATUS_ERR;

  *supported = 0u;
  status = val_doe_discovery(bdf, protocols, &protocol_count);
  if (status != ACS_STATUS_PASS)
    return status;

  for (uint32_t idx = 0; idx < protocol_count; ++idx)
  {
    if (protocols[idx].vendor_id != PCI_DOE_VENDOR_ID_PCISIG)
      continue;

    if ((protocols[idx].data_object_type == PCI_DOE_DATA_OBJECT_TYPE_SPDM) ||
        (protocols[idx].data_object_type == PCI_DOE_DATA_OBJECT_TYPE_SECURED_SPDM))
    {
      *supported = 1u;
      break;
    }
  }

  return ACS_STATUS_PASS;
}

static uint32_t
check_direct_p2p_disabled(uint32_t bdf)
{
  uint32_t dvsec_offset;
  uint32_t ctrl;

  if (val_pcie_find_vendor_dvsec(bdf,
                                 CXL_DVSEC_VENDOR_ID,
                                 CXL_DVSEC_ID_DEVICE,
                                 &dvsec_offset) != PCIE_SUCCESS)
    return ACS_STATUS_FAIL;

  if (val_pcie_read_cfg(bdf, dvsec_offset + CXL_DVSEC_CXL_CONTROL_OFFSET, &ctrl))
    return ACS_STATUS_FAIL;

  if ((ctrl & CXL_DVSEC_CXL_CONTROL_DIRECT_P2P_MEM_ENABLE) != 0u)
  {
    val_print(ACS_PRINT_ERR,
                " RCNSLJ: Direct P2P enabled for BDF 0x%x",
                (uint64_t)bdf);
    return ACS_STATUS_FAIL;
  }

  return ACS_STATUS_PASS;
}

static uint32_t
check_bi_disabled(const CXL_COMPONENT_ENTRY *component)
{
  uint64_t cap_base;
  uint32_t status;
  uint32_t ctrl;

  status = val_cxl_find_capability(component->component_reg_base,
                                   CXL_CAPID_BI_DECODER,
                                   &cap_base);
  if (status != ACS_STATUS_PASS)
  {
    val_print(ACS_PRINT_INFO,
              " RCNSLJ: BI Decoder cap not present for BDF 0x%x",
              (uint64_t)component->bdf);
    return ACS_STATUS_PASS;
  }

  ctrl = val_mmio_read(cap_base + CXL_BI_DECODER_CTRL_OFFSET);
  if ((ctrl & CXL_BI_DECODER_CTRL_BI_ENABLE) != 0u)
  {
    val_print(ACS_PRINT_ERR,
              " RCNSLJ: BI enabled for BDF 0x%x",
              (uint64_t)component->bdf);
    return ACS_STATUS_FAIL;
  }

  return ACS_STATUS_PASS;
}

static uint32_t
check_hdm_decoder_rmsd(const CXL_COMPONENT_ENTRY *component)
{
  uint64_t cap_base;
  uint32_t status;
  uint32_t failures = 0u;

  status = val_cxl_find_capability(component->component_reg_base,
                                   CXL_CAPID_HDM_DECODER,
                                   &cap_base);
  if (status != ACS_STATUS_PASS)
  {
    val_print(ACS_PRINT_ERR,
              " RCNSLJ: HDM decoder cap missing for BDF 0x%x",
              (uint64_t)component->bdf);
    return ACS_STATUS_FAIL;
  }

  val_print(ACS_PRINT_DEBUG,
            " RCNSLJ: HDM decoder cap_base 0x%llx",
            (uint64_t)cap_base);

  if (component->hdm_decoder_count == 0u)
  {
    val_print(ACS_PRINT_ERR,
              " RCNSLJ: No HDM decoders for BDF 0x%x",
              (uint64_t)component->bdf);
    return ACS_STATUS_FAIL;
  }

  {
    uint64_t ctrl_reg = cap_base + CXL_HDM_GLOBAL_CTRL_OFFSET;
    uint32_t ctrl_val = val_mmio_read(ctrl_reg);
    uint32_t ctrl_new = ctrl_val ^ 0x1u;

    /* Ensure the HDM decoder registers are mapped in the GPT before EL3 access. */
    if (val_add_gpt_entry_el3(ctrl_reg, GPT_ANY))
      failures++;

    failures += val_rmsd_write_protect_check(ctrl_reg, ctrl_new, ctrl_val);
  }

  if (failures != 0u)
  {
    val_print(ACS_PRINT_ERR,
              " RCNSLJ: RMSD write-protect failed for BDF 0x%x",
              (uint64_t)component->bdf);
    return ACS_STATUS_FAIL;
  }

  return ACS_STATUS_PASS;
}

static void
attempt_spdm_session(uint32_t bdf)
{
  val_spdm_context_t ctx;
  uint32_t session_id = 0u;
  uint32_t status;

  val_memory_set(&ctx, sizeof(ctx), 0);
  status = val_spdm_session_open(bdf, &ctx, &session_id);
  if (status == ACS_STATUS_PASS)
  {
    val_print(ACS_PRINT_INFO,
              " RCNSLJ: SPDM session established for BDF 0x%x",
              (uint64_t)bdf);
  }

  if (status == ACS_STATUS_SKIP)
    val_print(ACS_PRINT_DEBUG,
              " RCNSLJ: SPDM session skipped for BDF 0x%x",
              (uint64_t)bdf);
  else if (status != ACS_STATUS_PASS)
    val_print(ACS_PRINT_WARN,
              " RCNSLJ: SPDM session failed for BDF 0x%x",
              (uint64_t)bdf);

  (void)val_spdm_session_close(&ctx, session_id);
}

static void
payload(void)
{
  uint32_t pe_index = val_pe_get_index_mpid(val_pe_get_mpid());
  CXL_COMPONENT_TABLE *table = val_cxl_component_table_ptr();
  uint32_t evaluated = 0u;
  uint32_t failures = 0u;

  if ((table == NULL) || (table->num_entries == 0u))
  {
    val_print(ACS_PRINT_DEBUG, " RCNSLJ: No CXL components", 0);
    val_set_status(pe_index, "SKIP", 01);
    return;
  }

  for (uint32_t idx = 0; idx < table->num_entries; ++idx)
  {
    const CXL_COMPONENT_ENTRY *component = &table->component[idx];
    uint32_t rp_bdf;
    uint32_t cda_offset;
    uint32_t tsp_capable;
    uint32_t status;
    uint32_t cma_supported;

    if (component->device_type != CXL_DEVICE_TYPE_TYPE3)
      continue;

    if (component->bdf == CXL_COMPONENT_INVALID_INDEX)
      continue;

    /* Step 1: Filter Type-3 devices that are not TSP capable. */
    status = get_tsp_capable(component->bdf, &tsp_capable);
    if (status != ACS_STATUS_PASS)
    {
      val_print(ACS_PRINT_ERR,
                " RCNSLJ: Unable to read TSP capability for BDF 0x%x",
                (uint64_t)component->bdf);
      failures++;
      continue;
    }

    if (tsp_capable != 0u)
      continue;

    evaluated++;

    /* Step 2: Ensure the upstream root port exposes the RME-CDA DVSEC. */
    status = val_cxl_find_upstream_root_port(component->bdf, &rp_bdf);
    if (status != ACS_STATUS_PASS)
    {
      val_print(ACS_PRINT_ERR,
                " RCNSLJ: No root port for BDF 0x%x",
                (uint64_t)component->bdf);
      failures++;
      continue;
    }

    if (val_pcie_find_cda_capability(rp_bdf,
                                     &cda_offset) != PCIE_SUCCESS)
    {
      val_print(ACS_PRINT_ERR,
                " RCNSLJ: RME-CDA DVSEC missing for RP BDF 0x%x",
                (uint64_t)rp_bdf);
      failures++;
      continue;
    }

    /* Host-side MPE encryption coverage is handled by RLQMCY. */

    /* Step 3: Verify CMA-SPDM support via DOE discovery. */
    status = check_cma_support(component->bdf, &cma_supported);
    if (status != ACS_STATUS_PASS)
    {
      val_print(ACS_PRINT_ERR,
                " RCNSLJ: DOE discovery failed for BDF 0x%x",
                (uint64_t)component->bdf);
      failures++;
      continue;
    }
    if (cma_supported == 0u)
    {
      val_print(ACS_PRINT_ERR,
                " RCNSLJ: CMA-SPDM not advertised for BDF 0x%x",
                (uint64_t)component->bdf);
      failures++;
      continue;
    }

    /* Step 4: Check Direct P2P mem enable is disabled. */
    status = check_direct_p2p_disabled(component->bdf);
    if (status != ACS_STATUS_PASS)
    {
      failures++;
      continue;
    }

    /* Step 5: Ensure back-invalidate snoops are disabled. */
    status = check_bi_disabled(component);
    if (status != ACS_STATUS_PASS)
    {
      failures++;
      continue;
    }

    /* Step 6: Verify HDM decoder registers are RMSD write-protected. */
    status = check_hdm_decoder_rmsd(component);
    if (status != ACS_STATUS_PASS)
    {
      failures++;
      continue;
    }

    /* Step 7: Attempt an SPDM session for additional coverage. */
    attempt_spdm_session(component->bdf);
  }

  if (evaluated == 0u)
  {
    val_print(ACS_PRINT_DEBUG, " RCNSLJ: No non-TSP Type-3 devices", 0);
    val_set_status(pe_index, "SKIP", 02);
    return;
  }

  if (failures != 0u)
    val_set_status(pe_index, "FAIL", failures);
  else
    val_set_status(pe_index, "PASS", 01);
}
#else
static void
payload(void)
{
  uint32_t pe_index = val_pe_get_index_mpid(val_pe_get_mpid());

  val_print(ACS_PRINT_WARN,
            " SPDM support disabled - skipping RCNSLJ",
            0);
  val_set_status(pe_index, "SKIP", 03);
}
#endif

uint32_t
cxl_rcnslj_type3_no_tsp_entry(uint32_t num_pe)
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
