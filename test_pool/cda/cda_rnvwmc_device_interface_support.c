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
#include "val/include/val_da.h"
#include "val/include/val_cxl_spec.h"
#include "val/include/val_memory.h"
#include "val/include/val_pcie.h"
#include "val/include/val_pcie_spec.h"
#include "val/include/val_spdm.h"
#include "val/include/val_tdisp.h"

#define TEST_NAME "cda_rnvwmc_device_interface_support"
#define TEST_DESC "Device measurement and TDI assignment interfaces       "
#define TEST_RULE "RNVWMC"

#define RMECDA_TDISP_EN       (1u << 0)
#define RMECDA_LINK_STR_LOCK  (1u << 1)
#define TDISP_BASE_REQUESTS   0xFEu
/* TDISP report portions are addressed using a 16-bit offset. */
#define REPORT_BUFFER_SIZE   0x10000u

#if ENABLE_SPDM

/*
 * This test checks measurement retrieval and the protected TDI assignment
 * lifecycle on every applicable endpoint. PASS refers to these interface checks;
 * device attestation and other device compliance requirements need separate
 * evidence. Fetching measurements does not establish an attestation verdict.
 * All selected TDIs and their memory must be reserved for destructive ACS use:
 * STOP can scrub TDI-associated memory even though this test performs no DMA.
 */
static uint32_t
check_interface_report(const uint8_t *report, uint32_t size)
{
  const pci_tdisp_device_interface_report_struct_t *header;
  uint32_t offset;
  uint32_t info_size;

  if (size < sizeof(*header) + sizeof(info_size))
    return ACS_STATUS_FAIL;

  header = (const pci_tdisp_device_interface_report_struct_t *)report;
  offset = (uint32_t)sizeof(*header);
  /* Check the count before multiplying or reading any variable-length fields. */
  if (header->mmio_range_count >
      (size - offset - sizeof(info_size)) / sizeof(pci_tdisp_mmio_range_t))
    return ACS_STATUS_FAIL;

  /* The MMIO range array is followed by a little-endian device-specific data length. */
  offset += header->mmio_range_count * (uint32_t)sizeof(pci_tdisp_mmio_range_t);
  info_size = (uint32_t)report[offset] |
              ((uint32_t)report[offset + 1u] << 8) |
              ((uint32_t)report[offset + 2u] << 16) |
              ((uint32_t)report[offset + 3u] << 24);
  offset += sizeof(info_size);
  if (info_size != size - offset)
    return ACS_STATUS_FAIL;

  /* A cache-only device need not expose DCM or a DCM-specific range ID. */
  val_print(ACS_PRINT_DEBUG, " RNVWMC: interface report range count %u",
            header->mmio_range_count);
  return ACS_STATUS_PASS;
}

/* Verify the resulting state as well as the success of the preceding command. */
static uint32_t
check_state(val_spdm_context_t *ctx, uint32_t session_id,
             const pci_tdisp_interface_id_t *interface_id, uint8_t expected)
{
  uint8_t state;

  if (val_tdisp_get_interface_state(ctx, session_id, interface_id, &state) != ACS_STATUS_PASS)
    return ACS_STATUS_FAIL;

  if (state != expected)
  {
    val_print(ACS_PRINT_ERR, " RNVWMC: unexpected TDI state %u", state);
    val_print(ACS_PRINT_ERR, " RNVWMC: expected TDI state %u", expected);
    return ACS_STATUS_FAIL;
  }

  return ACS_STATUS_PASS;
}

/* Inspect existing IDE state before programming a link owned by this test. */
static uint32_t
check_idle_ide(uint32_t root_index, uint32_t endpoint_index)
{
  uint32_t root_state;
  uint32_t endpoint_state;
  uint32_t root_status = val_cxl_ide_get_status(root_index, &root_state);
  uint32_t endpoint_status = val_cxl_ide_get_status(endpoint_index, &endpoint_state);

  if ((root_status == ACS_STATUS_SKIP) || (endpoint_status == ACS_STATUS_SKIP))
  {
    val_print(ACS_PRINT_INFO, " RNVWMC: link IDE setup requires an unsupported interface", 0);
    return ACS_STATUS_SKIP;
  }

  if ((root_status != ACS_STATUS_PASS) || (endpoint_status != ACS_STATUS_PASS))
    return ACS_STATUS_FAIL;

  if (((root_state & CXL_IDE_STATUS_FIELD_MASK) != CXL_IDE_STATE_INSECURE) ||
      (((root_state >> CXL_IDE_STATUS_TX_SHIFT) & CXL_IDE_STATUS_FIELD_MASK) !=
       CXL_IDE_STATE_INSECURE) ||
      ((endpoint_state & CXL_IDE_STATUS_FIELD_MASK) != CXL_IDE_STATE_INSECURE) ||
      (((endpoint_state >> CXL_IDE_STATUS_TX_SHIFT) & CXL_IDE_STATUS_FIELD_MASK) !=
       CXL_IDE_STATE_INSECURE))
  {
    val_print(ACS_PRINT_INFO, " RNVWMC: existing IDE state is not idle; leaving link unchanged", 0);
    val_print(ACS_PRINT_INFO, " RNVWMC: root port IDE status 0x%x", root_state);
    val_print(ACS_PRINT_INFO, " RNVWMC: endpoint IDE status 0x%x", endpoint_state);
    return ACS_STATUS_SKIP;
  }

  return ACS_STATUS_PASS;
}

static uint32_t
check_endpoint(const CXL_COMPONENT_TABLE *table, uint32_t root_index,
                 uint32_t endpoint_index, uint32_t cap_base)
{
  const CXL_COMPONENT_ENTRY *root = &table->component[root_index];
  const CXL_COMPONENT_ENTRY *endpoint = &table->component[endpoint_index];
  val_spdm_context_t ctx;
  pci_tdisp_interface_id_t interface_id;
  pci_tdisp_requester_capabilities_t request_caps;
  pci_tdisp_responder_capabilities_t response_caps;
  pci_tdisp_lock_interface_param_t lock_param;
  uint8_t nonce[PCI_TDISP_START_INTERFACE_NONCE_SIZE];
  uint8_t *buffer = NULL;
  uint8_t state;
  uint8_t blocks;
  uint32_t size;
  uint32_t session_id;
  uint32_t ctl1_original;
  uint32_t readback;
  uint32_t ide_attempted = 0u;
  uint32_t lock_attempted = 0u;
  uint32_t ctl1_changed = 0u;
  uint32_t status;
  uint32_t result = ACS_STATUS_FAIL;
  uint64_t cfg_va = 0u;
  const char *step = "TDISP version negotiation";

  val_print(ACS_PRINT_INFO, " RNVWMC: checking endpoint BDF 0x%x", endpoint->bdf);
  /* Preserve host controls and leave any existing protected assignment untouched. */
  if (val_pcie_read_rmecda_ctl1(root->bdf, &ctl1_original) != PCIE_SUCCESS)
  {
    val_print(ACS_PRINT_ERR, " RNVWMC: host control read failed for BDF 0x%x", root->bdf);
    return ACS_STATUS_FAIL;
  }

  if ((ctl1_original & (RMECDA_TDISP_EN | RMECDA_LINK_STR_LOCK)) != 0u)
  {
    val_print(ACS_PRINT_INFO, " RNVWMC: root port already protected; skipping BDF 0x%x",
              root->bdf);
    return ACS_STATUS_SKIP;
  }

  /* Use one protected SPDM session for measurements and the TDISP lifecycle. */
  status = val_spdm_session_open(endpoint->bdf, &ctx, &session_id);
  if (status != ACS_STATUS_PASS)
  {
    val_print(ACS_PRINT_INFO, " RNVWMC: SPDM session setup status 0x%x", status);
    return (status == ACS_STATUS_SKIP) ? ACS_STATUS_SKIP : ACS_STATUS_FAIL;
  }

  val_memory_set(&interface_id, sizeof(interface_id), 0);
  interface_id.function_id = PCIE_CREATE_BDF_PACKED(endpoint->bdf);
  val_memory_set(&request_caps, sizeof(request_caps), 0);
  val_memory_set(&response_caps, sizeof(response_caps), 0);
  val_memory_set(&lock_param, sizeof(lock_param), 0);

  /* Check protocol support before changing the TDI or programming link protection. */
  status = val_spdm_send_pci_tdisp_get_version(&ctx, session_id, &interface_id);
  if (status != ACS_STATUS_PASS)
  {
    if (status == ACS_STATUS_SKIP)
      result = ACS_STATUS_SKIP;

    goto cleanup;
  }

  step = "TDISP capabilities";
  if (val_spdm_send_pci_tdisp_get_capabilities(&ctx, session_id, &interface_id,
                                               &request_caps, &response_caps) != ACS_STATUS_PASS)
    goto cleanup;

  /* Bits 1..7 describe GET_TDISP_VERSION through STOP_INTERFACE_REQUEST. */
  if ((response_caps.req_msg_supported[0] & TDISP_BASE_REQUESTS) != TDISP_BASE_REQUESTS)
  {
    val_print(ACS_PRINT_ERR, " RNVWMC: incomplete base TDISP request support 0x%x",
              response_caps.req_msg_supported[0]);
    goto cleanup;
  }

  /* Do not take over a TDI that is locked, running, or recovering from an error. */
  step = "initial TDI state";
  if (val_tdisp_get_interface_state(&ctx, session_id, &interface_id, &state) != ACS_STATUS_PASS)
    goto cleanup;

  if (state > PCI_TDISP_INTERFACE_STATE_ERROR)
  {
    val_print(ACS_PRINT_ERR, " RNVWMC: invalid TDI state %u", state);
    goto cleanup;
  }

  if (state != PCI_TDISP_INTERFACE_STATE_CONFIG_UNLOCKED)
  {
    val_print(ACS_PRINT_INFO, " RNVWMC: TDI is not unused CONFIG_UNLOCKED, state %u", state);
    result = ACS_STATUS_SKIP;
    goto cleanup;
  }

  /* Measurements and the later interface report can reuse the same buffer. */
  buffer = val_memory_alloc(REPORT_BUFFER_SIZE);
  if (buffer == NULL)
  {
    step = "measurement/report buffer allocation";
    result = ACS_STATUS_SKIP;
    goto cleanup;
  }

  /* The helper checks measurement count and record retrieval, not attestation policy. */
  step = "SPDM measurement retrieval";
  size = REPORT_BUFFER_SIZE;
  status = val_spdm_get_measurements(&ctx, session_id, &blocks, &size, buffer);
  if (status != ACS_STATUS_PASS)
  {
    if (status == ACS_STATUS_SKIP)
      result = ACS_STATUS_SKIP;

    goto cleanup;
  }

  val_print(ACS_PRINT_INFO, " RNVWMC: retrieved measurement blocks %u", blocks);

  step = "idle link IDE prerequisite";
  status = check_idle_ide(root_index, endpoint_index);
  if (status != ACS_STATUS_PASS)
  {
    result = status;
    goto cleanup;
  }

  /*
   * Use existing host mappings and device decoders. No test memory is exposed,
   * no DMA is started, and no DCM capacity or exerciser identity is required.
   */
  step = "host assignment setup";
  if (val_pcie_map_root_config(root->bdf, &cfg_va) != ACS_STATUS_PASS)
    goto cleanup;

  ctl1_changed = 1u;
  if (val_memory_write_el3(cfg_va + cap_base + RMECDA_CTL1_OFFSET,
                            ctl1_original | RMECDA_TDISP_EN) != ACS_STATUS_PASS)
    goto cleanup;

  step = "link IDE establishment";
  /* A failed setup may already have programmed keys; always clean it up. */
  ide_attempted = 1u;
  if (val_cxl_ide_establish_link(root_index, endpoint_index, &ctx, session_id) != ACS_STATUS_PASS)
    goto cleanup;

  step = "host link protection";
  if (val_cda_set_link_stream_lock(cfg_va, cap_base,
                                    ctl1_original | RMECDA_TDISP_EN, 1u) != ACS_STATUS_PASS)
    goto cleanup;

  if ((val_pcie_read_rmecda_ctl1(root->bdf, &readback) != PCIE_SUCCESS) ||
      ((readback & (RMECDA_TDISP_EN | RMECDA_LINK_STR_LOCK)) !=
       (RMECDA_TDISP_EN | RMECDA_LINK_STR_LOCK)))
    goto cleanup;

  /*
   * Lock the TDI only after link protection is ready. Track the attempt so
   * cleanup sends STOP even if the response or the following state check fails.
   */
  step = "LOCK_INTERFACE and CONFIG_LOCKED";
  lock_attempted = 1u;
  if (val_spdm_send_pci_tdisp_lock_interface(&ctx, session_id, &interface_id,
                                             &lock_param, nonce) != ACS_STATUS_PASS)
    goto cleanup;

  if (check_state(&ctx, session_id, &interface_id,
                   PCI_TDISP_INTERFACE_STATE_CONFIG_LOCKED) != ACS_STATUS_PASS)
    goto cleanup;

  /* Read the locked interface description and validate its variable-length layout. */
  step = "DEVICE_INTERFACE_REPORT";
  size = REPORT_BUFFER_SIZE;
  if (val_spdm_send_pci_tdisp_get_interface_report(&ctx, session_id, &interface_id,
                                                   buffer, &size) != ACS_STATUS_PASS)
    goto cleanup;

  if ((size > REPORT_BUFFER_SIZE) || (check_interface_report(buffer, size) != ACS_STATUS_PASS))
    goto cleanup;

  /* START uses the nonce returned by LOCK to authorize this assignment. */
  step = "START_INTERFACE and RUN";
  if (val_spdm_send_pci_tdisp_start_interface(&ctx, session_id, &interface_id,
                                              nonce) != ACS_STATUS_PASS)
    goto cleanup;

  if (check_state(&ctx, session_id, &interface_id,
                   PCI_TDISP_INTERFACE_STATE_RUN) != ACS_STATUS_PASS)
    goto cleanup;

  /* Complete the lifecycle and verify CONFIG_UNLOCKED before releasing protection. */
  step = "STOP_INTERFACE and CONFIG_UNLOCKED";
  if (val_tdisp_stop_to_config_unlocked(&ctx, session_id, &interface_id) != ACS_STATUS_PASS)
    goto cleanup;

  lock_attempted = 0u;
  result = ACS_STATUS_PASS;

cleanup:
  /*
   * Unwind partial setup in order: stop the TDI, unlock the host link, disable
   * IDE, then restore host controls and close the session. Continue cleanup
   * after an error, but never report a pass or skip if restoration fails.
   */
  if (result != ACS_STATUS_PASS)
    val_print((result == ACS_STATUS_SKIP) ? ACS_PRINT_INFO : ACS_PRINT_ERR,
              " RNVWMC: stopped at step: %a", (uint64_t)step);

  if ((lock_attempted != 0u) &&
      (val_tdisp_stop_to_config_unlocked(&ctx, session_id, &interface_id) != ACS_STATUS_PASS))
  {
    val_print(ACS_PRINT_ERR, " RNVWMC: TDI cleanup failed for BDF 0x%x", endpoint->bdf);
    result = ACS_STATUS_FAIL;
  }

  if (ctl1_changed != 0u)
  {
    if (val_cda_set_link_stream_lock(cfg_va, cap_base,
                                      ctl1_original | RMECDA_TDISP_EN, 0u) != ACS_STATUS_PASS)
    {
      val_print(ACS_PRINT_ERR, " RNVWMC: host link unlock failed for BDF 0x%x", root->bdf);
      result = ACS_STATUS_FAIL;
    }

  }

  if ((ide_attempted != 0u) &&
      (val_cxl_ide_disable_link(root_index, endpoint_index, &ctx, session_id) != ACS_STATUS_PASS))
  {
    val_print(ACS_PRINT_ERR, " RNVWMC: link IDE cleanup failed for BDF 0x%x", root->bdf);
    result = ACS_STATUS_FAIL;
  }

  if (ctl1_changed != 0u)
  {
    if ((val_memory_write_el3(cfg_va + cap_base + RMECDA_CTL1_OFFSET,
                               ctl1_original) != ACS_STATUS_PASS) ||
        (val_pcie_read_rmecda_ctl1(root->bdf, &readback) != PCIE_SUCCESS) ||
        (readback != ctl1_original))
    {
      val_print(ACS_PRINT_ERR, " RNVWMC: host control restore failed for BDF 0x%x", root->bdf);
      result = ACS_STATUS_FAIL;
    }

  }

  if (val_spdm_session_close(&ctx, session_id) != ACS_STATUS_PASS)
  {
    val_print(ACS_PRINT_ERR, " RNVWMC: SPDM session cleanup failed for BDF 0x%x", endpoint->bdf);
    result = ACS_STATUS_FAIL;
  }

  if (buffer != NULL)
    val_memory_free(buffer);

  return result;
}

static void
payload(void)
{
  uint32_t pe_index = val_pe_get_index_mpid(val_pe_get_mpid());
  CXL_COMPONENT_TABLE *table = val_cxl_component_table_ptr();
  uint32_t checked = 0u;
  uint32_t skipped = 0u;
  uint32_t failures = 0u;

  if ((val_is_coherent_da_supported() == 0u) || (table == NULL))
  {
    val_print(ACS_PRINT_INFO, " RNVWMC: coherent DA discovery is unavailable", 0);
    val_set_status(pe_index, "SKIP", 01);
    return;
  }

  /* Visit every eligible endpoint; a skip or failure must not hide the others. */
  for (uint32_t index = 0u; index < table->num_entries; ++index)
  {
    const CXL_COMPONENT_ENTRY *endpoint = &table->component[index];
    uint32_t root_bdf;
    uint32_t root_index;
    uint32_t cap_base;
    uint32_t status;

    if (endpoint->role != CXL_COMPONENT_ROLE_ENDPOINT)
      continue;

    /*
     * DEN0129 C.a limits CDA assignment to CHI-based devices. Native CXL
     * Type-1/2 are outside that version's scope; native Type-3 memory expansion
     * has separate requirements. CHI classification takes precedence over the
     * CXL-style device type: Type-1, Type-2, Type-3 and unclassified CHI entries
     * are all eligible here. Neither CXL.mem nor an exerciser BAR is required.
     */
    if (endpoint->chi_c2c_supported == 0u)
      continue;

    /* Resolve the endpoint's parent in the CXL/CHI component table. */
    if ((val_cxl_find_upstream_root_port(endpoint->bdf, &root_bdf) != ACS_STATUS_PASS) ||
        (val_cxl_find_component_index_by_bdf(root_bdf, &root_index) != ACS_STATUS_PASS))
    {
      val_print(ACS_PRINT_INFO, " RNVWMC: host port discovery unavailable for BDF 0x%x",
                endpoint->bdf);
      skipped++;
      continue;
    }

    if ((table->component[root_index].role != CXL_COMPONENT_ROLE_ROOT_PORT) ||
        (table->component[root_index].chi_c2c_supported == 0u))
    {
      /* Endpoints outside the supported CDA host topology are not applicable. */
      val_print(ACS_PRINT_INFO, " RNVWMC: no supported CDA host interface for BDF 0x%x",
                endpoint->bdf);
      continue;
    }

    status = val_pcie_find_cda_capability(root_bdf, &cap_base);
    if (status == PCIE_CAP_NOT_FOUND)
    {
      /* A host port without the RME-CDA interface is outside this test's scope. */
      val_print(ACS_PRINT_INFO, " RNVWMC: host has no RME-CDA DVSEC for BDF 0x%x",
                endpoint->bdf);
      continue;
    }

    if (status != PCIE_SUCCESS)
    {
      val_print(ACS_PRINT_ERR, " RNVWMC: host capability discovery failed for BDF 0x%x",
                endpoint->bdf);
      failures++;
      continue;
    }

    status = check_endpoint(table, root_index, index, cap_base);
    if (status == ACS_STATUS_PASS)
      checked++;
    else if (status == ACS_STATUS_SKIP)
      skipped++;
    else
      failures++;

  }

  val_print(ACS_PRINT_INFO, " RNVWMC: endpoints completing interface checks %u", checked);
  val_print(ACS_PRINT_INFO, " RNVWMC: endpoints skipped %u", skipped);
  val_print(ACS_PRINT_INFO, " RNVWMC: endpoints failed %u", failures);
  /*
   * Any endpoint failure wins. PASS requires at least one completed endpoint
   * and no untested applicable endpoints. Unresolved host discovery also
   * prevents PASS because applicability could not be established.
   */
  if (failures != 0u)
    val_set_status(pe_index, "FAIL", failures);
  else if (checked == 0u)
  {
    val_print(ACS_PRINT_INFO, " RNVWMC: no eligible endpoint completed the interface checks", 0);
    val_set_status(pe_index, "SKIP", 02);
  }
  else if (skipped != 0u)
  {
    val_print(ACS_PRINT_INFO,
              " RNVWMC: endpoint checks or host discovery remain incomplete", 0);
    val_set_status(pe_index, "SKIP", 04);
  }
  else
  {
    val_print(ACS_PRINT_INFO,
              " RNVWMC: measurement and assignment interface checks passed", 0);
    val_set_status(pe_index, "PASS", 01);
  }

}
#else
static void
payload(void)
{
  uint32_t pe_index = val_pe_get_index_mpid(val_pe_get_mpid());

  val_print(ACS_PRINT_INFO, " RNVWMC: SPDM requester support is disabled", 0);
  val_set_status(pe_index, "SKIP", 03);
}
#endif

uint32_t
cda_rnvwmc_device_interface_support_entry(uint32_t num_pe)
{
  uint32_t status;

  num_pe = 1u;
  status = val_initialize_test(TEST_NAME, TEST_DESC, num_pe, TEST_RULE);
  if (status != ACS_STATUS_SKIP)
    val_run_test_payload(num_pe, payload, 0);

  status = val_check_for_error(num_pe);
  val_report_status(0, "END");
  return status;
}
