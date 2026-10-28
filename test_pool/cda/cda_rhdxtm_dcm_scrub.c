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
#include "val/include/val_el32.h"
#include "val/include/val_memory.h"
#include "val/include/val_spdm.h"
#include "val/include/val_tdisp.h"

#define TEST_NAME "cda_rhdxtm_dcm_scrub"
#define TEST_DESC "CONFIG_UNLOCKED scrubs TDI-associated DCM contents       "
#define TEST_RULE "RHDXTM"

#define DECODER_SLOT              0u
#define RHDXTM_DCM_RANGE_ID       0xFFFFu
#define RHDXTM_TDISP_PAGE_SIZE    4096u
#define RHDXTM_SAMPLE_COUNT       8u
#define RHDXTM_SAMPLE_ALIGNMENT   64u
#define RHDXTM_PATTERN_BASE       0x52484458u

#if ENABLE_SPDM

typedef struct {
  val_spdm_context_t spdm_ctx;
  pci_tdisp_interface_id_t interface_id;
  uint8_t nonce[PCI_TDISP_START_INTERFACE_NONCE_SIZE];
  uint32_t session_id;
  uint32_t session_open;
  uint32_t interface_locked;
  uint32_t tdi_running;
  uint32_t ide_enabled;
} RHDXTM_LINK_STATE;

static void
init_link_state(RHDXTM_LINK_STATE *link)
{
  if (link == NULL)
    return;

  val_memory_set(link, sizeof(*link), 0);
}

static uint64_t
align_up(uint64_t value, uint64_t alignment)
{
  return (value + alignment - 1u) & ~(alignment - 1u);
}

/*
 * Locate the DCM range associated with this TDI in its architectural
 * DEVICE_INTERFACE_REPORT. FIRST_PAGE is a host physical page number in units
 * of 4 KiB after the reporting offset has been applied by the device.
 */
static uint32_t
find_reported_dcm_page(const uint8_t *report,
                       uint32_t report_size,
                       uint64_t window_base,
                       uint64_t window_size,
                       uint64_t page_size,
                       uint64_t *dcm_hpa_out)
{
  const pci_tdisp_device_interface_report_struct_t *interface_report;
  const pci_tdisp_mmio_range_t *ranges;
  uint64_t window_end;
  uint32_t max_ranges;

  val_print(ACS_PRINT_DEBUG, " RHDXTM: interface report size %u", report_size);
  if ((report == NULL) || (dcm_hpa_out == NULL) ||
      (report_size < sizeof(*interface_report)) ||
      (window_size == 0u) || (page_size == 0u))
  {
    val_print(ACS_PRINT_ERR, " RHDXTM: invalid report or DCM window", 0);
    return ACS_STATUS_ERR;
  }

  if ((window_base > (~0ULL - window_size)) ||
      ((page_size & (page_size - 1u)) != 0u))
  {
    val_print(ACS_PRINT_ERR, " RHDXTM: invalid DCM window bounds", 0);
    return ACS_STATUS_ERR;
  }

  interface_report =
    (const pci_tdisp_device_interface_report_struct_t *)report;
  ranges = (const pci_tdisp_mmio_range_t *)(interface_report + 1);
  max_ranges = (report_size - (uint32_t)sizeof(*interface_report)) /
               (uint32_t)sizeof(*ranges);
  val_print(ACS_PRINT_DEBUG,
            " RHDXTM: interface report range count %u",
            interface_report->mmio_range_count);
  if (interface_report->mmio_range_count > max_ranges)
  {
    val_print(ACS_PRINT_ERR, " RHDXTM: malformed interface report range count %u",
              interface_report->mmio_range_count);
    return ACS_STATUS_FAIL;
  }

  window_end = window_base + window_size;
  for (uint32_t index = 0u;
       index < interface_report->mmio_range_count;
       ++index)
  {
    uint64_t range_base;
    uint64_t range_size;
    uint64_t range_end;
    uint64_t intersection_base;
    uint64_t intersection_end;
    uint64_t candidate;

    val_print(ACS_PRINT_DEBUG, " RHDXTM: range ID 0x%x", ranges[index].range_id);
    val_print(ACS_PRINT_DEBUG,
              " RHDXTM: range first page 0x%llx",
              ranges[index].first_page);
    val_print(ACS_PRINT_DEBUG,
              " RHDXTM: range page count 0x%x",
              ranges[index].number_of_pages);

    if ((ranges[index].range_id != RHDXTM_DCM_RANGE_ID) ||
        (ranges[index].number_of_pages == 0u))
      continue;

    if (ranges[index].first_page > (~0ULL >> 12))
    {
      val_print(ACS_PRINT_ERR,
                " RHDXTM: range first page overflows an HPA",
                0);
      return ACS_STATUS_FAIL;
    }
    range_base = ranges[index].first_page << 12;

    range_size = (uint64_t)ranges[index].number_of_pages *
                 RHDXTM_TDISP_PAGE_SIZE;
    if ((range_size == 0u) || (range_base > (~0ULL - range_size)))
    {
      val_print(ACS_PRINT_ERR, " RHDXTM: invalid reported DCM range size", 0);
      return ACS_STATUS_FAIL;
    }
    range_end = range_base + range_size;

    intersection_base = (range_base > window_base) ? range_base : window_base;
    intersection_end = (range_end < window_end) ? range_end : window_end;
    candidate = align_up(intersection_base, page_size);

    if ((candidate < intersection_end) &&
        ((intersection_end - candidate) >= page_size))
    {
      *dcm_hpa_out = candidate;
      val_print(ACS_PRINT_INFO, " RHDXTM: reported DCM range base 0x%llx",
                range_base);
      val_print(ACS_PRINT_INFO, " RHDXTM: selected DCM HPA 0x%llx",
                candidate);
      return ACS_STATUS_PASS;
    }
  }

  val_print(ACS_PRINT_INFO,
            " RHDXTM: no range ID 0xFFFF overlaps the host-visible DCM window",
            0);
  return ACS_STATUS_SKIP;
}

/*
 * Establish the first protected session explicitly so ACS can consume the
 * DEVICE_INTERFACE_REPORT while the interface is CONFIG_LOCKED. No
 * exerciser-specific operation is used in this sequence.
 */
static uint32_t
lock_and_get_dcm_page(const VAL_CDA_DCM_WINDOW_CONTEXT *context,
                      RHDXTM_LINK_STATE *link,
                      uint64_t *dcm_hpa_out)
{
  uint8_t *report;
  uint32_t report_size;
  uint32_t report_pages;
  uint32_t page_size;
  uint32_t status;

  if ((context == NULL) || (link == NULL) || (dcm_hpa_out == NULL))
    return ACS_STATUS_ERR;

  init_link_state(link);

  page_size = val_memory_page_size();
  if (page_size == 0u)
    return ACS_STATUS_ERR;
  report_pages = (4096u + page_size - 1u) / page_size;
  if (report_pages == 0u)
    report_pages = 1u;

  report = (uint8_t *)val_memory_alloc_pages(report_pages);
  if (report == NULL)
    return ACS_STATUS_ERR;
  val_memory_set(report, report_pages * page_size, 0);

  report_size = report_pages * page_size;
  status = val_tdisp_lock_interface(context->endpoint_bdf,
                                    context->window_base,
                                    &link->spdm_ctx,
                                    &link->session_id,
                                    &link->interface_id,
                                    link->nonce,
                                    report,
                                    &report_size);
  if (status == ACS_STATUS_PASS)
  {
    link->session_open = 1u;
    link->interface_locked = 1u;
  }

  if (status == ACS_STATUS_PASS)
    status = find_reported_dcm_page(report,
                                    report_size,
                                    context->window_base,
                                    context->window_size,
                                    page_size,
                                    dcm_hpa_out);
  val_memory_free_pages(report, report_pages);

  if ((status != ACS_STATUS_PASS) && (link->session_open != 0u))
  {
    (void)val_spdm_send_pci_tdisp_stop_interface(&link->spdm_ctx,
                                                  link->session_id,
                                                  &link->interface_id);
    (void)val_spdm_session_close(&link->spdm_ctx, link->session_id);
    init_link_state(link);
  }
  return status;
}

static uint32_t
start_locked_interface(RHDXTM_LINK_STATE *link)
{
  uint32_t status;

  if ((link == NULL) || (link->session_open == 0u) ||
      (link->interface_locked == 0u))
    return ACS_STATUS_ERR;

  status = val_tdisp_start_locked_interface(&link->spdm_ctx,
                                             link->session_id,
                                             &link->interface_id,
                                             link->nonce);
  if (status != ACS_STATUS_PASS)
    return status;

  link->tdi_running = 1u;
  return ACS_STATUS_PASS;
}

static uint32_t
establish_run(const VAL_CDA_DCM_WINDOW_CONTEXT *context,
              RHDXTM_LINK_STATE *link)
{
  uint32_t status;

  init_link_state(link);
  status = val_tdisp_establish_run(context->endpoint_bdf,
                                   &link->spdm_ctx,
                                   &link->session_id,
                                   &link->interface_id);
  if (status != ACS_STATUS_PASS)
    return status;

  link->session_open = 1u;
  link->interface_locked = 1u;
  link->tdi_running = 1u;
  return ACS_STATUS_PASS;
}

static uint32_t
enable_ide(const VAL_CDA_DCM_WINDOW_CONTEXT *context,
           RHDXTM_LINK_STATE *link)
{
  uint32_t status;

  status = val_cxl_ide_establish_link(context->root_index,
                                      context->endpoint_index,
                                      &link->spdm_ctx,
                                      link->session_id);
  if (status == ACS_STATUS_PASS)
    link->ide_enabled = 1u;
  return status;
}

static uint32_t
stop_and_close(const VAL_CDA_DCM_WINDOW_CONTEXT *context,
               RHDXTM_LINK_STATE *link,
               uint32_t require_config_unlocked)
{
  uint32_t result;
  uint32_t status;

  if ((context == NULL) || (link == NULL))
    return ACS_STATUS_ERR;

  result = ACS_STATUS_PASS;
  if ((link->session_open != 0u) && (link->interface_locked != 0u))
  {
    if (require_config_unlocked != 0u)
      status = val_tdisp_stop_to_config_unlocked(&link->spdm_ctx,
                                                  link->session_id,
                                                  &link->interface_id);
    else
      status = val_spdm_send_pci_tdisp_stop_interface(&link->spdm_ctx,
                                                       link->session_id,
                                                       &link->interface_id);

    if (status != ACS_STATUS_PASS)
      result = ACS_STATUS_FAIL;
    else
    {
      link->tdi_running = 0u;
      link->interface_locked = 0u;
    }
  }

  if ((link->session_open != 0u) && (link->ide_enabled != 0u))
  {
    if (val_cxl_ide_disable_link(context->root_index,
                                 context->endpoint_index,
                                 &link->spdm_ctx,
                                 link->session_id) != ACS_STATUS_PASS)
      result = ACS_STATUS_FAIL;
    else
      link->ide_enabled = 0u;
  }

  if (link->session_open != 0u)
  {
    if (val_spdm_session_close(&link->spdm_ctx,
                               link->session_id) != ACS_STATUS_PASS)
      result = ACS_STATUS_FAIL;
    else
      link->session_open = 0u;
  }

  return result;
}

static uint32_t
sample_offset(uint32_t index, uint32_t page_size)
{
  uint32_t offset;

  offset = (uint32_t)(((uint64_t)index * page_size) / RHDXTM_SAMPLE_COUNT);
  return offset & ~(RHDXTM_SAMPLE_ALIGNMENT - 1u);
}

static uint32_t
sample_pattern(uint64_t dcm_hpa, uint32_t index)
{
  return RHDXTM_PATTERN_BASE ^ (uint32_t)dcm_hpa ^
         (0x11111111u * (index + 1u));
}

static uint32_t
write_and_verify_realm_patterns(volatile uint64_t *realm_alias,
                                uint64_t dcm_hpa,
                                uint32_t page_size)
{
  uint32_t observed;

  for (uint32_t index = 0u; index < RHDXTM_SAMPLE_COUNT; ++index)
  {
    uint32_t offset = sample_offset(index, page_size);
    uint32_t pattern = sample_pattern(dcm_hpa, index);
    uint64_t address = (uint64_t)realm_alias + offset;

    if ((val_memory_write_el3(address, pattern) != ACS_STATUS_PASS) ||
        (val_memory_read_el3(address, &observed) != ACS_STATUS_PASS))
      return ACS_STATUS_ERR;

    if (observed != pattern)
    {
      val_print(ACS_PRINT_ERR, " RHDXTM: pre-unlock readback 0x%x", observed);
      val_print(ACS_PRINT_ERR, " RHDXTM: expected pattern 0x%x", pattern);
      return ACS_STATUS_FAIL;
    }
  }

  return ACS_STATUS_PASS;
}

static uint32_t
verify_realm_patterns_scrubbed(volatile uint64_t *realm_alias,
                               uint64_t dcm_hpa,
                               uint32_t page_size)
{
  uint32_t observed;

  for (uint32_t index = 0u; index < RHDXTM_SAMPLE_COUNT; ++index)
  {
    uint32_t offset = sample_offset(index, page_size);
    uint32_t old_pattern = sample_pattern(dcm_hpa, index);
    uint64_t address = (uint64_t)realm_alias + offset;

    if (val_memory_read_el3(address, &observed) != ACS_STATUS_PASS)
    {
      val_print(ACS_PRINT_ERR,
                " RHDXTM: post-unlock DCM read did not complete at 0x%llx",
                dcm_hpa + offset);
      return ACS_STATUS_FAIL;
    }

    if (observed == old_pattern)
    {
      val_print(ACS_PRINT_ERR,
                " RHDXTM: Realm data remained after CONFIG_UNLOCKED at 0x%llx",
                dcm_hpa + offset);
      val_print(ACS_PRINT_ERR, " RHDXTM: retained value 0x%x", observed);
      return ACS_STATUS_FAIL;
    }
  }

  return ACS_STATUS_PASS;
}

static uint32_t
exercise_rule(VAL_CDA_DCM_WINDOW_CONTEXT *context)
{
  RHDXTM_LINK_STATE first_link;
  RHDXTM_LINK_STATE second_link;
  volatile uint64_t *realm_alias;
  uint64_t dcm_hpa;
  uint32_t page_size;
  uint32_t gpt_realm;
  uint32_t result;
  uint32_t status;

  if (context == NULL)
    return ACS_STATUS_ERR;

  init_link_state(&first_link);
  init_link_state(&second_link);
  realm_alias = NULL;
  dcm_hpa = 0u;
  gpt_realm = 0u;
  result = ACS_STATUS_FAIL;

  page_size = val_memory_page_size();
  if (page_size < RHDXTM_SAMPLE_ALIGNMENT)
    return ACS_STATUS_ERR;

  status = lock_and_get_dcm_page(context, &first_link, &dcm_hpa);
  if (status != ACS_STATUS_PASS)
    return status;

  if (val_add_gpt_entry_el3(dcm_hpa, GPT_REALM) != 0u)
    goto cleanup;
  gpt_realm = 1u;

  if (val_memory_map_realm_noncacheable_alias(dcm_hpa, &realm_alias)
      != ACS_STATUS_PASS)
    goto cleanup;

  status = start_locked_interface(&first_link);
  if (status != ACS_STATUS_PASS)
  {
    result = (status == ACS_STATUS_SKIP) ? ACS_STATUS_SKIP : ACS_STATUS_FAIL;
    goto cleanup;
  }

  status = enable_ide(context, &first_link);
  if (status != ACS_STATUS_PASS)
  {
    result = (status == ACS_STATUS_SKIP) ? ACS_STATUS_SKIP : ACS_STATUS_FAIL;
    goto cleanup;
  }

  /* Establish that Realm plaintext is present before triggering the rule. */
  status = write_and_verify_realm_patterns(realm_alias, dcm_hpa, page_size);
  if (status != ACS_STATUS_PASS)
  {
    result = status;
    goto cleanup;
  }

  /*
   * STOP_INTERFACE moves the TDI to CONFIG_UNLOCKED. Its successful response
   * is the architectural synchronization point for DCM scrubbing.
   */
  status = stop_and_close(context, &first_link, 1u);
  if (status != ACS_STATUS_PASS)
    goto cleanup;

  /*
   * Re-establish the protected host path before observing DCM. This makes a
   * completed read mandatory and avoids treating an access fault as evidence
   * that the previous Realm contents were scrubbed.
   */
  status = establish_run(context, &second_link);
  if (status != ACS_STATUS_PASS)
  {
    result = (status == ACS_STATUS_SKIP) ? ACS_STATUS_SKIP : ACS_STATUS_FAIL;
    goto cleanup;
  }

  status = enable_ide(context, &second_link);
  if (status != ACS_STATUS_PASS)
  {
    result = (status == ACS_STATUS_SKIP) ? ACS_STATUS_SKIP : ACS_STATUS_FAIL;
    goto cleanup;
  }

  status = verify_realm_patterns_scrubbed(realm_alias, dcm_hpa, page_size);
  if (status != ACS_STATUS_PASS)
  {
    result = status;
    goto cleanup;
  }

  val_print(ACS_PRINT_INFO,
            " RHDXTM: previous Realm contents absent after CONFIG_UNLOCKED",
            0);
  result = ACS_STATUS_PASS;

cleanup:
  if (stop_and_close(context, &second_link, 0u) != ACS_STATUS_PASS)
    result = ACS_STATUS_FAIL;
  if (stop_and_close(context, &first_link, 0u) != ACS_STATUS_PASS)
    result = ACS_STATUS_FAIL;
  if ((gpt_realm != 0u) && (val_add_gpt_entry_el3(dcm_hpa, GPT_ANY) != 0u))
    result = ACS_STATUS_FAIL;

  return result;
}

static void
payload(void)
{
  VAL_CDA_DCM_WINDOW_CONTEXT context;
  uint32_t component_count;
  uint32_t start_root_index;
  uint32_t context_prepared;
  uint32_t pe_index;
  uint32_t status;

  pe_index = val_pe_get_index_mpid(val_pe_get_mpid());
  component_count = (uint32_t)val_cxl_get_component_info(CXL_COMPONENT_INFO_COUNT, 0u);
  start_root_index = 0u;
  context_prepared = 0u;
  status = ACS_STATUS_SKIP;

  while (start_root_index < component_count)
  {
    status = val_cda_prepare_generic_dcm_window_from_root_index(DECODER_SLOT,
                                                                 start_root_index,
                                                                 &context);
    if (status != ACS_STATUS_PASS)
      break;

    context_prepared = 1u;
    status = exercise_rule(&context);

    if (val_cda_restore_dcm_window(&context) != ACS_STATUS_PASS)
    {
      val_print(ACS_PRINT_ERR, " RHDXTM: platform state restoration failed", 0);
      status = ACS_STATUS_FAIL;
    }
    context_prepared = 0u;

    if (status != ACS_STATUS_SKIP)
      break;

    start_root_index = context.root_index + 1u;
  }

  if ((context_prepared != 0u) &&
      (val_cda_restore_dcm_window(&context) != ACS_STATUS_PASS))
    status = ACS_STATUS_FAIL;

  if (status == ACS_STATUS_PASS)
    val_set_status(pe_index, "PASS", 01);
  else if (status == ACS_STATUS_SKIP)
    val_set_status(pe_index, "SKIP", 02);
  else
    val_set_status(pe_index, "FAIL", 02);
}

#else

static void
payload(void)
{
  uint32_t pe_index;

  pe_index = val_pe_get_index_mpid(val_pe_get_mpid());
  val_set_status(pe_index, "SKIP", 01);
}

#endif

uint32_t
cda_rhdxtm_dcm_scrub_entry(uint32_t num_pe)
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
