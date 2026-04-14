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
#include "val/include/val_spdm.h"
#include "val/include/val_mec.h"
#include "val/include/val_memory.h"
#include "val/include/val_pcie.h"
#include "val/include/val_pe.h"
#include "val/include/val_el32.h"

#define TEST_NAME "cxl_rlqmcy_type3_host_mpe"
#define TEST_DESC "Type-3 memory uses host-side MPE when no target encryption"
#define TEST_RULE "RLQMCY"

/* Test intent: validate RLQMCY behavior for Type-3 CXL.mem without target encryption. */

#if ENABLE_SPDM

#include "industry_standard/cxl_tsp.h"

#define DECODER_SLOT 0u
#define MECID1 0x1u
#define MECID2 0x2u
#define TEST_DATA_PATTERN 0xA5A5A5A5U

#define PCIE_LNKCAP_OFFSET 0x0Cu
#define PCIE_LNKCAP_PN_SHIFT 24u
#define PCIE_LNKCAP_PN_MASK 0xFFu
#define RMECDA_CTL1_TDISP_EN_MASK 0x1u
#define RMECDA_CTL1_LINK_STR_LOCK_MASK (1u << 1)

typedef struct {
  uint32_t host_index;
  uint32_t endpoint_index;
  uint64_t window_base;
  uint64_t window_size;
  uint64_t host_decoder_base_orig;
  uint64_t host_decoder_size_orig;
  uint64_t endpoint_decoder_base_orig;
  uint64_t endpoint_decoder_size_orig;
  uint32_t host_target_low_orig;
  uint32_t host_target_high_orig;
  uint32_t host_target_valid;
} CONTEXT;

static uint32_t
read_from_root(uint64_t address, uint32_t *value)
{
  if (value == NULL)
    return ACS_STATUS_ERR;

  shared_data->num_access = 1;
  shared_data->shared_data_access[0].addr = address;
  shared_data->shared_data_access[0].access_type = READ_DATA;

  if (val_pe_access_mut_el3())
  {
    val_print(ACS_PRINT_ERR, " RLQMCY: MUT read failed for 0x%llx", address);
    return ACS_STATUS_ERR;
  }

  *value = (uint32_t)shared_data->shared_data_access[0].data;
  return ACS_STATUS_PASS;
}

static uint32_t
write_from_root(uint64_t address, uint32_t value)
{
  shared_data->num_access = 1;
  shared_data->shared_data_access[0].addr = address;
  shared_data->shared_data_access[0].data = value;
  shared_data->shared_data_access[0].access_type = WRITE_DATA;

  if (val_pe_access_mut_el3())
  {
    val_print(ACS_PRINT_ERR, " RLQMCY: MUT write failed for 0x%llx", address);
    return ACS_STATUS_ERR;
  }

  return ACS_STATUS_PASS;
}

static uint32_t
map_window_alias(uint64_t phys,
                 uint32_t pas,
                 volatile uint32_t **virt_out)
{
  uint64_t page_size;
  uint64_t va;
  uint32_t attr;

  val_print(ACS_PRINT_DEBUG, " RLQMCY: Map window phys 0x%llx\n", phys);

  /* Validate inputs before building a temporary mapping. */
  if ((phys == 0u) || (virt_out == NULL))
  {
    val_print(ACS_PRINT_ERR, " RLQMCY: Invalid map inputs\n", 0);
    return ACS_STATUS_ERR;
  }

  /* Determine the page size used for the mapping. */
  page_size = (uint64_t)val_memory_page_size();
  if (page_size == 0u)
  {
    val_print(ACS_PRINT_ERR, " RLQMCY: Invalid page size\n", 0);
    return ACS_STATUS_ERR;
  }

  /* Obtain a free virtual address range for a single page. */
  va = val_get_free_va(page_size);
  if (va == 0u)
  {
    val_print(ACS_PRINT_ERR, " RLQMCY: Failed to get free VA\n", 0);
    return ACS_STATUS_ERR;
  }

  if (val_add_gpt_entry_el3(phys, GPT_ANY)) {
      val_print(ACS_PRINT_ERR, " Failed to add GPT entry for PA 0x%lx", phys);
      return ACS_STATUS_ERR;
  }
  /* Build device attributes with the requested PAS. */
  attr = LOWER_ATTRS(PGT_ENTRY_ACCESS |
                     SHAREABLE_ATTR(OUTER_SHAREABLE) |
                     GET_ATTR_INDEX(DEV_MEM_nGnRnE) |
                     PGT_ENTRY_AP_RW |
                     PAS_ATTR(pas));

  /* Map the physical window into the temporary VA region. */
  if (val_add_mmu_entry_el3(va, phys, attr))
  {
    val_print(ACS_PRINT_ERR, " RLQMCY: Failed to map window\n", 0);
    return ACS_STATUS_ERR;
  }

  /* Return the alias address to the caller. */
  *virt_out = (volatile uint32_t *)va;
  val_print(ACS_PRINT_DEBUG, " RLQMCY: Mapped alias 0x%llx\n", va);
  return ACS_STATUS_PASS;
}

static void
clear_decoder(uint64_t comp_base,
              uint32_t decoder_index,
              uint32_t clear_targets)
{
  uint64_t cap_base;
  uint64_t base_low_addr;
  uint64_t base_high_addr;
  uint64_t size_low_addr;
  uint64_t size_high_addr;
  uint64_t ctrl_addr;
  uint64_t target_low_addr;
  uint64_t target_high_addr;
  uint32_t ctrl;
  uint32_t attempt;

  /* Exit early if the component base is invalid. */
  if (comp_base == 0u)
    return;

  if (val_cxl_find_capability(comp_base, CXL_CAPID_HDM_DECODER, &cap_base)
      != ACS_STATUS_PASS)
    return;

  base_low_addr = cap_base + CXL_HDM_DECODER_BASE_LOW(decoder_index);
  base_high_addr = cap_base + CXL_HDM_DECODER_BASE_HIGH(decoder_index);
  size_low_addr = cap_base + CXL_HDM_DECODER_SIZE_LOW(decoder_index);
  size_high_addr = cap_base + CXL_HDM_DECODER_SIZE_HIGH(decoder_index);
  ctrl_addr = cap_base + CXL_HDM_DECODER_CTRL(decoder_index);
  target_low_addr = cap_base + CXL_HDM_DECODER_TARGET_LOW(decoder_index);
  target_high_addr = cap_base + CXL_HDM_DECODER_TARGET_HIGH(decoder_index);

  /* Clear COMMIT to release the decoder if it is still active. */
  ctrl = val_mmio_read(ctrl_addr);
  val_mmio_write(ctrl_addr, ctrl & ~CXL_HDM_COMMIT_BIT);
  for (attempt = 0; attempt < CXL_HDM_COMMIT_TIMEOUT_MS; ++attempt)
  {
    uint32_t status = val_mmio_read(ctrl_addr);
    if ((status & CXL_HDM_COMMITTED_BIT) == 0u)
      break;
    (void)val_time_delay_ms(1);
  }

  /* Clear the programmed base/size to avoid stale ranges. */
  val_mmio_write(base_low_addr, 0u);
  val_mmio_write(base_high_addr, 0u);
  val_mmio_write(size_low_addr, 0u);
  val_mmio_write(size_high_addr, 0u);

  /* Clear the target list when requested. */
  if (clear_targets != 0u)
  {
    val_mmio_write(target_low_addr, 0u);
    val_mmio_write(target_high_addr, 0u);
  }
}

static void
restore_host_target_list(const CONTEXT *context)
{
  uint64_t comp_base;
  uint64_t cap_base;

  /* Exit early if there is no saved target list. */
  if ((context == NULL) || (context->host_target_valid == 0u))
    return;

  comp_base = val_cxl_get_info(CXL_INFO_COMPONENT_BASE, context->host_index);
  if (comp_base == 0u)
    return;

  if (val_cxl_find_capability(comp_base, CXL_CAPID_HDM_DECODER, &cap_base)
      != ACS_STATUS_PASS)
    return;

  /* Restore the host target list programmed before the test. */
  val_mmio_write(cap_base + CXL_HDM_DECODER_TARGET_LOW(DECODER_SLOT),
                 context->host_target_low_orig);
  val_mmio_write(cap_base + CXL_HDM_DECODER_TARGET_HIGH(DECODER_SLOT),
                 context->host_target_high_orig);
}

static void
restore_decoders(const CONTEXT *context)
{
  CXL_COMPONENT_TABLE *table;
  uint64_t comp_base;

  /* Exit early if there is no saved decoder context. */
  if (context == NULL)
    return;

  /* Restore host decoder settings if they were captured. */
  if (context->host_index != CXL_COMPONENT_INVALID_INDEX)
  {
    if (context->host_decoder_size_orig != 0u)
    {
      (void)val_cxl_program_host_decoder(context->host_index,
                                         DECODER_SLOT,
                                         context->host_decoder_base_orig,
                                         context->host_decoder_size_orig);
      restore_host_target_list(context);
    }
    else
    {
      comp_base = val_cxl_get_info(CXL_INFO_COMPONENT_BASE, context->host_index);
      clear_decoder(comp_base, DECODER_SLOT, 1u);
    }
  }

  /* Restore endpoint decoder settings if they were captured. */
  if (context->endpoint_index != CXL_COMPONENT_INVALID_INDEX)
  {
    if (context->endpoint_decoder_size_orig != 0u)
    {
      (void)val_cxl_program_component_decoder(context->endpoint_index,
                                              DECODER_SLOT,
                                              context->endpoint_decoder_base_orig,
                                              context->endpoint_decoder_size_orig);
    }
    else
    {
      table = val_cxl_component_table_ptr();
      comp_base = 0u;
      if ((table != NULL) && (context->endpoint_index < table->num_entries))
        comp_base = table->component[context->endpoint_index].component_reg_base;
      clear_decoder(comp_base, DECODER_SLOT, 0u);
    }
  }
}

static uint32_t
program_host_target_list(uint32_t bdf,
                 uint64_t comp_base,
                 uint32_t decoder_index,
                 CONTEXT *context)
{
  uint32_t pcie_cap_offset;
  uint32_t lnkcap;
  uint32_t port_id;
  uint64_t hdm_cap_base;
  uint32_t target_low;
  uint32_t target_high;

  if (context == NULL)
    return ACS_STATUS_ERR;

  /* Read the root port number from PCIe LNKCAP.PN. */
  if (val_pcie_find_capability(bdf, PCIE_CAP, CID_PCIECS, &pcie_cap_offset) != 0u)
  {
    val_print(ACS_PRINT_ERR, " RLQMCY: PCIe cap not found", 0);
    return ACS_STATUS_ERR;
  }

  if (val_pcie_read_cfg(bdf, pcie_cap_offset + PCIE_LNKCAP_OFFSET, &lnkcap) != 0u)
  {
    val_print(ACS_PRINT_ERR, " RLQMCY: LNKCAP read failed", 0);
    return ACS_STATUS_ERR;
  }

  port_id = (lnkcap >> PCIE_LNKCAP_PN_SHIFT) & PCIE_LNKCAP_PN_MASK;
  val_print(ACS_PRINT_DEBUG, " RLQMCY: LNKCAP 0x%x\n", lnkcap);
  val_print(ACS_PRINT_DEBUG, " RLQMCY: Root port ID %u\n", port_id);

  /* Program the target list for the host decoder. */
  if (val_cxl_find_capability(comp_base, CXL_CAPID_HDM_DECODER, &hdm_cap_base)
      != ACS_STATUS_PASS)
  {
    val_print(ACS_PRINT_ERR, " RLQMCY: Host HDM cap missing", 0);
    return ACS_STATUS_ERR;
  }

  /* Capture the original target list for restore. */
  target_low = val_mmio_read(hdm_cap_base +
                             CXL_HDM_DECODER_TARGET_LOW(decoder_index));
  target_high = val_mmio_read(hdm_cap_base +
                              CXL_HDM_DECODER_TARGET_HIGH(decoder_index));
  context->host_target_low_orig = target_low;
  context->host_target_high_orig = target_high;
  context->host_target_valid = 1u;

  /* Program the target list for the selected root port. */
  val_mmio_write(hdm_cap_base + CXL_HDM_DECODER_TARGET_LOW(decoder_index),
                 port_id);
  val_mmio_write(hdm_cap_base + CXL_HDM_DECODER_TARGET_HIGH(decoder_index),
                 0u);
  val_print(ACS_PRINT_DEBUG, " RLQMCY: Target list programmed\n", 0);

  return ACS_STATUS_PASS;
}

static uint32_t
setup_decoders(const CXL_COMPONENT_ENTRY *root,
               const CXL_COMPONENT_ENTRY *endpoint,
               uint32_t endpoint_index,
               CONTEXT *context)
{
  uint32_t host_index;
  uint32_t status;
  uint64_t host_comp_base;

  val_print(ACS_PRINT_DEBUG,
            " RLQMCY: Setup decoders for endpoint %u\n",
            endpoint_index);

  /* Validate inputs before probing decoder capabilities. */
  if ((root == NULL) || (endpoint == NULL) || (context == NULL))
  {
    val_print(ACS_PRINT_ERR, " RLQMCY: Invalid decoder inputs\n", 0);
    return ACS_STATUS_ERR;
  }

  /* Initialize the context so cleanup logic can rely on defaults. */
  val_memory_set(context, sizeof(*context), 0);
  context->host_index = CXL_COMPONENT_INVALID_INDEX;
  context->endpoint_index = CXL_COMPONENT_INVALID_INDEX;
  context->host_target_valid = 0u;

  /* Resolve the host bridge index for programming decoders. */
  host_index = root->host_bridge_index;
  if (host_index == CXL_COMPONENT_INVALID_INDEX)
  {
    val_print(ACS_PRINT_DEBUG, " RLQMCY: Host bridge index invalid\n", 0);
    return ACS_STATUS_SKIP;
  }

  /* Reject host indices beyond the discovered device list. */
  if (host_index >= (uint32_t)val_cxl_get_info(CXL_INFO_NUM_DEVICES, 0))
  {
    val_print(ACS_PRINT_DEBUG, " RLQMCY: Host index out of range\n", 0);
    return ACS_STATUS_SKIP;
  }

  /* Ensure the host bridge advertises an HDM decoder. */
  host_comp_base = val_cxl_get_info(CXL_INFO_COMPONENT_BASE, host_index);
  if ((host_comp_base == 0u) ||
      (val_cxl_find_capability(host_comp_base,
                               CXL_CAPID_HDM_DECODER,
                               NULL) != ACS_STATUS_PASS))
  {
    val_print(ACS_PRINT_DEBUG, " RLQMCY: Host HDM decoder missing\n", 0);
    return ACS_STATUS_SKIP;
  }

  /* Ensure the endpoint also advertises an HDM decoder. */
  if ((endpoint->component_reg_base == 0u) ||
      (val_cxl_find_capability(endpoint->component_reg_base,
                               CXL_CAPID_HDM_DECODER,
                               NULL) != ACS_STATUS_PASS))
  {
    val_print(ACS_PRINT_DEBUG, " RLQMCY: Endpoint HDM decoder missing\n", 0);
    return ACS_STATUS_SKIP;
  }

  /* Select a CFMWS window shared between host and endpoint. */
  status = val_cxl_select_cfmws_window(host_index,
                                       &context->window_base,
                                       &context->window_size);
  if (status != ACS_STATUS_PASS)
  {
    val_print(ACS_PRINT_DEBUG, " RLQMCY: No CFMWS window\n", 0);
    return ACS_STATUS_SKIP;
  }

  context->host_index = host_index;
  context->endpoint_index = endpoint_index;

  /* Program the host target list to route to the downstream port. */
  status = program_host_target_list(root->bdf,
                                    host_comp_base,
                                    DECODER_SLOT,
                                    context);
  if (status != ACS_STATUS_PASS)
  {
    val_print(ACS_PRINT_ERR, " RLQMCY: Target list programming failed", 0);
    return status;
  }

  /* Save the original host decoder settings for restore. */
  if (val_cxl_get_decoder(context->host_index,
                          DECODER_SLOT,
                          &context->host_decoder_base_orig,
                          &context->host_decoder_size_orig) != 0u)
  {
    context->host_decoder_base_orig = 0u;
    context->host_decoder_size_orig = 0u;
  }

  /* Save the original endpoint decoder settings for restore. */
  if (val_cxl_get_component_decoder(context->endpoint_index,
                                    DECODER_SLOT,
                                    &context->endpoint_decoder_base_orig,
                                    &context->endpoint_decoder_size_orig) != 0u)
  {
    context->endpoint_decoder_base_orig = 0u;
    context->endpoint_decoder_size_orig = 0u;
  }

  /* Program the host decoder to target the selected window. */
  status = val_cxl_program_host_decoder(context->host_index,
                                        DECODER_SLOT,
                                        context->window_base,
                                        context->window_size);
  if (status != ACS_STATUS_PASS)
  {
    val_print(ACS_PRINT_ERR, " RLQMCY: Host decoder program failed\n", 0);
    restore_decoders(context);
    return status;
  }

  /* Program the endpoint decoder to match the host window. */
  status = val_cxl_program_component_decoder(context->endpoint_index,
                                             DECODER_SLOT,
                                             context->window_base,
                                             context->window_size);
  if (status != ACS_STATUS_PASS)
  {
    val_print(ACS_PRINT_ERR, " RLQMCY: Endpoint decoder program failed\n", 0);
    restore_decoders(context);
    return status;
  }

  val_print(ACS_PRINT_DEBUG, " RLQMCY: Decoder setup complete\n", 0);
  return ACS_STATUS_PASS;
}

static uint32_t
select_test_base(uint64_t window_base,
                 uint64_t window_size,
                 uint64_t *test_base_out)
{
  uint64_t page_size;
  uint64_t window_end;
  uint64_t aligned_base;

  val_print(ACS_PRINT_DEBUG, " RLQMCY: Select test base\n", 0);

  /* Require a valid output pointer for the chosen base. */
  if (test_base_out == NULL)
  {
    val_print(ACS_PRINT_ERR, " RLQMCY: Test base output NULL\n", 0);
    return ACS_STATUS_ERR;
  }

  /* Use the platform page size for alignment. */
  page_size = (uint64_t)val_memory_page_size();
  if (page_size == 0u)
  {
    val_print(ACS_PRINT_ERR, " RLQMCY: Invalid page size\n", 0);
    return ACS_STATUS_ERR;
  }

  /* Skip windows too small for a single mapped page. */
  if (window_size < page_size)
  {
    val_print(ACS_PRINT_DEBUG, " RLQMCY: Window smaller than page\n", 0);
    return ACS_STATUS_SKIP;
  }

  window_end = window_base + window_size;
  /* Detect overflow in the window end calculation. */
  if (window_end < window_base)
  {
    val_print(ACS_PRINT_ERR, " RLQMCY: Window end overflow\n", 0);
    return ACS_STATUS_ERR;
  }

  /* Align the base to the page size. */
  aligned_base = (window_base + page_size - 1u) & ~(page_size - 1u);
  if ((aligned_base + page_size) > window_end)
  {
    val_print(ACS_PRINT_DEBUG, " RLQMCY: Aligned base out of window\n", 0);
    return ACS_STATUS_SKIP;
  }

  /* Return the aligned base to the caller. */
  *test_base_out = aligned_base;
  val_print(ACS_PRINT_DEBUG, " RLQMCY: Test base 0x%llx\n", aligned_base);
  return ACS_STATUS_PASS;
}

static uint32_t
validate_host_mpe(uint64_t test_base)
{
  volatile uint32_t *mapped = NULL;
  uint32_t data_write = TEST_DATA_PATTERN;
  uint32_t data_read;
  uint32_t status;

  val_print(ACS_PRINT_DEBUG, " RLQMCY: Validate host MPE\n", 0);

  /* Host-side MPE should modify data when MECID changes across accesses. */

  /* Map the test base into a Realm PAS alias. */
  status = map_window_alias(test_base, REALM_PAS, &mapped);
  if (status != ACS_STATUS_PASS)
  {
    val_print(ACS_PRINT_ERR, " RLQMCY: Map alias failed\n", 0);
    return status;
  }

  /* Configure MECID1 for the write operation. */
  if (val_rlm_configure_mecid(MECID1))
  {
    val_print(ACS_PRINT_ERR, " RLQMCY: Failed to program MECID1", 0);
    return ACS_STATUS_FAIL;
  }

  val_print(ACS_PRINT_DEBUG, " RLQMCY: MECID1 programmed\n", 0);

  shared_data->num_access = 1;
  shared_data->shared_data_access[0].addr = (uint64_t)mapped;
  shared_data->shared_data_access[0].data = data_write;
  shared_data->shared_data_access[0].access_type = WRITE_DATA;

  /* Perform the write through the MUT access helper. */
  if (val_pe_access_mut_el3())
  {
    val_print(ACS_PRINT_ERR, " RLQMCY: Write to CXL.mem failed", 0);
    return ACS_STATUS_FAIL;
  }

  val_print(ACS_PRINT_DEBUG, " RLQMCY: Write complete\n", 0);

  /* Ensure data reaches the Point of Encryption before switching MECID. */
  if (val_cmo_to_poe(test_base))
  {
    val_print(ACS_PRINT_ERR, " RLQMCY: CMO to PoE failed", 0);
    return ACS_STATUS_FAIL;
  }

  val_print(ACS_PRINT_DEBUG, " RLQMCY: CMO to PoE complete\n", 0);

  /* Configure MECID2 for the read operation. */
  if (val_rlm_configure_mecid(MECID2))
  {
    val_print(ACS_PRINT_ERR, " RLQMCY: Failed to program MECID2", 0);
    return ACS_STATUS_FAIL;
  }

  val_print(ACS_PRINT_DEBUG, " RLQMCY: MECID2 programmed\n", 0);

  shared_data->num_access = 1;
  shared_data->shared_data_access[0].addr = (uint64_t)mapped;
  shared_data->shared_data_access[0].access_type = READ_DATA;

  /* Perform the read through the MUT access helper. */
  if (val_pe_access_mut_el3())
  {
    val_print(ACS_PRINT_ERR, " RLQMCY: Read from CXL.mem failed", 0);
    return ACS_STATUS_FAIL;
  }

  val_print(ACS_PRINT_DEBUG, " RLQMCY: Read complete\n", 0);

  data_read = shared_data->shared_data_access[0].data;
  val_print(ACS_PRINT_DEBUG, " RLQMCY: MECID2 read addr 0x%llx\n", (uint64_t)mapped);
  val_print(ACS_PRINT_DEBUG, " RLQMCY: MECID2 read data 0x%x\n", data_read);
  /* Data must differ when host-side MPE is applied. */
  if (data_read == data_write)
  {
    val_print(ACS_PRINT_ERR, " RLQMCY: Host-side MPE not observed", 0);
    return ACS_STATUS_FAIL;
  }

  val_print(ACS_PRINT_DEBUG, " RLQMCY: Host MPE validated\n", 0);
  return ACS_STATUS_PASS;
}

static void
payload(void)
{
  uint32_t pe_index = val_pe_get_index_mpid(val_pe_get_mpid());
  CXL_COMPONENT_TABLE *table = val_cxl_component_table_ptr();
  uint32_t failures = 0u;
  uint32_t evaluated = 0u;
  uint32_t targetless = 0u;
  uint32_t mec_enabled = 0u;
  uint32_t status;

  val_print(ACS_PRINT_DEBUG, " RLQMCY: Payload start\n", 0);

  /* Iterate Type-3 endpoints that report no target encryption support. */
  if ((table == NULL) || (table->num_entries == 0u))
  {
    val_print(ACS_PRINT_DEBUG, " RLQMCY: No CXL components discovered", 0);
    val_set_status(pe_index, "SKIP", 01);
    return;
  }

  /* Skip if Memory Encryption Contexts are not supported. */
  if (val_is_mec_supported() == 0u)
  {
    val_print(ACS_PRINT_DEBUG, " RLQMCY: MEC unsupported", 0);
    val_set_status(pe_index, "SKIP", 02);
    return;
  }

  /* Enable MEC for the duration of the test. */
  if (val_rlm_enable_mec())
  {
    val_print(ACS_PRINT_ERR, " RLQMCY: Failed to enable MEC", 0);
    val_set_status(pe_index, "FAIL", 01);
    return;
  }
  mec_enabled = 1u;
  val_print(ACS_PRINT_DEBUG, " RLQMCY: MEC enabled\n", 0);

  for (uint32_t root_index = 0; root_index < table->num_entries; ++root_index)
  {
    const CXL_COMPONENT_ENTRY *root = &table->component[root_index];
    const CXL_COMPONENT_ENTRY *endpoint;
    uint32_t endpoint_index;
    uint32_t rmecda_cap_base = 0u;
    uint32_t ctl1_original = 0u;
    uint32_t ctl1_programmed = 0u;
    uint32_t ctl1_readback = 0u;
    uint32_t ctl1_valid = 0u;
    uint64_t cfg_addr = 0u;
    uint64_t cfg_va = 0u;
    uint32_t attr;
    uint64_t tg;
    val_spdm_context_t ctx;
    uint32_t session_id = 0u;
    uint32_t session_active = 0u;
    libcxltsp_device_capabilities_t capabilities;
    uint32_t features;
    CONTEXT context;
    uint64_t test_base;

    /* Use root ports as the source for downstream CXL.mem devices. */
    if (root->role != CXL_COMPONENT_ROLE_ROOT_PORT)
      continue;

    val_print(ACS_PRINT_DEBUG, " RLQMCY: Root port %u\n", root_index);

    /* Locate a Type-3 endpoint reachable from the root port. */
    status = val_cxl_find_downstream_endpoint(root_index, &endpoint_index);
    if (status != ACS_STATUS_PASS)
    {
      val_print(ACS_PRINT_DEBUG, " RLQMCY: No endpoint for root\n", 0);
      continue;
    }

    endpoint = &table->component[endpoint_index];
    if (endpoint->device_type != CXL_DEVICE_TYPE_TYPE3)
      continue;

    val_print(ACS_PRINT_DEBUG,
              " RLQMCY: Type-3 endpoint %u\n",
              endpoint_index);

    /* Start an SPDM session to query CXL TSP capabilities. */
    status = val_spdm_session_open(endpoint->bdf, &ctx, &session_id);
    if (status == ACS_STATUS_SKIP)
      continue;
    if (status != ACS_STATUS_PASS)
    {
      val_print(ACS_PRINT_ERR, " RLQMCY: SPDM session open failed\n", 0);
      failures++;
      continue;
    }
    session_active = 1u;
    val_print(ACS_PRINT_DEBUG, " RLQMCY: SPDM session open\n", 0);

    /* Check the negotiated CXL TSP version for the endpoint. */
    status = val_spdm_send_cxl_tsp_get_version(&ctx, session_id);
    if (status != ACS_STATUS_PASS)
    {
      val_print(ACS_PRINT_ERR, " RLQMCY: Get version failed\n", 0);
      failures++;
      goto device_cleanup;
    }

    val_memory_set(&capabilities, sizeof(capabilities), 0);
    /* Fetch memory encryption capabilities via CXL TSP. */
    status = val_spdm_send_cxl_tsp_get_capabilities(&ctx,
                                                    session_id,
                                                    &capabilities);
    if (status != ACS_STATUS_PASS)
    {
      val_print(ACS_PRINT_ERR, " RLQMCY: Get capabilities failed\n", 0);
      failures++;
      goto device_cleanup;
    }

    features = capabilities.memory_encryption_features_supported;
    /* Skip devices that already support target encryption. */
    if ((features &
         CXL_TSP_MEMORY_ENCRYPTION_FEATURES_SUPPORT_ENCRYPTION) != 0u)
      goto device_cleanup;

    targetless++;
    val_print(ACS_PRINT_DEBUG, " RLQMCY: Targetless endpoint\n", 0);

    /* Enable CXL.mem in the endpoint device control DVSEC. */
    status = val_cxl_enable_mem(endpoint->bdf);
    if (status != ACS_STATUS_PASS)
    {
      val_print(ACS_PRINT_ERR, " RLQMCY: CXL.mem enable failed\n", 0);
      failures++;
      goto device_cleanup;
    }

    /* Map a window for the Type-3 device and verify host-side MPE. */
    status = setup_decoders(root, endpoint, endpoint_index, &context);
    if (status == ACS_STATUS_SKIP)
    {
      val_print(ACS_PRINT_DEBUG, " RLQMCY: Decoder setup skipped\n", 0);
      goto device_cleanup;
    }
    if (status != ACS_STATUS_PASS)
    {
      val_print(ACS_PRINT_ERR, " RLQMCY: Decoder setup failed\n", 0);
      failures++;
      goto device_cleanup;
    }

    /* Enable TDISP and lock the link after decoder programming. */
    status = val_pcie_find_cda_capability(root->bdf, &rmecda_cap_base);
    if (status != ACS_STATUS_PASS)
    {
      val_print(ACS_PRINT_DEBUG,
                " RLQMCY: RME-CDA DVSEC missing for BDF 0x%x",
                (uint64_t)root->bdf);
      goto device_cleanup;
    }

    cfg_addr = val_pcie_get_bdf_config_addr(root->bdf);
    tg = val_get_min_tg();
    if ((cfg_addr == 0u) || (tg == 0u))
    {
      val_print(ACS_PRINT_ERR,
                " RLQMCY: Invalid config mapping for BDF 0x%x",
                (uint64_t)root->bdf);
      failures++;
      goto device_cleanup;
    }

    cfg_va = val_get_free_va(tg);
    if (cfg_va == 0u)
    {
      val_print(ACS_PRINT_ERR,
                " RLQMCY: Config VA allocation failed for BDF 0x%x",
                (uint64_t)root->bdf);
      failures++;
      goto device_cleanup;
    }

    attr = LOWER_ATTRS(PGT_ENTRY_ACCESS | SHAREABLE_ATTR(OUTER_SHAREABLE) |
                       GET_ATTR_INDEX(DEV_MEM_nGnRnE) | PGT_ENTRY_AP_RW |
                       PAS_ATTR(ROOT_PAS));
    if (val_add_mmu_entry_el3(cfg_va, cfg_addr, attr))
    {
      val_print(ACS_PRINT_ERR,
                " RLQMCY: Config map failed for BDF 0x%x",
                (uint64_t)root->bdf);
      failures++;
      goto device_cleanup;
    }

    if (read_from_root(cfg_va + rmecda_cap_base + RMECDA_CTL1_OFFSET,
                       &ctl1_original) != ACS_STATUS_PASS)
    {
      val_print(ACS_PRINT_ERR,
                " RLQMCY: RMECDA_CTL1 read failed for BDF 0x%x",
                (uint64_t)root->bdf);
      failures++;
      goto device_cleanup;
    }

    ctl1_programmed = ctl1_original |
                      RMECDA_CTL1_TDISP_EN_MASK |
                      RMECDA_CTL1_LINK_STR_LOCK_MASK;
    if (write_from_root(cfg_va + rmecda_cap_base + RMECDA_CTL1_OFFSET,
                        ctl1_programmed) != ACS_STATUS_PASS)
    {
      val_print(ACS_PRINT_ERR,
                " RLQMCY: RMECDA_CTL1 write failed for BDF 0x%x",
                (uint64_t)root->bdf);
      failures++;
      goto device_cleanup;
    }

    if (read_from_root(cfg_va + rmecda_cap_base + RMECDA_CTL1_OFFSET,
                       &ctl1_readback) != ACS_STATUS_PASS)
    {
      val_print(ACS_PRINT_ERR,
                " RLQMCY: RMECDA_CTL1 readback failed for BDF 0x%x",
                (uint64_t)root->bdf);
      failures++;
      goto device_cleanup;
    }

    if ((ctl1_readback &
         (RMECDA_CTL1_TDISP_EN_MASK | RMECDA_CTL1_LINK_STR_LOCK_MASK)) !=
        (RMECDA_CTL1_TDISP_EN_MASK | RMECDA_CTL1_LINK_STR_LOCK_MASK))
    {
      val_print(ACS_PRINT_ERR,
                " RLQMCY: RMECDA_CTL1 not set for BDF 0x%x",
                (uint64_t)root->bdf);
      failures++;
      goto device_cleanup;
    }
    ctl1_valid = 1u;

    status = select_test_base(context.window_base,
                              context.window_size,
                              &test_base);
    /* Ensure the test base is valid and aligned. */
    if (status == ACS_STATUS_SKIP)
    {
      val_print(ACS_PRINT_DEBUG, " RLQMCY: Test base skipped\n", 0);
      restore_decoders(&context);
      goto device_cleanup;
    }
    if (status != ACS_STATUS_PASS)
    {
      val_print(ACS_PRINT_ERR, " RLQMCY: Test base selection failed\n", 0);
      restore_decoders(&context);
      failures++;
      goto device_cleanup;
    }

    status = validate_host_mpe(test_base);
    restore_decoders(&context);

    /* Restore the global MECID after the access sequence. */
    if (val_rlm_configure_mecid(VAL_GMECID))
      val_print(ACS_PRINT_WARN, " RLQMCY: Failed to restore GMECID", 0);

    if (status != ACS_STATUS_PASS)
    {
      val_print(ACS_PRINT_ERR, " RLQMCY: Host MPE validation failed\n", 0);
      failures++;
      goto device_cleanup;
    }

    evaluated++;
    val_print(ACS_PRINT_DEBUG, " RLQMCY: Endpoint evaluated\n", 0);

device_cleanup:
    if (ctl1_valid != 0u)
    {
      (void)write_from_root(cfg_va + rmecda_cap_base + RMECDA_CTL1_OFFSET,
                            ctl1_original);
    }
    /* Close the SPDM session if one was opened. */
    if (session_active != 0u)
    {
      if (val_spdm_session_close(&ctx, session_id) != ACS_STATUS_PASS)
      {
        val_print(ACS_PRINT_WARN,
                  " RLQMCY: Session close failed for BDF 0x%x",
                  (uint64_t)endpoint->bdf);
      }
      else
      {
        val_print(ACS_PRINT_DEBUG, " RLQMCY: Session closed\n", 0);
      }
    }
  }

  if (mec_enabled != 0u)
  {
    /* Disable MEC once the test completes. */
    if (val_rlm_disable_mec())
      val_print(ACS_PRINT_WARN, " RLQMCY: Failed to disable MEC", 0);
    else
      val_print(ACS_PRINT_DEBUG, " RLQMCY: MEC disabled\n", 0);
  }

  /* Skip when no Type-3 devices lacked target encryption. */
  if (targetless == 0u)
  {
    val_print(ACS_PRINT_DEBUG,
              " RLQMCY: No Type-3 devices without target encryption",
              0);
    val_set_status(pe_index, "SKIP", 03);
    return;
  }

  if (failures != 0u)
  {
    /* Report aggregated failures across endpoints. */
    val_set_status(pe_index, "FAIL", failures);
  }
  else if (evaluated == 0u)
  {
    /* Report skip when none were evaluated. */
    val_set_status(pe_index, "SKIP", 04);
  }
  else
  {
    /* Report pass with the number of evaluated endpoints. */
    val_set_status(pe_index, "PASS", evaluated);
  }

  val_print(ACS_PRINT_DEBUG, " RLQMCY: Payload end\n", 0);
}

#else

static void
payload(void)
{
  uint32_t pe_index = val_pe_get_index_mpid(val_pe_get_mpid());

  /* Report skip when SPDM is disabled in this build. */
  val_print(ACS_PRINT_WARN, " SPDM support disabled - skipping RLQMCY", 0);
  val_set_status(pe_index, "SKIP", 05);
}

#endif

uint32_t
cxl_rlqmcy_type3_host_mpe_entry(uint32_t num_pe)
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
