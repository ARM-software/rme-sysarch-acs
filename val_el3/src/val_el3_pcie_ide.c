/** @file
  * Copyright (c) 2025, 2026, Arm Limited or its affiliates. All rights reserved.
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
#include <val_el3_pe.h>
#include <val_el3_memory.h>
#include <val_el3_pcie_ide.h>
#include <val_el3_pgt.h>
#include <pal_el3.h>

/* RP configuration and key-management registers are accessed in Root PAS. */
static uint32_t
pcie_ide_map_mmio(uint64_t address)
{
  uint64_t attributes = LOWER_ATTRS(PGT_ENTRY_ACCESS |
                                   SHAREABLE_ATTR(OUTER_SHAREABLE) |
                                   GET_ATTR_INDEX(DEV_MEM_nGnRnE) |
                                   PGT_ENTRY_AP_RW | PAS_ATTR(ROOT_PAS));

  /* A zero address means PAL does not require this register mapping. */
  if (address == 0u)
    return PCIE_IDE_SUCCESS;
  if (val_el3_add_gpt_entry(address, GPT_ANY) != 0)
    return PCIE_IDE_ERROR;
  val_el3_tlbi_paallos();
  return val_el3_add_mmu_entry(address, address, attributes);
}

/* Map configuration space before PAL reads it to discover the RP backend. */
static uint32_t
pcie_ide_get_mapped_backend(const PCIE_IDE_REQUEST *request, PCIE_IDE_RP_REGISTERS *registers)
{
  uint64_t config_address;
  uint32_t status;

  status = pal_pcie_rp_ide_cfg_address(request->ecam_base, request->rp_id,
                                     &config_address);
  if (status != PCIE_IDE_SUCCESS)
    return status;

  if (pcie_ide_map_mmio(config_address) != PCIE_IDE_SUCCESS)
    return PCIE_IDE_ERROR;

  status = pal_pcie_rp_ide_km_address(config_address, registers);
  if (status != PCIE_IDE_SUCCESS)
    return status;

  if (pcie_ide_map_mmio(registers->keys) != PCIE_IDE_SUCCESS)
    return PCIE_IDE_ERROR;

  return pcie_ide_map_mmio(registers->control);
}

/* Validate the copied descriptor before discovering or touching RP registers. */
static uint32_t
pcie_ide_execute_request(uint32_t operation, const PCIE_IDE_REQUEST *request)
{
  const PCIE_IDE_SELECTOR *selector = &request->selector;
  PCIE_IDE_RP_REGISTERS registers = {0};
  uint32_t status;

  switch (operation) {
  case IDE_PCIE_KEY_PROG:
  case IDE_PCIE_KEY_GO:
  case IDE_PCIE_KEY_STOP:
    break;
  default:
    return PCIE_IDE_ERROR;
  }

  if (request->reserved != 0u || request->reserved2 != 0u)
    return PCIE_IDE_ERROR;

  /* The selector names one direction, key set and PR/NPR/Completion substream. */
  if (selector->direction > PCIE_IDE_TX || selector->key_set > 1u ||
      selector->sub_stream > 2u)
    return PCIE_IDE_ERROR;

  status = pcie_ide_get_mapped_backend(request, &registers);
  if (status != PCIE_IDE_SUCCESS)
    return status;

  switch (operation) {
  case IDE_PCIE_KEY_PROG:
    return pal_pcie_rp_ide_key_program(&registers, selector, &request->key);
  case IDE_PCIE_KEY_GO:
    return pal_pcie_rp_ide_key_go(&registers, selector);
  case IDE_PCIE_KEY_STOP:
    return pal_pcie_rp_ide_key_stop(&registers, selector);
  default:
    return PCIE_IDE_ERROR;
  }
}

/**
 * @brief Handle a Host VAL request for PCIe RP IDE key management.
 *
 * @param operation       PROGRAM, GO or STOP from shared_data->arg0.
 * @param request_address Address of the Host descriptor from shared_data->arg1.
 * @return PAL status, or PCIE_IDE_ERROR for an invalid descriptor.
 *
 * Host VAL maps the descriptor for EL3 access. Copy it before validation and
 * dispatch, then erase the local key material on every path after the copy.
 */
uint32_t
val_el3_pcie_ide_km_handle(uint32_t operation, uint64_t request_address)
{
  PCIE_IDE_REQUEST request;
  uint64_t request_end;
  uint32_t status;
  volatile uint8_t *key_bytes;

  /* Reject null or overflowing addresses before checking the mapped range. */
  if (request_address == 0u || request_address > UINT64_MAX - sizeof(request))
    return PCIE_IDE_ERROR;

  request_end = request_address + sizeof(request) - 1u;
  if ((val_el3_at_s1e3w(request_address) & 1u) != 0u ||
      (val_el3_at_s1e3w(request_end) & 1u) != 0u)
    return PCIE_IDE_ERROR;

  request = *(const PCIE_IDE_REQUEST *)request_address;
  status = pcie_ide_execute_request(operation, &request);

  /* Volatile stores prevent the compiler from removing the key wipe. */
  key_bytes = (volatile uint8_t *)&request.key;
  for (uint32_t index = 0; index < sizeof(request.key); ++index)
    key_bytes[index] = 0u;

  return status;
}
