/** @file
 * Copyright (c) 2026, Arm Limited or its affiliates. All rights reserved.
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
#include "include/val.h"
#include "include/val_common.h"
#include "include/val_pcie.h"
#include "include/val_memory.h"
#include "include/val_el32.h"
#include "include/val_ide_km.h"


/**
 * @brief Send an RP IDE operation and request descriptor to EL3.
 *
 * @param rp_bdf Root Port BDF.
 * @param operation PROGRAM, GO or STOP operation.
 * @param selector Stream, direction, key set and substream.
 * @param key Key material for PROGRAM; NULL for GO and STOP.
 * @return ACS_STATUS_PASS, ACS_STATUS_SKIP for an unsupported backend, or ACS_STATUS_ERR.
 */
static uint32_t
pcie_rp_ide_call(uint32_t rp_bdf, uint32_t operation,
                 const PCIE_IDE_SELECTOR *selector, const PCIE_IDE_KEY *key)
{
  PCIE_IDE_REQUEST request;
  uint32_t status = 1u;
  uint64_t cfg, va, pa, last, tg, attr;

  if (selector == NULL || selector->direction > PCIE_IDE_TX ||
      selector->key_set > 1u || selector->sub_stream > 2u ||
      (operation == IDE_PCIE_KEY_PROG && key == NULL))
    return ACS_STATUS_ERR;

  cfg = val_pcie_get_bdf_config_addr(rp_bdf);
  if (cfg == 0u)
    return ACS_STATUS_ERR;

  /* Prepare the RP IDE-KM request */
  val_memory_set(&request, sizeof(request), 0);
  request.rp_id = PCIE_CREATE_BDF_PACKED(rp_bdf);
  request.ecam_base = cfg - ((uint64_t)request.rp_id << 12);
  request.selector = *selector;
  if (key != NULL)
    request.key = *key;

  /* Map the request descriptor for EL3 access */
  tg = val_get_min_tg();
  attr = LOWER_ATTRS(PGT_ENTRY_ACCESS | SHAREABLE_ATTR(OUTER_SHAREABLE) |
                     PGT_ENTRY_AP_RW | PAS_ATTR(NONSECURE_PAS));
  va = (uint64_t)&request & ~(tg - 1u);
  last = ((uint64_t)&request + sizeof(request) - 1u) & ~(tg - 1u);
  for (; va <= last; va += tg) {
    pa = (uint64_t)val_memory_virt_to_phys((void *)va);
    if (val_add_gpt_entry_el3(pa, GPT_ANY) || val_add_mmu_entry_el3(va, pa, attr))
      goto cleanup;
  }

  /* Send the operation and descriptor address to EL3 */
  shared_data->arg0 = operation;
  shared_data->arg1 = (uint64_t)&request;
  shared_data->status_code = 0;
  UserCallSMC(ARM_ACS_SMC_FID, EL3_PCIE_IDE_KM, 0, 0, 0);

  status = shared_data->status_code;
  if (status != 0u) {
    if (status == PCIE_IDE_UNSUPPORTED)
      val_print(ACS_PRINT_WARN, " RP PCIe IDE backend unsupported, BDF: 0x%x", rp_bdf);
    else
      val_print(ACS_PRINT_ERR, " RP PCIe IDE operation failed, BDF: 0x%x", rp_bdf);
    val_print(ACS_PRINT_ERR, " RP IDE operation: 0x%x", operation);
    val_print(ACS_PRINT_ERR, " EL3/PAL status: 0x%x", status);
  }
cleanup:
  /* Erase the temporary key copy */
  val_memory_set(&request.key, sizeof(request.key), 0);
  if (status == PCIE_IDE_UNSUPPORTED)
    return ACS_STATUS_SKIP;
  return status == 0u ? ACS_STATUS_PASS : ACS_STATUS_ERR;
}

/**
 * @brief Program an RP IDE key through EL3.
 *
 * @param rp_bdf Root Port BDF.
 * @param selector Key selector.
 * @param key Key material and initial invocation field.
 * @return ACS_STATUS_PASS, ACS_STATUS_SKIP for an unsupported backend, or ACS_STATUS_ERR.
 */
uint32_t
val_pcie_rp_ide_key_program(uint32_t rp_bdf, const PCIE_IDE_SELECTOR *selector,
                           const PCIE_IDE_KEY *key)
{
  return pcie_rp_ide_call(rp_bdf, IDE_PCIE_KEY_PROG, selector, key);
}

/**
 * @brief Activate an RP IDE key set through EL3.
 *
 * @param rp_bdf Root Port BDF.
 * @param selector Key selector.
 * @return ACS_STATUS_PASS, ACS_STATUS_SKIP for an unsupported backend, or ACS_STATUS_ERR.
 */
uint32_t
val_pcie_rp_ide_key_go(uint32_t rp_bdf, const PCIE_IDE_SELECTOR *selector)
{
  return pcie_rp_ide_call(rp_bdf, IDE_PCIE_KEY_GO, selector, NULL);
}

/**
 * @brief Stop an RP IDE key set through EL3.
 *
 * @param rp_bdf Root Port BDF.
 * @param selector Key selector.
 * @return ACS_STATUS_PASS, ACS_STATUS_SKIP for an unsupported backend, or ACS_STATUS_ERR.
 */
uint32_t
val_pcie_rp_ide_key_stop(uint32_t rp_bdf, const PCIE_IDE_SELECTOR *selector)
{
  return pcie_rp_ide_call(rp_bdf, IDE_PCIE_KEY_STOP, selector, NULL);
}
