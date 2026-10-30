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

#ifndef __RME_ACS_DPT_H__
#define __RME_ACS_DPT_H__

#define DPT_NO_ACCESS_ENTRY        0
#define DPT_READ_ONLY_ACCESS_ENTRY 1
#define DPT_RDWR_ACCESS_ENTRY      17

typedef struct {
  uint64_t pa;
  uint64_t original_gpi;
  uint32_t saved;
} VAL_DPT_GPT_STATE;

/* Initialize state to zero before use. Save the original GPI before allowing
 * access to the granule. A failed update may still require restoration.
 * Callers invalidate the requester SMMU after all setup GPT changes.
 */
uint32_t val_dpt_allow_gpt(uint64_t pa, VAL_DPT_GPT_STATE *state);

/* Quiesce/unmap the requester before restoring. Failure leaves state saved;
 * keep the affected memory reserved until restoration and maintenance succeed.
 */
uint32_t val_dpt_restore_gpt(VAL_DPT_GPT_STATE *state,
                           smmu_master_attributes_t *master);

/* The exerciser must already contain byte_pattern. Prove a permitted write,
 * clear the destination, then deny the same write and check every byte.
 * The destination must be accessible through EL3. The caller must restore
 * DPT permission on every return, including partial setup failures.
 */
uint32_t val_dpt_check_denied_write(uint32_t instance, uint32_t smmu_index,
                                  uint64_t destination_va, uint64_t destination_pa,
                                  uint32_t length, uint8_t byte_pattern);

/* On failure, bus mastering is disabled. Stop the test and retain its mappings,
 * policy and buffers: an outstanding DMA cannot safely be aborted by this API.
 */
uint32_t val_dpt_wait_for_dma(uint32_t instance);

uint32_t
dpt_system_resource_valid_without_dpti_entry(uint32_t num_pe);

uint32_t
dpt_system_resource_valid_with_dpti_entry(uint32_t num_pe);

uint32_t
dpt_system_resource_invalid_entry(uint32_t num_pe);

uint32_t
dpt_p2p_different_rootport_valid_entry(uint32_t num_pe);

uint32_t
dpt_p2p_different_rootport_invalid_entry(uint32_t num_pe);

uint32_t
dpt_p2p_same_rootport_valid_entry(uint32_t num_pe);

uint32_t
dpt_p2p_same_rootport_invalid_entry(uint32_t num_pe);
/* Establish a P2P target link and BAR association, lock its RP stream,
 * and transition the target TDI to RUN.
 * active_count is zero until keys are established; clean up a nonzero count
 * with val_dpt_ide_stop(), including when setup subsequently fails.
 */
uint32_t
val_dpt_ide_setup_target(uint32_t ep_bdf, uint32_t rp_bdf, uint32_t req_rp_bdf,
                          uint64_t bar, uint64_t size, uint32_t *active_count);

/* Unlock the RP stream, stop both partners and clear address associations
 * before disabling TDISP. Continue cleanup after errors and return ERR if
 * any step failed. A zero rp_count requires no cleanup.
 */
uint32_t
val_dpt_ide_stop(uint32_t ep_bdf, uint32_t rp_bdf, uint32_t ep_count,
                   uint32_t rp_count);
#endif
