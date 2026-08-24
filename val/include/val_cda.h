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

#ifndef __RME_ACS_CDA_H__
#define __RME_ACS_CDA_H__

#include "val_cxl.h"

typedef struct {
  uint32_t decoder_index;
  uint32_t host_index;
  uint32_t root_index;
  uint32_t root_bdf;
  uint32_t endpoint_index;
  uint32_t endpoint_bdf;
  uint64_t window_base;
  uint64_t window_size;
  uint64_t host_decoder_base_orig;
  uint64_t host_decoder_size_orig;
  uint64_t endpoint_decoder_base_orig;
  uint64_t endpoint_decoder_size_orig;
  uint32_t host_target_low_orig;
  uint32_t host_target_high_orig;
  uint32_t host_decoder_valid;
  uint32_t endpoint_decoder_valid;
  uint32_t rmecda_ctl1_orig;
  uint32_t rmecda_ctl1_valid;
  uint32_t rmecda_cap_base;
  uint64_t rmecda_cfg_va;
} VAL_CDA_DCM_WINDOW_CONTEXT;

uint32_t cda_rjzqcp_reset_transition_entry(uint32_t num_pe);
uint32_t cda_rydsyl_d2h_sec_sid_rid_entry(uint32_t num_pe);
uint32_t cda_rdmspt_rid_range_check_entry(uint32_t num_pe);
uint32_t cda_rkrcwk_host_side_gpc_entry(uint32_t num_pe);
uint32_t cda_rshrmn_coherent_link_topology_entry(uint32_t num_pe);
uint32_t cda_rqwnbn_error_poison_response_entry(uint32_t num_pe);
uint32_t cda_rhttnb_dirty_snoop_blocked_entry(uint32_t num_pe);
uint32_t cda_rlmflx_config_unlocked_invalidate_entry(uint32_t num_pe);
uint32_t cda_rwfylw_dev_prop_lock_entry(uint32_t num_pe);
uint32_t cda_rfzbmw_external_dcm_ide_gate_entry(uint32_t num_pe);
uint32_t cda_rwwbpm_internal_dcm_run_gate_entry(uint32_t num_pe);
uint32_t cda_rqrmsc_dcm_ats_dependency_entry(uint32_t num_pe);
uint32_t cda_rfrfjg_tdi_snoop_access_entry(uint32_t num_pe);
uint32_t cda_rvhzcr_external_pas_check_entry(uint32_t num_pe);
uint32_t cda_ryjvjr_ats_te_pas_entry(uint32_t num_pe);
uint32_t cda_rshsxk_d2h_gpc_dpt_entry(uint32_t num_pe);

uint32_t val_cda_find_downstream_chi_c2c_exerciser_endpoint(uint32_t root_bdf,
                                                            uint32_t *endpoint_bdf_out);
uint32_t val_cda_is_downstream_chi_c2c_endpoint(const CXL_COMPONENT_ENTRY *entry,
                                                uint32_t root_bdf,
                                                uint32_t secondary_bus,
                                                uint32_t subordinate_bus);
uint32_t val_cda_select_dcm_page(uint64_t window_base,
                                 uint64_t window_size,
                                 uint64_t *page_out);
uint32_t val_cda_set_link_stream_lock(uint64_t cfg_va,
                                      uint32_t rmecda_cap_base,
                                      uint32_t ctl1_template,
                                      uint32_t lock);
uint32_t val_cda_program_rid_range(uint64_t cfg_va,
                                   uint32_t rmecda_cap_base,
                                   uint32_t ctl3_template,
                                   uint32_t ctl4_template,
                                   uint32_t rid_base,
                                   uint32_t rid_limit,
                                   uint32_t rid_range_valid);
uint32_t val_cda_tdi_snoop_attempt(uint32_t endpoint_bdf,
                                   uint64_t target_pa,
                                   uint32_t access_pas,
                                   uint32_t *result);
uint32_t val_cda_seed_realm_cache_line(volatile uint64_t *realm_alias,
                                       uint64_t value);
uint32_t val_cda_prepare_dcm_window(uint32_t decoder_index,
                                    VAL_CDA_DCM_WINDOW_CONTEXT *context);
uint32_t val_cda_prepare_dcm_window_with_dev_props(
                                    uint32_t decoder_index,
                                    uint32_t required_dev_properties,
                                    VAL_CDA_DCM_WINDOW_CONTEXT *context);
uint32_t val_cda_restore_dcm_window(const VAL_CDA_DCM_WINDOW_CONTEXT *context);

#endif
