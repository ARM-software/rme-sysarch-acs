/** @file
 * Copyright (c) 2024-2025, Arm Limited or its affiliates. All rights reserved.
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

#ifndef __RME_ACS_DA_H__
#define __RME_ACS_DA_H__

void val_da_get_addr_asso_block_base(uint32_t *num_sel_ide_stream_supp,
                         uint32_t *num_tc_supp,
                         uint32_t *current_base_offset,
                         uint32_t bdf,
                         uint32_t *num_addr_asso_block,
                         uint32_t *rid_limit,
                         uint32_t *rid_base,
                         uint32_t reg_value);

void val_da_get_next_rid_values(uint32_t *current_base_offset,
                    uint32_t *num_addr_asso_block,
                    uint32_t bdf,
                    uint32_t *next_rid_limit,
                    uint32_t *next_rid_base);

uint32_t
val_device_lock(uint32_t bdf);

uint32_t
val_device_unlock(uint32_t bdf);

uint32_t
val_get_sel_str_status(uint32_t bdf, uint32_t str_cnt, uint32_t *str_status);

uint32_t
val_get_sel_str_status(uint32_t bdf, uint32_t str_cnt, uint32_t *str_status);

uint32_t
val_ide_program_rid_base_limit_valid(uint32_t bdf, uint32_t str_cnt,
                                     uint32_t base, uint32_t limit, uint32_t valid);

uint32_t
val_ide_program_stream_id(uint32_t bdf, uint32_t str_cnt, uint32_t stream_id);

uint32_t
val_ide_set_sel_stream(uint32_t bdf, uint32_t str_cnt, uint32_t enable);

uint32_t
val_ide_get_num_sel_str(uint32_t bdf, uint32_t *num_sel_str);

uint32_t
val_ide_establish_stream(uint32_t bdf, uint32_t count, uint32_t stream_id, uint32_t base_limit);

uint32_t
val_register_get_num_entries(void);

uint32_t
val_intercnt_sec_prpty_check(uint64_t *register_entry_info);

uint32_t da_dvsec_register_config_entry(void);
uint32_t da_smmu_implementation_entry(void);
uint32_t da_tee_io_capability_entry(void);
uint32_t da_rootport_ide_features_entry(void);
uint32_t da_attribute_rmeda_ctl_registers_entry(void);
uint32_t da_p2p_btw_2_tdisp_devices_entry(void);
uint32_t da_outgoing_request_with_ide_tbit_entry(void);
uint32_t da_incoming_request_ide_sec_locked_entry(void);
uint32_t da_ctl_regs_rmsd_write_protect_property_entry(void);
uint32_t da_ide_state_rootport_error_entry(void);
uint32_t da_ide_state_tdisp_disable_entry(void);
uint32_t da_selective_ide_register_property_entry(void);
uint32_t da_rootport_tdisp_disabled_entry(void);
uint32_t da_autonomous_rootport_request_ns_pas_entry(void);
uint32_t da_incoming_request_ide_non_sec_unlocked_entry(void);
uint32_t da_outgoing_realm_rqst_ide_tbit_1_entry(void);
uint32_t da_ide_tbit_0_for_root_request_entry(void);
uint32_t da_rmsd_write_detect_property_entry(void);
uint32_t da_rootport_write_protect_full_protect_property_entry(void);
uint32_t da_interconnect_regs_rmsd_protected_entry(void);

#endif
