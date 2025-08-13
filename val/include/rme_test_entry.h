/** @file
 * Copyright (c) 2022-2025, Arm Limited or its affiliates. All rights reserved.
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

#ifndef __RME_TEST_ENTRY_H__
#define __RME_TEST_ENTRY_H__

#include "rme_acs_pe.h"

uint32_t rme_support_in_pe_entry(uint32_t num_pe);
uint32_t rme_gprs_scrubbed_after_reset_entry(void);
uint32_t rme_all_pe_has_feat_rng_or_rng_trap_entry(uint32_t num_pe);
uint32_t rme_gpc_for_system_resource_entry(void);
uint32_t rme_coherent_interconnect_supports_cmo_popa_entry(void);
uint32_t rme_resources_aligned_to_granularity_entry(void);
uint32_t rme_resources_are_not_physically_aliased_entry(void);
uint32_t rme_pe_do_not_have_arch_diff_entry(uint32_t num_pe);
uint32_t rme_mte_region_in_root_pas_entry(void);
uint32_t rme_encryption_for_all_pas_except_ns_entry(void);
uint32_t rme_pas_filter_functionality_entry(void);
uint32_t rme_realm_smem_behaviour_after_reset_entry(void);
uint32_t rme_pcie_devices_support_gpc_entry(void);
uint32_t rme_data_encryption_beyond_popa_entry(void);
uint32_t rme_data_encryption_with_different_tweak_entry(void);
uint32_t rme_msd_smem_in_root_pas_entry(void);
uint32_t rme_realm_smem_in_realm_pas_entry(void);
uint32_t rme_snoop_filter_considers_pas_entry(uint32_t num_pe);
uint32_t rme_cmo_popa_for_cacheability_shareability_entry(void);
uint32_t rme_memory_associated_with_pas_till_popa_entry(void);
uint32_t rme_interconnect_supports_tlbi_pa_entry(void);
uint32_t rme_ns_encryption_is_immutable_entry(void);
uint32_t rme_pe_context_after_exit_wfi_entry(void);
uint32_t rme_pe_context_after_pe_suspend_entry(void);
uint32_t rme_msd_save_restore_mem_in_root_pas_entry(void);
uint32_t rme_rnvs_in_root_pas_entry(void);
uint32_t rme_root_wdog_from_root_pas_entry(void);
uint32_t rme_root_wdog_fails_in_non_root_state_entry(void);
uint32_t rme_pas_filter_in_inactive_mode_entry(void);
uint32_t rme_smmu_blocks_request_at_registers_reset_entry(void);
uint32_t rme_system_reset_propagation_to_all_pe_entry(uint32_t num_pe);
uint32_t rme_msd_smem_in_root_after_reset_entry(void);
#endif /*__RME_TEST_ENTRY_H__*/

