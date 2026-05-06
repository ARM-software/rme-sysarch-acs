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

#ifndef __RME_ACS_CXL_H__
#define __RME_ACS_CXL_H__

#include "pal_interface.h"
#include "val_spdm.h"

#define CXL_COMPONENT_RCRB     0x1
#define CXL_COMPONENT_HDM      0x4
#define CXL_COMPONENT_MAILBOX  0x8
#define CXL_COMPONENT_TSP      0x10
#define CXL_COMPONENT_IDE      0x20
#define CXL_COMPONENT_EXT_SECURITY 0x40
#define CXL_COMPONENT_SECURITY 0x80
#define CXL_MAX_DECODER_SLOTS  32
#ifndef CXL_HDM_DECODER_SLOT_DEFAULT
#define CXL_HDM_DECODER_SLOT_DEFAULT 0u
#endif
#define CXL_COMPONENT_INVALID_INDEX  0xFFFFFFFFu
#define CXL_COMPONENT_TABLE_MAX_ENTRIES 1024U

/*
 * ---- CXL TSP helpers ----
 *
 * The libspdm CXL-TSP header (pulled in via val_spdm.h when ENABLE_SPDM is set)
 * provides the CXL_TSP_* spec constants. When SPDM support is disabled we still
 * compile tests that reference these values, so provide fallbacks here.
 */
#ifndef CXL_TSP_STATE_CONFIG_UNLOCKED
#define CXL_TSP_STATE_CONFIG_UNLOCKED 0u
#endif
#ifndef CXL_TSP_STATE_CONFIG_LOCKED
#define CXL_TSP_STATE_CONFIG_LOCKED 1u
#endif
#ifndef CXL_TSP_STATE_ERROR
#define CXL_TSP_STATE_ERROR 2u
#endif

#ifndef CXL_TSP_MEMORY_ENCRYPTION_FEATURES_ENABLE_ENCRYPTION
#define CXL_TSP_MEMORY_ENCRYPTION_FEATURES_ENABLE_ENCRYPTION 0x1u
#endif
#ifndef CXL_TSP_MEMORY_ENCRYPTION_FEATURES_ENABLE_CKID_BASED_ENCRYPTION
#define CXL_TSP_MEMORY_ENCRYPTION_FEATURES_ENABLE_CKID_BASED_ENCRYPTION 0x2u
#endif

/* Common defaults for configuring memory encryption via CXL TSP. */
#ifndef CXL_TSP_REQUESTED_CKIDS_DEFAULT
#define CXL_TSP_REQUESTED_CKIDS_DEFAULT 1u
#endif

#ifndef CXL_TSP_MEMORY_ENCRYPTION_FEATURES_ENABLE_MASK_DEFAULT
#define CXL_TSP_MEMORY_ENCRYPTION_FEATURES_ENABLE_MASK_DEFAULT \
  ((uint16_t)(CXL_TSP_MEMORY_ENCRYPTION_FEATURES_ENABLE_ENCRYPTION | \
              CXL_TSP_MEMORY_ENCRYPTION_FEATURES_ENABLE_CKID_BASED_ENCRYPTION))
#endif

/* Retry parameters for polling the TSP state over SPDM. */
#ifndef CXL_TSP_STATE_QUERY_RETRY_COUNT
#define CXL_TSP_STATE_QUERY_RETRY_COUNT 50u
#endif

#ifndef CXL_TSP_STATE_QUERY_RETRY_DELAY_MS
#define CXL_TSP_STATE_QUERY_RETRY_DELAY_MS 20u
#endif

typedef enum {
  CXL_COMPONENT_ROLE_UNKNOWN = 0,
  CXL_COMPONENT_ROLE_ROOT_PORT,
  CXL_COMPONENT_ROLE_SWITCH_UPSTREAM,
  CXL_COMPONENT_ROLE_SWITCH_DOWNSTREAM,
  CXL_COMPONENT_ROLE_ENDPOINT,
} CXL_COMPONENT_ROLE;

typedef enum {
  CXL_DEVICE_TYPE_UNKNOWN = 0,
  CXL_DEVICE_TYPE_TYPE1,
  CXL_DEVICE_TYPE_TYPE2,
  CXL_DEVICE_TYPE_TYPE3,
} CXL_DEVICE_TYPE;

typedef struct {
  uint64_t component_reg_base;
  uint64_t component_reg_length;
  uint64_t device_reg_base;
  uint32_t bdf;
  uint32_t role;
  uint32_t device_type;
  uint32_t host_bridge_index;
  uint32_t device_reg_length;
  uint32_t hdm_decoder_count;
  uint32_t chi_c2c_supported;
  uint32_t chi_c2c_dvsec_offset;
} CXL_COMPONENT_ENTRY;

typedef struct {
  uint32_t             num_entries;
  CXL_COMPONENT_ENTRY  component[];
} CXL_COMPONENT_TABLE;

#define CXL_COMPONENT_TABLE_SZ \
  (sizeof(CXL_COMPONENT_TABLE) + \
   (CXL_COMPONENT_TABLE_MAX_ENTRIES * sizeof(CXL_COMPONENT_ENTRY)))

typedef enum {
  CXL_COMPONENT_INFO_COUNT = 1,
  CXL_COMPONENT_INFO_ROLE,
  CXL_COMPONENT_INFO_DEVICE_TYPE,
  CXL_COMPONENT_INFO_HOST_BRIDGE_INDEX,
  CXL_COMPONENT_INFO_BDF_INDEX,
  CXL_COMPONENT_INFO_COMPONENT_BASE,
  CXL_COMPONENT_INFO_COMPONENT_LENGTH,
  CXL_COMPONENT_INFO_HDM_COUNT,
  CXL_COMPONENT_INFO_CHI_C2C_SUPPORTED,
  CXL_COMPONENT_INFO_CHI_C2C_DVSEC_OFFSET
} CXL_COMPONENT_INFO_e;


typedef enum {
  CXL_INFO_NUM_DEVICES = 1,
  CXL_INFO_COMPONENT_BASE,
  CXL_INFO_COMPONENT_LENGTH,
  CXL_INFO_COMPONENT_TYPE,
  CXL_INFO_HDM_COUNT,
  CXL_INFO_UID
} CXL_INFO_e;

typedef enum {
  CXL_TRUST_LEVEL_TRUSTED = 0,
  CXL_TRUST_LEVEL_DEVICE_MEMORY_ONLY = 1,
  CXL_TRUST_LEVEL_UNTRUSTED = 2,
  CXL_TRUST_LEVEL_RESERVED = 3
} CXL_TRUST_LEVEL;

struct pcie_endpoint_cfg;

void     val_cxl_create_info_table(uint64_t *cxl_info_table);
void     val_cxl_free_info_table(void);
uint64_t val_cxl_get_info(CXL_INFO_e type, uint32_t index);
uint32_t val_cxl_get_decoder(uint32_t index,
                             uint32_t decoder_index,
                             uint64_t *base,
                             uint64_t *length);
uint32_t val_cxl_get_component_decoder(uint32_t component_index,
                                       uint32_t decoder_index,
                                       uint64_t *base,
                                       uint64_t *length);
uint32_t val_cxl_get_cfmws_count(uint32_t index);
uint32_t val_cxl_get_cfmws(uint32_t index,
                           uint32_t window_index,
                           uint64_t *base,
                           uint64_t *length);
uint32_t val_cxl_program_host_decoder(uint32_t host_index,
                                      uint32_t decoder_index,
                                      uint64_t base,
                                      uint64_t length);
uint32_t val_cxl_program_component_decoder(uint32_t component_index,
                                           uint32_t decoder_index,
                                           uint64_t base,
                                           uint64_t length);
uint32_t val_cxl_create_component_table(void);
void     val_cxl_free_component_table(void);
CXL_COMPONENT_TABLE *
         val_cxl_component_table_ptr(void);
uint64_t val_cxl_get_component_info(CXL_COMPONENT_INFO_e type,
                                    uint32_t index);
uint32_t val_cxl_find_component_register_base(uint32_t bdf,
                                              uint64_t *component_base);
uint32_t val_cxl_find_capability(uint64_t component_base,
                                 uint16_t capability_id,
                                 uint64_t *cap_base_out);
uint32_t val_cxl_rp_is_not_subject_to_host_gpc(uint32_t rp_bdf);
uint32_t val_cxl_device_is_cxl(uint32_t bdf);
uint32_t val_cxl_component_add(uint32_t bdf);
void     val_cxl_print_component_summary(void);

uint32_t val_cxl_security_get_policy(uint32_t component_index,
                                     uint32_t *policy);
uint32_t val_cxl_security_get_device_trust_level(uint32_t component_index,
                                                 uint32_t *trust_level);

uint32_t val_cxl_ext_security_get_count(uint32_t component_index,
                                        uint32_t *count);
uint32_t val_cxl_ext_security_get_policy(uint32_t component_index,
                                         uint32_t entry_index,
                                         uint32_t *policy);
uint32_t val_cxl_ext_security_get_port_id(uint32_t component_index,
                                          uint32_t entry_index,
                                          uint32_t *port_id);
uint32_t val_cxl_ext_security_find_policy_by_port(uint32_t component_index,
                                                  uint32_t port_id,
                                                  uint32_t *policy);

uint32_t val_cxl_find_ext_security_policy(uint64_t cap_base,
                                          uint32_t port_id,
                                          uint32_t *policy_out,
                                          uint64_t *policy_pa_out);

uint32_t val_cxl_ide_get_capability(uint32_t component_index,
                                     uint32_t *capability);
uint32_t val_cxl_ide_get_control(uint32_t component_index,
                                  uint32_t *control);
uint32_t val_cxl_ide_get_status(uint32_t component_index,
                                 uint32_t *status);
uint32_t val_cxl_ide_get_error_status(uint32_t component_index,
                                       uint32_t *error_status);

uint32_t cxl_rjsdvg_little_endian_entry(uint32_t num_pe);
uint32_t cxl_rplykv_rdfwkw_rme_cda_dvsec_entry(uint32_t num_pe);
uint32_t cxl_rgvrqc_host_port_coverage_entry(uint32_t num_pe);
uint32_t cxl_host_port_rmsd_write_protect_entry(uint32_t num_pe);
uint32_t cxl_rwpgjb_rmsd_write_protect_property_entry(uint32_t num_pe);
uint32_t cxl_rphcgc_rmsd_full_protect_entry(uint32_t num_pe);
uint32_t cxl_rphwmm_rme_cda_tsp_entry(uint32_t num_pe);
uint32_t cxl_rjxpzp_pas_ckid_mapping_entry(uint32_t num_pe);
uint32_t cxl_rhmxtf_host_hdm_decoder_entry(uint32_t num_pe);
uint32_t cxl_rdhwnr_link_stream_lock_entry(uint32_t num_pe);
uint32_t cxl_rwyvcq_link_unlock_reject_entry(uint32_t num_pe);
uint32_t cxl_rxqhng_rid_range_reject_entry(uint32_t num_pe);
uint32_t cxl_rkjypb_cache_disable_entry(uint32_t num_pe);
uint32_t cxl_rplcmc_type3_target_ckid_entry(uint32_t num_pe);
uint32_t cxl_rlqmcy_type3_host_mpe_entry(uint32_t num_pe);
uint32_t cxl_rhcqws_host_side_mpe_entry(uint32_t num_pe);
uint32_t cxl_rptggp_cmo_to_cxl_mem_entry(uint32_t num_pe);
uint32_t cxl_rhhmvm_bisnp_pas_nonsecure_entry(uint32_t num_pe);
uint32_t cxl_rgbgqx_ctc_link_ide_entry(uint32_t num_pe);
uint32_t cxl_rxwjnn_type3_link_ide_entry(uint32_t num_pe);
uint32_t cxl_rcnslj_type3_no_tsp_entry(uint32_t num_pe);
uint32_t cxl_rfdvzc_tdisp_disable_entry(uint32_t num_pe);
uint32_t cxl_rbytyv_root_port_pas_behavior_entry(uint32_t num_pe);
uint32_t cxl_rnycll_tdisp_disable_reject_entry(uint32_t num_pe);
uint32_t cxl_rgtvgz_tdisp_enable_link_gate_entry(uint32_t num_pe);
uint32_t val_cxl_root_port_ide_program_and_enable(uint32_t rp_bdf,
                                                  uint8_t stream_id,
                                                  uint8_t key_slot,
                                                  const CXL_IDE_KEY_BUFFER *rx_key,
                                                  const CXL_IDE_KEY_BUFFER *tx_key);
uint32_t val_cxl_ide_disable_link(uint32_t root_index,
                                  uint32_t endpoint_index,
                                  val_spdm_context_t *context,
                                  uint32_t session_id);
uint32_t val_cxl_find_downstream_endpoint(uint32_t root_index,
                                          uint32_t *endpoint_index_out);
uint32_t val_cxl_find_upstream_root_port(uint32_t endpoint_bdf,
                                         uint32_t *root_bdf_out);
uint32_t val_cxl_ide_establish_link(uint32_t root_index,
                                   uint32_t endpoint_index,
                                   val_spdm_context_t *context,
                                    uint32_t session_id);
uint32_t val_cxl_tsp_configure_and_lock(uint32_t root_index,
                                        uint32_t endpoint_index,
                                        val_spdm_context_t *context,
                                        uint32_t session_id,
                                        uint32_t requested_ckids,
                                        uint16_t feature_enable_mask);
uint32_t val_cxl_select_cfmws_window(uint32_t host_index,
                                     uint64_t *base,
                                     uint64_t *size);
uint32_t val_cxl_enable_mem(uint32_t bdf);
uint32_t val_cxl_aer_clear(uint32_t bdf, uint32_t aer_offset);
uint32_t val_cxl_aer_read_uncorr(uint32_t bdf,
                                 uint32_t aer_offset,
                                 uint32_t *status_out);
uint32_t val_cxl_unlock_tsp_best_effort(uint32_t rp_bdf,
                                        uint32_t endpoint_bdf,
                                        const struct pcie_endpoint_cfg *cfg);

#endif /* __RME_ACS_CXL_H__ */
