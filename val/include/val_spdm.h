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

#ifndef __RME_ACS_SPDM_H__
#define __RME_ACS_SPDM_H__

#include "pal_interface.h"

#if defined(TARGET_EMULATION) || defined(TARGET_BM_BOOT)
#include <stdint.h>
#endif

#if ENABLE_SPDM && !defined(TARGET_EMULATION) && !defined(TARGET_BM_BOOT)
#ifndef LIBSPDM_STDINT_ALT
#define LIBSPDM_STDINT_ALT "../../platform/pal_uefi/include/pal_stdint_uefi.h"
#endif
#ifndef LIBSPDM_STDDEF_ALT
#define LIBSPDM_STDDEF_ALT "../../platform/pal_uefi/include/pal_stddef_uefi.h"
#endif
#ifndef LIBSPDM_STDBOOL_ALT
#define LIBSPDM_STDBOOL_ALT "../../platform/pal_uefi/include/pal_stdbool_uefi.h"
#endif
#endif

#if ENABLE_SPDM
#include "industry_standard/spdm.h"
#include "industry_standard/pcidoe.h"
#include "industry_standard/cxl_idekm.h"
#include "industry_standard/cxl_tsp.h"
#include "industry_standard/pci_tdisp.h"

#include "library/spdm_crypt_lib.h"
#include "library/cxl_ide_km_common_lib.h"
#include "library/cxl_tsp_common_lib.h"
#else
typedef struct {
  uint8_t object_id;
} cxl_ide_km_header_t;

typedef struct {
  cxl_ide_km_header_t header;
  uint8_t reserved;
  uint8_t port_index;
  uint8_t dev_func_num;
  uint8_t bus_num;
  uint8_t segment;
  uint8_t max_port_index;
  uint8_t caps;
} cxl_ide_km_query_resp_t;

#define CXL_IDE_KM_OBJECT_ID_QUERY_RESP 0x01

#define CXL_TSP_2ND_SESSION_COUNT 4
#define CXL_TSP_2ND_SESSION_KEY_SIZE 0x20

typedef struct {
  uint32_t key[8];
  uint32_t iv[3];
} cxl_ide_km_aes_256_gcm_key_buffer_t;

typedef struct {
  uint16_t memory_encryption_features_supported;
  uint32_t memory_encryption_algorithms_supported;
  uint16_t memory_encryption_number_of_range_based_keys;
  uint16_t te_state_change_and_access_control_features_supported;
  uint32_t supported_explicit_oob_te_state_granularity;
  uint32_t supported_explicit_ib_te_state_granularity;
  uint16_t configuration_features_supported;
  uint32_t number_of_ckids;
  uint8_t  number_of_secondary_sessions;
} libcxltsp_device_capabilities_t;

typedef struct {
  uint64_t te_state_granularity;
  uint8_t  length_index;
  uint8_t  reserved[7];
} cxl_tsp_explicit_ib_te_state_granularity_entry_t;

typedef struct {
  uint8_t key_material[CXL_TSP_2ND_SESSION_KEY_SIZE];
} cxl_tsp_secondary_session_psk_key_material_t;

typedef struct {
  uint16_t memory_encryption_features_enable;
  uint32_t memory_encryption_algorithm_select;
  uint16_t te_state_change_and_access_control_features_enable;
  uint32_t explicit_oob_te_state_granularity;
  uint16_t configuration_features_enable;
  uint32_t ckid_base;
  uint32_t number_of_ckids;
  cxl_tsp_explicit_ib_te_state_granularity_entry_t
    explicit_ib_te_state_granularity_entry[8];
} libcxltsp_device_configuration_t;

typedef struct {
  uint16_t configuration_validity_flags;
  uint8_t  secondary_session_ckid_type;
  cxl_tsp_secondary_session_psk_key_material_t
    secondary_session_psk_key_material[CXL_TSP_2ND_SESSION_COUNT];
} libcxltsp_device_2nd_session_info_t;

typedef struct {
  uint64_t starting_address;
  uint64_t length;
} cxl_tsp_memory_range_t;

#endif

#define VAL_SPDM_MAX_VERSION_COUNT 8

typedef struct {
  uint8_t major;
  uint8_t minor;
  uint8_t update;
  uint8_t alpha;
} val_spdm_version_t;

typedef struct {
  uint32_t             bdf;
  void                *spdm_context;
  uint8_t             *sender_buffer;
  uint8_t             *receiver_buffer;
  uint8_t             *scratch_buffer;
  uint32_t             sender_buffer_size;
  uint32_t             receiver_buffer_size;
  uint32_t             scratch_buffer_size;
  uint8_t              sender_in_use;
  uint8_t              receiver_in_use;
} val_spdm_context_t;

typedef struct {
  uint16_t vendor_id;
  uint8_t  data_object_type;
  uint8_t  reserved;
} val_pci_doe_protocol_t;

uint32_t val_spdm_context_init(uint32_t bdf,
                               val_spdm_context_t *context);
void     val_spdm_context_deinit(val_spdm_context_t *context);
uint32_t val_spdm_get_version(val_spdm_context_t *context,
                               val_spdm_version_t *versions,
                               uint8_t *version_count);
uint32_t val_spdm_session_open(uint32_t bdf,
                               val_spdm_context_t *context,
                               uint32_t *session_id);
uint32_t val_spdm_start_session(val_spdm_context_t *context,
                                uint32_t *session_id);
/* Retrieve measurements over an established secure session, not an attestation verdict. */
uint32_t val_spdm_get_measurements(val_spdm_context_t *context,
                                    uint32_t session_id,
                                    uint8_t *block_count,
                                    uint32_t *record_size,
                                    uint8_t *record);
uint32_t val_spdm_stop_session(val_spdm_context_t *context,
                               uint32_t session_id);
uint32_t val_spdm_session_close(val_spdm_context_t *context,
                                uint32_t session_id);
uint32_t val_spdm_send_cxl_ide_km_query(val_spdm_context_t *context,
                                        uint32_t session_id,
                                        uint8_t port_index,
                                        cxl_ide_km_query_resp_t *response,
                                        uint32_t *ide_reg_buffer,
                                        uint32_t *ide_reg_count);
uint32_t val_spdm_get_random(size_t size, uint8_t *buffer);
uint32_t val_spdm_send_cxl_ide_km_get_key(val_spdm_context_t *context,
                                          uint32_t session_id,
                                          uint8_t stream_id,
                                          uint8_t key_sub_stream,
                                          uint8_t port_index,
                                          cxl_ide_km_aes_256_gcm_key_buffer_t *key_buffer);
uint32_t val_spdm_send_cxl_ide_km_key_prog(val_spdm_context_t *context,
                                           uint32_t session_id,
                                           uint8_t stream_id,
                                           uint8_t key_sub_stream,
                                           uint8_t port_index,
                                           const cxl_ide_km_aes_256_gcm_key_buffer_t *key_buffer,
                                           uint8_t *ack_status);
uint32_t val_spdm_send_cxl_ide_km_key_set_go(val_spdm_context_t *context,
                                             uint32_t session_id,
                                             uint8_t stream_id,
                                             uint8_t key_sub_stream,
                                             uint8_t port_index);
uint32_t val_spdm_send_cxl_ide_km_key_set_stop(val_spdm_context_t *context,
                                                uint32_t session_id,
                                                uint8_t stream_id,
                                                uint8_t key_sub_stream,
                                                uint8_t port_index);
uint32_t val_spdm_send_cxl_tsp_get_version(val_spdm_context_t *context,
                                           uint32_t session_id);
uint32_t val_spdm_send_cxl_tsp_get_capabilities(val_spdm_context_t *context,
                                                uint32_t session_id,
                                                libcxltsp_device_capabilities_t *capabilities);
uint32_t val_spdm_send_cxl_tsp_set_configuration(val_spdm_context_t *context,
                                        uint32_t session_id,
                                        const libcxltsp_device_configuration_t *configuration,
                                        const libcxltsp_device_2nd_session_info_t *secondary_info);
uint32_t val_spdm_send_cxl_tsp_get_configuration(val_spdm_context_t *context,
                                                 uint32_t session_id,
                                                 libcxltsp_device_configuration_t *configuration,
                                                 uint8_t *tsp_state);
uint32_t val_spdm_send_cxl_tsp_lock_configuration(val_spdm_context_t *context,
                                                  uint32_t session_id);
uint32_t val_spdm_send_cxl_tsp_set_te_state(val_spdm_context_t *context,
                                            uint32_t session_id,
                                            uint8_t te_state,
                                            uint8_t range_count,
                                            const cxl_tsp_memory_range_t *ranges);
uint32_t val_doe_discovery(uint32_t bdf,
                           val_pci_doe_protocol_t *protocols,
                           uint32_t *protocol_count);

/* PCIe TDISP requester wrappers */
#if ENABLE_SPDM
uint32_t val_spdm_send_pci_tdisp_get_version(
                                      val_spdm_context_t *context,
                                      uint32_t session_id,
                                      const pci_tdisp_interface_id_t *interface_id);
uint32_t val_spdm_send_pci_tdisp_get_capabilities(
                                      val_spdm_context_t *context,
                                      uint32_t session_id,
                                      const pci_tdisp_interface_id_t *interface_id,
                                      const pci_tdisp_requester_capabilities_t *req,
                                      pci_tdisp_responder_capabilities_t *rsp);
uint32_t val_spdm_send_pci_tdisp_get_interface_state(
                                      val_spdm_context_t *context,
                                      uint32_t session_id,
                                      const pci_tdisp_interface_id_t *interface_id,
                                      uint8_t *tdi_state);
uint32_t val_spdm_send_pci_tdisp_get_interface_report(
                                      val_spdm_context_t *context,
                                      uint32_t session_id,
                                      const pci_tdisp_interface_id_t *interface_id,
                                      uint8_t *report,
                                      uint32_t *report_size);
uint32_t val_spdm_send_pci_tdisp_lock_interface(
                                      val_spdm_context_t *context,
                                      uint32_t session_id,
                                      const pci_tdisp_interface_id_t *interface_id,
                                      const pci_tdisp_lock_interface_param_t *param,
                                      uint8_t *start_interface_nonce);
uint32_t val_spdm_send_pci_tdisp_start_interface(
                                      val_spdm_context_t *context,
                                      uint32_t session_id,
                                      const pci_tdisp_interface_id_t *interface_id,
                                      const uint8_t *start_interface_nonce);
uint32_t val_spdm_send_pci_tdisp_stop_interface(
                                      val_spdm_context_t *context,
                                      uint32_t session_id,
                                      const pci_tdisp_interface_id_t *interface_id);
#endif /* ENABLE_SPDM */

#endif /* __RME_ACS_SPDM_H__ */
