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

#ifndef __RME_ACS_TDISP_H__
#define __RME_ACS_TDISP_H__

#include "val_spdm.h"

/* When ENABLE_SPDM=0, libspdm's pci_tdisp_interface_id_t is not available.
 * Define the minimal type needed by our TDISP APIs/tests.
 */
#if !ENABLE_SPDM
typedef struct {
  uint32_t function_id;
  uint64_t reserved;
} pci_tdisp_interface_id_t;
#endif

/* TDISP wire constants (PCIe TDISP). Define here to avoid test dependency on
 * libspdm headers. Guard with ifndef to avoid redefinition when libspdm is in
 * the include path.
 */
#ifndef PCI_TDISP_MESSAGE_VERSION_10
#define PCI_TDISP_MESSAGE_VERSION_10 0x10u
#endif

#ifndef PCI_TDISP_MESSAGE_VERSION
#define PCI_TDISP_MESSAGE_VERSION PCI_TDISP_MESSAGE_VERSION_10
#endif

#ifndef PCI_TDISP_VDM_REQ
#define PCI_TDISP_VDM_REQ 0x8Bu
#endif

#ifndef PCI_TDISP_VDM_RSP
#define PCI_TDISP_VDM_RSP 0x0Bu
#endif

#ifndef PCI_TDISP_ERROR
#define PCI_TDISP_ERROR 0x7Fu
#endif

#ifndef PCI_TDISP_INTERFACE_STATE_CONFIG_UNLOCKED
#define PCI_TDISP_INTERFACE_STATE_CONFIG_UNLOCKED 0u
#endif

/* Common limits. */
#define VAL_TDISP_ARM_VDM_MAX_RSP_SIZE 1024u

/* TDISP message header layout (PCI TDISP). */
#define VAL_TDISP_HDR_VERSION_OFF     0u
#define VAL_TDISP_HDR_MSG_TYPE_OFF    1u
#define VAL_TDISP_HDR_RESERVED_OFF    2u
#define VAL_TDISP_HDR_INTERFACE_OFF   4u
#define VAL_TDISP_HDR_SIZE            16u

/* Arm VDM header layout (Appendix B3). */
#define VAL_TDISP_VDM_HDR_OFF         (VAL_TDISP_HDR_SIZE)
#define VAL_TDISP_VDM_HDR_REG_OFF     0u
#define VAL_TDISP_VDM_HDR_LEN_OFF     1u
#define VAL_TDISP_VDM_HDR_VENDOR_OFF  2u
#define VAL_TDISP_VDM_HDR_SIZE        4u

/* Arm VDM header values. */
#define VAL_TDISP_ARM_VDM_REGISTRY_ID_PCISIG 0x00
#define VAL_TDISP_ARM_VDM_VENDOR_ID_LEN      0x02
#define VAL_TDISP_ARM_VDM_VENDOR_ID          0x13b5

/* Request/response header layout (Appendix B3). */
#define VAL_TDISP_REQ_RESP_HDR_OFF    (VAL_TDISP_VDM_HDR_OFF + \
                                       VAL_TDISP_VDM_HDR_SIZE)
#define VAL_TDISP_REQ_RESP_VER_OFF    0u
#define VAL_TDISP_REQ_RESP_TYPE_OFF   1u
#define VAL_TDISP_REQ_RESP_RSV_OFF    2u
#define VAL_TDISP_REQ_RESP_HDR_SIZE   4u

/* Arm VDM request/response header values. */
#define VAL_TDISP_ARM_VDM_VERSION            0x00

/* Minimum payload sizes. */
#define VAL_TDISP_ARM_VDM_BASE_SIZE   (VAL_TDISP_REQ_RESP_HDR_OFF + \
                                       VAL_TDISP_REQ_RESP_HDR_SIZE)
#define VAL_TDISP_SET_IF_PROP_OFF     (VAL_TDISP_ARM_VDM_BASE_SIZE)
#define VAL_TDISP_SET_IF_REQ_SIZE     (VAL_TDISP_SET_IF_PROP_OFF + 4u)

/* Arm VDM request/response types. */
#define VAL_TDISP_ARM_MSG_GET_VERSION_REQ    0x01
#define VAL_TDISP_ARM_MSG_GET_DEV_PROP_REQ   0x02
#define VAL_TDISP_ARM_MSG_SET_INTERFACE_REQ  0x05
#define VAL_TDISP_ARM_MSG_GET_VERSION_RESP   0x11
#define VAL_TDISP_ARM_MSG_GET_DEV_PROP_RESP  0x12
#define VAL_TDISP_ARM_MSG_SET_INTERFACE_RESP 0x15

/* GET_DEV_PROP_RESP fields. */
#define VAL_TDISP_DEV_PROP_PAS_CHECK         (1u << 0)
#define VAL_TDISP_DEV_PROP_MEC               (1u << 1)
#define VAL_TDISP_DEV_PROP_MECID_SHIFT       8
#define VAL_TDISP_DEV_PROP_MECID_MASK        (0x1Fu << VAL_TDISP_DEV_PROP_MECID_SHIFT)

void
val_tdisp_write_u16_le(uint8_t *buf, uint32_t offset, uint16_t value);

void
val_tdisp_write_u32_le(uint8_t *buf, uint32_t offset, uint32_t value);

void
val_tdisp_write_u64_le(uint8_t *buf, uint32_t offset, uint64_t value);

uint32_t
val_tdisp_vdm_get_version(val_spdm_context_t *context,
                          uint32_t session_id,
                          const pci_tdisp_interface_id_t *interface_id,
                          uint8_t *response,
                          uint32_t *response_size);

uint32_t
val_tdisp_vdm_get_dev_prop(val_spdm_context_t *context,
                           uint32_t session_id,
                           const pci_tdisp_interface_id_t *interface_id,
                           uint8_t *response,
                           uint32_t *response_size);

uint32_t
val_tdisp_vdm_set_interface(val_spdm_context_t *context,
                            uint32_t session_id,
                            const pci_tdisp_interface_id_t *interface_id,
                            uint16_t pmecid,
                            uint8_t *response,
                            uint32_t *response_size);

uint32_t
val_tdisp_vdm_send_raw_request(val_spdm_context_t *context,
                               uint32_t session_id,
                               const uint8_t *request,
                               uint32_t request_size,
                               uint8_t *response,
                               uint32_t *response_size);

uint32_t
val_tdisp_get_interface_state(val_spdm_context_t *context,
                              uint32_t session_id,
                              const pci_tdisp_interface_id_t *interface_id,
                              uint8_t *tdi_state);

uint32_t
val_rme_tdisp_execute_tests(uint32_t num_pe);

uint32_t
tdisp_rfpymv_vdm_response_check_entry(uint32_t num_pe);

uint32_t
tdisp_rgrpdp_get_dev_prop_req_entry(void);

uint32_t
tdisp_rghdcb_get_dev_prop_resp_format_entry(void);

#endif
