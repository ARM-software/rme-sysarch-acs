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

#include "include/val.h"
#include "include/val_interface.h"
#include "include/val_common.h"
#include "include/val_memory.h"
#include "include/val_tdisp.h"

#if ENABLE_SPDM
#include "acs_libspdm_config.h"
#include "library/spdm_return_status.h"
#include "library/pci_tdisp_requester_lib.h"
#endif

/**
  @brief  Write a 16-bit value in little-endian order.
**/
void
val_tdisp_write_u16_le(uint8_t *buf, uint32_t offset, uint16_t value)
{
  buf[offset] = (uint8_t)(value & 0xFFu);
  buf[offset + 1u] = (uint8_t)((value >> 8) & 0xFFu);
}

/**
  @brief  Write a 32-bit value in little-endian order.
**/
void
val_tdisp_write_u32_le(uint8_t *buf, uint32_t offset, uint32_t value)
{
  buf[offset] = (uint8_t)(value & 0xFFu);
  buf[offset + 1u] = (uint8_t)((value >> 8) & 0xFFu);
  buf[offset + 2u] = (uint8_t)((value >> 16) & 0xFFu);
  buf[offset + 3u] = (uint8_t)((value >> 24) & 0xFFu);
}

/**
  @brief  Write a 64-bit value in little-endian order.
**/
void
val_tdisp_write_u64_le(uint8_t *buf, uint32_t offset, uint64_t value)
{
  val_tdisp_write_u32_le(buf, offset, (uint32_t)(value & 0xFFFFFFFFu));
  val_tdisp_write_u32_le(buf, offset + 4u, (uint32_t)(value >> 32));
}

#if ENABLE_SPDM
/**
  @brief  Initialize the TDISP common message header.
**/
static void
val_tdisp_init_header(uint8_t *buf,
                      uint8_t msg_type,
                      const pci_tdisp_interface_id_t *interface_id)
{
  uint32_t function_id;
  uint64_t reserved;

  function_id = 0;
  reserved = 0;

  if (interface_id != NULL) {
    function_id = interface_id->function_id;
    reserved = interface_id->reserved;
  }

  buf[VAL_TDISP_HDR_VERSION_OFF] = PCI_TDISP_MESSAGE_VERSION;
  buf[VAL_TDISP_HDR_MSG_TYPE_OFF] = msg_type;
  val_tdisp_write_u16_le(buf, VAL_TDISP_HDR_RESERVED_OFF, 0);
  val_tdisp_write_u32_le(buf, VAL_TDISP_HDR_INTERFACE_OFF, function_id);
  val_tdisp_write_u64_le(buf, VAL_TDISP_HDR_INTERFACE_OFF + 4u, reserved);
}

static void
val_tdisp_init_vdm_header(uint8_t *buf)
{
  buf[VAL_TDISP_VDM_HDR_OFF + VAL_TDISP_VDM_HDR_REG_OFF] =
    VAL_TDISP_ARM_VDM_REGISTRY_ID_PCISIG;
  buf[VAL_TDISP_VDM_HDR_OFF + VAL_TDISP_VDM_HDR_LEN_OFF] =
    VAL_TDISP_ARM_VDM_VENDOR_ID_LEN;
  /* Vendor ID is a 16-bit field written in little-endian. */
  val_tdisp_write_u16_le(
    buf,
    VAL_TDISP_VDM_HDR_OFF + VAL_TDISP_VDM_HDR_VENDOR_OFF,
    VAL_TDISP_ARM_VDM_VENDOR_ID);
}

static void
val_tdisp_init_req_resp_header(uint8_t *buf, uint8_t msg_type)
{
  buf[VAL_TDISP_REQ_RESP_HDR_OFF + VAL_TDISP_REQ_RESP_VER_OFF] =
    VAL_TDISP_ARM_VDM_VERSION;
  buf[VAL_TDISP_REQ_RESP_HDR_OFF + VAL_TDISP_REQ_RESP_TYPE_OFF] = msg_type;
  val_tdisp_write_u16_le(buf,
                         VAL_TDISP_REQ_RESP_HDR_OFF +
                         VAL_TDISP_REQ_RESP_RSV_OFF,
                         0);
}

/**
  @brief  Send and receive an Arm TDISP VDM message.
**/
static uint32_t
val_tdisp_vdm_send_common(val_spdm_context_t *context,
                          uint32_t session_id,
                          const void *request,
                          uint32_t request_size,
                          uint8_t *response,
                          uint32_t *response_size)
{
  libspdm_return_t lib_status;
  size_t rsp_size;

  if ((context == NULL) || (context->spdm_context == NULL) ||
      (request == NULL) || (response == NULL) || (response_size == NULL)) {
    return ACS_STATUS_ERR;
  }

  if (*response_size >= LIBPCIDOE_SPDM_VENDOR_MAX_MESSAGE_SIZE)
    *response_size = (uint32_t)(LIBPCIDOE_SPDM_VENDOR_MAX_MESSAGE_SIZE - 1u);

  rsp_size = (size_t)(*response_size);
  lib_status = pci_tdisp_send_receive_data(context->spdm_context,
                                           &session_id,
                                           request,
                                           (size_t)request_size,
                                           response,
                                           &rsp_size);
  if (LIBSPDM_STATUS_IS_ERROR(lib_status)) {
    val_print(ACS_PRINT_ERR,
              " TDISP VDM send/recv failed 0x%x",
              lib_status);
    return ACS_STATUS_ERR;
	}

	*response_size = (uint32_t)rsp_size;
	return ACS_STATUS_PASS;
}
#endif

/**
  @brief  Send an Arm TDISP VDM GET_VERSION request.

  @param  context       SPDM context.
  @param  session_id    SPDM session identifier.
  @param  interface_id  TDISP interface identifier.
  @param  response      Response buffer.
  @param  response_size Response buffer size in/out.
  @return ACS_STATUS_PASS/SKIP/ERR.
**/
uint32_t
val_tdisp_vdm_get_version(val_spdm_context_t *context,
                          uint32_t session_id,
                          const pci_tdisp_interface_id_t *interface_id,
                          uint8_t *response,
                          uint32_t *response_size)
{
#if !defined(LIBSPDM_ENABLE_VENDOR_DEFINED_MESSAGES) || \
    (LIBSPDM_ENABLE_VENDOR_DEFINED_MESSAGES == 0)
  (void)context;
  (void)session_id;
  (void)interface_id;
  (void)response;
  (void)response_size;

  return ACS_STATUS_SKIP;
#else
  uint8_t request[VAL_TDISP_ARM_VDM_BASE_SIZE];
  uint32_t status;

  val_memory_set(request, sizeof(request), 0);
  val_tdisp_init_header(request, PCI_TDISP_VDM_REQ, interface_id);
  val_tdisp_init_vdm_header(request);
  val_tdisp_init_req_resp_header(request,
                                 VAL_TDISP_ARM_MSG_GET_VERSION_REQ);

  status = val_tdisp_vdm_send_common(context,
                                         session_id,
                                         request,
                                         (uint32_t)sizeof(request),
                                         response,
                                         response_size);
  return status;
#endif
}

/**
  @brief  Send an Arm TDISP VDM GET_DEV_PROP request.

  @param  context       SPDM context.
  @param  session_id    SPDM session identifier.
  @param  interface_id  TDISP interface identifier.
  @param  response      Response buffer.
  @param  response_size Response buffer size in/out.
  @return ACS_STATUS_PASS/SKIP/ERR.
**/
uint32_t
val_tdisp_vdm_get_dev_prop(val_spdm_context_t *context,
                           uint32_t session_id,
                           const pci_tdisp_interface_id_t *interface_id,
                           uint8_t *response,
                           uint32_t *response_size)
{
#if !defined(LIBSPDM_ENABLE_VENDOR_DEFINED_MESSAGES) || \
    (LIBSPDM_ENABLE_VENDOR_DEFINED_MESSAGES == 0)
  (void)context;
  (void)session_id;
  (void)interface_id;
  (void)response;
  (void)response_size;

  return ACS_STATUS_SKIP;
#else
  uint8_t request[VAL_TDISP_ARM_VDM_BASE_SIZE];
  uint32_t status;

  val_memory_set(request, sizeof(request), 0);
  val_tdisp_init_header(request, PCI_TDISP_VDM_REQ, interface_id);
  val_tdisp_init_vdm_header(request);
  val_tdisp_init_req_resp_header(request,
                                 VAL_TDISP_ARM_MSG_GET_DEV_PROP_REQ);

  status = val_tdisp_vdm_send_common(context,
                                         session_id,
                                         request,
                                         (uint32_t)sizeof(request),
                                         response,
                                         response_size);
  return status;
#endif
}

/**
  @brief  Send an Arm TDISP VDM SET_INTERFACE request.

  @param  context       SPDM context.
  @param  session_id    SPDM session identifier.
  @param  interface_id  TDISP interface identifier.
  @param  pmecid        Primary MECID to set.
  @param  response      Response buffer.
  @param  response_size Response buffer size in/out.
  @return ACS_STATUS_PASS/SKIP/ERR.
**/
uint32_t
val_tdisp_vdm_set_interface(val_spdm_context_t *context,
                            uint32_t session_id,
                            const pci_tdisp_interface_id_t *interface_id,
                            uint16_t pmecid,
                            uint8_t *response,
                            uint32_t *response_size)
{
#if !defined(LIBSPDM_ENABLE_VENDOR_DEFINED_MESSAGES) || \
    (LIBSPDM_ENABLE_VENDOR_DEFINED_MESSAGES == 0)
  (void)context;
  (void)session_id;
  (void)interface_id;
  (void)pmecid;
  (void)response;
  (void)response_size;

  return ACS_STATUS_SKIP;
#else
  uint8_t request[VAL_TDISP_SET_IF_REQ_SIZE];
  uint32_t status;

  val_memory_set(request, sizeof(request), 0);
  val_tdisp_init_header(request, PCI_TDISP_VDM_REQ, interface_id);
  val_tdisp_init_vdm_header(request);
  val_tdisp_init_req_resp_header(request,
                                 VAL_TDISP_ARM_MSG_SET_INTERFACE_REQ);
  val_tdisp_write_u32_le(request, VAL_TDISP_SET_IF_PROP_OFF,
                         (uint32_t)pmecid);

  status = val_tdisp_vdm_send_common(context,
                                         session_id,
                                         request,
                                         (uint32_t)sizeof(request),
                                         response,
                                         response_size);
  return status;
#endif
}

/**
  @brief  Send a raw Arm TDISP VDM request buffer.

  @param  context       SPDM context.
  @param  session_id    SPDM session identifier.
  @param  request       Raw request buffer.
  @param  request_size  Size of request buffer.
  @param  response      Response buffer.
  @param  response_size Response buffer size in/out.
  @return ACS_STATUS_PASS/SKIP/ERR.
**/
uint32_t
val_tdisp_vdm_send_raw_request(val_spdm_context_t *context,
                               uint32_t session_id,
                               const uint8_t *request,
                               uint32_t request_size,
                               uint8_t *response,
                               uint32_t *response_size)
{
#if !defined(LIBSPDM_ENABLE_VENDOR_DEFINED_MESSAGES) || \
    (LIBSPDM_ENABLE_VENDOR_DEFINED_MESSAGES == 0)
  (void)context;
  (void)session_id;
  (void)request;
  (void)request_size;
  (void)response;
  (void)response_size;

  return ACS_STATUS_SKIP;
#else
  return val_tdisp_vdm_send_common(context,
                                       session_id,
                                       request,
                                       request_size,
                                       response,
                                       response_size);
#endif
}

/**
  @brief  Get the TDISP interface state using SPDM.

  @param  context       SPDM context.
  @param  session_id    SPDM session identifier.
  @param  interface_id  TDISP interface identifier.
  @param  tdi_state     Pointer to return the interface state.
  @return ACS_STATUS_PASS/SKIP/ERR.
**/
uint32_t
val_tdisp_get_interface_state(val_spdm_context_t *context,
                              uint32_t session_id,
                              const pci_tdisp_interface_id_t *interface_id,
                              uint8_t *tdi_state)
{
#if ENABLE_SPDM
  return val_spdm_send_pci_tdisp_get_interface_state(context,
                                                     session_id,
                                                     interface_id,
                                                     tdi_state);
#else
  (void)context;
  (void)session_id;
  (void)interface_id;
  (void)tdi_state;
  return ACS_STATUS_SKIP;
#endif
}

/**
  @brief   Execute all TDISP compliance tests.

  @param   num_pe  Number of processing elements.
  @return  Consolidated status of the executed tests.
**/
uint32_t
val_rme_tdisp_execute_tests(uint32_t num_pe)
{
  uint32_t status;

  status = ACS_STATUS_SKIP;

  g_curr_module = 1 << TDISP_MODULE_ID;

  val_print(ACS_PRINT_ALWAYS, "\n\n*******************************************************\n", 0);
  status = tdisp_rgrpdp_get_dev_prop_req_entry();
  status |= tdisp_rghdcb_get_dev_prop_resp_format_entry();
  status |= tdisp_rfpymv_vdm_response_check_entry();

  return status;
}
