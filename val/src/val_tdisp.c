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
#include "include/val_pcie.h"
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
  @brief  Open an SPDM session and move a TDI interface to RUN.

  @param  endpoint_bdf      TDI endpoint BDF.
  @param  spdm_ctx          Caller-owned SPDM context.
  @param  session_id_out    Output SPDM session identifier.
  @param  interface_id_out  Output TDISP interface identifier.

  @return ACS_STATUS_PASS if the TDI reached RUN. ACS_STATUS_SKIP when the TDI
          flow is unsupported or does not reach the required state.
**/
uint32_t
val_tdisp_establish_run(uint32_t endpoint_bdf,
                        val_spdm_context_t *spdm_ctx,
                        uint32_t *session_id_out,
                        pci_tdisp_interface_id_t *interface_id_out)
{
#if ENABLE_SPDM
  pci_tdisp_requester_capabilities_t req_caps;
  pci_tdisp_responder_capabilities_t rsp_caps;
  pci_tdisp_lock_interface_param_t lock_param;
  uint8_t nonce[PCI_TDISP_START_INTERFACE_NONCE_SIZE];
  uint32_t session_id;
  uint32_t status;
  uint8_t tdi_state;

  if ((spdm_ctx == NULL) || (session_id_out == NULL) || (interface_id_out == NULL))
    return ACS_STATUS_ERR;

  *session_id_out = 0u;
  val_memory_set(spdm_ctx, sizeof(*spdm_ctx), 0);
  val_memory_set(&req_caps, sizeof(req_caps), 0);
  val_memory_set(&rsp_caps, sizeof(rsp_caps), 0);
  val_memory_set(&lock_param, sizeof(lock_param), 0);
  val_memory_set(nonce, sizeof(nonce), 0);

  interface_id_out->function_id = (uint32_t)PCIE_CREATE_BDF_PACKED(endpoint_bdf);
  interface_id_out->reserved = 0ull;

  status = val_spdm_session_open(endpoint_bdf, spdm_ctx, &session_id);
  if (status != ACS_STATUS_PASS)
    return status;

  status = val_spdm_send_pci_tdisp_get_version(spdm_ctx,
                                               session_id,
                                               interface_id_out);
  if (status != ACS_STATUS_PASS)
    goto close_session;

  status = val_spdm_send_pci_tdisp_get_capabilities(spdm_ctx,
                                                    session_id,
                                                    interface_id_out,
                                                    &req_caps,
                                                    &rsp_caps);
  if (status != ACS_STATUS_PASS)
    goto close_session;

  lock_param.flags = 0u;
  lock_param.default_stream_id = 0u;
  lock_param.reserved = 0u;
  lock_param.mmio_reporting_offset = 0ull;
  lock_param.bind_p2p_address_mask = 0ull;

  status = val_spdm_send_pci_tdisp_lock_interface(spdm_ctx,
                                                  session_id,
                                                  interface_id_out,
                                                  &lock_param,
                                                  nonce);
  if (status != ACS_STATUS_PASS)
    goto close_session;

  status = val_tdisp_get_interface_state(spdm_ctx,
                                         session_id,
                                         interface_id_out,
                                         &tdi_state);
  if (status != ACS_STATUS_PASS)
    goto close_session;

  if (tdi_state != PCI_TDISP_INTERFACE_STATE_CONFIG_LOCKED)
  {
    val_print(ACS_PRINT_INFO, " TDISP: interface not CONFIG_LOCKED 0x%x", tdi_state);
    status = ACS_STATUS_SKIP;
    goto close_session;
  }

  status = val_spdm_send_pci_tdisp_start_interface(spdm_ctx,
                                                   session_id,
                                                   interface_id_out,
                                                   nonce);
  if (status != ACS_STATUS_PASS)
    goto close_session;

  status = val_tdisp_get_interface_state(spdm_ctx,
                                         session_id,
                                         interface_id_out,
                                         &tdi_state);
  if (status != ACS_STATUS_PASS)
    goto close_session;

  if (tdi_state != PCI_TDISP_INTERFACE_STATE_RUN)
  {
    val_print(ACS_PRINT_INFO, " TDISP: interface not RUN 0x%x", tdi_state);
    status = ACS_STATUS_SKIP;
    goto close_session;
  }

  *session_id_out = session_id;
  return ACS_STATUS_PASS;

close_session:
  (void)val_spdm_session_close(spdm_ctx, session_id);
  return status;
#else
  (void)endpoint_bdf;
  (void)spdm_ctx;
  (void)session_id_out;
  (void)interface_id_out;

  return ACS_STATUS_SKIP;
#endif
}

/**
  @brief  Stop a TDISP interface if still running, then close its SPDM session.

  @param  spdm_ctx      SPDM context.
  @param  session_id    SPDM session identifier.
  @param  interface_id  TDISP interface identifier.
  @param  tdi_in_error  Nonzero when the interface is already in ERROR and STOP
                        should not be sent.

  @return ACS_STATUS_PASS/SKIP/ERR from the session close path.
**/
uint32_t
val_tdisp_stop_if_needed(val_spdm_context_t *spdm_ctx,
                         uint32_t session_id,
                         const pci_tdisp_interface_id_t *interface_id,
                         uint32_t tdi_in_error)
{
#if ENABLE_SPDM
  if ((spdm_ctx == NULL) || (session_id == 0u) || (interface_id == NULL))
    return ACS_STATUS_PASS;

  if (tdi_in_error == 0u)
    (void)val_spdm_send_pci_tdisp_stop_interface(spdm_ctx, session_id, interface_id);

  return val_spdm_session_close(spdm_ctx, session_id);
#else
  (void)spdm_ctx;
  (void)session_id;
  (void)interface_id;
  (void)tdi_in_error;

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
  status = val_execute_module_tests(TDISP_MODULE_ID,
                                    TDISP_MODULE_START,
                                    TDISP_MODULE_END,
                                    num_pe,
                                    status);

  return status;
}
