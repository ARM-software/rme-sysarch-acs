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
#include "include/val_pcie.h"
#include "include/val_memory.h"
#include "include/val_spdm.h"

#if ENABLE_SPDM

#include "acs_libspdm_config.h"
#include "library/spdm_common_lib.h"
#include "library/spdm_requester_lib.h"
#include "library/spdm_transport_pcidoe_lib.h"
#include "library/spdm_return_status.h"
#include "library/spdm_crypt_lib.h"
#include "industry_standard/spdm.h"
#include "industry_standard/pcidoe.h"
#include "industry_standard/cxl_idekm.h"
#include "industry_standard/spdm_secured_message.h"

#if defined(LIBSPDM_ENABLE_VENDOR_DEFINED_MESSAGES) && \
    (LIBSPDM_ENABLE_VENDOR_DEFINED_MESSAGES != 0)
#include "library/cxl_ide_km_requester_lib.h"
#include "library/cxl_tsp_requester_lib.h"
#include "library/pci_tdisp_requester_lib.h"
#endif

#define VAL_SPDM_REQUESTER_VERSION           SPDM_MESSAGE_VERSION_12
#define VAL_SPDM_SECURED_MESSAGE_VERSION     SECURED_SPDM_VERSION_11
#define VAL_SPDM_CT_EXPONENT                 20u
#define VAL_SPDM_REQUESTER_CAP_FLAGS         \
  (SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP | \
   SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP | \
   SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP | \
   SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP | \
   SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP)
#define VAL_SPDM_MEASUREMENT_SPEC            SPDM_MEASUREMENT_SPECIFICATION_DMTF
#define VAL_SPDM_OTHER_PARAMS_SUPPORT        SPDM_ALGORITHMS_OPAQUE_DATA_FORMAT_1
#define VAL_SPDM_BASE_ASYM_ALGOS             \
  (SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_3072 | \
   SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256 | \
   SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384)
#define VAL_SPDM_BASE_HASH_ALGOS             \
  (SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256 | \
   SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_384)
#define VAL_SPDM_DHE_GROUPS                  \
  (SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_256_R1 | \
   SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_384_R1)
#define VAL_SPDM_AEAD_CIPHER_SUITES          \
  (SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_128_GCM | \
   SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_256_GCM)
#define VAL_SPDM_KEY_SCHEDULE                SPDM_ALGORITHMS_KEY_SCHEDULE_HMAC_HASH
#define VAL_SPDM_REQ_BASE_ASYM_ALGOS         \
  (SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_3072 | \
   SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_2048 | \
   SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_3072 | \
   SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048)
#define VAL_SPDM_MAX_DIGEST_BUFFER_SIZE      (LIBSPDM_MAX_HASH_SIZE * SPDM_MAX_SLOT_COUNT)
#define VAL_SPDM_MAX_CERT_CHAIN_SIZE         LIBSPDM_MAX_CERT_CHAIN_SIZE

#define VAL_SPDM_MAX_SPDM_MSG_SIZE 0x1200u
#define VAL_SPDM_SENDER_BUFFER_SIZE \
  (LIBSPDM_PCI_DOE_TRANSPORT_HEADER_SIZE + VAL_SPDM_MAX_SPDM_MSG_SIZE + \
   LIBSPDM_PCI_DOE_TRANSPORT_TAIL_SIZE)
#define VAL_SPDM_RECEIVER_BUFFER_SIZE VAL_SPDM_SENDER_BUFFER_SIZE
#define VAL_SPDM_DEFAULT_TIMEOUT_US   5000000u

#define DOE_CAP_ID                     0x002Eu
#define DOE_CTRL_REG                   0x8u
#define DOE_STATUS_REG                 0xCu
#define DOE_WRITE_DATA_MAILBOX_REG     0x10u
#define DOE_READ_DATA_MAILBOX_REG      0x14u
#define DOE_STATUS_REG_BUSY            0u
#define DOE_STATUS_REG_ERROR           2u
#define DOE_STATUS_REG_READY           31u
#define DOE_MAX_DW_COUNT               0x40000u
#define DOE_MAX_POLL_RETRIES           1000000u

/**
  @brief  Compute the PCIe config-space offset for a BDF.

  @param  bdf  Concatenated segment:bus:device:function identifier.

  @return Offset within the ECAM window for the device.
**/
static uint64_t
val_spdm_get_cfg_offset(uint32_t bdf)
{
  uint64_t bus  = (uint64_t)PCIE_EXTRACT_BDF_BUS(bdf);
  uint64_t dev  = (uint64_t)PCIE_EXTRACT_BDF_DEV(bdf);
  uint64_t func = (uint64_t)PCIE_EXTRACT_BDF_FUNC(bdf);

  return (bus * PCIE_MAX_DEV * PCIE_MAX_FUNC * 4096u) +
         (dev * PCIE_MAX_FUNC * 4096u) +
         (func * 4096u);
}

/**
  @brief  Resolve DOE capability location for a device.

  @param  bdf   Device identifier.
  @param  ecam  Receives ECAM base address.
  @param  cfg   Receives config-space offset.
  @param  cap   Receives DOE capability offset.

  @return PCIE_SUCCESS on success, PCIE_CAP_NOT_FOUND otherwise.
**/
static uint32_t
val_spdm_doe_get_offsets(uint32_t bdf, uint64_t *ecam, uint64_t *cfg, uint32_t *cap)
{
  uint32_t ecam_index;

  if ((ecam == NULL) || (cfg == NULL) || (cap == NULL))
    return PCIE_CAP_NOT_FOUND;

  if (val_pcie_get_ecam_index(bdf, &ecam_index))
    return PCIE_CAP_NOT_FOUND;

  *ecam = val_pcie_get_info(PCIE_INFO_ECAM, ecam_index);
  if (*ecam == 0u)
    return PCIE_CAP_NOT_FOUND;

  *cfg = val_spdm_get_cfg_offset(bdf);

  return val_pcie_find_capability(bdf, PCIE_ECAP, DOE_CAP_ID, cap);
}

/**
  @brief  Submit a DOE request payload to the responder.

  @param  bdf       Target device identifier.
  @param  buffer    Pointer to DOE request bytes.
  @param  byte_len  Number of request bytes.

  @return 0 on success, non-zero on failure.
**/
static uint32_t
val_spdm_doe_send(uint32_t bdf, const void *buffer, uint32_t byte_len)
{
  uint64_t ecam;
  uint64_t cfg;
  uint32_t cap;
  uint32_t status;
  uint32_t retries = DOE_MAX_POLL_RETRIES;
  const uint8_t *src = (const uint8_t *)buffer;
  uint32_t aligned_len;

  if ((buffer == NULL) || (byte_len == 0u))
    return 1;

  status = val_spdm_doe_get_offsets(bdf, &ecam, &cfg, &cap);
  if (status != PCIE_SUCCESS)
    return 1;

  do {
    status = pal_mmio_read(ecam + cfg + cap + DOE_STATUS_REG);
    if (VAL_EXTRACT_BITS(status, DOE_STATUS_REG_BUSY, DOE_STATUS_REG_BUSY) == 0u)
      break;
  } while (--retries != 0u);

  if (retries == 0u)
    return 1;

  if (VAL_EXTRACT_BITS(status, DOE_STATUS_REG_ERROR, DOE_STATUS_REG_ERROR))
    return 1;

  aligned_len = (byte_len + 3u) & ~3u;

  for (uint32_t offset = 0; offset < aligned_len; offset += 4u) {
    uint32_t word = 0;
    for (uint32_t byte = 0; byte < 4u; ++byte) {
      uint32_t index = offset + byte;
      uint8_t value = (index < byte_len) ? src[index] : 0u;
      word |= ((uint32_t)value) << (byte * 8u);
    }
    pal_mmio_write(ecam + cfg + cap + DOE_WRITE_DATA_MAILBOX_REG, word);
  }

  pal_mmio_write(ecam + cfg + cap + DOE_CTRL_REG, (uint32_t)(1u << 31));

  return 0;
}

/**
  @brief  Read a DOE response payload from the responder.

  @param  bdf          Target device identifier.
  @param  buffer       Caller-provided destination buffer.
  @param  buffer_size  Size of the destination buffer in bytes.
  @param  bytes        Receives number of valid bytes.

  @return 0 on success, non-zero on failure.
**/
static uint32_t
val_spdm_doe_receive(uint32_t bdf, void *buffer, uint32_t buffer_size, uint32_t *bytes)
{
  uint64_t ecam;
  uint64_t cfg;
  uint32_t cap;
  uint32_t status;
  uint32_t retries = DOE_MAX_POLL_RETRIES;
  uint32_t header_dw[2];
  uint32_t total_dw;
  uint32_t payload_dw;
  uint8_t *dst = (uint8_t *)buffer;

  if ((buffer == NULL) || (bytes == NULL))
    return 1;

  status = val_spdm_doe_get_offsets(bdf, &ecam, &cfg, &cap);
  if (status != PCIE_SUCCESS)
    return 1;

  do {
    status = pal_mmio_read(ecam + cfg + cap + DOE_STATUS_REG);
    if ((VAL_EXTRACT_BITS(status, DOE_STATUS_REG_READY, DOE_STATUS_REG_READY) == 1u) &&
        (VAL_EXTRACT_BITS(status, DOE_STATUS_REG_BUSY, DOE_STATUS_REG_BUSY) == 0u))
      break;
  } while (--retries != 0u);

  if (retries == 0u)
    return 1;

  if (VAL_EXTRACT_BITS(status, DOE_STATUS_REG_ERROR, DOE_STATUS_REG_ERROR))
    return 1;

  header_dw[0] = pal_mmio_read(ecam + cfg + cap + DOE_READ_DATA_MAILBOX_REG);
  pal_mmio_write(ecam + cfg + cap + DOE_READ_DATA_MAILBOX_REG, 0);
  header_dw[1] = pal_mmio_read(ecam + cfg + cap + DOE_READ_DATA_MAILBOX_REG);
  pal_mmio_write(ecam + cfg + cap + DOE_READ_DATA_MAILBOX_REG, 0);

  total_dw = header_dw[1];
  if (total_dw == 0u)
    total_dw = DOE_MAX_DW_COUNT;
  if ((total_dw < 2u) || (total_dw > DOE_MAX_DW_COUNT))
    return 1;

  if ((total_dw * 4u) > buffer_size)
    return 1;

  payload_dw = total_dw - 2u;

  for (uint32_t idx = 0; idx < 2u; ++idx) {
    dst[idx * 4u + 0u] = (uint8_t)(header_dw[idx] & 0xFFu);
    dst[idx * 4u + 1u] = (uint8_t)((header_dw[idx] >> 8) & 0xFFu);
    dst[idx * 4u + 2u] = (uint8_t)((header_dw[idx] >> 16) & 0xFFu);
    dst[idx * 4u + 3u] = (uint8_t)((header_dw[idx] >> 24) & 0xFFu);
  }

  for (uint32_t payload = 0; payload < payload_dw; ++payload) {
    uint32_t value = pal_mmio_read(ecam + cfg + cap + DOE_READ_DATA_MAILBOX_REG);
    pal_mmio_write(ecam + cfg + cap + DOE_READ_DATA_MAILBOX_REG, 0);
    uint32_t offset = (payload + 2u) * 4u;
    dst[offset + 0u] = (uint8_t)(value & 0xFFu);
    dst[offset + 1u] = (uint8_t)((value >> 8) & 0xFFu);
    dst[offset + 2u] = (uint8_t)((value >> 16) & 0xFFu);
    dst[offset + 3u] = (uint8_t)((value >> 24) & 0xFFu);
  }

  status = pal_mmio_read(ecam + cfg + cap + DOE_STATUS_REG);
  if (VAL_EXTRACT_BITS(status, DOE_STATUS_REG_READY, DOE_STATUS_REG_READY))
    return 1;

  *bytes = total_dw * 4u;
  return 0;
}

uint32_t
val_doe_discovery(uint32_t bdf,
                  val_pci_doe_protocol_t *protocols,
                  uint32_t *protocol_count)
{
#if ENABLE_SPDM
  typedef struct {
    pci_doe_data_object_header_t header;
    pci_doe_discovery_request_t request;
  } VAL_DOE_DISCOVERY_REQUEST;

  typedef struct {
    pci_doe_data_object_header_t header;
    pci_doe_discovery_response_t response;
  } VAL_DOE_DISCOVERY_RESPONSE;

  VAL_DOE_DISCOVERY_REQUEST request;
  uint8_t response_buffer[sizeof(VAL_DOE_DISCOVERY_RESPONSE) + sizeof(uint32_t)];
  VAL_DOE_DISCOVERY_RESPONSE *response;
  uint32_t capacity;
  uint32_t bytes;
  uint32_t index = 0u;
  uint8_t next_index;
  uint32_t total_bytes;

  if ((protocols == NULL) || (protocol_count == NULL))
    return ACS_STATUS_ERR;

  capacity = *protocol_count;
  if (capacity == 0u)
    return ACS_STATUS_ERR;

  do {
    if (index > 0xFFu)
      return ACS_STATUS_ERR;

    val_memory_set(&request, sizeof(request), 0);
    request.header.vendor_id = PCI_DOE_VENDOR_ID_PCISIG;
    request.header.data_object_type = PCI_DOE_DATA_OBJECT_TYPE_DOE_DISCOVERY;
    request.header.length = sizeof(request) / sizeof(uint32_t);
    request.request.index = (uint8_t)index;
    request.request.version = 0u;

    if (val_spdm_doe_send(bdf, &request, (uint32_t)sizeof(request)))
      return ACS_STATUS_FAIL;

    bytes = sizeof(response_buffer);
    if (val_spdm_doe_receive(bdf, response_buffer, sizeof(response_buffer), &bytes))
      return ACS_STATUS_FAIL;

    if (bytes < sizeof(VAL_DOE_DISCOVERY_RESPONSE))
      return ACS_STATUS_ERR;

    response = (VAL_DOE_DISCOVERY_RESPONSE *)response_buffer;
    if (response->header.vendor_id != PCI_DOE_VENDOR_ID_PCISIG)
      return ACS_STATUS_ERR;
    if (response->header.data_object_type != PCI_DOE_DATA_OBJECT_TYPE_DOE_DISCOVERY)
      return ACS_STATUS_ERR;

    if (response->header.length == 0u)
      return ACS_STATUS_ERR;

    total_bytes = response->header.length * sizeof(uint32_t);
    if (total_bytes > bytes)
      return ACS_STATUS_ERR;

    if (index >= capacity)
      return ACS_STATUS_ERR;

    protocols[index].vendor_id = response->response.vendor_id;
    protocols[index].data_object_type = response->response.data_object_type;
    protocols[index].reserved = 0u;

    next_index = response->response.next_index;
    if (next_index == 0u)
      break;
    if (next_index != (uint8_t)(index + 1u))
      return ACS_STATUS_ERR;

    index = next_index;
  } while (1);

  *protocol_count = index + 1u;
  return ACS_STATUS_PASS;
#else
  (void)bdf;
  (void)protocols;
  if (protocol_count != NULL)
    *protocol_count = 0u;
  return ACS_STATUS_SKIP;
#endif
}

/**
  @brief  Fetch the VAL SPDM context wrapper associated with a libspdm handle.

  @param  spdm_context  libspdm context pointer.

  @return Pointer to the VAL wrapper or NULL on error.
**/
static val_spdm_context_t *
val_spdm_get_context(void *spdm_context)
{
  size_t ctx_size;
  libspdm_return_t status;
  val_spdm_context_t *ctx = NULL;
  libspdm_data_parameter_t parameter;

  parameter.location = LIBSPDM_DATA_LOCATION_LOCAL;
  ctx_size = sizeof(ctx);
  status = libspdm_get_data(spdm_context,
                            LIBSPDM_DATA_APP_CONTEXT_DATA,
                            &parameter,
                            &ctx,
                            &ctx_size);
  if (LIBSPDM_STATUS_IS_ERROR(status) || (ctx == NULL))
    return NULL;

  return ctx;
}

/**
  @brief  libspdm device I/O hook to transmit a request via DOE mailbox.

  @param  spdm_context  libspdm context provided by the framework.
  @param  message_size  Length of the SPDM message.
  @param  message       Pointer to the message buffer.
  @param  timeout       Unused timeout hint.

  @return libspdm status code indicating success or failure.
**/
static libspdm_return_t
val_spdm_send_message(void *spdm_context, size_t message_size,
                          const void *message, uint64_t timeout)
{
  val_spdm_context_t *ctx;

  (void)timeout;

  ctx = val_spdm_get_context(spdm_context);
  if ((ctx == NULL) || (message == NULL))
    return LIBSPDM_STATUS_INVALID_PARAMETER;

  if (message_size > ctx->sender_buffer_size)
    return LIBSPDM_STATUS_BUFFER_TOO_SMALL;

  if (val_spdm_doe_send(ctx->bdf, message, (uint32_t)message_size))
    return LIBSPDM_STATUS_SEND_FAIL;

  return LIBSPDM_STATUS_SUCCESS;
}

/**
  @brief  libspdm device I/O hook to receive a DOE response.

  @param  spdm_context   libspdm context provided by the framework.
  @param  message_size   On entry holds buffer size, on exit holds bytes read.
  @param  message        Receives pointer to the response buffer.
  @param  timeout        Unused timeout hint.

  @return libspdm status code indicating success or failure.
**/
static libspdm_return_t
val_spdm_receive_message(void *spdm_context, size_t *message_size,
                             void **message, uint64_t timeout)
{
  uint32_t bytes;
  val_spdm_context_t *ctx;

  (void)timeout;

  if ((message_size == NULL) || (message == NULL))
    return LIBSPDM_STATUS_INVALID_PARAMETER;

  ctx = val_spdm_get_context(spdm_context);
  if (ctx == NULL)
    return LIBSPDM_STATUS_INVALID_PARAMETER;

  bytes = ctx->receiver_buffer_size;
  if (val_spdm_doe_receive(ctx->bdf, ctx->receiver_buffer,
                           ctx->receiver_buffer_size, &bytes))
    return LIBSPDM_STATUS_RECEIVE_FAIL;

  *message_size = bytes;
  *message = ctx->receiver_buffer;

  return LIBSPDM_STATUS_SUCCESS;
}

/**
  @brief  Provide libspdm with a transmit buffer from the VAL pool.

  @param  spdm_context  libspdm context provided by the framework.
  @param  msg_buf_ptr   Receives pointer to the transport payload buffer.

  @return libspdm status indicating success or acquisition failure.
**/
static libspdm_return_t
val_spdm_acquire_sender_buffer(void *spdm_context, void **msg_buf_ptr)
{
  val_spdm_context_t *ctx;

  if (msg_buf_ptr == NULL)
    return LIBSPDM_STATUS_INVALID_PARAMETER;

  ctx = val_spdm_get_context(spdm_context);
  if ((ctx == NULL) || ctx->sender_in_use)
    return LIBSPDM_STATUS_ACQUIRE_FAIL;

  ctx->sender_in_use = 1;
  *msg_buf_ptr = ctx->sender_buffer + LIBSPDM_PCI_DOE_TRANSPORT_HEADER_SIZE;

  return LIBSPDM_STATUS_SUCCESS;
}

/**
  @brief  Mark the transmit buffer as free after libspdm use.

  @param  spdm_context  libspdm context provided by the framework.
  @param  msg_buf_ptr   Pointer previously returned by acquire API.
**/
static void
val_spdm_release_sender_buffer(void *spdm_context, const void *msg_buf_ptr)
{
  val_spdm_context_t *ctx;

  (void)msg_buf_ptr;
  ctx = val_spdm_get_context(spdm_context);
  if (ctx == NULL)
    return;

  ctx->sender_in_use = 0;
}

/**
  @brief  Provide libspdm with a receive buffer from the VAL pool.

  @param  spdm_context  libspdm context provided by the framework.
  @param  msg_buf_ptr   Receives pointer to the transport receive buffer.

  @return libspdm status indicating success or acquisition failure.
**/
static libspdm_return_t
val_spdm_acquire_receiver_buffer(void *spdm_context, void **msg_buf_ptr)
{
  val_spdm_context_t *ctx;

  if (msg_buf_ptr == NULL)
    return LIBSPDM_STATUS_INVALID_PARAMETER;

  ctx = val_spdm_get_context(spdm_context);
  if ((ctx == NULL) || ctx->receiver_in_use)
    return LIBSPDM_STATUS_ACQUIRE_FAIL;

  ctx->receiver_in_use = 1;
  *msg_buf_ptr = ctx->receiver_buffer;

  return LIBSPDM_STATUS_SUCCESS;
}

/**
  @brief  Release the receive buffer back to the VAL pool.

  @param  spdm_context  libspdm context provided by the framework.
  @param  msg_buf_ptr   Pointer previously returned by acquire API.
**/
static void
val_spdm_release_receiver_buffer(void *spdm_context, const void *msg_buf_ptr)
{
  val_spdm_context_t *ctx;

  (void)msg_buf_ptr;
  ctx = val_spdm_get_context(spdm_context);
  if (ctx == NULL)
    return;

  ctx->receiver_in_use = 0;
}

/**
  @brief  Tear down buffers and libspdm state owned by the VAL wrapper.

  @param  context  VAL SPDM context to clean up.
**/
static void
val_spdm_free_allocations(val_spdm_context_t *context)
{
  if (context == NULL)
    return;

  if (context->spdm_context != NULL)
    libspdm_deinit_context(context->spdm_context);

  if (context->sender_buffer != NULL)
    val_memory_free(context->sender_buffer);

  if (context->receiver_buffer != NULL)
    val_memory_free(context->receiver_buffer);

  if (context->scratch_buffer != NULL)
    val_memory_free(context->scratch_buffer);

  if (context->spdm_context != NULL)
    val_memory_free(context->spdm_context);

  context->spdm_context = NULL;
  context->sender_buffer = NULL;
  context->receiver_buffer = NULL;
  context->scratch_buffer = NULL;
  context->sender_buffer_size = 0;
  context->receiver_buffer_size = 0;
  context->scratch_buffer_size = 0;
  context->bdf = 0;
}

/**
  @brief  Program the default requester capabilities into the libspdm context.

  @param  spdm_context  libspdm context pointer.

  @return libspdm status code from the configuration sequence.
**/
static libspdm_return_t
val_spdm_set_default_capabilities(void *spdm_context)
{
  uint32_t data32 = 0;
  uint8_t data8;
  libspdm_return_t status;
  libspdm_data_parameter_t parameter;
  val_spdm_context_t *ctx;
  spdm_version_number_t requester_version;
  spdm_version_number_t secured_msg_version;

  val_memory_set(&parameter, sizeof(parameter), 0);
  parameter.location = LIBSPDM_DATA_LOCATION_LOCAL;
  ctx = val_spdm_get_context(spdm_context);

  val_print(ACS_PRINT_INFO, " SPDM DBG: Setting default caps (BDF 0x%x)",
            (uint64_t)(ctx != NULL ? ctx->bdf : ACS_INVALID_INDEX));

  requester_version = (spdm_version_number_t)VAL_SPDM_REQUESTER_VERSION <<
                      SPDM_VERSION_NUMBER_SHIFT_BIT;
  val_print(ACS_PRINT_DEBUG, " SPDM DBG: requester_version 0x%x", requester_version);
  status = libspdm_set_data(spdm_context,
                            LIBSPDM_DATA_SPDM_VERSION,
                            &parameter,
                            &requester_version,
                            sizeof(requester_version));
  if (LIBSPDM_STATUS_IS_ERROR(status)) {
    val_print(ACS_PRINT_ERR, " SPDM DBG: set requester version failed (0x%x)", status);
    return status;
  }

  val_memory_set(&parameter, sizeof(parameter), 0);
  parameter.location = LIBSPDM_DATA_LOCATION_LOCAL;

  secured_msg_version = (spdm_version_number_t)VAL_SPDM_SECURED_MESSAGE_VERSION <<
                        SPDM_VERSION_NUMBER_SHIFT_BIT;
  val_print(ACS_PRINT_DEBUG, " SPDM DBG: secured_msg_version 0x%x", secured_msg_version);
  status = libspdm_set_data(spdm_context,
                            LIBSPDM_DATA_SECURED_MESSAGE_VERSION,
                            &parameter,
                            &secured_msg_version,
                            sizeof(secured_msg_version));
  if (LIBSPDM_STATUS_IS_ERROR(status)) {
    val_print(ACS_PRINT_ERR, " SPDM DBG: set secured message version failed (0x%x)",
              status);
    return status;
  }

  val_memory_set(&parameter, sizeof(parameter), 0);


  parameter.location = LIBSPDM_DATA_LOCATION_LOCAL;
  data8 = VAL_SPDM_CT_EXPONENT;
  val_print(ACS_PRINT_DEBUG, " SPDM DBG: ct_exponent 0x%x", data8);
  status = libspdm_set_data(spdm_context,
                            LIBSPDM_DATA_CAPABILITY_CT_EXPONENT,
                            &parameter,
                            &data8,
                            sizeof(data8));
  if (LIBSPDM_STATUS_IS_ERROR(status)) {
    val_print(ACS_PRINT_ERR, " SPDM DBG: set local ct_exp failed (0x%x)", status);
    return status;
  }

  data32 = VAL_SPDM_REQUESTER_CAP_FLAGS;
  val_print(ACS_PRINT_DEBUG, " SPDM DBG: capability_flags 0x%x", data32);
  status = libspdm_set_data(spdm_context,
                            LIBSPDM_DATA_CAPABILITY_FLAGS,
                            &parameter,
                            &data32,
                            sizeof(data32));
  if (LIBSPDM_STATUS_IS_ERROR(status)) {
    val_print(ACS_PRINT_ERR, " SPDM DBG: set capability flags failed (0x%x)", status);
    return status;
  }

  data8 = VAL_SPDM_MEASUREMENT_SPEC;
  val_print(ACS_PRINT_DEBUG, " SPDM DBG: meas_spec 0x%x", data8);
  status = libspdm_set_data(spdm_context,
                            LIBSPDM_DATA_MEASUREMENT_SPEC,
                            &parameter,
                            &data8,
                            sizeof(data8));
  if (LIBSPDM_STATUS_IS_ERROR(status)) {
    val_print(ACS_PRINT_ERR, " SPDM DBG: set measurement spec failed (0x%x)", status);
    return status;
  }

  data8 = VAL_SPDM_OTHER_PARAMS_SUPPORT;
  val_print(ACS_PRINT_DEBUG, " SPDM DBG: other_params 0x%x", data8);
  status = libspdm_set_data(spdm_context,
                            LIBSPDM_DATA_OTHER_PARAMS_SUPPORT,
                            &parameter,
                            &data8,
                            sizeof(data8));
  if (LIBSPDM_STATUS_IS_ERROR(status)) {
    val_print(ACS_PRINT_ERR, " SPDM DBG: set other params failed (0x%x)", status);
    return status;
  }

  data32 = VAL_SPDM_BASE_ASYM_ALGOS;
  val_print(ACS_PRINT_DEBUG, " SPDM DBG: base_asym 0x%x", data32);
  status = libspdm_set_data(spdm_context,
                            LIBSPDM_DATA_BASE_ASYM_ALGO,
                            &parameter,
                            &data32,
                            sizeof(data32));
  if (LIBSPDM_STATUS_IS_ERROR(status)) {
    val_print(ACS_PRINT_ERR, " SPDM DBG: set base asym failed (0x%x)", status);
    return status;
  }

  data32 = VAL_SPDM_BASE_HASH_ALGOS;
  val_print(ACS_PRINT_DEBUG, " SPDM DBG: base_hash 0x%x", data32);
  status = libspdm_set_data(spdm_context,
                            LIBSPDM_DATA_BASE_HASH_ALGO,
                            &parameter,
                            &data32,
                            sizeof(data32));
  if (LIBSPDM_STATUS_IS_ERROR(status)) {
    val_print(ACS_PRINT_ERR, " SPDM DBG: set base hash failed (0x%x)", status);
    return status;
  }

  uint16_t data16;

  data16 = VAL_SPDM_DHE_GROUPS;
  val_print(ACS_PRINT_DEBUG, " SPDM DBG: dhe 0x%x", data16);
  status = libspdm_set_data(spdm_context,
                            LIBSPDM_DATA_DHE_NAME_GROUP,
                            &parameter,
                            &data16,
                            sizeof(data16));
  if (LIBSPDM_STATUS_IS_ERROR(status)) {
    val_print(ACS_PRINT_ERR, " SPDM DBG: set dhe group failed (0x%x)", status);
    return status;
  }

  data16 = VAL_SPDM_AEAD_CIPHER_SUITES;
  val_print(ACS_PRINT_DEBUG, " SPDM DBG: aead 0x%x", data16);
  status = libspdm_set_data(spdm_context,
                            LIBSPDM_DATA_AEAD_CIPHER_SUITE,
                            &parameter,
                            &data16,
                            sizeof(data16));
  if (LIBSPDM_STATUS_IS_ERROR(status)) {
    val_print(ACS_PRINT_ERR, " SPDM DBG: set AEAD failed (0x%x)", status);
    return status;
  }

  data16 = VAL_SPDM_KEY_SCHEDULE;
  val_print(ACS_PRINT_DEBUG, " SPDM DBG: key_schedule 0x%x", data16);
  status = libspdm_set_data(spdm_context,
                            LIBSPDM_DATA_KEY_SCHEDULE,
                            &parameter,
                            &data16,
                            sizeof(data16));
  if (LIBSPDM_STATUS_IS_ERROR(status)) {
    val_print(ACS_PRINT_ERR, " SPDM DBG: set key schedule failed (0x%x)", status);
    return status;
  }

  data16 = VAL_SPDM_REQ_BASE_ASYM_ALGOS;

  val_print(ACS_PRINT_DEBUG, " SPDM DBG: req_base_asym 0x%x", data16);
  status = libspdm_set_data(spdm_context,
                            LIBSPDM_DATA_REQ_BASE_ASYM_ALG,
                            &parameter,
                            &data16,
                            sizeof(data16));
  if (LIBSPDM_STATUS_IS_ERROR(status)) {
    val_print(ACS_PRINT_ERR, " SPDM DBG: set req base asym failed (0x%x)", status);
    return status;
  }

  return LIBSPDM_STATUS_SUCCESS;
}

#endif /* ENABLE_SPDM */

/**
  @brief  Initialise the VAL SPDM requester context for a PCIe device.

  @param  bdf      Target device identifier.
  @param  context  Caller-supplied context structure to populate.

  @return ACS_STATUS_PASS on success, ACS_STATUS_SKIP/ERR otherwise.
**/
uint32_t
val_spdm_context_init(uint32_t bdf,
                      val_spdm_context_t *context)
{
#if ENABLE_SPDM
  size_t scratch_size;
  size_t ctx_size;
  libspdm_return_t status;
  libspdm_data_parameter_t parameter;
  uint32_t doe_cap_offset;

  if (context == NULL)
    return ACS_STATUS_ERR;

  val_memory_set(context, sizeof(*context), 0);

  if (bdf == ACS_INVALID_INDEX) {
    val_print(ACS_PRINT_ERR, " SPDM: Invalid BDF 0x%x", bdf);
    return ACS_STATUS_ERR;
  }

  context->bdf = bdf;

  if (val_pcie_find_capability(context->bdf, PCIE_ECAP, DOE_CAP_ID,
                                                   &doe_cap_offset) != PCIE_SUCCESS) {
    val_print(ACS_PRINT_INFO, " SPDM: DOE capability missing for BDF 0x%lx",
              (uint64_t)context->bdf);
    return ACS_STATUS_SKIP;
  }

  ctx_size = libspdm_get_context_size();
  context->spdm_context = val_memory_alloc((uint32_t)ctx_size);
  if (context->spdm_context == NULL)
    goto error;

  if (LIBSPDM_STATUS_IS_ERROR(libspdm_init_context(context->spdm_context)))
    goto error;

  val_memory_set(&parameter, sizeof(parameter), 0);
  val_print(ACS_PRINT_INFO, " SPDM DBG: Binding val context (BDF 0x%x)",
            (uint64_t)context->bdf);
  parameter.location = LIBSPDM_DATA_LOCATION_LOCAL;
  status = libspdm_set_data(context->spdm_context,
                            LIBSPDM_DATA_APP_CONTEXT_DATA,
                            &parameter,
                            &context,
                            sizeof(context));
  if (LIBSPDM_STATUS_IS_ERROR(status))
    goto error;

  context->sender_buffer_size = VAL_SPDM_SENDER_BUFFER_SIZE;
  context->receiver_buffer_size = VAL_SPDM_RECEIVER_BUFFER_SIZE;

  context->sender_buffer = val_memory_alloc(context->sender_buffer_size);
  context->receiver_buffer = val_memory_alloc(context->receiver_buffer_size);

  if ((context->sender_buffer == NULL) || (context->receiver_buffer == NULL))
    goto error;

  libspdm_register_device_io_func(context->spdm_context,
                                  val_spdm_send_message,
                                  val_spdm_receive_message);

  libspdm_register_transport_layer_func(context->spdm_context,
                                        VAL_SPDM_MAX_SPDM_MSG_SIZE,
                                        LIBSPDM_PCI_DOE_TRANSPORT_HEADER_SIZE,
                                        LIBSPDM_PCI_DOE_TRANSPORT_TAIL_SIZE,
                                        libspdm_transport_pci_doe_encode_message,
                                        libspdm_transport_pci_doe_decode_message);

  status = val_spdm_set_default_capabilities(context->spdm_context);
  if (LIBSPDM_STATUS_IS_ERROR(status))
    goto error;

  val_print(ACS_PRINT_INFO, " SPDM DBG: Query scratch size (BDF 0x%x)",
            (uint64_t)context->bdf);
  scratch_size = libspdm_get_sizeof_required_scratch_buffer(context->spdm_context);
  val_print(ACS_PRINT_INFO, " SPDM DBG: Scratch size 0x%lx", (uint64_t)scratch_size);
  context->scratch_buffer_size = (uint32_t)scratch_size;
  context->scratch_buffer = val_memory_alloc(context->scratch_buffer_size);
  if (context->scratch_buffer == NULL)
    goto error;

  libspdm_register_device_buffer_func(context->spdm_context,
                                      context->sender_buffer_size,
                                      context->receiver_buffer_size,
                                      val_spdm_acquire_sender_buffer,
                                      val_spdm_release_sender_buffer,
                                      val_spdm_acquire_receiver_buffer,
                                      val_spdm_release_receiver_buffer);

  libspdm_set_scratch_buffer(context->spdm_context,
                             context->scratch_buffer,
                             context->scratch_buffer_size);
  val_print(ACS_PRINT_INFO, " SPDM DBG: Registered scratch buffer size 0x%lx",
            (uint64_t)context->scratch_buffer_size);

  status = libspdm_init_connection(context->spdm_context, false);
  if (LIBSPDM_STATUS_IS_ERROR(status)) {
    val_print(ACS_PRINT_ERR, " SPDM: init_connection failed (0x%x)", status);
    goto error;
  }

  return ACS_STATUS_PASS;

error:
  val_spdm_free_allocations(context);
  return ACS_STATUS_ERR;
#else
  (void)bdf;
  (void)context;
  val_print(ACS_PRINT_WARN, " SPDM: Feature disabled - skipping context init", 0);
  return ACS_STATUS_SKIP;
#endif
}

/**
  @brief  Release all resources associated with a VAL SPDM context.

  @param  context  Context returned by val_spdm_context_init().
**/
void
val_spdm_context_deinit(val_spdm_context_t *context)
{
#if ENABLE_SPDM
  if (context == NULL)
    return;

  val_spdm_free_allocations(context);
#else
  (void)context;
#endif
}

/**
  @brief  Retrieve the negotiated SPDM version from the responder.

  @param  context        Initialised VAL SPDM context.
  @param  versions       Output array for version data (must have >=1 entry).
  @param  version_count  Receives number of populated entries.

  @return ACS status code indicating success or failure.
**/
uint32_t
val_spdm_get_version(val_spdm_context_t *context,
                     val_spdm_version_t *versions,
                     uint8_t *version_count)
{
#if ENABLE_SPDM
  libspdm_return_t status;
  spdm_version_number_t negotiated_version;
  libspdm_data_parameter_t parameter;
  size_t data_size;

  if ((context == NULL) || (context->spdm_context == NULL) ||
      (versions == NULL) || (version_count == NULL))
    return ACS_STATUS_ERR;

  val_memory_set(&parameter, sizeof(parameter), 0);
  parameter.location = LIBSPDM_DATA_LOCATION_CONNECTION;
  data_size = sizeof(negotiated_version);

  status = libspdm_get_data(context->spdm_context,
                            LIBSPDM_DATA_SPDM_VERSION,
                            &parameter,
                            &negotiated_version,
                            &data_size);
  if (LIBSPDM_STATUS_IS_ERROR(status) || (data_size != sizeof(negotiated_version))) {
    val_print(ACS_PRINT_ERR, " SPDM: GET_VERSION data fetch failed (0x%x)", status);
    return ACS_STATUS_ERR;
  }

  versions[0].major  = (uint8_t)((negotiated_version >> 12) & 0xF);
  versions[0].minor  = (uint8_t)((negotiated_version >> 8)  & 0xF);
  versions[0].update = (uint8_t)((negotiated_version >> 4)  & 0xF);
  versions[0].alpha  = (uint8_t)(negotiated_version & 0xF);

  *version_count = 1;
  return ACS_STATUS_PASS;
#else
  (void)context;
  (void)versions;
  if (version_count != NULL)
    *version_count = 0;
  val_print(ACS_PRINT_WARN, " SPDM: Feature disabled - skipping GET_VERSION", 0);
  return ACS_STATUS_SKIP;
#endif
}

/**
  @brief  Establish an SPDM secure session with the responder.

  @param  context     Initialised VAL SPDM context.
  @param  session_id  Receives the negotiated session identifier.

  @return ACS status code indicating success or failure.
**/
uint32_t
val_spdm_session_open(uint32_t bdf,
                      val_spdm_context_t *context,
                      uint32_t *session_id)
{
#if ENABLE_SPDM
  uint32_t status;

  if ((context == NULL) || (session_id == NULL))
    return ACS_STATUS_ERR;

  *session_id = 0;

  status = val_spdm_context_init(bdf, context);
  if (status != ACS_STATUS_PASS)
    return status;

  status = val_spdm_start_session(context, session_id);
  if (status != ACS_STATUS_PASS) {
    val_spdm_context_deinit(context);
    return status;
  }

  return ACS_STATUS_PASS;
#else
  (void)bdf;
  (void)context;
  if (session_id != NULL)
    *session_id = 0;
  val_print(ACS_PRINT_WARN, " SPDM: Feature disabled - skipping session open", 0);
  return ACS_STATUS_SKIP;
#endif
}

uint32_t
val_spdm_start_session(val_spdm_context_t *context,
                       uint32_t *session_id)
{
#if ENABLE_SPDM
  libspdm_return_t status;
  uint8_t slot_mask = 0u;
  uint8_t slot_id = 0u;
  uint8_t digest_buffer[VAL_SPDM_MAX_DIGEST_BUFFER_SIZE];
  uint8_t *cert_chain = NULL;
  size_t cert_chain_size;
  uint32_t result = ACS_STATUS_ERR;

  if ((context == NULL) || (context->spdm_context == NULL) || (session_id == NULL))
    return ACS_STATUS_ERR;

  val_memory_set(digest_buffer, sizeof(digest_buffer), 0);
  cert_chain_size = VAL_SPDM_MAX_CERT_CHAIN_SIZE;

  cert_chain = val_memory_alloc((uint32_t)cert_chain_size);
  if (cert_chain == NULL) {
    val_print(ACS_PRINT_ERR, " SPDM: Certificate buffer alloc failed", 0);
    goto cleanup;
  }
  val_memory_set(cert_chain, (uint32_t)cert_chain_size, 0);

  status = libspdm_get_digest(context->spdm_context,
                              NULL,
                              &slot_mask,
                              digest_buffer);
  if (LIBSPDM_STATUS_IS_ERROR(status) || (slot_mask == 0u)) {
    val_print(ACS_PRINT_ERR, " SPDM: GET_DIGESTS failed (0x%x)", status);
    goto cleanup;
  }

  while ((slot_id < SPDM_MAX_SLOT_COUNT) && ((slot_mask & (1u << slot_id)) == 0u))
    ++slot_id;
  if (slot_id >= SPDM_MAX_SLOT_COUNT) {
    val_print(ACS_PRINT_ERR, " SPDM: No responder slot available (mask 0x%x)", slot_mask);
    goto cleanup;
  }

  val_print(ACS_PRINT_DEBUG, " SPDM DBG: Using responder slot %u", slot_id);

  status = libspdm_get_certificate(context->spdm_context,
                                   NULL,
                                   slot_id,
                                   &cert_chain_size,
                                   cert_chain);
  if (LIBSPDM_STATUS_IS_ERROR(status)) {
    val_print(ACS_PRINT_ERR, " SPDM: GET_CERTIFICATE failed (0x%x)", status);
    goto cleanup;
  }

  status = libspdm_start_session(context->spdm_context,
                                 false,
                                 NULL,
                                 0,
                                 SPDM_REQUEST_NO_MEASUREMENT_SUMMARY_HASH,
                                 slot_id,
                                 0,
                                 session_id,
                                 NULL,
                                 NULL);

  if (LIBSPDM_STATUS_IS_ERROR(status)) {
    val_print(ACS_PRINT_ERR, " SPDM: start_session failed (0x%x)", status);
    goto cleanup;
  }

  result = ACS_STATUS_PASS;
  val_print(ACS_PRINT_INFO, " SPDM DBG: session started (ID 0x%x)", (uint64_t)(*session_id));

cleanup:
  if (cert_chain != NULL)
    val_memory_free(cert_chain);

  return result;
#else
  (void)context;
  if (session_id != NULL)
    *session_id = 0;
  val_print(ACS_PRINT_WARN, " SPDM: Feature disabled - skipping session start", 0);
  return ACS_STATUS_SKIP;
#endif
}

/**
  @brief  Terminate an SPDM secure session.

  @param  context     Initialised VAL SPDM context.
  @param  session_id  Identifier returned from val_spdm_start_session().

  @return ACS status code indicating success or failure.
**/
uint32_t
val_spdm_stop_session(val_spdm_context_t *context,
                      uint32_t session_id)
{
#if ENABLE_SPDM
  libspdm_return_t status;

  if ((context == NULL) || (context->spdm_context == NULL))
    return ACS_STATUS_ERR;

  status = libspdm_stop_session(context->spdm_context,
                                session_id,
                                0);
  if (LIBSPDM_STATUS_IS_ERROR(status)) {
    val_print(ACS_PRINT_ERR, " SPDM: stop_session failed (0x%x)", status);
    return ACS_STATUS_ERR;
  }

  val_print(ACS_PRINT_INFO, " SPDM DBG: session ended (ID 0x%x)", (uint64_t)session_id);

  return ACS_STATUS_PASS;
#else
  (void)context;
  (void)session_id;
  val_print(ACS_PRINT_WARN, " SPDM: Feature disabled - skipping session stop", 0);
  return ACS_STATUS_SKIP;
#endif
}

/**
  @brief  Issue a CXL IDE KM query over the active SPDM session.

  @param  context     Initialised VAL SPDM context.
  @param  session_id  Active SPDM session identifier.
  @param  port_index  Target CXL port index.
  @param  response    Optional pointer to receive parsed IDE KM data.

  @return ACS status code indicating success or failure.
**/
uint32_t
val_spdm_session_close(val_spdm_context_t *context,
                       uint32_t session_id)
{
#if ENABLE_SPDM
  uint32_t status = ACS_STATUS_PASS;

  if (context == NULL)
    return ACS_STATUS_ERR;

  if ((context->spdm_context != NULL) && (session_id != 0u)) {
    uint32_t stop_status = val_spdm_stop_session(context, session_id);
    if (stop_status != ACS_STATUS_PASS)
      status = stop_status;
  }

  val_spdm_context_deinit(context);
  return status;
#else
  (void)context;
  (void)session_id;
  val_print(ACS_PRINT_WARN, " SPDM: Feature disabled - skipping session close", 0);
  return ACS_STATUS_SKIP;
#endif
}

uint32_t
val_spdm_send_cxl_ide_km_query(val_spdm_context_t *context,
                               uint32_t session_id,
                               uint8_t port_index,
                               cxl_ide_km_query_resp_t *response,
                               uint32_t *ide_reg_buffer,
                               uint32_t *ide_reg_count)
{
#if ENABLE_SPDM
#if !defined(LIBSPDM_ENABLE_VENDOR_DEFINED_MESSAGES) || \
    (LIBSPDM_ENABLE_VENDOR_DEFINED_MESSAGES == 0)
  (void)context;
  (void)session_id;
  (void)port_index;
  (void)response;
  (void)ide_reg_buffer;
  (void)ide_reg_count;

  val_print(ACS_PRINT_WARN, " SPDM: Vendor-defined messaging disabled", 0);
  return ACS_STATUS_SKIP;
#else
  libspdm_return_t status;
  uint8_t dev_func_num = 0;
  uint8_t bus_num = 0;
  uint8_t segment = 0;
  uint8_t max_port_index = 0;
  uint8_t caps = 0;
  uint32_t local_ide_reg_buffer[CXL_IDE_KM_IDE_CAP_REG_BLOCK_MAX_COUNT];
  uint32_t local_ide_reg_count;

  if ((context == NULL) || (context->spdm_context == NULL))
    return ACS_STATUS_ERR;

  if (((ide_reg_buffer == NULL) && (ide_reg_count != NULL)) ||
      ((ide_reg_buffer != NULL) && (ide_reg_count == NULL)))
    return ACS_STATUS_ERR;

  local_ide_reg_count = CXL_IDE_KM_IDE_CAP_REG_BLOCK_MAX_COUNT;
  status = cxl_ide_km_query(NULL,
                            context->spdm_context,
                            &session_id,
                            port_index,
                            &dev_func_num,
                            &bus_num,
                            &segment,
                            &max_port_index,
                            &caps,
                            local_ide_reg_buffer,
                            &local_ide_reg_count);
  if (status == LIBSPDM_STATUS_BUFFER_TOO_SMALL) {
    val_print(ACS_PRINT_ERR, " SPDM: IDE_KM reg buffer too small (port %u)",
              (uint64_t)port_index);
    val_print(ACS_PRINT_DEBUG, " SPDM DBG: IDE_KM required reg entries %u",
              (uint64_t)local_ide_reg_count);
    return ACS_STATUS_ERR;
  }
  if (LIBSPDM_STATUS_IS_ERROR(status)) {
    val_print(ACS_PRINT_ERR, " SPDM: IDE_KM query failed (0x%x)",
              (uint64_t)status);
    return ACS_STATUS_ERR;
  }

  if (response != NULL) {
    val_memory_set(response, (uint32_t)sizeof(*response), 0);
    response->header.object_id = CXL_IDE_KM_OBJECT_ID_QUERY_RESP;
    response->port_index = port_index;
    response->dev_func_num = dev_func_num;
    response->bus_num = bus_num;
    response->segment = segment;
    response->max_port_index = max_port_index;
    response->caps = caps;
  }

  if ((ide_reg_buffer != NULL) && (ide_reg_count != NULL)) {
    if (*ide_reg_count < local_ide_reg_count) {
      val_print(ACS_PRINT_ERR, " SPDM: IDE_KM reg copy buffer too small", 0);
      return ACS_STATUS_ERR;
    }
    for (uint32_t idx = 0; idx < local_ide_reg_count; ++idx)
      ide_reg_buffer[idx] = local_ide_reg_buffer[idx];
    *ide_reg_count = local_ide_reg_count;
  }

  val_print(ACS_PRINT_INFO, " CXL IDE_KM caps 0x%x",
            (uint64_t)caps);
  val_print(ACS_PRINT_INFO, " CXL IDE_KM port index %u",
            (uint64_t)port_index);

  return ACS_STATUS_PASS;
#endif
#else
  (void)context;
  (void)session_id;
  (void)port_index;
  (void)response;
  (void)ide_reg_buffer;
  (void)ide_reg_count;

  val_print(ACS_PRINT_WARN, " SPDM: Feature disabled - skipping IDE_KM query", 0);
  return ACS_STATUS_SKIP;
#endif
}

uint32_t
val_spdm_get_random(size_t size, uint8_t *buffer)
{
#if ENABLE_SPDM
  if ((buffer == NULL) || (size == 0u))
    return ACS_STATUS_ERR;

  if (!libspdm_get_random_number(size, buffer)) {
    val_print(ACS_PRINT_ERR, " SPDM: RNG failure for %u bytes", (uint64_t)size);
    return ACS_STATUS_ERR;
  }

  return ACS_STATUS_PASS;
#else
  (void)size;
  (void)buffer;

  val_print(ACS_PRINT_WARN, " SPDM: Feature disabled - skipping RNG request", 0);
  return ACS_STATUS_SKIP;
#endif
}

uint32_t
val_spdm_send_cxl_ide_km_get_key(val_spdm_context_t *context,
                                 uint32_t session_id,
                                 uint8_t stream_id,
                                 uint8_t key_sub_stream,
                                 uint8_t port_index,
                                 cxl_ide_km_aes_256_gcm_key_buffer_t *key_buffer)
{
#if ENABLE_SPDM
#if !defined(LIBSPDM_ENABLE_VENDOR_DEFINED_MESSAGES) || \
    (LIBSPDM_ENABLE_VENDOR_DEFINED_MESSAGES == 0)
  (void)context;
  (void)session_id;
  (void)stream_id;
  (void)key_sub_stream;
  (void)port_index;
  (void)key_buffer;

  val_print(ACS_PRINT_WARN, " SPDM: Vendor-defined messaging disabled", 0);
  return ACS_STATUS_SKIP;
#else
  libspdm_return_t status;

  if ((context == NULL) || (context->spdm_context == NULL) || (key_buffer == NULL))
    return ACS_STATUS_ERR;

  status = cxl_ide_km_get_key(NULL,
                              context->spdm_context,
                              &session_id,
                              stream_id,
                              key_sub_stream,
                              port_index,
                              key_buffer);
  if (LIBSPDM_STATUS_IS_ERROR(status)) {
    val_print(ACS_PRINT_ERR, " SPDM: IDE_KM GET_KEY failed (0x%x)",
              (uint64_t)status);
    return ACS_STATUS_ERR;
  }

  return ACS_STATUS_PASS;
#endif
#else
  (void)context;
  (void)session_id;
  (void)stream_id;
  (void)key_sub_stream;
  (void)port_index;
  (void)key_buffer;

  val_print(ACS_PRINT_WARN, " SPDM: Feature disabled - skipping IDE_KM GET_KEY", 0);
  return ACS_STATUS_SKIP;
#endif
}

uint32_t
val_spdm_send_cxl_ide_km_key_prog(val_spdm_context_t *context,
                                  uint32_t session_id,
                                  uint8_t stream_id,
                                  uint8_t key_sub_stream,
                                  uint8_t port_index,
                                  const cxl_ide_km_aes_256_gcm_key_buffer_t *key_buffer,
                                  uint8_t *ack_status)
{
#if ENABLE_SPDM
#if !defined(LIBSPDM_ENABLE_VENDOR_DEFINED_MESSAGES) || \
    (LIBSPDM_ENABLE_VENDOR_DEFINED_MESSAGES == 0)
  (void)context;
  (void)session_id;
  (void)stream_id;
  (void)key_sub_stream;
  (void)port_index;
  (void)key_buffer;
  (void)ack_status;

  val_print(ACS_PRINT_WARN, " SPDM: Vendor-defined messaging disabled", 0);
  return ACS_STATUS_SKIP;
#else
  libspdm_return_t status;
  uint8_t local_ack = 0;
  uint8_t *ack_ptr = ack_status;

  if ((context == NULL) || (context->spdm_context == NULL) || (key_buffer == NULL))
    return ACS_STATUS_ERR;

  if (ack_ptr == NULL)
    ack_ptr = &local_ack;

  status = cxl_ide_km_key_prog(NULL,
                               context->spdm_context,
                               &session_id,
                               stream_id,
                               key_sub_stream,
                               port_index,
                               key_buffer,
                               ack_ptr);
  if (LIBSPDM_STATUS_IS_ERROR(status)) {
    val_print(ACS_PRINT_ERR, " SPDM: IDE_KM KEY_PROG failed (0x%x)",
              (uint64_t)status);
    return ACS_STATUS_ERR;
  }

  if (ack_status == NULL)
    val_print(ACS_PRINT_INFO, " CXL IDE_KM KEY_PROG ack 0x%x", (uint64_t)local_ack);

  return ACS_STATUS_PASS;
#endif
#else
  (void)context;
  (void)session_id;
  (void)stream_id;
  (void)key_sub_stream;
  (void)port_index;
  (void)key_buffer;
  (void)ack_status;

  val_print(ACS_PRINT_WARN, " SPDM: Feature disabled - skipping IDE_KM KEY_PROG", 0);
  return ACS_STATUS_SKIP;
#endif
}

uint32_t
val_spdm_send_cxl_ide_km_key_set_go(val_spdm_context_t *context,
                                    uint32_t session_id,
                                    uint8_t stream_id,
                                    uint8_t key_sub_stream,
                                    uint8_t port_index)
{
#if ENABLE_SPDM
#if !defined(LIBSPDM_ENABLE_VENDOR_DEFINED_MESSAGES) || \
    (LIBSPDM_ENABLE_VENDOR_DEFINED_MESSAGES == 0)
  (void)context;
  (void)session_id;
  (void)stream_id;
  (void)key_sub_stream;
  (void)port_index;

  val_print(ACS_PRINT_WARN, " SPDM: Vendor-defined messaging disabled", 0);
  return ACS_STATUS_SKIP;
#else
  libspdm_return_t status;

  if ((context == NULL) || (context->spdm_context == NULL))
    return ACS_STATUS_ERR;

  status = cxl_ide_km_key_set_go(NULL,
                                 context->spdm_context,
                                 &session_id,
                                 stream_id,
                                 key_sub_stream,
                                 port_index);
  if (LIBSPDM_STATUS_IS_ERROR(status)) {
    val_print(ACS_PRINT_ERR, " SPDM: IDE_KM KEY_SET_GO failed (0x%x)",
              (uint64_t)status);
    return ACS_STATUS_ERR;
  }

  return ACS_STATUS_PASS;
#endif
#else
  (void)context;
  (void)session_id;
  (void)stream_id;
  (void)key_sub_stream;
  (void)port_index;

  val_print(ACS_PRINT_WARN, " SPDM: Feature disabled - skipping IDE_KM KEY_SET_GO", 0);
  return ACS_STATUS_SKIP;
#endif
}

uint32_t
val_spdm_send_cxl_ide_km_key_set_stop(val_spdm_context_t *context,
                                      uint32_t session_id,
                                      uint8_t stream_id,
                                      uint8_t key_sub_stream,
                                      uint8_t port_index)
{
#if ENABLE_SPDM
#if !defined(LIBSPDM_ENABLE_VENDOR_DEFINED_MESSAGES) || \
    (LIBSPDM_ENABLE_VENDOR_DEFINED_MESSAGES == 0)
  (void)context;
  (void)session_id;
  (void)stream_id;
  (void)key_sub_stream;
  (void)port_index;

  val_print(ACS_PRINT_WARN, " SPDM: Vendor-defined messaging disabled", 0);
  return ACS_STATUS_SKIP;
#else
  libspdm_return_t status;

  if ((context == NULL) || (context->spdm_context == NULL))
    return ACS_STATUS_ERR;

  status = cxl_ide_km_key_set_stop(NULL,
                                   context->spdm_context,
                                   &session_id,
                                   stream_id,
                                   key_sub_stream,
                                   port_index);
  if (LIBSPDM_STATUS_IS_ERROR(status)) {
    val_print(ACS_PRINT_ERR, " SPDM: IDE_KM KEY_SET_STOP failed (0x%x)",
              (uint64_t)status);
    return ACS_STATUS_ERR;
  }

  return ACS_STATUS_PASS;
#endif
#else
  (void)context;
  (void)session_id;
  (void)stream_id;
  (void)key_sub_stream;
  (void)port_index;

  val_print(ACS_PRINT_WARN, " SPDM: Feature disabled - skipping IDE_KM KEY_SET_STOP", 0);
  return ACS_STATUS_SKIP;
#endif
}

/**
  @brief   Issue a CXL TSP GET_VERSION request on the active SPDM session.

  @param  context     Initialised VAL SPDM context owning the session.
  @param  session_id  Identifier of the established SPDM session.

  @retval ACS_STATUS_PASS Command completed without libspdm errors.
  @retval ACS_STATUS_SKIP Feature or vendor messaging flow disabled.
  @retval ACS_STATUS_ERR  Invalid parameters or transport failure.
**/
uint32_t
val_spdm_send_cxl_tsp_get_version(val_spdm_context_t *context,
                                  uint32_t session_id)
{
#if ENABLE_SPDM
#if !defined(LIBSPDM_ENABLE_VENDOR_DEFINED_MESSAGES) || \
    (LIBSPDM_ENABLE_VENDOR_DEFINED_MESSAGES == 0)
  (void)context;
  (void)session_id;

  val_print(ACS_PRINT_WARN, " SPDM: Vendor-defined messaging disabled", 0);
  return ACS_STATUS_SKIP;
#else
  libspdm_return_t status;

  if ((context == NULL) || (context->spdm_context == NULL))
    return ACS_STATUS_ERR;

  status = cxl_tsp_get_version(NULL,
                               context->spdm_context,
                              &session_id);
  if (LIBSPDM_STATUS_IS_ERROR(status)) {
    val_print(ACS_PRINT_ERR, " SPDM: TSP GET_VERSION failed (0x%x)",
              (uint64_t)status);
    return ACS_STATUS_ERR;
  }

  return ACS_STATUS_PASS;
#endif
#else
  (void)context;
  (void)session_id;

  val_print(ACS_PRINT_WARN, " SPDM: Feature disabled - skipping TSP GET_VERSION", 0);
  return ACS_STATUS_SKIP;
#endif
}

/**
  @brief   Query CXL TSP capabilities for the responder.

  @param  context       Initialised VAL SPDM context owning the session.
  @param  session_id    Identifier of the established SPDM session.
  @param  capabilities  Output structure to receive the responder capabilities.

  @retval ACS_STATUS_PASS Command completed without libspdm errors.
  @retval ACS_STATUS_SKIP Feature or vendor messaging flow disabled.
  @retval ACS_STATUS_ERR  Invalid parameters or transport failure.
**/
uint32_t
val_spdm_send_cxl_tsp_get_capabilities(val_spdm_context_t *context,
                                       uint32_t session_id,
                                       libcxltsp_device_capabilities_t *capabilities)
{
#if ENABLE_SPDM
#if !defined(LIBSPDM_ENABLE_VENDOR_DEFINED_MESSAGES) || \
    (LIBSPDM_ENABLE_VENDOR_DEFINED_MESSAGES == 0)
  (void)context;
  (void)session_id;
  (void)capabilities;

  val_print(ACS_PRINT_WARN, " SPDM: Vendor-defined messaging disabled", 0);
  return ACS_STATUS_SKIP;
#else
  libspdm_return_t status;

  if ((context == NULL) || (context->spdm_context == NULL) || (capabilities == NULL))
    return ACS_STATUS_ERR;

  status = cxl_tsp_get_capabilities(NULL,
                                    context->spdm_context,
                                    &session_id,
                                                 capabilities);
  if (LIBSPDM_STATUS_IS_ERROR(status)) {
    val_print(ACS_PRINT_ERR, " SPDM: TSP GET_CAPABILITIES failed (0x%x)",
              (uint64_t)status);
    return ACS_STATUS_ERR;
  }

  return ACS_STATUS_PASS;
#endif
#else
  (void)context;
  (void)session_id;
  (void)capabilities;

  val_print(ACS_PRINT_WARN, " SPDM: Feature disabled - skipping TSP GET_CAPABILITIES", 0);
  return ACS_STATUS_SKIP;
#endif
}

/**
  @brief   Program TSP configuration for the responder and optional secondary session.

  @param  context        Initialised VAL SPDM context owning the session.
  @param  session_id     Identifier of the established SPDM session.
  @param  configuration  Desired device configuration payload.
  @param  secondary_info Optional secondary session parameters, may be NULL.

  @retval ACS_STATUS_PASS Command completed without libspdm errors.
  @retval ACS_STATUS_SKIP Feature or vendor messaging flow disabled.
  @retval ACS_STATUS_ERR  Invalid parameters or transport failure.
**/
uint32_t
val_spdm_send_cxl_tsp_set_configuration(val_spdm_context_t *context,
                                        uint32_t session_id,
                                        const libcxltsp_device_configuration_t *configuration,
                                        const libcxltsp_device_2nd_session_info_t *secondary_info)
{
#if ENABLE_SPDM
#if !defined(LIBSPDM_ENABLE_VENDOR_DEFINED_MESSAGES) || \
    (LIBSPDM_ENABLE_VENDOR_DEFINED_MESSAGES == 0)
  (void)context;
  (void)session_id;
  (void)configuration;
  (void)secondary_info;

  val_print(ACS_PRINT_WARN, " SPDM: Vendor-defined messaging disabled", 0);
  return ACS_STATUS_SKIP;
#else
  libspdm_return_t status;

  if ((context == NULL) || (context->spdm_context == NULL) || (configuration == NULL))
    return ACS_STATUS_ERR;

  status = cxl_tsp_set_configuration(NULL,
                                     context->spdm_context,
                                     &session_id,
                                     configuration,
                                     secondary_info);
  if (LIBSPDM_STATUS_IS_ERROR(status)) {
    val_print(ACS_PRINT_ERR, " SPDM: TSP SET_CONFIGURATION failed (0x%x)",
              (uint64_t)status);
    return ACS_STATUS_ERR;
  }

  return ACS_STATUS_PASS;
#endif
#else
  (void)context;
  (void)session_id;
  (void)configuration;
  (void)secondary_info;

  val_print(ACS_PRINT_WARN, " SPDM: Feature disabled - skipping TSP SET_CONFIGURATION", 0);
  return ACS_STATUS_SKIP;
#endif
}

/**
  @brief   Fetch the current TSP configuration and state from the responder.

  @param  context        Initialised VAL SPDM context owning the session.
  @param  session_id     Identifier of the established SPDM session.
  @param  configuration  Optional pointer to receive configuration data, may be NULL.
  @param  tsp_state      Optional pointer to receive the TSP state, may be NULL.

  @retval ACS_STATUS_PASS Command completed without libspdm errors.
  @retval ACS_STATUS_SKIP Feature or vendor messaging flow disabled.
  @retval ACS_STATUS_ERR  Invalid parameters or transport failure.
**/
uint32_t
val_spdm_send_cxl_tsp_get_configuration(val_spdm_context_t *context,
                                        uint32_t session_id,
                                        libcxltsp_device_configuration_t *configuration,
                                        uint8_t *tsp_state)
{
#if ENABLE_SPDM
#if !defined(LIBSPDM_ENABLE_VENDOR_DEFINED_MESSAGES) || \
    (LIBSPDM_ENABLE_VENDOR_DEFINED_MESSAGES == 0)
  (void)context;
  (void)session_id;
  (void)configuration;
  (void)tsp_state;

  val_print(ACS_PRINT_WARN, " SPDM: Vendor-defined messaging disabled", 0);
  return ACS_STATUS_SKIP;
#else
  libspdm_return_t status;

  if ((context == NULL) || (context->spdm_context == NULL))
    return ACS_STATUS_ERR;

  status = cxl_tsp_get_configuration(NULL,
                                     context->spdm_context,
                                     &session_id,
                                     configuration,
                                     tsp_state);
  if (LIBSPDM_STATUS_IS_ERROR(status)) {
    val_print(ACS_PRINT_ERR, " SPDM: TSP GET_CONFIGURATION failed (0x%x)",
              (uint64_t)status);
    return ACS_STATUS_ERR;
  }

  return ACS_STATUS_PASS;
#endif
#else
  (void)context;
  (void)session_id;
  (void)configuration;
  (void)tsp_state;

  val_print(ACS_PRINT_WARN, " SPDM: Feature disabled - skipping TSP GET_CONFIGURATION", 0);
  return ACS_STATUS_SKIP;
#endif
}

/**
  @brief   Lock the responder TSP configuration to prevent further updates.

  @param  context     Initialised VAL SPDM context owning the session.
  @param  session_id  Identifier of the established SPDM session.

  @retval ACS_STATUS_PASS Command completed without libspdm errors.
  @retval ACS_STATUS_SKIP Feature or vendor messaging flow disabled.
  @retval ACS_STATUS_ERR  Invalid parameters or transport failure.
**/
uint32_t
val_spdm_send_cxl_tsp_lock_configuration(val_spdm_context_t *context,
                                         uint32_t session_id)
{
#if ENABLE_SPDM
#if !defined(LIBSPDM_ENABLE_VENDOR_DEFINED_MESSAGES) || \
    (LIBSPDM_ENABLE_VENDOR_DEFINED_MESSAGES == 0)
  (void)context;
  (void)session_id;

  val_print(ACS_PRINT_WARN, " SPDM: Vendor-defined messaging disabled", 0);
  return ACS_STATUS_SKIP;
#else
  libspdm_return_t status;

  if ((context == NULL) || (context->spdm_context == NULL))
    return ACS_STATUS_ERR;

  status = cxl_tsp_lock_configuration(NULL,
                                      context->spdm_context,
                                      &session_id);
  if (LIBSPDM_STATUS_IS_ERROR(status)) {
    val_print(ACS_PRINT_ERR, " SPDM: TSP LOCK_CONFIGURATION failed (0x%x)",
              (uint64_t)status);
    return ACS_STATUS_ERR;
  }

  return ACS_STATUS_PASS;
#endif
#else
  (void)context;
  (void)session_id;

  val_print(ACS_PRINT_WARN, " SPDM: Feature disabled - skipping TSP LOCK_CONFIGURATION", 0);
  return ACS_STATUS_SKIP;
#endif
}

/**
  @brief   Command the responder to transition the TSP trusted execution state.

  @param  context      Initialised VAL SPDM context owning the session.
  @param  session_id   Identifier of the established SPDM session.
  @param  te_state     Target trusted execution state value.
  @param  range_count  Number of memory ranges provided in `ranges`.
  @param  ranges       Optional array of memory range descriptors (NULL if count is 0).

  @retval ACS_STATUS_PASS Command completed without libspdm errors.
  @retval ACS_STATUS_SKIP Feature or vendor messaging flow disabled.
  @retval ACS_STATUS_ERR  Invalid parameters or transport failure.
**/
uint32_t
val_spdm_send_cxl_tsp_set_te_state(val_spdm_context_t *context,
                                   uint32_t session_id,
                                   uint8_t te_state,
                                   uint8_t range_count,
                                   const cxl_tsp_memory_range_t *ranges)
{
#if ENABLE_SPDM
#if !defined(LIBSPDM_ENABLE_VENDOR_DEFINED_MESSAGES) || \
    (LIBSPDM_ENABLE_VENDOR_DEFINED_MESSAGES == 0)
  (void)context;
  (void)session_id;
  (void)te_state;
  (void)range_count;
  (void)ranges;

  val_print(ACS_PRINT_WARN, " SPDM: Vendor-defined messaging disabled", 0);
  return ACS_STATUS_SKIP;
#else
  libspdm_return_t status;

  if ((context == NULL) || (context->spdm_context == NULL) ||
      ((range_count != 0u) && (ranges == NULL)))
    return ACS_STATUS_ERR;

  status = cxl_tsp_set_te_state(NULL,
                                context->spdm_context,
                                &session_id,
                                te_state,
                                range_count,
                                   ranges);
  if (LIBSPDM_STATUS_IS_ERROR(status)) {
    val_print(ACS_PRINT_ERR, " SPDM: TSP SET_TE_STATE failed (0x%x)",
              (uint64_t)status);
    return ACS_STATUS_ERR;
  }

  return ACS_STATUS_PASS;
#endif
#else
  (void)context;
  (void)session_id;
  (void)te_state;
  (void)range_count;
  (void)ranges;

  val_print(ACS_PRINT_WARN, " SPDM: Feature disabled - skipping TSP SET_TE_STATE", 0);
  return ACS_STATUS_SKIP;
#endif
}

/* -------------------------------------------------------------------------- */
/*                           PCIe TDISP helper APIs                           */
/* -------------------------------------------------------------------------- */
#if ENABLE_SPDM

/**
  @brief  Issue PCIe TDISP GET_VERSION over an SPDM session.

  @param  context       VAL SPDM context.
  @param  session_id    SPDM session identifier.
  @param  interface_id  TDISP interface identifier.

  @return ACS_STATUS_PASS/SKIP/ERR.
**/
uint32_t
val_spdm_send_pci_tdisp_get_version(val_spdm_context_t *context,
                                    uint32_t session_id,
                                    const pci_tdisp_interface_id_t *interface_id)
{
#if !defined(LIBSPDM_ENABLE_VENDOR_DEFINED_MESSAGES) || \
    (LIBSPDM_ENABLE_VENDOR_DEFINED_MESSAGES == 0)
  (void)context;
  (void)session_id;
  (void)interface_id;

  val_print(ACS_PRINT_WARN,
            " SPDM: Vendor-defined messaging disabled",
            0);
  return ACS_STATUS_SKIP;
#else
  libspdm_return_t status;

  if ((context == NULL) || (context->spdm_context == NULL) ||
      (interface_id == NULL))
    return ACS_STATUS_ERR;

  status = pci_tdisp_get_version(NULL,
                                 context->spdm_context,
                                 &session_id,
                                 interface_id);
  if (LIBSPDM_STATUS_IS_ERROR(status)) {
    val_print(ACS_PRINT_ERR, " TDISP GET_VERSION failed 0x%x", status);
    return ACS_STATUS_ERR;
  }

  val_print(ACS_PRINT_INFO, " TDISP GET_VERSION ok 0x%x", status);

  return ACS_STATUS_PASS;
#endif
}

uint32_t
val_spdm_send_pci_tdisp_get_capabilities(
                                    val_spdm_context_t *context,
                                    uint32_t session_id,
                                    const pci_tdisp_interface_id_t *interface_id,
                                    const pci_tdisp_requester_capabilities_t *req,
                                    pci_tdisp_responder_capabilities_t *rsp)
{
#if !defined(LIBSPDM_ENABLE_VENDOR_DEFINED_MESSAGES) || \
    (LIBSPDM_ENABLE_VENDOR_DEFINED_MESSAGES == 0)
  (void)context;
  (void)session_id;
  (void)interface_id;
  (void)req;
  (void)rsp;

  return ACS_STATUS_SKIP;
#else
  libspdm_return_t status;

  if ((context == NULL) || (context->spdm_context == NULL) ||
      (interface_id == NULL) || (req == NULL) || (rsp == NULL))
    return ACS_STATUS_ERR;

  status = pci_tdisp_get_capabilities(NULL,
                                      context->spdm_context,
                                      &session_id,
                                      interface_id,
                                      req,
                                      rsp);
  if (LIBSPDM_STATUS_IS_ERROR(status)) {
    val_print(ACS_PRINT_ERR, " TDISP GET_CAPS failed 0x%x", status);
    return ACS_STATUS_ERR;
  }

  val_print(ACS_PRINT_INFO, " TDISP GET_CAPS ok 0x%x", status);

  return ACS_STATUS_PASS;
#endif
}

uint32_t
val_spdm_send_pci_tdisp_get_interface_state(
                                    val_spdm_context_t *context,
                                    uint32_t session_id,
                                    const pci_tdisp_interface_id_t *interface_id,
                                    uint8_t *tdi_state)
{
#if !defined(LIBSPDM_ENABLE_VENDOR_DEFINED_MESSAGES) || \
    (LIBSPDM_ENABLE_VENDOR_DEFINED_MESSAGES == 0)
  (void)context;
  (void)session_id;
  (void)interface_id;
  (void)tdi_state;

  return ACS_STATUS_SKIP;
#else
  libspdm_return_t status;

  if ((context == NULL) || (context->spdm_context == NULL) ||
      (interface_id == NULL) || (tdi_state == NULL))
    return ACS_STATUS_ERR;

  status = pci_tdisp_get_interface_state(NULL,
                                         context->spdm_context,
                                         &session_id,
                                         interface_id,
                                         tdi_state);
  if (LIBSPDM_STATUS_IS_ERROR(status)) {
    val_print(ACS_PRINT_ERR, " TDISP GET_STATE failed 0x%x", status);
    return ACS_STATUS_ERR;
  }

  val_print(ACS_PRINT_INFO, " TDISP GET_STATE ok 0x%x", status);

  return ACS_STATUS_PASS;
#endif
}

uint32_t
val_spdm_send_pci_tdisp_get_interface_report(
                                    val_spdm_context_t *context,
                                    uint32_t session_id,
                                    const pci_tdisp_interface_id_t *interface_id,
                                    uint8_t *report,
                                    uint32_t *report_size)
{
#if !defined(LIBSPDM_ENABLE_VENDOR_DEFINED_MESSAGES) || \
    (LIBSPDM_ENABLE_VENDOR_DEFINED_MESSAGES == 0)
  (void)context;
  (void)session_id;
  (void)interface_id;
  (void)report;
  (void)report_size;

  return ACS_STATUS_SKIP;
#else
  libspdm_return_t status;

  if ((context == NULL) || (context->spdm_context == NULL) ||
      (interface_id == NULL) || (report == NULL) ||
      (report_size == NULL))
    return ACS_STATUS_ERR;

  uint32_t size = *report_size;

  status = pci_tdisp_get_interface_report(NULL,
                                          context->spdm_context,
                                          &session_id,
                                          interface_id,
                                          report,
                                          &size);
  if (LIBSPDM_STATUS_IS_ERROR(status)) {
    val_print(ACS_PRINT_ERR, " TDISP GET_RPT failed 0x%x", status);
    return ACS_STATUS_ERR;
  }

  val_print(ACS_PRINT_INFO, " TDISP GET_RPT ok 0x%x", status);

  *report_size = size;
  return ACS_STATUS_PASS;
#endif
}

uint32_t
val_spdm_send_pci_tdisp_lock_interface(
                                    val_spdm_context_t *context,
                                    uint32_t session_id,
                                    const pci_tdisp_interface_id_t *interface_id,
                                    const pci_tdisp_lock_interface_param_t *param,
                                    uint8_t *start_interface_nonce)
{
#if !defined(LIBSPDM_ENABLE_VENDOR_DEFINED_MESSAGES) || \
    (LIBSPDM_ENABLE_VENDOR_DEFINED_MESSAGES == 0)
  (void)context;
  (void)session_id;
  (void)interface_id;
  (void)param;
  (void)start_interface_nonce;

  return ACS_STATUS_SKIP;
#else
  libspdm_return_t status;

  if ((context == NULL) || (context->spdm_context == NULL) ||
      (interface_id == NULL) || (param == NULL))
    return ACS_STATUS_ERR;

  status = pci_tdisp_lock_interface(NULL,
                                    context->spdm_context,
                                    &session_id,
                                    interface_id,
                                    param,
                                    start_interface_nonce);
  if (LIBSPDM_STATUS_IS_ERROR(status)) {
    val_print(ACS_PRINT_ERR, " TDISP LOCK_IF failed 0x%x", status);
    return ACS_STATUS_ERR;
  }

  val_print(ACS_PRINT_INFO, " TDISP LOCK_IF ok 0x%x", status);

  return ACS_STATUS_PASS;
#endif
}

uint32_t
val_spdm_send_pci_tdisp_start_interface(
                                    val_spdm_context_t *context,
                                    uint32_t session_id,
                                    const pci_tdisp_interface_id_t *interface_id,
                                    const uint8_t *start_interface_nonce)
{
#if !defined(LIBSPDM_ENABLE_VENDOR_DEFINED_MESSAGES) || \
    (LIBSPDM_ENABLE_VENDOR_DEFINED_MESSAGES == 0)
  (void)context;
  (void)session_id;
  (void)interface_id;
  (void)start_interface_nonce;

  return ACS_STATUS_SKIP;
#else
  libspdm_return_t status;

  if ((context == NULL) || (context->spdm_context == NULL) ||
      (interface_id == NULL) || (start_interface_nonce == NULL))
    return ACS_STATUS_ERR;

  status = pci_tdisp_start_interface(NULL,
                                     context->spdm_context,
                                     &session_id,
                                     interface_id,
                                     start_interface_nonce);
  if (LIBSPDM_STATUS_IS_ERROR(status)) {
    val_print(ACS_PRINT_ERR, " TDISP START_IF failed 0x%x", status);
    return ACS_STATUS_ERR;
  }

  val_print(ACS_PRINT_INFO, " TDISP START_IF ok 0x%x", status);

  return ACS_STATUS_PASS;
#endif
}

uint32_t
val_spdm_send_pci_tdisp_stop_interface(
                                    val_spdm_context_t *context,
                                    uint32_t session_id,
                                    const pci_tdisp_interface_id_t *interface_id)
{
#if !defined(LIBSPDM_ENABLE_VENDOR_DEFINED_MESSAGES) || \
    (LIBSPDM_ENABLE_VENDOR_DEFINED_MESSAGES == 0)
  (void)context;
  (void)session_id;
  (void)interface_id;

  return ACS_STATUS_SKIP;
#else
  libspdm_return_t status;

  if ((context == NULL) || (context->spdm_context == NULL) ||
      (interface_id == NULL))
    return ACS_STATUS_ERR;

  status = pci_tdisp_stop_interface(NULL,
                                    context->spdm_context,
                                    &session_id,
                                    interface_id);
  if (LIBSPDM_STATUS_IS_ERROR(status)) {
    val_print(ACS_PRINT_ERR, " TDISP STOP_IF failed 0x%x", status);
    return ACS_STATUS_ERR;
  }

  val_print(ACS_PRINT_INFO, " TDISP STOP_IF ok 0x%x", status);

  return ACS_STATUS_PASS;
#endif
}

#endif /* ENABLE_SPDM */
