/** @file
 * Copyright (c) 2026, Arm Limited or its affiliates. All rights reserved.
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
#ifndef ACS_LIBSPDM_CONFIG_H
#define ACS_LIBSPDM_CONFIG_H

#define LIBSPDM_DEBUG_ENABLE                      1
#define LIBSPDM_PRINT_ENABLE                      1
#define LIBSPDM_DEBUG_PRINT_ENABLE                1
#define LIBSPDM_MAX_VERSION_COUNT                 8
#define LIBSPDM_MAX_ROOT_CERT_SUPPORT             4
#define LIBSPDM_MAX_SESSION_COUNT                 1
#define LIBSPDM_MAX_CERT_CHAIN_SIZE               0x2000
#define LIBSPDM_MAX_MEASUREMENT_RECORD_SIZE       0x400
#define LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN          256
#define LIBSPDM_MAX_ENDPOINT_INFO_LENGTH          256
#define LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT    1
#define LIBSPDM_CERT_PARSE_SUPPORT                1

#define LIBSPDM_RSA_SSA_2048_SUPPORT              1
#define LIBSPDM_RSA_SSA_3072_SUPPORT              1
#define LIBSPDM_RSA_SSA_4096_SUPPORT              0
#define LIBSPDM_RSA_PSS_2048_SUPPORT              0
#define LIBSPDM_RSA_PSS_3072_SUPPORT              0
#define LIBSPDM_RSA_PSS_4096_SUPPORT              0
#define LIBSPDM_ECDSA_P256_SUPPORT                1
#define LIBSPDM_ECDSA_P384_SUPPORT                1
#define LIBSPDM_ECDSA_P521_SUPPORT                0
#define LIBSPDM_SM2_DSA_P256_SUPPORT              0
#define LIBSPDM_EDDSA_ED25519_SUPPORT             0
#define LIBSPDM_EDDSA_ED448_SUPPORT               0
#define LIBSPDM_FFDHE_2048_SUPPORT                1
#define LIBSPDM_FFDHE_3072_SUPPORT                0
#define LIBSPDM_FFDHE_4096_SUPPORT                0
#define LIBSPDM_ECDHE_P256_SUPPORT                1
#define LIBSPDM_ECDHE_P384_SUPPORT                1
#define LIBSPDM_ECDHE_P521_SUPPORT                0
#define LIBSPDM_SM2_KEY_EXCHANGE_P256_SUPPORT     0
#define LIBSPDM_AEAD_AES_128_GCM_SUPPORT          1
#define LIBSPDM_AEAD_AES_256_GCM_SUPPORT          1
#define LIBSPDM_AEAD_CHACHA20_POLY1305_SUPPORT    0
#define LIBSPDM_AEAD_SM4_128_GCM_SUPPORT          0
#define LIBSPDM_SHA256_SUPPORT                    1
#define LIBSPDM_SHA384_SUPPORT                    1
#define LIBSPDM_SHA512_SUPPORT                    0
#define LIBSPDM_SHA3_256_SUPPORT                  0
#define LIBSPDM_SM3_256_SUPPORT                   0

#define LIBSPDM_ENABLE_CAPABILITY_CERT_CAP        1
#define LIBSPDM_ENABLE_CAPABILITY_MEAS_CAP        1
#define LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP      1
#define LIBSPDM_ENABLE_CAPABILITY_CHUNK_CAP       0
#define LIBSPDM_ENABLE_CAPABILITY_CHAL_CAP        1
#define LIBSPDM_ENABLE_CAPABILITY_PSK_CAP         0
#define LIBSPDM_ENABLE_CAPABILITY_HBEAT_CAP       0
#define LIBSPDM_ENABLE_CAPABILITY_MUT_AUTH_CAP    0
#define LIBSPDM_ENABLE_CAPABILITY_ENCAP_CAP       0
#define LIBSPDM_ENABLE_CAPABILITY_CSR_CAP         0
#define LIBSPDM_ENABLE_CAPABILITY_SET_CERT_CAP    0
#define LIBSPDM_ENABLE_CAPABILITY_EVENT_CAP       0
#define LIBSPDM_EVENT_RECIPIENT_SUPPORT           0
#define LIBSPDM_ENABLE_VENDOR_DEFINED_MESSAGES    1
#define LIBSPDM_SEND_GET_CERTIFICATE_SUPPORT      1
#define LIBSPDM_RESPOND_IF_READY_SUPPORT          0

#define LIBSPDM_ENABLE_MSG_LOG                    1
#define LIBSPDM_CHECK_MACRO                       1
#define LIBSPDM_CHECK_SPDM_CONTEXT                1
#define LIBSPDM_HAL_PASS_SPDM_CONTEXT             0

#endif /* ACS_LIBSPDM_CONFIG_H */
