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

#ifndef LIBSPDM_MBEDTLS_MIN_CONFIG_H
#define LIBSPDM_MBEDTLS_MIN_CONFIG_H

#include <stddef.h>

/* Platform glue --------------------------------------------------------- */
#define MBEDTLS_PLATFORM_C
#define MBEDTLS_PLATFORM_MEMORY
#define MBEDTLS_NO_PLATFORM_ENTROPY

#ifdef MBEDTLS_PLATFORM_CALLOC_MACRO
#undef MBEDTLS_PLATFORM_CALLOC_MACRO
#endif
#define MBEDTLS_PLATFORM_CALLOC_MACRO    pal_mbedtls_calloc

#ifdef MBEDTLS_PLATFORM_FREE_MACRO
#undef MBEDTLS_PLATFORM_FREE_MACRO
#endif
#define MBEDTLS_PLATFORM_FREE_MACRO      pal_mem_free

extern void *pal_mbedtls_calloc(size_t count, size_t size);
extern void pal_mem_free(void *ptr);

#define MBEDTLS_NO_UDBL_DIVISION

/* Core crypto primitives ------------------------------------------------ */
#define MBEDTLS_BIGNUM_C
#define MBEDTLS_OID_C
#define MBEDTLS_ASN1_PARSE_C
#define MBEDTLS_ASN1_WRITE_C

#define MBEDTLS_MD_C
#define MBEDTLS_SHA256_C
#define MBEDTLS_SHA384_C
#define MBEDTLS_SHA512_C
#define MBEDTLS_SHA3_C
#define MBEDTLS_HKDF_C

#define MBEDTLS_CIPHER_C
#define MBEDTLS_AES_C
#define MBEDTLS_CCM_GCM_CAN_AES
#define MBEDTLS_GCM_C
#define MBEDTLS_CHACHAPOLY_C
#define MBEDTLS_CHACHA20_C
#define MBEDTLS_POLY1305_C

/* Public-key and X.509 stack ------------------------------------------- */
#define MBEDTLS_PK_C
#define MBEDTLS_PK_PARSE_C
#define MBEDTLS_RSA_C
#define MBEDTLS_PKCS1_V15
#define MBEDTLS_PKCS1_V21
#define MBEDTLS_ECP_C
#define MBEDTLS_ECDH_C
#define MBEDTLS_DHM_C
#define MBEDTLS_ECP_RESTARTABLE
#define MBEDTLS_ECDSA_C
#define MBEDTLS_ECP_DP_SECP256R1_ENABLED
#define MBEDTLS_ECP_DP_SECP384R1_ENABLED

#define MBEDTLS_GENPRIME

#define MBEDTLS_X509_USE_C
#define MBEDTLS_X509_CRT_PARSE_C
#define MBEDTLS_X509_CREATE_C
#define MBEDTLS_X509_CSR_PARSE_C
#define MBEDTLS_X509_CSR_WRITE_C
#define MBEDTLS_BASE64_C
#define MBEDTLS_PEM_PARSE_C
#define MBEDTLS_PK_WRITE_C

/* Bare-metal environment exclusions ------------------------------------ */
#ifdef MBEDTLS_HAVE_TIME
#undef MBEDTLS_HAVE_TIME
#endif
#ifdef MBEDTLS_HAVE_TIME_DATE
#undef MBEDTLS_HAVE_TIME_DATE
#endif
#ifdef MBEDTLS_PLATFORM_TIME_MACRO
#undef MBEDTLS_PLATFORM_TIME_MACRO
#endif
#ifdef MBEDTLS_PLATFORM_TIME_TYPE_MACRO
#undef MBEDTLS_PLATFORM_TIME_TYPE_MACRO
#endif
#ifdef MBEDTLS_PLATFORM_STD_TIME
#undef MBEDTLS_PLATFORM_STD_TIME
#endif
#ifdef MBEDTLS_PLATFORM_STD_TIME_TYPE
#undef MBEDTLS_PLATFORM_STD_TIME_TYPE
#endif
#ifdef MBEDTLS_FS_IO
#undef MBEDTLS_FS_IO
#endif
#ifdef MBEDTLS_PSA_ITS_FILE_C
#undef MBEDTLS_PSA_ITS_FILE_C
#endif
#ifdef MBEDTLS_PSA_CRYPTO_STORAGE_C
#undef MBEDTLS_PSA_CRYPTO_STORAGE_C
#endif

#endif /* LIBSPDM_MBEDTLS_MIN_CONFIG_H */
