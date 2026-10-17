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

#ifndef PAL_EL3_CXL_IDE_H
#define PAL_EL3_CXL_IDE_H

/* The including environment supplies the fixed-width integer types. */
#define CXL_IDE_SUCCESS 0u
#define CXL_IDE_ERROR   1u
#define CXL_IDE_UNSUPPORTED 2u

#define CXL_IDE_MODE_SKID        0u
#define CXL_IDE_MODE_CONTAINMENT 1u

/* CXL.cachemem uses a paired RX/TX key bank, relative to the Root Port. */
typedef struct {
  uint8_t stream_id;
  uint8_t key_slot;
} CXL_IDE_SELECTOR;

typedef struct {
  uint32_t key[8];
  uint32_t iv[3];
} CXL_IDE_KEY_BUFFER;

/* Root-only register pages. Discovery must not access unmapped MMIO. */
typedef struct {
  uint64_t aes;
  uint64_t cm_host;
} CXL_IDE_RP_REGISTERS;

#endif /* PAL_EL3_CXL_IDE_H */
