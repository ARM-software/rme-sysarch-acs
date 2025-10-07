/** @file
 * Copyright (c) 2025, Arm Limited or its affiliates. All rights reserved.
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

#ifndef VAL_EL3_HELPERS_H
#define VAL_EL3_HELPERS_H

#ifndef __ASSEMBLER__
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#endif

/* Shared constants used by both C and ASM */
/* Integer literal suffix helpers (mirrors TF-A style) */
#if defined(__ASSEMBLER__)
# define   U(_x)        (_x)
# define  UL(_x)        (_x)
# define ULL(_x)        (_x)
# define   L(_x)        (_x)
# define  LL(_x)        (_x)
#else
# define  U_(_x)        (_x##U)
# define   U(_x)        U_(_x)
# define  UL(_x)        (_x##UL)
# define ULL(_x)        (_x##ULL)
# define   L(_x)        (_x##L)
# define  LL(_x)        (_x##LL)
#endif
#include "val_el32.h"

#ifndef SIZE_4KB
#define SIZE_4KB        (4*1024)
#endif

/* Generic helpers */
#define VAL_EXTRACT_BITS(data, start, end) ((data >> start) & ((1ul << (end-start+1))-1))
#define get_max(a, b)   (((a) > (b))?(a):(b))
#define BITFIELD_DECL(type, name, msb, lsb) \
    const uint32_t name##_SHIFT = lsb; \
    const type name##_MASK = ((((type)0x1) << (msb - lsb + 1)) - 1);

#define BITFIELD_GET(name, val) ((val >> name##_SHIFT) & name##_MASK)
#define BITFIELD_SET(name, val) ((val & name##_MASK) << name##_SHIFT)
#define INPLACE(regfield, val) \
        (((val) + UL(0)) << (regfield##_SHIFT))

#endif /* VAL_EL3_HELPERS_H */
