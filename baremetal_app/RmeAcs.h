/** @file
 * Copyright (c) 2022-2026, Arm Limited or its affiliates. All rights reserved.
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

#ifndef __RME_ACS_LEVEL_H__
#define __RME_ACS_LEVEL_H__

#include "pal_image_def.h"
#include "pal_override_fvp.h"

#define SIZE_4K 0x1000

#define RME_ACS_MAJOR_VER  1
#define RME_ACS_MINOR_VER  0

#define RME_MIN_LEVEL_SUPPORTED 3
#define RME_MAX_LEVEL_SUPPORTED 6

#define INVALID_MPIDR       0xffffffff
#define STACK_SIZE          0x1000

#define PAGE_SIZE_4K        0x1000
#define PAGE_SIZE_16K       (4 * 0x1000)
#define PAGE_SIZE_64K       (16 * 0x1000)

#define PLATFORM_CPU_COUNT PLATFORM_OVERRIDE_PE_CNT

#if (PLATFORM_PAGE_SIZE == PAGE_SIZE_4K)
 #define PAGE_SIZE           PAGE_SIZE_4K
#elif (PLATFORM_PAGE_SIZE == PAGE_SIZE_16K)
 #define PAGE_SIZE           PAGE_SIZE_16K
#elif (PLATFORM_PAGE_SIZE == PAGE_SIZE_64K)
 #define PAGE_SIZE           PAGE_SIZE_64K
#endif

/*******************************************************************************
 * Used to align variables on the biggest cache line size in the platform.
 * This is known only to the platform as it might have a combination of
 * integrated and external caches.
 ******************************************************************************/
#define CACHE_WRITEBACK_SHIFT     6
#define CACHE_WRITEBACK_GRANULE   (1 << CACHE_WRITEBACK_SHIFT)

#ifdef _AARCH64_BUILD_
  unsigned long __stack_chk_guard = 0xBAAAAAAD;
  unsigned long __stack_chk_fail =  0xBAAFAAAD;
#endif

#define SCTLR_I_BIT         (1 << 12)
#define SCTLR_M_BIT         (1 << 0)
#define DISABLE_MMU_BIT     (0xFFFFFFFFFFFFFFFE)


/*
 * MMU configuration
 *
 * 1 = do val_setup_mmu/val_enable_mmu
 * 0 = skip MMU setup/enable
 *
 * Can be overridden from the build system, e.g.:
 *   -DACS_ENABLE_MMU=0
 */
#ifndef ACS_ENABLE_MMU
#define ACS_ENABLE_MMU   1
#endif

/*
 * Optional compile-time default enabled module list.
 *
 * If the build system defines, for example:
 *
 *   -DACS_ENABLED_MODULE_LIST=TIMER,PCIE
 *
 * then ACS will treat that as a static uint32_t[] containing the module
 * base IDs that are **enabled to run by default**.
 *
 * Semantics:
 *   - All modules are still compiled into the binary.
 *   - This list only controls which modules are enabled for execution.
 *   - If a runtime override is provided (g_module_array / EL3 params),
 *     it takes priority over this list.
 *
 * If ACS_ENABLED_MODULE_LIST is not defined, ACS falls back to:
 *   - runtime overrides (if present), otherwise
 *   - "all modules enabled" behaviour.
 */
#ifdef ACS_ENABLED_MODULE_LIST
#define ACS_HAS_ENABLED_MODULE_LIST  1
#else
#define ACS_HAS_ENABLED_MODULE_LIST  0
#endif

/*
 * EL3 convention:
 *   X19 = ACS_EL3_PARAM_MAGIC
 *   X20 = address of acs_el3_params in shared/shared-visible memory
 *
 * If X19 != ACS_EL3_PARAM_MAGIC, ACS ignores X20 and behaves as usual.
 */

/* Example magic: "ACSEL3P1" in ASCII */
#define ACS_EL3_PARAM_MAGIC   0x414353454C335031ULL  /* 'ACSEL3P1' */
#define ACS_EL3_PARAM_VERSION 0x3
#endif
