#/** @file
# Copyright (c) 2022-2023, 2025, Arm Limited or its affiliates. All rights reserved.
# SPDX-License-Identifier : Apache-2.0
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
#**/

/* Private worker functions for ASM_PFX() */
#define _CONCATENATE(a, b)  __CONCATENATE(a, b)
#define __CONCATENATE(a, b) a ## b
#include "include/val_mem_interface.h"
#include "include/val_std_smc.h"

/* The __USER_LABEL_PREFIX__ macro predefined by GNUC represents
   the prefix on symbols in assembly language.*/
#define __USER_LABEL_PREFIX__

#define ASM_PFX(name) _CONCATENATE (__USER_LABEL_PREFIX__, name)

#define GCC_ASM_EXPORT(func__)  \
       .global  _CONCATENATE (__USER_LABEL_PREFIX__, func__)    ;\
       .type ASM_PFX(func__), %function

#define GCC_ASM_IMPORT(func__)  \
       .extern  _CONCATENATE (__USER_LABEL_PREFIX__, func__)

.text
.align 3

GCC_ASM_EXPORT (ArmCallWFI)
GCC_ASM_EXPORT (ArmExecuteMemoryBarrier)
GCC_ASM_EXPORT (UserCallSMC)
GCC_ASM_EXPORT (set_daif)
GCC_ASM_EXPORT (write_gpr_and_reset)
GCC_ASM_EXPORT (check_gpr_after_reset)

ASM_PFX(write_gpr_and_reset):
  ldr x0, =GPR_WRITE_VAL
  mov x19, x0
  mov x20, x0
  mov x21, x0
  mov x22, x0
  mov x23, x0
  mov x24, x0
  mov x25, x0
  mov x26, x0
  mov x27, x0
  mov x28, x0
  mov x29, x0
  isb
  //Execute reset
  ldr x0, =ARM_SMC_ID_PSCI_SYSTEM_RESET
  smc #0
  ret

ASM_PFX(check_gpr_after_reset):
  ldr x0, =GPR_WRITE_VAL
  cmp x19, x0
  beq  ASM_PFX(check_fail)
  cmp x20, x0
  beq  ASM_PFX(check_fail)
  cmp x21, x0
  beq  ASM_PFX(check_fail)
  cmp x22, x0
  beq  ASM_PFX(check_fail)
  cmp x23, x0
  beq  ASM_PFX(check_fail)
  cmp x24, x0
  beq  ASM_PFX(check_fail)
  cmp x25, x0
  beq  ASM_PFX(check_fail)
  cmp x26, x0
  beq  ASM_PFX(check_fail)
  cmp x27, x0
  beq  ASM_PFX(check_fail)
  cmp x28, x0
  beq  ASM_PFX(check_fail)
  cmp x29, x0
  beq  ASM_PFX(check_fail)
ASM_PFX(check_pass):
  mov x0, #0x0
  ret
ASM_PFX(check_fail):
  mov x0, #0x1
  ret

ASM_PFX(set_daif):
  mov x0,#0x3c0
  msr DAIF,x0
  isb
  ret

ASM_PFX(UserCallSMC):
  stp x29, x30, [sp, #-0x10]!
  smc #0
  ldp x29,x30, [sp] ,#0x10
  ret

ASM_PFX(ArmCallWFI):
  wfi
  ret

ASM_PFX(ArmExecuteMemoryBarrier):
  dmb sy
  ret
