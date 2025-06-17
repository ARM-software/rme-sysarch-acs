## @file
 # Copyright (c) 2025, Arm Limited or its affiliates. All rights reserved.
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
 ##

 file(GLOB VAL_SRC
 "${VAL_DIR}/src/AArch64/PeRegSysSupport.S"
 "${VAL_DIR}/src/AArch64/PeTestSupport.S"
 "${VAL_DIR}/src/AArch64/ArchTimerSupport.S"
 "${VAL_DIR}/src/AArch64/GicSupport.S"
 "${VAL_DIR}/src/AArch64/RmeBootEntry.S"
 "${VAL_DIR}/src/AArch64/SystemReg.S"
 "${VAL_DIR}/src/AArch64/VecTable.S"
 "${VAL_DIR}/src/acs_status.c"
 "${VAL_DIR}/src/acs_pe.c"
 "${VAL_DIR}/src/acs_da.c"
 "${VAL_DIR}/src/acs_dpt.c"
 "${VAL_DIR}/src/acs_mec.c"
 "${VAL_DIR}/src/test_entry_rme.c"
 "${VAL_DIR}/src/acs_pe_infra.c"
 "${VAL_DIR}/src/acs_gic.c"
 "${VAL_DIR}/src/acs_gic_support.c"
 "${VAL_DIR}/src/acs_pcie.c"
 "${VAL_DIR}/src/acs_iovirt.c"
 "${VAL_DIR}/src/acs_smmu.c"
 "${VAL_DIR}/src/acs_test_infra.c"
 "${VAL_DIR}/src/acs_timer.c"
 "${VAL_DIR}/src/acs_timer_support.c"
 "${VAL_DIR}/src/acs_wd.c"
 "${VAL_DIR}/src/acs_wakeup.c"
 "${VAL_DIR}/src/acs_peripherals.c"
 "${VAL_DIR}/src/acs_memory.c"
 "${VAL_DIR}/src/acs_exerciser.c"
 "${VAL_DIR}/src/acs_pgt.c"
 "${VAL_DIR}/src/acs_el3.c"
 "${VAL_DIR}/src/acs_legacy.c"
 "${VAL_DIR}/src/sys_config.c"
 "${VAL_DIR}/sys_arch_src/smmu_v3/smmu_v3.c"
 "${VAL_DIR}/sys_arch_src/gic/gic.c"
 "${VAL_DIR}/sys_arch_src/gic/rme_exception.c"
 "${VAL_DIR}/sys_arch_src/gic/AArch64/rme_exception_asm.S"
 "${VAL_DIR}/sys_arch_src/gic/v3/gic_v3.c"
 "${VAL_DIR}/sys_arch_src/gic/v3/gic_v3_extended.c"
 "${VAL_DIR}/sys_arch_src/gic/v3/AArch64/v3_asm.S"
 "${VAL_DIR}/sys_arch_src/gic/v2/gic_v2.c"
 "${VAL_DIR}/sys_arch_src/gic/its/rme_gic_its.c"
 "${VAL_DIR}/sys_arch_src/gic/its/rme_gic_redistributor.c"
 "${ROOT_DIR}/baremetal_app/RmeAcsMain.c"

)

#Create compile list files
list(APPEND COMPILE_LIST ${VAL_SRC})
set(COMPILE_LIST ${COMPILE_LIST} PARENT_SCOPE)

# Create VAL library
add_library(${VAL_LIB} STATIC ${VAL_SRC})

target_include_directories(${VAL_LIB} PRIVATE
 ${CMAKE_CURRENT_BINARY_DIR}
 ${ROOT_DIR}
 ${VAL_DIR}
 ${PAL_DIR}
 ${VAL_DIR}/include/
 ${VAL_DIR}/sys_arch_src/gic/
 ${VAL_DIR}/sys_arch_src/gic/its/
 ${VAL_DIR}/sys_arch_src/gic/v2/
 ${VAL_DIR}/sys_arch_src/gic/v3/
 ${VAL_DIR}/sys_arch_src/smmu_v3/
 ${ROOT_DIR}/baremetal_app/
 ${ROOT_DIR}/val_el3/
 ${PAL_DIR}/include/
 ${PAL_DIR}/${TARGET}/include/
 ${PAL_DIR}/src/AArch64/
)

unset(VAL_SRC)
