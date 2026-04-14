## @file
# Copyright (c) 2025-2026, Arm Limited or its affiliates. All rights reserved.
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
 "${VAL_DIR}/src/val_status.c"
 "${VAL_DIR}/src/val_pe.c"
 "${VAL_DIR}/src/val_da.c"
 "${VAL_DIR}/src/val_dpt.c"
 "${VAL_DIR}/src/val_mec.c"
 "${VAL_DIR}/src/val_test_entry_rme.c"
 "${VAL_DIR}/src/val_pe_infra.c"
 "${VAL_DIR}/src/val_gic.c"
 "${VAL_DIR}/src/val_gic_support.c"
 "${VAL_DIR}/src/val_cxl.c"
 "${VAL_DIR}/src/val_cda.c"
 "${VAL_DIR}/src/val_pcie.c"
 "${VAL_DIR}/src/val_cxl.c"
 "${VAL_DIR}/src/val_spdm.c"
 "${VAL_DIR}/src/val_tdisp.c"
 "${VAL_DIR}/src/val_iovirt.c"
 "${VAL_DIR}/src/val_smmu.c"
 "${VAL_DIR}/src/val_test_infra.c"
 "${VAL_DIR}/src/val_timer.c"
 "${VAL_DIR}/src/val_timer_support.c"
 "${VAL_DIR}/src/val_wd.c"
 "${VAL_DIR}/src/val_wakeup.c"
 "${VAL_DIR}/src/val_peripherals.c"
 "${VAL_DIR}/src/val_memory.c"
 "${VAL_DIR}/src/val_exerciser.c"
 "${VAL_DIR}/src/val_pgt.c"
 "${VAL_DIR}/src/val_el3.c"
 "${VAL_DIR}/src/val_legacy.c"
 "${VAL_DIR}/src/sys_config.c"
 "${VAL_DIR}/sys_arch_src/smmu_v3/val_smmu_v3.c"
 "${VAL_DIR}/sys_arch_src/gic/val_sys_arch_gic.c"
 "${VAL_DIR}/sys_arch_src/gic/val_exception.c"
 "${VAL_DIR}/sys_arch_src/gic/AArch64/rme_exception_asm.S"
 "${VAL_DIR}/sys_arch_src/gic/v3/val_gic_v3.c"
 "${VAL_DIR}/sys_arch_src/gic/v3/val_gic_v3_extended.c"
 "${VAL_DIR}/sys_arch_src/gic/v3/AArch64/v3_asm.S"
 "${VAL_DIR}/sys_arch_src/gic/v2/val_gic_v2.c"
 "${VAL_DIR}/sys_arch_src/gic/its/val_gic_its.c"
"${VAL_DIR}/sys_arch_src/gic/its/val_gic_redistributor.c"
"${ROOT_DIR}/baremetal_app/RmeAcsMain.c"
"${ROOT_DIR}/baremetal_app/RmeAcsCommon.c"

)

#Create compile list files
list(APPEND COMPILE_LIST ${VAL_SRC})
set(COMPILE_LIST ${COMPILE_LIST} PARENT_SCOPE)

# Create VAL library
add_library(${VAL_LIB} STATIC ${VAL_SRC})

set(_val_private_includes
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
  ${ROOT_DIR}/tools/configs/
)

if(ENABLE_SPDM)
  list(APPEND _val_private_includes
    ${LIBSPDM_INCLUDE_DIR}
    ${LIBSPDM_OS_STUB_INCLUDE_DIR}
    ${SPDM_EMU_INCLUDE_DIR}
  )
endif()

target_include_directories(${VAL_LIB} PRIVATE ${_val_private_includes})
# Compose definitions so sources can detect whether SPDM support is present.
target_compile_definitions(${VAL_LIB} PRIVATE ENABLE_SPDM=$<IF:$<BOOL:${ENABLE_SPDM}>,1,0>)

# Propagate ACS print verbosity to VAL sources (used by bare-metal app).
target_compile_definitions(${VAL_LIB} PRIVATE "ACS_PRINT_LEVEL=${ACS_PRINT_LEVEL}")

if(ENABLE_SPDM)
  target_compile_definitions(${VAL_LIB} PRIVATE ${_libspdm_config_define})
endif()

unset(VAL_SRC)

if(ENABLE_SPDM)
  target_link_libraries(${VAL_LIB} PRIVATE
    spdm_requester_lib
    spdm_common_lib
    spdm_transport_pcidoe_lib
    spdm_secured_message_lib
    spdm_crypt_lib
    spdm_crypt_ext_lib
    cxl_ide_km_requester_lib
    pci_doe_requester_lib
    cxl_tsp_requester_lib
    pci_tdisp_requester_lib
    spdm_device_secret_lib_null
    memlib
    rnglib
    malloclib
    platform_lib_null
    debuglib
  )

  target_link_libraries(${VAL_LIB} PRIVATE
    cryptlib_mbedtls
    mbedcrypto
    mbedx509
    mbedtls)
endif()
