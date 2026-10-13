## @file
# Copyright (c) 2026, Arm Limited or its affiliates. All rights reserved.
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

# No SPDM instrumentation requested; skip wiring libspdm entirely.
if(NOT ENABLE_SPDM)
  return()
endif()

# Guard against multiple inclusion when the caller builds more than once.
if(TARGET spdm_requester_lib)
  return()
endif()

# Locate the vendored libspdm tree relative to the ACS root.
set(LIBSPDM_DIR "${ROOT_DIR}/ext/libspdm")
if(NOT EXISTS "${LIBSPDM_DIR}/CMakeLists.txt")
  message(FATAL_ERROR "[ACS] : libspdm submodule is missing. Please clone ext/libspdm before building.")
endif()

# Cache the libspdm root and public include directories for later consumers.
set(LIBSPDM_ROOT "${LIBSPDM_DIR}" CACHE INTERNAL "Path to vendored libspdm root" FORCE)
set(LIBSPDM_INCLUDE_DIR "${LIBSPDM_DIR}/include" CACHE INTERNAL "libspdm public headers" FORCE)
set(LIBSPDM_OS_STUB_INCLUDE_DIR "${LIBSPDM_DIR}/os_stub" CACHE INTERNAL "libspdm os_stub headers" FORCE)

# Stage libspdm build outputs under the ACS build directory and point to ACS configs.
set(LIBSPDM_BIN_DIR "${BUILD}/libspdm")
set(_libspdm_config_define "LIBSPDM_CONFIG=<acs_libspdm_config.h>")
set(_libspdm_config_dir "${ROOT_DIR}/tools/configs")
set(_mbedtls_config "${_libspdm_config_dir}/acs_libspdm_mbedtls_config.h")

# Control libspdm debug verbosity from the single ACS_PRINT_LEVEL knob:
# - ACS_PRINT_LEVEL <= 2 (DEBUG/INFO requested): enable INFO + ERROR.
# - ACS_PRINT_LEVEL >= 3 (TEST/WARN/ERR default): enable ERROR only.
if(DEFINED ACS_PRINT_LEVEL)
  if(ACS_PRINT_LEVEL LESS_EQUAL 2)
    set(_libspdm_debug_level "(LIBSPDM_DEBUG_INFO|LIBSPDM_DEBUG_ERROR)" CACHE INTERNAL "libspdm debug mask" FORCE)
  else()
    set(_libspdm_debug_level "LIBSPDM_DEBUG_ERROR" CACHE INTERNAL "libspdm debug mask" FORCE)
  endif()
else()
  # Default to ERROR only when ACS_PRINT_LEVEL isn't set for safety.
  set(_libspdm_debug_level "LIBSPDM_DEBUG_ERROR" CACHE INTERNAL "libspdm debug mask" FORCE)
endif()

# Keep the upstream cache variables in sync with our single supported backend.
set(ARCH "aarch64" CACHE STRING "libspdm target architecture" FORCE)
set(TOOLCHAIN "ARM_GNU_BARE_METAL" CACHE STRING "libspdm toolchain" FORCE)
set(CMAKE_BUILD_TYPE "Release" CACHE STRING "libspdm build type" FORCE)
set(ENABLE_BINARY_BUILD "0" CACHE STRING "disable libspdm binary build" FORCE)
set(ENABLE_CODEQL "OFF" CACHE STRING "disable libspdm codeql flow" FORCE)
set(DISABLE_TESTS "1" CACHE STRING "disable libspdm unit tests" FORCE)
set(MBEDTLS_CONFIG_FILE "${_mbedtls_config}" CACHE FILEPATH "mbedTLS configuration for libspdm" FORCE)

# Capture the SPDM-EMU helper project location for DOE/CXL requesters.
set(SPDM_EMU_DIR "${ROOT_DIR}/ext/spdm-emu")
set(SPDM_EMU_INCLUDE_DIR "${SPDM_EMU_DIR}/include" CACHE INTERNAL "spdm-emu public headers" FORCE)

# All libspdm static libraries consumed by ACS.
set(_libspdm_sources
  ${LIBSPDM_DIR}/library/spdm_common_lib
  ${LIBSPDM_DIR}/library/spdm_requester_lib
  ${LIBSPDM_DIR}/library/spdm_secured_message_lib
  ${LIBSPDM_DIR}/library/spdm_transport_pcidoe_lib
  ${LIBSPDM_DIR}/library/spdm_crypt_lib
  ${LIBSPDM_DIR}/os_stub/memlib
  ${LIBSPDM_DIR}/os_stub/malloclib
  ${LIBSPDM_DIR}/os_stub/platform_lib_null
  ${LIBSPDM_DIR}/os_stub/debuglib
  ${LIBSPDM_DIR}/os_stub/spdm_crypt_ext_lib
  ${LIBSPDM_DIR}/os_stub/spdm_device_secret_lib_null
)

# Ensure the libspdm mbedTLS submodule is present before we build its wrappers.
set(_libspdm_mbedtls_dir "${LIBSPDM_DIR}/os_stub/mbedtlslib/mbedtls")
if(NOT EXISTS "${_libspdm_mbedtls_dir}/library")
  message(STATUS "[ACS] : Initializing libspdm mbedtls submodule")
  execute_process(
    COMMAND git submodule update --init os_stub/mbedtlslib/mbedtls
    WORKING_DIRECTORY "${LIBSPDM_DIR}"
    RESULT_VARIABLE _mbedtls_result
    OUTPUT_STRIP_TRAILING_WHITESPACE
    ERROR_STRIP_TRAILING_WHITESPACE)
  if(NOT _mbedtls_result EQUAL 0 OR NOT EXISTS "${_libspdm_mbedtls_dir}/library")
    message(FATAL_ERROR "[ACS] : Failed to initialize libspdm mbedtls submodule. Run \"git -C ext/libspdm submodule update --init os_stub/mbedtlslib/mbedtls\" manually.")
  endif()
endif()
list(APPEND _libspdm_sources
  ${LIBSPDM_DIR}/os_stub/cryptlib_mbedtls
  ${LIBSPDM_DIR}/os_stub/mbedtlslib
)

# SPDM-EMU helper libraries that provide CXL/DOE/TDISP shims.
set(_spdm_emu_sources
  ${SPDM_EMU_DIR}/library/cxl_ide_km_requester_lib
  ${SPDM_EMU_DIR}/library/pci_ide_km_requester_lib
  ${SPDM_EMU_DIR}/library/pci_doe_requester_lib
  ${SPDM_EMU_DIR}/library/cxl_tsp_requester_lib
  ${SPDM_EMU_DIR}/library/pci_tdisp_requester_lib
)

# Apply common include paths, defines, and warning relaxations to libspdm targets.
function(_acs_configure_spdm_target target)
  target_include_directories(${target} PRIVATE
    "${LIBSPDM_DIR}/include"
    "${LIBSPDM_DIR}/os_stub"
    "${SPDM_EMU_INCLUDE_DIR}"
    "${ROOT_DIR}/val/include"
    "${_libspdm_config_dir}"
  )
  target_compile_definitions(${target} PRIVATE
    ${_libspdm_config_define}
    "LIBSPDM_DEBUG_LEVEL_CONFIG=${_libspdm_debug_level}"
  )
  target_compile_options(${target} PRIVATE
    -Wno-unused-parameter
    -Wno-sign-compare
    -Wno-incompatible-pointer-types
    -Wno-old-style-declaration
    -Wno-empty-body
  )
endfunction()

# Apply consistent configuration to the SPDM-EMU helper libraries.
function(_acs_configure_spdm_emu_target target)
  target_include_directories(${target} PRIVATE
    "${LIBSPDM_DIR}/include"
    "${SPDM_EMU_INCLUDE_DIR}"
    "${ROOT_DIR}/val/include"
    "${_libspdm_config_dir}"
  )
  target_compile_definitions(${target} PRIVATE ${_libspdm_config_define})
  target_compile_options(${target} PRIVATE
    -Wno-unused-parameter
    -Wno-sign-compare
    -Wno-incompatible-pointer-types
  )
endfunction()

if(NOT TARGET rnglib)
  add_library(rnglib STATIC "${ROOT_DIR}/platform/pal_baremetal/src/pal_rng.c")
  # Provide libspdm with a platform RNG interface even when the PAL omits it.
  target_include_directories(rnglib PRIVATE
    "${LIBSPDM_DIR}/include"
    "${LIBSPDM_DIR}/os_stub"
    "${LIBSPDM_DIR}/os_stub/include"
    "${ROOT_DIR}/platform/pal_baremetal/include"
    "${ROOT_DIR}/platform/pal_baremetal/${TARGET}/include"
    "${_libspdm_config_dir}"
  )
  target_compile_definitions(rnglib PRIVATE ${_libspdm_config_define})
endif()

# Temporarily drop strict-overflow warning so libspdm builds cleanly.
set(_saved_c_flags "${CMAKE_C_FLAGS}")
string(REPLACE "-Wstrict-overflow" "" CMAKE_C_FLAGS "${CMAKE_C_FLAGS}")

# Build each libspdm component and apply the common configuration wrapper.
foreach(_source_dir IN LISTS _libspdm_sources)
  get_filename_component(_lib_name "${_source_dir}" NAME)
  add_subdirectory(${_source_dir} "${LIBSPDM_BIN_DIR}/${_lib_name}")
  get_target_property(_lib_type ${_lib_name} TYPE)
  if(NOT _lib_type STREQUAL "INTERFACE_LIBRARY")
    _acs_configure_spdm_target(${_lib_name})
  endif()
endforeach()

# Bring in the SPDM-EMU requester helpers with matching configuration.
foreach(_source_dir IN LISTS _spdm_emu_sources)
  get_filename_component(_lib_name "${_source_dir}" NAME)
  add_subdirectory(${_source_dir} "${LIBSPDM_BIN_DIR}/${_lib_name}")
  _acs_configure_spdm_emu_target(${_lib_name})
endforeach()

# Restore the original compiler flags once libspdm configuration is complete.
set(CMAKE_C_FLAGS "${_saved_c_flags}")

target_link_libraries(spdm_requester_lib PRIVATE spdm_common_lib spdm_crypt_lib)
target_link_libraries(spdm_secured_message_lib PRIVATE spdm_crypt_lib)
target_link_libraries(spdm_common_lib PRIVATE spdm_crypt_lib)

# Propagate the ACS mbedTLS configuration header into each mbedTLS-related target.
foreach(_mbed_target IN ITEMS cryptlib_mbedtls mbedtls mbedx509 mbedcrypto)
  if(TARGET ${_mbed_target})
    target_compile_definitions(${_mbed_target} PRIVATE "-DMBEDTLS_CONFIG_FILE=\"${_mbedtls_config}\"")
  endif()
endforeach()

# Ensure the libspdm cryptlib wrapper links against the concrete mbedTLS library.
if(TARGET cryptlib_mbedtls AND TARGET mbedtlslib)
  target_link_libraries(cryptlib_mbedtls PUBLIC mbedtlslib)
endif()

# Tie libspdm's crypt layer to the wrapper so the symbols resolve.
if(TARGET spdm_crypt_lib AND TARGET cryptlib_mbedtls)
  target_link_libraries(spdm_crypt_lib PUBLIC cryptlib_mbedtls)
endif()
