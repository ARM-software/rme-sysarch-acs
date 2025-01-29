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

# Set the minimum required version of CMake for the project
cmake_minimum_required(VERSION 3.17)
project(rme-acs LANGUAGES)

# Tool dependency check
get_filename_component(ROOT_DIR . ABSOLUTE)
set(VAL_DIR "${ROOT_DIR}/val/" CACHE INTERNAL "Setting VAL directory to ${VAL_DIR}" FORCE)
set(PAL_DIR "${ROOT_DIR}/platform/pal_baremetal/" CACHE INTERNAL "Setting PAL directory to ${PAL_DIR}" FORCE)
set(TEST_DIR "${ROOT_DIR}/test_pool/" CACHE INTERNAL "Setting TEST directory to ${TEST_DIR}" FORCE)

# Set internal build directory variable
set(BUILD ${CMAKE_CURRENT_BINARY_DIR} CACHE INTERNAL "Setting build directory to ${BUILD}" FORCE)
file(MAKE_DIRECTORY ${BUILD}/output/)

# Set global compile list variable
set(COMPILE_LIST "")

# Include cmake support module
include(${ROOT_DIR}/tools/cmake/toolchain/default.cmake)
include(${ROOT_DIR}/tools/cmake/toolchain/utils.cmake)

# Valid value range for command line argument
list(APPEND ARM_ARCH_MAJOR_LIST 8 9)

# Check for valid targets
_get_sub_dir_list(TARGET_LIST ${ROOT_DIR}/platform/pal_baremetal/)
if(NOT DEFINED TARGET)
    set(TARGET ${TARGET_DFLT} CACHE INTERNAL "Defaulting target to ${TARGET}" FORCE)
else()
    set(TARGET ${TARGET} CACHE INTERNAL "TARGET is set to ${TARGET}" FORCE)
endif()

if(NOT ${TARGET} IN_LIST TARGET_LIST)
    message(FATAL_ERROR "[ACS] : Error: Unspported value for -DTARGET=, supported targets are : ${TARGET_LIST}")
else()
    message(STATUS "[ACS] : TARGET is set to ${TARGET}")
endif()

# Check for ARM_ARCH_MAJOR
if(NOT DEFINED ARM_ARCH_MAJOR)
    set(ARM_ARCH_MAJOR "${ARM_ARCH_MAJOR_DFLT}" CACHE INTERNAL "Default ARM_ARCH_MAJOR value" FORCE)
        message(STATUS "[ACS] : Defaulting ARM_ARCH_MAJOR to ${ARM_ARCH_MAJOR}")
else()
    if(NOT ${ARM_ARCH_MAJOR} IN_LIST ARM_ARCH_MAJOR_LIST)
        message(FATAL_ERROR "[ACS] : Error: Unspported value for -DARM_ARCH_MAJOR=, supported values are : ${ARM_ARCH_MAJOR_LIST}")
    endif()
    message(STATUS "[ACS] : ARM_ARCH_MAJOR is set to ${ARM_ARCH_MAJOR}")
endif()

# Check for ARM_ARCH_MINOR
if(NOT DEFINED ARM_ARCH_MINOR)
    set(ARM_ARCH_MINOR "${ARM_ARCH_MINOR_DFLT}" CACHE INTERNAL "Default ARM_ARCH_MINOR value" FORCE)
        message(STATUS "[ACS] : Defaulting ARM_ARCH_MINOR to ${ARM_ARCH_MINOR}")
else()
    message(STATUS "[ACS] : ARM_ARCH_MINOR is set to ${ARM_ARCH_MINOR}")
endif()

# Setup toolchain parameters for compilation and link
include(${ROOT_DIR}/tools/cmake/toolchain/common.cmake)

# CMake clean target
list(APPEND CLEAN_LIST
        ${CMAKE_CURRENT_BINARY_DIR}/${OUTPUT_HEADER}
        ${CMAKE_CURRENT_BINARY_DIR}/output
)

# Include the files for make clean
foreach(clean_item ${CLEAN_LIST})
        set_property(DIRECTORY APPEND PROPERTY ADDITIONAL_MAKE_CLEAN_FILES ${clean_item})
endforeach()

add_subdirectory(${ROOT_DIR}/tools/cmake/rme)
