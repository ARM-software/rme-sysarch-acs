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
 set(TEST_INCLUDE ${CMAKE_CURRENT_BINARY_DIR})
 list(APPEND TEST_INCLUDE
     ${VAL_DIR}/
     ${ROOT_DIR}/
     ${TEST_DIR}/
     ${VAL_DIR}/src/
     ${VAL_DIR}/include/
     ${PAL_DIR}/src/
     ${PAL_DIR}/include/
     ${PAL_DIR}/${TARGET}/src/
     ${PAL_DIR}/${TARGET}/include/
 )

 set(TEST_LIB ${EXE_NAME}_test_lib)

 # Compile all .c/.S files from test directory
 file(GLOB TEST_SRC
     "${ROOT_DIR}/test_pool/*/test*.c"
 )

 # Create TEST library
 add_library(${TEST_LIB} STATIC ${TEST_SRC})

 #Create compile list files
 list(APPEND COMPILE_LIST ${TEST_SRC})
 set(COMPILE_LIST ${COMPILE_LIST} PARENT_SCOPE)

 target_include_directories(${TEST_LIB} PRIVATE ${TEST_INCLUDE}

 )

 create_executable(${EXE_NAME} ${BUILD}/output/ "")
 unset(TEST_SRC)