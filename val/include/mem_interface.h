/** @file
 * Copyright (c) 2022-2023, Arm Limited or its affiliates. All rights reserved.
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

#ifndef __MEM_INTERFACE_H__
#define __MEM_INTERFACE_H__

#define RESET_TST12_FLAG 12
#define RESET_TST31_FLAG 31
#define RESET_TST32_FLAG 32
#define RESET_TST2_FLAG 34
#define RESET_LS_TEST3_FLAG 503
#define RESET_LS_DISBL_FLAG 500

#define GPR_WRITE_VAL 0x1234567890ABCDEF
#define SIZE_4K  (4*1024)
#define SIZE_16K (16*1024)
#define SIZE_64K (64*1024)

#endif /* __MEM_INTERFACE_H__ */
