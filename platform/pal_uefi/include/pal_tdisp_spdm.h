/** @file
 * Copyright (c) 2022-2024, Arm Limited or its affiliates. All rights reserved.
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

#ifndef __RME_ACS_TDISP_SPDM_H__
#define __RME_ACS_TDISP_SPDM_H__

#define VENDOR_DEFINED_REQUEST

/* DOE Capability Register */
#define DOE_CAP_ID 0x002E

#define DOE_CAP_REG                     0x4
#define DOE_CTRL_REG                    0x8
#define DOE_STATUS_REG                  0xC
#define DOE_WRITE_DATA_MAILBOX_REG      0x10
#define DOE_READ_DATA_MAILBOX_REG       0x14

#define DOE_STATUS_REG_BUSY     0
#define DOE_STATUS_REG_ERROR    2
#define DOE_STATUS_REG_READY    31

#endif
