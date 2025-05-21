/** @file
 * Copyright (c) 2022-2023, 2025, Arm Limited or its affiliates. All rights reserved.
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

#ifndef __RME_ACS_PERIPHERALS_H__
#define __RME_ACS_PERIPHERALS_H__

#define WIDTH_BIT8     0x1
#define WIDTH_BIT16    0x2
#define WIDTH_BIT32    0x4

#define RME_UARTDR    0x0
#define RME_UARTRSR   0x4
#define RME_UARTFR    0x18
#define RME_UARTLCR_H 0x2C
#define RME_UARTCR    0x30
#define RME_UARTIMSC  0x38
#define RME_UARTRIS   0x3C
#define RME_UARTMIS   0x40
#define RME_UARTICR   0x44

typedef enum {
  NUM_USB,
  NUM_SATA,
  NUM_UART,
  NUM_ALL,
  USB_BASE0,
  USB_FLAGS,
  USB_GSIV,
  USB_BDF,
  SATA_BASE0,
  SATA_BASE1,
  SATA_FLAGS,
  SATA_GSIV,
  SATA_BDF,
  UART_BASE0,
  UART_GSIV,
  UART_FLAGS,
  ANY_FLAGS,
  ANY_GSIV,
  ANY_BDF,
  MAX_PASIDS
} PERIPHERAL_INFO_e;

uint64_t val_peripheral_get_info(PERIPHERAL_INFO_e info_type, uint32_t index);
uint32_t val_peripheral_is_pcie(uint32_t bdf);

#endif // __RME_ACS_PERIPHERAL_H__
