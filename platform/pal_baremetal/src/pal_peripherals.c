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

#include "include/pal_pcie_enum.h"
#include "include/pal_common_support.h"
#include "FVP/include/pal_override_struct.h"

extern PLATFORM_OVERRIDE_UART_INFO_TABLE platform_uart_cfg;

#define USB_CLASSCODE   0x0C0300
#define SATA_CLASSCODE  0x010600
#define BAR0            0
#define BAR1            1
#define BAR2            2
#define BAR3            3
#define BAR4            4
#define BAR5            5

/**
  @brief  This API fills in the PERIPHERAL_INFO_TABLE with information about peripherals
          in the system.

  @param  peripheralInfoTable  - Address where the Peripheral information needs to be filled.

  @return  None
**/
void
pal_peripheral_create_info_table(PERIPHERAL_INFO_TABLE *peripheralInfoTable)
{

  uint32_t   DeviceBdf = 0;
  uint32_t   StartBdf  = 0;
  uint32_t   bar_index;
  PERIPHERAL_INFO_BLOCK *per_info = NULL;

  if (peripheralInfoTable == NULL) {
    print(ACS_PRINT_ERR, "Input Peripheral Table Pointer is NULL. Cannot create Peripheral INFO ");
    return;
  }

  per_info = peripheralInfoTable->info;

  peripheralInfoTable->header.num_usb = 0;
  peripheralInfoTable->header.num_sata = 0;
  peripheralInfoTable->header.num_uart = 0;
  peripheralInfoTable->header.num_all = 0;
  per_info->base0 = 0;

  /* check for any USB Controllers */
  do {

       print(ACS_PRINT_INFO, "Entered USB loop ");
       DeviceBdf = pal_pcie_get_bdf(USB_CLASSCODE, StartBdf);
       if (DeviceBdf != 0) {
          per_info->type  = PERIPHERAL_TYPE_USB;
          for (bar_index = 0; bar_index < TYPE0_MAX_BARS; bar_index++)
          {
              per_info->base0 = pal_pcie_get_base(DeviceBdf, bar_index);
              if (per_info->base0 != 0)
                  break;
          }
          per_info->bdf   = DeviceBdf;
          print(ACS_PRINT_INFO, "Found a USB controller %4x ", per_info->base0);
          peripheralInfoTable->header.num_usb++;
          peripheralInfoTable->header.num_all++;
          per_info++;
       }
       StartBdf = pal_increment_bus_dev(DeviceBdf);

  } while (DeviceBdf != 0);

  StartBdf = 0;
  /* check for any SATA Controllers */
  do {

       print(ACS_PRINT_INFO, "Entered SATA loop ");
       DeviceBdf = pal_pcie_get_bdf(SATA_CLASSCODE, StartBdf);
       if (DeviceBdf != 0) {
          per_info->type  = PERIPHERAL_TYPE_SATA;
          for (bar_index = 0; bar_index < TYPE0_MAX_BARS; bar_index++)
          {
              per_info->base0 = pal_pcie_get_base(DeviceBdf, bar_index);
              if (per_info->base0 != 0)
                  break;
          }
          per_info->bdf   = DeviceBdf;
          print(ACS_PRINT_INFO, "Found a SATA controller %4x ", per_info->base0);
          peripheralInfoTable->header.num_sata++;
          peripheralInfoTable->header.num_all++;
          per_info++;
       }
       //Increment and check if we have more controllers
       StartBdf = pal_increment_bus_dev(DeviceBdf);

  } while (DeviceBdf != 0);

  /* UART details
   * Assumption that UART bdf details is
   * known to platform owner */
  uint64_t uart = platform_uart_cfg.Address;

  if (uart) {
    peripheralInfoTable->header.num_uart++;
    per_info->base0 = platform_uart_cfg.BaseAddress.Address;
    per_info->irq   = platform_uart_cfg.GlobalSystemInterrupt;
    per_info->type  = PERIPHERAL_TYPE_UART;
    peripheralInfoTable->header.num_all++;
    per_info++;
  }

  per_info->type = 0xFF; //indicate end of table

}

uint64_t
pal_memory_ioremap(void *ptr, uint32_t size, uint32_t attr)
{
  (void) size;
  (void) attr;

  return (uint64_t)ptr;
}

void
pal_memory_unmap(void *ptr)
{
  (void) ptr;

  return;
}
