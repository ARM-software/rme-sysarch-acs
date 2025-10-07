/** @file
 * Copyright (c) 2024-2025, Arm Limited or its affiliates. All rights reserved.
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

#include "val/include/val_pcie.h"
#include "val/include/val_pcie_spec.h"

pcie_cfgreg_bitfield_entry bf_info_table18[] = {
    // PCI Express Extended Capability Header (Memory Space Enable)
    {
       HEADER,                       // Part of PCIe header register
       0,                            // Capability ID for HEADER
       0,                            // Extended Capability ID (not applicable for HEADER)
       0x04,                         // 4-byte aligned offset for Command Register
       RP,                           // Root Port (RP)
       1,                            // Start bit position
       1,                            // End bit position
       0,                            // Bit value
       WRITE_DETECT,                // Access type: WRITE_DETECT
       "WARNING",                   // Warning message
       "ERROR Write-detect failed for Memory Space/Bus Master" // Error message
    },
    // PCI Express Extended Capability Header (Bus Master Enable)
    {
       HEADER,                       // Part of PCIe header register
       0,                            // Capability ID for HEADER
       0,                            // Extended Capability ID (not applicable for HEADER)
       0x04,                         // 4-byte aligned offset for Command Register
       RP,                           // Root Port (RP)
       2,                            // Start bit position
       2,                            // End bit position
       0,                            // Bit value
       WRITE_DETECT,                // Access type: WRITE_DETECT
       "WARNING",                   // Warning message
       "ERROR Write-detect failed for Memory Space/Bus Master" // Error message
    },
    // BIST Register - Start bit 0, End bit 3 (Bits [3:0])
    {
       HEADER,                       // Part of PCIe header register
       0,                            // Capability ID for HEADER
       0,                            // Extended Capability ID (not applicable for HEADER)
       0x0C,                         // 4-byte aligned offset for BIST Register
       RP,                           // Root Port (RP)
       6,                            // Start bit position (BIST Register)
       6,                            // End bit position (BIST Register)
       0,                            // Bit value
       WRITE_DETECT,                // Access type: WRITE_DETECT
       "WARNING",                   // Warning message
       "ERROR Write-detect failed for BIST Register" // Error message
    },
    // Base Address Registers (BAR)
    {
       HEADER,                       // Part of PCIe header register
       0,                            // Capability ID for HEADER
       0,                            // Extended Capability ID (not applicable for HEADER)
       0x10,                         // 4-byte aligned offset for Base Address Registers
       RP,                           // Root Port (RP)
       31,                           // Start bit position (Bits [31:0])
       0,                            // End bit position (Bits [31:0])
       0xFFFFFFFF,                   // Bit value
       WRITE_DETECT,                // Access type: WRITE_DETECT
       "WARNING",                   // Warning message
       "ERROR Write-detect failed for Base Address Registers" // Error message
    },
    // Primary Bus Number
    {
       HEADER,                       // Part of PCIe header register
       0,                            // Capability ID for HEADER
       0,                            // Extended Capability ID (not applicable for HEADER)
       0x18,                         // 4-byte aligned offset for Primary Bus Number
       RP,                           // Root Port (RP)
       0,                            // Start bit position
       7,                            // End bit position
       0,                            // Bit value
       WRITE_DETECT,                // Access type: WRITE_DETECT
       "WARNING",                   // Warning message
       "ERROR Write-detect failed for Primary Bus Number" // Error message
    },
    // Secondary Bus Number
    {
       HEADER,                       // Part of PCIe header register
       0,                            // Capability ID for HEADER
       0,                            // Extended Capability ID (not applicable for HEADER)
       0x18,                         // 4-byte aligned offset for Secondary Bus Number
       RP,                           // Root Port (RP)
       8,                            // Start bit position
       15,                           // End bit position
       0,                            // Bit value
       WRITE_DETECT,                // Access type: WRITE_DETECT
       "WARNING",                   // Warning message
       "ERROR Write-detect failed for Secondary Bus Number" // Error message
    },
    // Subordinate Bus Number
    {
       HEADER,                       // Part of PCIe header register
       0,                            // Capability ID for HEADER
       0,                            // Extended Capability ID (not applicable for HEADER)
       0x18,                         // 4-byte aligned offset for Subordinate Bus Number
       RP,                           // Root Port (RP)
       16,                           // Start bit position
       23,                           // End bit position
       0,                            // Bit value
       WRITE_DETECT,                // Access type: WRITE_DETECT
       "WARNING",                   // Warning message
       "ERROR Write-detect failed for Subordinate Bus Number" // Error message
    },
    // Memory Base
    {
       HEADER,                       // Part of PCIe header register
       0,                            // Capability ID for HEADER
       0,                            // Extended Capability ID (not applicable for HEADER)
       0x20,                         // 4-byte aligned offset for Memory Base
       RP,                           // Root Port (RP)
       4,                            // Start bit position (Bits [31:0])
       15,                           // End bit position (Bits [31:0])
       0,                            // Bit value
       WRITE_DETECT,                // Access type: WRITE_DETECT
       "WARNING",                   // Warning message
       "ERROR Write-detect failed for Memory Base/Memory Limit" // Error message
    },
    // Memory Base/Memory Limit
    {
       HEADER,                       // Part of PCIe header register
       0,                            // Capability ID for HEADER
       0,                            // Extended Capability ID (not applicable for HEADER)
       0x20,                         // 4-byte aligned offset for Memory Base/Limit
       RP,                           // Root Port (RP)
       20,                            // Start bit position (Bits [31:0])
       31,                           // End bit position (Bits [31:0])
       0,                            // Bit value
       WRITE_DETECT,                // Access type: WRITE_DETECT
       "WARNING",                   // Warning message
       "ERROR Write-detect failed for Memory Base/Memory Limit" // Error message
    },
    // Prefetchable Memory Base/Prefetchable Memory Limit
    {
       HEADER,                       // Part of PCIe header register
       0,                            // Capability ID for HEADER
       0,                            // Extended Capability ID (not applicable for HEADER)
       0x24,                         // 4-byte aligned offset for Prefetchable Memory Base/Limit
       RP,                           // Root Port (RP)
       0,                            // Start bit position (Bits [31:0])
       31,                           // End bit position (Bits [31:0])
       0,                            // Bit value
       WRITE_DETECT,                // Access type: WRITE_DETECT
       "WARNING",                   // Warning message
       "ERROR Write-detect failed for Prefetchable Memory Base/Limit" // Error message
    },
    // Device Control Register - Extended Tag Field Enable bit
    {
       PCIE_CAP,                     // Part of PCIe capability register
       CID_PCIECS,                            // Capability ID for Device Control
       0,                            // Extended Capability ID (not applicable for Device Control)
       0x08,                         // 4-byte aligned offset for Device Control Register
       RP,                           // Root Port (RP)
       8,                            // Start bit position (Extended Tag Field Enable)
       8,                            // End bit position (Extended Tag Field Enable)
       0,                            // Bit value
       WRITE_DETECT,                // Access type: WRITE_DETECT
       "WARNING",                   // Warning message
       "ERROR Write-detect failed for Extended Tag Field Enable" // Error message
    },
    // Device Control 2 Register - 10-Bit Tag Requester Enable bit (bit 12)
    {
       PCIE_CAP,                     // Part of PCIe capability register
       CID_PCIECS,                            // Capability ID for Device Control 2
       0,                            // Extended Capability ID (not applicable for Device Control 2)
       0x28,                         // 4-byte aligned offset for Device Control 2 Register
       RP,                           // Root Port (RP)
       12,                           // Start bit position (10-Bit Tag Requester Enable)
       12,                           // End bit position (10-Bit Tag Requester Enable)
       0,                            // Bit value
       WRITE_DETECT,                // Access type: WRITE_DETECT
       "WARNING",                   // Warning message
       "ERROR Write-detect failed for 10-Bit Tag Requester Enable" // Error message
    },
    // Device Control 3 Register - 14-Bit Tag Requester Enable bit (bit 6)
    {
       PCIE_ECAP,                    // Part of PCIe capability register
       0,                            // Capability ID for Device Control 3
       ECID_DCAP3,                   // Extended Capability ID (not applicable for Device Control 3)
       0x08,                         // 4-byte aligned offset for Device Control 3 Register
       RP,                           // Root Port (RP)
       6,                            // Start bit position (14-Bit Tag Requester Enable)
       6,                            // End bit position (14-Bit Tag Requester Enable)
       0,                            // Bit value
       WRITE_DETECT,                // Access type: WRITE_DETECT
       "WARNING",                   // Warning message
       "ERROR Write-detect failed for 14-Bit Tag Requester Enable" // Error message
    },
    // Enhanced Allocation - Bits [21:16]
    {
       PCIE_CAP,                     // Part of PCIe extended capability register
       CID_EA,                       // Capability ID for Enhanced Allocation
       0,                            // Extended Capability ID (not applicable)
       0x00,                         // 4-byte aligned offset for Enhanced Allocation
       RP,                           // Root Port (RP)
       16,                           // Start bit position (Bits [21:16])
       21,                           // End bit position (Bits [21:16])
       0,                            // Bit value
       WRITE_DETECT,                // Access type: WRITE_DETECT
       "WARNING",                   // Warning message
       "ERROR Write-detect failed for Enhanced Allocation" // Error message
    },
    // Multicast - MC_Enable bit (bit 31)
    {
       PCIE_ECAP,                    // Part of PCIe capability register
       0,                            // Capability ID for Multicast
       ECID_MC,                      // Extended Capability ID (not applicable for Multicast)
       0x04,                         // 4-byte aligned offset for Multicast
       RP,                           // Root Port (RP)
       31,                           // Start bit position (MC_Enable)
       31,                           // End bit position (MC_Enable)
       0,                            // Bit value
       WRITE_DETECT,                // Access type: WRITE_DETECT
       "WARNING",                   // Warning message
       "ERROR Write-detect failed for MC_Enable" // Error message
    },
    // Resizable BAR Control Register - BAR Size bits (bits 13:8)
    {
       PCIE_ECAP,                    // Part of PCIe capability register
       0,                            // Capability ID for Resizable BAR
       ECID_RBAR,                    // Extended Capability ID (not applicable for Resizable BAR)
       0x08,                         // 4-byte aligned offset for Resizable BAR Control Register
       RP,                           // Root Port (RP)
       8,                            // Start bit position (BAR Size)
       13,                           // End bit position (BAR Size)
       0,                            // Bit value
       WRITE_DETECT,                // Access type: WRITE_DETECT
       "WARNING",                   // Warning message
       "ERROR Write-detect failed for BAR Size" // Error message
    },
};
