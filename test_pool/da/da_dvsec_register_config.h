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

#include "val/include/rme_acs_pcie.h"
#include "val/include/rme_acs_pcie_spec.h"

pcie_cfgreg_bitfield_entry bf_info_table[] = {

    // Bit-field entry 1: PCI Express Extended Capability Header(RMEDA_ECH), bit[15:0] Data Select
    {
       PCIE_ECAP,                               // Part of PCIe capability register
       0,                                       // not Applicable
       RMEDA_ECH_ID,                            // Extended Capability id
       RMEDA_ECH,                               // Offset from capability id base
       RP,                                      // Search for the required RootPort
       0,                                       // Start bit position
       15,                                      // End bit position
       0x0023,                                  // ECH ID
       READ_ONLY,                               // Attribute is READ_ONLY
       "ERROR ECH_ID mismatch",             // Invalid configured value
       "ERROR ECH_ID attribute mismatch"    // Invalid attribute
    },
    //Bit-field entry 2: ECH_CAP_VER, bit[19:16] Data Select
    {
       PCIE_ECAP,                               // Part of PCIe capability register
       0,                                       // not Applicable
       RMEDA_ECH_ID,                            // Extended Capability id
       RMEDA_ECH,                               // Offset from capability id base
       RP,                                      // Search for the required RootPort
       16,                                      // Start bit position
       19,                                      // End bit position
       0x1,                                     // Capability Version(Version 1)
       READ_ONLY,                               // Attribute is READ_ONLY
       "ERROR Capability version mismatch",   // Invalid configured value
       "ERROR Capability version attribute mismatch" // Invalid attribute
    },
    //Bit-field entry 3: RME-DA DVSEC Header 1(DVSEC Vendor ID), bit[15:0] Data Select
    {
       PCIE_ECAP,                               // Part of PCIe capability register
       0,                                       // not Applicable
       RMEDA_ECH_ID,                            // Extended Capability id
       RMEDA_HEAD1,                             // Offset from capability id base
       RP,                                      // Search for the required RootPort
       0,                                       // Start bit position
       15,                                      // End bit position
       0x13B5,                                  // Vendor ID
       READ_ONLY,                               // Attribute is READ_ONLY
       "ERROR DVSEC Vendor ID mismatch",      // Invalid configured value
       "ERROR DVSEC Vendor ID attribute mismatch" // Invalid attribute
    },
    //Bit-field entry 4: DVSEC_REVISION, bit[19:16] Data Select
    {
       PCIE_ECAP,                               // Part of PCIe capability register
       0,                                       // not Applicable
       RMEDA_ECH_ID,                            // Extended Capability id
       RMEDA_HEAD1,                             // Offset from capability id base
       RP,                                      // Search for the required RootPort
       16,                                      // Start bit position
       19,                                      // End bit position
       0x0,                                     // DVSEC revision(Revision 0)
       READ_ONLY,                               // Attribute is READ_ONLY
       "ERROR DVSEC_REVISION value mismatch",    // Invalid configured value
       "ERROR DVSEC REVISIOn attribute mismatch" // Invalid attribute
    },
    //Bit-field entry 5: DVSEC_LENGTH in bytes, bit[31:20] Data Select
   {
       PCIE_ECAP,                               // Part of PCIe capability register
       0,                                       // not Applicable
       RMEDA_ECH_ID,                            // Extended Capability id
       RMEDA_HEAD1,                             // Offset from capability id base
       RP,                                      // Search for the required RootPort
       20,                                      // Start bit position
       31,                                      // End bit position
       0x014,                                   // DVSEC length in bytes
       READ_ONLY,                               // Attribute is READ_ONLY
       "ERROR DVSEC_LENGTH value mismatch",   // Invalid configured value
       "ERROR DVSEC_LENGTH attribute mismatch" // Invalid attribute
    },
    //Bit-field entry 6: RME-DA DVSEC Header 2 (DVSEC_ID), bit[15:0] Data Select
   {
       PCIE_ECAP,                               // Part of PCIe capability register
       0,                                       // not Applicable
       RMEDA_ECH_ID,                            // Extended Capability id
       RMEDA_HEAD2,                             // Offset from capability id base
       RP,                                      // Search for the required RootPort
       0,                                       // Start bit position
       15,                                      // End bit position
       0xFF01,                                  // Vendor-defined DVSEC ID
       READ_ONLY,                               // Attribute is READ_ONLY
       "ERROR DVSEC_ID value mismatch",       // Invalid configured value
       "ERROR DVSEC_ID attribute mismatch"    // Invalid attribute
    },
    //Bit-field entry 7: RME-DA Control register 1, bit[31:1] RES0 check
    {
       PCIE_ECAP,                               // Part of PCIe capability register
       0,                                       // not Applicable
       RMEDA_ECH_ID,                            // Extended Capability id
       RMEDA_CTL1,                              // Offset from capability id base
       RP,                                      // Search for the required RootPort
       1,                                       // Start bit position
       31,                                      // End bit position
       0,                                       // Unimplemented bits
       RSVDP_RO,                                // Attribute is RsvdP
       "ERROR UnIMP bits are Not RES0",       // Invalid configured value
       "ERROR UnIMP Bits attribute mismatch"  // Invalid attribute
    },

};
