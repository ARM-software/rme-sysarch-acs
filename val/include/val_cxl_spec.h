/** @file
 * Copyright (c) 2022-2026, Arm Limited or its affiliates. All rights reserved.
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

#ifndef __RME_ACS_CXL_SPEC_H__
#define __RME_ACS_CXL_SPEC_H__

/*
 * CXL + PCIe extended capability helpers
 * Note: Some generic PCIe defines may already exist in rme_acs_pcie_spec.h.
 * Guard duplicates to avoid -Wmacro-redefined turning into build errors.
 */

/* PCIe ECAP/DVSEC */
#define CXL_DVSEC_VENDOR_ID             0x1E98  /* CXL Consortium Vendor ID */

/* ---- CXL DVSEC IDs you'll encounter on endpoints/ports ----
   NOTE: Leave as constants here; exact list evolves per CXL 3.x.
   You only need the Register Locator to find MMIO blocks.
*/
#define CXL_DVSEC_ID_DEVICE             0x0000
#define CXL_DVSEC_ID_FUNCTION_MAP       0x0002
#define CXL_DVSEC_ID_PORT_EXTENSIONS    0x0003
#define CXL_DVSEC_ID_GPF_PORT           0x0004
#define CXL_DVSEC_ID_GPF_DEVICE         0x0005
#define CXL_DVSEC_ID_PCIE_FLEXBUS_PORT  0x0007
#define CXL_DVSEC_ID_REGISTER_LOCATOR   0x0008

/* ---- Register Locator entry decode ---- */
#define CXL_RL_ENTRY_SIZE               0x08    /* bytes per entry per spec */
#define CXL_RL_HDR_OFFSET_ENTRIES       0x0C    /* Entries start after 12B header */

/* Per-entry fields (offsets from start of an entry)
   DW0 layout (little endian):
     [2:0]   BAR Indicator
     [7:3]   Reserved
     [15:8]  Block Identifier (8-bit)
     [31:16] Register Offset bits [31:16]
   DW1: Register Offset bits [63:32] (relative to BAR base)
   Register Offset bits [15:0] are zero (64 KiB alignment).
*/
#define CXL_RL_ENTRY_DW0_OFF            0x00
#define CXL_RL_ENTRY_DW1_OFF            0x04
#define CXL_RL_ENTRY_OFFSET_LOW_MASK    0xFFFF0000u

/* Block IDs commonly seen (8-bit identifiers per RL DW0[15:8]) */
#define CXL_REG_BLOCK_COMPONENT         0x01    /* CXL Component Registers */
#define CXL_REG_BLOCK_DEVICE            0x03    /* CXL Device Registers */

/* BAR field helpers */
#define CXL_RL_BAR_NUM(b)               ((b) & 0x7)
#define CXL_RL_BAR_IS_64B(b)            (((b) >> 7) & 0x1)

/* CXL.cachemem Primary range offset (per CXL 3.1 Table 8-21): BAR + 4KB */
#ifndef CXL_CACHEMEM_PRIMARY_OFFSET
#define CXL_CACHEMEM_PRIMARY_OFFSET     0x1000
#endif

/* Size of the CXL.cachemem Primary window used for Component registers */
#ifndef CXL_CACHEMEM_PRIMARY_SIZE
#define CXL_CACHEMEM_PRIMARY_SIZE       0x1000
#endif

/* ---- CXL Capability header dword (array form per 8.2.4/8.2.4.1) ----
   [15:0]  CapID
   [19:16] CapVersion (4 bits)
   [23:20] CXL.cachemem Version (only in the first header element at +0x00)
   [31:24] Size/Next (context-dependent)
*/
#define CXL_CAP_HDR_SIZE                0x04
#define CXL_CAP_HDR_CAPID(x)            ((uint16_t)((x) & 0xFFFF))
#define CXL_CAP_HDR_VER(x)              ((uint8_t)(((x) >> 16) & 0xF))
#define CXL_CAP_HDR_NEXT(x)             ((uint8_t)(((x) >> 24) & 0xFF))
#define CXL_CAP_HDR_PTR_SHIFT           20
#define CXL_CAP_HDR_PTR_MASK            0xFFFu
#define CXL_CAP_HDR_POINTER(x)          (((x) >> CXL_CAP_HDR_PTR_SHIFT) & CXL_CAP_HDR_PTR_MASK)
/* Cachemem version field present only in header element at +0x00 */
#define CXL_CAP_HDR_CACHEMEM_VER(x)     ((uint8_t)(((x) >> 20) & 0xF))
/* Number of entries in the primary component capability array (first dword @ +0x00) */
#define CXL_CAP_ARRAY_ENTRIES(x)        CXL_CAP_HDR_NEXT(x)

/* Known CXL Component Cap IDs (subset; print unknowns too) */
#define CXL_CAPID_COMPONENT_CAP         0x0001
#define CXL_CAPID_RAS                   0x0002
#define CXL_CAPID_SECURITY              0x0003
#define CXL_CAPID_LINK                  0x0004
#define CXL_CAPID_HDM_DECODER           0x0005
#define CXL_CAPID_BI_DECODER            0x000C
#define CXL_CAPID_EXT_SECURITY          0x0006
#define CXL_CAPID_IDE                   0x0007
#define CXL_CAPID_SNOOP_FILTER          0x0008

/* CXL Device Register Cap IDs you'll commonly see */
#define CXL_DEVCAPID_DEVICE_STATUS      0x0001
#define CXL_DEVCAPID_MAILBOX            0x0002
#define CXL_DEVCAPID_MEMORY_DEVICE_STS  0x4000  /* device-type dependent */

/* ---- CXL helper status codes (for VAL CXL helpers) ---- */
/* Status codes returned by BAR resolution helpers */
#define VAL_CXL_BAR_SUCCESS            0x00000000
#define VAL_CXL_BAR_ERR_INVALID_INDEX  0x00000001
#define VAL_CXL_BAR_ERR_CFG_READ       0x00000002
#define VAL_CXL_BAR_ERR_NOT_MMIO       0x00000003
#define VAL_CXL_BAR_ERR_ZERO           0x00000004

/* ---- CXL DVSEC header offsets and fields ---- */
#define CXL_DVSEC_HDR1_OFFSET          0x04
#define CXL_DVSEC_HDR2_OFFSET          0x08
#define CXL_DVSEC_HDR1_VENDOR_ID_MASK  0xFFFF
#define CXL_DVSEC_HDR1_REV_SHIFT       16
#define CXL_DVSEC_HDR1_REV_MASK        0xF
#define CXL_DVSEC_HDR1_LEN_SHIFT       20
#define CXL_DVSEC_HDR1_LEN_MASK        0xFFF
#define CXL_DVSEC_HDR2_ID_MASK         0xFFFF

#define CXL_DVSEC_CXL_CAPABILITY_OFFSET 0x0A
#define CXL_DVSEC_CXL_CAPABILITY_SHIFT  16
#define CXL_DVSEC_CXL_CAPABILITY_MASK   0xFFFFu
#define CXL_DVSEC_CXL_CAP_TSP_CAPABLE   (1u << 12)
#define CXL_DVSEC_CXL_CAP_CACHE_CAPABLE (1u << 0)
#define CXL_DVSEC_CXL_CAP_IO_CAPABLE    (1u << 1)
#define CXL_DVSEC_CXL_CAP_MEM_CAPABLE   (1u << 2)

/* ---- CXL DVSEC Device Control ---- */
#define CXL_DVSEC_CTRL_OFFSET           0x0C
#define CXL_DVSEC_MEM_ENABLE            (1u << 2)

/* ---- Arm RME-CDA DVSEC register layout ---- */
#define RMECDA_ECH_OFFSET               0x0u
#define RMECDA_ECH_ID                   0x0023u
#define RMECDA_ECH_CAP_VER              0x1u
#define RMECDA_HEAD1_OFFSET             0x4u
#define RMECDA_HEAD1_DVSEC_VID          0x13B5u
#define RMECDA_HEAD1_DVSEC_REV          0x0u
#define RMECDA_HEAD1_DVSEC_LENGTH       0x1Cu
#define RMECDA_HEAD2_OFFSET             0x8u
#define RMECDA_CTL1_OFFSET              0xCu
#define RMECDA_CTL2_OFFSET              0x10u
#define RMECDA_CTL3_OFFSET              0x14u
#define RMECDA_CTL4_OFFSET              0x18u

/* ---- CXL Register Locator entry fields (DW0) ---- */
#define CXL_RL_ENTRY_BIR_SHIFT         0
#define CXL_RL_ENTRY_BIR_MASK          0x7
#define CXL_RL_ENTRY_BLOCKID_SHIFT     8
#define CXL_RL_ENTRY_BLOCKID_MASK      0xFF

/* ---- CXL Device Register Block: Capabilities Array ---- */
#define CXL_DEV_CAP_ARR_HDR_OFFSET     0x0
#define CXL_DEV_CAP_ARR_COUNT_SHIFT    32
#define CXL_DEV_CAP_ARR_COUNT_MASK     0xFFFF
#define CXL_DEV_CAP_ARR_BASE_OFFSET    0x10
#define CXL_DEV_CAP_ELEM_SIZE          16
#define CXL_DEV_CAP_ARR_HDR_SIZE       8

/* Device Capabilities element (first 64-bit dword) fields */
#define CXL_DEV_CAP_ELEM_W0_ID_MASK       0xFFFF
#define CXL_DEV_CAP_ELEM_W0_VER_SHIFT     16
#define CXL_DEV_CAP_ELEM_W0_VER_MASK      0xFF
#define CXL_DEV_CAP_ELEM_W0_OFF_SHIFT     32
#define CXL_DEV_CAP_ELEM_W0_OFF_MASK      0xFFFFFFFFu
#define CXL_DEV_CAP_MAX_GUARD          64

#define CXL_DEVICE_CAP_DEVICE_TYPE_SHIFT   0
#define CXL_DEVICE_CAP_DEVICE_TYPE_MASK    0x7

/* ---- HDM Decoder capability offsets ---- */
#define CXL_HDM_CAP_REG_OFFSET              0x00
#define CXL_HDM_GLOBAL_CTRL_OFFSET          0x04
#define CXL_HDM_DECODER_STRIDE              0x20
#define CXL_HDM_DECODER_BASE_LOW(n)   (0x10 + (n) * CXL_HDM_DECODER_STRIDE)
#define CXL_HDM_DECODER_BASE_HIGH(n)  (0x14 + (n) * CXL_HDM_DECODER_STRIDE)
#define CXL_HDM_DECODER_SIZE_LOW(n)   (0x18 + (n) * CXL_HDM_DECODER_STRIDE)
#define CXL_HDM_DECODER_SIZE_HIGH(n)  (0x1C + (n) * CXL_HDM_DECODER_STRIDE)
#define CXL_HDM_DECODER_CTRL(n)       (0x20 + (n) * CXL_HDM_DECODER_STRIDE)
#define CXL_HDM_DECODER_TARGET_LOW(n) (0x24 + (n) * CXL_HDM_DECODER_STRIDE)
#define CXL_HDM_DECODER_TARGET_HIGH(n) (0x28 + (n) * CXL_HDM_DECODER_STRIDE)
#define CXL_HDM_COMMIT_BIT                (1u << 9)
#define CXL_HDM_COMMITTED_BIT             (1u << 10)
#define CXL_HDM_COMMIT_TIMEOUT_MS         20u

#define CXL_BI_DECODER_CAP_OFFSET      0x00
#define CXL_BI_DECODER_CTRL_OFFSET     0x04
#define CXL_BI_DECODER_STATUS_OFFSET   0x08

#define CXL_HDM_DECODER_COUNT_MASK          0xFu
#define CXL_HDM_DECODER_COUNT_SHIFT         0

/* ---- CXL Component Register Primary Array ---- */
#define CXL_COMPONENT_CAP_ARRAY_OFFSET 0x0

/* Other Register Block IDs */
#define CXL_REG_BLOCK_VENDOR_SPECIFIC   0xFF

/* ---- CXL Security Capability registers ---- */
#define CXL_SECURITY_POLICY_OFFSET              0x00u
#define CXL_SECURITY_POLICY_TRUST_LEVEL_MASK    0x3u
#define CXL_SECURITY_POLICY_TRUST_LEVEL_SHIFT   0
#define CXL_SECURITY_POLICY_BLOCK_HDM_DB        (1u << 2)

/* ---- CXL Extended Security Capability registers ---- */
#define CXL_EXT_SECURITY_COUNT_OFFSET           0x00u
#define CXL_EXT_SECURITY_COUNT_MASK             0xFFu
#define CXL_EXT_SECURITY_ENTRY_STRIDE           0x8u
#define CXL_EXT_SECURITY_POLICY_BASE            0x04u
#define CXL_EXT_SECURITY_PORT_ID_BASE           0x08u
#define CXL_EXT_SECURITY_PORT_ID_MASK           0xFFu

/* ---- CXL IDE Capability registers ---- */
#define CXL_IDE_REG_CAPABILITY                  0x00u
#define CXL_IDE_REG_CONTROL                     0x04u
#define CXL_IDE_REG_STATUS                      0x08u
#define CXL_IDE_REG_ERROR_STATUS                0x0Cu

#define CXL_IDE_CAP_CAPABLE                     (1u << 0)
#define CXL_IDE_CAP_MODE_SKID                   (1u << 1)
#define CXL_IDE_CAP_MODE_CONTAINMENT            (1u << 2)
#define CXL_IDE_CAP_SUPPORTED_ALGO_MASK         (0x1Fu << 17)
#define CXL_IDE_CAP_IDE_STOP_CAPABLE            (1u << 22)
#define CXL_IDE_CAP_LOPT_CAPABLE                (1u << 23)
#define CXL_IDE_STATUS_FIELD_MASK               0xFu
#define CXL_IDE_STATUS_TX_SHIFT                 4u
#define CXL_IDE_STATE_INSECURE                  0x4u

#endif /* __RME_ACS_CXL_SPEC_H__ */
