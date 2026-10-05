/** @file
 * Copyright (c) 2016-2022, 2024-2026, Arm Limited or its affiliates. All rights reserved.
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
/**
 * This file contains REFERENCE CODE for Exerciser PAL layer.
 * The API's and MACROS needs to be populate as per platform config.
**/

#ifndef __PAL_EXERCISER_H__
#define __PAL_EXERCISER_H__

#define EXERCISER_ID  0xED0113B5 //device id + vendor id
#define TEST_REG_COUNT 10
#define TEST_DDR_REGION_CNT 16

#define BUS_MEM_EN_MASK 0x06

#define PCIE_EXTRACT_BDF_SEG(bdf)  ((bdf >> 24) & 0xFF)
#define PCIE_EXTRACT_BDF_BUS(bdf)  ((bdf >> 16) & 0xFF)
#define PCIE_EXTRACT_BDF_DEV(bdf)  ((bdf >> 8) & 0xFF)
#define PCIE_EXTRACT_BDF_FUNC(bdf) (bdf & 0xFF)

#define PCIE_CREATE_BDF_PACKED(bdf)  PCIE_EXTRACT_BDF_FUNC(bdf) | \
                                    (PCIE_EXTRACT_BDF_DEV(bdf) << 3) | \
                                    (PCIE_EXTRACT_BDF_BUS(bdf) << 8)

/* PCIe Config space Offset */
#define BAR0_OFFSET        0x10
#define COMMAND_REG_OFFSET 0x04
#define CAP_PTR_OFFSET     0x34
#define PCIE_CAP_OFFSET    0x100

#define PCIE_CAP_CTRL_OFFSET 0x4// offset from the extended capability header

/* Exerciser MMIO Offsets */
#define INTXCTL       0x004
#define MSICTL        0x000
#define DMACTL1       0x08
#define DMA_BUS_ADDR  0x010
#define DMA_LEN       0x018
#define DMASTATUS     0x01C
#define PASID_VAL     0x020
#define ATSCTL        0x024
#define DMA_USE_ATC_ENTRY_MASK (1u << 9)
#define ATS_ADDR      0x028
#define ATS_REPLY     0x038
#define TXN_TRACE     0x40
#define TXN_CTRL_BASE 0x44
#define SEC_SID_CTL      0x94
#define CXL_CMD_OP       0x80
#define CXL_CMD_ADDR_LO  0x84
#define CXL_CMD_ADDR_HI  0x88
#define CXL_CMD_DATA0_LO 0x8C
#define CXL_CMD_DATA0_HI 0x90
#define PCI_MAX_BUS     255
#define PCI_MAX_DEVICE  31

#define DVSEC_CTRL     0x8
#define PCI_EXT_CAP_ID 0x10
#define PASID          0x1B
#define PCIE           0x1
#define PCI            0x0
#define DVSEC          0x0023
#define AER            0x0001

/* PCI/PCIe express extended capability structure's
   next capability pointer mask and cap ID mask */
#define PCIE_NXT_CAP_PTR_MASK 0x0FFF
#define PCIE_CAP_ID_MASK      0xFFFF
#define PCI_CAP_ID_MASK       0x00FF
#define PCI_NXT_CAP_PTR_MASK  0x00FF
#define CAP_PTR_MASK          0x00FF

#define CLR_INTR_MASK       0xFFFFFFFE
#define PASID_TLP_STOP_MASK 0xFFFFFFBF
#define PASID_VAL_MASK      ((0x1ul << 20) - 1)
#define PASID_VAL_SHIFT     12
#define PASID_LEN_SHIFT     7
#define PASID_LEN_MASK      0x7ul
#define PASID_EN_SHIFT      6
#define DMA_TO_DEVICE_MASK  0xFFFFFFEF

/* shift_bit */
#define SHIFT_1BIT             1
#define SHIFT_2BIT             2
#define SHIFT_4BIT             4
#define SHITT_8BIT             8
#define MASK_BIT               1
#define PREFETCHABLE_BIT_SHIFT 3
#define ERR_CODE_SHIFT         20
#define FATAL_SHIFT            31
#define ERROR_INJECT_BIT       17
#define CXL_SEC_SID_REALM       (1u << 1)
#define CXL_SEC_SID_VALID       (1u << 31)
#define CXL_CMD_OP_MASK         0xFu
#define CXL_CMD_STATUS_MASK     (0xFu << 8)
#define CXL_CMD_STATUS_DONE     (0x1u << 8)
#define CXL_CMD_STATUS_ERR      (0x2u << 8)
#define CXL_CMD_CLEAR_ERR       (1u << 30)
#define CXL_CMD_TRIGGER         (1u << 31)

#define PCI_CAP_PTR_OFFSET 8
#define PCIE_CAP_PTR_OFFSET 20

#define MSI_GENERATION_MASK     (1 << 31)

#define NO_SNOOP_START_MASK 0x20
#define NO_SNOOP_STOP_MASK  0xFFFFFFDF
#define PCIE_CAP_DIS_MASK 0xFFFEFFFF
#define PCIE_CAP_EN_MASK (1 << 16)
#define PASID_EN_MASK    (1 << 6)
#define RID_CTL_REG    0x3C
#define RID_VALUE_MASK 0xFFFF
#define RID_VALID_MASK (1ul << 31)
#define RID_VALID      1
#define RID_NOT_VALID  0
#define ATS_TRIGGER    1
#define ATS_INV        (1 << 5)
#define ATS_STATUS     (1ul << 7)
#define ATS_REQUEST_ATTR_T       (1u << 0)
#define ATS_REQUEST_ATTR_XT      (1u << 1)
#define ATS_REQUEST_T_MASK       (1u << 10)
#define ATS_REQUEST_XT_MASK      (1u << 11)
#define ATS_REQUEST_ATTR_REG_MASK (ATS_REQUEST_T_MASK | ATS_REQUEST_XT_MASK)
#define TXN_INVALID    0xFFFFFFFF
#define TXN_START      1
#define TXN_STOP       0

typedef enum {
    TYPE0 = 0x0,
    TYPE1 = 0x1,
} EXERCISER_CFG_HEADER_TYPE;

typedef enum {
    CFG_READ   = 0x0,
    CFG_WRITE  = 0x1,
} EXERCISER_CFG_TXN_ATTR;

typedef enum {
    EDMA_NO_SUPPORT   = 0x0,
    EDMA_COHERENT     = 0x1,
    EDMA_NOT_COHERENT = 0x2,
    EDMA_FROM_DEVICE  = 0x3,
    EDMA_TO_DEVICE    = 0x4
} EXERCISER_DMA_ATTR;

typedef enum {
    SNOOP_ATTRIBUTES = 0x1,
    LEGACY_IRQ       = 0x2,
    MSIX_ATTRIBUTES  = 0x3,
    DMA_ATTRIBUTES   = 0x4,
    P2P_ATTRIBUTES   = 0x5,
    PASID_ATTRIBUTES = 0x6,
    CFG_TXN_ATTRIBUTES = 0x7,
    ATS_RES_ATTRIBUTES = 0x8,
    TRANSACTION_TYPE  = 0x9,
    NUM_TRANSACTIONS  = 0xA,
    ADDRESS_ATTRIBUTES = 0xB,
    DATA_ATTRIBUTES = 0xC,
    ERROR_INJECT_TYPE = 0xD,
    EXERCISER_CXL_CMD_OP = 0x11,
    EXERCISER_CXL_CMD_ADDR = 0x12,
    EXERCISER_CXL_CMD_DATA0 = 0x13,
    EXERCISER_SEC_SID = 0x15,
    EXERCISER_ATS_REQUEST_ATTRIBUTES = 0x16,
    TRANSACTION_RECORD = 0x17
} EXERCISER_PARAM_TYPE;

#define EXERCISER_TXN_ATTR_READ              (1u << 1)
#define EXERCISER_TXN_ATTR_CONFIG            (1u << 2)
#define EXERCISER_TXN_ATTR_CACHE_MAINTENANCE (1u << 3)
#define EXERCISER_TXN_ATTR_SNOOP             (1u << 4)

typedef enum {
    TXN_REQ_ID     = 0x0,
    TXN_ADDR_TYPE  = 0x1,
    TXN_REQ_ID_VALID    = 0x2,
    TXN_ATC_ENTRY       = 0x3,
} EXERCISER_TXN_ATTR;

typedef enum {
    ATC_ENTRY_DISABLE = 0x0,
    ATC_ENTRY_ENABLE  = 0x1
} EXERCISER_TXN_ATC_ENTRY;

typedef enum {
    AT_UNTRANSLATED = 0x0,
    AT_TRANS_REQ    = 0x1,
    AT_TRANSLATED   = 0x2,
    AT_RESERVED     = 0x3
} EXERCISER_TXN_ADDR_TYPE;

typedef enum {
    EXERCISER_RESET = 0x1,
    EXERCISER_ON    = 0x2,
    EXERCISER_OFF   = 0x3,
    EXERCISER_ERROR = 0x4
} EXERCISER_STATE;

typedef enum {
    START_DMA     = 0x1,
    GENERATE_MSI  = 0x2,
    GENERATE_L_INTR = 0x3,  //Legacy interrupt
    MEM_READ      = 0x4,
    MEM_WRITE     = 0x5,
    CLEAR_INTR    = 0x6,
    PASID_TLP_START = 0x7,
    PASID_TLP_STOP  = 0x8,
    TXN_NO_SNOOP_ENABLE  = 0x9,
    TXN_NO_SNOOP_DISABLE = 0xa,
    START_TXN_MONITOR    = 0xb,
    STOP_TXN_MONITOR     = 0xc,
    ATS_TXN_REQ          = 0xd,
    INJECT_ERROR         = 0xe,
    ATS_INV_CACHE        = 0xf,
    CXL_CMD_START        = 0x10
} EXERCISER_OPS;

#define CXL_CMD_OP_BACKDOOR_READ64           0x1u
#define CXL_CMD_OP_BACKDOOR_WRITE64          0x2u
#define CXL_CMD_OP_BISNP                     0x3u
#define CXL_CMD_OP_DCM_CACHE_DIRTY           0x4u
#define CXL_CMD_OP_DCM_SET_REALM_ASSIGNMENT  0x6u
#define CXL_CMD_OP_DCM_CACHE_WRITEBACK       0x8u
/* data[15:0] selects the response MECID; data[16] enables the override. */
#define CXL_CMD_OP_SNOOP_RESPONSE_MECID      0x9u
#define CXL_SNOOP_RESPONSE_MECID_VALID       (1u << 16)
#define CXL_SNOOP_RESULT_VALID                (1u << 0)
#define CXL_SNOOP_RESULT_EMITTED              (1u << 1)
#define CXL_SNOOP_RESULT_BLOCKED              (1u << 2)
/* Normalized PAL observations, not architectural host-port register bits. */
#define CXL_SNOOP_RESULT_HOST_ACCEPTED         (1u << 3)
#define CXL_SNOOP_RESULT_HOST_REJECTED         (1u << 4)

typedef enum {
    ACCESS_TYPE_RD = 0x0,
    ACCESS_TYPE_RW = 0x1
} ECAM_REG_ATTRIBUTE;

struct ecam_reg_data {
    UINT32 offset;    //Offset into 4096 bytes ecam config reg space
    UINT32 attribute;
    UINT32 value;
};

struct exerciser_data_cfg_space {
    struct ecam_reg_data reg[TEST_REG_COUNT];
};

typedef enum {
    DEVICE_nGnRnE = 0x0,
    DEVICE_nGnRE  = 0x1,
    DEVICE_nGRE   = 0x2,
    DEVICE_GRE    = 0x3
} ARM_DEVICE_MEM;

typedef enum {
    NORMAL_NC = 0x4,
    NORMAL_WT = 0x5
} ARM_NORMAL_MEM;

typedef enum {
    MMIO_PREFETCHABLE = 0x0,
    MMIO_NON_PREFETCHABLE = 0x1
} BAR_MEM_TYPE;

struct exerciser_data_bar_space {
    void *base_addr;
    BAR_MEM_TYPE type;
};

typedef union exerciser_data {
    struct exerciser_data_cfg_space cfg_space;
    struct exerciser_data_bar_space bar_space;
} exerciser_data_t;

typedef enum {
    EXERCISER_DATA_CFG_SPACE = 0x1,
    EXERCISER_DATA_BAR0_SPACE = 0x2,
    EXERCISER_DATA_MMIO_SPACE = 0x3,
} EXERCISER_DATA_TYPE;

typedef enum {
    CORR_RCVR_ERR = 0x0,
    CORR_BAD_TLP  = 0x1,
    CORR_BAD_DLLP = 0x2,
    CORR_RPL_NUM_ROLL = 0x3,
    CORR_RPL_TMR_TIMEOUT = 0x4,
    CORR_ADV_NF_ERR = 0x5,
    CORR_INT_ERR = 0x6,
    CORR_HDR_LOG_OVRFL = 0x7,
    UNCORR_DL_ERROR = 0x8,
    UNCORR_SD_ERROR = 0x9,
    UNCORR_PTLP_REC = 0xA,
    UNCORR_FL_CTRL_ERR = 0xB,
    UNCORR_CMPT_TO = 0xC,
    UNCORR_AMPT_ABORT = 0xD,
    UNCORR_UNEXP_CMPT = 0xE,
    UNCORR_RCVR_ERR = 0xF,
    UNCORR_MAL_TLP = 0x10,
    UNCORR_ECRC_ERR = 0x11,
    UNCORR_UR = 0x12,
    UNCORR_ACS_VIOL = 0x13,
    UNCORR_INT_ERR = 0x14,
    UNCORR_MC_BLK_TLP = 0x15,
    UNCORR_ATOP_EGR_BLK = 0x16,
    UNCORR_TLP_PFX_EGR_BLK = 0x17,
    UNCORR_PTLP_EGR_BLK = 0x18,
    INVALID_CFG = 0x19
} EXERCISER_ERROR_CODE;

UINT32 pal_mmio_read(UINT64 addr);
UINT64 pal_mmio_read64(UINT64 addr);
VOID pal_mmio_write(UINT64 addr, UINT32 data);
VOID pal_mmio_write64(UINT64 addr, UINT64 data);
UINT64 pal_pcie_get_mcfg_ecam();
UINT64 pal_exerciser_get_pcie_config_offset(UINT32 Bdf);
UINT32 pal_exerciser_find_pcie_capability(UINT32 ID, UINT32 Bdf, UINT32 Value, UINT32 *Offset);
UINT32 pal_exerciser_set_param(EXERCISER_PARAM_TYPE Type, UINT64 Value1, UINT64 Value2, UINT32 Bdf);
UINT32 pal_exerciser_get_param(EXERCISER_PARAM_TYPE Type, UINT64 *Value1, UINT64 *Value2, UINT32 Bdf);
UINT32 pal_exerciser_set_state(EXERCISER_STATE State, UINT64 *Value, UINT32 Bdf);
UINT32 pal_exerciser_get_state(EXERCISER_STATE *State, UINT32 Bdf);
UINT32 pal_exerciser_ops(EXERCISER_OPS Ops, UINT64 Param, UINT32 Bdf);
UINT32 pal_cda_tdi_snoop_attempt(UINT32 Bdf, UINT64 TargetHpa,
                                 UINT32 PasRealm, UINT32 *Result);
#define PAL_CDA_SNOOP_SUCCESS     0u
#define PAL_CDA_SNOOP_UNSUPPORTED 1u
#define PAL_CDA_SNOOP_ERROR       2u
UINT32 pal_cda_host_snoop_prepare(UINT32 RootBdf, UINT32 EndpointBdf,
                                   UINT64 PermittedHpa, UINT64 UnknownHpa);
UINT32 pal_cda_host_snoop_trigger(UINT32 EndpointBdf, UINT64 TargetHpa);
UINT32 pal_cda_host_snoop_restore(UINT32 EndpointBdf);
UINT32 pal_exerciser_get_data(EXERCISER_DATA_TYPE Type, exerciser_data_t *Data, UINT32 Bdf, UINT64 Ecam);

#endif
