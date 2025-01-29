/** @file
 * Copyright (c) 2025, Arm Limited or its affiliates. All rights reserved.
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
#ifndef __SMMU_V3_H__
#define __SMMU_V3_H__

#include <val_el3/ack_include.h>

#define BITFIELD_DECL(type, name, msb, lsb) \
    const uint32_t name##_SHIFT = lsb; \
    const type name##_MASK = ((((type)0x1) << (msb - lsb + 1)) - 1);

#define BITFIELD_GET(name, val) ((val >> name##_SHIFT) & name##_MASK)
#define BITFIELD_SET(name, val) ((val & name##_MASK) << name##_SHIFT)

BITFIELD_DECL(uint32_t, IDR5_OAS, 2, 0)
uint32_t smmu_oas[SMMU_OAS_MAX_IDX] = {32, 36, 40, 42, 44, 48, 52};

#define CMDQ_OP_PREFETCH_CFG 0x1
#define CMDQ_OP_CFGI_STE 0x3
#define CMDQ_OP_CFGI_ALL 0x4
#define CMDQ_OP_TLBI_EL2_ALL 0x20
#define CMDQ_OP_TLBI_NSNH_ALL 0x30
#define CMDQ_OP_CMD_SYNC 0x46

#define BYTES_PER_DWORD 8

BITFIELD_DECL(uint32_t, IDR0_ST_LEVEL, 28, 27)
#define SMMU_IDR0_OFFSET 0x0
#define IDR0_ST_LEVEL_2LVL 1
#define IDR0_CD2L (1 << 19)
#define IDR0_HYP (1 << 9)
#define IDR0_COHACC (1 << 4)

BITFIELD_DECL(uint32_t, IDR0_TTF, 3, 2)
#define IDR0_TTF_AARCH64 2
#define IDR0_TTF_AARCH32_64 3
#define IDR0_S1P (1 << 1)
#define IDR0_S2P (1 << 0)

#define SMMU_IDR1_OFFSET 0x4
#define IDR1_TABLES_PRESET (1 << 30)
#define IDR1_QUEUES_PRESET (1 << 29)
#define IDR1_REL (1 << 28)
BITFIELD_DECL(uint32_t, IDR1_CMDQS, 25, 21)
BITFIELD_DECL(uint32_t, IDR1_SSIDSIZE, 10, 6)
BITFIELD_DECL(uint32_t, IDR1_SIDSIZE, 5, 0)

#define SMMU_CR0_OFFSET 0x20
#define CR0_EVENTQEN (1 << 2)
#define CR0_CMDQEN (1 << 3)
#define CR0_SMMUEN (1 << 0)

#define SMMU_CR0ACK_OFFSET 0x24

#define SMMU_CR1_OFFSET 0x28

#define ENABLE_E2H (1 << 0)

#define SMMU_AIDR_OFFSET 0x1C

#define SMMU_R_PAGE_0_OFFSET 	0x40000
#define SMMU_R_PAGE_1_OFFSET 	0x50000

/*Registers in Realm Page 0*/
#define SMMU_R_IDR0		(SMMU_R_PAGE_0_OFFSET + 0x0000)
#define SMMU_R_IDR1		(SMMU_R_PAGE_0_OFFSET + 0x0004)
#define SMMU_R_IDR2		(SMMU_R_PAGE_0_OFFSET + 0x0008)
#define SMMU_R_IDR3		(SMMU_R_PAGE_0_OFFSET + 0x000C)
#define SMMU_R_IDR4		(SMMU_R_PAGE_0_OFFSET + 0x0010)
#define SMMU_R_AIDR		(SMMU_R_PAGE_0_OFFSET + 0x001C)
#define SMMU_R_CR0		(SMMU_R_PAGE_0_OFFSET + 0x0020)
#define SMMU_R_CR0ACK		(SMMU_R_PAGE_0_OFFSET + 0x0024)
#define SMMU_R_CR1		(SMMU_R_PAGE_0_OFFSET + 0x0028)
#define SMMU_R_CR2		(SMMU_R_PAGE_0_OFFSET + 0x002C)
#define SMMU_R_GBPA		(SMMU_R_PAGE_0_OFFSET + 0x0044)
#define SMMU_R_AGBPA		(SMMU_R_PAGE_0_OFFSET + 0x0048)
#define SMMU_R_IRQ_CTRL		(SMMU_R_PAGE_0_OFFSET + 0x0050)
#define SMMU_R_IRQ_CTRLACK	(SMMU_R_PAGE_0_OFFSET + 0x0054)
#define SMMU_R_GERROR		(SMMU_R_PAGE_0_OFFSET + 0x0060)
#define SMMU_R_GERRORN		(SMMU_R_PAGE_0_OFFSET + 0x0064)
#define SMMU_R_GERROR_IRQ_CFG0	(SMMU_R_PAGE_0_OFFSET + 0x0068)
#define SMMU_R_GERROR_IRQ_CFG1	(SMMU_R_PAGE_0_OFFSET + 0x0070)
#define SMMU_R_GERROR_IRQ_CFG2	(SMMU_R_PAGE_0_OFFSET + 0x0074)
#define SMMU_R_STRTAB_BASE	(SMMU_R_PAGE_0_OFFSET + 0x0080)
#define SMMU_R_STRTAB_BASE_CFG	(SMMU_R_PAGE_0_OFFSET + 0x0088)
#define SMMU_R_CMDQ_BASE	(SMMU_R_PAGE_0_OFFSET + 0x0090)
#define SMMU_R_CMDQ_PROD	(SMMU_R_PAGE_0_OFFSET + 0x0098)
#define SMMU_R_CMDQ_CONS	(SMMU_R_PAGE_0_OFFSET + 0x009C)
#define SMMU_R_EVTQ_BASE	(SMMU_R_PAGE_0_OFFSET + 0x00A0)
#define SMMU_R_EVTQ_IRQ_CFG0	(SMMU_R_PAGE_0_OFFSET + 0x00B0)
#define SMMU_R_EVENTQ_IRQ_CFG1	(SMMU_R_PAGE_0_OFFSET + 0x00B8)
#define SMMU_R_EVENTQ_IRQ_CFG2	(SMMU_R_PAGE_0_OFFSET + 0x00BC)
#define SMMU_R_PRIQ_BASE	(SMMU_R_PAGE_0_OFFSET + 0x00C0)
#define SMMU_R_PRIQ_IRQ_CFG0	(SMMU_R_PAGE_0_OFFSET + 0x00D0)
#define SMMU_R_PRIQ_IRQ_CFG1	(SMMU_R_PAGE_0_OFFSET + 0x00D8)
#define SMMU_R_PRIQ_IRQ_CFG2	(SMMU_R_PAGE_0_OFFSET + 0x00DC)
#define SMMU_R_MPAMIDR		(SMMU_R_PAGE_0_OFFSET + 0x0130)
#define SMMU_R_GMPAM		(SMMU_R_PAGE_0_OFFSET + 0x0138)

#define SMMU_R_IDR6		(SMMU_R_PAGE_0_OFFSET + 0x0190)
#define SMMU_R_DPT_BASE		(SMMU_R_PAGE_0_OFFSET + 0x0200)
#define SMMU_R_DPT_BASE_CFG	(SMMU_R_PAGE_0_OFFSET + 0x0208)
#define SMMU_R_DPT_CFG_FAR	(SMMU_R_PAGE_0_OFFSET + 0x0210)
#define SMMU_R_MECIDR		(SMMU_R_PAGE_0_OFFSET + 0x0220)
#define SMMU_R_GMECID		(SMMU_R_PAGE_0_OFFSET + 0x0228)

/*Registers in Realm Page 1*/
#define SMMU_R_EVTQ_PROD  	(SMMU_R_PAGE_1_OFFSET + 0x00A8)
#define SMMU_R_EVTQ_CONS	(SMMU_R_PAGE_1_OFFSET + 0x00AC)
#define SMMU_R_PRIQ_PROD	(SMMU_R_PAGE_1_OFFSET + 0x00C8)
#define SMMU_R_PRIQ_CONS	(SMMU_R_PAGE_1_OFFSET + 0x00CC)

/* R_IR0 features */
#define ATS_SHIFT		UL(10)
#define MSI_SHIFT		UL(13)
#define PRI_SHIFT		UL(16)

/* R_IR3 features */
#define DPT_SHIFT		UL(15)
#define MEC_SHIFT		UL(16)

#define SMMUV3_FEAT_R_ATS	UL(1 << 1)
#define SMMUV3_FEAT_R_MSI	UL(1 << 2)
#define SMMUV3_FEAT_R_PRI	UL(1 << 3)
#define SMMUV3_FEAT_R_MEC	UL(1 << 4)

/* R_AIDR features */
#define ARCH_REV_SHIFT 		UL(0)
#define ARCH_REV_WIDTH 		UL(8)

#define MASK(regfield) \
        ((~0UL >> (64UL - (regfield##_WIDTH))) << (regfield##_SHIFT))

#define EXTRACT_BIT(regfield, reg) \
        (((reg) >> (regfield##_SHIFT)) & UL(1))

#define EXTRACT(regfield, reg) \
        (((reg) & MASK(regfield)) >> (regfield##_SHIFT))

BITFIELD_DECL(uint32_t, CR1_TABLE_SH, 11, 10)
BITFIELD_DECL(uint32_t, CR1_TABLE_OC, 9, 8)
BITFIELD_DECL(uint32_t, CR1_TABLE_IC, 7, 6)
BITFIELD_DECL(uint32_t, CR1_QUEUE_SH, 5, 4)
BITFIELD_DECL(uint32_t, CR1_QUEUE_OC, 3, 2)
BITFIELD_DECL(uint32_t, CR1_QUEUE_IC, 1, 0)
#define CR1_CACHE_NC 0
#define CR1_CACHE_WB 1
#define CR1_CACHE_WT 2

#define SMMU_CR2_OFFSET 0x2c
#define SMMU_GERROR_OFFSET 0x60

#define SMMU_STRTAB_BASE_OFFSET 0x80
#define STRTAB_BASE_RA (1UL << 62)
BITFIELD_DECL(uint64_t, STRTAB_BASE_ADDR, 51, 6)

#define SMMU_STRTAB_BASE_CFG_OFFSET 0x88
BITFIELD_DECL(uint32_t, STRTAB_BASE_CFG_FMT, 17, 16)
#define STRTAB_BASE_CFG_FMT_LINEAR 0
#define STRTAB_BASE_CFG_FMT_2LVL 1
BITFIELD_DECL(uint32_t, STRTAB_BASE_CFG_SPLIT, 10, 6)
BITFIELD_DECL(uint32_t, STRTAB_BASE_CFG_LOG2SIZE, 5, 0)

#define SMMU_SH_NSH 0
#define SMMU_SH_OSH 2
#define SMMU_SH_ISH 3
#define SMMU_MEMATTR_DEVICE_nGnRE 0x1
#define SMMU_MEMATTR_OIWB 0xf

#define QUEUE_BASE_RWA (1UL << 62)
BITFIELD_DECL(uint64_t, QUEUE_BASE_ADDR, 51, 5)
BITFIELD_DECL(uint64_t, QUEUE_BASE_LOG2SIZE, 4, 0)

#define STRTAB_L1_SZ_SHIFT 20
#define STRTAB_SPLIT 8

#define STRTAB_L1_DESC_DWORDS 1
#define STRTAB_L1_DESC_SIZE 8
BITFIELD_DECL(uint64_t, STRTAB_L1_DESC_SPAN, 4, 0)
BITFIELD_DECL(uint64_t, STRTAB_L1_DESC_L2PTR, 51, 6)

#define STRTAB_STE_DWORDS 8
#define STRTAB_STE_0_V (1UL << 0)
BITFIELD_DECL(uint64_t, STRTAB_STE_0_CONFIG, 3, 1)
#define STRTAB_STE_0_CONFIG_ABORT 0
#define STRTAB_STE_0_CONFIG_BYPASS 4
#define STRTAB_STE_0_CONFIG_S1_TRANS 5
#define STRTAB_STE_0_CONFIG_S2_TRANS 6

BITFIELD_DECL(uint64_t, STRTAB_STE_0_S1FMT, 5, 4)
#define STRTAB_STE_0_S1FMT_LINEAR 0
#define STRTAB_STE_0_S1FMT_64K_L2 2
BITFIELD_DECL(uint64_t, STRTAB_STE_0_S1CONTEXTPTR, 51, 6)
BITFIELD_DECL(uint64_t, STRTAB_STE_0_S1CDMAX, 63, 59)

#define STRTAB_STE_1_S1DSS_SSID0   0x2
#define STRTAB_STE_1_S1C_CACHE_NC 0UL
#define STRTAB_STE_1_S1C_CACHE_WBRA 1UL
BITFIELD_DECL(uint64_t, STRTAB_STE_1_S1DSS, 1, 0)
BITFIELD_DECL(uint64_t, STRTAB_STE_1_S1CIR, 3, 2)
BITFIELD_DECL(uint64_t, STRTAB_STE_1_S1COR, 5, 4)
BITFIELD_DECL(uint64_t, STRTAB_STE_1_S1CSH, 7, 6)
BITFIELD_DECL(uint64_t, STRTAB_STE_1_EATS, 29, 28)
BITFIELD_DECL(uint64_t, STRTAB_STE_1_STRW, 31, 30)
#define STRTAB_STE_1_STRW_NSEL1 0UL
#define STRTAB_STE_1_STRW_EL2 2UL
BITFIELD_DECL(uint64_t, STRTAB_STE_1_SHCFG, 45, 44)
#define STRTAB_STE_1_SHCFG_INCOMING 1UL

BITFIELD_DECL(uint64_t, STRTAB_STE_2_S2VMID, 15, 0)
BITFIELD_DECL(uint64_t, STRTAB_STE_2_VTCR, 50, 32)
BITFIELD_DECL(uint64_t, STRTAB_STE_2_VTCR_S2T0SZ, 5, 0)
BITFIELD_DECL(uint64_t, STRTAB_STE_2_VTCR_S2SL0, 7, 6)
BITFIELD_DECL(uint64_t, STRTAB_STE_2_VTCR_S2IR0, 9, 8)
BITFIELD_DECL(uint64_t, STRTAB_STE_2_VTCR_S2OR0, 11, 10)
BITFIELD_DECL(uint64_t, STRTAB_STE_2_VTCR_S2SH0, 13, 12)
BITFIELD_DECL(uint64_t, STRTAB_STE_2_VTCR_S2TG, 15, 14)
BITFIELD_DECL(uint64_t, STRTAB_STE_2_VTCR_S2PS, 18, 16)

#define STRTAB_STE_2_S2AA64 (1UL << 51)
#define STRTAB_STE_2_S2PTW (1UL << 54)
#define STRTAB_STE_2_S2R (1UL << 58)

BITFIELD_DECL(uint64_t, STRTAB_STE_3_S2TTB, 51, 4)

#define QUEUE_DWORDS_PER_ENT 2
BITFIELD_DECL(uint64_t, CMDQ_0_OP, 7, 0)
BITFIELD_DECL(uint64_t, CMDQ_CFGI_1_RANGE, 4, 0)
#define CMDQ_CFGI_1_ALL_STES 31
#define CMD_SID_SHIFT 		 U(32)
#define CMD_SID_MASK 		 0xFFFFFFFF

#define SMMU_CMDQ_POLL_TIMEOUT 0x100000

#define CDTAB_SPLIT			10
#define CDTAB_L2_ENTRY_COUNT	(1 << CDTAB_SPLIT)

#define CDTAB_L1_DESC_DWORDS	1
#define CDTAB_L1_DESC_V			(1UL << 0)
BITFIELD_DECL(uint64_t, CDTAB_L1_DESC_L2PTR, 51, 12)

#define CDTAB_CD_DWORDS		8
BITFIELD_DECL(uint64_t, CDTAB_CD_0_TCR_T0SZ, 5, 0)
BITFIELD_DECL(uint64_t, CDTAB_CD_0_TCR_TG0, 7, 6)
BITFIELD_DECL(uint64_t, CDTAB_CD_0_TCR_IRGN0, 9, 8)
BITFIELD_DECL(uint64_t, CDTAB_CD_0_TCR_ORGN0, 11, 10)
BITFIELD_DECL(uint64_t, CDTAB_CD_0_TCR_SH0, 13, 12)
#define CDTAB_CD_0_TCR_EPD0	(1ULL << 14)
#define CDTAB_CD_0_TCR_EPD1	(1ULL << 30)

#define CDTAB_CD_0_ENDI		(1UL << 15)
#define CDTAB_CD_0_V		(1UL << 31)

BITFIELD_DECL(uint64_t, CDTAB_CD_0_TCR_IPS, 34, 32)
#define CDTAB_CD_0_AA64		(1UL << 41)
#define CDTAB_CD_0_R		(1UL << 45)
#define CDTAB_CD_0_A		(1UL << 46)
#define CDTAB_CD_0_ASET		(1UL << 47)
BITFIELD_DECL(uint64_t, CDTAB_CD_0_ASID, 63, 48)

BITFIELD_DECL(uint64_t, CDTAB_CD_1_TTB0, 51, 4)

typedef struct {
    uint32_t prod;
    uint32_t cons;
    uint32_t log2nent;
} smmu_queue_t;

typedef struct {
    smmu_queue_t queue;
    void    *base_ptr;
    uint8_t *base;
    uint64_t base_phys;
    uint64_t queue_base;
    uint64_t entry_size;
    uint32_t *prod_reg;
    uint32_t *cons_reg;
} smmu_queue_type_t;

typedef struct {
    uint8_t  span;
    void     *l2ptr;
    uint64_t *l2desc64;
    uint64_t l2desc_phys;
} smmu_strtab_l1_desc_t;

typedef struct {
    uint16_t vmid;
    uint64_t vttbr;
    uint64_t vtcr;
} smmu_stage2_config_t;

typedef struct {
    uint16_t    asid;
    uint64_t    ttbr;
    uint64_t    tcr;
    uint64_t    mair;
} smmu_cdtab_ctx_desc_t;

typedef struct {
    void     *l2ptr;
    uint64_t *l2desc64;
    uint64_t l2desc_phys;
} smmu_cdtab_l1_ctx_desc_t;

typedef struct {
    void                           *cdtab_ptr;
    uint64_t                       *cdtab64;
    uint64_t                       cdtab_phys;
    smmu_cdtab_l1_ctx_desc_t       *l1_desc;
    unsigned int                   l1_ent_count;
} smmu_cdtab_config_t;

typedef struct {
    smmu_cdtab_config_t             cdcfg;
    smmu_cdtab_ctx_desc_t        cd;
    uint8_t                         s1fmt;
    uint8_t                         s1cdmax;
} smmu_stage1_config_t;

typedef struct {
    void     *strtab_ptr;
    uint64_t *strtab64;
    uint64_t strtab_phys;
    smmu_strtab_l1_desc_t *l1_desc;
    uint32_t l1_ent_count;
    uint64_t strtab_base;
    uint32_t strtab_base_cfg;
} smmu_strtab_config_t;

typedef struct {
    uint64_t base;
    uint64_t ias;
    uint64_t oas;
    uint32_t ssid_bits;
    uint32_t sid_bits;
    smmu_queue_type_t cmd_type;
    smmu_queue_type_t evnt_type;
    smmu_strtab_config_t strtab_cfg;
    union {
        struct {
           uint32_t st_level_2lvl:1;
           uint32_t cd2l:1;
           uint32_t hyp:1;
           uint32_t s1p:1;
           uint32_t s2p:1;
        };
        uint32_t bitmap;
    } supported;
} smmu_dev_t;

typedef enum {
    SMMU_STAGE_S1 = 0,
    SMMU_STAGE_S2,
    SMMU_STAGE_BYPASS
} smmu_stage_t;

typedef struct {
#define MAX_PAGE_TABLES_PER_MASTER 8
    smmu_dev_t *smmu;
    smmu_stage_t stage;
    smmu_stage1_config_t stage1_config;
    smmu_stage2_config_t stage2_config;
    uint32_t sid;
    uint32_t ssid;
    uint32_t ssid_bits;
} smmu_master_t;

#endif /*__SMMU_V3_H__ */
