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

#ifndef __RME_ACS_PE_H__
#define __RME_ACS_PE_H__

#include "pal_interface.h"

#define ul(x) ((unsigned long)(x))

#define MAX_NUM_PE               (2 << 27)

#define MPIDR_AFF_MASK           (0xFF00FFFFFF)

#define INPLACE(regfield, val) \
        (((val) + ul(0)) << (regfield##_SHIFT))

#define MASK(regfield) \
        ((~0ul >> (64ul - (regfield##_WIDTH))) << (regfield##_SHIFT))


/* MPIDR macros */
#define PAL_MPIDR_AFFLVL_MASK    0xffull
#define PAL_MPIDR_AFFINITY_BITS  8
#define PAL_MPIDR_AFF0_SHIFT     0
#define PAL_MPIDR_AFF1_SHIFT     8u
#define PAL_MPIDR_AFF2_SHIFT     16u
#define PAL_MPIDR_AFF3_SHIFT     32u
#define PAL_MPIDR_AFFLVL0        0x0ull
#define PAL_MPIDR_AFFLVL1        0x1ull
#define PAL_MPIDR_AFFLVL2        0x2ull
#define PAL_MPIDR_AFFLVL3        0x3ull
#define PAL_MPIDR_AFFINITY_MASK ((PAL_MPIDR_AFFLVL_MASK << PAL_MPIDR_AFF3_SHIFT) | \
                 (PAL_MPIDR_AFFLVL_MASK << PAL_MPIDR_AFF2_SHIFT) | \
                 (PAL_MPIDR_AFFLVL_MASK << PAL_MPIDR_AFF1_SHIFT) | \
                 (PAL_MPIDR_AFFLVL_MASK << PAL_MPIDR_AFF0_SHIFT))

#define PAL_INVALID_MPID        0xFFFFFFFFu

//
//  AARCH64 processor exception types.
//
#define EXCEPT_AARCH64_SYNCHRONOUS_EXCEPTIONS    0
#define EXCEPT_AARCH64_IRQ                       1
#define EXCEPT_AARCH64_FIQ                       2
#define EXCEPT_AARCH64_SERROR                    3

// AArch64 Exception Level
#define AARCH64_EL2  0x8
#define AARCH64_EL1  0x4
#define AARCH64_EL_MASK (0x3ull << 2)

#define AARCH64_HCR_E2H_MASK (0x1ull << 34)
#define AARCH64_HCR_VM_MASK  (0x1ull << 0)
#define AARCH64_TTBR_ADDR_MASK (((0x1ull << 47) - 1) << 1)
#define RME_TCR_TG1_SHIFT   30
#define RME_TCR_SH1_SHIFT   28
#define RME_TCR_ORGN1_SHIFT 26
#define RME_TCR_IRGN1_SHIFT 24
#define RME_TCR_T1SZ_SHIFT  16

#define RME_TCR_TG1_MASK   (0x3ull << RME_TCR_TG1_SHIFT)
#define RME_TCR_SH1_MASK   (0x3ull << RME_TCR_SH1_SHIFT)
#define RME_TCR_ORGN1_MASK (0x3ull << RME_TCR_ORGN1_SHIFT)
#define RME_TCR_IRGN1_MASK (0x3ull << RME_TCR_IRGN1_SHIFT)
#define RME_TCR_T1SZ_MASK  (0x3full << RME_TCR_T1SZ_SHIFT)

#define RME_TCR_TG0_SHIFT   14
#define RME_TCR_SH0_SHIFT   12
#define RME_TCR_ORGN0_SHIFT 10
#define RME_TCR_IRGN0_SHIFT 8
#define RME_TCR_T0SZ_SHIFT  0

#define RME_TCR_TG0_MASK    (0x3ull << RME_TCR_TG0_SHIFT)
#define RME_TCR_SH0_MASK    (0x3ull << RME_TCR_SH0_SHIFT)
#define RME_TCR_ORGN0_MASK  (0x3ull << RME_TCR_ORGN0_SHIFT)
#define RME_TCR_IRGN0_MASK  (0x3ull << RME_TCR_IRGN0_SHIFT)
#define RME_TCR_T0SZ_MASK   (0x3full << RME_TCR_T0SZ_SHIFT)

#define RME_TCR_IPS_SHIFT  32
#define RME_TCR_IPS_MASK   (0x7ull << RME_TCR_IPS_SHIFT)
#define RME_TCR_PS_SHIFT   16
#define RME_TCR_PS_MASK    (0x7ull << RME_TCR_PS_SHIFT)

#define RME_MIN_TG4_SHIFT  28
#define RME_MIN_TG16_SHIFT 24

#define RME_MIN_TG4_MASK   (0xfull << RME_MIN_TG4_SHIFT)
#define RME_MIN_TG16_MASK  (0xfull << RME_MIN_TG16_SHIFT)

#define VTCR_IRGN0_SHIFT        8
#define VTCR_IRGN0_WIDTH        2
#define VTCR_IRGN0_WBRAWA       INPLACE(VTCR_IRGN0, ul(1))

#define VTCR_ORGN0_SHIFT        10
#define VTCR_ORGN0_WIDTH        2
#define VTCR_ORGN0_WBRAWA       INPLACE(VTCR_ORGN0, ul(1))

#define VTCR_SH0_SHIFT          12
#define VTCR_SH0_WIDTH          2
#define VTCR_SH0_IS             INPLACE(VTCR_SH0, ul(3))

#define VTCR_TG0_SHIFT          14
#define VTCR_TG0_WIDTH          2
#define VTCR_TG0_4K             INPLACE(VTCR_TG0, ul(0))

#define VTCR_PS_SHIFT           16
#define VTCR_PS_WIDTH           3
#define VTCR_PS_40              INPLACE(VTCR_PS, ul(2))

#define VTCR_DS_SHIFT           32
#define VTCR_DS_WIDTH           1
#define VTCR_DS_52BIT           INPLACE(VTCR_DS, ul(1))

#define VTCR_VS                 (ul(1) << 19)
#define VTCR_NSA                (ul(1) << 30)
#define VTCR_RES1               (ul(1) << 31)

#define VTCR_T0SZ_SHIFT         0
#define VTCR_T0SZ_WIDTH         6
#define VTCR_T0SZ_24            INPLACE(VTCR_T0SZ, ul(24))

#define VTCR_SL0_SHIFT          6
#define VTCR_SL0_WIDTH          2

#define VTCR_SL0_4K_L2          INPLACE(VTCR_SL0, ul(0))
#define VTCR_SL0_4K_L1          INPLACE(VTCR_SL0, ul(1))
#define VTCR_SL0_4K_L0          INPLACE(VTCR_SL0, ul(2))
#define VTCR_SL0_4K_L3          INPLACE(VTCR_SL0, ul(3))
#define VTCR_SL0_4K_LM1         VTCR_SL0_4K_L2

#define VTCR_RESET_VAL     (0x1ull << 31)

typedef enum {
  MPIDR_EL1 = 1,
  ID_AA64PFR0_EL1,
  ID_AA64PFR1_EL1,
  ID_AA64MMFR0_EL1,
  ID_AA64MMFR1_EL1,
  ID_AA64MMFR2_EL1,
  ID_AA64MMFR3_EL1,
  ID_AA64DFR0_EL1,
  ID_AA64DFR1_EL1,
  CTR_EL0,
  ID_AA64ISAR0_EL1,
  ID_AA64ISAR1_EL1,
  SCTLR_EL3,
  SCTLR_EL2,
  SCTLR_EL1,
  PMCR_EL0,
  PMOVSSET_EL0,
  PMOVSCLR_EL0,
  PMINTENSET_EL1,
  PMINTENCLR_EL1,
  CurrentEL,
  MDCR_EL2,
  VBAR_EL2,
  CCSIDR_EL1,
  CSSELR_EL1,
  CLIDR_EL1,
  ID_DFR0_EL1,
  ID_ISAR0_EL1,
  ID_ISAR1_EL1,
  ID_ISAR2_EL1,
  ID_ISAR3_EL1,
  ID_ISAR4_EL1,
  ID_ISAR5_EL1,
  ID_MMFR0_EL1,
  ID_MMFR1_EL1,
  ID_MMFR2_EL1,
  ID_MMFR3_EL1,
  ID_MMFR4_EL1,
  ID_PFR0_EL1,
  ID_PFR1_EL1,
  MIDR_EL1,
  MVFR0_EL1,
  MVFR1_EL1,
  MVFR2_EL1,
  PMCEID0_EL0,
  PMCEID1_EL0,
  VMPIDR_EL2,
  VPIDR_EL2,
  PMBIDR_EL1,
  PMSIDR_EL1,
  LORID_EL1,
  ERRIDR_EL1,
  ERR0FR_EL1,
  ERR1FR_EL1,
  ERR2FR_EL1,
  ERR3FR_EL1,
  PMSIRR_EL1,
  PMSCR_EL2,
  PMSFCR_EL1,
  PMBPTR_EL1,
  PMBLIMITR_EL1,
  ESR_EL2,
  FAR_EL2,
  RDVL,
  MAIR_ELx,
  TCR_ELx,
  TTBR_ELx,
  VTTBR,
  VTCR,
  HCR,
  MECIDR_EL2
} RME_ACS_PE_REGS;

uint64_t ArmReadMpidr(void);

uint64_t ArmReadIdPfr0(void);

uint64_t ArmReadIdPfr1(void);

uint64_t ArmReadHcr(void);

uint64_t AA64ReadMmfr0(void);

uint64_t AA64ReadMmfr1(void);

uint64_t AA64ReadMmfr2(void);

uint64_t AA64ReadMmfr3(void);

uint64_t AA64ReadCtr(void);

uint64_t AA64ReadIsar0(void);

uint64_t AA64ReadIsar1(void);

uint64_t AA64ReadSctlr3(void);

uint64_t AA64ReadSctlr2(void);

uint64_t AA64ReadSctlr1(void);

uint64_t AA64ReadPmcr(void);

uint64_t AA64ReadIdDfr0(void);

uint64_t AA64ReadIdDfr1(void);

uint64_t AA64ReadCurrentEL(void);

uint64_t AA64ReadMdcr2(void);

void AA64WriteMdcr2(uint64_t write_data);

uint64_t AA64ReadVbar2(void);

void AA64WriteVbar2(uint64_t write_data);

void AA64WritePmcr(uint64_t write_data);

void AA64WritePmovsset(uint64_t write_data);

void AA64WritePmovsclr(uint64_t write_data);

void AA64WritePmintenset(uint64_t write_data);

void AA64WritePmintenclr(uint64_t write_data);

uint64_t AA64ReadCcsidr(void);

uint64_t AA64ReadCsselr(void);

void AA64WriteCsselr(uint64_t write_data);

uint64_t AA64ReadClidr(void);

uint64_t ArmReadDfr0(void);

uint64_t ArmReadIsar0(void);

uint64_t ArmReadIsar1(void);

uint64_t ArmReadIsar2(void);

uint64_t ArmReadIsar3(void);

uint64_t ArmReadIsar4(void);

uint64_t ArmReadIsar5(void);

uint64_t ArmReadMmfr0(void);

uint64_t ArmReadMmfr1(void);

uint64_t ArmReadMmfr2(void);

uint64_t ArmReadMmfr3(void);

uint64_t ArmReadMmfr4(void);

uint64_t ArmReadPfr0(void);

uint64_t ArmReadPfr1(void);

uint64_t ArmReadMidr(void);

uint64_t ArmReadMvfr0(void);

uint64_t ArmReadMvfr1(void);

uint64_t ArmReadMvfr2(void);

uint64_t AA64ReadPmceid0(void);

uint64_t AA64ReadPmceid1(void);

uint64_t AA64ReadVmpidr(void);

uint64_t AA64ReadVpidr(void);

uint64_t AA64ReadPmbidr(void);

uint64_t AA64ReadPmsidr(void);

uint64_t AA64ReadLorid(void);

uint64_t AA64ReadErridr(void);

uint64_t AA64ReadErr0fr(void);

uint64_t AA64ReadErr1fr(void);

uint64_t AA64ReadErr2fr(void);

uint64_t AA64ReadErr3fr(void);

uint64_t AA64ReadMair1(void);

uint64_t AA64ReadMair2(void);

uint64_t AA64ReadTcr1(void);

uint64_t AA64ReadTcr2(void);

uint64_t AA64ReadVttbr(void);

uint64_t AA64ReadVtcr(void);

uint64_t AA64ReadTtbr0El1(void);

uint64_t AA64ReadTtbr0El2(void);

uint64_t AA64ReadTtbr1El1(void);

uint64_t AA64ReadTtbr1El2(void);

uint64_t AA64ReadMecidrEl2(void);

void AA64WritePmsirr(uint64_t write_data);

void AA64WritePmscr2(uint64_t write_data);

void AA64WritePmsfcr(uint64_t write_data);

void AA64WritePmbptr(uint64_t write_data);

void AA64WritePmblimitr(uint64_t write_data);

uint64_t AA64ReadEsr2(void);

uint64_t AA64ReadSp(void);

uint64_t AA64ReadSpsel(void);

uint64_t AA64ReadSP_EL0(void);

uint64_t AA64WriteSp(uint64_t write_data);

uint64_t AA64ReadFar2(void);

uint64_t ArmRdvl(void);

void ArmCallWFI(void);

void ArmExecuteMemoryBarrier(void);

void SpeProgramUnderProfiling(uint64_t interval, uint64_t address);

void DisableSpe(void);

void val_pe_update_elr(void *context, uint64_t offset);

uint64_t val_pe_get_esr(void *context);
uint64_t val_pe_get_elr(void *context);

uint64_t val_pe_get_far(void *context);

void val_pe_spe_program_under_profiling(uint64_t interval, addr_t address);

void val_pe_spe_disable(void);

void val_pe_context_save(uint64_t sp, uint64_t elr);
void val_pe_initialize_default_exception_handler(void (*esr)(uint64_t, void *));
void val_pe_context_restore(uint64_t sp);
void val_pe_default_esr(uint64_t interrupt_type, void *context);
void val_pe_cache_clean_range(uint64_t start_addr, uint64_t length);
void val_pe_cache_clean_invalidate_range(uint64_t start_addr, uint64_t length);
void val_pe_cache_invalidate_range(uint64_t start_addr, uint64_t length);
void set_daif(void);
void AA64WriteSctlr1(uint64_t write_data);
void AA64WriteHcr(uint64_t write_data);
void AA64WriteVttbr(uint64_t write_data);
void AA64WriteVtcr(uint64_t write_data);

#endif

