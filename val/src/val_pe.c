/** @file
 * Copyright (c) 2023, 2025, Arm Limited or its affiliates. All rights reserved.
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

#include "include/val.h"
#include "include/val_pe.h"
#include "include/val_common.h"
#include "include/val_std_smc.h"
#include "include/val_memory.h"


/**
  @brief   Pointer to the memory location of the PE Information table
**/
extern PE_INFO_TABLE *g_pe_info_table;
/**
  @brief   global structure to pass and retrieve arguments for the SMC call
**/
extern ARM_SMC_ARGS g_smc_args;

/**
  @brief   This API provides a 'C' interface to call System register reads
           1. Caller       -  Test Suite
           2. Prerequisite -  None
  @param   reg_id  - the system register index for which data is returned
  @return  the value read from the system register.
**/
uint64_t
val_pe_reg_read(uint32_t reg_id)
{

  switch (reg_id)
  {
      case MPIDR_EL1:
          return ArmReadMpidr();
      case ID_AA64PFR0_EL1:
          return ArmReadIdPfr0();
      case ID_AA64PFR1_EL1:
          return ArmReadIdPfr1();
      case ID_AA64MMFR0_EL1:
          return AA64ReadMmfr0();
      case ID_AA64MMFR1_EL1:
          return AA64ReadMmfr1();
      case ID_AA64MMFR2_EL1:
          return AA64ReadMmfr2();
      case ID_AA64MMFR3_EL1:
          return AA64ReadMmfr3();
      case CTR_EL0:
          return AA64ReadCtr();
      case ID_AA64ISAR0_EL1:
          return AA64ReadIsar0();
      case ID_AA64ISAR1_EL1:
          return AA64ReadIsar1();
      case SCTLR_EL3:
          return AA64ReadSctlr3();
      case SCTLR_EL2:
          return AA64ReadSctlr2();
      case SCTLR_EL1:
          return AA64ReadSctlr1();
      case PMCR_EL0:
          return AA64ReadPmcr();
      case ID_AA64DFR0_EL1:
          return AA64ReadIdDfr0();
      case ID_AA64DFR1_EL1:
          return AA64ReadIdDfr1();
      case CurrentEL:
          return AA64ReadCurrentEL();
      case MDCR_EL2:
          return AA64ReadMdcr2();
      case VBAR_EL2:
          return AA64ReadVbar2();
      case CCSIDR_EL1:
          return AA64ReadCcsidr();
      case CSSELR_EL1:
          return AA64ReadCsselr();
      case CLIDR_EL1:
          return AA64ReadClidr();
      case ID_DFR0_EL1:
          return ArmReadDfr0();
      case ID_ISAR0_EL1:
          return ArmReadIsar0();
      case ID_ISAR1_EL1:
          return ArmReadIsar1();
      case ID_ISAR2_EL1:
          return ArmReadIsar2();
      case ID_ISAR3_EL1:
          return ArmReadIsar3();
      case ID_ISAR4_EL1:
          return ArmReadIsar4();
      case ID_ISAR5_EL1:
          return ArmReadIsar5();
      case ID_MMFR0_EL1:
          return ArmReadMmfr0();
      case ID_MMFR1_EL1:
          return ArmReadMmfr1();
      case ID_MMFR2_EL1:
          return ArmReadMmfr2();
      case ID_MMFR3_EL1:
          return ArmReadMmfr3();
      case ID_MMFR4_EL1:
          return ArmReadMmfr4();
      case ID_PFR0_EL1:
          return ArmReadPfr0();
      case ID_PFR1_EL1:
          return ArmReadPfr1();
      case MIDR_EL1:
          return ArmReadMidr();
      case MVFR0_EL1:
          return ArmReadMvfr0();
      case MVFR1_EL1:
          return ArmReadMvfr1();
      case MVFR2_EL1:
          return ArmReadMvfr2();
      case PMCEID0_EL0:
          return AA64ReadPmceid0();
      case PMCEID1_EL0:
          return AA64ReadPmceid1();
      case VMPIDR_EL2:
          return AA64ReadVmpidr();
      case VPIDR_EL2:
          return AA64ReadVpidr();
      case PMBIDR_EL1:
          return AA64ReadPmbidr();
      case PMSIDR_EL1:
          return AA64ReadPmsidr();
      case LORID_EL1:
          return AA64ReadLorid();
      case ERRIDR_EL1:
          return AA64ReadErridr();
      case ERR0FR_EL1:
          return AA64ReadErr0fr();
      case ERR1FR_EL1:
          return AA64ReadErr1fr();
      case ERR2FR_EL1:
          return AA64ReadErr2fr();
      case ERR3FR_EL1:
          return AA64ReadErr3fr();
      case ESR_EL2:
          return AA64ReadEsr2();
      case FAR_EL2:
          return AA64ReadFar2();
      case RDVL:
          return ArmRdvl();
      case MAIR_ELx:
          if (AA64ReadCurrentEL() == AARCH64_EL1)
            return AA64ReadMair1();
          if (AA64ReadCurrentEL() == AARCH64_EL2)
            return AA64ReadMair2();
        break;
      case TCR_ELx:
          if (AA64ReadCurrentEL() == AARCH64_EL1)
            return AA64ReadTcr1();
          if (AA64ReadCurrentEL() == AARCH64_EL2)
            return AA64ReadTcr2();
        break;
      case VTTBR:
          return AA64ReadVttbr();
          break;
      case VTCR:
          return AA64ReadVtcr();
          break;
      case MECIDR_EL2:
          return AA64ReadMecidrEl2();
          break;
      default:
           val_report_status(val_pe_get_index_mpid(val_pe_get_mpid()), "FAIL");
  }

  return 0x0;
}

/**
  @brief   This API provides a 'C' interface to call System register writes
           1. Caller       -  Test Suite
           2. Prerequisite -  None
  @param   reg_id  - the system register index for which data is written
  @param   write_data - the 64-bit data to write to the system register
  @return  None
**/
void
val_pe_reg_write(uint32_t reg_id, uint64_t write_data)
{

  switch (reg_id)
  {
      case CSSELR_EL1:
          AA64WriteCsselr(write_data);
          break;
      case PMCR_EL0:
          AA64WritePmcr(write_data);
          break;
      case PMOVSSET_EL0:
          AA64WritePmovsset(write_data);
          break;
      case PMOVSCLR_EL0:
          AA64WritePmovsclr(write_data);
          break;
      case PMINTENSET_EL1:
          AA64WritePmintenset(write_data);
          break;
      case PMINTENCLR_EL1:
          AA64WritePmintenclr(write_data);
          break;
      case MDCR_EL2:
          AA64WriteMdcr2(write_data);
          break;
      case VBAR_EL2:
          AA64WriteVbar2(write_data);
          break;
      case PMSIRR_EL1:
          AA64WritePmsirr(write_data);
          break;
      case PMSCR_EL2:
          AA64WritePmscr2(write_data);
          break;
      case PMSFCR_EL1:
          AA64WritePmsfcr(write_data);
          break;
      case PMBPTR_EL1:
          AA64WritePmbptr(write_data);
          break;
      case PMBLIMITR_EL1:
          AA64WritePmblimitr(write_data);
          break;
      case SCTLR_EL1:
          AA64WriteSctlr1(write_data);
          break;
      case VTTBR:
          return AA64WriteVttbr(write_data);
          break;
      case VTCR:
          return AA64WriteVtcr(write_data);
          break;
      case HCR:
          return AA64WriteHcr(write_data);
          break;
      default:
           val_report_status(val_pe_get_index_mpid(val_pe_get_mpid()), "FAIL");
  }

}

/**
  @brief   This API indicates the presence of exception level 3
           1. Caller       -  Test Suite
           2. Prerequisite -  None
  @param   None
  @return  1 if EL3 is present, 0 if EL3 is not implemented
**/
uint8_t
val_is_el3_enabled()
{
  uint64_t data;

  data = val_pe_reg_read(ID_AA64PFR0_EL1);
  return ((data >> 12) & 0xF);

}

/**
  @brief   This API indicates the presence of exception level 2
           1. Caller       -  Test Suite
           2. Prerequisite -  None
  @param   None
  @return  1 if EL2 is present, 0 if EL2 is not implemented
**/
uint8_t
val_is_el2_enabled()
{

  uint64_t data;

  data = val_pe_reg_read(ID_AA64PFR0_EL1);
  return ((data >> 8) & 0xF);

}

uint32_t val_pe_reg_read_tcr(uint32_t ttbr1, PE_TCR_BF *tcr)
{
    uint64_t val = val_pe_reg_read(TCR_ELx);
    uint32_t el = AA64ReadCurrentEL() & AARCH64_EL_MASK;
    uint8_t tg_ttbr0[3] = {12 /*4KB*/, 16 /*64KB*/, 14 /*16KB*/};
    uint8_t tg_ttbr1[4] = {0 /* N/A */, 14 /*16KB*/, 12 /*4KB*/, 16 /* 64KB*/};
    uint64_t e2h;

    if ((tcr == NULL) ||
        (el != AARCH64_EL1 && el != AARCH64_EL2))
        return ACS_STATUS_ERR;

    if (el == AARCH64_EL2)
        e2h = ArmReadHcr() & AARCH64_HCR_E2H_MASK;

    if (el == AARCH64_EL1 || (el == AARCH64_EL2 && e2h))
    {
        tcr->ps = (val & RME_TCR_IPS_MASK) >> RME_TCR_IPS_SHIFT;
        if (ttbr1) {
            tcr->tg = (val & RME_TCR_TG1_MASK) >> RME_TCR_TG1_SHIFT;
            if (tcr->tg == 0 || tcr->tg > 3)
                return ACS_STATUS_ERR;
            tcr->tg_size_log2 = tg_ttbr1[tcr->tg];
            tcr->sh = (val & RME_TCR_SH1_MASK) >> RME_TCR_SH1_SHIFT;
            tcr->orgn = (val & RME_TCR_ORGN1_MASK) >> RME_TCR_ORGN1_SHIFT;
            tcr->irgn = (val & RME_TCR_IRGN1_MASK) >> RME_TCR_IRGN1_SHIFT;
            tcr->tsz = (val & RME_TCR_T1SZ_MASK) >> RME_TCR_T1SZ_SHIFT;
            return 0;
        }
    } else if (!ttbr1)
        tcr->ps = (val & RME_TCR_PS_MASK) >> RME_TCR_PS_SHIFT;
    else
        return ACS_STATUS_ERR;

    tcr->tg = (val & RME_TCR_TG0_MASK) >> RME_TCR_TG0_SHIFT;
    if (tcr->tg > 2)
        return ACS_STATUS_ERR;
    tcr->tg_size_log2 = tg_ttbr0[tcr->tg];
    tcr->sh = (val & RME_TCR_SH0_MASK) >> RME_TCR_SH0_SHIFT;
    tcr->orgn = (val & RME_TCR_ORGN0_MASK) >> RME_TCR_ORGN0_SHIFT;
    tcr->irgn = (val & RME_TCR_IRGN0_MASK) >> RME_TCR_IRGN0_SHIFT;
    tcr->tsz = (val & RME_TCR_T0SZ_MASK) >> RME_TCR_T0SZ_SHIFT;
    return 0;
}

uint32_t val_pe_reg_read_ttbr(uint32_t ttbr1, uint64_t *ttbr_ptr)
{
    uint32_t el = AA64ReadCurrentEL() & AARCH64_EL_MASK;
    typedef uint64_t (*ReadTtbr_t)();
    ReadTtbr_t ReadTtbr[2][2] = {{AA64ReadTtbr0El1, AA64ReadTtbr0El2},
                                  {AA64ReadTtbr1El1, AA64ReadTtbr1El2} };

    if ((ttbr_ptr == NULL) ||
        (el != AARCH64_EL1 && el != AARCH64_EL2) ||
        ttbr1 > 1)
        return ACS_STATUS_ERR;

    *ttbr_ptr = ReadTtbr[ttbr1][(el >> 2) - 1]();
    return 0;
}

uint32_t val_pe_get_vtcr(VTCR_EL2_INFO *vtcr)
{
    uint64_t val;
    PE_TCR_BF tcr;
    uint8_t tg_vtbr[3] = {12 /*4KB*/, 16 /*64KB*/, 14 /*16KB*/};
    uint64_t hcr;

    val = val_pe_reg_read(VTCR);
    val_print(ACS_PRINT_DEBUG, " VTCR: 0x%llx", val);
    if (val != VTCR_RESET_VAL) {
            vtcr->ps = (val & MASK(VTCR_PS)) >> VTCR_PS_SHIFT;
            vtcr->tg = (val & MASK(VTCR_TG0)) >> VTCR_TG0_SHIFT;
            vtcr->tg_size_log2 = tg_vtbr[vtcr->tg];
            vtcr->sh = (val & MASK(VTCR_SH0)) >> VTCR_SH0_SHIFT;
            vtcr->orgn = (val & MASK(VTCR_ORGN0)) >> VTCR_ORGN0_SHIFT;
            vtcr->irgn = (val & MASK(VTCR_IRGN0)) >> VTCR_IRGN0_SHIFT;
            vtcr->tsz = (val & MASK(VTCR_T0SZ)) >> VTCR_T0SZ_SHIFT;
            vtcr->sl = (val & MASK(VTCR_SL0)) >> VTCR_SL0_SHIFT;
            return 0;
    }

    /* Disable the Stage 2 MMU to write to vtcr */
    hcr = ArmReadHcr();

    if (hcr & 0x1)
        val_pe_reg_write(HCR, hcr & ~0x1);

    val_pe_reg_read_tcr(0, &tcr);
    val = 0;
    val = (INPLACE(VTCR_TG0, (tcr.tg))     |
           INPLACE(VTCR_PS, (tcr.ps))      |
           VTCR_RES1 | VTCR_NSA            |
           INPLACE(VTCR_T0SZ, (tcr.tsz))   |
           INPLACE(VTCR_IRGN0, (tcr.irgn)) |
           INPLACE(VTCR_ORGN0, (tcr.orgn)) |
           INPLACE(VTCR_SH0, (tcr.sh))     |
           VTCR_SL0_4K_L0);
    val_pe_reg_write(VTCR, val);

    /* Enable the stage 2 MMU now */
    val_pe_reg_write(HCR, hcr | 0x1);

    /* Now again read back the VTCR reg and store it in the struct */
    val = val_pe_reg_read(VTCR);
    val_print(ACS_PRINT_DEBUG, " VTCR after write: 0x%llx", val);
    vtcr->ps = (val & MASK(VTCR_PS)) >> VTCR_PS_SHIFT;
    vtcr->tg = (val & MASK(VTCR_TG0)) >> VTCR_TG0_SHIFT;
    vtcr->tg_size_log2 = tg_vtbr[vtcr->tg];
    vtcr->sh = (val & MASK(VTCR_SH0)) >> VTCR_SH0_SHIFT;
    vtcr->orgn = (val & MASK(VTCR_ORGN0)) >> VTCR_ORGN0_SHIFT;
    vtcr->irgn = (val & MASK(VTCR_IRGN0)) >> VTCR_IRGN0_SHIFT;
    vtcr->tsz = (val & MASK(VTCR_T0SZ)) >> VTCR_T0SZ_SHIFT;
    vtcr->sl = (val & MASK(VTCR_SL0)) >> VTCR_SL0_SHIFT;
    return 0;

}

uint32_t val_pe_get_vtbr(uint64_t *ttbr_ptr)
{
    if ((ttbr_ptr == NULL))
        return ACS_STATUS_ERR;

    *ttbr_ptr = AA64ReadVttbr();
    return 0;
}
