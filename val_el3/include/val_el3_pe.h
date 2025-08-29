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

#ifndef VAL_EL3_PE_H
#define VAL_EL3_PE_H

#include <val_el3_helpers.h>

#define SCR_NS_SHIFT       0
#define SCR_NS_MASK        (0x1ull << SCR_NS_SHIFT)
#define SCR_NSE_SHIFT      62
#define SCR_NSE_MASK       (0x1ull << SCR_NSE_SHIFT)
#define SCR_MEC_EN_SHIFT   49
#define SCR_MEC_EN_MASK    (0x1ull << SCR_MEC_EN_SHIFT)
#define SCR_SCTLR2EN_SHIFT 44
#define SCR_SCTLR2EN_MASK  (0x1ull << SCR_SCTLR2EN_SHIFT)
#define SCTLR2_EMEC_SHIFT  1
#define SCTLR2_EMEC_MASK   (0x1ull << SCTLR2_EMEC_SHIFT)
#define ID_AA64MMFR3_EL1_MEC_SHIFT          U(28)
#define ID_AA64MMFR3_EL1_MEC_MASK           ULL(0xf)
#define ID_AA64MMFR3_EL1_SCTLRX_SHIFT       U(4)
#define ID_AA64MMFR3_EL1_SCTLRX_MASK        ULL(0xf)

/* Prototypes moved from ack_common.c */
#ifndef __ASSEMBLER__
void val_pe_reg_read_msd(void);
void val_pe_reg_list_cmp_msd(void);
uint64_t val_pe_reg_read(uint32_t reg_id);
uint64_t read_elr_el3(void);
uint64_t read_far(void);
uint64_t read_esr_el3(void);
uint64_t read_sp_el0(void);
uint64_t read_spsr_el3(void);
uint64_t read_mair_el3(void);
void write_mair_el3(uint64_t value);
uint64_t read_gpccr_el3(void);
uint64_t read_gptbr_el3(void);
uint64_t read_scr_el3(void);
uint64_t read_sctlr_el3(void);
uint64_t read_sctlr_el2(void);
uint64_t write_scr_el3(uint64_t value);
uint64_t read_tcr_el3(void);
uint64_t read_tcr_el2(void);
uint64_t read_ttbr_el3(void);
uint64_t read_ttbr_el2(void);
uint64_t read_vtcr(void);
uint64_t read_vttbr(void);
void write_vttbr(uint64_t write_value);
void write_vtcr(uint64_t write_data);
uint64_t read_sctlr2_el3(void);
uint64_t write_sctlr2_el3(uint64_t value);
void write_mecid_rl_a_el3(uint64_t mecid);
uint64_t read_mecid_rl_a_el3(void);
uint64_t read_id_aa64mmfr3_el1(void);
void branch_asm(uint64_t el3_handler);
#endif /* __ASSEMBLER__ */

#endif /* VAL_EL3_PE_H */
