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

#ifndef VAL_EL3_PGT_H
#define VAL_EL3_PGT_H

#include <val_el3_helpers.h>
#include <val_el3_pe.h>

/* Defines used in pagetables and exceptionhandling */
#define RME_ACS_GPCCR_PPS_SHIFT      0
#define RME_ACS_GPCCR_L0GPTSZ_SHIFT 20
#define RME_ACS_GPCCR_PGS_SHIFT     14
#define RME_ACS_GPCCR_ORGN_SHIFT    10
#define RME_ACS_GPCCR_IRGN_SHIFT     8
#define RME_ACS_GPCCR_SH_SHIFT      12

#define RME_ACS_GPCCR_PPS_MASK      (0x7ull << RME_ACS_GPCCR_PPS_SHIFT)
#define RME_ACS_GPCCR_L0GPTSZ_MASK  (0xfull << RME_ACS_GPCCR_L0GPTSZ_SHIFT)
#define RME_ACS_GPCCR_PGS_MASK      (0x2ull << RME_ACS_GPCCR_PGS_SHIFT)
#define RME_ACS_GPCCR_ORGN_MASK     (0X2ull << RME_ACS_GPCCR_ORGN_SHIFT)
#define RME_ACS_GPCCR_IRGN_MASK     (0X2ull << RME_ACS_GPCCR_IRGN_SHIFT)
#define RME_ACS_GPCCR_SH_MASK       (0X2ull << RME_ACS_GPCCR_SH_SHIFT)

#define IS_GPT_ENTRY_TABLE(val) ((val & 0xF) == 0x3)
#define IS_GPT_ENTRY_BLOCK(val) ((val & 0xF) == 0x1)
#define IS_GPT_ENTRY_CONTIG(val) ((val & 0xF) == 0x1)

#define GPT_SCR_GPF_SHIFT  48
#define GPT_SCR_GPF_MASK   (0x1ull << GPT_SCR_GPF_SHIFT)

#define DESC_NSE_BIT    11
#define DESC_NS_BIT     5
#define PGT_LVL_MAX     4
#define PGT_STAGE1      1
#define PGT_STAGE2      2
#define SIZE_4KB        (4*1024)
#define SIZE_16KB       (16*1024)
#define SIZE_64KB       (64*1024)
#define AARCH64_TTBR_ADDR_MASK  (((0x1ull << 47) - 1) << 1)
#define IS_PGT_ENTRY_PAGE(val)  (val & 0x2)
#define IS_PGT_ENTRY_BLOCK(val) !(val & 0x2)
#define PGT_STAGE1_AP_RW        (0x1ull << 6)
#define PGT_ENTRY_TABLE_MASK    (0x1 << 1)
#define PGT_ENTRY_VALID_MASK    0x1
#define PGT_ENTRY_PAGE_MASK     (0x1 << 1)
#define PGT_ENTRY_BLOCK_MASK    (0x0 << 1)
#define PGT_ENTRY_ACCESS_SET    (0x1 << 10)

/* TCR_EL3 register defines */
#define TCR_EL3_TG0_SHIFT   14
#define TCR_EL3_SH0_SHIFT   12
#define TCR_EL3_ORGN0_SHIFT 10
#define TCR_EL3_IRGN0_SHIFT 8
#define TCR_EL3_T0SZ_SHIFT  0

#define TCR_EL3_TG0_MASK   (0x3ull << TCR_EL3_TG0_SHIFT)
#define TCR_EL3_SH0_MASK   (0x3ull << TCR_EL3_SH0_SHIFT)
#define TCR_EL3_ORGN0_MASK (0x3ull << TCR_EL3_ORGN0_SHIFT)
#define TCR_EL3_IRGN0_MASK (0x3ull << TCR_EL3_IRGN0_SHIFT)
#define TCR_EL3_T0SZ_MASK  (0x3Full << TCR_EL3_T0SZ_SHIFT)

#define TCR_EL3_PS_SHIFT   16
#define TCR_EL3_PS_MASK    (0x7ull << TCR_EL3_PS_SHIFT)

#ifndef __ASSEMBLER__
typedef struct gpt_attributes {
  uint32_t pps:3;
  uint32_t pgs:2;
  uint32_t l0gptsz:4;
  uint32_t orgn:2;
  uint32_t irgn:2;
  uint32_t sh:2;
} PE_GPCCR_BF;

typedef struct gpt_descriptors {
  uint64_t gpt_base;    // Base table adrress
  uint32_t size;        // Region size
  uint32_t level;       // Level of GPT lookup
  uint32_t contig_size; // Contiguous region size
  uint64_t pa;          // PA uniquely identifying the GPT entry
  PE_GPCCR_BF gpccr;    // GPCCR_EL3 register
} gpt_descriptor_t;

typedef struct {
  uint32_t ps:3;
  uint32_t tg:2;
  uint32_t sh:2;
  uint32_t orgn:2;
  uint32_t irgn:2;
  uint32_t tsz:6;
  uint32_t sl:2;
  uint32_t tg_size_log2:5;
} TCR_EL3_INFO;

typedef struct {
  uint32_t ps:3;
  uint32_t tg:2;
  uint32_t sh:2;
  uint32_t orgn:2;
  uint32_t irgn:2;
  uint32_t tsz:6;
  uint32_t sl:2;
  uint32_t tg_size_log2:5;
} VTCR_EL2_INFO;

typedef struct {
  uint64_t pgt_base;
  uint32_t ias;
  uint32_t oas;
  uint64_t mair;
  uint32_t stage;
  TCR_EL3_INFO tcr;
  VTCR_EL2_INFO vtcr;
} pgt_descriptor_t;

typedef struct {
  uint64_t physical_address;
  uint64_t virtual_address;
  uint64_t length;
  uint64_t attributes;
} memory_region_descriptor_t;

void val_el3_setup_acs_pgt_values(void);
void val_el3_add_gpt_entry(uint64_t arg0, uint64_t arg1);
uint64_t val_el3_get_gpt_index(uint64_t pa, uint8_t level, uint8_t l0gptsz,
                       uint8_t pps, uint8_t p);
bool val_el3_is_gpi_valid(uint64_t gpi);
uint64_t val_el3_modify_gpt_gpi(uint64_t entry, uint64_t pa, uint8_t level,
                        uint8_t p, uint64_t GPI);
uint32_t val_el3_add_mmu_entry(uint64_t arg0, uint64_t arg1, uint64_t arg2);
uint64_t val_el3_modify_desc(uint64_t table_desc, uint8_t start_bit,
                     uint64_t value_to_set, uint8_t num_bits);
uint32_t val_el3_log2_page_size(uint64_t size);
void val_el3_get_tcr_info(TCR_EL3_INFO *tcr_el3);
uint32_t val_el3_realm_pgt_create(memory_region_descriptor_t *mem_desc,
                              pgt_descriptor_t *pgt_desc);
void val_el3_realm_pgt_destroy(pgt_descriptor_t *pgt_desc);
uint64_t val_el3_at_s1e3w(uint64_t VA);

#endif /* __ASSEMBLER__ */

#endif /* VAL_EL3_PGT_H */
