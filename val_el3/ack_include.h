/** @file
 * Copyright (c) 2022-2023, Arm Limited or its affiliates. All rights reserved.
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

#define VAL_EXTRACT_BITS(data, start, end) ((data >> start) & ((1ul << (end-start+1))-1))

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
#define SCR_NS_SHIFT       0
#define SCR_NS_MASK        (0x1ull << SCR_NS_SHIFT)
#define SCR_NSE_SHIFT      62
#define SCR_NSE_MASK       (0x1ull << SCR_NSE_SHIFT)

#define ALLEXCPTNS_MASK 0x7ULL
#define ALLEXCPTNS_MASK_BIT 6

#define GPF_ESR_READ    0x96000028ULL
#define GPF_ESR_WRITE   0x96000068ULL
#define get_max(a, b)   (((a) > (b))?(a):(b))
#define NSE_SET(val)    ((val == SECURE_PAS || val == NONSECURE_PAS) ? 0 : 1)
#define NS_SET(val)     ((val == ROOT_PAS || val == SECURE_PAS) ? 0 : 1)
#define DESC_NSE_BIT    11
#define DESC_NS_BIT     5
#define PGT_IAS         40
#define PAGT_OAS        40
#define PGT_STAGE1      1
#define PGT_STAGE2      2
#define SIZE_4KB        (4*1024)
#define AARCH64_TTBR_ADDR_MASK  (((0x1ull << 47) - 1) << 1)
#define IS_PGT_ENTRY_PAGE(val)  (val & 0x2)
#define IS_PGT_ENTRY_BLOCK(val) !(val & 0x2)
#define PGT_STAGE1_AP_RW        (0x1ull << 6)
#define PGT_ENTRY_TABLE_MASK    (0x1 << 1)
#define PGT_ENTRY_VALID_MASK    0x1
#define PGT_ENTRY_PAGE_MASK     (0x1 << 1)
#define PGT_ENTRY_BLOCK_MASK    (0x0 << 1)
#define PGT_ENTRY_ACCESS_SET    (0x1 << 10)

#define CIPOPA_NS_BIT           63
#define CIPOPA_NSE_BIT          62

#ifndef __ASSEMBLER__

#include <stdbool.h>
#include <stdint.h>
#include "pal_el3/pal_el3_print.h"
#include "pal_el3/acs_el3.h"
#include "val/include/rme_acs_el32.h"

#endif //__ASSEMBLER__

#include "val/include/sys_config.h"

/* Address Defines related to shared data */
#define ARM_TF_SHARED_ADDRESS (SHARED_ADDRESS + SIZE_4KB - 0x20)
#define SHARED_OFFSET_ELR     (SHARED_ADDRESS + 0x8)
#define SHARED_OFFSET_SPSR    (SHARED_ADDRESS + 0x10)
#define SHARED_OFFSET_EXC_EXP (SHARED_ADDRESS + 0x18)
#define SHARED_OFFSET_EXC_GEN (SHARED_ADDRESS + 0x20)
#define SHARED_OFFSET_ACC_MUT (SHARED_ADDRESS + 0x28)
#define SHARED_OFFSET_ESR_VAL (SHARED_ADDRESS + 0x30)
#define SHARED_OFFSET_ARG0    (SHARED_ADDRESS + 0x38)
#define SHARED_OFFSET_ARG1    (SHARED_ADDRESS + 0x40)
#define ACS_EL3_STACK (SHARED_ADDRESS + SIZE_4KB - 0x100)
#define ACS_EL3_HANDLER_SAVED_POINTER (SHARED_ADDRESS + 0x800)

#ifndef __ASSEMBLER__

void val_security_state_change(uint64_t attr_nse_ns);
void set_daif(void);
void val_pas_filter_active_mode(int enable);
void val_smmu_access_disable(void);
void val_wd_set_ws0_el3(uint64_t VA_RT_WDOG,
                        uint32_t timer_expire_ticks,
                        uint64_t counter_freq);
void val_wd_enable(uint64_t wdog_ctrl_base);
void val_wd_disable(uint64_t wdog_ctrl_base);
void val_pe_reg_list_cmp_msd(void);
void val_pe_reg_read_msd(void);
uint64_t val_pe_reg_read(uint32_t reg_id);
uint64_t read_elr_el3(void);
uint64_t read_far(void);
uint64_t read_esr_el3(void);
uint64_t read_sp_el0(void);
uint64_t read_spsr_el3(void);
uint64_t read_mair_el3(void);
void val_prog_legacy_tz(int enable);
void val_enable_ns_encryption(void);
void val_disable_ns_encryption(void);
void write_mair_el3(uint64_t value);
void asm_eret_smc(void);
void update_elr_el3(uint64_t reg_value);
void update_spsr_el3(uint64_t reg_value);
void exception_handler_user(void);
void tlbi_vae3(uint64_t VA);
void rme_install_handler(void);
void add_gpt_entry(uint64_t PA, uint64_t GPI);
void add_mmu_entry(uint64_t VA, uint64_t PA, uint64_t acc_pas);
void map_shared_mem(void);
void ack_handler_el3(void);
void save_vbar_el3(uint64_t *el3_handler);
void program_vbar_el3(void (*)(void));
void asm_eret(void);
void access_mut(void);
uint64_t read_gpccr_el3(void);
uint64_t read_gptbr_el3(void);
uint64_t read_scr_el3(void);
uint64_t read_sctlr_el3(void);
uint64_t read_sctlr_el2(void);
uint64_t write_scr_el3(uint64_t value);
uint64_t read_tcr_el3(void);
uint64_t read_ttbr_el3(void);
uint64_t at_s1e3w(uint64_t VA);
uint64_t get_gpt_index(uint64_t PA, uint8_t level, uint8_t l0gptsz, uint8_t pps, uint8_t p);
bool is_gpi_valid(uint64_t GPI);
uint64_t modify_gpt_gpi(uint64_t entry, uint64_t pa, uint8_t level, uint8_t p, uint64_t GPI);
void tlbi_paallos(void);
void cln_and_invldt_cache(uint64_t *desc_addr);
void clean_cache(uint64_t *address);
void invalidate_cache(uint64_t *address);
void val_data_cache_ops_by_va_el3(uint64_t address, uint32_t type);
void val_memory_set_el3(void *buf, uint32_t size, uint8_t value);
void cmo_cipapa(uint64_t PA);
void plat_arm_acs_user_smc_handler(uint64_t services, uint64_t arg0, uint64_t arg1, uint64_t arg2);
void branch_asm(uint64_t el3_handler);
uint64_t modify_desc(uint64_t desc, uint8_t start_bit, uint64_t value_to_set, uint8_t num_bits);
uint32_t log2_page_size(uint64_t size);
void acs_str(uint64_t *address, uint64_t data);
void acs_ldr_pas_filter(uint64_t *address, uint64_t data);
uint32_t val_get_pgt_attr_indx(uint64_t table_desc);

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
} PE_TCR_BF;

typedef struct {
  uint64_t pgt_base;
  uint32_t ias;
  uint32_t oas;
  uint64_t mair;
  uint32_t stage;
  PE_TCR_BF tcr;
} pgt_descriptor_t;

#endif //__ASSEMBLER__

