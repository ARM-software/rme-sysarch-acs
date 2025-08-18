/** @file
 * Copyright (c) 2022-2025, Arm Limited or its affiliates. All rights reserved.
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

#define ALLEXCPTNS_MASK 0x7ULL
#define ALLEXCPTNS_MASK_BIT 6

#define GPF_ESR_READ    0x96000028ULL
#define GPF_ESR_WRITE   0x96000068ULL
#define get_max(a, b)   (((a) > (b))?(a):(b))
#define CIPOPA_NS_BIT           63
#define CIPOPA_NSE_BIT          62
#define CIPAE_NS_BIT           63
#define CIPAE_NSE_BIT          62


/* Page table defines */
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

#include <stdbool.h>
#include <string.h>
#include <stdint.h>
#include "pal_el3/pal_el3_print.h"
#include "pal_el3/acs_el3.h"

#endif //__ASSEMBLER__

#include "val/include/val_el32.h"

/* Address Defines related to shared data */
#define ARM_TF_SHARED_ADDRESS (PLAT_SHARED_ADDRESS + SIZE_4KB - 0x20)
#define SHARED_OFFSET_ELR     (PLAT_SHARED_ADDRESS + 0x8)
#define SHARED_OFFSET_SPSR    (PLAT_SHARED_ADDRESS + 0x10)
#define SHARED_OFFSET_EXC_EXP (PLAT_SHARED_ADDRESS + 0x18)
#define SHARED_OFFSET_EXC_GEN (PLAT_SHARED_ADDRESS + 0x20)
#define SHARED_OFFSET_ACC_MUT (PLAT_SHARED_ADDRESS + 0x28)
#define SHARED_OFFSET_ESR_VAL (PLAT_SHARED_ADDRESS + 0x30)
#define SHARED_OFFSET_ARG0    (PLAT_SHARED_ADDRESS + 0x38)
#define SHARED_OFFSET_ARG1    (PLAT_SHARED_ADDRESS + 0x40)
#define ACS_EL3_STACK (PLAT_SHARED_ADDRESS + SIZE_4KB - 0x100)
#define ACS_EL3_HANDLER_SAVED_POINTER (PLAT_SHARED_ADDRESS + 0x800)

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

typedef struct {
    uint32_t smmu_index;
    uint32_t streamid;
    uint32_t substreamid;
    uint32_t ssid_bits;
    uint32_t stage2;
    uint32_t bypass;
} smmu_master_attributes_t;

typedef struct BlockHeader {
    size_t size;                // Size of the block
    int is_free;                // Block free status
    struct BlockHeader *next;   // Pointer to the next block
} BlockHeader;

typedef struct {
    uint8_t *base;              // Base address of the memory pool
    size_t size;                // Total size of the pool
    BlockHeader *free_list;     // Head of the free list
} MemoryPool;

void val_smmu_init_el3(uint32_t num_smmu, uint64_t smmu_base_arr[]);
uint32_t val_smmu_rlm_map(smmu_master_attributes_t master_attr, pgt_descriptor_t pgt_desc);
void val_security_state_change(uint64_t attr_nse_ns);
void set_daif(void);
void val_pas_filter_active_mode(int enable);
void val_smmu_access_disable(uint64_t smmu_base);
void val_smmu_access_enable(uint64_t smmu_base);
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
void tlbi_alle3is(void);
void isb(void);
void rme_install_handler(void);
void add_gpt_entry(uint64_t PA, uint64_t GPI);
uint32_t add_mmu_entry(uint64_t VA, uint64_t PA, uint64_t acc_pas);
uint32_t val_realm_pgt_create(memory_region_descriptor_t *mem_desc, pgt_descriptor_t *pgt_desc);
void val_realm_pgt_destroy(pgt_descriptor_t *pgt_desc);
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
uint64_t read_tcr_el2(void);
uint64_t read_ttbr_el3(void);
uint64_t read_ttbr_el2(void);
uint64_t read_vtcr(void);
uint64_t read_vttbr(void);
void write_vttbr(uint64_t write_value);
void write_vtcr(uint64_t write_data);
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
void plat_arm_acs_smc_handler(uint64_t services, uint64_t arg0, uint64_t arg1, uint64_t arg2);
void branch_asm(uint64_t el3_handler);
uint64_t modify_desc(uint64_t desc, uint8_t start_bit, uint64_t value_to_set, uint8_t num_bits);
uint32_t log2_page_size(uint64_t size);
void acs_str(uint64_t *address, uint64_t data);
void acs_ldr_pas_filter(uint64_t *address, uint64_t data);
uint32_t val_get_pgt_attr_indx(uint64_t table_desc);
void *val_memory_virt_to_phys_el3(void *va);
void *val_memory_phys_to_virt(uint64_t pa);
void *val_memory_alloc_el3(size_t size, size_t alignment);
void val_memory_free_el3(void *ptr);
void *val_memory_calloc_el3(size_t num, size_t size, size_t alignment);
void val_smmu_root_config_service(uint64_t arg0, uint64_t arg1, uint64_t arg2);
void val_get_tcr_info(TCR_EL3_INFO *tcr_el3);
void val_mmio_write_el3(uintptr_t addr, uint32_t val);
uint32_t val_mmio_read_el3(uintptr_t addr);
uint32_t val_mmio_read64_el3(uintptr_t addr);
void val_mmio_write64_el3(uintptr_t addr, uint64_t val);
void mem_barrier(void);
uint32_t val_dpt_add_entry(uint64_t translated_addr, uint64_t smmu_info);
void val_dpt_invalidate_all(uint64_t smmu_index);
uint64_t read_sctlr2_el3(void);
uint64_t write_sctlr2_el3(uint64_t value);
void write_mecid_rl_a_el3(uint64_t mecid);
uint64_t read_mecid_rl_a_el3(void);
void val_write_mecid(uint32_t mecid);
uint64_t read_id_aa64mmfr3_el1(void);
unsigned int val_is_mec_supported(void);
void val_mec_service(uint64_t arg0, uint64_t arg1, uint64_t arg2);
void val_enable_mec(void);
void val_disable_mec(void);
uint32_t val_is_mec_enabled(void);
void cmo_cipae(uint64_t PA);
uint32_t val_smmu_set_rlm_ste_mecid(smmu_master_attributes_t master_attr, uint32_t mecid);
bool val_smmu_supports_mec(uint64_t smmu_base);
uint32_t val_smmu_get_mecidw(uint64_t smmu_base);

#endif //__ASSEMBLER__
