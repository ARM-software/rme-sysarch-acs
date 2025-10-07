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

#include <val_el3_debug.h>
#include <val_el3_pgt.h>
#include <val_el3_memory.h>

#define get_min(a, b) (((a) < (b))?(a):(b))

#define MAX_ENTRIES_4K      512L
#define MAX_ENTRIES_16K     2048L
#define MAX_ENTRIES_64K     8192L

#define PGT_LEVEL_0   0
#define PGT_LEVEL_1   1
#define PGT_LEVEL_2   2
#define PGT_LEVEL_3   3

uint64_t free_pa = PLAT_FREE_MEM_START;

static uint32_t pg_size;
static uint32_t bits_p_level;
static uint64_t pgt_addr_mask;
uint64_t is_values_init = 0;
uint64_t offset = 0;

typedef struct {
    uint64_t *tt_base;
    uint64_t input_base;
    uint64_t input_top;
    uint64_t output_base;
    uint32_t level;
    uint32_t size_log2;
    uint32_t nbits;
} tt_descriptor_t;

typedef struct {
    uint32_t l0_index;
    uint32_t l1_index;
    uint32_t l2_index;
    uint32_t l3_index;
    uint64_t size_used;
} acs_pgt_t;

static acs_pgt_t acs_pgt_info;

void val_el3_setup_acs_pgt_values(void)
{
    acs_pgt_info.l0_index = 0;
    acs_pgt_info.l1_index = 0;
    acs_pgt_info.l2_index = 0;
    acs_pgt_info.l3_index = 0;
    acs_pgt_info.size_used = 0;
}


static
uint32_t get_pgt_index(uint32_t level)
{
    switch (level)
    {
        case(PGT_LEVEL_0):
            return acs_pgt_info.l0_index;
        case(PGT_LEVEL_1):
            return acs_pgt_info.l1_index;
        case(PGT_LEVEL_2):
            return acs_pgt_info.l2_index;
        case(PGT_LEVEL_3):
            return acs_pgt_info.l3_index;
        default:
            return 0;
    }
}

static
void increment_pgt_index(uint32_t level, uint32_t max_index)
{
    switch (level)
    {
        case(PGT_LEVEL_1):
            if (acs_pgt_info.l1_index == (max_index - 1)) {
                acs_pgt_info.l1_index = 0;
                acs_pgt_info.l0_index++;
            }
            break;
        case(PGT_LEVEL_2):
            if (acs_pgt_info.l2_index == (max_index - 1)) {
                acs_pgt_info.l2_index = 0;
                acs_pgt_info.l1_index++;
            }
            break;
        case(PGT_LEVEL_3):
            if (acs_pgt_info.l3_index == (max_index - 1)) {
                acs_pgt_info.l3_index = 0;
                acs_pgt_info.l2_index++;
            } else
                acs_pgt_info.l3_index++;
            break;
        default:
            break;
    }

  return;
}

static
uint32_t get_entries_per_level(uint32_t page_size)
{
    switch (page_size)
    {
        case(SIZE_4KB):   //4kb granule
            return MAX_ENTRIES_4K;
        case(SIZE_16KB):  //16kb granule
            return MAX_ENTRIES_16K;
        case(SIZE_64KB):  //64kb granule
            return MAX_ENTRIES_64K;
        default:
            ERROR("       %x granularity not supported.i\n", pg_size);
            return 0;
    }
}

static
uint64_t get_block_size(uint32_t level)
{
    uint32_t entries = get_entries_per_level(pg_size);
    switch (level)
    {
        case(PGT_LEVEL_0):  // For L0 table translation
            if (pg_size == SIZE_4KB)
                return (uint64_t)(pg_size * entries * entries * entries);
            else if (pg_size == SIZE_16KB)
                return (uint64_t)(pg_size * entries * entries * 2); // only 2 lookup tables in L0
            else {
                ERROR("       L0 tables not supported for page size %x\n", pg_size);
                return 0;
            }
        case(PGT_LEVEL_1):  // For L1 table translation
            if (pg_size == SIZE_4KB || pg_size == SIZE_16KB)
                return (uint64_t)(pg_size * entries * entries);
            else
                return (uint64_t)(pg_size * entries * 64); // 64 Lookup tables in L1 (64KB Gran)
        case(PGT_LEVEL_2):  // For L2 table translation
            return (uint64_t)(pg_size * entries);
        case(PGT_LEVEL_3):  // For L3 table translation
            return (uint64_t)(pg_size);
        default:
            return 0;
    }
}

/**
  @brief   This function maps a given Physical Address into the GPT table with the specified GPI
           1. Caller       -  Test Suite
  @param   arg0 - Physical Address needed to be mapped into the GPT table
  @param   arg1 - GPI encoding required for the corresponding Physical Address
  @return  None
**/
void val_el3_add_gpt_entry(uint64_t arg0, uint64_t arg1)
{
    gpt_descriptor_t gpt_desc;
    uint64_t PA = arg0;
    uint64_t gpi = arg1;
    uint64_t base, *gpt_entry_base_0, index_0, index_1, *l0_entry, *l1_entry, *gpt_entry_base_1;
    uint8_t p, pgs[3] = {12 /*4KB*/, 16 /*64KB*/, 14 /*16KB*/};
    uint8_t pps, pps_[7] = {32 /*4GB*/, 36 /*64GB*/, 40 /*1TB*/, 42 /*4TB*/,
        44 /*16TB*/, 48 /*256TB*/, 52 /*1PB*/};
    uint8_t l0gptsz, x, l0_idx_width;

    /* Get translation attributes via GPCCR */
    uint64_t val = val_el3_read_gpccr_el3();

    gpt_desc.gpccr.pps = (val & RME_ACS_GPCCR_PPS_MASK) >> RME_ACS_GPCCR_PPS_SHIFT;
    gpt_desc.gpccr.l0gptsz = (val & RME_ACS_GPCCR_L0GPTSZ_MASK) >> RME_ACS_GPCCR_L0GPTSZ_SHIFT;
    gpt_desc.gpccr.pgs = (val & RME_ACS_GPCCR_PGS_MASK) >> RME_ACS_GPCCR_PGS_SHIFT;
    gpt_desc.gpccr.orgn = (val & RME_ACS_GPCCR_ORGN_MASK) >> RME_ACS_GPCCR_ORGN_SHIFT;
    gpt_desc.gpccr.irgn = (val & RME_ACS_GPCCR_IRGN_MASK) >> RME_ACS_GPCCR_IRGN_SHIFT;
    gpt_desc.gpccr.sh = (val & RME_ACS_GPCCR_SH_MASK) >> RME_ACS_GPCCR_SH_SHIFT;
    INFO("gpccr->pps = %d\n", gpt_desc.gpccr.pps);
    INFO("gpccr->pgs = %d\n", gpt_desc.gpccr.pgs);
    INFO("gpccr->l0gptsz = %d\n", gpt_desc.gpccr.l0gptsz);
    INFO("gpccr->orgn = %d\n", gpt_desc.gpccr.orgn);
    INFO("gpccr->irgn = %d\n", gpt_desc.gpccr.irgn);
    INFO("gpccr->sh = %d\n", gpt_desc.gpccr.sh);
        /* Get GPTBR */
    base = val_el3_read_gptbr_el3();
    INFO("GPT_base = 0x%lx\n", base);
    p = pgs[gpt_desc.gpccr.pgs];
    pps = pps_[gpt_desc.gpccr.pps];
    l0gptsz = gpt_desc.gpccr.l0gptsz + 30;
    l0_idx_width = (pps > l0gptsz) ? (pps - l0gptsz) : 0;
    /* The level 0 GPT is aligned in memory to the greater of:
        1. the size of the level 0 GPT in bytes.
        2. 4KB.
    */
    x = get_max(l0_idx_width + 3, 12);
    gpt_desc.gpt_base = (base << 12) & ~((0x1ull << x) - 1);
    VERBOSE("Level 0 Base address = 0x%lx\n", gpt_desc.gpt_base);

        /*    Level 0 GPT walk     */
    index_0 = val_el3_get_gpt_index(PA, 0, l0gptsz, pps, p);
    VERBOSE("Index at L0 = %lu  \n", index_0);
    gpt_entry_base_0 = (uint64_t *) (gpt_desc.gpt_base);
    l0_entry = &gpt_entry_base_0[index_0];
    VERBOSE("val_pe_gpt_map_add: l0 entry value = %lx     \n", *l0_entry);
    VERBOSE("val_pe_gpt_map_add: l0 entry address = %lx     \n", (uint64_t)l0_entry);

    if (IS_GPT_ENTRY_TABLE(*l0_entry))
    {
        VERBOSE("The Table Descriptor\n");
        /* Table_descriptor[63:52,11:4] = RES0 */
        *l0_entry &= ~((((0x1ull << 12) - 1) << 52) | (((0x1ull << 8) - 1) << 4));
        /* Table_descriptor[51:12] = Next level Base address */
        gpt_desc.gpt_base = *l0_entry & (((0x1ull << 40) - 1) << 12);
        VERBOSE("val_pe_gpt_map_add: gpt_desc.gpt_base at L0 = %lx     \n", gpt_desc.gpt_base);

    } else {
        /* Block_descriptor[63:8] = RES0 */
        VERBOSE("The Block Descriptor\n");
        *l0_entry = val_el3_modify_gpt_gpi(*l0_entry, PA, 0, p, gpi);
        val_el3_cln_and_invldt_cache(l0_entry);
        gpt_desc.size = p;
        gpt_desc.contig_size = l0gptsz;
        gpt_desc.level = 0;
        gpt_desc.pa = PA;
        VERBOSE("val_pe_gpt_map_add: l0 entry after modification = %lx     \n", *l0_entry);
        VERBOSE("val_pe_gpt_map_add: level  = %u     \n", gpt_desc.level);
        VERBOSE("val_pe_gpt_map_add: size  = %x     \n", gpt_desc.size);
        VERBOSE("val_pe_gpt_map_add: PA  = %lx     \n", gpt_desc.pa);
        return;
    }

        /*              Level 1 GPT walk        */
    index_1 = val_el3_get_gpt_index(PA, 1, l0gptsz, pps, p);
    VERBOSE("Index at L1= %lu  \n", index_1);
    gpt_entry_base_1 = (uint64_t *) gpt_desc.gpt_base;
    VERBOSE("val_pe_gpt_map_add: gpt_entry_base_1 = %lx     \n", (uint64_t)gpt_entry_base_1);
    l1_entry = &gpt_entry_base_1[index_1];
    VERBOSE("val_pe_gpt_map_add: l1_entry = %lx     \n", *l1_entry);
    VERBOSE("val_pe_gpt_map_add: l1_entry address = %lx     \n", (uint64_t)l1_entry);
    if (IS_GPT_ENTRY_CONTIG(*l1_entry))
    {
        /* Contiguous_descriptor[63:10] = RES0 */
        VERBOSE("The Contiguous Descriptor\n");
        *l1_entry = val_el3_modify_gpt_gpi(*l1_entry, PA, 1, p, gpi);
        val_el3_cln_and_invldt_cache(l1_entry);
        gpt_desc.size = p;
        gpt_desc.level = 1;
        //Contiguous_descriptor_entry[9:8] = Contiguous Region Size
        if (((*l1_entry >> 8) & 0x3) == 0x1)
            /* [9:8] = 0b01, then the GPT range is 2MB(21 bits) */
            gpt_desc.contig_size = 21;
        else if (((*l1_entry >> 8) & ((0x1u << 2) - 1)) == 0x2)
            /* [9:8] = 0b10, then the GPT range is 32MB(25 bits) */
            gpt_desc.contig_size = 25;
        else
            /* [9:8] = 0b11, then the GPT range is 512MB(29 bits) */
            gpt_desc.contig_size = 29;
    } else {
        VERBOSE("The Granule Descriptor\n");
        *l1_entry = val_el3_modify_gpt_gpi(*l1_entry, PA, 1, p, gpi);
        val_el3_cln_and_invldt_cache(l1_entry);
        gpt_desc.size = p;
        gpt_desc.contig_size = gpt_desc.size;                       //No Contiguity
        gpt_desc.level = 1;
    }
    gpt_desc.pa = PA;
    VERBOSE("val_pe_gpt_map_add: l1 entry after gpi modification = %lx     \n", *l1_entry);
    VERBOSE("val_pe_gpt_map_add: level  = %u     \n", gpt_desc.level);
    VERBOSE("val_pe_gpt_map_add: size  = %u     \n", gpt_desc.size);
    VERBOSE("val_pe_gpt_map_add: contiguous size  = %u     \n", gpt_desc.contig_size);
    VERBOSE("val_pe_gpt_map_add: PA  = %lx     \n", gpt_desc.pa);
    return;

}

/**
  @brief   This function provides the Index for the corresponding level of GPT
           1. Caller       -  Test Suite
           2. Prerequisite -  add_gpt_entry.
  @param   pa      -    Phyical Address that is being mapped into the GPT table.
  @param   level   -  Level needed to find out the type of descriptor entry
  @param   l0gptsz - Level 0 GPT size
  @param   pps     - Physical protected size
  @param   p       - Physical Granule Size(PGS) that is used to get the index
  @return  idx     - Index for the entry in the table
**/
uint64_t val_el3_get_gpt_index(uint64_t pa, uint8_t level, uint8_t l0gptsz, uint8_t pps, uint8_t p)
{

    uint64_t idx = 0;

    switch (level)
    {
        case 0:
            /* PA[pps-1:l0gptsz] = Level 0 Index */
            idx = (pa >> l0gptsz) & ((0x1u << (pps - l0gptsz)) - 1);
            break;
        case 1:
            /* PA[l0gptsz-1:p+4] = Level 1 Index */
            idx = (pa >> (p + 4)) & ((0x1ul << (l0gptsz - (p + 4))) - 1);
            break;
        default:
            ERROR("Not a valid Level entry");
            break;
    }
    return idx;
}

/**
  @brief   This function checks to see if a GPI value is valid
           1. Caller       -  Test Suite
           2. Prerequisite -  add_gpt_entry.
  @param   gpi  -       GPI to check for validity.
  @return  True for a valid GPI, false for an invalid one.
**/
bool val_el3_is_gpi_valid(uint64_t gpi)
{

    if ((gpi == GPT_NOACCESS) || (gpi == GPT_ANY) ||
       ((gpi >= GPT_SECURE) && (gpi <= GPT_REALM))) {
        return true;
    }
    return false;
}

/**
  @brief   This function allows user to modify the table entry to the specified GPI encoding
           1. Caller       -  Test Suite
           2. Prerequisite -  add_gpt_entry
  @param   entry - Descriptor entry that needs the GPI modification
  @param   pa    - Physical Address that is involved in the GPT mapping
  @param   level - Level needed to find out the type of descriptor entry
  @param   p     - Physical Granule Size(PGS) that is used to get the GPI index
  @param   GPI   - The specified encoding to modify the Descriptor entry with
  @return  entry - Modified entry
**/
uint64_t val_el3_modify_gpt_gpi(uint64_t entry, uint64_t pa, uint8_t level, uint8_t p, uint64_t GPI)
{

    uint64_t gpi;

    switch (level)
    {
        case 0:
            /* Block Descriptor */
            gpi = (entry >> 4) & 0xf;           //Block_descriptor[7:4] = GPI value
            VERBOSE("val_pe_gpt_map_add: gpi  = %lx     \n", gpi);
            if (!val_el3_is_gpi_valid(gpi))             //Check if the GPI value is a valid encoding
                ERROR("Invalid GPI 0x%lx", gpi);
            if (gpi != GPI)
            {
                /* To change the memory mapping to the required security state */
                entry &= ~(0xfull << 4);
                entry |= (GPI << 4);
            }
            break;
        case 1:
            if (IS_GPT_ENTRY_CONTIG(entry))
            {
                /* Contiguous Decsriptor */
                gpi = (entry >> 4) & 0xf;           //Contiguous_descriptor_entry[7:4] = GPI value
                VERBOSE("val_pe_gpt_map_add: gpi  = %lx     \n", gpi);
                //Check if the GPI value is a valid encoding
                if (!val_el3_is_gpi_valid(gpi))
                    ERROR("Invalid GPI 0x%lx", gpi);
                if (gpi != GPI)
                {
                    /* To change the memory mapping to the required security state */
                    entry &= ~(0xfull << 4);
                    entry |= (GPI << 4);
                }
                break;
            } else {
                /* Granule Descriptor */
                uint8_t gpi_index = (pa >> p) & 0xf; //PA[p+3:p] = Index for the GPI value
                /* Granules_descriptor[4*i + 3: 4*i] = GPI value */
                gpi = (entry >> (4 * gpi_index)) & 0xf;
                VERBOSE("val_pe_gpt_map_add: gpi  = %lx     \n", gpi);
                //Check if the GPI value is a valid encoding
                if (!val_el3_is_gpi_valid(gpi))
                    ERROR("Invalid GPI 0x%lx", gpi);
                if (gpi != GPI)
                {
                    /* To change the memory mapping to the required security state */
                    entry &= ~(0xfull << (4 * gpi_index));
                    entry |= (GPI << (4 * gpi_index));
                }
                break;
            }
        default:
            VERBOSE("Not a valid Level entry");
    }
    return entry;
}

/**
  @brief   This function maps a passed Virtual Address to the mentioned
           Physical Address and changes the Access PAS if it's required
           1. Caller       -  Test Suite
           2. Prerequisite -  None
  @param   arg0 - Virtual Address needed for the MMU mapping
  @param   arg1 - Physical Address needed to be mapped to the Virtual Address
  @param   arg2 - Access PAS for the corresponding mapping if specified or NON_SECURE by default
  @return  0 on Success and 1 on Failure
**/
uint32_t val_el3_add_mmu_entry(uint64_t arg0, uint64_t arg1, uint64_t arg2)
{
    uint64_t input_address = arg0, page_size;
    uint64_t output_address, attr;
    uint64_t *table_desc, tt_base_phys, *tt_base_virt;
    uint32_t num_pgt_levels, page_size_log2, index;
    uint32_t this_level, bits_remaining, bits_at_this_level, bits_per_level;
    pgt_descriptor_t pgt_desc;
    uint32_t oas_bit_arr[8] = {32, 36, 40, 42, 44, 48, 52, 56}; /* Physical address sizes */
    uint32_t tg_arr[3] = {SIZE_4KB, SIZE_16KB, SIZE_64KB}; /* Translation Granule Size */

    output_address = arg1;
    attr = arg2;
    INFO("val_pe_mmu_map_add: Output Address = 0x%lx\n", output_address);
    INFO("val_pe_mmu_map_add: Input Address = 0x%lx\n", input_address);
    INFO("val_pe_mmu_map_add: Attribute = 0x%lx\n", attr);

    val_el3_get_tcr_info(&pgt_desc.tcr);
    pgt_desc.pgt_base = val_el3_read_ttbr_el3() & AARCH64_TTBR_ADDR_MASK;
    pgt_desc.stage = PGT_STAGE1;
    pgt_desc.ias = 64 - pgt_desc.tcr.tsz;
    pgt_desc.oas = oas_bit_arr[pgt_desc.tcr.ps];
    VERBOSE("Input addr size in bits (ias) = %d\n", pgt_desc.ias);
    VERBOSE("Output addr size in bits (oas) = %d\n", pgt_desc.oas);

    page_size = tg_arr[pgt_desc.tcr.tg];
    page_size_log2 = val_el3_log2_page_size(page_size);
    bits_per_level = page_size_log2 - 3;
    num_pgt_levels = (pgt_desc.ias - page_size_log2 + bits_per_level - 1)/bits_per_level;
    num_pgt_levels = (num_pgt_levels > 4)?4:num_pgt_levels;
    tt_base_phys = pgt_desc.pgt_base;
    this_level = 0;
    bits_remaining = (num_pgt_levels - 1) * bits_per_level + page_size_log2;
    bits_at_this_level = pgt_desc.ias - bits_remaining;
    tt_base_virt = (uint64_t *)tt_base_phys;

    if (output_address >= (0x1ull << pgt_desc.oas))
    {
        ERROR("val_pe_mmu_map_add: output address size error\n");
        return 1;
    }

    if (input_address >= (0x1ull << pgt_desc.ias))
    {
        ERROR("val_pe_mmu_map_add: input address size error \
                        and truncating to %d-bits\n", pgt_desc.ias);
        input_address &= ((0x1ull << pgt_desc.ias) - 1);
    }

    while (1) {
        index = (input_address >> bits_remaining) & ((0x1ul << bits_at_this_level) - 1);
        table_desc = &tt_base_virt[index];
        INFO("val_pe_mmu_map_add: this_level = %d     \n", this_level);
        INFO("val_pe_mmu_map_add: index = %d     \n", index);
        INFO("val_pe_mmu_map_add: table_desc at level %d at address 0x%lx = %lx     \n",
            this_level, (uint64_t)table_desc, *table_desc);
        if (this_level == (num_pgt_levels - 1))
        {
            *table_desc = PGT_ENTRY_PAGE_MASK | PGT_ENTRY_VALID_MASK;
            *table_desc |= (output_address & ~(uint64_t)(page_size - 1));
            *table_desc |= attr;
            break;
        }
        /* If a descriptor has no entry or is a block descriptor or the address
         * of the descriptor is un-initialized,
         * then populate it with the right address to be used from the free memory
         */
        if (*table_desc == 0 || IS_PGT_ENTRY_BLOCK(*table_desc) || (*table_desc & 0xf) == 0xf)
        {

            tt_base_phys = free_pa;
            free_pa = free_pa + SIZE_4KB;
            *table_desc = PGT_ENTRY_TABLE_MASK | PGT_ENTRY_VALID_MASK;
            tt_base_virt = (uint64_t *)tt_base_phys;
            *table_desc |= (uint64_t)(tt_base_virt) & ~(page_size - 1);
            if (((val_el3_at_s1e3w((uint64_t)tt_base_virt)) & 0x1) == 0x1)
                val_el3_add_mmu_entry((uint64_t)tt_base_virt,
                                      (uint64_t)tt_base_virt, NONSECURE_PAS);
            VERBOSE("val_pe_mmu_map_add: table_desc = %lx     \n", *table_desc);
            ++this_level;
            bits_remaining -= bits_per_level;
            bits_at_this_level = bits_per_level;
            continue;
        }
        if (IS_PGT_ENTRY_BLOCK(*table_desc))
        {
            *table_desc = PGT_ENTRY_PAGE_MASK | PGT_ENTRY_VALID_MASK;
            *table_desc |= (output_address & ~(bits_remaining - 1));
            *table_desc |= attr;
            break;
        }

        tt_base_phys = *table_desc & (((0x1ull << (48 - page_size_log2)) - 1) << page_size_log2);
        tt_base_virt = (uint64_t *)tt_base_phys;
        ++this_level;
        bits_remaining -= bits_per_level;
        bits_at_this_level = bits_per_level;
    }
    val_el3_cln_and_invldt_cache(table_desc);
    INFO("val_pe_mmu_map_add: table_desc = %lx     \n", *table_desc);
    return 0;
}

uint64_t
val_el3_modify_desc(uint64_t table_desc, uint8_t start_bit, uint64_t value_to_set, uint8_t num_bits)
{

    uint64_t bit_mask = 1, bin_mltpl = 2;
    while (num_bits)
    {
        bit_mask *= bin_mltpl;
        --num_bits;
    }
    bit_mask -= 1;
    /* To clear the bits from "start_bit" to "start_bit + num_bits" position */
    table_desc &= ~(bit_mask << start_bit);
    /* To set the bits at the "start_bit" position to required value_to_set */
    return table_desc |= (value_to_set << start_bit);

}

uint32_t val_el3_log2_page_size(uint64_t size)
{
    int bit = 0;

    while (size != 0)
    {
        if (size & 1)
            return bit;
        size >>= 1;
        ++bit;
    }
    return 0;
}

/**
  @brief   This API reads the TCR register and fills info to structure.
           1. Caller       -  Test Suite
           2. Prerequisite -  None
  @param   *tcr_el3 - To fill the TCR information.
  @return  None
**/
void val_el3_get_tcr_info(TCR_EL3_INFO *tcr_el3)
{

  uint64_t tcr_val;

  tcr_val = val_el3_read_tcr_el3();
  tcr_el3->tg = (tcr_val & TCR_EL3_TG0_MASK) >> TCR_EL3_TG0_SHIFT;
  tcr_el3->ps = (tcr_val & TCR_EL3_PS_MASK) >> TCR_EL3_PS_SHIFT;
  tcr_el3->sh = (tcr_val & TCR_EL3_SH0_MASK) >> TCR_EL3_SH0_SHIFT;
  tcr_el3->orgn = (tcr_val & TCR_EL3_IRGN0_MASK) >> TCR_EL3_IRGN0_SHIFT;
  tcr_el3->tsz = (tcr_val & TCR_EL3_T0SZ_MASK) >> TCR_EL3_T0SZ_SHIFT;
}

/**
 * @brief Populate a page table level with valid translation entries.
 *
 * @param tt_desc     Translation table descriptor for the current level.
 * @param mem_desc    Memory region descriptor to be mapped.
 * @return 0 on success, 1 on failure.
 */
static uint32_t fill_translation_table(tt_descriptor_t tt_desc,
                                       memory_region_descriptor_t *mem_desc)
{
    uint64_t block_size = 0x1ull << tt_desc.size_log2;
    uint64_t input_address, output_address, filled_tables, table_index, max_allowed_mem;
    uint64_t *tt_base_next_level, *table_desc;
    tt_descriptor_t tt_desc_next_level;

    INFO("      tt_desc.level: %d\n", tt_desc.level);
    INFO("      tt_desc.input_base: 0x%lx\n", tt_desc.input_base);
    INFO("      tt_desc.input_top: 0x%lx\n", tt_desc.input_top);
    INFO("      tt_desc.output_base: 0x%lx\n", tt_desc.output_base);
    INFO("      tt_desc.size_log2: %d\n", tt_desc.size_log2);
    INFO("      tt_desc.nbits: %d\n", tt_desc.nbits);

    if (!is_values_init) {
        val_el3_setup_acs_pgt_values();
        is_values_init = 1;
    }

    for (input_address = tt_desc.input_base, output_address = tt_desc.output_base;
         input_address < tt_desc.input_top;
         input_address += (block_size - offset), output_address += (block_size - offset))
    {
        table_index = input_address >> tt_desc.size_log2 & ((0x1ull << tt_desc.nbits) - 1);
        table_desc = &tt_desc.tt_base[table_index];

        INFO("      table_index = %lx\n", table_index);

        if (tt_desc.level == 3)
        {
            //Create level 3 page descriptor entry
            *table_desc = PGT_ENTRY_PAGE_MASK | PGT_ENTRY_VALID_MASK;
            *table_desc |= (output_address & ~(uint64_t)(pg_size - 1));
            *table_desc |= mem_desc->attributes;
            *table_desc |= PGT_ENTRY_ACCESS_SET;
            INFO("      page_descriptor = 0x%lx\n", *table_desc);
            /* Keep a count of number of L3 tables filled. If the number exceedes the limit, move
               to next L2 table and continue.  */
            increment_pgt_index(tt_desc.level, get_entries_per_level(pg_size));
            offset = 0;
            continue;
        }

        //Are input and output addresses eligible for being described via block descriptor?
        if ((input_address & (block_size - 1)) == 0 &&
             (output_address & (block_size - 1)) == 0 &&
             tt_desc.input_top >= (input_address + block_size - 1)) {
            //Create a block descriptor entry
            *table_desc = PGT_ENTRY_BLOCK_MASK | PGT_ENTRY_VALID_MASK;
            *table_desc |= (output_address & ~(block_size - 1));
            *table_desc |= mem_desc->attributes;
            *table_desc |= PGT_ENTRY_ACCESS_SET;
            INFO("      block_descriptor = 0x%lx\n", *table_desc);
            increment_pgt_index(tt_desc.level, get_entries_per_level(pg_size));
            offset = 0;
            continue;
        }
        /*
        If there's no descriptor populated at current index of this page_table, or
        If there's a block descriptor, allocate new page, else use the already populated address.
        Block descriptor info will be overwritten in case its there.
        */
        if (*table_desc == 0 || IS_PGT_ENTRY_BLOCK(*table_desc))
        {
            tt_base_next_level = val_el3_memory_alloc(SIZE_4KB, SIZE_4KB);
            if (tt_base_next_level == NULL)
            {
                ERROR("  fill_translation_table: page allocation failed\n");
                return 1;
            }
            val_el3_memory_set(tt_base_next_level, pg_size, 0);
        } else
            tt_base_next_level = val_el3_memory_phys_to_virt(*table_desc & pgt_addr_mask);

        tt_desc_next_level.tt_base    = tt_base_next_level;
        tt_desc_next_level.input_base = input_address;
        filled_tables                 = get_pgt_index(tt_desc.level + 1);
        offset                        = filled_tables * get_block_size(tt_desc.level + 1);

        INFO("       filled_tables in next level = 0x%lx\n", filled_tables);
        INFO("       offset = 0x%lx\n", offset);

        // Calculate the maximum allowed mem addr that can be mapped for the L0/L1/L2 table.
        // This prevents overwriting page tables.
        max_allowed_mem                = input_address + block_size - offset - 1;
        tt_desc_next_level.input_top   = get_min(tt_desc.input_top, max_allowed_mem);
        tt_desc_next_level.output_base = output_address;
        tt_desc_next_level.level       = tt_desc.level + 1;
        tt_desc_next_level.size_log2   = tt_desc.size_log2 - bits_p_level;
        tt_desc_next_level.nbits       = bits_p_level;
        increment_pgt_index(tt_desc.level, get_entries_per_level(pg_size));

        if (fill_translation_table(tt_desc_next_level, mem_desc))
        {
            val_el3_memory_free(tt_base_next_level);
            return 1;
        }

        *table_desc = PGT_ENTRY_TABLE_MASK | PGT_ENTRY_VALID_MASK;
        *table_desc |= (uint64_t)val_el3_memory_virt_to_phys(tt_base_next_level)
                                                             & ~(uint64_t)(pg_size - 1);
        INFO("      Table descriptor address = 0x%lx\n", (uint64_t) table_desc);
        INFO("      table_descriptor = 0x%lx\n", *table_desc);
    }
    return 0;
}

/**
 * @brief Create page tables to map the specified memory regions.
 *
 * @param mem_desc    Memory region descriptor list to be mapped.
 * @param pgt_desc    Page table configuration descriptor (input/output).
 * @return 0 on success, 1 on failure.
 */
uint32_t val_el3_realm_pgt_create(memory_region_descriptor_t *mem_desc, pgt_descriptor_t *pgt_desc)
{
    uint64_t *tt_base;
    tt_descriptor_t tt_desc;
    uint32_t num_pgt_levels, page_size_log2;
    memory_region_descriptor_t *mem_desc_iter;

    pg_size = SIZE_4KB;
    page_size_log2 = val_el3_log2_page_size(pg_size);
    bits_p_level = page_size_log2 - 3;
    num_pgt_levels = (pgt_desc->ias - page_size_log2 + bits_p_level - 1)/bits_p_level;
    num_pgt_levels = (num_pgt_levels > 4)?4:num_pgt_levels;
    INFO("      val_pgt_create: nbits_per_level = %d\n", bits_p_level);
    INFO("      val_pgt_create: page_size_log2 = %d\n", page_size_log2);

    /* check whether input page descriptor has base addr of translation table
       to use. If the pgt_base member is NULL allocate a page to create a new
       table, else update existing translation table */
    if (pgt_desc->pgt_base == (uint64_t) NULL) {
        tt_base = (uint64_t *) val_el3_memory_alloc(SIZE_4KB, SIZE_4KB);
        if (tt_base == NULL) {
            ERROR("      val_pgt_create: page allocation failed\n");
            return 1;
        }
        val_el3_memory_set(tt_base, pg_size, 0);
    }
    else
        tt_base = (uint64_t *) pgt_desc->pgt_base;

    tt_desc.tt_base = tt_base;
    pgt_addr_mask = ((0x1ull << (48 - page_size_log2)) - 1) << page_size_log2;

    for (mem_desc_iter = mem_desc; mem_desc_iter->length != 0; ++mem_desc_iter)
    {
        INFO("      val_pgt_create:i/p addr 0x%lx\n", mem_desc->virtual_address);
        INFO("      val_pgt_create:o/p addr 0x%lx\n", mem_desc->physical_address);
        INFO("      val_pgt_create:length 0x%lx\n\n ", mem_desc->length);
        if ((mem_desc->virtual_address & (uint64_t)(pg_size - 1)) != 0 ||
            (mem_desc->physical_address & (uint64_t)(pg_size - 1)) != 0)
            {
                ERROR("      val_pgt_create: address alignment error\n");
                return 1;
            }

        if (mem_desc->physical_address >= (0x1ull << pgt_desc->oas))
        {
            ERROR("      val_pgt_create: output address size error\n");
            return 1;
        }

        if (mem_desc->virtual_address >= (0x1ull << pgt_desc->ias))
        {
            ERROR("      val_pgt_create: input address size error \
                            and truncating to %d-bits\n", pgt_desc->ias);
            mem_desc->virtual_address &= ((0x1ull << pgt_desc->ias) - 1);
        }

#ifndef TARGET_BM_BOOT
        // TCR won't be populated for the initial PGT that are created for MMU init.
        // Removing this check in case of baremetal boot flow.
        if ((pgt_desc->vtcr.tg_size_log2) != page_size_log2)
        {
            ERROR("      val_pgt_create: input page_size 0x%x \
                            not supported\n", (0x1 << pgt_desc->vtcr.tg_size_log2));
            return 1;
        }
#endif
        tt_desc.input_base = mem_desc->virtual_address & ((0x1ull << pgt_desc->ias) - 1);
        tt_desc.input_top = tt_desc.input_base + mem_desc->length - 1;
        tt_desc.output_base = mem_desc->physical_address & ((0x1ull << pgt_desc->oas) - 1);
        tt_desc.level = 4 - num_pgt_levels;
        tt_desc.size_log2 = (num_pgt_levels - 1) * bits_p_level + page_size_log2;
        tt_desc.nbits = pgt_desc->ias - tt_desc.size_log2;

        if (fill_translation_table(tt_desc, mem_desc))
        {
            val_el3_memory_free(tt_base);
            return 1;
        }
    }

    pgt_desc->pgt_base = (uint64_t)val_el3_memory_virt_to_phys(tt_base);

    return 0;
}

/**
 * @brief Recursively free page tables starting from the given level.
 *
 * @param tt_base             Base virtual address of the page table.
 * @param bits_at_this_level Number of bits used at this page table level.
 * @param this_level         Current page table level (0-3).
 * @return void
 */
static void free_translation_table(uint64_t *tt_base, uint32_t bits_at_this_level,
                                                                 uint32_t this_level)
{
    uint32_t index;
    uint64_t *tt_base_next_virt;

    if (this_level == 3)
        return;
    for (index = 0; index < (0x1ul << bits_at_this_level); ++index)
    {
        if (tt_base[index] != 0)
        {
            if (IS_PGT_ENTRY_BLOCK(tt_base[index]))
                continue;
            tt_base_next_virt = val_el3_memory_phys_to_virt((tt_base[index] & pgt_addr_mask));
            if (tt_base_next_virt == NULL)
                continue;
            free_translation_table(tt_base_next_virt, bits_p_level, this_level+1);
            INFO("      free_translation_table: \
                        tt_base_next_virt = %lx\n", (uint64_t)tt_base_next_virt);
            val_el3_memory_free(tt_base_next_virt);
        }
    }
}

/**
 *  @brief Free all page tables in the page table hierarchy starting from the base page table.
 *
 *  @param pgt_desc - page table base and translation attributes.
 *
 *  @return void
**/
void val_el3_realm_pgt_destroy(pgt_descriptor_t *pgt_desc)
{
    uint32_t page_size_log2, num_pgt_levels;
    uint64_t *pgt_base_virt = val_el3_memory_phys_to_virt(pgt_desc->pgt_base);

    if (!pgt_desc->pgt_base)
        return;

    INFO("      val_pgt_destroy: pgt_base = %lx\n", pgt_desc->pgt_base);
    page_size_log2 = val_el3_log2_page_size(pg_size);
    bits_p_level =  page_size_log2 - 3;
    pgt_addr_mask = ((0x1ull << (pgt_desc->ias - page_size_log2)) - 1) << page_size_log2;
    num_pgt_levels = (pgt_desc->ias - page_size_log2 + bits_p_level - 1)/bits_p_level;

    free_translation_table(pgt_base_virt,
                           pgt_desc->ias - ((num_pgt_levels - 1) * bits_p_level + page_size_log2),
                           4 - num_pgt_levels);
    val_el3_memory_free(pgt_base_virt);
}
