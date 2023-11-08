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

#include <val_el3/ack_include.h>

uint64_t free_pa = FREE_MEM_START;

/**
  @brief   This function maps a given Physical Address into the GPT table with the specified GPI
           1. Caller       -  Test Suite
  @param   arg0 - Physical Address needed to be mapped into the GPT table
  @param   arg1 - GPI encoding required for the corresponding Physical Address
  @return  None
**/
void add_gpt_entry(uint64_t arg0, uint64_t arg1)
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
    uint64_t val = read_gpccr_el3();

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
    base = read_gptbr_el3();
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
    index_0 = get_gpt_index(PA, 0, l0gptsz, pps, p);
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
        *l0_entry = modify_gpt_gpi(*l0_entry, PA, 0, p, gpi);
        cln_and_invldt_cache(l0_entry);
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
    index_1 = get_gpt_index(PA, 1, l0gptsz, pps, p);
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
        *l1_entry = modify_gpt_gpi(*l1_entry, PA, 1, p, gpi);
        cln_and_invldt_cache(l1_entry);
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
        *l1_entry = modify_gpt_gpi(*l1_entry, PA, 1, p, gpi);
        cln_and_invldt_cache(l1_entry);
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
uint64_t get_gpt_index(uint64_t pa, uint8_t level, uint8_t l0gptsz, uint8_t pps, uint8_t p)
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
            INFO("Not a valid Level entry");
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
bool is_gpi_valid(uint64_t gpi)
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
uint64_t modify_gpt_gpi(uint64_t entry, uint64_t pa, uint8_t level, uint8_t p, uint64_t GPI)
{

    uint64_t gpi;

    switch (level)
    {
        case 0:
            /* Block Descriptor */
            gpi = (entry >> 4) & 0xf;           //Block_descriptor[7:4] = GPI value
            VERBOSE("val_pe_gpt_map_add: gpi  = %lx     \n", gpi);
            if (!is_gpi_valid(gpi))             //Check if the GPI value is a valid encoding
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
                if (!is_gpi_valid(gpi))             //Check if the GPI value is a valid encoding
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
                if (!is_gpi_valid(gpi))              //Check if the GPI value is a valid encoding
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
  @return  None
**/
void add_mmu_entry(uint64_t arg0, uint64_t arg1, uint64_t arg2)
{
    uint64_t input_address = arg0, page_size;
    uint64_t output_address, acc_pas, attr, share_attr, cache_attr;
    uint64_t *table_desc, tt_base_phys, *tt_base_virt;
    uint32_t num_pgt_levels, page_size_log2, index;
    uint32_t this_level, bits_remaining, bits_at_this_level, bits_per_level;
    uint32_t attr_indx;
    uint64_t mair_val;
    pgt_descriptor_t pgt_desc;

    attr = arg2;
    acc_pas = VAL_EXTRACT_BITS(attr, 0, 1);
    share_attr = VAL_EXTRACT_BITS(attr, 2, 3);
    cache_attr = VAL_EXTRACT_BITS(attr, 4, 11);
    output_address = arg1;

    INFO("val_pe_mmu_map_add: Output Address = 0x%lx\n", output_address);
    INFO("val_pe_mmu_map_add: Input Address = 0x%lx\n", input_address);
    INFO("val_pe_mmu_map_add: Access PAS = 0x%lx\n", acc_pas);

    pgt_desc.pgt_base = read_ttbr_el3() & AARCH64_TTBR_ADDR_MASK;
    pgt_desc.stage = PGT_STAGE1;
    pgt_desc.ias = PGT_IAS;
    pgt_desc.oas = PAGT_OAS;
    page_size = SIZE_4KB;
    page_size_log2 = log2_page_size(page_size);
    bits_per_level = page_size_log2 - 3;
    num_pgt_levels = (pgt_desc.ias - page_size_log2 + bits_per_level - 1)/bits_per_level;
    num_pgt_levels = (num_pgt_levels > 4)?4:num_pgt_levels;
    tt_base_phys = pgt_desc.pgt_base;
    this_level = 4 - num_pgt_levels;
    bits_remaining = (num_pgt_levels - 1) * bits_per_level + page_size_log2;
    bits_at_this_level = pgt_desc.ias - bits_remaining;
    tt_base_virt = (uint64_t *)tt_base_phys;
    while (1) {
        index = (input_address >> bits_remaining) & ((0x1ul << bits_at_this_level) - 1);
        table_desc = &tt_base_virt[index];
        INFO("val_pe_mmu_map_add: this_level = %d     \n", this_level);
        INFO("val_pe_mmu_map_add: index = %d     \n", index);
        INFO("val_pe_mmu_map_add: table_desc at level %d at address 0x%lx = %lx     \n",
            this_level, (uint64_t)table_desc, *table_desc);
        if (this_level == 3)
        {
            *table_desc = PGT_ENTRY_PAGE_MASK | PGT_ENTRY_VALID_MASK;
            *table_desc |= PGT_STAGE1_AP_RW;
            *table_desc |= (output_address & ~(uint64_t)(page_size - 1));
            *table_desc |= PGT_ENTRY_ACCESS_SET;
            /* To set the NS and NSE bits of descriptor according to the requested PAS */
            *table_desc = modify_desc(*table_desc, DESC_NSE_BIT, NSE_SET(acc_pas), 1);
            *table_desc = modify_desc(*table_desc, DESC_NS_BIT, NS_SET(acc_pas), 1);
            /* Set the shareabality attribute */
            *table_desc |= modify_desc(*table_desc, PGT_SHAREABLITY_SHIFT, share_attr, 2);
	    /* Set the cacheability attribute if specified */
	    if (cache_attr != 0) {
              attr_indx = val_get_pgt_attr_indx(*table_desc);
              mair_val = modify_desc(read_mair_el3(), MAIR_ATTR_SHIFT(attr_indx), cache_attr, 8);
              write_mair_el3(mair_val);
	    }
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
            if (((at_s1e3w((uint64_t)tt_base_virt)) & 0x1) == 0x1)
                add_mmu_entry((uint64_t)tt_base_virt, (uint64_t)tt_base_virt, NONSECURE_PAS);
            VERBOSE("val_pe_mmu_map_add: table_desc = %lx     \n", *table_desc);
            ++this_level;
            bits_remaining -= bits_per_level;
            bits_at_this_level = bits_per_level;
            continue;
        }
        if (IS_PGT_ENTRY_BLOCK(*table_desc))
        {
            *table_desc = PGT_ENTRY_PAGE_MASK | PGT_ENTRY_VALID_MASK;
            *table_desc |= PGT_STAGE1_AP_RW;
            *table_desc |= (output_address & ~(bits_remaining - 1));
            *table_desc |= PGT_ENTRY_ACCESS_SET;
            /* To set the NS and NSE bits of descriptor according to the requested PAS */
            *table_desc = modify_desc(*table_desc, DESC_NSE_BIT, NSE_SET(acc_pas), 1);
            *table_desc = modify_desc(*table_desc, DESC_NS_BIT, NS_SET(acc_pas), 1);
	    /* Set the shareabality attribute */
	    *table_desc |= modify_desc(*table_desc, PGT_SHAREABLITY_SHIFT, share_attr, 2);
	    /* Set the cacheability attribute if specified */
            if (cache_attr != 0) {
              attr_indx = val_get_pgt_attr_indx(*table_desc);
              mair_val = modify_desc(read_mair_el3(), MAIR_ATTR_SHIFT(attr_indx), cache_attr, 8);
              write_mair_el3(mair_val);
            }
            break;
        }

        tt_base_phys = *table_desc & (((0x1ull << (48 - page_size_log2)) - 1) << page_size_log2);
        tt_base_virt = (uint64_t *)tt_base_phys;
        ++this_level;
        bits_remaining -= bits_per_level;
        bits_at_this_level = bits_per_level;
    }
    cln_and_invldt_cache(table_desc);
    INFO("val_pe_mmu_map_add: table_desc = %lx     \n", *table_desc);
    return;
}

uint64_t
modify_desc(uint64_t table_desc, uint8_t start_bit, uint64_t value_to_set, uint8_t num_bits)
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

uint32_t log2_page_size(uint64_t size)
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

uint32_t val_get_pgt_attr_indx(uint64_t table_desc)
{
    uint32_t attr_indx;

    attr_indx = ((table_desc & MAIR_ATTR_INDX_MASK) >> MAIR_ATTR_INDX_SHIFT);
    return attr_indx;
}
