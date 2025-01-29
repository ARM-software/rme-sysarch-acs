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

#include "val_el3/smmuv3_el3.h"
#include <stdlib.h>

#define MEMORY_POOL_SIZE (2 * 1024 * 1024)
#define HARD_CODED_ADDRESS (void *)(FREE_MEM_SMMU) // Replace with a valid hardcoded address

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

static MemoryPool mem_pool = {
    .base = (uint8_t *)HARD_CODED_ADDRESS, // Hardcoded address
    .size = MEMORY_POOL_SIZE,
    .free_list = NULL,
};

// Initialize the memory pool with a single large free block
void memory_pool_init(void)
{
    mem_pool.free_list = (BlockHeader *)mem_pool.base;
    mem_pool.free_list->size = mem_pool.size - sizeof(BlockHeader);
    mem_pool.free_list->is_free = 1;
    mem_pool.free_list->next = NULL;
}

// Split a large free block into two smaller blocks
void split_block(BlockHeader *block, size_t size)
{
    BlockHeader *new_block = (BlockHeader *)((uint8_t *)block + sizeof(BlockHeader) + size);
    new_block->size = block->size - size - sizeof(BlockHeader);
    new_block->is_free = 1;
    new_block->next = block->next;

    block->size = size;
    block->next = new_block;
}

// Aligns a given size to the nearest multiple of `alignment`
static size_t align_size(size_t size, size_t alignment)
{
    return (size + (alignment - 1)) & ~(alignment - 1);
}

// Allocate memory from the pool
void *my_malloc(size_t size, size_t alignment)
{
    if (!mem_pool.free_list) {
        memory_pool_init(); // Initialize pool on first call
    }

    size = align_size(size, alignment); // Align the requested size
    BlockHeader *current = mem_pool.free_list;

    while (current) {
        // Align the starting address of the block
        uintptr_t block_start = (uintptr_t)current + sizeof(BlockHeader);
        uintptr_t aligned_start = align_size(block_start, alignment);
        size_t alignment_padding = aligned_start - block_start;

        if (current->is_free && current->size >= size + alignment_padding) {
            if (current->size > size + alignment_padding + sizeof(BlockHeader)) {
                split_block(current, size + alignment_padding);
            }
            current->is_free = 0;
            return (void *)aligned_start;
        }
        current = current->next;
    }

    return NULL;
}

// Free allocated memory
void my_free(void *ptr)
{
    if (!ptr) return;

    BlockHeader *block = (BlockHeader *)((uint8_t *)ptr - sizeof(BlockHeader));
    block->is_free = 1;

    // Coalesce adjacent free blocks
    BlockHeader *current = mem_pool.free_list;
    while (current) {
        if (current->is_free && current->next && current->next->is_free) {
            current->size += current->next->size + sizeof(BlockHeader);
            current->next = current->next->next;
        }
        current = current->next;
    }
}

// Allocate and zero-initialize memory
void *my_calloc(size_t num, size_t size, size_t alignment)
{
    size_t total_size = num * size;
    void *ptr = my_malloc(total_size, alignment);
    if (ptr) {
        memset(ptr, 0, total_size);
    }
    return ptr;
}

smmu_dev_t *g_smmu;
uint32_t g_num_smmus;
uint32_t g_sid;

struct smmu_master_node {
    smmu_master_t *master;
    struct smmu_master_node *next;
};

struct smmu_master_node *g_smmu_master_list_head = NULL;

#define dsb(scope) asm volatile("dsb " #scope : : : "memory")

static inline void val_mmio_write(uintptr_t addr, uint32_t val)
{
        (void)addr;
        (void)val;

        dsb(st);
        asm volatile("str %w0, [%1]" :  : "r" (val), "r" (addr));
        dsb(st);
}

static inline uint32_t val_mmio_read(uintptr_t addr)
{
        uint32_t val;

        (void)addr;

        dsb(ld);
        asm volatile("ldr %w0, [%1]" : "=r" (val) : "r" (addr));
        dsb(ld);
        return val;
}

static inline void val_mmio_write64(uintptr_t addr, uint64_t val)
{
        (void)addr;
        (void)val;

        dsb(st);
        asm volatile("str %0, [%1]" :  : "r" (val), "r" (addr));
        dsb(st);
}

void *val_memory_virt_to_phys(void *va)
{
    return va;
}

void *
val_memory_alloc(uint32_t size, size_t alignment)
{
    return my_malloc(size, alignment);
}

void *
val_memory_calloc(uint32_t num, uint32_t size, size_t alignment)
{
    return my_calloc(num, size, alignment);
}

void
val_memory_set(void *buf, uint32_t size, uint8_t value)
{
    memset(buf, value, size);
}

void
val_memory_free(void *addr)
{
    my_free(addr);
}

static uint64_t align_to_size(uint64_t addr,  uint64_t size)
{
    return ((size - (addr & (size-1)) + addr) & ~(size-1));
}

static uint32_t smmu_cmdq_inc_prod(smmu_queue_t *q)
{
    return (q->prod + 1) & ((0x1ul << (q->log2nent + 1)) - 1);
}

static uint32_t smmu_queue_full(smmu_queue_t *q)
{
    uint32_t index_mask = ((0x1ul << q->log2nent) - 1);
    uint32_t wrap_mask = (0x1ul << q->log2nent);

    return ((q->prod & index_mask) == (q->cons & index_mask)) &&
           ((q->prod & wrap_mask) != (q->cons & wrap_mask));
}

static uint32_t smmu_queue_empty(smmu_queue_t *q)
{
    uint32_t index_mask = ((0x1ul << q->log2nent) - 1);
    uint32_t wrap_mask = (0x1ul << q->log2nent);

    return ((q->prod & index_mask) == (q->cons & index_mask)) &&
           ((q->prod & wrap_mask) == (q->cons & wrap_mask));
}

static int smmu_cmdq_build_cmd(uint64_t *cmd, uint8_t opcode)
{
    val_memory_set(cmd, QUEUE_DWORDS_PER_ENT << 3, 0);
    cmd[0] |= BITFIELD_SET(CMDQ_0_OP, opcode);

    switch (opcode) {
    case CMDQ_OP_TLBI_EL2_ALL:
    case CMDQ_OP_TLBI_NSNH_ALL:
    case CMDQ_OP_CMD_SYNC:
        break;
    case CMDQ_OP_CFGI_ALL:
        cmd[1] |= BITFIELD_SET(CMDQ_CFGI_1_RANGE, CMDQ_CFGI_1_ALL_STES);
        break;
    case CMDQ_OP_PREFETCH_CFG:
        cmd[0] |= ((unsigned long)((g_sid) & (CMD_SID_MASK)) << (CMD_SID_SHIFT));
        break;
    case CMDQ_OP_CFGI_STE:
        cmd[0] |= ((unsigned long)((g_sid) & (CMD_SID_MASK)) << (CMD_SID_SHIFT));
                cmd[1] = 1;
                break;
    default:
        ERROR("\n      Unsupported SMMU command 0x%x    ", opcode);
        return -1;
    }

    return 0;
}

static int smmu_cmdq_write_cmd(smmu_dev_t *smmu, uint64_t *cmd)
{
    uint32_t timeout = SMMU_CMDQ_POLL_TIMEOUT;
    int ret = 0, i;
    uint64_t *cmd_dst;
    smmu_queue_type_t *cmdq = &smmu->cmd_type;

    smmu_queue_t queue = {
                .log2nent = cmdq->queue.log2nent,
            };

    while (smmu_queue_full(&cmdq->queue) && timeout)
        timeout--;

    if (!timeout) {
        ERROR("\n      SMMU CMD queue is full     ");
        return -1;
    }

    queue.prod = val_mmio_read((uint64_t)cmdq->prod_reg);
    cmd_dst = (uint64_t *)(cmdq->base +
              ((queue.prod & ((0x1ull << queue.log2nent) - 1)) *
              (cmdq->entry_size)));
    for (i = 0; i < QUEUE_DWORDS_PER_ENT; ++i)
        cmd_dst[i] = cmd[i];
    queue.prod = smmu_cmdq_inc_prod(&queue);

#ifndef TARGET_LINUX
    dsb(sy);
#endif
    val_mmio_write((uint64_t)cmdq->prod_reg, queue.prod);

    return ret;
}

static int smmu_cmdq_issue_cmd(smmu_dev_t *smmu,
                   uint8_t opcode)
{
    uint64_t cmd[QUEUE_DWORDS_PER_ENT];

    if (smmu_cmdq_build_cmd(cmd, opcode))
        return -1;

    return smmu_cmdq_write_cmd(smmu, cmd);
}

static void smmu_cmdq_poll_until_consumed(smmu_dev_t *smmu)
{
    uint32_t timeout = SMMU_CMDQ_POLL_TIMEOUT;
    smmu_queue_type_t *cmdq = &smmu->cmd_type;
    smmu_queue_t queue = {
                .log2nent = smmu->cmd_type.queue.log2nent,
                .prod = val_mmio_read((uint64_t)smmu->cmd_type.prod_reg),
                .cons = val_mmio_read((uint64_t)smmu->cmd_type.cons_reg)
            };

    while (timeout > 0) {
        if (smmu_queue_empty(&queue))
            break;
        queue.cons = val_mmio_read((uint64_t)cmdq->cons_reg);
        timeout--;
    }

    if (!timeout) {
        ERROR("\n    CMDQ poll timeout at 0x%08x       ", queue.prod);
        ERROR("\n    prod_reg = 0x%08x       ", val_mmio_read((uint64_t)smmu->cmd_type.prod_reg));
        ERROR("\n    cons_reg = 0x%08x       ", val_mmio_read((uint64_t)smmu->cmd_type.cons_reg));
        ERROR("\n    gerror   = 0x%08x       ", val_mmio_read(smmu->base + SMMU_R_GERROR));
    }
}

static void smmu_tlbi_cached_ste(smmu_dev_t *smmu)
{
    /* Invalidate any cached configuration */
    smmu_cmdq_issue_cmd(smmu, CMDQ_OP_CFGI_STE);
    smmu_cmdq_issue_cmd(smmu, CMDQ_OP_CMD_SYNC);

    smmu_cmdq_poll_until_consumed(smmu);
}

static void smmu_tlbi_prefetch_cfg(smmu_dev_t *smmu)
{
    /* Invalidate any cached configuration */
    smmu_cmdq_issue_cmd(smmu, CMDQ_OP_CFGI_STE);

    smmu_cmdq_poll_until_consumed(smmu);
}

static void smmu_tlbi_cfgi(smmu_dev_t *smmu)
{
    /* Invalidate any cached configuration */
    smmu_cmdq_issue_cmd(smmu, CMDQ_OP_CFGI_ALL);
    if (smmu->supported.hyp)
        smmu_cmdq_issue_cmd(smmu, CMDQ_OP_TLBI_EL2_ALL);
    smmu_cmdq_issue_cmd(smmu, CMDQ_OP_TLBI_NSNH_ALL);
    smmu_cmdq_issue_cmd(smmu, CMDQ_OP_CMD_SYNC);

    smmu_cmdq_poll_until_consumed(smmu);
}

static void smmu_strtab_write_ste(smmu_master_t *master, uint64_t *ste, smmu_dev_t *smmu)
{
    uint64_t val = STRTAB_STE_0_V;
    smmu_stage2_config_t *stage2_cfg = NULL;
    smmu_stage1_config_t *stage1_cfg = NULL;

    if (master) {
        switch (master->stage) {
        case SMMU_STAGE_S1:
            stage1_cfg = &master->stage1_config;
            break;
        case SMMU_STAGE_S2:
            stage2_cfg = &master->stage2_config;
            break;
        case SMMU_STAGE_BYPASS:
            val |= BITFIELD_SET(STRTAB_STE_0_CONFIG,
                    STRTAB_STE_0_CONFIG_BYPASS);
            ste[0] = val;
            ste[1] = BITFIELD_SET(STRTAB_STE_1_SHCFG,
                     STRTAB_STE_1_SHCFG_INCOMING);
            ste[2] = 0;
            return;
        default:
            return;
        }
    }
    else
    {
        val |= BITFIELD_SET(STRTAB_STE_0_CONFIG,
                    STRTAB_STE_0_CONFIG_BYPASS);

        ste[0] = val;
        ste[1] = BITFIELD_SET(STRTAB_STE_1_SHCFG,
                 STRTAB_STE_1_SHCFG_INCOMING);
        ste[2] = 0;
        return;
    }

    if (stage2_cfg) {
        ste[1] |= BITFIELD_SET(STRTAB_STE_1_STRW, 0x2) |
                  BITFIELD_SET(STRTAB_STE_1_EATS, 0x1);
        ste[2] = (BITFIELD_SET(STRTAB_STE_2_S2VMID, stage2_cfg->vmid) |
              BITFIELD_SET(STRTAB_STE_2_VTCR, stage2_cfg->vtcr) |
              STRTAB_STE_2_S2PTW | STRTAB_STE_2_S2AA64 |
              STRTAB_STE_2_S2R);

        ste[3] = (stage2_cfg->vttbr & STRTAB_STE_3_S2TTB_MASK);

        val |= BITFIELD_SET(STRTAB_STE_0_CONFIG, STRTAB_STE_0_CONFIG_S2_TRANS);
    }

    if (stage1_cfg) {
        ste[1] = BITFIELD_SET(STRTAB_STE_1_S1DSS, STRTAB_STE_1_S1DSS_SSID0) |
             BITFIELD_SET(STRTAB_STE_1_S1CIR, STRTAB_STE_1_S1C_CACHE_WBRA) |
             BITFIELD_SET(STRTAB_STE_1_S1COR, STRTAB_STE_1_S1C_CACHE_WBRA) |
             BITFIELD_SET(STRTAB_STE_1_S1CSH, SMMU_SH_ISH) |
             BITFIELD_SET(STRTAB_STE_1_EATS, 0x1);

        val |= (stage1_cfg->cdcfg.cdtab_phys &
            (STRTAB_STE_0_S1CONTEXTPTR_MASK << STRTAB_STE_0_S1CONTEXTPTR_SHIFT)) |
            BITFIELD_SET(STRTAB_STE_0_CONFIG, STRTAB_STE_0_CONFIG_S1_TRANS) |
            BITFIELD_SET(STRTAB_STE_0_S1CDMAX, stage1_cfg->s1cdmax) |
            BITFIELD_SET(STRTAB_STE_0_S1FMT, stage1_cfg->s1fmt);
    }

    ste[0] = val;
    smmu_tlbi_cached_ste(smmu);

    /* Issue a PREFETCH command so that new config for SID is fetched by SMMU */
    smmu_tlbi_prefetch_cfg(smmu);

}

static uint32_t smmu_strtab_init_linear(smmu_dev_t *smmu)
{
    uint64_t *ste;
    uint32_t size, i;
    smmu_strtab_config_t *cfg = &smmu->strtab_cfg;

    size = (1 << smmu->sid_bits) * (STRTAB_STE_DWORDS << 3);
    cfg->strtab_ptr = val_memory_calloc(2, size, SIZE_4KB);
    if (!cfg->strtab_ptr) {
        ERROR("\n      Failed to allocate linear stream table.     ");
        return 0;
    }

    cfg->strtab_phys = align_to_size((uint64_t)val_memory_virt_to_phys(cfg->strtab_ptr), size);
    cfg->strtab64 = (uint64_t *)align_to_size((uint64_t)cfg->strtab_ptr, size);
    cfg->l1_ent_count = 1 << smmu->sid_bits;
    cfg->strtab_base_cfg = BITFIELD_SET(STRTAB_BASE_CFG_FMT, STRTAB_BASE_CFG_FMT_LINEAR) |
                           BITFIELD_SET(STRTAB_BASE_CFG_LOG2SIZE, smmu->sid_bits);

    for (ste = cfg->strtab64, i = 0; i < cfg->l1_ent_count; ++i, ste += STRTAB_STE_DWORDS)
        smmu_strtab_write_ste(NULL, ste, smmu);
    return 1;
}

static uint32_t smmu_event_queue_init(smmu_dev_t *smmu)
{
    smmu_queue_type_t *eventq = &smmu->evnt_type;
    uint64_t eventq_size = ((1 << eventq->queue.log2nent) * QUEUE_DWORDS_PER_ENT) << 3;

    eventq_size = (eventq_size < 32)?32:eventq_size;
    eventq->base_ptr = val_memory_calloc(2, eventq_size, SIZE_4KB);
    if (!eventq->base_ptr) {
        ERROR("\n      Failed to allocate queue struct.     ");
        return 0;
    }
    eventq->base_phys = (uint64_t)val_memory_virt_to_phys(eventq->base_ptr);
    eventq->base = (uint8_t *)eventq->base_ptr;

    eventq->prod_reg = (uint32_t *)(smmu->base + SMMU_R_EVTQ_PROD);
    eventq->cons_reg = (uint32_t *)(smmu->base + SMMU_R_EVTQ_CONS);
    eventq->entry_size = QUEUE_DWORDS_PER_ENT << 3;

    eventq->queue_base = QUEUE_BASE_RWA |
                       (eventq->base_phys & (QUEUE_BASE_ADDR_MASK << QUEUE_BASE_ADDR_SHIFT)) |
                       BITFIELD_SET(QUEUE_BASE_LOG2SIZE, eventq->queue.log2nent);

    eventq->queue.prod = eventq->queue.cons = 0;
    return 1;
}

static uint32_t smmu_cmd_queue_init(smmu_dev_t *smmu)
{
    smmu_queue_type_t *cmdq = &smmu->cmd_type;
    uint64_t cmdq_size = ((1 << cmdq->queue.log2nent) * QUEUE_DWORDS_PER_ENT) << 3;

    cmdq_size = (cmdq_size < 32)?32:cmdq_size;
    cmdq->base_ptr = val_memory_calloc(2, cmdq_size, SIZE_4KB);
    if (!cmdq->base_ptr) {
        ERROR("\n      Failed to allocate queue struct.     ");
        return 0;
    }

    cmdq->base_phys = (uint64_t)val_memory_virt_to_phys(cmdq->base_ptr);
    cmdq->base = (uint8_t *)cmdq->base_ptr;

    cmdq->prod_reg = (uint32_t *)(smmu->base + SMMU_R_CMDQ_PROD);
    cmdq->cons_reg = (uint32_t *)(smmu->base + SMMU_R_CMDQ_CONS);
    cmdq->entry_size = QUEUE_DWORDS_PER_ENT << 3;

    cmdq->queue_base = QUEUE_BASE_RWA |
                       (cmdq->base_phys & (QUEUE_BASE_ADDR_MASK << QUEUE_BASE_ADDR_SHIFT)) |
                       BITFIELD_SET(QUEUE_BASE_LOG2SIZE, cmdq->queue.log2nent);

    cmdq->queue.prod = cmdq->queue.cons = 0;
    return 1;
}

static void smmu_free_strtab(smmu_dev_t *smmu)
{
    uint32_t i;

    smmu_strtab_config_t *cfg = &smmu->strtab_cfg;

    if (cfg->strtab_ptr == NULL)
        return;
    if (smmu->supported.st_level_2lvl &&
        cfg->l1_desc != NULL)
    {
        for (i = 0; i < cfg->l1_ent_count; ++i)
        {
            if (cfg->l1_desc[i].l2ptr != NULL)
                val_memory_free(cfg->l1_desc[i].l2ptr);
        }
        val_memory_free(cfg->l1_desc);
    }
    val_memory_free(cfg->strtab_ptr);
}

/* Stream table manipulation functions */
static void
smmu_strtab_write_level1_desc(uint64_t *dst, smmu_strtab_l1_desc_t *desc)
{
    uint64_t val = 0;

    val |= BITFIELD_SET(STRTAB_L1_DESC_SPAN, desc->span);
    val |= desc->l2desc_phys & (STRTAB_L1_DESC_L2PTR_MASK << STRTAB_L1_DESC_L2PTR_SHIFT);
    *dst = val;
}

static int smmu_strtab_init_level2(smmu_dev_t *smmu, uint32_t sid)
{
    uint64_t size, *ste;
    void *strtab;
    int i;
    smmu_strtab_config_t *cfg = &smmu->strtab_cfg;
    smmu_strtab_l1_desc_t *desc = &cfg->l1_desc[sid >> STRTAB_SPLIT];

    if (desc->l2ptr)
        return 1;

    size = (1 << STRTAB_SPLIT) * STRTAB_STE_DWORDS * BYTES_PER_DWORD;
    strtab = &cfg->strtab64[(sid >> STRTAB_SPLIT) * STRTAB_L1_DESC_DWORDS];

    desc->span = STRTAB_SPLIT + 1;
    desc->l2ptr = val_memory_calloc(2, size, SIZE_16KB);
    if (!desc->l2ptr) {
        ERROR("\n       failed to allocate l2 stream table for SID %u   ", sid);
        return 0;
    }

    desc->l2desc_phys = align_to_size((uint64_t)val_memory_virt_to_phys(desc->l2ptr), size);
    desc->l2desc64 = (uint64_t *)align_to_size((uint64_t)desc->l2ptr, size);
    for (ste = desc->l2desc64, i = 0; i < (1 << STRTAB_SPLIT); ++i, ste += STRTAB_STE_DWORDS)
        smmu_strtab_write_ste(NULL, ste, smmu);

    smmu_strtab_write_level1_desc(strtab, desc);
    return 1;
}

static int smmu_strtab_init_level1(smmu_dev_t *smmu)
{
    smmu_strtab_config_t *cfg = &smmu->strtab_cfg;

    cfg->l1_desc = val_memory_calloc(cfg->l1_ent_count, sizeof(*cfg->l1_desc), SIZE_4KB);

    if (!cfg->l1_desc) {
        ERROR("\n      failed to allocate l1 stream table desc     ");
        return 0;
    }

    return 1;
}

static int smmu_strtab_init_2level(smmu_dev_t *smmu)
{
    uint32_t log2size, l1_tbl_size;
    smmu_strtab_config_t *cfg = &smmu->strtab_cfg;
    int ret;

    log2size = smmu->sid_bits - STRTAB_SPLIT;
    cfg->l1_ent_count = 1 << log2size;

    log2size += STRTAB_SPLIT;

    l1_tbl_size = cfg->l1_ent_count * STRTAB_L1_DESC_SIZE;
    cfg->strtab_ptr = val_memory_alloc(2 * l1_tbl_size, SIZE_4KB);

    if (!cfg->strtab_ptr) {
        ERROR("\n      failed to allocate l1 stream table     ");
        return 0;
    }

    cfg->strtab_phys = (uint64_t)val_memory_virt_to_phys(cfg->strtab_ptr);
    cfg->strtab64 = (uint64_t *)cfg->strtab_ptr;
    cfg->strtab_base_cfg = BITFIELD_SET(STRTAB_BASE_CFG_FMT, STRTAB_BASE_CFG_FMT_2LVL) |
                           BITFIELD_SET(STRTAB_BASE_CFG_LOG2SIZE, log2size) |
                           BITFIELD_SET(STRTAB_BASE_CFG_SPLIT, STRTAB_SPLIT);

    ret = smmu_strtab_init_level1(smmu);
    if (!ret) {
        val_memory_free(cfg->strtab_ptr);
        return 0;
    }
    return 1;
}

static uint32_t smmu_strtab_init(smmu_dev_t *smmu)
{
    uint64_t data;
    int ret;

    if (smmu->supported.st_level_2lvl)
        ret = smmu_strtab_init_2level(smmu);
    else
        ret = smmu_strtab_init_linear(smmu);

    if (!ret) {
        ERROR("\n      Stream table init failed     ");
        return ret;
    }

    /* Set the strtab base address */
    data = smmu->strtab_cfg.strtab_phys & (STRTAB_BASE_ADDR_MASK << STRTAB_BASE_ADDR_SHIFT);
    data |= STRTAB_BASE_RA;
    smmu->strtab_cfg.strtab_base = data;

    return 1;
}

static int smmu_reg_write_sync(smmu_dev_t *smmu, uint32_t val,
                   unsigned int reg_off, unsigned int ack_off)
{
    uint64_t timeout = 0x1000000;
    uint32_t reg;

    val_mmio_write(smmu->base + reg_off, val);

    while (timeout--) {
        reg = val_mmio_read(smmu->base + ack_off);
        if (reg == val)
            return 0;
    }

    return 1;
}

static int smmu_dev_disable(smmu_dev_t *smmu)
{
    int ret;

    ret = smmu_reg_write_sync(smmu, 0, SMMU_R_CR0, SMMU_R_CR0ACK);
    if (ret)
        ERROR("\n    failed to clear cr0     ");

    return ret;
}

static int smmu_reset(smmu_dev_t *smmu)
{
    int ret;
    uint32_t r_cr0, r_cr1, r_cr2;

    r_cr0 = val_mmio_read(smmu->base + SMMU_R_CR0);
    r_cr0 &= ~CR0_SMMUEN;
    ret = smmu_reg_write_sync(smmu, r_cr0, SMMU_R_CR0, SMMU_R_CR0ACK);
    if (ret) {
        ERROR("\n      failed to clear SMMU_CR0     ");
        return ret;
    }

    r_cr1 = BITFIELD_SET(CR1_TABLE_SH,  SMMU_SH_ISH) | BITFIELD_SET(CR1_QUEUE_SH, SMMU_SH_ISH) |
           BITFIELD_SET(CR1_TABLE_IC, CR1_CACHE_WB) | BITFIELD_SET(CR1_QUEUE_IC, CR1_CACHE_WB) |
           BITFIELD_SET(CR1_TABLE_OC, CR1_CACHE_WB) | BITFIELD_SET(CR1_QUEUE_OC, CR1_CACHE_WB);
    val_mmio_write(smmu->base + SMMU_R_CR1, r_cr1);

    r_cr2 = val_mmio_read(smmu->base + SMMU_R_CR2);
    r_cr2 |= ENABLE_E2H;
    val_mmio_write(smmu->base + SMMU_R_CR2, r_cr2); //Enable E2H

    val_mmio_write64(smmu->base + SMMU_R_STRTAB_BASE, smmu->strtab_cfg.strtab_base);
    val_mmio_write(smmu->base + SMMU_R_STRTAB_BASE_CFG,
            smmu->strtab_cfg.strtab_base_cfg);

    val_mmio_write64(smmu->base + SMMU_R_CMDQ_BASE, smmu->cmd_type.queue_base);
    val_mmio_write(smmu->base + SMMU_R_CMDQ_PROD, smmu->cmd_type.queue.prod);
    val_mmio_write(smmu->base + SMMU_R_CMDQ_CONS, smmu->cmd_type.queue.cons);

    val_mmio_write64(smmu->base + SMMU_R_EVTQ_BASE, smmu->evnt_type.queue_base);
    val_mmio_write(smmu->base + SMMU_R_EVTQ_PROD, smmu->evnt_type.queue.prod);
    val_mmio_write(smmu->base + SMMU_R_EVTQ_CONS, smmu->evnt_type.queue.cons);

    r_cr0 = val_mmio_read(smmu->base + SMMU_R_CR0);
    r_cr0 |= CR0_CMDQEN;
    ret = smmu_reg_write_sync(smmu, r_cr0, SMMU_R_CR0,
                      SMMU_R_CR0ACK);
    if (ret) {
        ERROR("\n      failed to enable command queue     ");
        return ret;
    }

    r_cr0 |= CR0_EVENTQEN;
    ret = smmu_reg_write_sync(smmu, r_cr0, SMMU_R_CR0,
                      SMMU_R_CR0ACK);
    if (ret) {
        ERROR("\n      failed to enable command queue     ");
        return ret;
    }

    smmu_tlbi_cfgi(smmu);

    r_cr0 |= CR0_SMMUEN;
    ret = smmu_reg_write_sync(smmu, r_cr0, SMMU_R_CR0,
                      SMMU_R_CR0ACK);
    if (ret) {
        ERROR("\n      failed to enable SMMU     ");
        return ret;
    }
    return 1;
}

uint32_t smmu_set_state(uint32_t smmu_index, uint32_t en)
{
    smmu_dev_t *smmu;
    uint32_t cr0_val;
    int ret;

    if (smmu_index >= g_num_smmus)
    {
        ERROR("\n      smmu_set_state: invalid smmu index    ");
        return 1;
    }

    smmu = &g_smmu[smmu_index];
    if (smmu->base == 0)
    {
        ERROR("\n      smmu_set_state: smmu unsupported     ");
        return 1;
    }

    cr0_val = val_mmio_read(smmu->base + SMMU_CR0_OFFSET);

    if (en)
        cr0_val |= (uint32_t)CR0_SMMUEN;
    else
        cr0_val &= ~((uint32_t)CR0_SMMUEN);

    ret = smmu_reg_write_sync(smmu, cr0_val, SMMU_CR0_OFFSET,
                      SMMU_CR0ACK_OFFSET);
    if (ret)
    {
        ERROR("\n      smmu_set_state: failed to set SMMU state     ");
        return ret;
    }
    return 0;
}

/**
  @brief Disable SMMU translations
  @param smmu_index - Index of SMMU in global SMMU table.
  @return status
**/
uint32_t
val_smmu_disable(uint32_t smmu_index)
{
  return smmu_set_state(smmu_index, 0);
}

/**
  @brief Enable SMMU translations
  @param smmu_index - Index of SMMU in global SMMU table.
  @return status
**/
uint32_t
val_smmu_enable(uint32_t smmu_index)
{
  return smmu_set_state(smmu_index, 1);
}

static uint32_t smmu_probe(smmu_dev_t *smmu)
{
    uint32_t idr0, idr1, idr5;

    idr0 = val_mmio_read(smmu->base + SMMU_IDR0_OFFSET);

    if (BITFIELD_GET(IDR0_ST_LEVEL, idr0) == IDR0_ST_LEVEL_2LVL)
        smmu->supported.st_level_2lvl = 1;

    if (idr0 & IDR0_CD2L)
        smmu->supported.cd2l = 1;

    if (idr0 & IDR0_HYP)
        smmu->supported.hyp = 1;

    if (idr0 & IDR0_S1P)
        smmu->supported.s1p = 1;

    if (idr0 & IDR0_S2P)
        smmu->supported.s2p = 1;

    if (!(idr0 & (IDR0_S1P | IDR0_S2P))) {
        ERROR("\n      no translation support!     ");
        return 0;
    }

    switch (BITFIELD_GET(IDR0_TTF, idr0)) {
    case IDR0_TTF_AARCH32_64:
        smmu->ias = 40;
        break;
    case IDR0_TTF_AARCH64:
        break;
    default:
        ERROR("\n      AArch64 table format not supported!     ");
        return 0;
    }

    idr1 = val_mmio_read(smmu->base + SMMU_IDR1_OFFSET);
    if (idr1 & (IDR1_TABLES_PRESET | IDR1_QUEUES_PRESET)) {
        ERROR("\n      fixed table base address not supported     ");
        return 0;
    }

    smmu->cmd_type.queue.log2nent = BITFIELD_GET(IDR1_CMDQS, idr1);

    /* SID/SSID sizes */
    smmu->sid_bits = BITFIELD_GET(IDR1_SIDSIZE, idr1);
    smmu->ssid_bits = BITFIELD_GET(IDR1_SSIDSIZE, idr1);

    INFO("ssid_bits = %d", smmu->ssid_bits);
    INFO("sid_bits = %d\n", smmu->sid_bits);

    if (smmu->sid_bits <= STRTAB_SPLIT)
        smmu->supported.st_level_2lvl = 0;

    /* IDR5 */
    idr5 = val_mmio_read(smmu->base + SMMU_IDR5_OFFSET);

    if (BITFIELD_GET(IDR5_OAS, idr5) >= SMMU_OAS_MAX_IDX) {
        ERROR("\n      Unknown output address size     ");
        return 0;
    }
    smmu->oas = smmu_oas[BITFIELD_GET(IDR5_OAS, idr5)];
    smmu->ias = get_max(smmu->ias, smmu->oas);

    INFO("ias %ld-bit ", smmu->ias);
    INFO("oas %ld-bit\n", smmu->oas);

    return 1;
}

static uint64_t *smmu_strtab_get_ste_for_sid(smmu_dev_t *smmu, uint32_t sid)
{
    smmu_strtab_config_t *cfg = &smmu->strtab_cfg;
    smmu_strtab_l1_desc_t *l1_desc;
    if (!smmu->supported.st_level_2lvl)
        return &cfg->strtab64[sid * STRTAB_STE_DWORDS];

    l1_desc = &cfg->l1_desc[((sid >> STRTAB_SPLIT) * STRTAB_L1_DESC_DWORDS)];
    return &l1_desc->l2desc64[((sid & ((1 << STRTAB_SPLIT) - 1)) * STRTAB_STE_DWORDS)];
}

static void dump_strtab(uint64_t *ste)
{
    int i;

    for (i = 0; i < 8; i++) {
        INFO("ste[%d] = ", i);
        INFO("%p\n", (void *)ste[i]);
    }
}

static void dump_cdtab(uint64_t *ctx_desc)
{
    int i;

    for (i = 0; i < 8; i++) {
        INFO("ctx_desc[%d] = ", i);
        INFO("%lx\n", ctx_desc[i]);
    }
}

static void smmu_cdtab_write_l1_desc(uint64_t *dst,
                      smmu_cdtab_l1_ctx_desc_t *l1_desc)
{
    uint64_t val = (l1_desc->l2desc_phys &
          (CDTAB_L1_DESC_L2PTR_MASK << CDTAB_L1_DESC_L2PTR_SHIFT)) | CDTAB_L1_DESC_V;

    *dst = val;
}

static int smmu_cdtab_alloc_leaf_table(smmu_cdtab_l1_ctx_desc_t *l1_desc)
{
    uint64_t size = CDTAB_L2_ENTRY_COUNT * (CDTAB_CD_DWORDS << 3);

    l1_desc->l2ptr = val_memory_alloc(size*2, BYTES_PER_DWORD);
    if (!l1_desc->l2ptr) {
        ERROR("\n      failed to allocate context descriptor table     ");
        return 1;
    }
    l1_desc->l2desc_phys = align_to_size((uint64_t)val_memory_virt_to_phys(l1_desc->l2ptr), size);
    l1_desc->l2desc64 = (uint64_t *)align_to_size((uint64_t)l1_desc->l2ptr, size);
    return 0;
}

static uint64_t *smmu_cdtab_get_ctx_desc(smmu_master_t *master)
{
    smmu_cdtab_config_t *cdcfg = &master->stage1_config.cdcfg;
    smmu_cdtab_l1_ctx_desc_t *l1_desc;
    uint64_t *l1ptr;
    uint32_t idx;

    if (master->stage1_config.s1fmt == STRTAB_STE_0_S1FMT_LINEAR)
        return cdcfg->cdtab64 + master->ssid * CDTAB_CD_DWORDS;

    idx = master->ssid >> CDTAB_SPLIT;
    l1_desc = &cdcfg->l1_desc[idx];
    if (!l1_desc->l2ptr) {
        if (smmu_cdtab_alloc_leaf_table(l1_desc))
            return NULL;

        l1ptr = cdcfg->cdtab64 + idx * CDTAB_L1_DESC_DWORDS;
        smmu_cdtab_write_l1_desc(l1ptr, l1_desc);
    }
    idx = master->ssid & (CDTAB_L2_ENTRY_COUNT - 1);
    return l1_desc->l2desc64 + idx * CDTAB_CD_DWORDS;
}

static int smmu_cdtab_write_ctx_desc(smmu_master_t *master,
                   int ssid, smmu_cdtab_ctx_desc_t *cd)
{
    uint64_t val;
    uint64_t *cdptr;

    if (ssid >= (1 << master->stage1_config.s1cdmax))
    {
        ERROR("\n      smmu_cdtab_write_ctx_desc: ssid out of range     ");
        return 0;
    }

    cdptr = smmu_cdtab_get_ctx_desc(master);
    if (!cdptr)
    {
        ERROR("\n      smmu_cdtab_write_ctx_desc: cdptr is NULL     ");
        return 0;
    }

    cdptr[1] = cd->ttbr & CDTAB_CD_1_TTB0_MASK;
    cdptr[2] = 0;
    cdptr[3] = cd->mair;

    val = cd->tcr |
        CDTAB_CD_0_R | CDTAB_CD_0_A | CDTAB_CD_0_ASET |
        CDTAB_CD_0_AA64 |
        BITFIELD_SET(CDTAB_CD_0_ASID, cd->asid) |
        CDTAB_CD_0_V;

    cdptr[0] = val;
    dump_cdtab(cdptr);

    return 1;
}

static void smmu_cdtab_free(smmu_master_t *master)
{
    uint64_t max_contexts;
    uint32_t i;
    uint32_t num_l1_ents;
    smmu_stage1_config_t *cfg = &master->stage1_config;
    smmu_cdtab_config_t *cdcfg = &cfg->cdcfg;

    max_contexts = 1 << cfg->s1cdmax;

    if (master->smmu->supported.cd2l &&
        max_contexts > CDTAB_L2_ENTRY_COUNT)
    {
        num_l1_ents = (max_contexts + CDTAB_L2_ENTRY_COUNT - 1)/CDTAB_L2_ENTRY_COUNT;
        for (i = 0; i < num_l1_ents; i++)
        {
            if (cdcfg->l1_desc[i].l2ptr != NULL)
                val_memory_free(cdcfg->l1_desc[i].l2ptr);

        }
        val_memory_free(cdcfg->l1_desc);
    }
    val_memory_free(cdcfg->cdtab_ptr);
    cdcfg->cdtab_ptr = NULL;
}

static int smmu_cdtab_alloc(smmu_master_t *master)
{
    uint64_t l1_tbl_size;
    uint64_t cdmax;
    smmu_stage1_config_t *cfg = &master->stage1_config;
    smmu_cdtab_config_t *cdcfg = &cfg->cdcfg;

    cdmax = 1 << cfg->s1cdmax;

    if (master->smmu->supported.cd2l && cdmax > CDTAB_L2_ENTRY_COUNT)
    {
        cfg->s1fmt = STRTAB_STE_0_S1FMT_64K_L2;
        cdcfg->l1_ent_count = (cdmax + CDTAB_L2_ENTRY_COUNT - 1)/CDTAB_L2_ENTRY_COUNT;

        cdcfg->l1_desc =
                val_memory_calloc(cdcfg->l1_ent_count, sizeof(*cdcfg->l1_desc), BYTES_PER_DWORD);

        if (!cdcfg->l1_desc)
            return 0;

        l1_tbl_size = cdcfg->l1_ent_count * (CDTAB_L1_DESC_DWORDS << 3);
    } else {
        cfg->s1fmt = STRTAB_STE_0_S1FMT_LINEAR;
        cdcfg->l1_ent_count = cdmax;
        l1_tbl_size = cdmax * (CDTAB_CD_DWORDS << 3);
    }

    cdcfg->cdtab_ptr = val_memory_calloc(2, l1_tbl_size, BYTES_PER_DWORD);
    if (!cdcfg->cdtab_ptr) {
        ERROR("\n      smmu_cdtab_alloc: alloc failed     ");
        return 0;
    }

    cdcfg->cdtab_phys =
                align_to_size((uint64_t)val_memory_virt_to_phys(cdcfg->cdtab_ptr), l1_tbl_size);
    cdcfg->cdtab64 = (uint64_t *)align_to_size((uint64_t)cdcfg->cdtab_ptr, l1_tbl_size);

    return 1;
}

smmu_master_t *smmu_master_at(uint32_t sid)
{
    struct smmu_master_node *node = g_smmu_master_list_head;

    while (node != NULL)
    {
        if (node->master->sid == sid)
            return node->master;
        node = node->next;
    }
    node = val_memory_alloc(sizeof(struct smmu_master_node), BYTES_PER_DWORD);
    if (node == NULL)
        return NULL;

    node->master = val_memory_calloc(1, sizeof(smmu_master_t), BYTES_PER_DWORD);
    if (node->master == NULL)
    {
        val_memory_free(node);
        return NULL;
    }

    node->next = g_smmu_master_list_head;
    g_smmu_master_list_head = node;

    return node->master;
}

/**
  @brief - 1. Determine if stage 1 or stage 2 translation is needed.
           2. Populate stage1 or stage2 configuration data structures. Create and populate
              context descriptor tables as well in case of stage 1 transalation.
           3. Get pointer to stream table entry corresponding to master stream id
           4. Populate the stream table entry, with stage1/2 configuration.
           5. Invalidate all SMMU config and tlb entries, so that stream table is accessed,
              at the next memory access from a master.
  @param master_attr - structured data about the master (like streamid, smmu index).
  @param pgt_desc - page table base and translation attributes
  @return status
**/
uint32_t val_smmu_rlm_map(smmu_master_attributes_t master_attr, pgt_descriptor_t pgt_desc)
{
    smmu_master_t *master;
    smmu_dev_t *smmu;
    uint64_t *ste;

    g_sid = master_attr.streamid;
    if (g_smmu == NULL)
        return 1;

    if (master_attr.smmu_index >= g_num_smmus)
    {
        ERROR("\n      val_smmu_map: invalid smmu index     ");
        return 1;
    }

    smmu = &g_smmu[master_attr.smmu_index];
    if (smmu->base == 0)
    {
        ERROR("\n      val_smmu_map: smmu unsupported     ");
        return 1;
    }

    master = smmu_master_at(master_attr.streamid);
    if (master == NULL)
        return 1;

    if (master->smmu == NULL)
    {
        master->smmu = smmu;
        master->sid = master_attr.streamid;
        master->ssid_bits = master_attr.ssid_bits;
    }

    /* Support for stage 1 and stage 2 translations in one stream table entry(STE)
     * This implementation only supports either stage 1 or stage 2 in one STE
     */
    if (master_attr.stage2)
    {
        if (!smmu->supported.s2p)
            return 1;
        master->stage = SMMU_STAGE_S2;
    }
    else if (master_attr.bypass)
    {
        master->stage = SMMU_STAGE_BYPASS;
    } else
    {
        if (!smmu->supported.s1p)
            return 1;
        master->stage = SMMU_STAGE_S1;
        master->ssid = master_attr.substreamid;
    }

    if (master_attr.streamid >= (0x1ul << smmu->sid_bits))
    {
        ERROR("\n    val_smmu_map: sid %d out of range       ", master_attr.streamid);
        return 1;
    }

    if (smmu->supported.st_level_2lvl) {
        if (!smmu_strtab_init_level2(smmu, g_sid))
        {
            ERROR("\n      val_smmu_map: l2 stream table init failed     ");
            return 1;
        }
    }

    if (master->stage == SMMU_STAGE_S2)
    {
        smmu_stage2_config_t *cfg = &master->stage2_config;

        cfg->vmid = 0;
        cfg->vttbr = pgt_desc.pgt_base;
        cfg->vtcr = BITFIELD_SET(STRTAB_STE_2_VTCR_S2T0SZ, pgt_desc.tcr.tsz) |
                    BITFIELD_SET(STRTAB_STE_2_VTCR_S2SL0, pgt_desc.tcr.sh) |
                    BITFIELD_SET(STRTAB_STE_2_VTCR_S2IR0, pgt_desc.tcr.irgn) |
                    BITFIELD_SET(STRTAB_STE_2_VTCR_S2OR0, pgt_desc.tcr.orgn) |
                    BITFIELD_SET(STRTAB_STE_2_VTCR_S2SH0, pgt_desc.tcr.sh) |
                    BITFIELD_SET(STRTAB_STE_2_VTCR_S2TG, pgt_desc.tcr.tg) |
                    BITFIELD_SET(STRTAB_STE_2_VTCR_S2PS, pgt_desc.tcr.ps);
    }

    if (master->stage == SMMU_STAGE_S1)
    {
        smmu_stage1_config_t *cfg = &master->stage1_config;

        cfg->s1cdmax = master->ssid_bits;
        if (cfg->cdcfg.cdtab_ptr == NULL) {
            if (!smmu_cdtab_alloc(master))
                return 1;
        }

        cfg->cd.asid = 0;
        cfg->cd.ttbr = pgt_desc.pgt_base;
        cfg->cd.tcr  = BITFIELD_SET(CDTAB_CD_0_TCR_T0SZ, pgt_desc.tcr.tsz) |
                       BITFIELD_SET(CDTAB_CD_0_TCR_TG0, pgt_desc.tcr.tg) |
                       BITFIELD_SET(CDTAB_CD_0_TCR_IRGN0, pgt_desc.tcr.irgn) |
                       BITFIELD_SET(CDTAB_CD_0_TCR_ORGN0, pgt_desc.tcr.orgn) |
                       BITFIELD_SET(CDTAB_CD_0_TCR_SH0, pgt_desc.tcr.sh) |
                       BITFIELD_SET(CDTAB_CD_0_TCR_IPS, pgt_desc.tcr.ps) |
                       CDTAB_CD_0_TCR_EPD1 | CDTAB_CD_0_AA64;

        cfg->cd.mair  = pgt_desc.mair;

       if (!smmu_cdtab_write_ctx_desc(master, master->ssid, &cfg->cd))
            return 1;
    }

    ste = smmu_strtab_get_ste_for_sid(smmu, master->sid);
    smmu_strtab_write_ste(master, ste, smmu);
    dump_strtab(ste);

    smmu_tlbi_cfgi(smmu);

    return 0;
}

/**
  @brief Clear stream table entry, free any context descriptor tables and
         page tables corresponding to given master device
  @param master_attr - structured data about the master (like streamid, smmu index)
  @return void
**/
void val_smmu_unmap(smmu_master_attributes_t master_attr)
{
    smmu_master_t *master;
    smmu_dev_t *smmu;
    uint64_t *strtab;

    smmu = &g_smmu[master_attr.smmu_index];
    if (smmu->base == 0)
    {
        ERROR("\n      val_smmu_map: smmu unsupported     ");
        return;
    }

    master = smmu_master_at(master_attr.streamid);
    if (master == NULL)
        return;

    if (master->smmu == NULL)
        return;

    if (master_attr.streamid >= (0x1ul << master->smmu->sid_bits))
        return;

    strtab = master->smmu->strtab_cfg.strtab64 + master_attr.streamid * STRTAB_STE_DWORDS;
    smmu_strtab_write_ste(NULL, strtab, smmu);

    smmu_cdtab_free(master);
    smmu_tlbi_cfgi(master->smmu);
    val_memory_set(master, sizeof(smmu_master_t), 0);
}

uint32_t smmu_init(smmu_dev_t *smmu)
{
    if (smmu->base == 0)
        return 1;

    if (!smmu_probe(smmu))
        return 1;

    if (!smmu_cmd_queue_init(smmu))
        return 1;

    if (!smmu_event_queue_init(smmu))
        return 1;

    if (!smmu_strtab_init(smmu))
        return 1;

    if (!smmu_reset(smmu))
        return 1;

    return 0;
}

/**
  @brief  Disable all SMMUs and free all associated memory
  @return void
**/
void val_smmu_stop(void)
{
    int i;
    smmu_dev_t *smmu;

    for (i = 0; i < g_num_smmus; i++)
    {
        smmu = &g_smmu[i];
        if (smmu->base == 0)
            continue;
        smmu_dev_disable(smmu);
        if (smmu->cmd_type.base_ptr)
            val_memory_free(smmu->cmd_type.base_ptr);
        smmu_free_strtab(smmu);
    }
    val_memory_free(g_smmu);
}

/**
  @brief  Scan all available SMMUs in the system and initialize all v3.x SMMUs
  @return Initialzation status
**/
uint32_t val_smmu_init(uint32_t num_smmu)
{
    int i;

    g_num_smmus = num_smmu;
    if (g_num_smmus == 0)
        return 1;

    g_smmu = val_memory_calloc(g_num_smmus, sizeof(smmu_dev_t), BYTES_PER_DWORD);
    if (!g_smmu)
    {
        ERROR("\n      val_smmu_init: memory allocation failure     ");
        return 1;
    }

    for (i = 0; i < g_num_smmus; ++i) {
        if (EXTRACT(ARCH_REV, val_mmio_read(ROOT_IOVIRT_SMMUV3_BASE + SMMU_AIDR_OFFSET)) != 3)
        {
            ERROR("\n val_smmu_init: SMMUv3.x supported, \
                                skipping smmu %d", i);
            continue;
        }
        g_smmu[i].base = ROOT_IOVIRT_SMMUV3_BASE;
        if (smmu_init(&g_smmu[i]))
        {
            ERROR("\n      val_smmu_init: smmu %d init failed     ", i);
            g_smmu[i].base = 0;
            return 1;
        }
    }
    return 0;
}
