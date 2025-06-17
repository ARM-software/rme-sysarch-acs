/** @file
  * Copyright (c) 2023-2025, Arm Limited or its affiliates. All rights reserved.
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

#include "val_el3/ack_include.h"

static MemoryPool mem_pool = {
    .base = (uint8_t *)FREE_MEM_SMMU, // Hardcoded address
    .size = MEMORY_POOL_SIZE,
    .free_list = NULL,
};

/**
 *  @brief  Clean and Invalidate the Data cache line containing
 *          the input physical address to the point of physical
 *          aliasing at EL3
 *          1. Caller       -  Test Suite
 *          2. Prerequisite -  The address should be mapped successfully
 *  @param  PA - Physical address needed for the cache maintenance
 *  @param  acc_pas - Access PAS that speciies the target PAS of the given PA
 *  @return None
**/
void val_data_cache_ops_by_va_el3(uint64_t VA, uint32_t type)
{

  switch (type)
  {
    case CLEAN_AND_INVALIDATE:
      cln_and_invldt_cache((uint64_t *)VA);
      break;
    case CLEAN:
      clean_cache((uint64_t *)VA);
      break;
    case INVALIDATE:
      invalidate_cache((uint64_t *)VA);
      break;
    default:
      ERROR("Invalid cache operation\n");
      break;
  }
}

/**
 *  @brief  This API is used to enable the NS_Encryption
 *          1. Caller       -  Test Suite
 *  @param  None
 *  @return None
**/
void val_enable_ns_encryption(void)
{
  pal_enable_ns_encryption();
}

/**
 *  @brief  This API is used to enable the NS_Encryption
 *          1. Caller       -  Test Suite
 *          2. Prerequisite -  val_enable_ns_encryption
 *  @param  None
 *  @return None
**/
void val_disable_ns_encryption(void)
{
  pal_disable_ns_encryption();
}

/**
 *  @brief  This API is used to program the LEGACY_TZ input for enabling/disabling
 *  it in the system.
 *          1. Caller       -  Test Suite
 *          2. Prerequisite -  val_enable_ns_encryption
 *  @param  enable - Enable if 1
 *  @return None
**/
void val_prog_legacy_tz(int enable)
{
  return pal_prog_legacy_tz(enable);
}

/**
  @brief   This API saves the contents fof the registers specified in the structure
           before an event.
           1. Caller       -  Test Suite
           2. Prerequisite -  None
  @param   None
  @return  None
**/
void val_pe_reg_read_msd(void)
{
  int num_regs;

  num_regs = shared_data->reg_info.num_regs;
  for (int i = 0; i < num_regs; i++) {
    shared_data->reg_info.reg_list[i].saved_reg_value =
            val_pe_reg_read(shared_data->reg_info.reg_list[i].reg_name);
  }
}

/**
  @brief   This API provides a comparison between the saved registers and the present value
           after an event.
           1. Caller       -  Test Suite
           2. Prerequisite -  val_reg_read_msd
  @param   None
  @return  None
**/
void val_pe_reg_list_cmp_msd(void)
{
  uint64_t reg_val;
  int cmp_fail;
  int num_regs;

  num_regs = shared_data->reg_info.num_regs;
  reg_val = 0;
  cmp_fail = 0;
  for (int i = 0; i < num_regs; i++) {
    reg_val = val_pe_reg_read(shared_data->reg_info.reg_list[i].reg_name);
    if (shared_data->reg_info.reg_list[i].saved_reg_value != reg_val) {
        ERROR("The register has not retained it's original value \n");
        cmp_fail++;
    }
    reg_val = 0;
  }
  //If the comparision is failed at any time, SET the shared generic flag
  if (cmp_fail > 0)
      shared_data->generic_flag = SET;

}

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
      case GPCCR_EL3_MSD:
          return read_gpccr_el3();
      case GPTBR_EL3_MSD:
          return read_gptbr_el3();
      case TCR_EL3_MSD:
          return read_tcr_el3();
      case TTBR_EL3_MSD:
          return read_ttbr_el3();
      case SCR_EL3_MSD:
          return read_scr_el3();
      case SCTLR_EL3_MSD:
          return read_sctlr_el3();
      case SCTLR_EL2_MSD:
          return read_sctlr_el2();
      default:
          ERROR("Specify the correct register index\n");
          return 0;
  }
}

/**
 *  @brief  This API is used to set the given memory with the required data
 *          with the specified size
 *          1. Caller       -  Test Suite
 *  @param  address - The address buffer that needs to be set
 *  @param  size - Size of the buffer upto which the test needs to fill in the data
 *  @param  value - Data needed to set the buffer with
 *  @return None
**/
void val_memory_set_el3(void *address, uint32_t size, uint8_t value)
{
  memset(address, value, size);
}

/**
 *  @brief  This API is used to set/clear the active mode of PAS_FILTER
 *          present in the system.
 *          1. Caller   - Test suite
 *  @param  enable - Bit to enable the active mode: SET to Active mode,
 *                   CLEAR to In-Active
 *  @return None
**/
void val_pas_filter_active_mode(int enable)
{
  //Change the mode to Active from In-active
  pal_pas_filter_active_mode(enable);
}
/**
  @brief   This API Enables root watchdog by writing to Control Base register
  @param   wdog_ctrl_base - Watchdog control base register
  @return  None
 **/
void
val_wd_enable(uint64_t wdog_ctrl_base)
{
    if (shared_data->generic_flag) {
      shared_data->exception_expected = SET;
      shared_data->access_mut = CLEAR;
    }
    *(uint64_t *)(wdog_ctrl_base + 0) = SET;
}

/**
  @brief   This API Disbles root watchdog by writing to Control Base register
  @param   wdog_ctrl_base - Watchdog control base register
  @return  None
 **/
void
val_wd_disable(uint64_t wdog_ctrl_base)
{
    *(uint64_t *)(wdog_ctrl_base + 0) = CLEAR;
}

/**
  @brief   This API arms the Root watchdog by writing to Control Base register.
  @param   VA_RT_WDOG - VA of Root watchdog control base register that is mapped
                        to PA, Root watchdog control base register.
  @param   timeout - ticks to generation of ws0 interrupt.
  @param   counter_freq - System counter frequency.
  @return  None
 **/
void val_wd_set_ws0_el3(uint64_t VA_RT_WDOG, uint32_t timeout, uint64_t counter_freq)
{
  uint32_t wor_l;
  uint32_t wor_h = 0;
  uint64_t ctrl_base;
  uint32_t data;

  ctrl_base = VA_RT_WDOG;
  if (!timeout) {
      INFO("Disabling the Root watchdog\n");
      val_wd_disable(ctrl_base);
      return;
  }

  data = VAL_EXTRACT_BITS(*(uint64_t *)(ctrl_base + WD_IIDR_OFFSET), 16, 19);

  /* Option to override system counter frequency value */
  /* Check if the timeout value exceeds */
  if (data == 0)
  {
      if ((counter_freq * timeout) >> 32)
      {
          ERROR("Counter frequency value exceeded\n");
      }
  }

  wor_l = (uint32_t)(counter_freq * timeout);
  wor_h = (uint32_t)((counter_freq * timeout) >> 32);

  if (shared_data->generic_flag) {
    shared_data->exception_expected = SET;
    shared_data->access_mut = CLEAR;
  }
  *(uint64_t *)(ctrl_base + 8) =  wor_l;

  /* Upper bits are applicable only for WDog Version 1 */
  if (data == 1) {
      if (shared_data->generic_flag) {
        shared_data->exception_expected = SET;
        shared_data->access_mut = CLEAR;
      }
      *(uint64_t *)(ctrl_base + 12) = wor_h;
  }

  INFO("Enabling the Root watchdog\n");
  val_wd_enable(ctrl_base);

}

/**
  @brief   This API Disbles accesses from the SMMU and client devices
           by writing to ACCESSEN bit of SMMU_ROOT_CR0 register.
  @return  None
 **/
void val_smmu_access_disable(void)
{
  *(uint32_t *)(ROOT_IOVIRT_SMMUV3_BASE + SMMU_ROOT_CR0) = CLEAR;
}

/**
 *  @brief  This API is used to change the security state of EL2 and lower levels by writing
 *          to the SCR_EL3 register.
 *  @return None
 */
void val_security_state_change(uint64_t attr_nse_ns)
{
  uint64_t scr_data, nse_bit, ns_bit;

  nse_bit = NSE_SET(attr_nse_ns);
  ns_bit = NS_SET(attr_nse_ns);
  scr_data = read_scr_el3();
  //The SCR_EL3.NSE and SCR_EL3.NS bits decides the security state
  scr_data &= (~SCR_NSE_MASK & ~SCR_NS_MASK);
  scr_data |= ((nse_bit << SCR_NSE_SHIFT) | (ns_bit << SCR_NS_SHIFT));
  write_scr_el3(scr_data);

}

/**
 * @brief Initialize the memory pool with a single large free block
 *
 * @return None
 */
void memory_pool_init(void)
{
    mem_pool.free_list = (BlockHeader *)mem_pool.base;
    mem_pool.free_list->size = mem_pool.size - sizeof(BlockHeader);
    mem_pool.free_list->is_free = 1;
    mem_pool.free_list->next = NULL;
}


/**
 * @brief  Split a large free block into two smaller blocks
 *
 * @return None
 */
void split_block(BlockHeader *block, size_t size)
{
    BlockHeader *new_block = (BlockHeader *)((uint8_t *)block + sizeof(BlockHeader) + size);
    new_block->size = block->size - size - sizeof(BlockHeader);
    new_block->is_free = 1;
    new_block->next = block->next;

    block->size = size;
    block->next = new_block;
}

/**
 * @brief  Returns the sligned address with the given size
 *
 * @param  size        Size in bytes to align
 * @param  alignment   alignment required
 * @return address aligned to the specified alignment till the 'size'
 */
static size_t align_size(size_t size, size_t alignment)
{
    return (size + (alignment - 1)) & ~(alignment - 1);
}

/**
 * @brief  Allocates requested buffer size in bytes in a contiguous memory
 *         and returns the base address of the range.
 *
 * @param  Size         allocation size in bytes
 * @param  alignment    Required alignment for the buffer
 * @retval if SUCCESS   pointer to allocated memory
 * @retval if FAILURE   NULL
 */
void *val_memory_alloc_el3(size_t size, size_t alignment)
{
    uint32_t mecid = 0;

    if (!mem_pool.free_list)
    {
        memory_pool_init(); // Initialize pool on first call
    }

    /* If MEC is enabled, the memory pool structures need to be accessed with
       VAL_GMECID */
    if (val_is_mec_enabled())
    {
        mecid = read_mecid_rl_a_el3();
        val_write_mecid(VAL_GMECID);
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
            /* Restore MECID */
            if (val_is_mec_enabled())
                val_write_mecid(mecid);
            return (void *)aligned_start;
        }
        current = current->next;
    }

    /* Restore MECID */
    if (val_is_mec_enabled())
        val_write_mecid(mecid);

    return NULL;
}

/**
  @brief  Free the memory allocated by UEFI Framework APIs
  @param  ptr the base address of the memory range to be freed

  @return None
**/
void val_memory_free_el3(void *ptr)
{
    uint32_t mecid = 0;

    if (!ptr) return;

   /* If MEC is enabled, the memory pool structures need to be accessed with
       VAL_GMECID */
    if (val_is_mec_enabled())
    {
        mecid = read_mecid_rl_a_el3();
        val_write_mecid(VAL_GMECID);
    }


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

    /* Restore MECID */
    if (val_is_mec_enabled())
        val_write_mecid(mecid);
}

/**
 * @brief  Allocates requested buffer size in bytes with zeros in a contiguous memory
 *         and returns the base address of the range.
 *
 * @param  size         allocation size in bytes
 * @param  num          Requested number of (buffer * size)
 * @retval ptr          pointer to allocated memory
 */
void *val_memory_calloc_el3(size_t num, size_t size, size_t alignment)
{
    size_t total_size = num * size;
    void *ptr = val_memory_alloc_el3(total_size, alignment);
    if (ptr) {
        memset(ptr, 0, total_size);
    }
    return ptr;
}

/**
 * @brief  Returns the physical address of the requested Virtual address
 *
 * @param  Va  Virtual address
 * @return Va  Returns the VA because of the 1:1 memory mapping
 */
void *val_memory_virt_to_phys(void *va)
{
  return va;
}

/**
 * @brief  Returns the virtual address of the requested physical address
 *
 * @param  pa  Physical address
 * @return pa  Returns the PA because of the 1:1 memory mapping
 */
void *val_memory_phys_to_virt(uint64_t pa)
{
  return (void *)pa;
}

/**
 * @brief  Conducts the SMMUv3 Root/Realm configuration/initialization in el3
 *
 * @return None
 */
void val_smmu_root_config_service(uint64_t arg0, uint64_t arg1, uint64_t arg2)
{
  uint64_t data;
  smmu_master_attributes_t smmu_attr;
  pgt_descriptor_t pgt_attr;

  switch (arg0)
  {
      case SMMU_ROOT_RME_IMPL_CHK:
          INFO("SMMU base address & offset: 0x%lx \n",
                      (uint64_t)ROOT_IOVIRT_SMMUV3_BASE + SMMU_ROOT_IDRO);
          data = *(uint32_t *)(ROOT_IOVIRT_SMMUV3_BASE + SMMU_ROOT_IDRO);
          INFO("SMMU ROOT IDRO: 0x%lx", data);
          shared_data->shared_data_access[0].data = data;
          break;
      case SMMU_RLM_PGT_INIT:
          INFO("SMMU Realm Initialisation\n");
          val_smmu_init(arg1);
          break;
      case SMMU_RLM_SMMU_MAP:
          INFO("SMMU realm page table map\n");
          memcpy((void *)&smmu_attr, (void *)arg1, sizeof(smmu_master_attributes_t));
          memcpy((void *)&pgt_attr, (void *)arg2, sizeof(pgt_descriptor_t));
          val_smmu_rlm_map((smmu_master_attributes_t)smmu_attr, (pgt_descriptor_t)pgt_attr);
          break;
      case SMMU_RLM_ADD_DPT_ENTRY:
          INFO("SMMU add DPT entry\n");
          val_dpt_add_entry(arg1, arg2);
          break;
      case SMMU_RLM_DPTI:
          INFO("SMMU DPT Invalidate\n");
          val_dpt_invalidate_all(arg1);
          break;
      case SMMU_CHECK_MEC_IMPL:
          shared_data->shared_data_access[0].data = val_smmu_supports_mec(arg1);
          break;
      case SMMU_GET_MECIDW:
          shared_data->shared_data_access[0].data = val_smmu_get_mecidw(arg1);
          break;
      case SMMU_CONFIG_MECID:
          memcpy((void *)&smmu_attr, (void *)arg1, sizeof(smmu_master_attributes_t));
          val_smmu_set_rlm_ste_mecid((smmu_master_attributes_t)smmu_attr, arg2);
          break;
      default:
          INFO(" Invalid SMMU ROOT register config\n");
          break;
  }
}

/**
 * @brief Check if the Processing Element (PE) supports MEC (Memory Encryption Context).
 *
 * This function reads the ID_AA64MMFR3_EL1 system register to determine whether
 * the Memory Encryption Context (MEC) feature is implemented by the PE (Processor Element).
 *
 *
 * @return 1 if MEC is supported, 0 otherwise.
 *
 */
unsigned int val_is_mec_supported(void)
{
    return (unsigned int)(read_id_aa64mmfr3_el1() >>
        ID_AA64MMFR3_EL1_MEC_SHIFT) & ID_AA64MMFR3_EL1_MEC_MASK;
}

/**
 * @brief Checks if SCTLR Extension is supported.
 *
 * @return 4-bit field indicating SCTLR Extension support level.
 */
static unsigned int val_is_sctlrx_supported(void)
{
    return (unsigned int)((read_id_aa64mmfr3_el1() >>
        ID_AA64MMFR3_EL1_SCTLRX_SHIFT) & ID_AA64MMFR3_EL1_SCTLRX_MASK);
}

/**
 * @brief Enable MEC (Memory Encryption Context) support if available.
 *
 * This function checks if the current Processing Element (PE) supports MEC.
 * If supported, it enables the necessary bits SCTLR2_EL3 system register
 * to activate the Memory Encryption Context feature.
 *
 * @param none
 * @return none
 */
void val_enable_mec(void)
{
    uint64_t sctlr2_el3;

    sctlr2_el3 = read_sctlr2_el3();

    /* Check if MEC is supported on this Processing Element */
    if (val_is_mec_supported() && val_is_sctlrx_supported()) {
        /* Enable EMEC (Enable MEC bit) in SCTLR2_EL3 */
        sctlr2_el3 |= SCTLR2_EMEC_MASK;
        write_sctlr2_el3(sctlr2_el3);
    } else {
        /* Log an error if FEAT_MEC or FEAT_SCTLR2 is not supported */
        ERROR("PE doesn't support FEAT_MEC or FEAT_SCTLR2\n");
    }
}

/**
 * @brief Disable MEC (Memory Encryption Context)
 *
 * @param none
 * @return none
 */
void val_disable_mec(void)
{
    uint64_t sctlr2_el3;

    sctlr2_el3 = read_sctlr2_el3();

    /* Check if MEC is supported on this Processing Element */
    if (val_is_mec_supported() && val_is_sctlrx_supported()) {
        /* Disable EMEC (clear MEC enable bit) in SCTLR2_EL3 */
        sctlr2_el3 &= ~SCTLR2_EMEC_MASK;
        write_sctlr2_el3(sctlr2_el3);
    } else {
        /* Log an error if FEAT_MEC or FEAT_SCTLR2 is not supported */
        ERROR("PE doesn't support FEAT_MEC or FEAT_SCTLR2\n");
    }
}

/**
 * @brief Check if MEC (Memory Encryption Context) is enabled.
 *
 * This function verifies whether the Memory Encryption Context feature
 * is currently enabled by checking the corresponding bits in the
 * SCTLR2_EL3 system register.
 *
 * @param none
 * @return 1 if MEC is enabled, 0 otherwise.
 */
uint32_t val_is_mec_enabled(void)
{
  uint64_t sctlr2_el3 = 0;

  /* Read current SCTLR2_EL3 value */
  if (val_is_sctlrx_supported())
      sctlr2_el3 = read_sctlr2_el3();

  /* Check if SCTLR2_EL3.EMEC bit is set */
  if (sctlr2_el3 & SCTLR2_EMEC_MASK) {
      /* MEC is enabled */
      return 1U;
  } else {
      /* MEC is not enabled */
      return 0U;
  }
}

/**
 * @brief Write the specified MECID (Memory Encryption Context ID) to MECID_RL_A_EL3 register.
 *
 * This function programs the MECID_RL_A_EL3 system register with the given MECID value.
 * After writing the register, it performs an Instruction Synchronization Barrier (ISB)
 * to ensure the write is globally visible and completes execution ordering,
 * followed by a TLB invalidation at EL3 for all entries (TLBI ALLE3IS).
 *
 * @param mecid The MECID value to be written (32-bit).
 *
 * @return none.
 */
void val_write_mecid(uint32_t mecid)
{
    /* Write the given MECID to MECID_RL_A_EL3 system register */
    write_mecid_rl_a_el3(mecid);

    /* Ensure instruction execution order and completion of register write */
    isb();

    /* Invalidate all TLB entries at EL3 (Inner Shareable domain) */
    tlbi_alle3is();
}

/**
 * @brief Handle MEC (Memory Encryption Context) related service requests.
 *
 * @param arg0 Command ID indicating the MEC service to perform. Supported values:
 * @param arg1 Argument associated with the command (used for CONFIG_MECID).
 * @param arg2 Reserved for future use or command-specific extensions.
 * @return none.
 */
void val_mec_service(uint64_t arg0, uint64_t arg1, uint64_t arg2)
{
  switch (arg0)
  {
    case ENABLE_MEC:
      INFO("Enabling MEC\n");
      val_enable_mec();
      break;

    case CONFIG_MECID:
      INFO("Config mecid\n");
      val_write_mecid(arg1);
      break;

    case DISABLE_MEC:
      INFO("Disabling MEC\n");
      val_disable_mec();
      break;

    default:
      INFO("Invalid MEC service\n");
      break;
  }
}
