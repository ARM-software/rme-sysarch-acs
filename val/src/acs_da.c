/** @file
 * Copyright (c) 2024-2025, Arm Limited or its affiliates. All rights reserved.
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

#include "include/rme_acs_val.h"
#include "include/rme_acs_common.h"
#include "include/rme_acs_pcie.h"
#include "include/rme_acs_da.h"

#include "include/rme_acs_memory.h"
#include "include/rme_acs_iovirt.h"
#include "include/mem_interface.h"
#include "include/rme_acs_el32.h"
#include "include/mem_interface.h"
#include "include/pal_interface.h"

#define TEST_DATA_1 0xabababab
#define TEST_DATA_2 0xcdcdcdcd

REGISTER_INFO_TABLE  *g_register_info_table;

/**
  @brief   This API will execute all RME DA tests designated for a given compliance level
           1. Caller       -  Application layer.
           2. Prerequisite -  val_pe_create_info_table, val_allocate_shared_mem
  @param   num_pe - the number of PE to run these tests on.
  @return  Consolidated status of all the tests run.
**/
uint32_t
val_rme_da_execute_tests(uint32_t num_pe)
{
  (void) num_pe;
  uint32_t status = ACS_STATUS_SKIP, i, reset_status, smmu_cnt;
  uint64_t num_smmus = val_smmu_get_info(SMMU_NUM_CTRL, 0);
  uint64_t smmu_base_arr[num_smmus], pgt_attr_el3;

  for (i = 0 ; i < MAX_TEST_SKIP_NUM ; i++) {
      if (g_skip_test_num[i] == ACS_RME_DA_TEST_NUM_BASE) {
          val_print(ACS_PRINT_TEST, "      USER Override - Skipping all RME tests \n", 0);
          return ACS_STATUS_SKIP;
      }
  }

  if (g_single_module != SINGLE_MODULE_SENTINEL && g_single_module != ACS_RME_DA_TEST_NUM_BASE &&
       (g_single_test == SINGLE_MODULE_SENTINEL ||
       (g_single_test - ACS_RME_DA_TEST_NUM_BASE > 100 ||
          g_single_test - ACS_RME_DA_TEST_NUM_BASE <= 0))) {
    val_print(ACS_PRINT_TEST, " USER Override - Skipping all RME tests \n", 0);
    val_print(ACS_PRINT_TEST, " (Running only a single module)\n", 0);
    return ACS_STATUS_SKIP;
  }

  g_curr_module = 1 << DA_MODULE;

  if (!g_rl_smmu_init)
  {
      smmu_cnt = 0;

      while (smmu_cnt < num_smmus)
      {
        smmu_base_arr[smmu_cnt] = val_smmu_get_info(SMMU_CTRL_BASE, smmu_cnt);
        smmu_cnt++;
      }
      /* Map the Pointer in EL3 as NS Access PAS so that EL3 can access this struct pointers */
      pgt_attr_el3 = LOWER_ATTRS(PGT_ENTRY_ACCESS | SHAREABLE_ATTR(OUTER_SHAREABLE) |
                                 PGT_ENTRY_AP_RW | PAS_ATTR(NONSECURE_PAS));
      val_add_mmu_entry_el3((uint64_t)(smmu_base_arr), (uint64_t)(smmu_base_arr), pgt_attr_el3);
      val_rlm_smmu_init(num_smmus, smmu_base_arr);

      g_rl_smmu_init = 1;
  }

  reset_status = val_read_reset_status();

  if (reset_status != RESET_TST12_FLAG &&
      reset_status != RESET_TST31_FLAG &&
      reset_status != RESET_TST2_FLAG &&
      reset_status != RESET_LS_DISBL_FLAG &&
      reset_status != RESET_LS_TEST3_FLAG)
  {
      /* DA-ACS tests */
      status = da001_entry();
      status |= da002_entry();
      status |= da003_entry();
      status |= da004_entry();
      status |= da005_entry();
      status |= da006_entry();
      status |= da007_entry();
      status |= da008_entry();
      status |= da009_entry();
      status |= da010_entry();
      status |= da011_entry();
      status |= da012_entry();
      status |= da013_entry();
      status |= da014_entry();
      status |= da015_entry();
      status |= da016_entry();
      status |= da017_entry();
      status |= da018_entry();
      status |= da019_entry();
      status |= da020_entry();

      val_print_test_end(status, "RME-DA");
  }

  return status;

}

void
val_register_create_info_table(uint64_t *register_info_table)
{
  g_register_info_table = (REGISTER_INFO_TABLE *)register_info_table;

  pal_register_create_info_table(g_register_info_table);
}

void *
val_register_table_ptr(void)
{
  return g_register_info_table;
}

uint32_t
val_register_get_num_entries(void)
{
  return pal_register_get_num_entries();
}

void
val_da_get_addr_asso_block_base(uint32_t *num_sel_ide_stream_supp,
                         uint32_t *num_tc_supp,
                         uint32_t *current_base_offset,
                         uint32_t bdf,
                         uint32_t *num_addr_asso_block,
                         uint32_t *rid_limit,
                         uint32_t *rid_base,
                         uint32_t reg_value)
{

  /* Get the number of Selective IDE Streams */
  *num_sel_ide_stream_supp = (reg_value & NUM_SEL_STR_MASK) >> NUM_SEL_STR_SHIFT;
  /* Get the number of TCs supported for Link IDE */
  *num_tc_supp = (reg_value & NUM_TC_SUPP_MASK) >> NUM_TC_SUPP_SHIFT;

  /* Base offset of Link IDE Register Block */
  *current_base_offset = *current_base_offset + IDE_CAP_REG_SIZE; //IDE Reg size

  /* Base offset of Selective IDE Stream Block */
  *current_base_offset = *current_base_offset + ((*num_tc_supp + 1) * LINK_IDE_BLK_SIZE);

  /* Get the number of Address Associaltion Register Blocks */
  val_pcie_read_cfg(bdf, *current_base_offset, &reg_value);
  *num_addr_asso_block = (reg_value & NUM_ADDR_ASSO_REG_MASK) >> NUM_ADDR_ASSO_REG_SHIFT;

  /* Base offset of IDE RID Association Register 1 */
  *current_base_offset = *current_base_offset + SEL_IDE_CAP_REG_SIZE;

  /* Get the RID Limit from IDE RID Association Register 1 */
  *rid_limit = VAL_EXTRACT_BITS(val_pcie_read_cfg(bdf, *current_base_offset, rid_limit), 8, 23);
  val_print(ACS_PRINT_INFO, "\n       RID Limit: %x", *rid_limit);

  /* Base offset of IDE RID Association Register 2 */
  *current_base_offset = *current_base_offset + RID_ADDR_REG1_SIZE;

  /* Get the RID Limit from IDE RID Association Register 2 */
  *rid_base = VAL_EXTRACT_BITS(val_pcie_read_cfg(bdf, *current_base_offset, rid_base), 8, 23);
  val_print(ACS_PRINT_INFO, "\n       RID Base: %x", *rid_base);

  /* Base offset of IDE Address Association Register Block */
  *current_base_offset = *current_base_offset + RID_ADDR_REG2_SIZE; // Addr ass base
}

void
val_da_get_next_rid_values(uint32_t *current_base_offset,
                    uint32_t *num_addr_asso_block,
                    uint32_t bdf,
                    uint32_t *next_rid_limit,
                    uint32_t *next_rid_base)
{
  uint32_t reg_value;

  /* Base offset of next Selective IDE Stream Register Block */
  *current_base_offset = *current_base_offset + (*num_addr_asso_block * IDE_ADDR_REG_BLK_SIZE);

  /* Get the number of Address Associaltion Register Blocks */
  val_pcie_read_cfg(bdf, *current_base_offset, &reg_value);
  *num_addr_asso_block = (reg_value & NUM_ADDR_ASSO_REG_MASK) >> NUM_ADDR_ASSO_REG_SHIFT;

  /* Base offset of IDE RID Association Register 1 */
  *current_base_offset = *current_base_offset + SEL_IDE_CAP_REG_SIZE;

  /* Get the RID Limit from IDE RID Association Register 1 */
  *next_rid_limit = VAL_EXTRACT_BITS(
                    val_pcie_read_cfg(bdf, *current_base_offset, next_rid_limit),
                    8, 23);
  val_print(ACS_PRINT_INFO, "\n       RID Limit: %x", *next_rid_limit);

  /* Base offset of IDE RID Association Register 2 */
  *current_base_offset = *current_base_offset + RID_ADDR_REG1_SIZE;

  /* Get the RID Limit from IDE RID Association Register 2 */
  *next_rid_base = VAL_EXTRACT_BITS(
                   val_pcie_read_cfg(bdf, *current_base_offset, next_rid_base),
                   8, 23);
  val_print(ACS_PRINT_INFO, "\n       RID Base: %x", *next_rid_base);
}

uint32_t
val_device_lock(uint32_t bdf)
{
  return pal_device_lock(bdf);
}

uint32_t
val_device_unlock(uint32_t bdf)
{
  return pal_device_unlock(bdf);
}

uint32_t val_ide_set_sel_stream(uint32_t bdf, uint32_t str_cnt, uint32_t enable)
{
  uint32_t reg_value;
  uint32_t ide_cap_base;
  uint32_t num_tc_supp;
  uint32_t num_sel_ide_stream_supp;
  uint32_t sel_ide_str_supported;
  uint32_t current_base_offset;
  uint32_t num_addr_asso_block;
  uint32_t count;

  /* Check IDE Extended Capability register is present */
  if (val_pcie_find_capability(bdf, PCIE_ECAP, ECID_IDE, &ide_cap_base) != PCIE_SUCCESS)
  {
      val_print(ACS_PRINT_ERR,
                    "\n       PCIe IDE Capability not present for BDF: 0x%x", bdf);
      return 1;
  }

  /* Check if Selective IDE Stream is supported */
  val_pcie_read_cfg(bdf, ide_cap_base + IDE_CAP_REG, &reg_value);
  sel_ide_str_supported = (reg_value & SEL_IDE_STR_MASK) >> SEL_IDE_STR_SHIFT;
  if (!sel_ide_str_supported)
  {
      val_print(ACS_PRINT_ERR, "\n       Selective IDE str not supported for BDF: %x", bdf);
      return 1;
  }

  /* Get the number of Selective IDE stream */
  num_sel_ide_stream_supp = (reg_value & NUM_SEL_STR_MASK) >> NUM_SEL_STR_SHIFT;

  /* Skip past the Link IDE register block */
  num_tc_supp = (reg_value & NUM_TC_SUPP_MASK) >> NUM_TC_SUPP_SHIFT;
  current_base_offset = ide_cap_base + IDE_CAP_REG_SIZE;
  current_base_offset = current_base_offset + ((num_tc_supp + 1) * LINK_IDE_BLK_SIZE);

  count = 0;
  while (count++ <= num_sel_ide_stream_supp)
  {
      val_pcie_read_cfg(bdf, current_base_offset, &reg_value);
      num_addr_asso_block = (reg_value & NUM_ADDR_ASSO_REG_MASK) >> NUM_ADDR_ASSO_REG_SHIFT;

      /* Set/Unset the Selective IDE Stream enable bit */
      if (count == str_cnt)
      {
          val_pcie_read_cfg(bdf, current_base_offset + SEL_IDE_CAP_CNTRL_REG, &reg_value);
          if (enable)
              val_pcie_write_cfg(bdf, current_base_offset + SEL_IDE_CAP_CNTRL_REG, reg_value | 1);
          else
              val_pcie_write_cfg(bdf, current_base_offset + SEL_IDE_CAP_CNTRL_REG, 0);

          return 0;
      }

      /* Base offset of IDE RID Association Register 1 */
      current_base_offset = current_base_offset + SEL_IDE_CAP_REG_SIZE;

      /* Base offset of IDE RID Association Register 2 */
      current_base_offset = current_base_offset + RID_ADDR_REG1_SIZE;

      /* Base offset of IDE Address Association Register Block */
      current_base_offset = current_base_offset + RID_ADDR_REG2_SIZE;

      /* Base offset of next Selective IDE Stream Register Block */
      current_base_offset +=  (num_addr_asso_block * IDE_ADDR_REG_BLK_SIZE);
  }

  /* If the Stream doesn't match the required selective stream, return failure */
  return 1;
}


uint32_t val_ide_program_stream_id(uint32_t bdf, uint32_t str_cnt, uint32_t stream_id)
{
  uint32_t reg_value;
  uint32_t ide_cap_base;
  uint32_t num_tc_supp;
  uint32_t num_sel_ide_stream_supp;
  uint32_t sel_ide_str_supported;
  uint32_t current_base_offset;
  uint32_t num_addr_asso_block;
  uint32_t count;

  /* Check IDE Extended Capability register is present */
  if (val_pcie_find_capability(bdf, PCIE_ECAP, ECID_IDE, &ide_cap_base) != PCIE_SUCCESS)
  {
      val_print(ACS_PRINT_ERR,
                    "\n       PCIe IDE Capability not present for BDF: 0x%x", bdf);
      return 1;
  }

  /* Check if Selective IDE Stream is supported */
  val_pcie_read_cfg(bdf, ide_cap_base + IDE_CAP_REG, &reg_value);
  sel_ide_str_supported = (reg_value & SEL_IDE_STR_MASK) >> SEL_IDE_STR_SHIFT;
  if (!sel_ide_str_supported)
  {
      val_print(ACS_PRINT_ERR, "\n       Selective IDE str not supported for BDF: %x", bdf);
      return 1;
  }

  /* Get the number of Selective IDE stream */
  num_sel_ide_stream_supp = (reg_value & NUM_SEL_STR_MASK) >> NUM_SEL_STR_SHIFT;

  /* Skip past the Link IDE register block */
  num_tc_supp = (reg_value & NUM_TC_SUPP_MASK) >> NUM_TC_SUPP_SHIFT;
  current_base_offset = ide_cap_base + IDE_CAP_REG_SIZE;
  current_base_offset = current_base_offset + ((num_tc_supp + 1) * LINK_IDE_BLK_SIZE);

  count = 0;
  while (count++ <= num_sel_ide_stream_supp)
  {
      val_pcie_read_cfg(bdf, current_base_offset, &reg_value);
      num_addr_asso_block = (reg_value & NUM_ADDR_ASSO_REG_MASK) >> NUM_ADDR_ASSO_REG_SHIFT;

      /* Write the given Stream ID in the Selective IDE Stream control Register Bit[31:24] */
      if (count == str_cnt)
      {
          val_pcie_write_cfg(bdf, current_base_offset + SEL_IDE_CAP_CNTRL_REG,
                            (stream_id << 24) & 0xFF000000);
          return 0;
      }

      /* Base offset of IDE RID Association Register 1 */
      current_base_offset = current_base_offset + SEL_IDE_CAP_REG_SIZE;

      /* Base offset of IDE RID Association Register 2 */
      current_base_offset = current_base_offset + RID_ADDR_REG1_SIZE;

      /* Base offset of IDE Address Association Register Block */
      current_base_offset = current_base_offset + RID_ADDR_REG2_SIZE;

      /* Base offset of next Selective IDE Stream Register Block */
      current_base_offset +=  (num_addr_asso_block * IDE_ADDR_REG_BLK_SIZE);
    }

  /* If the Stream doesn't match the required selective stream, return failure */
  return 1;
}

uint32_t val_ide_program_rid_base_limit_valid(uint32_t bdf, uint32_t str_cnt,
                               uint32_t base, uint32_t limit, uint32_t valid)
{
  uint32_t reg_value;
  uint32_t ide_cap_base;
  uint32_t num_tc_supp;
  uint32_t num_sel_ide_stream_supp;
  uint32_t sel_ide_str_supported;
  uint32_t current_base_offset;
  uint32_t num_addr_asso_block;
  uint32_t rid_asso_reg_1;
  uint32_t rid_asso_reg_2;
  uint32_t count;

  /* Check IDE Extended Capability register is present */
  if (val_pcie_find_capability(bdf, PCIE_ECAP, ECID_IDE, &ide_cap_base) != PCIE_SUCCESS)
  {
      val_print(ACS_PRINT_ERR,
                    "\n       PCIe IDE Capability not present for BDF: 0x%x", bdf);
      return 1;
  }

  /* Check if Selective IDE Stream is supported */
  val_pcie_read_cfg(bdf, ide_cap_base + IDE_CAP_REG, &reg_value);
  sel_ide_str_supported = (reg_value & SEL_IDE_STR_MASK) >> SEL_IDE_STR_SHIFT;
  if (!sel_ide_str_supported)
  {
      val_print(ACS_PRINT_ERR, "\n       Selective IDE str not supported for BDF: %x", bdf);
      return 1;
  }

  /* Get the number of Selective IDE stream */
  num_sel_ide_stream_supp = (reg_value & NUM_SEL_STR_MASK) >> NUM_SEL_STR_SHIFT;

  /* Skip past the Link IDE register block */
  num_tc_supp = (reg_value & NUM_TC_SUPP_MASK) >> NUM_TC_SUPP_SHIFT;
  current_base_offset = ide_cap_base + IDE_CAP_REG_SIZE;
  current_base_offset = current_base_offset + ((num_tc_supp + 1) * LINK_IDE_BLK_SIZE);

  count = 0;
  while (count++ <= num_sel_ide_stream_supp)
  {
      val_pcie_read_cfg(bdf, current_base_offset, &reg_value);
      num_addr_asso_block = (reg_value & NUM_ADDR_ASSO_REG_MASK) >> NUM_ADDR_ASSO_REG_SHIFT;

      /* Base offset of IDE RID Association Register 1 */
      current_base_offset = current_base_offset + SEL_IDE_CAP_REG_SIZE;
      rid_asso_reg_1 = current_base_offset;

      /* Base offset of IDE RID Association Register 2 */
      current_base_offset = current_base_offset + RID_ADDR_REG1_SIZE;
      rid_asso_reg_2 = current_base_offset;

      if (count == str_cnt)
      {
          /* Write RID Limit value in the RID Assosiation Register 1 */
          val_pcie_write_cfg(bdf, rid_asso_reg_1, (limit << 8) & 0xFFFF00);
          /* Write RID Base value in the RID Assosiation Register 2 */
          val_pcie_write_cfg(bdf, rid_asso_reg_2, (base << 8) & 0xFFFF00);
          /* Enable the valid bit in the RID Assosiation Register 2 */
          val_pcie_write_cfg(bdf, rid_asso_reg_2, valid);

          return 0;
      }

      /* Base offset of IDE Address Association Register Block */
      current_base_offset = current_base_offset + RID_ADDR_REG2_SIZE;

      /* Base offset of next Selective IDE Stream Register Block */
      current_base_offset +=  (num_addr_asso_block * IDE_ADDR_REG_BLK_SIZE);
  }

  /* If the Stream doesn't match the required selective stream, return failure */
  return 1;
}

uint32_t val_ide_get_num_sel_str(uint32_t bdf, uint32_t *num_sel_str)
{
  uint32_t reg_value;
  uint32_t ide_cap_base;
  uint32_t sel_ide_str_supported;

  /* Check IDE Extended Capability register is present */
  if (val_pcie_find_capability(bdf, PCIE_ECAP, ECID_IDE, &ide_cap_base) != PCIE_SUCCESS)
  {
      val_print(ACS_PRINT_ERR,
                    "\n       PCIe IDE Capability not present for BDF: 0x%x", bdf);
      return 1;
  }

  /* Check if Selective IDE Stream is supported */
  val_pcie_read_cfg(bdf, ide_cap_base + IDE_CAP_REG, &reg_value);
  sel_ide_str_supported = (reg_value & SEL_IDE_STR_MASK) >> SEL_IDE_STR_SHIFT;
  if (!sel_ide_str_supported)
  {
      val_print(ACS_PRINT_ERR, "\n       Selective IDE str not supported for BDF: %x", bdf);
      return 1;
  }

  /* Get the number of Selective IDE stream */
  *num_sel_str = ((reg_value & NUM_SEL_STR_MASK) >> NUM_SEL_STR_SHIFT) + 1;

  return 0;
}

uint32_t val_get_sel_str_status(uint32_t bdf, uint32_t str_cnt, uint32_t *str_status)
{
  uint32_t reg_value;
  uint32_t ide_cap_base;
  uint32_t num_tc_supp;
  uint32_t num_sel_ide_stream_supp;
  uint32_t sel_ide_str_supported;
  uint32_t current_base_offset;
  uint32_t num_addr_asso_block;
  uint32_t count;

  /* Check IDE Extended Capability register is present */
  if (val_pcie_find_capability(bdf, PCIE_ECAP, ECID_IDE, &ide_cap_base) != PCIE_SUCCESS)
  {
      val_print(ACS_PRINT_ERR,
                    "\n       PCIe IDE Capability not present for BDF: 0x%x", bdf);
      return 1;
  }

  /* Check if Selective IDE Stream is supported */
  val_pcie_read_cfg(bdf, ide_cap_base + IDE_CAP_REG, &reg_value);
  sel_ide_str_supported = (reg_value & SEL_IDE_STR_MASK) >> SEL_IDE_STR_SHIFT;
  if (!sel_ide_str_supported)
  {
      val_print(ACS_PRINT_ERR, "\n       Selective IDE str not supported for BDF: %x", bdf);
      return 1;
  }

  /* Get the number of Selective IDE stream */
  num_sel_ide_stream_supp = (reg_value & NUM_SEL_STR_MASK) >> NUM_SEL_STR_SHIFT;

  /* Skip past the Link IDE register block */
  num_tc_supp = (reg_value & NUM_TC_SUPP_MASK) >> NUM_TC_SUPP_SHIFT;
  current_base_offset = ide_cap_base + IDE_CAP_REG_SIZE;
  current_base_offset = current_base_offset + ((num_tc_supp + 1) * LINK_IDE_BLK_SIZE);

  count = 0;
  while (count++ <= num_sel_ide_stream_supp)
  {
      val_pcie_read_cfg(bdf, current_base_offset, &reg_value);
      num_addr_asso_block = (reg_value & NUM_ADDR_ASSO_REG_MASK) >> NUM_ADDR_ASSO_REG_SHIFT;

      /* Get the Status of Selective IDE Stream state */
      if (count == str_cnt)
      {
          val_pcie_read_cfg(bdf, current_base_offset + SEL_IDE_CAP_STATUS_REG, &reg_value);
          *str_status = reg_value & SEL_IDE_STATE_MASK;
          return 0;
      }

      /* Base offset of IDE RID Association Register 1 */
      current_base_offset = current_base_offset + SEL_IDE_CAP_REG_SIZE;

      /* Base offset of IDE RID Association Register 2 */
      current_base_offset = current_base_offset + RID_ADDR_REG1_SIZE;

      /* Base offset of IDE Address Association Register Block */
      current_base_offset = current_base_offset + RID_ADDR_REG2_SIZE;

      /* Base offset of next Selective IDE Stream Register Block */
      current_base_offset +=  (num_addr_asso_block * IDE_ADDR_REG_BLK_SIZE);
  }

  /* If the Stream doesn't match the required selective stream, return failure */
  return 1;
}

uint32_t
val_ide_establish_stream(uint32_t bdf, uint32_t count, uint32_t stream_id, uint32_t base_limit)
{
  uint32_t status, reg_value;

  status = val_ide_program_rid_base_limit_valid(bdf, count,
             PCIE_CREATE_BDF_PACKED(base_limit), PCIE_CREATE_BDF_PACKED(base_limit), 1);
  if (status)
  {
      val_print(ACS_PRINT_ERR, "\n       Failed to set RID values for BDF: 0x%x", bdf);
      return 1;
  }

  status = val_ide_program_stream_id(bdf, count, stream_id);
  if (status)
  {
      val_print(ACS_PRINT_ERR, "\n       Failed to set Stream ID for BDF: 0x%x", bdf);
      return 1;
  }

  status = val_ide_set_sel_stream(bdf, count, 1);
  if (status)
  {
      val_print(ACS_PRINT_ERR, "\n       Failed to enable Sel Stream for BDF: 0x%x", bdf);
      return 1;
  }

  status = val_get_sel_str_status(bdf, count, &reg_value);
  if (status)
  {
      val_print(ACS_PRINT_ERR, "\n       Fail to get Sel Stream state for BDF: 0x%x", bdf);
      return 1;
  }

  if (reg_value != STREAM_STATE_SECURE)
  {
      val_print(ACS_PRINT_ERR, "\n       Sel Stream is not in Secure for BDF: 0x%x", bdf);
      return 1;
  }

  return 0;
}

uint32_t val_intercnt_sec_prpty_check(uint64_t *register_entry_info)
{
  REGISTER_INFO_TABLE *register_entry;
  uint32_t rd_data = 0;
  uint32_t data_rt, data_ns, org_data;

  register_entry = (REGISTER_INFO_TABLE *)register_entry_info;

  if (register_entry->type != INTERCONNECT)
      return 0;

  val_print(ACS_PRINT_DEBUG, "\nAddress: 0x%x", register_entry->bdf);
  val_print(ACS_PRINT_DEBUG, "\nProperty: %d", register_entry->property);

  data_rt = TEST_DATA_1;
  data_ns = TEST_DATA_2;

  switch (register_entry->property)
  {
     case RMSD_PROTECT:
          /* Store the original data */
          shared_data->num_access = 1;
          shared_data->shared_data_access[0].addr = register_entry->address;
          shared_data->shared_data_access[0].access_type = READ_DATA;
          val_pe_access_mut_el3();
          org_data = shared_data->shared_data_access[0].data;

          /* Write the data_rt from ROOT */
          shared_data->num_access = 1;
          shared_data->shared_data_access[0].addr = register_entry->address;
          shared_data->shared_data_access[0].access_type = WRITE_DATA;
          shared_data->shared_data_access[0].data = data_rt;

          /* Read the data from NS */
          rd_data = val_mmio_read(register_entry->address);

          /* Fail if the NS read is successfull */
          if (rd_data == data_rt)
          {
              val_print(ACS_PRINT_ERR, "\n      Read success from NS for addr: 0x%lx",
                        register_entry->address);
              return 1;
          }

          /* Write the data_ns from NS */
          val_mmio_write(register_entry->address, data_ns);
          rd_data = val_mmio_read(register_entry->address);

          /* Fail if the NS write is successfull */
          if (rd_data == data_ns)
          {
              val_print(ACS_PRINT_ERR, "\n      Write from NS is successfull for address: 0x%x",
                        register_entry->address);
              return 1;
          }

          /* Restore the original data */
          shared_data->num_access = 1;
          shared_data->shared_data_access[0].addr = register_entry->address;
          shared_data->shared_data_access[0].access_type = WRITE_DATA;
          shared_data->shared_data_access[0].data = org_data;
          val_pe_access_mut_el3();

          rd_data = 0;
          break;

    default:
      val_print(ACS_PRINT_ERR, "\n       Invalid Security Property: %d", register_entry->property);
      return 1;
  }

  return 0;
}
