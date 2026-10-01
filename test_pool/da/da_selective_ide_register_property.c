/** @file
 * Copyright (c) 2024-2026, Arm Limited or its affiliates. All rights reserved.
 * SPDX-License-Identifier : Apache-2.0

 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use
 * this file except in compliance with the License.
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

#include "val/include/val.h"
#include "val/include/val_interface.h"

#include "val/include/val_el32.h"
#include "val/include/val_pcie.h"
#include "val/include/val_memory.h"
#include "val/include/val_pcie_enumeration.h"
#include "val/include/val_exerciser.h"
#include "val/include/val_smmu.h"
#include "val/include/val_pe.h"
#include "val/include/val_da.h"

#define TEST_NAME "da_selective_ide_register_property"
#define TEST_DESC "Check Selective IDE Streams are Locked/Unlocked        "
#define TEST_RULE "RYHQQL"

#define MAX_LOCKABLE_IDE_STREAMS 32
#define WRITE_DETECT_RETRIES 100

static
int
write_from_root(uint64_t addr, uint32_t data)
{

  shared_data->num_access = 1;
  shared_data->shared_data_access[0].addr = addr;
  shared_data->shared_data_access[0].data = data;
  shared_data->shared_data_access[0].access_type = WRITE_DATA;

  if (val_pe_access_mut_el3())
  {
    val_print(ACS_PRINT_ERR, " MUT Access failed for VA: 0x%llx", addr);
    return 1;
  }
  return 0;
}

static
void
payload(void)
{
  uint32_t pe_index;
  pcie_device_bdf_table *bdf_tbl_ptr;
  uint32_t tbl_index;
  uint32_t dp_type;
  uint32_t bdf;
  uint32_t reg_value;
  uint32_t test_fail = 0;
  uint32_t test_skip = 1;
  uint32_t count;
  uint32_t status;
  uint32_t pgt_attr_el3;
  uint32_t lock_mask;
  uint64_t va;
  uint64_t cfg_addr;
  uint32_t da_cap_base;
  uint32_t ide_cap_base;
  uint32_t stream_id;
  uint32_t str_base;
  uint32_t str_size;
  uint32_t num_test_streams;
  uint32_t control;
  uint32_t active_stream;
  uint32_t num_sel_streams, num_link_streams;
  uint32_t retry, index, complete;

  tbl_index = 0;
  pe_index = val_pe_get_index_mpid(val_pe_get_mpid());
  bdf_tbl_ptr = val_pcie_bdf_table_ptr();
  if ((bdf_tbl_ptr == NULL) || (bdf_tbl_ptr->num_entries == 0))
  {
      val_print(ACS_PRINT_WARN, " No PCIe BDF entries discovered", 0);
      val_set_status(pe_index, "SKIP", 01);
      return;
  }

  while (tbl_index < bdf_tbl_ptr->num_entries)
  {
      bdf = bdf_tbl_ptr->device[tbl_index++].bdf;
      dp_type = val_pcie_device_port_type(bdf);

      if (dp_type != RP)
          continue;

      test_skip = 0;

      val_print(ACS_PRINT_TEST, " Checking BDF: 0x%x", bdf);

      /* Get the PCIE DVSEC Capability register */
      if (val_pcie_find_da_capability(bdf, &da_cap_base) != PCIE_SUCCESS)
      {
          val_print(ACS_PRINT_ERR,
                          " PCIe DA DVSEC capability not present,bdf 0x%x", bdf);
          test_fail++;
          continue;
      }

      /* Map the configuration address before writing from root as ROOT PAS */
      va = val_get_free_va(val_get_min_tg());
      cfg_addr = val_pcie_get_bdf_config_addr(bdf);
      pgt_attr_el3 = LOWER_ATTRS(PGT_ENTRY_ACCESS | SHAREABLE_ATTR(OUTER_SHAREABLE)
                          | GET_ATTR_INDEX(DEV_MEM_nGnRnE) | PGT_ENTRY_AP_RW | PAS_ATTR(ROOT_PAS));
      if (!cfg_addr || val_add_mmu_entry_el3(va, cfg_addr, pgt_attr_el3))
      {
          val_print(ACS_PRINT_ERR, " Failed to map RP configuration for BDF: 0x%x", bdf);
          test_fail++;
          continue;
      }

      if (val_ide_get_num_sel_str(bdf, &num_sel_streams) ||
          val_get_num_link_str(bdf, &num_link_streams) ||
          val_pcie_find_capability(bdf, PCIE_ECAP, ECID_IDE, &ide_cap_base) != PCIE_SUCCESS)
      {
          val_print(ACS_PRINT_ERR, " Failed to read IDE stream counts for BDF: 0x%x", bdf);
          test_fail++;
          continue;
      }

      /* RMEDA_CTL2 has no lock bits for Selective IDE streams with index > 31. */
      num_test_streams = num_sel_streams;
      if (num_test_streams > MAX_LOCKABLE_IDE_STREAMS)
          num_test_streams = MAX_LOCKABLE_IDE_STREAMS;
      lock_mask = num_test_streams == MAX_LOCKABLE_IDE_STREAMS ?
                  0xFFFFFFFFu : (1u << num_test_streams) - 1;
      active_stream = 0;

      if (val_pcie_enable_tdisp(bdf) ||
          val_pcie_read_cfg(bdf, da_cap_base + RMEDA_CTL1, &reg_value) != PCIE_SUCCESS ||
          !(reg_value & 1u))
      {
          val_print(ACS_PRINT_ERR, " Unable to set tdisp_en for BDF: 0x%x", bdf);
          test_fail++;
          goto port_cleanup;
      }

      str_base = ide_cap_base + IDE_CAP_REG_SIZE + num_link_streams * LINK_IDE_BLK_SIZE;
      for (count = 1; count <= num_test_streams; count++, str_base += str_size)
      {
          /* Walk variable-length blocks to read the target's control register. */
          str_size = SEL_IDE_CAP_REG_SIZE + RID_ADDR_REG1_SIZE + RID_ADDR_REG2_SIZE;
          if (str_base + str_size > PCIE_CFG_SIZE ||
              val_pcie_read_cfg(bdf, str_base, &reg_value) != PCIE_SUCCESS)
          {
              val_print(ACS_PRINT_ERR, " Failed to read Sel stream capability, BDF: 0x%x", bdf);
              test_fail++;
              goto port_cleanup;
          }

          str_size += ((reg_value & NUM_ADDR_ASSO_REG_MASK) >> NUM_ADDR_ASSO_REG_SHIFT) *
                      IDE_ADDR_REG_BLK_SIZE;

          if (str_base + str_size > PCIE_CFG_SIZE)
          {
              val_print(ACS_PRINT_ERR, " Invalid Sel stream register block, BDF: 0x%x", bdf);
              test_fail++;
              goto port_cleanup;
          }

          if (write_from_root(va + da_cap_base + RMEDA_CTL2, 0) ||
              val_pcie_read_cfg(bdf, da_cap_base + RMEDA_CTL2, &reg_value) != PCIE_SUCCESS ||
              (reg_value & lock_mask))
          {
              val_print(ACS_PRINT_ERR, " Failed to unlock Sel streams for BDF: 0x%x", bdf);
              test_fail++;
              goto port_cleanup;
          }

          /* The setup helper accepts an unpacked BDF and checks the Secure state. */
          active_stream = count;
          status = val_ide_establish_stream(bdf, count, val_generate_stream_id(),
                                           bdf);
          if (status)
          {
              val_print(ACS_PRINT_ERR, " Failed to establish stream for bdf: 0x%x", bdf);
              test_fail++;
              goto stream_cleanup;
          }

          /* Lock every implemented block to verify that write detection clears all locks. */
          if (write_from_root(va + da_cap_base + RMEDA_CTL2, lock_mask) ||
              val_pcie_read_cfg(bdf, da_cap_base + RMEDA_CTL2, &reg_value) != PCIE_SUCCESS ||
              (reg_value & lock_mask) != lock_mask)
          {
              val_print(ACS_PRINT_ERR, " Failed to lock Sel streams for BDF: 0x%x", bdf);
              test_fail++;
              goto stream_cleanup;
          }

          /* Locking must leave the target enabled and Secure immediately before the NS write. */
          if (val_pcie_read_cfg(bdf, str_base + SEL_IDE_CAP_CNTRL_REG,
                               &control) != PCIE_SUCCESS ||
              !(control & SEL_IDE_STR_EN_MASK) ||
              val_get_sel_str_status(bdf, count, &reg_value) ||
              reg_value != STREAM_STATE_SECURE)
          {
              val_print(ACS_PRINT_ERR,
                        " Locked stream is not enabled and Secure for BDF: 0x%x", bdf);
              test_fail++;
              goto stream_cleanup;
          }

          /* Change only Stream ID through the normal Non-secure configuration access path. */
          stream_id = (control & SEL_IDE_STR_ID_MASK) >> SEL_IDE_STR_ID_SHIFT;
          stream_id = stream_id == 0xFFu ? 1u : stream_id + 1;
          status = val_ide_program_stream_id(bdf, count, stream_id);
          if (status)
          {
              val_print(ACS_PRINT_ERR, " Failed to re-set Stream ID for BDF: 0x%x", bdf);
              test_fail++;
              goto stream_cleanup;
          }

          /* Observe the violation before any software unlock, disable or cleanup. */
          for (retry = 0; retry < WRITE_DETECT_RETRIES; retry++)
          {
              complete = 0;
              status = val_pcie_read_cfg(bdf, da_cap_base + RMEDA_CTL2, &reg_value);
              if (status != PCIE_SUCCESS)
                  break;

              complete = (reg_value & lock_mask) == 0;

              /* IFLPRX applies to all hosted streams, including indices above 31. */
              for (index = 1; index <= num_sel_streams; index++)
              {
                  status = val_get_sel_str_status(bdf, index, &reg_value);
                  if (status)
                      break;

                  if (reg_value != STREAM_STATE_INSECURE)
                      complete = 0;
              }

              if (status)
                  break;

              /* Link IDE is optional; its status helper uses zero-based indices. */
              for (index = 0; index < num_link_streams; index++)
              {
                  status = val_get_link_str_status(bdf, index, &reg_value);
                  if (status)
                      break;

                  if (reg_value != STREAM_STATE_INSECURE)
                      complete = 0;
              }

              if (status || complete)
                  break;

              if (retry + 1 < WRITE_DETECT_RETRIES)
                  val_time_delay_ms(1);
          }
          if (status || !complete)
          {
              val_print(ACS_PRINT_ERR,
                        " IDE streams not Insecure or locks not cleared, BDF: %x", bdf);
              test_fail++;
          }

stream_cleanup:
          if (write_from_root(va + da_cap_base + RMEDA_CTL2, 0) ||
              val_pcie_read_cfg(bdf, da_cap_base + RMEDA_CTL2, &reg_value) != PCIE_SUCCESS ||
              (reg_value & lock_mask) || val_ide_set_sel_stream(bdf, count, 0) ||
              val_pcie_read_cfg(bdf, str_base + SEL_IDE_CAP_CNTRL_REG,
                               &control) != PCIE_SUCCESS || (control & SEL_IDE_STR_EN_MASK))
          {
              val_print(ACS_PRINT_ERR, " Failed to clean up Sel stream for BDF: 0x%x", bdf);
              test_fail++;
              break;
          }
          active_stream = 0;
      }

port_cleanup:
      /* Leave the RP unlocked with TDISP disabled on success and failure paths. */
      if (write_from_root(va + da_cap_base + RMEDA_CTL2, 0) ||
          val_pcie_read_cfg(bdf, da_cap_base + RMEDA_CTL2, &reg_value) != PCIE_SUCCESS ||
          (reg_value & lock_mask))
          test_fail++;
      if (val_pcie_disable_tdisp(bdf) ||
          val_pcie_read_cfg(bdf, da_cap_base + RMEDA_CTL1, &reg_value) != PCIE_SUCCESS ||
          (reg_value & 1u))
      {
          val_print(ACS_PRINT_ERR, " Failed to disable TDISP for BDF: 0x%x", bdf);
          test_fail++;
      }
      if (active_stream && val_ide_set_sel_stream(bdf, active_stream, 0))
          test_fail++;

  }

  if (test_skip)
      val_set_status(pe_index, "SKIP", 01);
  else if (test_fail)
      val_set_status(pe_index, "FAIL", 01);
  else
      val_set_status(pe_index, "PASS", 01);

  return;
}

uint32_t
da_selective_ide_register_property_entry(uint32_t num_pe)
{

  num_pe = 1;
  uint32_t status = ACS_STATUS_FAIL;  //default value

  status = val_initialize_test(TEST_NAME, TEST_DESC, num_pe, TEST_RULE);

  /* This check is when user is forcing us to skip this test */
  if (status != ACS_STATUS_SKIP)
      val_run_test_payload(num_pe, payload, 0);

  /* get the result from all PE and check for failure */
  status = val_check_for_error(num_pe);

  val_report_status(0, "END");

  return status;
}
