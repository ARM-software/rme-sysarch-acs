/** @file
 * Copyright (c) 2024-2025, 2026, Arm Limited or its affiliates. All rights reserved.
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
#define _TEST_
#include "val/include/val.h"
#include "val/include/val_interface.h"

#include "val/include/val_el32.h"
#include "val/include/val_pcie.h"
#include "val/include/val_memory.h"
#include "val/include/val_pgt.h"
#include "val/include/val_pcie_enumeration.h"
#include "val/include/val_exerciser.h"
#include "val/include/val_smmu.h"
#include "val/include/val_pe.h"
#include "val/include/val_da.h"
#include "val/include/val_dpt.h"
#include "val/include/val_iovirt.h"
#include "val/include/val_gic.h"
#include "val/include/val_gic_support.h"
#include "val/sys_arch_src/gic/its/val_gic_its.h"

#define TEST_NAME "da_p2p_btw_2_tdisp_devices"
#define TEST_DESC "P2P traffic between two TDISP devices                  "
#define TEST_RULE "RMDPKR"

/* The peers are on different Root Ports, so each uses stream block 1. */
#define P2P_IDE_STREAM 1u

typedef struct {
    smmu_master_attributes_t master;
    pgt_descriptor_t pgt_desc;
    VAL_DPT_GPT_STATE bar_gpt;
    uint32_t mapped;
} p2p_realm_mapping_t;

static uint32_t
prepare_p2p_mapping(uint32_t req_bdf, uint64_t bar_base, p2p_realm_mapping_t *mapping)
{
    static const uint32_t pa_bits[] = {32u, 36u, 40u, 42u, 44u, 48u};
    memory_region_descriptor_t mem_desc[2] = {0};
    smmu_master_attributes_t *master = &mapping->master;
    pgt_descriptor_t *pgt_desc = &mapping->pgt_desc;
    uint32_t device_id, its_id, ps;
    uint64_t bar_page = bar_base & ~((uint64_t)PAGE_SIZE_4K - 1u);

    master->smmu_index = val_iovirt_get_rc_smmu_index(PCIE_EXTRACT_BDF_SEG(req_bdf),
                                                     PCIE_CREATE_BDF_PACKED(req_bdf));
    if (master->smmu_index == ACS_INVALID_INDEX ||
        val_iovirt_get_smmu_info(SMMU_CTRL_ARCH_MAJOR_REV, master->smmu_index) != 3u)
    {
        val_print(ACS_PRINT_WARN, " No SMMUv3 path for requester BDF: 0x%x", req_bdf);
        return ACS_STATUS_SKIP;
    }

    /* The SMMU SID comes from IOVIRT, independently of the PCIe IDE Stream ID. */
    if (val_iovirt_get_device_info(PCIE_CREATE_BDF_PACKED(req_bdf),
                                   PCIE_EXTRACT_BDF_SEG(req_bdf),
                                   &device_id, &master->streamid, &its_id))
        return ACS_STATUS_ERR;
    master->stage2 = 1u;

    pgt_desc->ias = val_smmu_get_info(SMMU_IN_ADDR_SIZE, master->smmu_index);
    pgt_desc->oas = val_smmu_get_info(SMMU_OUT_ADDR_SIZE, master->smmu_index);
    if (pgt_desc->ias < 32u || pgt_desc->oas < 32u)
        return ACS_STATUS_ERR;

    /* The EL3 page-table builder uses 4-KiB granules and up to four levels. */
    if (pgt_desc->ias > 48u)
        pgt_desc->ias = 48u;
    if (pgt_desc->oas > 48u)
        pgt_desc->oas = 48u;
    if (bar_base >= (1ull << pgt_desc->ias) || bar_base >= (1ull << pgt_desc->oas))
    {
        val_print(ACS_PRINT_ERR, " Peer BAR exceeds SMMU mapping range: 0x%lx", bar_base);
        return ACS_STATUS_ERR;
    }

    for (ps = 0u; ps < sizeof(pa_bits) / sizeof(pa_bits[0]); ++ps)
        if (pa_bits[ps] == pgt_desc->oas)
            break;
    if (ps == sizeof(pa_bits) / sizeof(pa_bits[0]))
        return ACS_STATUS_ERR;

    /* Configure the SMMU's stage 2 without changing the PE's VTCR or VTTBR. */
    pgt_desc->stage = PGT_STAGE2;
    pgt_desc->vtcr.ps = ps;
    pgt_desc->vtcr.tg = 0u;
    pgt_desc->vtcr.tg_size_log2 = 12u;
    pgt_desc->vtcr.tsz = 64u - pgt_desc->ias;
    pgt_desc->vtcr.sl = pgt_desc->ias > 39u ? 2u : 1u;
    pgt_desc->vtcr.sh = 3u;
    pgt_desc->vtcr.irgn = 1u;
    pgt_desc->vtcr.orgn = 1u;

    /* DMA uses the BAR address directly. Map its entire page, even for a byte read.
     * S2 MemAttr=0 selects Device-nGnRnE; NS=0 keeps the output in Realm PAS.
     * mem_desc[1] remains the zero-length terminator required by the EL3 builder.
     */
    mem_desc[0].virtual_address = bar_page;
    mem_desc[0].physical_address = bar_page;
    mem_desc[0].length = PAGE_SIZE_4K;
    mem_desc[0].attributes = PGT_STAGE2_AP_RO;

    if (val_memory_map_el3_data((uint64_t)mem_desc, sizeof(mem_desc), NONSECURE_PAS) ||
        val_memory_map_el3_data((uint64_t)master, sizeof(*master), NONSECURE_PAS) ||
        val_memory_map_el3_data((uint64_t)pgt_desc, sizeof(*pgt_desc), NONSECURE_PAS))
        return ACS_STATUS_ERR;

    /* Preserve NS access to the exerciser's BAR while permitting Realm DMA. */
    if (val_dpt_allow_gpt(bar_page, &mapping->bar_gpt) ||
        val_smmu_gpt_invalidate_el3(master))
        return ACS_STATUS_ERR;

    if (val_rlm_pgt_create(mem_desc, pgt_desc) || val_smmu_rlm_map_el3(master, pgt_desc))
        return ACS_STATUS_ERR;
    mapping->mapped = 1u;
    return ACS_STATUS_PASS;
}

static uint32_t
release_p2p_mapping(p2p_realm_mapping_t *mapping)
{
    uint32_t status = ACS_STATUS_PASS;

    if (mapping->mapped)
    {
        if (val_smmu_rlm_unmap_el3(&mapping->master))
        {
            /* Retain tables and GPT permission if the SMMU might still use them. */
            val_print(ACS_PRINT_ERR, " Failed to unmap requester SID: 0x%x",
                      mapping->master.streamid);
            return ACS_STATUS_ERR;
        }

        mapping->mapped = 0u;
    }

    if (mapping->pgt_desc.pgt_base &&
        val_rlm_pgt_destroy(&mapping->pgt_desc))
        status = ACS_STATUS_ERR;

    /* After unmapping, restore GPT permissions even if table destruction failed. */
    if (val_dpt_restore_gpt(&mapping->bar_gpt, &mapping->master))
        status = ACS_STATUS_ERR;

    return status;
}

uint32_t
get_target_exer_bdf(uint32_t req_rp_bdf, uint32_t *tgt_e_bdf,
                    uint32_t *tgt_rp_bdf, uint64_t *bar_base)
{

  uint32_t erp_bdf;
  uint32_t e_bdf;
  uint32_t instance;
  uint32_t req_rp_ecam_index;
  uint32_t erp_ecam_index;
  uint32_t status;

  instance = val_exerciser_get_info(EXERCISER_NUM_CARDS);

  while (instance-- != 0)
  {
      /* if init fail moves to next exerciser */
      if (val_exerciser_init(instance))
          continue;

      e_bdf = val_exerciser_get_bdf(instance);

      /* Read e_bdf BAR Register to get the Address to perform P2P */
      /* If No BAR Space, continue */
      val_pcie_get_mmio_bar(e_bdf, bar_base);
      if (*bar_base == 0)
          continue;

      /* Get RP of the exerciser */
      if (val_pcie_get_rootport(e_bdf, &erp_bdf))
          continue;

      if (req_rp_bdf != erp_bdf)
      {
          status = val_pcie_get_ecam_index(req_rp_bdf, &req_rp_ecam_index);
          if (status)
          {
             val_print(ACS_PRINT_ERR, " Error Ecam index for req RP BDF: 0x%x", req_rp_bdf);
             goto test_fail;
          }

          status = val_pcie_get_ecam_index(erp_bdf, &erp_ecam_index);
          if (status)
          {
             val_print(ACS_PRINT_ERR, " Error Ecam index for tgt RP BDF: 0x%x", erp_bdf);
             goto test_fail;
          }

          if ((val_pcie_get_info(PCIE_INFO_ECAM, req_rp_ecam_index) !=
               val_pcie_get_info(PCIE_INFO_ECAM, erp_ecam_index)) ||
              (val_pcie_get_info(PCIE_INFO_SEGMENT, req_rp_ecam_index) !=
               val_pcie_get_info(PCIE_INFO_SEGMENT, erp_ecam_index)))
              continue;

          *tgt_e_bdf = e_bdf;
          *tgt_rp_bdf = erp_bdf;

          /* Enable Bus Master Enable */
          val_pcie_enable_bme(e_bdf);
          /* Enable Memory Space Access */
          val_pcie_enable_msa(e_bdf);

          return ACS_STATUS_PASS;
      }
  }

test_fail:
  /* Return failure if No Such Exerciser Found */
  *tgt_e_bdf = 0;
  *tgt_rp_bdf = 0;
  *bar_base = 0;
  return ACS_STATUS_FAIL;
}

uint32_t
check_p2p_transaction(uint32_t req_instance, uint64_t bar_base)
{
  /* This test uses stage-2 translation, without ATS or a cached ATC entry. */
  if (val_exerciser_set_param(CFG_TXN_ATTRIBUTES, TXN_ADDR_TYPE,
                              AT_UNTRANSLATED, req_instance) != ACS_STATUS_PASS ||
      val_exerciser_set_param(CFG_TXN_ATTRIBUTES, TXN_ATC_ENTRY,
                              ATC_ENTRY_DISABLE, req_instance) != ACS_STATUS_PASS ||
      val_exerciser_set_param(DMA_ATTRIBUTES, bar_base, 1, req_instance) != ACS_STATUS_PASS)
  {
      val_print(ACS_PRINT_ERR, " Failed to configure P2P DMA for exerciser %u", req_instance);
      return ACS_STATUS_ERR;
  }

  if (val_exerciser_ops(START_DMA, EDMA_TO_DEVICE, req_instance) != ACS_STATUS_PASS)
  {
      val_print(ACS_PRINT_ERR, " P2P DMA read failed for exerciser %u", req_instance);
      return ACS_STATUS_ERR;
  }

  return ACS_STATUS_PASS;
}

static
void
payload(void)
{

  uint32_t status;
  uint32_t index;
  uint32_t req_e_bdf;
  uint32_t req_rp_bdf;
  uint32_t tgt_e_bdf;
  uint32_t tgt_rp_bdf;
  uint32_t instance;
  uint32_t test_skip;
  uint64_t bar_base;
  uint32_t test_fails;
  uint32_t req_ide_active = 0;
  uint32_t tgt_ide_active = 0;
  uint32_t ide_unsupported = 0;
  uint32_t dma_failed = 0;
  uint32_t req_tdisp_attempted = 0;
  uint32_t tgt_tdisp_attempted = 0;
  p2p_realm_mapping_t mapping;

  test_skip = 1;
  test_fails = 0;
  index = val_pe_get_index_mpid(val_pe_get_mpid());
  instance = val_exerciser_get_info(EXERCISER_NUM_CARDS);
  if (instance == 0)
  {
    val_print(ACS_PRINT_WARN, " No exerciser cards discovered", 0);
    val_set_status(index, "SKIP", 01);
    return;
  }

  while (instance-- != 0)
  {
      req_ide_active = 0;
      tgt_ide_active = 0;
      dma_failed = 0;
      req_tdisp_attempted = 0;
      tgt_tdisp_attempted = 0;
      val_memory_set(&mapping, sizeof(mapping), 0);
      mapping.master.smmu_index = ACS_INVALID_INDEX;

      /* if init fail moves to next exerciser */
      if (val_exerciser_init(instance))
          continue;

      req_e_bdf = val_exerciser_get_bdf(instance);
      val_print(ACS_PRINT_TEST, " Requester exerciser BDF - 0x%x", req_e_bdf);
      if (val_dpt_wait_for_dma(instance) != ACS_STATUS_PASS)
      {
          val_set_status(index, "FAIL", 01);
          return;
      }

      /* Get RP of the exerciser */
      if (val_pcie_get_rootport(req_e_bdf, &req_rp_bdf))
          continue;

      /* Find another exerciser on other rootport,
         Skip the current exerciser if no such exerciser if found */
      if (get_target_exer_bdf(req_rp_bdf, &tgt_e_bdf, &tgt_rp_bdf, &bar_base))
          continue;

      status = prepare_p2p_mapping(req_e_bdf, bar_base, &mapping);
      if (status == ACS_STATUS_SKIP)
          continue;
      if (status != ACS_STATUS_PASS)
      {
          val_print(ACS_PRINT_ERR, " Failed to map requester for P2P DMA, BDF: 0x%x", req_e_bdf);
          test_fails++;
          goto test_clean;
      }

      test_skip = 0;

      /* An enable failure can occur after TDISP_EN was written. */
      req_tdisp_attempted = 1;
      if (val_pcie_enable_tdisp(req_rp_bdf))
      {
          val_print(ACS_PRINT_ERR, " Unable to set tdisp_en for BDF: 0x%x", req_rp_bdf);
          test_fails++;
          goto test_clean;
      }

      tgt_tdisp_attempted = 1;
      if (val_pcie_enable_tdisp(tgt_rp_bdf))
      {
          val_print(ACS_PRINT_ERR, " Unable to set tdisp_en for BDF: 0x%x", tgt_rp_bdf);
          test_fails++;
          goto test_clean;
      }

      val_print(ACS_PRINT_DEBUG, " Target exerciser BDF - 0x%x", tgt_e_bdf);

      status = val_pcie_ide_establish(req_e_bdf, req_rp_bdf, P2P_IDE_STREAM,
                          val_generate_stream_id(), PCIE_CREATE_BDF_PACKED(req_e_bdf));
      if (status == ACS_STATUS_SKIP)
      {
          ide_unsupported = 1;
          goto test_clean;
      }

      if (status != ACS_STATUS_PASS)
      {
          val_print(ACS_PRINT_ERR, " Failed to establish requester IDE, BDF: 0x%x", req_e_bdf);
          test_fails++;
          goto test_clean;
      }

      req_ide_active = P2P_IDE_STREAM;
      if (val_ide_set_sel_stream_lock(req_rp_bdf, req_ide_active, 1))
      {
          val_print(ACS_PRINT_ERR, " Failed to lock requester IDE, RP BDF: 0x%x", req_rp_bdf);
          test_fails++;
          goto test_clean;
      }

      /* The target helper establishes IDE, associates the single-byte BAR read,
       * verifies Secure state, locks the RP stream and transitions the TDI to RUN.
       */
      status = val_dpt_ide_setup_target(tgt_e_bdf, tgt_rp_bdf, req_rp_bdf,
                                      bar_base, 1u, &tgt_ide_active);
      if (status == ACS_STATUS_SKIP)
      {
          ide_unsupported = 1;
          goto test_clean;
      }

      if (status != ACS_STATUS_PASS)
      {
          val_print(ACS_PRINT_ERR, " Failed to establish target IDE, BDF: 0x%x", tgt_e_bdf);
          test_fails++;
          goto test_clean;
      }

      if (val_device_lock(req_e_bdf))
      {
          val_print(ACS_PRINT_ERR, " Failed to lock the device: 0x%lx", req_e_bdf);
          test_fails++;
          goto test_clean;
      }

      /* Check if P2P transaction causes any deadlock */
      status = check_p2p_transaction(instance, bar_base);
      if (status)
      {
          test_fails++;
          dma_failed = 1;
      }

test_clean:
      /* A timeout can leave DMA outstanding. Retain all state until it is idle. */
      if (val_dpt_wait_for_dma(instance) != ACS_STATUS_PASS)
      {
          val_set_status(index, "FAIL", ++test_fails);
          return;
      }

      if (release_p2p_mapping(&mapping) != ACS_STATUS_PASS)
      {
          val_print(ACS_PRINT_ERR, " Failed to release P2P mapping, BDF: 0x%x", req_e_bdf);
          val_pcie_disable_bme(req_e_bdf);
          val_set_status(index, "FAIL", ++test_fails);
          return;
      }

      val_print(ACS_PRINT_DEBUG, " Putting the devices back into unlocked state", 0);
      if (req_ide_active &&
          val_dpt_ide_stop(req_e_bdf, req_rp_bdf, P2P_IDE_STREAM, req_ide_active))
          test_fails++;
      if (tgt_ide_active &&
          val_dpt_ide_stop(tgt_e_bdf, tgt_rp_bdf, P2P_IDE_STREAM, tgt_ide_active))
          test_fails++;
      if (req_tdisp_attempted && val_pcie_disable_tdisp(req_rp_bdf))
          test_fails++;
      if (tgt_tdisp_attempted && val_pcie_disable_tdisp(tgt_rp_bdf))
          test_fails++;
      /* Clear Error Status Bits */
      val_pcie_clear_device_status_error(req_rp_bdf);
      val_pcie_clear_sig_target_abort(req_rp_bdf);
      if (dma_failed)
      {
          val_set_status(index, "FAIL", test_fails);
          return;
      }
  }

  if (test_fails)
      val_set_status(index, "FAIL", test_fails);
  else if (ide_unsupported)
      val_set_status(index, "SKIP", 03);
  else if (test_skip)
      val_set_status(index, "SKIP", 02);
  else
      val_set_status(index, "PASS", 01);

}

uint32_t
da_p2p_btw_2_tdisp_devices_entry(uint32_t num_pe)
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
