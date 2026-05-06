/** @file
 * Copyright (c) 2026, Arm Limited or its affiliates. All rights reserved.
 * SPDX-License-Identifier : Apache-2.0
 *
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

#include "val/include/val.h"
#include "val/include/val_interface.h"
#include "val/include/val_cxl.h"
#include "val/include/val_spdm.h"
#include "val/include/val_pe.h"
#include "val/include/val_mec.h"
#include "val/include/val_iovirt.h"
#include "val/include/val_smmu.h"
#include "val/include/val_el32.h"
#include "val/include/val_memory.h"

#if ENABLE_SPDM
#include "industry_standard/cxl_tsp.h"
#endif

#define TEST_NAME "cxl_rplcmc_type3_target_ckid"
#define TEST_DESC "Target-side encryption exposes adequate CKID space"
#define TEST_RULE "RPLCMC"

#if ENABLE_SPDM
static uint32_t
get_common_mecid_width(uint32_t *width_out)
{
  uint32_t mec_supported = val_is_mec_supported();
  uint32_t mec_enabled = 0u;
  uint32_t num_smmu;
  uint32_t common_width;
  uint32_t pe_width;
  uint32_t status = ACS_STATUS_FAIL;

  /* Validate caller storage for returning the width. */
  if (width_out == NULL)
    return ACS_STATUS_FAIL;

  /* Skip the query when MEC is not supported. */
  if (mec_supported == 0u)
    return ACS_STATUS_SKIP;

  /* Enable MEC to query MECID width information. */
  if (val_rlm_enable_mec())
  {
    val_print(ACS_PRINT_ERR, " RPLCMC: Failed to enable MEC for width query", 0);
    return ACS_STATUS_FAIL;
  }
  mec_enabled = 1u;

  /* Start with the PE MECID width as the common baseline. */
  pe_width = (uint32_t)VAL_EXTRACT_BITS(val_pe_reg_read(MECIDR_EL2), 0, 3) + 1u;
  common_width = pe_width;

  /* Find the minimum MECID width across MEC-capable SMMUs. */
  num_smmu = (uint32_t)val_smmu_get_info(SMMU_NUM_CTRL, 0);
  for (uint32_t idx = 0; idx < num_smmu; ++idx)
  {
    uint64_t smmu_base = val_smmu_get_info(SMMU_CTRL_BASE, idx);

    /* Verify SMMU MEC implementation and skip if not present. */
    if (val_smmu_rlm_check_mec_impl(smmu_base))
    {
      val_print(ACS_PRINT_ERR,
                " RPLCMC: MEC implementation check failed for SMMU index %x",
                (uint64_t)idx);
      goto cleanup;
    }

    if (shared_data->shared_data_access[0].data == 0u)
      continue;

    /* Read the SMMU MECID width and adjust the common width. */
    if (val_smmu_rlm_get_mecidw(smmu_base))
    {
      val_print(ACS_PRINT_ERR,
                " RPLCMC: Failed to read MECID width for SMMU index %x",
                (uint64_t)idx);
      goto cleanup;
    }

    uint32_t smmu_width = (uint32_t)shared_data->shared_data_access[0].data + 1u;
    if (smmu_width < common_width)
      common_width = smmu_width;
  }

  *width_out = common_width;
  status = ACS_STATUS_PASS;

cleanup:
  /* Disable MEC if it was enabled locally. */
  if (mec_enabled != 0u)
  {
    if (val_rlm_disable_mec())
      val_print(ACS_PRINT_WARN,
                " RPLCMC: Failed to disable MEC after width query",
                0);
  }

  return status;
}

static void
payload(void)
{
  uint32_t pe_index = val_pe_get_index_mpid(val_pe_get_mpid());
  CXL_COMPONENT_TABLE *component_table = val_cxl_component_table_ptr();
  uint32_t type3_devices = 0;
  uint32_t encryption_capable = 0;
  uint32_t evaluated = 0;
  uint32_t failures = 0;
  uint32_t common_width = 0;
  uint64_t required_ckids64;
  uint32_t required_ckids;
  uint32_t status;

  /* Determine the common MECID width needed for CKID sizing. */
  status = get_common_mecid_width(&common_width);
  if (status == ACS_STATUS_SKIP)
  {
    val_print(ACS_PRINT_DEBUG,
              " RPLCMC: MEC unsupported - skipping test",
              0);
    val_set_status(pe_index, "SKIP", 01);
    return;
  }
  if (status != ACS_STATUS_PASS)
  {
    val_print(ACS_PRINT_ERR,
              " RPLCMC: Unable to determine common MECID width",
              0);
    val_set_status(pe_index, "FAIL", 01);
    return;
  }

  /* Ensure CXL components exist before evaluating Type-3 devices. */
  if ((component_table == NULL) || (component_table->num_entries == 0u))
  {
    val_print(ACS_PRINT_DEBUG,
              " RPLCMC: No CXL components discovered - skipping test",
              0);
    val_set_status(pe_index, "SKIP", 02);
    return;
  }

  /* Compute the minimum CKID count derived from the common width. */
  if (common_width >= 32u)
  {
    required_ckids = 0xFFFFFFFFu;
  }
  else
  {
    required_ckids64 = (1ull << common_width) + 1ull;
    required_ckids = (uint32_t)required_ckids64;
  }

  /* Scan Type-3 components and validate target encryption capabilities. */
  for (uint32_t idx = 0; idx < component_table->num_entries; ++idx)
  {
    const CXL_COMPONENT_ENTRY *component = &component_table->component[idx];
    libcxltsp_device_capabilities_t capabilities;
    val_spdm_context_t ctx;
    uint32_t session_id = 0u;
    uint32_t session_active = 0u;
    uint32_t features;

    if (component->device_type != CXL_DEVICE_TYPE_TYPE3)
      continue;

    /* Open a SPDM session to query CXL TSP capabilities. */
    type3_devices++;
    val_memory_set(&capabilities, sizeof(capabilities), 0);

    status = val_spdm_session_open(component->bdf, &ctx, &session_id);
    if (status == ACS_STATUS_SKIP)
    {
      val_print(ACS_PRINT_WARN,
                " RPLCMC: DOE absent for device BDF 0x%x - skipping",
                (uint64_t)component->bdf);
      continue;
    }
    if (status != ACS_STATUS_PASS)
    {
      val_print(ACS_PRINT_ERR,
                " RPLCMC: Failed to open SPDM session for BDF 0x%x",
                (uint64_t)component->bdf);
      failures++;
      continue;
    }
    session_active = 1u;

    /* Fetch device capabilities and confirm encryption support. */
    status = val_spdm_send_cxl_tsp_get_version(&ctx, session_id);
    if (status != ACS_STATUS_PASS)
    {
      val_print(ACS_PRINT_ERR,
                " RPLCMC: TSP GET_VERSION failed for BDF 0x%x",
                (uint64_t)component->bdf);
      failures++;
      goto device_cleanup;
    }

    status = val_spdm_send_cxl_tsp_get_capabilities(&ctx,
                                                    session_id,
                                                    &capabilities);
    if (status != ACS_STATUS_PASS)
    {
      val_print(ACS_PRINT_ERR,
                " RPLCMC: TSP GET_CAPABILITIES failed for BDF 0x%x",
                (uint64_t)component->bdf);
      failures++;
      goto device_cleanup;
    }

    features = capabilities.memory_encryption_features_supported;
    if ((features & CXL_TSP_MEMORY_ENCRYPTION_FEATURES_SUPPORT_ENCRYPTION) == 0u)
    {
      goto device_cleanup;
    }

    /* Validate CKID-based encryption support and CKID count. */
    encryption_capable++;
    evaluated++;

    if ((features & CXL_TSP_MEMORY_ENCRYPTION_FEATURES_SUPPORT_CKID_BASED_ENCRYPTION) == 0u)
    {
      val_print(ACS_PRINT_ERR,
                " RPLCMC: CKID-based encryption missing for BDF 0x%x",
                (uint64_t)component->bdf);
      failures++;
      goto device_cleanup;
    }

    if (capabilities.number_of_ckids < required_ckids)
    {
      val_print(ACS_PRINT_ERR,
                " RPLCMC: Device 0x%x reports insufficient CKIDs",
                (uint64_t)component->bdf);
      val_print(ACS_PRINT_ERR,
                " RPLCMC: Device CKIDs %x",
                (uint64_t)capabilities.number_of_ckids);
      val_print(ACS_PRINT_ERR,
                " RPLCMC: Minimum required CKIDs %x",
                (uint64_t)required_ckids);
      failures++;
      goto device_cleanup;
    }

device_cleanup:
    /* Close the SPDM session when it was opened. */
    if (session_active != 0u)
    {
      if (val_spdm_session_close(&ctx, session_id) != ACS_STATUS_PASS)
      {
        val_print(ACS_PRINT_WARN,
                  " RPLCMC: Session close failed for BDF 0x%x",
                  (uint64_t)component->bdf);
      }
    }
  }

  /* Report overall status based on evaluated devices and failures. */
  if (type3_devices == 0u)
  {
    val_print(ACS_PRINT_DEBUG,
              " RPLCMC: No Type-3 components discovered",
              0);
    val_set_status(pe_index, "SKIP", 03);
    return;
  }

  if (encryption_capable == 0u)
  {
    val_print(ACS_PRINT_DEBUG,
              " RPLCMC: No Type-3 devices advertise target encryption",
              0);
    val_set_status(pe_index, "SKIP", 04);
    return;
  }

  if (failures != 0u)
  {
    val_set_status(pe_index, "FAIL", failures);
  }
  else if (evaluated == 0u)
  {
    val_set_status(pe_index, "SKIP", 05);
  }
  else
  {
    val_set_status(pe_index, "PASS", evaluated);
  }
}
#else

static void
payload(void)
{
  uint32_t pe_index = val_pe_get_index_mpid(val_pe_get_mpid());

  val_print(ACS_PRINT_WARN,
            " SPDM support disabled - skipping RPLCMC",
            0);
  val_set_status(pe_index, "SKIP", 04);
}
#endif

uint32_t
cxl_rplcmc_type3_target_ckid_entry(uint32_t num_pe)
{
  num_pe = 1;
  uint32_t status;

  /* Initialize the test and invoke the payload on the primary PE. */
  status = val_initialize_test(TEST_NAME, TEST_DESC, num_pe, TEST_RULE);

  if (status != ACS_STATUS_SKIP)
    val_run_test_payload(num_pe, payload, 0);

  /* Consolidate and report the test status. */
  status = val_check_for_error(num_pe);

  val_report_status(0, "END");

  return status;
}
