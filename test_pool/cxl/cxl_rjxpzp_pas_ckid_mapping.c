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
#include "val/include/val_cxl_spec.h"
#include "val/include/val_pcie.h"
#include "val/include/val_pcie_spec.h"
#include "val/include/val_spdm.h"
#include "val/include/val_mec.h"
#include "val/include/val_memory.h"
#include "val/include/val_pe.h"
#include "val/include/val_el32.h"

#define TEST_NAME "cxl_rjxpzp_pas_ckid_mapping"
#define TEST_DESC "RME-CDA DVSEC enforces PAS/MECID->TEE/CKID mapping      "
#define TEST_RULE "RJXPZP"

#if ENABLE_SPDM

#include "industry_standard/cxl_tsp.h"
#include "library/spdm_return_status.h"
#include "library/cxl_tsp_requester_lib.h"

#define DECODER_SLOT 0u
#define TEST_DATA_PATTERN 0xA5A5A5A5u
#define RJXPZP_CKID_MAX 0x2000u

#define RMECDA_CTL1_TDISP_EN_MASK 0x1u
#define RMECDA_CTL1_LINK_STR_LOCK_MASK (1u << 1)
#define RMECDA_CTL1_FIRST_TEE_CKID_SHIFT 16u
#define RMECDA_CTL1_FIRST_TEE_CKID_MASK (0x1FFFu << RMECDA_CTL1_FIRST_TEE_CKID_SHIFT)

typedef enum {
  EXPECT_SUCCESS = 0,
  EXPECT_UE
} TEST_EXPECTATION;

typedef enum {
  CASE_NS_BASE = 0,
  CASE_RL_LOW,
  CASE_RL_HIGH,
  CASE_RL_OVERFLOW_UE,
  CASE_RL_MID,
  CASE_RT_BASE,
  CASE_RT_ALT,
  CASE_SC_BASE,
  CASE_NS_EDGE,
  CASE_RL_EDGE0,
  CASE_RL_EDGE1,
  CASE_RL_EDGE_OVERFLOW_UE,
  CASE_RT_EDGE
} TEST_CASE_KIND;

typedef struct {
  const char           *name;
  uint32_t              pas;
  TEST_CASE_KIND        kind;
  TEST_EXPECTATION    expectation;
} TEST_VECTOR;

static const TEST_VECTOR test_stimulus[] = {
  { "NS-01", NONSECURE_PAS, CASE_NS_BASE,             EXPECT_SUCCESS },
  { "RL-01", REALM_PAS,     CASE_RL_LOW,              EXPECT_SUCCESS },
  { "RL-02", REALM_PAS,     CASE_RL_HIGH,             EXPECT_SUCCESS },
  { "RL-03", REALM_PAS,     CASE_RL_OVERFLOW_UE,      EXPECT_UE      },
  { "RL-04", REALM_PAS,     CASE_RL_MID,              EXPECT_SUCCESS },
  { "RT-01", ROOT_PAS,      CASE_RT_BASE,             EXPECT_SUCCESS },
  { "RT-02", ROOT_PAS,      CASE_RT_ALT,              EXPECT_SUCCESS },
  { "SC-01", SECURE_PAS,    CASE_SC_BASE,             EXPECT_UE      },
  { "WR-NS", NONSECURE_PAS, CASE_NS_EDGE,             EXPECT_SUCCESS },
  { "WR-R1", REALM_PAS,     CASE_RL_EDGE0,            EXPECT_SUCCESS },
  { "WR-R2", REALM_PAS,     CASE_RL_EDGE1,            EXPECT_SUCCESS },
  { "WR-R3", REALM_PAS,     CASE_RL_EDGE_OVERFLOW_UE, EXPECT_UE      },
  { "WR-RT", ROOT_PAS,      CASE_RT_EDGE,             EXPECT_SUCCESS }
};

typedef struct {
  uint32_t host_index;
  uint32_t root_index;
  uint32_t endpoint_index;
  uint64_t window_base;
  uint64_t window_size;
  CXL_DECODER_STATE host_decoder;
  CXL_DECODER_STATE endpoint_decoder;
} CONTEXT;

static uint32_t
map_window_alias(uint64_t phys,
                 uint32_t pas,
                 volatile uint32_t **virt_out)
{
  /* Map a single page of device memory into the requested PAS. */
  uint64_t page_size = (uint64_t)val_memory_page_size();
  uint64_t va;
  uint32_t attr;

  if ((phys == 0u) || (virt_out == NULL))
    return ACS_STATUS_ERR;

  if (page_size == 0u)
    return ACS_STATUS_ERR;

  va = val_get_free_va(page_size);
  if (va == 0u)
    return ACS_STATUS_ERR;

  attr = LOWER_ATTRS(PGT_ENTRY_ACCESS |
                     SHAREABLE_ATTR(OUTER_SHAREABLE) |
                     GET_ATTR_INDEX(DEV_MEM_nGnRnE) |
                     PGT_ENTRY_AP_RW |
                     PAS_ATTR(pas));

  if (val_add_mmu_entry_el3(va, phys, attr))
    return ACS_STATUS_ERR;

  *virt_out = (volatile uint32_t *)va;
  return ACS_STATUS_PASS;
}

static uint32_t
read_from_root(uint64_t address, uint32_t *value)
{
  if (value == NULL)
    return ACS_STATUS_ERR;

  shared_data->num_access = 1;
  shared_data->shared_data_access[0].addr = address;
  shared_data->shared_data_access[0].access_type = READ_DATA;

  if (val_pe_access_mut_el3())
    return ACS_STATUS_ERR;

  *value = (uint32_t)shared_data->shared_data_access[0].data;
  return ACS_STATUS_PASS;
}

static uint32_t
write_from_root(uint64_t address, uint32_t value)
{
  shared_data->num_access = 1;
  shared_data->shared_data_access[0].addr = address;
  shared_data->shared_data_access[0].data = value;
  shared_data->shared_data_access[0].access_type = WRITE_DATA;

  if (val_pe_access_mut_el3())
    return ACS_STATUS_ERR;

  return ACS_STATUS_PASS;
}

static uint32_t
restore_decoders(CONTEXT *context)
{
  /* Restore both complete snapshots, including initially inactive decoders. */
  return val_cxl_restore_decoders(&context->host_decoder, &context->endpoint_decoder);
}

static uint32_t
prepare_decoders(uint32_t bdf, CONTEXT *context)
{
  if (context == NULL)
    return ACS_STATUS_ERR;

  return val_cxl_prepare_decoders(context->host_index, context->endpoint_index,
                                  DECODER_SLOT, bdf, &context->host_decoder,
                                  &context->endpoint_decoder);
}

static uint32_t
program_rmecda_ctl1(uint32_t root_bdf,
                    uint64_t cfg_va,
                    uint32_t rmecda_cap_base,
                    uint16_t first_tee_ckid)
{
  /* Update FIRST_TEE_CKID for the current test vector. */
  uint32_t ctl1_value;
  uint32_t ctl1_readback = 0u;

  if (val_pcie_enable_tdisp(root_bdf) ||
      read_from_root(cfg_va + rmecda_cap_base + RMECDA_CTL1_OFFSET,
                     &ctl1_value) != ACS_STATUS_PASS)
    return ACS_STATUS_ERR;

  ctl1_value |= RMECDA_CTL1_LINK_STR_LOCK_MASK;
  ctl1_value &= ~RMECDA_CTL1_FIRST_TEE_CKID_MASK;
  ctl1_value |= ((uint32_t)first_tee_ckid << RMECDA_CTL1_FIRST_TEE_CKID_SHIFT)
                & RMECDA_CTL1_FIRST_TEE_CKID_MASK;
  if (write_from_root(cfg_va + rmecda_cap_base + RMECDA_CTL1_OFFSET,
                      ctl1_value) != ACS_STATUS_PASS)
    return ACS_STATUS_ERR;

  if (read_from_root(cfg_va + rmecda_cap_base + RMECDA_CTL1_OFFSET,
                     &ctl1_readback) != ACS_STATUS_PASS)
    return ACS_STATUS_ERR;

  if ((ctl1_readback &
       (RMECDA_CTL1_TDISP_EN_MASK | RMECDA_CTL1_LINK_STR_LOCK_MASK)) !=
      (RMECDA_CTL1_TDISP_EN_MASK | RMECDA_CTL1_LINK_STR_LOCK_MASK))
  {
    val_print(ACS_PRINT_ERR,
              " RJXPZP: RMECDA_CTL1 lock/tdisp not set for RP 0x%x",
              root_bdf);
    return ACS_STATUS_FAIL;
  }

  if ((ctl1_readback & RMECDA_CTL1_FIRST_TEE_CKID_MASK) !=
      ((uint32_t)first_tee_ckid << RMECDA_CTL1_FIRST_TEE_CKID_SHIFT))
  {
    val_print(ACS_PRINT_ERR,
              " RJXPZP: FIRST_TEE_CKID readback mismatch for RP 0x%x",
              root_bdf);
    return ACS_STATUS_FAIL;
  }

  return ACS_STATUS_PASS;
}

static uint32_t
resolve_vector_from_caps(const TEST_VECTOR *vector,
                         uint32_t requested_ckids,
                         uint32_t mecid_max,
                         uint16_t *first_tee_ckid_out,
                         uint32_t *mecid_out,
                         uint32_t *skip_case)
{
  /* Resolve test scenario using runtime CKID count and MECID width limits. */
  uint32_t max_ckid;
  uint32_t first_tee_ckid;
  uint32_t realm_limit;
  uint32_t overflow_base;

  if ((vector == NULL) || (first_tee_ckid_out == NULL) || (mecid_out == NULL) ||
      (skip_case == NULL) ||
      (requested_ckids == 0u))
    return ACS_STATUS_ERR;

  *skip_case = 0u;
  max_ckid = requested_ckids - 1u;
  if (max_ckid > 0x1FFFu)
    max_ckid = 0x1FFFu;

  first_tee_ckid = (max_ckid >= 0x100u) ? 0x100u : max_ckid;
  *first_tee_ckid_out = (uint16_t)first_tee_ckid;
  *mecid_out = 0u;

  switch (vector->kind)
  {
  case CASE_NS_BASE:
    if (first_tee_ckid == 0u)
    {
      *skip_case = 1u;
      break;
    }
    *mecid_out = (mecid_max < 0xA0u) ? mecid_max : 0xA0u;
    if (*mecid_out >= first_tee_ckid)
      *mecid_out = first_tee_ckid - 1u;
    break;
  case CASE_RL_LOW:
    realm_limit = max_ckid - first_tee_ckid;
    *mecid_out = (realm_limit < 0x5u) ? realm_limit : 0x5u;
    if (*mecid_out > mecid_max)
      *mecid_out = mecid_max;
    break;
  case CASE_RL_HIGH:
    realm_limit = max_ckid - first_tee_ckid;
    *mecid_out = (mecid_max < realm_limit) ? mecid_max : realm_limit;
    break;
  case CASE_RL_OVERFLOW_UE:
  case CASE_RL_EDGE_OVERFLOW_UE:
    overflow_base = 0x2000u - first_tee_ckid;
    if (mecid_max < overflow_base)
    {
      *skip_case = 1u;
      break;
    }
    *mecid_out = overflow_base;
    break;
  case CASE_RL_MID:
    realm_limit = max_ckid - first_tee_ckid;
    *mecid_out = (realm_limit < 0x1234u) ? realm_limit : 0x1234u;
    if (*mecid_out > mecid_max)
      *mecid_out = mecid_max;
    break;
  case CASE_RT_BASE:
    *mecid_out = 0u;
    if (*mecid_out > mecid_max)
      *mecid_out = mecid_max;
    break;
  case CASE_RT_ALT:
    *mecid_out = (mecid_max < 0x555u) ? mecid_max : 0x555u;
    break;
  case CASE_SC_BASE:
    *mecid_out = 0u;
    break;
  case CASE_NS_EDGE:
    if (first_tee_ckid == 0u)
    {
      *skip_case = 1u;
      break;
    }
    *mecid_out = first_tee_ckid - 1u;
    if (*mecid_out > mecid_max)
      *mecid_out = mecid_max;
    break;
  case CASE_RL_EDGE0:
    *mecid_out = 0u;
    break;
  case CASE_RL_EDGE1:
    realm_limit = max_ckid - first_tee_ckid;
    *mecid_out = (realm_limit == 0u) ? 0u : 1u;
    if (*mecid_out > realm_limit)
      *mecid_out = realm_limit;
    if (*mecid_out > mecid_max)
      *mecid_out = mecid_max;
    break;
  case CASE_RT_EDGE:
    *mecid_out = mecid_max;
    break;
  default:
    return ACS_STATUS_ERR;
  }

  return ACS_STATUS_PASS;
}

static uint32_t
derive_ckid(uint32_t pas,
            uint32_t mecid,
            uint16_t first_tee_ckid,
            uint32_t *ckid_out,
            uint8_t *ue_out)
{
  /* Apply RJXPZP PAS/MECID to CKID/TEE mapping from the rule. */
  uint32_t ckid = 0u;
  uint8_t ue = 0u;

  if ((ckid_out == NULL) || (ue_out == NULL))
    return ACS_STATUS_ERR;

  switch (pas)
  {
  case NONSECURE_PAS:
    if (mecid >= first_tee_ckid)
    {
      ue = 1u;
      ckid = mecid;
    }
    else
    {
      ckid = mecid;
    }
    break;
  case REALM_PAS:
    ckid = (uint32_t)first_tee_ckid + mecid;
    if (ckid > 0x1FFFu)
      ue = 1u;
    break;
  case ROOT_PAS:
    ckid = first_tee_ckid;
    break;
  case SECURE_PAS:
    ue = 1u;
    break;
  default:
    ue = 1u;
    break;
  }

  *ckid_out = ckid;
  *ue_out = ue;
  return ACS_STATUS_PASS;
}

static uint32_t
set_target_ckid_random_key(val_spdm_context_t *context,
                             uint32_t session_id,
                             uint32_t ckid,
                             uint8_t ckid_type)
{
  cxl_tsp_set_target_ckid_random_key_req_t request;
  cxl_tsp_set_target_ckid_random_key_rsp_t response;
  size_t response_size = sizeof(response);
  libspdm_return_t status;

  /* Leave entropy validity flags clear as the target supplies its own entropy. */
  val_memory_set(&request, sizeof(request), 0);
  request.header.tsp_version = CXL_TSP_MESSAGE_VERSION;
  request.header.op_code = CXL_TSP_OPCODE_SET_TARGET_CKID_RANDOM_KEY;
  request.ckid = ckid;
  request.attributes = ckid_type;
  val_memory_set(&response, sizeof(response), 0);
  status = cxl_tsp_send_receive_data(context->spdm_context,
                                     &session_id,
                                     &request,
                                     sizeof(request),
                                     &response,
                                     &response_size);
  if (LIBSPDM_STATUS_IS_ERROR(status) || (response_size != sizeof(response)) ||
      (response.header.tsp_version != CXL_TSP_MESSAGE_VERSION) ||
      (response.header.op_code != CXL_TSP_OPCODE_SET_TARGET_CKID_RANDOM_KEY_RSP))
  {
    val_print(ACS_PRINT_ERR, " RJXPZP: SET_TARGET_CKID_RANDOM_KEY failed (0x%x)",
              (uint64_t)status);
    return ACS_STATUS_ERR;
  }

  return ACS_STATUS_PASS;
}

static uint32_t
clear_target_ckid_key(val_spdm_context_t *context,
                      uint32_t session_id,
                      uint32_t ckid)
{
  cxl_tsp_clear_target_ckid_key_req_t request;
  cxl_tsp_clear_target_ckid_key_rsp_t response;
  size_t response_size = sizeof(response);
  libspdm_return_t status;

  val_memory_set(&request, sizeof(request), 0);
  val_memory_set(&response, sizeof(response), 0);
  request.header.tsp_version = CXL_TSP_MESSAGE_VERSION;
  request.header.op_code = CXL_TSP_OPCODE_CLEAR_TARGET_CKID_KEY;
  request.ckid = ckid;

  status = cxl_tsp_send_receive_data(context->spdm_context,
                                     &session_id,
                                     &request,
                                     sizeof(request),
                                     &response,
                                     &response_size);
  if (LIBSPDM_STATUS_IS_ERROR(status) || (response_size != sizeof(response)) ||
      (response.header.tsp_version != CXL_TSP_MESSAGE_VERSION) ||
      (response.header.op_code != CXL_TSP_OPCODE_CLEAR_TARGET_CKID_KEY_RSP))
  {
    val_print(ACS_PRINT_ERR, " RJXPZP: CLEAR_TARGET_CKID_KEY failed (0x%x)",
              (uint64_t)status);
    return ACS_STATUS_ERR;
  }

  return ACS_STATUS_PASS;
}

/* Both CKIDs use TVM keys. Only the Realm MECID changes between reads.
 * This checks encryption isolation, rather than exact CKID or TEE values.
 */
static uint32_t
check_realm_mecid_isolation(val_spdm_context_t *context,
                            uint32_t session_id,
                            uint64_t address,
                            uint32_t mecid,
                            uint32_t alternate_mecid,
                            uint32_t alternate_ckid)
{
  uint32_t baseline;
  uint32_t pattern;
  uint32_t readback;
  uint32_t result = ACS_STATUS_PASS;

  /* Keep the original TVM key installed and ask the target for a second key. */
  if (set_target_ckid_random_key(context, session_id, alternate_ckid,
          CXL_TSP_SET_CKID_RANDOM_KEY_ATTRIBUTES_CKID_TYPE_TVM_CKID) != ACS_STATUS_PASS)
    return ACS_STATUS_FAIL;

  /* Save the word through the original Realm MECID before modifying it. */
  if (read_from_root(address, &baseline) != ACS_STATUS_PASS)
  {
    result = ACS_STATUS_FAIL;
    goto clear_key;
  }

  /* Write and verify the pattern using the original key. */
  pattern = baseline ^ TEST_DATA_PATTERN;
  if ((write_from_root(address, pattern) != ACS_STATUS_PASS) ||
      (read_from_root(address, &readback) != ACS_STATUS_PASS) ||
      (readback != pattern))
  {
    result = ACS_STATUS_FAIL;
    goto restore_memory;
  }

  /* Read without writing through the alternate MECID: its key must not
   * recover the original plaintext.
   */
  if (val_rlm_configure_mecid(alternate_mecid))
    result = ACS_STATUS_FAIL;
  else if (read_from_root(address, &readback) != ACS_STATUS_PASS)
    result = ACS_STATUS_FAIL;
  else if (readback == pattern)
  {
    val_print(ACS_PRINT_ERR, " RJXPZP: different Realm MECID recovered plaintext", 0);
    result = ACS_STATUS_FAIL;
  }

  /* Restore the original MECID before any further writes. Stop the caller's
   * test accesses if this fails, to avoid restoring data through the wrong key.
   */
  if (val_rlm_configure_mecid(mecid))
  {
    (void)clear_target_ckid_key(context, session_id, alternate_ckid);
    return ACS_STATUS_ERR;
  }

  /* The alternate read must leave the original plaintext recoverable. */
  if ((read_from_root(address, &readback) != ACS_STATUS_PASS) ||
      (readback != pattern))
    result = ACS_STATUS_FAIL;

restore_memory:
  if ((write_from_root(address, baseline) != ACS_STATUS_PASS) ||
      (read_from_root(address, &readback) != ACS_STATUS_PASS) ||
      (readback != baseline))
    result = ACS_STATUS_FAIL;

clear_key:
  if (clear_target_ckid_key(context, session_id, alternate_ckid) != ACS_STATUS_PASS)
    result = ACS_STATUS_FAIL;

  return result;
}

static uint32_t
exercise_root_port(const CXL_COMPONENT_TABLE *table,
                   uint32_t root_index)
{
  /* Drive RJXPZP test flow for a single root port with a downstream Type-3 device. */
  const CXL_COMPONENT_ENTRY *root_port;
  const CXL_COMPONENT_ENTRY *endpoint;
  CONTEXT context;
  uint32_t root_bdf;
  uint32_t rmecda_cap_base = 0u;
  uint32_t rmecda_ctl1_original = 0u;
  uint32_t status;
  uint32_t endpoint_index = CXL_COMPONENT_INVALID_INDEX;
  uint32_t host_index;
                 uint64_t host_comp_base;
  uint32_t failures = 0u;
  uint32_t executed = 0u;
  val_spdm_context_t ctx;
  uint32_t session_id = 0u;
  uint32_t session_active = 0u;
  uint32_t ide_active = 0u;
  uint32_t mec_enabled = 0u;
  uint32_t tsp_locked = 0u;
  PCIE_ENDPOINT_CFG endpoint_cfg;
  libcxltsp_device_capabilities_t capabilities;
  uint32_t requested_ckids;
  uint32_t mecid_width;
  uint32_t mecid_max;
  uint64_t mecid_max64;
  uint16_t feature_enable_mask;
  uint32_t active_ckid = RJXPZP_CKID_MAX;
  uint64_t cfg_addr;
  uint64_t cfg_va = 0u;
  uint64_t tg;
  uint64_t original_gpi = 0u;
  uint32_t gpt_modified = 0u;
  uint32_t attr;

  val_memory_set(&context, sizeof(context), 0);
  context.host_index = CXL_COMPONENT_INVALID_INDEX;
  context.root_index = root_index;
  context.endpoint_index = CXL_COMPONENT_INVALID_INDEX;

  if ((table == NULL) || (root_index >= table->num_entries))
    return ACS_STATUS_ERR;

  /* Skip non-root-port entries. */
  root_port = &table->component[root_index];
  if (root_port->role != CXL_COMPONENT_ROLE_ROOT_PORT)
    return ACS_STATUS_SKIP;

  root_bdf = root_port->bdf;
  if (root_bdf == 0u)
    return ACS_STATUS_ERR;

  /* Ensure the root port exposes the RME-CDA DVSEC. */
  if (val_pcie_find_cda_capability(root_bdf, &rmecda_cap_base) != PCIE_SUCCESS)
    return ACS_STATUS_SKIP;

  /* Find a downstream Type-3 endpoint for CXL.mem testing. */
  status = val_cxl_find_downstream_endpoint(root_index, &endpoint_index);
  if (status != ACS_STATUS_PASS)
    return ACS_STATUS_SKIP;

  endpoint = &table->component[endpoint_index];
  if (endpoint->device_type != CXL_DEVICE_TYPE_TYPE3)
    return ACS_STATUS_SKIP;

  if (val_pcie_save_endpoint_cfg(endpoint->bdf, &endpoint_cfg) != ACS_STATUS_PASS)
  {
    val_print(ACS_PRINT_WARN,
              " RJXPZP: Failed to snapshot EP cfg for cleanup (BDF 0x%x)",
              (uint64_t)endpoint->bdf);
    endpoint_cfg.valid = 0u;
  }

  host_index = root_port->host_bridge_index;
  if (host_index == CXL_COMPONENT_INVALID_INDEX)
    return ACS_STATUS_SKIP;

  if (host_index >= (uint32_t)val_cxl_get_info(CXL_INFO_NUM_DEVICES, 0))
    return ACS_STATUS_SKIP;

  /* Require HDM decoders on host and endpoint. */
  host_comp_base = val_cxl_get_info(CXL_INFO_COMPONENT_BASE, host_index);
  if ((host_comp_base == 0u) ||
      (val_cxl_find_capability(host_comp_base,
                               CXL_CAPID_HDM_DECODER,
                               NULL) != ACS_STATUS_PASS))
    return ACS_STATUS_SKIP;

  if ((endpoint->component_reg_base == 0u) ||
      (val_cxl_find_capability(endpoint->component_reg_base,
                               CXL_CAPID_HDM_DECODER,
                               NULL) != ACS_STATUS_PASS))
    return ACS_STATUS_SKIP;

  /* Select a CFMWS window for CXL.mem access. */
  status = val_cxl_select_cfmws_window(host_index,
                                       &context.window_base,
                                       &context.window_size);
  if (status != ACS_STATUS_PASS)
    return ACS_STATUS_SKIP;

  context.host_index = host_index;
  context.endpoint_index = endpoint_index;

  cfg_addr = val_pcie_get_bdf_config_addr(root_bdf);
  tg = val_get_min_tg();
  if ((cfg_addr == 0u) || (tg == 0u))
    return ACS_STATUS_SKIP;

  cfg_va = val_get_free_va(tg);
  if (cfg_va == 0u)
    return ACS_STATUS_ERR;

  attr = LOWER_ATTRS(PGT_ENTRY_ACCESS | SHAREABLE_ATTR(OUTER_SHAREABLE) |
                     GET_ATTR_INDEX(DEV_MEM_nGnRnE) | PGT_ENTRY_AP_RW |
                     PAS_ATTR(ROOT_PAS));
  if (val_add_mmu_entry_el3(cfg_va, cfg_addr, attr))
    return ACS_STATUS_ERR;

  /* Capture and program HDM decoder settings. */
  status = prepare_decoders(root_bdf, &context);
  if (status != ACS_STATUS_PASS)
  {
    if (restore_decoders(&context) != ACS_STATUS_PASS)
      return ACS_STATUS_FAIL;
    return status;
  }

  status = val_cxl_program_saved_decoder(&context.host_decoder,
                                         context.window_base,
                                         context.window_size);
  if (status != ACS_STATUS_PASS)
  {
    if (restore_decoders(&context) != ACS_STATUS_PASS)
      return ACS_STATUS_FAIL;
    return (status == ACS_STATUS_SKIP) ? ACS_STATUS_SKIP : ACS_STATUS_FAIL;
  }

  status = val_cxl_program_saved_decoder(&context.endpoint_decoder,
                                         context.window_base,
                                         context.window_size);
  if (status != ACS_STATUS_PASS)
  {
    if (restore_decoders(&context) != ACS_STATUS_PASS)
      return ACS_STATUS_FAIL;
    return (status == ACS_STATUS_SKIP) ? ACS_STATUS_SKIP : ACS_STATUS_FAIL;
  }

  /* Save RMECDA control state for later restoration. */
  if (read_from_root(cfg_va + rmecda_cap_base + RMECDA_CTL1_OFFSET,
                     &rmecda_ctl1_original) != ACS_STATUS_PASS)
  {
    (void)restore_decoders(&context);
    return ACS_STATUS_FAIL;
  }

  /* Establish the SPDM session used for CXL-TSP vendor-defined messaging. */
  status = val_spdm_session_open(endpoint->bdf, &ctx, &session_id);
  if (status == ACS_STATUS_SKIP)
  {
    if (restore_decoders(&context) != ACS_STATUS_PASS)
      return ACS_STATUS_FAIL;
    return ACS_STATUS_SKIP;
  }
  if (status != ACS_STATUS_PASS)
  {
    (void)restore_decoders(&context);
    return ACS_STATUS_FAIL;
  }
  session_active = 1u;

  /* Query the target's encryption capabilities. */
  status = val_spdm_send_cxl_tsp_get_version(&ctx, session_id);
  if (status != ACS_STATUS_PASS)
  {
    (void)restore_decoders(&context);
    (void)val_spdm_session_close(&ctx, session_id);
    return ACS_STATUS_FAIL;
  }

  val_memory_set(&capabilities, sizeof(capabilities), 0);
  status = val_spdm_send_cxl_tsp_get_capabilities(&ctx, session_id, &capabilities);
  if (status == ACS_STATUS_SKIP)
  {
    status = restore_decoders(&context);
    (void)val_spdm_session_close(&ctx, session_id);
    return (status == ACS_STATUS_PASS) ? ACS_STATUS_SKIP : ACS_STATUS_FAIL;
  }
  if (status != ACS_STATUS_PASS)
  {
    (void)restore_decoders(&context);
    (void)val_spdm_session_close(&ctx, session_id);
    return ACS_STATUS_FAIL;
  }

  if ((capabilities.memory_encryption_features_supported &
       CXL_TSP_MEMORY_ENCRYPTION_FEATURES_SUPPORT_ENCRYPTION) == 0u)
  {
    status = restore_decoders(&context);
    (void)val_spdm_session_close(&ctx, session_id);
    return (status == ACS_STATUS_PASS) ? ACS_STATUS_SKIP : ACS_STATUS_FAIL;
  }

  if ((capabilities.memory_encryption_features_supported &
       CXL_TSP_MEMORY_ENCRYPTION_FEATURES_SUPPORT_CKID_BASED_ENCRYPTION) == 0u)
  {
    status = restore_decoders(&context);
    (void)val_spdm_session_close(&ctx, session_id);
    return (status == ACS_STATUS_PASS) ? ACS_STATUS_SKIP : ACS_STATUS_FAIL;
  }

  requested_ckids = capabilities.number_of_ckids;
  if (requested_ckids == 0u)
  {
    status = restore_decoders(&context);
    (void)val_spdm_session_close(&ctx, session_id);
    return (status == ACS_STATUS_PASS) ? ACS_STATUS_SKIP : ACS_STATUS_FAIL;
  }

  mecid_width = (uint32_t)VAL_EXTRACT_BITS(val_pe_reg_read(MECIDR_EL2), 0, 3) + 1u;
  if (mecid_width >= 32u)
    mecid_max = 0xFFFFFFFFu;
  else
  {
    mecid_max64 = (1ull << mecid_width) - 1ull;
    mecid_max = (uint32_t)mecid_max64;
  }

  /* Enable CXL.mem only for the endpoint that passed TSP capability filtering. */
  status = val_cxl_enable_mem(endpoint->bdf);
  if (status != ACS_STATUS_PASS)
  {
    if (restore_decoders(&context) != ACS_STATUS_PASS)
      status = ACS_STATUS_FAIL;
    (void)val_spdm_session_close(&ctx, session_id);
    return status;
  }

  feature_enable_mask = (uint16_t)(CXL_TSP_MEMORY_ENCRYPTION_FEATURES_ENABLE_ENCRYPTION |
                                   CXL_TSP_MEMORY_ENCRYPTION_FEATURES_ENABLE_CKID_BASED_ENCRYPTION);

  /* Establish IDE before locking TSP and issuing protected CXL.mem traffic. */
  status = val_cxl_ide_establish_link(root_index, endpoint_index, &ctx, session_id);
  if (status != ACS_STATUS_PASS)
  {
    restore_decoders(&context);
    (void)val_spdm_session_close(&ctx, session_id);
    return (status == ACS_STATUS_SKIP) ? ACS_STATUS_SKIP : ACS_STATUS_FAIL;
  }
  ide_active = 1u;

  /* Configure and lock TSP with CKID-based encryption enabled. */
  status = val_cxl_tsp_configure_and_lock(root_index,
                                          endpoint_index,
                                          &ctx,
                                          session_id,
                                          requested_ckids,
                                          feature_enable_mask);
  if (status == ACS_STATUS_SKIP)
  {
    (void)val_cxl_ide_disable_link(root_index, endpoint_index, &ctx, session_id);
    status = restore_decoders(&context);
    (void)val_spdm_session_close(&ctx, session_id);
    return (status == ACS_STATUS_PASS) ? ACS_STATUS_SKIP : ACS_STATUS_FAIL;
  }
  if (status != ACS_STATUS_PASS)
  {
    (void)val_cxl_ide_disable_link(root_index, endpoint_index, &ctx, session_id);
    (void)restore_decoders(&context);
    (void)val_spdm_session_close(&ctx, session_id);
    return ACS_STATUS_FAIL;
  }

  tsp_locked = 1u;

  /* Enable MEC so MECID programming affects CXL.mem transactions. */
  if (val_is_mec_supported() == 0u)
  {
    (void)val_cxl_ide_disable_link(root_index, endpoint_index, &ctx, session_id);
    (void)val_spdm_session_close(&ctx, session_id);
    (void)val_cxl_unlock_tsp_best_effort(root_bdf, endpoint->bdf, &endpoint_cfg);
    if (restore_decoders(&context) != ACS_STATUS_PASS)
      return ACS_STATUS_FAIL;
    return ACS_STATUS_SKIP;
  }

  if (val_rlm_enable_mec())
  {
    (void)val_cxl_ide_disable_link(root_index, endpoint_index, &ctx, session_id);
    (void)val_spdm_session_close(&ctx, session_id);
    (void)val_cxl_unlock_tsp_best_effort(root_bdf, endpoint->bdf, &endpoint_cfg);
    (void)restore_decoders(&context);
    return ACS_STATUS_FAIL;
  }
  mec_enabled = 1u;

  if (val_get_gpt_entry_el3(context.window_base, &original_gpi) ||
      val_add_gpt_entry_el3(context.window_base, GPT_ANY))
  {
    val_print(ACS_PRINT_ERR, " RJXPZP: CXL.mem GPT setup failed", 0);
    failures++;
    goto cleanup;
  }
  gpt_modified = 1u;

  /* Iterate the PAS/MECID vectors and validate expected outcomes. */
  for (uint32_t index = 0; index < (sizeof(test_stimulus) / sizeof(test_stimulus[0])); ++index)
  {
    const TEST_VECTOR *vector = &test_stimulus[index];
    volatile uint32_t *mapped = NULL;
    uint16_t first_tee_ckid;
    uint32_t mecid;
    uint32_t ckid = 0u;
    uint8_t derived_ue = 0u;
    uint32_t baseline = 0u;
    uint32_t pattern = 0u;
    uint32_t readback;
    uint8_t ckid_type;
    uint32_t ckid_valid = 0u;
    uint32_t skip_case = 0u;

    status = resolve_vector_from_caps(vector,
                                      requested_ckids,
                                      mecid_max,
                                      &first_tee_ckid,
                                      &mecid,
                                      &skip_case);
    if (status != ACS_STATUS_PASS)
    {
      failures++;
      continue;
    }
    if (skip_case != 0u)
    {
      val_print(ACS_PRINT_DEBUG, " RJXPZP: skipping scenario due to width/CKID limits", 0);
      continue;
    }

    /* Derive the expected CKID mapping for the stimulus vector. */
    status = derive_ckid(vector->pas, mecid, first_tee_ckid, &ckid, &derived_ue);
    if (status != ACS_STATUS_PASS)
    {
      failures++;
      continue;
    }
    if ((vector->expectation == EXPECT_SUCCESS) && (derived_ue != 0u))
      val_print(ACS_PRINT_WARN,
                " RJXPZP: rule mismatch for %a",
                (uint64_t)vector->name);
    else if ((vector->expectation == EXPECT_UE) && (derived_ue == 0u))
      val_print(ACS_PRINT_WARN,
                " RJXPZP: rule mismatch for %a",
                (uint64_t)vector->name);

    /* Apply the requested FIRST_TEE_CKID for this vector. */
    if (program_rmecda_ctl1(root_bdf,
                            cfg_va,
                            rmecda_cap_base,
                            first_tee_ckid) != ACS_STATUS_PASS)
    {
      failures++;
      continue;
    }

    /* Map the window into the PAS specified by the test vector. */
    if (map_window_alias(context.window_base,
                         vector->pas,
                         &mapped) != ACS_STATUS_PASS)
    {
      failures++;
      continue;
    }

    /* Program MECID for the current access context. */
    if (val_rlm_configure_mecid(mecid))
    {
      failures++;
      continue;
    }

    ckid_valid = ((ckid <= 0x1FFFu) && (ckid < requested_ckids)) ? 1u : 0u;

    if ((vector->expectation == EXPECT_SUCCESS) && (ckid_valid == 0u))
    {
      failures++;
      continue;
    }

    /* Install the expected OSCKID or TVMCKID key for this PAS. */
    if (vector->expectation == EXPECT_SUCCESS)
    {
      if ((active_ckid != RJXPZP_CKID_MAX) &&
          (clear_target_ckid_key(&ctx, session_id, active_ckid) != ACS_STATUS_PASS))
      {
        failures++;
        break;
      }
      active_ckid = RJXPZP_CKID_MAX;
      ckid_type = (vector->pas == NONSECURE_PAS) ?
          CXL_TSP_SET_CKID_RANDOM_KEY_ATTRIBUTES_CKID_TYPE_OS_CKID :
          CXL_TSP_SET_CKID_RANDOM_KEY_ATTRIBUTES_CKID_TYPE_TVM_CKID;
      if (set_target_ckid_random_key(&ctx, session_id, ckid, ckid_type) != ACS_STATUS_PASS)
      {
        failures++;
        break;
      }
      active_ckid = ckid;
    }

    executed++;

    /* Build a pattern to write to the device memory range. */
    if (vector->expectation == EXPECT_SUCCESS)
    {
      /* Read through the same EL3 PAS alias and MECID as the test access. */
      shared_data->exception_expected = CLEAR;
      if (read_from_root((uint64_t)mapped, &baseline) != ACS_STATUS_PASS)
      {
        failures++;
        continue;
      }
      pattern = baseline ^ TEST_DATA_PATTERN;
      if ((pattern == baseline) || (pattern == 0xFFFFFFFFu))
        pattern ^= 0x1u;
    }
    else
    {
      pattern = TEST_DATA_PATTERN ^ mecid;
      if (pattern == 0u)
        pattern = TEST_DATA_PATTERN;
    }

    if (vector->expectation == EXPECT_UE)
    {
      /* Rejected writes complete without an in-band error. Probe separately so
       * a write fault cannot be mistaken for the expected read abort.
       */
      shared_data->exception_expected = CLEAR;
      if (write_from_root((uint64_t)mapped, pattern) != ACS_STATUS_PASS)
      {
        val_print(ACS_PRINT_ERR, " RJXPZP: rejected write did not complete for %a",
                  (uint64_t)vector->name);
        failures++;
        continue;
      }

      /* SBSA CXL_08/CXL_09: consuming the rejected read's poison raises SEA.
       * The EL3 handler validates the syndrome, load instruction and address.
       * No particular Root Port AER status is required for this rejection.
       */
      shared_data->access_mut = CLEAR;
      shared_data->exception_generated = CLEAR;
      shared_data->exception_expected = SET;
      shared_data->esr_value = SEA_ESR_READ;
      shared_data->num_access = 1;
      shared_data->shared_data_access[0].addr = (uint64_t)mapped;
      shared_data->shared_data_access[0].access_type = READ_DATA;

      status = val_pe_access_mut_el3();
      shared_data->exception_expected = CLEAR;
      shared_data->esr_value = 0u;
      if ((status != ACS_STATUS_PASS) || (shared_data->exception_generated != SET))
      {
        val_print(ACS_PRINT_ERR, " RJXPZP: expected external read abort not observed for %a",
                  (uint64_t)vector->name);
        failures++;
      }
      shared_data->exception_generated = CLEAR;
      continue;
    }

    /* Generate a write followed by a read to provoke the mapping logic. */
    shared_data->exception_expected = CLEAR;
    shared_data->num_access = 2;
    shared_data->shared_data_access[0].addr = (uint64_t)mapped;
    shared_data->shared_data_access[0].data = pattern;
    shared_data->shared_data_access[0].access_type = WRITE_DATA;
    shared_data->shared_data_access[1].addr = (uint64_t)mapped;
    shared_data->shared_data_access[1].access_type = READ_DATA;

    if (val_pe_access_mut_el3())
    {
      failures++;
      continue;
    }

    readback = (uint32_t)shared_data->shared_data_access[1].data;
    /* Validate the observed behavior against expectation. */
    if (vector->expectation == EXPECT_SUCCESS)
    {
      if (readback != pattern)
      {
        val_print(ACS_PRINT_ERR, " RJXPZP: %a failed", (uint64_t)vector->name);
        val_print(ACS_PRINT_ERR, " RJXPZP: Read 0x%x", (uint64_t)readback);
        failures++;
      }

      else if (vector->pas == REALM_PAS)
      {
        uint32_t alternate_mecid = (mecid == 0u) ? 1u : 0u;
        uint32_t alternate_ckid = first_tee_ckid + alternate_mecid;

        if ((alternate_mecid <= mecid_max) && (alternate_ckid < requested_ckids) &&
            (alternate_ckid < RJXPZP_CKID_MAX))
        {
          status = check_realm_mecid_isolation(&ctx, session_id,
                                               (uint64_t)mapped, mecid,
                                               alternate_mecid, alternate_ckid);
          if (status != ACS_STATUS_PASS)
          {
            val_print(ACS_PRINT_ERR, " RJXPZP: Realm MECID isolation failed for %a",
                      (uint64_t)vector->name);
            failures++;
            if (status == ACS_STATUS_ERR)
              break;
          }
        }
        else
          val_print(ACS_PRINT_DEBUG, " RJXPZP: insufficient CKIDs for isolation probe", 0);
      }

      /* Restore the original value for successful accesses. */
      shared_data->num_access = 1;
      shared_data->shared_data_access[0].addr = (uint64_t)mapped;
      shared_data->shared_data_access[0].data = baseline;
      shared_data->shared_data_access[0].access_type = WRITE_DATA;
      status = val_pe_access_mut_el3();

      if (status == ACS_STATUS_PASS)
        status = read_from_root((uint64_t)mapped, &readback);

      if ((status != ACS_STATUS_PASS) || (readback != baseline))
      {
        val_print(ACS_PRINT_ERR, " RJXPZP: baseline restore failed for %a",
                  (uint64_t)vector->name);
        failures++;
      }
    }

  }
cleanup:
  if ((gpt_modified != 0u) &&
      val_add_gpt_entry_el3(context.window_base, original_gpi))
  {
    val_print(ACS_PRINT_ERR, " RJXPZP: CXL.mem GPT restore failed", 0);
    failures++;
  }

  /* Restore other fields without changing TDISP outside the common helpers. */
  uint32_t ctl1_current;
  if (read_from_root(cfg_va + rmecda_cap_base + RMECDA_CTL1_OFFSET,
                     &ctl1_current) != ACS_STATUS_PASS ||
      write_from_root(cfg_va + rmecda_cap_base + RMECDA_CTL1_OFFSET,
                       (rmecda_ctl1_original & ~RMECDA_CTL1_TDISP_EN_MASK) |
                       (ctl1_current & RMECDA_CTL1_TDISP_EN_MASK)) != ACS_STATUS_PASS)
  {
    val_print(ACS_PRINT_ERR, " RJXPZP: RMECDA_CTL1 restore failed", 0);
    failures++;
  }

  status = (rmecda_ctl1_original & RMECDA_CTL1_TDISP_EN_MASK) ?
           val_pcie_enable_tdisp(root_bdf) : val_pcie_disable_tdisp(root_bdf);
  if (status)
  {
    val_print(ACS_PRINT_ERR, " RJXPZP: TDISP restore failed", 0);
    failures++;
  }

  if (mec_enabled != 0u)
  {
    (void)val_rlm_configure_mecid(0u);
    (void)val_rlm_disable_mec();
  }

  if ((ide_active != 0u) &&
      (val_cxl_ide_disable_link(root_index, endpoint_index, &ctx, session_id) !=
       ACS_STATUS_PASS))
    failures++;

  if (session_active != 0u)
    (void)val_spdm_session_close(&ctx, session_id);

  if (tsp_locked != 0u)
    (void)val_cxl_unlock_tsp_best_effort(root_bdf, endpoint->bdf, &endpoint_cfg);

  if (restore_decoders(&context) != ACS_STATUS_PASS)
    failures++;

  if (failures != 0u)
    return ACS_STATUS_FAIL;
  if (executed == 0u)
    return ACS_STATUS_SKIP;
  return ACS_STATUS_PASS;
}

static void
payload(void)
{
  /* Scan CXL component table and validate each eligible root port. */
  uint32_t pe_index = val_pe_get_index_mpid(val_pe_get_mpid());
  CXL_COMPONENT_TABLE *table = val_cxl_component_table_ptr();
  uint32_t tested = 0u;
  uint32_t failures = 0u;

  if ((table == NULL) || (table->num_entries == 0u))
  {
    val_print(ACS_PRINT_DEBUG, " RJXPZP: No CXL components discovered", 0);
    val_set_status(pe_index, "SKIP", 01);
    return;
  }

  /* Walk each component, exercising only eligible root ports. */
  for (uint32_t idx = 0; idx < table->num_entries; ++idx)
  {
    /* Filter to CXL root ports before invoking the test flow. */
    if (table->component[idx].role != CXL_COMPONENT_ROLE_ROOT_PORT)
      continue;

    /* Run the RJXPZP stimulus for this root port. */
    uint32_t result = exercise_root_port(table, idx);

    /* Skip ports that are not applicable to this rule. */
    if (result == ACS_STATUS_SKIP)
    {
      continue;
    }

    /* Track tested ports and any failures. */
    tested++;
    if (result != ACS_STATUS_PASS)
      failures++;
  }

  /* Report consolidated status for the test. */
  if (tested == 0u)
  {
    val_set_status(pe_index, "SKIP", 02);
  }
  else if (failures != 0u)
  {
    val_set_status(pe_index, "FAIL", failures);
  }
  else
  {
    val_set_status(pe_index, "PASS", tested);
  }
}
#else

static void
payload(void)
{
  uint32_t pe_index = val_pe_get_index_mpid(val_pe_get_mpid());

  val_print(ACS_PRINT_WARN,
            " SPDM support disabled - skipping RJXPZP",
            0);
  val_set_status(pe_index, "SKIP", 04);
}
#endif
uint32_t
cxl_rjxpzp_pas_ckid_mapping_entry(uint32_t num_pe)
{
  num_pe = 1;
  uint32_t status;

  status = val_initialize_test(TEST_NAME, TEST_DESC, num_pe, TEST_RULE);

  if (status != ACS_STATUS_SKIP)
    val_run_test_payload(num_pe, payload, 0);

  status = val_check_for_error(num_pe);

  val_report_status(0, "END");

  return status;
}
