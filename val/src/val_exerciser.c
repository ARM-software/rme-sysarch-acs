/** @file
 * Copyright (c) 2022-2026, Arm Limited or its affiliates. All rights reserved.
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

#include "include/val.h"
#include "include/val_exerciser.h"
#include "include/val_cxl.h"
#include "include/val_el32.h"
#include "include/val_pcie.h"
#include "include/val_smmu.h"

#define VAL_EXERCISER_MAX_CAPTURE_RECORDS 32u

EXERCISER_INFO_TABLE g_exerciser_info_table;
CXL_EXERCISER_INFO_TABLE g_cxl_exerciser_info_table;

extern uint32_t pcie_bdf_table_list_flag;

/**
  @brief   This API popultaes information from all the PCIe stimulus generation IP available
           in the system into exerciser_info_table structure
  @param   exerciser_info_table - Table pointer to be filled by this API
  @return  exerciser_info_table - Contains info to communicate with stimulus generation hardware
**/
void val_exerciser_create_info_table(void)
{
  uint32_t Bdf;
  uint32_t reg_value;
  uint32_t num_bdf;
  uint32_t cxl_idx;
  pcie_device_bdf_table *bdf_table;
  CXL_COMPONENT_TABLE *cxl_table;

  g_exerciser_info_table.num_exerciser = 0;
  g_cxl_exerciser_info_table.num_exerciser = 0;

  bdf_table = val_pcie_bdf_table_ptr();
  num_bdf = (bdf_table != NULL) ? bdf_table->num_entries : 0;
  /* CXL discovery must also run when the ordinary PCIe table is empty. */
  if (num_bdf == 0)
      val_print(ACS_PRINT_DEBUG, " No BDFs discovered            ", 0);

  while (num_bdf-- != 0)
  {

      Bdf = bdf_table->device[num_bdf].bdf;
      /* Probe pcie device Function with this bdf */
      if (val_pcie_read_cfg(Bdf, TYPE01_VIDR, &reg_value) == PCIE_NO_MAPPING)
      {
          /* Skip this BDF so other PCIe and CXL devices can still be discovered. */
          val_print(ACS_PRINT_ERR, " BDF 0x%x mapping issue", Bdf);
          continue;
      }

      /* Store the Function's BDF if there was a valid response */
      if (pal_is_bdf_exerciser(Bdf))
      {
          g_exerciser_info_table.e_info[g_exerciser_info_table.num_exerciser].bdf = Bdf;
          g_exerciser_info_table.e_info[g_exerciser_info_table.num_exerciser++].initialized = 0;
          val_print(ACS_PRINT_DEBUG, " exerciser Bdf %x", Bdf);
      }
  }

  /* Populate the CXL exerciser table based on discovered CXL endpoints. */
  cxl_table = val_cxl_component_table_ptr();
  if ((cxl_table != NULL) && (cxl_table->num_entries != 0u))
  {
      for (cxl_idx = 0u; cxl_idx < cxl_table->num_entries; ++cxl_idx)
      {
          uint32_t cxl_bdf = cxl_table->component[cxl_idx].bdf;

          if (cxl_table->component[cxl_idx].role != CXL_COMPONENT_ROLE_ENDPOINT)
              continue;

          if (!pal_is_bdf_exerciser(cxl_bdf))
              continue;

          if (g_cxl_exerciser_info_table.num_exerciser >= MAX_EXERCISER_CARDS)
              break;

          g_cxl_exerciser_info_table
              .e_info[g_cxl_exerciser_info_table.num_exerciser].bdf = cxl_bdf;
          g_cxl_exerciser_info_table
              .e_info[g_cxl_exerciser_info_table.num_exerciser++].initialized = 0;
          val_print(ACS_PRINT_DEBUG, " cxl exerciser Bdf %x", cxl_bdf);
      }
  }

  val_print(ACS_PRINT_ALWAYS, "\n PCIE_INFO: Number of exerciser cards : %4d",
                                                             g_exerciser_info_table.num_exerciser);
  val_print(ACS_PRINT_ALWAYS, "\n CXL_INFO: Number of CXL exerciser cards : %4d",
                                                         g_cxl_exerciser_info_table.num_exerciser);
  if (g_cxl_exerciser_info_table.num_exerciser != 0u)
  {
      for (cxl_idx = 0u; cxl_idx < g_cxl_exerciser_info_table.num_exerciser; ++cxl_idx)
      {
          val_print(ACS_PRINT_INFO, " CXL exerciser BDF 0x%x",
                    g_cxl_exerciser_info_table.e_info[cxl_idx].bdf);
      }
  }
  return;
}

uint32_t val_get_exerciser_err_info(EXERCISER_ERROR_CODE type)
{
    switch (type) {
    case CORR_RCVR_ERR:
         return CORR_RCVR_ERR_OFFSET;
    case CORR_BAD_TLP:
         return CORR_BAD_TLP_OFFSET;
    case CORR_BAD_DLLP:
         return CORR_BAD_DLLP_OFFSET;
    case CORR_RPL_NUM_ROLL:
         return CORR_RPL_NUM_ROLL_OFFSET;
    case CORR_RPL_TMR_TIMEOUT:
         return CORR_RPL_TMR_TIMEOUT_OFFSET;
    case CORR_ADV_NF_ERR:
         return CORR_ADV_NF_ERR_OFFSET;
    case CORR_INT_ERR:
         return CORR_INT_ERR_OFFSET;
    case CORR_HDR_LOG_OVRFL:
         return CORR_HDR_LOG_OVRFL_OFFSET;
    case UNCORR_DL_ERROR:
         return UNCORR_DL_ERROR_OFFSET;
    case UNCORR_SD_ERROR:
         return UNCORR_SD_ERROR_OFFSET;
    case UNCORR_PTLP_REC:
         return UNCORR_PTLP_REC_OFFSET;
    case UNCORR_FL_CTRL_ERR:
         return UNCORR_FL_CTRL_ERR_OFFSET;
    case UNCORR_CMPT_TO:
         return UNCORR_CMPT_TO_OFFSET;
    case UNCORR_AMPT_ABORT:
         return UNCORR_AMPT_ABORT_OFFSET;
    case UNCORR_UNEXP_CMPT:
         return UNCORR_UNEXP_CMPT_OFFSET;
    case UNCORR_RCVR_ERR:
         return UNCORR_RCVR_ERR_OFFSET;
    case UNCORR_MAL_TLP:
         return UNCORR_MAL_TLP_OFFSET;
    case UNCORR_ECRC_ERR:
         return UNCORR_ECRC_ERR_OFFSET;
    case UNCORR_UR:
         return UNCORR_UR_OFFSET;
    case UNCORR_ACS_VIOL:
         return UNCORR_ACS_VIOL_OFFSET;
    case UNCORR_INT_ERR:
         return UNCORR_INT_ERR_OFFSET;
    case UNCORR_MC_BLK_TLP:
         return UNCORR_MC_BLK_TLP_OFFSET;
    case UNCORR_ATOP_EGR_BLK:
         return UNCORR_ATOP_EGR_BLK_OFFSET;
    case UNCORR_TLP_PFX_EGR_BLK:
         return UNCORR_TLP_PFX_EGR_BLK_OFFSET;
    case UNCORR_PTLP_EGR_BLK:
         return UNCORR_PTLP_EGR_BLK_OFFSET;
    default:
         val_print(ACS_PRINT_ERR, " Invalid error offset ", 0);
         return 0;
    }
}


/**
  @brief   This API returns the requested information about the PCIe stimulus hardware
  @param   type         - Information type required from the stimulus hadrware
  @return  value        - Information value for input type
**/
uint32_t val_exerciser_get_info(EXERCISER_INFO_TYPE type)
{
    switch (type) {
    case EXERCISER_NUM_CARDS:
         return g_exerciser_info_table.num_exerciser;
    default:
         return 0;
    }
}

uint32_t val_cxl_exerciser_get_info(CXL_EXERCISER_INFO_TYPE type)
{
    switch (type) {
    case CXL_EXERCISER_NUM_CARDS:
        return g_cxl_exerciser_info_table.num_exerciser;
    default:
        return 0;
    }
}

/**
  @brief   This API writes the configuration parameters of the PCIe stimulus generation hardware
  @param   type         - Parameter type that needs to be set in the stimulus hadrware
  @param   value1       - Parameter 1 that needs to be set
  @param   value2       - Parameter 2 that needs to be set
  @param   instance     - Stimulus hardware instance number
  @return  status       - SUCCESS if the input parameter type is successfully written
**/
uint32_t val_exerciser_set_param(EXERCISER_PARAM_TYPE type, uint64_t value1, uint64_t value2,
                                 uint32_t instance)
{
    return pal_exerciser_set_param(type, value1, value2,
                                   g_exerciser_info_table.e_info[instance].bdf);
}

uint32_t
val_exerciser_set_param_by_bdf(EXERCISER_PARAM_TYPE type, uint64_t value1, uint64_t value2,
                               uint32_t bdf)
{
    return pal_exerciser_set_param(type, value1, value2, bdf);
}

uint32_t val_exerciser_get_bdf(uint32_t instance)
{
    return g_exerciser_info_table.e_info[instance].bdf;
}

uint32_t val_cxl_exerciser_get_bdf(uint32_t instance)
{
    return g_cxl_exerciser_info_table.e_info[instance].bdf;
}

uint32_t val_cxl_exerciser_get_instance_by_bdf(uint32_t bdf, uint32_t *instance)
{
    uint32_t idx;

    if (instance == NULL)
        return 1;

    for (idx = 0u; idx < g_cxl_exerciser_info_table.num_exerciser; ++idx)
    {
        if (g_cxl_exerciser_info_table.e_info[idx].bdf == bdf)
        {
            *instance = idx;
            return 0;
        }
    }

    return 1;
}

/**
  @brief   This API reads the configuration parameters of the PCIe stimulus generation hardware
  @param   type         - Parameter type that needs to be read from the stimulus hadrware
  @param   value1       - Parameter 1 that is read from hardware
  @param   value2       - Parameter 2 that is read from hardware
  @param   instance     - Stimulus hardware instance number
  @return  status       - SUCCESS if the requested parameter type is successfully read
**/
uint32_t val_exerciser_get_param(EXERCISER_PARAM_TYPE type, uint64_t *value1, uint64_t *value2,
                                 uint32_t instance)
{
    return pal_exerciser_get_param(type, value1, value2,
                                   g_exerciser_info_table.e_info[instance].bdf);

}

uint32_t
val_exerciser_get_param_by_bdf(EXERCISER_PARAM_TYPE type, uint64_t *value1, uint64_t *value2,
                               uint32_t bdf)
{
    return pal_exerciser_get_param(type, value1, value2, bdf);
}

/**
  @brief   This API sets the state of the PCIe stimulus generation hardware
  @param   state        - State that needs to be set for the stimulus hadrware
  @param   value        - Additional information associated with the state
  @param   instance     - Stimulus hardware instance number
  @return  status       - SUCCESS if the input state is successfully written to hardware
**/
uint32_t val_exerciser_set_state(EXERCISER_STATE state, uint64_t *value, uint32_t instance)
{
    return pal_exerciser_set_state(state, value, g_exerciser_info_table.e_info[instance].bdf);
}

/**
  @brief   This API obtains the state of the PCIe stimulus generation hardware
  @param   state        - State that is read from the stimulus hadrware
  @param   instance     - Stimulus hardware instance number
  @return  status       - SUCCESS if the state is successfully read from hardware
**/
uint32_t val_exerciser_get_state(EXERCISER_STATE *state, uint32_t instance)
{
    return pal_exerciser_get_state(state, g_exerciser_info_table.e_info[instance].bdf);
}

/**
  @brief   This API obtains initializes
  @param   instance     - Stimulus hardware instance number
  @return  status       - SUCCESS if the state is successfully read from hardware
**/
uint32_t val_exerciser_init(uint32_t instance)
{
  uint32_t Bdf;
  uint64_t Ecam;
  uint64_t cfg_addr;
  EXERCISER_STATE state;

  if (!g_exerciser_info_table.e_info[instance].initialized)
  {
      Bdf = g_exerciser_info_table.e_info[instance].bdf;
      if (pal_exerciser_get_state(&state, Bdf) || (state != EXERCISER_ON)) {
          val_print(ACS_PRINT_ERR, " Exerciser Bdf %lx not ready", Bdf);
          return 1;
      }

      // setting command register for Memory Space Enable and Bus Master Enable
      Ecam = val_pcie_get_ecam_base(Bdf);

      /* There are 8 functions / device, 32 devices / Bus and each has a 4KB config space */
      cfg_addr = (PCIE_EXTRACT_BDF_BUS(Bdf) * PCIE_MAX_DEV * PCIE_MAX_FUNC * 4096) +
                 (PCIE_EXTRACT_BDF_DEV(Bdf) * PCIE_MAX_FUNC * 4096) +
                 (PCIE_EXTRACT_BDF_FUNC(Bdf) * 4096);

      pal_mmio_write((Ecam + cfg_addr + COMMAND_REG_OFFSET),
                  (pal_mmio_read((Ecam + cfg_addr) + COMMAND_REG_OFFSET) | BUS_MEM_EN_MASK));

      g_exerciser_info_table.e_info[instance].initialized = 1;
  } else
          val_print(ACS_PRINT_INFO, " Already initialized %d", instance);
  return 0;
}

uint32_t
val_exerciser_init_by_bdf(uint32_t bdf)
{
    EXERCISER_STATE state;

    if (pal_exerciser_get_state(&state, bdf) || (state != EXERCISER_ON))
        return 1;

    return 0;
}
/**
  @brief   This API performs the input operation using the PCIe stimulus generation hardware
  @param   ops          - Operation that needs to be performed with the stimulus hadrware
  @param   value        - Additional information to perform the operation
  @param   instance     - Stimulus hardware instance number
  @return  status       - SUCCESS if the operation is successfully performed using the hardware
**/
uint32_t val_exerciser_ops(EXERCISER_OPS ops, uint64_t param, uint32_t instance)
{
    return pal_exerciser_ops(ops, param, g_exerciser_info_table.e_info[instance].bdf);
}

uint32_t
val_exerciser_ops_by_bdf(EXERCISER_OPS ops, uint64_t param, uint32_t bdf)
{
    return pal_exerciser_ops(ops, param, bdf);
}

/** Start a new exerciser transaction-monitor capture. */
uint32_t
val_exerciser_start_transaction_monitor_by_bdf(uint32_t bdf)
{
    return (val_exerciser_ops_by_bdf(START_TXN_MONITOR, 0u, bdf) == 0u) ?
           ACS_STATUS_PASS : ACS_STATUS_SKIP;
}

/** Stop an exerciser transaction-monitor capture. */
uint32_t
val_exerciser_stop_transaction_monitor_by_bdf(uint32_t bdf)
{
    return (val_exerciser_ops_by_bdf(STOP_TXN_MONITOR, 0u, bdf) == 0u) ?
           ACS_STATUS_PASS : ACS_STATUS_ERR;
}

/** Read and remove one complete entry from the exerciser transaction trace. */
uint32_t
val_exerciser_get_transaction_record_by_bdf(
                                uint32_t bdf,
                                VAL_EXERCISER_TRANSACTION_RECORD *record)
{
    uint64_t attributes;
    uint64_t address;

    if (record == NULL)
        return ACS_STATUS_ERR;

    attributes = 0u;
    address = 0u;
    if (val_exerciser_get_param_by_bdf(TRANSACTION_RECORD,
                                       &attributes,
                                       &address,
                                       bdf) != 0u)
        return ACS_STATUS_SKIP;

    record->attributes = (uint32_t)attributes;
    record->address = address;
    return ACS_STATUS_PASS;
}

/** Drain a transaction capture and report a matching address and attributes. */
uint32_t
val_exerciser_find_transaction_by_bdf(uint32_t bdf,
                                      uint64_t address,
                                      uint32_t required_attributes,
                                      uint32_t *observed)
{
    VAL_EXERCISER_TRANSACTION_RECORD record;

    if (observed == NULL)
        return ACS_STATUS_ERR;

    *observed = 0u;
    for (uint32_t index = 0u;
         index < VAL_EXERCISER_MAX_CAPTURE_RECORDS;
         ++index)
    {
        if (val_exerciser_get_transaction_record_by_bdf(bdf, &record)
            != ACS_STATUS_PASS)
            break;

        val_print(ACS_PRINT_DEBUG,
                  " Exerciser trace attributes 0x%x",
                  (uint64_t)record.attributes);
        val_print(ACS_PRINT_DEBUG,
                  " Exerciser trace address 0x%llx",
                  record.address);

        if ((record.address == address) &&
            ((record.attributes & required_attributes) == required_attributes))
            *observed = 1u;
    }

    return ACS_STATUS_PASS;
}

/**
  @brief Issue an ATS translation request and return the complete response.

  @param bdf      Exerciser BDF
  @param iova     Address to translate
  @param length   Requested access length
  @param request_attributes  ATS T/XT request attributes
  @param result   Translation completion information

  @return ACS_STATUS_PASS when the request was issued and its response read,
          or ACS_STATUS_ERR when the exerciser interface could not be used.
**/
uint32_t
val_exerciser_ats_translate_by_bdf(uint32_t bdf,
                                   uint64_t iova,
                                   uint32_t length,
                                   uint32_t request_attributes,
                                   VAL_ATS_TRANSLATION_RESULT *result)
{
    uint64_t response_attributes;
    uint32_t request_status;

    if ((iova == 0u) || (length == 0u) || (result == NULL) ||
        ((request_attributes & ~VAL_ATS_REQUEST_ATTR_MASK) != 0u))
        return ACS_STATUS_ERR;

    val_memory_set(result, sizeof(*result), 0);

    if (val_exerciser_set_param_by_bdf(EXERCISER_ATS_REQUEST_ATTRIBUTES,
                                       request_attributes,
                                       0u,
                                       bdf) != 0u)
        return ACS_STATUS_ERR;

    if (val_exerciser_set_param_by_bdf(DMA_ATTRIBUTES,
                                       iova,
                                       length,
                                       bdf) != 0u)
        return ACS_STATUS_ERR;

    (void)val_exerciser_ops_by_bdf(ATS_INV_CACHE, 0u, bdf);

    request_status = val_exerciser_ops_by_bdf(ATS_TXN_REQ, iova, bdf);

    response_attributes = 0u;
    if (val_exerciser_get_param_by_bdf(ATS_RES_ATTRIBUTES,
                                       &result->translated_pa,
                                       &response_attributes,
                                       bdf) != 0u)
        return ACS_STATUS_ERR;

    result->response_attributes = (uint32_t)response_attributes;
    result->completion_success = (request_status == 0u) ? 1u : 0u;
    result->te =
        ((result->response_attributes & VAL_ATS_TE_MASK) != 0u) ? 1u : 0u;

    return ACS_STATUS_PASS;
}

/**
  @brief Perform DMA using a translation cached by an earlier ATS request.

  The DMA address remains the original IOVA. The exerciser obtains the output
  address and permissions from its ATC and emits a PCIe Translated request.

  @param bdf        Exerciser BDF
  @param iova       Original address used for the ATS request
  @param length     DMA transfer length
  @param direction  Exerciser DMA direction

  @return ACS_STATUS_PASS when DMA completes, ACS_STATUS_FAIL when the
          transaction is rejected, or ACS_STATUS_ERR for invalid input/setup.
**/
uint32_t
val_exerciser_dma_with_atc_by_bdf(uint32_t bdf,
                                  uint64_t iova,
                                  uint32_t length,
                                  EXERCISER_DMA_ATTR direction)
{
    uint32_t dma_status;

    if ((iova == 0u) || (length == 0u))
        return ACS_STATUS_ERR;

    if ((val_exerciser_set_param_by_bdf(DMA_ATTRIBUTES,
                                        iova,
                                        length,
                                        bdf) != 0u) ||
        (val_exerciser_set_param_by_bdf(CFG_TXN_ATTRIBUTES,
                                        TXN_ADDR_TYPE,
                                        AT_UNTRANSLATED,
                                        bdf) != 0u) ||
        (val_exerciser_set_param_by_bdf(CFG_TXN_ATTRIBUTES,
                                        TXN_ATC_ENTRY,
                                        ATC_ENTRY_ENABLE,
                                        bdf) != 0u))
        return ACS_STATUS_ERR;

    dma_status = val_exerciser_ops_by_bdf(START_DMA, direction, bdf);
    return (dma_status == 0u) ? ACS_STATUS_PASS : ACS_STATUS_FAIL;
}

uint32_t
val_cxl_exerciser_execute_cmd(uint32_t bdf, uint32_t opcode,
                              uint64_t address, uint64_t data,
                              uint64_t *readback)
{
    if (val_exerciser_set_param_by_bdf(EXERCISER_CXL_CMD_OP,
                                       opcode,
                                       0u,
                                       bdf) != 0u)
        return ACS_STATUS_FAIL;

    if (val_exerciser_set_param_by_bdf(EXERCISER_CXL_CMD_ADDR,
                                       address,
                                       0u,
                                       bdf) != 0u)
        return ACS_STATUS_FAIL;

    if ((opcode != CXL_CMD_OP_BACKDOOR_READ64) &&
        (val_exerciser_set_param_by_bdf(EXERCISER_CXL_CMD_DATA0,
                                        data,
                                        0u,
                                        bdf) != 0u))
        return ACS_STATUS_FAIL;

    if (val_exerciser_ops_by_bdf(CXL_CMD_START, 0u, bdf) != 0u)
        return ACS_STATUS_FAIL;

    if ((readback != NULL) &&
        (val_exerciser_get_param_by_bdf(EXERCISER_CXL_CMD_DATA0,
                                        readback,
                                        NULL,
                                        bdf) != 0u))
        return ACS_STATUS_FAIL;

    return ACS_STATUS_PASS;
}

/**
  @brief  Enable or disable an exerciser override for snoop-response MECID.

  This is an implementation-defined coherent exerciser stimulus. It permits a
  host test to generate both permitted and unpermitted response MECIDs without
  exposing any private host-port decision state.
**/
uint32_t
val_cxl_exerciser_set_snoop_response_mecid(uint32_t bdf,
                                            uint16_t mecid,
                                            uint32_t enable)
{
    uint64_t control;

    control = (enable != 0u) ?
              (CXL_SNOOP_RESPONSE_MECID_VALID | (uint64_t)mecid) : 0u;
    return val_cxl_exerciser_execute_cmd(bdf,
                                         CXL_CMD_OP_SNOOP_RESPONSE_MECID,
                                         0u,
                                         control,
                                         NULL);
}

uint32_t
val_cxl_exerciser_backdoor_read64(uint32_t bdf, uint64_t dpa, uint64_t *readback)
{
    return val_cxl_exerciser_execute_cmd(bdf,
                                         CXL_CMD_OP_BACKDOOR_READ64,
                                         dpa,
                                         0u,
                                         readback);
}

uint32_t
val_cxl_exerciser_backdoor_write64(uint32_t bdf, uint64_t dpa, uint64_t data)
{
    return val_cxl_exerciser_execute_cmd(bdf,
                                         CXL_CMD_OP_BACKDOOR_WRITE64,
                                         dpa,
                                         data,
                                         NULL);
}

/**
  @brief   This API returns test specific data from the PCIe stimulus generation hardware
  @param   type         - data type for which the data needs to be returned
  @param   data         - test specific data to be be filled by pal layer
  @param   instance     - Stimulus hardware instance number
  @return  status       - SUCCESS if the requested data is successfully filled
**/
uint32_t val_exerciser_get_data(EXERCISER_DATA_TYPE type, exerciser_data_t *data,
                                uint32_t instance)
{
    uint32_t bdf = g_exerciser_info_table.e_info[instance].bdf;
    uint64_t ecam = val_pcie_get_ecam_base(bdf);

    return pal_exerciser_get_data(type, data, bdf, ecam);
}
