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

#include "pal_common_support.h"
#include "pal_pcie_enum.h"

uint32_t response[100] = {0};
uint8_t *response_8bit = (uint8_t *)response;

void pal_form_get_version_msg(uint32_t req_id, uint8_t *request, uint64_t *req_length)
{
    /* SPDM message */
    request[0] = 0x12;
    request[1] = 0xFE; // RequestResponseCode // application data
    request[2] = 0x00;
    request[3] = 0x00;
    request[4] = 0x3; // StandardID // application data
    request[5] = 0x00; // StandardID // application data
    request[6] = 0x02; // Length of vendor ID // application data
    request[7] = 0x01; // Vendor ID
    request[8] = 0x00; // Vendor ID
    request[9] = 0x12; // Payload Length // application data
    request[10] = 0x00; // Payload Length // application data

    /* TDISP Message */
    request[11] = 0x1; // protocol id // application data
    request[12] = 0x10; // tdisp version // application data
    request[13] = 0x81; // message type
    //request[14] & [15] Reserved
    request[16] = VAL_EXTRACT_BITS(req_id, 0, 7);// 12 byte interface ID = 4 bytes Requester ID
    request[17] = VAL_EXTRACT_BITS(req_id, 8, 15);// + 8 bytes reserved
    request[18] = 0;
    request[19] = 0;
    //Tdisp Message Payload
    //Reserved till request[27]
    request[28] = 0x01; // version count
    request[29] = 0x10; // version 1
    *req_length = 0x1e;
    print(ACS_PRINT_INFO, "Request message: 0x", 0);
    for (uint32_t i = 0; i < *req_length; i++)
    {
        print(ACS_PRINT_INFO, "%x ", request[i]);
    }

}

void pal_form_tdisp_lock_msg(uint32_t req_id, uint8_t *request, uint64_t *req_length)
{
    /* SPDM message */
    request[0] = 0x12;
    request[1] = 0xFE; // RequestResponseCode // application data
    request[2] = 0x00;
    request[3] = 0x00;
    request[4] = 0x3; // StandardID // application data
    request[5] = 0x00; // StandardID // application data
    request[6] = 0x02; // Length of vendor ID // application data
    request[7] = 0x01; // Vendor ID
    request[8] = 0x00; // Vendor ID
    request[9] = 0x24; // Payload Length // application data
    request[10] = 0x00; // Payload Length // application data

    /* TDISP Message */
    request[11] = 0x1; // protocol id // application data
    request[12] = 0x10; // tdisp version // application data
    request[13] = 0x83; // message type
    //request[14] & [15] Reserved
    request[16] = VAL_EXTRACT_BITS(req_id, 0, 7);// 12 byte interface ID = 4 bytes Requester ID
    request[17] = VAL_EXTRACT_BITS(req_id, 8, 15);
    // + 8 bytes reserved
    request[28] = 0x00; // flags 0-7
    request[29] = 0x00; // lags 8-15
    request[30] = 0x00; // Stream ID
    request[31] = 0x00; // Reserved
    // MMIO Reporting Offset for 8 bytes is treated as 0
    // BIND_P2P_ADDRESS_MASK for 8 bytes is treated as 0
    *req_length = 0x30;
    print(ACS_PRINT_DEBUG, "Request message: 0x", 0);
    for (uint32_t i = 0; i < *req_length; i++)
    {
        print(ACS_PRINT_INFO, "%x ", request[i]);
    }

}

void pal_form_tdisp_run_msg(uint32_t req_id, uint8_t *request, uint64_t *req_length)
{
    /* SPDM message */
    request[0] = 0x12;
    request[1] = 0xFE; // RequestResponseCode // application data
    request[2] = 0x00;
    request[3] = 0x00;
    request[4] = 0x3; // StandardID // application data
    request[5] = 0x00; // StandardID // application data
    request[6] = 0x02; // Length of vendor ID // application data
    request[7] = 0x01; // Vendor ID
    request[8] = 0x00; // Vendor ID
    request[9] = 0x30; // Payload Length // application data
    request[10] = 0x00; // Payload Length // application data

    /* TDISP Message */
    request[11] = 0x1; // protocol id // application data
    request[12] = 0x10; // tdisp version // application data
    request[13] = 0x86; // message type
    //request[14] & [15] Reserved
    request[16] = VAL_EXTRACT_BITS(req_id, 0, 7);// 12 byte interface ID = 4 bytes Requester ID
    request[17] = VAL_EXTRACT_BITS(req_id, 8, 15);
    // + 8 bytes reserved
    for (int nonce_cnt = 0; nonce_cnt < 32; nonce_cnt++)
    {
        request[28 + nonce_cnt] = response_8bit[28 + nonce_cnt];
    }
    *req_length = 0x3c;
    print(ACS_PRINT_DEBUG, "Request message: 0x", 0);
    for (uint32_t i = 0; i < *req_length; i++)
    {
        print(ACS_PRINT_INFO, "%x ", request[i]);
    }

}
void pal_form_tdisp_get_state_msg(uint32_t req_id, uint8_t *request, uint64_t *req_length)
{
    /* SPDM message */
    request[0] = 0x12;
    request[1] = 0xFE; // RequestResponseCode // application data
    request[2] = 0x00;
    request[3] = 0x00;
    request[4] = 0x3; // StandardID // application data
    request[5] = 0x00; // StandardID // application data
    request[6] = 0x02; // Length of vendor ID // application data
    request[7] = 0x01; // Vendor ID
    request[8] = 0x00; // Vendor ID
    request[9] = 0x10; // Payload Length // application data
    request[10] = 0x00; // Payload Length // application data

    /* TDISP Message */
    request[11] = 0x1; // protocol id // application data
    request[12] = 0x10; // tdisp version // application data
    request[13] = 0x85; // message type
    //request[14] & [15] Reserved
    request[16] = VAL_EXTRACT_BITS(req_id, 0, 7);// 12 byte interface ID = 4 bytes Requester ID
    request[17] = VAL_EXTRACT_BITS(req_id, 8, 15);
    // Reserved till [27]
    *req_length = 0x1c;
    print(ACS_PRINT_DEBUG, "Request message: 0x", 0);
    for (uint32_t i = 0; i < *req_length; i++)
    {
        print(ACS_PRINT_INFO, "%x ", request[i]);
    }

}

uint32_t pal_write_doe_msgo_doe_mailbox(uint32_t bdf, uint32_t *request, uint64_t req_length)
{
    /* Need to implement */
    uint32_t value, doe_cap_base, status;
    uint64_t i, doe_length, Ecam, config_addr;;

    Ecam = pal_pcie_get_mcfg_ecam(); // Getting the ECAM address
    config_addr = pal_exerciser_get_pcie_config_offset(bdf);
    doe_cap_base = 0;
    status = pal_exerciser_find_pcie_capability(DOE_CAP_ID, bdf, PCIE, &doe_cap_base);

    if (status)
    {
        print(ACS_PRINT_ERR, "\n       DOE capability not found", 0);
        return 1;
    }

    value = pal_mmio_read(Ecam + config_addr + doe_cap_base + DOE_STATUS_REG);
    if (VAL_EXTRACT_BITS(value, DOE_STATUS_REG_BUSY, DOE_STATUS_REG_BUSY))
    {
        print(ACS_PRINT_ERR, "\nDOE Busy bit is set", 0);
        return 1;
    }

    value = pal_mmio_read(Ecam + config_addr + doe_cap_base + DOE_STATUS_REG);
    if (VAL_EXTRACT_BITS(value, DOE_STATUS_REG_ERROR, DOE_STATUS_REG_ERROR))
    {
        print(ACS_PRINT_ERR, "\nDOE Error bit is set", 0);
        return 1;
    }

    doe_length = (req_length % 4) ? ((req_length >> 2) + 1) : (req_length >> 2);

    pal_mmio_write(Ecam + config_addr + doe_cap_base + DOE_WRITE_DATA_MAILBOX_REG, 0x10001);
    pal_mmio_write(Ecam + config_addr + doe_cap_base + DOE_WRITE_DATA_MAILBOX_REG,
                                    (uint32_t)doe_length + 0x2);

    for (i = 0; i < doe_length; i++)
    {
        print(ACS_PRINT_INFO, "\n Writing request[%lld]: 0x%lx to DOE mailbox", i, request[i]);
        pal_mmio_write(Ecam + config_addr + doe_cap_base + DOE_WRITE_DATA_MAILBOX_REG, request[i]);
    }

    /*Set Go bit*/
    pal_mmio_write(Ecam + config_addr + doe_cap_base + DOE_CTRL_REG, (uint32_t)(1 << 31));
    return 0;
}

uint32_t pal_host_pcie_doe_recv_resp(uint32_t bdf, uint32_t *resp_addr, uint64_t *resp_len)
{
    uint32_t value, length, doe_cap_base, status;
    uint64_t i, Ecam, config_addr;

    Ecam = pal_pcie_get_mcfg_ecam(); // Getting the ECAM address
    config_addr = pal_exerciser_get_pcie_config_offset(bdf);
    doe_cap_base = 0;
    status = pal_exerciser_find_pcie_capability(DOE_CAP_ID, bdf, PCIE, &doe_cap_base);

    if (status)
    {
        print(ACS_PRINT_ERR, "\n       DOE capability not found", 0);
        return 1;
    }

    value = pal_mmio_read(Ecam + config_addr + doe_cap_base + DOE_STATUS_REG);
    if (!(VAL_EXTRACT_BITS(value, DOE_STATUS_REG_READY, DOE_STATUS_REG_READY)))
    {
        print(ACS_PRINT_ERR, "\nDOE Ready bit is not set", 0);
        return 1;
    }

    value = pal_mmio_read(Ecam + config_addr + doe_cap_base + DOE_STATUS_REG);

    if (VAL_EXTRACT_BITS(value, DOE_STATUS_REG_ERROR, DOE_STATUS_REG_ERROR))
    {
        print(ACS_PRINT_ERR, "\nDOE Error bit is set", 0);
        return 1;
    }

    /* Reading DOE Header 1 */
    value = pal_mmio_read(Ecam + config_addr + doe_cap_base + DOE_READ_DATA_MAILBOX_REG);
    pal_mmio_write(Ecam + config_addr + doe_cap_base + DOE_READ_DATA_MAILBOX_REG, 0);

    /* Reading DOE Header 2 - Length */
    value = pal_mmio_read(Ecam + config_addr + doe_cap_base + DOE_READ_DATA_MAILBOX_REG);
    pal_mmio_write(Ecam + config_addr + doe_cap_base + DOE_READ_DATA_MAILBOX_REG, 0);

    length = value - 0x2;
    *resp_len = (uint64_t)(length * 4);
    print(ACS_PRINT_INFO, "\n Length of the DW: 0x%llx in bytes", *resp_len);

    for (i = 0; i < length; i++)
    {
        value = pal_mmio_read(Ecam + config_addr + doe_cap_base + DOE_READ_DATA_MAILBOX_REG);
        pal_mmio_write(Ecam + config_addr + doe_cap_base + DOE_READ_DATA_MAILBOX_REG, 0);
        *resp_addr++ = value;
    }

    value = pal_mmio_read(Ecam + config_addr + doe_cap_base + DOE_STATUS_REG);
    if (VAL_EXTRACT_BITS(value, DOE_STATUS_REG_READY, DOE_STATUS_REG_READY))
    {
        print(ACS_PRINT_ERR, "\nDOE Busy bit is not clear", 0);
        return 1;
    }

    return 0;
}

uint32_t pal_check_doe_response(uint32_t bdf)
{
    /* Need to implement */
    uint64_t resp_len;

    if (pal_host_pcie_doe_recv_resp(bdf, &response[0], &resp_len))
    {
        print(ACS_PRINT_ERR, "\n Responose failed ", 0);
        return 1;
    }

    print(ACS_PRINT_INFO, "\n       Response: 0x", 0);
    for (uint32_t i = 0; i < resp_len; i++)
    {
        print(ACS_PRINT_INFO, "%02x ", response_8bit[i]);
    }

    return 0;
}

uint32_t pal_device_unlock(uint32_t bdf)
{
    uint8_t req_addr[50] = {0};
    uint16_t req_id;
    uint32_t *req_addr_4byte;
    uint64_t req_length;

    req_id = PCIE_CREATE_BDF_PACKED(bdf);
    /* SPDM message */
    req_addr[0] = 0x12;
    req_addr[1] = 0xFE; // RequestResponseCode // application data
    req_addr[2] = 0x00;
    req_addr[3] = 0x00;
    req_addr[4] = 0x3; // StandardID // application data
    req_addr[5] = 0x00; // StandardID // application data
    req_addr[6] = 0x02; // Length of vendor ID // application data
    req_addr[7] = 0x01; // Vendor ID
    req_addr[8] = 0x00; // Vendor ID
    req_addr[9] = 0x10; // Payload Length // application data
    req_addr[10] = 0x00; // Payload Length // application data

    /* TDISP Message */
    req_addr[11] = 0x1; // protocol id // application data
    req_addr[12] = 0x10; // tdisp version // application data
    req_addr[13] = 0x87; // message type
    //req_addr[14] & [15] Reserved
    req_addr[16] = VAL_EXTRACT_BITS(req_id, 0, 7);// 12 byte interface ID = 4 bytes Requester ID
    req_addr[17] = VAL_EXTRACT_BITS(req_id, 8, 15);
    // Reserved till [27]
    req_length = 0x1c;
    print(ACS_PRINT_DEBUG, "Request message: 0x", 0);
    for (uint32_t i = 0; i < req_length; i++)
    {
        print(ACS_PRINT_INFO, "%x ", req_addr[i]);
    }

    req_addr_4byte = (uint32_t *)req_addr;
    pal_write_doe_msgo_doe_mailbox(bdf, req_addr_4byte, req_length);
    if (pal_check_doe_response(bdf))
        print(ACS_PRINT_ERR, "\n       TDSIP Locking failed", 0);

    /* Get the device state */
    pal_mem_set(&req_addr, sizeof(req_addr), 0);
    pal_form_tdisp_get_state_msg(req_id, req_addr, &req_length);

    req_addr_4byte = (uint32_t *)req_addr;
    pal_write_doe_msgo_doe_mailbox(bdf, req_addr_4byte, req_length);
    if (pal_check_doe_response(bdf))
      print(ACS_PRINT_ERR, "\n       TDSIP Locking failed", 0);

  return 0;
}

uint32_t pal_device_lock(uint32_t bdf)
{
  uint64_t req_length;
  uint16_t req_id;
  uint8_t req_addr_get_version_spdm[4] = {0};
  uint8_t req_addr[100] = {0};
  uint32_t *req_addr_4byte;

  req_id = PCIE_CREATE_BDF_PACKED(bdf);

  req_addr_get_version_spdm[0] = 0x10;
  req_addr_get_version_spdm[1] = 0x84;
  req_addr_get_version_spdm[2] = 0;
  req_addr_get_version_spdm[3] = 0;

  req_length = 0x4;
  req_addr_4byte = (uint32_t *)req_addr_get_version_spdm;
  pal_write_doe_msgo_doe_mailbox(bdf, req_addr_4byte, req_length);
  pal_check_doe_response(bdf);

  /* Get TDISP Version */
  pal_form_get_version_msg(req_id, req_addr, &req_length);

  req_addr_4byte = (uint32_t *)req_addr;
  /* Write the created request message to doe_write_data_mailbox register */
  pal_write_doe_msgo_doe_mailbox(bdf, req_addr_4byte, req_length);

  /* Finally check the response from the doe_read_data_mailbox register */
  if (pal_check_doe_response(bdf))
    print(ACS_PRINT_ERR, "\n       TDSIP Get version failed", 0);

  /* Get device state */
  pal_mem_set(&req_addr, sizeof(req_addr), 0);
  pal_form_tdisp_get_state_msg(req_id, req_addr, &req_length);

  req_addr_4byte = (uint32_t *)req_addr;
  pal_write_doe_msgo_doe_mailbox(bdf, req_addr_4byte, req_length);
  if (pal_check_doe_response(bdf))
    print(ACS_PRINT_ERR, "\n       TDSIP Locking failed", 0);

  /* Lock the device */
  pal_mem_set(&req_addr, sizeof(req_addr), 0);
  pal_form_tdisp_lock_msg(req_id, req_addr, &req_length);

  req_addr_4byte = (uint32_t *)req_addr;
  pal_write_doe_msgo_doe_mailbox(bdf, req_addr_4byte, req_length);
  if (pal_check_doe_response(bdf))
    print(ACS_PRINT_ERR, "\n       TDSIP Locking failed", 0);

  /* Start the TDI (RUN) */
  pal_mem_set(&req_addr, sizeof(req_addr), 0);
  pal_form_tdisp_run_msg(req_id, req_addr, &req_length);

  req_addr_4byte = (uint32_t *)req_addr;
  pal_write_doe_msgo_doe_mailbox(bdf, req_addr_4byte, req_length);
  if (pal_check_doe_response(bdf))
    print(ACS_PRINT_ERR, "\n       TDSIP Locking failed", 0);

  /* Get the device state */
  pal_mem_set(&req_addr, sizeof(req_addr), 0);
  pal_form_tdisp_get_state_msg(req_id, req_addr, &req_length);

  req_addr_4byte = (uint32_t *)req_addr;
  pal_write_doe_msgo_doe_mailbox(bdf, req_addr_4byte, req_length);
  if (pal_check_doe_response(bdf))
    print(ACS_PRINT_ERR, "\n       TDSIP Locking failed", 0);

  return 0;
}
