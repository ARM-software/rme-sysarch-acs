/** @file
 * Copyright (c) 2022-2023, 2025-2026, Arm Limited or its affiliates. All rights reserved.
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

#include "include/pal_common_support.h"
#include "include/pal_pcie_enum.h"
#include "FVP/include/pal_override_struct.h"

#ifdef ENABLE_OOB
#include  <Library/ShellCEntryLib.h>
#include  <Library/UefiBootServicesTableLib.h>
#include  <Library/UefiLib.h>
#include  <Library/ShellLib.h>
#include  <Library/PrintLib.h>
#include  <Library/BaseMemoryLib.h>
#endif

extern PCIE_INFO_TABLE *g_pcie_info_table;

uint64_t
pal_pcie_get_mcfg_ecam();

uint64_t
pal_exerciser_get_ecam(uint32_t bdf)
{

  uint32_t i = 0;
  uint32_t bus = PCIE_EXTRACT_BDF_BUS(bdf);

  while (i < g_pcie_info_table->num_entries)
  {
    if ((bus >= g_pcie_info_table->block[i].start_bus_num) &&
         (bus <= g_pcie_info_table->block[i].end_bus_num))
    {
      return g_pcie_info_table->block[i].ecam_base;
    }
    i++;
  }
  print(ACS_PRINT_ERR, " No ECAM base ");
  return 0;
}

/**
  @brief This API will return the ECSR base address of particular BAR Index
**/
uint64_t
pal_exerciser_get_ecsr_base(uint32_t Bdf, uint32_t BarIndex)
{
   return pal_pcie_get_base(Bdf, BarIndex);
}

uint64_t
pal_exerciser_get_pcie_config_offset(uint32_t Bdf)
{
  uint32_t bus     = PCIE_EXTRACT_BDF_BUS(Bdf);
  uint32_t dev     = PCIE_EXTRACT_BDF_DEV(Bdf);
  uint32_t func    = PCIE_EXTRACT_BDF_FUNC(Bdf);
  uint64_t cfg_addr;

   /* There are 8 functions / device, 32 devices / Bus and each has a 4KB config space */
  cfg_addr = (bus * PCIE_MAX_DEV * PCIE_MAX_FUNC * 4096) + \
               (dev * PCIE_MAX_FUNC * 4096) + (func * 4096);

  return cfg_addr;
}

/**
  @brief  This API returns if the device is a exerciser
  @param  bdf - Bus/Device/Function
  @return 1 - true 0 - false
**/
uint32_t
pal_is_bdf_exerciser(uint32_t bdf)
{
  uint64_t Ecam;
  uint32_t vendor_dev_id;
  Ecam = pal_pcie_get_mcfg_ecam();

  vendor_dev_id = pal_mmio_read(Ecam + pal_exerciser_get_pcie_config_offset(bdf));
  if (vendor_dev_id == EXERCISER_ID)
     return 1;
  else
     return 0;
}

/**
  @brief   This API writes the configuration parameters of the PCIe stimulus generation hardware
  @param   Type         - Parameter type that needs to be set in the stimulus hadrware
  @param   Value1       - Parameter 1 that needs to be set
  @param   Value2       - Parameter 2 that needs to be set
  @param   Instance     - Stimulus hardware instance number
  @return  Status       - SUCCESS if the input paramter type is successfully written
**/
uint32_t pal_exerciser_set_param(EXERCISER_PARAM_TYPE Type, uint64_t Value1, uint64_t Value2, uint32_t Bdf)
{
 /* Below code is not applicable for Bare-metal
  * Only for FVP OOB experience
  */

  uint32_t Data;
  uint32_t CapabilityOffset = 0;
  uint64_t Base;
  uint64_t Ecam;
  uint32_t bdf;

  Base = pal_exerciser_get_ecsr_base(Bdf,0);
  Ecam = pal_exerciser_get_ecam(Bdf);

  switch (Type) {

      case SNOOP_ATTRIBUTES:
          return 0;

      case LEGACY_IRQ:
          return 0;

      case DMA_ATTRIBUTES:
          /* Do not change the address/length of an outstanding command. */
          if (pal_mmio_read(Base + DMACTL1) & EXERCISER_DMA_TRIGGER_MASK)
              return EXERCISER_DMA_BUSY;
          if (Value2 > 0xFFFFFFFFULL)
              return EXERCISER_DMA_INVALID;
          pal_mmio_write64(Base + DMA_BUS_ADDR, Value1);
          /* DMASTATUS immediately follows this 32-bit register. */
          pal_mmio_write(Base + DMA_LEN, (uint32_t)Value2);
          return EXERCISER_DMA_SUCCESS;

      case P2P_ATTRIBUTES:
          return 0;

      case PASID_ATTRIBUTES:
          Data = pal_mmio_read(Base + DMACTL1);
          Data &= ~(PASID_LEN_MASK << PASID_LEN_SHIFT);
          Data |= ((Value1 - 16) & PASID_LEN_MASK) << PASID_LEN_SHIFT;
          pal_mmio_write(Base + DMACTL1, Data);
          return 0;

      case MSIX_ATTRIBUTES:
          return 0;

      case CFG_TXN_ATTRIBUTES:
          switch (Value1) {

            case TXN_REQ_ID:
                /* Change Requester ID for DMA Transaction.*/
                Data = (Value2 & RID_VALUE_MASK) | RID_VALID_MASK;
                pal_mmio_write(Base + RID_CTL_REG, Data);
                return 0;
            case TXN_REQ_ID_VALID:
                switch (Value2)
                {
                    case RID_VALID:
                        Data = pal_mmio_read(Base + RID_CTL_REG);
                        Data |= RID_VALID_MASK;
                        pal_mmio_write(Base + RID_CTL_REG, Data);
                        return 0;
                    case RID_NOT_VALID:
                        pal_mmio_write(Base + RID_CTL_REG, 0);
                        return 0;
                }
                return 0;
            case TXN_ADDR_TYPE:
                /* Change Address Type for DMA Transaction.*/
                Data = pal_mmio_read(Base + DMACTL1);
                Data &= ~(0x3u << 10);
                switch (Value2)
                {
                    case AT_UNTRANSLATED:
                        Data |= (0x1u << 10);
                        break;
                    case AT_TRANSLATED:
                        Data |= (0x2u << 10);
                        break;
                    case AT_RESERVED:
                        Data |= (0x3u << 10);
                        break;
                    default:
                        return 1;
                }
                pal_mmio_write(Base + DMACTL1, Data);
                return 0;
            case TXN_ATC_ENTRY:
                Data = pal_mmio_read(Base + DMACTL1);
                if (Value2 == ATC_ENTRY_ENABLE)
                    Data |= DMA_USE_ATC_ENTRY_MASK;
                else if (Value2 == ATC_ENTRY_DISABLE)
                    Data &= ~DMA_USE_ATC_ENTRY_MASK;
                else
                    return 1;
                pal_mmio_write(Base + DMACTL1, Data);
                return 0;
            default:
                return 1;
          }

     case ERROR_INJECT_TYPE:
        pal_exerciser_find_pcie_capability(DVSEC, Bdf, PCIE, &CapabilityOffset);
        Data = pal_mmio_read(Ecam + CapabilityOffset +
                             pal_exerciser_get_pcie_config_offset(Bdf) + DVSEC_CTRL);
        Data = ((Value1 << ERR_CODE_SHIFT) | (Value2 << FATAL_SHIFT));
        pal_mmio_write(Ecam + CapabilityOffset + DVSEC_CTRL +
                             pal_exerciser_get_pcie_config_offset(Bdf), Data);
        if (Value1 <= 0x7)
                return 2;
        else
                return 3;

      case ENABLE_POISON_MODE:
        pal_exerciser_find_pcie_capability(DVSEC, Bdf, PCIE, &CapabilityOffset);
        Data = pal_mmio_read(Ecam + CapabilityOffset +
                             pal_exerciser_get_pcie_config_offset(Bdf) + DVSEC_CTRL);
        Data = Data | (1 << 18);
        pal_mmio_write(Ecam + CapabilityOffset + DVSEC_CTRL +
                             pal_exerciser_get_pcie_config_offset(Bdf), Data);
        return 0;

      case ENABLE_RAS_CTRL:
        bdf = (uint32_t)Value2;
        Base = pal_exerciser_get_ecsr_base(bdf, 0);
        Base = Base & BAR64_MASK;
        pal_mmio_write((Base + RAS_OFFSET + CTRL_OFFSET), 0x1);
        return 0;

      case DISABLE_POISON_MODE:
        pal_exerciser_find_pcie_capability(DVSEC, Bdf, PCIE, &CapabilityOffset);
        Data = pal_mmio_read(Ecam + CapabilityOffset +
                             pal_exerciser_get_pcie_config_offset(Bdf) + DVSEC_CTRL);
        Data = Data & (0 << 18);
        pal_mmio_write(Ecam + CapabilityOffset + DVSEC_CTRL +
                             pal_exerciser_get_pcie_config_offset(Bdf), Data);
        return 0;

      case EXERCISER_CXL_CMD_OP:
        pal_mmio_write(Base + CXL_CMD_OP, (uint32_t)Value1);
        print(ACS_PRINT_DEBUG, " CXL_CMD_OP write 0x%x", (uint32_t)Value1);
        return 0;

      case EXERCISER_CXL_CMD_ADDR:
        pal_mmio_write(Base + CXL_CMD_ADDR_LO, (uint32_t)Value1);
        pal_mmio_write(Base + CXL_CMD_ADDR_HI, (uint32_t)(Value1 >> 32));
        return 0;

      case EXERCISER_CXL_CMD_DATA0:
        pal_mmio_write(Base + CXL_CMD_DATA0_LO, (uint32_t)Value1);
        pal_mmio_write(Base + CXL_CMD_DATA0_HI, (uint32_t)(Value1 >> 32));
        return 0;

      case EXERCISER_SEC_SID:
        /* Setting Non-secure and releasing the override are distinct operations. */
        Data = (Value1 == EXERCISER_SEC_SID_DEFAULT) ? 0u :
               ((uint32_t)(Value1 & SEC_SID_VALUE_REG_MASK) | SEC_SID_VALUE_REG_VALID);
        pal_mmio_write(Base + SEC_SID_VALUE_REG, Data);
        return 0;

      case EXERCISER_ATS_REQUEST_ATTRIBUTES:
        if ((Value1 & ~(ATS_REQUEST_ATTR_T | ATS_REQUEST_ATTR_XT)) != 0u)
            return 1;
        Data = pal_mmio_read(Base + ATSCTL) & ~ATS_REQUEST_ATTR_REG_MASK;
        if ((Value1 & ATS_REQUEST_ATTR_T) != 0u)
            Data |= ATS_REQUEST_T_MASK;
        if ((Value1 & ATS_REQUEST_ATTR_XT) != 0u)
            Data |= ATS_REQUEST_XT_MASK;
        pal_mmio_write(Base + ATSCTL, Data);
        return 0;

      default:
          return 1;
  }

  return 1;
}

/**
  @brief Wait for the command to finish before consuming its status.
  A timeout leaves the command outstanding; it must not be reprogrammed.
**/
static uint32_t
pal_exerciser_wait_dma(uint64_t Base)
{
    uint32_t poll;
    uint32_t status;

    for (poll = 0; poll < EXERCISER_DMA_POLL_LIMIT; ++poll) {
        if ((pal_mmio_read(Base + DMACTL1) & EXERCISER_DMA_TRIGGER_MASK) == 0) {
            status = pal_mmio_read(Base + DMASTATUS) & EXERCISER_DMA_STATUS_MASK;
            pal_mmio_write(Base + DMASTATUS, EXERCISER_DMA_STATUS_CLEAR);
            return status;
        }
    }

    return EXERCISER_DMA_TIMEOUT;
}

/**
  @brief Trigger DMA and return the completed result, or a software failure.
**/
uint32_t
pal_exerciser_start_dma_direction(uint64_t Base, EXERCISER_DMA_ATTR Direction)
{
    uint32_t control;

    if (Direction != EDMA_TO_DEVICE && Direction != EDMA_FROM_DEVICE)
        return EXERCISER_DMA_INVALID;

    control = pal_mmio_read(Base + DMACTL1);
    if (control & EXERCISER_DMA_TRIGGER_MASK)
        return EXERCISER_DMA_BUSY;

    control &= ~EXERCISER_DMA_DIRECTION_MASK;
    if (Direction == EDMA_FROM_DEVICE)
        control |= EXERCISER_DMA_DIRECTION_MASK;

    pal_mmio_write(Base + DMASTATUS, EXERCISER_DMA_STATUS_CLEAR);
    pal_mmio_write(Base + DMACTL1, control | EXERCISER_DMA_TRIGGER_START);
    return pal_exerciser_wait_dma(Base);
}

/**
  @brief This function finds the PCI capability and return 0 if it finds.
**/
uint32_t pal_exerciser_find_pcie_capability (uint32_t ID, uint32_t Bdf, uint32_t Value, uint32_t *Offset)
{
  uint64_t NxtPtr;
  uint32_t Data;
  uint32_t TempId;
  uint64_t Ecam;
  uint32_t IdMask;
  uint32_t PtrMask;
  uint32_t PtrOffset;

  Ecam = pal_pcie_get_mcfg_ecam();
  NxtPtr = PCIE_CAP_OFFSET;

  if (Value == 1) {
      IdMask = PCIE_CAP_ID_MASK;
      PtrMask = PCIE_NXT_CAP_PTR_MASK;
      PtrOffset = PCIE_CAP_PTR_OFFSET;
      NxtPtr = PCIE_CAP_OFFSET;
  }
  else {
      IdMask = PCI_CAP_ID_MASK;
      PtrMask = PCI_NXT_CAP_PTR_MASK;
      PtrOffset = PCI_CAP_PTR_OFFSET;
      NxtPtr = (pal_mmio_read(Ecam + CAP_PTR_OFFSET + pal_exerciser_get_pcie_config_offset(Bdf))) & CAP_PTR_MASK;
  }
  while (NxtPtr != 0) {
    Data = pal_mmio_read(Ecam + pal_exerciser_get_pcie_config_offset(Bdf) + NxtPtr);
    TempId = Data & IdMask;
    if (TempId == ID){
        *Offset = NxtPtr;
        return 0;
    }
    NxtPtr = (Data >> PtrOffset) & PtrMask;
  }
  print(ACS_PRINT_ERR," No capabilities found",0);
  return 1;
}

/**
  @brief   This API reads the configuration parameters of the PCIe stimulus generation hardware
  @param   Type         - Parameter type that needs to be read from the stimulus hadrware
  @param   Value1       - Parameter 1 that is read from hardware
  @param   Value2       - Parameter 2 that is read from hardware
  @param   Instance     - Stimulus hardware instance number
  @return  Status       - SUCCESS if the requested paramter type is successfully read
**/
uint32_t pal_exerciser_get_param(EXERCISER_PARAM_TYPE Type, uint64_t *Value1, uint64_t *Value2, uint32_t Bdf)
{
  uint32_t Status;
  uint32_t Temp;
  uint32_t tx_attr;
  uint32_t addr_low;
  uint32_t addr_high;
  uint64_t Base;

  Base = pal_exerciser_get_ecsr_base(Bdf,0);
  switch (Type) {

      case SNOOP_ATTRIBUTES:
          return 0;
      case LEGACY_IRQ:
          *Value1 = pal_mmio_read(Base + INTXCTL);
          return pal_mmio_read(Base + INTXCTL) | MASK_BIT ;
      case DMA_ATTRIBUTES:
          *Value1 = pal_mmio_read(Base + DMA_BUS_ADDR); // Reading the data from DMA Control Register 2
          *Value2 = pal_mmio_read(Base + DMA_LEN); // Reading the data from DMA Control Register 3
          Temp = pal_mmio_read(Base + DMASTATUS);
          Status = Temp & MASK_BIT;// returning the DMA status
          return Status;
      case P2P_ATTRIBUTES:
          return 0;
      case PASID_ATTRIBUTES:
          *Value1 = ((pal_mmio_read(Base + DMACTL1) >> PASID_LEN_SHIFT) & PASID_LEN_MASK) + 16;
          return 0;
      case MSIX_ATTRIBUTES:
          *Value1 = pal_mmio_read(Base + MSICTL);
          return pal_mmio_read(Base + MSICTL) | MASK_BIT;
      case ATS_RES_ATTRIBUTES:
          *Value1 = (uint64_t)pal_mmio_read(Base + ATS_ADDR);
          *Value1 |= (uint64_t)pal_mmio_read(Base + ATS_ADDR + 4) << 32;
          if (Value2 != NULL)
              *Value2 = pal_mmio_read(Base + ATS_REPLY);
          return 0;
      case EXERCISER_CXL_CMD_DATA0:
          *Value1 = (uint64_t)pal_mmio_read(Base + CXL_CMD_DATA0_LO);
          *Value1 |= ((uint64_t)pal_mmio_read(Base + CXL_CMD_DATA0_HI)) << 32;
          return 0;
      case TRANSACTION_RECORD:
          if ((Value1 == NULL) || (Value2 == NULL))
              return 1;
          tx_attr = pal_mmio_read(Base + TXN_TRACE);
          if (tx_attr == TXN_INVALID)
              return 1;
          addr_low = pal_mmio_read(Base + TXN_TRACE);
          addr_high = pal_mmio_read(Base + TXN_TRACE);
          (void)pal_mmio_read(Base + TXN_TRACE);
          (void)pal_mmio_read(Base + TXN_TRACE);
          *Value1 = tx_attr;
          *Value2 = addr_low | ((uint64_t)addr_high << 32);
          return 0;
      case EXERCISER_SEC_SID:
          *Value1 = (uint64_t)(pal_mmio_read(Base + SEC_SID_VALUE_REG) & SEC_SID_VALUE_REG_MASK);
          return 0;
      default:
          return 1;
  }
}

/**
  @brief   This API obtains the state of the PCIe stimulus generation hardware
  @param   State        - State that is read from the stimulus hadrware
  @param   Bdf          - Stimulus hardware bdf number
  @return  Status       - SUCCESS if the state is successfully read from hardware
**/
uint32_t pal_exerciser_get_state(EXERCISER_STATE *State, uint32_t Bdf)
{
   /* Below code is not applicable for Bare-metal
    * Only for FVP OOB experience
    */
    (void) Bdf;
    *State = EXERCISER_ON;
    return 0;
}

/**
  @brief   This API performs the input operation using the PCIe stimulus generation hardware
  @param   Ops          - Operation thta needs to be performed with the stimulus hadrware
  @param   Value        - Additional information to perform the operation
  @param   Instance     - Stimulus hardware instance number
  @return  Status       - SUCCESS if the operation is successfully performed using the hardware
**/
uint32_t pal_exerciser_ops(EXERCISER_OPS Ops, uint64_t Param, uint32_t Bdf)
{
  uint64_t Base;
  uint64_t Ecam;
  uint32_t CapabilityOffset;
  uint32_t data, poll;
  Base = pal_exerciser_get_ecsr_base(Bdf,0);
  Ecam = pal_exerciser_get_ecam(Bdf);
  switch(Ops){

    case DMA_WAIT:
        return pal_exerciser_wait_dma(Base);

    case START_DMA:
        switch (Param) {

            case EDMA_NO_SUPPORT:
                return EXERCISER_DMA_INVALID;
            case EDMA_COHERENT:
                return EXERCISER_DMA_INVALID;
            case EDMA_NOT_COHERENT:
                return EXERCISER_DMA_INVALID;
            case EDMA_FROM_DEVICE:
                return pal_exerciser_start_dma_direction(Base, EDMA_FROM_DEVICE);// DMA from Device
            case EDMA_TO_DEVICE:
                return pal_exerciser_start_dma_direction(Base, EDMA_TO_DEVICE);// DMA to Device
            default:
                return EXERCISER_DMA_INVALID;
        }

    case GENERATE_MSI:
        /* Param is the msi_index */
        pal_mmio_write( Base + MSICTL ,(pal_mmio_read(Base + MSICTL) | (MSI_GENERATION_MASK) | (Param)));
        return 0;

    case GENERATE_L_INTR:
        pal_mmio_write(Base + INTXCTL , (pal_mmio_read(Base + INTXCTL) | MASK_BIT));
        return 0; //Legacy interrupt

    case MEM_READ:
        return 0;

    case MEM_WRITE:
        return 0;

    case CLEAR_INTR:
        pal_mmio_write(Base + INTXCTL , (pal_mmio_read(Base + INTXCTL) & CLR_INTR_MASK));
        return 0;

    case PASID_TLP_START:
        data = pal_mmio_read(Base + DMACTL1);
        data |= (MASK_BIT << PASID_EN_SHIFT);
        pal_mmio_write(Base + DMACTL1, data);
        data = ((Param & PASID_VAL_MASK));
        pal_mmio_write(Base + PASID_VAL, data);

        if (!pal_exerciser_find_pcie_capability(PASID, Bdf, PCIE, &CapabilityOffset)) {
            pal_mmio_write(Ecam + pal_exerciser_get_pcie_config_offset(Bdf) + CapabilityOffset + PCIE_CAP_CTRL_OFFSET,
                            (pal_mmio_read(Ecam + pal_exerciser_get_pcie_config_offset(Bdf) + CapabilityOffset + PCIE_CAP_CTRL_OFFSET)) | PCIE_CAP_EN_MASK);
            return 0;
        }
        return 1;

    case PASID_TLP_STOP:
        pal_mmio_write(Base + DMACTL1, (pal_mmio_read(Base + DMACTL1) & PASID_TLP_STOP_MASK));

        if (!pal_exerciser_find_pcie_capability(PASID, Bdf, PCIE, &CapabilityOffset)) {
            pal_mmio_write(Ecam + pal_exerciser_get_pcie_config_offset(Bdf) + CapabilityOffset + PCIE_CAP_CTRL_OFFSET,
                            (pal_mmio_read(Ecam + pal_exerciser_get_pcie_config_offset(Bdf) + CapabilityOffset + PCIE_CAP_CTRL_OFFSET)) & PCIE_CAP_DIS_MASK);
            return 0;
        }
        return 1;

    case TXN_NO_SNOOP_ENABLE:
        pal_mmio_write(Base + DMACTL1, (pal_mmio_read(Base + DMACTL1)) | NO_SNOOP_START_MASK);//enabling the NO SNOOP
        return 0;

    case TXN_NO_SNOOP_DISABLE:
        pal_mmio_write(Base + DMACTL1, (pal_mmio_read(Base + DMACTL1)) & NO_SNOOP_STOP_MASK);//disabling the NO SNOOP
        return 0;

    case START_TXN_MONITOR:
        pal_mmio_write(Base + TXN_CTRL_BASE, TXN_START);
        return 0;

    case STOP_TXN_MONITOR:
        pal_mmio_write(Base + TXN_CTRL_BASE, TXN_STOP);
        return 0;

    case ATS_TXN_REQ:
        pal_mmio_write(Base + DMA_BUS_ADDR, Param);
        pal_mmio_write(Base + ATSCTL,
                       (pal_mmio_read(Base + ATSCTL) & ATS_REQUEST_ATTR_REG_MASK) |
                       ATS_TRIGGER);
        /* Status is valid only after the translation is no longer in flight. */
        for (poll = 0; poll < EXERCISER_ATS_POLL_LIMIT; ++poll) {
            data = pal_mmio_read(Base + ATSCTL);
            if (!(data & ATS_IN_FLIGHT))
                return !(data & ATS_STATUS);
        }
        return 1;

    case ATS_INV_CACHE:
        pal_mmio_write(Base + ATSCTL,
                       (pal_mmio_read(Base + ATSCTL) & ATS_REQUEST_ATTR_REG_MASK) |
                       ATS_INV);
        return 0;

    case CXL_CMD_START:
        {
        uint32_t cmd;
        uint32_t opcode;

        cmd = pal_mmio_read(Base + CXL_CMD_REG);
        print(ACS_PRINT_DEBUG, " CXL_CMD_START prev cmd 0x%x", cmd);
        opcode = cmd & CXL_CMD_OP_MASK;
        if ((cmd & CXL_CMD_STATUS_MASK) == CXL_CMD_STATUS_ERR)
        {
            uint32_t idx;

            pal_mmio_write(Base + CXL_CMD_REG, opcode | CXL_CMD_CLEAR_ERR);
            for (idx = 0u; idx < 10000u; ++idx)
            {
                data = pal_mmio_read(Base + CXL_CMD_REG);
                if ((data & CXL_CMD_STATUS_MASK) != CXL_CMD_STATUS_ERR)
                    break;
            }
            if (idx == 10000u)
                return 1;
        }

        pal_mmio_write(Base + CXL_CMD_REG, opcode | CXL_CMD_TRIGGER);
        print(ACS_PRINT_DEBUG, " CXL_CMD_REG trigger write 0x%x",
              opcode | CXL_CMD_TRIGGER);
        for (uint32_t idx = 0u; idx < 10000u; ++idx)
        {
            data = pal_mmio_read(Base + CXL_CMD_REG);
            if ((data & CXL_CMD_STATUS_MASK) == CXL_CMD_STATUS_DONE)
                return 0;
            if ((data & CXL_CMD_STATUS_MASK) == CXL_CMD_STATUS_ERR)
            {
                print(ACS_PRINT_DEBUG, " CXL_CMD_START error cmd 0x%x", data);
                return 1;
            }
        }
        print(ACS_PRINT_DEBUG, " CXL_CMD_START timed out for BDF 0x%x", Bdf);
        return 1;
        }

    case INJECT_ERROR:
        pal_exerciser_find_pcie_capability(DVSEC, Bdf, PCIE, &CapabilityOffset);
        data = pal_mmio_read(Ecam + pal_exerciser_get_pcie_config_offset(Bdf) +
                             CapabilityOffset + DVSEC_CTRL);
        data = data | (1 << ERROR_INJECT_BIT);
        pal_mmio_write(Ecam + pal_exerciser_get_pcie_config_offset(Bdf) + CapabilityOffset +
                       DVSEC_CTRL, data);
        return Param;

    default:
        return PCIE_CAP_NOT_FOUND;
  }
  return 1;
}

/**
  @brief  Ask a TDI to originate an attributed BISnp request.

  @param  Bdf        Exerciser endpoint BDF identifying the TDI.
  @param  TargetHpa  Target host physical address.
  @param  PasRealm   Nonzero to request Realm Access PAS.
  @param  Result     Request result flags: VALID plus EMITTED or BLOCKED, and
                     the observed host response when the request was emitted.

  @return 0 when the platform returned a valid result, nonzero otherwise.
**/
uint32_t
pal_cda_tdi_snoop_attempt(uint32_t Bdf, uint64_t TargetHpa,
                          uint32_t PasRealm, uint32_t *Result)
{
    uint64_t raw_result = 0u;
    uint32_t sec_sid;
    uint32_t status;

    if (Result == NULL)
        return 1;
    *Result = 0u;

    sec_sid = (PasRealm != 0u) ? SEC_SID_VALUE_REG_MASK : 0u;
    status = pal_exerciser_set_param(EXERCISER_SEC_SID,
                                      sec_sid,
                                      0u,
                                      Bdf);
    if (status == 0u)
        status = pal_exerciser_set_param(EXERCISER_CXL_CMD_OP,
                                         CXL_CMD_OP_BISNP,
                                         0u,
                                         Bdf);
    if (status == 0u)
        status = pal_exerciser_set_param(EXERCISER_CXL_CMD_ADDR,
                                         TargetHpa,
                                         0u,
                                         Bdf);

    /* Do not interpret data left by an earlier command as a snoop result. */
    if (status == 0u)
        status = pal_exerciser_set_param(EXERCISER_CXL_CMD_DATA0, 0u, 0u, Bdf);

    if (status == 0u)
        status = pal_exerciser_ops(CXL_CMD_START, 0u, Bdf);
    if (status == 0u)
        status = pal_exerciser_get_param(EXERCISER_CXL_CMD_DATA0,
                                         &raw_result,
                                         NULL,
                                         Bdf);

    (void)pal_exerciser_set_param(EXERCISER_SEC_SID, EXERCISER_SEC_SID_DEFAULT, 0u, Bdf);
    if (status != 0u)
        return 1;

    /*
     * A status-only BISnp command completes successfully after the upstream
     * transaction succeeds. DATA0 is zero when no detailed result is supplied.
     * Retain explicit observations when available. A command error alone cannot
     * distinguish local blocking from host rejection and is not normalized here.
     */
    if (raw_result == 0u)
        *Result = CXL_SNOOP_RESULT_VALID | CXL_SNOOP_RESULT_EMITTED |
                  CXL_SNOOP_RESULT_HOST_ACCEPTED;
    else
        *Result = (uint32_t)raw_result;

    return 0;
}

/*
 * A platform port must establish and verify host snoop eligibility and supply
 * a genuine snoop stimulus with snoop-specific endpoint monitoring. No such
 * host setup is supplied by the default PAL; leave all state unchanged.
 */
uint32_t
pal_cda_host_snoop_prepare(uint32_t RootBdf, uint32_t EndpointBdf,
                            uint64_t PermittedHpa, uint64_t UnknownHpa)
{
    (void)RootBdf;
    (void)EndpointBdf;
    (void)PermittedHpa;
    (void)UnknownHpa;
    return PAL_CDA_SNOOP_UNSUPPORTED;
}

uint32_t
pal_cda_host_snoop_trigger(uint32_t EndpointBdf, uint64_t TargetHpa)
{
    (void)EndpointBdf;
    (void)TargetHpa;
    return PAL_CDA_SNOOP_UNSUPPORTED;
}

uint32_t
pal_cda_host_snoop_restore(uint32_t EndpointBdf)
{
    (void)EndpointBdf;
    return PAL_CDA_SNOOP_SUCCESS;
}

/**
  @brief   This API sets the state of the PCIe stimulus generation hardware
  @param   State        - State that needs to be set for the stimulus hadrware
  @param   Value        - Additional information associated with the state
  @param   Instance     - Stimulus hardware instance number
  @return  Status       - SUCCESS if the input state is successfully written to hardware
**/
uint32_t pal_exerciser_set_state (EXERCISER_STATE State, uint64_t *Value, uint32_t Instance)
{
    (void) State;
    (void) Value;
    (void) Instance;
    return 0;
}

/**
  @brief   This API returns test specific data from the PCIe stimulus generation hardware
  @param   type         - data type for which the data needs to be returned
  @param   data         - test specific data to be be filled by pal layer
  @param   instance     - Stimulus hardware instance number
  @return  status       - SUCCESS if the requested data is successfully filled
**/
uint32_t pal_exerciser_get_data(EXERCISER_DATA_TYPE Type, exerciser_data_t *Data, uint32_t Bdf, uint64_t Ecam)
{
 /* Below code is not applicable for Bare-metal
  * Only for FVP OOB experience
  */

  uint32_t Index;
  uint64_t EcamBase;
  uint64_t EcamBAR0;
  uint64_t EcamBAR;

  EcamBase = (Ecam + pal_exerciser_get_pcie_config_offset(Bdf));

  uint32_t offset_table[TEST_REG_COUNT] = {0x00,0x08,0x00,0x08,0x00,0x08,0x00,0x08,0x00,0x08};
  uint32_t attr_table[TEST_REG_COUNT] = {ACCESS_TYPE_RD,ACCESS_TYPE_RD,ACCESS_TYPE_RD,ACCESS_TYPE_RD,ACCESS_TYPE_RD,
                                       ACCESS_TYPE_RD,ACCESS_TYPE_RD,ACCESS_TYPE_RD,ACCESS_TYPE_RD,ACCESS_TYPE_RD,};

  switch(Type){
      case EXERCISER_DATA_CFG_SPACE:
          for (Index = 0; Index < TEST_REG_COUNT; Index++) {
              Data->cfg_space.reg[Index].offset = (offset_table[Index] + pal_exerciser_get_pcie_config_offset (Bdf));
              Data->cfg_space.reg[Index].attribute = attr_table[Index];
              Data->cfg_space.reg[Index].value = pal_mmio_read(EcamBase + offset_table[Index]);
          }
          return 0;
      case EXERCISER_DATA_BAR0_SPACE:
          EcamBAR0 = pal_exerciser_get_ecsr_base(Bdf, 0);
          Data->bar_space.base_addr = (void *)EcamBAR0;
          if (((pal_exerciser_get_ecsr_base(Bdf,0) >> PREFETCHABLE_BIT_SHIFT) & MASK_BIT) == 0x1)
              Data->bar_space.type = MMIO_PREFETCHABLE;
          else
              Data->bar_space.type = MMIO_NON_PREFETCHABLE;
          return 0;
      case EXERCISER_DATA_MMIO_SPACE:
          Index = 1;
          Data->bar_space.base_addr = 0;
          while (Index < TYPE0_MAX_BARS)
          {
              EcamBAR = pal_exerciser_get_ecsr_base(Bdf, Index);

              /* Check if the BAR is Memory Mapped IO type */
              if (((EcamBAR >> BAR_MIT_SHIFT) & BAR_MIT_MASK) == MMIO)
              {
                  Data->bar_space.base_addr = (void *)(EcamBAR);
                  if (((EcamBAR >> PREFETCHABLE_BIT_SHIFT) & MASK_BIT) == 0x1)
                      Data->bar_space.type = MMIO_PREFETCHABLE;
                  else
                      Data->bar_space.type = MMIO_NON_PREFETCHABLE;

                  Data->bar_space.base_addr = (void *)EcamBAR;
                  return 0;
              }

              if (((EcamBAR >> BAR_MDT_SHIFT) & BAR_MDT_MASK) == BITS_64)
              {
                  /* Adjust the index to skip next sequential BAR */
                  Index++;
              }

              /* Adjust index to point to next BAR */
              Index++;
          }

          return 1;
      default:
          return 1;
    }
}
