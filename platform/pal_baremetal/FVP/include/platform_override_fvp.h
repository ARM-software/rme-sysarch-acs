/** @file
 * Copyright (c) 2022-2024, Arm Limited or its affiliates. All rights reserved.
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

#include <stdio.h>
#include <stdint.h>

/** Begin config **/

/* Settings */
#define PLATFORM_OVERRIDE_PRINT_LEVEL  0x3    //The permissible levels are 1,2,3,4 and 5

/* PCIe BAR config parameters*/
#define PLATFORM_OVERRIDE_PCIE_BAR64_VAL   0x4040000000
#define PLATFORM_OVERRIDE_RP_BAR64_VAL     0x4080000000
#define PLATFORM_OVERRIDE_PCIE_BAR32NP_VAL 0x60200000
#define PLATFORM_OVERRIDE_PCIE_BAR32P_VAL  0x60000000
#define PLATFORM_OVERRIDE_RP_BAR32_VAL     0x60800000

/* PE platform config paramaters */
#define PLATFORM_OVERRIDE_PE_CNT           16
#define PLATFORM_OVERRIDE_PE0_INDEX        0x0
#define PLATFORM_OVERRIDE_PE0_MPIDR        0x0
#define PLATFORM_OVERRIDE_PE1_INDEX        0x1
#define PLATFORM_OVERRIDE_PE1_MPIDR        0x10000
#define PLATFORM_OVERRIDE_PE2_INDEX        0x2
#define PLATFORM_OVERRIDE_PE2_MPIDR        0x20000
#define PLATFORM_OVERRIDE_PE3_INDEX        0x3
#define PLATFORM_OVERRIDE_PE3_MPIDR        0x30000
#define PLATFORM_OVERRIDE_PE4_INDEX        0x4
#define PLATFORM_OVERRIDE_PE4_MPIDR        0x40000
#define PLATFORM_OVERRIDE_PE5_INDEX        0x5
#define PLATFORM_OVERRIDE_PE5_MPIDR        0x50000
#define PLATFORM_OVERRIDE_PE6_INDEX        0x6
#define PLATFORM_OVERRIDE_PE6_MPIDR        0x60000
#define PLATFORM_OVERRIDE_PE7_INDEX        0x7
#define PLATFORM_OVERRIDE_PE7_MPIDR        0x70000
#define PLATFORM_OVERRIDE_PE8_INDEX        0x8
#define PLATFORM_OVERRIDE_PE8_MPIDR        0x80000
#define PLATFORM_OVERRIDE_PE9_INDEX        0x9
#define PLATFORM_OVERRIDE_PE9_MPIDR        0x90000
#define PLATFORM_OVERRIDE_PE10_INDEX       0xA
#define PLATFORM_OVERRIDE_PE10_MPIDR       0xA0000
#define PLATFORM_OVERRIDE_PE11_INDEX       0xB
#define PLATFORM_OVERRIDE_PE11_MPIDR       0xB0000
#define PLATFORM_OVERRIDE_PE12_INDEX       0xC
#define PLATFORM_OVERRIDE_PE12_MPIDR       0xC0000
#define PLATFORM_OVERRIDE_PE13_INDEX       0xD
#define PLATFORM_OVERRIDE_PE13_MPIDR       0xD0000
#define PLATFORM_OVERRIDE_PE14_INDEX       0xE
#define PLATFORM_OVERRIDE_PE14_MPIDR       0xE0000
#define PLATFORM_OVERRIDE_PE15_INDEX       0xF
#define PLATFORM_OVERRIDE_PE15_MPIDR       0xF0000

/* GIC platform config parameters*/
#define PLATFORM_OVERRIDE_GIC_VERSION       0x3
#define PLATFORM_OVERRIDE_CORE_COUNT        0x4
#define PLATFORM_OVERRIDE_CLUSTER_COUNT     0x2
#define PLATFORM_OVERRIDE_GICC_COUNT        16
#define PLATFORM_OVERRIDE_GICD_COUNT        0x1
#define PLATFORM_OVERRIDE_GICRD_COUNT       0x1
#define PLATFORM_OVERRIDE_GICITS_COUNT      0x6
#define PLATFORM_OVERRIDE_GICH_COUNT        0x1
#define PLATFORM_OVERRIDE_GICMSIFRAME_COUNT 0x0
#define PLATFORM_OVERRIDE_GICC_TYPE         0x1000
#define PLATFORM_OVERRIDE_GICD_TYPE         0x1001
#define PLATFORM_OVERRIDE_GICC_GICRD_TYPE   0x1002
#define PLATFORM_OVERRIDE_GICR_GICRD_TYPE   0x1003
#define PLATFORM_OVERRIDE_GICITS_TYPE       0x1004
#define PLATFORM_OVERRIDE_GICMSIFRAME_TYPE  0x1005
#define PLATFORM_OVERRIDE_GICH_TYPE         0x1006
#define PLATFORM_OVERRIDE_GICC_BASE         0x30000000
#define PLATFORM_OVERRIDE_GICD_BASE         0x30000000
#define PLATFORM_OVERRIDE_GICRD_BASE        0x301C0000
#define PLATFORM_OVERRIDE_GICITS_BASE       0x30040000
#define PLATFORM_OVERRIDE_GICH_BASE         0x2C010000
#define PLATFORM_OVERRIDE_GICITS0_BASE      0x30040000
#define PLATFORM_OVERRIDE_GICITS0_ID        0
#define PLATFORM_OVERRIDE_GICITS1_BASE      0x30080000
#define PLATFORM_OVERRIDE_GICITS1_ID        0x1
#define PLATFORM_OVERRIDE_GICITS2_BASE      0x300C0000
#define PLATFORM_OVERRIDE_GICITS2_ID        0x2
#define PLATFORM_OVERRIDE_GICITS3_BASE      0x30100000
#define PLATFORM_OVERRIDE_GICITS3_ID        0x3
#define PLATFORM_OVERRIDE_GICITS4_BASE      0x30140000
#define PLATFORM_OVERRIDE_GICITS4_ID        0x4
#define PLATFORM_OVERRIDE_GICITS5_BASE      0x30180000
#define PLATFORM_OVERRIDE_GICITS5_ID        0x5
#define PLATFORM_OVERRIDE_GICIRD_LENGTH     (0x20000*8)

/*
 *Secure EL1 timer Flags, Non-Secure EL1 timer Flags, EL2 timer Flags,
 *and Virtual timer Flags all can have the same definition as follows.
 */
#define INTERRUPT_IS_LEVEL_TRIGGERED 0x0
#define INTERRUPT_IS_EDGE_TRIGGERED  0x1
#define INTERRUPT_IS_ACTIVE_HIGH     0x0
#define INTERRUPT_IS_ACTIVE_LOW      0x1

#define TIMER_MODE      INTERRUPT_IS_LEVEL_TRIGGERED
#define TIMER_POLARITY  INTERRUPT_IS_ACTIVE_LOW

#define TIMER_IS_SECURE     0x1

#define TIMER_IS_ALWAYS_ON_CAPABLE   0x1

/* Timer platform config parameters */
#define PLATFORM_OVERRIDE_S_EL1_TIMER_FLAGS     ((TIMER_POLARITY << 1) | (TIMER_MODE << 0))
#define PLATFORM_OVERRIDE_NS_EL1_TIMER_FLAGS    ((TIMER_POLARITY << 1) | (TIMER_MODE << 0))
#define PLATFORM_OVERRIDE_NS_EL2_TIMER_FLAGS    ((TIMER_POLARITY << 1) | (TIMER_MODE << 0))
#define PLATFORM_OVERRIDE_VIRTUAL_TIMER_FLAGS   ((TIMER_POLARITY << 1) | (TIMER_MODE << 0))
#define PLATFORM_OVERRIDE_S_EL1_TIMER_GSIV      0x1D
#define PLATFORM_OVERRIDE_NS_EL1_TIMER_GSIV     0x1E
#define PLATFORM_OVERRIDE_NS_EL2_TIMER_GSIV     0x1A
#define PLATFORM_OVERRIDE_VIRTUAL_TIMER_GSIV    0x1B
#define PLATFORM_OVERRIDE_EL2_VIR_TIMER_GSIV    0
#define PLATFORM_OVERRIDE_PLATFORM_TIMER_COUNT  0x3

#define PLATFORM_OVERRIDE_SYS_TIMER_TYPE        0x2001
#define PLATFORM_OVERRIDE_TIMER_TYPE            PLATFORM_OVERRIDE_SYS_TIMER_TYPE
#define PLATFORM_OVERRIDE_TIMER_COUNT           0x2
#define PLATFORM_OVERRIDE_TIMER_CNTCTL_BASE     0x2a810000

#define PLATFORM_OVERRIDE_TIMER_CNTBASE_0       0x2a830000
#define PLATFORM_OVERRIDE_TIMER_CNTEL0BASE_0    0xFFFFFFFFFFFFFFFF
#define PLATFORM_OVERRIDE_TIMER_GSIV_0          0x6d
#define PLATFORM_OVERRIDE_TIMER_VIRT_GSIV_0     0x0
#define PLATFORM_OVERRIDE_TIMER_PHY_FLAGS_0     0x0
#define PLATFORM_OVERRIDE_TIMER_VIRT_FLAGS_0    0x0
#define PLATFORM_OVERRIDE_TIMER_CMN_FLAGS_0     ((TIMER_IS_ALWAYS_ON_CAPABLE << 1) | (!TIMER_IS_SECURE << 0))
#define PLATFORM_OVERRIDE_TIMER_FLAGS_0         ((PLATFORM_OVERRIDE_TIMER_CMN_FLAGS_0 << 16) | \
                                                 (PLATFORM_OVERRIDE_TIMER_VIRT_FLAGS_0 << 8) | \
                                                 (PLATFORM_OVERRIDE_TIMER_PHY_FLAGS_0))

#define PLATFORM_OVERRIDE_TIMER_CNTBASE_1       0x2a820000
#define PLATFORM_OVERRIDE_TIMER_CNTEL0BASE_1    0xFFFFFFFFFFFFFFFF
#define PLATFORM_OVERRIDE_TIMER_GSIV_1          0x6c
#define PLATFORM_OVERRIDE_TIMER_VIRT_GSIV_1     0x0
#define PLATFORM_OVERRIDE_TIMER_PHY_FLAGS_1     0x0
#define PLATFORM_OVERRIDE_TIMER_VIRT_FLAGS_1    0x0
#define PLATFORM_OVERRIDE_TIMER_CMN_FLAGS_1     ((TIMER_IS_ALWAYS_ON_CAPABLE << 1) | (TIMER_IS_SECURE << 0))
#define PLATFORM_OVERRIDE_TIMER_FLAGS_1         ((PLATFORM_OVERRIDE_TIMER_CMN_FLAGS_1 << 16) | \
                                                 (PLATFORM_OVERRIDE_TIMER_VIRT_FLAGS_1 << 8) | \
                                                 (PLATFORM_OVERRIDE_TIMER_PHY_FLAGS_1))
#define PLATFORM_OVERRIDE_TIMER_CNTFRQ         0x0

/* Define the Timeout values to be used */
#define PLATFORM_OVERRIDE_TIMEOUT_LARGE         0x100000
#define PLATFORM_OVERRIDE_TIMEOUT_MEDIUM        0x10000
#define PLATFORM_OVERRIDE_TIMEOUT_SMALL         0x100

/* PCIE platform config parameters */
#define PLATFORM_OVERRIDE_NUM_ECAM                1

/* Offset from the memory range to be accesed
 * Modify this macro w.r.t to the requirement */
#define MEM_OFFSET_SMALL   0x10
#define MEM_OFFSET_MEDIUM  0x1000

/* Platform config parameters for ECAM_0 */
#define PLATFORM_OVERRIDE_PCIE_ECAM_BASE_ADDR_0   0x4000000000
#define PLATFORM_OVERRIDE_PCIE_SEGMENT_GRP_NUM_0  0x0
#define PLATFORM_OVERRIDE_PCIE_START_BUS_NUM_0    0x0
#define PLATFORM_OVERRIDE_PCIE_END_BUS_NUM_0      0x11

#define PLATFORM_OVERRIDE_PCIE_MAX_BUS      0x12
#define PLATFORM_OVERRIDE_PCIE_MAX_DEV      32
#define PLATFORM_OVERRIDE_PCIE_MAX_FUNC     8

/* Sample macros for ECAM_1
 * #define PLATFORM_OVERRIDE_PCIE_ECAM_BASE_ADDR_1  0x00000000
 * #define PLATFORM_OVERRIDE_PCIE_SEGMENT_GRP_NUM_1 0x0
 * #define PLATFORM_OVERRIDE_PCIE_START_BUS_NUM_1   0x0
 * #define PLATFORM_OVERRIDE_PCIE_END_BUS_NUM_1     0x0
 */


/* PCIE device hierarchy table */

#define PLATFORM_PCIE_NUM_ENTRIES        38
#define PLATFORM_PCIE_P2P_NOT_SUPPORTED  1

/* PERIPHERAL platform config parameters */
#define PLATFORM_OVERRIDE_PERIPHERAL_COUNT 3  //UART + USB + SATA

#define UART_ADDRESS                     0xF9750000
#define BASE_ADDRESS_ADDRESS             0x7FF80000
#define UART_GLOBAL_SYSTEM_INTERRUPT     0x93

/* IOVIRT platform config parameters */
/* IOVIRT platform config parameters */
#define IOVIRT_ADDRESS                0xF280AC18
#define IORT_NODE_COUNT               9
#define NUM_ITS_COUNT                 4
#define IOVIRT_ITS_COUNT              1
#define IOVIRT_SMMUV3_COUNT           4
#define IOVIRT_RC_COUNT               1
#define IOVIRT_SMMUV2_COUNT           0
#define IOVIRT_NAMED_COMPONENT_COUNT  0
#define IOVIRT_PMCG_COUNT             0
#define IOVIRT_SMMUV3_0_BASE_ADDRESS  0x280000000
#define IOVIRT_SMMUV3_1_BASE_ADDRESS  0x288000000
#define IOVIRT_SMMUV3_2_BASE_ADDRESS  0x290000000
#define IOVIRT_SMMUV3_3_BASE_ADDRESS  0x298000000
#define IOVIRT_SMMU_CTX_INT_OFFSET    0x0
#define IOVIRT_SMMU_CTX_INT_CNT       0x0
#define IOVIRT_RC_PCI_SEG_NUM         0x0
#define IOVIRT_RC_MEMORY_PROPERTIES   0x0
#define IOVIRT_RC_ATS_ATTRIBUTE       0x1

#define RC_MAP0_INPUT_BASE            0x0
#define RC_MAP0_ID_COUNT              0x8FF
#define RC_MAP0_OUTPUT_BASE           0x40000
#define RC_MAP0_OUTPUT_REF            0x488
#define RC_MAP1_INPUT_BASE            0x900
#define RC_MAP1_ID_COUNT              0x2FF
#define RC_MAP1_OUTPUT_BASE           0x40900
#define RC_MAP1_OUTPUT_REF            0x5B4
#define RC_MAP2_INPUT_BASE            0xC00
#define RC_MAP2_ID_COUNT              0x2FF
#define RC_MAP2_OUTPUT_BASE           0x40C00
#define RC_MAP2_OUTPUT_REF            0x6E0
#define RC_MAP3_INPUT_BASE            0xF00
#define RC_MAP3_ID_COUNT              0x2FF
#define RC_MAP3_OUTPUT_BASE           0x40F00
#define RC_MAP3_OUTPUT_REF            0x80C

#define SMMUV3_0_ID_MAP0_INPUT_BASE   0x0
#define SMMUV3_0_ID_MAP0_ID_COUNT     0x0
#define SMMUV3_0_ID_MAP0_OUTPUT_BASE  0x80000
#define SMMUV3_0_ID_MAP0_OUTPUT_REF   0x18
#define SMMUV3_0_ID_MAP1_INPUT_BASE   0x40000
#define SMMUV3_0_ID_MAP1_ID_COUNT     0x8FF
#define SMMUV3_0_ID_MAP1_OUTPUT_BASE  0x40000
#define SMMUV3_0_ID_MAP1_OUTPUT_REF   0x18

#define SMMUV3_1_ID_MAP0_INPUT_BASE   0x0
#define SMMUV3_1_ID_MAP0_ID_COUNT     0x0
#define SMMUV3_1_ID_MAP0_OUTPUT_BASE  0x80000
#define SMMUV3_1_ID_MAP0_OUTPUT_REF   0x134
#define SMMUV3_1_ID_MAP1_INPUT_BASE   0x40900
#define SMMUV3_1_ID_MAP1_ID_COUNT     0x2FF
#define SMMUV3_1_ID_MAP1_OUTPUT_BASE  0x40900
#define SMMUV3_1_ID_MAP1_OUTPUT_REF   0x134

#define SMMUV3_2_ID_MAP0_INPUT_BASE   0x0
#define SMMUV3_2_ID_MAP0_ID_COUNT     0x0
#define SMMUV3_2_ID_MAP0_OUTPUT_BASE  0x80000
#define SMMUV3_2_ID_MAP0_OUTPUT_REF   0x250
#define SMMUV3_2_ID_MAP1_INPUT_BASE   0x40C00
#define SMMUV3_2_ID_MAP1_ID_COUNT     0x2FF
#define SMMUV3_2_ID_MAP1_OUTPUT_BASE  0x40C00
#define SMMUV3_2_ID_MAP1_OUTPUT_REF   0x250

#define SMMUV3_3_ID_MAP0_INPUT_BASE   0x0
#define SMMUV3_3_ID_MAP0_ID_COUNT     0x0
#define SMMUV3_3_ID_MAP0_OUTPUT_BASE  0x80000
#define SMMUV3_3_ID_MAP0_OUTPUT_REF   0x36C
#define SMMUV3_3_ID_MAP1_INPUT_BASE   0x40F00
#define SMMUV3_3_ID_MAP1_ID_COUNT     0x2FF
#define SMMUV3_3_ID_MAP1_OUTPUT_BASE  0x40F00
#define SMMUV3_3_ID_MAP1_OUTPUT_REF   0x36C

#define IOVIRT_RC_NUM_MAP             4
#define IOVIRT_SMMUV3_0_NUM_MAP       2
#define IOVIRT_SMMUV3_1_NUM_MAP       2
#define IOVIRT_SMMUV3_2_NUM_MAP       2
#define IOVIRT_SMMUV3_3_NUM_MAP       2
#define IOVIRT_MAX_NUM_MAP            12


/* DMA platform config parameters */
#define PLATFORM_OVERRIDE_DMA_CNT   0

/*Exerciser platform config details*/
#define TEST_REG_COUNT              10
#define EXERCISER_ID                0xED0113B5
#define PCIE_CAP_CTRL_OFFSET        0x4// offset from the extended capability header

/* Exerciser MMIO Offsets */
#define INTXCTL         0x004
#define MSICTL          0x000
#define DMACTL1         0x08
#define DMA_BUS_ADDR    0x010
#define DMA_LEN         0x018
#define DMASTATUS       0x01C
#define PCI_MAX_BUS     255
#define PCI_MAX_DEVICE  31
#define PASID_VAL       0x020
#define ATSCTL          0x024
#define TXN_TRACE       0x40
#define TXN_CTRL_BASE   0x44
#define ATS_ADDR        0x028

#define PCI_EXT_CAP_ID  0x10
#define PASID           0x1B
#define PCIE            0x1
#define PCI             0x0

/* PCI/PCIe express extended capability structure's
   next capability pointer mask and cap ID mask */
#define PCIE_NXT_CAP_PTR_MASK 0x0FFF
#define PCIE_CAP_ID_MASK      0xFFFF
#define PCI_CAP_ID_MASK       0x00FF
#define PCI_NXT_CAP_PTR_MASK  0x00FF
#define CAP_PTR_MASK          0x00FF

#define CLR_INTR_MASK       0xFFFFFFFE
#define PASID_TLP_STOP_MASK 0xFFFFFFBF
#define PASID_VAL_MASK      ((0x1ul << 20) - 1)
#define PASID_VAL_SHIFT     12
#define PASID_LEN_SHIFT     7
#define PASID_LEN_MASK      0x7ul
#define PASID_EN_SHIFT      6
#define DMA_TO_DEVICE_MASK  0xFFFFFFEF

/* shift_bit */
#define SHIFT_1BIT             1
#define SHIFT_2BIT             2
#define SHIFT_4BIT             4
#define SHITT_8BIT             8
#define MASK_BIT               1
#define PREFETCHABLE_BIT_SHIFT 3

#define PCI_CAP_PTR_OFFSET  8
#define PCIE_CAP_PTR_OFFSET 20

#define MSI_GENERATION_MASK (1 << 31)

#define NO_SNOOP_START_MASK 0x20
#define NO_SNOOP_STOP_MASK  0xFFFFFFDF
#define PCIE_CAP_DIS_MASK   0xFFFEFFFF
#define PCIE_CAP_EN_MASK    (1 << 16)
#define PASID_EN_MASK       (1 << 6)

/* PCIe Config space Offset */
#define BAR0_OFFSET        0x10
#define COMMAND_REG_OFFSET 0x04
#define CAP_PTR_OFFSET     0x34
#define PCIE_CAP_OFFSET    0x100

#define RID_CTL_REG    0x3C
#define RID_VALUE_MASK 0xFFFF
#define RID_VALID_MASK (1ul << 31)
#define RID_VALID      1
#define RID_NOT_VALID  0
#define ATS_TRIGGER    1
#define ATS_STATUS     (1ul << 7)
#define TXN_INVALID    0xFFFFFFFF
#define TXN_START      1
#define TXN_STOP       0

#define PCIE_CAP_CTRL_OFFSET 0x4// offset from the extended capability header
