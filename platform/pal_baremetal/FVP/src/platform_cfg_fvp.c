/** @file
 * Copyright (c) 2022-2023, Arm Limited or its affiliates. All rights reserved.
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

#include "../include/pal_common_support.h"
#include "include/platform_override_struct.h"

PE_INFO_TABLE platform_pe_cfg = {

    .header.num_of_pe = PLATFORM_OVERRIDE_PE_CNT,
    .pe_info[0].pe_num      = PLATFORM_OVERRIDE_PE0_INDEX,
    .pe_info[0].mpidr       = PLATFORM_OVERRIDE_PE0_MPIDR,

    .pe_info[1].pe_num      = PLATFORM_OVERRIDE_PE1_INDEX,
    .pe_info[1].mpidr       = PLATFORM_OVERRIDE_PE1_MPIDR,

    .pe_info[2].pe_num      = PLATFORM_OVERRIDE_PE2_INDEX,
    .pe_info[2].mpidr       = PLATFORM_OVERRIDE_PE2_MPIDR,

    .pe_info[3].pe_num      = PLATFORM_OVERRIDE_PE3_INDEX,
    .pe_info[3].mpidr       = PLATFORM_OVERRIDE_PE3_MPIDR,

    .pe_info[4].pe_num      = PLATFORM_OVERRIDE_PE4_INDEX,
    .pe_info[4].mpidr       = PLATFORM_OVERRIDE_PE4_MPIDR,

    .pe_info[5].pe_num      = PLATFORM_OVERRIDE_PE5_INDEX,
    .pe_info[5].mpidr       = PLATFORM_OVERRIDE_PE5_MPIDR,

    .pe_info[6].pe_num      = PLATFORM_OVERRIDE_PE6_INDEX,
    .pe_info[6].mpidr       = PLATFORM_OVERRIDE_PE6_MPIDR,

    .pe_info[7].pe_num      = PLATFORM_OVERRIDE_PE7_INDEX,
    .pe_info[7].mpidr       = PLATFORM_OVERRIDE_PE7_MPIDR,

    .pe_info[8].pe_num      = PLATFORM_OVERRIDE_PE8_INDEX,
    .pe_info[8].mpidr       = PLATFORM_OVERRIDE_PE8_MPIDR,

    .pe_info[9].pe_num      = PLATFORM_OVERRIDE_PE9_INDEX,
    .pe_info[9].mpidr       = PLATFORM_OVERRIDE_PE9_MPIDR,

    .pe_info[10].pe_num     = PLATFORM_OVERRIDE_PE10_INDEX,
    .pe_info[10].mpidr      = PLATFORM_OVERRIDE_PE10_MPIDR,

    .pe_info[11].pe_num     = PLATFORM_OVERRIDE_PE11_INDEX,
    .pe_info[11].mpidr      = PLATFORM_OVERRIDE_PE11_MPIDR,

    .pe_info[12].pe_num     = PLATFORM_OVERRIDE_PE12_INDEX,
    .pe_info[12].mpidr      = PLATFORM_OVERRIDE_PE12_MPIDR,

    .pe_info[13].pe_num     = PLATFORM_OVERRIDE_PE13_INDEX,
    .pe_info[13].mpidr      = PLATFORM_OVERRIDE_PE13_MPIDR,

    .pe_info[14].pe_num     = PLATFORM_OVERRIDE_PE14_INDEX,
    .pe_info[14].mpidr      = PLATFORM_OVERRIDE_PE14_MPIDR,

    .pe_info[15].pe_num     = PLATFORM_OVERRIDE_PE15_INDEX,
    .pe_info[15].mpidr      = PLATFORM_OVERRIDE_PE15_MPIDR,

};


PLATFORM_OVERRIDE_GIC_INFO_TABLE platform_gic_cfg = {

    .gic_version   = PLATFORM_OVERRIDE_GIC_VERSION,
    .num_gicc      = PLATFORM_OVERRIDE_GICC_COUNT,
    .num_gicd      = PLATFORM_OVERRIDE_GICD_COUNT,
    .num_gicrd     = PLATFORM_OVERRIDE_GICRD_COUNT,
    .num_gicits    = PLATFORM_OVERRIDE_GICITS_COUNT,
    .num_gich      = PLATFORM_OVERRIDE_GICH_COUNT,
    .num_msiframes = PLATFORM_OVERRIDE_GICMSIFRAME_COUNT,

    .gicrd_length = PLATFORM_OVERRIDE_GICIRD_LENGTH,

    .gicc_base[0]   = PLATFORM_OVERRIDE_GICC_BASE,
    .gicc_base[1]   = PLATFORM_OVERRIDE_GICC_BASE,
    .gicc_base[2]   = PLATFORM_OVERRIDE_GICC_BASE,
    .gicc_base[3]   = PLATFORM_OVERRIDE_GICC_BASE,
    .gicc_base[4]   = PLATFORM_OVERRIDE_GICC_BASE,
    .gicc_base[5]   = PLATFORM_OVERRIDE_GICC_BASE,
    .gicc_base[6]   = PLATFORM_OVERRIDE_GICC_BASE,
    .gicc_base[7]   = PLATFORM_OVERRIDE_GICC_BASE,
    .gicc_base[8]   = PLATFORM_OVERRIDE_GICC_BASE,
    .gicc_base[9]   = PLATFORM_OVERRIDE_GICC_BASE,
    .gicc_base[10]  = PLATFORM_OVERRIDE_GICC_BASE,
    .gicc_base[11]  = PLATFORM_OVERRIDE_GICC_BASE,
    .gicc_base[12]  = PLATFORM_OVERRIDE_GICC_BASE,
    .gicc_base[13]  = PLATFORM_OVERRIDE_GICC_BASE,
    .gicc_base[14]  = PLATFORM_OVERRIDE_GICC_BASE,
    .gicc_base[15]  = PLATFORM_OVERRIDE_GICC_BASE,

    .gicd_base[0]   = PLATFORM_OVERRIDE_GICD_BASE,
    .gicrd_base[0]  = PLATFORM_OVERRIDE_GICRD_BASE,
    .gicits_base[0] = PLATFORM_OVERRIDE_GICITS0_BASE,
    .gicits_id[0]   = PLATFORM_OVERRIDE_GICITS0_ID,
    .gicits_base[1] = PLATFORM_OVERRIDE_GICITS1_BASE,
    .gicits_id[1]   = PLATFORM_OVERRIDE_GICITS1_ID,
    .gicits_base[2] = PLATFORM_OVERRIDE_GICITS2_BASE,
    .gicits_id[2]   = PLATFORM_OVERRIDE_GICITS2_ID,
    .gicits_base[3] = PLATFORM_OVERRIDE_GICITS3_BASE,
    .gicits_id[3]   = PLATFORM_OVERRIDE_GICITS3_ID,
    .gicits_base[4] = PLATFORM_OVERRIDE_GICITS4_BASE,
    .gicits_id[4]   = PLATFORM_OVERRIDE_GICITS4_ID,
    .gicits_base[5] = PLATFORM_OVERRIDE_GICITS5_BASE,
    .gicits_id[5]   = PLATFORM_OVERRIDE_GICITS5_ID,
    .gich_base[0]   = PLATFORM_OVERRIDE_GICH_BASE

};

PLATFORM_OVERRIDE_TIMER_INFO_TABLE platform_timer_cfg = {

    .header.s_el1_timer_flags   = PLATFORM_OVERRIDE_S_EL1_TIMER_FLAGS,
    .header.ns_el1_timer_flags  = PLATFORM_OVERRIDE_NS_EL1_TIMER_FLAGS,
    .header.el2_timer_flags     = PLATFORM_OVERRIDE_NS_EL2_TIMER_FLAGS,
    .header.s_el1_timer_gsiv    = PLATFORM_OVERRIDE_S_EL1_TIMER_GSIV,
    .header.ns_el1_timer_gsiv   = PLATFORM_OVERRIDE_NS_EL1_TIMER_GSIV,
    .header.el2_timer_gsiv      = PLATFORM_OVERRIDE_NS_EL2_TIMER_GSIV,
    .header.virtual_timer_flags = PLATFORM_OVERRIDE_VIRTUAL_TIMER_FLAGS,
    .header.virtual_timer_gsiv  = PLATFORM_OVERRIDE_VIRTUAL_TIMER_GSIV,
    .header.el2_virt_timer_gsiv = PLATFORM_OVERRIDE_EL2_VIR_TIMER_GSIV,
    .header.num_platform_timer  = PLATFORM_OVERRIDE_PLATFORM_TIMER_COUNT,

    .gt_info.type               = PLATFORM_OVERRIDE_TIMER_TYPE,
    .gt_info.timer_count        = PLATFORM_OVERRIDE_TIMER_COUNT,
    .gt_info.block_cntl_base    = PLATFORM_OVERRIDE_TIMER_CNTCTL_BASE,
    .gt_info.GtCntBase[0]       = PLATFORM_OVERRIDE_TIMER_CNTBASE_0,
    .gt_info.GtCntBase[1]       = PLATFORM_OVERRIDE_TIMER_CNTBASE_1,
    .gt_info.GtCntEl0Base[0]    = PLATFORM_OVERRIDE_TIMER_CNTEL0BASE_0,
    .gt_info.GtCntEl0Base[1]    = PLATFORM_OVERRIDE_TIMER_CNTEL0BASE_1,
    .gt_info.gsiv[0]            = PLATFORM_OVERRIDE_TIMER_GSIV_0,
    .gt_info.gsiv[1]            = PLATFORM_OVERRIDE_TIMER_GSIV_1,
    .gt_info.virt_gsiv[0]       = PLATFORM_OVERRIDE_TIMER_VIRT_GSIV_0,
    .gt_info.virt_gsiv[1]       = PLATFORM_OVERRIDE_TIMER_VIRT_GSIV_1,
    .gt_info.flags[0]           = PLATFORM_OVERRIDE_TIMER_FLAGS_0,
    .gt_info.flags[1]           = PLATFORM_OVERRIDE_TIMER_FLAGS_1

};


PCIE_INFO_TABLE platform_pcie_cfg = {
    .num_entries             = PLATFORM_OVERRIDE_NUM_ECAM,
    .block[0].ecam_base      = PLATFORM_OVERRIDE_PCIE_ECAM_BASE_ADDR_0,
    .block[0].segment_num    = PLATFORM_OVERRIDE_PCIE_SEGMENT_GRP_NUM_0,
    .block[0].start_bus_num  = PLATFORM_OVERRIDE_PCIE_START_BUS_NUM_0,
    .block[0].end_bus_num    = PLATFORM_OVERRIDE_PCIE_END_BUS_NUM_0

/** Configure more PCIe info details as per specification for more than 1 ECAM
    Refer to platform_override_fvp.h file for an example
**/
};

PLATFORM_OVERRIDE_IOVIRT_INFO_TABLE platform_iovirt_cfg = {
    .Address               = IOVIRT_ADDRESS,
    .node_count            = IORT_NODE_COUNT,
    .type[0]               = IOVIRT_NODE_ITS_GROUP,
    .type[1]               = IOVIRT_NODE_ITS_GROUP,
    .type[2]               = IOVIRT_NODE_ITS_GROUP,
    .type[3]               = IOVIRT_NODE_ITS_GROUP,
    .type[4]               = IOVIRT_NODE_SMMU_V3,
    .type[5]               = IOVIRT_NODE_SMMU_V3,
    .type[6]               = IOVIRT_NODE_SMMU_V3,
    .type[7]               = IOVIRT_NODE_SMMU_V3,
    .type[8]               = IOVIRT_NODE_PCI_ROOT_COMPLEX,
    .num_map[4]            = IOVIRT_SMMUV3_0_NUM_MAP,
    .num_map[5]            = IOVIRT_SMMUV3_1_NUM_MAP,
    .num_map[6]            = IOVIRT_SMMUV3_2_NUM_MAP,
    .num_map[7]            = IOVIRT_SMMUV3_3_NUM_MAP,
    .num_map[8]            = IOVIRT_RC_NUM_MAP,

    .map[4].input_base[0]  = SMMUV3_0_ID_MAP0_INPUT_BASE,
    .map[4].id_count[0]    = SMMUV3_0_ID_MAP0_ID_COUNT,
    .map[4].output_base[0] = SMMUV3_0_ID_MAP0_OUTPUT_BASE,
    .map[4].output_ref[0]  = SMMUV3_0_ID_MAP0_OUTPUT_REF,
    .map[4].input_base[1]  = SMMUV3_0_ID_MAP1_INPUT_BASE,
    .map[4].id_count[1]    = SMMUV3_0_ID_MAP1_ID_COUNT,
    .map[4].output_base[1] = SMMUV3_0_ID_MAP1_OUTPUT_BASE,
    .map[4].output_ref[1]  = SMMUV3_0_ID_MAP1_OUTPUT_REF,

    .map[5].input_base[0]  = SMMUV3_1_ID_MAP0_INPUT_BASE,
    .map[5].id_count[0]    = SMMUV3_1_ID_MAP0_ID_COUNT,
    .map[5].output_base[0] = SMMUV3_1_ID_MAP0_OUTPUT_BASE,
    .map[5].output_ref[0]  = SMMUV3_1_ID_MAP0_OUTPUT_REF,
    .map[5].input_base[1]  = SMMUV3_1_ID_MAP1_INPUT_BASE,
    .map[5].id_count[1]    = SMMUV3_1_ID_MAP1_ID_COUNT,
    .map[5].output_base[1] = SMMUV3_1_ID_MAP1_OUTPUT_BASE,
    .map[5].output_ref[1]  = SMMUV3_1_ID_MAP1_OUTPUT_REF,


    .map[6].input_base[0]  = SMMUV3_2_ID_MAP0_INPUT_BASE,
    .map[6].id_count[0]    = SMMUV3_2_ID_MAP0_ID_COUNT,
    .map[6].output_base[0] = SMMUV3_2_ID_MAP0_OUTPUT_BASE,
    .map[6].output_ref[0]  = SMMUV3_2_ID_MAP0_OUTPUT_REF,
    .map[6].input_base[1]  = SMMUV3_2_ID_MAP1_INPUT_BASE,
    .map[6].id_count[1]    = SMMUV3_2_ID_MAP1_ID_COUNT,
    .map[6].output_base[1] = SMMUV3_2_ID_MAP1_OUTPUT_BASE,
    .map[6].output_ref[1]  = SMMUV3_2_ID_MAP1_OUTPUT_REF,


    .map[7].input_base[0]  = SMMUV3_3_ID_MAP0_INPUT_BASE,
    .map[7].id_count[0]    = SMMUV3_3_ID_MAP0_ID_COUNT,
    .map[7].output_base[0] = SMMUV3_3_ID_MAP0_OUTPUT_BASE,
    .map[7].output_ref[0]  = SMMUV3_3_ID_MAP0_OUTPUT_REF,
    .map[7].input_base[1]  = SMMUV3_3_ID_MAP1_INPUT_BASE,
    .map[7].id_count[1]    = SMMUV3_3_ID_MAP1_ID_COUNT,
    .map[7].output_base[1] = SMMUV3_3_ID_MAP1_OUTPUT_BASE,
    .map[7].output_ref[1]  = SMMUV3_3_ID_MAP1_OUTPUT_REF,

    .map[8].input_base[0]  = RC_MAP0_INPUT_BASE,
    .map[8].id_count[0]    = RC_MAP0_ID_COUNT,
    .map[8].output_base[0] = RC_MAP0_OUTPUT_BASE,
    .map[8].output_ref[0]  = RC_MAP0_OUTPUT_REF,
    .map[8].input_base[1]  = RC_MAP1_INPUT_BASE,
    .map[8].id_count[1]    = RC_MAP1_ID_COUNT,
    .map[8].output_base[1] = RC_MAP1_OUTPUT_BASE,
    .map[8].output_ref[1]  = RC_MAP1_OUTPUT_REF,
    .map[8].input_base[2]  = RC_MAP2_INPUT_BASE,
    .map[8].id_count[2]    = RC_MAP2_ID_COUNT,
    .map[8].output_base[2] = RC_MAP2_OUTPUT_BASE,
    .map[8].output_ref[2]  = RC_MAP2_OUTPUT_REF,
    .map[8].input_base[3]  = RC_MAP3_INPUT_BASE,
    .map[8].id_count[3]    = RC_MAP3_ID_COUNT,
    .map[8].output_base[3] = RC_MAP3_OUTPUT_BASE,
    .map[8].output_ref[3]  = RC_MAP3_OUTPUT_REF


};

PLATFORM_OVERRIDE_NODE_DATA platform_node_type = {
    .its_count                        = IOVIRT_ITS_COUNT,
    .smmu[0].base                     = IOVIRT_SMMUV3_0_BASE_ADDRESS,
    .smmu[1].base                     = IOVIRT_SMMUV3_1_BASE_ADDRESS,
    .smmu[2].base                     = IOVIRT_SMMUV3_2_BASE_ADDRESS,
    .smmu[3].base                     = IOVIRT_SMMUV3_3_BASE_ADDRESS,
    .smmu[0].context_interrupt_offset = IOVIRT_SMMU_CTX_INT_OFFSET,
    .smmu[0].context_interrupt_count  = IOVIRT_SMMU_CTX_INT_CNT,
    .rc.segment                       = IOVIRT_RC_PCI_SEG_NUM,
    .rc.cca                           = IOVIRT_RC_MEMORY_PROPERTIES,
    .rc.ats_attr                      = IOVIRT_RC_ATS_ATTRIBUTE

};

PLATFORM_OVERRIDE_UART_INFO_TABLE platform_uart_cfg = {
    .Address               = UART_ADDRESS,
    .BaseAddress.Address   = BASE_ADDRESS_ADDRESS,
    .GlobalSystemInterrupt = UART_GLOBAL_SYSTEM_INTERRUPT,
};

DMA_INFO_TABLE platform_dma_cfg = {
    .num_dma_ctrls = PLATFORM_OVERRIDE_DMA_CNT

    /** Place holder
    .info[0].target = TARGET,
    .info[0].port = PORT,
    .info[0].host = HOST,
    .info[0].flags = FLAGS,
    .info[0].type = TYPE**/
};
