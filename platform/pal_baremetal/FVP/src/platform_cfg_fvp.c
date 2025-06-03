/** @file
 * Copyright (c) 2022-2025, Arm Limited or its affiliates. All rights reserved.
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

/* Populate the skip array with the module or test names to be excluded from the run */
char8_t *g_skip_test_str[MAX_TEST_SKIP_NUM] = {
    "rme", "gic", "smmu", "legacy",
    "da_autonomous_rootport_request_ns_pas",
    SKIP_TEST_SENTINEL, SKIP_TEST_SENTINEL, SKIP_TEST_SENTINEL,
    SKIP_TEST_SENTINEL, SKIP_TEST_SENTINEL
};
char8_t *g_single_test_str = SINGLE_TEST_SENTINEL_STR;
char8_t *g_single_module_str = SINGLE_MODULE_SENTINEL_STR;

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
    .pe_info[7].mpidr       = PLATFORM_OVERRIDE_PE7_MPIDR
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

    .gicd_base[0]   = PLATFORM_OVERRIDE_GICD_BASE,
    .gicrd_base[0]  = PLATFORM_OVERRIDE_GICRD_BASE,
    .gicits_base[0] = PLATFORM_OVERRIDE_GICITS0_BASE,
    .gicits_id[0]   = PLATFORM_OVERRIDE_GICITS0_ID
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
};

PCIE_READ_TABLE platform_pcie_device_hierarchy = {
    .num_entries             = PLATFORM_PCIE_NUM_ENTRIES,

    .device[0].class_code    = PLATFORM_PCIE_DEV0_CLASSCODE,
    .device[0].vendor_id     = PLATFORM_PCIE_DEV0_VENDOR_ID,
    .device[0].device_id     = PLATFORM_PCIE_DEV0_DEV_ID,
    .device[0].bus           = PLATFORM_PCIE_DEV0_BUS_NUM,
    .device[0].dev           = PLATFORM_PCIE_DEV0_DEV_NUM,
    .device[0].func          = PLATFORM_PCIE_DEV0_FUNC_NUM,
    .device[0].seg           = PLATFORM_PCIE_DEV0_SEG_NUM,
    .device[0].dma_support   = PLATFORM_PCIE_DEV0_DMA_SUPPORT,
    .device[0].dma_coherent  = PLATFORM_PCIE_DEV0_DMA_COHERENT,
    .device[0].p2p_support   = PLATFORM_PCIE_DEV0_P2P_SUPPORT,
    .device[0].dma_64bit     = PLATFORM_PCIE_DEV0_DMA_64BIT,
    .device[0].behind_smmu   = PLATFORM_PCIE_DEV0_BEHIND_SMMU,
    .device[0].atc_present   = PLATFORM_PCIE_DEV0_ATC_SUPPORT,

    .device[1].class_code    = PLATFORM_PCIE_DEV1_CLASSCODE,
    .device[1].vendor_id     = PLATFORM_PCIE_DEV1_VENDOR_ID,
    .device[1].device_id     = PLATFORM_PCIE_DEV1_DEV_ID,
    .device[1].bus           = PLATFORM_PCIE_DEV1_BUS_NUM,
    .device[1].dev           = PLATFORM_PCIE_DEV1_DEV_NUM,
    .device[1].func          = PLATFORM_PCIE_DEV1_FUNC_NUM,
    .device[1].seg           = PLATFORM_PCIE_DEV1_SEG_NUM,
    .device[1].dma_support   = PLATFORM_PCIE_DEV1_DMA_SUPPORT,
    .device[1].dma_coherent  = PLATFORM_PCIE_DEV1_DMA_COHERENT,
    .device[1].p2p_support   = PLATFORM_PCIE_DEV1_P2P_SUPPORT,
    .device[1].dma_64bit     = PLATFORM_PCIE_DEV1_DMA_64BIT,
    .device[1].behind_smmu   = PLATFORM_PCIE_DEV1_BEHIND_SMMU,
    .device[1].atc_present   = PLATFORM_PCIE_DEV1_ATC_SUPPORT,

    .device[2].class_code    = PLATFORM_PCIE_DEV2_CLASSCODE,
    .device[2].vendor_id     = PLATFORM_PCIE_DEV2_VENDOR_ID,
    .device[2].device_id     = PLATFORM_PCIE_DEV2_DEV_ID,
    .device[2].bus           = PLATFORM_PCIE_DEV2_BUS_NUM,
    .device[2].dev           = PLATFORM_PCIE_DEV2_DEV_NUM,
    .device[2].func          = PLATFORM_PCIE_DEV2_FUNC_NUM,
    .device[2].seg           = PLATFORM_PCIE_DEV2_SEG_NUM,
    .device[2].dma_support   = PLATFORM_PCIE_DEV2_DMA_SUPPORT,
    .device[2].dma_coherent  = PLATFORM_PCIE_DEV2_DMA_COHERENT,
    .device[2].p2p_support   = PLATFORM_PCIE_DEV2_P2P_SUPPORT,
    .device[2].dma_64bit     = PLATFORM_PCIE_DEV2_DMA_64BIT,
    .device[2].behind_smmu   = PLATFORM_PCIE_DEV2_BEHIND_SMMU,
    .device[2].atc_present   = PLATFORM_PCIE_DEV2_ATC_SUPPORT,

    .device[3].class_code    = PLATFORM_PCIE_DEV3_CLASSCODE,
    .device[3].vendor_id     = PLATFORM_PCIE_DEV3_VENDOR_ID,
    .device[3].device_id     = PLATFORM_PCIE_DEV3_DEV_ID,
    .device[3].bus           = PLATFORM_PCIE_DEV3_BUS_NUM,
    .device[3].dev           = PLATFORM_PCIE_DEV3_DEV_NUM,
    .device[3].func          = PLATFORM_PCIE_DEV3_FUNC_NUM,
    .device[3].seg           = PLATFORM_PCIE_DEV3_SEG_NUM,
    .device[3].dma_support   = PLATFORM_PCIE_DEV3_DMA_SUPPORT,
    .device[3].dma_coherent  = PLATFORM_PCIE_DEV3_DMA_COHERENT,
    .device[3].p2p_support   = PLATFORM_PCIE_DEV3_P2P_SUPPORT,
    .device[3].dma_64bit     = PLATFORM_PCIE_DEV3_DMA_64BIT,
    .device[3].behind_smmu   = PLATFORM_PCIE_DEV3_BEHIND_SMMU,
    .device[3].atc_present   = PLATFORM_PCIE_DEV3_ATC_SUPPORT,

    .device[4].class_code    = PLATFORM_PCIE_DEV4_CLASSCODE,
    .device[4].vendor_id     = PLATFORM_PCIE_DEV4_VENDOR_ID,
    .device[4].device_id     = PLATFORM_PCIE_DEV4_DEV_ID,
    .device[4].bus           = PLATFORM_PCIE_DEV4_BUS_NUM,
    .device[4].dev           = PLATFORM_PCIE_DEV4_DEV_NUM,
    .device[4].func          = PLATFORM_PCIE_DEV4_FUNC_NUM,
    .device[4].seg           = PLATFORM_PCIE_DEV4_SEG_NUM,
    .device[4].dma_support   = PLATFORM_PCIE_DEV4_DMA_SUPPORT,
    .device[4].dma_coherent  = PLATFORM_PCIE_DEV4_DMA_COHERENT,
    .device[4].p2p_support   = PLATFORM_PCIE_DEV4_P2P_SUPPORT,
    .device[4].dma_64bit     = PLATFORM_PCIE_DEV4_DMA_64BIT,
    .device[4].behind_smmu   = PLATFORM_PCIE_DEV4_BEHIND_SMMU,
    .device[4].atc_present   = PLATFORM_PCIE_DEV4_ATC_SUPPORT,

    .device[5].class_code    = PLATFORM_PCIE_DEV5_CLASSCODE,
    .device[5].vendor_id     = PLATFORM_PCIE_DEV5_VENDOR_ID,
    .device[5].device_id     = PLATFORM_PCIE_DEV5_DEV_ID,
    .device[5].bus           = PLATFORM_PCIE_DEV5_BUS_NUM,
    .device[5].dev           = PLATFORM_PCIE_DEV5_DEV_NUM,
    .device[5].func          = PLATFORM_PCIE_DEV5_FUNC_NUM,
    .device[5].seg           = PLATFORM_PCIE_DEV5_SEG_NUM,
    .device[5].dma_support   = PLATFORM_PCIE_DEV5_DMA_SUPPORT,
    .device[5].dma_coherent  = PLATFORM_PCIE_DEV5_DMA_COHERENT,
    .device[5].p2p_support   = PLATFORM_PCIE_DEV5_P2P_SUPPORT,
    .device[5].dma_64bit     = PLATFORM_PCIE_DEV5_DMA_64BIT,
    .device[5].behind_smmu   = PLATFORM_PCIE_DEV5_BEHIND_SMMU,
    .device[5].atc_present   = PLATFORM_PCIE_DEV5_ATC_SUPPORT,

    .device[6].class_code    = PLATFORM_PCIE_DEV6_CLASSCODE,
    .device[6].vendor_id     = PLATFORM_PCIE_DEV6_VENDOR_ID,
    .device[6].device_id     = PLATFORM_PCIE_DEV6_DEV_ID,
    .device[6].bus           = PLATFORM_PCIE_DEV6_BUS_NUM,
    .device[6].dev           = PLATFORM_PCIE_DEV6_DEV_NUM,
    .device[6].func          = PLATFORM_PCIE_DEV6_FUNC_NUM,
    .device[6].seg           = PLATFORM_PCIE_DEV6_SEG_NUM,
    .device[6].dma_support   = PLATFORM_PCIE_DEV6_DMA_SUPPORT,
    .device[6].dma_coherent  = PLATFORM_PCIE_DEV6_DMA_COHERENT,
    .device[6].p2p_support   = PLATFORM_PCIE_DEV6_P2P_SUPPORT,
    .device[6].dma_64bit     = PLATFORM_PCIE_DEV6_DMA_64BIT,
    .device[6].behind_smmu   = PLATFORM_PCIE_DEV6_BEHIND_SMMU,
    .device[6].atc_present   = PLATFORM_PCIE_DEV6_ATC_SUPPORT,

    .device[7].class_code    = PLATFORM_PCIE_DEV7_CLASSCODE,
    .device[7].vendor_id     = PLATFORM_PCIE_DEV7_VENDOR_ID,
    .device[7].device_id     = PLATFORM_PCIE_DEV7_DEV_ID,
    .device[7].bus           = PLATFORM_PCIE_DEV7_BUS_NUM,
    .device[7].dev           = PLATFORM_PCIE_DEV7_DEV_NUM,
    .device[7].func          = PLATFORM_PCIE_DEV7_FUNC_NUM,
    .device[7].seg           = PLATFORM_PCIE_DEV7_SEG_NUM,
    .device[7].dma_support   = PLATFORM_PCIE_DEV7_DMA_SUPPORT,
    .device[7].dma_coherent  = PLATFORM_PCIE_DEV7_DMA_COHERENT,
    .device[7].p2p_support   = PLATFORM_PCIE_DEV7_P2P_SUPPORT,
    .device[7].dma_64bit     = PLATFORM_PCIE_DEV7_DMA_64BIT,
    .device[7].behind_smmu   = PLATFORM_PCIE_DEV7_BEHIND_SMMU,
    .device[7].atc_present   = PLATFORM_PCIE_DEV7_ATC_SUPPORT,
/** Configure more PCIe info details as per specification for more than 1 ECAM
    Refer to platform_override_fvp.h file for an example
**/
};

PCIE_ROOT_INFO_TABLE platform_root_pcie_cfg = {
    .block[0].hb_enteries         = PLATFORM_OVERRIDE_PCIE_ECAM0_HB_COUNT,
    .block[0].hb_bar32_value[0]   = PLATFORM_OVERRIDE_PCIE_ECAM0_HB_BAR32,
    .block[0].hb_bar64_value[0]   = PLATFORM_OVERRIDE_PCIE_ECAM0_HB_BAR64,
    .block[0].segment_num[0]      = PLATFORM_OVERRIDE_PCIE_ECAM0_SEG_NUM,
    .block[0].start_bus_num[0]    = PLATFORM_OVERRIDE_PCIE_ECAM0_START_BUS_NUM,
    .block[0].end_bus_num[0]      = PLATFORM_OVERRIDE_PCIE_ECAM0_END_BUS_NUM,
    .block[0].ep_bar64_value[0]   = PLATFORM_OVERRIDE_PCIE_ECAM0_EP_BAR64,
    .block[0].rp_bar64_value[0]   = PLATFORM_OVERRIDE_PCIE_ECAM0_RP_BAR64,
    .block[0].ep_npbar32_value[0] = PLATFORM_OVERRIDE_PCIE_ECAM0_EP_NPBAR32,
    .block[0].ep_pbar32_value[0]  = PLATFORM_OVERRIDE_PCIE_ECAM0_EP_PBAR32,
    .block[0].rp_bar32_value[0]   = PLATFORM_OVERRIDE_PCIE_ECAM0_RP_BAR32,
};

PLATFORM_OVERRIDE_IOVIRT_INFO_TABLE platform_iovirt_cfg = {
    .Address               = IOVIRT_ADDRESS,
    .node_count            = IORT_NODE_COUNT,
    .type[0]               = IOVIRT_NODE_ITS_GROUP,
    .type[1]               = IOVIRT_NODE_SMMU_V3,
    .type[2]               = IOVIRT_NODE_PCI_ROOT_COMPLEX,
    .num_map[1]            = IOVIRT_SMMUV3_0_NUM_MAP,
    .num_map[2]            = IOVIRT_RC_NUM_MAP,

    .map[1].input_base[0]  = SMMUV3_0_ID_MAP0_INPUT_BASE,
    .map[1].id_count[0]    = SMMUV3_0_ID_MAP0_ID_COUNT,
    .map[1].output_base[0] = SMMUV3_0_ID_MAP0_OUTPUT_BASE,
    .map[1].output_ref[0]  = SMMUV3_0_ID_MAP0_OUTPUT_REF,

    .map[2].input_base[0]  = RC_MAP0_INPUT_BASE,
    .map[2].id_count[0]    = RC_MAP0_ID_COUNT,
    .map[2].output_base[0] = RC_MAP0_OUTPUT_BASE,
    .map[2].output_ref[0]  = RC_MAP0_OUTPUT_REF,

};

PLATFORM_OVERRIDE_NODE_DATA platform_node_type = {
    .its_count                        = IOVIRT_ITS_COUNT,
    .smmu[0].base                     = IOVIRT_SMMUV3_0_BASE_ADDRESS,
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
