/** @file
 * Copyright (c) 2023, Arm Limited or its affiliates. All rights reserved.
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


#include "include/platform_overrride_fvp.h"
#include "include/rme_acs_val.h"
#include "include/sys_config.h"

MEM_REGN_INFO_TABLE mem_region_cfg = {

        .header.num_of_regn_gpc = GPC_PROTECTED_REGION_CNT,

    .regn_info[0].base_addr = GPC_PROTECTED_REGION_0_START_ADDR,
    .regn_info[0].regn_size = GPC_PROTECTED_REGION_0_SIZE,
    .regn_info[0].resourse_pas = GPC_PROTECTED_REGION_0_PAS,

    .regn_info[1].base_addr = GPC_PROTECTED_REGION_1_START_ADDR,
    .regn_info[1].regn_size = GPC_PROTECTED_REGION_1_SIZE,
    .regn_info[1].resourse_pas = GPC_PROTECTED_REGION_1_PAS,

    .regn_info[2].base_addr = GPC_PROTECTED_REGION_2_START_ADDR,
    .regn_info[2].regn_size = GPC_PROTECTED_REGION_2_SIZE,
    .regn_info[2].resourse_pas = GPC_PROTECTED_REGION_2_PAS,

    .regn_info[3].base_addr = GPC_PROTECTED_REGION_3_START_ADDR,
    .regn_info[3].regn_size = GPC_PROTECTED_REGION_3_SIZE,
    .regn_info[3].resourse_pas = GPC_PROTECTED_REGION_3_PAS,

};

MEM_REGN_INFO_TABLE mem_region_pas_filter_cfg = {

        .header.num_of_regn_pas_filter = PAS_PROTECTED_REGION_CNT,
    .regn_info[0].base_addr = PAS_PROTECTED_REGION_0_START_ADDR,
    .regn_info[0].regn_size = PAS_PROTECTED_REGION_0_SIZE,
    .regn_info[0].resourse_pas = PAS_PROTECTED_REGION_0_PAS,

    .regn_info[1].base_addr = PAS_PROTECTED_REGION_1_START_ADDR,
    .regn_info[1].regn_size = PAS_PROTECTED_REGION_1_SIZE,
    .regn_info[1].resourse_pas = PAS_PROTECTED_REGION_1_PAS,

    .regn_info[2].base_addr = PAS_PROTECTED_REGION_2_START_ADDR,
    .regn_info[2].regn_size = PAS_PROTECTED_REGION_2_SIZE,
    .regn_info[2].resourse_pas = PAS_PROTECTED_REGION_2_PAS,

    .regn_info[3].base_addr = PAS_PROTECTED_REGION_3_START_ADDR,
    .regn_info[3].regn_size = PAS_PROTECTED_REGION_3_SIZE,
    .regn_info[3].resourse_pas = PAS_PROTECTED_REGION_3_PAS,

};

ROOT_REGSTR_TABLE root_registers_cfg = {

        .num_reg = RT_REG_CNT,

    .rt_reg_info[0].rt_reg_base_addr = RT_REG_0_START_ADDR,
    .rt_reg_info[0].rt_reg_size = RT_REG_0_SIZE,

    .rt_reg_info[1].rt_reg_base_addr = RT_REG_1_START_ADDR,
    .rt_reg_info[1].rt_reg_size = RT_REG_1_SIZE,

    .rt_reg_info[2].rt_reg_base_addr = RT_REG_2_START_ADDR,
    .rt_reg_info[2].rt_reg_size = RT_REG_2_SIZE,

    .rt_reg_info[3].rt_reg_base_addr = RT_REG_3_START_ADDR,
    .rt_reg_info[3].rt_reg_size = RT_REG_3_SIZE,

};
