## @file
## Copyright (c) 2023, Arm Limited or its affiliates. All rights reserved.
## SPDX-License-Identifier : Apache-2.0
##
## Licensed under the Apache License, Version 2.0 (the "License");
## you may not use this file except in compliance with the License.
## You may obtain a copy of the License at
##
##  http://www.apache.org/licenses/LICENSE-2.0
##
## Unless required by applicable law or agreed to in writing, software
## distributed under the License is distributed on an "AS IS" BASIS,
## WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
## See the License for the specific language governing permissions and
## limitations under the License.


import yaml
import os
Config_file = os.environ["ACS_HOME"] + "/arcui_output/target_config.yaml"
OUT_FILE = os.environ["ACS_HOME"] + "/arcui_output/generated_code.c"
def generate_c_code():
    with open(Config_file ,'r') as yaml_file:
        defines = yaml.safe_load(yaml_file)

    code = """/** @file
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

"""

    for i in range(int(defines['GpcRegions']['CNT'],16)):
        code += f"    .regn_info[{i}].base_addr = GPC_PROTECTED_REGION_{i}_START_ADDR,\n"
        code += f"    .regn_info[{i}].regn_size = GPC_PROTECTED_REGION_{i}_SIZE,\n"
        code += f"    .regn_info[{i}].resourse_pas = GPC_PROTECTED_REGION_{i}_PAS,\n\n"

    code += """};

MEM_REGN_INFO_TABLE mem_region_pas_filter_cfg = {

        .header.num_of_regn_pas_filter = PAS_PROTECTED_REGION_CNT,
"""

    for i in range(int(defines['MemoryMap']['CNT'],16)):
        code += f"    .regn_info[{i}].base_addr = PAS_PROTECTED_REGION_{i}_START_ADDR,\n"
        code += f"    .regn_info[{i}].regn_size = PAS_PROTECTED_REGION_{i}_SIZE,\n"
        code += f"    .regn_info[{i}].resourse_pas = PAS_PROTECTED_REGION_{i}_PAS,\n\n"

    code += """};

ROOT_REGSTR_TABLE root_registers_cfg = {

        .num_reg = RT_REG_CNT,

"""
    for i in range(int(defines['RootReg']['CNT'],16)):
        code += f"    .rt_reg_info[{i}].rt_reg_base_addr = RT_REG_{i}_START_ADDR,\n"
        code += f"    .rt_reg_info[{i}].rt_reg_size = RT_REG_{i}_SIZE,\n\n"

    code += "};\n"

    return code

c_code = generate_c_code()

with open(OUT_FILE, "w") as file:
    file.write(c_code)
