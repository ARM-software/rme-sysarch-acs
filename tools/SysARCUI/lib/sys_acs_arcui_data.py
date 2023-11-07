# @file
# Copyright (c) 2023, Arm Limited or its affiliates. All rights reserved.
# SPDX-License-Identifier : Apache-2.0
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

# Path for component reference databse to be defined with respect to environment variable
REF_DB_PATH = '/tools/SysARCUI/reference_db_rme/'

# Generated Output file names
TGT_CFG_FILE_NAME = 'target_config.yaml'
SYS_CFG_HEADER_FILE_NAME = 'platform_overrride_fvp.h'
ERROR_LOG_FILE_NAME = 'tc_error_log'

# Argument Parser data for 'gen_tgt_cfg' tool
GEN_TGT_CFG_DATA = [{
    'short_name': '-odir',
    'long_name': '--odir',
    'type': str,
    'nargs': None,
    'default': '',
    'help': 'Directory for Target config file.'
}]

# Argument Parser data for 'process_tgt_cfg' tool
PROCESS_TGT_CFG_DATA = [{
    'short_name': '-process',
    'long_name': '--process',
    'type': str,
    'nargs': '+',
    'default': ["gen_sys_cfg", "check_tgt_consistency"],
    'help': 'Processes to be implemented.'
}, {
    'short_name': '-odir',
    'long_name': '--odir',
    'type': str,
    'nargs': None,
    'default': '',
    'help': 'Output directory for generated Header file.'
}, {
    'short_name': '-itgt_cfg',
    'long_name': '--itgt_cfg',
    'type': str,
    'nargs': None,
    'default': '',
    'help': 'Input Target config file path.'
}]

# Copyright header data for System config header file
COPYRIGHT_HEADER = '/** @file\n * Copyright (c) {}, Arm Limited or its affiliates. All rights reserved.\n * SPDX-License-Identifier : Apache-2.0\n * Licensed under the Apache License, Version 2.0 (the "License");\n * you may not use this file except in compliance with the License.\n * You may obtain a copy of the License at\n *\n *  http://www.apache.org/licenses/LICENSE-2.0\n *\n * Unless required by applicable law or agreed to in writing, software\n * distributed under the License is distributed on an "AS IS" BASIS,\n * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.\n * See the License for the specific language governing permissions and\n * limitations under the License.\n**/\n\n'
