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
export ACS_HOME=`pwd`

# Python modules and settings
set PY_VERSION_0=3.6.5

#module load swdev
#module load util
#module load risauto/python3.6.5/0.6
#module load python/pyyaml_py3.6.5/5.1

echo "If you want to Generate target config then type Generate otherwise type Open"
read userInput

 if [[ "$userInput" == "Generate" ]]
 then
 	$ACS_HOME/tools/SysARCUI/lib/gen_tgt_cfg -odir $ACS_HOME/arcui_output
 	echo "Generating target config"
 else
 	echo "Opening previous target config"
 fi
vim $ACS_HOME/arcui_output/target_config.yaml
$ACS_HOME/tools/SysARCUI/lib/process_tgt_cfg -process gen_sys_cfg -odir $ACS_HOME/arcui_output  -itgt_cfg $ACS_HOME/arcui_output/target_config.yaml
python3 $ACS_HOME/tools/SysARCUI/reference_db_rme/gen_struct.py

echo "Do you want to copy generated files to main database?"
echo "Type Yes to Copy now"
echo "Type No to Copy later manually"
read userInput2

 if [[ "$userInput2" == "Yes" ]]
 then
        cp $ACS_HOME/arcui_output/generated_code.c $ACS_HOME/val/src/sys_config.c
        cp $ACS_HOME/arcui_output/platform_overrride_fvp.h $ACS_HOME/val/include/platform_overrride_fvp.h
        echo "Copying Generated files"
 else
        echo "Please check generated output in $ACS_HOME/arcui_output"
 fi

