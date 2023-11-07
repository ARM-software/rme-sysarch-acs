#########################################################################
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
##########################################################################

# ========== gen_tgt_cfg ==========

Introduction:
====================
gen_tgt_cfg is a tool that auto-generates target config file in yaml format with reference component json files as the input. The generated target config file, after being amended by partners, is used as an input to process_tgt_cfg tool to generate system config files.
The tool can auto-generate the target_config.yaml file in the specified output directory path. However if no particular path is provided, it will generate the file in a pre-defined default output directory.

Output files:
--------------------
- target_config.yaml    : This is the auto-generated target configuration file for the partner implementation.

The output file shall be present in the pre-declared default directory or in the directory specified by the -odir argument.

Input file schema (<component_name>.json):
----------------------------------------
{
    "component": "<component_name>",
    "n": <number of instances of component>,
    "print_prefix": "<print-prefix for component in output header file>",
    "parameters": [
          {
            "name": "<parameter_name>",
            "default_value": "<default value/expression for parameter>",
            "description": "<comment description of parameter>"
          },
          {
            "name": "<sub-component name>",
            "description": "<description of sub-component and its parameters>",
            "parameters": [
                {
                    "name": "<parameter_name>",
                    "default_value": "<default value/expression for parameter>",
                    "description": "<comment description of parameter>"
                }
            ]
        }
    ]
}

NOTE: The expressions defined in the input json files should be in Python format such that 'eval()' function can be applied to evaluate those expressions.

Output file schema (target_config.yaml)
----------------------------------------
<component_name>:
  <parameter_name>: '<default value for parameter>'
  <sub-component name with instance num>:
    <parameter>: '<default_value>'

SYNOPSIS
--------------------
$ACS_HOME/tools/SysARCUI/lib/gen_tgt_cfg  [options]

-odir <dir>    : Output directory for auto-generated target config file.
                 Default output path is pre-defined and hence, this argument is optional.

SETUP
--------------------
Make sure the following setup is in place, before gen_tgt_cfg tool is run:
- source syscomp_rme/setup.csh

EXAMPLES
--------------------
$ACS_HOME/tools/SysARCUI/lib/gen_tgt_cfg -odir /home/xyz/outdir/


# ========== process_tgt_cfg ==========

Introduction:
====================
process_tgt_cfg is a tool that generates system config header file and error log file with input as the target config file and component reference database. This tool can perform two processes: generation of system config header file and checking target consistency rules. However, it is optional to carry out any of these processes.
The tool can generate the system config files in the specified output directory path. However if no particular path is provided, it will generate the file in a pre-defined default output directory.

Output files:
--------------------
- platform_override_fvp.h    : This is the generated system configuration header file which will be included in the other scripts of the system.
- tc_error_log               : This is an error log file which is generated on failing of the target consistency rule checks.

The output files shall be present in the pre-declared default directory or in the directory specified by the -odir argument.

Input file schema:
-------------------------
<target_config>.yaml:
--------------------
<component_name>:
  <parameter_name>: '<default value for parameter>'
  <sub-component name with instance num>:
    <parameter>: '<default_value>'

<TC_rules>.json:
--------------------
{
    "parameters":
        [
            {
                "name": "<name of the rule>",
                "value": "<rule expression>",
                "possible_values": ["<expected outcomes>"],
                "description": "<comment description of the rule>"
           }
        ]
}

Output file schema:
-------------------------
<platform_override_fvp>.h
-------------------------
#define <print-prefix>_<parameter_name> <value of parameter>
#define <print-prefix>_<sub-component name>_<parameter> <value of parameter>

<tc_error_log>
-------------------------
ERROR:: Target config consistency check failed for: <name of the rule>. Expression: <rule expression> Expected value(s): <expected outcomes> Actual value: <hex value obtained upon evaluation>

SYNOPSIS
-------------------------
$ACS_HOME/tools/SysARCUI/lib/process_tgt_cfg  [options]

-process <processes>    : List of processes to be carried out.
                          By default, both the processes, 'gen_sys_cfg' and 'check_tgt_consistency', will be executed and hence, this argument is optional.

-odir <dir>             : Output directory for generated system config files.
                          Default output path is pre-declared and hence, this argument is optional.

-itgt_cfg <tgt_cfg>     : Input target config file.
                          Default input target config file path is pre-defined and hence, this argument is optional.

SETUP
-------------------------
Make sure the following setup is in place, before process_tgt_cfg tool is run:
- source rme-acs/setup.sh

EXAMPLES
-------------------------
Run process_tgt_cfg for gen_sys_cfg process:
$ACS_HOME/tools/SysARCUI/lib/process_tgt_cfg -process gen_sys_cfg -odir /home/xyz/outdir/ -itgt_cfg $ACS_HOME/tools/SysARCUI/tgt_cfg/target_config.yaml

Run process_tgt_cfg for check_tgt_consistency process:
$ACS_HOME/tools/SysARCUI/lib/process_tgt_cfg -process check_tgt_consistency -odir /home/xyz/outdir/ -itgt_cfg $ACS_HOME/tools/SysARCUI/tgt_cfg/target_config.yaml

