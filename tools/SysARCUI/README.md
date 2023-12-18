# SysARCUI

Sys-ARCUI comprises of two tools: 'gen_tgt_cfg' and 'process_tgt_cfg'. The first tool, _gen_tgt_cfg_, facilitates the generation of a Target configuration file containing all component names and their parameters with pre-set default values. This file serves as an interface for partners to amend and input their desired values for various parameters. The second tool, _process_tgt_cfg_, takes this amended Target config file as an input and generates a header file, which can be utilised in various systems. Both the tools are designed to be easy to use and below, you'll find a more detailed explanation of how each of them works.

# gen_tgt_cfg

## Introduction:

gen_tgt_cfg is a tool that auto-generates target config file in yaml format with reference component json files as the input. The generated target config file, after being amended by partners, is used as an input to process_tgt_cfg tool to generate system config files.
The tool can auto-generate the target_config.yaml file in the specified output directory path. However if no particular path is provided, it will generate the file in a pre-defined default output directory.

## Output files:

- target_config.yaml : This is the auto-generated target configuration file for the partner implementation.

The output file shall be present in the pre-declared default directory or in the directory specified by the -odir argument.

## Input file schema (<component_name>.json):
```
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
```
NOTE: The expressions defined in the input json files should be in Python format such that 'eval()' function can be applied to evaluate those expressions.

## Output file schema (target_config.yaml)
```
<component_name>:
  <parameter_name>: '<default value for parameter>'
  <sub-component name with instance num>:
    <parameter>: '<default_value>'
```

## SYNOPSIS
```
$ACS_HOME/tools/SysARCUI/lib/gen_tgt_cfg  [options]

-odir <dir>    : Output directory for auto-generated target config file.
                 Default output path is pre-defined and hence, this argument is optional.
```

## EXAMPLES

$ACS_HOME/tools/SysARCUI/lib/gen_tgt_cfg -odir /home/xyz/outdir/

# process_tgt_cfg 

## Introduction:

process_tgt_cfg is a tool that generates system config header file and error log file with input as the target config file and component reference database. This tool can perform two processes: generation of system config header file and checking target consistency rules. However, it is optional to carry out any of these processes.
The tool can generate the system config files in the specified output directory path. However, if no particular path is provided, it will generate the file in a pre-defined default output directory.

## Output files:
```
- platform_override_fvp.h    : This is the generated system configuration header file which will be included in the other scripts of the system.
- tc_error_log               : This is an error log file which is generated on failing of the target consistency rule checks.
```
The output files shall be present in the pre-declared default directory or in the directory specified by the -odir argument.

## Input file schema:

### <target_config>.yaml:
```
<component_name>:
  <parameter_name>: '<default value for parameter>'
  <sub-component name with instance num>:
    <parameter>: '<default_value>'
```
### <TC_rules>.json:
```
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
```
## Output file schema:

### <platform_override_fvp>.h
```
#define <print-prefix>_<parameter_name> <value of parameter>
#define <print-prefix>_<sub-component name>_<parameter> <value of parameter>
```
### <tc_error_log>
```
ERROR:: Target config consistency check failed for: <name of the rule>. Expression: <rule expression> Expected value(s): <expected outcomes> Actual value: <hex value obtained upon evaluation>
```
SYNOPSIS
```
$ACS_HOME/tools/SysARCUI/lib/process_tgt_cfg  [options]

-process <processes>    : List of processes to be carried out.
                          By default, both the processes, 'gen_sys_cfg' and 'check_tgt_consistency', will be executed and hence, this argument is optional.

-odir <dir>             : Output directory for generated system config files.
                          Default output path is pre-declared and hence, this argument is optional.

-itgt_cfg <tgt_cfg>     : Input target config file.
                          Default input target config file path is pre-defined and hence, this argument is optional.
```

# EXAMPLES

Run process_tgt_cfg for gen_sys_cfg process:
```
$ACS_HOME/tools/SysARCUI/lib/process_tgt_cfg -process gen_sys_cfg -odir /home/xyz/outdir/ -itgt_cfg $ACS_HOME/tools/SysARCUI/tgt_cfg/target_config.yaml
```
Run process_tgt_cfg for check_tgt_consistency process:
```
$ACS_HOME/tools/SysARCUI/lib/process_tgt_cfg -process check_tgt_consistency -odir /home/xyz/outdir/ -itgt_cfg $ACS_HOME/tools/SysARCUI/tgt_cfg/target_config.yaml
```

# RME-ACS SysARCUI setup:

Output files can be generated by sourcing $ACS_HOME/setup.sh file which generates both target_config.yaml and platform_override_fvp.h files using the tools gen_tgt_cfg and process_tgt_cfg.

## RME-ACS reference database

RME-ACS reference data base consists of the following files:

### Output yaml file
```
- target_config.yaml  : This is the auto-generated target configuration file for the partner implementation. Partner can generate this output file freshly or use the previously generated file.
```
### Input script for generating sys_config.c
```
- gen_struct.py       : This script generates the sys_config.c file that contains the structure definitions using the target_config file's inputs of memory regions such as GPC protected, PAS protected and Memory Mapped Registers of ROOT PAS, etc..,
```
### Input (<>.json) files
```
- COMMON_FLAGS.json   : This json shall contain the PAS defines
- FeatureSupport.json : This json shall contain the information regarding the system's features such as Legacy_TZ, NS_Encryption, pas filter active mode, etc whether these features are supported or not.
- GpcRegions.json.    : This json shall contain the information regarding the System's GPC protected regions.
- MemoryMap.json      : This json shall contain the PAS protected  memory region.
- RootReg.json        : This json shall contain the Memory Mapped Registers Accessible Only by ROOT PAS.
- TC_rules.json       : This json contains the Target Consistency rules.
```

