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
""" Base class of System ACS Arcui """

# ------------------------------------------------------------------------
import argparse
import os
import re
import json
from sys_acs_arcui_data import REF_DB_PATH


class SysAcsArcui:
    """ Base class for auto-generating System configuration files """

    def __init__(self):
        """ Constructor of base class """
        self.acs_home = ""
        self.ref_db_path = ""
        self.prefix = {}
        self.instances = {}
        self.tgt_cfg_dict = {}
        self.expressions = {}

    def get_parser(self, tool_data):
        """ Parse command line arguments """
        parser = argparse.ArgumentParser()
        for args in tool_data:
            parser.add_argument(
                args.get('short_name'),
                args.get('long_name'),
                type=args.get('type'),
                nargs=args.get('nargs'),
                default=args.get('default'),
                help=args.get('help'))
        return parser

    def set_ref_db_path(self):
        """ Setting and checking environment variable and Reference db path for any errors """
        nr_errors = 0
        if os.environ.get('ACS_HOME') is None:
            print("ERROR:: Environment variable 'ACS_HOME' not set")
            nr_errors += 1
            return nr_errors

        self.acs_home = os.environ.get('ACS_HOME')
        self.ref_db_path = os.path.join(self.acs_home + REF_DB_PATH)

        if not os.path.exists(self.ref_db_path):
            print("ERROR:: Path for Reference database: " + self.ref_db_path +
                  ", does not exist")
            nr_errors += 1

        return nr_errors

    def check_hex_val(self, def_val):
        """ Checks whether an input string is hexa-decimal value or not """
        try:
            int(def_val, 16)
            return True
        except ValueError:
            return False

    def replace_operators(self, expr):
        """ Replace logical operators in expressions for evaluation """
        revised_expr = expr.replace(".", "__")
        revised_expr = revised_expr.replace("&&", "and")
        revised_expr = revised_expr.replace("||", "or")
        revised_expr = revised_expr.replace("!", "not")
        revised_expr = revised_expr.replace("not=", "!=")
        return revised_expr

    def gen_comp_config_dict(self, parent, param_var=''):
        """ Generation of dictionaries containing all parameters with their default values or expressions for a specific component """
        config_dict = {}
        expressions_val = {}
        for parameters in range(0, len(parent['parameters'])):
            if parent['parameters'][parameters].get('parameters') is not None:
                sub_parent = parent['parameters'][parameters]
                sub_component = parent['parameters'][parameters]['name']
                if "<n>" in sub_component:
                    for instance_num in range(0, int(parent['n'])):
                        sub_component_instance = sub_component.replace(
                            "<n>", str(instance_num))
                        sub_param_var = f"{param_var}{sub_component_instance}__"
                        sub_config_dict, sub_expressions_val = self.gen_comp_config_dict(
                            sub_parent, param_var=sub_param_var)
                        config_dict[sub_param_var[:-2]] = sub_config_dict
                        expressions_val.update(sub_expressions_val)
                else:
                    sub_param_var = f"{param_var}{sub_component}__"
                    sub_config_dict, sub_expressions_val = self.gen_comp_config_dict(
                        sub_parent, param_var=sub_param_var)
                    config_dict[sub_param_var[:-2]] = sub_config_dict
                    expressions_val.update(sub_expressions_val)
            else:
                default_value = parent['parameters'][parameters][
                    'default_value']
                if self.check_hex_val(default_value):
                    config_dict[parent['parameters'][parameters][
                        'name']] = default_value
                else:
                    default_value = self.replace_operators(default_value)
                    if "<n>" in default_value:
                        instance = re.search(r'\d+', param_var).group()
                        default_value = default_value.replace("<n>", instance)
                    expressions_val[param_var + parent['parameters']
                                    [parameters]['name']] = default_value
        return config_dict, expressions_val

    def comp_cfg_gen(self, reference_path, component):
        """ Populate target config and expressions' dictionaries for a specific component with component name as key and derived dictionary as value """
        reference_db = {}
        try:
            with open(reference_path, 'r') as ref:
                reference_db = json.load(ref)
        except Exception as exception:
            print("ERROR:: Unable to parse json file: " + reference_path +
                  ". " + str(exception))
            return

        self.prefix[component] = reference_db['print_prefix']
        self.instances[component] = reference_db['n']

        comp_cfg_dict = {}
        comp_expr_dict = {}
        comp_cfg_dict[component], comp_expr_dict[
            component] = self.gen_comp_config_dict(reference_db)

        return comp_cfg_dict, comp_expr_dict

    def tgt_cfg_gen(self):
        """ Iterating over each component reference file inside Ref. db to generate and populate the final Target config file, as well as remove redundant pairs from expressions' dictionary """
        reference_paths = {}

        ref_files = os.listdir(self.ref_db_path)
        ordered_file_paths = sorted([
            os.path.join(self.ref_db_path, comp_file_name)
            for comp_file_name in ref_files
        ])
        for component_file in ordered_file_paths:
            if os.path.isfile(component_file) and component_file.endswith(
                    '.json'
            ) and os.path.basename(component_file) != "TC_rules.json":
                component_name = os.path.splitext(
                    os.path.basename(component_file))[0]
                reference_paths[component_name] = component_file

        for comp_name, comp_path in reference_paths.items():
            component_config, component_expr = self.comp_cfg_gen(
                comp_path, comp_name)
            self.tgt_cfg_dict.update(component_config)

            for component, expr_dict in component_expr.items():
                if bool(expr_dict):
                    self.expressions[component] = expr_dict
