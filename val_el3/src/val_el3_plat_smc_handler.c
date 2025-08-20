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
#include <val_el3_debug.h>
#include <val_el3_exception.h>
#include <val_el3_memory.h>
#include <val_el3_pe.h>
#include <val_el3_pgt.h>
#include <val_el3_security.h>
#include <val_el3_smmu.h>
#include <val_el3_wd.h>
#include <val_el3_mec.h>

void plat_arm_acs_smc_handler(uint64_t services, uint64_t arg0, uint64_t arg1, uint64_t arg2);

/**
 *  @brief  This API is used to branch out to all the different functions in EL3
 *          1. Caller       -  Test Suite
 *  @param  services -  The type of service to carry out the EL3 operation
 *  @param  arg0     -  The argument is specific to the test requirement
 *  @param  arg1     -  The argument is specific to the test requirement
 *  @param  arg2     -  The argument is specific to the test requirement
 *  @return None
**/
void plat_arm_acs_smc_handler(uint64_t services, uint64_t arg0, uint64_t arg1, uint64_t arg2)
{

  INFO("User SMC Call started for service = 0x%lx arg0 = 0x%lx arg1 = 0x%lx arg2 = 0x%lx \n",
        services, arg0, arg1, arg2);

  bool mapped = ((val_el3_at_s1e3w((uint64_t)shared_data)) & 0x1) != 0x1;

  if (mapped) {
    shared_data->status_code = 0;
    shared_data->error_code = 0;
    shared_data->error_msg[0] = '\0';
  }
  switch (services)
  {
    case RME_INSTALL_HANDLER:
      INFO("RME Handler Installing service \n");
      val_el3_rme_install_handler();
      break;
    case RME_ADD_GPT_ENTRY:
      INFO("RME GPT mapping service \n");
      val_el3_add_gpt_entry(arg0, arg1);
      val_el3_tlbi_paallos();
      break;
    case RME_ADD_MMU_ENTRY:
      INFO("RME MMU mapping service \n");
      if (val_el3_add_mmu_entry(arg0, arg1, arg2) == 0) {
          val_el3_tlbi_vae3(arg0);
          shared_data->status_code = 0;
          shared_data->error_code = 0;
          shared_data->error_msg[0] = '\0';
      } else {
          shared_data->status_code = 1;
          const char *msg = "EL3: MMU entry addition failed";
          int i = 0; while (msg[i] && i < sizeof(shared_data->error_msg) - 1) {
              shared_data->error_msg[i] = msg[i]; i++;
          }
          shared_data->error_msg[i] = '\0';
      }
      break;
    case RME_MAP_SHARED_MEM:
      val_el3_map_shared_mem(arg0);
      break;
    case RME_CMO_POPA:
      INFO("RME CMO to PoPA service \n");
      arg0 = val_el3_modify_desc(arg0, CIPOPA_NS_BIT, NS_SET(arg1), 1);
      arg0 = val_el3_modify_desc(arg0, CIPOPA_NSE_BIT, NSE_SET(arg1), 1);
      val_el3_cmo_cipapa(arg0);
      break;
    case RME_ACCESS_MUT:
      INFO("RME MEMORY ACCESS SERVICE\n");
      val_el3_access_mut();
      break;
    case RME_DATA_CACHE_OPS:
      INFO("RME data cache maintenance operation service \n");
      val_el3_data_cache_ops_by_va(arg0, arg1);
      break;
    case RME_MEM_SET:
      INFO("RME memory write service\n");
      val_el3_memory_set((uint64_t *)arg0, arg1, arg2);
      break;
    case RME_NS_ENCRYPTION:
      INFO("RME Non-secure Encryption Enable/Disable service\n");
      if (arg0 == SET)
        val_el3_enable_ns_encryption();
      else
        val_el3_disable_ns_encryption();
      break;
    case RME_READ_AND_CMPR_REG_MSD:
      INFO("RME Registers Read and Compare service\n");
      if (arg0 == SET) {
        val_el3_pe_reg_list_cmp_msd();
        INFO("Register comparision\n");
      } else {
        val_el3_pe_reg_read_msd();
        INFO("Register read\n");
      }
      break;
    case LEGACY_TZ_ENABLE:
      INFO("Legacy System Service\n");
      val_el3_prog_legacy_tz(arg0);
      break;
    case ROOT_WATCHDOG:
      INFO("Root watchdog service \n");
      if (shared_data->generic_flag) {
        val_el3_set_daif();
        shared_data->exception_expected = SET;
        shared_data->access_mut = CLEAR;
      }
      val_el3_wd_set_ws0(arg0, arg1, arg2);
      shared_data->generic_flag = CLEAR;
      break;
    case PAS_FILTER_SERVICE:
      INFO("PAS filter mode service \n");
      val_el3_pas_filter_active_mode(arg0);
      break;
    case SMMU_ROOT_SERVICE:
      INFO("ROOT SMMU service \n");
      if (arg1)
        val_el3_smmu_access_enable(arg0);
      else
        val_el3_smmu_access_disable(arg0);
      break;
    case SEC_STATE_CHANGE:
      INFO("Security STte change service \n");
      val_el3_security_state_change(arg0);
      break;
    case SMMU_CONFIG_SERVICE:
      INFO("SMMU ROOT Register Configuration validate \n");
      val_el3_smmu_root_config_service(arg0, arg1, arg2);
      break;
    case RME_PGT_CREATE:
      INFO("RME pgt_create service \n");
      if (val_el3_realm_pgt_create((memory_region_descriptor_t *)arg0,
                                   (pgt_descriptor_t *) arg1) != 0)
      {
          shared_data->status_code = 1;
          const char *msg = "EL3: PGT creation failed";
          int i = 0; while (msg[i] && i < sizeof(shared_data->error_msg) - 1) {
              shared_data->error_msg[i] = msg[i]; i++;
          }
          shared_data->error_msg[i] = '\0';
      }
      break;
    case RME_PGT_DESTROY:
      INFO("RME pgt_destroy service \n");
      val_el3_realm_pgt_destroy((pgt_descriptor_t *) arg0);
      break;
    case MEC_SERVICE:
      INFO("MEC Service");
      val_el3_mec_service(arg0, arg1, arg2);
      break;
    case RME_CMO_POE:
      INFO("RME CMO to PoE service \n");
      arg0 = val_el3_modify_desc(arg0, CIPAE_NS_BIT, 1, 1);
      arg0 = val_el3_modify_desc(arg0, CIPAE_NSE_BIT, 1, 1);
      val_el3_cmo_cipae(arg0);
      break;
    default:
      if (mapped) {
        shared_data->status_code = 0xFFFFFFFF;
        const char *msg = "EL3: Unknown SMC service";
        int i = 0;
        while (msg[i] && i < sizeof(shared_data->error_msg) - 1) {
              shared_data->error_msg[i] = msg[i]; i++;
        }
        shared_data->error_msg[i] = '\0';
      }
      INFO(" Service not present\n");
      break;
  }
}
