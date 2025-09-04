/** @file
  * Copyright (c) 2025, Arm Limited or its affiliates. All rights reserved.
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
#include <val_el3_mec.h>
#include <val_el3_pe.h>
#include <val_el3_memory.h>

/**
 * @brief Query architectural support for MEC feature.
 *
 * @return 1 if MEC is supported, 0 otherwise.
 */
unsigned int val_el3_is_mec_supported(void)
{
    return (unsigned int)(val_el3_read_id_aa64mmfr3_el1() >>
        ID_AA64MMFR3_EL1_MEC_SHIFT) & ID_AA64MMFR3_EL1_MEC_MASK;
}

/**
 * @brief Check if SCTLRx extensions are supported (internal helper).
 *
 * @return 1 if supported, 0 otherwise.
 */
static unsigned int val_el3_is_sctlrx_supported(void)
{
    return (unsigned int)((val_el3_read_id_aa64mmfr3_el1() >>
        ID_AA64MMFR3_EL1_SCTLRX_SHIFT) & ID_AA64MMFR3_EL1_SCTLRX_MASK);
}

/**
 * @brief Enable MEC by setting SCR_EL3 and SCTLR2_EL3.EMEC.
 */
void val_el3_enable_mec(void)
{
    uint64_t sctlr2_el3;

    sctlr2_el3 = val_el3_read_sctlr2_el3();

    /* Check if MEC is supported on this Processing Element */
    if (val_el3_is_mec_supported() && val_el3_is_sctlrx_supported()) {
        /* Enable EMEC (Enable MEC bit) in SCTLR2_EL3 */
        sctlr2_el3 |= SCTLR2_EMEC_MASK;
        val_el3_write_sctlr2_el3(sctlr2_el3);
    } else {
        /* Log an error if FEAT_MEC or FEAT_SCTLR2 is not supported */
        ERROR("PE doesn't support FEAT_MEC or FEAT_SCTLR2\n");
        shared_data->status_code = 1;
        const char *msg = "EL3: FEAT_MEC OR FEAT_SCTLR2 absent";
        int i = 0; while (msg[i] && i < sizeof(shared_data->error_msg) - 1) {
            shared_data->error_msg[i] = msg[i]; i++;
        }
        shared_data->error_msg[i] = '\0';
    }
}

/**
 * @brief Disable MEC by clearing SCTLR2_EL3.EMEC.
 */
void val_el3_disable_mec(void)
{
    uint64_t sctlr2_el3;

    sctlr2_el3 = val_el3_read_sctlr2_el3();

    /* Check if MEC is supported on this Processing Element */
    if (val_el3_is_mec_supported() && val_el3_is_sctlrx_supported()) {
        /* Disable EMEC (clear MEC enable bit) in SCTLR2_EL3 */
        sctlr2_el3 &= ~SCTLR2_EMEC_MASK;
        val_el3_write_sctlr2_el3(sctlr2_el3);
    } else {
        /* Log an error if FEAT_MEC or FEAT_SCTLR2 is not supported */
        shared_data->status_code = 1;
        const char *msg = "EL3: FEAT_MEC OR FEAT_SCTLR2 absent";
        ERROR("\n %s", msg);
        int i = 0; while (msg[i] && i < sizeof(shared_data->error_msg) - 1) {
            shared_data->error_msg[i] = msg[i]; i++;
        }
        shared_data->error_msg[i] = '\0';
    }
}

/**
 * @brief Check if MEC is currently enabled.
 *
 * @return 1 if enabled, 0 otherwise.
 */
uint32_t val_el3_is_mec_enabled(void)
{
  uint64_t sctlr2_el3 = 0;

  /* Read current SCTLR2_EL3 value */
  if (val_el3_is_sctlrx_supported())
      sctlr2_el3 = val_el3_read_sctlr2_el3();

  /* Check if SCTLR2_EL3.EMEC bit is set */
  if (sctlr2_el3 & SCTLR2_EMEC_MASK) {
      /* MEC is enabled */
      return 1U;
  } else {
      /* MEC is not enabled */
      return 0U;
  }
}

/**
 * @brief Write the given MECID value to MECID_RL_A_EL3 and perform required maintenance.
 *
 * @param mecid  MECID value.
 */
void val_el3_write_mecid(uint32_t mecid)
{
    /* Write the given MECID to MECID_RL_A_EL3 system register */
    val_el3_write_mecid_rl_a_el3(mecid);

    /* Ensure instruction execution order and completion of register write */
    val_el3_isb();

    /* Invalidate all TLB entries at EL3 (Inner Shareable domain) */
    val_el3_tlbi_alle3is();
}

/**
 * @brief MEC service dispatch from SMC handler.
 *
 * @param arg0  Service selector.
 * @param arg1  Service argument 1.
 * @param arg2  Service argument 2.
 */
void val_el3_mec_service(uint64_t arg0, uint64_t arg1, uint64_t arg2)
{
  switch (arg0)
  {
    case ENABLE_MEC:
      INFO("Enabling MEC\n");
      val_el3_enable_mec();
      break;

    case CONFIG_MECID:
      INFO("Config mecid\n");
      val_el3_write_mecid(arg1);
      break;

    case DISABLE_MEC:
      INFO("Disabling MEC\n");
      val_el3_disable_mec();
      break;

    default:
      INFO("Invalid MEC service\n");
      break;
  }
}
