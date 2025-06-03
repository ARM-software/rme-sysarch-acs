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

#ifndef __VAL_INTERFACE_H__
#define __VAL_INTERFACE_H__

#include "pal_interface.h"

#ifdef TARGET_EMULATION
#define TRUE 1
#define FALSE 0
#define BIT0 (1)
#define BIT1 (1 << 1)
#define BIT4 (1 << 4)
#define BIT6 (1 << 6)
#define BIT14 (1 << 14)
#define BIT29 (1 << 29)
#endif

/* set G_PRINT_LEVEL to one of the below values in your application entry
  to control the verbosity of the prints */
#define ACS_PRINT_ALWAYS  6    /* No log-level prefix or newline. For inline/multi-part prints */
#define ACS_PRINT_ERR   5      /* Only Errors. use this to de-clutter the
                                  terminal and focus only on specifics */
#define ACS_PRINT_WARN  4      /* Only warnings & errors. use this to de-clutter
                                  the terminal and focus only on specifics */
#define ACS_PRINT_TEST  3      /* Test description and result descriptions. THIS is DEFAULT */
#define ACS_PRINT_DEBUG 2      /* For Debug statements. contains register dumps etc */
#define ACS_PRINT_INFO  1      /* Print all statements. Do not use unless really needed */

#define ACS_STATUS_FAIL      0x90000000
#define ACS_STATUS_ERR       0xEDCB1234  //some impropable value?
#define ACS_STATUS_SKIP      0x10000000
#define ACS_STATUS_PASS      0x0
#define ACS_INVALID_INDEX    0xFFFFFFFF

#define NOT_IMPLEMENTED         0x4B1D  /* Feature or API not imeplemented */

#define VAL_EXTRACT_BITS(data, start, end) ((data >> start) & ((1ul << (end-start+1))-1))

#define SINGLE_TEST_SENTINEL_STR   "SINGLE_TEST_NONE"
#define SINGLE_MODULE_SENTINEL_STR "SINGLE_MODULE_NONE"
#define SKIP_TEST_SENTINEL         "SKIP_TEST_NONE"

#define USER_SMC_IMM     0x100
#define ARM_ACS_SMC_FID  0xC2000060

#define FILENAME (__builtin_strrchr("/" __FILE__, '/') + 1)
#define val_print(level, string, data) val_log_context(level, string, data, FILENAME, __LINE__)

/* GENERIC VAL APIs */
void UserCallSMC(uint64_t smc_fid, uint64_t service, uint64_t arg0,
                     uint64_t arg1, uint64_t arg2);
uint32_t val_configure_acs(void);
void val_allocate_shared_mem(void);
void val_free_shared_mem(void);
void val_print_raw(uint64_t uart_address, uint32_t level, char8_t *string, uint64_t data);
void val_log_context(uint32_t level, char8_t *string, uint64_t data, const char *file, int line);
void val_set_test_data(uint32_t index, uint64_t addr, uint64_t test_data);
void val_get_test_data(uint32_t index, uint64_t *data0, uint64_t *data1);
uint32_t val_strncmp(char8_t *str1, char8_t *str2, uint32_t len);
void    *val_memcpy(void *dest_buffer, void *src_buffer, uint32_t len);
uint32_t val_generate_stream_id(void);
uint64_t val_time_delay_ms(uint64_t time_ms);

/* VAL PE APIs */
uint32_t val_pe_create_info_table(uint64_t *pe_info_table);
void     val_pe_free_info_table(void);
uint32_t val_pe_get_num(void);
uint64_t val_pe_get_mpid_index(uint32_t index);
uint64_t val_pe_get_mpid(void);
uint32_t val_pe_get_index_mpid(uint64_t mpid);
uint32_t val_pe_install_esr(uint32_t exception_type, void (*esr)(uint64_t, void *));
uint64_t val_get_primary_mpidr(void);

void     val_execute_on_pe(uint32_t index, void (*payload)(void), uint64_t args);
int      val_suspend_pe(uint64_t entry, uint32_t context_id);

/* Memory Tests APIs */
#define MEM_ALIGN_4K       0x1000
#define MEM_ALIGN_8K       0x2000
#define MEM_ALIGN_16K      0x4000
#define MEM_ALIGN_32K      0x8000
#define MEM_ALIGN_64K      0x10000

/* VAL RME APIs */
uint32_t val_rme_execute_tests(uint32_t num_pe);
void val_data_cache_ops_by_va_el3(uint64_t address, uint32_t type);
void val_memory_set_el3(void *buf, uint32_t size, uint8_t value);
void val_add_mmu_entry_el3(uint64_t VA, uint64_t PA, uint64_t attr);
void val_add_gpt_entry_el3(uint64_t PA, uint64_t gpi);
void val_pe_access_mut_el3(void);
void val_data_cache_ops_by_pa_el3(uint64_t PA, uint64_t acc_pas);
void val_rme_install_handler_el3(void);
void val_enable_ns_encryption(void);
void val_disable_ns_encryption(void);
void val_read_pe_regs_bfr_low_pwr_el3(void);
void val_cmpr_pe_regs_aftr_low_pwr_el3(void);
void val_prog_legacy_tz(int enable);
void val_wd_set_ws0_el3(uint64_t VA_RT_WDOG, uint32_t timeout, uint64_t counter_freq);
void val_pas_filter_active_mode_el3(int enable);
void val_smmu_access_disable(uint64_t smmu_base);
void val_smmu_access_enable(uint64_t smmu_base);
void val_change_security_state_el3(int sec_state);
void write_gpr_and_reset(void);
uint32_t check_gpr_after_reset(void);
void val_smmu_check_rmeda_el3(uint64_t smmu_base);
void val_rlm_smmu_init(uint64_t num_smmu, uint64_t *smmu_base_arr);
void val_smmu_rlm_map_el3(smmu_master_attributes_t *smmu_attr, pgt_descriptor_t *pgt_attr);
void val_register_create_info_table(uint64_t *register_info_table);
void val_dpt_add_entry(uint64_t translated_addr, uint32_t smmu_index);
void val_dpt_invalidate_all(uint64_t smmu_index);
void val_rlm_pgt_create(memory_region_descriptor_t *mem_desc, pgt_descriptor_t *pgt_desc);
void val_rlm_pgt_destroy(pgt_descriptor_t *pgt_desc);
void val_rlm_enable_mec(void);
void val_rlm_disable_mec(void);
void val_smmu_rlm_check_mec_impl(uint64_t smmu_base);
void val_smmu_rlm_get_mecidw(uint64_t smmu_base);
void val_cmo_to_poe(uint64_t PA);
void val_rlm_configure_mecid(uint32_t mecid);
void val_smmu_rlm_configure_mecid(smmu_master_attributes_t *smmu_attr, uint32_t mecid);

/* PCIe VAL APIs */
void     val_pcie_create_info_table(uint64_t *pcie_info_table);
uint32_t val_pcie_create_device_bdf_table(void);
void     val_pcie_free_info_table(void);

//Legacy system VAL APIs
uint32_t val_legacy_execute_tests(uint32_t num_pe);

/* GIC VAL APIs */
uint32_t val_gic_create_info_table(uint64_t *gic_info_table);

typedef enum {
  GIC_INFO_VERSION = 1,
  GIC_INFO_SEC_STATES,
  GIC_INFO_AFFINITY_NS,
  GIC_INFO_ENABLE_GROUP1NS,
  GIC_INFO_SGI_NON_SECURE,
  GIC_INFO_SGI_NON_SECURE_LEGACY,
  GIC_INFO_DIST_BASE,
  GIC_INFO_CITF_BASE,
  GIC_INFO_NUM_RDIST,
  GIC_INFO_RDIST_BASE,
  GIC_INFO_NUM_ITS,
  GIC_INFO_ITS_BASE,
  GIC_INFO_NUM_MSI_FRAME
} GIC_INFO_e;

uint32_t
val_gic_get_info(GIC_INFO_e type);
void     val_gic_free_info_table(void);
uint32_t val_gic_execute_tests(uint32_t num_pe);
uint32_t val_gic_install_isr(uint32_t int_id, void (*isr)(void));
uint32_t val_gic_end_of_interrupt(uint32_t int_id);
uint32_t val_gic_route_interrupt_to_pe(uint32_t int_id, uint64_t mpidr);
uint32_t val_gic_get_interrupt_state(uint32_t int_id);
void val_gic_clear_interrupt(uint32_t int_id);
void val_gic_cpuif_init(void);
uint32_t val_gic_request_irq(uint32_t irq_num, uint32_t mapped_irq_num, void *isr);
void val_gic_free_irq(uint32_t irq_num, uint32_t mapped_irq_num);
void val_gic_set_intr_trigger(uint32_t int_id, INTR_TRIGGER_INFO_TYPE_e trigger_type);
uint32_t val_gic_get_intr_trigger_type(uint32_t int_id, INTR_TRIGGER_INFO_TYPE_e *trigger_type);
uint32_t val_gic_its_configure(void);
uint32_t val_gic_request_msi(uint32_t bdf, uint32_t device_id, uint32_t its_id,
                             uint32_t int_id, uint32_t msi_index);
void val_gic_free_msi(uint32_t bdf, uint32_t device_id, uint32_t its_id,
                      uint32_t int_id, uint32_t msi_index);
uint32_t val_gic_its_get_base(uint32_t its_id, uint64_t *its_base);

/*TIMER VAL APIs */
void     val_timer_create_info_table(uint64_t *timer_info_table);
void     val_timer_free_info_table(void);

/* RME-DA APIs */
uint32_t val_rme_da_execute_tests(uint32_t num_pe);

/* IO-VIRT APIs */
void     val_iovirt_create_info_table(uint64_t *iovirt_info_table);
void     val_iovirt_free_info_table(void);

/* SMMU API */
uint32_t val_smmu_execute_tests(uint32_t num_pe);

/* POWER and WAKEUP APIs */
typedef enum {
    RME_POWER_SEM_B = 1,
    RME_POWER_SEM_c,
    RME_POWER_SEM_D,
    RME_POWER_SEM_E,
    RME_POWER_SEM_F,
    RME_POWER_SEM_G,
    RME_POWER_SEM_H,
    RME_POWER_SEM_I
} RME_POWER_SEM_e;

uint32_t val_power_enter_semantic(RME_POWER_SEM_e semantic);
uint32_t val_wakeup_execute_tests(uint32_t level, uint32_t num_pe);

/* Peripheral Tests APIs */
void     val_peripheral_create_info_table(uint64_t *peripheral_info_table);
void     val_peripheral_free_info_table(void);

#define MEM_ATTR_UNCACHED  0x2000
#define MEM_ATTR_CACHED    0x1000

/* Identify memory type using MAIR attribute, refer to ARM ARM VMSA for details */

#define MEM_NORMAL_WB_IN_OUT(attr) (((attr & 0xcc) == 0xcc) || (((attr & 0x7) >= 5) && (((attr >> 4) & 0x7) >= 5)))
#define MEM_NORMAL_NC_IN_OUT(attr) (attr == 0x44)
#define MEM_DEVICE(attr) ((attr & 0xf0) == 0)
#define MEM_SH_INNER(sh) (sh == 0x3)

/* Secure mode EL3 Firmware tests */

typedef struct {
  uint64_t   test_index;
  uint64_t   test_arg01;
  uint64_t   test_arg02;
  uint64_t   test_arg03;
} RME_SMC_t;

/**
  Trigger an SMC call

  SMC calls can take up to 7 arguments and return up to 4 return values.
  Therefore, the 4 first fields in the ARM_SMC_ARGS structure are used
  for both input and output values.

**/
void
ArmCallSmc(
  ARM_SMC_ARGS  *Args,
  int32_t      Conduit
  );

void     val_secure_call_smc(RME_SMC_t *smc);
uint32_t val_secure_get_result(RME_SMC_t *smc, uint32_t timeout);
uint32_t val_secure_execute_tests(uint32_t level, uint32_t num_pe);
uint32_t val_secure_trusted_firmware_init(void);
void     val_system_reset(void);

/* RME-DPT APIs */
uint32_t val_rme_dpt_execute_tests(uint32_t num_pe);

/* RME-MEC APIs */
uint32_t val_rme_mec_execute_tests(uint32_t num_pe);

#endif
