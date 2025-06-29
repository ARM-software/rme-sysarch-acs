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

#define SINGLE_TEST_SENTINEL   10000
#define SINGLE_MODULE_SENTINEL 10001

#define USER_SMC_IMM     0x100
#define ARM_ACS_SMC_FID  0xC2000060

/* GENERIC VAL APIs */
uint32_t val_configure_acs(void);
void val_allocate_shared_mem(void);
void val_free_shared_mem(void);
void val_print(uint32_t level, char8_t *string, uint64_t data);
void val_print_raw(uint64_t uart_address, uint32_t level, char8_t *string,
                                                                uint64_t data);
void val_print_test_end(uint32_t status, char8_t *string);
void val_set_test_data(uint32_t index, uint64_t addr, uint64_t test_data);
void val_get_test_data(uint32_t index, uint64_t *data0, uint64_t *data1);
uint32_t val_strncmp(char8_t *str1, char8_t *str2, uint32_t len);
void    *val_memcpy(void *dest_buffer, void *src_buffer, uint32_t len);
uint32_t val_generate_stream_id(void);
uint64_t val_time_delay_ms(uint64_t time_ms);

/* VAL PE APIs */
uint32_t val_pe_execute_tests(uint32_t level, uint32_t num_pe);
uint32_t val_pe_create_info_table(uint64_t *pe_info_table);
void     val_pe_free_info_table(void);
uint32_t val_pe_get_num(void);
uint64_t val_pe_get_mpid_index(uint32_t index);
uint32_t val_pe_get_pmu_gsiv(uint32_t index);
uint64_t val_pe_get_mpid(void);
uint32_t val_pe_get_index_mpid(uint64_t mpid);
uint32_t val_pe_install_esr(uint32_t exception_type, void (*esr)(uint64_t, void *));
uint64_t val_get_primary_mpidr(void);

void     val_execute_on_pe(uint32_t index, void (*payload)(void), uint64_t args);
int      val_suspend_pe(uint64_t entry, uint32_t context_id);
void     UserCallSMC(uint64_t smc_fid, uint64_t service, uint64_t arg0,
                     uint64_t arg1, uint64_t arg2);
void     tlbi_alle2(void);
uint64_t ats1e2r(uint64_t VA);

/* Memory Tests APIs */
#define MEM_ALIGN_4K       0x1000
#define MEM_ALIGN_8K       0x2000
#define MEM_ALIGN_16K      0x4000
#define MEM_ALIGN_32K      0x8000
#define MEM_ALIGN_64K      0x10000

/* Mem Map APIs */
void val_mmap_add_region(uint64_t va_base, uint64_t pa_base,
                uint64_t length, uint64_t attributes);
uint32_t val_setup_mmu(void);
uint32_t val_enable_mmu(void);

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
void val_smmu_access_disable(void);
void val_change_security_state_el3(int sec_state);
void write_gpr_and_reset(void);
uint32_t check_gpr_after_reset(void);
void val_smmu_check_rmeda_el3(void);
void val_rlm_smmu_init(uint32_t num_smmu);
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

//Legacy system VAL APIs
uint32_t val_legacy_execute_tests(uint32_t num_pe);

/* GIC VAL APIs */
uint32_t    val_gic_create_info_table(uint64_t *gic_info_table);

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
typedef enum {
  TIMER_INFO_CNTFREQ = 1,
  TIMER_INFO_PHY_EL1_INTID,
  TIMER_INFO_PHY_EL1_FLAGS,
  TIMER_INFO_VIR_EL1_INTID,
  TIMER_INFO_VIR_EL1_FLAGS,
  TIMER_INFO_PHY_EL2_INTID,
  TIMER_INFO_PHY_EL2_FLAGS,
  TIMER_INFO_VIR_EL2_INTID,
  TIMER_INFO_VIR_EL2_FLAGS,
  TIMER_INFO_NUM_PLATFORM_TIMERS,
  TIMER_INFO_IS_PLATFORM_TIMER_SECURE,
  TIMER_INFO_SYS_CNTL_BASE,
  TIMER_INFO_SYS_CNT_BASE_N,
  TIMER_INFO_FRAME_NUM,
  TIMER_INFO_SYS_INTID,
  TIMER_INFO_SYS_TIMER_STATUS
} TIMER_INFO_e;

#define RME_TIMER_FLAG_ALWAYS_ON 0x4

void     val_timer_create_info_table(uint64_t *timer_info_table);
void     val_timer_free_info_table(void);
uint32_t val_timer_execute_tests(uint32_t level, uint32_t num_pe);
uint64_t val_timer_get_info(TIMER_INFO_e info_type, uint64_t instance);
void     val_timer_set_phy_el1(uint64_t timeout);
void     val_timer_set_vir_el1(uint64_t timeout);
void     val_timer_set_phy_el2(uint64_t timeout);
void     val_timer_set_vir_el2(uint64_t timeout);
void     val_timer_set_system_timer(addr_t cnt_base_n, uint32_t timeout);
void     val_timer_disable_system_timer(addr_t cnt_base_n);
uint32_t val_timer_skip_if_cntbase_access_not_allowed(uint64_t index);
void val_platform_timer_get_entry_index(uint64_t instance, uint32_t *block, uint32_t *index);
uint64_t val_get_phy_el2_timer_count(void);
uint64_t val_get_phy_el1_timer_count(void);

uint64_t val_get_counter_frequency(void);


/* PCIE VAL APIs */
void     val_pcie_enumerate(void);
void     val_pcie_create_info_table(uint64_t *pcie_info_table);
uint32_t val_pcie_create_device_bdf_table(void);
addr_t val_pcie_get_ecam_base(uint32_t rp_bdf);
void *val_pcie_bdf_table_ptr(void);
uint32_t val_pcie_get_max_bdf(void);
void     val_pcie_free_info_table(void);
uint32_t val_pcie_execute_tests(uint32_t enable_pcie, uint32_t level, uint32_t num_pe);
uint32_t val_pcie_is_devicedma_64bit(uint32_t bdf);
uint32_t val_pcie_device_driver_present(uint32_t bdf);
uint32_t val_pcie_scan_bridge_devices_and_check_memtype(uint32_t bdf);
void val_pcie_read_ext_cap_word(uint32_t bdf, uint32_t ext_cap_id, uint8_t offset, uint16_t *val);
uint32_t val_pcie_get_pcie_type(uint32_t bdf);
uint32_t val_pcie_p2p_support(void);
uint32_t val_pcie_dev_p2p_support(uint32_t bdf);
uint32_t val_pcie_multifunction_support(uint32_t bdf);
uint32_t val_pcie_is_onchip_peripheral(uint32_t bdf);
uint32_t val_pcie_device_port_type(uint32_t bdf);
uint32_t val_pcie_find_capability(uint32_t bdf, uint32_t cid_type,
                                           uint32_t cid, uint32_t *cid_offset);
void val_pcie_disable_bme(uint32_t bdf);
void val_pcie_enable_bme(uint32_t bdf);
void val_pcie_disable_msa(uint32_t bdf);
void val_pcie_enable_msa(uint32_t bdf);
uint32_t val_pcie_is_msa_enabled(uint32_t bdf);
void val_pcie_clear_urd(uint32_t bdf);
uint32_t val_pcie_is_urd(uint32_t bdf);
void val_pcie_enable_eru(uint32_t bdf);
void val_pcie_disable_eru(uint32_t bdf);
uint32_t val_pcie_bitfield_check(uint32_t bdf, uint64_t *bf_entry);
uint32_t val_pcie_register_bitfields_check(uint64_t *bf_info_table, uint32_t table_size);
uint32_t val_pcie_function_header_type(uint32_t bdf);
void val_pcie_get_mmio_bar(uint32_t bdf, void *base);
uint32_t val_pcie_get_downstream_function(uint32_t bdf, uint32_t *dsf_bdf);
uint32_t val_pcie_get_rootport(uint32_t bdf, uint32_t *rp_bdf);
uint8_t val_pcie_parent_is_rootport(uint32_t dsf_bdf, uint32_t *rp_bdf);
uint8_t val_pcie_is_host_bridge(uint32_t bdf);
void val_pcie_clear_device_status_error(uint32_t bdf);
uint32_t val_pcie_is_device_status_error(uint32_t bdf);
uint32_t val_pcie_is_sig_target_abort(uint32_t bdf);
void val_pcie_clear_sig_target_abort(uint32_t bdf);
uint32_t val_pcie_mem_get_offset(uint32_t type);
uint32_t val_pcie_get_bar_index(uint32_t bdf, uint64_t bar_address, uint32_t *bar_index);

/* RME-DA APIs */
uint32_t val_rme_da_execute_tests(uint32_t num_pe);
uint32_t val_pcie_find_da_capability(uint32_t bdf, uint32_t *cid_offset);

/* IO-VIRT APIs */
typedef enum {
  SMMU_NUM_CTRL = 1,
  SMMU_CTRL_BASE,
  SMMU_CTRL_ARCH_MAJOR_REV,
  SMMU_IOVIRT_BLOCK,
  SMMU_SSID_BITS,
  SMMU_IN_ADDR_SIZE,
  SMMU_OUT_ADDR_SIZE
} SMMU_INFO_e;

typedef enum {
  SMMU_CAPABLE     = 1,
  SMMU_CHECK_DEVICE_IOVA,
  SMMU_START_MONITOR_DEV,
  SMMU_STOP_MONITOR_DEV,
  SMMU_CREATE_MAP,
  SMMU_UNMAP,
  SMMU_IOVA_PHYS,
  SMMU_DEV_DOMAIN,
  SMMU_GET_ATTR,
  SMMU_SET_ATTR,
} SMMU_OPS_e;

typedef enum {
  NUM_PCIE_RC = 1,
  RC_SEGMENT_NUM,
  RC_ATS_ATTRIBUTE,
  RC_MEM_ATTRIBUTE,
  RC_IOVIRT_BLOCK,
  RC_SMMU_BASE
} PCIE_RC_INFO_e;

void     val_iovirt_create_info_table(uint64_t *iovirt_info_table);
void     val_iovirt_free_info_table(void);
uint32_t val_iovirt_get_rc_smmu_index(uint32_t rc_seg_num, uint32_t rid);
uint32_t val_smmu_execute_tests(uint32_t num_pe);
uint64_t val_smmu_get_info(SMMU_INFO_e type, uint32_t index);
uint64_t val_iovirt_get_smmu_info(SMMU_INFO_e type, uint32_t index);

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

typedef enum {
    PER_FLAG_MSI_ENABLED = 0x2
} PERIPHERAL_FLAGS_e;

/* Peripheral Tests APIs */
typedef enum {
  NUM_USB,
  NUM_SATA,
  NUM_UART,
  NUM_ALL,
  USB_BASE0,
  USB_FLAGS,
  USB_GSIV,
  USB_BDF,
  SATA_BASE0,
  SATA_BASE1,
  SATA_FLAGS,
  SATA_GSIV,
  SATA_BDF,
  UART_BASE0,
  UART_GSIV,
  UART_FLAGS,
  ANY_FLAGS,
  ANY_GSIV,
  ANY_BDF,
  MAX_PASIDS
} PERIPHERAL_INFO_e;

void     val_peripheral_create_info_table(uint64_t *peripheral_info_table);
void     val_peripheral_free_info_table(void);
uint32_t val_peripheral_execute_tests(uint32_t level, uint32_t num_pe);
uint64_t val_peripheral_get_info(PERIPHERAL_INFO_e info_type, uint32_t index);
uint32_t val_peripheral_is_pcie(uint32_t bdf);

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

/* PCIe Exerciser tests */
uint32_t val_exerciser_execute_tests(uint32_t level);


/* RME-DPT APIs */
uint32_t val_rme_dpt_execute_tests(uint32_t num_pe);

/* RME-MEC APIs */
uint32_t val_rme_mec_execute_tests(uint32_t num_pe);

#endif
