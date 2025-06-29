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

#ifndef __PAL_INTERFACE_H__
#define __PAL_INTERFACE_H__

#ifdef TARGET_LINUX
#include <linux/slab.h>
#endif

#if TARGET_BM_BOOT

#include "platform_override_fvp.h"

  #define VAL_TG0_4K      0x0
  #define VAL_TG0_64K     0x1
  #define VAL_TG0_16K     0x2

  #define PAGE_SIZE_4K    0x1000
  #define PAGE_SIZE_16K   (4 * 0x1000)
  #define PAGE_SIZE_64K   (16 * 0x1000)
  #define PAGE_BITS_4K    12
  #define PAGE_BITS_16K   14
  #define PAGE_BITS_64K   16

  #if (PLATFORM_PAGE_SIZE == PAGE_SIZE_4K)
    #define PAGE_ALIGNMENT      PAGE_SIZE_4K
    #define PAGE_SIZE           PAGE_SIZE_4K
    #define TCR_TG0             VAL_TG0_4K
  #elif (PLATFORM_PAGE_SIZE == PAGE_SIZE_16K)
    #define PAGE_ALIGNMENT      PAGE_SIZE_16K
    #define PAGE_SIZE           PAGE_SIZE_16K
    #define TCR_TG0             VAL_TG0_16K
  #elif (PLATFORM_PAGE_SIZE == PAGE_SIZE_64K)
    #define PAGE_ALIGNMENT      PAGE_SIZE_64K
    #define PAGE_SIZE           PAGE_SIZE_64K
    #define TCR_TG0             VAL_TG0_64K
  #endif

  #define MMU_PGT_IAS      PLATFORM_OVERRIDE_MMU_PGT_IAS
  #define MMU_PGT_OAS      PLATFORM_OVERRIDE_MMU_PGT_OAS
#endif

#ifdef TARGET_LINUX
  typedef char          char8_t;
  typedef long long int addr_t;
#define TIMEOUT_LARGE    0x1000000
#define TIMEOUT_MEDIUM   0x100000
#define TIMEOUT_SMALL    0x1000

#define PCIE_MAX_BUS   256
#define PCIE_MAX_DEV    32
#define PCIE_MAX_FUNC    8

#elif TARGET_EMULATION
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include "../platform/pal_baremetal/FVP/include/platform_override_fvp.h"
  typedef uint64_t addr_t;
  typedef char     char8_t;
  typedef uint64_t dma_addr_t;

#define TIMEOUT_LARGE    PLATFORM_OVERRIDE_TIMEOUT_LARGE
#define TIMEOUT_MEDIUM   PLATFORM_OVERRIDE_TIMEOUT_MEDIUM
#define TIMEOUT_SMALL    PLATFORM_OVERRIDE_TIMEOUT_SMALL

#define PCIE_MAX_BUS    PLATFORM_BM_OVERRIDE_PCIE_MAX_BUS
#define PCIE_MAX_DEV    PLATFORM_BM_OVERRIDE_PCIE_MAX_DEV
#define PCIE_MAX_FUNC   PLATFORM_BM_OVERRIDE_PCIE_MAX_FUNC

#else
  typedef INT8   int8_t;
  typedef INT32  int32_t;
  typedef CHAR8  char8_t;
  typedef CHAR16 char16_t;
  typedef UINT8  uint8_t;
  typedef UINT16 uint16_t;
  typedef UINT32 uint32_t;
  typedef UINT64 uint64_t;
  typedef UINT64 addr_t;

#if PLATFORM_OVERRIDE_TIMEOUT
    #define TIMEOUT_LARGE    PLATFORM_OVERRIDE_TIMEOUT_LARGE
    #define TIMEOUT_MEDIUM   PLATFORM_OVERRIDE_TIMEOUT_MEDIUM
    #define TIMEOUT_SMALL    PLATFORM_OVERRIDE_TIMEOUT_SMALL
#else
    #define TIMEOUT_LARGE    0x1000000
    #define TIMEOUT_MEDIUM   0x100000
    #define TIMEOUT_SMALL    0x1000
#endif

#if PLATFORM_OVERRIDE_MAX_BDF
    #define PCIE_MAX_BUS    PLATFORM_OVERRIDE_PCIE_MAX_BUS
    #define PCIE_MAX_DEV    PLATFORM_OVERRIDE_PCIE_MAX_DEV
    #define PCIE_MAX_FUNC   PLATFORM_OVERRIDE_PCIE_MAX_FUNC
#else
    #define PCIE_MAX_BUS   256
    #define PCIE_MAX_DEV    32
    #define PCIE_MAX_FUNC    8
#endif

#endif

#define ONE_MILLISECOND 1000

#define PCIE_SUCCESS            0x00000000  /* Operation completed successfully */
#define PCIE_NO_MAPPING         0x10000001  /* A mapping to a Function does not exist */
#define PCIE_CAP_NOT_FOUND      0x10000010  /* The specified capability was not found */
#define PCIE_UNKNOWN_RESPONSE   0xFFFFFFFF  /* Function not found or UR response from completer */


#define RME_ACS_NVM_MEM         0x82800000

/**  PE Test related Definitions **/

/**
  @brief Conduits for service calls (SMC vs HVC).
**/
#define CONDUIT_SMC       0
#define CONDUIT_HVC       1
#define CONDUIT_UNKNOWN  -1
#define CONDUIT_NONE     -2
int32_t pal_psci_get_conduit(void);

/**
  @brief  number of PEs discovered
**/
typedef struct {
  uint32_t num_of_pe;
} PE_INFO_HDR;

/**
  @brief  structure instance for PE entry
**/
typedef struct {
  uint32_t   pe_num;    ///< PE Index
  uint32_t   attr;      ///< PE attributes
  uint64_t   mpidr;     ///< PE MPIDR
  uint32_t   pmu_gsiv;  ///< PMU Interrupt ID
} PE_INFO_ENTRY;

typedef struct {
  PE_INFO_HDR    header;
  PE_INFO_ENTRY  pe_info[];
} PE_INFO_TABLE;

typedef struct {
  uint32_t ps:3;
  uint32_t tg:2;
  uint32_t sh:2;
  uint32_t orgn:2;
  uint32_t irgn:2;
  uint32_t tsz:6;
  uint32_t sl:2;
  uint32_t tg_size_log2:5;
} PE_TCR_BF;

typedef struct {
  uint32_t ps:3;
  uint32_t tg:2;
  uint32_t sh:2;
  uint32_t orgn:2;
  uint32_t irgn:2;
  uint32_t tsz:6;
  uint32_t sl:2;
  uint32_t tg_size_log2:5;
} VTCR_EL2_INFO;

void pal_pe_create_info_table(PE_INFO_TABLE *pe_info_table);

/**
  @brief  Structure to Pass SMC arguments. Return data is also filled into
          the same structure.
**/
typedef struct {
  uint64_t  Arg0;
  uint64_t  Arg1;
  uint64_t  Arg2;
  uint64_t  Arg3;
  uint64_t  Arg4;
  uint64_t  Arg5;
  uint64_t  Arg6;
  uint64_t  Arg7;
} ARM_SMC_ARGS;

void pal_pe_call_smc(ARM_SMC_ARGS *args, int32_t conduit);
void pal_pe_execute_payload(ARM_SMC_ARGS *args);
uint32_t pal_pe_install_esr(uint32_t exception_type, void (*esr)(uint64_t, void *));
uint32_t pal_get_cpu_count(void);
uint64_t *pal_get_phy_mpidr_list_base(void);
/* ********** PE INFO END **********/


/** GIC Tests Related definitions **/

/**
  @brief  GIC Info header - Summary of GIC subsytem
**/
typedef struct {
  uint32_t gic_version;
  uint32_t num_gicd;
  uint32_t num_gicrd;
  uint32_t num_its;
  uint32_t num_msi_frame;
  uint32_t num_gich;
} GIC_INFO_HDR;

/* Interrupt Trigger Type */
typedef enum {
  INTR_TRIGGER_INFO_LEVEL_LOW,
  INTR_TRIGGER_INFO_LEVEL_HIGH,
  INTR_TRIGGER_INFO_EDGE_FALLING,
  INTR_TRIGGER_INFO_EDGE_RISING
} INTR_TRIGGER_INFO_TYPE_e;

/**
  @brief  structure instance for GIC entry
**/
typedef struct {
  uint32_t type;
  uint64_t base;
  uint32_t entry_id;  /* This entry_id is used to tell component ID */
  uint64_t length;  /* This length is only used in case of Re-Distributor Range Address length */
  uint32_t flags;
  uint32_t spi_count;
  uint32_t spi_base;
} GIC_INFO_ENTRY;

/**
  @brief  GIC Information Table
**/
typedef struct {
  GIC_INFO_HDR   header;
  GIC_INFO_ENTRY gic_info[];  ///< Array of Information blocks - instantiated for each GIC type
} GIC_INFO_TABLE;

typedef struct {
 uint32_t     ID;
 uint64_t     Base;
 uint64_t     CommandQBase;
 uint32_t     IDBits;
 uint64_t     ITTBase;
} GIC_ITS_BLOCK;

typedef struct {
 uint64_t         GicDBase;
 uint64_t         GicRdBase;
 uint32_t         GicNumIts;
 GIC_ITS_BLOCK    GicIts[];
} GIC_ITS_INFO;

typedef enum {
  ENTRY_TYPE_CPUIF = 0x1000,
  ENTRY_TYPE_GICD,
  ENTRY_TYPE_GICC_GICRD,
  ENTRY_TYPE_GICR_GICRD,
  ENTRY_TYPE_GICITS,
  ENTRY_TYPE_GIC_MSI_FRAME,
  ENTRY_TYPE_GICH
} GIC_INFO_TYPE_e;

void     pal_gic_create_info_table(GIC_INFO_TABLE *gic_info_table);
uint32_t pal_gic_install_isr(uint32_t int_id, void (*isr)(void));
void pal_gic_end_of_interrupt(uint32_t int_id);
uint32_t pal_gic_request_irq(unsigned int irq_num, unsigned int mapped_irq_num, void *isr);
void pal_gic_free_irq(unsigned int irq_num, unsigned int mapped_irq_num);
uint32_t pal_gic_set_intr_trigger(uint32_t int_id, INTR_TRIGGER_INFO_TYPE_e trigger_type);
uint32_t pal_target_is_bm(void);

/** Timer tests related definitions **/

/**
  @brief  GIC Info header - Summary of Timer subsytem
**/
typedef struct {
  uint32_t s_el1_timer_flag;
  uint32_t ns_el1_timer_flag;
  uint32_t el2_timer_flag;
  uint32_t el2_virt_timer_flag;
  uint32_t s_el1_timer_gsiv;
  uint32_t ns_el1_timer_gsiv;
  uint32_t el2_timer_gsiv;
  uint32_t virtual_timer_flag;
  uint32_t virtual_timer_gsiv;
  uint32_t el2_virt_timer_gsiv;
  uint32_t num_platform_timer;
  uint32_t num_watchdog;
  uint32_t sys_timer_status;
} TIMER_INFO_HDR;

#define TIMER_TYPE_SYS_TIMER 0x2001

/**
  @brief  structure instance for TIMER entry
**/
typedef struct {
  uint32_t type;
  uint32_t timer_count;
  uint64_t block_cntl_base;
  uint8_t  frame_num[8];
  uint64_t GtCntBase[8];
  uint64_t GtCntEl0Base[8];
  uint32_t gsiv[8];
  uint32_t virt_gsiv[8];
  uint32_t flags[8];
} TIMER_INFO_GTBLOCK;

typedef struct {
  TIMER_INFO_HDR     header;
  TIMER_INFO_GTBLOCK gt_info[];
} TIMER_INFO_TABLE;

void pal_timer_create_info_table(TIMER_INFO_TABLE *timer_info_table);
uint64_t pal_timer_get_counter_frequency(void);

/* PCIe Tests related definitions */

/**
  @brief PCI Express Info Table
**/
typedef struct {
  addr_t   ecam_base;     ///< ECAM Base address
  uint32_t segment_num;   ///< Segment number of this ECAM
  uint32_t start_bus_num; ///< Start Bus number for this ecam space
  uint32_t end_bus_num;   ///< Last Bus number
} PCIE_INFO_BLOCK;

typedef struct {
  uint32_t num_entries;
  PCIE_INFO_BLOCK  block[];
} PCIE_INFO_TABLE;


void     pal_pcie_enumerate(void);
uint32_t pal_pcie_enumerate_device(uint32_t bus, uint32_t sec_bus);
void     pal_pcie_program_bar_reg(uint32_t bus, uint32_t dev, uint32_t func);
void     pal_pci_cfg_write(uint32_t bus, uint32_t dev, uint32_t func, int offset, int data);
uint32_t pal_pci_cfg_read(uint32_t bus, uint32_t dev, uint32_t func, int offset, uint32_t *value);

uint64_t pal_pcie_get_mcfg_ecam(void);
void     pal_pcie_create_info_table(PCIE_INFO_TABLE *PcieTable);
uint32_t pal_pcie_io_read_cfg(uint32_t bdf, uint32_t offset, uint32_t *data);
uint32_t pal_pcie_get_bdf_wrapper(uint32_t class_code, uint32_t start_bdf);
void *pal_pci_bdf_to_dev(uint32_t bdf);
void pal_pci_read_config_byte(uint32_t bdf, uint8_t offset, uint8_t *val);
void pal_pci_write_config_byte(uint32_t bdf, uint8_t offset, uint8_t val);
void pal_pcie_read_ext_cap_word(uint32_t seg, uint32_t bus, uint32_t dev, uint32_t fn,
                                uint32_t ext_cap_id, uint8_t offset, uint16_t *val);
uint32_t pal_pcie_get_pcie_type(uint32_t seg, uint32_t bus, uint32_t dev, uint32_t fn);
uint32_t pal_pcie_p2p_support(void);
uint32_t pal_pcie_dev_p2p_support(uint32_t seg, uint32_t bus, uint32_t dev, uint32_t fn);
uint32_t pal_pcie_is_cache_present(uint32_t seg, uint32_t bus, uint32_t dev, uint32_t fn);
uint32_t pal_pcie_is_onchip_peripheral(uint32_t bdf);
void pal_pcie_io_write_cfg(uint32_t bdf, uint32_t offset, uint32_t data);
uint32_t pal_pcie_check_device_list(void);
uint32_t pal_pcie_check_device_valid(uint32_t bdf);
uint32_t pal_pcie_mem_get_offset(uint32_t type);

uint32_t pal_pcie_bar_mem_read(uint32_t bdf, uint64_t address, uint32_t *data);
uint32_t pal_pcie_bar_mem_write(uint32_t bdf, uint64_t address, uint32_t data);
/**
  @brief  Instance of SMMU INFO block
**/
typedef struct {
  uint32_t arch_major_rev;  ///< Version 1 or 2 or 3
  addr_t base;              ///< SMMU Controller base address
} SMMU_INFO_BLOCK;

typedef struct {
  uint32_t segment;
  uint32_t ats_attr;
  uint32_t cca;          //Cache Coherency Attribute
  uint64_t smmu_base;
} IOVIRT_RC_INFO_BLOCK;

typedef struct {
  uint64_t base;
  uint32_t overflow_gsiv;
  uint32_t node_ref;
} IOVIRT_PMCG_INFO_BLOCK;

typedef enum {
  IOVIRT_NODE_ITS_GROUP = 0x00,
  IOVIRT_NODE_NAMED_COMPONENT = 0x01,
  IOVIRT_NODE_PCI_ROOT_COMPLEX = 0x02,
  IOVIRT_NODE_SMMU = 0x03,
  IOVIRT_NODE_SMMU_V3 = 0x04,
  IOVIRT_NODE_PMCG = 0x05
} IOVIRT_NODE_TYPE;

typedef enum {
  IOVIRT_FLAG_DEVID_OVERLAP_SHIFT,
  IOVIRT_FLAG_STRID_OVERLAP_SHIFT,
  IOVIRT_FLAG_SMMU_CTX_INT_SHIFT,
} IOVIRT_FLAG_SHIFT;

typedef struct {
  uint32_t input_base;
  uint32_t id_count;
  uint32_t output_base;
  uint32_t output_ref;
} ID_MAP;

typedef union {
  uint32_t id[4];
  ID_MAP map;
} NODE_DATA_MAP;

#define MAX_NAMED_COMP_LENGTH 256

typedef union {
  char name[MAX_NAMED_COMP_LENGTH];
  IOVIRT_RC_INFO_BLOCK rc;
  IOVIRT_PMCG_INFO_BLOCK pmcg;
  uint32_t its_count;
  SMMU_INFO_BLOCK smmu;
} NODE_DATA;

typedef struct {
  uint32_t type;
  uint32_t num_data_map;
  NODE_DATA data;
  uint32_t flags;
  NODE_DATA_MAP data_map[];
} IOVIRT_BLOCK;

#define IOVIRT_NEXT_BLOCK(b) (IOVIRT_BLOCK *)((uint8_t *)(&b->data_map[0]) + b->num_data_map * sizeof(NODE_DATA_MAP))
#define ALIGN_MEMORY(b, bound) (IOVIRT_BLOCK *) (((uint64_t)b + bound - 1) & (~(bound - 1)))
#define IOVIRT_CCA_MASK ~((uint32_t)0)

typedef struct {
  uint32_t num_blocks;
  uint32_t num_smmus;
  uint32_t num_pci_rcs;
  uint32_t num_named_components;
  uint32_t num_its_groups;
  uint32_t num_pmcgs;
  IOVIRT_BLOCK blocks[];
} IOVIRT_INFO_TABLE;

void pal_iovirt_create_info_table(IOVIRT_INFO_TABLE *iovirt);
uint32_t pal_iovirt_check_unique_ctx_intid(uint64_t smmu_block);
uint32_t pal_iovirt_unique_rid_strid_map(uint64_t rc_block);
uint64_t pal_iovirt_get_rc_smmu_base(IOVIRT_INFO_TABLE *iovirt, uint32_t rc_seg_num, uint32_t rid);

/**
  @brief SMMU Info Table
**/
typedef struct {
  uint32_t smmu_num_ctrl;       ///< Number of SMMU Controllers in the system
  SMMU_INFO_BLOCK smmu_block[]; ///< Array of Information blocks - instantiated for each SMMU Controller
} SMMU_INFO_TABLE;

typedef struct {
    uint32_t smmu_index;
    uint32_t streamid;
    uint32_t substreamid;
    uint32_t ssid_bits;
    uint32_t stage2;
} smmu_master_attributes_t;

typedef struct {
    uint64_t pgt_base;
    uint32_t ias;
    uint32_t oas;
    uint64_t mair;
    uint32_t stage;
    PE_TCR_BF tcr;
    VTCR_EL2_INFO vtcr;
} pgt_descriptor_t;

typedef struct {
    uint64_t physical_address;
    uint64_t virtual_address;
    uint64_t length;
    uint64_t attributes;
} memory_region_descriptor_t;

void     pal_smmu_create_info_table(SMMU_INFO_TABLE *smmu_info_table);
uint32_t pal_smmu_check_device_iova(void *port, uint64_t dma_addr);
void     pal_smmu_device_start_monitor_iova(void *port);
void     pal_smmu_device_stop_monitor_iova(void *port);
uint32_t pal_smmu_max_pasids(uint64_t smmu_base);
uint32_t pal_smmu_create_pasid_entry(uint64_t smmu_base, uint32_t pasid);
uint32_t pal_smmu_disable(uint64_t smmu_base);
uint64_t pal_smmu_pa2iova(uint64_t smmu_base, uint64_t pa);


/** Peripheral Tests related definitions **/

/**
  @brief  Summary of Peripherals in the system
**/
typedef struct {
  uint32_t    num_usb;   ///< Number of USB  Controllers
  uint32_t    num_sata;  ///< Number of SATA Controllers
  uint32_t    num_uart;  ///< Number of UART Controllers
  uint32_t    num_all;   ///< Number of all PCI Controllers
} PERIPHERAL_INFO_HDR;

typedef enum {
  PERIPHERAL_TYPE_USB = 0x2000,
  PERIPHERAL_TYPE_SATA,
  PERIPHERAL_TYPE_UART,
  PERIPHERAL_TYPE_OTHER,
  PERIPHERAL_TYPE_NONE
} PER_INFO_TYPE_e;

/**
  @brief  Instance of peripheral info
**/
typedef struct {
  PER_INFO_TYPE_e  type;  ///< PER_INFO_TYPE
  uint32_t         bdf;   ///< Bus Device Function
  uint64_t         base0; ///< Base Address of the controller
  uint64_t         base1; ///< Base Address of the controller
  uint32_t         irq;   ///< IRQ to install an ISR
  uint32_t         flags;
  uint32_t         msi;   ///< MSI Enabled
  uint32_t         msix;  ///< MSIX Enabled
  uint32_t         max_pasids;
} PERIPHERAL_INFO_BLOCK;

/**
  @brief Peripheral Info Structure
**/
typedef struct {
  PERIPHERAL_INFO_HDR     header;
  PERIPHERAL_INFO_BLOCK   info[]; ///< Array of Information blocks - instantiated for each peripheral
} PERIPHERAL_INFO_TABLE;

void  pal_peripheral_create_info_table(PERIPHERAL_INFO_TABLE *per_info_table);
uint32_t pal_peripheral_is_pcie(uint32_t seg, uint32_t bus, uint32_t dev, uint32_t fn);

/**
  @brief MSI(X) controllers info structure
**/

typedef struct {
  uint32_t         vector_upper_addr; ///< Bus Device Function
  uint32_t         vector_lower_addr; ///< Base Address of the controller
  uint32_t         vector_data;       ///< Base Address of the controller
  uint32_t         vector_control;    ///< IRQ to install an ISR
  uint32_t         vector_irq_base;   ///< Base IRQ for the vectors in the block
  uint32_t         vector_n_irqs;     ///< Number of irq vectors in the block
  uint32_t         vector_mapped_irq_base; ///< Mapped IRQ number base for this MSI
} PERIPHERAL_VECTOR_BLOCK;

typedef struct PERIPHERAL_VECTOR_LIST_STRUCT {
  PERIPHERAL_VECTOR_BLOCK vector;
  struct PERIPHERAL_VECTOR_LIST_STRUCT *next;
} PERIPHERAL_VECTOR_LIST;

uint32_t pal_get_msi_vectors(uint32_t seg, uint32_t bus, uint32_t dev, uint32_t fn, PERIPHERAL_VECTOR_LIST **mvector);

#define LEGACY_PCI_IRQ_CNT 4  // Legacy PCI IRQ A, B, C. and D
#define MAX_IRQ_CNT 0xFFFF    // This value is arbitrary and may have to be adjusted

typedef struct {
  uint32_t  irq_list[MAX_IRQ_CNT];
  uint32_t  irq_count;
} PERIFERAL_IRQ_LIST;

typedef struct {
  PERIFERAL_IRQ_LIST  legacy_irq_map[LEGACY_PCI_IRQ_CNT];
} PERIPHERAL_IRQ_MAP;

#define DEVCTL_SNOOP_BIT 11        // Device control register no snoop bit

uint32_t pal_pcie_get_legacy_irq_map(uint32_t seg, uint32_t bus, uint32_t dev, uint32_t fn, PERIPHERAL_IRQ_MAP *irq_map);
uint32_t pal_pcie_is_device_behind_smmu(uint32_t seg, uint32_t bus, uint32_t dev, uint32_t fn);
uint32_t pal_pcie_get_root_port_bdf(uint32_t *seg, uint32_t *bus, uint32_t *dev, uint32_t *func);
uint32_t pal_pcie_get_device_type(uint32_t seg, uint32_t bus, uint32_t dev, uint32_t fn);
uint32_t pal_pcie_get_snoop_bit(uint32_t seg, uint32_t bus, uint32_t dev, uint32_t fn);
uint32_t pal_pcie_get_dma_support(uint32_t seg, uint32_t bus, uint32_t dev, uint32_t fn);
uint32_t pal_pcie_get_dma_coherent(uint32_t seg, uint32_t bus, uint32_t dev, uint32_t fn);
uint32_t pal_pcie_is_devicedma_64bit(uint32_t seg, uint32_t bus, uint32_t dev, uint32_t fn);
uint32_t pal_pcie_device_driver_present(uint32_t seg, uint32_t bus, uint32_t dev, uint32_t fn);
uint32_t pal_pcie_scan_bridge_devices_and_check_memtype(uint32_t seg, uint32_t bus,
                                                            uint32_t dev, uint32_t fn);
uint32_t pal_pcie_get_rp_transaction_frwd_support(uint32_t seg, uint32_t bus, uint32_t dev, uint32_t fn);
uint32_t pal_device_lock(uint32_t bdf);
uint32_t pal_device_unlock(uint32_t bdf);

/* Common Definitions */
void     pal_print(char8_t *string, uint64_t data);
void     pal_uart_print(int log, const char *fmt, ...);
void     pal_print_raw(uint64_t addr, char8_t *string, uint64_t data);
uint32_t pal_strncmp(char8_t *str1, char8_t *str2, uint32_t len);
void    *pal_memcpy(void *dest_buffer, void *src_buffer, uint32_t len);
void    *pal_mem_alloc(uint32_t size);
void    *pal_mem_calloc(uint32_t num, uint32_t size);
void    *pal_mem_alloc_cacheable(uint32_t bdf, uint32_t size, void **pa);
void     pal_mem_free(void *buffer);
int      pal_mem_compare(void *src, void *dest, uint32_t len);
void     pal_mem_set(void *buf, uint32_t size, uint8_t value);
void     pal_mem_free_cacheable(uint32_t bdf, unsigned int size, void *va, void *pa);
void    *pal_mem_virt_to_phys(void *va);
void    *pal_mem_phys_to_virt(uint64_t pa);
void     pal_mmu_add_mmap(void);
void    *pal_mmu_get_mmap_list(void);
uint32_t pal_mmu_get_mapping_count(void);

uint64_t pal_time_delay_ms(uint64_t time_ms);
void     pal_mem_allocate_shared(uint32_t num_pe, uint32_t sizeofentry);
void     pal_mem_free_shared(void);
uint64_t pal_mem_get_shared_addr(void);

uint8_t  pal_mmio_read8(uint64_t addr);
uint16_t pal_mmio_read16(uint64_t addr);

uint32_t pal_mem_page_size(void);
void    *pal_mem_alloc_pages(uint32_t num_pages);
void     pal_mem_free_pages(void *page_base, uint32_t num_pages);
void    *pal_aligned_alloc(uint32_t alignment, uint32_t size);

uint32_t pal_mmio_read(uint64_t addr);
uint64_t pal_mmio_read64(uint64_t addr);
void     pal_mmio_write8(uint64_t addr, uint8_t data);
void     pal_mmio_write16(uint64_t addr, uint16_t data);
void     pal_mmio_write(uint64_t addr, uint32_t data);
void     pal_mmio_write64(uint64_t addr, uint64_t data);

void     pal_mem_set(void *Buf, uint32_t Size, uint8_t Value);

void     pal_pe_update_elr(void *context, uint64_t offset);
uint64_t pal_pe_get_esr(void *context);
uint64_t pal_pe_get_elr(void *context);
uint64_t pal_pe_get_far(void *context);
void     pal_pe_data_cache_ops_by_va(uint64_t addr, uint32_t type);

/* Non-Volatile Memory functions definitioins */
void pal_write_reset_status(uint64_t nvm_mem, uint32_t status);
uint32_t pal_read_reset_status(uint64_t nvm_mem);
void pal_save_global_test_data(uint64_t nvm_mem, uint32_t total_tests,
                               uint32_t tests_passed, uint32_t tests_failed);
void pal_restore_global_test_data(uint64_t nvm_mem, uint32_t *total_tests,
                                  uint32_t *tests_passed, uint32_t *tests_failed);

#define CLEAN_AND_INVALIDATE  0x1
#define CLEAN                 0x2
#define INVALIDATE            0x3

/* Exerciser definitions */
#define MAX_ARRAY_SIZE 32
#define TEST_REG_COUNT 10
#define TEST_DDR_REGION_CNT 16
#define RID_VALID      1
#define RID_NOT_VALID  0

#define EXERCISER_ID   0xED0113B5 //device id + vendor id

typedef enum {
    TYPE0 = 0x0,
    TYPE1 = 0x1,
} EXERCISER_CFG_HEADER_TYPE;

typedef enum {
    CFG_READ   = 0x0,
    CFG_WRITE  = 0x1,
} EXERCISER_CFG_TXN_ATTR;

typedef enum {
    EDMA_NO_SUPPORT   = 0x0,
    EDMA_COHERENT     = 0x1,
    EDMA_NOT_COHERENT = 0x2,
    EDMA_FROM_DEVICE  = 0x3,
    EDMA_TO_DEVICE    = 0x4
} EXERCISER_DMA_ATTR;

typedef enum {
    SNOOP_ATTRIBUTES = 0x1,
    LEGACY_IRQ       = 0x2,
    MSIX_ATTRIBUTES  = 0x3,
    DMA_ATTRIBUTES   = 0x4,
    P2P_ATTRIBUTES   = 0x5,
    PASID_ATTRIBUTES = 0x6,
    CFG_TXN_ATTRIBUTES = 0x7,
    ATS_RES_ATTRIBUTES = 0x8,
    TRANSACTION_TYPE  = 0x9,
    NUM_TRANSACTIONS  = 0xA,
    ADDRESS_ATTRIBUTES = 0xB,
    DATA_ATTRIBUTES = 0xC,
    ERROR_INJECT_TYPE = 0xD
} EXERCISER_PARAM_TYPE;

typedef enum {
    TXN_REQ_ID     = 0x0,
    TXN_ADDR_TYPE  = 0x1,
    TXN_REQ_ID_VALID    = 0x2,
} EXERCISER_TXN_ATTR;

typedef enum {
    AT_UNTRANSLATED = 0x0,
    AT_TRANS_REQ    = 0x1,
    AT_TRANSLATED   = 0x2,
    AT_RESERVED     = 0x3
} EXERCISER_TXN_ADDR_TYPE;

typedef enum {
    EXERCISER_RESET = 0x1,
    EXERCISER_ON    = 0x2,
    EXERCISER_OFF   = 0x3,
    EXERCISER_ERROR = 0x4
} EXERCISER_STATE;

typedef enum {
    START_DMA     = 0x1,
    GENERATE_MSI  = 0x2,
    GENERATE_L_INTR = 0x3,  //Legacy interrupt
    MEM_READ      = 0x4,
    MEM_WRITE     = 0x5,
    CLEAR_INTR    = 0x6,
    PASID_TLP_START = 0x7,
    PASID_TLP_STOP  = 0x8,
    TXN_NO_SNOOP_ENABLE  = 0x9,
    TXN_NO_SNOOP_DISABLE = 0xa,
    START_TXN_MONITOR    = 0xb,
    STOP_TXN_MONITOR     = 0xc,
    ATS_TXN_REQ          = 0xd,
    INJECT_ERROR         = 0xe,
    ATS_INV_CACHE        = 0xf
} EXERCISER_OPS;

typedef enum {
    ACCESS_TYPE_RD = 0x0,
    ACCESS_TYPE_RW = 0x1
} ECAM_REG_ATTRIBUTE;

struct ecam_reg_data {
    uint32_t offset;    //Offset into 4096 bytes ecam config reg space
    uint32_t attribute;
    uint32_t value;
};

struct exerciser_data_cfg_space {
    struct ecam_reg_data reg[TEST_REG_COUNT];
};

typedef enum {
    DEVICE_nGnRnE = 0x0,
    DEVICE_nGnRE  = 0x1,
    DEVICE_nGRE   = 0x2,
    DEVICE_GRE    = 0x3
} ARM_DEVICE_MEM;

typedef enum {
    NORMAL_NC = 0x4,
    NORMAL_WT = 0x5
} ARM_NORMAL_MEM;

typedef enum {
    MMIO_PREFETCHABLE = 0x0,
    MMIO_NON_PREFETCHABLE = 0x1
} BAR_MEM_TYPE;

struct exerciser_data_bar_space {
    void *base_addr;
    BAR_MEM_TYPE type;
};

typedef union exerciser_data {
    struct exerciser_data_cfg_space cfg_space;
    struct exerciser_data_bar_space bar_space;
} exerciser_data_t;

typedef enum {
    EXERCISER_DATA_CFG_SPACE = 0x1,
    EXERCISER_DATA_BAR0_SPACE = 0x2,
    EXERCISER_DATA_MMIO_SPACE = 0x3,
} EXERCISER_DATA_TYPE;

uint32_t pal_is_bdf_exerciser(uint32_t bdf);
uint32_t pal_exerciser_set_param(EXERCISER_PARAM_TYPE type, uint64_t value1, uint64_t value2, uint32_t bdf);
uint32_t pal_exerciser_get_param(EXERCISER_PARAM_TYPE type, uint64_t *value1, uint64_t *value2, uint32_t bdf);
uint32_t pal_exerciser_set_state(EXERCISER_STATE state, uint64_t *value, uint32_t bdf);
uint32_t pal_exerciser_get_state(EXERCISER_STATE *state, uint32_t bdf);
uint32_t pal_exerciser_ops(EXERCISER_OPS ops, uint64_t param, uint32_t instance);
uint32_t pal_exerciser_get_data(EXERCISER_DATA_TYPE type, exerciser_data_t *data, uint32_t bdf, uint64_t ecam);

typedef enum {
  RMSD_WRITE_PROTECT = 0,
  RMSD_FULL_PROTECT = 1,
  RMSD_PROTECT = 2
} RMSD_SECURITY_PROPERTY;

typedef enum {
  PCIE_RP = 0,
  INTERCONNECT = 1
} REGISTER_TYPE;

typedef struct {
  uint32_t type;
  uint32_t bdf;
  uint64_t address;
  uint32_t property;
} REGISTER_INFO_TABLE;

uint32_t pal_register_get_num_entries(void);
void pal_register_create_info_table(REGISTER_INFO_TABLE *registerInfoTable);

#endif

