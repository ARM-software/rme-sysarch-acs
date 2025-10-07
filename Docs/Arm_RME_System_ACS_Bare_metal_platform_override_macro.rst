Bare-metal Macros for Platform Configuration
============================================

This section documents the bare-metal macros for PE, GIC, Timer, PCIe, and SMMU components as used in the RME ACS platform override definitions.

Steps to Customize Bare-metal Code
==================================

To adapt this bare-metal platform code to your own hardware:

1. Create a new directory under `pal_baremetal/FVP/` for your platform:
   ::

        mkdir pal_baremetal/FVP/<platform_name>

2. Copy the reference implementation:
   ::

        cp -r pal_baremetal/FVP/ pal_baremetal/FVP/<platform_name>

3. Port required APIs in the relevant files under the same directory.

4. Update `pal_override_<platform_name>.h` and `pal_el3_config.h` with your platform-specific macro definitions.

5. Use the macro patterns documented below to understand how to provide your hardware's configuration.


PE Macros
---------

Platform cores are identified by index and MPIDR, with optional PMU interrupt values.

Example (8 cores):

.. code-block:: c

    #define PLATFORM_OVERRIDE_PE_CNT 0x8

    // Core 0 to 7 indexed macros
    #define PLATFORM_OVERRIDE_PE<n>_INDEX     <index>     // 0-based
    #define PLATFORM_OVERRIDE_PE<n>_MPIDR     <mpidr>     // e.g., 0x0, 0x100, ...
    #define PLATFORM_OVERRIDE_PE<n>_PMU_GSIV  <gsiv>      // e.g., 0x17

Where `<n>` ranges from 0 to PLATFORM_OVERRIDE_PE_CNT - 1.

The following macros are used to configure MMU page granularity and address size:

.. code-block:: c

    #define PLATFORM_PAGE_SIZE              0x1000  // Page size used in MMU (4KB typical)
    #define PLATFORM_OVERRIDE_MMU_IAS       48      // Input Address Size in bits
    #define PLATFORM_OVERRIDE_MMU_OAS       48      // Output Address Size in bits

.. code-block:: c

    typedef struct {
        uint32_t num_of_pe;
    } PE_INFO_HDR;

    typedef struct {
        uint32_t pe_num;
        uint32_t attr;
        uint64_t mpidr;
        uint32_t pmu_gsiv;
    } PE_INFO_ENTRY;

    typedef struct {
        PE_INFO_HDR header;
        PE_INFO_ENTRY pe_info[];
    } PE_INFO_TABLE;

GIC Macros
----------

GIC components (GICC, GICD, GICRD, GICITS, GICH, GICMSIFRAME) are described per-instance.

Example for a single GIC instance:

.. code-block:: c

    #define PLATFORM_OVERRIDE_GICD_COUNT 0x1
    #define PLATFORM_OVERRIDE_GICD_BASE_0 0x30000000
    #define PLATFORM_OVERRIDE_GICRD_COUNT 0x1
    #define PLATFORM_OVERRIDE_GICRD_BASE_0 0x300C0000
    #define PLATFORM_OVERRIDE_GICITS_COUNT 0x1
    #define PLATFORM_OVERRIDE_GICITS_BASE_0 0x30040000
    // etc. for each GIC component

    // Types and lengths are similarly indexed if multiple instances
    #define PLATFORM_OVERRIDE_GICD_TYPE 0x1001
    #define PLATFORM_OVERRIDE_GICIRD_LENGTH (0x20000*8)

Where macros with _<n> suffix are repeated for each instance, n in 0 to COUNT-1.

.. code-block:: c

    typedef struct {
        uint32_t gic_version;
        uint32_t num_gicc;
        uint32_t num_gicd;
        uint32_t num_gicrd;
        uint32_t num_gicits;
        uint32_t num_gich;
        uint32_t num_msiframes;
        uint32_t gicc_type;
        uint32_t gicd_type;
        uint32_t gicrd_type;
        uint32_t gicrd_length;
        uint32_t gicits_type;
        uint64_t gicc_base[PLATFORM_OVERRIDE_GICC_COUNT];
        uint64_t gicd_base[PLATFORM_OVERRIDE_GICD_COUNT];
        uint64_t gicrd_base[PLATFORM_OVERRIDE_GICRD_COUNT];
        uint64_t gicits_base[PLATFORM_OVERRIDE_GICITS_COUNT];
        uint64_t gicits_id[PLATFORM_OVERRIDE_GICITS_COUNT];
        uint64_t gich_base[PLATFORM_OVERRIDE_GICH_COUNT];
        uint64_t gicmsiframe_base[PLATFORM_OVERRIDE_GICMSIFRAME_COUNT];
        uint64_t gicmsiframe_id[PLATFORM_OVERRIDE_GICMSIFRAME_COUNT];
        uint32_t gicmsiframe_flags[PLATFORM_OVERRIDE_GICMSIFRAME_COUNT];
        uint32_t gicmsiframe_spi_count[PLATFORM_OVERRIDE_GICMSIFRAME_COUNT];
        uint32_t gicmsiframe_spi_base[PLATFORM_OVERRIDE_GICMSIFRAME_COUNT];
    } PLATFORM_OVERRIDE_GIC_INFO_TABLE;

Timer Macros
------------

Timer interrupt and block macros are specified per timer.

Example:

.. code-block:: c

    #define PLATFORM_OVERRIDE_PLATFORM_TIMER_COUNT 0x2
    #define PLATFORM_OVERRIDE_S_EL1_TIMER_GSIV 0x1D
    #define PLATFORM_OVERRIDE_NS_EL1_TIMER_GSIV 0x1E
    // ... similarly for each timer type and count
    // If multiple timers, use _<n> suffix, e.g.:
    #define PLATFORM_OVERRIDE_TIMER<n>_GSIV <gsiv>

.. code-block:: c

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

    typedef struct {
        uint32_t type;
        uint32_t timer_count;
        uint64_t block_cntl_base;
        uint8_t frame_num[8];
        uint64_t GtCntBase[8];
        uint64_t GtCntEl0Base[8];
        uint32_t gsiv[8];
        uint32_t virt_gsiv[8];
        uint32_t flags[8];
    } TIMER_INFO_GTBLOCK;

    typedef struct {
        TIMER_INFO_HDR header;
        TIMER_INFO_GTBLOCK gt_info[];
    } TIMER_INFO_TABLE;

PCIe Macros
-----------

These macros configure the ECAM regions and BAR addresses for PCIe root ports and endpoints.

Example for one ECAM region:

.. code-block:: c

    #define PLATFORM_OVERRIDE_NUM_ECAM 1
    #define PLATFORM_OVERRIDE_PCIE_ECAM_BASE_ADDR_0 0x60000000
    #define PLATFORM_OVERRIDE_PCIE_SEGMENT_GRP_NUM_0 0x0
    #define PLATFORM_OVERRIDE_PCIE_START_BUS_NUM_0 0x0
    #define PLATFORM_OVERRIDE_PCIE_END_BUS_NUM_0 0xFF
    // BAR macros for each ECAM region
    #define PLATFORM_OVERRIDE_PCIE_ECAM0_EP_BAR64 0x4000100000
    #define PLATFORM_OVERRIDE_PCIE_ECAM0_RP_BAR64 0x4000000000
    // ... and so on for each ECAM index

Where macros with _<n> suffix are repeated for each ECAM region (0 to NUM_ECAM-1).

.. code-block:: c

    typedef struct {
        uint64_t ecam_base;
        uint32_t segment_num;
        uint32_t start_bus_num;
        uint32_t end_bus_num;
    } PCIE_INFO_BLOCK;

    typedef struct {
        uint32_t num_entries;
        PCIE_INFO_BLOCK block[];
    } PCIE_INFO_TABLE;

    typedef struct {
        uint64_t class_code;
        uint32_t device_id;
        uint32_t vendor_id;
        uint32_t bus;
        uint32_t dev;
        uint32_t func;
        uint32_t seg;
        uint32_t dma_support;
        uint32_t dma_coherent;
        uint32_t p2p_support;
        uint32_t dma_64bit;
        uint32_t behind_smmu;
        uint32_t atc_present;
        PERIPHERAL_IRQ_MAP irq_map;
    } PCIE_READ_BLOCK;

SMMU and IOVIRT Macros
----------------------

These macros describe the number of IOVIRT nodes and SMMU components used in the platform.

Example:

.. code-block:: c

    #define IORT_NODE_COUNT 0x13
    #define IOVIRT_SMMUV3_COUNT 5
    #define IOVIRT_SMMUV2_COUNT 0
    #define RC_COUNT 0x1
    #define PMCG_COUNT 0x1
    #define IOVIRT_NAMED_COMPONENT_COUNT 2
    #define IOVIRT_ITS_COUNT 0x1
    // For each SMMU, RC, PMCG, Named Component, etc., macros with _<n> suffix are used
    // Example:
    #define IOVIRT_SMMUV3_BASE_0 0x2b400000
    #define IOVIRT_SMMUV3_BASE_1 0x2b500000
    // ... up to IOVIRT_SMMUV3_BASE_<count-1>

.. code-block:: c

    typedef struct {
        uint32_t type;
        uint32_t num_data_map;
        NODE_DATA data;
        uint32_t flags;
        NODE_DATA_MAP data_map[];
    } IOVIRT_BLOCK;

    typedef struct {
        uint32_t arch_major_rev;
        uint64_t base;
    } SMMU_INFO_BLOCK;

    typedef struct {
        uint32_t segment;
        uint32_t ats_attr;
        uint32_t cca;
        uint64_t smmu_base;
    } IOVIRT_RC_INFO_BLOCK;

    typedef struct {
        uint64_t base;
        uint32_t overflow_gsiv;
        uint32_t node_ref;
    } IOVIRT_PMCG_INFO_BLOCK;

    typedef struct {
        uint64_t smmu_base;
        uint32_t cca;
        char name[MAX_NAMED_COMP_LENGTH];
    } IOVIRT_NAMED_COMP_INFO_BLOCK;

    typedef struct {
        char identifier[MAX_CS_COMP_LENGTH];
        char dev_name[MAX_CS_COMP_LENGTH];
    } PLATFORM_OVERRIDE_CORESIGHT_COMP_INFO_BLOCK;

    typedef struct {
        PLATFORM_OVERRIDE_CORESIGHT_COMP_INFO_BLOCK component[CS_COMPONENT_COUNT];
    } PLATFORM_OVERRIDE_CS_COMP_NODE_DATA;

    typedef struct {
        uint32_t input_base;
        uint32_t id_count;
        uint32_t output_base;
        uint32_t output_ref;
    } ID_MAP;

