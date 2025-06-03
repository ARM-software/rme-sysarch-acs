RME System ACS Platform Porting Guide
=====================================


1. Overview to RME ACS
======================


1.1 RME System ACS and its design
----------------------------------

The Arm Confidential Compute Architecture (Arm CCA) enables secure execution environments called
Realms. These allow protection of VM or application data from even privileged software. To validate
hardware compliance, Arm provides a self-checking, portable C-based test suite called the
Architecture Compliance Suite (ACS).

ACS is built in a layered architecture that consists of the following components:

- **PAL (Platform Abstraction Layer):** Platform-specific APIs and data
- **VAL (Validation Abstraction Layer):** Platform-independent logic that calls PAL
- **Test Pool:** Implements the actual tests
- **Application Layer:** Orchestrates and allocates tables for test execution


1.2 Overview of RME Tests
-------------------------

.. list-table:: Test Environments and Suites
   :header-rows: 1
   :widths: 30 70

   * - Test Environment
     - Test Suites
   * - UEFI Shell
     - RME, GIC, SMMU, Legacy System, DA, DPT, MEC
   * - Bare-metal
     - RME, GIC, SMMU, Legacy System, DA, DPT, MEC

1.3 Boot Framework
------------------

The bootwrapper is a simple implementation of a boot loader to boot up the system and transition
to the ACS where a specific set of tests are run.

The bootwrapper initializes the hardware and loads the ACS into memory, allowing the system to start up,
independent of UEFI and execute ACS tests automatically. This reduces porting complexity for partners
and provides off-the-shelf system initialization code.

1.3.1 Boot Process and Boot Flow
--------------------------------

The boot process is the sequence of operations that occurs when a system is powered on or restarted,
allowing it to transition from a power-off state to an operational state.

A boot loader (or boot manager) is responsible for initiating this process and loading the operating
system or test environment. In this context, the TF-A boot path for AArch64 includes:

- BL1: Trusted ROM
- BL2: Platform Init Firmware
- BL31: EL3 Runtime Software
- BL33: Non-trusted Firmware (Baremetal ACS)

--------------------------------
**Figure 1-1: System Boot Flow**
--------------------------------

::

        Root World             |        Non-secure World
        ==========             |        =================
                               |
    +---------------------+    |    
    |      Boot ROM       |    |    
    |        (BL1)        |    |    
    +---------------------+    |    
              |                |    
           (1)|                |    
              v                |    
    +---------------------+    |    
    | Platform Init FW    |    |    
    |       (BL2)         |    |    
    +---------------------+    |    
              |                |    
           (2)|                |    
              v                |    
    +---------------------+    |     +------------------------+
    |  EL3 Runtime FW     |--------->|     Baremetal ACS      |
    |       (BL31)        |  (3)     |         (BL33)         |
    +---------------------+          +------------------------+

1.3.2 Boot Framework for Bare-metal
-----------------------------------

With the introduction of `bootwrapper`, the UEFI layer is bypassed in the ACS boot flow.

RME ACS with bootwrapper runs as non-trusted firmware at BL33.

---------------------------------------
**Figure 1-2: ACS Boot Framework Flow**
---------------------------------------

::

                          +--------------------+
                          |     ARM TF-A       |
                          +---------+----------+
                                    |
                          +---------v----------+
                          |    Stage BL1       |
                          +---------+----------+
                                    |
                          +---------v----------+
                          |    Stage BL32      |
                          +---------+----------+
                                    |
                          +---------v----------+
                          | Load Image at BL33 |
                          +---------+----------+
          ARM TF-A                  |
          --------------------------|----------------------------
          System ACS                v
              +---------------------------------------------+
              |            Bootwrapper Execution            |
              |  +---------------------------------------+  |
              |  |        Setup Vector Table             |  |
              |  +---------------------------------------+  |
              |  |    ICache / DCache Invalidation       |  |
              |  +---------------------------------------+  |
              |  |            Stack Init                 |  |
              |  +---------------------------------------+  |
              |  |         BSS Region Init               |  |
              |  +---------------------------------------+  |
              |  | Memory Mapping (Devices/Peripherals)  |  |
              |  +---------------------------------------+  |
              |  |        Page Table Creation            |  |
              |  +---------------------------------------+  |
              |  |              MMU Init                 |  |
              |  +---------------------------------------+  |
              |  |   PCIe, SMMU, GIC Initialization      |  |
              |  +---------------------------------------+  |
              |  |             Test Suite                |  |
              |  +---------------------------------------+  |
              +---------------------------------------------+


2. Execution of RME ACS
=======================

This section provides information on the execution of the RME ACS on a full-chip SoC emulation
environment.

2.1 SoC Emulation Environment
-----------------------------

Executing RME ACS on a full-chip emulation environment requires implementation of the Platform
Abstraction Layer (PAL).
PAL provides SoC-specific details including:

- Capabilities
- Base addresses
- IRQ numbers

In UEFI systems, this is gathered from UEFI tables. In bare-metal, a tabular format is used instead
and populated manually in code.


2.2 Bare-metal Boot Requirements
--------------------------------

This section details system-specific definitions required for booting RME ACS in a bare-metal setup.

.. code-block:: c

   #define PLARFORM_MEMORY_POOL_SIZE              (250 * 100000)
   #define PLATFORM_SHARED_MEMORY_REGION          0x100000
   #define PLATFORM_NORMAL_WORLD_IMAGE_BASE       0x88000000
   #define PLATFORM_NORMAL_WORLD_IMAGE_SIZE       0x4000000


`PLATFORM_NORMAL_WORLD_IMAGE_BASE` is the entry point to BL33.


2.3 UEFI Shell Application
--------------------------

This section provides information on executing tests from the UEFI Shell application.

**Command Syntax**

.. code-block:: shell

   Shell> rme.efi [-v <n>] [-skip <x,y,z>] [-t <test id>] [-m <module id>]

**Argument Descriptions**

+----------+---------------------------------------------------------------+
| Argument | Description                                                   |
+==========+===============================================================+
| -v       | Print verbosity level (1 to 5)                                |
| -skip    | Skip specific tests or entire modules                         |
| -t       | Run a single test                                             |
| -m       | Run all tests in a single module (overrides -t)               |
+----------+---------------------------------------------------------------+

**Examples**

.. code-block:: shell

   Shell> rme.efi -v 2 -skip gic,rme_support_in_pe

This command prints debug-level logs and skips GIC module and test rme_support_in_pe.

.. code-block:: shell

   Shell> rme.efi -m rme -skip mec_effect_of_popa_cmo

This command runs only the RME module and skips RME test mec_effect_of_popa_cmo.


3. PAL APIs and Their Details
=============================

.. list-table::
   :header-rows: 1
   :widths: 50 15 30

   * - Function Prototype
     - Bare-metal Implementation
     - UEFI Implementation
   * - ``void pal_pe_create_info_table(PE_INFO_TABLE *PeTable);``
     - Yes
     - Yes
   * - ``void pal_pe_call_smc(ARM_SMC_ARGS *args);``
     - Yes
     - Yes
   * - ``void pal_pe_execute_payload(ARM_SMC_ARGS *args);``
     - Yes
     - Yes
   * - ``void pal_pe_update_elr(void *context,uint64_t offset);``
     - Platform-specific
     - Yes
   * - ``uint64_t pal_pe_get_esr(void *context);``
     - Platform-specific
     - Yes
   * - ``void pal_pe_data_cache_ops_by_va(uint64_t addr, uint32_t type);``
     - Yes
     - Yes
   * - ``uint64_t pal_pe_get_far(void *context);``
     - Platform-specific
     - Yes
   * - ``uint32_t pal_pe_install_esr(uint32_t exception_type, void (*esr)(uint64_t, void *));``
     - Platform-specific
     - Yes
   * - ``uint32_t pal_pe_get_num();``
     - Yes
     - Yes
   * - ``uint32_t pal_psci_get_conduit(void);``
     - Platform-specific
     - Yes
   * - ``void pal_gic_create_info_table(GIC_INFO_TABLE* gic_info_table);``
     - Yes
     - Yes
   * - ``uint32_t pal_gic_install_isr(uint32_t int_id, void(*isr)(void));``
     - Platform-specific
     - Yes
   * - ``uint32_t pal_gic_end_of_interrupt(uint32_t int_id);``
     - Platform-specific
     - Yes
   * - ``uint32_t pal_gic_request_irq(unsigned int irq_num, unsigned int mapped_irq_num, void *isr);``
     - Platform-specific
     - Yes
   * - ``void pal_gic_free_irq(unsigned int irq_num, unsigned int mapped_irq_num);``
     - Platform-specific
     - Yes
   * - ``uint32_t pal_gic_set_intr_trigger(uint32_t int_id, INTR_TRIGGER_INFO_TYPE_etrigger_type);``
     - Platform-specific
     - Yes
   * - ``void pal_timer_create_info_table(TIMER_INFO_TABLE *timer_info_table);``
     - Yes
     - Yes
   * - ``void pal_wd_create_info_table(WD_INFO_TABLE *wd_table);``
     - Yes
     - Yes
   * - ``void pal_iovirt_create_info_table(IOVIRT_INFO_TABLE *iovirt);``
     - Yes
     - Yes
   * - ``uint64_t pal_iovirt_get_rc_smmu_base(IOVIRT_INFO_TABLE *iovirt, uint32_t rc_seg_num, uint32_t rid);``
     - Yes
     - Yes
   * - ``void pal_peripheral_create_info_table(PERIPHERAL_INFO_TABLE *per_info_table);``
     - Yes
     - Yes
   * - ``void pal_memory_create_info_table(MEMORY_INFO_TABLE *memoryInfoTable);``
     - Platform-specific
     - Yes
   * - ``uint64_t pal_memory_ioremap(void *addr, uint32_t size, uint32_t attr);``
     - Platform-specific
     - Platform-specific
   * - ``void pal_memory_unmap(void *addr);``
     - Platform-specific
     - Platform-specific
   * - ``uint8_t pal_mmio_read8(uint64_t addr);``
     - Yes
     - Yes
   * - ``uint16_t pal_mmio_read16(uint64_t addr);``
     - Yes
     - Yes
   * - ``uint32_t pal_mmio_read(uint64_t addr);``
     - Yes
     - Yes
   * - ``uint64_t pal_mmio_read64(uint64_t addr);``
     - Yes
     - Yes
   * - ``void pal_mmio_write8(uint64_t addr, uint8_t data);``
     - Yes
     - Yes
   * - ``void pal_mmio_write16(uint64_t addr, uint16_t data);``
     - Yes
     - Yes
   * - ``void pal_mmio_write(uint64_t addr, uint32_t data);``
     - Yes
     - Yes
   * - ``void pal_mmio_write64(uint64_t addr, uint64_t data);``
     - Yes
     - Yes
   * - ``void pal_print(char8_t *string, uint64_t data);``
     - Platform-specific
     - Yes
   * - ``void pal_print_raw(uint64_t addr, char *string, uint64_t data);``
     - Yes
     - Yes
   * - ``void pal_mem_free(void *buffer);``
     - Platform-specific
     - Yes
   * - ``int pal_mem_compare(void *src, void *dest, uint32_t len);``
     - Yes
     - Yes
   * - ``void pal_mem_set(void *buf, uint32_t size, uint8_t value);``
     - Yes
     - Yes
   * - ``void pal_mem_allocate_shared(uint32_t num_pe, uint32_t sizeofentry);``
     - Yes
     - Yes
   * - ``uint64_t pal_mem_get_shared_addr(void);``
     - Yes
     - Yes
   * - ``void pal_mem_free_shared(void);``
     - Yes
     - Yes
   * - ``void *pal_mem_alloc(uint32_t size);``
     - Platform-specific
     - Yes
   * - ``void *pal_mem_virt_to_phys(void *va);``
     - Platform-specific
     - Platform-specific
   * - ``void *pal_mem_alloc_cacheable(uint32_t Bdf, uint32_t Size, void **Pa);``
     - Platform-specific
     - Yes
   * - ``void pal_mem_free_cacheable(uint32_t Bdf, uint32_t Size, void *Va, void *Pa);``
     - Platform-specific
     - Yes
   * - ``void *pal_mem_phys_to_virt(uint64_t Pa);``
     - Platform-specific
     - Platform-specific
   * - ``uint32_t pal_strncmp(char8_t *str1, char8_t *str2, uint32_t len);``
     - Yes
     - Yes
   * - ``void *pal_memcpy(void *dest_buffer, void *src_buffer, uint32_t len);``
     - Yes
     - Yes
   * - ``uint64_t pal_time_delay_ms(uint64_t time_ms);``
     - Platform-specific
     - Yes
   * - ``uint32_t pal_mem_page_size();``
     - Platform-specific
     - Yes
   * - ``void *pal_mem_alloc_pages(uint32_t NumPages);``
     - Platform-specific
     - Yes
   * - ``void pal_mem_free_pages(void *PageBase, uint32_t NumPages);``
     - Platform-specific
     - Yes
   * - ``void *pal_mem_calloc(uint32_t num, uint32_t Size);``
     - Platform-specific
     - Yes
   * - ``void *pal_aligned_alloc(uint32_t alignment, uint32_t size);``
     - Platform-specific
     - Yes
   * - ``void pal_mem_free_aligned(void *buffer);``
     - Platform-specific
     - Yes
   * - ``void pal_driver_uart_pl011_putc(int c);``
     - Yes
     - Yes

Note: Platform-specific means the partner must provide their implementation for that PAL API.


4. Prerequisites
================

ACK test requires to execute the code at EL3 for GPT/MMU modification, so ensure that the following
requirements are met.

- When Non-secure EL2 executes 'smc' with SMC FID, 0xC2000060, EL3 Firmware is expected to branch to
  plat_arm_acs_smc_handler function which is predefined in ACK.
- To generate binary file for EL3 code, follow the build steps in README of val_el3.
- 2MB memory must be flat mapped in EL3-MMU with Root access PAS and GPI as ROOT/ALL_ACCESS, which
  is used for MMU tables in EL3.
- 2MB Free memory which is used as PA in tests.
- 2MB memory that is flat-mapped as Realm Access PAS which is used for Realm SMMU tables.
- 4KB/16KB/64KB shared memory that is used,
  a) as a structure, shared_data_el32 to share data between EL3 and EL2 domains,
  b) to save/restore registers and sp_el3, and tf-handler entry address.
- 512MB Unused VA space (within 48bits) that is used in the tests as VA.
- 4KB of Non-Volatile memory that is used only in reset tests.


5. Abbreviations
================

.. list-table::
  :header-rows: 1
  :widths: 20 80

  * - Abbreviation
    - Expansion
  * - ACPI
    - Advanced Configuration and Power Interface
  * - ACS
    - Architecture Compliance Suite
  * - BDF
    - Bus, Device, and Function
  * - CMO
    - Cache Maintenance Operation
  * - DA
    - Device Assignment
  * - DMA
    - Direct Memory Access
  * - DPT
    - Device Permission Table
  * - ECAM
    - Enhanced Configuration Access Mechanism
  * - ELx
    - Exception Level x (where x can be 0 to 3)
  * - GIC
    - Generic Interrupt Controller
  * - HVC
    - Hyper Visor Call
  * - IDE
    - Integrity and Data Encryption
  * - IOMMU
    - Input-Output Memory Management Unit
  * - IORT
    - Input Output Remapping Table
  * - IOVIRT
    - Input Output Virtualization
  * - ITS
    - Interrupt Translation Service
  * - KM
    - Key Management
  * - LPI
    - Locality-specific Peripheral Interrupt
  * - MEC
    - Memory Encryption Context
  * - MECID
    - Memory Encryption Context Identifier
  * - MPAM
    - Memory System Resource Partitioning and Monitoring
  * - MSI
    - Message-Signaled Interrupt
  * - MTE
    - Memory Tagging Extension
  * - MMU
    - Memory Management Unit
  * - PAL
    - Platform Abstraction Layer
  * - PCIe
    - Peripheral Component Interconnect Express
  * - PE
    - Processing Element
  * - PoC
    - Point of Coherence
  * - PoE
    - Point of Encryption
  * - PoPA
    - Point of Physical Aliasing
  * - PSCI
    - Power State Coordination Interface
  * - RC
    - Root Complex
  * - RCiEP
    - Root Complex integrated End Point
  * - RP
    - Root Port
  * - RME
    - Realm Management Extension
  * - RMM
    - Realm Management Monitor
  * - RMSD
    - Realm Management Security Domain
  * - SBSA
    - Server Base System Architecture
  * - SMC
    - Secure Monitor Call
  * - SMMU
    - System Memory Management Unit
  * - SoC
    - System on Chip
  * - TDI
    - TEE Device Interface
  * - TDISP
    - TEE Device Interface Security Protocol
  * - TEE
    - Trusted Execution Environment
  * - UEFI
    - Unified Extensible Firmware Interface
  * - UART
    - Universal Asynchronous Receiver and Transmitter
  * - VAL
    - Validation Abstraction Layer


License
=======

RME System ACS is distributed under Apache v2.0 License.

*Copyright (c) 2023-2025, Arm Limited and Contributors. All rights reserved.*
