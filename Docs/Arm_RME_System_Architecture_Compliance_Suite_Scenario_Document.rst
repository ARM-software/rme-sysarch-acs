****************************************************************
Arm RME System Architecture Compliance Suite - Scenario Document
****************************************************************

.. contents:: Contents
  :depth: 2

Testcase checklist
==================

.. list-table::
  :header-rows: 1
  :widths: 20 30 35

  * - **Test Name**
    - **Validated rule(s)**
    - **Algorithm**
  * - 

      `rme_support_in_pe <../test_pool/rme/rme_support_in_pe.c>`_

    - 

      RGSRPS: All A-profile application PEs in the system implement the Realm Management Extension (RME).

    - 

      Read of ID_AA64PFR0_EL1.RME should return >= 1 for all PEs.

  * - 

      `rme_gprs_scrubbed_after_reset <../test_pool/rme/rme_gprs_scrubbed_after_reset.c>`_

    - 

      RNULL: GPRs must be scrubbed after reset.

    - 

      1. Select the Realm Security State of EL2 by writing to SCR_EL3.NSE and NS bit.
      2. Write GPR_WRITE_VAL to GPRs from x19-x29 using asm function and execute reset.
      3. Check if GPRs have retained their value or have they been scrubbed.

  * - 

      `rme_all_pe_has_feat_rng_or_rng_trap <../test_pool/rme/rme_all_pe_has_feat_rng_or_rng_trap.c>`_

    - 

      RQYRGG: MSD and RMSD are provided with a private interface for accessing a True Random Number Generator (TRNG) that meets the certification profile of the system.

    - 

      Check that all application PEs support FEAT_RNG or FEAT_RNG_TRAP by reading the bit[63:60] of ID_AA64ISAR0_EL1 and bits[31:28] of ID_AA64PFR0_EL1 against 0x1.

      If either of them is implemented, the test is expected to PASS.

  * - 

      `rme_gpc_for_system_resource <../test_pool/rme/rme_gpc_for_system_resource.c>`_

    - 

      RBJVZS: An access to a Resource is associated with an Access PAS in accordance with the PAS Access Table.

      RGDVSZ: A PA of an access to a memory-mapped peripheral is associated with a PAS until reaching the PAS filter assigned to protect the peripheral

      RDVPGT: A private PAS filter allows access to a register only if the Access PAS matches a Resource PAS that the register is associated with.

    - 

      Accesses with same resource PAS and access PAS are successful otherwise generates fault.

  * - 

      `rme_coherent_interconnect_supports_cmo_popa <../test_pool/rme/rme_coherent_interconnect_supports_cmo_popa.c>`_

    - 

      RXTSXB: An RME coherent interconnect supports cache maintenance operations to the PoPA.

      RLCXDB: Completion of a PoPA CMO for a given PA guarantees that both:

      - Any dirty cached or transient state associated with the PA before the PoPA has been cleaned to after the PoPA.
      - Any cached or transient state associated with the PA before the PoPA has been invalidated.

    - 

      Coherent interconnect supports CMO to PoPA.

      1. CMO to PoPA cleans dirty copy till PoPA and invalidates all cached copies.
      2. PA1 is marked as All Access Permitted.
      3. PA1 is initialized with random data.
      4. VA1 is mapped to PA1 as secure PAS in MMU with cacheable attribute.
      5. VA2 is mapped to PA1 as nonsecure in MMU with cacheable attribute.
      6. Read VA1 returns data1.
      7. Read VA2 returns data2.
      8. Store data3 in VA1.
      9. Issue CMO to PoPA for PA1 secure and nonsecure.
      10. Read of VA2 must return data4 (! = data2) (ciphertext of data3).

  * - 

      `rme_resources_aligned_to_granularity <../test_pool/rme/rme_resources_aligned_to_granularity.c>`_ & `rme_resources_are_not_physically_aliased <../test_pool/rme/rme_resources_are_not_physically_aliased.c>`_

    - 

      RKGDVK: A Resource can be associated with a PAS using a Granule Protection Table if the following conditions are met:

      - There is only a single PA within each PAS through which the Resource can be reached and the value of the PA is the same across all physical address spaces.
      - The Resource can be assigned to a PAS at page granularity.

    - 

      *rme_resources_aligned_to_granularity:* Check that the address range of resources (that need to be protected by GPT) are aligned to page granularity.

      *rme_resources_are_not_physically_aliased:* Check that the address range of resources (that need to be protected by GPT) are aligned to one another.

  * - 

      `rme_pe_do_not_have_arch_diff <../test_pool/rme/rme_pe_do_not_have_arch_diff.c>`_

    - 

      RSQMWT: Application PEs in an RME system do not have architectural differences unless this is explicitly permitted by `RME_System_Architecture_Spec`_ specification.

    - 

      Verify application PEs in an RME system do not have any architectural differences.

      Below registers list will be checked:

      CCSIDR_EL1, ID_AA64PFR0_EL1, ID_AA64PFR1_EL1, ID_AA64DFR0_EL1, ID_AA64DFR1_EL1, ID_AA64MMFR0_EL1, ID_AA64MMFR1_EL1, CTR_EL0, ID_AA64ISAR0_EL1, ID_AA64ISAR1_EL1, MPIDR_EL1, MIDR_EL1, ID_DFR0_EL1, ID_ISAR0_EL1, ID_ISAR1_EL1, ID_ISAR2_EL1, ID_ISAR3_EL1, ID_ISAR4_EL1, ID_ISAR5_EL1, ID_MMFR0_EL1, ID_MMFR1_EL1, ID_MMFR2_EL1, ID_MMFR3_EL1, ID_MMFR4_EL1, ID_PFR0_EL1, ID_PFR1_EL1, MVFR0_EL1, MVFR1_EL1, MVFR2_EL1, PMCEID0_EL0, PMCEID1_EL0, PMCR_EL0, PMBIDR_EL1, PMSIDR_EL1, ERRIDR_EL1, ERR0FR_EL1, ERR1FR_EL1, ERR2FR_EL1, ERR3FR_EL1, LORID_EL1

  * - 

      `rme_mte_region_in_root_pas <../test_pool/rme/rme_mte_region_in_root_pas.c>`_

    - 

      RJYMQD: Allocation and protection of the address range assigned to an MTE carve-out are controlled by either SSD or MSD.

    - 

      1. MTE carve-out region is not accessible by NS/S/RL accesses.
      2. NS, S and RL accesses to MTE carve-out region generate a fault (fault might not be generated).

  * - 

      `rme_encryption_for_all_pas_except_ns <../test_pool/rme/rme_encryption_for_all_pas_except_ns.c>`_

    - 

      RQDPVN: Any PAS other than the Non-secure PAS must have encryption enabled.

    - 

      1. PA1 marked as all access permitted.
      2. PA1 is mapped as VA1_S, VA2_NS, VA3_RL, VA4_RT.
      3. Store data1 using VA2_NS.
      4. Read of VA1_S, VA3_RL, VA4_RT must return unique values (!= data1).

  * - 

      `rme_pas_filter_functionality <../test_pool/rme/rme_pas_filter_functionality.c>`_

    - 

      RBJVZS: An access to a Resource is associated with an Access PAS in accordance with the PAS Access Table

      RYKVJK: A PAS filter enforces the PAS protection check by permitting access to a Resource only if the Access PAS matches a Resource PAS with which that the Resource is associated.

      RGDVSZ: A PA of an access to a memory-mapped peripheral is associated with a PAS until reaching the PAS filter assigned to protect the peripheral

    - 

      All protected memory regions are accessible only when resource PAS & access PAS are same.

      Accesses with same resource PAS and access PAS are successful.

  * - 

      `rme_realm_smem_behaviour_after_reset <../test_pool/rme/rme_realm_smem_behaviour_after_reset.c>`_

    - 

      RZQQSQ: SMEM that can be dynamically assigned to the Realm PAS, or the Secure PAS is either immediately assigned to the Root PAS or scrubbed on an RME system reset.

    - 

      1. Verify Realm SMEM does not reveal old data after system reset.
      2. Returned data is not DATA1.

  * - 

      `rme_pcie_devices_support_gpc <../test_pool/rme/rme_pcie_devices_support_gpc.c>`_

    - 

      RMZJXC: Every requester in the system is subjected to the PAS protection check

    - 

      PCIe devices are subject to PAS protection check.

      DMA transactions to secure, root and realm memory will generate fault.

  * - 

      `rme_data_encryption_beyond_popa <../test_pool/rme/rme_data_encryption_beyond_popa.c>`_

    - 

      RMLFBL (first part): External memory that is assigned to Secure PAS, Realm PAS, or Root PAS must be encrypted using a method that provides a different encryption context for each PAS

    - 

      Data is encrypted when written in memory/any shared cache beyond PoPA.

      1. PA1 is marked as All Access Permitted.
      2. Store DATA1 in PA1_RT; CMO till PoPA (for all PAS).
      3. Read using PA_S return DATA2.
      4. READ using PA_RL return DATA3.
      5. READ using PA_NS return DATA4.
      6. DATA1! = DATA2! = DATA3! = DATA4.
      7. Note: The third point of this rule is not validated in ACS.

  * - 

      `rme_data_encryption_with_different_tweak <../test_pool/rme/rme_data_encryption_with_different_tweak.c>`_

    - 

      RMLFBL (second part): External memory that is assigned to Secure PAS, Realm PAS, or Root PAS must be encrypted using a method that provides a different address tweak for each encryption data block, such as a 128-bit memory block

    - 

      Data is encrypted with a different tweak in each 128-bit of data block.

      1. Store DATA1 in PA1_S and (PA1_S + 16).
      2. CMO to PoPA using S and NS PAS.
      3. Read PA1_NS returns DATA2.
      4. Read PA1_NS+16 returns DATA3.
      5. DATA2 and DATA3 are different.

  * - 

      `rme_msd_smem_in_root_pas <../test_pool/rme/rme_msd_smem_in_root_pas.c>`_

    - 

      RCSSDG: MSD SMEM is in the Root PAS.

    - 

      MSD SMEM is in ROOT PAS.

      1. Access MSD SMEM with S, NS, RT & RL access PAS.
      2. Only RT accesses are successful.

  * - 

      `rme_realm_smem_in_realm_pas <../test_pool/rme/rme_realm_smem_in_realm_pas.c>`_

    - 

      RCMMCZ: Realm SMEM is in realm PAS (if Realm SMEM is defined statically).        

    - 

      1. Verify that Realm SMEM is in realm PAS (if Realm SMEM is defined statically).
      2. Root, Secure and Non-secure access to Realm SMEM returns error.

  * - 

      `rme_snoop_filter_considers_pas <../test_pool/rme/rme_snoop_filter_considers_pas.c>`_ & `rme_memory_associated_with_pas_till_popa <../test_pool/rme/rme_memory_associated_with_pas_till_popa.c>`_

    - 

      RWFQKD: A PA that targets memory that can be cached is associated with a PAS until reaching the PoPA.

      RFRMJJ: Where a PA is associated with a PAS, any PA compared operation includes the PAS.

    - 

      *Test rme_memory_associated_with_pas_till_popa:*

      1. A location PA1 is marked as “All Access Permitted” in GPT.
      2. Cacheable store to PA1_NS is not visible to PA1_RL, PA1_RT, PA1_S.

      *Test rme_snoop_filter_considers_pas:*

      1. PA1 is marked as Shareable in both PE0 & PE1.
      2. PE0: PA1 marked as Root PAS.
      3. PE1: PA1 marked as Realm PAS.
      4. PE1 must not generate snoop access to PE0.
      5. As a result, update to PE0.

  * - 

      `rme_cmo_popa_for_cacheability_shareability <../test_pool/rme/rme_cmo_popa_for_cacheability_shareability.c>`_

    - 

      RFXQCD: A PoPA CMO applies to any cache before the PoPA, including system caches that are located beyond the Point of Coherency.

      RQBNJF: A PoPA CMO applies to any cached copy in the system with the specified {PAS, PA} regardless of both:

      - The shareability domain it was cached with.
      - Whether the system supports a single or multiple Outer Shareable shareability domains

    - 

      1. PA1 is marked as All Access Permitted.
      2. PA1 is initialized with random data.
      3. VA1 is mapped to PA1 as secure PAS in MMU with Non-cacheable attribute.
      4. VA2 is mapped to PA1 as nonsecure in MMU with Non-cacheable attribute.
      5. Read VA1 returns data1.
      6. Read VA2 returns data2.
      7. Store data3 in VA1.
      8. Issue CMO to PoPA for PA1 secure and nonsecure.
      9. Read of VA2 must return data4 (! = data2) (ciphertext of data3).

  * - 

      `rme_interconnect_supports_tlbi_pa <../test_pool/rme/rme_interconnect_supports_tlbi_pa.c>`_

    - 

      RJRJSQ: An RME coherent interconnect complies with a Distributed Virtual Memory (DVM) version that supports Realm Translation Regimes and TLB Invalidate by PA operations.

    - 

      Check interconnect supports TLBI PA operation by changing GPT entry.

      1. Map VA1 to PA1 as secure memory both in MMU and GPT.
      2. Access VA1.
      3. Change PA1 to non-secure using Undelegated algo.
      4. Issue TLBI PA as a part of undelegated algorithm.
      5. Access to VA1 will generate fault.

  * - 

      `rme_ns_encryption_is_immutable <../test_pool/rme/rme_ns_encryption_is_immutable.c>`_

    - 

      RVSMPS: The decision to enable encryption for the Non-secure PAS is either hardwired or defined at boot and immutable once set.

    - 

      1. NSencryption(enable=1).
      2. Once enabled then we cannot disable by calling NSencryption(enable=0).
      3. Store data1 in PA1_NS.
      4. Read PA1_NS will return data1.
      5. CMO to PoPA for PA1.
      6. Enable NS encryption.
      7. CMO to PoPA for PA1.
      8. Read of PA1_NS will return data2 which is not same as data1.
      9. Disable NS encryption.
      10. CMO to PoPA.
      11. Read of PA1 still returns data2.

  * - 

      `rme_pe_context_after_exit_wfi <../test_pool/rme/rme_pe_context_after_exit_wfi.c>`_ & `rme_pe_context_after_pe_suspend <../test_pool/rme/rme_pe_context_after_pe_suspend.c>`_

    - 

      RMLJVR: On an exit from a low power state in which system context is preserved, power control guarantees that MSD state is fully preserved. If MSD state is not preserved, power control applies an RME system reset.

    - 

      PE context must be preserved after exit from WFI or suspend.

      1. Install the ISR for PE timer interrupt ID.
      2. Save all the RME related PE registers before going to low power mode or CPU suspend.
      3. Start the PE timer that is set to pe_timer_ticks.
      4. Initiate the low power state entry:

      - For rme_pe_context_after_exit_wfi (low power state entry), initiate using WFI instruction.
      - For rme_pe_context_after_pe_suspend (CPU suspend state entry), initiate using PSCI_CPU_SUSPEND smc call.

      5. PE interrupt wakes up the PE before the timeout and is handled.
      6. The same PE registers are checked against the saved values.
      7. The test expects the values to be similar and if so, test will PASS, otherwise will FAIL.

  * - 

      `rme_msd_save_restore_mem_in_root_pas <../test_pool/rme/rme_msd_save_restore_mem_in_root_pas.c>`_

    - 

      RZNLSZ: Save/Restore operations for MSD state can only be done by MSD or a Trusted subsystem and use on-chip storage that is not accessible from Realm PAS, Secure PAS or Non-secure PAS.

    - 

      MSD state save restore location is not accessible via S/NS/RL accesses.

  * - 

      `rme_rnvs_in_root_pas <../test_pool/rme/rme_rnvs_in_root_pas.c>`_

    - 

      RQCHPW: The system supports a method for permanently blocking write access from application PEs to all RNVS parameters.

    - 

      RNVS programming functions (memory mapped: RME_RNVS_MAILBOX_MEM) can only be accessed from Root PAS.

      Non-Root access to RNVS programming functions generate faults.

      Note: Review PAL function after implementation. We can test mailbox is not accessible from non-Root PAS.

  * - 

      `rme_root_wdog_from_root_pas <../test_pool/rme/rme_root_wdog_from_root_pas.c>`_ & `rme_root_wdog_fails_in_non_root_state <../test_pool/rme/rme_root_wdog_fails_in_non_root_state.c>`_

    - 

      RZHBBL: The memory-mapped registers of a Root watchdog are in the Root PAS.

      RVXGBP: A Root watchdog can trigger an RME system reset when predefined expiration conditions are met.

    - 

      Programming of Root watchdog, RT_WDOG_CTRL register, from ROOT state only will generate an interrupt.

      The rme_root_wdog_from_root_pas will generate a watchdog interrupt when the Root watchdog is programmed from the Root PAS.

      The rme_root_wdog_fails_in_non_root_state won't generate a watchdog interrupt when the Root watchdog is programmed from the non-Root PAS, in this case, from Non-Secure PAS.

  * - 

      `rme_pas_filter_in_inactive_mode <../test_pool/rme/rme_pas_filter_in_inactive_mode.c>`_

    - 

      RDQTSG: An MPE or a PAS filter in a non-ACTIVE mode in which context is not fully retained blocks its operation and does not service requests until it is in ACTIVE mode again

    - 

      PAS filter must block access to protected regions in Inactive mode.
  
      1. Change ACTIVE mode of PAS filter (if supported).
      2. Access PA range that is monitored by PAS filter.
      3. Read of protected regions does not return data.

  * - 

      `rme_smmu_blocks_request_at_registers_reset <../test_pool/rme/rme_smmu_blocks_request_at_registers_reset.c>`_

    - 

      RGFGZM: If a requester-side Granular PAS filter is in reset state, any requester that is associated with it is either in reset state or blocked from accessing memory.

    - 

      If SMMU is in reset state it blocks all memory access requests from the devices attached to it.

      DMA accesses from Exerciser is blocked.

  * - 

      `rme_system_reset_propagation_to_all_pe <../test_pool/rme/rme_system_reset_propagation_to_all_pe.c>`_

    - 

      RKKSQB: All A-profile application PEs in the system implement the Realm Management Extension (RME).

    - 

      1. Write non-reset value to SCTLR_EL1/any other system register for all PEs.
      2. Apply system reset and check that the system register value is reset.

  * - 

      `rme_msd_smem_in_root_after_reset <../test_pool/rme/rme_msd_smem_in_root_after_reset.c>`_

    - 

      RNXJLB: On an RME system reset MSD SMEM is either immediately assigned to the Root PAS or scrubbed and is available for access by the PE boot ROM as soon as it starts executing.

    - 

      Apply system reset.

      Access using Root access PAS to Root SMEM is successful

  * - 

      `gic_its_subjected_to_gpc_check <../test_pool/gic/gic_its_subjected_to_gpc_check.c>`_

    - 

      RNULL: GIC ITS memory accesses are only to non-secure memory.

    - 

      1. Program ITT table base with Root PA.
      2. Generate access using ITS commands.
      3. Expect faults for all the above accesses.
      4. GIC ITS memory accesses are only to non-secure memory.
      5. Program ITT table base with Root PA and generate access using ITS commands.
      6. Expect faults for all the above accesses.

  * - 

      `smmu_implements_rme <../test_pool/smmu/smmu_implements_rme.c>`_

    - 

      RNJRPC: An SMMU in an RME system complies with the `SMMU_RME_Spec`_ specification.

    - 

      SMMU must implement RME.

      Check If SMMU_IDR0.RME_IMPL[30] == 0b1.

  * - 

      `smmu_responds_to_gpt_tlb <../test_pool/smmu/smmu_responds_to_gpt_tlb.c>`_

    - 

      RJDBCS: An MMU-attached PAS filter in a non-ACTIVE mode either continues to respond to GPT cache invalidations, or invalidates any cached state when moving back to ACTIVE mode

    - 

      SMMU must respond to GPT cache invalidate in In-active mode.

      1. Change mode of PAS filter to In-Active (if supported).
      2. Verify that in In-active mode it responds to GPT cache invalidate.
      3. PWR_Down_SMMU à Invalidate GPT à PWR_UP_SMMU.
      4. Issue a DMA through SMMU.
      5. Observe new GPI value.

  * - 

      `legacy_tz_support_check <../test_pool/legacy_system/legacy_tz_support_check.c>`_

    - 

      RKXMHF: A system that contains RME components, which have the LEGACY_TZ_EN input, will drive a common tie-off input value into all components.

      RCLKXF: A PE that supports the LEGACY_TZ_EN tie-off hides the RME capability if LEGACY_TZ_EN is TRUE and reverts all functionality defined by RME.

    - 

      1. Turn on the LEGACY_TZ_EN input.
      2. The bit[52:55] of ID_AA64PFR0_EL1 register is checked for PE's RME implementation.
      3. The bit[30] of SMMU_IDR0 register is checked for SMMU's RME implementation.
      4. These bits are expected to be unset once LEGACY_TZ_EN is enabled.

  * - 

      `legacy_tz_en_drives_root_to_secure <../test_pool/legacy_system/legacy_tz_en_drives_root_to_secure.c>`_

    - 

      RHCGZN: If LEGACY_TZ_EN is TRUE, PAS[1] is driven to 0b0 by any logic that enforces the PAS Access Table

    - 

      When Legacy_TZ_En = True, all Root registers (Interconnect registers SAM registers, DMC- DRAM memory controllers, Timer register) that controls global functionality must be accessible using secure PAS only.

      Note: The partner has to provide the implementation details of the ROOT registers.

  * - 

      `legacy_tz_enable_before_resetv <../test_pool/legacy_system/legacy_tz_enable_before_reset.c>`_

    - 

      RKQLKN: LEGACY_TZ_EN is not permitted to change value after RME system reset has been deasserted.

    - 

      1. The bit[52:55] of ID_AA64PFR0_EL1 register is checked for PE's RME implementation.
      2. The bit[30] of SMMU_IDR0 register is checked for SMMU's RME implementation.
      3. These bits are expected to be RES0 once LEGACY_TZ_EN is enabled.

  * - 

      `legacy_tz_enable_after_reset <../test_pool/legacy_system/legacy_tz_enable_after_reset.c>`_

    - 

      RKQLKN: LEGACY_TZ_EN is not permitted to change value after RME system reset has been deasserted.

    - 

      1. The system reset is de-asserted.
      2. Enable LEGACY_TZ_EN.
      3. Check the bit[52:55] of ID_AA64PFR0_EL1 register for PE's RME implementation.
      4. Check the bit[30] of SMMU_IDR0 register for SMMU's RME implementation.
      5. These bits are expected to remain set after the de-assertion of system reset, indicating that enabling LEGACY_TZ_EN has no effect.

  * - 

      `da_dvsec_register_config <../test_pool/da/da_dvsec_register_config.c>`_

    - 

      RDVJRV: The RME-DA DVSEC is implemented in compliance with PCIe and has the following format

      RNWSJB: All Root Ports in an RME-DA system must implement the RME-DA DVSEC

    - 

      1. For each function, read the RMEDA registers (DA Capability) and check the corresponding values and its attribute matches the `RME_System_Architecture_Spec` specification.
      2. No mismatch in both values and attribute properties of the registers

  * - 

      `da_smmu_implementation <../test_pool/da/da_smmu_implementation.c>`_

    - 

      RNJRPC: An SMMU in an RME system complies with the `SMMU_RME_Spec`_ specification and, if the system supports RME-DA or MEC, with SMMU for RME-DA

    - 

      1. For each SMMU in the system, check if the ROOT_IDR0 register has RME_IMPL set.
      2. The expected bit values should be set in SMMU

  * - 

      `da_tee_io_capability <../test_pool/da/da_tee_io_capability.c>`_

    - 

      RLGXBX: An RME-DA Root Port sets the TEE-IO Supported bit in the Device Capabilities Register.

    - 

      For all Root Ports in the system, the TEE-IO supported bit in the PCIe Extended Capability register should be set.

  * - 

      `da_rootport_ide_features <../test_pool/da/da_rootport_ide_features.c>`_

    - 

      RGRCKL: An RME-DA Root Port supports the following IDE features:

      - At least one Selective IDE Stream.NUM_SEL_STR denotes the number of Selective IDE Streams supported by the Root Port.
      - At least three Address Association registers for each Selective IDE Stream.
      - The TEE-Limited Stream IDE capability.

    - 

      1. For all RootPorts in the system, check at least one Selective IDE Stream is supported and TEE-Limited Stream is supported in the IDE Capability register.
      2. Check at least three Address Association registers in the Address association block.
      3. The RootPort should have all the expected values required for the IDE feature.

  * - 

      `da_attribute_rmeda_ctl_registers <../test_pool/da/da_attribute_rmeda_ctl_registers.c>`_

    - 

      RDVJRV: The RME-DA DVSEC is implemented in compliance with PCIe.

    - 

      1. Check the attribute of the RMEDA_CTRL register.
      2. The RSVDP fields and RW fields should behave as expected.

  * - 

      `da_p2p_btw_2_tdisp_devices <../test_pool/da/da_p2p_btw_2_tdisp_devices.c>`_

    - 

      RMDPKR: When P2P traffic between two TDISP devices is routed through the Root Complex, then for any non-posted request that is forwarded by the Root Complex from a source peer to a target peer, the Root Complex must guarantee that the corresponding completion will be forwarded back to the source peer only if it arrived from the target peer.

    - 

      Peer-to-Peer transaction between two TDISP devices must be handled correctly.

      1. Get two Exerciser EPs under two different RPs.
      2. Transition both the exerciser into TDISP RUN state.
      3. Perform a Peer-to-Peer transaction.
      4. Check the competition is obtained only after it is arrived from the target peer.

  * - 

      `da_outgoing_request_with_ide_tbit <../test_pool/da/da_outgoing_request_with_ide_tbit.c>`_

    - 

      RDVKPF: An outgoing request that has to be sent with IDE-Tbit==1 but that cannot be associated with a Selective IDE Stream that is Locked and in the IDE Secure state, is rejected with error by the RP

    - 

      Outgoing request with IDE-Tbit must be rejected by RootPort.

      1. For each function, If it is a RP, get the Endpoint BAR Base below it if it is available.
      2. Otherwise use the RP's BAR address.
      3. Map the BAR to Root PAS and read the data at BAR address from Root world.
      4. The request should be rejected by the RootPort.

  * - 

      `da_incoming_request_ide_sec_locked <../test_pool/da/da_incoming_request_ide_sec_locked.c>`_

    - 

      RKZBHV: When RMEDA_CTL1.TDISP_EN==1, the RP permits an incoming request to have IDE-Tbit==1 if it arrived on a Selective IDE Stream that is Locked and in the IDE Secure state or if this is enabled by an IMPLEMENTATION DEFINED configuration that is controlled by MSD firmware or a Trusted subsystem, and otherwise rejects the request.

      RMYKFH: When an RP forwards an incoming request over a host interface it sets the SMMU SEC_SID, StreamID and SubstreamID fields as follows:

      - If the request has IDE-Tbit==1, SEC_SID is set to 0b10 (Realm). Otherwise SEC_SID is set to 0b00 (Non-secure).
      - SMMU StreamID and SubstreamID are set using the RID and PASID fields in accordance with `BSA_Spec`_ and `SBSA_Spec`_ specifications.

      RGKHSZ: An RME-DA RP performs the following operations for all outgoing TLPs:

      - Associate the TLP with an IDE Stream.
      - Set the IDE-Tbit of the TLP to the appropriate value.

      RZJJMZ: As a requester, an RCiEP sets the SMMU SEC_SID, StreamID and SubstreamID fields of a request as follows:

      - If the request must be sent with IDE-Tbit==1, the RCiEP sets SEC_SID to 0b10 (Realm). Otherwise the RCiEP sets SEC_SID to 0b00 (Non-secure).
      - SMMU StreamID and SubstreamID are set using the RID and PASID fields in accordance with `BSA_Spec`_ and `SBSA_Spec`_ specifications.

    - 

      1. Establish an IDE stream in the RP and set the TDISP_EN to 1.
      2. Ensure the stream is in secure state.
      3. Lock the corresponding Selective IDE register block in RMEDA_CTL2 register.
      4. Map the configuration address before writing as REALM PAS.
      5. Perform a DMA transaction with IDE-Tbit = 1.
      6. Generate a transaction with IDE-Tbit=0 should be rejected by RP.
      7. The incoming request should be permitted by the RP when IDE-Tbit = 1 and should be rejected when IDE-Tbit = 0.

  * - 

      `da_ctl_regs_rmsd_write_protect_property <../test_pool/da/da_ctl_regs_rmsd_write_protect_property.c>`_

    - 

      RNPGJV: RMEDA_CTL registers must behave as write-protect.

    - 

      1. Read the RMEDA_CTL registers and check if they can be updated from the Root world.
      2. Also check if they cannot be updated from the Secure and Non-Secure world.
      3. RMEDA_CTL registers should behave as write-protect.

  * - 

      `da_ide_state_rootport_error <../test_pool/da/da_ide_state_rootport_error.c>`_

    - 

      RPJGJK: IDE stream must be transitioned to insecure state from secure state when RP has error.

    - 

      1. Establish an IDE stream between the Exerciser EP and its RP.
      2. Inject an error from the exerciser which reaches the RP.
      3. The IDE stream should be transitioned to insecure state from secure state.

  * - 

      `da_ide_state_tdisp_disable <../test_pool/da/da_ide_state_tdisp_disable.c>`_

    - 

      RRNQNM: When RMEDA_CTL1.TDISP_EN==0:

      - The RP rejects an incoming request if it has IDE-Tbit==1 .
      - The RP rejects with error an outgoing request if it would otherwise need to be sent with IDE-Tbit==1.

      RGKHSZ: An RME-DA RP performs the following operations for all outgoing TLPs:

      - Associate the TLP with an IDE Stream.
      - Set the IDE-Tbit of the TLP to the appropriate value.

      RDNFTD: A PA of an access to a PCIe Root Port is associated with a PAS until reaching the Root Port.

    - 

      1. Disable the TDISP_EN bit in the RP.
      2. Configure the exerciser EP under the RP to TDISP RUN state (IDE-Tbit = 1).
      3. Perform a DMA transaction from the Exerciser EP to NS memory.
      4. Map the BAR of the Exerciser EP to ROOT PAS.
      5. Perform a read from PE from ROOT.
      6. Check if both the transaction are rejected and should be unsuccessful.

  * - 

      `da_selective_ide_register_property <../test_pool/da/da_selective_ide_register_property.c>`_

    - 

      RYHQQL: When a Selective IDE register block is Unlocked (SEL_STR_LOCK is 0):

      - The block registers do not have any register security property
      - The associated Selective IDE Stream is in Unlocked state

      When a Selective IDE register block is Locked (SEL_STR_LOCK is 1):

      - The block registers are RMSD write-detect
      - The associated Selective IDE Stream is in Locked state

    - 

      IDE stream must be transitioned to Insecure state when Selective IDE register block is locked and re-configured.

      1. Configure IDE stream between RP and EP and set it to Secure state.
      2. Lock the Selective IDE register block by setting SEL_STR_LOCK to 1.
      3. Re-Configure the IDE stream.
      4. Check that the IDE stream is transitioned to Insecure state which validates the RMSD write-detect property.

  * - 

      `da_rootport_tdisp_disabled <../test_pool/da/da_rootport_tdisp_disabled.c>`_

    - 

      RHCMWC: The RMEDA_CTL registers are RMSD write-protect by hardware default.

    - 

      IDE stream must be transitioned to Insecure state when TDISP_EN is disabled.

      1. After enabling the TDISP_EN, establish the IDE stream between the RP and EP.
      2. Once done, set the TDISP_EN to 0.
      3. Check if the IDE stream is transitioned to Insecure state.

  * - 

      `da_autonomous_rootport_request_ns_pas <../test_pool/da/da_autonomous_rootport_request_ns_pas.c>`_

    - 

      RMJNLW: Requests that are autonomously initiated by the RP over its host interface are tagged with PAS==Non-secure. Likewise, a request initiated by the RP over the PCIe interface must have IDE-Tbit==0.

    - 

      RMSD write-detect property must be validated.

      1. Map the GIC ITS ITT base to ROOT PAS.
      2. Generate an MSI from the RP by injecting an error in RP.
      3. Map the GIC ITS ITT base to NON-SECURE PAS.
      4. Generate an MSI from the RP by injecting an error in RP.
      5. Check that the interrupt is not serviced in NS world when ITT is mapped to ROOT.
      6. Check that the interrupt is serviced in NS world when ITT is mapped to NS.

  * - 

      `da_incoming_request_ide_non_sec_unlocked <../test_pool/da/da_incoming_request_ide_non_sec_unlocked.c>`_

    - 

      RKZBHV: When RMEDA_CTL1.TDISP_EN==1, the RP permits an incoming request to have IDE-Tbit==1 if it arrived on a Selective IDE Stream that is Locked and in the IDE Secure state or if this is enabled by an IMPLEMENTATION DEFINED configuration that is controlled by MSD firmware or a Trusted subsystem, and otherwise rejects the request.

      RZJJMZ: As a requester, an RCiEP sets the SMMU SEC_SID, StreamID and SubstreamID fields of a request as follows:

      - If the request must be sent with IDE-Tbit==1, the RCiEP sets SEC_SID to 0b10 (Realm). Otherwise the RCiEP sets SEC_SID to 0b00 (Non-secure).
      - SMMU StreamID and SubstreamID are set using the RID and PASID fields in accordance with `BSA_Spec`_ and `SBSA_Spec`_ specifications.

    - 

      1. Set the TDISP_EN to 1.
      2. Perform a DMA transaction with IDE-Tbit = 1.
      3. Generate a transaction with IDE-Tbit=1 should be rejected by RP.
      4. The incoming request should be rejected by the RP when IDE-Tbit = 1, but not in secure state and locked state.

  * - 

      `da_outgoing_realm_rqst_ide_tbit_1 <../test_pool/da/da_outgoing_realm_rqst_ide_tbit_1.c>`_ & `da_ide_tbit_0_for_root_request <../test_pool/da/da_ide_tbit_0_for_root_request.c>`_

    - 

      RCFQBW: IDE-Tbit for an outgoing PCIe Memory Request or Configuration Request is set based on the request PAS: If PAS is Realm or Root then IDE-Tbit is 1 and otherwise it is 0.

      RGBVTS: As a completer of memory requests a TDISP-compliant RCiEP extracts the request IDE-Tbit from the request PAS: If PAS is Realm or Root then IDE-Tbit is 1, otherwise it is 0.

    - 

      1. Retrieve the BAR of the Endpoint (skipping this step if the Endpoint lacks an MMIO BAR), identify the RootPort for the Endpoint, and enable the TDISP_EN bit in the RME-DA DVSEC register.
      2. Map the BAR address to Realm PAS, establish an IDE Stream between the RootPort and Endpoint, and transition the Endpoint to the TDISP RUN state.
      3. Perform write and read operations at the BAR address from the Realm world.
      4. Additionally, retrieve the BAR of the Endpoint (skipping if it lacks an MMIO BAR), enable the TDISP_EN bit in the RME-DA DVSEC register, and map the BAR address to Non-Secure PAS.
      5. Perform write and read operations at the BAR address from the Root world.
      6. The request should be accepted by the RootPort, confirming that the IDE-Tbit is set appropriately based on the PAS mapping.

      da_outgoing_realm_rqst_ide_tbit_1: This test checks that an outgoing request with IDE-Tbit set to 1 is accepted by the RootPort when the BAR address is mapped to Realm PAS.
      da_ide_tbit_0_for_root_request: This test checks that an outgoing request with IDE-Tbit set to 0 is accepted by the RootPort when the BAR address is mapped to Non-Secure PAS.

      Similarly, the request should also be allowed by the RootPort when the BAR address is mapped to Non-Secure PAS.

  * - 

      `da_rmsd_write_detect_property <../test_pool/da/da_rmsd_write_detect_property.c>`_

    - 

      RPCRFM: When RMEDA_CTL1.TDISP_EN==1 the following registers are RMSD write-detect:

      - RP configurations that are not allowed to be modified when the RP has an IDE Stream bound to a TDI as specified in `TDISP_Spec`_.
      - IMPLEMENTATION DEFINED registers that can impact the RME security guarantee and that must be programmed by Non-secure state.
      - For example, RP registers that perform address translation between system hardware address space and PCIe address space.

      RGSTJC: Any of the following events transitions all hosted IDE Streams to IDE Insecure state:

      - A reset or loss of state of a write-detect, write-protect or full-protect register.
      - A reset or loss of state of a Root Port component that affects the RME security guarantee.

    - 

      IMPLEMENTATION DEFINED registers that can impact the RME security guarantee and that must be programmed by Non-secure state.

      For example, RP registers that perform address translation between system hardware address space and PCIe address space.

      1. Establish an IDE stream between RP and EP.
      2. The IDE stream should be in secure state.
      3. Modify the RP configuration registers.
      4. Check the write-detect property by ensuring the IDE stream is transitioned to Insecure state.

  * - 

      `da_rootport_write_protect_full_protect_property <../test_pool/da/da_rootport_write_protect_full_protect_property.c>`_

    - 

      RXHMDQ: When RMEDA_CTL1.TDISP_EN==1 the following registers are RMSD write-protect:

      - IMPLEMENTATION DEFINED registers that can impact the RME security guarantee and that are programmed by MSD firmware or a Trusted subsystem. For Example:
      - Registers that allow reading or modifying any Transaction Layer Packet (TLP) parameters, such as its address or data, or that may lead to a drop, corrupt, replay or reorder of a TLP,
      - Before IDE is applied (for outgoing TLPs ) or,
      - After the IDE check (for incoming TLPs).
      - Registers that allow forwarding a Poisoned TLP as a non-Poisoned TLP.
      - Registers that define the method of signaling an Unsupported Request (UR) over the host interface.
      - A register that controls the Root Port ID or the PCIe Segment Number of the Root Port.
      - Registers that may affect the correctness of IDE functionality, for example error injection controls.

      RNXJKQ: When RMEDA_CTL1.TDISP_EN==1 the following registers are RMSD full-protect:

      - IDE key programming registers.
      - Registers that store IDE confidential information, for example Initialization Vectors (IV) or IMPLEMENTATION DEFINED confidential state.
      - Registers that store payload from TLPs that have IDE-Tbit==1.

    - 

      1. Verify that the implementation-defined root port registers identified as RMSD write/full-protect are writable when the RMEDA_CTL1.TDISP_EN register is disabled.
      2. When TDISP_EN is enabled, validate that these registers are protected against write access from NS.
      3. When RMEDA_CTL1.TDISP_EN is enabled, any attempt to write to these RMSD write/full-protect registers from NS must fail with an appropriate fault or error.

      Note: The addresses of these registers are retrieved from the PAL, and their write-protect/full-protect behavior is tested by attempting write operations.

  * - 

      `da_interconnect_regs_rmsd_protected <../test_pool/da/da_interconnect_regs_rmsd_protected.c>`_

    - 

      RTTPLM: Interconnect registers mapping PAs to PCIe Root Ports must be MSD-Protected and accessible only from MSD domain.

    - 

      1. Validate that the interconnect registers responsible for mapping PAs to PCIe Root Ports are implemented as MSD-Protected registers and ensure that they are accessible exclusively from the MSD domain.
      2. Retrieve the register addresses as provided by the PAL implementation and attempt to access them from both MSD and non-MSD domains.
      3. Access to the registers should succeed when performed from the MSD domain, whereas access from non-MSD domains should fail with an appropriate fault or error.

  * - 

      `dpt_system_resource_valid_without_dpti <../test_pool/dpt/dpt_system_resource_valid_without_dpti.c>`_, `dpt_system_resource_valid_with_dpti <../test_pool/dpt/dpt_system_resource_valid_with_dpti.c>`_, `dpt_system_resource_invalid <../test_pool/dpt/dpt_system_resource_invalid.c>`_, `dpt_p2p_same_rootport_valid <../test_pool/dpt/dpt_p2p_same_rootport_valid.c>`_, `dpt_p2p_same_rootport_invalid <../test_pool/dpt/dpt_p2p_same_rootport_invalid.c>`_, `dpt_p2p_different_rootport_valid <../test_pool/dpt/dpt_p2p_different_rootport_valid.c>`_, `dpt_p2p_different_rootport_invalid <../test_pool/dpt/dpt_p2p_different_rootport_invalid.c>`_

    - 

      RQRMPD: A translated access from a TDI that is assigned to Realm state is subject to DPT checks, unless where stated otherwise.

      RPGSTQ: An RME system can include on-chip TDISP-compliant devices that are measured and attested by HES or MSD. For such a device:

      - DPT checks can be skipped.
      - GPC cannot be skipped

    - 

      IDE-tagged transactions from Exerciser Endpoint must undergo DPT enforcement through R_SMMU.

      1. Validate that IDE-tagged transactions from the Exerciser Endpoint undergo proper DPT enforcement through the R_SMMU.
      2. Establish an IDE stream between the Root Port and Exerciser, configure secure EL3 memory for DMA, and evaluate both successful and failed flows based on whether a DPT Invalidate command is issued.

      The test ensures that transactions with stale or missing DPT entries are blocked and those with valid, updated entries are allowed.

      Observations: The transaction initiated by the Exerciser passed through the R_SMMU and was subjected to DPT checks as expected.

  * - 

      `mec_support_mecid_and_mecid_width <../test_pool/mec/mec_support_mecid_and_mecid_width.c>`_ 

    - 

      RBJVZS: An access to a Resource is associated with a MECID, in accordance with the rules specified in MEC section of `RME_PE_Spec`_ and `SMMU_RME_Spec`_ specification.
      IXQKRQ: Arm Recommends that all RME system components support the same MECID width, to avoid faulty behavior

    - 

      1. Check that all requesters (PEs and SMMUs) support MEC.
      2. Read MECID width of all the requesters and establish a common MECID width - MECIDW.
      3. Check that both 2^(MECIDW - 1) and 2^(MECIDW - 2) works.
      4. Map VA to PA in Realm PAS.
      5. Enable MEC.
      6. Write data to VA with MECID as 2 ^ (MECIDW - 1) and issue CMO to PoPA/PoE.
      7. Read VA and store as data1.
      8. Write data to VA with MECID as 2 ^ (MECIDW - 2) and issue CMO to PoPA/PoE.
      9. Read VA and store as data2.
      10. All requesters support MEC and data1 != data2.

  * - 

      `mec_mecid_assosiation_and_encryption <../test_pool/mec/mec_mecid_assosiation_and_encryption.c>`_

    - 

      RTBZM: An access to a cacheable memory Location is associated with a MECID until reaching the PoE.

      RMLFBL: External memory assigned to Secure PAS, Realm PAS, or Root PAS must be encrypted using a method that provides a different encryption context for each MECID in the Realm PAS.

      RMYWVB: Data is encrypted before being written to external memory or to any shared cache that resides past the PoPA. In a system with MEC, data is encrypted before being written to external memory or to any shared cache that resides past the PoE

    - 

      1. MAP VA to PA in Realm PAS.
      2. Write to VA with data1 with MECID1.
      3. Issue CMO to PoPA/PoE and Read VA with MECID2 store in data2.
      4. Perform similar DMA transaction from a PCIE device to validate SMMU MECID tagging.
      5. data1 should not be equal to data2.

  * - 

      `mec_cmo_uses_correct_mecid <../test_pool/mec/mec_cmo_uses_correct_mecid.c>`_

    - 

      RQBNJF: A PoPA CMO affects any cached copy in the system with the specified {PAS, PA} regardless of the MECID that it was cached with, in a system with MEC

      IMNGJT: In an RME system with MEC, RLCXDB also applies to any cached or transient state associated with the PA before the PoE

    - 

      1. Map VA to PA in Realm PAS.
      2. Enable MEC, Sect MECID = MECID1.
      3. Write data1 to VA.
      4. Change MECID = MECID2, Issue CMO(clean and invalidate) to PoPA.
      5. Mark VA as non-cacheable.
      6. Change MECID back to MECID1.
      7. Read VA == data1(indicates cache was cleaned and regardless of MECID being MECID2 while issuing CMO).
      8. Write data2 to VA.
      9. Mark memory as cacheable.
      10. Read VA == data2(indicates cache was invalidated).
      11. Reads to VA in the above steps are as specified in the scenario.

  * - 

      `mec_effect_of_popa_cmo <../test_pool/mec/mec_effect_of_popa_cmo.c>`_

    - 

      RKMNQX: Memory accesses resulting from a cache clean operation, due to cache maintenance operations and natural evictions, use the MECID that the entry was cached with.

    - 

      Multi PE Variant 1:

      .. list-table::
          :widths: 50 50
          :header-rows: 1

          * - Primary PE
            - Secondary PE
          * - Enable MEC, Set MECID1

              Map VA to PA in Realm PAS
            
              Write data1, Issue CMO to PoC
            
              Set MECID2, issue CMO to PoC
            - Map VA to PA in Realm PAS
          
              Enable MEC, Set MECID1
            
              Read VA, read data == data1


      Multi PE Variant 2:

      .. list-table::
          :widths: 50 50
          :header-rows: 1

          * - Primary PE
            - Secondary PE
          * - Enable MEC, Set MECID1

              Map VA to PA in Realm PAS

              Write data1
            - Map VA to PA in Realm PAS

              Enable MEC, Set MECID2

              Issue CMO to PoC

              Set MECID1

              Read VA, read data == data1

      Single PE scenario:

      1. Enable MEC, Set MECID1.
      2. Map VA to PA in Realm PAS.
      3. Write data1, Issue CMO to PoC.
      4. Set MECID2.
      5. Issue CMO to PoC.
      6. Set MECID1.
      7. read VA, read data == data1.

      Repeat the above for CMOs to PoE and PoPA.

      Reads to VA in above steps are as specified in the scenarios.



Out of Compliance scope rules
=============================

The following rules are out of compliance scope due to the following reasons:

- No specific scenario possible. It is partially/fully tested as a part of other scenarios. 
- PE ACS has tested this feature using memory transaction from PE.
- Lack of common debugger available for testing.
- Other resources, like System PMU events, IDE_KM, RNVS registers are impdef.
- Lack of non-a-profile processor for testing.
- Dependency on Non-Arm IP/ implementation defined features. 
- System ACS infra doesn't support coherent devices yet. 

.. list-table::
    :header-rows: 1
    :widths: 25 75

    * - **Category**
      - **Rules**
    * - System PMU counters
      - RHRVJB: A system PMU counter that is accessible in the Secure PAS can only count events that are attributable to the Secure PAS or to the Non-secure PAS.
      
        RBSZPN: A system PMU counter that is accessible in the Realm PAS can only count events that are attributable to the Realm PAS or to the Non-secure PAS.
        
        RTMSNN: A system PMU counter that is accessible in the Root PAS can count events that are attributable to any PAS.
        
        RMMPWY: A system PMU counter that is accessible in the Non-secure PAS can count events that are attributable to a specific PAS if there is a per-PAS authentication control that can permit events from that PAS to be counted.
        
        RPLXZB: A per-PAS authentication control can be driven by a debug authentication interface signal or by a register accessible in the corresponding PAS or in the Root PAS.
        
        RCFYKS: An event that is not explicitly associated with a PAS but can leak confidential information is implicitly associated with the Root PAS.

    * - Debug
      - RQSXBZ: RMSD external debugging and Root external debugging are disabled by default on a Secured Arm CCA system.
      
        RHLTLK: RMSD external debugging can only be authorized following an RME system reset and before RMSD firmware is loaded and cannot change state until a subsequent RME system reset.
        
        RXVNFV: Root external debugging can only be authorized following an RME system reset and before MSD firmware is loaded and cannot change state until a subsequent RME system reset.
        
        RGTPGZ: When Root external debugging is enabled, the RNVS confidential parameters are either inaccessible, scrubbed, or populated with debug values.
        
        RRHGKX: Access to a Secured Arm CCA system through an external debug or test interface, including debug access ports, JTAG ports, and scan interfaces is disabled by default. Debug access can be enabled following validation of a debug certificate or password which is injected via an external debug interface.
        
        RQLPNL: When external debugging is enabled for any Security state, external requests to power-up a component within a level of the system hierarchy (PE, PE-Cluster, System) are permitted but must be executed by trusted power control.

    * - Hardware Enabled security
      - RNWQBJ: If HES is hosted as a tenant within a multi-tenant Trusted subsystem, HES functionality must be isolated from other tenants, such that tenants must not be able to monitor HES functionality or impact HES functionality or integrity.
      
        RHJSSG: The HES implementation exposes a private interface to SSD components such as Trusted subsystems for requesting HES services.
        
        RCGDVX: The HES implementation exposes a programming interface in the Root PAS, shared by all application PEs, allowing MSD and PE Initial boot ROM to request for HES services.
        
        RBQPFG: HES has exclusive read and write access to RNVS confidential parameters.
        
        RBTWVY: A measurement register can be either extended using a secure hash algorithm, locked, or reset.
        
        RDFPJL: HES has exclusive access to extend, lock, and reliably obtain the value of a measurement register it owns.
        
        RFWSRF: Once locked, a measurement cannot be further extended until it is reset.
        
        RWYSLK: An RME system reset is the only method to reset a measurement owned by HES.
        
        RXCRMH: On an RME system reset, HES state is reset to a known value, including all measurements and ephemeral cryptographic context.

    * - RAS
      - RGNGMB: Only SSD or MSD can control whether recording is performed for error records that might contain confidential information.
      
        RGZTVL: Critical Error Interrupts (CI) must be wired to a Trusted subsystem that will respond with an RME system reset.
        
        RLWVCX: An uncontainable error results in an RME system reset.
        
        RJNBWJ: Only SSD or MSD can enable or disable the generation of a CI.
        
        RXPCTR: Where an MPE provides support for integrity, if it detects an integrity error it can perform one of the following responses: Respond by returning poison back to the consumer and record the error as a deferred error. Respond with an in-band error response and record the error as an uncorrected error.
        
        RHSVLQ: Only SSD or MSD must be able to control the abilities of detecting, propagating, and reporting MPE integrity errors.
        
        RGZHTD: In addition to providing encryption and, where implemented, integrity capabilities, the MPE can pass poison information: Note: If a requester above the MPE defers errors by writing poison, then the MPE must be able to pass this value through to the memory system below it as poison. If a requester above the MPE consumes a memory location that has been marked as poison, either because of that access or a previous access, the MPE must pass that poison to consumer.

    * - RNVS
      - RWNPYD: A programming interface that allows read and write access to RNVS must be in the Root PAS.
      
        RLMSSL: The system supports a method for permanently blocking read access from application PEs to RNVS confidential parameters.
        
        RVXBYG: System support for any memory protection property reported in System Properties is immutable and applicable for all DRAM memory controllers in the system.

    * - Trusted System Control Processor
      - RSXCFK: A Trusted SCP is an on-chip control processor that is trusted by MSD and can access resources in the Root PAS.
      
        RZHJQJ: A Trusted SCP is considered a Trusted subsystem and must meet the applicable security requirements, for example, supporting Secure boot and having attestable firmware.
        
        RMZDXV: It is permitted for a Trusted SCP to have a mechanism to bypass a PAS filter which filters its transactions.

    * - DA
      - RWBJJT: TSM functionality in RME-DA is implemented within RMSD.
      
        RBDLXG: An RME-DA Root Port exposes an IDE key programming interface for the following IDE key management (IDE_KM) data objects: KEY_PROG, K_SET_GO, K_SET_STOP
        
        RVCRRM: An RME-DA Root Port must support IDE key refresh operations in compliance with [13].
        
        RFSFST: The RP IDE logic must be able to detect that an IDE key set requires a refresh and perform one or more of the following: Assert a dedicated interrupt that will be delivered to a Trusted subsystem. Transition the corresponding IDE Stream to Insecure state.
        
        RBWFTS: RMSD ensures that Selective IDE Streams are configured such that different IDE Streams are assigned with RID ranges and address ranges that are not overlapping.
        
        RSWBSV: IDE-Tbit of PCIe messages is set as follows: For messages generated from DTI requests, IDE-Tbit is extracted from the DTI request in compliance with AMBA DTI Revision 3 (See: SMMU for RME-DA [6]). For Vendor-Defined messages, the IDE-Tbit is permitted to be 1 if the RP has a method to associate the message with the Root or Realm Security states. For any other message, IDE-Tbit is set to 0. For example, Power Management messages.
        
        RCKJMN: IDE-Tbit for PCIe completions is set in compliance with IDE [13] and TDISP [8]. This means that: For ATS Translation Requests, the host will set the IDE-Tbit on the corresponding ATS Translation Completion to match the IDE-Tbit value of the request. For ATS-translated read requests the host will set the IDE-Tbit value on the corresponding read completion to match the value of the request, with the following exception: If a P2P read request with IDE-Tbit==1 is forwarded through the host to a non-TDISP device, the host is permitted but not required to set IDE-Tbit==0 on the corresponding completion.
        
        RLMFSV: When RMEDA_CTL1.TDISP_EN==1, any RP debug functionality that might affect the RME security guarantee is disabled unless explicitly enabled by one of the following: An access to a write-protect register. An assertion of a debug authentication signal indicating that either RMSD external debugging or Root external debugging are enabled.
        
        RQNTYC: The PCIe segment and RIDs that are allocated to an RCiEP are either defined statically or configured using an RMSD write-protect register.

    * - Miscellaneous
      - RDFYXL: In an RME system, any access by a requester and any instruction executed by a PE is associated with a single Security state.
      
        RQDWVC: Either SSD or MSD controls Association of a Resource with a Resource PAS.
        
        RSCDLL: Once assigned, the value of an Access PAS cannot be altered.
        
        RWRGTF: Access to the Root PAS is only permitted for Trusted requesters.
        
        RWJNMD: Granule Protection Check for on-chip Resources can only rely on Granule Protection Tables that are stored on-chip or are stored off-chip with equivalent level of integrity and replay protection.
        
        RGQCQT: A Granule Protection Check that applies to non-idempotent locations does not permit any access to be speculatively performed to a non-idempotent location before the Granule Protection Check for the access is complete.
        
        RBNSQB: An ECC-scrubbing engine located after the PoPA must not leak confidential information, for example through error record registers.
        
        RRHBJN: The Security state of a non-PE requester that is not a Trusted subsystem can be either Secure or Non-Secure state.
        
        RMCMSH: A fully coherent non-PE requester, which is not part of the System Security Domain (SSD), will not observe coherent traffic for addresses in the Secure, Realm, or Root PAS.
        
        RRGQRT: If a programmable completer-side PAS filter can assign resources to all physical address spaces then: The registers that control the filter are in the Root PAS. On an RME system reset, Resources controlled by the filter are either assigned to the Root PAS or are reset to a known value.
        
        RGLLZY: If a programmable completer-side PAS filter assigns resources only to the Secure PAS and Non-secure PAS then: The registers that control the filter are in the Secure PAS or in the Root PAS. On an RME system reset, Resources controlled by the filter are either assigned to the Secure PAS or the Root PAS or are reset to a known value.
        
        RJSDVG: All RME structures and fields use little-endian convention.
        
        RSPLKT: The address ranges of MSD SMEM are either defined statically or defined by SSD following an RME system reset.
        
        RZVQGS: The address ranges of SMEM assigned to the Realm PAS and Secure PAS are either defined statically or by SSD or MSD.
        
        RZCJHY: The access control path that protects SMEM is not affected by state from non-shielded memory.
        
        RXBKYB: All bus and interconnect decoding components between the point where the Access PAS is assigned and the PoPA are PAS tag aware.
        
        RLCXDB: Completion of a PoPA CMO for a given PA guarantees that both: Any dirty cached or transient state associated with the PA before the PoPA has been cleaned to after the PoPA. Any cached or transient state associated with the PA before the PoPA has been invalidated.
        
        RCMMDG: For any cache before the PoPA, cache prefetching across granule-boundary is allowed only after querying the GPC for the PAS association of the next granule.
        
        RPSGCM: A cache maintenance operation performed on a clean cache entry never results with a write of entry content past the PoPA.
        
        RKSPKN: Encryption keys used by MPE are stored in registers that are reset to a known default value on an RME system reset.
        
        RYHXPH: An MPE integrity error is reported as an external abort to a software or hardware agent consuming the error.
        
        RYJDSJ: Any captured details of an MPE integrity error are only visible to MSD.
        
        RLPQSN: An MPE property that is reported through the System Properties structure in Root Non-volatile Storage (RNVS) is supported for all external memory ports in the system.
        
        RVDFYZ: A register that is located outside of the Root PAS but can affect a service provided by MSD must be implemented as a measurable register.
        
        RYLVDB: A measurable register is a write-lockable register that MSD has a trusted method to obtain its value.
        
        RRFSYB: An RME system propagates a 2-bit MPAM_SP field to all MSCs that are either a Four-space MSC or have a PARTID space mapper.
        
        RCFYBJ: An IMPLEMENTATION DEFINED property of an architecture extension, or an IMPLEMENTATION DEFINED difference between application PEs must not create an exposure that could break the RME security guarantee.
        
        RXKBNZ: PE behavior is UNPREDICTABLE when the following are true: An IMPLEMENTATION DEFINED difference between application PEs is visible to software, for example through different System register values across PEs. There is a mismatch between the register value assumed by software running on a PE and the actual hardware value of the PE. An example where such mismatch could occur, is if software obtained the value by reading it on a different PE.
        
        RLRQXZ: A software-initiated power state transition in an RME system at any level of the system hierarchy (PE, PE-cluster, System) is validated by MSD or by a Trusted subsystem.
        
        RWJVRX: Save/Restore operations for MSD PE context can only be done by MSD or a Trusted subsystem and use storage that is not accessible from Realm, Secure and Non-secure states.
        
        RMVZHF: Save/Restore operations for RMSD PE context can only be done by RMSD, MSD, or a Trusted subsystem and use storage that is not accessible from Secure and Non-secure states.
        
        RRCLYM: Save/Restore operations for PE context of Secure state can only be done by MSD or a Trusted subsystem or software running in the Secure state and use storage that is not accessible from Realm and Non-secure states.
        
        RGVJYZ: Any register that affects a system power policy or a hardware power mode is implemented as an MSD-Protected Register (MPR).
        
        RKYXMR: Any power management operation that can affect MSD state or the RME security guarantee must be validated by MSD or a Trusted subsystem.
        
        RHJHRL: On an RME system reset, all Trusted requesters and Trusted subsystems are reset. Any Trusted subsystem state that might include MSD or RMSD confidential information is reset to known values.
        
        RHLKZP: An RME system reset might propagate to any component that implements RAS [6] as an Error recovery reset.
        
        RSSGMJ: The reset of a system component that affects the RME security guarantee can only be controlled by MSD or a Trusted subsystem or driven by an RME system reset.
        
        RCKBGZ: A legacy completer is attached to an RME IP by driving the NS signal of the completer from PAS [0] of the RME IP.
        
        RYKSSD: A legacy requester is attached to an RME IP by driving PAS [0] of the RME IP from the NS signal of the legacy requester and driving PAS [1] of the RME IP to 0b0.
        
        RYXFMV: A requester that is accessing memory-mapped resources not through a stage 1 or stage 2 MMU/SMMU must support a method that is enforced by SSD hardware for tagging accesses with an Access PAS, in accordance with the PAS Access Table (Table B2.1). For example: A Debug Access Port (DAP) can expose a programming register to an external debugger that allows setting an Access PAS to one of the permitted values, as implied by the debug authentication interface state, for any access that targets main memory or an APB peripheral. If the debug authentication interface permits RMSD external debugging but not Secure external debugging then DAP hardware would reject an attempt to program the register to Access PAS == Secure. Furthermore, if the debug authentication interface permits RMSD external debugging then DAP hardware can permit accesses with Access PAS == Realm to specify a programmed MECID.
        
        RLYXGC: A CTC interface in a multi-chip RME system supports all of: Transport of the PAS tag with any access that specifies a physical address (PA). Transport of the MECID with any access that specifies a PA, if the RME system supports MEC. Transport of CMO and DVM messages that RME and MEC [1] specify.
  


License
=======

RME System ACS is distributed under Apache v2.0 License.

*Copyright (c) 2023-2025, Arm Limited and Contributors. All rights reserved.*


.. _RME_System_Architecture_Spec: https://developer.arm.com/documentation/den0024/latest
.. _RME_PE_Spec: https://developer.arm.com/documentation/ddi0615/latest
.. _SMMU_RME_Spec: https://developer.arm.com/documentation/ihi0094/latest
.. _PSCI_Spec: https://developer.arm.com/documentation/den0022/latest
.. _GIC_Spec: https://developer.arm.com/documentation/ihi0069/latest
.. _BSA_Spec: https://developer.arm.com/documentation/den0094/latest
.. _SBSA_Spec: https://developer.arm.com/documentation/den0029/latest 
.. _PCIE_Spec: PCI-SIG
.. _TDISP_Spec: PCI-SIG