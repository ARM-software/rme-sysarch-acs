******************************************
Arm RME System ACS - CDA Scenario Document
******************************************

.. contents:: Contents
   :depth: 2

Introduction
============

This document describes the Coherent Device Assignment (CDA) test scenarios
in the Arm RME System Architecture Compliance Suite. Each scenario identifies
the architectural rule, the test implementation, and the test algorithm.

Rule descriptions summarize DEN0129 C.a, section B2.3.5, RME Coherent Device
Assignment. The specification remains normative. Test results apply to the
checks described in each scenario.

For scenarios from other test modules, including CXL host-port tests, see the
`System ACS Scenario Document <Arm_RME_System_Architecture_Compliance_Suite_Scenario_Document.rst>`_.

Test Prerequisites
==================

- Traffic-generation scenarios require an exerciser and the host-port,
  translation, TDISP, IDE, and monitoring capabilities specified by the
  individual algorithm.
- RNVWMC and RHDXTM do not require an exerciser. RKRCWK selects a Type-3
  memory endpoint. RJZQCP uses CXL IDE and CXL-TSP interfaces.
- Use quiesced devices and memory reserved for ACS. STOP_INTERFACE, reset,
  and ERROR transitions can scrub DCM or invalidate protected state.
- HPA accesses exercise the host-visible coherent path. Direct-DPA
  operations, where specified, initialize or observe device media.
- Platform-specific stimulus and observation operations are provided through
  the Platform Abstraction Layer (PAL). Each scenario specifies how missing
  prerequisites affect its result.

CDA Test Scenarios
==================

RSHRMN
------

**Test:** `cda_rshrmn_coherent_link_topology <../test_pool/cda/cda_rshrmn_coherent_link_topology.c>`_

**Rule Summary**

RSHRMN: For each coherent link, at most a single coherent device is permitted to be attached to a host node over that link. A coherent device is permitted to include multiple requesters and multiple home agents.

**Algorithm**

1. Skip the test if the platform does not advertise coherent DA support.
2. Enumerate the CXL component table and select root ports that are marked CHI-C2C capable and expose the RME-CDA DVSEC.
3. For each selected root port, read the Type-1 secondary/subordinate bus range and find downstream CHI-C2C endpoint components.
4. Group downstream endpoints by segment, bus, and device number, ignoring function number because multiple requesters can be represented as multiple functions within one coherent device.
5. Pass the link when exactly one coherent device group is present.
6. Fail the link when more than one coherent device group is present under the same coherent root port.
7. Skip the link when no downstream CHI-C2C coherent endpoint is present.

Note: This scenario checks coherent-link topology using enumerated endpoint identities.

RNVWMC
------

**Test:** `cda_rnvwmc_device_interface_support <../test_pool/cda/cda_rnvwmc_device_interface_support.c>`_

**Rule Summary**

RNVWMC: An RME-CDA coherent device supports compliant measurement and TDI assignment interfaces, meets the applicable TDISP security, memory encryption, MEC and coherency requirements, and conforms to the coherent-device rules in this section.

**Algorithm**

1. Require coherent DA discovery and SPDM requester support. Enumerate every CHI-C2C endpoint beneath a CHI-C2C root port with an RME-CDA DVSEC, without requiring an exerciser or selecting only the first endpoint.
2. Use only quiesced TDIs and associated memory reserved for ACS, with valid host mappings and device decoder configuration already established. Require an unprotected host port, an unused CONFIG_UNLOCKED TDI, and idle IDE state before making changes. Leave existing assignments and active links untouched.
3. Open an SPDM secure session. Negotiate TDISP version and capabilities, require advertisement of the seven base TDISP requests from GET_VERSION through STOP_INTERFACE_REQUEST, and query the interface state. A missing local transport or requester capability is a prerequisite skip; malformed responses or failed supported exchanges fail the test.
4. Query the measurement count and retrieve all measurement records over the same secure session using the generic VAL SPDM helper. Require a valid non-empty record and a block count matching the count query. The SPDM library validates the protocol exchange; no expected measurement digest or certificate specific to a device implementation is embedded in the test.
5. Require idle link IDE status accessible through the existing VAL interfaces; otherwise skip because the protected assignment setup is unavailable. Save RMECDA_CTL1, enable TDISP, establish link IDE, and set LINK_STR_LOCK. Verify host control readback. The test does not program new DMA mappings, start device traffic, require DCM, or alter HDM decoders. Missing CXL IDE registers must not be interpreted as evidence that a CHI link needs no IDE protection.
6. Send LOCK_INTERFACE_REQUEST and require CONFIG_LOCKED. Retrieve the DEVICE_INTERFACE_REPORT and validate its variable-length range list and device-specific information boundaries. Do not require a DCM range for a cache-only device. The requester library validates the response identity and assembles report portions.
7. Send START_INTERFACE_REQUEST with the nonce returned by LOCK_INTERFACE and require RUN. Send STOP_INTERFACE_REQUEST and require CONFIG_UNLOCKED. An unexpected state after either operation is a failure, not a prerequisite skip.
8. On every exit, stop any interface whose lock was attempted, remove ACS-created link protection and IDE state, restore RMECDA_CTL1, close the session, and free the report buffer. Cleanup failures fail the test. STOP can scrub TDI-associated memory, so this scenario must not be run on a live assigned workload.
9. Check every applicable endpoint, continuing after a skip or failure. Report FAIL if any attempted check or cleanup fails. Otherwise report SKIP if no endpoint completes the interface sequence, any applicable endpoint is skipped, or unresolved host discovery prevents determining applicability. Report PASS only when at least one endpoint completes and all applicable endpoints pass, including cleanup. Endpoints outside the supported CDA host topology or beneath a host port without an RME-CDA DVSEC do not prevent PASS. Print endpoint counts and the stage preventing completion.

Applicability: DEN0129 C.a, section B2.3.5, limits this version of RME-CDA assignment to CHI-based devices. A CHI-C2C endpoint remains eligible whether its CXL-style device classification is Type-1, Type-2, Type-3, or unknown; neither CXL.mem support nor an exerciser identity is required. Native CXL Type-1/Type-2 devices are outside that version's assignment scope, and native CXL Type-3 memory-expansion requirements are separate. Non-DOE and integrated-device management transports are not implemented by this scenario.

Note: This scenario validates measurement retrieval and TDI assignment interfaces. Certificate validation and measurement appraisal are not performed by this test. Results are PASS, FAIL, or SKIP.

RQWNBN
------

**Test:** `cda_rqwnbn_error_poison_response <../test_pool/cda/cda_rqwnbn_error_poison_response.c>`_

**Rule Summary**

RQWNBN: When a TDI of a coherent device is in the ERROR TDISP state, then for any cached Location in the Realm PAS that is associated with the TDI:

- The coherent device will poison write-backs of that Location from the cache.
- The coherent device will respond with a poison to snoop requests to that Location.

**Algorithm**

1. Select a CHI-C2C-capable CXL root port that exposes the RME-CDA DVSEC and locate a downstream CHI-C2C exerciser endpoint. Skip the test if no such endpoint is available.
2. Require a clean RMECDA_CTL1 state for the selected root port. Skip that root port if RMECDA_CTL1.TDISP_EN or RMECDA_CTL1.LINK_STR_LOCK is already set so the test does not consume preserved state from another CDA scenario.
3. Require and enable CXL.cache, enable CXL.mem, select a CFMWS-backed DCM page, and program the host and endpoint HDM decoders for that window so coherent accesses can use host-visible HPAs.
4. Enable RMECDA_CTL1.TDISP_EN and set RMECDA_CTL1.LINK_STR_LOCK after decoder programming is complete.
5. Select two DCM pages from the CFMWS-backed window. Map one page as a cacheable Realm alias for the snoop-response check. Assign both pages to the endpoint TDI, establish SPDM/TDISP, and transition the TDI to RUN.
6. Initialize each backing DCM Location through a non-cacheable Realm mapping, then read it through a cacheable Realm mapping to establish a clean coherent line. Evict local PE copies using set/way maintenance, without broadcasting an invalidation to the device. For each Location, obtain its HPA through ATS, perform an ATC-backed device read, return the captured value to a separate host buffer, and compare it with the initialized value. Mark each existing Realm cache line dirty only after this population and verification flow succeeds; successful DMA alone does not prove cache residency.
7. Force the TDI into ERROR by closing the SPDM session while the TDI is in RUN state.
8. Clear the root-port AER Uncorrectable Status register, then issue a protected host demand read to the cacheable Realm alias so the host attempts to consume or snoop the TDI-associated cached Location. Require the read to report a synchronous external abort, as specified by the RAS architecture for consumption of poisoned data. Fail if the read completes normally or reports a different exception syndrome. Treat returned data and root-port AER state as diagnostic information only for this subcase.
9. Clear AER again, then issue an exerciser cache-writeback command for the second dirty Realm DCM Location. Require a fresh Poisoned TLP Received indication at the root port. The command may report failure when the receiving port terminates the poisoned writeback; this is accepted only when the freshly cleared AER status records the poison event. Report SKIP if the required writeback poison indication is not observed.
10. Clear AER status, clear both DCM assignments when safe, reset/unlock the endpoint after the intentional TDI ERROR, close any still-open SPDM/TDISP session, and restore RMECDA/decoder state.

Note: This CDA scenario is applicable only to CHI-C2C-capable devices. ACS observes snoop-response poison through the synchronous external abort produced by a CPU demand read. The writeback subcase uses the root-port Poisoned TLP indication because host software cannot directly inspect the device cache writeback payload.

RLMFLX
------

**Test:** `cda_rlmflx_config_unlocked_invalidate <../test_pool/cda/cda_rlmflx_config_unlocked_invalidate.c>`_

**Rule Summary**

RLMFLX: When a TDI transitions to CONFIG_UNLOCKED TDISP state, the coherent device must invalidate content associated with that TDI that is stored in the device, including cached copies of Locations and ATC entries. Dirty cached data must be written back and invalidated when writeback is possible, for example while the IDE Stream is secure.

**Algorithm**

1. Select a CHI-C2C-capable CXL root port that exposes the RME-CDA DVSEC and locate a downstream CHI-C2C exerciser endpoint. Skip the test if no such endpoint is available.
2. Require a clean RMECDA_CTL1 state, require and enable CXL.cache, enable CXL.mem, select a CFMWS-backed DCM page, and program the host and endpoint HDM decoders for that window.
3. Enable RMECDA_CTL1.TDISP_EN and set RMECDA_CTL1.LINK_STR_LOCK after decoder programming is complete.
4. Map the selected DCM page as a cacheable Realm alias, assign the DCM page to the endpoint TDI, establish SPDM/TDISP, transition the TDI to RUN, and establish the CXL IDE link.
5. Optionally prepare an ATS stale-translation probe by enabling ATS, mapping an ACS-owned IOVA to one Non-secure PA through the Realm SMMU stage-2 context, installing DPT entries, and issuing an ATS request while the TDI is in RUN. If the exerciser cannot issue the ATS request, continue with the mandatory dirty-cache invalidation check.
6. Initialize backing DCM through a non-cacheable Realm mapping and populate a clean line through a cacheable Realm read while the TDI is in RUN and IDE is active. Evict local PE copies using set/way maintenance and mark the existing device line dirty before transitioning the TDI. Do not broadcast an invalidation during setup or before the post-transition read, as this could remove the device state being checked.
7. Issue STOP_INTERFACE_REQUEST and verify that the TDI reaches CONFIG_UNLOCKED state.
8. If the ATS stale-translation probe was available, remap the same IOVA to a different PA while the TDI is in CONFIG_UNLOCKED.
9. Close the first SPDM session, re-establish the TDI in RUN, and re-establish the CXL IDE link. Evict local PE copies using set/way clean-and-invalidate with other PEs quiescent; the PE has not written the cacheable alias, so there is no dirty PE copy of the selected Location to write back. Do not send an address-based invalidation to the device. Clear the root-port AER Uncorrectable Status register, then issue a protected host read to the cacheable Realm alias. Fail if the read faults or reports an uncorrectable error, because that indicates stale dirty TDI-owned state was not invalidated across CONFIG_UNLOCKED. Do not require the backing DCM to retain the dirty value because the CONFIG_UNLOCKED transition also scrubs TDI-associated DCM in compliance with RHDXTM.
10. If the ATS stale-translation probe was available, issue the ATS request again after re-entering RUN and fail if the returned translation is the old PA rather than the remapped PA.
11. Clear AER status, stop and close any active TDISP session, clear the DCM assignment, restore ATS, RMECDA, HDM decoder, GPT, SMMU, and DPT state, and free any allocated ACS pages.

Note: This CDA scenario is applicable only to CHI-C2C-capable devices. The dirty-cache check is mandatory; the ATC invalidation check is executed when the platform exerciser exposes a usable ATS request stimulus.

RVPKVF
------

**Test:** `cda_rvpkvf_tdi_state_independent <../test_pool/cda/cda_rvpkvf_tdi_state_independent.c>`_

**Rule Summary**

RVPKVF: The following operations must not be affected by the TDISP state of a TDI:

- Host-to-device requests on the CHI SNP channel.
- Device-to-host requests on the CHI SNP channel.
- Host-to-device requests on the CHI REQ channel.

**Algorithm**

1. Select a CHI-C2C-capable CXL root port and downstream exerciser endpoint, program a host-visible DCM window, and select three DCM pages. If an implementation-defined stimulus required by the test is unavailable, restore that endpoint and continue with the next eligible CHI-C2C endpoint. Skip the test only if no endpoint can provide all required stimuli.
2. Configure Realm SMMU and DPT mappings for the DCM pages, enable ATS for the endpoint, program the endpoint RID in the RME-CDA RID range, and associate the pages with the endpoint TDI.
3. Save the endpoint's original cache-enable state, then enable and verify the advertised cache capability used by the exerciser stimulus. Transition the TDI to RUN and establish the coherent-link IDE stream. Seed two DCM Locations, fetch each Location through an ATS-derived Realm translation, and copy the fetched data to a separate Non-secure verification page to confirm that the device-originated coherent read completed.
4. Evict local PE copies during cache-line setup using set/way maintenance rather than broadcasting an invalidation to the device. Mark the two retained device cache lines dirty. Reserve the third DCM page for repeatable device-to-host snoop and host request stimuli.
5. While the TDI is in RUN, dirty a PE cache line and immediately perform the monitored clean and invalidate to generate a host-to-device request on the CHI REQ channel. Next issue a host demand read that requires a host-to-device snoop, then issue a TDI-attributed device-to-host Realm snoop. Use the exerciser's incoming coherent-transaction monitor to verify that the generated request and demand read reach the device interface, and verify that the device-to-host request is emitted. Match the generated request by its HPA because the coherent writeback can be represented downstream as an ordinary cacheable write. The test does not require a host-port monitoring interface.
6. Repopulate the PE cache line while Realm access remains permitted, then close the protected SPDM session to transition the TDI from RUN to ERROR without changing the DCM associations.
7. Immediately check the staged host writeback after the transition, before the host-to-device snoop with the second dirty device line and the device-to-host snoop. This minimizes intervening work that could evict the staged PE cache line before capture starts. Verify through the exerciser interface that all three operation classes remain available in ERROR. A fault while consuming the ERROR-state snoop response is permitted because response poisoning is checked separately by RQWNBN.
8. Reset the endpoint out of ERROR and restore its PCIe configuration. Open a fresh SPDM session, explicitly stop IDE at the endpoint and root port, verify both link ends are INSECURE, and close the recovery session. Clear the DCM associations and restore ATS, SMMU, DPT, GPT, RID-range, decoder, RME-CDA, and the saved cache-enable state. Report failure if cleanup does not complete.

RWFYLW
------

**Test:** `cda_rwfylw_dev_prop_lock <../test_pool/cda/cda_rwfylw_dev_prop_lock.c>`_

**Rule Summary**

RWFYLW: Any configuration register in an RME-CDA coherent device that affects the RME security guarantee must either be exclusively controlled by the device DSM, or be locked and verified by the device DSM before responding to TDISP LOCK_INTERFACE_REQUEST. The DSM verification includes address-decoder consistency checks to prevent aliasing and to ensure DCM is only accessible through host-visible address ranges, and includes implementation-defined memory integrity, error injection, and debug controls exposed by the device.

**Algorithm**

1. Select a CHI-C2C-capable CXL root port that exposes the RME-CDA DVSEC and locate a downstream CHI-C2C exerciser endpoint. Skip the test if no such endpoint is available.
2. Select a CFMWS-backed DCM window and a same-sized aligned address range that is outside every host-visible CFMWS window. Save the original RMECDA_CTL1 value and the original host and endpoint HDM decoder state for cleanup.
3. Clear RMECDA_CTL1.TDISP_EN and RMECDA_CTL1.LINK_STR_LOCK through Root access for the ACS setup phase, then program both host and endpoint HDM decoders to the same CFMWS-backed DCM window. This establishes a valid, non-aliased address-decoder configuration before protection is enabled.
4. Set RMECDA_CTL1.TDISP_EN and RMECDA_CTL1.LINK_STR_LOCK through Root access and verify the bits read back as set before testing register protection.
5. While the TDI is still CONFIG_UNLOCKED, attempt to mutate the endpoint HDM decoder to the non-host-visible address range and reread the decoder. Fail the test if the decoder base or size changes. This verifies that an address-decoder register affecting DCM access is already protected before the DSM accepts LOCK_INTERFACE.
6. Open an SPDM session to the endpoint TDI, issue TDISP GET_VERSION and GET_CAPABILITIES, and keep the interface in CONFIG_UNLOCKED state.
7. Send Arm TDISP VDM GET_DEV_PROP and validate that the response framing and PROPERTIES reserved bits are correct. Save the PROPERTIES field and the opaque implementation-defined REGISTER_LIST bytes returned before LOCK_INTERFACE.
8. Send TDISP LOCK_INTERFACE_REQUEST and verify that the TDI reaches CONFIG_LOCKED state.
9. Send GET_DEV_PROP again and verify that PROPERTIES and REGISTER_LIST size are unchanged after LOCK_INTERFACE. If REGISTER_LIST is non-empty, compare the pre-lock and post-lock REGISTER_LIST bytes and fail if the DSM-provided validation blob changed across lock.
10. If REGISTER_LIST is empty, query TDISP GET_DEVICE_INTERFACE_REPORT and require PCI_TDISP_INTERFACE_INFO.NO_UPDATE_AFTER_LOCK to be set. This is the generic observable for devices whose RME-sensitive registers are DSM-owned or globally locked rather than exposed through GET_DEV_PROP.
11. While the TDI is CONFIG_LOCKED, repeat the endpoint HDM decoder mutation attempt to the non-host-visible address range and reread the decoder. Fail the test if the decoder base or size changes after lock.
12. Stop the TDI interface, close the SPDM session, clear RMECDA protection for cleanup, restore original decoder state, restore RMECDA_CTL1, and report PASS only when the protected decoder state cannot be mutated before or after LOCK_INTERFACE and the DSM property/register-list observable is stable across LOCK_INTERFACE.

Note: The GET_DEV_PROP REGISTER_LIST encoding is implementation-defined. ACS compares the returned bytes across LOCK_INTERFACE and checks protection of the standard HDM decoder registers. If the register list is empty, the test checks NO_UPDATE_AFTER_LOCK in the interface report.

RJZQCP
------

**Test:** `cda_rjzqcp_reset_transition <../test_pool/cda/cda_rjzqcp_reset_transition.c>`_

**Rule Summary**

RJZQCP: Upon any device reset or power state transition that has one or more of the following consequences:

- May affect the confidentiality or integrity of any Location in the Realm PAS, for example memory contents at rest or in transit.
- Resets cache state or invalidates cache lines without a write-back
- Resets coherency structures state
- Resets a protected register or any context that was configured by DSM, for example PAS filter or encryption context.

an RME-CDA coherent device guarantees the following:

- The IDE Stream transitions to Insecure state.
- All TDIs transition to the TDISP ERROR state and are then permitted to transition to CONFIG_UNLOCKED state, in compliance with [4].
- Memory encryption keys are reset to a known default value.
  - Subsequently, device completer-side PAS filters are permitted to transition all DCM Locations from the Realm PAS to the Non-secure PAS.
- The device is permitted to clean and invalidate device caches upon the event.
  - If clean and invalidate of device caches does not occur upon the event, it still occurs when the associated TDIs transition to CONFIG_UNLOCKED state, in compliance with RLMFLX.
  - Write-backs that occur during cache invalidation are not guaranteed to complete successfully, as the device-side PAS check might fail these.

**Algorithm**

1. Establish a CXL IDE link to the downstream endpoint and lock the endpoint TSP instance via SPDM.
2. Trigger an endpoint reset (FLR if supported, else Secondary Bus Reset).
3. After reset, verify Link IDE stream states are Insecure and the TSP instance is not CONFIG_LOCKED.

Note: This scenario requires SPDM/DOE support to query and configure CXL-TSP.

RHDXTM
------

**Test:** `cda_rhdxtm_dcm_scrub <../test_pool/cda/cda_rhdxtm_dcm_scrub.c>`_

**Rule Summary**

RHDXTM: When a TDI transitions to the CONFIG_UNLOCKED TDISP state, the coherent device must scrub all contents of DCM Locations associated with the TDI. Scrubbing can be implemented by coherently overwriting the contents or by resetting the associated memory-encryption context to a known default value after invalidating cached content.

**Algorithm**

1. Select a CHI-C2C-capable root port that exposes the RME-CDA DVSEC and any downstream CHI-C2C endpoint. Endpoint selection does not require PAL exerciser support.
2. Program a host-visible CFMWS-backed DCM window and begin the standard SPDM/TDISP lock sequence for the endpoint.
3. Read the TDISP DEVICE_INTERFACE_REPORT while the TDI is CONFIG_LOCKED. Locate the MMIO_RANGE whose range ID is 0xFFFF and select a page where that reported TDI-associated DCM range overlaps the host-visible DCM window.
4. Associate the selected HPA with Realm PAS in the host GPT, map it as non-cacheable Realm memory, transition the TDI to RUN, and establish the coherent-link IDE stream.
5. Write distinct address-dependent patterns at multiple cache-line-separated offsets through the architectural host-to-device HPA path and read them back. This proves that the Realm plaintext is present in the TDI-associated DCM before the transition under test.
6. Send STOP_INTERFACE_REQUEST while IDE remains active. Require the successful response and verify that the TDI reaches CONFIG_UNLOCKED; this is the synchronization point for the required scrub operation.
7. Close the first protected session, establish a fresh TDISP RUN session and IDE stream, and read the same DCM HPAs through the architectural Realm path. Require every read to complete so an access fault cannot be mistaken for scrubbing.
8. Fail if any sampled Location still contains its previous Realm plaintext. Do not require a fixed replacement value because RHDXTM permits either explicit overwrite or memory-encryption-context reset.
9. Stop the second TDISP session and restore the GPT, RME-CDA, and decoder state.

Note: This is a coherent-device compliance test that uses only standard host-visible HPA accesses and TDISP operations. It does not require exerciser DMA, direct-DPA media access, or implementation-defined endpoint commands.

RKRCWK
------

**Test:** `cda_rkrcwk_host_side_gpc <../test_pool/cda/cda_rkrcwk_host_side_gpc.c>`_

**Rule Summary**

RKRCWK: An access from a PE to any memory location, including to DCM, is subject to host-side GPC.

**Algorithm**

1. Discover a root port with a downstream Type-3 memory endpoint, host and endpoint HDM decoders, and a CFMWS window large enough for one translation granule. Skip if no usable configuration is found. An exerciser is not required.
2. Enable CXL.mem, save the decoder and host target-list state, and program a host-visible DCM window targeting the selected endpoint.
3. Select the first DCM page in that window. Set its GPT association to GPT_ANY and map a non-cacheable Non-secure alias for a protected PE access through EL3.
4. Attempt a store through the Non-secure alias and require the baseline access to complete without a protection fault. Skip if the baseline cannot be established, so an inaccessible DCM window cannot be mistaken for working GPC enforcement.
5. Change only the selected page's GPT association to Realm and repeat the store through the same Non-secure alias. Require the EL3 access helper to report the expected protection fault. Fail if the mismatched-PAS store completes.
6. Clear EL3 access state, restore the page to GPT_ANY, and restore saved decoder and host target-list configuration.

Note: This scenario checks host-side GPC using a Non-secure PE store to a Type-3 device memory page assigned to Realm PAS.

RQRMSC
------

**Test:** `cda_rqrmsc_dcm_ats_dependency <../test_pool/cda/cda_rqrmsc_dcm_ats_dependency.c>`_

**Rule Summary**

RQRMSC: If PAS_CHECK==FALSE, internal access to DCM is subject to host-side GPC and the device is not permitted to access DCM without first using ATS for host-side address translation and GPC. If PAS_CHECK==TRUE, internal access to DCM is subject to the device-side PAS protection check and direct DCM access without ATS is permitted by the rule.

**Algorithm**

1. Select a CHI-C2C-capable CXL root port that exposes the RME-CDA DVSEC and locate a downstream CHI-C2C exerciser endpoint. Skip the test if no such endpoint is available.
2. Program the host and endpoint CXL.mem decoders, program the RMECDA RID range for the endpoint Requester ID, enable RMECDA_CTL1.TDISP_EN, and set RMECDA_CTL1.LINK_STR_LOCK.
3. Select a DCM HPA from the programmed CXL.mem window and translate it through the endpoint HDM decoder to obtain the corresponding DPA. The HPA is used by the transaction under test; the DPA is used only to initialize and observe device media.
4. Query the endpoint PAS_CHECK property through TDISP GET_DEV_PROP. If PAS_CHECK==TRUE, skip the ATS dependency checks because the rule permits device-side PAS checks for direct DCM access.
5. For PAS_CHECK==FALSE, verify ATS capability is present and enable ATS for the endpoint.
6. Allocate an ACS-owned source page and a separate page-aligned IOVA. Configure the Realm SMMU stage-2 tables so the source IOVA resolves to the Non-secure source PA and the DCM IOVA resolves to the selected DCM HPA with Realm output PAS.
7. Establish TDISP RUN and CXL IDE. Load a known value into the exerciser using an ATS translation and an ATC-backed DMA from the Non-secure source page.
8. ATS-dependency negative check: invalidate the endpoint ATC and request an ATC-backed DMA with the DCM IOVA before issuing ATS for that IOVA. Verify that the device rejects the operation because no valid ATS-derived ATC entry exists, and verify through the DPA observation backdoor that DCM remains unchanged.
9. Positive check: issue ATS_TXN_REQ for the DCM IOVA and verify that the response is successful, grants access, returns the selected DCM HPA, and reports Realm output PAS. Issue DMA with USE_ATC_ENTRY using the original DCM IOVA, then read the corresponding DPA through the media observation backdoor and verify the known value reached DCM.
10. Host-GPC negative check: seed a different baseline at the DCM DPA, assign the DCM HPA to Non-secure PAS in GPT, invalidate the SMMU GPC cache and endpoint ATC, and issue a Realm ATS_TXN_REQ again for the same DCM IOVA. Fail if ATS returns a usable translation. Attempt an ATC-backed DMA and verify that DCM remains unchanged, then restore all modified state.

Note: This CDA scenario is applicable only to CHI-C2C-capable devices. Direct-DPA operations initialize and observe device media independently of the HPA access under test.

RWWBPM
------

**Test:** `cda_rwwbpm_internal_dcm_run_gate <../test_pool/cda/cda_rwwbpm_internal_dcm_run_gate.c>`_

**Rule Summary**

RWWBPM: An RME-CDA coherent device must not permit an internal access to DCM to specify PAS==Realm unless the access is from a TDI in the RUN TDISP state.

**Algorithm**

1. Select a CHI-C2C-capable CXL root port and downstream exerciser, select a CFMWS location, and program the host and endpoint HDM decoders. Use the host-visible DCM HPA for the access under test and derive its DPA only for direct-media setup and observation.
2. Query the endpoint PAS_CHECK property, configure SMMU stage-2 mappings for a Non-secure source page and the Realm DCM HPA, install the required DPT entries, and program the endpoint RID range. For PAS_CHECK==FALSE, enable ATS; for PAS_CHECK==TRUE, configure direct PA transactions with explicit Realm SEC_SID and ATC use disabled.
3. Establish IDE and transition the endpoint TDI to RUN, assign the selected DCM HPA to Realm, and seed a baseline value through the DPA backdoor.
4. Load a host-owned value into the exerciser and write it to the DCM HPA with Realm PAS. Use ATS followed by ATC-backed DMA when PAS_CHECK==FALSE, or direct HPA DMA when PAS_CHECK==TRUE, then verify through DPA media readback that the write succeeded in RUN.
5. While still in RUN, prepare a different source value and, for PAS_CHECK==FALSE, cache the translation needed for the negative transaction. Restore a known media baseline and transition the TDI out of RUN with STOP_INTERFACE.
6. Re-issue the same Realm write path selected by PAS_CHECK and verify that the non-RUN access is rejected and that the requested write value did not reach DCM. Permit the old baseline to change because STOP_INTERFACE transitions the TDI to CONFIG_UNLOCKED and can independently scrub associated DCM.

RFZBMW
------

**Test:** `cda_rfzbmw_external_dcm_ide_gate <../test_pool/cda/cda_rfzbmw_external_dcm_ide_gate.c>`_

**Rule Summary**

RFZBMW: An RME-CDA coherent device must not permit an external access to DCM to specify PAS==Realm unless the TDI is in the RUN TDISP state and the coherent link IDE stream is active.

**Algorithm**

1. Select a CHI-C2C-capable CXL root port that exposes the RME-CDA DVSEC and a downstream CHI-C2C exerciser endpoint, program host and endpoint decoders for a CXL.mem window, and derive the selected DCM page's DPA from the endpoint decoder.
2. Establish an SPDM session, transition the endpoint TDI to RUN, establish CXL IDE, and enable RMECDA_CTL1.TDISP_EN and RMECDA_CTL1.LINK_STR_LOCK.
3. Assign a selected host-visible DCM page to Realm.
4. Issue an external write followed by a read that specifies PAS==Realm while IDE is active and verify the read returns the written value.
5. Disable the IDE stream while keeping the TDI in RUN, restore a known baseline value at the same Realm-assigned DCM page, and re-issue the same external PAS==Realm access.
6. Verify that the IDE-disabled external PAS==Realm access is rejected. Stop the TDISP session before cleanup; any subsequent DCM media readback is diagnostic because the CONFIG_UNLOCKED transition can scrub the old contents.

RVHZCR
------

**Test:** `cda_rvhzcr_external_pas_check <../test_pool/cda/cda_rvhzcr_external_pas_check.c>`_

**Rule Summary**

RVHZCR: If PAS_CHECK==TRUE, device-side PAS protection checks apply both to internal access and external access to DCM.

**Algorithm**

1. Select a CHI-C2C-capable CXL root port that exposes the RME-CDA DVSEC and a downstream CHI-C2C exerciser endpoint, then program host and endpoint decoders for a host-visible DCM window.
2. Read the Arm TDISP device properties and skip the test unless PAS_CHECK is set.
3. Select a DCM page, map its HPA as Realm PAS, assign the page to Realm at the device, and seed its corresponding DPA media with a known value.
4. Transition the TDI to RUN, establish the coherent-link IDE stream, and verify an external Realm-PAS read through the HPA returns the known value.
5. Flush the host cacheline, stop the protected path, remove the device-side Realm association, and seed a different protected value while retaining the Realm GPT association.
6. Re-establish TDI RUN and IDE, then issue the same external Realm-PAS HPA read. Verify that the access faults or does not return the protected media value.
7. Stop the TDISP session, disable IDE, restore the GPT, decoder, and RME-CDA state, and clear any remaining DCM assignment.

Note: This scenario exercises external access to DCM on devices that advertise PAS_CHECK==TRUE. Internal access is not tested by this scenario.

RSTQHS
------

**Test:** `cda_rstqhs_unknown_snoop_filter <../test_pool/cda/cda_rstqhs_unknown_snoop_filter.c>`_

**Rule Summary**

RSTQHS: The host is permitted to forward a host-to-device snoop request to a coherent device only if the request specifies a Location known to be resident in the device cache, a Location the device is permitted to access, a MECID the device is permitted to use, or an address in the Non-secure PA space.

**Algorithm**

1. Select a CHI-C2C-capable root port with an RME-CDA DVSEC and a downstream CHI-C2C exerciser endpoint, then program a host-visible DCM window.
2. Select two adjacent DCM pages and change their GPT association to Realm PAS.
3. Establish TDISP RUN and the coherent-link IDE stream so transport security does not independently prevent host-to-device snoops.
4. Use the platform PAL to establish and verify host snoop eligibility: the first Realm Location is an eligible positive target; the second has no known cached copy, permitted PA association, or permitted MECID. Require support for a host snoop stimulus and snoop-specific endpoint transaction records. Skip if these prerequisites cannot be established.
5. Start the exerciser transaction monitor and ask the PAL to trigger a host snoop candidate for the permitted Location. Wait for completion and require a matching incoming snoop record as positive calibration. Ordinary memory reads and cache-maintenance records do not qualify as snoop evidence.
6. Start a fresh capture and trigger the unknown Realm candidate without granting it permission or populating it in the device cache. Wait for the forwarding decision and observation to complete. Fail if a matching snoop is observed; otherwise pass. Unsupported stimulus does not count as successful filtering.
7. Restore the host state saved by the PAL, including after a partially completed setup. Stop TDISP and IDE, then restore GPT and decoder state.

Note: IKMFFT specifies an implementation-defined host mechanism. The platform PAL must establish host snoop eligibility and provide the stimulus and snoop observation required by the algorithm. Skip if these operations are unavailable.

RHTTNB
------

**Test:** `cda_rhttnb_dirty_snoop_blocked <../test_pool/cda/cda_rhttnb_dirty_snoop_blocked.c>`_

**Rule Summary**

RHTTNB: If a host-to-device snoop request cannot be forwarded to a coherent device, for example because the IDE Stream is in Insecure state, and the host port is tracking the Location as potentially owned by the device in a Dirty state, the host port must respond with poison and fixed data. If the host port cannot associate the response with a correct MECID, it must use the default MECID of zero.

**Algorithm**

1. Select a CHI-C2C-capable CXL root port that exposes the RME-CDA DVSEC and locate a downstream CHI-C2C exerciser endpoint. Skip the test if no such endpoint is available.
2. Require a clean RMECDA_CTL1 state for the selected root port. Skip that root port if RMECDA_CTL1.TDISP_EN or RMECDA_CTL1.LINK_STR_LOCK is already set.
3. Require and enable CXL.cache, enable CXL.mem, select a CFMWS-backed DCM page, and program the host and endpoint HDM decoders for that window.
4. Enable RMECDA_CTL1.TDISP_EN and set RMECDA_CTL1.LINK_STR_LOCK after decoder programming is complete.
5. Map the selected DCM page as a cacheable Realm alias, assign the DCM page to the endpoint TDI, establish SPDM/TDISP, transition the TDI to RUN, and establish the CXL IDE link.
6. Initialize backing DCM through a non-cacheable Realm mapping and populate a clean line through a cacheable Realm read while the TDI is in RUN and IDE is active. Evict local PE copies using set/way maintenance without broadcasting an invalidation to the device, then mark the retained device line dirty before disabling the IDE link.
7. Disable the CXL IDE link while the TDI remains in RUN state. This creates the RHTTNB condition where a host-to-device snoop cannot be forwarded to the coherent device.
8. Clear root-port AER status when available, then issue a protected host read to the cacheable Realm alias so the host port must resolve a potentially device-owned dirty Location without forwarding the snoop.
9. Pass when consuming the poison raises a synchronous external abort. If the read completes, require poison/fixed data rather than the original dirty value cached by the TDI. AER status is recorded only as diagnostic information because a coherent poison response does not require a PCIe Poisoned TLP indication.
10. Clear AER status, stop the TDI interface, close the SPDM session, clear the DCM assignment, and reset the endpoint to discard the dirty cache line before restoring RMECDA/decoder state.

Note: This CDA scenario is applicable only to CHI-C2C-capable devices. The protected read distinguishes the architecturally expected synchronous external abort from unrelated faults. Endpoint reset prevents dirty cache state from affecting subsequent CDA tests.

RYDSYL
------

**Test:** `cda_rydsyl_d2h_sec_sid_rid <../test_pool/cda/cda_rydsyl_d2h_sec_sid_rid.c>`_

**Rule Summary**

RYDSYL: An RME-CDA coherent device guarantees that the CHI SEC_SID and CHI RID fields on any device-to-host memory request from a TDI or from a cache associated with a TDI are set as follows:

- If the TDI is in the RUN TDISP state, CHI SEC_SID is Realm. Otherwise, CHI SEC_SID is Non-secure.
- The CHI RID field is set to the Requester ID of the TDI. For a TDI in the RUN TDISP state, this value is equal to the Requester ID field in the TDISP-specified INTERFACE_ID of the TDI.
- A device-to-host access from a cache specifies the SEC_SID and RID fields of the allocating access.

**Algorithm**

1. Select a CHI-C2C-capable CXL root port that exposes the RME-CDA DVSEC and a downstream CHI-C2C exerciser endpoint. Skip the test if no such endpoint is available.
2. Enable CXL.mem for the endpoint and map the root port configuration space for Root access. Save the original RMECDA_CTL1, RMECDA_CTL3, and RMECDA_CTL4 register values for cleanup.
3. Clear RMECDA_CTL1.LINK_STR_LOCK before changing the RID window. Program RMECDA_CTL4.RID_BASE and RMECDA_CTL3.RID_LIMIT to the endpoint TDI Requester ID, set RMECDA_CTL4.RID_RANGE_VALID, and then set RMECDA_CTL1.TDISP_EN and RMECDA_CTL1.LINK_STR_LOCK.
4. Establish an SPDM session, transition the endpoint TDI to RUN, establish the CXL IDE link if supported, and verify that the link IDE stream is Active when IDE is supported.
5. Configure SMMU mappings and GPT entries for Realm DMA source and destination buffers. Program the exerciser to use translated addressing and its own Requester ID.
6. With the TDI in RUN state, issue device-to-host DMA without explicitly overriding SEC_SID in the exerciser. Verify the DMA completes and the destination buffer matches the source buffer. This acceptance indirectly validates that the device/root complex supplied the TDI Requester ID and Realm identity required by the configured RID window and Realm access policy.
7. Stop the TDI so it is no longer in RUN state and issue the same Realm DMA path. Verify the request is rejected and the destination buffer is not updated.
8. Disable the IDE link if it was enabled, close the SPDM session, restore GPT/SMMU state, and restore RMECDA_CTL1, RMECDA_CTL3, and RMECDA_CTL4.

Note: This CDA scenario is applicable only to CHI-C2C-capable devices. The CHI SEC_SID and CHI RID fields are not directly readable by ACS software, so the test uses host-port RID range programming and Realm DMA acceptance/rejection as the observable validation mechanism.

RYJVJR
------

**Test:** `cda_ryjvjr_ats_te_pas <../test_pool/cda/cda_ryjvjr_ats_te_pas.c>`_

**Rule Summary**

RYJVJR: An SMMU in an RME-CDA system supports populating the TE Memory Attribute bit in ATS Translation Completions with the PA space resolved by translation.

**Algorithm**

1. Select a CHI-C2C-capable CXL root port that exposes the RME-CDA DVSEC and locate a downstream CHI-C2C exerciser endpoint. Skip the test if no such endpoint is available.
2. Locate the SMMUv3 instance and StreamID associated with the endpoint. Require SMMU_R_IDR0.ATS and SMMU_R_IDR3.XT to be implemented.
3. Enable endpoint ATS, enable the SMMU, and allocate separate Non-secure and Realm output pages with distinct IOVAs.
4. Install a Realm stage-2 translation context mapping the first IOVA to the Non-secure page and the second IOVA to the Realm page.
5. Configure the Realm DPT region containing the first output PA with AC=0b01 so that it resolves to the Non-secure PA space. Grant read and write access and invalidate cached DPT state.
6. Establish the endpoint TDI in RUN state and establish the CXL IDE link.
7. Issue an unconstrained Realm-tagged ATS Translation Request for the first IOVA. Require a successful completion with non-zero permissions and the expected translated PA, and verify that TE is clear because translation resolved to the Non-secure PA space.
8. Reprogram the DPT region containing the second output PA with AC=0b00 so that it resolves to the Realm PA space, invalidate the DPT and exerciser ATC, and issue a request with the same Realm attributes for the second IOVA. Require a successful completion with non-zero permissions and the expected translated PA, and verify that TE is set. Reprogramming between requests keeps the test independent of the implemented DPT block granularity.
9. Stop the TDI session and restore the IDE, ATS, SMMU, DPT, GPT, and allocated-memory state.

Note: The request attributes are identical for both translations and do not constrain the output PA space. ATS Translation Completion bit[6] carries the SMMU-resolved TE value for a Realm stream. The same bit position carries the PCIe Global attribute in contexts where TE is not applicable.

RFRFJG
------

**Test:** `cda_rfrfjg_tdi_snoop_access <../test_pool/cda/cda_rfrfjg_tdi_snoop_access.c>`_

**Rule Summary**

RFRFJG: A TDI must not issue a snoop request to a physical address unless it is permitted to directly access that physical address.

**Algorithm**

1. Select a CHI-C2C-capable CXL root port and downstream exerciser endpoint, program the endpoint decoder for a CFMWS window, and select two DCM pages.
2. Program the RME-CDA RID range to admit the selected endpoint, enable the TDISP and link-stream-lock controls, transition the endpoint TDI to RUN, and establish the coherent-link IDE stream.
3. Assign page A to Realm while page B remains unassigned, then request Realm-PAS BISnp transactions attributed to that TDI.
4. Verify from the PAL snoop observation that the snoop to page A was emitted and that the snoop to page B was blocked without emitting a transaction.
5. Move the Realm assignment from page A to page B and repeat both checks to verify that the current Realm assignment controls access.
6. Clear Realm assignments, disable IDE, stop the TDISP session, and restore the decoder and RME-CDA controls.

Note: The device-to-host snoop carries the selected PAS and TDI attribution and is subject to the originating TDI's physical-address permission check. Calibrate the permitted snoop only after RUN, IDE, and the page association are established. Skip if local blocking cannot be observed; a generic command error does not prove that the TDI prevented emission.

RNSMGT
------

**Test:** `cda_rnsmgt_dependent_coverage <../test_pool/cda/cda_rnsmgt_dependent_coverage.c>`_

**Rule Summary**

RNSMGT: A host port must be able to identify that a PA of a device-to-host access falls within the DCM range of the coherent device attached to that port.

**Algorithm**

1. Obtain the recorded results of RSHSXK and RJSYPS, which run earlier in the CDA module and exercise the host port's use of the requesting device's DCM range.
2. Pass when both prerequisite tests pass.
3. Report PASSED PARTIAL when one prerequisite passes and the other is skipped.
4. Skip when both prerequisite tests are skipped.
5. Fail for every other combination, including a failure from either prerequisite.

Note: This test performs no additional hardware stimulus. RNSMGT is covered indirectly by the architecturally observable behavior validated by RSHSXK and RJSYPS.

RSHSXK
------

**Test:** `cda_rshsxk_d2h_gpc_dpt <../test_pool/cda/cda_rshsxk_d2h_gpc_dpt.c>`_

**Rule Summary**

RSHSXK: For a device-to-host request that specifies a PA and is sent on the CHI REQ channel or a non-coherent channel, the host enforces the GPC and, when SEC_SID is Realm, the DPT. The host is permitted to omit these checks when the PA is within the DCM range of the requesting device.

**Algorithm**

1. Select a CHI-C2C-capable CXL root port that exposes the RME-CDA DVSEC and locate a downstream CHI-C2C exerciser endpoint. Skip the test if no such endpoint is available.
2. Save the root-port RME-CDA controls, program the permitted RID range for the endpoint, enable TDISP enforcement, and set LINK_STR_LOCK.
3. Transition the TDI to RUN and establish the CXL IDE stream.
4. Reserve adjacent source and destination pages from ACS host memory and verify that their PA range does not overlap any advertised CFMWS window. This prevents the optional DCM-range exemption from applying. Configure stage-1 and Realm stage-2 identity mappings for the endpoint StreamID, mark both output pages as Realm in GPT, grant both pages read/write access in DPT, and invalidate cached SMMU policy state.
5. Configure the endpoint to issue AT=Translated requests that specify the host-buffer PAs and use its natural Requester ID. Initialize the host source and destination with different patterns, perform DMA to the device from the source, then perform device-to-host DMA to the destination without overriding SEC_SID. Program AT=Translated for every DMA because the transaction attribute applies to one request.
6. Positive GPC control: with matching Realm GPT state and read/write DPT permissions, require the DMA operations to complete and require the source and destination host buffers to match.
7. GPC negative check: reset the destination to a sentinel pattern, change only the destination GPT entry to Non-secure, invalidate SMMU GPT state, and repeat the device-to-host DMA. Restore the Realm GPT entry before observation and require the complete destination sentinel to remain unchanged.
8. DPT check: configure a valid Realm SEC_SID and reinitialize both host buffers. Set their GPT entries to match the Non-secure PAS of the translated requests and program read/write DPT entries whose AC field selects Non-secure output PA space, then perform a new source-to-device and device-to-destination DMA round trip. Restore the Realm GPT entries before observation and require the buffers to match. For the negative check, reset the destination sentinel, restore its matching Non-secure GPT entry, change only its DPT entry to no-access, invalidate policy state, and repeat the D2H DMA. Restore GPT and DPT permission before observation and require the complete destination sentinel to remain unchanged.
9. Disable IDE, stop and close the TDISP session, restore the permitted RID range and RMECDA controls, restore DPT and GPT state, destroy the SMMU mappings, and disable the endpoint SMMU context.

Note: This CDA scenario is applicable only to CHI-C2C-capable devices. It uses ACS-owned HCM pages rather than DCM, so an accepted request cannot be explained by the rule's optional DCM-range check exemption.

RDMSPT
------

**Test:** `cda_rdmspt_rid_range_check <../test_pool/cda/cda_rdmspt_rid_range_check.c>`_

**Rule Summary**

RDMSPT: For an RME-CDA coherent CHI-C2C device, device-to-host requests are accepted by the host port only when the Requester ID is inside the permitted RMECDA RID range while RMECDA_CTL1.LINK_STR_LOCK is set.

**Algorithm**

1. Select a CHI-C2C-capable CXL root port that exposes the RME-CDA DVSEC and locate a downstream CHI-C2C exerciser endpoint. Skip the test if no such endpoint is available.
2. Enable CXL.mem for the endpoint, map the root port configuration space for Root access, and save the original RMECDA_CTL1, RMECDA_CTL3, and RMECDA_CTL4 register values for cleanup.
3. Allocate source and destination DMA pages, mark them Non-secure in GPT, and map the same VA/PA pairs for EL3 access so the test can initialize and compare buffers safely after ownership changes.
4. Configure an identity SMMU mapping for both DMA pages, enable the SMMU for the endpoint stream, and program the exerciser to use translated addressing.
5. Use the endpoint's natural Requester ID. Do not spoof or override the exerciser RID; this keeps the check aligned with the Requester ID emitted by the TDI/exerciser path.
6. Positive check: clear RMECDA_CTL1.LINK_STR_LOCK, program RMECDA_CTL4.RID_BASE and RMECDA_CTL3.RID_LIMIT to exactly the endpoint Requester ID, set RMECDA_CTL4.RID_RANGE_VALID, then set RMECDA_CTL1.LINK_STR_LOCK.
7. Load the exerciser device buffer using host-to-device DMA, issue device-to-host DMA into the destination page, and verify that the destination buffer matches the source buffer. A match means the in-range Requester ID was accepted.
8. Negative check: clear RMECDA_CTL1.LINK_STR_LOCK, program a valid RID range that excludes the endpoint Requester ID, set RMECDA_CTL4.RID_RANGE_VALID, and set RMECDA_CTL1.LINK_STR_LOCK again.
9. Issue device-to-host DMA without reloading the device buffer and verify the destination buffer remains different from the source buffer. A mismatch means the out-of-range Requester ID was rejected by the host port.
10. Restore RMECDA_CTL1, RMECDA_CTL3, and RMECDA_CTL4, disable the endpoint SMMU mapping, restore GPT entries, and free the DMA pages.

Note: This CDA scenario is applicable only to CHI-C2C-capable devices and validates the RID range indirectly through D2H DMA acceptance/rejection.

RJSYPS
------

**Test:** `cda_rjsyps_d2h_snp_range <../test_pool/cda/cda_rjsyps_d2h_snp_range.c>`_

**Rule Summary**

RJSYPS: The host port applies the DCM Access PAS policy to device-to-host CHI SNP requests and rejects requests whose PA is outside the attached device's DCM range.

**Algorithm**

1. Select a CHI-C2C-capable root port and downstream exerciser, then program the host and endpoint HDM decoders for a CFMWS-backed DCM window.
2. Select an address inside the DCM window and an allocated Non-secure host-memory address outside that window.
3. Establish the TDI RUN state and coherent-link IDE stream, associate the in-range DCM page with Realm, and give that page conflicting Non-secure GPT state.
4. Issue a Realm device-to-host SNP to the in-range DCM PA and verify from the coherent response that the request succeeds without applying GPC or DPT checks.
5. Issue a Non-secure device-to-host SNP to the out-of-range host PA. Verify from the coherent error response that the host rejects it despite the address having matching Non-secure GPC state.
6. Clear the DCM assignment and restore the TDISP, IDE, GPT, and decoder state.

Note: Successful upstream transaction completion can establish emission and host acceptance. A generic command error cannot distinguish local blocking from host rejection. Skip if the required emission or host-response evidence is unavailable; do not treat an ambiguous error as successful range enforcement.

RDRVTK
------

**Test:** `cda_rdrvtk_d2h_mecid <../test_pool/cda/cda_rdrvtk_d2h_mecid.c>`_

**Rule Summary**

RDRVTK: The host must guarantee that every device-to-host request and device-to-host response is associated with a MECID that the device is permitted to use.

**Algorithm**

1. Select a CHI-C2C-capable root port with an RME-CDA DVSEC and a downstream CHI-C2C exerciser endpoint that advertises MEC support and a non-zero MECID width. Require host MEC support.
2. Configure the TDI primary MECID to 1 with SET_INTERFACE while the TDI is CONFIG_UNLOCKED. Program the root-port RID range for the endpoint, enable TDISP enforcement, set LINK_STR_LOCK, then transition the TDI to RUN and establish the coherent-link IDE stream.
3. Allocate separate source, destination, and verification pages. Create a Realm SMMU stage-2 context for the endpoint StreamID covering the ACS-owned HCM pages, two DCM pages, and the Non-secure verification page. Configure the Realm STE to select MECID 1 and mark the Realm output pages in GPT.
4. Initialize the source and destination under MECID 1 with different patterns. Issue an untranslated device read from the source IOVA followed by a device write to the destination IOVA, using the endpoint's natural RID and Realm SEC_SID. The Realm SMMU translates both requests and associates them with MECID 1 from the endpoint STE. Require the buffers to match under MECID 1.
5. Clean the HCM data to the Point of Encryption, select MECID 0 on the PE, and require the destination not to expose the original plaintext pattern. Restore MECID 1 and require the source and destination to match again. This data-path observation verifies that the SMMU-selected permitted MECID was associated with the D2H read and write requests.
6. If the exerciser can select a MECID on a snoop response, associate two DCM pages with the TDI, configure the required DPT permissions, enable ATS, populate and verify a coherent Realm line on each page, and mark each existing line Dirty. Translate each HPA through the endpoint HDM decoder and use a direct-DPA exerciser operation to replace the backing DCM value without changing the dirty cached value.
7. Configure the first snoop response to carry permitted MECID 1 and issue a protected Realm host read. Require the read to complete and return the dirty cached value rather than the distinct backing value; this calibrates the snoop-response path.
8. Configure the second snoop response to carry unpermitted MECID 0 and issue the same protected Realm host read. Fail if the read completes with the dirty cached value. A synchronous fault or the distinct backing value demonstrates that the host did not consume the unpermitted response. For any other normal-completion value, report PASSED PARTIAL.
9. If response-MECID selection or the coherent cache-fill stimulus is unavailable, report PASSED PARTIAL after the mandatory D2H request checks pass. Otherwise require both request and response checks to pass.
10. Disable the response override, clear the DCM assignments, disable IDE, stop the TDISP session, and restore CXL.cache, ATS, SMMU, DPT, GPT, RID-range, PMECID, MEC, decoder, and RME-CDA state.

Note: The response-MECID operation is an implementation-defined exerciser stimulus. ACS evaluates the response using the host read outcome and returned data. The HCM request check requires host memory encryption and SMMU MECID selection.

License
========

RME System ACS is distributed under Apache v2.0 License.

*Copyright (c) 2023-2026, Arm Limited and Contributors. All rights reserved.*
