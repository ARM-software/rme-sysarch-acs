# RME System ACS Exerciser API porting guide

This guide describes the exerciser PAL behavior required to run RME System ACS
tests. It is intended for silicon partners and EDA vendors mapping the ACS APIs
to a programmable endpoint, verification IP, or equivalent stimulus source.

The reference register behavior is documented in [Exerciser.md](Exerciser.md).
A platform does not need to reproduce that register layout if its PAL presents
the same behavior to ACS.

## PAL entry points

The PAL implements the following entry points declared in
[`val/include/pal_interface.h`](../val/include/pal_interface.h):

```c
uint32_t pal_is_bdf_exerciser(uint32_t bdf);
uint32_t pal_exerciser_set_param(EXERCISER_PARAM_TYPE type,
                                 uint64_t value1, uint64_t value2,
                                 uint32_t bdf);
uint32_t pal_exerciser_get_param(EXERCISER_PARAM_TYPE type,
                                 uint64_t *value1, uint64_t *value2,
                                 uint32_t bdf);
uint32_t pal_exerciser_set_state(EXERCISER_STATE state,
                                 uint64_t *value, uint32_t bdf);
uint32_t pal_exerciser_get_state(EXERCISER_STATE *state, uint32_t bdf);
uint32_t pal_exerciser_ops(EXERCISER_OPS ops, uint64_t param,
                           uint32_t bdf);
uint32_t pal_exerciser_get_data(EXERCISER_DATA_TYPE type,
                                exerciser_data_t *data,
                                uint32_t bdf, uint64_t ecam);
```

Unless an operation documents another result, return `0` for success and a
nonzero value for failure. Do not return success for an unsupported operation.
`bdf` identifies the exact endpoint to control; the PAL must not silently use a
different exerciser instance.

The examples show call ordering; callers must check each API's return convention
before consuming its outputs or proceeding to the next operation.

Reference implementations are in
[`platform/pal_uefi/src/pal_exerciser.c`](../platform/pal_uefi/src/pal_exerciser.c)
and
[`platform/pal_baremetal/src/pal_exerciser.c`](../platform/pal_baremetal/src/pal_exerciser.c).

## Discovery and initialization

`pal_is_bdf_exerciser(bdf)` returns nonzero only for a controllable exerciser.
The reference implementation recognizes combined Vendor/Device ID
`0xED0113B5`. RME System ACS calls this function while building both its PCIe
and CXL exerciser tables.

`pal_exerciser_get_state()` must report `EXERCISER_ON` when the device is ready.
Memory Space and Bus Mastering must be enabled before traffic, with usable BARs
assigned by the platform. The instance-based `val_exerciser_init()` enables
these command bits; `val_exerciser_init_by_bdf()` only checks readiness.

CHI-C2C capability alone does not identify an exerciser. Tests requiring custom
stimulus also check exerciser discovery and the capabilities needed by the
scenario. The reference `get_state` reports ON and `set_state` is a stub; these
calls do not discover command support or replace the SPDM/TDISP state machine.

## DMA

Configure the bus address and length:

```c
pal_exerciser_set_param(DMA_ATTRIBUTES, address, length, bdf);
```

Start the transfer:

```c
pal_exerciser_ops(START_DMA, direction, bdf);
```

| `direction` | Required operation |
| --- | --- |
| `EDMA_TO_DEVICE` | Device reads `length` bytes from `address` into its local DMA data area |
| `EDMA_FROM_DEVICE` | Device writes `length` bytes from its local DMA data area to `address` |

The operation must not report success until the transaction has completed or
failed. Its status must distinguish a successful DMA from a range or internal
error. DMA attributes configured by the following APIs remain in effect until
changed or reset.

The local DMA data area is implementation-defined. For portable readback,
transfer an initialized host source buffer to the device, transfer the data
back to a separate host destination, and compare the host buffers. Do not
assume an internal buffer is exposed through a particular BAR. Map both buffers
when EL3 accesses them and apply the required cache maintenance.

### Address type

```c
pal_exerciser_set_param(CFG_TXN_ATTRIBUTES,
                         TXN_ADDR_TYPE, address_type, bdf);
```

Pass a logical enum, not the raw DMA Control register encoding:

| `address_type` | PAL value | Reference DMA control bits `[11:10]` |
| --- | ---: | ---: |
| `AT_UNTRANSLATED` | `0x0` | `0x1` |
| `AT_TRANSLATED` | `0x2` | `0x2` |
| `AT_RESERVED` | `0x3` | `0x3` |

The register reset encoding `0x0` also means Untranslated. `AT_TRANS_REQ`
is declared but is not supported by this setter; issue ATS through
`ATS_TXN_REQ`. Reserved address-type stimulus is expected to fail DMA.

### ATC-backed DMA

After obtaining a usable ATS translation, submit the original IOVA and enable
the cached-translation path:

```c
pal_exerciser_set_param(DMA_ATTRIBUTES, iova, length, bdf);
pal_exerciser_set_param(CFG_TXN_ATTRIBUTES, TXN_ADDR_TYPE,
                         AT_UNTRANSLATED, bdf);
pal_exerciser_set_param(CFG_TXN_ATTRIBUTES, TXN_ATC_ENTRY,
                         ATC_ENTRY_ENABLE, bdf);
pal_exerciser_ops(START_DMA, direction, bdf);
```

`TXN_ATC_ENTRY` controls reference DMA control bit 9. The endpoint obtains the
output address and permissions from the matching ATC entry and emits the
Translated transaction. If the entry is absent, does not cover the whole
transfer, or lacks permission, DMA must fail without issuing a replacement ATS
request or falling back to untranslated access. This is distinct from forcing
`AT_TRANSLATED` with a supplied physical address.

`val_exerciser_dma_with_atc_by_bdf()` performs this sequence. It does not issue
ATS or disable ATC use afterwards. Before a direct-address DMA or during
cleanup, set `TXN_ATC_ENTRY` to `ATC_ENTRY_DISABLE` and restore the intended
address type. An ATC invalidation discards entries but does not disable ATC use.

### Requester ID override

Set and enable an override:

```c
pal_exerciser_set_param(CFG_TXN_ATTRIBUTES, TXN_REQ_ID,
                         requester_id, bdf);
```

Disable the override and restore the enumerated Requester ID:

```c
pal_exerciser_set_param(CFG_TXN_ATTRIBUTES, TXN_REQ_ID_VALID,
                         RID_NOT_VALID, bdf);
```

The override is a negative-test feature and must be scoped to the selected
endpoint.

### No Snoop

```c
pal_exerciser_ops(TXN_NO_SNOOP_ENABLE, 0, bdf);
pal_exerciser_ops(TXN_NO_SNOOP_DISABLE, 0, bdf);
```

Enable causes subsequent DMA requests to carry the PCIe No Snoop attribute;
Disable restores snooped requests.

### PASID TLP prefix

Start PASID-tagged DMA using the supplied 20-bit PASID:

```c
pal_exerciser_ops(PASID_TLP_START, pasid, bdf);
```

This operation enables PASID in the endpoint capability and in the exerciser
DMA control, then programs the PASID value. Stop PASID-tagged DMA with:

```c
pal_exerciser_ops(PASID_TLP_STOP, pasid, bdf);
```

The Stop operation disables both the generated PASID prefix and the endpoint
PASID Enable bit. `PASID_ATTRIBUTES` is used when the platform needs to expose
or configure the supported PASID width.

## ATS

Configure request attributes separately from the expected translation result:

```c
pal_exerciser_set_param(EXERCISER_ATS_REQUEST_ATTRIBUTES,
                         request_attributes, 0, bdf);
```

Logical bit 0 is T (`VAL_ATS_REQUEST_T`) and bit 1 is XT
(`VAL_ATS_REQUEST_XT`); other bits are invalid. The reference PAL maps these
to ATS control bits 10 and 11 and preserves them across `ATS_TXN_REQ` and
`ATS_INV_CACHE`. Select the request attributes for the stream and platform;
do not derive them from the desired output TE. SEC_SID DMA control is a
separate parameter.

Program the untranslated input address and transfer size with
`DMA_ATTRIBUTES`, then request translation:

```c
pal_exerciser_set_param(DMA_ATTRIBUTES, input_address, length, bdf);
pal_exerciser_ops(ATS_TXN_REQ, input_address, bdf);
```

Read the translated address and normalized response attributes:

```c
uint64_t translated_address;
uint64_t response_attributes;

pal_exerciser_get_param(ATS_RES_ATTRIBUTES,
                         &translated_address, &response_attributes, bdf);
```

`ATS_TXN_REQ` returns zero when translation status reports success.
`ATS_RES_ATTRIBUTES` returns zero when the result was read; that alone does
not establish a successful or permitted translation. Check completion status,
the returned address, and permissions before using an entry. The endpoint and
its upstream path must have ATS enabled before the request is issued.

| Response field | Normalized bits |
| --- | ---: |
| Execute, Write, Read permissions | 0, 1, 2 |
| Privileged Execute, Write, Read permissions | 3, 4, 5 |
| Global (`VAL_ATS_GLOBAL_MASK`) | 6 |
| Untranslated Access Only | 7 |
| Non-Snooped Access | 8 |
| TE (`VAL_ATS_TE_MASK`) | 9 |

TE and Global are independent; these are the ACS response representation, not
ATS wire-field positions. For the Realm-stream checks, TE distinguishes the
resolved Non-secure output (0) from Realm output (1).

`val_exerciser_ats_translate_by_bdf()` sets request attributes, programs the
input, invalidates the ATC, issues ATS, and reads `VAL_ATS_TRANSLATION_RESULT`.
Its return status describes the interface operation; inspect
`completion_success`, `translated_pa`, `response_attributes`, and `te` for the
translation verdict. A denied translation can be an expected negative result.

Invalidate the exerciser ATC and cached result with:

```c
pal_exerciser_ops(ATS_INV_CACHE, 0, bdf);
```

Subsequent ATC-backed DMA must not reuse an invalidated entry. Program the full
64-bit input with `DMA_ATTRIBUTES` before `ATS_TXN_REQ`; do not rely on the
request trigger alone to initialize both address halves. The current reference
PAL samples ATS/DMA status immediately, so an asynchronous exerciser port must
wait for completion with a bounded timeout before returning.

## Interrupt generation

Generate MSI index `msi_index`:

```c
pal_exerciser_ops(GENERATE_MSI, msi_index, bdf);
```

The PAL must program the MSI index and trigger the interrupt on the selected
endpoint. It must not return success for an index the endpoint cannot generate.

For legacy interrupts:

```c
pal_exerciser_ops(CLEAR_INTR, irq, bdf);
pal_exerciser_ops(GENERATE_L_INTR, irq, bdf);
```

`GENERATE_L_INTR` asserts the interrupt and `CLEAR_INTR` deasserts it.

## Transaction monitoring

Start capture before the transactions under test and stop it afterwards:

```c
pal_exerciser_ops(START_TXN_MONITOR, 0, bdf);
/* Perform the transactions under test. */
pal_exerciser_ops(STOP_TXN_MONITOR, 0, bdf);
```

The reference start/stop operations do not use `param` to select a traffic
class. For correlated address/attribute evidence, read one complete record:

```c
uint64_t attributes;
uint64_t address;

pal_exerciser_get_param(TRANSACTION_RECORD, &attributes, &address, bdf);
```

The flags are `EXERCISER_TXN_ATTR_READ` (bit 1),
`EXERCISER_TXN_ATTR_CONFIG` (bit 2),
`EXERCISER_TXN_ATTR_CACHE_MAINTENANCE` (bit 3), and
`EXERCISER_TXN_ATTR_SNOOP` (bit 4). A different native trace format must be
normalized by PAL. Set SNOOP only for an actual received snoop.

The reference UEFI PAL also provides these legacy queries; each call consumes
a separate record. The reference bare-metal PAL provides `TRANSACTION_RECORD`
instead of these field-specific queries:

| Type | Output |
| --- | --- |
| `CFG_TXN_ATTRIBUTES` | `value1`: native Type bit (bit 0); not the normalized CONFIG bit |
| `TRANSACTION_TYPE` | `value2`: `CFG_READ` or `CFG_WRITE` |
| `ADDRESS_ATTRIBUTES` | `value1`: 64-bit transaction address |
| `DATA_ATTRIBUTES` | `value1`: 64-bit transaction data |

The native reference trace is a destructive stream of five DWORDs per record.
If the platform uses that layout, one logical PAL read must consume one whole
record and return the requested field consistently. An invalid or empty trace
must return failure. The `TRANSACTION_RECORD` path consumes the data DWORDs
too, but returns only the attributes and address.

Use `val_exerciser_get_transaction_record_by_bdf()` or
`val_exerciser_find_transaction_by_bdf()` to inspect a stopped capture. The
latter matches both the exact address and required attributes. An empty trace
alone does not prove filtering; first verify the stimulus and positive capture.

## Error injection

Select the error and whether it is fatal:

```c
pal_exerciser_set_param(ERROR_INJECT_TYPE, error_code, fatal, bdf);
```

Trigger the selected error:

```c
pal_exerciser_ops(INJECT_ERROR, error_code, bdf);
```

These reference calls are exceptions to the usual zero-success convention:
`ERROR_INJECT_TYPE` returns the error class (2 for correctable, 3 for
uncorrectable codes), and `INJECT_ERROR` returns the supplied code. Confirm the
effect through the applicable device or host error status, not these values
alone.

| Error | Code |
| --- | ---: |
| Correctable Receiver Error | `0x00` |
| Correctable Bad TLP | `0x01` |
| Correctable Bad DLLP | `0x02` |
| Correctable Replay Number Rollover | `0x03` |
| Correctable Replay Timer Timeout | `0x04` |
| Correctable Advisory Non-Fatal Error | `0x05` |
| Correctable Internal Error | `0x06` |
| Correctable Header Log Overflow | `0x07` |
| Uncorrectable Data Link Error | `0x08` |
| Uncorrectable Surprise Down Error | `0x09` |
| Uncorrectable Poisoned TLP Received | `0x0A` |
| Uncorrectable Flow Control Error | `0x0B` |
| Uncorrectable Completion Timeout | `0x0C` |
| Uncorrectable Completer Abort | `0x0D` |
| Uncorrectable Unexpected Completion | `0x0E` |
| Uncorrectable Receiver Overflow | `0x0F` |
| Uncorrectable Malformed TLP | `0x10` |
| Uncorrectable ECRC Error | `0x11` |
| Uncorrectable Unsupported Request | `0x12` |
| Uncorrectable ACS Violation | `0x13` |
| Uncorrectable Internal Error | `0x14` |
| Uncorrectable Multicast Blocked TLP | `0x15` |
| Uncorrectable AtomicOp Egress Blocked | `0x16` |
| Uncorrectable TLP Prefix Blocked Egress | `0x17` |
| Uncorrectable Poisoned TLP Egress Blocked | `0x18` |
| Invalid configuration | `0x19` |

The error must be injected by the selected endpoint and reflected in the
architecturally applicable endpoint, Root Port, AER, and IDE state.

## CXL memory and BISNP commands

The following three PAL parameter types and one operation form the CXL command
interface:

| PAL item | Meaning |
| --- | --- |
| `EXERCISER_CXL_CMD_OP` | Select the supported CXL/CDA command |
| `EXERCISER_CXL_CMD_ADDR` | Set the 64-bit address in the domain required by the command |
| `EXERCISER_CXL_CMD_DATA0` | Set or get the 64-bit payload/result |
| `CXL_CMD_START` | Trigger the selected command and wait for completion |

The command values and address domains are listed in
[CDA stimulus contracts](#cda-stimulus-contracts). These are the logical PAL
values; a PAL translating to another native interface must preserve their
meaning.

The CXL command interface uses one combined register at BAR0 offset `0x80`:

| Field | Bits |
| --- | ---: |
| Opcode | `[3:0]` |
| Status | `[11:8]` |
| Clear error | `30` |
| Trigger | `31` |

The 64-bit command address is held at offsets `0x84` and `0x88`, and the
64-bit data or result is held at offsets `0x8C` and `0x90`. Starting a command
sets bit `31` in the same register as the opcode. The exerciser clears the
trigger after handling the write and reports completion or failure in bits
`[11:8]`.

### CXL backdoor read

```c
uint64_t data;
uint64_t unused;

pal_exerciser_set_param(EXERCISER_CXL_CMD_OP,
                         CXL_CMD_OP_BACKDOOR_READ64, 0, bdf);
pal_exerciser_set_param(EXERCISER_CXL_CMD_ADDR, dpa, 0, bdf);
pal_exerciser_ops(CXL_CMD_START, 0, bdf);
pal_exerciser_get_param(EXERCISER_CXL_CMD_DATA0,
                         &data, &unused, bdf);
```

### CXL backdoor write

```c
pal_exerciser_set_param(EXERCISER_CXL_CMD_OP,
                         CXL_CMD_OP_BACKDOOR_WRITE64, 0, bdf);
pal_exerciser_set_param(EXERCISER_CXL_CMD_ADDR, dpa, 0, bdf);
pal_exerciser_set_param(EXERCISER_CXL_CMD_DATA0, data, 0, bdf);
pal_exerciser_ops(CXL_CMD_START, 0, bdf);
```

### CXL BISNP

```c
pal_exerciser_set_param(EXERCISER_CXL_CMD_OP,
                         CXL_CMD_OP_BISNP, 0, bdf);
pal_exerciser_set_param(EXERCISER_CXL_CMD_ADDR, hpa, 0, bdf);
pal_exerciser_ops(CXL_CMD_START, 0, bdf);
```

`CXL_CMD_START` must trigger the command, poll or wait for completion, and
return failure on command error or timeout. If the native command status
contains a stale error, clear it before triggering the new command as required
by the device ABI.

Backdoor read and write use the debug device-media path with DPA input.
`BISNP` requests the upstream snoop operation exposed by the coherent endpoint;
its protocol, PAS attribution, and completion evidence must match the scenario.

### CDA stimulus contracts

The CXL command interface also carries the coherent-device stimuli used by
CDA tests. Command support and native register layouts are platform-specific.
The logical commands are defined in
[`val/include/pal_interface.h`](../val/include/pal_interface.h):

| Command | Value | Address | Required role |
| --- | ---: | --- | --- |
| `CXL_CMD_OP_BACKDOOR_READ64` | `0x1` | DPA | Read device media independently of the normal coherent access under test. |
| `CXL_CMD_OP_BACKDOOR_WRITE64` | `0x2` | DPA | Seed device media independently of the normal coherent access under test. |
| `CXL_CMD_OP_BISNP` | `0x3` | HPA | Request the upstream snoop operation exposed by the exerciser. |
| `CXL_CMD_OP_DCM_CACHE_DIRTY` | `0x4` | HPA | Prepare dirty device-cache state for an existing populated Realm line. |
| `CXL_CMD_OP_DCM_SET_REALM_ASSIGNMENT` | `0x6` | HPA | Establish or clear a device-side Realm association for the DCM Location. This does not configure host GPT ownership. |
| `CXL_CMD_OP_DCM_CACHE_WRITEBACK` | `0x8` | HPA | Write back the specified device cache line through the coherent path for host-visible observation. |
| `CXL_CMD_OP_SNOOP_RESPONSE_MECID` | `0x9` | Unused; pass zero | Enable or clear a response-MECID override for permitted and unpermitted snoop-response tests. |

Backdoor operations take a device physical address (DPA); DCM assignment,
cache-state, writeback, and snoop operations take a host physical address
(HPA). `val_cxl_hpa_to_dpa()` derives the DPA from a supported endpoint HDM
decoder configuration. Do not assume HPA and DPA are identical or substitute
a backdoor operation for the normal transaction being checked.

`DCM_SET_REALM_ASSIGNMENT` takes `DATA0=1` to associate the selected DCM
Location with Realm and `DATA0=0` to clear that association. Host GPT state,
SMMU mappings, and TDISP/IDE setup remain separate. `DCM_CACHE_DIRTY` operates
on an already populated line; the current tests pass zero in `DATA0`.
`DCM_CACHE_WRITEBACK` also takes zero in `DATA0` and must exercise device-cache
writeback rather than perform a direct-media write. A failed command must not
be reported as successful merely because it is a negative-test stimulus.

The snoop stimulus must have the protocol meaning and completion evidence
required by the scenario. The command name alone is not proof of CHI SNP
channel coverage. `pal_cda_tdi_snoop_attempt()` supplies the selected HPA and
PAS and returns normalized emission, local-blocking, and host-completion
evidence to VAL. Result flags such as `CXL_SNOOP_RESULT_HOST_ACCEPTED` and
`CXL_SNOOP_RESULT_HOST_REJECTED` are PAL observations, not architectural
host-port register bits. Derive them from actual exerciser or coherent-response
evidence; a status-only interface may not expose every distinction.

The result must contain VALID and exactly one of EMITTED or BLOCKED. An emitted
request may additionally report HOST_ACCEPTED or HOST_REJECTED, but not both;
a locally blocked request cannot carry a host-response flag. The reference
PAL selects Realm when `pas_realm` is nonzero, or Non-secure when it is zero,
and releases the SEC_SID override after the attempt. A successful helper call
means an observation is available, not that the requested access was permitted.

The reference PAL treats a successful BISnp command with zero `DATA0` as
`VALID | EMITTED | HOST_ACCEPTED`: this command completes successfully only
after its upstream transaction succeeds. Explicit nonzero result flags remain
subject to VAL validation. `DATA0` is cleared before each attempt to discard
stale results. An error or timeout is not proof of local blocking or host
rejection; tests skip an observation they cannot establish rather than count
it as a successful negative check.

For the response-MECID override, `DATA0[15:0]` selects the MECID and
`DATA0[16]` enables the override. Clear the enable bit during cleanup.
`val_cxl_exerciser_set_snoop_response_mecid()` packages this control for tests.

These interfaces describe endpoint capabilities. They do not require private
host-port acceptance bits or a host-port monitoring backdoor. Unsupported
commands and missing observations must not return fabricated success.
Command completion alone is not the compliance verdict: the test evaluates
the resulting data, response, exception, or fresh error status as appropriate.

### Realm cache-line setup

`val_cda_populate_realm_device_cache_line()` uses the seed helper below, obtains
an ATS-derived Realm translation, and reads DCM into the exerciser with
ATC-backed DMA. It then obtains a translation for a host verification buffer,
returns the captured data through DMA, and compares it with the seed. This
requires prepared SMMU mappings, GPT/DPT state, TDI RUN, IDE, and ATS support;
it does not inspect an internal device buffer.

`val_cda_seed_realm_cache_line()` initializes backing DCM through a
non-cacheable Realm alias, verifies a cacheable read, then evicts the executing
PE's copies with local set/way maintenance. The helper is for single-PE test
setup with other PEs quiescent. It does not invalidate system or device caches.
Address-based invalidation to PoC is unsuitable here because it can remove the
device line that the test needs to retain. `DCM_CACHE_DIRTY` must still reject
a missing line; data returned by DMA alone does not prove cache residency.

The EL3 implementation reuses TF-A's cache-geometry-aware `dcsw_op_all()`
routine. Rebuild and package the ACS EL3 payload together with the ACS
application when adding this cache-maintenance operation.

### Host snoop eligibility and observation

`pal_cda_host_snoop_prepare(root_bdf, endpoint_bdf, permitted_hpa, unknown_hpa)`
must save platform state and verify eligibility for a positive Realm snoop,
and the absence of all forwarding conditions for the unknown Realm target.
It must also establish a supported stimulus and an endpoint monitor that can
distinguish received snoops from memory requests and cache maintenance.

`pal_cda_host_snoop_trigger(endpoint_bdf, target_hpa)` initiates a genuine
host snoop candidate without altering that eligibility. Success means the
forwarding decision and monitor observation have completed, including when
the host suppresses the candidate. It is not a verdict on host compliance.

Use `PAL_CDA_SNOOP_SUCCESS`, `PAL_CDA_SNOOP_UNSUPPORTED`, or
`PAL_CDA_SNOOP_ERROR` for setup and trigger results. Restore saved state with
`pal_cda_host_snoop_restore(endpoint_bdf)` after every setup attempt, including
failure or unsupported results; restoration returns success only when state
is restored or no state was changed.

Only actual received host-to-device snoops may set
`EXERCISER_TXN_ATTR_SNOOP` in normalized transaction records. This logical PAL
flag is not a requirement for an architectural host-port register or a native
exerciser register encoding. Do not derive it from the read or CMO bit alone.
The default PAL leaves state unchanged and reports setup/trigger unsupported.

## CHI-C2C SEC_SID

Set the security attribute for subsequent CHI-C2C DMA:

```c
pal_exerciser_set_param(EXERCISER_SEC_SID, sec_sid, 0, bdf);
```

RME System ACS uses:

| `sec_sid` | Request PAS |
| ---: | --- |
| `0b00` | Non-secure |
| `0b10` | Realm |

The PAL argument is the logical `SEC_SID`, not a raw control-register value.
The register at BAR0 offset `0x94` is writable only for CHI-C2C exercisers.
Bit `0` is reserved, bit `1` supplies `SEC_SID_BIT_1`, and bit `31` enables
its propagation on subsequent DMA requests. The register value is:

```c
(1u << 31) | (sec_sid & (1u << 1))
```

The programmed value applies to subsequent CHI-C2C DMA until changed or
reset. A PAL must report failure if SEC_SID control is requested for an
endpoint that does not support it.

To release the override and restore the exerciser's default SEC_SID selection,
pass `EXERCISER_SEC_SID_DEFAULT` as `sec_sid`. The reference PAL clears the
register, including its valid bit. This differs from programming `0b00`,
which explicitly selects Non-secure while leaving the override enabled.

## License

Arm RME System ACS is distributed under the Apache License 2.0. See
[`LICENSE.md`](../LICENSE.md) for the full license text.

* * *

Copyright (c) 2026, Arm Limited or its affiliates. All rights reserved.
