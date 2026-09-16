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
Before the first transaction, ACS enables PCI Memory Space and Bus Mastering.
The platform must assign usable control and data BARs.

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

### Address type

```c
pal_exerciser_set_param(CFG_TXN_ATTRIBUTES,
                         TXN_ADDR_TYPE, address_type, bdf);
```

`address_type` is stored in bits `[11:10]` of the DMA Control register:

- `0x0`: Default, treated as Untranslated
- `0x1`: Untranslated
- `0x2`: Translated
- `0x3`: Reserved

If the value is Reserved, the exerciser reports a DMA error and clears the
field.

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

Program the untranslated input address and transfer size with
`DMA_ATTRIBUTES`, then request translation:

```c
pal_exerciser_set_param(DMA_ATTRIBUTES, input_address, length, bdf);
pal_exerciser_ops(ATS_TXN_REQ, input_address, bdf);
```

Read the translated address:

```c
uint64_t translated_address;
uint64_t implementation_data;

pal_exerciser_get_param(ATS_RES_ATTRIBUTES,
                         &translated_address, &implementation_data, bdf);
```

The operation succeeds only when the ATS response indicates successful
translation. The endpoint and its upstream path must have ATS enabled before
the request is issued.

Invalidate the exerciser ATC and cached result with:

```c
pal_exerciser_ops(ATS_INV_CACHE, 0, bdf);
```

When subsequent DMA uses `AT_TRANSLATED`, the PAL and endpoint must preserve
the intended translated-address behavior and must not reuse an invalidated ATC
entry.

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
pal_exerciser_ops(START_TXN_MONITOR, transaction_class, bdf);
/* Perform the transactions under test. */
pal_exerciser_ops(STOP_TXN_MONITOR, transaction_class, bdf);
```

Read the captured record with `pal_exerciser_get_param()`:

| Type | Returned value |
| --- | --- |
| `CFG_TXN_ATTRIBUTES` | Configuration or Memory classification |
| `TRANSACTION_TYPE` | Read or Write classification |
| `ADDRESS_ATTRIBUTES` | 64-bit transaction address |
| `DATA_ATTRIBUTES` | 64-bit transaction data |

The native reference trace is a destructive stream of five DWORDs per record.
If the platform uses that layout, one logical PAL read must consume one whole
record and return the requested field consistently. An invalid or empty trace
must return failure.

## Error injection

Select the error and whether it is fatal:

```c
pal_exerciser_set_param(ERROR_INJECT_TYPE, error_code, fatal, bdf);
```

Trigger the selected error:

```c
pal_exerciser_ops(INJECT_ERROR, error_code, bdf);
```

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
| `EXERCISER_CXL_CMD_OP` | Select `BACKDOOR_READ64`, `BACKDOOR_WRITE64`, or `BISNP` |
| `EXERCISER_CXL_CMD_ADDR` | Set the 64-bit CXL physical address |
| `EXERCISER_CXL_CMD_DATA0` | Set or get the 64-bit payload/result |
| `CXL_CMD_START` | Trigger the selected command and wait for completion |

The opcode values are:

| Opcode | Value |
| --- | ---: |
| `CXL_CMD_OP_BACKDOOR_READ64` | `0x1` |
| `CXL_CMD_OP_BACKDOOR_WRITE64` | `0x2` |
| `CXL_CMD_OP_BISNP` | `0x3` |

The PAL API uses these values. A PAL translating to a different native
interface must retain them.

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
pal_exerciser_set_param(EXERCISER_CXL_CMD_ADDR, address, 0, bdf);
pal_exerciser_ops(CXL_CMD_START, 0, bdf);
pal_exerciser_get_param(EXERCISER_CXL_CMD_DATA0,
                         &data, &unused, bdf);
```

### CXL backdoor write

```c
pal_exerciser_set_param(EXERCISER_CXL_CMD_OP,
                         CXL_CMD_OP_BACKDOOR_WRITE64, 0, bdf);
pal_exerciser_set_param(EXERCISER_CXL_CMD_ADDR, address, 0, bdf);
pal_exerciser_set_param(EXERCISER_CXL_CMD_DATA0, data, 0, bdf);
pal_exerciser_ops(CXL_CMD_START, 0, bdf);
```

### CXL BISNP

```c
pal_exerciser_set_param(EXERCISER_CXL_CMD_OP,
                         CXL_CMD_OP_BISNP, 0, bdf);
pal_exerciser_set_param(EXERCISER_CXL_CMD_ADDR, address, 0, bdf);
pal_exerciser_ops(CXL_CMD_START, 0, bdf);
```

`CXL_CMD_START` must trigger the command, poll or wait for completion, and
return failure on command error or timeout. If the native command status
contains a stale error, clear it before triggering the new command as required
by the device ABI.

Backdoor read and write must use the debug CXL memory path. `BISNP` must
generate the upstream CXL Back-Invalidate stimulus; replacing it with a
backdoor memory operation is not equivalent.

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

## License

Arm RME System ACS is distributed under the Apache License 2.0. See
[`LICENSE.md`](../LICENSE.md) for the full license text.

* * *

Copyright (c) 2026, Arm Limited or its affiliates. All rights reserved.
