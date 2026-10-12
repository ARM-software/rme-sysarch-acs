# IDE-KM PAL porting guide

This guide describes the ACS Root Port (RP) interfaces for PCIe and CXL IDE key
management. Host VAL handles endpoint protocol messages over secured SPDM;
EL3 PAL performs platform-specific RP programming. Obtain register definitions
and programming rules from the platform provider. A backend does not need to
reproduce another platform's register layout.

PCIe and CXL currently use separate Host VAL, EL3 service, and PAL interfaces.
Implement the interface for the protocol being tested. Keep platform discovery,
MMIO access, hardware completion checks, and error handling inside `pal_el3`.
Do not call Host `pal/` from EL3 or introduce dependencies on Host VAL
implementation code. Use configured include directories for shared headers.

## PCIe

Implement the PCIe backend in `pal_el3/<platform>/src/pal_pcie_ide.c`.

### Responsibilities and request flow

Host VAL establishes secured SPDM with the endpoint and exchanges endpoint
PCIe IDE-KM messages. RP key programming uses the platform implementation
through EL3:

```text
Test -> val_pcie_ide_establish_streams()
     -> val_pcie_rp_ide_key_program/go/stop()
     -> EL3_PCIE_IDE_KM SMC
     -> val_el3_pcie_ide_km_handle()
     -> pal_pcie_rp_ide_*()
```

Host VAL maps the request descriptor for EL3 access. The SMC service takes the
operation in `shared_data->arg0` and the descriptor address in
`shared_data->arg1`. EL3 copies and validates the descriptor, discovers and maps
the RP registers, dispatches the operation, and erases its local key copy.
Status is returned through `shared_data->status_code`.

PAL owns platform register discovery, key-slot selection, MMIO access,
completion polling, and hardware error handling. Keep these operations in
`pal_el3`; do not call Host `pal/` or depend on Host VAL implementation code.
PAL types are declared in
[`pal_el3_pcie_ide.h`](../pal_el3/include/pal_el3_pcie_ide.h).
The EL3 request descriptor is declared in
[`val_el3_pcie_ide.h`](../val_el3/include/val_el3_pcie_ide.h).

### Information supplied to PAL

| Field | ACS meaning |
| --- | --- |
| `ecam_base` | ECAM base for the RP's segment. |
| `rp_id` | Packed PCI RID: bus in bits 15:8, device in 7:3, function in 2:0. |
| `selector.stream_id` | Eight-bit Stream ID; not the Selective IDE block index. |
| `selector.key_set` | Key set 0 or 1. Current establishment selects set 0. |
| `selector.sub_stream` | 0 = Posted, 1 = Non-Posted, 2 = Completion. |
| `selector.direction` | `PCIE_IDE_RX` or `PCIE_IDE_TX`, relative to the RP. |
| `key.key[8]` | Eight 32-bit words of AES-256 key material. |
| `key.initial_ifv` | Initial invocation field, represented as a 64-bit value. |

Translate this representation into the platform's key word order, byte order,
IV encoding, and slot selection. RP RX receives the matching endpoint TX key;
RP TX receives the matching endpoint RX key. Host VAL currently forms
`initial_ifv` from endpoint IV words 0 and 1, with word 0 in the low 32 bits.
The current descriptor carries no additional platform-specific IV fields.

If hardware selects a Selective IDE register block rather than a Stream ID,
resolve the supplied Stream ID against that RP's configured blocks. Tests can
use EP block 1 with RP block 2; do not assume matching block numbers or always
select RP block 1.

### PAL entry points

| API | Implementation responsibility |
| --- | --- |
| `pal_pcie_rp_ide_cfg_address(ecam_base, rp_id, config)` | Validate the RP identity and return the configuration address needed for discovery. For conventional ECAM, the address is `ecam_base + ((uint64_t)rp_id << 12)`; check bounds and overflow. |
| `pal_pcie_rp_ide_km_address(config, registers)` | Discover the backend from RP configuration space or platform data, validate availability, and initialize all register-region outputs. |
| `pal_pcie_rp_ide_key_program(registers, selector, key)` | Program the selected key and invocation field. Follow hardware staging and completion rules; do not activate the transmitter here. |
| `pal_pcie_rp_ide_key_go(registers, selector)` | Activate the selected receive or transmit key set and wait for the platform's completion condition. |
| `pal_pcie_rp_ide_key_stop(registers, selector)` | Stop/invalidate the selected key set using the platform's defined mechanism. Handle cleanup after partial programming as well as a fully established stream. |

PROGRAM and GO must return success only after the requested platform operation
has completed. Use bounded polling for busy/completion registers. STOP should
tolerate an already inactive key set because cleanup can follow partial setup.
Do not silently substitute one substream, direction, or key set for another.

The current Host setup enables the EP and RP streams after key programming,
activates receivers at both ports before transmitters, and then polls both
ports for Secure. PAL must preserve this sequencing. Stream configuration,
RID/address associations, TDISP operations, and Secure polling remain VAL work.
STOP is used during teardown through `val_device_unlock()` and during failed
establishment; it is not an optional backend operation.

### Register mapping and memory access

EL3 maps the configuration address before calling
`pal_pcie_rp_ide_km_address()`. It then maps the nonzero `registers->keys` and
`registers->control` addresses before PROGRAM, GO, or STOP. Mappings are identity
mappings with Root PAS, Device-nGnRnE attributes, and read/write permission;
the mapping helper also requests `GPT_ANY` for the address.

`registers->config` is available to PAL but is not separately mapped by the
current dispatcher. Keep it within the already mapped configuration region or
extend the mapping implementation when introducing a different region.
Discovery must not read key/control MMIO before those regions are mapped.

The current interface supplies addresses, not aperture lengths. Check that
every accessed register lies within the mapped translation granules. A backend
spanning additional granules needs corresponding EL3 mappings; returning a
base address alone does not map the entire aperture. Platform firmware must
also permit the intended Root accesses through its memory and bus protection.

Use platform MMIO accessors and the barriers/readbacks required by the hardware.
Do not cache request pointers or retain temporary key copies. Do not print keys
or invocation fields in diagnostics.

### Return values

| PAL status | Host result |
| --- | --- |
| `PCIE_IDE_SUCCESS` | `ACS_STATUS_PASS`; setup continues. |
| `PCIE_IDE_ERROR` | `ACS_STATUS_ERR`; setup fails. |
| `PCIE_IDE_UNSUPPORTED` | `ACS_STATUS_SKIP`; setup callers report unsupported. |
| `PCIE_IDE_BUSY` | Currently treated as an error; Host VAL does not retry. |

## CXL

The existing CXL RP APIs are declared in each platform's `pal_el3.h` and
implemented in `pal_el3/<platform>/src/pal_el3.c`. This section documents the
current interface; it does not require moving CXL to the PCIe request model.

### Responsibilities and request flow

```text
Host CXL VAL -> val_cxl_root_port_ide_*_el3()
             -> EL3_IDE_KM SMC
             -> val_el3_ide_km_*()
             -> pal_cxl_root_port_ide_*()
```

Host VAL obtains the RP BAR0 address and queries the key-management base through
EL3. It maps that register region with Root PAS, Device-nGnRnE attributes,
read/write permission, and GPT_ANY. For programming, Host VAL also maps the RX
and TX key buffers for EL3 access. Unlike PCIe discovery, this mapping is
arranged by Host VAL before the programming call.

The existing Host helper assumes a 4 KiB key-management register region. Check
that this covers the ported backend; extend the mapping if its registers span
additional translation granules.

### EL3 service arguments

| Field | Current CXL service meaning |
| --- | --- |
| `shared_data->arg0` | `IDE_GET_BASE`, `IDE_ENABLE`, or `IDE_DISABLE`. |
| `shared_data->arg2` | RP BAR0 base; GET_BASE returns the key-management base here. |
| `shared_data->arg3` | Stream ID for ENABLE and DISABLE. |
| `shared_data->arg4` | Platform key-slot selector for ENABLE and DISABLE. |
| `shared_data->arg5` | Address of the RP RX key buffer for ENABLE. |
| `shared_data->arg6` | Address of the RP TX key buffer for ENABLE. |

`CXL_IDE_KEY_BUFFER` contains `key[8]` and `iv[3]`, both arrays of 32-bit words.
The RX/TX names are relative to the RP: endpoint TX feeds RP RX, and endpoint RX
consumes RP TX. Interpret key/IV representation and slot selection according to
the platform backend. The reference programming function currently writes the
key words, but does not consume the supplied `iv` array; port IV programming
explicitly where the hardware requires it.

### PAL entry points

| API | Implementation responsibility |
| --- | --- |
| `pal_cxl_root_port_ide_get_km_base(bar0_base, ide_km_base)` | Discover and return the RP key-management register base. This query precedes register mapping; do not rely on unmapped key-management MMIO during discovery. |
| `pal_cxl_root_port_ide_program_and_enable(bar0_base, stream_id, key_slot, rx_key, tx_key)` | Resolve the selected stream/slot, program both RP directions, and activate the RP according to its backend rules. Programming and activation are combined in this interface. |
| `pal_cxl_root_port_ide_disable(bar0_base, stream_id, key_slot)` | Stop the selected RP stream/slot and verify completion. |

These APIs return zero for success and nonzero for failure. The current CXL SMC
handler reports PAL failures through `shared_data->status_code` and
`shared_data->error_msg`; it does not use the PCIe unsupported-to-SKIP mapping.

Support the supplied stream and slot selectors, or reject unsupported values
explicitly. The reference disable function does not use those selectors, so
check their handling when porting to a backend with multiple streams or slots.
Use bounded completion polling and platform MMIO access/barrier rules. Do not
retain key-buffer pointers or print key material.

Do not assume PCIe PR/NPR/Completion selectors or separate RP PROGRAM/GO/STOP
operations apply to the CXL API. Any future interface migration should update
Host VAL and EL3 together; the existing CXL path remains separate.
