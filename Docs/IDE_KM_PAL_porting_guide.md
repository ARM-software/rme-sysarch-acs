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

`pal_pcie_rp_ide_cfg_address()` must resolve the configuration address without
reading MMIO. EL3 maps that address before calling
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

Implement the CXL.cachemem backend in
`pal_el3/<platform>/src/pal_cxl_ide.c`, alongside `pal_pcie_ide.c`.
The PAL uses the same discovery, PROGRAM, GO and STOP structure as PCIe, with
CXL-specific selectors and register regions declared in
[`pal_el3_cxl_ide.h`](../pal_el3/include/pal_el3_cxl_ide.h).
Entry points are declared in each platform's `pal_el3.h`; EL3 VAL declarations
are in [`val_el3_cxl_ide.h`](../val_el3/include/val_el3_cxl_ide.h).

### Responsibilities and request flow

```text
Host CXL VAL -> val_cxl_root_port_ide_*_el3()
             -> EL3_CXL_IDE_KM SMC
             -> val_el3_ide_km_*()
             -> pal_cxl_rp_ide_cfg_address()
             -> pal_cxl_rp_ide_km_address()
             -> pal_cxl_rp_ide_key_program() / key_go() / key_stop()
```

Host VAL supplies the segment ECAM base and packed Root Port Requester ID.
EL3 asks PAL to resolve the configuration address, maps it in Root PAS, then
asks PAL to discover the AES and CXL.CM pages. EL3 maps those pages as
Device-nGnRnE, read/write, GPT_ANY; a shared AES/CM page is mapped once.
Host VAL maps RX/TX key buffers for EL3 access before PROGRAM.
Platforms with fixed register apertures resolve them in PAL without VAL macros.
Discovery runs before each PROGRAM, GO and STOP. Initialize both register-region
outputs on success. Return zero only for regions the backend does not access.
As with PCIe, bases do not describe aperture lengths: each accessed register
must lie in a mapped granule, or EL3 mapping must be extended accordingly.

PROGRAM, GO and STOP are separate operations. RP PROGRAM completes before
either endpoint KEY_SET_GO. Both endpoint KEY_SET_GO operations complete before
RP GO. A failed PROGRAM must not invoke GO. Failures from the RP PROGRAM attempt
onward trigger best-effort STOP at both endpoint directions and the RP, while
preserving the original establishment result. STOP must handle partially
programmed or already inactive banks. Teardown attempts all three STOPs before
returning the first failure; after successful STOPs, VAL verifies both ports are
Insecure. Use bounded hardware completion polling in each PAL operation.

### EL3 service arguments

| Field | CXL service meaning |
| --- | --- |
| `shared_data->arg0` | `IDE_CXL_KEY_PROG`, `IDE_CXL_KEY_GO`, or `IDE_CXL_KEY_STOP`. |
| `shared_data->arg1` | Packed Root Port Requester ID. |
| `shared_data->arg2` | Segment ECAM base. |
| `shared_data->arg3` | Stream ID. |
| `shared_data->arg4` | Paired key-bank slot. |
| `shared_data->arg5` | Address of the RP RX key buffer for PROGRAM; IDE mode for GO (0 = Skid, 1 = Containment). |
| `shared_data->arg6` | Address of the RP TX key buffer for PROGRAM. |

### PAL entry points

| API | Implementation responsibility |
| --- | --- |
| `pal_cxl_rp_ide_cfg_address(ecam_base, rp_id, config)` | Resolve configuration address without MMIO access. |
| `pal_cxl_rp_ide_km_address(config, registers)` | Discover AES and CXL.CM pages after EL3 maps configuration space. |
| `pal_cxl_rp_ide_key_program(registers, selector, rx_key, tx_key)` | Load both RP directions and complete RX preparation for incoming IDE.START, without starting RP TX. |
| `pal_cxl_rp_ide_key_go(registers, selector, mode)` | Apply the requested mode, then activate the selected bank after the endpoint is armed. |
| `pal_cxl_rp_ide_key_stop(registers, selector)` | Stop the selected stream/key bank and verify completion. |

`CXL_IDE_SELECTOR` contains eight-bit `stream_id` and `key_slot` fields; current
establishment uses stream 0 and slot 0.
`CXL_IDE_RP_REGISTERS` contains `aes` and `cm_host`; these can name the same page
or separate pages. `CXL_IDE_KEY_BUFFER` contains `key[8]` and `iv[3]`, both arrays
of 32-bit words. RX/TX directions are relative to the RP: endpoint TX feeds RP
RX, and endpoint RX consumes RP TX. The paired programming API reflects this
CXL flow; PCIe PR/NPR/Completion substream selectors do not apply.

Establishment programs endpoint RX/TX and then RP RX/TX before issuing any GO.
Successful RP PROGRAM must leave its receiver ready to accept the endpoint's
IDE.START; complete any platform-specific RX arming in that operation. Endpoint
RX GO and TX GO then complete before RP GO starts the RP transmitter. A backend
must not defer RX readiness until the paired RP GO operation.

The FVP backend retains its synthetic BAR-relative page. It writes key words
and does not consume `iv`, because this synthetic interface has no IV
registers. A hardware backend must implement its required key/IV representation,
bank selection, completion polling and MMIO/barrier rules. Do not retain
key-buffer pointers or print key material.

The RD-V3 backend provides empty placeholders, like its PCIe IDE backend.
Every CXL entry point returns `CXL_IDE_UNSUPPORTED` without accessing registers
or writing output arguments. A platform implementation is required.

CXL PAL operations return `CXL_IDE_SUCCESS` (zero), `CXL_IDE_ERROR` (one), or
`CXL_IDE_UNSUPPORTED` (two). The current CXL SMC interface treats nonzero PAL
status as failure; it does not yet propagate unsupported as a Host SKIP.
The CXL SMC handler returns operation status in `shared_data->status_code`.
PROGRAM and STOP failures also populate `shared_data->error_msg`; the Host GO
wrapper prints its own failure message.

Implement all five PAL entry points listed above.

The EL3 Makefile collects all platform `src/*.c` files, so the dedicated CXL
source is included automatically.
