<!-- SPDX-FileCopyrightText: 2026 André Fiedler -->
<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->

# Serial utility protocol

`openrdx-serial` is a separate macOS native command for inspecting, preparing, and applying a dock manufacturing serial change. There is no GUI action for this operation. The utility preserves leading zeroes and selects an exact USB serial, vendor `1a5a`, product `0005`, and nonzero USB location. Ambiguous selection fails.

Serial mutation requires the dedicated OpenRDX 1.09 receiver protocol. OpenRDX 1.08 rejects its non-mutating capability probe, so the utility cannot change a serial on 1.08. Building this utility does not install firmware. Hardware serial writes and USB re-enumeration through this new utility have not been verified on a physical dock.

For command syntax, private plan storage and recovery ordering, see [serial utility development](../development/serial-utility.md). For operation steps, use the [operator guide](../serial-utility.md).

## Receiver protocol

The closed native operations are independently validated in Rust, worker framing, and C:

| Operation                 | Request                                                | Transfer           |
| ------------------------- | ------------------------------------------------------ | ------------------ |
| 29: sector chunk          | `E7 00 03 <E0 + index/2> <00 or 80> 80`; index `0..31` | 128 bytes inbound  |
| 30: capability            | `3B 02 53 00 00 01 00 00 00 00`                        | None; no mutation  |
| 31: set serial            | `3B 02 53 00 00 00 00 01 18 00`                        | 280 bytes outbound |
| 32: mechanism diagnostics | `E8 00 00 00 00 80`                                    | 128 bytes inbound  |

The existing fixed manufacturing-record operations 26 and 27 remain unchanged. Sector and mechanism reads require an admitted BOT transport.

The set-serial payload contains:

| Bytes  | Meaning                                                                      |
| ------ | ---------------------------------------------------------------------------- |
| 0–7    | ASCII `RDXSER01`                                                             |
| 8–11   | Little-endian CRC-32/IEEE of the expected original complete 4096-byte sector |
| 12     | `0` for a valid record, `1` only to reconstruct an entirely erased record    |
| 13     | Reserved zero                                                                |
| 14–23  | Ten ASCII unit-serial digits                                                 |
| 24–279 | Exact expected original 256-byte manufacturing record                        |

The receiver compares the raw expected record and whole-sector CRC, checks the empty physical bay independently, rejects partially corrupt records, patches only allowed identity fields, and verifies the complete sector readback. It does not reboot automatically. The host then performs its own exact whole-sector comparison before reset.

Source contracts: `src/serial_record.rs` contains checksum, reconstruction, CRC, and expected-sector logic; `src/serial_cli/flow.rs` contains ordering and physical-bay validation; `macos-native/src/serial_contract.rs` and `native/macos/rdx_serial_contract.inc` validate payloads independently. The receiver implementation is `src/rdx_mount/rdx_manager_serial.c` in the firmware repository; physical diagnostics originate in `rdx_mechanism_read_diagnostics()` in its `rdx_mechanism.c`.

## Validation scope

Deterministic tests cover leading-zero decimal handling, strict command grammar, full-sector input, valid/erased/corrupt states, CRC-32's standard vector, plan roundtrips, stale sectors, wrong serial/location, modified checksums and CRCs, old-firmware capability rejection with zero mutations, GPIO5 presence independent of GPIO2 CAM state, nonidle mechanisms, durable/no-overwrite files, no-symlink reads, and exact full-sector readback. Native tests inspect exact CDBs and reject out-of-range indices, offsets, modes, record flags, and malformed payloads without opening hardware.

These are host and protocol tests, not evidence of a completed hardware serial change.
