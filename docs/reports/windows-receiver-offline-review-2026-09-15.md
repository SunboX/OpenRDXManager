<!-- SPDX-FileCopyrightText: 2026 André Fiedler -->
<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->

# Windows receiver offline review — 2026-09-15

Historical report. Results and limitations apply to the described host, device and date; subsequent reports may supersede them.

Result: **27 host-only checks passed**, including the expected complete 1.10
container transfer and authentication. This narrows the investigation but does
not diagnose the physical dock's `firmware-command-invalid` error or verify an
update. No application protocol, receiver source or release image was changed.
No device command, reset, firmware write or new USB capture was initiated.

## Evidence and method

The preceding [USB capture results](windows-usb-trace-result-2026-09-15.md) recovered
no command bytes. This pass instead reviewed the adjacent `../../../OpenRDX` source
at commit `01cc3814664bb6fdbe72ecfd1e9dd3dd52a48e9c`. The inspected receiver, USB
and header files and `dist/OpenRDX-v1-10.bin` have no scoped Git changes.
The immutable 62,110-byte container has SHA-256
`4570b50ad44ef88bb45e239ee1a5866fdee2d85a3be30f6da57afd1e8228975a`.
Neither artifact identity nor the dock's reported revision proves that its
installed flash contains those exact bytes.

New analysis tools:

- `analysis/scripts/review_receiver_offline.mjs` extracts actual receiver SHA-256,
  download, authentication, activation, SCSI dispatch and buffer-routing code.
- `analysis/scripts/receiver_offline_fixture.c` supplies RAM-only flash operations,
  injected mutation latches and a finite assertion matrix. Manufacturing/serial
  writes are stub-rejected; there is no USB, SPTI or device-opening API.

The generator changes only the extracted SCSI wrapper's `inline` linkage to
`static` for the host compiler. Target scalar types are represented with fixed
width host types, and the two mocked receive allocation capacities are 4,096 and
0x1014 bytes. The mock is not the target DMA layout. Invalid-length tests inject
wrapper fields and bound the fixture copy; they do not emulate an oversized USB
receive. SPI operations update process memory and counters, not real flash.

MSVC 14.40.33807 compiled the final 841-line generated C file with C11,
`/W3 /WX`, and exited 0. The simulation also exited 0. This is an x64 host
simulation on Windows ARM64, not a TI firmware build or a replacement target ABI.
It does not execute the USB state machine, emulate timing/interrupt concurrency,
exercise Windows storage drivers or prove hardware flash behavior.

## Expected host sequence versus receiver checks

Manager references: `native/rdx-service/src/firmware.rs:43` and `:332` define
4,096-byte sequential chunks; `src/protocol/cdb.rs:493` within that crate constructs
the ten-byte command. The Windows companion encoder in
`native/rdx-service/windows-native/src/lib.rs` independently uses the same shape.
Its `src/native.rs:716` and `:723` supply the request CDB length and actual data
length to SPTI. These are source observations, not captured outgoing commands.

The fixture reconstructs that reviewed shape; it does not execute the Rust
encoders. For this container, there are fifteen 4,096-byte chunks and one
670-byte chunk at offset 61,440. The initial CDB is
`3B 04 00 00 00 00 00 10 00 00`: mode 4, buffer zero, offset zero, length 4,096,
control zero. Nominal completion uses mode 5, offset 62,110 and no payload.

Receiver references below are relative to `../../../OpenRDX`.

| Check or failure class                         | Source boundary                            | Offline result                                                                                         |
| ---------------------------------------------- | ------------------------------------------ | ------------------------------------------------------------------------------------------------------ |
| Command length must be ten bytes               | `src/rdx_mount/scsi.c:2635`                | Injected 12- and 16-byte lengths rejected before mock SPI                                              |
| Reserved fields, buffer ID and received length | `src/rdx_mount/rdx_manager_protocol.c:822` | Reserved bits, buffer 1, control 1 and short completed length rejected                                 |
| Manufacturing or serial mutation interlock     | Same handler, lines 845 and 870            | Each injected latch rejects before mock SPI                                                            |
| Download bounds and sequence                   | Same handler, lines 876–893                | Zero/oversized length, overrun, missing first chunk and offset gap rejected                            |
| First chunk and restart                        | `src/rdx_mount/rdx_manager_protocol.c:542` | Offset zero erases mock boot area; another offset zero erases it again                                 |
| Image authentication                           | Same handler, lines 904–916                | Exact image accepted; changed payload produces authentication failure, not invalid-field at that point |
| Activation eligibility                         | Same handler, lines 922–938                | Complete valid image accepted; failed-image activation rejected without additional mock SPI            |

The nominal replay accepted all sixteen chunks using the actual SHA routines and
authentication code. Its payload bytes matched mock flash; the first four vector
bytes stayed erased until mock activation, which programmed them and set the
deferred-reset counter to five. No reset function was executed.

An injected initial SPI failure returned internal-target-failure. A subsequent
nonzero chunk returned invalid-field because a transfer had not been established.
Thus the error may describe sequence/state, not only a literal malformed CDB.
The existing Manager's immediate stop on a failed chunk is an important boundary.

## USB packet splitting is not an established explanation

The receive buffer is **4 KiB**, as declared in
`include/rdx_mount/tusb9260.h:351`. `src/rdx_mount/ums_bot.c:1033` requests the smaller
of the declared transfer and that buffer. All expected chunks fit in it.
The data-out completion callback at `ums_bot.c:1164` passes completed length
through `rdx_manager_write_buffer_host_length` in `rdx_manager_serial.c:36`.
For firmware buffer zero, a genuinely short completed length would reach the
receiver's length-equality guard and can produce invalid-field.

However, `usb_hal.c:306` initializes the completion counter once per receive and
`usb_hal_isr.c:371` and `:471` **accumulate** transferred bytes. The source does not
support assuming that a 4-KiB chunk becomes a 512- or 1,024-byte host length simply
because USB transports it in packets. Short completion, transport alteration and
runtime state remain unmeasured possibilities, not confirmed causes.

## Safety consequence and remaining diagnostic boundary

`rdx_begin_update` erases sixteen 4-KiB sectors before accepting the first chunk;
`rdx_program_container_payload` at `rdx_manager_protocol.c:420` programs payload
while downloading, before final image authentication and activation. Therefore
“not activated” does **not** establish that flash remained untouched. A later
transfer failure could leave incomplete boot contents while the running firmware
still answers status queries. The failed chunk is not known from the available
hardware evidence, so this review does not claim that happened on this dock.

Keep the powered dock as-is; do not use a reset or another firmware attempt as a
diagnostic probe. No speculative padding, chunk-size, sense-buffer or receiver
protocol fix is justified by these results. To identify the actual rejection
branch, the missing evidence is the rejected command length/fields, completed
payload length, transfer position and receiver state at the failure boundary.
Qualifying a different capture point is the next candidate; any driver, host,
device-state or firmware change needs a separately reviewed scope and approval.

## Reproduction and retained results

From the Manager directory, with a configured host MSVC INCLUDE/LIB/PATH:

```powershell
node analysis/scripts/review_receiver_offline.mjs ../../OpenRDX ../../OpenRDX/dist/OpenRDX-v1-10.bin <new-local-output-dir> <absolute-path-to-cl.exe>
```

The output directory must not already exist. The run reads the image, creates a
local generated source/executable and saves `build.txt`, `cases.txt`, and a hashed
`manifest.json`; it never invokes the bundled firmware updater.

Final evidence remains in the Windows staging root under
`receiver-offline-review-891b589a/`. Generated source SHA-256:
`a5ff6eb6d95ecb5634e4a2d68ee519c79bb9e3e7f1149c18a2e9940cd18b52c2`.
Fixture SHA-256:
`ed38a3f1aca22ce1f77ed3cb497dd49f2de9112019d8dc9ef645cfa12d2f7edc`.
The manifest also records all extracted input source hashes. Earlier failed CMD
compiler-launch artifacts and the preliminary successful fixture remain in their
separate output directories; no evidence was overwritten or deleted.

`npm run format:check` passed on the shared checkout using PowerShell as the npm
script shell and the existing staged Windows Prettier shim on PATH. The first
attempt could not locate that shim; it did not report an application style error.
The script excludes analysis/docs by design. The new MJS tool was separately
formatted with the same Prettier configuration and passed `node --check`, then
the final source was recompiled and all 27 checks passed again.

Application/native production tests and Electron smoke were not rerun for this
analysis-only change. No new app launch or successful hardware update is claimed.
