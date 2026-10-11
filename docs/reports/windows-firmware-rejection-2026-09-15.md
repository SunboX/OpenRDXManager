<!-- SPDX-FileCopyrightText: 2026 André Fiedler -->
<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->

# Windows firmware rejection — 2026-09-15

Historical report. Results and limitations apply to the described host, device and date; subsequent reports may supersede them.

Firmware updating remains unresolved. This follow-up changes Manager retry
handling and diagnostics; it does not establish successful hardware updating.
The running application was left untouched, and no firmware command, reset,
power cycle, manufacturing write or cartridge write was dispatched in this pass.
The chronological Windows feature verification report was read first.

## Observed failure

The supplied screenshot reports `firmware-command-invalid` during transfer,
support ID `support:op:594502de-8e5a-4783-b98a-f2d8f5259435`. Its local operation
log entered `firmware-writing` at 04:23:50.137 UTC, then recovery/readback and
failure at 04:23:51.744 UTC. It did not publish a finalizing stage. The existing
log does not identify the rejected chunk or the actual USB command fields.

A read-only Windows CIM/PnP check still found the TANDBERG RDX with revision
`0110` and the USBSTOR parent driver. This establishes recognition, not firmware
integrity or successful activation. The earlier change from a 252-byte to a
32-byte sense buffer did not eliminate the reported failure. That speculative
change and its new layout assertions have been reverted.

The Manager maps parsed sense `05/24/00` to `firmware-command-invalid`.
ASC/ASCQ `24/00` means invalid command fields, while `04/01` indicates a device
becoming ready. These are distinct conditions, not interchangeable retry advice.
See the [T10 ASC/ASCQ assignments](https://www.t10.org/lists/asc-num.txt).

## Receiver comparison, not a confirmed root cause

The actual 1.10 source is in the adjacent `OpenRDX` repository, not the older
`Complete_OpenRDX/TUSB9261_RDX_PlatformIO` checkout (version 1.06). Its
`dist/OpenRDX-v1-10.bin` matches the selected 62,110-byte artifact's SHA-256:
`4570b50ad44ef88bb45e239ee1a5866fdee2d85a3be30f6da57afd1e8228975a`.
Artifact equality does not prove the connected device contains those same bytes.

Relevant 1.10 source boundaries:

- `src/rdx_mount/scsi.c::scsi_handle_write_buffer_cmd` requires a ten-byte command.
- `src/rdx_mount/ums_bot.c::ums_bot_process_CBW` takes command length from the
  USB wrapper. Its data-out callback passes received length through
  `rdx_manager_write_buffer_host_length`.
- `src/rdx_mount/rdx_manager_protocol.c::rdx_manager_handle_write_buffer` rejects
  mismatched command/data lengths, invalid fields, manufacturing/serial mutation
  interlocks, invalid chunk bounds and invalid transfer sequence.
- The Manager's semantic/native encoders and bundled updater both request a
  ten-byte mode-4 command, buffer ID zero, sequential offsets and bounded chunks.

Several receiver branches can produce the same error. No USB capture establishes
which branch was reached, whether a field was altered in transit, or which chunk
failed. Do not label command padding, virtualization or firmware corruption as
the confirmed cause. No receiver code or immutable release artifact was edited.

## Implemented Manager changes

`TransportError::permits_firmware_retry` no longer accepts every CHECK CONDITION.
Invalid/unsupported commands, signature/protection failures, hardware/media
errors and unknown sense are terminal. Device-sense retry eligibility is limited
to unit attention and the explicit becoming-ready condition. Existing bounded
transport-recovery cases and fresh binding, revision, media and preservation
checks remain required; a retry remains at most one whole-image restart.

The production transfer helper now emits a fixed, bounded diagnostic vocabulary:
attempt one/two; first/intermediate/final failed chunk; sanitized cause; retry
eligibility/suppression; and complete transfer. No raw sense, command bytes,
payload, filename or serial is added. The main-process allowlist filters these
diagnostics before private logging. Failure diagnostics do not advance lifecycle
stages. The helper was split into `firmware_transfer.rs` to keep the worker below
1,000 lines. The production prohibition on activation after failed transfer remains.

## Verification

Verification uses a separate local application copy under the Windows staging
root, `firmware-rejection-verification`; the open application is still the previous
build. New deterministic tests cover invalid-field rejection at the first,
intermediate and final chunk, immediate stop, no retry eligibility, exact bytes
on successful transfer and rejection of non-allowlisted/raw diagnostic suffixes.

- `npm run native:test`: 529 passed, zero failed.
- Windows companion tests, including native layout and closed-command contracts:
  71 passed, zero failed.
- Full application formatting and changed Rust formatting checks passed.
- The initial full JavaScript run stopped in native pretest setup. Restoring the
  complete staged Windows toolchain PATH allowed the normal build to pass; no
  application guard was changed to bypass the build.
- `npm run smoke -- --disable-gpu --user-data-dir=<isolated-profile>` passed,
  exit 0, including the normal runtime build. The renderer mounted, but the
  isolated instance reported `service=unavailable mode=none hardware=false`.
  This is UI startup proof only, not native-service readiness or hardware proof.
  The original elevated application remained running; no cause is assigned to
  the separate instance's unavailability without further evidence.
- Full `npm test`, including the normal native pretest build: 885 passed,
  eight explicitly skipped, zero failed (893 total). Both complete screenshot
  runs, exact repeatability and injected visual-corruption rejection passed.

Evidence logs are retained in the local `Windows-20260913` staging root:
`firmware-rejection-native-tests.txt`, `firmware-rejection-companion-tests.txt`,
`firmware-rejection-node-tests.txt`, `firmware-rejection-node-tests-retry.txt`
and `firmware-rejection-smoke.txt`.
No successful physical update is claimed. Before another hardware attempt, the
remaining investigation needs actual transfer-boundary evidence; repeated
screenshots alone cannot identify the rejected command field.
