<!-- SPDX-FileCopyrightText: 2026 André Fiedler -->
<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->

# Write/read test implementation

## Report and evidence

The user reported that **Run Write/Read Test** produced no visible start,
failure, or success information. The real Tests view showed the action as
available for the selected Tandberg drive and inserted cartridge.

The local activity log recorded operation
`op:9a7132bc-4b60-40d1-94cd-21c935c9d437` queued at 06:54:51.197 UTC on
2026-09-11, started at `host-writing` at 06:54:51.449, then failed when the
native service exited at 06:54:51.493. The service restarted immediately.
This was an operation lifecycle contract error, not evidence of a completed
filesystem test or a defective cartridge.

## Cause and correction

`run_write_read_test_observed` in
`native/rdx-service/src/operations/volume.rs` reports `host-writing` while
cancellation is still available during preflight. Before entering the
synchronous file I/O primitive, it reports the same stage with cancellation
closed. The native lifecycle validator previously rejected that legitimate
transition as `BackendContract`, ending the service generation. The Electron
coordinator's corresponding policy also rejected it.

`native/rdx-service/src/service/lifecycle.rs` and
`src/main/operation-lifecycle-policy.mjs` now explicitly accept cancellation
closing at `host-writing`, as they already do for safe eject at its host
dispatch boundary. The exception is limited to those exact operation/stage
pairs. Cancellation cannot reopen after file I/O starts. Ordered readback,
cleanup, and terminal validation still apply.

The existing renderer submission, progress, success, and failure components
remain the presentation path; no successful result is inferred from accepting
the start request. The diagnostic still uses its bounded, app-owned temporary
file and preserves independent cleanup evidence.

## Verification

The native regression reproduced `Err(BackendContract)` before the fix, and
the matching Electron regression rejected the progress event. Both pass with
the correction. `test/write-read-lifecycle.test.mjs` exercises the actual
renderer button, intent adapter, coordinator, store, progress rendering, and
terminal result. It also verifies that a service-loss failure remains visible
when the same device is rediscovered.

`npm run native:test` passed 434 tests. `npm run native:check` passed Rust
formatting, all-target compilation, and Clippy. The runtime build passed.
`npm run format:check` and `npm run smoke` passed. The full `npm test` run
passed 756 of 757 tests; the consecutive Electron visual QA test timed out.
Its isolated rerun reached a keyboard-focus assertion with
`windowFocusedAtTraversal: false`. The full suite is therefore not recorded
as passing. Both focused renderer/coordinator write/read regressions passed.

## Live hardware verification

On 2026-09-11, the rebuilt app ran the test against the selected Tandberg
drive and IMATION RDX-320 cartridge. Operation
`op:a559a17d-fe84-42d5-b953-6525b07254ab` started at 07:07:48.483 UTC,
published writing, reading, and cleanup stages, then reported failure at
07:07:48.787 UTC. The Electron and native service processes remained running.
The real Tests view displayed a persistent **Write/Read Test failed** result
with the primary error and cleanup evidence. These events are recorded in
the local `RDXManager.jsonl` activity log.

This run did not prove successful file I/O: `diskutil info -plist disk14s1`
reported NTFS, `Writable: false`, and `WritableVolume: false` for the mounted
cartridge at `/Volumes/RDX-320`, while the physical media was writable.
The macOS file-test preflight in
`native/rdx-service/macos-native/src/host.rs` rejects read-only mounts before
creating its file. The current error projection reports
`host-operation-failed at host-writing` and conservative
`cleanup-incomplete at host-cleanup`. Directory inspection found no
`.openrdx-write-read-*.tmp` files remaining. No existing cartridge files,
firmware, mount settings, or filesystem format were changed.
