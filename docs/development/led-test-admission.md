<!-- SPDX-FileCopyrightText: 2026 André Fiedler -->
<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->

# LED test admission

## Admission during discovery

The reported LED Test error was **operation-in-progress**, even though the Tests
workspace showed no active operation. Auto Scan holds the main coordinator's
exclusive operation reservation while discovery uses the native device lease.
The renderer does not represent a background scan as an active diagnostic.
Previously, a click during that interval failed before a diagnostic was queued.

The main coordinator now waits for the scan already in progress before admitting
a user operation. It does not request an extra scan or resend an operation. The
shared GUI/MCP dispatcher waits before its safety preflight, and direct/tray
starts follow the same rule inside the coordinator. After the wait, admission
checks the original requested device ID and revision, live capabilities,
privilege, service readiness, confirmation, and lock ownership again.

A changed device revision is still rejected; the request is never silently
retargeted. An ambiguous scan outcome keeps the reservation and cannot authorize
an operation. A real active operation still rejects another action immediately.
The renderer's existing submission message remains visible during this wait.

Implementation: `src/main/operation-coordinator.mjs`,
`src/main/application-dispatcher.mjs`, and `src/main/service-runtime.mjs`.
Regression coverage: `test/operation-scan-admission.test.mjs` reproduces a click
while a scan acknowledgement is held, verifies one eventual dispatch, and covers
concurrent requests, revision changes, genuine contention, and ambiguous scans.
The existing scan reservation test now verifies waiting rather than rejection.

The admission change did not alter LED command payloads, firmware, or timing.

## Incomplete visual sequence

The user confirmed that both LEDs blinked green once after admission was fixed,
but the original Manager ran a longer color sequence. The production native
worker restored normal LED control after only 750 ms. This prematurely ended
the firmware-owned diagnostic sequence despite both commands returning SCSI GOOD.

The original Windows 2.0.1.54 and macOS 0.1.0.1 Manager start a 300-ms timer, send
LED-on once, advance a progress counter by four each tick, and send LED-off once
when the counter exceeds 100. This gives a nominal 26-tick, 7.8-second interval.
Exact implementation anchors and payloads are recorded in
`docs/protocols/features/13-led-test.md`. The visual colors are controlled by
the device firmware, not by repeated host commands.

`native/rdx-service/src/service/hardware/diagnostics.rs` now retains LED diagnostic
mode for 26 intervals of 300 ms after a successful ON command. Accepted
cancellation ends the wait at the next interval; normal ownership restoration
and identity readback still run before a terminal result. No firmware change or
additional command payload was needed.

Deterministic regression tests record the actual wait schedule without sleeping
or using hardware. The original 750-ms delay failed both the full-cycle and
mid-cycle cancellation cases. The corrected implementation passes those cases
and the already-cancelled case. The existing production worker test allows the
full visual interval before expecting completion; its ON/OFF command count and
queued-cancellation recovery checks remain in place.

## Admission verification on 2026-09-11

The focused coordinator, dispatcher, IPC, and diagnostic regression run passed
63 tests. Formatting and the Electron smoke check passed. The full suite recorded
723 passes and three reported failures (including a parent failure) in the two
existing Electron visual focus checks; the focus report had
`windowFocusedAtTraversal:false`.

After the app restarted with the change, LED Test was run from its real Tests
view with Auto Scan enabled and the same Tandberg drive/cartridge selected.
Operation `op:a1634867-99fc-471a-959b-92c94bfdc01c` ran at
06:39:01–06:39:02 UTC. Its local activity log contains queued, started at
`led-testing`, progress at `led-readback`, and succeeded at `complete`. The actual
window showed **LED Test passed**, **SCSI GOOD**, and **Normal LED ownership
restored**, with the Auto Scan switch still on. This proves command completion
and cleanup; physical LED color/brightness requires observation at the drive.

## Sequence verification on 2026-09-11

`npm run native:test` passed all 433 tests. `npm run native:check` passed Rust
formatting, all-target compilation, and Clippy with warnings denied.
`npm run build:runtime`, `npm run format:check`, and
`env -u ELECTRON_RUN_AS_NODE npm run smoke` passed. The subsequently completed
full `npm test` run reported 754 passes and zero failures, including the real
Electron visual checks (`/tmp/openrdx-async-full-tests.log`).

After rebuilding and restarting the app/service, the same connected Tandberg
drive was selected with its cartridge inserted and Auto Scan enabled. The real
GUI showed **LED test in progress** during the longer interval, then a green
**LED Test passed** result with **SCSI GOOD** and **Normal LED ownership restored**.
Operation `op:a6b20104-5cbd-4aea-a739-5920d3cd79fa` started at
06:51:32.944 UTC, reached `led-readback` at 06:51:40.890, and succeeded at
06:51:40.961: 8.017 seconds from start to completion. These events are recorded
in the local `RDXManager.jsonl` activity log. The user then confirmed that both
drive and cartridge LEDs flashed green and amber and that the full sequence
matches the original RDX Manager. This adds physical observation to the command
completion and UI evidence.
