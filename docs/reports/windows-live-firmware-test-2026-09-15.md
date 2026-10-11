<!-- SPDX-FileCopyrightText: 2026 André Fiedler -->
<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->

# Windows live firmware test — 2026-09-15

Historical report. Results and limitations apply to the described host, device and date; subsequent reports may supersede them.

## Result

One explicitly user-authorized firmware update was executed on the exact selected
connected TANDBERG RDX through the production main-process service runtime and
operation coordinator. It failed with `firmware-command-invalid`.

The diagnostic capture identifies the failure at the **first 4,096-byte
WRITE BUFFER request**, not at activation. Exactly one firmware request was
submitted; no automatic whole-image retry, subsequent chunk, or mode-5
activation command was observed. The dock remained responsive and reported
firmware `0110` (1.10) and no media afterward.

This is a failed hardware update, not a successful firmware installation. A
responsive dock and zero host-reported completed bytes do not prove that its
flash is unchanged. No power cycle, reset, raw alternate command, manufacturing
restore, recovery bootstrap, or second update attempt was performed.

## Scope and preparation

The user explicitly requested testing the update on the connected hardware,
then authorized proceeding. This changes the earlier reports' read-only scope
for this one guarded test; it does not authorize bypassing protocol safeguards.

The user had closed the old elevated Manager window. Its windowless main process
was stopped only after checking its exact executable, process creation time,
absence of a window, and unchanged terminal status-refresh audit record. Its
native child exited without a separate forced termination. No concurrent native
hardware owner remained.

Windows administrator approval was provided through the normal UAC prompt.
The reviewed short-path diagnostic development build was used. The normal
`npm run smoke -- --disable-gpu --user-data-dir=<existing-local-profile>`
rebuild and real Electron launch passed with:

```text
OpenRDXManager service readiness: ready native hardware=true capability=available
OpenRDXManager smoke test passed: renderer=mounted service=ready mode=native hardware=true capability=none
```

The native executable SHA-256 was checked before and after that build:
`3b9006495dac3005a1ed4ef48ed3c305e65e9991cd9879e65f05a80ee07d18cd`.

The test required a single exact approved device identity, the expected installed
revision, no cartridge, native privilege and hardware readiness. It then
completed a real status refresh and qualified a correlated successful read in
the separate ACL-verified SPTI log before reserving firmware admission.

The normal `FirmwareFileSelectionService` token, file identity and OpenRDX
manifest checks were retained. An additional claim-time hash pin restricted the
request to the previously approved 62,110-byte image:
`4570b50ad44ef88bb45e239ee1a5866fdee2d85a3be30f6da57afd1e8228975a`.
A create-new, flushed attempt marker prevents accidental replay of the harness.
All native firmware preflight, transfer, preservation and readback guards
remained in place.

## Measured native-boundary evidence

Test interval: **2026-09-15 16:35:44.246–16:35:46.490 UTC**.
Firmware operation: `op:d8b0aed4-e6f3-4b39-a50c-4733c1b5f327`.
Support ID: `support:op:d8b0aed4-e6f3-4b39-a50c-4733c1b5f327`.

The correlated SPTI submit/completion pair has generation 1, sequence 47:

| Field                        | Observed value                                    |
| ---------------------------- | ------------------------------------------------- |
| Submitted command            | `3B 04 00 00 00 00 00 10 00 00` (10 bytes)        |
| Request                      | Data-out, 4,096 bytes, mode 4, buffer 0, offset 0 |
| Submit/completion UTC        | 16:35:44.721 / 16:35:44.724                       |
| Host result                  | Device response, not host I/O failure             |
| SCSI status                  | `02` (CHECK CONDITION)                            |
| Host-reported completed data | 0 bytes                                           |
| Decoded sense                | Fixed format `70`, key `05`, ASC `24`, ASCQ `00`  |
| Reported/copied sense length | 18 / 18 bytes                                     |
| Valid sense field pointer    | None                                              |
| Host I/O bytes returned      | 74                                                |

There are 160 safe header/sense observations in this test capture and exactly
one WRITE BUFFER submission. No command payload, raw sense payload, factory
identity contents or device secrets were captured.

The terminal lifecycle event was published at `firmware-readback` after the
normal reconnect/readback cleanup. That terminal stage does not mean the
transfer or activation succeeded: the primary failure is the first write above.
The runtime closed successfully only after releasing its operation ownership.
No native hardware process remained at the final process check.

## Interpretation and remaining uncertainty

Subsequent [readback and BOT cleanup work](windows-bot-cleanup-fix-2026-09-15.md)
verified that two full stored boot-region reads match the approved 1.10 image
exactly and corrected a separately reproduced error-cleanup underflow in receiver
source. That fix is not deployed and does not resolve the initial rejection.

The captured host command matches the expected first command already exercised
by the offline receiver review. This rules out a malformed first CDB at the
observed Windows SPTI submission boundary for this attempt. It does not establish
the USB CBW contents, received device-side data length, the actual running
receiver implementation, or its mutation/transfer state. The sense response
contains no valid pointer identifying the rejected field.

The earlier
[offline receiver review](windows-receiver-offline-review-2026-09-15.md)
documents several state and length checks that also return `05/24/00`.
Consequently, changing chunk size, padding the command, altering activation, or
retrying with a different transport is not justified by this capture alone.
The unresolved boundary is between the valid host submission and the dock's
rejection; this report does not claim a specific receiver branch or a fixed
firmware-update flow.

## Retained local evidence

All live artifacts are under the existing Windows staging root:
`C:/Users/afiedler/AppData/Local/Packages/OpenAI.Codex_2p2nqsd0c76g0/LocalCache/Local/OpenRDXManager/Windows-20260913`.

- `hardware-test-20260915-run1-result.json`: fixed-field outcome and lifecycle history.
- `hardware-test-20260915-run1-console.txt`: live stage publication.
- `hardware-test-20260915-run1-smoke.txt`: normal rebuild and Electron smoke proof.
- `hardware-test-20260915-run1-runner.txt`: scoped restart and final exit status.
- `hardware-test-20260915-run1-attempt.json`: single-attempt reservation.
- `single-firmware-test-20260915.mjs` and
  `run-single-firmware-test-20260915.ps1`: inspected test/launch source.
- `user-data/logs/hardware-test-20260915-run1/RDXManager.jsonl`: normal private audit log.
- `user-data/logs/hardware-test-20260915-run1/spti/RDXManager.jsonl`: correlated private SPTI capture.

Node syntax and PowerShell parser checks passed before dispatch. The update test
returned exit 1 for its observed firmware failure, not a host harness exception.
No production source was changed during this live-test turn. The earlier full
test results and their unresolved failures remain accurately recorded in the
[diagnostics report](windows-spti-diagnostics-2026-09-15.md).
