<!-- SPDX-FileCopyrightText: 2026 André Fiedler -->
<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->

# Windows SPTI diagnostics — 2026-09-15

Historical report. Results and limitations apply to the described host, device and date; subsequent reports may supersede them.

The user approved the proposed native-boundary diagnostic change, rebuild and
read-only qualification. This change does **not** establish the cause of the
firmware rejection or a successful firmware update. No firmware attempt, dock
reset, power cycle, manufacturing write or cartridge write is part of this work.

The chronological Windows feature verification report and the subsequent
[capture alternatives report](windows-capture-alternatives-2026-09-15.md) supplied
the starting evidence. The latter remains a record of the earlier, read-only
investigation, not a description of this implementation turn.

## Implemented boundary

`native/rdx-service/windows-native/src/spti_diagnostics.rs` observes the assembled
SPTI header immediately before the two `DeviceIoControl` calls in `native.rs`.
After each call it records bounded completion fields. It does not alter the CDB,
data buffer, timeout, sense allocation, native result or firmware state machine.

The explicit development opt-in is `OPENRDX_SPTI_DIAGNOSTICS=1`. Both the Electron
runtime and native debug executable must opt in. Packaged application runtimes
do not enable the sink, and release native builds do not emit these observations.
The normal child environment remains closed; only this fixed boolean is added.

Admitted command headers are the fixed inquiry variants, bounded LOG/MODE SENSE
reads, and firmware WRITE BUFFER modes 4/5 with buffer ID zero. Unknown commands,
cartridge writes, encryption commands and manufacturing record commands are
excluded. Zero-padded command lengths and firmware header/transfer-length
mismatches remain observable rather than being silently corrected.

Each admitted request has one sequence number and separate submit/completion
records. Retained fields are the hexadecimal header, direction, requested and
completed lengths, SCSI status, reported/copied sense lengths, native returned
control length and a fixed host outcome. CHECK CONDITION sense is decoded only
from a complete standard fixed/descriptor header. Fixed-format illegal-request
field/bit pointers are retained when present and valid. No raw sense, transfer
payload, device serial, path, handle, manufacturing record or key is retained.

`src/main/spti-diagnostics.mjs` independently validates the exact schema and header
allowlist. It correlates each completion with the original submitted header,
direction and length; duplicate, orphaned or mismatched records are rejected.
An opaque capture ID separates application runs, and main-owned generation
numbers separate native children.

The dedicated log uses the existing Windows ACL/reparse-point verified logger:
`<userData>/logs/spti/RDXManager.jsonl`. Metadata is under each JSON record's
`details` object. Normal event-log redaction and mandatory audit failure handling
are unchanged. Optional diagnostic failures disable this separate capture without
changing hardware outcomes or normal operation admission.

Bounds: 128 read requests plus 128 firmware requests per native process; at most
512 emitted lines per child, four captured generations and 2,048 records per
application run. Each native line is at most 512 characters at the parser
boundary. Disk rotation retains at most a 1 MiB current log and a 1 MiB backup.
The flag is not persisted in application settings; omit it on the next launch
to disable capture.

## Verification and deployment notes

New deterministic tests cover default-off behavior, closed header/sense schemas,
actual header padding, separate quotas, field pointers, truncated sense, split
stderr records, oversized input, generation correlation and logger failures.
The production logger is also exercised to verify approved metadata survives
without relaxing redaction. No test fixture dispatches a firmware update.

The first full build failed because its generated executable paths exceeded the
Windows linker's supported path length. A shorter local verification/runtime
copy was created at `C:/Users/afiedler/rdx-spti-20260915`; build guards were not
relaxed. An incomplete dependency copy was corrected before rerunning the normal
build and test scripts. The shared source checkout remains authoritative.

The existing elevated Manager was visually inspected: the selected TANDBERG RDX
reported Good, USB 3, revision 1.10 and no media. The normal close request through
computer-use did not close its elevated window. The user was asked only for the
necessary manual close, leaving the dock powered and connected. Do not replace
the running executable, force-kill its service or start a second hardware owner.

## Verified results

- Full `npm test`, including its normal native/preload pretest builds: 891 passed,
  one failed, eight skipped (900 total). All seven new diagnostic tests passed.
  The failure was `consecutive real visual QA commands preserve isolated captures
and leave canonical evidence unchanged`: its injected-raster-noise visual
  subprocess returned a command failure. The separate wrong-raster rejection
  check passed. This is not an all-tests pass, and no cause is assigned without
  additional evidence; no timeout or visual assertion was weakened.
- Windows native companion: 76 tests passed, zero failed; includes all five new
  header/sense/quota tests. `cargo clippy --all-targets --all-features -- -D warnings`
  also passed for that companion.
- Full native service suite with `--no-fail-fast`: 527 tests passed. The one
  blocked target, `compatibility_setup`, could not execute because Windows
  returned elevation-required error 740. Its three offline assertions were not
  executed, so the overall native suite returned nonzero. No elevation guard was
  bypassed to make this result pass.
- A synthetic header was persisted and read back using the real Windows native
  ACL-verified file adapter and production diagnostic logger. The isolated test
  directory was removed afterward. This proves private persistence, not hardware.
- `npm run smoke -- --disable-gpu --user-data-dir=<isolated-local-profile>` passed
  with the normal complete runtime rebuild, exit 0. The real renderer mounted and
  native service was ready but unprivileged: `hardware=false`,
  `raw-transport-unavailable`. This is application launch proof only.
- Full Prettier and changed Rust formatting checks passed. Focused tracked diff
  whitespace checks passed. Existing unrelated changes remain untouched.

The rebuilt native executable SHA-256 is
`3b9006495dac3005a1ed4ef48ed3c305e65e9991cd9879e65f05a80ee07d18cd`.
It is in the short-path development copy, not the still-running older application.

Evidence logs remain local under the `Windows-20260913` staging root:
`spti-native-tests-final.txt`, `spti-native-clippy.txt`,
`spti-service-tests-complete.txt`, `spti-npm-tests-final.txt`, `spti-smoke.txt`
and `spti-format-check.txt`. Earlier failed setup/build attempts are retained
separately rather than overwritten by the final verification logs.

## Later authorized hardware test

After this read-only qualification report, the user explicitly authorized one
live firmware update. The new build's hardware-ready smoke check and live SPTI
capture qualification passed. The first 4-KiB firmware transfer was rejected
with `05/24/00`; no second transfer or activation was submitted. See
[the live test report](windows-live-firmware-test-2026-09-15.md) for measured
command fields, exact scope, outcome and retained evidence. The section below
records the earlier gate, not the current test status.

## Remaining live gate at the original report time

The old elevated Manager must quit normally before its replacement can own the
dock. `launch-spti-diagnostics.ps1` in the local staging root is prepared but has
not been dispatched. It rejects an existing native service or saved drive-letter
configuration, uses the normal npm smoke/start scripts, preserves the existing
profile, and requires successful native hardware readiness before leaving the
new app open. Windows administrator approval is required for that development
launch; it must be supplied by the user, not automated or bypassed.

No live SPTI observation from the rebuilt app has been claimed. The
native-boundary records would establish host-submitted fields only; they do not
establish USB CBW/physical-wire bytes or receiver firmware state. A firmware
retry remains outside this read-only qualification.
