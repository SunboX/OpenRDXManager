<!-- SPDX-FileCopyrightText: 2026 André Fiedler -->
<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->

# Windows receiver boot init fix — 2026-09-16

Historical report. Results and limitations apply to the described host, device and date; subsequent reports may supersede them.

The subsequent investigation and full current backup are documented in
[the native Windows handoff](native-windows-firmware-handoff-2026-10-08.md).
Its evidence supersedes broad recovery conclusions in this historical report.

## Outcome

The firmware source defect is fixed and a complete TI-built development candidate
has been produced and tested. **It has not been installed on the dock.** One
explicitly authorized production-path update was submitted to the selected,
empty connected dock at `2026-09-16T04:54:56Z`. It stopped during
`firmware-validating` with `firmware-receiver-readiness-unknown`, before firmware
transfer. No second attempt, safety-latch bypass, reset, ROM operation, or
manufacturing write was performed.

Support ID: `support:op:d81595ba-fa4b-4386-aeff-e27aec50329a`.

This supersedes the earlier assertion that the response proved a manufacturing
write and that a full power cycle would clear its latch. The user's preceding
attempt `op:10e2f535-1f5f-4ed9-8fa2-565b4afbec85` also stopped at preflight;
that earlier Manager version displayed the overly specific power-cycle advice.

## Confirmed source/build defect; live-cause boundary

Paths in this section are relative to the sibling firmware repository
`../../../OpenRDX`.

- `src/rdx_mount/rdx_manufacturing.c` declared
  `static BOOLEAN_T rdx_mfg_mutation_started;` without an initializer.
- `src/rdx_mount/c_int00.c::init_globals` copies `.cinit` records. It does not
  independently zero the latch's uninitialized storage.
- TI documents that the ARM9 ABI does not automatically initialize uninitialized
  variables. See the [TI ARM Compiler 5.2 guide](https://www.ti.com/lit/ug/spnu151j/spnu151j.pdf),
  sections 6.10.3 and 6.10.4.1. Host C tests that zero static storage do not prove
  this target's startup behavior.
- The returned original-image comparator places the latch at `0x0800F200`, with
  no manufacturing-object `.cinit` entry. The actual TI compiler likewise emits
  no latch initializer for the previous declaration.
- The receiver checks this latch before the serial capability query and ordinary
  firmware download. A nonzero value can therefore prevent update admission
  without any manufacturing write having occurred.

The running RAM value was not read. This proves a target startup defect and a
plausible explanation for the observed rejection; it does not retrospectively
prove the exact cause of every earlier failure.

## Correction

The declaration now explicitly uses `= FALSE`. The real TI 5.2.9 compiler emits
the zero initializer, and the linked candidate contains this 12-byte `.cinit`
record at runtime address `0x0800CDA8`:

```text
04 00 00 00 00 F2 00 08 00 00 00 00
```

It copies four zero bytes to `0x0800F200` during boot. A real manufacturing write
still sets the latch to TRUE before mutation. No command, USB reset, or protocol
initialization clears it. The new regression test checks both the source contract
and assembly emitted from the actual production C source by the TI compiler.

Manager still requires both fixed non-mutating capability queries to succeed.
Every rejected/unknown result stops preflight without attributing mutation
history or recommending a reset. These failures are not offered as immediately
retryable. Factory-record backup, identity binding, image validation, transfer,
and finalization guards remain in force.

## Candidate identity and preservation

The build used TI ARM CGT **5.2.9**, the existing `ti_arm9_abi` flags and linker
configuration, and the normal `tusb9261_ti_cgt` PlatformIO environment. The Windows
compiler was available under `\\Mac\Home\ti\ti-cgt-arm_5.2.9`; another compiler
handoff was unnecessary. Build and generated outputs were isolated in
`C:/Users/afiedler/rdx-bootinit-candidate-20260916/`.

The complete generated six-file bundle is in that directory's `dist/`. It includes
the existing development BOT cleanup change as well as the new initializer;
it is not the earlier BOT-only candidate. Version remains 1.10, so revision
readback alone could not prove installation of this particular image.

| Artifact                                       | SHA-256                                                            |
| ---------------------------------------------- | ------------------------------------------------------------------ |
| New `OpenRDX-v1-10.bin` (62,110 bytes)         | `c6f4334552dfab7443948f22cfb11a9218b01394eb76f06b147edc4e748c799c` |
| New boot image                                 | `3191b86bded273ab8099bcaad63d878057f023cecb29aab13e03b883fdd11264` |
| New runtime image                              | `204927b506c18b6b45fc3a4604f8d4ea7c6ec59eb9de7535f76de9b95f93c791` |
| Original shared distribution, unchanged        | `4570b50ad44ef88bb45e239ee1a5866fdee2d85a3be30f6da57afd1e8228975a` |
| Earlier returned BOT-only candidate, unchanged | `879d97119d1510a1e2ab6392dd5ee135f883cf5fea1332dd8a867efb48618f06` |

No release was published and no shared distribution files were replaced.

## Actual hardware attempt

The normal Electron smoke launch rebuilt the native service and passed with
`renderer=mounted`, `service=ready`, and `hardware=true`. Native Windows input
could not operate the previously elevated app through the computer-use tool.
A manually approved administrator runner instead verified its exact process
identity and terminal prior operation, stopped only that idle app/service, and
used the production service runtime for one update request. Durable create-new
markers prevent accidental reruns. It did not automate Windows approval.

The runner pinned the selected dock, empty-media state, candidate bytes and
manifest, and required a fresh successful status refresh with correlated native
SPTI read evidence. The update returned a preflight failure. The device remained
enumerated as revision `0110` with no media; the service then stopped normally.

The new SPTI log contains 51 submitted read headers and no firmware mode-4 or
mode-5 submission. It is a bounded, allowlisted host diagnostic, not a USB capture:
manufacturing/serial capability queries are intentionally excluded, so it does
not independently establish their fresh sense values. Lifecycle evidence and
the tested preflight control flow establish that transfer was not entered.
The September 15 direct/buffered capability results remain historical evidence.

Local evidence root:
`C:/Users/afiedler/AppData/Local/Packages/OpenAI.Codex_2p2nqsd0c76g0/LocalCache/Local/OpenRDXManager/Windows-20260913/`

- `hardware-test-20260916-bootinit-result.json`, SHA-256
  `4d567ebfd3a5ef1148ce72b9b583057894896ea1b3599924ade59a0cca4fdaa8`.
- `user-data/logs/hardware-test-20260916-bootinit/RDXManager.jsonl`.
- `user-data/logs/hardware-test-20260916-bootinit/spti/RDXManager.jsonl`, SHA-256
  `c49bee4eceaee4e5305d727772c214627ab6fc8bf386bdd380cbdf0e130648e3`.

Launcher, one-shot runner and console logs are preserved in
`C:/Users/afiedler/rdx-bootinit-probe-20260916/`. The runner exited 1 because the
update did not succeed, not because a successful flash was interrupted.

## Verification

| Check                                                           | Result                                   |
| --------------------------------------------------------------- | ---------------------------------------- |
| New boot-initializer regression tests, real TI compiler enabled | 2 passed                                 |
| Firmware `python -m unittest discover -s tests -v`              | 263 passed, 39 skipped; exit 0           |
| `pio run -e tusb9261_ti_cgt`                                    | Complete target build and bundle; exit 0 |
| Generated bundle validation, version 1.10                       | Passed                                   |
| Manager Cargo, all features, library tests                      | 172 passed; exit 0                       |
| Manager Clippy, all targets/features, warnings denied           | Passed; exit 0                           |
| Focused Node firmware feedback/model tests                      | 8 passed; exit 0                         |
| `npm run format:check`, source-matched Windows mirror           | Passed; exit 0                           |
| Real Electron `npm run smoke`, elevated native hardware         | Passed; exit 0                           |
| One production update on connected hardware                     | Blocked at preflight; no flash           |

The firmware suite's optional host-compiler tests are among the skips; target TI
initializer verification did run. Earlier incomplete test staging failed and was
corrected; the definitive full log is `full-firmware-tests-verified.txt` in the
probe directory. The whole Manager Node suite was not rerun in this iteration;
the previous broad-suite exceptions remain recorded in the September 15 report.

## Remaining boundary

The new firmware fixes future boot initialization only after it is installed.
It cannot repair an already blocked running receiver through that receiver's
rejected ordinary-update path. Another identical retry or an assumed power-cycle
fix is not justified. Installation now requires a separately validated recovery
procedure preserving the dock's complete factory data. No such recovery action
is claimed or silently substituted for the authorized ordinary retry here.

## Reconnected hardware checkpoint — 2026-10-08

After the user connected the dock to Windows, fresh PnP/CIM evidence identified
the same `1A5A:0005` receiver, USB serial `007820999743`, revision `0110`.
There was no concurrent Manager/native owner and no TI ROM device. The WMI
`MediaLoaded` flag was true with no size; retained-handle mechanism reads,
rather than that stale flag, verified an idle physically empty bay.

An administrator-approved read-only probe completed at
`2026-10-08T05:37:19Z`. INQUIRY, dock VPD83 and mechanism reads succeeded before
and after the two capability queries. The exact manufacturing query returned
GOOD through direct and buffered SPTI; the exact serial query returned
CHECK CONDITION `05/24/00` through both. This fresh result reproduces the earlier
blocked readiness pattern. It does not measure the running latch's RAM value.

The new guarded runner stopped on these replies. **No firmware-update operation
was submitted, no firmware bytes were transferred, and no reset was sent.**
The prepared ordinary updater would have run only after all four capability
completions were successful; its create-new attempt markers were not consumed.
The probe's offline allowlist self-test rejected all 27 forbidden frames.

A separate production Manager runtime then captured the complete 4096-byte
manufacturing sector into the existing native protected backup store, checked
unchanged repeated device reads and reopened the new saved entry. It completed
at `2026-10-08T05:39:41Z` and stopped normally. This is a fresh manufacturing-sector
backup, **not a full current SPI or operational-state backup**. Private bytes and
saved identifiers were not copied into this report or console output.

The corrected candidate's five bundle entries still match its checksum file.
The retained historical same-unit 262,144-byte SPI archive also matches its
previously recorded digest; this does not establish that it matches today's
operational state. The candidate remains uninstalled and the dock still reports
`0110`. No source or release image changed in this checkpoint.

Evidence in `C:/Users/afiedler/rdx-recovery-20261008/`:

- `readiness-result.json`, SHA-256
  `65e8d8630acfceb41c0a4fbf6be5c734b0bea4c0f779c47943ad39441c3a5761`.
- `factory-backup-result.json`, SHA-256
  `90edd80b606d375fb73545d902c556c43da4d2849fc9a3fc6a9d8b8ffd3dd535`.
- `readiness-probe.ps1`, `run-guarded.ps1`, `runner-result.txt`, and the separate
  `capture-factory-backup.mjs`, `run-factory-backup.ps1` and capture console log.

The repair now requires a ROM installation route with preservation and readback
of this unit's current records. The board-level J7 route in the sibling firmware
repository's `docs/development/rom-loader-recovery.md` requires physical operator
work; it is not remotely enterable through the blocked ordinary updater. The
document explicitly says to stop before ROM entry if record-preserving recovery
is unavailable. The expected TI command-line FlashBurner installation was absent
on this Windows machine. Manager's existing receipt-based ROM controller is
macOS-specific and pins public 1.07; it cannot be treated as a Windows installer
for this development 1.10 candidate. Entering J7 or programming the generic
application HEX alone would not complete the missing preservation workflow.

For the subsequent software fixes and definitive broad test results, see
[Windows fix verification — 2026-10-08](windows-fix-verification-2026-10-08.md).
Those passing software checks do not remove this physical recovery boundary.
