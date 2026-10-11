<!-- SPDX-FileCopyrightText: 2026 André Fiedler -->
<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->

# Manufacturing verification

## v1.10 Manager compatibility and original-identity recovery — 2026-09-13

The attached dock advertised USB `bcdDevice=0x0110`; the local operation log
recorded a successful firmware update at `2026-09-13T07:29:22.715Z`. The Manager's
receiver allowlist stopped at 1.09, rejecting backup before the restore probe.
The allowlist now includes the released 1.10 while rejecting unknown revisions.

A valid checksum on a reconstructed record does not prove its serial is original.
The restore form now requires separate consent when the selected original backup
has a different identity. The optional `allowIdentityChange` flag defaults false
in the service and is passed explicitly through both identity checks. Original
serial confirmation, physical association, current-sector backup, fresh complete
comparison, a single write, and complete readback remain required.

Verification for this correction:

- The v1.10 worker regression failed with `manufacturing-unavailable` before the
  allowlist fix and passed afterward. Automatic update-preservation coverage also
  includes an installed 1.10 receiver.
- All 235 native library tests passed. Additional recovery assertions verify
  that identity-change consent cannot bypass a wrong serial, missing physical
  acknowledgment, or stale device revision.
- The focused Node run passed 34 tests, including manufacturing UI/service and
  the platform-verification suite. Rust all-target checks, Clippy and formatting
  passed.
- The real Electron manufacturing acceptance harness passed with synthetic
  hardware, including separate identity consent through preload/main validation.
  Its screenshot was inspected; the new confirmation and restore button fit.
- The Electron smoke launch passed. The full Node run passed 834 of 837 tests;
  failures concerned process timeout cleanup and general visual-evidence/focus
  repeatability. The timeout suite passed separately. The isolated general visual
  suite passed four checks and reproduced one screenshot-repeatability failure;
  its generated changes were reverted. This is not an all-suite pass.

No physical manufacturing restore was issued. The rebuilt development launcher
requires the normal administrator authorization before live verification of the
updated service can continue.

The Manager changes and the sibling firmware receiver were tested without
flashing a dock or writing manufacturing data on physical hardware.

## Passing checks

- `npm run format:check` and `npm run native:check` passed, including Rust
  formatting, all-target compilation and Clippy with warnings denied.
- Focused Node tests for the device client, native interoperability,
  manufacturing service/UI, MCP tools and preload contract passed: 74 tests.
- The native service library passed all 228 tests. These include the real
  serialized hardware worker with simulated SCSI responses and real private
  filesystem storage, mandatory update backups, restore admission, damaged
  records, changed captures, uncertain completion and neighboring-sector data.
- The macOS companion passed 68 tests with `--features test-hooks`, excluding
  the existing `mounted_filesystem_discriminants_include_ntfs` test. That test
  expects native discriminant 3 to be unsupported; the unchanged implementation
  maps it to the macOS filesystem type.
- `env -u ELECTRON_RUN_AS_NODE npm run test:manufacturing:electron` passed.
  The actual protected Electron window, preload and main-process route validators
  exercised backup and explicitly confirmed restore against a synthetic service.
  Captures checked 1024×768 and 1280×900 layouts and control bounds. No native
  transport was created by this acceptance harness.
- `env -u ELECTRON_RUN_AS_NODE npm run smoke` passed with a mounted renderer and
  correctly reported unavailable hardware service; no live hardware proof is implied.
- The sibling firmware's Python suite passed 243 tests, with three existing skips.
  Its tests compile the actual C receiver, dispatcher and bounded SPI routines
  against simulated registers and NOR storage.
- The TI CGT 5.2.9 PlatformIO build completed successfully from an ASCII-path
  source copy matching the checkout. The linked firmware used 57,964 bytes of
  program/data memory with 6,291 bytes remaining; the 2 KiB stack was unchanged.

## Full-suite limitations

The completed `npm test` run passed 823 of 825 tests. The failures were native
generation restart timing and consecutive visual-evidence repeatability. The
restart test subsequently passed in isolation. The screenshot test observed
different scroll geometry between captures. Generated changes to unrelated
tracked visual evidence were discarded; manufacturing-specific captures remain
separate.

The full `npm run native:test` run stopped at the existing CLI empty-scan test:
`rdxctl --scan` emits a usage diagnostic when its unchanged worker launcher
re-executes the CLI with the internal SCSI-worker argument.

Further broad reruns stalled while launching compiled test executables on this
host. Sampling an affected process showed only `_dyld_start`, before Rust test
entry. Those owned test processes were stopped; the stalled reruns are not
reported as passes. No operating-system protection was disabled.

## Physical validation still required

Installing this firmware, restoring a real dock, power-cycle identity activation,
physical cartridge insertion races and interrupted NOR programming remain
unverified. The source implementation and host simulations do not establish a
safe physical release or power-loss recovery procedure.

## Backup-triggered service shutdown

A later live attempt on 2026-09-12 reached service readiness and then switched
to `event-log-unavailable` when **Backup manufacturing data** was clicked.
The local log retained 313 native diagnostic records during 18:59:54 UTC.
Each manufacturing-sector read emits repeated SCSI worker breadcrumbs; these
informational records were incorrectly admitted as non-replaceable priority
entries in the 256-entry logger queue. Saturation latched a logging failure and
shut down the hardware service.

`EventLogger` now coalesces contiguous queued informational service diagnostics,
retaining the latest breadcrumb. Audit records, service lifecycle records,
warning/error diagnostics, and explicit `writeCritical` calls preserve their
ordered priority. Actual persistence failures still stop hardware access.

`test/manufacturing-diagnostic-burst.test.mjs` reproduces the backup route through
the production logger, service client and manufacturing coordinator with 1,024
native diagnostic messages and real temporary log files. Disabling the fix
reproduces `event-log-priority-overflow`; enabling it allows the backup reply,
log flush and service readiness to succeed. Logger tests also check audit
ordering and preservation of warning, error and mandatory diagnostic records.

Verification of this fix:

- The logger, manufacturing-burst, logging-latch and critical-audit checks passed.
- `npm test` passed 826 of 828 tests. Two visual checks were disturbed by
  workspace/window changes during that run. An isolated
  `node --test test/visual-qa-electron.test.mjs` rerun passed all five checks,
  including both failed cases, with no workspace or UI interaction during it.
- `env -u ELECTRON_RUN_AS_NODE npm run smoke` and `npm run format:check` passed.
  The smoke launch was unprivileged and reported unavailable hardware service.
- A physical backup after the fix remains unverified. The earlier development
  process was closed, and a new hardware session requires the normal macOS
  administrator-authorized `npm start` launch. No manufacturing restore or
  firmware write was performed during this investigation.

## Saved-backup dropdown refresh regression

The saved-backup selector shared `manufacturing:backup` as its focus key with
the backup button. An unchanged device refresh therefore moved focus to the
button. Automatic scans also disabled the entire manufacturing form, closing
the native selector while the operator was using it.

The selector now owns a distinct focus key, and local form editing remains
available during discovery. Backup and restore commands still wait for scanning
to finish; changed device identities or revisions still invalidate confirmations.

Two regressions in `test/manufacturing-ui.test.mjs` reproduce the lost focus and
disabled selector before the fix and pass afterward. The Electron manufacturing
acceptance harness also checks three scan cycles in Chromium: the same selector
remains enabled and focused, with zero mutations to its markup, while the backup
command stays disabled during scanning. Existing synthetic backup and confirmed
restore flows pass in that harness.

The reloaded live Manager was inspected with a validated dock and Auto Scan
enabled. The selector retained focus across background refreshes. The UI tool
did not expose the native popup reliably, so this is not evidence that the open
popup itself was visually observed across those refreshes. No restore or
firmware write was performed.

Final verification for the dropdown fix:

- The focused manufacturing and shared renderer-refresh suites passed all 19
  tests, and `npm run test:manufacturing:electron` passed with the added
  Chromium refresh assertions.
- `npm test` passed 828 of 830 tests. Both failures were existing visual QA
  checks reporting `windowFocusedAtTraversal: false` and a missing visible
  keyboard-focus ring. On an isolated visual-suite rerun, both of those checks
  passed, but the same desktop-focus failure interrupted the console-injection
  subtest before it reached its intended injected error. Neither complete run
  is reported as a pass.
- `env -u ELECTRON_RUN_AS_NODE npm run smoke` passed with a mounted renderer;
  its unprivileged session reported unavailable hardware service.
- `npm run format:check` and `git diff --check` passed. Unrelated tracked
  screenshots regenerated by visual QA were restored to their prior contents.

## Single manufacturing backup folder (2026-09-12)

The default macOS store is now the authenticated desktop account's
`Library/Application Support/OpenRDXManager/manufacturing-backups`. Manual
backup, automatic pre-update and pre-restore capture, inventory and restore
selection all resolve that same store. Existing service-owned records are moved
there; the former location is never used as an alternate inventory or write
fallback. The folder button waits for the native relocation gate before asking
Electron to open that actual directory.

Focused verification:

- 26 native manufacturing tests passed, including original-inode preservation,
  duplicate-safe relocation, interrupted staging/source cleanup, incomplete
  evidence, conflicts, storage permissions and the existing firmware backup gate.
  The empty root-owned parent recovery branch requires a privileged test run.
- 12 native framed-service protocol tests passed; `npm run native:check` passed.
- 32 focused JavaScript tests passed for folder opening, rejected paths/senders,
  preparation ordering/failure, duplicate requests, selector stability and preload.
- `env -u ELECTRON_RUN_AS_NODE npm run test:manufacturing:electron` passed. The
  real Electron fixture exercises the button through preload/main dispatch;
  its file-manager boundary is simulated. The 1280-pixel view was inspected.
- `env -u ELECTRON_RUN_AS_NODE npm run smoke` passed with a mounted renderer
  and its expected unprivileged unavailable-service state.
- `npm test`: 834 passed, one failed. Consecutive full visual-QA captures differed
  in screenshot bytes and resulting tracked-evidence status; no source edits or
  other UI actions ran during that comparison. Generated evidence was restored.
- The broader `npm run native:test` stopped at the existing CLI scan stderr
  assertion. An isolated rerun reproduced it: the macOS SCSI worker starts the
  current `rdxctl` executable with an internal worker argument the CLI rejects,
  emitting a usage error while scan returns an empty result. Those worker and
  CLI implementations were unchanged by the backup-folder change.
- `npm run format:check` and `git diff --check` passed.

These checks do not perform a firmware update or manufacturing restore on hardware.
