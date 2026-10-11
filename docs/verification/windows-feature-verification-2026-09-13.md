<!-- SPDX-FileCopyrightText: 2026 André Fiedler -->
<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->

# Windows feature verification — 2026-09-13

This is a partial development verification on Windows 11 ARM64 in Parallels,
using the x64 Node/Electron/Rust development runtime. It is not an all-features
pass or a firmware release qualification.

This report is chronological. For the latest broad software verification, see
[the October 8 fix report](../reports/windows-fix-verification-2026-10-08.md). Earlier
failures below describe earlier builds and are not necessarily remaining
blockers. The firmware recovery boundary is documented separately there.

## Firmware correction and remaining gate

The Windows command classifier did not recognize either fixed manufacturing
record read. `WindowsDeviceHandle::execute` therefore returned `NotSent` before
SPTI, and ordinary firmware preflight reported `firmware-manufacturing-unreadable`.

The Windows service and native companion now map exactly the two 128-byte
data-in commands for `0x3E000` and `0x3E080`. Other vendor commands remain
rejected. The mapping was extracted into a focused module to keep the Windows
adapter below the repository's file-size limit. No generic CDB submission,
manufacturing restore, or safety-policy bypass was introduced.

There is a separate, existing blocker: `PlatformBackend::backup_manufacturing_record`
requires durable private storage, but its implementation is macOS-only. Windows
returns `firmware-manufacturing-backup-unavailable`. This guard remains intact.
The fixed record reads alone do not make Windows firmware updates complete.

All five artifact checksums in the local OpenRDX 1.10 release bundle matched.
The selected container is 62,110 bytes, SHA-256
`4570b50ad44ef88bb45e239ee1a5866fdee2d85a3be30f6da57afd1e8228975a`.
Bundle integrity is not publisher authentication or physical-update proof.

## Software checks before the safe-eject correction

| Check                                                  | Result                                                                                                                 |
| ------------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------- |
| Native Windows companion library                       | 47 passed, including both new fixed-read tests                                                                         |
| Node firmware-preservation regressions                 | 2 passed                                                                                                               |
| Windows firmware-file identity regressions             | 3 passed; all 3 failed before the correction                                                                           |
| Native development service and Windows addon build     | Passed                                                                                                                 |
| Prettier full `format:check`                           | Passed                                                                                                                 |
| Changed Rust files, `rustfmt --check`                  | Passed                                                                                                                 |
| Focused tracked diff whitespace check                  | Passed                                                                                                                 |
| Latest full `npm test`, including native pretest build | 820 passed, 37 failed, 2 skipped; 859 total                                                                            |
| Full native service library tests                      | Cannot compile on Windows because the existing macOS test-hooks dependency imports Unix-only APIs                      |
| Latest Electron smoke                                  | Passed, exit 0: renderer mounted, native service ready but unprivileged (`hardware=false`); not hardware qualification |

At this point, all 37 Node failure names occurred in the preceding 48-failure Windows
baseline. The file-identity correction resolved 11 failures and introduced no
new failure names. Remaining failures include platform expectations, symlink
privileges, logging/support paths, and runtime/visual tests. This does not
convert the full suite into a pass or establish that baseline failures are
harmless. The recorded full-run output is `firmware-file-identity-complete-tests.txt`
in the local Windows staging root. An intermediate run without the staged Cargo
environment had two additional native-build failures; the recorded latest run
includes the correct Cargo/Rustup environment and the normal native pretest build.

The latest launch used `npm run smoke -- --disable-gpu` with the physical local
Windows profile and no `--in-process-gpu` option. It completed the normal runtime
build and exited successfully; output is retained in `post-cartridge-smoke.txt`.
An earlier smoke invocation mounted the renderer but exited nonzero
(`-2147483645`). The later pass does not establish the cause of that earlier exit.
The computer-use skill was inspected, but its required `node_repl` runtime was
unavailable; no independent visual inspection is claimed.

The two new Windows-service unit tests also cover exact semantic mapping,
read-only risk, timeouts, and continued rejection of neighboring vendor reads.
Those tests are present in source but could not run through the blocked full
native-service test target; they are not counted among the 47 companion tests.

## Physical feature status

The administrator-authorized live check at 17:11 UTC used the production runtime,
identity checks, coordinator and private audit logger. Discovery and status refresh
passed with one TANDBERG RDX reporting revision `0110` and no media. The LED cycle,
restoration and readback completed successfully; this is protocol evidence, not
an independent visual observation of the LEDs.

Self-test failed with `host-operation-failed` while the bay was empty. The current
1.10 source in `scsi.c::scsi_handle_send_diagnostic_cmd` verifies cartridge blocks.
The user then inserted the 320 GB cartridge; the 17:26 UTC live retest detected
320,072,933,376 bytes and passed status refresh, but self-test failed again.
Its history reached `diagnostic-running` and `diagnostic-cleanup`; the public
error is generic and does not establish whether the cause is firmware, transport,
or a cartridge fault. The service remained ready with no restart and stopped
cleanly. The write/read test was not dispatched after this failure. No drive or
SATA mode was changed.

The first new firmware attempt stopped at `queued` with `firmware-file-changed`.
A no-hardware file probe reproduced Windows pathname `lstat.dev=0` versus a
nonzero device ID from `FileHandle.stat()` for the same unchanged image. Selection
now records identity from an opened handle, and claim compares handle identity
again. It preserves volume ID, inode, size and timestamp checks, repeats the
non-link pathname checks at selection, and closes the initial handle. Three new
deterministic regressions verify the Windows case, replacement by another volume,
and a pathname swap during selection. All three failed before and pass after
the correction. The actual local 1.10 container and paired manifest now claim
successfully through the production file-selection service.

The second live attempt at 17:19 UTC passed file validation and read the complete
factory record. It stopped at `firmware-validating` with the expected
`firmware-manufacturing-backup-unavailable`, proving that Windows still lacks the
required persistent backup implementation. It never entered firmware writing.
The service remained ready in generation 1 with no restart, and stopped cleanly.
Backup-folder preparation returned success, but that acknowledgment is not proof
of a functional backup store; the actual persistence gate failed.

Loaded-cartridge self-test has therefore been performed and failed. The new-file
64 KiB write/read/cleanup check remains unrun because that diagnostic failed.
A separate administrator-authorized safe-eject check at 17:56 UTC passed status
refresh and reached `host-unmounting`, `host-ejecting`, and `eject-readback`.
It failed with `operation-timeout` after the native ten-second departure window.
The Windows adapter invokes `IOCTL_STORAGE_EJECT_MEDIA` once and requires fresh
`IOCTL_STORAGE_CHECK_VERIFY2` evidence of absence before reporting success.
The final application snapshot still reported media present, and a later Windows
CIM query also reported loaded media. The user confirmed that the cartridge
remained fully inserted, so physical safe eject did not complete. No retry or
force-eject fallback was dispatched. The
service remained ready with no restart and stopped cleanly. Evidence is retained
in `windows-safe-eject-verification.json` in the local Windows staging root.

Follow-up source inspection found that the shared safe-eject path reconciles
an ambiguous native eject error through departure readback. If departure also
fails, the terminal currently reports the readback failure without exposing the
earlier native error. Therefore `operation-timeout` alone does not prove that
Windows accepted the eject IOCTL or identify a mechanical fault. A local-only,
fixed INQUIRY/MODE SENSE probe was prepared to read page 0x31 logical-unload and
auto-reload flags plus the page 0x33 physical-button gate. Its non-elevated open
returned `AccessDenied`. After Windows consent, the check completed at 18:15 UTC:
the exact TANDBERG RDX reported revision `0110`, both page 0x31 logical-unload and
auto-reload flags were false, and the page 0x33 physical-button-inhibit flag was
false. All four fixed read commands returned SCSI GOOD with no reported sense.
Evidence is retained in `readonly-eject-policy-authorized.txt` in the local
Windows staging root. These are current policy observations, not the state at
the earlier eject dispatch, and they do not expose the separate PREVENT/ALLOW
medium-removal interlock. The missing allow-removal preparation therefore remains
a hypothesis, not a confirmed cause. No policy flag has been changed.

The reference Windows 2.0.1.54 Manager also contains an eject preparation step
absent from the tested implementation: `FUN_00444ef0` issues media-removal control
`0x2D4804` with false and a `SCPAMediaRemoval` command constructed by
`FUN_00447c00` as opcode `0x1E` with byte 4 zero. Its safe eject path calls that
preparation before `FUN_00445040` dispatches `0x2D4808` eject. Evidence is in
the Windows Manager 2.0.1.54 implementation reference around
lines 57281, 59836, and 85785. Microsoft's
[media-removal control documentation](https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ni-winioctl-ioctl_storage_media_removal)
describes the corresponding device-lock control. This missing preparation is
a plausible explanation, not a confirmed cause of the live failure. No removal
interlock was cleared and no new eject attempt was made during this diagnosis.
Formatting, forced eject, encryption/credential changes, manufacturing restore,
drive-letter changes and drive/SATA-mode changes were not dispatched on hardware.
Broad automated tests exercise those code paths and rejection rules, but do not
establish physical feature success.

No firmware transfer or cartridge-data write has occurred in this verification.

## Safe-eject correction and current software verification

After the user authorized the fix and one normal safe-eject retest, both normal
Windows branches were changed to use the private prepared-eject sequence. The
already-dismounted branch keeps its successful safe-dismount lease; the no-mount
branch keeps its existing no-mount and retained-volume checks. Both retain their
volume handles through Windows allow-removal, the exact no-data SCSI allow-removal
command, and the storage eject IOCTL. Disk and retained-volume authority are
revalidated before each step. A failure stops immediately, and any failure after
the first preparation attempt remains completion-unknown. Forced eject is
unchanged and is never called as fallback. Departure readback is still mandatory.

The commands are private native helpers, not new renderer/CLI operations or a
generic CDB surface. Seven fixed diagnostic codes identify each step's outcome
and binding failure without passing raw stderr, sense buffers, or identities
through the main-process filter. These diagnostics preserve causal evidence
when the existing shared departure reconciliation ends with a timeout.

| Current check                                                         | Result                                                   |
| --------------------------------------------------------------------- | -------------------------------------------------------- |
| Windows native companion tests                                        | 51 passed, including 4 new safe-eject tests              |
| Focused routing and transport tests                                   | 20 passed, including 3 new Node tests                    |
| Full `npm test` with native pretest build                             | 822 passed, 38 failed, 2 skipped; 862 total              |
| Additional build-lock timing failure, isolated rerun                  | Passed                                                   |
| Electron smoke with normal runtime build                              | Passed, exit 0; unprivileged renderer/runtime proof only |
| Full `format:check`, focused Rust formatting, tracked diff whitespace | Passed                                                   |

The 38 full-run failure names are the preceding 37 plus the previously observed
`serializes two recoverers that bind the same stale entry before either unlink
proceeds`. It passed in isolation, but the full suite is still not a pass. Latest
outputs are `safe-eject-complete-tests.txt`, `safe-eject-native-final-tests.txt`,
`safe-eject-build-lock-rerun.txt`, and `safe-eject-smoke.txt` in the Windows staging
root. The staged hardware service SHA-256 is
`23e2c471839bab5a63997541027f3217d4581cda42d84c90e0dc2d1c4919172f`.

The one-shot hardware retest verified that exact binary hash, selected the same
validated TANDBERG RDX and 320,072,933,376-byte cartridge, and admitted only status
refresh followed by one normal safe eject. It refuses an existing result file,
concurrent app/service, or saved drive-letter preferences. After Windows consent,
the retest completed at 18:37:58 UTC: both status refresh and safe eject succeeded.
The eject history reached `host-unmounting`, `host-ejecting`, `eject-readback`,
and `complete`; the final application snapshot reported `no-media` and firmware
revision `0110`. The native service remained ready with no restart and stopped
cleanly. This is successful live command and departure-readback evidence, not an
independent visual observation that the cartridge physically popped out.

The result is retained separately in
`windows-safe-eject-fixed-verification.json`, preserving the failed pre-fix
result. No forced eject, firmware transfer, cartridge-file write, or policy-flag
change was dispatched. This successful retest supports the prepared-eject fix
on this dock; it does not resolve the separate firmware-backup and self-test
failures or establish an all-features pass.

## Windows completion work and live factory-backup verification

The follow-up implementation adds a Windows native manufacturing store under the
system ProgramData known folder, `OpenRDXManager\manufacturing-backups`. The
protected DACL grants only System, Administrators and LocalService; only those
principals may own production objects. LocalService-created and administrator-
created records share the same verified access policy. Every local ancestor is
retained without write/delete sharing, and reparse objects, extra hardlinks,
unexpected permissions and nonlocal/non-ACL volumes are rejected. New artifacts
are exclusive, write-through and explicitly flushed; every saved byte is reopened
and compared. A manifest is published only after record/sector files. Existing
artifacts are neither overwritten nor repaired. The renderer cannot supply a root
or filename. The folder button now resolves this same known folder through the
native addon and cannot create an unprotected substitute.

The Windows semantic adapter now includes the complete fixed manufacturing-sector
reads, operational-state and mechanism queries, the non-writing restore-capability
probe, and the independently validated 528-byte compare-and-replace restore. The
existing explicit original-identity confirmation and pre-restore sector-backup
requirements remain. No raw-command surface was added. The macOS-only ownership
implementation is target-gated so portable service tests compile on Windows;
foreign-platform ownership calls reject without creating a substitute lock.

The live administrator-authorized check at **19:13 UTC** used native binary
SHA-256 `5dfa0faca19caa3a1af1bf47ca58306b0d7cfd09355abeb3dd6e2a0a25cd5ba9`.
Discovery and status passed for the same empty TANDBERG RDX, revision `0110`.
LED cycle, restore and protocol readback passed. Native folder preparation,
factory inventory, complete sector capture, durable backup and a subsequent
inventory reopen all passed: the verified inventory grew from zero to one
record. Both backup and restore-capability probes reported support. This does
**not** establish that a restore write succeeds: none was dispatched. The service
remained ready in generation 1 with no restart and stopped cleanly. Evidence is
`windows-backup-feature-verification.json` in the Windows staging root. Raw backup
bytes and the unit's serial are intentionally absent from this report.

Current completed software checks are 160 native service library tests passed,
58 Windows companion tests passed, and 10 focused JavaScript tests passed. The
full Node run is 826 passed, 38 failed and 2 skipped (866 total); the failure names
match the preceding run, including its intermittent build-lock test. The Electron
smoke passed with a mounted renderer and ready unprivileged service. Broader native
integration testing and loaded-cartridge diagnosis are continuing. A subsequent
native loader correction opens Windows directory/reparse handles for actual type
inspection; the live backup binary above predates that loader-only correction.

The new self-test breadcrumbs retain closed native/SCSI/parser failure categories
without raw sense bytes. The loaded self-test, 64 KiB write/read/cleanup and a new
safe-eject check still require the cartridge to be inserted. Firmware transfer,
formatting, forced eject, encryption/credential changes, manufacturing restore,
drive-letter changes and drive/SATA-mode changes have not been performed in this
follow-up. The existing evidence gate for SECURITY PROTOCOL OUT remains closed;
its payload is not sufficiently established to implement by guessing.

## Loaded-cartridge outcome and final build from this implementation pass

After the user's cartridge-insertion confirmation, the one-shot production
coordinator check ran at **19:22:57 UTC** with the previously verified
`5dfa0f...` service. It required the same sole TANDBERG RDX and exactly
320,072,933,376 bytes of media capacity before each admitted operation. Status
refresh succeeded. The self-test reached the native SCSI boundary and returned
the closed `windows-self-test-no-media` diagnostic. Its operation failed and
completed cleanup. The service remained ready without restarting and stopped
cleanly; its final inventory still reported media present and revision `0110`.
The exclusive report is `windows-cartridge-completion-verification.json`.

The harness stopped on that failure, so **no 64 KiB file was created and no eject
was attempted in this run**. A subsequent read-only Windows storage check found
the same 320,072,933,376-byte RDX online, healthy, writable and neither boot nor
system storage, with an NTFS volume reporting healthy/OK. This confirms a
disagreement between the diagnostic completion and the current host/media
snapshot. It does not establish whether the dock firmware, cartridge, Windows
storage stack or USB passthrough caused that disagreement. No alternate self-test
command, forced eject or raw-media write was used.

Two additional Manager reporting corrections now preserve this evidence: a
no-medium CHECK CONDITION maps to the existing `media-required` error without
changing dispatch uncertainty, and self-test failure retains its original
`diagnostic-running` primary stage even after `diagnostic-cleanup`. Neither
change converts a failed diagnostic into success. A pair of native regression
tests covers the cause/certainty and primary-stage mapping.

Final staged native service SHA-256:
`757c525104871478286e048ad95627a1fbc094258538d31f68b6fd31a921f431`.
This build includes the Windows regular-file loader check and the diagnostic
reporting corrections. It passed the normal Electron startup smoke with a mounted
renderer and ready unprivileged service; it was not used for another live
self-test, flash or cartridge-data write.

Final verification results:

- The full JavaScript run completed with **834 passed, 30 failed and 2 skipped**
  out of 866 tests. Four outdated Windows native-runtime/path expectations were
  corrected, and missing immutable test references were staged. Remaining
  failures include POSIX-only fixture assumptions, logger/support-export tests,
  MCP settings/token handling and Windows process-launch/visual-QA coverage.
  They are recorded failures, not a clean release gate.
- The native all-features integration run completed every target. Its failures
  were a diagnostic-fixture worker-release race and the `session_api` compile-
  error snapshots. The fixture now queues an exact rescan barrier before the
  next diagnostic, without changing production locking or inserting sleeps.
  The subsequent complete all-features library rerun passed **163/163**.
- The remaining `session_api` failure is three of seven expected compiler-error
  snapshots differing under Rust 1.98.1. The compiler still rejects those three
  prohibited API uses; the snapshots were not blindly overwritten or skipped.
  The other native integration targets passed. The complete native suite is
  therefore still not a pass.
- The Windows native companion passed **58/58** tests, including actual private
  filesystem/ACL, exclusive-write, hardlink and retained-ancestor checks. The
  focused JavaScript Windows completion/folder/preservation group passed 10/10.
- Repository JavaScript/Markdown formatting and final Electron smoke passed.

Evidence files in the Windows staging root are
`windows-completion-full-tests-final2.txt`,
`windows-completion-all-native-final2.txt`,
`windows-completion-native-final3.txt`,
`windows-completion-companion-final.txt`,
`windows-completion-format-final.txt` and
`windows-completion-smoke-final2.txt`.

The real factory backup is preserved in the native protected store. The app is
closed after verification, and the cartridge remains inserted. No firmware
transfer, manufacturing restore, formatting, forced eject, encryption/credential
change, drive-letter change or drive/SATA-mode change was performed in this
implementation pass. A separately validated flashing/recovery procedure remains
required before flashing firmware artifacts; destructive cartridge testing also
requires an explicitly disposable target. The work is **partial completion**, not
an assertion that every missing feature is implemented or that all features work.

## Unattended follow-up

The user authorized continued implementation/testing while away. Work stayed in
software and disposable local fixtures. No UAC prompt, device write, firmware
transfer, cartridge test file, eject, format, credential change on the cartridge,
or manufacturing restore was performed in this follow-up. The real MCP endpoint
was not enabled, and no release, Git commit or push was created.

### Implemented and verified behavior

- Windows MCP preferences and token files now use native fixed-filename storage,
  current-user owner/protected DACL verification, local-volume and retained
  ancestor checks, hardlink/reparse rejection and bounded same-handle reads.
  New token creation is exclusive, flushed and read back. Existing credentials
  with unverified privacy are rejected without permission repair or replacement.
  Settings publication uses an exclusive temporary file, flush/readback and an
  atomic same-directory rename, including replacement while retaining the
  verified old settings handle.
- Shared native private-file directory pins now request data-read access as well
  as metadata access. Child renames retain those pins instead of releasing them
  to work around sharing conflicts. The private NT rename operation has only two
  closed destinations; logger rotation still cannot overwrite an existing backup.
  Its same-parent/null-root semantics and settings-only replacement flags follow
  Microsoft's [FILE_RENAME_INFORMATION contract](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/ns-ntifs-_file_rename_information)
  and [FileRenameInformationEx class](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ne-wdm-_file_information_class).
- Real Windows fixtures cover settings persistence/replacement, credential reuse,
  ACL exposure, hardlinks, junctions, fixed-name/type/size/receiver rejection and
  concurrent initialization. An actual stdio bridge authenticates to an ephemeral
  loopback fixture using the protected token file, reads app/tool data, and rejects
  reconnection after fixture token permissions are deliberately exposed. No real
  hardware service is attached to this endpoint.
- Cross-platform tests now use production native Windows logging, host-correct
  support-export paths and Windows child-exit semantics. Linux desktop entries
  consistently use Linux path rules. Pure macOS package/build argument validation
  precedes its unchanged platform execution gate. File-symlink tests skip only
  the unavailable Windows creation privilege; native junction/hardlink tests run.
- Visual tests keep host-specific captures separate from canonical research
  screenshots. Windows uses a fixed 2x test scale, avoiding fractional-DPI native
  minimum-window rounding. The reproduced disabled-reasons failure was a heading
  behind its scroll container's clip, despite being within viewport coordinates.
  Anchor selection now requires actual DOM hit-test visibility; pixel, fiducial,
  accessibility and console-error checks remain mandatory. Failure diagnostics
  identify the exact scene and retain the failed fixture image and inspection.
  Variable compositor retry counts are retained separately in
  `visual-qa-capture-metrics.json`; the deterministic manifest excludes those
  timing-dependent counts. Both their range and the exact repeatability of the
  manifest/screenshots are tested, including intentional raster noise/corruption.
- The remaining full-run MCP bridge failure was a concurrent dependency-removal
  race: npm's log confirms a successful `npm ci` in the shared stage at 20:32 UTC,
  while the bridge reported a missing MCP package before credential validation.
  Full-test setup now prepares preload/native dependencies before workers start;
  nested visual commands skip lifecycle setup hooks. They still execute the
  public visual harness and all raster/console/identity assertions. The isolated
  nine-test Windows MCP rerun passed without weakening the privacy assertion.
- Compact acceptance now checks all current frozen API groups. Windows resize
  diagnostics reproduced a 1440x900 renderer still being measured after requesting
  1024x768. Acceptance tests now wait for bounded exact viewport readback and a
  second post-paint observation, preserving the existing layout assertions.
- MCP UI acceptance has an explicit unattended clipboard fixture. It invokes
  production copy actions without reading or replacing any host clipboard content;
  evidence labels this as fixture clipboard coverage, not host clipboard testing.
- Image review found that earlier manufacturing screenshots could retain the
  unscrolled Utilities frame even though DOM assertions passed. The capture now
  requires visible target hit-testing and the existing canonical pixel/fiducial
  checks on the brand plus manufacturing heading/confirmation context. Disabled
  restore controls keep their original faded appearance and admission rules.
  Two additional DOM regressions cover the intended context, marker replacement
  and rejection of a missing target.
- The three Rust-version-sensitive session API tests now check the compiler's
  primary JSON diagnostics, error codes/symbols and exact source locations, after
  successfully compiling a positive public-type control. The remaining four
  session compile-fail snapshots still run. No invalid API use is accepted merely
  because compilation failed for an unrelated reason.

### Current build and verified results

The normal `npm run build:runtime` completed. The hardware service remains
SHA-256 `757c525104871478286e048ad95627a1fbc094258538d31f68b6fd31a921f431`;
the rebuilt Windows client addon is
`03966e098f63fcf1ee6de8baabe7d5caf380e603f02d69eeedd53d0e8981bd07`.
This follow-up did not change the hardware command implementation.
The full Node run used addon
`bd5201080dd2e4308af18241a444c206c044e1247ec5b54844dfeca8e3844383`;
the normal final smoke rebuilt the same sources and produced the final addon
above. These are separate builds, not a byte-identity claim.

- Full `npm test`, including setup before concurrent workers: **880 passed,
  eight explicitly skipped, zero failed** (888 total). The full 62-scene visual
  runs, repeatability, unchanged canonical evidence and injected error/corruption
  rejection passed. Evidence: `windows-followup-full-tests-final3.txt`.
  Two later manufacturing-capture DOM regressions are additional focused checks,
  not included in this full-run count.
- Native all-features tests: **523 passed**, zero failed, across 48 reported
  targets (including zero-test binaries/doc tests). All seven prohibited session
  API uses were checked. Evidence: `windows-followup-native-all.txt`.
- Native no-default-features tests: **382 passed**, zero failed. Evidence:
  `windows-followup-native-no-default.txt`.
- Windows native companion: **71 passed** (58 library and 13 integration tests),
  zero failed. Evidence: `windows-followup-native-companion.txt`.
- Focused Windows logger/MCP/controller tests: **22 passed, one explicitly skipped**
  file-symlink case, zero failed. Evidence: `windows-followup-mcp-final2.txt`.
  The final rebuilt addon rerun, also including the two manufacturing-capture
  regressions, passed **24 tests with one explicit skip and zero failures**.
  Evidence: `windows-followup-final-addon-tests2.txt`.
- Standalone real Electron matrix: **62 validated screenshots**.
  Evidence: `windows-followup-visual-fixed.txt`, with the isolated manifest and
  captures under `app/out/verification/windows-unattended-visual-fixed/`.
- Compact real Electron API/layout/focus/pointer/scroll acceptance: **passed**.
  Evidence: `windows-followup-compact-final.txt`.
- MCP real Electron acceptance: **passed**, with 57 tools listed and 20 operation
  definitions inspected, actual UI enable/disable, authenticated read-only calls,
  preferences round-trip and no renderer errors. This is not execution of all 57
  tools. Hardware readiness was false; no device mutation was attempted. The
  ephemeral endpoint was disabled again, and the host clipboard was untouched.
  Evidence: `windows-followup-mcp-electron-final.txt` and
  `app/test-results/mcp/acceptance.json` plus two screenshots.
- Manufacturing real Electron acceptance: **passed**, including repeated backup
  refresh/focus stability, folder intent, backup, confirmed restore and confirmed
  identity-recovery flows. All service responses were synthetic and no native
  transport was created. The final seven captures additionally passed painted-
  context checks; image review confirmed the actual identity-recovery controls
  are visible. Evidence: `windows-followup-manufacturing-painted-final.txt` and
  the manifest/captures in
  `app/out/verification/manufacturing-painted-unattended-final/`.
  Older screenshots under `manufacturing-unattended/` are superseded and must
  not be used as painted recovery evidence.
- Final normal Electron smoke: **passed**, exit 0, renderer mounted and native
  service ready with `hardware=false`. This is unprivileged startup proof, not
  live-device qualification. Evidence: `windows-followup-smoke-final.txt`.
- Source JavaScript/Markdown formatting passed. Evidence:
  `windows-followup-source-format-final.txt`.
- Native API documentation generation passed with rustdoc warnings treated as
  errors; its Windows companion dependency still emits two unused-code warnings.
  Evidence: `windows-followup-native-doc.txt`.
- `npm run native:check` reached Clippy after its missing component was installed
  into the isolated development toolchain. It **failed** on existing Windows-
  unused factory snapshot/migration/recovery/macOS code and a fixture style lint.
  Warnings-as-errors were not disabled. Evidence:
  `windows-followup-native-check3.txt`. This remains a failed release-quality gate.
  The no-default-features check reaches the same Clippy blockers; its preceding
  `cargo check` succeeds. Evidence: `windows-followup-native-check-no-default.txt`.

All named text results are in the Windows `Windows-20260913` staging root.
Two earlier stage-only diagnostic Rust sources were preserved in its
`verification-sources/` directory so Cargo no longer automatically treats them
as application binaries. Source-repository files and immutable inputs were not
removed.

A final read-only Windows storage query still reported TANDBERG RDX revision
`0110`, driver problem code 0, 320,072,933,376 bytes, online/healthy, writable and
neither boot nor system storage. This is host inventory evidence, not a passing
self-test. The earlier loaded-cartridge `windows-self-test-no-media` result
remains unresolved; the authorized 64 KiB test remains gated on a passing
self-test. A separately validated flashing/recovery procedure and an explicitly
disposable cartridge are still required for the respective unsafe workflows.
The final process inventory found no running OpenRDXManager Electron or hardware
service process. The app is closed and the cartridge remains inserted.
