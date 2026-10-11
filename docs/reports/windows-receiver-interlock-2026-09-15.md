<!-- SPDX-FileCopyrightText: 2026 André Fiedler -->
<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->

# Windows receiver interlock — 2026-09-15

Historical report. Results and limitations apply to the described host, device and date; subsequent reports may supersede them.

> **Correction, 2026-09-16:** The diagnosis and power-cycle advice below are
> historical, not current guidance. TI ARM9 COFF does not zero uninitialized
> static storage, and the released manufacturing latch has no boot initializer.
> These responses therefore do not prove a previous manufacturing write or that
> power cycling will clear the latch. Manager now blocks with readiness unknown.
> The corrected TI-built candidate was selected for one controlled hardware
> retry, which stopped before transfer. See the
> [boot initialization correction and actual result](windows-receiver-boot-init-fix-2026-09-16.md).

## Result and boundary

The connected dock's current read-only responses identify the manufacturing-write
interlock in the reviewed OpenRDX 1.10 receiver. Manager now detects that condition
during preflight, before any firmware download, instead of reporting an invalid
command after entering the writing stage. The firmware's safety latch is not
cleared or bypassed. A hardware power cycle and successful update remain unverified.

No firmware data, activation, device reset, ROM command, motor operation or driver
change was sent during this investigation. The separate TI-built BOT-cleanup
candidate was not flashed and the original distribution was not overwritten.

## Live evidence

At `2026-09-15T18:48:46.4866093Z` through `18:48:46.5027619Z`, one fixed read-only
probe retained the selected disk handle and verified standard INQUIRY, dock VPD83
identity, and an idle physically empty mechanism before and after these queries:

| Exact CDB              | Purpose                                   | Direct SPTI                | Buffered SPTI              |
| ---------------------- | ----------------------------------------- | -------------------------- | -------------------------- |
| `3B024D00000100000000` | Manufacturing restore capability, no data | GOOD                       | GOOD                       |
| `3B025300000100000000` | Serial capability, no data                | CHECK CONDITION `05/24/00` | CHECK CONDITION `05/24/00` |

Every query returned zero data bytes. All six identity/mechanism reads succeeded.
The probe permits only those two zero-data queries and three fixed input reads;
it rejects firmware writes, flash access, resets and arbitrary command fields.
Its offline self-test rejected 27 forbidden frames before hardware access.
This is Windows command-completion evidence, not a physical USB capture.

Local evidence:

- `C:/Users/afiedler/rdx-readonly-capabilities-20260915.ps1`, SHA-256
  `65362fd8cda2aeef19db2668769e44674489f1ff0f7b9c29ca0940412bce5c09`.
- `C:/Users/afiedler/rdx-readonly-capabilities-20260915-result.json`, SHA-256
  `224d00663cd264c1b50ecc7de71271377c90da7dfef21011b1fa974ae2a905d5`.

The result and script are preserved; neither contains a firmware or factory-data
dump. The script's target identity is local, not a public diagnostic interface.

## Why this narrows the rejection

Receiver paths here are relative to `../../../OpenRDX`:

1. `scsi.c::scsi_handle_write_buffer_cmd` checks the ten-byte CDB length before
   routing either capability query. Manufacturing-query success therefore
   contradicts a blanket ten-byte-CDB rejection on these measured routes.
2. `rdx_manager_protocol.c::rdx_manager_manufacturing_restore_blocked` excludes a
   started/failed update, pending activation and serial mutation. The exact
   manufacturing query returns GOOD only after passing this gate.
3. `rdx_manager_protocol.c::rdx_manager_handle_write_buffer` also checks
   `rdx_manufacturing_mutation_started()` before admitting the exact serial query.
   That same check rejects mode-4 firmware download with invalid-field sense.
4. `rdx_manufacturing.c` sets this latch before a manufacturing write and leaves it
   set until reboot, including after verified completion. Its own capability
   query remains non-mutating and returns GOOD while that latch is set.

This interpretation is supported by the returned TI instruction listing of the exact
base comparator: normal WRITE BUFFER handler `0x08006260`, manufacturing-latch
call/check at `0x080062A6`/`0x080062AA`, and serial-query branch at `0x08006520`.
The comparator reproduces the previously stored original image byte-for-byte.
It does not independently measure currently executing RAM or retrospectively
prove that every older screenshot had the same cause.

The corrected host replay also reproduces a zero-data serial query succeeding
with the latch clear, failing before SPI with the latch set, and the separate
manufacturing gate remaining open in that state. All **134** replay checks pass
in `C:/Users/afiedler/rdx-interlock-receiver-review-20260915/`.

## Implemented Manager correction

- The reviewed **1.10** ordinary-update path runs the two exact no-data queries
  after the existing durable factory backup and repeated record comparison,
  before announcing firmware writing. Older and migration receiver flows remain
  unchanged; their support for this exact response contract is not assumed.
- Both GOOD replies admit the existing updater without changing chunks, image
  authentication, preservation, retry policy or activation.
- Manufacturing GOOD plus serial `05/24/00` becomes
  `firmware-power-cycle-required`. This guidance additionally requires a complete,
  non-erased checksum-valid saved record and fresh same-lease identity verification.
- Missing/contradictory/unknown responses stop at preflight with
  `firmware-receiver-readiness-unknown`; they do not recommend a reset. A damaged
  record retains recovery guidance instead of acquiring power-cycle advice.
- Windows gains a closed read-only serial-capability mapping; macOS uses its
  existing native semantic operation. No raw CDB or arbitrary address is exposed.
- All eight locales explain the failure. The power-cycle instruction explicitly
  names **both USB and the power adapter**. It is displayed only for the validated
  preflight error, never for a failure reported during writing.

Source entry points: `native/rdx-service/src/service/hardware/firmware_interlock.rs`,
`native/rdx-service/src/service/hardware/firmware.rs`,
`native/rdx-service/src/protocol/manufacturing.rs`,
`native/rdx-service/windows-native/src/openrdx.rs`, and
`src/renderer/firmware-failure-reasons.mjs`.

The unsigned fixture explanation was also corrected. Endpoint counter declarations
are extracted and type-checked against the real header; signedness drift fails
the model contract. The returned candidate/report remain immutable evidence.
See the corrected [BOT cleanup analysis](windows-bot-cleanup-fix-2026-09-15.md).

## Verification

Verification used the explicit Windows build mirror at
`C:/Users/afiedler/rdx-spti-20260915/`; source changes were copied from this
workspace. Firmware artifacts were not copied over or changed.

| Check                                                                         | Result                                                           |
| ----------------------------------------------------------------------------- | ---------------------------------------------------------------- |
| Focused Node model, UI and preservation tests                                 | 10 passed; exit 0                                                |
| Signed receiver source replay, MSVC with warnings as errors                   | 134 checks passed                                                |
| Full `npm test`                                                               | 894 passed, 8 skipped, 1 failed; exit 1                          |
| Native Cargo, all features, no-fail-fast                                      | 530 tests passed; one test executable could not launch; exit 101 |
| Windows native companion Cargo tests                                          | 77 passed; exit 0                                                |
| Cargo Clippy, all targets/features, warnings denied                           | Passed; exit 0                                                   |
| `npm run format:check` in the source-matched Windows mirror                   | Passed; exit 0                                                   |
| `rustfmt --check` on this task's Rust files, without traversing child modules | Passed; exit 0                                                   |
| Real Electron interlock acceptance, including current-scene pixel checks      | Passed at both sizes; exit 0                                     |
| `npm run smoke`                                                               | Passed; exit 0                                                   |

The full Node failure is the previously observed visual-QA isolation/repeatability
test at `test/visual-qa-electron.test.mjs:171`: its injected-raster-noise child
command failed. The native exception is `compatibility_setup`, which Windows
refused to execute with error 740 (elevation required); its tests did not run.
Neither broad suite is reported as wholly passing. Logs are
`C:/Users/afiedler/rdx-interlock-{focused-final,node-tests,native-all,companion-tests,smoke}-20260915.txt`.
Whole-workspace Cargo formatting also reports pre-existing import ordering in
`macos-native/src/lib.rs` and `windows-native/tests/portable_contract.rs`; those
unrelated files were not reformatted. The UNC checkout lacks the Windows Prettier
launcher, so the successful npm formatting check used the source-matched mirror.

The first Electron fixture run rendered correctly but shared a cache with other
visual tests. A subsequent unvalidated screenshot was stale despite correct DOM
text; `rdx-interlock-electron-text-final-20260915` must not be used as visual proof.
The final harness uses a separate user-data directory and verifies both painted
text and scene-specific pixel markers before saving screenshots. It passed at
1024x768 and 1280x900 without cache warnings, requiring one capture per size.
The earlier real window was inspected with the computer-use skill, and the final
validated screenshot was also inspected. Prominent fixture labels prevent
confusion with hardware evidence. Final screenshots and assertions are under
`C:/Users/afiedler/rdx-interlock-electron-validated-20260915/`; the matching `.txt`
file records exit-zero completion. No hardware transport exists in this harness.

The ordinary unprivileged `npm run smoke` passed with `renderer=mounted` and
`hardware=false`, as expected without Windows raw-device authority. That proves
the app launches, not that an update succeeded. Live evidence for this task is the
separate exact-device read-only probe above.

The updated normal app launch uses
`C:/Users/afiedler/run-openrdx-interlock-fix-20260915.ps1`. At verification time,
Windows was awaiting manual UAC approval, so the elevated app was not confirmed
running. The launcher submits no firmware operation. The remaining hardware step
is a full physical power cycle of the empty dock, followed by fresh preflight;
neither that cycle nor a successful firmware update is claimed here.
