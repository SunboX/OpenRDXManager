<!-- SPDX-FileCopyrightText: 2026 André Fiedler -->
<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->

# Native Windows investigation — 2026-10-08

Historical report. Results and limitations apply to the described host, device and date; subsequent reports may supersede them.

Historical read-only investigation. The later [native Windows recovery report](windows-flash-recovery-2026-10-08.md)
records the explicitly authorized flash and successful complete physical readback.
Its current results supersede the pre-recovery status below.

Normal updates on Windows and macOS remain unproved. The directly connected
receiver still contains the old 1.10 image and rejects the Serial capability
query. No firmware, Manufacturing or State data was written during this
investigation. The user requested continued USB-only recovery investigation
and prefers to keep the enclosure closed; reaching J7 would require opening the enclosure.

The new offline bootstrap candidate fits the installed TI tool's input limit
and restores this snapshot's exact raw records in compiled ARM emulation.
That is a candidate for physical qualification, not a qualified flashing route.

The follow-up [installed-binary USB recovery audit](installed-binary-usb-recovery-audit-2026-10-08.md)
completed 271 bounded offline execution cases against the captured original
instruction bytes. It found no qualified non-destructive closed-enclosure route;
normal download shares the failing Serial latch check. J7 remains an untested
physical fallback. The follow-up performed no hardware commands.

A subsequent [live ROM-loader qualification](rom-loader-qualification-2026-10-08.md)
confirmed one healthy TI ROM instance on the same USB port and reported flash
presence after the user entered bootloader mode and removed J7. Only read-only
probes were executed. Programming and rollback remain unqualified.

## Provenance and host

All 139 transfer-manifest entries passed size and SHA-256 verification. Local
clones retain the transferred revisions:

- Manager: `d6272c92bda14a502aec485d3a952ce7c4c43730`.
- Firmware: `c12f1d24c8781d27eac4643bcf2aa3b8c54fa3d3`.

Native Windows x64 build 26200, Node 23.1.0, Visual Studio 2022 Build Tools
17.14.37, PlatformIO Python 3.11 and TI ARM CGT 5.2.5 were available. Rust was
installed separately for this investigation; its current stable version is
1.99.0. Its local Cargo/Rustup roots are under `D:\RDX-Tools-20261008`, with
environment changes limited to individual commands. This is not evidence that
the repository's Rust 1.85 minimum was tested.

Private evidence is in `native-windows-20261008-1/` beside the transfer's
`START_HERE.md`, outside either Git checkout. Its ACL and the retained private
evidence ACL allow the current user, SYSTEM and Administrators. Raw images and
personalized bootstrap bytes must remain outside Git.

## Live read-only results

The selected USB parent was resolved afresh; its disk was `PHYSICALDRIVE2`,
rather than the historical VM's drive 1. Identity, INQUIRY, VPD83 and the
physical mechanism diagnostic were checked before and after each probe. The
mechanism was empty and idle. `RDXmon` was stopped for each probe and restored
to its initially running state afterward.

At 09:30:25 UTC, both Windows direct and buffered SPTI paths produced:

| Query                    | CDB                    | Host             | SCSI result                       |
| ------------------------ | ---------------------- | ---------------- | --------------------------------- |
| Manufacturing capability | `3B024D00000100000000` | Success; error 0 | GOOD                              |
| Serial capability        | `3B025300000100000000` | Success; error 0 | CHECK CONDITION, sense `05/24/00` |

This reproduces the macOS and Windows VM result on a native PC. It strengthens
the receiver-side explanation but does not substitute for RAM inspection or a
USB packet trace. The production readiness gate remains enabled.

At 09:32:26–29 UTC, the bounded E7 read path captured all 262,144 SPI bytes
twice, with identical results. SHA-256:

`027e4a699c5589bda268b92efc3f76143b9790a18e13da43381957aeb5e3ee32`

This is also byte-identical to the transferred current snapshot. The installed
boot remains the old image identified in the original handoff. Evidence:
`readiness-result.json`, `snapshot-result.json`, `snapshot-comparison.json`,
their console logs and the private `current-spi.bin`. The ported probes retain
their CDB allowlists, retained-handle identity checks and fail-closed guards;
their offline rejection self-tests passed before elevation.

## Installed TI tool limitation

Installed GUI: TI TUSB926x FlashBurner 2.10.0.0, SHA-256:

`29c92ad710e07c14b01a5d1b5dc5abbddcb1e7175dc0f52ca99ca19034379bd8`

Static reflection-only IL inspection found that `ProgramFull_Button_Click`
calls `StartBurning(true)`. That path retains a **65,535-byte BIN maximum**.
The BIN length comparison rejects a 262,144-byte file before device selection
or programming. The preserved complete backup and full repair candidate cannot
be supplied unchanged through this installed GUI.

The normal application path has a different limit. Changing formats, splitting
the backup, or removing the GUI check is not a qualified restoration method.

The signed x64 burner driver is staged as `oem60.inf`, matching ROM interface
`USB\VID_0451&PID_926B&MI_01`. There was no present ROM-loader instance during
the investigation. The installed CLI is version 1.3.1; its runtime ROM probe
was not exercised. Static inspection of the driver's bulk transfer path uses
a 32-bit length, but that does not prove the ROM accepts a 256 KiB image or
that the tool can read back or restore one.

Evidence: `inspect-ti-il.ps1`, `ti-image-parser-il.txt`, `ti-recovery-il.txt`
and the TI driver instruction listing. The inspected assembly was never invoked for
programming. TI's [FlashBurner guide, SLLU125D](https://www.ti.com/lit/ug/sllu125d/sllu125d.pdf)
describes full-image formatting in section 4.2 and distinguishes transfer
receipt from flash readback in section 5.4.

The reference [Luxonis USB flasher](https://github.com/luxonis/tusb926x-flash-burner),
revision `b254bce6788e120cfab0d1df9e84792758606bb7`, also imposes a 65,535-byte
input limit and constructs descriptors for application input. Its source was
inspected locally; it was not executed against hardware and is not a validated
full-backup restoration alternative.

Static inspection did not establish a non-destructive software transition into
ROM on the currently installed receiver. `src/rdx_mount/scsi.c` handles the TI
device-reset opcode by disconnecting USB and calling `system_reset()`; that
alone does not force ROM while a valid SPI image exists. The old TI vendor
unlock/erase/reset example in `usb_vendor.c` is excluded with `#if 0` and would
erase SPI if enabled. Neither path was sent as an experimental device command.
HID RAM-download code in a source file is insufficient proof that the installed
normal-mode USB configuration exposes a usable, safe RAM loader.
TI's [guide, section 3.1](https://www.ti.com/lit/ug/sllu125d/sllu125d.pdf)
explicitly limits its download-setup report to the bootloader. Section 4.7
describes mass-storage-to-bootloader transition through flash erasure, rather
than a reset that preserves the installed image. This does not provide a
qualified closed-enclosure recovery route for the present receiver.
The final Windows PnP inventory showed the selected receiver as USB mass storage
with its disk/volume children, with no matching HID or ROM instance. The current
transferred source also explicitly rejects the legacy TI SCSI unlock/erase
opcodes. These source observations are not a live execution test of those
opcodes on the old installed image. Evidence: `final-usb-inventory.json`.

## Offline USB bootstrap candidate

The existing `analysis/migration-bootstrap` design restores saved records
before the corrected receiver starts USB. A new isolated experiment combines
that maintained overlay with the exact transferred current firmware build
inputs, compiled using native TI ARM CGT 5.2.5. The historical builder's pinned
5.2.9 source checks and historical artifacts were not relaxed or replaced.

Complete coverage of the fresh snapshot was checked:

| SPI interval      | Contents                      |
| ----------------- | ----------------------------- |
| `[0,61710)`       | Boot image                    |
| `[61710,253952)`  | All `FF`                      |
| `[253952,254208)` | 256-byte Manufacturing record |
| `[254208,258048)` | All `FF`                      |
| `[258048,258112)` | 64-byte State record          |
| `[258112,262144)` | All `FF`                      |

Both record checksums, Manufacturing schema 6, exact selected-unit serial and
supported State mode were checked. A negative test adding a non-erased byte
outside those records rejects this route. The private package embeds the exact
320 raw bytes, rather than reconstructing only selected semantic fields.

The generated ROM image is **61,710 bytes**. The overlay validates its package
and digest, preflights both records before programming, programs fixed primary
record addresses without issuing erase commands, and compares readback before
USB startup. Existing SPI status polling is unbounded, which remains a physical
failure-mode limitation. The package cannot establish physical target identity
before the ROM programmer erases flash; same-unit ROM binding is still required.

Actual TI-generated Thumb restore and SHA-256 code passed Unicorn emulation
with only the `SpiOps` boundary modeled. Eight synthetic scenarios cover
invalid/placeholder packages, blank restoration, matching reboot, retaining a
bound newer State, rejecting an unbound State, partial replay and readback
failure. The selected raw records additionally passed a complete 262,144-byte
comparison against the current snapshot with only its boot region replaced.
A second matching boot performed no writes.

Private reproducibility evidence:

- `build-current-bootstrap.py`, `qualify-current-bootstrap.py`.
- `current-bootstrap/current-source-inputs.json`: all build-input and overlay
  hashes; `current-bootstrap/artifacts/build-evidence.json`: compiler, link
  placement and artifact hashes.
- `private-usb-bootstrap-candidate/verification.json`: personalized image hash,
  exact snapshot binding, emulator/qualifier hashes and all qualification results.
- `current-bootstrap-qualification.log` and corresponding exit status.

The template contains no selected-unit record data. The personalized candidate
is private, labeled `UNVALIDATED`, and is neither a normal Manager container nor
an approved FlashBurner input. Emulation does not model ROM erase/programming,
SPI timing, interrupted power, USB enumeration or the physical board.

## Build and QA

An isolated normal TI 5.2.5 build produced and validated the complete six-file
1.10 bundle. The canonical checkout's distribution was preserved. New container
SHA-256: `4607fc4bced3868e65af13201f7c7aa86f1dd626099780fd95af3473057cdc97`.
This is a new uninstalled Windows build, not the preserved TI 5.2.9 candidate.

The firmware suite completed 302 tests successfully, with 39 skipped. A Windows
SCons fixture failed initially because its implicit default environment tried
to load MSVC discovery modules absent from PlatformIO's reduced SCons. The
fixture now declares `DefaultEnvironment(tools=[])` before using `Dir`; the
full suite passed afterward. Production compiler selection was unchanged.

The first completed native Manager suite ran 911 tests: 898 passed, 5 failed
and 8 skipped. One failure came from the settings-ordering test extracting an
LF delimiter from a CRLF Windows checkout. The test now normalizes line endings
before extracting the unchanged production function. Remaining real Electron
visual tests failed at raster-anchor validation, with a dependent missing
baseline screenshot. The guard was not weakened. Initial toolchain-path linker
failures were resolved by moving the isolated Rust installation to its shorter
path. A subsequent full run after the test fix confirmed the ordering test
passes, but finished with 897 passed, 6 failed and 8 skipped: the visual failures
persisted, and bridge cleanup/build concurrency tests additionally hit their
deadlines. That run overlapped native Rust quality checks; load sensitivity is
an inference, not an established explanation. Focused serialized rechecks and
final command statuses are recorded in the private session logs. The focused
recheck with the configured native toolchain passed all 17 settings-ordering,
bridge and build-concurrency tests. `npm run format:check` also passed. These
focused passes do not turn either failed full suite into a pass.

`npm run native:quality` passed with Rust 1.99, covering formatting, checks,
Clippy, all-feature and no-default-feature tests, and documentation. It emitted
a dependency warning about `fetch_update` deprecation in `spti_diagnostics.rs`;
changing to a new API without checking the supported minimum Rust version
would not be an appropriate recovery fix. QA failures
must remain visible; no cross-platform release or normal-update success is
claimed by this report.

`npm run smoke` exited 0 and confirmed the renderer mounted. Its service was
unavailable with `event-log-unavailable`, so this is renderer-launch proof
only. A direct native adapter check returned `windows-log-path-unverified`.
Read-only Windows handle inspection showed that opening the usual Roaming
`OpenRDXManager` directory from this Codex-launched process resolved into
`%LOCALAPPDATA%\Packages\OpenAI.Codex_2p2nqsd0c76g0\LocalCache\Roaming\OpenRDXManager`.
This is consistent with the parent app's packaged-process filesystem
redirection. The adapter correctly rejected the expected/actual path mismatch.
Preparing the log directory using that actual canonical pathname passed native
no-reparse and user-only DACL proof. No security check was relaxed, and normal
application service readiness outside this launch context remains unverified.
Evidence: `manager-smoke-2.log`, `windows-log-path-probe.json`,
`windows-log-canonical-proof.json`.

## Remaining physical qualification

The small bootstrap remains a candidate for recovery over USB after ROM entry.
The follow-up binary audit found no qualified software ROM-entry path with the
enclosure closed. Before programming, the following evidence is needed:

1. A demonstrated safe software ROM-entry path through the external USB
   connection, or an explicitly chosen J7 fallback. No such software path has
   been qualified here. For the fallback, the same physical receiver must be
   bound to exactly one J7 ROM-loader instance, with correct
   HID/burner interfaces and confirmed M25PE20 presence, using the documented
   board procedure. Software cannot fit or remove the board's J7 link.
2. A reviewed procedure for this exact small, already-formatted bootstrap image
   and the installed tool, including erase coverage and failure recovery. A
   retained backup alone is insufficient while restoring that full backup via
   the installed GUI is unsupported.
3. After an authorized qualified write: physical boot, both readiness queries,
   full same-unit SPI readback and exact raw-record comparison. A transfer
   receipt or successful emulation cannot satisfy these checks.
4. Normal Manager update and subsequent verification on native Windows and
   macOS, with the corrected production receiver installed.

No J7 transition, reset command, ROM programming, direct SPI write, interlock
bypass, remote push or release was performed in this investigation.
