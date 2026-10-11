<!-- SPDX-FileCopyrightText: 2026 André Fiedler -->
<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->

# macOS formatting implementation

The Utilities format card offers the native macOS filesystem personalities:
exFAT; MS-DOS FAT (automatic), FAT12, FAT16 and FAT32; Mac OS Extended with
case-sensitive and journaled variants; and APFS with case-sensitive and
encrypted variants. NTFS creation is unavailable through Apple's native tools.
Free Space is not a filesystem and is not presented as a formatted cartridge.

FAT12 and FAT16 remain visible but cannot be selected for cartridges beyond
their supported capacity. exFAT and FAT support Windows interoperability.
APFS and Mac OS Extended are Mac formats. macOS filesystem encryption is
separate from the RDX drive's cartridge-protection protocol.

The exact dock/cartridge confirmation, selected format, and transient password
fields survive a background refresh of the same cartridge. Replacing the
cartridge clears the confirmation and passwords. Passwords must match; they
are cleared from the controls when submitted, excluded from renderer state and
HTML, redacted in native Debug output, and zeroed when native ownership ends.

Formatting destroys existing cartridge data. Encrypted formatting creates an
empty APFS volume and encrypts it with the supplied password. It does not claim
to securely erase old unencrypted data. Loss of that password can make the new
volume inaccessible.

## Implementation and evidence

The previous renderer preserved typed text but reapplied the format button's
initial disabled attribute on every Auto Scan refresh. `format-form.mjs` now
recomputes readiness from current controls and device capability after each
render. `macos-format-options.test.mjs` and `utility-workflows.test.mjs` exercise
refresh, secret handling, submission, changed media, and terminal results.

The native format path runs the fixed Apple `/usr/sbin/diskutil` executable
with closed arguments, a clean environment, isolated output, and bounded
execution. It validates the exact IOMedia authority and raw descriptor, then releases
its claim and raw descriptor so Apple can open the disk exclusively. It retains
the IOMedia identity, resolves the current BSD identity again before each
mutation, and passes encryption
passwords through an anonymous stdin pipe. No password is placed in argv.
Apple's format tool receives the Disk Arbitration claim only after native
preflight and unmount complete. GPT is used for Mac formats and exFAT media
above the MBR capacity limit; smaller cross-platform formats use MBR.

Success requires a writable mounted filesystem of the selected type, unchanged
whole-disk capacity, and completed encryption when requested. APFS volumes must
map through exactly one physical store on the retained disk. Shared containers
and unrelated synthesized disks are rejected. Errors remain failures even when
an earlier formatting stage has already changed the disk.

Reference: `diskutil listFilesystems`, local `diskutil apfs encryptVolume` help,
and Apple's [filesystem format guide](https://support.apple.com/guide/disk-utility/dsku19ed921c/mac).

## Verification

All 13 format choices passed production formatter and readback checks on
throwaway virtual disk images, including both encrypted APFS variants. The
APFS test also checks physical versus synthesized disk selection and rejection
of a mismatched physical store. These are host formatter tests, not proof that
a physical RDX cartridge was erased. The connected cartridge has not been
formatted during this change.

Run the explicit disposable-image check with:

```sh
cargo test --manifest-path native/rdx-service/Cargo.toml --all-features \
  --test macos_formats all_native_formats -- --ignored --nocapture
```

The normal native suite validates bounded password parsing and redaction;
image creation remains opt-in. Verification on 2026-09-11 also included:

- 435 native tests passed. The encrypted APFS image check was repeated after
  fixing the raw-descriptor handoff to Apple's formatter and passed.
  A subsequent full-suite repeat was stopped after macOS held a test executable
  at `_dyld_start` before its tests began; that repeat is not counted as passed.
- 61 focused workflow/bridge tests and 33 integration/localization tests passed.
- The complete application suite reported 758 passes out of 761 tests. The
  failures were in Electron visual automation, including its timeout and
  screenshot-completion checks; this is not an all-green suite result.
- Runtime build, native checks, Electron smoke, and Prettier checks passed.
- The restarted app showed the expanded formatting card with the physical RDX
  connected. Entering the exact identity enabled the format button. The input
  was cleared without submitting an erase. Native UI automation could not
  reliably operate the dropdown in the administrator-launched window, so that
  interaction is covered by renderer tests rather than complete live UI proof.

## Queued exFAT failure on physical RDX

The 2026-09-11 09:59 local attempt stopped before formatter dispatch. The local
event log recorded `macos-da-pinned-authority-succeeded` followed by
`macos-da-direct-failed` while the operation was queued. The macOS candidate
open path incorrectly mapped that ambiguous unmount failure to
`device-not-found`. The exact cartridge was still mounted as NTFS afterward.

Apple's non-forced `diskutil unmountDisk` succeeded on that same connected
Tandberg disk, and its existing NTFS volume was remounted successfully without
formatting. The native DA adapter now allows that fixed-tool fallback for a
generic unmount failure as well as eject. Before fallback it proves that the
current BSD target still matches the retained IOMedia identity and raw disk
descriptor. Busy, removed, and timeout results do not trigger fallback; an
identity mismatch or failed Apple command remains a failure. Generic native
failures no longer imply that the device disappeared.

The native regression reproduces the original callback failure and verifies
successful fallback, changed identity, failed fallback, and busy-device
rejection. All 21 native bridge contract tests and 29 focused JavaScript tests
passed, as did the runtime build and native compiler/linter checks. This proves
the recovery path and the separate live unmount, not a completed physical
cartridge format through the updated service.

The next physical attempt at 10:10 local reached
`macos-diskutil-unmount-target-revalidated` and
`macos-diskutil-unmount-enter`, then returned
`macos-diskutil-unmount-exit-nonzero`. It still stopped before formatter
dispatch. This confirms that the fallback ran, but does not establish why
Apple rejected that particular unmount.

During a separate disposable exFAT image probe, Apple's diagnostic explicitly
identified the running Parallels VM process as the unmount dissenter. A repeat
unmounted successfully while the raw read-only descriptor remained open, so
that descriptor alone is not a demonstrated cause. Windows 11 currently has
Parallels SmartMount removable-drive sharing enabled. Parallels is therefore
a candidate for the physical-disk failure, not a confirmed cause. No VM
sharing settings were changed during this investigation.

The native fallback now privately reads bounded Apple stderr and recognizes
an explicit unmount-dissenter diagnostic as `volume-busy`. It emits only the
fixed `macos-diskutil-unmount-busy` trace token; arbitrary utility text and
process details are not forwarded to application logs. Other failures retain
their original classification, and no forced unmount is introduced.

After that diagnostic change, all 21 native bridge contract tests and all 29
focused JavaScript tests passed. Runtime build, native compiler/linter checks,
Electron smoke, and Prettier checks passed. Two full application-suite attempts
ended with exit status 137 before a summary; neither is counted as a passed
suite. Physical formatting through the app remains unverified.
