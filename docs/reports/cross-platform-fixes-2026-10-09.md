<!-- SPDX-FileCopyrightText: 2026 André Fiedler -->
<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->

# Cross platform fixes — 2026-10-09

Historical report. Results and limitations apply to the described host, device and date; subsequent reports may supersede them.

The renderer completion feedback, operation lifecycle validation, exact-cartridge
rename draft handling and main-process console broken-pipe protection run on
Windows, macOS and Linux. A succeeded operation releases its hardware lock
immediately; its completion banner remains for eight seconds of foreground time.
The native service accepts the cancellable `format-validating` stage, preventing
the host from rejecting a valid format transition and getting stuck in teardown.

## Native cartridge labels

The shared service only admits an identity-bound `volume-label-set` operation for
a present, mounted, writable cartridge with simple topology. The native backend
revalidates its exact retained authorities before writing, then checks readback.
No caller supplies a disk path, mount path, executable, or command-line argument.
Windows continues using its exact volume backend; Windows drive-letter
availability no longer controls label editing on other platforms.

Linux uses `FS_IOC_GETFSLABEL` and `FS_IOC_SETFSLABEL` on its retained mounted
directory descriptor, with block/sysfs and mountinfo graph revalidation and
cartridge VPD identity checks surrounding dispatch. Only native `exfat` and
`ntfs3` mount types are accepted. A driver or kernel that lacks the read ioctl
does not expose rename readiness. FUSE/ntfs-3g is not supported by this path.
The request numbers are generated using libc's architecture-specific ioctl
encoding, rather than an x86-only literal.

macOS uses `fgetattrlist`/`fsetattrlist` with `ATTR_VOL_NAME` on an exact retained
mount root validated against its Disk Arbitration and IOMedia mapping. It first
checks `VOL_CAP_INT_VOL_RENAME`, rejects read-only writes, and supports exFAT,
HFS+ and APFS. Cached discovery refreshes the label through Disk Arbitration
without unmounting or acquiring SCSI, with matching media fingerprints before
and after the read. Canonically equivalent Unicode readback is accepted and
displayed in NFC. NTFS and FAT are not enabled by this backend.

The common input limit is 32 UTF-16 units, with an 11-unit exFAT limit. Native
filesystem restrictions can reject a request, including clearing a name. A
post-dispatch identity or readback failure reports completion uncertainty;
Manager does not claim that an unverified rename succeeded.

Primary API sources: [Linux ioctl definitions](https://github.com/torvalds/linux/blob/master/include/uapi/linux/fs.h),
[exFAT ioctl implementation](https://github.com/torvalds/linux/blob/master/fs/exfat/file.c),
[NTFS3 ioctl implementation](https://github.com/torvalds/linux/blob/master/fs/ntfs3/file.c),
[Apple getattrlist contract](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/man/man2/getattrlist.2),
[Apple setattrlist contract](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/man/man2/setattrlist.2).

## Scope of platform-specific format fixes

The VDS pending-status, retained volume-lock, native RAW filesystem query and
quick NTFS/exFAT fixes belong to Windows. Linux already invokes its closed quick
format workflow; macOS uses Apple formatting and Disk Arbitration. The firmware
capacity-preservation fix runs on the dock and therefore applies to all hosts.
Neither a service/renderer test nor compilation proves successful formatting.

### Windows VDS duplicate GUID aliases

A subsequent physical format test reached `format-finalizing` and failed with
`unsafe-volume-topology`. Read-only queries proved the selected cartridge had
one new GPT basic-data partition without a recognized filesystem. VDS reported
the same valid GUID twice for an unrelated system volume; the formatter's
pathname parser rejected that repetition before reaching the selected volume.
The same query uniquely matched the selected cartridge and reported NTFS and
exFAT format support. This identifies a host-side lookup failure, not successful
filesystem creation.

The parser now validates every bounded pathname, canonicalizes its GUID and
collapses repeated aliases within that one VDS volume. It still rejects null,
empty and malformed entries, preserves distinct GUIDs, and matches only the
exact retained target GUID. Regression tests exercise the production native
parser against the observed duplicate-alias shape and invalid evidence. This
change is confined to the Windows backend; native Linux/macOS format paths are
unchanged. The subsequent physical format qualification is recorded below.

The Windows companion suite passed all 99 tests after this fix, including five
new native-parser regression tests. Service Clippy and formatting checks passed.
The rebuilt runtime passed `npm run smoke` with a fresh test user-data directory:
the sandboxed renderer mounted and the native service reached `ready`. The
ordinary smoke profile could not access its administrator-created event log;
the fresh profile avoids that permission mismatch without altering normal data.

API contract: [Microsoft QueryVolumeGuidPathnames](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-vds/7710d42a-8427-415e-a8f6-795d66a3c8bd).

### Windows post-format remount verification

The next physical exFAT attempt created an `OPENRDX` filesystem that Windows
reported healthy and mounted, but Manager reported `stale-device-revision` during
`format-finalizing`. The old volume lease required the pre-format mount-path
snapshot to remain unchanged after VDS. Formatting can replace that filesystem
stack and assign a mount path, so the old snapshot is not valid remount authority.

After confirmed VDS completion the native backend now releases the old volume
handles, then fresh-enumerates and pins the sole exact volume. It requires the
same volume GUID, complete storage identity, ordered partition extent, retained
physical dock, cartridge generation and capacity. Only mount associations may
change. The fresh mount snapshot is still fully revalidated, followed by the
existing filesystem/mounted-state readback stage. Bounded retries perform only
read-only scans; they never dispatch another format. General pre-write mount
validation remains strict, and identity mismatch or failed VDS completion still
reports uncertainty.

All 105 Windows companion tests passed, including six new remount-identity
regressions covering mount arrival/reassignment, GUID/storage/extent replacement
and unrelated volumes. All 15 shared host-operation state tests, service Clippy
and formatting checks also passed. An isolated current-source Electron app with
the newly built native service passed startup with a mounted sandboxed renderer
and native service readiness.

The user repeated the physical exFAT format in the corrected Manager and
confirmed success on 2026-10-09. The application log independently records
`format-finalizing`, `format-readback` and `succeeded`/`complete` at 09:29:16 CEST.
A read-only Windows query afterward reports one healthy exFAT volume named
`OPENRDX` on the selected 3 TB RDX cartridge. The subsequent normal application
exit records native service exit code zero and the stopped lifecycle state.
This qualifies the tested Windows exFAT flow; physical NTFS and macOS/Linux
format tests remain separate qualification work.

## Checks on this Windows host

- The complete fixture-enabled native service suite passed 536 tests; the
  Windows companion suite passed 94 tests. Portable Linux label-payload and
  macOS attribute-buffer/Unicode tests also passed on Windows. Unix sysfs
  fixture tests are target-gated rather than imported into Windows builds.
- `cargo check --target x86_64-unknown-linux-gnu --all-targets --all-features`
  passed for the actual Linux service and companion code. Existing unrelated
  unused-code/import warnings remain on that target.
- macOS service and companion Rust sources passed an Apple Silicon target
  check in a private copy whose build script skipped the unchanged Apple C
  bridge. This checks Rust types, not Apple framework compilation or linkage.
  No macOS SDK build or macOS/Linux hardware test was performed here.
- Windows `cargo clippy --all-targets --all-features -- -D warnings`, Rust
  formatting and the application's `npm run format:check` passed. The older
  Windows companion's atomic-method deprecation remains a dependency warning.
- The current app and a newly compiled service passed the real Electron smoke
  path from an isolated test copy, with native service readiness and a mounted
  sandboxed renderer. Raw hardware transport was unavailable in that
  unprivileged smoke profile; this is application runtime proof only.
- Renderer tests cover native label admission and eight-second completion
  feedback for `win32`, `darwin` and `linux`. A real closed stdout pipe test
  confirms the child survives subsequent console output.
- Whole Node suites were exercised. Existing real Electron visual-QA raster
  anchor/capture failures remain; the suite is not reported wholly green.
  Build/restart follow-up checks use the configured Rust environment and
  test-owned staging instead of replacing the running application's service.

The firmware capacity fix was separately revalidated with all 307 Python tests
(39 skips), a successful TI ARM CGT 5.2.5 PlatformIO build, and complete rebuilt
bundle checksum verification. Generated release bytes are preserved by Git
attributes and were checked again in the staged index.

## Dedicated-system hardware checks

On each dedicated macOS/Linux system, build the native service and run its full
native tests, application tests and Electron smoke test. Then use the selected
RDX dock to verify insertion/ejection, writable and read-only media, label display,
rename, clearing and Unicode, and preservation of existing cartridge files.
Check exFAT on both hosts, HFS+/APFS on macOS, and a label-ioctl-capable native
NTFS3 driver on Linux. Check that unsupported drivers disable Rename.

Finally test the normal destructive-format confirmation on a disposable
cartridge, watch validation/writing/finalization/readback, and verify the result
in the host file manager. Confirm the completed message remains readable, normal
tray exit succeeds afterward, and a failed operation does not wedge service
teardown. The initial cross-platform code qualification performed no formatting
or label writes on the connected cartridge; the subsequent Windows exFAT format
qualification is recorded above.
