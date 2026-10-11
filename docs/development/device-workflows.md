<!-- SPDX-FileCopyrightText: 2026 André Fiedler -->
<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->

# Device workflows

Retained implementation notes from the previous root README. Dated device results apply only to their recorded hardware and firmware; they are not general compatibility guarantees.

OpenRDXManager is a native-ESM Electron application intended to provide an open management interface for RDX drives and media. The Phase 1 application shell opens one secure local `1280 × 800` window, supports a `1024 × 768` minimum, and presents device discovery, selected-device status, operation progress/failure, and truthful service-recovery states.

The title bar and Windows/Linux menu strip use the dashboard's dark blue,
with native window controls and a draggable title. The menu strip opens the
original native submenus and supports keyboard navigation and F10 access.
macOS keeps its system menu bar. Native popups and dialogs request the dark theme,
including when the desktop is set to light mode; their exact colors follow the host theme.
Closing a window revokes its trusted renderer using the captured contents,
avoiding a native getter exception after the window has been destroyed.

The unified dark dashboard preserves the original Manager's four device areas:
**Status**, **Encryption**, **Tests**, and **Utilities**. Local Help and the
Compatibility & Acceptance surface map all 25 numbered feature documents to a
current production route, operation, help entry, or explicit platform/evidence
boundary. A visible boundary is not counted as a working hardware operation.

After a selected dock disconnects, choose it again from the device rail or the
**Select an RDX drive** prompt when it returns. Cartridge spin-up can delay a
discovery scan; a valid late discovery reply is consumed without replacing newer
status or restarting the hardware service. See the
[Windows insertion investigation](../../docs/reports/windows-media-insertion-2026-10-08.md).

Linux discovery now reads the complete cartridge device-identity VPD page,
including its four-byte header and 512-byte ATA identify payload. A loaded RDX
dock is therefore no longer discarded because this identity read was truncated.
Incomplete or malformed cartridge identity evidence still blocks admission.
The block-topology check also distinguishes the kernel's `scsi_device` from its
`scsi_target` and `scsi_host` ancestors, which share the same SCSI subsystem.
It retains exact device, block, mount, and cartridge identity checks; ambiguous
or unsupported topology remains blocked. See the
[Linux SCSI device-type definitions](https://github.com/torvalds/linux/blob/master/drivers/scsi/scsi_sysfs.c).
Kernel namespace mounts used by Snap are retained with their validated `nsfs`
root syntax instead of invalidating the entire mount inventory. Ordinary mount
paths and filesystem roots remain strictly checked. See the
[Linux namespace-root representation](https://github.com/torvalds/linux/blob/master/fs/nsfs.c).
Linux also preserves the exact enumeration authority after discovery validation
so Safe Eject and other operations can reopen the detected dock. Each operation
still opens an exclusive SG lease and checks its device number and retained
sysfs instance. Failed scans preserve the last committed reopen records; a
successful replacement invalidates records from the previous generation.
Linux block identity leases use `O_PATH` so retaining the exact block inode
cannot acquire the SCSI disk driver's media-removal lock. Safe eject still
requires normal unmount and authoritative departure readback. A definitive
rejection at the eject stage remains visible as an operation failure without
restarting the hardware service; ambiguous eject completion still requires
readback. The kernel's [SCSI disk open/release implementation](https://github.com/torvalds/linux/blob/master/drivers/scsi/sd.c)
documents why a readable block descriptor prevents removable-media eject.

Linux cartridge VPD queries first check current media with standard TEST UNIT
READY. Cached identity pages cannot report an ejected cartridge as still loaded.
Insertion UNIT ATTENTION permits only bounded read-only retries; dock removal
cannot be mistaken for verified cartridge departure.

Mounted Linux cartridges now use the root-owned UDisks2 daemon's normal
`Filesystem.Unmount` API. The helper matches its uncached block-device number
and complete mount set against retained kernel evidence, closes its own
filesystem references, and verifies all selected mounts are gone before
requesting physical eject. This supports the shared mount trees used by Linux
desktops. External filesystem users still block Safe Eject; no force or lazy
unmount is requested. UDisks2 and the system bus must be available. See the
[UDisks2 unmount contract](https://storaged.org/doc/udisks2-api/latest/gdbus-org.freedesktop.UDisks2.Filesystem.html).

Live Linux verification on 2026-10-10 completed normal Safe Eject on the selected
TANDBERG RDX dock (`1a5a:0005`) with mounted exFAT media: unmount, mechanical
eject, and fresh departure readback reached `succeeded/complete`. A subsequent
production scan retained the dock as `no-media`. A separate disposable-loop
acceptance test verified busy-user rejection, normal unmount, and identity-only
block descriptors without selecting any other physical drive. This evidence is
specific to the tested connected dock and Linux host.

Linux formatting offers **ext4 (default), ext3, ext2, XFS, Btrfs, F2FS, NTFS,
exFAT, FAT16 and FAT32**. Each choice uses its fixed native `mkfs` tool and the
corresponding Linux or Microsoft partition type. Preflight checks tools and
capacity before unmounting or writing the layout. Install `util-linux` plus the
selected formatter package: `e2fsprogs`, `xfsprogs`, `btrfs-progs`, `f2fs-tools`,
`ntfs-3g`, `exfatprogs`, or `dosfstools`. These are filesystem creation choices;
read-only, network, and multi-device filesystems are not format targets.

Linux formatting retains the exact confirmed dock and cartridge lease across
its own unmount and partition-layout changes. Those expected changes no longer
cause `stale-device-revision`; fresh identity, capacity, write protection and
safe topology still must match. The layout continuation is consumed once, and
external remounts or cartridge replacement remain blocked. Regression tests
exercise the complete service flow and rejected identity changes without hardware.

After formatting, the root-owned UDisks2 daemon rescans the exact partition,
verifies its on-disk personality (including FAT width), and mounts it. Completion
also requires unchanged cartridge capacity, exact partition extent, and the
matching kernel mount. Ext3 readback remains distinct from ext4 even when the
ext4 kernel driver mounts it. Btrfs mount tracking binds anonymous mount device
numbers to the kernel FSID and complete sysfs membership; shared/multi-device
Btrfs and subvolume-only mounts remain blocked. See the
[UDisks2 block API](https://storaged.org/doc/udisks2-api/latest/gdbus-org.freedesktop.UDisks2.Block.html),
[Linux Btrfs UAPI](https://github.com/torvalds/linux/blob/master/include/uapi/linux/btrfs.h),
and [Btrfs formatting documentation](https://btrfs.readthedocs.io/en/latest/mkfs.btrfs.html).
Windows and macOS retain their respective host-supported choices.

Linux acceptance on 2026-10-10 verified all ten choices on disposable 1 GiB loop
images using the production formatter arguments and descriptor sandbox, actual
partition rediscovery, UDisks2 signature/mount readback, and normal unmount.
Backup_02 was not formatted. Run the opt-in test as root with the required tools:
`cargo test --manifest-path native/rdx-service/linux-native/Cargo.toml --lib all_linux_formats_on_disposable_partitioned_loops -- --ignored --nocapture`.
This proves the host pipeline on loop images; RDX format completion on physical
media requires a separately selected disposable cartridge.
The isolated Chromium form check uses synthetic data and never connects to a
drive: set `OPENRDX_LINUX_FORMAT_EVIDENCE_DIRECTORY` to a temporary directory and
run `env -u ELECTRON_RUN_AS_NODE npm run test:linux-format:electron`.

Firmware revisions appear as readable versions in Status and Compatibility:
`0106` becomes `1.06`, and `0283` becomes `2.83`. The legacy OpenRDX marker
`0001` remains unchanged because it does not identify a release. Support
diagnostics and update checks retain the original reported revision.

The firmware chooser is attached to the application window, includes lowercase
and uppercase `.bin`/`.bip` files, and shows selection failures beside the
firmware action through background refreshes. The button stays busy while the
chooser is open. After selection, the request uses the latest revision only if
the same empty dock, product family and firmware revision are still selected.
The renderer reads the service’s cached inventory after selection. Main may
advance a valid request’s revision after its already-running discovery scan only
when the same empty dock, firmware, capabilities and service generation remain
unchanged. Native admission still validates that exact refreshed revision.

Firmware failures remain visible when a USB reset removes the selected dock from discovery. The error code and support ID stay beside the connection guidance, and retry stays disabled while the original dock is unavailable. Post-activation readback waits up to two minutes for the same dock, without repeating its firmware transfer. The reconnect stage explains how to attach the reset USB device to a virtual-machine guest while keeping the dock powered.

If post-transfer reconnection or identity verification cannot complete, the error is `firmware-reconnect-failed`. The localized message explains that firmware may already be installed and asks the user to reconnect the same dock to the guest and inspect its version. This is separate from `stale-device-revision`, which still rejects a stale request before admission; an unverified update never receives a success banner.

To run the isolated selection
check without hardware writes, set `OPENRDX_FIRMWARE_SELECTION_EVIDENCE_DIRECTORY`
and run `env -u ELECTRON_RUN_AS_NODE npm run test:firmware-selection:electron`.

For firmware updates, select the release `.bin` in **Utilities → Update Firmware**
and keep its matching `.json` manifest beside it. The chooser verifies this pair
before returning a file token, so missing or mismatched manifests show actionable
feedback beside the button before an operation is accepted. Registration repeats
these checks to reject files changed after selection. A prominent localized alert
explains that the JSON must come from the same release, sit in the same folder
with its original matching name, and be followed by selecting the BIN again.
The macOS first-installation
flow for the researched vendor 2.83 dock and published OpenRDX 1.07 now includes
two prompted USB power cycles. Follow each prompt and click **Continue after
reconnecting**; the normal procedure keeps J7 open. Physical qualification of
this new flow is pending. See [firmware updates](../../docs/firmware-updates.md).

OpenRDX 1.11 is recognized as an installed update receiver as well as a target
release, so its factory records are verified after activation and before another
update. Its two receiver-readiness queries remain mandatory. Unknown future
receiver revisions remain blocked.

Ordinary OpenRDX updates verify the dock’s complete factory identity record
through two fixed 128-byte reads on Linux as well as Windows and macOS. Linux
also maps the two no-data receiver readiness queries required by firmware 1.10.
These mappings expose no arbitrary memory address or factory-write payload.
The complete record is verified
before writing, before retries and finalization, and after activation. An entirely
erased record can be preserved unchanged so firmware 1.09 can be installed for
explicit serial repair. The update itself does not restore missing identity data.
Unreadable or checksum-corrupt records block the update; any record change also
prevents successful completion. This check does not cover vendor-firmware restoration.

The update requires a verified private backup of the complete factory record
before writing. Linux uses root-owned `/var/lib/OpenRDXManager/manufacturing-backups`
with checked system ancestry, private directories/files, exclusive creation,
durable flushes and independent readback. Unsafe existing permissions, symlinks
or unreadable storage reject the update without changing those paths. Windows
uses the native ProgramData known folder under
`OpenRDXManager\manufacturing-backups`, with a protected administrator/System/
LocalService ACL, retained local-disk ancestry, exclusive new files, checked flush,
and independent content/manifest readback. Existing unsafe permissions or redirected
paths are rejected, not repaired. Initial provisioning requires administrator
authority. The folder action opens this same native-resolved location; it does not
create a second unprotected directory. Linux still rejects unavailable persistence.
Windows maps the fixed factory-sector reads, operational-state/mechanism queries,
restore-capability probe, and validated compare-and-replace restore. These are
closed protocol operations, not arbitrary flash access. Restore keeps the existing
explicit identity confirmation, pre-write backup, and readback guards.

Manual manufacturing backups remain available during routine Auto Scan refreshes.
A click queues one backup until the current scan and support read finish, then
uses the latest exact revision of the same empty dock. Changed identity, firmware,
media or service generation cancels an unsubmitted backup. Restore still requires
fresh support and renewed explicit consent. Backup success stays visible across
routine telemetry refreshes. Platforms without a supported whole-sector restore
route use the updater's two fixed 128-byte factory reads for manual backup, with
durable private storage and complete repeated readback; this grants no restore
or arbitrary flash authority.
Firmware-file tokens capture identity from an opened handle and compare it with
the claim-time handle. This avoids Windows pathname/handle device-ID differences
without removing the volume-ID check; changed files and volumes remain rejected.
See [factory-record preservation](../../docs/manufacturing-backup-restore.md).

For the reviewed OpenRDX 1.10 receiver, ordinary updates now check two fixed,
non-mutating capability queries after the factory-record backup and before the
first firmware chunk. Rejected or unknown responses stop the attempt without
recommending another retry or asserting a previous manufacturing write. The
released receiver's safety latch lacks the explicit boot initializer required
by TI ARM9 COFF; a power cycle therefore cannot be assumed to clear it. A corrected
TI-built development image exists, but the connected dock still blocked the
controlled retry before transfer. No safety latch is cleared or bypassed. See
[boot initialization fix and hardware result](../../docs/reports/windows-receiver-boot-init-fix-2026-09-16.md).

Windows self-test diagnostics now distinguish native/transport failures, malformed
completion evidence, and closed device-error classes without logging raw device
data. A dock-reported absent medium is surfaced as `media-required`, retaining
the dispatch uncertainty and original diagnostic stage after cleanup. A cached
loaded-cartridge snapshot never overrides a failing diagnostic or authorizes an
automatic write-test fallback. Unprivileged native-handshake tests also cover
Windows discovery without granting raw-device authority. The native test suite
can run on Windows without importing the macOS Unix
ownership implementation; unsupported-host ownership remains fail-closed. These
implementation changes alone are not physical firmware or all-features qualification.

If an interrupted installation leaves the dock in TI ROM mode, Manager offers
built-in recovery using its saved unit profile. The dock may be connected to any
USB port before selecting it. Follow the recovery panel's power-cycle prompt;
keep the saved profile for future recovery.

AI agents can connect to the running application through its optional MCP
server to read device values and request supported operations. Open **MCP
settings** in the top bar to enable local access and copy the agent configuration.
See [AI agent access](../../docs/ai-agent-access.md) for setup, tools, and current capability limits.

On Windows, MCP settings and its bearer token use the native private-file
boundary: local volume and pinned-ancestor checks, no reparse points or hardlinks,
verified current-user ownership, and a protected user-only DACL. Settings are
flushed, read back and atomically replaced; token creation is exclusive and never
repairs or reuses a credential with unverified privacy. The endpoint remains
disabled until explicitly enabled. This requires the rebuilt Windows client
addon; no raw filesystem handle or arbitrary filename is exposed to the renderer.

Return to [development documentation](README.md).
