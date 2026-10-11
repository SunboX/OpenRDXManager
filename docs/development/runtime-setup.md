<!-- SPDX-FileCopyrightText: 2026 André Fiedler -->
<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->

# Runtime setup

## Application version

`package.json` owns the Manager version. Change it with `npm version <version> --no-git-tag-version --ignore-scripts`; npm also updates its lockfile. Electron uses this manifest for support summaries and update comparisons. The application metadata module reads the same manifest for Help/About and MCP endpoints, and macOS packaging uses it for bundle metadata.

Help/About receives metadata from the existing validated preload API. Documentation screenshots obtain that metadata from the package as well. Native helper crates and device firmware have separate versions.

## Requirements

- Node.js 22.12.0 or newer
- npm
- Rust 1.85.0 or newer with Cargo (for the portable native service)
- A supported desktop environment for Electron

The checked-in `.nvmrc` selects Node.js 22.16.0.

Windows builds also need Microsoft C++ Build Tools for the selected Node/Rust
architecture. The native service accepts both framed-session exit outcomes
(`EndOfInput` and `ShutdownRequested`) when releasing a Windows connection.
Opening the Electron UI alone does not enable discovery: build the native
runtime, and ensure Device Manager reports the RDX storage device without errors.

The Windows main process supplies a native private-event-log adapter from the
staged client addon. It verifies the current user owner and protected user-only
DACL, rejects reparse points and hard-linked files, and pins the complete local
directory ancestry during asynchronous file access. Appends are flushed before
success, and rotation uses a verified handle without replacing an existing backup.
Missing native code or failed security checks still fail closed with
`event-log-unavailable`. The development launcher does not request Windows
elevation, which the native raw-device transport requires.
A successful UI smoke test is not evidence of working Windows drive discovery.

When the launching host virtualizes application-data paths, use a verified physical
local profile with `npm run smoke -- --user-data-dir=<absolute-physical-directory>`
(or the same argument with `npm start`). The logger intentionally rejects a nominal
path redirected outside its pinned ancestry. An alternate profile keeps separate
settings; this does not install or authorize the production Windows service.

Native Windows discovery checks the retained disk for an empty cartridge bay
before inspecting volume topology. Windows may expose an empty RDX bay as a
zero-length placeholder volume; only a native no-media result followed by exact
dock revalidation is accepted as an empty bay. Present cartridges still require
the complete volume safety checks, and other query failures remain errors.

Windows also keeps a cartridge visible when its sole verified volume is RAW
(partitioned without a recognized filesystem). Only Windows' explicit RAW
filesystem name or unrecognized-volume result becomes absent filesystem space
facts. Manager queries filesystem information on the retained volume handle
before requesting free space: opening RAW media for read/write access can make
path-based queries report invalid parameters. That generic error alone never
proves RAW; access and I/O failures still reject the observation. Exact disk, volume topology, and
post-query identity checks remain required. This allows a failed or unfinished
format to be inspected without losing the dock from Manager.

Windows formatting now accepts an in-progress VDS status from either the status
call or its operation-result output. It continues polling until a terminal
result instead of treating a pending method result as failure. NTFS and exFAT
both use quick format; the bounded formatter does not request a full NTFS
surface pass on multi-terabyte cartridges. Actual format completion on hardware
remains subject to a separate device test.

Cartridge labels can be read and renamed through native backends on Windows,
Linux, and macOS. The shared UI binds each draft to its exact cartridge and
shows completion for eight seconds of foreground time. Windows uses retained
volume authority; Linux reads the current label through the root-owned UDisks2
object for the exact mounted block, including freshly formatted ext4 cartridges.
The rename field retains unfinished edits and the cursor across background
discovery revisions. Saving uses the latest device revision; changing the
cartridge, filesystem or reported current name discards the old draft.
Linux renames ext2/3/4 through that same host object. Mounted NTFS, exFAT, XFS
and Btrfs label changes use a verified readable mount descriptor, kernel ioctl
and daemon rescan/readback. FAT and F2FS names are displayed but
mounted rename remains unavailable. Ext labels are limited to 16 UTF-8 bytes,
XFS to 12, and the field rejects oversized multibyte names before submission.
Linux acceptance reads labels on all ten disposable-image formats and renames
and clears the seven supported mounted formats. The connected ext4 cartridge's
`OPENRDX` name was verified read-only; it was not renamed during testing.
For the isolated UI check, set `OPENRDX_LINUX_LABEL_EVIDENCE_DIRECTORY` and run
`env -u ELECTRON_RUN_AS_NODE npm run test:linux-label:electron`.
macOS uses volume attributes on a retained
Disk Arbitration/IOMedia-validated mount fd
(exFAT, HFS+, APFS). Unsupported drivers remain unavailable. All backends check
write protection, topology, current identity and label readback. The common
name limit is 32 UTF-16 units, reduced to 11 for exFAT; blank requests clear the
name where the filesystem supports it. macOS Unicode readback accounts for
canonical decomposition. Main-process console EPIPE handling is also shared
across platforms so a closed launcher pipe cannot interrupt a device operation.
See [cross-platform qualification](../../docs/reports/cross-platform-fixes-2026-10-09.md) for
checks performed here and the remaining dedicated-system hardware tests.

Present-cartridge discovery verifies each volume's native storage type before
requesting disk extents. Positively identified CD/DVD volumes (including Parallels'
virtual DVD drive) are unrelated to physical RDX disks and receive no disk-only
extent query. Their identities and mount paths remain in the complete safety
inventory; unknown types, failed queries on disks, and ambiguous disk topology
still fail closed. An unrelated optical drive therefore cannot hide a mounted
RDX cartridge by rejecting an inapplicable disk query.

Windows normal safe eject retains its exact volume leases through both recovered
allow-removal steps: `IOCTL_STORAGE_MEDIA_REMOVAL(false)` and the fixed no-data
SCSI `ALLOW MEDIUM REMOVAL` command. Both must succeed before the storage eject
request, with fresh identity checks between steps. These private preparation
commands run only after the existing safe dismount or no-mount checks; they do
not bypass flushing, unlock filesystem volumes, or fall back to forced eject.
Actual media departure remains mandatory before reporting success.

## Native Service Staging

The development hooks build the exact Cargo-reported `openrdx-hardware`
artifact in a repository-controlled target and stage it at
`out/native/<platform>/`. A bounded cross-process lock serializes Cargo and
staging, records a unique owner token and process ID, and recovers a lock only
when its owner is no longer observable. A contending hook times out instead of
waiting forever.

Stale removal first publishes a process-unique hard-link recovery claim bound
to the checked lock entry. Every acquisition and release honors active claims,
and each acquisition publishes a unique intent before checking them. A
recoverer waits for every earlier intent before unlinking, so neither a delayed
recoverer nor an already-admitted acquisition can reuse the shared path as an
ABA target. A claim left by a killed recoverer can be atomically adopted because
claim names are never reused. Strict owner records, a malformed-record grace
period, and conservative treatment of live or reused process IDs keep malformed
state from becoming either immediate lock theft or an unbounded deadlock. Exact
ownership is revalidated immediately before Cargo, staging copy, and runtime
rename.

The hook keeps the last-known-good executable in place throughout compilation
and validation. It copies a verified artifact to a unique file beside the
runtime executable, then uses one same-directory atomic rename. A Cargo,
validation, sharing, or rename failure removes the temporary file and leaves
the previous executable intact. Tests can select only an explicit existing
test runtime root; callers cannot provide an arbitrary final path.

Controlled roots are canonicalized, and every existing or newly created source
and destination component is checked with `lstat` and `realpath`. Windows
junctions and symbolic links are rejected. Detection of other uncommon Windows
reparse tags follows the guarantees of Node's filesystem APIs. Rechecking paths
immediately before copy and rename narrows race exposure, but portable
path-based APIs cannot eliminate every hostile local time-of-check/time-of-use
replacement; the repository itself must therefore remain writable only by
trusted local users.

## Install and Run

Install the locked dependencies and launch the application:

```sh
nvm use
npm ci
npm start
```

On macOS and Linux, `npm start` requests administrator authorization for the
exact repository-built development hardware service. Electron and its sandboxed
renderer continue to run as the signed-in user; only the debug helper is started
through `sudo`, over private inherited stdio pipes. This path neither installs
nor connects to the production launchd/systemd service. A non-elevated helper
remains fail-closed.

Current macOS also requires two one-time development-host settings before it
will execute the repository-built helper: system Developer Mode and permission
for Terminal to run local development software. Follow the exact setup and
verification steps in
[`docs/development/macos-hardware-access.md`](../../docs/development/macos-hardware-access.md). Start `npm start` from
that approved Terminal application; a development run always builds and starts
`out/native/macos/openrdx-hardware` and never falls back to an installed helper.

Return to [development documentation](README.md).
