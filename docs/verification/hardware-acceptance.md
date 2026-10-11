<!-- SPDX-FileCopyrightText: 2026 André Fiedler -->
<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->

# Hardware acceptance

## Status and evidence boundary

Physical acceptance is **in progress**. A TANDBERG RDX USB dock and disposable
320 GB test cartridge are attached to the current Mac. A bounded low-level
transport probe has completed a physical SCSI INQUIRY through macOS
`IOUSBHost`, and the development Electron application has validated the dock
through the repository-built elevated helper without using an installed
service. Cartridge-state acceptance and the checklist operations below remain
pending. Host-side fixtures, cross-target compilation, and native adapter tests
are useful source/build/runtime evidence, but they are not substitutes for
those pending application-level results.

### Current attached-hardware observation

On 2026-08-29, macOS 26.6.1 (`darwin-arm64`, build `25G76`) reported one USB
dock with vendor `TANDBERG`, product `RDX`, USB serial `007820746632`, vendor ID
`0x1a5a`, product ID `0x0006`, and firmware revision `0227`. Its disposable
test cartridge appeared as a 320.1 GB removable, physically writable device
with an NTFS partition named `RDX-320`; macOS mounted that NTFS volume
read-only.

After unmounting the cartridge volume, a temporary root-run transport probe
captured the exact USB ancestor, selected the single mass-storage interface
(`08/06/50`), completed the 64-byte BOT data phase, recovered the expected
first command-status-wrapper bulk-IN stall by clearing the endpoint stall, and
validated the matching command-status wrapper. The returned physical INQUIRY
identity was vendor `TANDBERG`, product `RDX`, revision `0227`. Releasing the
capture rematched the storage driver and returned the disk to macOS. This is
physical read-only transport evidence.

The development Electron application then requested administrator authorization
for only its repository-built debug helper. Electron remained under the signed-in
user while the helper ran as root over private stdio. Its scan validated one
drive as vendor `TANDBERG`, product `RDX`, revision `0227`, device serial
`7820746632`, and USB 3. Repeated scans kept the helper alive. The later UI media
snapshot reported `No cartridge`, so cartridge status, diagnostics, eject,
write/read, and format are not accepted by this observation. No credentials
were entered into logs or repository files.

Historical vendor qualification is recorded in
[`protocols/features/24-platform-hardware-and-media-compatibility.md`](../protocols/features/24-platform-hardware-and-media-compatibility.md).
It does not certify OpenRDXManager on a current Windows, Linux, or macOS host.
Current acceptance must identify the exact host, OS/runtime, dock, firmware,
media, command, result, date, and operator for every executed row.

## Evidence rules

Before starting a row:

1. Select the explicitly named test host and validated RDX dock. Record the OS
   name/version and architecture plus the Manager, Electron, and native-service
   versions/mode as the row's OS/runtime evidence.
2. Record the dock model/serial, firmware revision, interface, cartridge
   model/serial/capacity, media state, filesystem, and write-protect state.
3. Confirm the row's risk, prerequisites, expected identity, cleanup, and stop
   conditions. Use disposable media for any write, format, reset, or encryption
   flow.
4. Preserve the exact UI or CLI request, native terminal result, relevant
   redacted activity/support correlation, and any cleanup result.
5. Enter evidence only after the operator observes the result on the named
   physical hardware. A build, fixture, mocked response, or result from a
   different host does not fill a row.

If the device identity, revision, privilege state, firmware, interface, or media
state differs from the planned row, stop and open a new record. Do not overwrite
earlier evidence. Passwords, keys, authorization blobs, and unrestricted host
paths must not enter this document.

## Ordered physical checklist

The `Target scope` and `Prerequisite / expected boundary` columns describe the
test to run; they are not evidence. Evidence fields including OS/runtime remain
empty until the application-level execution supplies every value. The low-level INQUIRY
observation above therefore does not pre-fill a checklist row.

| Step | Risk                        | Target scope                                             | Operation                                       | Prerequisite / expected boundary                                                                              | Date | Host | OS / runtime | Dock / model | Dock firmware | Cartridge / media | Exact command and result | Operator |
| ---: | --------------------------- | -------------------------------------------------------- | ----------------------------------------------- | ------------------------------------------------------------------------------------------------------------- | ---- | ---- | ------------ | ------------ | ------------- | ----------------- | ------------------------ | -------- |
|    1 | Read-only                   | macOS                                                    | Start service; scan with no dock                | Empty inventory, explicit hardware/transport state, no device command                                         |      |      |              |              |               |                   |                          |          |
|    2 | Read-only                   | Windows                                                  | Install privileged endpoint; scan with no dock  | Endpoint ACL/readiness recorded; empty inventory is not an error                                              |      |      |              |              |               |                   |                          |          |
|    3 | Read-only                   | Linux                                                    | Install service/udev policy; scan with no dock  | Exact supported VID/PID policy; empty inventory is not an error                                               |      |      |              |              |               |                   |                          |          |
|    4 | Read-only                   | Windows, Linux, macOS                                    | Discover one supported dock without media       | Stable validated identity; no-media dock remains visible                                                      |      |      |              |              |               |                   |                          |          |
|    5 | Read-only                   | Windows, Linux, macOS                                    | Insert/eject/reinsert and observe hotplug       | Monotonic arrival/removal revisions; no unexpected eject                                                      |      |      |              |              |               |                   |                          |          |
|    6 | Read-only                   | Windows, Linux, macOS                                    | Refresh complete drive and cartridge Status     | Each documented field is reported or carries an explicit unavailable reason                                   |      |      |              |              |               |                   |                          |          |
|    7 | Read-only                   | Windows, Linux, macOS                                    | Event Log, update check, and RDX System Summary | Redacted local evidence; no upload and no device mutation                                                     |      |      |              |              |               |                   |                          |          |
|    8 | Routine diagnostic          | Windows, Linux, macOS                                    | Self Test, first pass                           | Supported dock; retain exact terminal and sense/result evidence                                               |      |      |              |              |               |                   |                          |          |
|    9 | Routine diagnostic          | Windows, Linux, macOS                                    | Self Test, second pass                          | Repeat after the documented pause; compare with first pass                                                    |      |      |              |              |               |                   |                          |          |
|   10 | Routine diagnostic          | Windows, Linux, macOS                                    | LED Test                                        | Observe LED transitions; record cleanup/restoration separately                                                |      |      |              |              |               |                   |                          |          |
|   11 | Routine diagnostic          | Windows, Linux, macOS                                    | Write/Read Test                                 | Disposable formatted writable media with free space; verify test-file deletion                                |      |      |              |              |               |                   |                          |          |
|   12 | Routine                     | Windows, Linux, macOS                                    | Safe eject                                      | Mounted disposable media; host flush/unmount before exact-target departure                                    |      |      |              |              |               |                   |                          |          |
|   13 | Configuration               | Windows                                                  | Set and reset persistent drive letter           | Supported USB3 dock, no media, available letter, protected endpoint                                           |      |      |              |              |               |                   |                          |          |
|   14 | Configuration               | Windows, Linux, macOS                                    | Change Fixed/Removable mode and restore         | No media; capability reported; current-mode selection is a no-op                                              |      |      |              |              |               |                   |                          |          |
|   15 | Configuration               | Windows, Linux, macOS                                    | Change SATA III mode and restore                | SATA III dock only, no media; USB must remain explicitly unavailable                                          |      |      |              |              |               |                   |                          |          |
|   16 | Critical                    | Windows, Linux, macOS                                    | Force eject                                     | Disposable media, risk acknowledged; record possible cached-data loss and readback                            |      |      |              |              |               |                   |                          |          |
|   17 | Critical                    | Supported interface for exact image                      | Firmware preflight rejection cases              | Media present, wrong family/extension, invalid/signature/downgrade cases must send no WRITE BUFFER            |      |      |              |              |               |                   |                          |          |
|   18 | Critical                    | Supported interface for exact image                      | Firmware update and reconnect                   | No media, uninterrupted power, matching verified image; retain every stage and post-update identity/revision  |      |      |              |              |               |                   |                          |          |
|   19 | Configuration / destructive | Evidence-proven platform and dock only                   | Basic access and credential lifecycle           | Exact selector/descriptor fixtures registered; create/change/enable/disable/delete and reinsertion state      |      |      |              |              |               |                   |                          |          |
|   20 | Configuration / destructive | RDX SATA III only                                        | Automatic drive/media authentication            | Evidence-proven association; temporary-slot and read-only/write options checked; delete and reinsert          |      |      |              |              |               |                   |                          |          |
|   21 | Destructive                 | Evidence-proven platform and compatible media only       | AES setup, removal, and passwordless reset      | Compatible AES media layout proven; exact identity confirmation; disposable media; recovery limits understood |      |      |              |              |               |                   |                          |          |
|   22 | Destructive                 | Windows, Linux, macOS where capability reports available | Partition and format                            | Disposable selected media, exact identity confirmation, NTFS/exFAT platform boundary, post-format rediscovery |      |      |              |              |               |                   |                          |          |

Rows 19 through 21 remain blocked while their exact security write semantics or
compatible AES media layout are evidence-incomplete. A disabled UI with the
correct reason is the expected result; it is not a successful physical
operation and does not fill an execution-evidence cell.

## Required platform and hardware coverage

Acceptance is not complete until the applicable checklist rows cover:

- a current supported x64 Windows host with the installed constrained service;
- a current supported Linux host with the installed service and exact udev
  access policy;
- a current supported macOS host, including an explicit transport-unavailable
  result when the active stack cannot expose safe pass-through;
- USB and SATA dock families available to the operator, including at least one
  USB3 dock at firmware 0283 or later for its published password-protection
  qualification and an RDX SATA III dock for SATA-only features;
- no-media, writable, physical-write-protected, credential-read-only,
  protected-locked, protected-unlocked, and insufficient-free-space states;
- disposable NTFS and exFAT media where the host operation claims support;
- a matching signed firmware image and bounded negative images for firmware
  preflight, without applying an incompatible or unsigned downgrade.

Unavailable equipment stays documented as missing coverage. It must not be
replaced with another model's result or a fixture.

## Acceptance completion gate

For each executed row, verify that the UI, Electron main process, native
service, and physical outcome agree. Primary and cleanup failures remain
separate; cancellation and completion-unknown outcomes are not converted to
success. Attach or reference redacted logs and screenshots outside this table
when useful, but keep the exact typed terminal result in the row.

The hardware acceptance gate passes only when all applicable rows contain the
required evidence, all unexpected outcomes are resolved and rerun, destructive
rows use disposable media, and an operator explicitly signs off the final
matrix. Until then, application documentation and About/Compatibility surfaces
must continue to say that physical hardware verification is pending.
