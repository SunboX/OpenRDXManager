<!-- SPDX-FileCopyrightText: 2026 André Fiedler -->
<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->

# Tray, service and background integration

## User-visible behavior

RDX Manager runs in the Windows notification area, provides the Management
pop-up, tracks drive/media changes and keeps supporting integration available
without the full window remaining open. Installer options include normal and
silent deployment (`isSilent=true` in the bundled installer flow).

## Bundled components

The installer does more than place `RDXManager.exe`. Reference payloads include
or reference:

- RDXmon service/driver components for device/media monitoring and persistent
  drive-letter handling;
- a shell integration/extension for RDX actions;
- `RdxCmdLine.exe` for scripted scan/eject;
- Dokan and `RDXEncrypt` components used by software-encrypted volumes;
- Qt runtime/plugins/translations and OpenSSL libraries;
- local help/manual, uninstaller and installer support files.

The exact file inventory and hashes remain in `analysis/extracted/`, staged
payload indexes and `analysis/SHA256SUMS.txt`.

## Internal boundaries

The tray process owns UI, periodic scan and operation orchestration. RDXmon and
the OS storage stack handle lower-level arrival/mount/drive-letter events.
Privileged changes require administrative context. On macOS, the analogous
old build uses a signed privileged helper and SCSI kernel extension instead of
the Windows RDXmon/Dokan stack.

Background integration itself sends no unique CDB; it discovers state changes
and invokes the same per-feature command classes documented in this directory.

## Implementation details

The Manager tray process owns Qt UI/actions and periodically pushes discovery
and selected-device state. `RDXmon.exe` is a separate background component for
device/media events, drive-letter policy and service-side operations. Qt Core,
Network and Remote Objects libraries in the Eject payload provide the IPC
framework; UI strings such as `verify_Dokan_install` and
`dokanInstallStatusChanged` show Manager/service state exchange. Dokan and
`RDXEncrypt` participate only for software-encrypted mounts.

On macOS the privilege boundary is explicit XPC/Authorization Services. The
helper validates the `com.tandbergdata.rdx.sendScsiCommand` right, opens
`/dev/RDXDisk%ld` and invokes private driver ioctl `0xC0086102`. Related ioctls
`0xC0086101` and `0xC0086104` query driver and device/mount state.

## Protocol details

There are three distinct protocol layers:

| Layer                                  | Mechanism                                        | Payload/result                                                |
| -------------------------------------- | ------------------------------------------------ | ------------------------------------------------------------- |
| Manager ↔ Windows background component | Qt Remote Objects/service calls                  | state/action messages; exact generated schema not established |
| Manager ↔ macOS helper                 | XPC dictionary plus Authorization external form  | command, `sg_io_hdr`, data/sense and status reply             |
| helper/Manager ↔ device                | Windows SCSI pass-through or macOS private ioctl | CDB, direction, data, sense, transport status                 |

Mac `sg_io_hdr` direction values are `-2` data-out, `-3` data-in and `-1` no
data. Windows uses IOCTL `0x4D014` for direct data and `0x4D004` for buffered/
no-data commands. Clean result maps to `0`, OS/ioctl failure to `3`, and SCSI
status/sense failure to `4`. Background integration selects and transports a
feature command; it does not define a fourth drive-side opcode.

Evidence anchors: installer component inventory in
`../firmware-update.md`, Mac helper-focused algorithm outline,
and Windows Qt Remote Objects/Dokan strings.

## PDF-derived background behavior and release history

RDX Manager is launched from its installed desktop/Start-menu entry and may
remain available through its notification-area integration. The main Drive
List and the per-drive Management pop-up cannot be operated simultaneously;
while a Utility operation is running, the user cannot start another utility,
switch tabs, or close the pop-up. Attempting to close it produces a warning.

Relevant background-component changes documented by the release notes are:

- version 2.0.0 made RDXmon enforce the USB3 dock's persistent drive letter
  when Windows tries to reassign it;
- version 2.0.0 fixed a Windows timer wraparound after 24.8 days of continuous
  RDXmon operation that could eject newly inserted media after a few seconds;
- version 0.1.0.25 automatically changed USB-device removal policy to
  **Optimize for Performance** / **Better Performance**;
- versions 0.1.0.25 and 0.1.0.30 improved RDXmon event logging;
- version 0.1.0.40 improved Fixed-Disk Mode behavior and uninstall handling;
- Mac 0.1.0.1 fixed intermittent sleep-time cartridge ejection and spurious
  `Disk Not Ejected Properly` messages while the Mac slept.

These are host/service lifecycle behaviors. They select or coordinate existing
device operations and do not define a new SCSI CDB.

Source coverage: Product Manual pp. 10-14 and 31; Windows 2.0.1 Release Notes
pp. 1-3; Mac 0.1.0.1 Release Notes p. 1.
