<!-- SPDX-FileCopyrightText: 2026 André Fiedler -->
<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->

# Drive discovery and Auto Scan

## Overview

RDX Manager enumerates supported RDX docks, displays them in a drive list and
updates the selected drive's status. With **Tools > Auto Scan** enabled it
rescans once per second, so insertion/removal and drive-state changes appear
without a manual refresh. Auto Scan is enabled by default in the documented
Windows build.

The tray/menu entry opens the Management pop-up for the selected device. If
more than one drive is attached, the drive selector chooses which dock the
Status, Encryption, Test and Utility tabs operate on.

## Implementation overview

Windows code contains device-discovery, serial-number and drive-list refresh
paths and imports SetupAPI/Configuration Manager and storage-device APIs. The
macOS build uses IOKit and its privileged helper to locate the underlying
SCSI device. Both ultimately create a `prostor::ScsiDevice`, which is the
shared transport object for subsequent command classes.

Discovery is OS enumeration, not a broadcast sent to all disks. Candidate
devices are identified, opened and queried; the Manager then uses INQUIRY and
RDX-specific information pages to populate stable identity and capability
data. Failed opens or commands leave a drive unavailable rather than treating
an arbitrary removable disk as RDX.

## Timing and results

- Auto Scan interval: one second, stated in the bundled manual.
- Success: discovered device appears and its tabs become applicable.
- No media: the dock remains listed; cartridge status is `No Media` and
  cartridge-only fields are blank.
- Removal/transport failure: refresh removes or marks the device unavailable.

Exact Windows device-interface GUID filtering is not yet specified in a
standalone source file. Evidence is in the Windows binary strings/imports, the
macOS symbols, and manual pages 13–14.

## Implementation details

On Windows the enumeration layer uses `SetupDiGetClassDevsW`,
`SetupDiEnumDeviceInfo`, `SetupDiGetDeviceRegistryPropertyW` and
`SetupDiGetDevicePropertyW`. A selected disk is normalized to
`\\.\PhysicalDriveN` and opened with `CreateFileW` using read/write access and
read/write sharing. `RDXmon` supplies media-arrival/background integration;
the Manager process owns the one-second refresh timer and UI model.

On macOS, IOKit discovery identifies the RDX storage service, while privileged
SCSI operations are packaged by the GUI and sent over XPC to
`com.tandbergdata.rdx.HelperTool`. The helper opens `/dev/RDXDisk%ld`, exposed
by `RDXMonitor.kext`.

## Protocol details

Discovery itself is an operating-system device-interface protocol. After a
candidate is opened, the Manager confirms and populates it with this command
family:

| Purpose                      | Command                                                          | Direction |
| ---------------------------- | ---------------------------------------------------------------- | --------- |
| confirm SCSI target/identity | INQUIRY `0x12`, standard and selected VPD pages                  | data-in   |
| detect ready/no-media state  | TEST UNIT READY `00 00 00 00 00 00`                              | none      |
| drive-specific status        | LOG SENSE `0x4D`, page `0x20`                                    | data-in   |
| cartridge-specific status    | LOG SENSE `0x4D`, page `0x21`                                    | data-in   |
| RDX mode/capabilities        | MODE SENSE(10) `0x5A`, pages `0x31`, `0x33`, `0x34` as supported | data-in   |

Windows sends data commands with `IOCTL_SCSI_PASS_THROUGH_DIRECT` (`0x4D014`)
and no-data/buffered commands with `IOCTL_SCSI_PASS_THROUGH` (`0x4D004`). The
Manager transport result is `0` for clean completion, `3` for host/IOCTL or
transfer failure, and `4` for non-zero SCSI status with sense data. Only a
candidate whose identity/capability replies are consistent with RDX is added
as a manageable dock.

Evidence anchors: Windows Manager 2.0.1.54 and macOS Manager 0.1.0.1
implementation references, and the transport section of
[the firmware protocol reference](../firmware-update.md).

## PDF-derived UI and release details

The Drive List is a table with one row per discovered dock. The manual names
these columns: drive letter, drive vendor, drive type, drive status, cartridge
vendor, cartridge size, cartridge status, and Data Access. Its two action
buttons are **Scan for RDX Drives** and **Manage RDX Drive**. A single click on
either a row or **Manage RDX Drive** opens the four-tab Management pop-up for
that dock. **File > Exit** closes Manager; **Tools > Auto Scan** toggles the
once-per-second scan and **Tools > Event Logging** controls host logging.

The manual describes Auto Scan as scanning the "network." Implementation review
shows OS device enumeration, so that phrase means the Manager's discoverable
device set rather than a proven IP broadcast protocol. Manual scanning and
Auto Scan share the same enumeration path.

Historical Windows changes relevant to discovery are:

- version 2.0.1 disables **Manage RDX Drive** when the drive list is empty;
- version 0.1.0.40 fixed a crash caused by clicking **Scan for RDX Drives** in
  rapid succession;
- version 0.1.0.25 renamed the Drive List's `Cartridge Model` field to
  `Cartridge Size`.

Source coverage: Product Manual pp. 11-14; Windows 2.0.1 Release Notes pp. 1-3.
