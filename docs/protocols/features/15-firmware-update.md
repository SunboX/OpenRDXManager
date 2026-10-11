<!-- SPDX-FileCopyrightText: 2026 André Fiedler -->
<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->

# Firmware update

## User flow

Utility **Update Firmware** accepts `.BIP` for USB2/SATA1 products or `.BIN`
for USB3/SATA3 products. Media must be ejected, including when the dock is in
Fixed Disk mode. The Manager validates product/version/header data before
enabling transfer.

## Exact modern USB3/SATA3 protocol

The reviewed Tandberg 2.83 update path uses SCSI WRITE BUFFER (`0x3B`),
mode `0x04`, buffer ID `0`, 4-KiB chunks, then a zero-length mode `0x05`
finalize command. The image is a 62,110-byte signed container whose TI boot
region maps byte-for-byte to controller flash. The controller erases/programs only flash
`0x00000..0x0FFFF`, validates the staged image, writes bytes 4 onward first,
and commits bytes 0–3 last so an interrupted image is not boot-valid.

Expected host success is SCSI GOOD for each chunk and reconnection after the
final activation command. CHECK CONDITION/sense, validation failure, timeout
or missing reconnect fails the operation. The older `.BIP` family uses legacy
WRITE BUFFER classes and a distinct header/check-enable sequence.

## Complete reference

All CDB layouts, transfer offsets/lengths, validation algorithms, return
semantics, bundled firmware, internal classes/tools and controller firmware
references are documented in
[firmware-update.md](../firmware-update.md).
Persistent manufacturing/configuration areas that survive the update are in
[high-flash-configuration.md](../high-flash-configuration.md).

## Implementation details

`TAD_FirmwareFile` validates/opens/seeks/reads the image. The TAD download test
ejects media, constructs `SCWbRDXDownloadMicrocodeTAD`, streams the entire file,
performs one full retry from offset zero on ordinary command failure, sends the
finalize command, closes/reopens the device and polls reconnect with limit 15.
Windows opens `\\.\PhysicalDriveN` and uses
`IOCTL_SCSI_PASS_THROUGH_DIRECT` (`0x4D014`) for data chunks; the zero-length
final command may use buffered `IOCTL_SCSI_PASS_THROUGH` (`0x4D004`).

Drive firmware validates rolling checks, SHA-256/RSA-1024 PKCS#1-v1.5
signature, TI record checks and flash programming. Digital-signature failure
returns sense `07/74/08`, mapped by Manager to internal error `0x63` and
`Firmware Signature Error`.

## Protocol details

CDB format:

```text
3B mm 00 oo oo oo ll ll ll 00
```

`mm=04` streams data, `mm=05` finalizes; offset and length are big-endian
24-bit values. For firmware 0283 there are 16 data CDBs and one finalize CDB.
The boundary commands are:

```text
first:       3B 04 00 00 00 00 00 10 00 00   (offset 0, length 0x1000)
last data:   3B 04 00 00 F0 00 00 02 9E 00   (offset 0xF000, length 0x029E)
finalize:    3B 05 00 00 F2 9E 00 00 00 00   (offset 0xF29E, length 0)
```

Each data command expects no response payload and SCSI GOOD. Result `3` is
host pass-through/transfer failure; `4` is SCSI/sense failure. After finalize,
temporary disconnect followed by successful rediscovery is expected.

## PDF-derived user procedure and safety rules

The manual requires the cartridge to be ejected even when the dock is in Fixed
Disk mode and warns not to power off the system during updating. **Help > Check
for Updates** can locate a release/link, but the Utility still accepts a local
image chosen in a file dialog. `.BIP` applies to USB2/SATA1 drive families and
`.BIN` to USB3/SATA3. Manager checks that the image is structurally valid and
belongs to the selected product before transfer.

After **Open**, the update runs to completion; the manual describes it as
taking a few seconds. Green progress plus a success message is the documented
UI result. If it fails, the manual instructs the user to rerun the update
immediately. That instruction is in addition to the implementation's one
automatic whole-file retry; it does not mean failed chunks are assumed good.
While the Utility runs, the user cannot run another utility, switch tabs or
close the Management pop-up.

### Signed-firmware transition and rollback restriction

Firmware 0278 introduced digitally signed images. The release notes explicitly
state that after upgrading to signed firmware, earlier unsigned firmware can
no longer be loaded. Firmware 0283 retains that signed-image path; signature
failure is represented by the `07/74/08` sense result described above. This is
a security-enforced downgrade boundary, not merely a GUI version warning.

## Bundled USB3 firmware release history

The supplied 0283 release bulletin applies to USB3 Internal, USB3 External and
USB3+ External RDX QuikStor drives. It records the following drive behavior,
which is distinct from the host download protocol.

### Firmware 0283

- added password-protection support for future host software encryption in
  both Removable-Disk and Fixed-Disk modes;
- reduced power-saving inactivity activation from 10 minutes to 5 minutes;
- fixed START STOP UNIT cartridge eject in Fixed-Disk mode;
- fixed host-software and push-button eject in Fixed-Disk mode;
- added WRITE(FUA) support. Firmware 0278 advertised write cache through MODE
  SENSE, so Windows could issue FUA writes; lack of FUA handling had generated
  Windows Application-log disk warnings.

### Firmware 0278

- introduced digitally signed firmware and the no-unsigned-downgrade rule;
- added the groundwork for software encryption on USB3 models;
- allowed eject after USB disconnect from a Mac;
- allowed eject after Windows USB disconnect when removal policy is Optimize/
  Better Performance;
- corrected the cartridge load counter so each load increments it;
- improved cache synchronization during host shutdown to prevent data loss;
- fixed Fixed-Disk mode reverting to Removable mode after a power cycle.

The cache-synchronization fix could reduce Windows performance for files under
10 MB. The bulletin recommends Optimize/Better Performance instead of Quick
Removal when performance is required, with the normal safe-removal/cache-risk
implications.

### Firmware 0227

- used 100-percent-duty-cycle actuation for every eject attempt;
- fixed an amber LED after emergency eject followed by insertion in Fixed-Disk
  mode without the power adapter;
- fixed an amber cartridge LED when USB was disconnected during loading;
- fixed cartridges failing to eject after USB was disconnected during host
  access;
- turned the fan off after emergency eject;
- fixed some SSD cartridges showing amber in a USB3+ dock;
- prevented HDD spin-up when inserted in a powered USB3+ dock without a USB
  host connection;
- prevented eject during host disk access in Fixed-Disk mode;
- lengthened cartridge-insert reset timing for slower-spinning HDDs;
- fixed failure to detect a cartridge after a firmware-update error.

Source coverage: Product Manual pp. 31-33; USB3 Firmware 0283 Release Notes
pp. 1-2; Windows 2.0.1 Release Notes p. 2.
