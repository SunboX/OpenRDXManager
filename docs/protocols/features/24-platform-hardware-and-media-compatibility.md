<!-- SPDX-FileCopyrightText: 2026 André Fiedler -->
<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->

# Platform, hardware and media compatibility

## Compatibility purpose

RDX Manager gates features using the host OS, dock family, interface,
firmware/capability replies, media state and privileges. The PDFs contain both
a 2020 Windows 2.0.1 release matrix and a later Rev F manual summary; this file
preserves their exact scope instead of merging differences silently.

## Windows 2.0.1 release matrix

The 2020 release bulletin lists:

| Operating system                   | Architecture/qualification     |
| ---------------------------------- | ------------------------------ |
| Windows 7                          | x86 and x64, all service packs |
| Windows 8                          | x86 and x64, all service packs |
| Windows 8.1                        | x86 and x64, all service packs |
| Windows 10                         | x86 and x64, all editions      |
| Windows Small Business Server 2011 | x64, all editions              |
| Windows Server 2012                | x64, all editions              |
| Windows Server 2012 R2             | x64, all editions              |
| Windows Server 2016                | all editions                   |
| Windows Server 2019                | all editions                   |

The Rev F manual's summary instead names Windows 7, 8, 10, Server 2008, Server
2012, Server 2012 R2, Server 2016 and Server 2019. It omits Windows 8.1/SBS
2011 from that short list but includes Server 2008. This documentation
difference is retained; it should not be interpreted as proof that an unlisted
modern or historical OS was tested with the supplied 2.0.1.54 installer.

## macOS compatibility

The manual lists OS X 10.11 through 10.13 for Apple users. The supplied Mac
artifact is Manager 0.1.0.1 with an older kernel-extension/privileged-helper
architecture. Its release note fixes sleep-related eject behavior but does not
publish a broader OS matrix. Modern macOS compatibility is therefore not
claimed.

## RDX model and cartridge scope

Windows Manager 2.0.1 is documented as working with all RDX QuikStor and RDX
QuikStation models, all Standard and OEM cartridge capacities, all cartridge
generations, and previous USB and SATA drive models. Individual features still
have narrower gates:

| Feature                              | Published qualification                      |
| ------------------------------------ | -------------------------------------------- |
| Persistent Set Drive Letter          | USB3 dock; Windows 7 or later; media removed |
| USB3 volume password protection      | dock firmware 0283 or later                  |
| Protected-media interchange          | compatible with RDX SATA III                 |
| Automatic drive/media authentication | RDX SATA III                                 |
| Change SATA III Mode                 | SATA III only; disabled for USB              |
| Change Fixed/Removable mode          | only when dock reports support               |
| Windows quick format                 | Windows 7 or later; NTFS/exFAT               |
| Firmware image                       | `.BIP` for USB2/SATA1; `.BIN` for USB3/SATA3 |

The firmware 0283 bulletin specifically applies to USB3 Internal, USB3
External and USB3+ External QuikStor models. Its password-protection support
works in both Fixed-Disk and Removable-Disk modes.

## Privilege and media-state gates

Administrative rights are documented for installation, configuration,
licensing and updating. The CLI eject appendix also requests administrator
rights, although Windows 0.1.0.40 reports improved non-admin CLI functionality
without specifying its exact boundary.

Firmware update, persistent drive-letter selection, Fixed/Removable mode and
SATA III mode require no inserted cartridge. Formatting and Write/Read Test
require inserted media; the latter additionally requires a formatted,
writable cartridge with free space. Protection-management controls require an
authenticated session when access is disabled.

## Implementation details

Host compatibility begins at installer/OS checks. At runtime Manager enumerates
the dock, reads INQUIRY identity plus vendor LOG/MODE pages, and exposes only
controls supported by the reported product/capability/state. This layered
gating explains why an all-model Manager release does not make every control
available on every model.

The exact current support status of operating systems newer than those PDFs is
outside the supplied evidence. The matrix records vendor claims for these
artifacts, not an independent live certification.

## Protocol details

Compatibility discovery uses existing commands rather than a single feature
CDB:

```text
OS/installer checks
  + INQUIRY identity/revision
  + TEST UNIT READY media state
  + LOG SENSE pages 0x20/0x21
  + MODE SENSE pages 0x31/0x33/0x34
  -> enable, disable or hide feature controls
```

An unsupported product, missing vendor page or wrong media state prevents the
operation before its setter/download command is sent. Host result `3` and SCSI
result `4` retain the shared meanings documented in feature 01.

Source coverage: Product Manual pp. 8-9 and 30-37; Windows 2.0.1 Release Notes
pp. 1-3; USB3 Firmware 0283 Release Notes p. 1; Mac 0.1.0.1 Release Notes p. 1.

Bundled sources: [Product Manual](../../../original-inputs/RDX+Manager+Manual+1022447+Rev+F.pdf), [Windows 2.0.1 Release Notes](../../../original-inputs/RDX+Manager+2.0.1+Release+Notes.pdf), [USB3 Firmware 0283 Release Notes](../../../original-inputs/RDX+Dock+USB+3.0+FW_0283+Release+Notes.pdf), and [Mac 0.1.0.1 Release Notes](../../../original-inputs/RDX+Manager+for+Mac+Release+Notes+ver.+0.1.0.1.pdf).
