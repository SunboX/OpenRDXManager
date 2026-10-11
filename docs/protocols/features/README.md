<!-- SPDX-FileCopyrightText: 2026 André Fiedler -->
<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->

# Vendor feature references

This directory documents each user-visible capability supplied by RDX Manager
2.0.1.54 for Windows, with the older 2.0.1.50 and symbol-bearing macOS build
used as corroborating evidence. Each document separates published behavior,
reference implementation facts, and unresolved details.

| Feature                                       | Document                                                  | Main mechanism                                                       |
| --------------------------------------------- | --------------------------------------------------------- | -------------------------------------------------------------------- |
| Drive discovery and Auto Scan                 | [01](01-drive-discovery-and-auto-scan.md)                 | OS device enumeration plus periodic refresh                          |
| Drive/cartridge status                        | [02](02-drive-and-cartridge-status.md)                    | SCSI INQUIRY, LOG SENSE, MODE SENSE and capacity commands            |
| Event logging                                 | [03](03-event-logging.md)                                 | Manager operation log with rotation                                  |
| System summary                                | [04](04-system-summary.md)                                | OS and per-device diagnostic collection                              |
| Help and update checking                      | [05](05-help-and-update-checking.md)                      | local manual plus network version check                              |
| Full-disk AES-256-XTS encryption              | [06](06-full-disk-aes-256-xts-encryption.md)              | cartridge protection commands plus Windows software-encryption layer |
| Basic password protection                     | [07](07-basic-password-protection.md)                     | cartridge password/access-control commands                           |
| Disable/enable cartridge access               | [08](08-disable-and-enable-cartridge-access.md)           | authenticate/lock session state                                      |
| Change/remove protection                      | [09](09-change-and-remove-protection.md)                  | password lifecycle and optional destructive reset                    |
| Advanced passwords and permissions            | [10](10-advanced-passwords-and-permissions.md)            | up to eight cartridge credential slots                               |
| Automatic drive/media authentication          | [11](11-automatic-drive-media-authentication.md)          | drive-generated SATA III credential association                      |
| Self Test                                     | [12](12-self-test.md)                                     | SCSI diagnostic path                                                 |
| LED Test                                      | [13](13-led-test.md)                                      | vendor diagnostic LED commands                                       |
| Write/Read Test                               | [14](14-write-read-test.md)                               | host filesystem write/read/compare/delete                            |
| Firmware update                               | [15](15-firmware-update.md)                               | validated image plus SCSI WRITE BUFFER                               |
| Set/reset drive letter                        | [16](16-set-and-reset-drive-letter.md)                    | Windows RDXmon registry mapping                                      |
| Partition and format                          | [17](17-partition-and-format-cartridge.md)                | Windows disk/volume APIs, NTFS or exFAT                              |
| Change Fixed/Removable mode                   | [18](18-change-drive-mode.md)                             | vendor RDX MODE SENSE/SELECT page                                    |
| Change SATA III speed mode                    | [19](19-change-sata-iii-mode.md)                          | vendor MODE SENSE/SELECT field                                       |
| Eject and command-line eject                  | [20](20-eject-cartridge-and-command-line.md)              | OS dismount/eject plus SCSI media control                            |
| GUI language selection                        | [21](21-gui-language-selection.md)                        | bundled Qt translations and `-l` option                              |
| Tray/background integration                   | [22](22-tray-and-background-integration.md)               | RDXmon, shell extension and Manager tray process                     |
| Installation, launch, Exit and uninstallation | [23](23-installation-launch-exit-and-uninstallation.md)   | Qt installer components, silent mode and Windows lifecycle           |
| Platform/hardware/media compatibility         | [24](24-platform-hardware-and-media-compatibility.md)     | OS matrix plus runtime product/capability gates                      |
| Support and troubleshooting                   | [25](25-support-troubleshooting-and-known-limitations.md) | logs, system summary, driver/cache limitations and release fixes     |

## Evidence convention

- **Proven** means directly present in executable code/symbols, bundled files,
  controller firmware reference, or the official bundled manual.
- **Strong inference** means multiple artifacts agree but an original source
  definition or live device trace is absent.
- **Unknown** is kept explicit. In particular, most non-firmware utilities do
  not expose every final CDB byte in the currently focused implementation review.

No script in this analysis sends SCSI commands to a device. The reusable
extractors operate on saved installer, executable and flash-image files only.

Every numbered feature document includes explicit **Implementation
details** and **Protocol details** sections. Protocol tables identify exact
CDBs, directions, page/selector fields and expected result handling where the
binary proves them. Host-only features identify their OS/IPC/file/network
protocol instead. Stripped vendor selector names and nondeterministic OS block
traffic remain explicitly marked rather than guessed.

These additions use the Windows Manager 2.0.1.54 and macOS Manager 0.1.0.1
implementation references. Source identities and hashes are retained in the
local research inventories; the
[firmware protocol reference](../firmware-update.md)
summarizes the supporting material and verification limits.

## Bundled PDF coverage

The user-visible procedures, defaults, warnings, compatibility qualifications,
troubleshooting guidance and complete minor/major release-history bullets from
all four supplied PDFs are distributed across the relevant numbered feature
files. `PDF-derived` sections are published/vendor behavior; they do not
replace or weaken the separate implementation/protocol evidence.

- [RDX Manager Product Manual Rev F](../../../original-inputs/RDX+Manager+Manual+1022447+Rev+F.pdf)
- [RDX Manager for Windows 2.0.1 Release Notes](../../../original-inputs/RDX+Manager+2.0.1+Release+Notes.pdf)
- [RDX USB3 Firmware 0283 Release Notes](../../../original-inputs/RDX+Dock+USB+3.0+FW_0283+Release+Notes.pdf)
- [RDX Manager for Mac 0.1.0.1 Release Notes](../../../original-inputs/RDX+Manager+for+Mac+Release+Notes+ver.+0.1.0.1.pdf)
