<!-- SPDX-FileCopyrightText: 2026 André Fiedler -->
<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->

# Support, troubleshooting and known limitations

## Recommended diagnostic order

The manual recommends checking **Help > Check for Updates** before other
troubleshooting so Manager and dock firmware are current for the applicable
product. Event Logging should be enabled when an operational failure needs to
be captured, and **Help > Support** generates the system summary described in
feature 04.

For a support request, save `RdxSystemSummary.txt` (the manual recommends the
desktop), attach it, and include:

- the symptoms;
- when the issue occurred;
- activities that trigger it;
- affected file objects;
- installed third-party applications, especially antivirus and backup tools.

The Rev F manual prints these contacts:

```text
EMEA:     supportEMEA@overlandtandberg.com
APAC:     supportEMEA@overlandtandberg.com
Americas: supportUS@overlandtandberg.com
```

APAC and EMEA are deliberately reproduced exactly as printed.

## Cannot write to a cartridge

First check the physical write-protect tab and whether the authenticated
encryption/password credential is read-only. A Write/Read Test additionally
needs formatted media and free space. Host handles, dismount failures or a
read-only filesystem/driver path can also block formatting or test writes.

## Read-only media on SATA I/SATA III

The manual records a chipset/driver limitation in which some Windows systems
using Microsoft SATA drivers cannot read an RDX cartridge in read-only mode on
SATA I or SATA III docks. Read/write cartridges operate normally, but media
can become unreadable when either the physical write-protect tab is set or a
read-only encryption password is used.

The suggested remedy is a motherboard/chipset-vendor SATA driver. The latest
version reported as tested by the manual is Intel Enterprise driver 4.3,
`13.1.0.1058`. Installing an incorrect SATA driver can prevent Windows from
booting, so the manual advises backing up data and proceeding carefully.

Its recommended update path is Device Manager, then the applicable **IDE ATA /
ATAPI controllers** or enterprise **Storage controller**, controller
properties, **Update Driver**, and **Browse my computer for driver software**.
For a first-time upgrade, supply a location containing only one candidate and
never force an incompatible load. To switch among already loaded Microsoft/
Intel drivers, use **Let me pick from a list**; `Standard SATA AHCI Controller`
is the default Microsoft entry described by the manual.

## Performance and cache-policy qualification

Firmware 0278's shutdown cache-synchronization fix prevents data loss but may
slow Windows read/write work involving files smaller than 10 MB. Its bulletin
suggests **Optimize for Performance** / **Better Performance** instead of
Quick Removal. That policy increases the importance of flush/safe-eject
discipline. Firmware 0283 added WRITE(FUA) support after 0278 began advertising
write cache; without it, certain Windows FUA requests generated Application-log
disk warnings.

## Historical issues documented as fixed

The PDFs preserve these smaller version-specific fixes, useful when diagnosing
an older installation:

- empty Drive List now disables **Manage RDX Drive** (Windows 2.0.1);
- RDXmon no longer ejects newly inserted media after its Windows timer runs
  continuously for 24.8 days (2.0.0);
- rapid repeated manual scans no longer crash Manager (0.1.0.40);
- SATA III mode communication, Fixed-Disk operation, non-admin CLI behavior and
  uninstall were improved (0.1.0.40);
- Japanese-mode firmware updating and translations were fixed (0.1.0.33);
- installer failures report better messages, intermittent eject was fixed,
  Drive Policy displays, Encryption cannot close mid-operation, and Explorer
  eject no longer produces an Event Viewer warning (0.1.0.28);
- software-encryption MBR partitioning ensures a non-zero disk signature
  (0.1.0.30);
- Mac 0.1.0.1 no longer intermittently ejects during sleep or reports false
  `Disk Not Ejected Properly` messages during sleep;
- firmware 0227/0278/0283 eject, LED, fan, spin-up, load-counter, power-cycle,
  cache and post-update-detection fixes are itemized in feature 15.

## Firmware-update failure

Do not power off during an update and remove the cartridge first. Manager
validates product/image compatibility before transfer. If the update fails,
the manual says to rerun it immediately. A signature failure on signed
firmware, invalid product image, transport error or missing reconnect must not
be treated as a successful update; exact senses/results are in feature 15.

## Implementation details

Support diagnosis aggregates host text logs, OS/service state, system-summary
queries, Manager UI messages, SCSI status/sense, and optional Test-tab results.
There is no privileged "send support report" device command: the user saves the
report and emails it. Driver replacement and cache/removal policy changes are
Windows administrative operations outside Manager's SCSI transport.

## Protocol details

The diagnostic data path is:

```text
feature operation -> OS error and/or SCSI result/sense -> Event Log
device status commands + host/component versions -> RdxSystemSummary.txt
user -> attach report and context -> support email
```

Troubleshooting actions then reuse existing protocols: update checking uses
HTTP(S), tests use feature 12-14 paths, firmware uses WRITE BUFFER, and safe
eject uses the OS plus feature-20 SCSI coordination. The support workflow adds
no new CDB or device return value.

Source coverage: Product Manual pp. 12 and 35-38; Windows 2.0.1 Release Notes
pp. 1-3; USB3 Firmware 0283 Release Notes pp. 1-2; Mac 0.1.0.1 Release Notes
p. 1.

Bundled sources: [Product Manual](../../../original-inputs/RDX+Manager+Manual+1022447+Rev+F.pdf), [Windows 2.0.1 Release Notes](../../../original-inputs/RDX+Manager+2.0.1+Release+Notes.pdf), [USB3 Firmware 0283 Release Notes](../../../original-inputs/RDX+Dock+USB+3.0+FW_0283+Release+Notes.pdf), and [Mac 0.1.0.1 Release Notes](../../../original-inputs/RDX+Manager+for+Mac+Release+Notes+ver.+0.1.0.1.pdf).
