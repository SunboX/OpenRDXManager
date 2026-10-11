<!-- SPDX-FileCopyrightText: 2026 André Fiedler -->
<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->

# RDX system summary

## Overview

**Help > Support > Generate RDX System Summary** collects host and RDX-device
diagnostics and asks the user where to save:

```text
RdxSystemSummary.txt
```

The result is intended for attachment to a support request. It can collect
information from multiple discovered devices, with the UI reporting
`Collecting information from %d devices.`

## Collected sources

Reference strings and command classes show a combination of:

- Manager/driver/service versions and operating-system information;
- discovered dock identity, firmware and connection data;
- drive and cartridge status/capacity/protection information;
- encryption/password-protection state (`Encrypted`/`NOT Encrypted`);
- diagnostic results and SCSI/sense information available to the Manager.

Collection reuses the status command objects; there is no single "system
summary" SCSI opcode. Each device query returns through the normal transport,
and the host writes a text report.

## Result semantics

Saving the file is the success condition. Individual unavailable devices can
produce error/status entries while the overall report is still generated.
The exact textual ordering is version-specific; the fixed default filename
and multi-device collection behavior are proven by the Windows executable.

## Implementation details

The summary controller snapshots the discovered-device list, reports the
device count, then executes the same `Test_DockInfo`/status readers used by the
main UI for each target. Host information and installed component versions are
added before a normal file-save dialog writes `RdxSystemSummary.txt`. A failed
query is rendered as diagnostic text; it does not abort collection for the
remaining drives.

This design avoids a second privileged protocol: the summary generator is an
aggregator over existing getters and OS/version APIs.

## Protocol details

For each device the collection sequence can include:

1. TEST UNIT READY (`0x00`) for path/media state.
2. INQUIRY (`0x12`) standard/VPD for dock and cartridge identity.
3. LOG SENSE page `0x20` for drive information.
4. LOG SENSE page `0x21` for cartridge information when media is present.
5. MODE SENSE(10) pages `0x31`/`0x34` for format, operation mode and link
   configuration.
6. SECURITY PROTOCOL IN (`0xA2`, protocol `0x20`) only when protection
   capability/state must be summarized.

Each command is independent. A non-zero transport/SCSI result produces an
error/unavailable entry and collection proceeds. The output protocol is a
user-selected host text file, not a drive-side report format.

Evidence anchors: `Test_DockInfo` symbols, the `RdxSystemSummary.txt` and
`Collecting information from %d devices.` strings, and feature 02's exact
status CDBs.

## PDF-derived workflow and historical interfaces

The documented GUI route is **Help > Support > Generate RDX System Summary**.
A file chooser asks where to save `RdxSystemSummary.txt`; the manual recommends
the desktop. After saving, the Support dialog displays the selected path. The
report is intended to be attached to a support email together with symptoms,
time of occurrence, triggering activities, affected file objects, and a list
of third-party applications such as antivirus and backup software.

Windows release 0.1.0.30 added RDX media encryption status to the summary.
Release 0.1.0.28 also added a command-line function that writes an RDX system
summary in XML format. Neither supplied PDF publishes that command's option
syntax or XML schema, so the existence and output format are documented here
without inventing a switch or element layout. The GUI text-file workflow is
the interface explicitly described by the supplied manual.

Source coverage: Product Manual pp. 12 and 38; Windows 2.0.1 Release Notes
pp. 2-3.
