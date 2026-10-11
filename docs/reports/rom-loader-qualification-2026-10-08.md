<!-- SPDX-FileCopyrightText: 2026 André Fiedler -->
<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->

# ROM loader qualification — 2026-10-08

Historical report. Results and limitations apply to the described host, device and date; subsequent reports may supersede them.

Historical read-only qualification. The subsequent [native Windows recovery](windows-flash-recovery-2026-10-08.md)
programmed the selected bootstrap and verified all physical SPI bytes and both
readiness queries. The pre-programming status below describes this earlier stage.

The user entered bootloader mode and confirmed that J7 had been removed while
the receiver remained connected. Native Windows enumeration and two read-only
TI probes confirm one ROM-loader instance, healthy driver interfaces and
reported flash presence. This completes the initial ROM-access qualification.
Programming, record restoration and rollback remain unqualified; no image was
selected or written.

## Target binding

At approximately 11:27 UTC, Windows exposed one composite parent:

`USB\VID_0451&PID_926B\TUSB9260BL01`

Its HID interface `MI_00` and Flash Burner interface `MI_01` both reported
status OK and problem code 0, sharing the same parent and container. The burner
interface uses the previously staged `oem60.inf` driver. The normal receiver
`1A5A:0005` was absent from present-device enumeration.

The ROM parent's location path was:

`PCIROOT(0)#PCI(1A00)#USBROOT(0)#USB(1)#USB(2)`

This matches the retained normal receiver's Windows location property.
Binding is based on that port continuity and the user's physical transition;
`TUSB9260BL01` is a generic ROM identifier, not the unit's manufacturing serial.
No manufacturing serial or independent SPI chip identification was read through
ROM during this stage.

## Read-only probe

The pinned installed executable was:

`C:\Program Files (x86)\Texas Instruments Inc\Command Line FlashBurner\TUSB926x_CL_Burner.exe`

Version 1.3.1.0, SHA-256
`4bea39462d697550497edfcf1804640739c350a0927619a66e444e60116755f3`.

Only `/p` was supplied. Two elevated invocations, at approximately 11:28 and
11:29 UTC, produced the same output:

```text
Boot Loader Instance 0
Path: HID\VID_0451&PID_926B&MI_00\8&1DF2187B&0&0000
Flash Burner driver: Yes
Flash Present: True
```

The helper enforced one healthy parent on the expected port, both healthy
interfaces sharing that parent, the executable hash, absence of competing
device processes and a 30-second command budget. It stopped `RDXmon` for each
probe and restored it afterward. A final Windows service query confirmed
`RDXmon` Running. Final PnP enumeration still showed the same healthy ROM
interfaces.

### Exit-code interpretation

The initial unelevated launch was rejected by Windows before execution. The
first elevated wrapper did not retain the child process's exit code; its
positive stdout is retained, but its wrapper status is 1. The corrected process
capture measured CLI exit code **1**, empty stderr and the same positive stdout.
It also returned wrapper status 1 because it incorrectly assumed `/p` must
exit 0. Those original logs and statuses remain intact.

Reflection-only inspection of the exact CLI's `Program.Main` establishes why:
return local 0 is initialized to 1 at `IL_0000`–`IL_0001`; `/p` dispatches only
`PopulateDevicesList` and `PrintDevicesList` at `IL_04CC`–`IL_04D6`; without
`FirmwareSelected`, `IL_0593`–`IL_0598` branches to `IL_0765`, which returns
that unchanged local. Thus exit 1 is expected for `/p` alone in this pinned
binary. This is not a general rule that TI exit 1 means success.

An offline qualifier validates the binary hash, those IL anchors, exact
single-instance output, empty stderr, recorded exit, target port and monitor
restoration before producing `rom-probe-qualification.json` with exit 0.
Qualification is limited to ROM access and the tool's reported flash presence.

## Programming boundary and proposed next stage

The prepared private bootstrap is 61,710 bytes, SHA-256
`874b666f6c4efd75d30235e1f70aefc2d7fbeca430ebe314233d94ed12ae90a9`.
It binds 320 exact raw Manufacturing/State bytes to the retained current
snapshot. Compiled ARM emulation of record restoration has passed, including
a complete modeled SPI comparison and a matching second boot with no writes.
The candidate is hardware unvalidated and has not been supplied to the live
programmer.

Before a write, the separate procedure still needs to establish acceptance of
this exact already-formatted small image, actual erase coverage, and a usable
failure/rollback route. The installed GUI cannot accept the complete 256 KiB
backup unchanged. ROM entry does not resolve that limitation. Generic normal
application programming would not prove preservation of high-flash records.

The post-write requirements would be physical boot, exact receiver identity,
both readiness queries, full same-unit SPI readback and exact Manufacturing/
State comparison, followed by normal update verification on Windows and macOS.
TI's [FlashBurner guide, section 5.4](https://www.ti.com/lit/ug/sllu125d/sllu125d.pdf)
explains why a transfer receipt cannot establish correct flash programming.
These are pending requirements, not steps executed by this qualification.

The firmware repository's `AGENTS.md` additionally requires an explicit flash
request and a separately validated safety procedure. Reporting bootloader
entry authorizes this read-only follow-up in context; it does not satisfy those
write-stage requirements by itself.

## Evidence

Private files are beside `START_HERE.md` under
`native-windows-20261008-1/`, outside Git:

- `rom-loader-pnp-initial.json`, `rom-loader-pnp-final.json` and
  `rom-probe-service-final.json`.
- `run-rom-probe-first-attempt.ps1`, `run-rom-probe.ps1`, their launch records,
  original probe stdout/stderr, transcripts and exit files.
- `inspect-ti-cli-il.ps1`, `ti-cli-probe-il.txt`: reflection-only CLI analysis;
  no vendor method was invoked by the analysis script.
- `qualify-rom-probe.py`, `rom-probe-qualification.json` and qualifier log.
- `EVIDENCE_MANIFEST.json`: updated hashes and reverified unchanged backup files.

See the [native Windows investigation](native-windows-investigation-2026-10-08.md)
and [installed-binary audit](installed-binary-usb-recovery-audit-2026-10-08.md)
for the earlier closed-enclosure investigation. J7 entry and reported flash
presence were previously untested; the live results above supersede that
specific earlier limitation, while all programming limitations remain.
