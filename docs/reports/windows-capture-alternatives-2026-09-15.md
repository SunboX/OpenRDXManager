<!-- SPDX-FileCopyrightText: 2026 André Fiedler -->
<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->

# Windows capture alternatives — 2026-09-15

Historical report. Results and limitations apply to the described host, device and date; subsequent reports may supersede them.

Result: existing storage logs provide some real CDB bytes, but **no retained
firmware-failure command was recovered**. USBSTOR WPP decoding could not be
qualified with the installed tools and matching public symbols. This pass did
not start another capture, install a driver, attach a debugger, change the app,
reset the dock or initiate an update.

The [offline receiver review](windows-receiver-offline-review-2026-09-15.md) and
[USB capture results](windows-usb-trace-result-2026-09-15.md) remain applicable.

## Already-enabled ClassPnP log

Local `Get-WinEvent -ListProvider Microsoft-Windows-StorDiag` metadata defines
event 507 with `CdbByteCount`, `CdbBytes`, SCSI/SRB status and sense fields.
`Microsoft-Windows-Storage-ClassPnP/Operational` was already enabled; no log
configuration was changed. Microsoft documents this channel's firmware error
records and warns that their accuracy depends on the reporting driver:
[Troubleshooting drive firmware updates](https://learn.microsoft.com/en-us/windows-server/storage/troubleshoot-firmware-update).

At the first retained-record check, the oldest event was record 290505, dated
**2026-09-15 14:44:40.0713537 UTC**. The known firmware failure occurred around
14:29 UTC. An explicit event-507 query for 14:28–14:31 UTC returned zero records.
Only the current ClassPnP Operational EVTX was found in the standard event-log
directory; no ClassPnP archive was listed. The current log cannot establish what
the earlier request contained, or whether it was logged before retention rolled.

A separate bounded query of the latest 300 event-507 records matched the selected
dock's vendor/model and serial privately. These records span
15:06:26.7508667–15:07:43.2913994 UTC:

| Count | CDB bytes              | Reported CDB length | Sense key / ASC / ASCQ |
| ----- | ---------------------- | ------------------- | ---------------------- |
| 225   | `000000000000`         | 6                   | `02 / 3A / 00`         |
| 75    | `25000000000000000000` | 10                  | `02 / 3A / 00`         |

No `3B` firmware command occurs in that sample. The existing requests were not
initiated by this investigation; the log evidence does not identify their
originating application. Neither repeating these responses nor reading their
headers reproduces a firmware rejection. Raw identity fields were not copied
into this report or sent to a web service.

Coverage is an important limitation. In Microsoft's current
[ClassPnP driver sample](https://github.com/microsoft/Windows-driver-samples/blob/main/storage/class/classpnp/src/class.c),
`ClassDeviceControl` handles SCSI pass-through IOCTLs at lines 6697–6749 by
forwarding to the lower driver. The Manager uses `IOCTL_SCSI_PASS_THROUGH_DIRECT`
in `native/rdx-service/windows-native/src/native.rs:737`. The sample is not proof
of the installed binary's implementation, but its distinct forwarding path is
a reason **not to infer pass-through coverage** from ordinary ClassPnP CDB logs.

## USB storage driver's WPP provider

`logman query providers` identifies `USB Storage Driver Tracing Provider`, GUID
`72FB9358-A9B3-41E0-AE41-E8DECA41E3A8`. Its local metadata includes IOCTL flag
`0x10` and read/write flag `0x8`. Registration alone does not prove useful CDB
events or a working decoder. This provider was not enabled in this pass.

The already-installed SDK includes ARM64 `tracepdb.exe` and `tracefmt.exe`
10.0.22621.3233. Microsoft describes extracting WPP formatting instructions with
[Tracepdb](https://learn.microsoft.com/en-us/windows-hardware/drivers/devtest/tracepdb)
and notes that no TMF is produced when a PDB lacks such instructions in
[Tracepdb commands](https://learn.microsoft.com/en-us/windows-hardware/drivers/devtest/tracepdb-commands).

Read-only `dumpbin /headers` on the installed `USBSTOR.SYS` showed ARM64 and RSDS
PDB identity `2C992DDD-5C04-C1CA-F9A5-AD839D93D89D`, age 1, `usbstor.pdb`.
Driver file version: 10.0.26100.1. Driver SHA-256:
`16a8aa269ce72b2475876cf509bda949cd7b6bd096919c966909039e82db9757`.

The first Tracepdb image/symbol-server attempt reported a missing `symsrv.dll`,
despite returning exit 0. It produced no TMFs. To separate that tool dependency
from symbol availability, the matching public PDB was downloaded directly from
Microsoft's symbol server using the observed GUID/age, not an unrelated build.
No driver or executable was downloaded or installed.

- Symbol URL: `https://msdl.microsoft.com/download/symbols/usbstor.pdb/2C992DDD5C04C1CAF9A5AD839D93D89D1/usbstor.pdb`
- Downloaded length: 167,936 bytes.
- SHA-256: `6b71b7e6cd5fe5c2759f83bb5de84fa3f69b093c56a3b6feeac817d6a5e6c5e4`.
- Direct `tracepdb -f <pdb> -p <fresh-tmf-directory> -v`: exit 1,
  reported **No Trace entries found**, zero generated TMF files.

The PDB and empty TMF directory remain under the local Windows staging root at
`usbstor-symbol-review-96ee6d4e/`. This is an offline metadata result, not proof
that the driver emits no trace events. No undecodable live trace was started.

## Other routes and proposed next scope

USBPcap/dumpcap were not found on PATH, no USBPcap/Npcap driver was listed by the
driver inventory, and no Wireshark/USBPcap directory was found in the checked
Program Files location. USBPcap's upstream
[Windows ARM64 support request](https://github.com/desowin/usbpcap/issues/128)
remains open. No compatible capture-driver route has been qualified here.
Debugger attachment, driver replacement and moving the dock to another host
were not attempted.

The next controllable observation point is the Manager's native SPTI boundary:
the assembled header immediately before `DeviceIoControl`, and bounded completion
fields immediately after it. This would require a separately approved app change
and restart. It could establish host-submitted fields, lengths and decoded sense;
it would **not** establish the USB CBW, physical-wire bytes or receiver state.

Proposed constraints: opt-in and local-only; narrow command allowlist; no payload,
serial, path, key or raw memory logging; bounded record count/size; deterministic
tests for permitted and rejected fields; preserve operation locking, stop/retry
policy, manufacturing checks and activation gates. First qualification would use
an ordinary read-only refresh. A firmware attempt remains a separate decision.

No application, native or firmware source changed in this investigation. No
successful firmware update or confirmed root cause is claimed.
`npm run format:check` passed on the shared checkout with the existing Windows
Prettier shim and PowerShell script shell; docs are excluded by that script.
Application tests and smoke were not rerun for this documentation-only change.
