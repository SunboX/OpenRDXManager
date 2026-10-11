<!-- SPDX-FileCopyrightText: 2026 André Fiedler -->
<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->

# Windows USB trace result — 2026-09-15

Historical report. Results and limitations apply to the described host, device and date; subsequent reports may supersede them.

Result: capture and decoding succeeded, but the command-byte qualification gate
did not pass. No firmware attempt is authorized by this result.

## Scope and app state

The existing staged Manager was reopened after process and window inventories
found it closed. Its normal `npm run smoke` passed with the renderer mounted,
native service ready and `hardware=true`; the subsequent normal `npm start`
also reported native hardware readiness. The staged native binary SHA-256 was
`8ac797971be7a346493f071333a3142c2298658cb5b15b33ad739ecab1775df2`.
This is the existing staged application, not proof that the later source-only
retry/diagnostic changes are loaded.

The subsequent user-supplied failure screenshot and private log show a separate
firmware attempt at 14:29:19–14:29:21 UTC. It failed after entering transfer;
no finalizing lifecycle event was recorded. The capture below started later and
does not contain that attempt. The assistant did not initiate that firmware
operation. The later Status screenshot reports Good, no media, USB 3 and
firmware 1.10. Recognition and a reported revision do not verify an update.

## Capture evidence

- Host: Windows 11 ARM64 in Parallels; selected dock on the guest USBXHCI path.
- Collector: `OpenRDX-USB-462f811f-6a32-4ce7-8290-df7c2e2ae65d`.
- Capture helper start/stop: **14:32:02.203–14:32:57.810 UTC**.
- USBXHCI and UCX: level 5, `0x81` (Default + PartialDataBusTrace).
  USBHUB3: level 5, `0x1` (Default).
- Non-circular binary capture, 64 MiB limit, no append/overwrite, 60-second
  collector limit and an independent helper stop after approximately 55 seconds.
- Original ETL: 20,840,448 bytes; 11,891 decoded events; zero reported lost events
  and buffers. `tracerpt` exited 0. Original and decode-copy hashes match:
  `c9094db47e22f8a26789e63da94324c3264f59421e7eb34c0bfd3e1e9d8507a1`.
- Stop returned 0; the elevated session query then reported collector not found;
  deletion of this collector's definition returned 0. Raw files were retained.
  A later unprivileged global session query returned access denied; it is not
  substituted for the elevated cleanup evidence.
- No new `status-refresh` operation appeared in the inspected Manager log during
  this interval. Therefore a manually triggered refresh is not claimed.

The helper was passive: it submitted no device command, reset or power cycle.
Traffic from the already-running host/application was still present. Raw ETL,
decoded XML, private identity metadata, launch output and collector output remain
in the local staging root under
`usb-trace/readonly-462f811f-6a32-4ce7-8290-df7c2e2ae65d/`.
The directory has a protected DACL limited to the current user, Administrators
and SYSTEM; the decoded XML inherited those three entries. Raw USB evidence was
not copied into the shared checkout or uploaded.

## What the trace establishes

USBHUB3 rundown identifies the selected vendor/product/device identity on port 11. Its device handle matches UCX rundown and transfer records. The native PnP
inventory independently reported that port. This is target association at the
guest USB boundary, not a physical-wire capture.

For that device, UCX records 3,185 bulk transfer starts and 3,185 completions.
Among the completions are 988 successful 31-byte OUT transfers and 988 successful
13-byte IN transfers. Those lengths are consistent with BOT command/status
wrappers, but lengths alone do not prove their contents or matching tags.

There are also 495 zero-length IN completions with URB status `0xC0000004`.
Microsoft identifies that USB status as `USBD_STATUS_STALL_PID`; see its
[ETW troubleshooting example](https://learn.microsoft.com/en-us/windows-hardware/drivers/usbcon/case-study--troubleshooting-an-unknown-usb-device-by-using-etw-and-netmon).
The trace does not identify the associated SCSI command or establish that these
stalls caused the earlier firmware rejection. USB status must not be confused
with an identically numbered NTSTATUS or interpreted as SCSI sense.

## Why qualification failed

The decoded bulk records contain URB headers, buffer addresses, transfer lengths,
flags and completion statuses, but no captured buffer payload. A field inventory
found no transfer-payload byte array, and a raw ETL scan found no literal BOT CBW
or CSW signatures. The raw scan is supplementary, not a general ETL decoder.
No complete CBW, CDB, CSW tag or sense response was recovered. The prior
`firmware-command-invalid` therefore remains undiagnosed at command-field level.

Microsoft documents limited payload for PartialDataBusTrace and up to 4 KiB for
FullDataBusTrace, with an MDL-chain limitation. That documentation does not prove
payload availability on this host; see
[USB trace capture filters](https://learn.microsoft.com/en-us/windows-hardware/drivers/usbcon/how-to-capture-a-usb-event-trace).

## Proposed next gate after the first capture

A separately approved, short **read-only** full-payload qualification capture is
the next candidate. Review its increased privacy scope first because provider-wide
USB tracing may include other devices. Coordinate the Refresh click before
starting the bounded window. Preserve the first capture and use a new private
directory and collector. No flashing is needed to test capture capability.

If complete target-associated command/status bytes still cannot be recovered,
stop and evaluate a different validated capture point or decoding method. Do not
guess protocol variants, reset the dock or attempt another firmware update.

## User-approved full-payload follow-up

The user authorized one fuller, read-only capture after the provider-wide privacy
scope was explained. The existing application was left running. No firmware
attempt, reset, power cycle or driver installation was initiated.

The second collector used Default + FullDataBusTrace (`0x101`) at level 5 for
USBXHCI, UCX and USBHUB3. Its saved configuration confirms all three masks. The
same size, duration, cleanup and private-directory controls were retained; a new
collector and directory preserved all first-run evidence.

- Collector: `OpenRDX-USB-526d6ac4-9d97-4f15-98d8-6b0227e0dfa2`.
- Helper start/stop: **14:42:39.582–14:43:35.983 UTC**.
- Original ETL: **22,151,168 bytes**, **12,503 events**, zero reported lost events
  and buffers. `tracerpt` exited 0. Original and decode-copy hashes match:
  `26b14b4134c80af7357388d6794b37f64f3f7a1e177abce782d687a57f78619c`.
- The bounded timer stopped collection. Stop and collector-definition deletion
  returned 0; the elevated post-stop query reported collector not found.
  The later `stop.request` marker did not cause that already-completed stop.
- The user confirmed one Refresh click. No new status-refresh lifecycle entry
  was found in the inspected log, so its exact timing and completion are not
  independently correlated to this trace. Absence of that entry alone does not
  establish that the user did not click or that refreshing failed.
- Raw files remain under the local staging root's
  `usb-trace/readonly-full-526d6ac4-9d97-4f15-98d8-6b0227e0dfa2/` directory.
  Its protected ACL and the decoded XML's inherited entries are limited to the
  current user, Administrators and SYSTEM. No raw capture was uploaded.

Rundown again associates the selected dock with guest port 11 and the matching
UCX device handle. Its completion records include 982 successful 31-byte OUT and
982 successful 13-byte IN transfers, plus 495 zero-length IN completions with
USB status `0xC0000004`. These are transfer-level observations, not recovered
SCSI commands, matched CBW/CSW tags, or the cause of the earlier firmware failure.
Other USB-device events were also present and were excluded from those counts.

The full XML field inventory still contains URB buffer addresses, lengths and
statuses without a transfer-payload array. A supplementary raw scan again found
no literal CBW or CSW signatures. No complete command, status wrapper or sense
response was recovered. **Full-payload qualification also did not pass.**

There is no basis for a firmware retry from either capture. Further work should
first validate a different capture/decoding route or examine the receiver's
rejection logic offline. Another hardware capture, driver change or firmware
attempt is not automatically authorized. The app and powered dock are left as-is.

The subsequent [offline receiver review](windows-receiver-offline-review-2026-09-15.md)
passed 27 RAM-only checks of the expected command sequence. It does not recover
the missing hardware command bytes or establish a root cause.
