<!-- SPDX-FileCopyrightText: 2026 André Fiedler -->
<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->

# Windows USB trace investigation plan — 2026-09-15

Historical plan. This records the requirements and approach at the stated date; it does not establish current completion or hardware acceptance. See [verification](../verification/README.md) for recorded results.

Status at preparation: not executed. Phase A was subsequently attempted;
see [the capture qualification result](../reports/windows-usb-trace-result-2026-09-15.md).
Capture succeeded but complete command bytes were not recovered. This plan does
not authorize another flash. The dock should remain powered and connected.

## Objective

Identify the command and transfer boundary that produces
`firmware-command-invalid`, without guessing command variants or bypassing the
Manager's preservation and activation gates. The previous failure is documented
in `windows-firmware-rejection-2026-09-15.md`.

## Verified host and selected route

- Windows 11 Pro, build 26200, native ARM64, running in Parallels.
- The selected dock's current parent chain is USBSTOR, USBHUB3, then USBXHCI
  (the guest names the controller Renesas USB 3.10).
- Built-in `logman.exe`, `tracerpt.exe` and `wevtutil.exe` are available.
- USBXHCI, UCX and USBHUB3 ETW providers are registered. Local provider queries
  report `Default=0x1`, `PartialDataBusTrace=0x80`, `FullDataBusTrace=0x100`.
  The UCX manifest contains bulk/interrupt transfer event definitions.
- USBPcapCMD and dumpcap were not found on PATH or in the checked standard
  installation directories. Upstream still has an open
  [Windows ARM64 support request](https://github.com/desowin/usbpcap/issues/128).
  No USBPcap installation, test-signing, driver replacement or reboot is proposed.

Use Windows ETW first. Microsoft documents limited transfer payload capture with
PartialDataBusTrace; Default alone omits transfer events. FullDataBusTrace can
retain up to 4 KiB, but is not selected initially. Provider availability does not
prove that this VM will expose enough command bytes. See Microsoft's
[USB tracing guidance](https://learn.microsoft.com/en-us/windows-hardware/drivers/usbcon/how-to-capture-a-usb-event-trace).

## Phase A: qualify capture using reads only

This is the next proposed action and requires administrator consent to run the
trace. It does not involve firmware selection or the Update Firmware button.

1. Re-identify the selected dock and its current controller/port. Do not rely on
   `PhysicalDrive1` or a cached USB address alone. Record identity privately.
2. Confirm the Manager is idle. Arrange one ordinary read-only status refresh
   through the existing application; do not start a competing device service.
3. Create a unique `OpenRDX-USB-<run-id>` collector and new local output directory
   below the Windows staging root's `usb-trace` folder. Verify that only the
   current user, Administrators and SYSTEM have the intended access. Do not save
   raw captures to the shared Mac checkout or commit them.
4. Configure the collector as below. Start it only after every configuration
   command succeeds, then confirm that it is running. Record the UTC start time.
5. Perform one status refresh. Stop collection immediately afterwards, with a
   maximum scheduled duration of 60 seconds. Record the UTC stop time.
6. Confirm the collector is stopped and the ETL is closed. Decode a copy with
   `tracerpt` to XML plus its summary; preserve the original ETL and its SHA-256.
7. Verify target association, complete command wrappers, matching status replies
   and transfer lengths. Check trace loss and capture truncation. Do not proceed
   on an empty trace, missing target, incomplete command bytes or missing replies.

Proposed configuration, not a command already executed:

| Setting         | Value                                                     |
| --------------- | --------------------------------------------------------- |
| Providers       | USBXHCI and UCX: `0x81`; USBHUB3: `0x1`                   |
| Event level     | 5                                                         |
| Format and size | Binary, 64 MiB maximum; no append or overwrite            |
| Duration        | `-rf 00:01:00`; manual stop after the refresh             |
| Buffers         | `-bs 128 -nb 16 128`                                      |
| Timing          | Performance-counter timestamps; one-second flush interval |

The local `logman create trace /?` and `tracerpt /?` output confirmed these
options. Duration/file-size controls are documented in
[logman create trace](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/logman-create-trace).
The executing helper must check exit codes and stop its own collector in cleanup.
Delete only its collector definition after confirming it stopped; retain capture
files. Never stop or delete another session. Hitting a capture limit stops tracing,
not the app or the dock.

USB ETW is not assumed to filter by the selected dock at capture time. Other USB
traffic may be retained. Avoid entering credentials or generating unrelated USB
traffic during the short window. Select the dock's events offline and redact the
human-readable summary; retain raw evidence locally. Do not disconnect the dock
to simplify the trace. Expanded payload capture needs a separate privacy review.

## Phase A acceptance gate

For this BOT path, require the entire 31-byte command block wrapper (CBW), its
16-byte command storage area and a matching 13-byte command status wrapper (CSW).
Match their tags, endpoint and device association, not just adjacent timestamps.
Interpret wrapper integers as little-endian; the firmware command's offset and
length fields are big-endian. The CBW layout and tag relationship are specified
in [USB Mass Storage Bulk-Only Transport, sections 5.1–5.2](https://www.usb.org/sites/default/files/usbmassbulk_10.pdf).

A read-only capture qualifies the tracing mechanism; it cannot reproduce a
firmware data-out rejection. If partial capture omits required bytes or the ETL
cannot be decoded, stop at that finding. Do not retry flashing to test the logger.
Assess a separately approved short full-payload capture of the same read-only
scenario, or a validated capture point outside the guest, before proceeding.

## Phase B: conditional firmware investigation, not authorized here

Only propose this after Phase A passes and the existing recovery procedure has
been reviewed. Obtain explicit authorization for the hardware workflow.

- First load and verify the tested Manager build containing terminal invalid-field
  handling and the new fixed diagnostics. The current open application was left
  on its earlier build; copying source or seeing a mounted renderer is not proof
  that it loaded the new native service. Record the actual executable hash and
  confirm native hardware readiness.
- Revalidate the exact dock, empty bay, unchanged image/manifest, durable factory
  backup and stable power through the normal Manager gates. A failed prerequisite
  stops this phase without any firmware command.
- Capture one user-initiated workflow, with no manual retry. The current policy
  may retry once for an eligible transient failure; invalid-field rejection is
  not eligible. Explain and agree that distinction before the workflow begins.
- Keep the Manager's operation/support ID, attempt breadcrumbs, complete USB
  command/status sequence, requested/completed data lengths and sense response.
  Correlate the first rejection and distinguish it from read-only recovery.
- Do not inject alternate WRITE BUFFER commands, change chunk size, clear device
  interlocks, force activation, power-cycle or invoke a recovery uploader.
  An incomplete transfer must not authorize mode-5 activation.

### Expected transfer, derived from current Manager source

The selected image is 62,110 bytes: fifteen 4,096-byte chunks plus a 670-byte
tail. Sources: `native/rdx-service/src/protocol/cdb.rs::write_buffer`,
`src/firmware.rs` within that crate, and `service/hardware/firmware_transfer.rs`.
These are comparison values, not commands to submit directly.

| Field                     | First chunk        | Final chunk         |
| ------------------------- | ------------------ | ------------------- |
| Command length            | 10                 | 10                  |
| Opcode / mode / buffer ID | `3B / 04 / 00`     | `3B / 04 / 00`      |
| Offset, bytes 3–5         | `00 00 00`         | `00 F0 00` (61,440) |
| Length, bytes 6–8         | `00 10 00` (4,096) | `00 02 9E` (670)    |
| Control byte 9            | `00`               | `00`                |
| CBW data direction        | OUT                | OUT                 |
| CBW declared data length  | 4,096              | 670                 |

Record the actual CBW command length rather than treating its 16-byte storage
capacity as a sixteen-byte command. Compare completed data length with declared
length, and associate CSW residue/status and subsequent sense with the correct tag.

## Interpretation and stopping rules

- Missing/truncated evidence: capture failure, not a device diagnosis.
- Unexpected command fields: locate the discrepancy between Manager encoding,
  native request and the observed guest USB boundary before changing protocol.
- Correct command fields but short/failed data: investigate that transfer boundary;
  do not infer that the whole image reached the receiver.
- Complete guest-side data with `05/24/00`: inspect the 1.10 receiver's framing,
  transfer-sequence and manufacturing/serial interlock branches. Identical sense
  from several branches does not identify which one executed.
- Guest ETW does not directly prove bytes on the physical USB wire after Parallels
  forwarding, or receiver RAM/flash contents. Leave those conclusions unproven.

The deliverable from Phase A is a pass/fail capture-qualification summary. A later
Phase B deliverable would name the failed attempt/chunk, observed fields, data and
status evidence, comparison results, and the remaining uncertainty. Neither phase
automatically authorizes a firmware fix, another attempt or a power cycle.

## Preparation verification

Checked on this host: ARM64 OS, selected USB parent chain, provider registration,
keyword masks, UCX event schema, command help and transfer-size arithmetic.
Application source and immutable firmware were not edited for this plan.
No capture execution, live CDB decoding or hardware success is claimed.
