<!-- SPDX-FileCopyrightText: 2026 André Fiedler -->
<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->

# Self Test

## Overview

Self Test checks host-to-drive communication and, when inserted, basic
cartridge operation. The manual recommends first running it with no cartridge
to isolate dock/host communication, then repeating with media to include the
cartridge path.

## Implementation overview

The symbol-bearing Manager contains `SCSdSelfTest`, `SCSdDiagTest` and
`Test_SelfTest` classes. `SCSd` denotes the SEND DIAGNOSTIC command family;
the standard opcode is `0x1D`. The test operation sends the diagnostic request,
waits/polls for completion, and decodes SCSI status and sense data.

Expected outcomes are UI/log messages for pass or failure. A transport failure,
CHECK CONDITION, timeout or diagnostic failure is a failed test; `No Media`
is acceptable for the drive-only phase but naturally excludes cartridge
testing.

The exact command is described below. It has no parameter list; timeout remains
the transport object's configured value rather than a CDB field.

## Implementation details

`Test_SelfTest::RunTest` constructs `SCSdSelfTest`, calls the common
`TestOperation::RunTest`, then sends the command once through
`ScsiDevice::SendCmd`. A non-zero result is passed to
`GetScsiErrorString(..., "Error on Self Test.")` and terminates the operation
with test error `10`. There is no host-side data comparison or polling loop in
this specific method.

The test with/without cartridge differs in what the controller can exercise;
the host sends the same command. Running without media isolates dock command
transport, as recommended by the manual.

## Protocol details

The exact six-byte CDB is:

```text
1D 04 00 00 00 00
```

Opcode `0x1D` is SEND DIAGNOSTIC. Byte 1 bit 2 is the SELF-TEST bit; PF,
device-offline and unit-offline bits are clear. Parameter-list length is zero,
direction is none. SCSI GOOD is pass. Any non-zero Manager transport result,
CHECK CONDITION or sense is failure; there is no response payload.

Evidence anchors: `SCSdSelfTest` constructor at Mac runtime `0x100061970` and
`Test_SelfTest::RunTest` at `0x10007CFA0`.

## PDF-derived execution and result presentation

All Test-tab operations start automatically when their button is clicked. A
shared progress bar occupies the message area: it advances while the operation
runs, turns green and displays a success message on pass, and remains blank/
gray with a failure message on failure.

The manual recommends a two-pass isolation procedure. First run Self Test with
no cartridge to test host-to-dock communication. Then insert a cartridge and
repeat to include dock-to-cartridge communication. The same `1D 04` CDB is
sent; the media state changes what the dock can exercise internally.

Source coverage: Product Manual pp. 30-31.
