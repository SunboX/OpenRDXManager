<!-- SPDX-FileCopyrightText: 2026 André Fiedler -->
<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->

# LED Test

## Overview

LED Test alternately flashes the drive and cartridge indicators green and then
amber. A cartridge must be inserted to observe its own LED; the dock LED can
still be checked independently. The purpose is to verify that hardware LEDs
can represent normal and warning/error states.

## Implementation overview

Original Manager symbols include `SCSdDtLedOn` and `SCSdDtLedOff` beside the
SEND DIAGNOSTIC test classes. The Manager sends diagnostic-on once, leaves the
device running its visual sequence for about 7.8 seconds, then sends
diagnostic-off once to restore normal LED control.

The command travels through the common SCSI transport. Successful SCSI status
advances the test sequence; CHECK CONDITION, timeout or device removal produces
an LED Test failure message and event-log entry.

The exact vendor parameter bytes are listed below. Leaving normal LED
behavior restored remains an important cleanup requirement.

## Implementation details

`Test_led::RunTest` constructs both `SCSdDtLedOn` and `SCSdDtLedOff`. Its
internal phase flag chooses which command is sent on that invocation. The start
handler sets the flag to true and starts a 300-ms UI timer. Each timer callback
increments a counter from zero by four; when it exceeds 100 (the 26th tick), the
handler invokes `Test_led` with false. The timer updates progress; it does not
send repeated LED commands or select individual colors. A non-zero command
result is formatted as `Error on LED Test.` and exits with test error `10`.

This timing is supported independently by the Windows Manager 2.0.1.54
implementation reference (LED click branch around `0x00416C9C`, and
`FUN_0041e5c0` / `updateTestProgress`) and the macOS Manager 0.1.0.1 reference (
`Dialog::on_ledTestButton_clicked` at `0x1000233E0` and
`Dialog::updateTestProgress` at `0x100021230`). The original timer starts before
the synchronous ON command; 7.8 seconds is its nominal UI interval. OpenRDXManager
holds diagnostic mode for that full interval after a successful ON command,
checking cancellation every 300 ms, before mandatory OFF and identity readback.

Both commands derive from `SCSdDiagTest`, which allocates an eight-byte
parameter list, zeros it, writes the vendor diagnostic header and encodes a
32-bit test enumeration in big-endian order.

## Protocol details

Both phases use this CDB:

```text
1D 00 00 00 08 00
```

It is SEND DIAGNOSTIC (`0x1D`), data-out, parameter length 8. Payloads are:

```text
LED/test on:   80 00 00 04 00 00 00 00
LED/test off:  80 00 00 04 00 00 00 01
```

Byte `0x80` is the Tandberg diagnostic page/type, bytes 2–3 give a four-byte
body, and bytes 4–7 contain the big-endian test code (`0` or `1`). There is no
data-in reply. Each phase requires SCSI GOOD; CHECK CONDITION stops the test.

Evidence anchors: `SCSdDiagTest` `0x1000619E0`, `SCSdDtLedOn`
`0x100061D80`, `SCSdDtLedOff` `0x100061DE0`, and `Test_led::RunTest`
`0x10007D240`.

## PDF-derived execution and observation

The manual describes both dock and cartridge LEDs alternating first green and
then amber for several seconds. A cartridge must be inserted to observe its
LED. The test is intended to prove that both indicators can communicate normal
and warning/error state to the user; it does not validate every firmware
condition that can later select those colors.

The shared Test-tab progress bar turns green and reports success only after the
sequence completes. On command/test failure it remains blank/gray and shows a
failure message. Normal LED ownership must be restored after either result.

Source coverage: Product Manual pp. 30-31.
