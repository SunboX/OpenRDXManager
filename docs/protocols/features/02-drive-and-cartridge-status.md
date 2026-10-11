<!-- SPDX-FileCopyrightText: 2026 André Fiedler -->
<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->

# Drive and cartridge status

## Overview

The default Status tab reports drive serial number, vendor, product ID,
firmware revision, product type, connection type, operation mode, status,
load count, drive errors, cam state and bus-power state. With media inserted it
also reports cartridge vendor/product/serial, capacity, HDD firmware,
cartridge status, write-protection and accumulated data read/written.

## Implementation overview

The symbol-bearing Manager names the relevant readers:

- standard SCSI INQUIRY/VPD and READ CAPACITY classes for identity/capacity;
- `SCLsnDriveInfoPg` for vendor LOG SENSE page `0x20`;
- `SCLsnCartInfoPg` for the cartridge information page;
- `SCModeRdxFeatures` and `SCModeRdxFeaturesExtension` for operation and
  capability flags;
- TEST UNIT READY for media/ready state.

The drive-info parser's original output strings name `Drive Status`, `Load
Count`, `Drive Errors`, `Cam Home`, and `Bus power status`. This confirms that
flash state-record offset `0x3F004` is the persistent Load Count: controller
firmware increments it only after a successful media-load activation.

## Return handling

Successful commands return their data-in buffers and are decoded field by
field. A SCSI CHECK CONDITION is interpreted using sense key/ASC/ASCQ and
becomes states such as no media, not ready, write protected or device error.
Blank cartridge fields with `No Media` are expected, not a discovery failure.

The exact vendor LOG SENSE parameter offsets can be established in a future
focused implementation review; the class and human-readable semantics are proven, but
this document does not invent byte offsets that have not been traced.

## Implementation details

The long-lived device model owns preconstructed command objects including
`SCTestUnitRdy`, `SCInqStd`, `SCLsnDriveInfoPg`, `SCLsnCartInfoPg`,
`SCLsnTemperaturePg`, `SCLsnInformationalExceptions`, and
`SCModeRdxFeaturesExtension`. Safe getter variants first verify that the
required parameter bytes were received; missing/truncated parameters become
an unavailable field instead of an out-of-bounds read.

`SCLogSense::FindUint32Parameter` walks LOG SENSE parameter headers and decodes
big-endian parameter values. The drive page exposes original getters for load
count, LED reasons, cam status, connection type, bus-power status and link
speeds. The cartridge page exposes capacity/free/used, data read/written,
status, link speed, LED reasons, and individual read/write-protection flags.

## Protocol details

The two principal exact CDB templates are:

```text
Drive:      4D 00 20 00 00 00 00 00 FE 00
Cartridge:  4D 00 21 00 00 00 00 00 FE 00
```

They are ten-byte LOG SENSE commands (`0x4D`), current cumulative values,
vendor pages `0x20` and `0x21`, allocation length `0x00FE`, data-in. Returned
pages start with the standard four-byte LOG SENSE page header and then
parameter records (`parameter code`, control, length, value). The parser uses
parameter codes rather than assuming a single packed C structure.

Additional exact command forms used by the tab are:

```text
TEST UNIT READY: 00 00 00 00 00 00
MODE SENSE(10):  5A 00 pp 00 00 00 00 00 FE 00
```

where `pp` is the requested vendor page. INQUIRY is opcode `0x12`; standard
identity fields are vendor bytes 8–15, product bytes 16–31 and revision bytes
32–35. SCSI GOOD plus a sufficiently long payload is success. CHECK CONDITION
is decoded through fixed-format sense; host transport results `3` and `4` have
the meanings documented in feature 01.

Evidence anchors: macOS symbols/functions at `SCLsnDriveInfoPg` runtime
`0x10005B780` and `SCLsnCartInfoPg` `0x10005CC40`.

## PDF-derived field inventory and presentation rules

The manual's Status tab separates drive data from cartridge data. The complete
documented drive-side presentation includes:

- OEM Name, serial number, product/vendor identity and firmware revision;
- Born On Date (which may be blank on older models), product/connection type
  and current operation mode;
- drive status, load count, drive errors and cam state;
- Drive Policy, shown for an external dock and describing its performance
  policy;
- Power Source, shown for an external USB3 dock as Adapter Powered or Bus
  Powered.

The documented cartridge presentation includes cartridge vendor, model,
serial number, status (`Good` or `Cartridge Error`), load count, HDD firmware,
cartridge type, write-protect state (`OFF` permits writes, `ON` blocks them),
temperature in degrees Celsius, total capacity with used/available space, Free
Space, Bytes Read and Bytes Written. With no cartridge, dock data remains
available while the cartridge side shows only `No Media` and leaves its other
fields blank.

Windows release 0.1.0.28 fixed Drive Policy not appearing in the Status window,
and release 0.1.0.30 added media-encryption state to the system summary. These
are presentation/history facts; they do not introduce additional LOG SENSE
pages beyond the command families above.

Source coverage: Product Manual pp. 14-15; Windows 2.0.1 Release Notes pp. 2-3.
