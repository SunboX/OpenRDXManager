<!-- SPDX-FileCopyrightText: 2026 André Fiedler -->
<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->

# Change Fixed Disk / Removable Disk mode

## Overview

The utility changes how an RDX dock reports its media to the host: **Fixed
Disk** or **Removable Disk**. This affects operating-system caching/removal
policy and which utilities are enabled. The operation is drive configuration,
not a conversion of cartridge data.

The manual requires media removal before changing the mode. A device refresh
or reconnect can be necessary before the host observes the new mode.

## Internal command path

Original symbols identify `SCModeRdxFeaturesExtension::GetOperationMode` and
`SetOperationMode` built on SCSI MODE SENSE(10)/MODE SELECT(10). The Manager:

```text
MODE SENSE vendor RDX feature page
    -> preserve unrelated fields
    -> change operation-mode enumeration
    -> MODE SELECT with saved-page semantics
    -> refresh/reconnect and verify reported mode
```

Successful MODE SELECT and subsequent readback are the expected result.
Unsupported hardware/page, invalid field, media present, CHECK CONDITION or
failure to reconnect/read back causes failure.

The field is vendor MODE PAGE `0x34`, byte 4 bits 0–2. For the Manager's values
`1` and `2`, the controller saves the low two bits in its upper-flash state
record as documented separately.

## Implementation details

`Test_OperationMode::SetMode` first sends MODE SENSE, converts the successfully
received command object to MODE SELECT, sets the Save Pages bit, replaces only
the low three bits of page byte 4 and sends it back. Query performs MODE SENSE
and masks the same bits. Original enum strings identify:

| Value | Original meaning                  |
| ----: | --------------------------------- |
|   `0` | Not Configured                    |
|   `1` | Standard (legacy removable)       |
|   `2` | Fixed/Removable (Windows Backup)  |
|   `3` | Device Remove on Cartridge Remove |

The GUI's Removable/Fixed choices select the applicable legacy versus
fixed/removable behavior; capability checks hide unsupported values.

## Protocol details

Read template:

```text
5A 00 34 00 00 00 00 00 FE 00
```

This is MODE SENSE(10), current page `0x34`, allocation `0x00FE`, data-in.
After preserving the returned header/block descriptors/page bytes, write uses:

```text
55 11 00 00 00 00 00 LL LL 00
```

MODE SELECT(10) `0x55`, byte 1 `0x11` = PF plus SP/save, parameter length
`LL LL`, data-out. Page byte 4 is `(old & 0xF8) | (mode & 7)`. SCSI GOOD is
required for both commands; a read failure prevents any write.

Evidence anchors: `SCModeRdxFeaturesExtension` constructor `0x100067F40`,
`SetOperationMode` `0x1000680B0`, and `Test_OperationMode::SetMode`
`0x10009BCA0`.

## PDF-derived availability and UI behavior

The Utility button is enabled only if the selected dock reports mode-change
support. No media may be present; if a cartridge is inserted, Manager tells the
user to eject it before continuing. The dialog highlights the current Fixed or
Removable setting in blue. Selecting the already-active mode or **Cancel**
closes the dialog without writing MODE SELECT; selecting the other mode runs
the change and reports progress in the message-area bar.

Historical firmware context explains why mode persistence matters. Firmware
0278 fixed Fixed-Disk mode reverting to Removable after a power cycle, and
0283 fixed START STOP UNIT, host-software and push-button eject behavior in
Fixed-Disk mode. Windows Manager 0.1.0.40 also reports enhanced Fixed-Disk Mode
functionality. These fixes do not change the page-`0x34` setter documented
above.

Source coverage: Product Manual pp. 31 and 34; Windows 2.0.1 Release Notes
p. 2; USB3 Firmware 0283 Release Notes pp. 1-2.
