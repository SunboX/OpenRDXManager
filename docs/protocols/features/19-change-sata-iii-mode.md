<!-- SPDX-FileCopyrightText: 2026 André Fiedler -->
<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->

# Change SATA III speed mode

## Overview

On SATA III RDX docks the Manager switches between these advertised host-link
sets:

- `1.5G / 3G` compatibility mode;
- `3G / 6G` high-speed mode.

The choice limits/changes maximum negotiated SATA host speed. It does not alter
cartridge capacity or filesystem contents. Media removal and device refresh/
power-cycle behavior may be required by the UI/drive.

## Internal command path

Original symbols name
`SCModeRdxFeaturesExtension::GetMaxHostSataSpeed` and
`SetMaxHostSataSpeed`. Like operation mode, the Manager reads the vendor RDX
MODE page, modifies only the relevant enumeration, sends MODE SELECT with save
semantics and verifies the resulting setting after refresh.

Success is SCSI GOOD plus matching readback/drive rediscovery. Non-SATA III
products hide or disable the control. Unsupported value, CHECK CONDITION or
failure to reconnect/read back is reported as failure.

The exact MODE page byte and the two GUI values are described below.

## Implementation details

`Test_Sata3Mode::SetSata3Mode` sends MODE SENSE page `0x34`, compares the
current maximum-host-speed byte, converts the response to MODE SELECT, changes
the value, and sends it. It then sends `SCSdUnitReset` and calls
`WaitForDeviceReconnect(15)`. The UI code selects value `2` or `3`; value `2`
is the `1.5G / 3G` compatibility choice and value `3` is `3G / 6G`.

The operation is only offered when device information identifies the SATA III
product enumeration. No filesystem sectors are intentionally changed.

## Protocol details

Read uses MODE SENSE(10):

```text
5A 00 34 00 00 00 00 00 FE 00
```

Within returned page `0x34`, byte 6 is `MaxHostSataSpeed`. The Manager writes
`0x02` or `0x03` there, preserves all other bytes, and sends MODE SELECT(10):

```text
55 10 00 00 00 00 00 LL LL 00
```

PF is set; this setter path does not explicitly set SP in the reference test.
It then sends the vendor unit-reset SEND DIAGNOSTIC object, expects temporary
disconnect, and polls reconnect up to 15 iterations. That reset object is the
exact no-data CDB `1D 05 00 00 00 00`. Success therefore requires MODE SELECT
GOOD, reset command acceptance and rediscovery.

Evidence anchors: `Get/SetMaxHostSataSpeed` at `0x100068160/0x100068190` and
`Test_Sata3Mode::SetSata3Mode` at `0x1000A20F0`.

## PDF-derived defaults and exact UI constraints

The vendor recommends retaining the default **1.5G / 3G** mode. The manual
states that the **3G / 6G** choice produces a performance improvement only with
RDX SSD media. It is therefore not a general recommendation for HDD
cartridges.

This utility is SATA III-specific; for a USB dock its button is grayed out.
Changing the mode requires no inserted cartridge. If media is present, Manager
offers to eject it first. The current mode is highlighted in blue, and choosing
that same mode or **Cancel** exits without sending the setter. A different
choice runs quickly, with progress reported in the bottom message area.

Windows release 0.1.0.40 records improved communication while changing SATA
III modes. The supplied release notes do not define a different CDB, field or
return code for that improvement.

Source coverage: Product Manual pp. 31 and 34-35; Windows 2.0.1 Release Notes
p. 2.
