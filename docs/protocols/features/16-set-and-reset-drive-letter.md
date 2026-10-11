<!-- SPDX-FileCopyrightText: 2026 André Fiedler -->
<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->

# Set and reset drive letter

## Overview

The Windows Manager assigns a persistent preferred drive letter to a specific
RDX dock serial number. The setting takes effect after the next media
insertion/device refresh and survives a reboot. **Reset Drive Letter** removes
the preference and lets Windows choose again. Media must be ejected for the
documented UI action.

## Exact storage mechanism

The Windows executable contains this registry path:

```text
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RDXmon\DriveLetters\%1
```

Here `%1` is the dock identity/serial. The `DriveLetter` value stores the
selection. RDXmon, the installed background service/driver component, applies
the mapping when the cartridge volume appears. Administrative access is
required to change `HKLM`.

## Results

- Set success: registry mapping exists; UI explains that the change applies on
  next insertion.
- Reset success: serial-specific mapping/value is removed; Windows is free to
  allocate another letter.
- Letter conflict or policy failure: RDXmon/Windows can reject or choose a
  different assignment and the Manager logs/reports failure.

No SCSI CDB changes the letter; this feature is entirely a Windows mount/
registry policy keyed to the physical dock.

## Implementation details

The Manager obtains the stable dock serial from its normal discovery/status
path, opens the serial-specific RDXmon key under HKLM, and writes or deletes the
`DriveLetter` value. RDXmon observes the next volume arrival and applies the
preference while Windows assigns the mount point. The GUI disables this action
while media is present to avoid renaming a live mounted volume.

Reset removes only the selected dock's preference; it does not delete the
whole `DriveLetters` tree. Administrative access is needed for HKLM writes.

## Protocol details

This is a registry/service protocol, not SCSI:

```text
key:   HKLM\SYSTEM\CurrentControlSet\Services\RDXmon\DriveLetters\<dock-serial>
value: DriveLetter = selected letter
```

The setting is consumed asynchronously on the next media/device arrival.
Success of the registry write means the preference was stored; final success
is the subsequent volume appearing at that letter. Conflicts remain subject to
Windows mount-manager policy. No controller flash, MODE page or cartridge
sector is modified.

## PDF-derived availability and UI procedure

The release notes identify this as a USB3-dock feature. The supplied manual
requires Windows 7 or later and no inserted media; with media present the
Utility control is inactive until the cartridge is ejected. The selection list
contains only letters the OS currently considers available.

The set flow is: select a letter, click **Set Drive Letter**, confirm **Yes**,
close the dialog, and observe the new letter after the Drive List refresh. The
reset flow is: reopen the same utility, click **Reset Drive Letter**, confirm,
and close; Windows then manages future assignments.

Windows 2.0.0 introduced the persistent mapping specifically because Windows
can reassign letters previously used by removable USB devices and thereby
break automated jobs. RDXmon overrides such reassignment attempts for the
configured USB3 dock. This persistence is dock-specific rather than cartridge-
specific.

Source coverage: Product Manual pp. 31-33; Windows 2.0.1 Release Notes p. 2.
