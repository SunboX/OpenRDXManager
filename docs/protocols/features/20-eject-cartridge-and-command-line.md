<!-- SPDX-FileCopyrightText: 2026 André Fiedler -->
<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->

# Eject cartridge and command-line eject

## GUI behavior

**Eject Cartridge** requests safe removal of inserted media. The Manager first
coordinates host filesystem flush/dismount and then asks the RDX drive/OS to
eject. Success is reported as `Eject Cartridge Passed`; open handles, protected
access state, transport error or mechanical failure can produce `Eject
Cartridge Failed`.

The common device path includes START STOP UNIT media-control behavior and RDX
eject feature settings. On macOS the application uses Disk Arbitration plus
its SCSI helper; Windows uses the storage stack/RDXmon and device command path.

## `RdxCmdLine.exe`

The Windows installation exposes the same operation for scripts. Documented
options are:

```text
RdxCmdLine.exe -? | -h | --help
RdxCmdLine.exe -v | --version
RdxCmdLine.exe -s | --scan
RdxCmdLine.exe -e | --eject <drive-letter>
RdxCmdLine.exe -f | --force
```

`--scan` lists RDX targets. `--eject` selects a drive letter. `--force`
requests the force path when ordinary safe eject cannot complete; it risks
unflushed data if applications still hold/write the volume. Administrative
execution is documented.

The exact numeric process exit-code table is not printed in the supplied
manual and has not been established, so automation should use both process status
and emitted success/failure text until that table is traced.

## Implementation details

`Test_EjectVolume` decides whether an OS eject is required, performs the
platform-specific dismount/eject, and runs post-success or rollback behavior.
Original methods include `SetupInternalUnloadOrReload`, `OSEjectNeeded`,
`RunOSSpecificEject`, `EjectDiskVolumeApple` and `UndoInternalUnload`. macOS
calls Disk Arbitration `DADiskEject`; Windows coordinates the mount/storage
stack and RDXmon. `RdxCmdLine.exe` reuses the same discovery/eject library.

The drive also exposes eject policy via MODE page `0x31` (SkipEject bit 3 and
AutoReload bit 4 of page byte 4), eject polling via page `0x33`, and a vendor
SEND DIAGNOSTIC eject-mode command.

## Protocol details

The vendor eject-mode parameter command is:

```text
CDB:      1D 00 00 00 06 00
payload:  85 00 00 04 vv 00
```

It is SEND DIAGNOSTIC, six bytes data-out; `vv` is the boolean eject-mode
value. Policy queries use MODE SENSE(10) page `0x31` or `0x33`; modifications
reuse MODE SELECT(10) after preserving the received page. Safe physical eject
also depends on successful host flush/dismount, so SCSI GOOD alone is not the
overall success condition.

CLI parsing is a host protocol (`--scan`, `--eject <letter>`, optional
`--force`). `--force` changes host dismount policy; it does not select an
unverified alternate SCSI opcode. Numeric process exit codes remain unresolved.

Evidence anchors: `SCSdEjectMode` `0x100061C50`, pages `0x31`/`0x33`, and
`Test_EjectVolume` methods beginning at `0x10007D4F0`.

## PDF-derived GUI/CLI workflow and behavior history

The Utility-tab action remotely ejects an inserted cartridge and is the
required preparation for firmware updating and mode changes. As with other
utilities, progress/result appears in the message area and the Management
pop-up cannot switch tabs, start another utility or close until completion.

The manual presents `rdxcmdline.exe` for backup applications without an eject
facility and says it can force media eject. Its printed options are the help,
version, scan, eject-by-drive-letter and force flags listed above. The same
manual requires Administrator privileges. Windows release 0.1.0.40 says CLI
functionality for non-Admin users was enhanced, but does not state which
operations or privilege boundary changed; automation should therefore retain
the manual's conservative administrator requirement unless the installed
build is tested.

Historical changes affecting eject semantics include:

- Windows 0.1.0.30 introduced command-line media eject;
- Windows 0.1.0.28 fixed intermittent media-eject failure and suppressed an
  Event Viewer warning from Windows Explorer right-click eject;
- firmware 0283 fixed START STOP UNIT, host-software and button eject in
  Fixed-Disk mode;
- firmware 0278 allowed eject after USB disconnect on Mac and on Windows with
  Optimize/Better Performance removal policy;
- firmware 0227 fixed multiple disconnect/load/emergency-eject cases, turned
  the fan off after emergency eject, used full-duty eject attempts, and
  prevented eject during Fixed-Disk host access;
- Mac Manager 0.1.0.1 fixed intermittent cartridge ejection during system
  sleep and false `Disk Not Ejected Properly` messages during sleep.

These histories explain platform/version behavior but do not override the
safe-eject rule: ordinary eject must flush/dismount successfully, while force
eject can risk unwritten cached data.

## OpenRDXManager production CLI boundary

The new `rdxctl` keeps the documented administrative requirement for hardware
mutation. `--eject` accepts only a bounded opaque `rdx:` identity returned by
`--scan`; it never accepts or prints a device node, volume path, drive recipe,
raw CDB, or confirmation payload. After argument validation and the force-risk
warning, it acquires the same nonblocking operating-system ownership domain as
the authenticated Electron hardware service **before** constructing its own
registry-owning hardware backend. That ownership remains live through fresh
discovery, exact ID/revision binding, host dismount policy, device dispatch,
departure readback, and backend destruction.

The authenticated service holds that domain for its complete framed client
session. A simultaneous Electron/CLI attempt therefore fails closed before a
second hardware registry exists; it cannot run two independent mutations
against the same dock. macOS uses the root-owned, single-link, mode-`0600`
`/var/run/openrdx-hardware.lock`. Linux uses the equivalent
`/run/openrdx/openrdx-hardware.lock` inside the root-owned runtime directory.
Both opens reject symbolic links and use a kernel nonblocking exclusive lock.
Windows uses `Global\OpenRDXHardwareMutation`, created first and retained by
the LocalService process with a protected DACL granting only LocalSystem,
Administrators, and LocalService the exact synchronize/release mask. A direct
client must also prove its process token is fully elevated. An absent,
pre-existing, inaccessible, or busy ownership boundary never falls back to
uncoordinated direct access.

Direct root/elevated authority is evaluated separately from authenticated
service installation, running, or enablement facts; it never claims an IPC
endpoint identity. Exact platform and candidate access remain mandatory. If a
CLI already owns mutation when an authenticated service session arrives, only
that accepted session is closed as busy. The service returns to its bounded
accept loop, so contention does not retire the privileged endpoint generation.

Portable and no-device tests prove parsing, redaction, acquisition ordering,
contention rejection, and exact revisioned fixture behavior. They do not prove
that the installed boundary works on an untested native Windows/Linux host or
that an attached RDX cartridge physically ejected.

Source coverage: Product Manual pp. 31, 35 and 37; Windows 2.0.1 Release Notes
pp. 2-3; USB3 Firmware 0283 Release Notes pp. 1-2; Mac 0.1.0.1 Release Notes
p. 1.
