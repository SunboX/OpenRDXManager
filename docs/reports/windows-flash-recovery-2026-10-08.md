<!-- SPDX-FileCopyrightText: 2026 André Fiedler -->
<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->

# Windows flash recovery — 2026-10-08

Historical report. Results and limitations apply to the described host, device and date; subsequent reports may supersede them.

The selected receiver now runs the corrected normal OpenRDX 1.10 firmware after
a successful update through the real Windows Manager. Independent physical
readback matches all 262,144 expected bytes. The original 256-byte Manufacturing
and 64-byte State records are byte-identical, and both capability queries succeed
through direct and buffered Windows SPTI. Manager is open with the exact drive
connected and its firmware workflow available. This supersedes the earlier
reports' pre-recovery status.

## Recovery performed

The user explicitly requested flashing after entering J7 ROM mode and removing
the link. The guarded helper bound the ROM instance to the previously verified
physical USB port, checked healthy HID/burner interfaces, pinned the installed TI
CLI assembly and selected image, and preserved both original full backups.

The installed TI CLI library provided HID preparation and reset. A fixed Win32
wrapper sent the exact already-formatted 61,710-byte image unchanged through the
installed Flash Burner driver, using the GUI full-image path's IOCTL `0x222000`.
It did not pass this image through the CLI normal-container formatter. Driver
transfer and reset succeeded at 11:56 UTC. No automatic retry followed preparation.

Earlier helper failures stopped before HID preparation: wrong process bitness,
GUI/CLI property differences, then an unavailable public vendor file-open method.
Their records remain in the private evidence directory; none wrote firmware.

The receiver returned as its original normal USB identity. At 12:01 UTC,
`post-bootstrap/` captured readiness and two identical full SPI reads. The
independent comparison reconstructed every expected byte from the selected boot,
erased padding and original records:

- Bootstrap SHA-256: `874b666f6c4efd75d30235e1f70aefc2d7fbeca430ebe314233d94ed12ae90a9`.
- Full installed SPI SHA-256: `c8056ec5aca8651a3e6031506eeaa31bb184b73960c8f7c006ceae8a42c2fedb`.
- Both Manufacturing and Serial capability queries: host success, SCSI GOOD,
  direct and buffered. Previously Serial returned `05/24/00`.
- Original complete backup remains SHA-256
  `027e4a699c5589bda268b92efc3f76143b9790a18e13da43381957aeb5e3ee32`.

Raw records, personalized images, complete snapshots and console transcripts
remain outside Git in the ACL-protected `native-windows-20261008-1/` directory.

## Windows application

The source-built application passes its official `npm run smoke` command when
given the verified physical user-data directory. The renderer mounted and the
service reported `ready native`. That unprivileged smoke correctly reported
`hardware=false`; real raw-device access still requires administrator elevation.
No logger privacy check or renderer sandbox setting was relaxed.

The transfer root now contains `Start-OpenRDXManager.cmd`. Its local PowerShell
helper requests elevation, pauses the competing vendor monitor for the application's
lifetime, launches the source-built production main/preload/service with the
verified physical profile, and restores the monitor when the application exits.
It does not select or flash a firmware file automatically. This is a development
launcher for this workspace, not an installer or distributable release.

## Normal Manager update

At 12:12:50–12:12:59 UTC the real Manager firmware operation completed with
terminal state `succeeded`, stage `complete`. Recorded stages were validation,
writing, finalization, reconnect and firmware readback. The verification harness used
the unchanged production Electron main, sandboxed renderer, preload IPC and native
service. Only its file chooser is preselected to the user's approved native TI
5.2.5 corrected 1.10 container. All firmware validation, admission, readiness,
backup, write and post-write checks remained production code. This was an actual
native Windows USB update, not a simulated transport or operation-admission check.

At 12:13 UTC, after Manager stopped, the independent probes read the entire SPI
twice and rechecked Manufacturing and Serial readiness through both SPTI routes.
Every expected byte matched the normal production boot, erased padding and the
original records. Installed full SPI SHA-256:
`c44846f67181949a7a7437791aba8f9c872428e1197c92a86672c172a8f23d7f`.
Evidence: `manager-update-2-result.json`, `post-manager-update/comparison.json`,
the full snapshot and readiness logs in that private subdirectory.

Manager then reopened using the ordinary launcher. At 12:13:19 UTC its real
preload inventory reported `ready`, `privileged: true`, `hardwareReady: true`,
the exact TANDBERG RDX serial, no media, revision 1.10 and firmware-update
capability `available`. The actual captured window shows Hardware connected and
the available firmware workflow. Evidence: `manager-running.json` and
`manager-running.png`. Sandbox and context isolation remain enabled; Node
integration remains disabled. The generic platform-wide `hardwareVerified` flag
remains false; this report qualifies this receiver's update flow only.

Two earlier UAC attempts were cancelled before a helper started. After the user
started the setup from Explorer, the first elevated Manager harness stopped before
file selection because its subscription initializer returned an uncloneable
function to Electron. No firmware operation was admitted. That attempt's files
and script sources are retained in `manager-attempt-1/`. The corrected harness
returned a cloneable scalar and required the earlier attempt to have stopped
before selection. There was no retry of a dispatched firmware write.

The reusable launcher was also verified without elevation at 12:09 UTC: the real
renderer mounted, the service was connected, and it correctly rejected privileged
hardware access. Captured preferences confirm sandbox and context isolation
enabled, Node integration disabled. Evidence is `manager-launch-check.json` and
`manager-launch-check.png`; these do not claim an elevated hardware test.

Selected container SHA-256:
`4607fc4bced3868e65af13201f7c7aa86f1dd626099780fd95af3473057cdc97`.
Verified installed normal boot SHA-256:
`86dd1fade35225dd69ef09df4b9f13488052613c22dacd198e8aeec423fa865e`.

Rollback of a full 256 KiB image through the installed vendor tool remains
unqualified. Native Windows recovery does not qualify macOS normal updates,
other receivers, cartridge operations, or a signed production installer.
