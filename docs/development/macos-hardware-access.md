<!-- SPDX-FileCopyrightText: 2026 André Fiedler -->
<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->

# macOS hardware access for development

OpenRDXManager development builds use the helper built from the current
checkout. They do not install, register, or connect to the packaged launchd
service. The exact development executable is:

```text
out/native/macos/openrdx-hardware
```

Electron and its sandboxed renderer remain unprivileged. `npm start` obtains
administrator authorization and starts only that repository-built helper with
`sudo` over inherited private stdio pipes.

## One-Time macOS Settings

Current macOS releases can stop a newly linked local helper before its `main`
function runs, even when its Mach-O structure and code signature validate. The
development Terminal must be allowed to execute local software that does not
meet the normal distribution policy.

First enable the system developer authorization policy:

```sh
sudo /usr/sbin/DevToolsSecurity -enable
```

Then add Terminal to the Developer Tools privacy list:

```sh
/usr/sbin/spctl developer-mode enable-terminal
```

The second command adds the entry but does not enable its switch. Open:

**System Settings → Privacy & Security → Developer Tools**

Turn on **Terminal**. Approve the macOS authentication prompt if one appears.
This permission applies to development processes launched from Terminal, so
start OpenRDXManager from that Terminal application rather than from a different
unapproved launcher.

These settings authorize local development software; they do not install an
OpenRDXManager service, weaken Electron renderer isolation, or grant the
renderer direct hardware access.

## Verify the Host

Confirm the system policy and kernel Developer Mode flag:

```sh
/usr/sbin/DevToolsSecurity -status
sysctl -n security.mac.amfi.developer_mode_status
```

The first command must report that developer mode is enabled, and the second
must print `1`.

Build the normal development helper, then confirm that it reaches its own
argument parser instead of hanging before `main`:

```sh
npm run build:native-service
./out/native/macos/openrdx-hardware --bad
echo $?
```

The helper must print `openrdx-hardware: invalid service arguments` and exit
with status `2`.

## Start the Development App

Run the application from the approved Terminal:

```sh
npm start
```

Enter administrator credentials only in the Terminal-owned `sudo` prompt.
OpenRDXManager does not collect or relay the password. The development runtime
must connect to the exact helper from `out/native/macos/`; it must not fall back
to an installed application service.

If the UI reports that the hardware service is unavailable, run the verification
commands above in the same Terminal. A helper that hangs on the `--bad` probe is
still blocked by macOS execution policy. A helper that returns status `2` has
crossed that boundary; service authorization and hardware discovery can then be
diagnosed separately.

## Safe Eject on macOS 26

macOS 26 can reject a third-party `DADiskUnmount` request with
`kDAReturnNotPrivileged` even when the development helper runs as `root`.
Apple's `/usr/sbin/diskutil` carries the private disk-device entitlement needed
to cross that host boundary.

OpenRDXManager first tries its retained Disk Arbitration object. Only a proven
`kDAReturnNotPrivileged` or `kDAReturnNotPermitted` result enables the fallback.
The helper then starts the fixed Apple executable directly, without a command
shell, passes only the already validated whole-disk `diskN` identity, removes
ambient environment values, redirects child stdio away from the service
protocol, and enforces the same bounded timeout. Safe Eject still keeps host
unmount and physical eject as two separate lifecycle stages.

The USB-to-storage handoff can also leave the exact cartridge already
unmounted. A `kDAReturnNotMounted` result therefore satisfies the unmount stage
only; OpenRDXManager still runs the separate physical-eject stage and verifies
that the exact cartridge departs before reporting success.

The local activity log records only fixed outcome codes such as
`macos-da-direct-already-unmounted`, `macos-diskutil-unmount-succeeded`, and
`macos-diskutil-eject-succeeded`. Paths, native status values, and Apple utility
output are not forwarded to the renderer or stored in support logs.

No additional privacy switch or installed service is required for this
fallback. The administrator authorization acquired by `npm start` remains the
only development elevation boundary.
