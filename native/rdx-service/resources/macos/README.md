<!-- SPDX-FileCopyrightText: 2026 André Fiedler -->
<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->

# macOS privileged-service metadata

`com.openrdx.hardware.plist` is the packaged metadata for the signed
`SMAppService` launch daemon. It describes a root-owned, group-writable mode
`0660` Unix socket and the bundle-relative helper executable with fixed
`launchd-socket` arguments. The helper still validates kernel peer credentials
and the manager's designated code requirement at accept time; socket access
alone is never authority. Metadata presence does not mean the service is
registered, approved, enabled, running, or authenticated.

The controlled package build embeds one exact ten-character signing Team ID in
the helper. At startup the helper constructs only `identifier
"com.openrdx.manager" and anchor apple generic and certificate leaf[subject.OU]
= "TEAMID0000"`. Missing build-time identity, alternative operators, clauses,
whitespace, escaping, lower-case identifiers, and malformed team identifiers
are rejected before launchd activation. The validated requirement is then
checked against the accepted audit-token guest with strict Security.framework
validation.
The socket accept is bounded to ten seconds and the first complete framed
request is bounded by the shared two-second absolute handshake deadline.

Before constructing a native hardware backend, the daemon creates or validates
the root-owned, single-link, regular mode-`0600`
`/var/run/openrdx-hardware.lock` and acquires it without waiting. It retains the
kernel lock for the complete authenticated framed session. An administrator-run
`rdxctl` uses the same fixed ownership file and holds its lock from before
backend construction through exact-device departure readback. Final-component
symlinks, foreign ownership, broadened permissions, contention, and incomplete
metadata fail closed; the lock does not replace audit-token peer validation.

The packaged Electron main process registers and inspects this fixed daemon only
through the zero-argument ServiceManagement bridge. macOS owns administrator
approval and daemon lifecycle. No legacy kernel component or host
security-configuration bypass is part of this design.
