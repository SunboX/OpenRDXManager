<!-- SPDX-FileCopyrightText: 2026 André Fiedler -->
<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->

# Application checks

Software checks and retained physical acceptance notes. Hardware statements describe the recorded checkpoint, rather than every current device or release.

## Feature Coverage and Physical Acceptance

The application bundles a concrete manifest for all 25 documented feature
groups and exposes it alongside current host/device capabilities, the bounded
historical vendor compatibility matrix, troubleshooting order, and known
limits. Historical Windows/macOS qualification does not certify a current host.
Security writes and compatible AES media layout remain visibly
`evidence-incomplete` unless their exact protocol fixtures enable them.
Modern USB3/SATA3 firmware execution accepts a matching verified `.BIN` image
through the bounded preflight and native operation path. Legacy USB2/SATA1
`.BIP` images remain fail-closed as `legacy-bip-format-unproven`; source and
fixture coverage do not prove either firmware path on physical hardware.

Use [`docs/verification/hardware-acceptance.md`](../../docs/verification/hardware-acceptance.md) for physical
validation. Its checklist runs read-only discovery/status first, then
diagnostics and reversible configuration, and only then firmware, security,
and destructive disposable-media flows. The current Mac has validated the
attached dock through the development application; cartridge-state and broader
physical operation acceptance remain pending.

## Verification

Run the Node test suite:

```sh
npm test
```

Run the portable native Rust model and protocol tests:

```sh
npm run native:test
npm run native:test:no-default
```

Record this host's bounded build, native-quality, service-handshake, and
read-only discovery evidence:

```sh
npm run verify:native-platform
```

The generated report is written under `out/verification/` and always keeps
physical evidence separate as `hardware.verified: false` with an empty
operation list. See
[`docs/verification/platform-verification.md`](../../docs/verification/platform-verification.md) for the reviewed
native-host matrix and physical acceptance boundary.

Format native Rust source or run the all-feature, no-default-feature, and
Rustdoc quality gate:

```sh
npm run native:fmt
npm run native:quality
```

Launch Electron, wait for the dashboard renderer to mount and the local device
service to reach a terminal ready/unavailable handshake state, then exit
automatically:

```sh
npm run smoke
```

Some automated agent environments set `ELECTRON_RUN_AS_NODE=1`. In that case, remove the variable for the runtime check:

```sh
env -u ELECTRON_RUN_AS_NODE npm run smoke
```

On a development machine without native RDX integration, the expected terminal
result is a ready `no-device` service with `hardware=false`. That proves the
Electron/preload/service boundary and an empty discovery result; it does not
prove a connected dock or any physical hardware operation. A terminal
service-unavailable result is also a completed handshake outcome, not a hardware
success.

Run the deterministic real-Electron functional and screenshot matrix:

```sh
npm run test:visual
```

The visual command captures the complete 31-state fixture matrix at the minimum
`1024 × 768` and expanded `1440 × 900` window sizes. It fails closed on
missing inspection evidence, horizontal clipping, unlabeled controls, disabled
gates without reasons, hidden service status, remote resources, missing local
fonts/icons, CSP drift, console/page/load errors, or renderer crashes. Evidence is written to
`docs/evidence/phase-4-task-8/`. Fixture modes live only in the separate
`electron-test/` entrypoint and cannot be activated by production application
arguments.

The Node suite runs visual captures in an isolated host-specific directory and
checks that canonical research screenshots remain unchanged. `npm test` prepares
the preload and native runtime before starting concurrent workers. Nested visual
commands skip npm lifecycle hooks, preventing dependency repair from removing
packages while another test imports them; standalone visual commands retain setup.
Windows visual QA
uses a fixed 2x scale to avoid fractional-DPI rounding; production scaling is
unchanged. Painted anchors must pass DOM hit testing as well as pixel checks, so
a heading clipped by a scrolled panel cannot be mistaken for visible content.
Failed captures retain scene-specific diagnostics in the selected evidence
directory. Actual repaint retry counts are retained separately in
`visual-qa-capture-metrics.json`; the deterministic manifest excludes those
volatile counts without discarding them. The compact Electron check uses the same
Windows test scale and verifies the complete frozen public API, including
manufacturing, recovery and MCP, without exposing raw command authority.
Acceptance window resizing waits for exact Chromium viewport readback before
checking layout. Manufacturing screenshots additionally require DOM hit testing
and matching painted heading/confirmation anchors; an unrelated or stale frame
cannot count as recovery evidence. Disabled controls retain their normal faded
appearance and their unchanged admission gates.
The MCP UI acceptance command accepts
`--mcp-acceptance-private-clipboard` for unattended runs: production main/preload
copy actions use a test-owned in-memory text clipboard, and evidence explicitly
does not claim host clipboard verification. The real Windows clipboard is untouched.
Native Windows logger/MCP tests verify real ACLs, junctions and
hardlinks; file-symlink-only cases explicitly skip when Windows denies the
required creation privilege. Linux launcher paths use Linux path semantics on
every test host. macOS build/package inputs are validated before their unchanged
host-only execution gate; this does not enable macOS packaging on Windows.

Session API tests retain compile-fail checks for forbidden device/firmware
ownership. Three checks whose explanatory text varies between Rust versions now
verify primary JSON error codes, symbols and source locations after a successful
public-type control. They do not accept unrelated compilation failures, bypass
the compiler, or execute generated fixtures.

Return to [verification documentation](README.md).
