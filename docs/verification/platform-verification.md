<!-- SPDX-FileCopyrightText: 2026 André Fiedler -->
<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->

# Platform verification

## Purpose and proof boundary

`npm run verify:native-platform` records native software readiness without
turning a successful build, test, service handshake, or discovery result into
physical-hardware proof. The command does not mutate RDX devices, attached
media, or host device configuration: it runs fixed build/quality commands,
starts the staged hardware service, completes its strict handshake, requests
the read-only device list, and shuts the service down. It writes only ordinary
generated build artifacts plus the report below `out/verification/`.

The generated JSON always contains:

- host operating system and architecture;
- Node.js, npm, Rust, and Cargo versions;
- bounded runtime-build and native-quality results;
- the native service handshake and platform-capability state;
- the count of validated devices returned by read-only discovery; and
- a separate `hardware` object with `verified: false` and `operations: []`.

The verification command deliberately has no option that can mark hardware as
verified or add accepted operations. Physical acceptance requires a separate,
explicitly reviewed run on a named dock and cartridge. Destructive acceptance
also requires media that the operator has explicitly designated disposable.

## Run the verification

Use the repository Node.js version, then run:

```sh
nvm use
npm run verify:native-platform
```

The command exits `0` only when the required tools are available, the runtime
build and native quality gate pass, and the service completes a valid handshake
plus read-only list request. No attached device is a valid result and is
reported as `discoveredDeviceCount: 0` rather than as a failure.

The native quality scripts call the installed `cargo-fmt` and `cargo-clippy`
binaries directly. The verifier resolves the real Cargo binary and adds only
that binary's sibling directory to its child-process search path. This supports
package-manager layouts that install those tools without exposing them through
`cargo fmt` or `cargo clippy`; it does not change the host search path or install
toolchain components.

Reports are atomically written to:

```text
out/verification/<node-platform>-<architecture>.json
```

`out/` is generated and Git-ignored. Review the JSON after every run; do not
copy a passing state to another operating system or architecture.

## Report schema

The stable schema is intentionally split at the physical-evidence boundary:

```json
{
    "schemaVersion": 1,
    "generatedAt": "2026-08-28T18:11:35.399Z",
    "platform": { "os": "darwin", "arch": "arm64" },
    "tools": {
        "node": "v22.16.0",
        "npm": "10.9.2",
        "rustc": "rustc 1.95.0 (59807616e 2026-04-14) (Homebrew)",
        "cargo": "cargo 1.95.0 (f2d3ce0bd 2026-03-21) (Homebrew)"
    },
    "build": {
        "command": "npm run build:runtime",
        "passed": true,
        "exitCode": 0,
        "durationMs": 1179
    },
    "tests": {
        "command": "npm run native:quality",
        "passed": true,
        "exitCode": 0,
        "durationMs": 79629
    },
    "nativeService": {
        "smokePassed": true,
        "handshake": {
            "status": "ready",
            "mode": "native",
            "hardwareReady": false,
            "platformCapability": {
                "state": "insufficient-permission",
                "reason": "privileged-service-unavailable"
            }
        },
        "discoveredDeviceCount": 0
    },
    "hardware": { "verified": false, "operations": [] }
}
```

Durations and versions are observations from one host, not compatibility
promises. The committed documentation summarizes reviewed evidence; the
generated report remains the machine-readable source for that run.

## Reviewed native-host evidence

| Review date | Host                 | Build                 | Native quality        | Service handshake                                          | Validated devices | Physical operations                                                             |
| ----------- | -------------------- | --------------------- | --------------------- | ---------------------------------------------------------- | ----------------: | ------------------------------------------------------------------------------- |
| 2026-08-28  | macOS `darwin-arm64` | Passed                | Passed                | Ready, native mode; privileged service unavailable         |                 0 | None; hardware unverified                                                       |
| 2026-08-29  | macOS `darwin-arm64` | Passed                | Passed                | Ready, native mode; elevated repository development helper |                 1 | Application scan validated TANDBERG RDX; cartridge-state and operations pending |
| Not run     | Windows              | No native-host report | No native-host report | No native-host report                                      |                 — | None; hardware unverified                                                       |
| Not run     | Linux                | No native-host report | No native-host report | No native-host report                                      |                 — | None; hardware unverified                                                       |

The reviewed macOS run used Node.js 22.16.0, npm 10.9.2, and Homebrew
Rust/Cargo 1.95.0. macOS attached `com.apple.provenance` to generated Rust test
executables and stalled them before `main`. For this local evidence run only,
Cargo used a fresh target below `/private/tmp` and an ephemeral `RUSTC_WRAPPER`
that removed the attribute and ad-hoc signed only rustc's exact explicit Mach-O
test output. The wrapper was deleted and the isolated target was moved to Trash
after the run. The production verifier does not sign, remove attributes from,
or scan generated artifacts.

Windows and Linux have source, fixture, and cross-target coverage elsewhere in
the repository. That does not replace running this command on native Windows
and Linux hosts, so those rows remain unverified here.

## Physical acceptance matrix

Record application-level physical evidence only after the exact host, dock,
firmware, cartridge, and result have been reviewed. The 2026-08-29 low-level
The macOS probe validated `TANDBERG RDX` revision `0227` through physical USB
BOT, including endpoint-stall recovery and driver rematch. The development
Electron application then validated the same dock through its elevated
repository-built helper without an installed endpoint. Because the later media
snapshot reported `No cartridge` and no operation ran, the generated report
remains `hardware.verified: false` with no accepted operations.

| Operation class                 | macOS                                                        | Windows                                             | Linux                                               |
| ------------------------------- | ------------------------------------------------------------ | --------------------------------------------------- | --------------------------------------------------- |
| Discovery and status            | Application drive discovery proven; cartridge status pending | Pending native host and attached RDX hardware       | Pending native host and attached RDX hardware       |
| Self-test and LED test          | Pending attached RDX hardware                                | Pending native host and attached RDX hardware       | Pending native host and attached RDX hardware       |
| Safe and forced eject           | Pending disposable test media                                | Pending native host and disposable test media       | Pending native host and disposable test media       |
| Mode and drive-letter changes   | Pending compatible test dock                                 | Pending native host and compatible test dock        | Pending native host where applicable                |
| Firmware update                 | Pending recoverable test dock                                | Pending native host and recoverable test dock       | Pending native host and recoverable test dock       |
| Partition, format, and security | Pending explicitly disposable media                          | Pending native host and explicitly disposable media | Pending native host and explicitly disposable media |

Code signing, notarization, service installation, packaging, publishing, and
distribution remain separate release work and are not proven by this report.
