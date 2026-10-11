<!-- SPDX-FileCopyrightText: 2026 André Fiedler -->
<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->

# Implementation verification

## Evidence boundary

This record separates four kinds of evidence:

1. **Fixture proof** exercises the real renderer, immutable store, workflows,
   validation, and narrow main-process service APIs with deterministic data.
2. **Build and contract proof** compiles code and runs portable tests, but does
   not prove a native host installation or attached hardware.
3. **Native-host runtime proof** starts the application or hardware service on
   the named operating system and records its actual terminal readiness state.
4. **Physical hardware proof** requires an explicitly selected RDX dock and,
   where applicable, a disposable cartridge. Only this evidence can complete
   [`hardware-acceptance.md`](hardware-acceptance.md).

A TANDBERG RDX USB dock and disposable 320 GB test cartridge are attached to
the current Mac. A bounded root-run `IOUSBHost`/BOT probe physically completed
SCSI INQUIRY and returned `TANDBERG`, `RDX`, revision `0227`. The development
Electron application subsequently completed an administrator-authorized scan
through the repository-built helper and displayed the same dock identity plus
device serial `7820746632` and USB 3. It did not connect to an installed service.
The later UI media snapshot reported `No cartridge`, so no cartridge status,
diagnostic, eject, write, format, firmware, or security result is claimed by
this document.

## Integrated functional fixture

[`test/integration/application-flow.test.mjs`](../../test/integration/application-flow.test.mjs)
mounts the production renderer controller and real views around strict device
snapshots. Operating-system and hardware effects are replaced only at the
existing intent, utility, and support boundaries. The summary and activity
exports use the real allowlist-only `SupportSummaryService`.

The flow verifies:

- selecting between two validated devices and rendering Status identity and
  firmware fields;
- the mutually exclusive disabled/enabled access controls;
- Self Test, LED Test, and Write/Read Test admission, operation-specific
  progress, cleanup-aware success results, and the one-operation lock;
- rejection of device selection while an operation owns the identity lock;
- Safe Eject admission through the closed structured utility request;
- suppression of a current Fixed/Removable mode no-op;
- firmware rejection while a cartridge is inserted, before any firmware
  operation is sent;
- rejection of a wrong exact-cartridge confirmation before format admission;
- language persistence and the renderer language-change callback;
- redacted local activity export and `RdxSystemSummary.txt` generation;
- a hardware-service crash, visible unavailable state, bounded retry intent,
  and recovery through a fresh discovery epoch.

Focused run on 2026-08-29 with Node.js 22.16.0:

```text
node --test test/integration/application-flow.test.mjs
tests 1, pass 1, fail 0
```

This is integrated application behavior with fixture devices. It is not an
attached-device result.

## Platform verification status

| Platform             | Source / portable proof                                                                                                                                                             | Native-host proof                                                                                                                                                                 | Attached RDX proof                                                                                        |
| -------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------- |
| macOS `darwin-arm64` | Runtime build, native quality, Node/Electron coverage, USB BOT wire/recovery tests, and Electron smoke passed                                                                       | The elevated repository-built development helper handshook in `native` mode and stayed alive across repeated scans without an installed service                                   | Application scan validated the TANDBERG RDX dock; cartridge-state and operation acceptance remain pending |
| Windows              | Windows models, endpoint policy, volume parsing, operation policy, service metadata, drive-letter policy, and non-Windows fail-closed stubs are covered by portable Rust/Node tests | Not run on a Windows host; installed named-pipe service, ACLs, SetupAPI discovery, SCSI pass-through, volume operations, and the N-API client remain native-host acceptance items | Pending                                                                                                   |
| Linux                | Linux models, endpoint policy, SG layout, operation policy, service/udev resources, and non-Linux fail-closed stubs are covered by portable Rust/Node tests                         | Not run on a Linux host; installed systemd socket service, peer credentials, udev/polkit access, SG I/O, mount operations, and native hotplug remain native-host acceptance items | Pending                                                                                                   |

The macOS machine-readable report is generated at
`out/verification/darwin-arm64.json` and is summarized in
[`platform-verification.md`](platform-verification.md). Its physical section is
deliberately:

```json
{
    "hardware": {
        "verified": false,
        "operations": []
    }
}
```

Portable Windows and Linux tests prove shared parsing, policy, schema, and
fail-closed behavior on the current build host. They do not execute code behind
the native `cfg(windows)` or `cfg(target_os = "linux")` host boundaries and
must not be reported as native Windows or Linux runtime success.

## Feature limits retained by verification

- Modern USB3/SATA3 firmware accepts only a matching, locally verified `.BIN`
  image through the bounded picker and native update path. It has not been
  transferred to physical hardware in this verification.
- Legacy USB2/SATA1 `.BIP` images remain blocked as
  `legacy-bip-format-unproven`.
- Security writes whose selectors, descriptors, policy flags, or compatible
  AES media layout are not proven remain visibly `evidence-incomplete` and
  disabled. A correct disabled state is not an operation success.
- Drive-letter changes are Windows-only and require the installed constrained
  service plus an authoritative available-letter list.
- `rdxctl --eject` and `--force` are wired to a real administrator-only native
  backend on macOS, Windows, and Linux. The CLI and authenticated service share
  one fail-closed OS ownership domain that encloses backend construction,
  exact-ID/revision discovery, dispatch, readback, and destruction. Default
  non-fixture tests prove ownership ordering/contention and native macOS lock
  integrity, including rejection of Unix special permission bits. Busy service
  sessions are refused individually without retiring the endpoint, and direct
  process authority remains separate from service/endpoint readiness facts.
  Fixture tests prove the complete revision-bound eject lifecycle.
  This does not replace installed native Windows/Linux acceptance or attached
  RDX eject proof.
- Format, reset, protection, firmware, force-eject, and write/read acceptance
  require the exact target identity and appropriate disposable or recoverable
  hardware.
- Packaging, code signing, notarization, installer behavior, publishing, and
  automatic application installation are separate release work.

## Visual verification matrix

The real Electron visual gate completed on 2026-08-29. The deterministic matrix
contains 31 states at both `1024 x 768` and `1440 x 900`, producing 62 PNGs plus
the machine-readable
[`visual-qa-results.json`](../evidence/phase-4-task-8/visual-qa-results.json)
manifest under [`docs/evidence/phase-4-task-8/`](../evidence/phase-4-task-8/).
Coverage includes:

- no device, ready device, no media, protected locked, and protected unlocked;
- Status, Encryption, Tests, Utilities, Activity, Help, Support, and
  Compatibility surfaces;
- routine, critical, and destructive preflight/progress states;
- a disabled-control rationale inventory with an associated rationale brought
  into the viewport, terminal success, terminal failure, service unavailable,
  and update unavailable;
- English, Chinese, German, French, Italian, Portuguese, Spanish, and Japanese;
- layout and accessibility evidence plus local-resource, error-stream, and
  renderer-health checks.

Every capture passed the local-resource, exact-window-bounds, sampled
horizontal-clipping, accessible-label, service-provenance, local-font/icon, CSP,
console, page-error, load-failure, and renderer-crash contracts. All captures
have zero horizontal scroll offsets, and the topbar, brand, and topbar action
cluster remain inside the viewport. Ordinary scenes have zero vertical scroll
offsets. For scenes intentionally positioned below the fold, the manifest
proves that the defining protected-access, destructive-preflight,
disabled-rationale, or unavailable-update target is inside the captured
viewport. The capture boundary also requires the returned bitmap to contain
foreground pixels inside renderer-declared brand, device-rail, main-surface,
and command-rail rectangles, or corresponding modal-overlay rectangles. The
separate Electron visual-QA entrypoint injects one unobtrusive three-by-three
pixel, uniquely colored positional fiducial into each test-only rectangle; this
instrumentation is absent from the production renderer and application. The
full screenshot is normalized to sRGB, decoded to top-down RGBA, and sliced at
the physical projection of that exact DOM rectangle. A bounded
invalidate/repaint retry rejects stale or horizontally shifted compositor
frames even when DOM geometry and plausible themed foreground remain correct;
the foreground count, fiducial count, and attempt count are recorded per
capture. The QA process hides the wall-clock-driven macOS overlay scrollbar;
the actual scroll offsets remain explicit in the manifest.

The manifest inventories all 288 disabled controls rendered across the matrix.
Keys are unique within each capture, and each control has rendered,
DOM-associated rationale text; keys are not claimed to be globally unique
across scenes or viewport sizes, and the complete inventory is not claimed to
be simultaneously visible in one screenshot. The dedicated disabled-reasons
capture brings one associated rationale into view and is pixel-distinct from
the generic Encryption capture at both sizes. State-specific checks also prove
protected-access locked/unlocked polarity, an enabled exact-identity
destructive preflight without starting an operation, and the visible
unavailable-update result.

Two explicit consecutive canonical runs preserved byte-identical content for
all 63 artifacts and identical scoped Git status. The process-level visual
suite passed three consecutive times at 5/5. Each run covered injected
before-mount and during-transition console failures, two canonical preservation
runs, distinct disabled-rationale captures, and meaningful-versus-bounded-noise
raster discrimination, including a process-level injected themed stale raster
without positional fiducials:

```text
env -u ELECTRON_RUN_AS_NODE npm run test:visual
OpenRDXManager visual QA passed: 62 screenshots

node --test test/visual-qa-electron.test.mjs
tests 5, pass 5, fail 0
```

The minimum-size routine-active, destructive-active, and operation-failure
captures were reviewed directly after viewport-reset hardening, along with the
protected locked/unlocked, destructive preflight, disabled-rationale,
unavailable-update, Chinese minimum-size, and Japanese expanded-size captures.
This is real Electron rendering around deterministic local fixtures and a
controlled no-device runtime transition. It does not represent attached RDX
execution.

The earlier files under `docs/evidence/phase-1-task-8/` remain historical shell
baselines and are not used as proof of the completed Phase 4 matrix.

## Final repeatable gate

Run from the repository root with the checked-in Node.js version:

```sh
nvm use
npm test
npm run test:visual
npm run native:test
npm run native:fmt
npm run native:check
npm run format
npm run format:check
env -u ELECTRON_RUN_AS_NODE npm run smoke
git diff --check
git status --short
```

For a native-host record, also run:

```sh
npm run verify:native-platform
```

Review command exit codes and output, the focused Git diff, the generated
platform JSON, and the Electron window. A successful no-device smoke test proves
the Electron/preload/service lifecycle on that host; it does not promote any
row in the physical hardware checklist.

## Completion handoff

Source, integrated fixture, full visual matrix, and the current macOS
low-level attached-device transport probe are complete. The privileged
application scan, all checklist operations, and native Windows and Linux host
reports remain pending. Continue with the ordered checklist in
[`hardware-acceptance.md`](hardware-acceptance.md) after the macOS
administrator-authorized service path is active and when the named Windows and
Linux hosts are available.
