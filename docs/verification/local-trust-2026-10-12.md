<!-- SPDX-FileCopyrightText: 2026 André Fiedler -->
<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->

# Locally trusted installation verification, 2026-10-12

## Current delivery state

The working tree implements the approved Windows/macOS local installation mode and uses application version **1.0.1** from `package.json`. The starting commit was `14a07d4`. Local implementation and verification initially remained uncommitted at the user’s request. On 2026-10-12 the user explicitly authorized committing, pushing, all platform builds and a new release after successful verification. The checks below describe the pre-release local evidence; native CI and installed acceptance must be recorded separately.

Local source verification is separate from installed-service and physical-device acceptance. No privileged installation was performed on the macOS development host. Windows native checks ran in the local Windows 11 ARM64 VM using x64 Rust/Node/MSVC; they do not establish native Windows ARM64 compatibility or a completed installer lifecycle.

## Completed local checks

- `npm test`: 1,066 passed, 19 skipped, zero failed. Test files run sequentially; real Electron screenshot assertions and existing time limits remain intact. Both complete visual runs and the intentional raster-error rejection passed.
- `npm run native:quality`: passed formatting, all-target checks and strict clippy for both feature configurations, native tests and strict API documentation.
- Shared trust policy: 26 tests passed. macOS native boundary: 74 passed, one physical-device test ignored. macOS installer: 16 tests passed, including ten cleanup-failure/retry scenarios exercised by a focused real-file test.
- `env -u ELECTRON_RUN_AS_NODE npm run smoke`: passed with the renderer mounted. The host service was unavailable; this establishes application startup only.
- Windows x64 VM: 111 native unit and 20 integration tests passed; release Rust/static-library and all five C++ sources compiled and linked with warnings denied. The addon rejected absent enrollment. Actual pinned NSIS archive-mode compilation, protected temporary-path selection despite a user TEMP override, user-owned source rejection, and PowerShell 5.1 boundary/lifecycle checks passed. Full installation was not run. The VM idle-pause setting and original stopped state were restored.
- Final macOS ARM64 PKG, DMG and ZIP build passed. Artifact checks verified strict seals, the release helper UUID, version, root payload/script metadata, exact script/native CLI bytes, extracted payload inventory, PKG parsing and the PKG-only DMG. The packaged app passed actual renderer/fuse and external-Node MCP verification; service authentication remained unavailable on the uninstalled host. The redistributed MIT notice for the derived Windows templates is included.
- Installer configuration, final inventory, copied-runtime/tamper policies, setup UI/locales, actual fuse-wire interpretation, PKG script metadata and PowerShell argument/error forwarding have focused regression coverage.
- Final real packaged UI: English/German installer guidance and Help/About were inspected at 1280×800; version 1.0.1 appears only in About. Repeated **Check again** did not elevate or alter the older service registration. Captures are under `out/verification/local-trust-ui/final/`. An optional unsupported CDP native-resize query was followed by renderer-target disappearance while the main process remained; its cause is unverified, and no additional German About or native-resize proof is claimed. The owned test process was closed afterward.

Detailed local logs are generated under `.tmp/`; screenshots and native fixtures are under `out/`. These are ignored build/verification artifacts and are not release evidence published to GitHub.

## Authentication and recovery boundaries

The elevated installer owns the exact installed app and enrollment. Native peers verify protected runtime bytes and kernel process identity before accepting protocol traffic. A portable copy, absent enrollment, modified runtime or spoofed peer cannot gain hardware authority through the setup UI.

Ownership-only historical records permit elevated repair or removal of a damaged generation. They never authorize IPC. Setup records first-install intent before writing payload files; new enrollment is published only after complete verification. Failed setup leaves privileged access disabled.

macOS keeps its separately signed route explicit. That route additionally requires a compiled Team ID, strict code seals, protected runtime and the five required Electron fuse states. A real public signing certificate was not exercised here. Windows uses the new local installer route; an older unrecorded installation must be removed through its original uninstaller before migration.

Final read-only reviews found no remaining actionable issue in the amended source. macOS removal retains the current ownership history through cleanup failures; Windows removal quiesces native ownership before process shutdown. Post-review focused tests and formatting passed.

## Release validation

1. Review the final scoped diff and local verification results. The user has authorized committing and pushing the scoped release changes.
2. Run the six native GitHub build jobs for macOS, Windows and Linux, each in x64 and ARM64. Do not publish if any required check fails. The complete release inventory is 16 installers, including two standalone macOS PKGs.
3. Exercise actual clean installation, authenticated installed-app launch, copied-app rejection, harmless runtime tamper rejection, repair, upgrade, interrupted setup recovery and owned removal on disposable Windows/macOS systems. Confirm installer temporary-source protection and that macOS Installer extracts protected scripts with the required ownership.
4. On Windows, verify the limited active-console Manager and LocalService hardware service; SYSTEM/session-zero execution does not count. On macOS, launch the installed app as the desktop user after administrator-approved PKG setup.
5. Select an explicitly identified RDX dock for non-destructive physical access checks. Verify service/device readiness and supported read-only status before considering any device mutation. Software or no-device CI success does not prove physical access.
6. Verify all installer names, versions and checksums, then publish only after the required installer, architecture and device evidence is complete.

The macOS development host still has an older SMAppService registration associated with the original 0.1.0 app at `dist/macos/OpenRDXManager.app`. The new installer must not silently replace this unrecorded registration. Use the original app's service controls to unregister it before a deliberately authorized migration; no such change was made during local checks.

See the [approved specification](../specs/locally-trusted-installation-2026-10-12.md), [implementation plan](../plans/locally-trusted-installation-2026-10-12.md) and [user installation guide](../installation.md).

## Release preflight amendment

The fresh pre-commit suite exposed an intermittent macOS QA resize mismatch: the viewport and CSS title had settled but the native overlay API retained the prior width. The QA helper now waits for the renderer viewport and reaffirms unchanged native button visibility, which explicitly publishes overlay layout in Electron 44. The exact overlay/CSS geometry and raster assertions remain unchanged. A focused ordering regression failed before the amendment and passed afterward. Source reference: [Electron 44 native window implementation](https://github.com/electron/electron/blob/v44.0.0/shell/browser/native_window_mac.mm#L1409-L1421). Full-suite verification is rerun before committing.

The later fresh suite also exposed an intermittent visual-process deadline without a completion marker. Phase diagnostics and a reduced reload reproduction were added; the reduced reproduction and a traced full 62-capture run passed. The cause of the deadline is not verified. Optional phase traces remain available through `OPENRDX_VISUAL_QA_TRACE=1`; a fresh complete traced suite is required before commit.

The user selected this Mac for read-only physical acceptance. The current `IOUSBHostDevice` registry identifies dock `1a5a:0005`, serial `007820999743`; the legacy USB plane and System Profiler returned no devices. This is identification only, not installed-service or hardware-protocol proof. The earlier 0.1.0 registration remains and new PKG installation requires administrator authentication.

Final pre-commit verification: `OPENRDX_VISUAL_QA_TRACE=1 npm test` passed with 1,069 tests passing, 19 skipped and zero failed. Both complete screenshot runs and intentionally corrupted-image rejection passed. Formatting and staged diff checks passed. This supersedes the failed diagnostic preflight attempts; it does not establish physical or installed-service acceptance.
