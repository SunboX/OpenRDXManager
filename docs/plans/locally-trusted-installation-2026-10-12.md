<!-- SPDX-FileCopyrightText: 2026 André Fiedler -->
<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->

# Locally trusted installation implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox syntax for tracking.

**Goal:** Deliver authenticated locally trusted Windows and macOS installation without public signing credentials.

**Architecture:** Elevated installers protect and enroll the complete app runtime. Native peers verify enrolled content and operating-system process identities before admitting protocol traffic. Packaging generates enrollment only after executable editing/signing and adds native install/repair/remove transactions.

**Tech stack:** Electron 44, electron-builder 26.17, Node 22.16+, Rust 2024, macOS Security/launchd/Installer, Windows SCM/SetupAPI/NSIS.

**Spec:** `docs/specs/locally-trusted-installation-2026-10-12.md` (approved).

## Global constraints

- Keep application files below 1,000 lines, document APIs, preserve renderer isolation and all firmware/device/operation checks.
- Local trust is explicit administrator enrollment, never signature failure fallback or caller/environment policy selection.
- Windows remains LocalService; no class-wide/raw disk rights for interactive users. macOS uses the system PKG/launchd route.
- Never publish with failed or unverified installer/authentication gates. No physical mutation is authorized by a hardware-free test.
- Runtime inventory v1 is bounded JSON with `schemaVersion: 1`, `platform: "macos" | "windows"`, `files: [{path, size, sha256}]`, `links: [{path, target}]`, and `managerCdHash`/`helperCdHash` (40 lowercase hexadecimal characters on macOS, empty on Windows). Unknown fields, duplicate paths, traversal and absolute paths are rejected. Hashes are SHA-256 lowercase hex; paths use `/`.
- Windows inventory is generated at `<packaged-root>/resources/local-trust/runtime.json` after final EXE editing. It excludes its own path. Installer copies it to `%ProgramData%/OpenRDXManager/LocalTrust/runtime.json` only after verification. macOS inventory stays outside the signed bundle, is generated from the final app, then installed under `/Library/Application Support/OpenRDXManager/LocalTrust/runtime.json`.
- Windows app root is the existing fixed native Manager location in Program Files. macOS app root is `/Applications/OpenRDXManager.app`. Native fixed paths own policy; JSON cannot choose them.
- macOS framework symlinks are permitted only as explicit inventory entries with pinned literal relative targets resolving inside the protected app. Enrollment ancestors and all Windows reparse points are rejected. Unexpected app inputs cannot become executable configuration.

## Task 1: Shared bounded inventory and protected verification

Files: new `native/rdx-service/local-trust/{Cargo.toml,src/lib.rs}`, child Cargo dependencies, tests in that crate. Root owns this task and coordinates consumers.

Interfaces: `parse_inventory(bytes: &[u8], platform: &str) -> Result<RuntimeInventory, TrustError>`; `verify_runtime(root: &Path, inventory: &RuntimeInventory) -> Result<(), TrustError>`; `verify_enrollment(path: &Path, platform: &str) -> Result<RuntimeInventory, TrustError>`. Native platform ACL adapters prove protection before file content is accepted. Unix verification validates root ownership/no group or other write, ACL restrictions, no-follow parent traversal and retained identity. Windows implements its complete owner/DACL/reparse counterpart in the Windows task.

- [x] Write failing tests using temporary real files: valid inventory succeeds; duplicate/traversal/unknown keys/platform mismatch fail; wrong hash/size and escaping links fail.
  ```rust
  assert!(parse_inventory(br#"{"schemaVersion":1,"platform":"windows","files":[],"links":[],"managerCdHash":"","helperCdHash":""}"#, "macos").is_err());
  ```
- [x] Run `cargo test --manifest-path native/rdx-service/local-trust/Cargo.toml`; confirm missing implementation/failed assertions, then implement strict serde schema and SHA-256 retained-file verification. Do not weaken ownership for production tests; expose content-only verification separately from protection.
- [x] Run crate tests and native formatter/clippy, record results in this plan. Reuse production verification for temporary fixtures without accepting test paths as production trust locations.

## Task 2: Windows native enrollment, service and scoped devices

Files: `windows-native/src/local_trust.rs`, dedicated `installer.rs`/`device_access.rs`, `src/bin/openrdx-local-install.rs`, existing endpoint/service ACL/readiness modules and child Cargo configuration. Windows worker owns these paths only.

Interfaces: fixed install actions `install`, `verify`, `repair`, `remove`; no free path/SID/device arguments. Installer takes a verified Manager PID only for the existing active-console provisioning flow. `verify_installed_local_trust()` verifies protected fixed enrollment and app; client/server call it before authenticated readiness.

- [x] Write negative policy tests before implementation: writable/foreign/reparse runtime, copied Manager, spoofed server, service SID mismatch, unknown device or broadened ACL fail.
  ```rust
  assert!(validate_install_action("enroll-arbitrary-path").is_err());
  ```
- [x] Observe failures with child crate tests, implement protected handle/ACL policy and enrollment transaction. Preserve exact SCM configuration, pipe peer/session/SID checks and LocalService token validation.
- [x] Implement fixed registration and owned removal, active-user provisioning and service-specific SID; add positively identified per-instance RDX device access with protected prior-policy storage, verification and safe restoration. Refuse unsupported effective permissions without LocalSystem fallback.
- [x] Run all Windows child crate tests and native Windows builds on a Windows host; report platform-unavailable checks honestly. No macOS compile counts as Windows proof.

## Task 3: macOS native enrollment and mutual authentication

Files: `native/rdx-service/src/endpoint.rs`, `macos-native/src/endpoint.rs`, C endpoint implementation, new native macOS client addon/build script, `src/main/macos-native-endpoint.mjs`, `src/main/device-service-endpoint.mjs`, associated tests. macOS worker owns these paths only; coordinate dependency files before edits.

Interfaces: `createMacOsNativeEndpointConnector({addonPath})` mirrors direct Windows socket EventEmitter contract with `serverIdentityVerified()`. Fixed local enrollment creates a strict identifier+cdhash requirement. No arbitrary requirement or app path may enter from IPC.

- [x] Write failing requirement/peer tests rejecting missing/malformed enrollment, wrong cdhash, copied app, console mismatch, non-root/spoofed helper and resource tampering.
  ```js
  assert.equal(socket.serverIdentityVerified(), false)
  ```
- [x] Implement root-protected enrollment/resource verification and audit-token caller matching. Keep signed Team-ID policy distinct. Add pinned helper verification on the retained client socket before ready/data/write; update transport tests for both native platforms.
- [x] Run native macOS tests, addon build, focused Node tests and actual addon unauthorized-client test. Report any administrator-required installed validation separately.

## Task 4: Final packaging inventory, fuses and installers

Files: `scripts/local-trust-inventory.mjs`, `scripts/installer-config.mjs`, `scripts/prepare-installer-runtime.mjs`, Windows NSIS hooks, macOS PKG scripts, `scripts/release-assets.mjs`, workflow and packaging tests. Root owns integration; no concurrent edits with platform workers.

Interfaces: `createRuntimeInventory({root, platform})` returns strict v1 format; after-sign hook emits Windows inventory or prepares macOS PKG payload. macOS PKG scripts install the fixed protected payload and register only its daemon; NSIS invokes only the fixed native install actions after placing files.

- [x] Write failing final-inventory tests (tamper and unsafe paths) plus configuration assertions for NSIS include, PKG assets and fuses. Run `node --test test/installer-config.test.mjs test/local-trust-inventory.test.mjs test/release-assets.test.mjs` before implementation.
- [x] Implement inventory generation and install hooks. Generate macOS PKG outside signed app, include it in DMG and standalone assets. Keep ZIP portable. Set RunAsNode/NodeOptions/NodeCliInspect false, embedded ASAR integrity and only-ASAR true; assert actual packaged values.
- [x] Update the exact release inventory from 14 to 16 installers (one PKG per macOS architecture) and workflow collection. Preserve external-Node MCP launch with unpacked production dependencies.
- [ ] Package native host builds, verify final seals/inventory/fuses and actual app launch. No install script may run during an ordinary package build.

## Task 5: Setup UI, user guide and release gates

Files: macOS service-management/controller and narrow setup UI/locales/tests; user installation guide; CI native installed verification scripts. A separate worker may own UI/docs once native interfaces are fixed.

- [x] Write failing controller tests for installed local-mode status and repair guidance. Implement those states without auto elevation or SMAppService registration in local mode. Portable copies must display installer guidance.
- [ ] Verify clean install, repair, upgrade, tamper rejection, rollback and removal in disposable Windows/macOS systems using the actual installed app and service. Test unauthorized-client refusal before hardware traffic.
- [x] Run available local `npm run format:check`, `npm test`, `env -u ELECTRON_RUN_AS_NODE npm run smoke`, native quality checks and macOS ARM64 packaged launch/MCP; inspect focused Git diff. All architecture-specific installed verification remains in the pending CI gate above.
- [ ] Obtain non-destructive physical RDX acceptance on explicitly identified devices separately from no-device CI. Publish only after required evidence is complete; preserve the existing release if any gate is blocked.

## Execution ledger

- 2026-10-12: User approved design and authorized implementation and installer setup; publishing remains conditional on verification.
- Ruling: The inventory must remain outside the final signed macOS bundle to preserve its seal; known internal framework links are explicitly pinned rather than treated as arbitrary symlinks. Costs if wrong: packaged launch or strict seal verification fails and blocks release.
- Ruling: Execute platform-native workers in parallel with disjoint ownership, then integrate packaging. Shared inventory format above binds all workers.
- Ruling: macOS `/Applications` is an operating-system-owned root:admin directory with mode 0775. Permit only that exact trusted administrator-group ancestor; app content stays root-owned without group/other write. Do not change the system directory or grant ordinary-user writes. A wrong exception would permit replacement by an untrusted principal, so negative owner/group/path tests are required.
- Packaging RED: hardened fuse/fixed NSIS/PKG inventory tests failed as expected before implementation. GREEN: 13 focused inventory/configuration/release tests passed after implementation.

- 2026-10-12: Package version is 1.0.1. The user explicitly deferred commits, pushes, GitHub builds and publishing until a joint evening session. All changes and verification artifacts remain local.
- Ruling: Historical enrollment proves ownership for elevated repair/removal only. Modified or incomplete runtime bytes never authenticate a client or service. Candidate enrollment is published only after complete verification; any failed transaction leaves hardware access disabled.
- Ruling: First-install intent must be durable before payload writes. Incoming installer executables and their fixed sibling inventory require protected ownership, parent paths, no links and exact candidate hashes. Neither an unsigned caller nor arbitrary JSON may select a trust root.
- Ruling: macOS published inventory is root-owned 0644 because ordinary authenticated clients must read its public hashes; transaction/history files remain private 0600. Publication uses a retained verified inode and atomic rename.
- Packaging: PKG script archive headers are explicitly normalized to root:wheel without changing payload, BOM, script content or PackageInfo bytes. This is artifact verification; actual Installer extraction and privileged lifecycle acceptance remain pending.
- Packaging: Windows pins electron-builder NSIS toolset 1.2.1 and rejects custom compiler/resource overrides. Its elevation helper is included before inventory generation, and incoming bootstrap inventory is staged outside packaged native resources.
- Verification: Screenshot suites exceeded their existing child deadline when test files ran concurrently. The complete visual matrix passed with sequential test files; the npm command now serializes files without relaxing screenshot assertions or time limits.
- Compatibility: The macOS public-signing route remains explicitly separate and requires a compiled Team ID plus protected runtime, strict seals and fuses. A real public-signing certificate was not used in this local task. Windows local installation replaces the older signing-only installation path; unenrolled older installations require removal through their original installer.
- Pending gates: Actual elevated Windows/macOS installer lifecycle, both architectures in GitHub builds, and physical RDX acceptance. No portable launch, mock or platform-native unit test substitutes for these gates.

- Final local verification: 1,066 Node tests passed (19 skipped), native quality and actual development/packaged smoke passed; shared policy 26, macOS native 74 (one hardware test ignored), macOS installer 16 and Windows x64 native 111+20 tests passed. Windows NSIS/archive/lifecycle/temporary-source fixtures and native build passed. macOS ARM64 final PKG/DMG/ZIP, extracted payload/inventory, root script headers, strict seals, fuses, release helper and MCP bridge passed. See `docs/verification/local-trust-2026-10-12.md`; actual installed authentication, other architectures and physical access remain pending.

- 2026-10-12: User resumed release work and explicitly authorized commit, push, all platform builds, and a new release afterward. Required verification gates still apply.

## Namespace isolation amendment, 2026-10-13

Host installation repeatedly encountered macOS reactivating the old signed 0.1.0 registration, including after the exact original controller and a disabled cached-record check. The trigger remains unverified. Local and signed modes therefore use separate fixed launchd labels and sockets; both retain complete enrollment, protected runtime and peer authentication. The standalone plist and helper installation paths remain unchanged. An exact owned previous local job may be quiesced under protected history and retained leases; foreign/signed jobs are preserved. The shared hardware mutation lease remains required. Cross-platform, installed lifecycle and selected read-only physical acceptance remain open release gates.

## Task 6: Fresh executable macOS supervisor, 2026-10-13

Spec: the fresh executable supervisor amendment in `docs/specs/locally-trusted-installation-2026-10-12.md`. This corrects execution of the existing approved installer transaction; it adds no alternative trust route. The precise internal cause of EINVAL remains unconfirmed. The observed unsafe post-fork library boundary must be removed, without retries or permission exceptions.

Files: modify `native/local-install/macos/src/{main,package_source,transaction}.rs`; create cohesive native supervisor spawn/role modules and focused tests; update `test/macos-local-installer.test.mjs` only where source contracts move. Keep every file below 1,000 lines. Packaging continues shipping the same fixed `openrdx-local-install` executable; the optional diagnostic remains excluded.

Interfaces: a retained package-source guard provides its kernel-derived executable path, protected inventory bytes, retained CLI/inventory descriptors and `recheck() -> Result<(), String>`. The spawn boundary consumes that guard and the setup/hardware/listener/ready descriptors, returning only the actual kernel child ID in an owned cleanup guard. Internal entry consumes only compiled FD roles 3–8 and the exact literal `--internal-supervisor`. Normal `parse_action` still admits only prepare/install/verify/repair/remove. Existing private Y/N readiness and root C commit frames remain the transaction result interface.

- [x] Write RED regressions for a fixed internal role with extra arguments or ordinary UID, descriptor source/destination collisions, wrong file/socket roles, source inode mismatch and launch-frame failure. Preserve the original five-action public parser negatives.
- [x] Run a real ordinary-user fresh-exec fixture proving ACL checks execute in the new image, transferred descriptors retain exact inodes, and an independent contender remains blocked after parent handles close. Never label this privileged installation proof. Existing scratch evidence is `.tmp/postfork-exec-proof.log`.
- [x] Implement the retained source guard and collision-safe `posix_spawn` file actions. Stage descriptors above all fixed destinations, clear unrelated environment/descriptors, open standard streams on `/dev/null`, and restore transferred descriptors' close-on-exec bits in the new image. Recheck source identities immediately before spawning and in the child.
- [x] Implement root-only internal role validation and fresh historical/namespace/lease proof before calling the existing quiesce/revoke/commit sequence. Do not carry a caller-provided loaded-registration decision across the process boundary. Reject malformed roles before any privileged transaction action.
- [x] Test original-error preservation, actual child-only bounded kill/reap, exact owned socket cleanup and lease continuity on every spawn/readiness failure. Retain the 600-second transaction and fixed root peer checks; never use a supplied PID or fallback enrollment.
- [x] Run `SDKROOT=/Library/Developer/CommandLineTools/SDKs/MacOSX26.5.sdk cargo test --manifest-path native/local-install/macos/Cargo.toml --locked --features postfork-diagnostic`, feature Clippy with warnings denied, Rust formatting, focused Node packaging contracts and `npm run format:check`. Obtain independent read-only security/lifecycle review of the final diff.
- [ ] Build an actual fresh ARM64 PKG/ZIP, verify source, executable identities, root script metadata, exact payload inventory and strict seals, then obtain the user's administrator installation step. Verify installed native service authentication and selected dock identity/status without a device mutation. Require clean/repair/removal and copied/tampered rejection on both macOS CI architectures; require both Windows and Linux jobs and all 16 installers before creating the release.

## Task 7: Diagnose remaining installed acceptance failures, 2026-10-14

The fresh executable installer and installed Mac authentication now pass. The selected dock is rejected at worker acquisition before identity dispatch. Both Windows runners supplied elevated Manager and scheduled-worker tokens despite the existing launch paths. These observations require diagnostics at the failing boundaries before a transport or token-launch correction; they do not justify changing service authentication, account policy or device commands.

Mac worker scope: retain the fixed private child argument, root admission, exact rematch, acquisition/cleanup sequence and existing absolute initialization/command deadlines. Reuse the native bridge's existing bounded acquisition recorder, capturing only the owned worker's nonblocking stderr alongside its private stdout. Reconstruct compiled phase and closed error-category codes; never forward arbitrary child text, paths or identity. Drain flushed precleanup evidence before child termination, clear historical diagnostics after successful READY, and keep intermediate legacy failures distinct from terminal USB acquisition failure. Preserve complete discovery accounting with at most 32 rejection rows by folding overflow into the generic rejection count. No additional device operation is part of diagnostic getter or host fixtures.

Windows verifier scope: read only exact-size elevation type, linked-token availability, UAC policy, local builtin-account equality and the actual registered task run level. Publish boolean facts only, close owned query/linked handles, and preserve the original installer error and all existing launch, selection, session, principal and elevation guards. Do not change the paused VM, UAC, accounts, service permissions or production launcher while the context remains unobserved.

- [x] Reproduce loss of worker startup evidence and missing Windows context with focused RED checks; implement the bounded observations above.
- [x] Run real hardware-free child/pipe regressions for EOF, buffered precleanup evidence, malformed/oversized diagnostics, noisy stderr, unchanged deadlines, successful READY clearing and exact child reaping. Test complete 32-row overflow accounting and existing Busy behavior.
- [x] Run applicable native, Node, formatting and source checks; obtain independent read-only reviews of final production/verification diffs.
- [ ] Build and verify a fresh Mac package, obtain the user's native administrator installation step, and inspect its existing discovery result. Run the Windows context on both native CI architectures. Select any subsequent correction only from those observed facts.
- [ ] Complete the existing installed lifecycle, selected physical identity/status and all-installer release gates before publication.

Both Windows CI architectures now establish that UAC is enabled, the task is configured for LUA, and the selected console user is the local builtin Administrator. Their worker tokens are elevated, have Default elevation type and no linked token. The next Windows step is an opt-in test-only `CreateRestrictedToken` query probe. It neither launches nor impersonates a token, and its fixed CI wrapper rejects zero tests, missing observations, malformed output and failed Cargo execution. Successful queries are diagnostic evidence, not eligible Manager or installed-authentication proof. Select a launch correction only after both native runners report the derived token facts.
