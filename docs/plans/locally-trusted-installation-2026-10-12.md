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

Installed worker diagnostics now identify USB interface initialization as the remaining Mac boundary. The SDK permits the existing None option and nil queue, and documents delayed interface availability after configuration; a publication race remains an inference. Refine only the already-captured native error at this boundary into a fixed standard-IOReturn name. Preserve the original status, options, rematch/retry policy and deadlines; retain an unknown fallback and the reused-NSError provenance limitation. Rebuild/install and read existing discovery before selecting a transport correction.

The actual Windows x64 token probe creates a same-user/session, unelevated restricted token with administrator groups deny-only and only change-notification privilege present/enabled. Its integrity remains high. A prospective correction to the approved console-user handoff must explicitly lower and verify medium integrity and verify the exact protected Manager process; API query success alone cannot authorize release. Native ARM64 facts match x64. The reviewed launch proposal requires separate owned/borrowed process guards, retained inventory authority, exact same-console source and child proof, a defined publication/resume/admission transaction, primary-error preservation and no alternate launch/privilege route. A separate test-only medium-label experiment must pass on both Windows CI architectures before implementing the launcher.

### Windows handoff integration after actual child proof

Both native architectures passed medium-token readback in run 38520935645. The subsequent harmless child gate failed in run 38529387046 without exposing its cause; no process execution proof is claimed. Commit `73355be` adds fixed harness scheduling and closed failure diagnostics. Production integration remains held until both Windows runners establish actual suspended image/token proof, independent child execution and explicit cleanup.

The subsequent correction stays within the approved locally trusted design:

1. Add closed `install-console` and `repair-console` actions while retaining existing verified-PID forms. Accept no arbitrary executable, account, SID, session, environment or command arguments.
2. After `prepare_runtime`, retain the complete prepared inventory authority while resolving one kernel-verified ordinary console Manager, or creating an owned suspended Manager from the same caller's proven restricted medium token. Refuse elevated, conflicting, stale or different-console candidates; a different administrator can reuse the actual console user's verified Manager but cannot derive another account's identity.
3. Preserve existing service configuration, exact DACL, Manager token/image revalidation, scoped device policy, service SID and enrollment checks. Perform all fatal identity, console, liveness and policy checks before enrollment publication, which is the commit boundary and can admit an already-running Manager. Keep a created child suspended through that boundary, then resume it. Report subsequent startup/resume failures as committed setup requiring repair; preserve enrollment/history/device policy rather than assuming admitted hardware work can be terminated or rolled back. Keep created and borrowed guards distinct; never terminate a reused Manager or enroll a substitute after forwarding/exit. Any later termination or teardown requires independently verified hardware exclusion/quiescence.

   Publication must distinguish `NotPublished`, `Published` and `PublicationUncertain`. Mark the transaction and owned guard committed at successful rename before publication readback. A later readback failure, or uncertain visibility/durability, preserves enrollment/history/device policy and reports repair required unless non-publication is independently proved; a single `Result` must not trigger automatic precommit cleanup after a possible publication.

4. Preserve the primary failure and separately record closed rollback outcomes. Before precommit enrollment deletion or device-policy rollback, verify actual service quiescence/stopped state under the existing ownership mechanism; START-DACL revocation alone does not drain retained handles or connections. Restore only this transaction's exact still-owned changes, preserving previously valid grants and disconnected-device journal rows. Do not call the global historical device restore operation indiscriminately after failed repair. If quiescence or exact restoration cannot be proved, preserve history/journal and report repair required.
5. Replace the unconditional StdUtils/fallback and PowerShell PID selection with the fixed native console action. For an assisted different-account installation, offer a finite Retry/Cancel budget only when there are exactly zero eligible Managers and the caller SID differs from the console SID, after payload copy: the console user opens the exact installed Manager and retries within the same installer. Elevated/conflicting/unsafe candidates and all other denials remain hard failure; silent installation fails closed. Re-running the complete EXE with Manager open is not a demonstrated recovery route because its earlier process-close/uninstall/copy stages precede enrollment.
6. Give the disposable CI verifier a separate test-only fixed ordinary-worker bridge using the proven token/process path. Retain its own and selected Manager guards, finite operation modes and protected fixture identity; Manager mode waits for native handoff instead of launching a partial payload. Ship no general launcher.

Require focused negative tests for account/session switches, forbidden token properties, ambiguous/live-process changes, API failures, owned-child cleanup and rollback; then require both actual Windows installed lifecycle jobs. Complete all six final builds, all 16 installers and selected physical identity/status acceptance before publication.

### Isolated child process DACL control, 2026-10-14

Actual 71fa717 logs on both Windows architectures agree: medium child identity/token snapshots, fixture read/execute access, enabled Users/logon groups and queried object labels pass; source context enters the fixture, but reduced context fails DLL initialization. Source permits SDK ALL_ACCESS on child process/thread/token objects while derived/actual do not. This is a boundary to test, not a proven cause or production remedy.

Implement a separate opt-in ignored native control and strict fixed CI wrapper. First create an untreated owned suspended Wait fixture using the unchanged ordinary path. Retain bounded private owner/group/DACL/LABEL observations for its process, thread and token, prove exact image/token/current console, then measure the expected fixed DLL initialization failure and explicitly reap. Retain the same pinned Wait fixture across the matched baseline/treatment and clean it on every exit path. For the treatment, change only the process security descriptor: preserve its observed owner/group/LABEL and complete original ordinary DACL, adding one non-inheriting ALLOW ACE with SDK PROCESS_ALL_ACCESS for the exact verified TokenUser SID. Preserve every existing ACE, including denials; use no null DACL, broader trustee, token/default-DACL mutation or thread descriptor change. Pass a correctly sized non-inheriting SECURITY_ATTRIBUTES for the process only, keeping the original thread attributes, flags, environment, image selection, desktop, current directory and no-handle-inheritance settings.

Require private bounded descriptor readback showing exactly the intended process DACL and unchanged other security components; require unchanged thread/token descriptors and source token/default-DACL snapshots. Revalidate image, medium token, exact console identity and liveness immediately before resume. The same fixed hang fixture must remain alive at 100 ms, then be terminated/reaped through its owned handle; the positive fixture must complete independent self-token checks with exit zero and complete owned fixture cleanup. Failure, inconsistent controls or unsupported descriptor forms remain failure; retain the original error and independent cleanup outcomes. Only closed compiled phase/error/category tokens and boolean facts may leave the native test.

Use genuine RED tests for descriptor bounds, preservation of old ACE bytes/denials, exact one-user concrete-mask addition, owner/group/LABEL changes, unexpected thread/token changes, malformed/duplicate/unknown/orphan phase evidence and missing native execution/cleanup. Compile/test/Clippy/format and independently review frozen hashes before pushing. Run the optional control only after successful fixture compilation, preserve the fatal unchanged ordinary gate, exclude its three-day diagnostics from installer assets, and require actual results on both architectures before selecting a next step. No production, account, service, VM or hardware changes belong to this control.

### Fixed object DACL matrix after process-only insufficiency

Actual 53d9aa8 controls on both architectures establish exact process-only isolation and complete owned cleanup, but treatment still exits with DLL initialization failure. This change alone is insufficient; no positive fixture execution occurred. Implement a separate test-only eight-row matrix: baseline, process, thread, process-thread, token, process-token, thread-token and all three. Each row uses a fresh owned reduced token and at most one live owned child, the same retained fixed Wait image/options, and an independent positive image only after successful hang survival. Process/thread treatments add one exact-user concrete SDK ACE to private copies of their descriptors and pass only correctly sized noninheriting attributes.

Token treatments change only the fresh derived token object's DACL, never TokenDefaultDacl or token privileges/groups/owner/LABEL/session. A factory-only FreshDerivedToken type must own CreateRestrictedToken output exclusively and expose no source/raw-handle setter. The new token inherits source-handle rights; explicitly obtain READ_CONTROL/WRITE_DAC plus the existing fixed rights after recording source object descriptors, default DACL and full queried properties. Only the fresh derived type may call SetKernelObjectSecurity with DACL_SECURITY_INFORMATION. Preserve every old ACE/denial and all other components, and require exact treatment propagation into the actual child's token descriptor before resume. An unestablished intervention never resumes or yields a tested startup outcome. Avoid owner-setting DuplicateTokenEx and privilege adjustments.

Require source/object/default-DACL/reduction snapshots, exact image/current-console proof immediately before every resume, and independent owned reaping/fixture cleanup for every row. Stop further launches on source mismatch, unresolved cleanup or insufficient cleanup reserve. Bound total native work below the wrapper's 120-second deadline and preserve its 65 KB complete-output bound through compact closed markers. Preserve first infrastructure/isolation errors while collecting independently safe rows. Require eight unique fixed roles and internally consistent phase, outcome, exit and cleanup records; accept no caller-selected target, mask, trustee or variant.

Diagnostic completion and startup proof are distinct. Eight correctly isolated and cleaned loader failures may establish complete observations with no successful startup; they never authorize production integration or clear the fatal ordinary gate. A startup candidate requires hang survival plus independent self-check exit zero and cleanup, then actual confirmation on both architectures. Run real host descriptor negatives and strict parser RED regressions, cross-x64 compilation/Clippy, formatting and independent frozen review before committing. Keep the optional artifact outside installer collection. No production, account, service, VM or hardware change is part of this matrix.

### Fresh Mac interface error evidence

The selected dock is present again and installed authentication passes, but initial discovery records `usb-open-interface/io-internal-error`. The initializer returns nil; its shared NSError slot can retain an earlier error and provides no domain/current-call evidence. SDK contracts permit the current None/default/queue:nil call and retained child-before-parent ownership. [Apple DTS's matching error discussion](https://developer.apple.com/forums/thread/844378) recommends userInfo inspection and does not establish a signing, entitlement or full-disk-access remedy. Do not change those permissions or transport sequencing from this observation.

Capture a freshly nil-initialized per-call NSError slot at the same single interface constructor. Preserve existing transport result mapping separately, including previous shared-slot fallback when the constructor supplies no new error; changing that mapping requires separate reviewed behavior evidence. Before existing cleanup, emit only bounded compiled error-domain, known failure-reason, underlying-domain and known-code classes, with explicit missing/unknown cases. Classify only exact recognized domains and bounded recognized strings; never emit raw userInfo, text, paths, identifiers or recursive error objects. Retain the current options, capture/configuration/rematch, calls, retries, deadlines, command admission and release ordering.

Forward closed provenance through the existing nonblocking worker diagnostic path without extra discovery, inflated candidate counts or historical-error retention after READY. Keep malformed/unknown data private and fail closed; retain original acquisition status independently of diagnostic classes. Split cohesive modules before the 1,000-line limit. A real hardware-free constructor stub must reproduce stale shared-error attribution, verify fresh missing evidence and a genuine error/underlying classification, and assert one constructor call, unchanged returned NativeStatus and exact release order. Add malformed/oversized/unknown/privacy/READY-clearing/EOF regressions for the worker parser. Run applicable root/child native tests and Clippy, focused Node tests, Rust/npm formatting and independent frozen review before packaging. Build and verify a concrete fresh PKG before asking for the user's required administrator installation; then read the selected dock's existing discovery result before any transport remedy. No signing, entitlement, privacy, OS, VM or device-management change belongs to this diagnostic.
