<!-- SPDX-FileCopyrightText: 2026 André Fiedler -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# macOS Authenticated GUI Worker Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task by task. Steps use checkbox (`- [ ]`) syntax for tracking. Root and independent design review precede implementation; this document does not authorize privileged execution, installation, device operations, commits or publication.

**Goal:** Start every authenticated macOS capture worker in its verified Manager peer's graphical audit session, retaining the service's privileged credentials and existing device ownership boundaries.

**Architecture:** Retain an opaque, revocable capability from the already authenticated native connection. Each worker spawn freshly validates that exact live peer, session and installed generation, invokes the fixed public `launchctl asuser` route, and completes a private child context handshake before worker IOKit access. Initial discovery, reacquisition and recovery share this factory; explicit direct CLI remains a separate authority route.

**Tech Stack:** Existing Rust service and macos-native crate, existing C endpoint verifier, public Security/AuthSession/libbsm/task audit APIs, `/bin/launchctl`, existing owned child pipes and bounded worker protocol. No dependencies or private audit APIs.

**Spec:** `docs/specs/locally-trusted-installation-2026-10-12.md`, together with the design contract below. This is a proposed extension of the approved locally trusted installation architecture, pending root and independent review before source changes.

## Global constraints

- Preserve signed and locally enrolled Manager authentication, protected runtime/seal checks, fixed endpoint namespaces, hardware ownership leases and manufacturing evidence gates.
- No renderer changes, caller-selected UID/PID/path/argument/environment, global UID-to-session registry, backup-owner-derived authority, TCC reset, policy exemption or new device command.
- Windows and Linux behavior is unchanged. New native policy is macOS-only; shared context edits must be mechanical and covered in both feature modes.
- Keep every handwritten file below 1,000 lines. Use Node.js 22.12.0 or newer and the checked-in `.nvmrc` when running application checks.
- Root probe success is context/transport evidence only. Actual installed capture and selected-device acceptance remain separate gates.
- This task produces a plan only. Implementation, packaging and live verification follow review and existing authorization boundaries; no new user design-approval round is required.

## Evidence and present boundaries

The completed, root-run synthetic diagnostic is `/private/tmp/openrdx-system-session-result-lilz44d7.json`. Its three baseline cases ran with anonymous audit UID `0xffffffff`, ASID `100013`, root session and no graphical session. Its three `asuser` cases had audit UID `502`, ASID `100014`, graphical session and no root-session attribute. Real/effective UID and GID remained zero. The retained actual child PID, parent PID, process group/session, pipes, exit 37, SIGTERM, bounded SIGKILL escalation and reaping passed. The exact temporary diagnostic job was unloaded and its directory removed. These numbers describe this run; none becomes a production constant.

| Evidence | SHA-256 |
| --- | --- |
| Root result JSON above | `49051a8b9703ceaab2c38bac77e652ecdb8057104c756f9ab4fd0078a380e6c4` |
| `.tmp/probe-root-system-gui-session.py` | `7a06daeadd37abf7927bd0195022b7b8e4e1663b4b24bfb2aea2d7ec076641fe` |
| `.tmp/root-system-session-payload` | `ae2c477d6e66556e2da00c315434963e3611f0ce04bf6627a69ffab07930ac85` |
| `.tmp/root-system-session-manual-entry.txt` | `0db8a583755e7c1206589bf46f4ac9e11489d556d772e901726c0ef0880c9c98` |
| `.tmp/root-system-session-frozen-sha256.txt` | `db460402e2577ebfedce03aa2756b53e46c791e2a2644e0031313dd0c115e49c` |

Current source exports only authenticated UID: `native/rdx-service/native/macos/rdx_endpoint_identity.c:151–236` already obtains the whole `LOCAL_PEERTOKEN` and uses `kSecGuestAttributeAudit` for dynamic code verification, but returns only UID. `macos-native/src/endpoint.rs:53` retains a stream and UID. `src/service/execution_context.rs:12` is currently `Copy`, with flags and optional backup-owner UID. None of those values currently supplies a GUI-session capability.

Worker creation currently occurs at `src/platform/macos/open_candidate.rs:104` and `src/platform/macos/host.rs:29–46`; recovery constructs a backend at `src/service/recovery/native.rs:280`. The actual process creation is `macos-native/src/scsi_worker.rs:52`. All paths below are relative to `native/rdx-service/` unless stated otherwise.

Public SDK evidence: `Security.framework/Headers/AuthSession.h:128–147` documents querying any known session ID through `SessionGetInfo`. `bsm/libbsm.h` exposes audit UID, effective UID, PID, PID version and ASID getters. Use these supported interfaces, including the existing audit-token-bound `SecCodeCopyGuestWithAttributes`; no audit-session mutation API is introduced.

## Design contract

### Connection authority and lifetime

`MacManagerSessionLease` is a unique, non-`Clone`, non-`Copy` owner created once from a successfully accepted native Manager connection. Its `MacWorkerFactory` handles are `Clone` and share one private `Arc<PeerSessionState>`; cloning cannot create a new lifetime. State contains the original full kernel audit token, derived UID/EUID/PID/PID-version/ASID, the accepted socket, pinned Manager requirement and runtime-generation evidence, plus an active/revoked admission gate. Fields and constructors remain private; neither serde nor a general UID constructor exists. Debug output redacts peer data.

The endpoint session owner encloses the framed reader, writer, runtime and recovery lifetime. An explicit `revoke()` closes new spawn/request admission on first EOF, protocol failure, cancellation or session exit **before** waiting for recovery teardown; owner `Drop` repeats revocation defensively. The framed runtime additionally owns an inner `SessionRevokeGuard`, declared after its runtime/recovery owners and before processing any request, so reverse local drop order revokes before recovery `Drop`/join on every return, writer failure and unwind. The outer endpoint lease alone is too late. Socket clones for the reader/writer share the state but never own revocation or mint a lease. Factory clones retained by a handle/recovery task remain permanently unusable after revocation. A subsequent connection gets a different owner/state even for the same UID.

Use a private mutex admission gate for the active state and final pre-IOKit acknowledgement. Perform all native Security.framework, session and generation validation **outside** that mutex; a stalled native call must not prevent EOF/teardown from revoking. After validation, acquire the gate only for the final active/state/deadline check and bounded nonblocking-pipe ACK. Serialize the quick active check at each new runtime-request admission with revocation, including queued requests not yet admitted. Do not hold the gate through device operations. Work admitted first retains its existing deadlines, cancellation checkpoints, certainty and cleanup; revocation prevents later requests and every later spawn. Cleanup/release needs no fresh GUI admission. Do not add per-SCSI-command validation, a logical-operation permit layer, forced mutation termination or new cleanup commands.

On macOS, add `Option<MacWorkerFactory>` to `ServiceExecutionContext`, retain `Clone` and remove `Copy`; getters borrow `&self`. Preserve `Copy` on other platforms with a conditional derive. Use one small `duplicate_for_runtime(&self) -> Self` helper at shared backend/runtime/recovery transfers: its macOS branch returns `self.clone()` and its non-macOS branch returns `*self`. Mac-only transfers may clone directly. This avoids `clone_on_copy` warnings without broad lint suppression. Equality of two factory handles is shared-state identity, never a comparison of UID alone. Flag-only context constructors carry no factory. `with_backup_owner` continues to select storage ownership only and cannot attach a factory. Attaching an opaque native-minted factory requires the endpoint/process-authorized context; absence or mismatch denies the authenticated GUI route.

### Fresh validation and session generation

Before **each initial, reacquisition or recovery spawn**, and again immediately before admitting worker IOKit initialization:

1. Require active connection state, original service credentials and unchanged pinned installation generation. Reuse the existing local inventory/requirement comparison or signed protected-runtime verification; do not accept a new generation into an old connection.
2. Obtain the accepted socket's full kernel credentials/token again and compare the complete token to the retained original. A socket token may be cached after peer exit, so this comparison alone is insufficient.
3. Perform a fresh dynamic-code lookup using the retained full audit token, including its kernel PID version, and repeat the existing dynamic identity, exact executable, marker, nested static seal and pinned requirement checks. Failure to resolve a live exact process denies admission; do not fall back to PID-only lookup or `kill(pid, 0)`.
4. Require audit UID and effective UID equal the non-root current `/dev/console` owner; positive peer PID, nonzero PID version and an ASID that is neither zero nor either reserved sentinel. Query `SessionGetInfo(peer_asid)` and require success, returned ID equal to that ASID, graphical access, no root-session attribute and no remote-session attribute. Test those known bits with masks; tolerate other bits rather than requiring exact attribute equality (the actual valid probe returned `0x6030`). Keep raw attributes private. Recheck console owner after native identity/session validation.
5. Compare all retained token fields and generation in validation outside the admission mutex; then perform the final active/state/deadline check under the gate before ACK. A live socket, a surviving GUI session or the same console UID individually is insufficient. Peer death/exec, PID reuse, logout, console switch and generation replacement make fresh worker eligibility fail closed. These checks do not promise continuous per-command session verification of an already admitted operation.

The ASID retained at authentication is the connection's session generation. `launchctl asuser` selects a session for the UID rather than an arbitrary supplied ASID. Therefore, even after parent validation, the actual child must prove the **exact retained ASID**; a same-UID login in another session must fail closed. Do not infer an ASID from a console UID. This is conservative if the OS cannot provide the required public evidence; no UID-only fallback is allowed.

### Fixed launch and child context proof

The GUI factory launches exactly:

```text
/bin/launchctl asuser <decimal UID from verified native lease> <verified current executable> --openrdx-internal-macos-scsi-worker
```

The executable comes from `current_exe()` and must match the current service's protected installed executable and pinned generation. Never use the Manager path as the worker program. Clear the child environment, retaining only fixed `LANG=C`; use absolute paths. The only child descriptors are the existing owned stdin/stdout/stderr pipes; all service sockets, locks, retained source files and unrelated descriptors remain close-on-exec. Preserve parent hardware ownership continuously; no lock descriptor is delegated to the worker.

Add a versioned private context preflight before existing `FRAME_INIT` is allowed to enumerate or open IOKit. Use new fixed context frame kinds and a bounded fixed-width record, below the existing 8,192-byte frame cap. Parent sends expected mode, UID/AUID/ASID, service PID and actual service GID/EGID; those expectations come only from its native capability/credentials. Worker independently reads public `TASK_AUDIT_TOKEN`, `SessionGetInfo(callerSecuritySession)` and real/effective credentials/PID/PPID, checks the expectations, and returns its observations without touching IOKit. Parent requires:

- Child PID and audit PID equal the actual retained `Child::id()`; PPID equals this service; child PID version is valid.
- Real/effective UID remain zero, GID/EGID equal the actual service values, and child AUID/ASID equal the verified Manager's exact AUID/ASID with eligible graphical session attributes.
- Fresh parent lease/peer/generation validation still passes before a fixed `CONTEXT_OK` acknowledgement. Only then may worker initialization enumerate, rematch, capture or open an interface.

Do not hardcode GID zero: the synthetic probe used zero, while the installed local service's configured group can differ. Preserve the existing service account and group gates. A launchctl wrapper that leaves the real worker as a different grandchild fails PID proof; no guessed PID search is permitted.

The current 15-second initialization budget begins after the child and pipes are owned/configured. Preflight and existing INIT share that one absolute deadline; no separate reset or extra 15-second phase. Keep existing identity timeout (5 seconds), command deadline (request timeout plus 5 seconds), release timeout (5 seconds), reap timeout (500 milliseconds), nonblocking pipe setup, bounded diagnostics and `UNREAPED_WORKER` Busy gate. Child ownership is armed immediately on spawn and survives every failed setup/proof/read/write/ACK. Kill/reap only that retained child, never the peer, a process group or a caller PID. Every new write/read is deadline-bounded, including EINTR and malformed/partial frames.

Native Security.framework verification remains synchronous, as at today's accept boundary. Check the absolute deadline before and after verification and refuse an expired result; do not claim these checks can preempt a stuck native call. Review measured verification latency before release. A separate cancellable verifier process is outside this change and must not be introduced implicitly to hide this limitation.

The private proof contains sensitive process/session metadata. Keep it inside owned pipes; expose only closed stage/error tokens through existing diagnostics. No new public service response shape, raw token, UID, ASID, PID, path or environment value is logged.

### Admission, reacquisition and explicit CLI

Initial open, storage handoff/reacquisition, migration identity and recovery keep the same per-connection factory. Preserve exact candidate guards, optional telemetry, cached/staged recipes, mapping invalidation, unmount ordering and parent authority release. A factory does not select a device and cannot replace the exact rematch identity. Fresh full peer/session/generation validation applies to every new initial/reacquisition/recovery spawn and its final ACK; do not add revalidation to commands on an existing worker. The runtime's quick active guard rejects new requests after revocation, including queued requests not yet admitted. Existing admitted calls preserve their current deadlines, cancellation, certainty and cleanup, with no new permit layer. Cleanup/release is never gated on fresh GUI eligibility.

The explicit direct CLI and serial CLI use a distinct native-minted direct-process factory after the existing actual privilege checks. It uses the current executable directly and proves unchanged caller audit session/credentials plus actual child identity in the same private preflight; it never calls `asuser`. Privileged debug stdio may use this direct-process route only under its existing debug/process authorization. Missing GUI authority never falls back to direct authority. A context boolean, CLI argument, backup UID or renderer message cannot manufacture either native factory.

## Implementation tasks

Each task is a sequential review unit. Record a genuine failing test before its implementation and retain its output. Do not commit or push during these tasks unless the root receives explicit authorization. New test constructors/injected native observations stay test-only and never substitute fabricated proof in production.

### Task 1: Retain and freshly verify the native peer/session proof

**Files:** Modify `native/macos/rdx_endpoint_identity.c`, `native/macos/rdx_endpoint_identity.h`, `native/macos/rdx_endpoint.c`, `native/macos/rdx_iokit.h`, `macos-native/build.rs`, `macos-native/src/lib.rs`, `macos-native/src/ffi.rs` and `macos-native/src/endpoint.rs`; create cohesive `native/macos/rdx_peer_session.c`, `macos-native/src/peer_session.rs` and `macos-native/src/peer_session_tests.rs`. Register native sources in `build.rs` and Rust modules in `lib.rs`.

**Interfaces:** Add a dedicated version-1 C output record containing the full eight-word audit token; its size/version are checked at the FFI boundary and its Rust fields stay private. Preserve the old socket/UID accept entry as a compatibility wrapper. New `rdx_macos_accept_launchd_manager_with_session(listener, requirement, out_socket, out_session)` and `rdx_macos_revalidate_manager_session(socket, requirement, expected_session)` share the original full verifier. Rust exposes no raw record getter. This separate record does not alter existing ABI-4 layouts.

- [ ] Add tests for exact token retention only after full authentication, wrong record size/version, UID/AUID/EUID mismatch, invalid PID/version/ASID, dead/changed-token guest lookup, invalid/non-graphical/root/remote session, console change and pinned-runtime replacement. Require valid graphical attributes with additional unknown bits, including the observed `0x6030`, to pass the session-bit classifier. Existing copied/tampered Manager rejection remains asserted.
- [ ] Run the new focused `peer_session` tests through the child crate and capture failure before adding the new native API. A missing API/compiler failure is initial scaffold evidence; require behavioral rejection failures once the fixture compiles.
- [ ] Implement one shared native verifier and the new bounded output record. The decisive logic is:

```text
accept: original credentials + dynamic/static seal proof -> full token -> eligible SessionGetInfo(token.asid) -> private record
revalidate: exact retained token + fresh token-bound live SecCode proof + same eligible session + console before/after -> success
failure anywhere -> no session record / no authority
```

- [ ] Run `cargo test --manifest-path native/rdx-service/macos-native/Cargo.toml peer_session` and the existing endpoint contract tests. Compile the native C path against the public SDK. Require all old authentication negatives and new session negatives green; mocks prove branching only, while installed dynamic-peer proof remains Task 6.

### Task 2: Introduce revocable connection ownership and explicit context cloning

**Files:** Modify `macos-native/src/endpoint.rs`, `macos-native/src/lib.rs`, `src/service/execution_context.rs`, `src/bin/openrdx-hardware.rs`, `src/service/runtime_loop.rs`, `src/service/recovery_session.rs` and context transfer sites in `src/service/recovery/native.rs`/`src/platform/macos.rs`; create `macos-native/src/worker_factory.rs`. Keep modules cohesive rather than enlarging existing near-limit files.

**Interfaces:** `ManagerEndpointConnection::begin_worker_session(&mut self) -> Result<MacManagerSessionLease, NativeError>` is one-shot across stream clones. `MacManagerSessionLease::factory(&self) -> MacWorkerFactory`, `revoke(&self)`, and `Drop` use shared private state. `MacWorkerFactory::revalidate(&self) -> Result<(), NativeError>` implements Task 1 plus generation/lifetime checks outside the admission mutex; `ensure_active(&self) -> Result<(), NativeError>` is the quick new-request admission check. `SessionRevokeGuard::new(factory: MacWorkerFactory) -> Self` revokes on `Drop`. `ServiceExecutionContext::with_macos_worker_factory(self, factory: MacWorkerFactory) -> Self` attaches only to an authenticated/process-authorized context; `macos_worker_factory(&self) -> Option<&MacWorkerFactory>` borrows the opaque handle; `duplicate_for_runtime(&self) -> Self` handles platform-aware duplication.

- [ ] Add behavioral tests: stream clones cannot mint two owners; owner drop/revoke disables all existing factory clones; EOF/first-frame error/cancellation/writer failure/unwind invalidates before recovery join; queued unadmitted requests refuse after revocation; a fresh same-UID connection cannot revive an old factory; backup-owner and flag-only contexts have no factory. Barrier regressions must hold recovery teardown pending and prove the inner guard already revoked, and stall native validation while proving another thread can revoke. Use synchronization barriers rather than sleeps.
- [ ] Run focused endpoint/context/recovery tests and capture their failure under the current UID-only/Copy model.
- [ ] Implement the private owner/state split, macOS-only non-Copy context and borrowed getters. Use `duplicate_for_runtime()` at shared transfers, with cfg branches that clone on macOS and copy elsewhere. Own the lease in the connection-session scope; declare the inner RAII guard after runtime/recovery owners and before any session work. All early returns, writer errors and unwinds must revoke before those owners drop/join. Recovery holds a factory clone, never the lease owner. Preserve non-macOS Copy and current boolean authorization semantics.

```rust
// Target ownership usage; only accepted native connection can mint this lease.
let session = connection.begin_worker_session()?;
let context = context.with_macos_worker_factory(session.factory());
// Inside the framed runtime, after creating its inactive runtime/recovery owners:
let _revoke_before_runtime_drop = SessionRevokeGuard::new(session.factory());
// Process requests only after this guard exists; reverse drop order revokes first.
```

- [ ] Run focused tests plus `cargo check --manifest-path native/rdx-service/Cargo.toml --all-targets --all-features` and `--no-default-features`; inspect all context transfers for accidental owner cloning or UID reconstruction. Run both feature-mode Clippy checks with warnings denied, including non-macOS CI, to catch `clone_on_copy` rather than suppressing it.

### Task 3: Gate the fixed launch with actual child context proof

**Files:** Modify `macos-native/src/scsi_worker.rs`, existing worker protocol/dispatch modules and their test modules; create `macos-native/src/worker_context.rs` and public-API C self-audit helper beside `rdx_peer_session.c`. Add focused owned-child process fixtures. Keep diagnostics modules' existing bounds/privacy contracts.

**Interfaces:** `MacWorkerFactory::spawn(&self, identity: &MacRematchIdentity) -> Result<MacScsiWorkerLease, NativeError>` is the authenticated GUI entry. Native self-audit returns a private fixed-width `WorkerContext` record. Internal `verify_child_context(expected, observed, owned_child_pid)` is pure and cannot grant a factory. New context frame kinds precede INIT and share its existing absolute deadline.

- [ ] Add real child-pipe regressions for context-before-IOKit ordering, successful fixed preflight, wrong actual PID/PPID, root credential loss, GID drift, wrong UID/ASID, stale peer between proof and ACK, malformed/partial/oversized proof, EOF, silent deadline, stderr chatter and setup failure. Add a barrier case revoking during native validation; the final gate must refuse ACK without blocking revocation on that validation. Assert zero initializer/capture calls on every refusal. Genuine ordinary-context self-audit fixtures use the real public APIs; positive graphical-root expectations stay in the already completed synthetic evidence and Task 6 acceptance.
- [ ] Run focused `worker_context` and owned-child tests, demonstrating current INIT can occur without proof and the new refusal expectations are red.
- [ ] Implement the fixed launcher, cleared environment/descriptor policy, early owned-child guard and the preflight. Validate actual `Child::id()` against self-audit; revalidate/gate the exact connection before ACK; only then send existing INIT. Maintain one initialization deadline, original native error mapping and all existing kill/reap/Busy behavior.

```text
own Child+pipes -> nonblocking setup -> context request -> bounded self-proof
-> exact actual child + fresh peer/session/generation validation outside gate
-> gate: active/state/deadline check + bounded CONTEXT_OK
-> unchanged INIT(identity) -> unchanged READY / native failure
```

- [ ] Run child worker/context/diagnostic tests, including original failure/setup/reaping and 32-record diagnostic accounting regressions. Audit descriptors for close-on-exec and verify fixed executable/argv/environment assertions. No blocking pipe drain, unbounded child wait or retry that resets the deadline is acceptable; record the synchronous native-verification limitation separately.

### Task 4: Carry the factory through every device worker lifecycle

**Files:** Modify `src/platform/macos.rs`, `src/platform/macos/open_candidate.rs`, `src/platform/macos/host.rs`, `src/service/recovery/native.rs` and their focused platform/recovery fixtures. Update `test/discovery-diagnostics-stage-contract.test.mjs` only if closed context-stage tokens need source-contract coverage.

**Interfaces:** The Mac backend extracts and retains `MacWorkerFactory`; each `MacOsDeviceHandle` retains its clone. Replace authenticated-route raw `MacScsiWorkerLease::spawn(identity)` with `factory.spawn(identity)` in initial discovery and `start_scsi_worker`. Recovery receives `context.duplicate_for_runtime()` with that same factory. Do not add factory revalidation to retained-worker commands or a new operation-permit type; quick active-state checking belongs at new runtime-request admission from Task 2.

- [ ] Add tests asserting factory calls for initial open, migration identity, storage handoff/reacquisition and recovery after rematch. Invalidate the owner between spawns and assert refusal before the next initializer. Assert same-UID/new-ASID and new installation generation cannot reuse cached recipes or recovery context as authority for a new worker. Preserve a regression where an already admitted multi-command operation reaches its existing cancellation/certainty/cleanup checkpoints after revocation without a new GUI check or new command; a queued unadmitted request must refuse.
- [ ] Run those tests red against the raw spawn paths. Keep exact accepted-candidate, unmount, mapping invalidation, parent-drop, optional-telemetry and recovery command-order assertions intact.
- [ ] Replace only the authority source at those paths, preserving native return/options/deadlines and lease/recipe sequencing. Retain a refused worker's existing native error/privacy behavior; do not introduce capture retries or fallback to parent IOKit.

```text
unchanged exact candidate / storage handoff / release ordering
-> retained connection factory fresh validation + spawn
-> unchanged identity/command protocol and completion
```

- [ ] Run focused platform/recovery and Node diagnostic contracts. Search all `MacScsiWorkerLease::spawn`, `start_scsi_worker`, `MacOsDeviceHandle` constructors and `readiness_backend` context transfers; classify every remaining direct spawn as the explicit Task 5 route or a test-only fixture.

### Task 5: Keep direct CLI authority explicit and non-fallback

**Files:** Modify `src/service/direct.rs`, `src/serial_cli/native.rs`, `src/bin/openrdx-serial.rs`, relevant Mac worker exports and focused CLI/serial fixtures; touch service debug-stdio setup only for its existing privileged direct-process route.

**Interfaces:** `MacDirectWorkerFactory::for_current_privileged_process() -> Result<MacDirectWorkerFactory, NativeError>` performs the actual native privilege probe and retains its own self-audit baseline. `spawn(&self, identity: &MacRematchIdentity) -> Result<MacScsiWorkerLease, NativeError>` invokes the current executable directly with the route's existing fixed internal worker argument and requires exact unchanged self-audit session/credentials in Task 3 preflight. It cannot be constructed from `ServiceExecutionContext` flags alone.

- [ ] Add tests proving unprivileged/direct-flag-only denial, missing GUI-factory denial without direct fallback, direct mode never calls `asuser`, backup-owner independence, and serial route's exact target/unmounted-media/USB checks before spawn.
- [ ] Capture red failures before adding direct factory construction, then implement the native-minted direct-process path. Preserve shared ownership guard and serial's fixed internal argument/dispatch; no caller-selected mode or arguments.

```text
explicit existing CLI route + native privilege check -> direct factory
authenticated endpoint + missing/revoked factory -> deny, never direct factory
```

- [ ] Run focused CLI, serial and ownership suites in default and no-default feature modes. Confirm no production direct factory construction is reachable from renderer/endpoint payload fields.

### Task 6: Verify source, installed runtime and selected dock separately

**Files:** Add focused source/runtime contracts in the existing test directories; update this plan with observed evidence and the relevant maintained Mac installation/readme documentation after implementation. Production changes remain limited to Tasks 1–5.

- [ ] Freeze reviewed source hashes. Run `npm run native:test`, `npm run native:test:no-default`, `npm run native:check`, `npm run native:check:no-default`, the macos-native child suite, `npm test`, `npm run format:check` and `env -u ELECTRON_RUN_AS_NODE npm run smoke`. Require both Mac architectures and unchanged Windows/Linux release gates; a macOS-only host cannot prove their compilation/runtime behavior.
- [ ] Review actual linked SDK/API use, source hashes and private context framing. Run public self-audit/pipe tests without devices. Retain real RED/GREEN logs and distinguish injected failure tests from actual kernel proof. No test may skip a new failure because the host happens to have the desired session.
- [ ] After packaging is authorized, install the exact candidate through the maintained local installer path. Verify installation seal/enrollment, actual anonymous-root service credentials and authenticated installed Manager connection. Record parent/child context internally using bounded private evidence, demonstrating actual held worker PID, unchanged root credentials/service GID, and exact peer AUID/ASID before IOKit. Do not expose raw proof in public diagnostics.
- [ ] Exercise safe actual connection closure/peer exit and controlled replacement-generation refusal without device operations first. Cover peer exec/PID-version change, stale ASID, console switch and same-UID logout/login policy with deterministic kernel-metadata boundary fixtures; distinguish these policy tests from live session-transition proof. Do not log out or switch the user's console by default, or create a new disruptive manual release gate: perform such a transition only if separately needed and authorized, otherwise record it as unrun. Stale factory clones must refuse new spawns/requests; a fresh authenticated connection must obtain its own proof. Confirm copied/tampered clients still fail, service retirement still works, and repair/removal behavior is unchanged.
- [ ] On the explicitly selected dock, verify the authorized discovery/status flow against the installed candidate and capture the exact closed failure/success stage. Exercise reacquisition/recovery only within the already authorized flow and preserve existing device/unmount/capture semantics. Do not add eject, formatting, firmware writes, media writes or reset operations to prove this change. A graphical root worker still may fail interface opening; record that result without attributing it to TCC or claiming a fix.
- [ ] Keep release/publication blocked until exact candidate source/build/install/authentication, actual selected-device acceptance and the existing complete 16-asset cross-platform gates pass. Record unsupported/unrun conditions separately; no unit-test or synthetic session result clears hardware acceptance.

## Review and execution handoff

Root and an independent reviewer must first assess this document's native identity proof, unique owner/revocation timing, shared factory/context cloning, exact child PID/session proof and every spawn path. Any public API limitation that prevents the stipulated proof blocks implementation of that route; it does not justify lowering the gate. The internal errno-22 history and installed USB interface failure remain observations, not confirmed causal explanations for this proposed change.

After that design review, execute Tasks 1–5 sequentially with focused red/green evidence and review checkpoints, then Task 6's separate verification gates. No implementation or privileged action has been performed as part of preparing this plan.
