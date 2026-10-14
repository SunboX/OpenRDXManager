# Windows Owned Token Control Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task after the root agent explicitly approves execution. Steps use checkbox (`- [ ]`) syntax for tracking. This handoff authorizes a plan only; do not implement, commit, push, dispatch workflows or operate the VM now.

**Goal:** Test whether adding one exact console-user token-object ACE to the actual primary token of a privately owned suspended medium child permits the unchanged harmless fixture to start.

**Architecture:** A separate ignored Windows test measures an untreated Wait child, then treats the actual token of a new owned Wait child, and finally independently proves execution using the fixed Proof executable. A private ownership factory holds the returned child and token handles, requires fresh kernel proofs and nonaliasing token identities before its single DACL setter, and rejects any incomplete isolation before resume. The original medium-child gate and eight-row matrix remain unchanged.

**Tech Stack:** Rust 2024, checked-in `windows` SDK bindings, host-executed pure Rust regressions, Node 22 test runner, existing bounded Cargo wrapper and GitHub Actions diagnostics artifact.

**Spec:** [Locally trusted installation plan](locally-trusted-installation-2026-10-12.md), especially “Fixed object DACL matrix after process-only insufficiency” and “Read-only token object lineage and descriptor profile”; the explicit constraints below define this new isolated control. Execution requires a separate root-agent GO after review.

<!-- SPDX-FileCopyrightText: 2026 André Fiedler -->
<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->

## Global constraints

- Test-only scope under `#[cfg(test)]`; no production CLI, NSIS, Manager launch, enrollment or authentication changes.
- Preserve the existing **90-second native global deadline**, **19-second launch/reap reserve**, **120-second wrapper deadline**, and **65,536-byte combined stdout/stderr bound**. No bounds expansion.
- One live child maximum. Every launch requires at least 19,000 ms remaining. Reuse the existing 10,000 ms maximum wait and 3,000 ms held-handle reap bound; stop further launches on source mismatch, unresolved cleanup or insufficient reserve.
- Source derivation rights are exactly `TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_ADJUST_DEFAULT | READ_CONTROL`; this mode never opens a source handle with `WRITE_DAC`.
- The new actual-child token handle requests exactly `TOKEN_QUERY | READ_CONTROL | WRITE_DAC`, only after fresh suspended-child proof. No privilege enable, impersonation, owner-setting, token-property/default-DACL setter or `SANDBOX_INERT`.
- Existing `OwnedChild::create` remains NULL/NULL process/thread attributes, fixed environment/desktop/CWD/image, existing flags, no inherited handles and no redirected standard handles.
- Add exactly one noninheritable ALLOW ACE with the concrete SDK `TOKEN_ALL_ACCESS` mask for the privately verified console-user SID. Preserve all original ACE bytes, DENY entries, order, owner, group, LABEL and descriptor control.
- Preserve source and derived complete snapshots, default ACLs and object descriptors; preserve child process/thread descriptors and actual token complete properties/default ACL. Private identities and buffers never implement `Debug` or reach output.
- Unknown query/layout/comparison is unavailable, never inequality or permission. No actual-token mutation if it aliases source or supplied derived token.
- Fixture cleanup/release is deferred while any owned child termination remains unverified; final RAII reaps the owned child first, suppresses Fixture Drop on unresolved failure and preserves the exact protected private fixtures.
- Owned process/thread/token guards are established immediately after API success, including later validation failures. Only held factory-owned handles may be terminated/reaped. No PID discovery, borrowed-object reset or rollback writes.
- Original error wins; all independent cleanup attempts and preservation observations execute and retain separate closed outcomes.
- Native and JavaScript files have SPDX notices and function documentation; every handwritten file is below 1,000 lines.
- No hardware, VM, account, service, UAC, global ACL, registry, loader, environment or launch-option changes. Root owns review, commits, pushes, packages and authoritative CI.

## Observed evidence and cause limits

Exact source: `2ec0cba59c76de252fb133b7b8bb63bbb42d2ac6`, run [38600914983](https://github.com/SunboX/OpenRDXManager/actions/runs/38600914983), x64 job `115979630784`, ARM64 job `115979631017`. All six artifact logs are byte-identical across architectures. Both matrix logs have SHA-256 **`0e19d905ad71b1aad0aac454d3354072e017eb11501739c4ab766727da283a4e`**.

Local evidence: `.tmp/windows-2ec-token-{x64,arm64}/windows-token-object-dacl-matrix.log`, `.tmp/windows-2ec-token-compare.json` (SHA-256 `96ba588061cac22757074cb21c03f95c01b13dc82c012ceb593203366a6e280f`) and `.tmp/windows-2ec-token-evidence.json` (SHA-256 `520ebd29893a5cc92368fe73202421a4595dfc7096c129d7066c493bc2ab6c84`).

In each of the four TOKEN rows, all fresh image/medium/console and complete-property checks succeeded. Exact SDK token statistics are known: source, supplied derived token and actual child token have distinct TokenIds; AuthenticationIds match. Actual ModifiedId equals the supplied derived token's observed ModifiedId and differs from source. Neither logon identity nor ModifiedId establishes object ownership or API origin.

The actual child's token ACL exactly matches baseline bytes, used ACE sequence, header and padding. The fixed added grant is absent in baseline and actual, present once in expected; `one-addition=false`. Owner/group/LABEL/control, old ACEs and DENY entries are preserved. The unchanged exact guard reports `read/EvidenceIncomplete` before treatment resume. These observations establish that the previous supplied-token intervention was absent from the actual token, not why the API produced distinct objects or why DLL initialization failed.

The first four untreated/process/thread controls still exit `status-dll-init-failed`; baseline/medium observations and source-context fixed exit-36 proof pass, while ordinary child and process/matrix native gates fail. All owned cleanup/source checks pass. Optional GitHub step `success` is `continue-on-error` normalization, not native success. This new experiment must not turn an observed control pass into production authorization.

## File map and stable interfaces

The exact native base directory is:

`native/rdx-service/windows-native/src/service_acl/windows_impl/restricted_token_probe/medium/`

| File | Action and responsibility |
| --- | --- |
| `native/rdx-service/windows-native/src/service_acl/windows_impl/restricted_token_probe/medium/actual_token_protocol.rs` | Create pure lifecycle/epoch admission and deadline model used by the native control, with host-executable negative tests. |
| `native/rdx-service/windows-native/src/service_acl/windows_impl/restricted_token_probe/medium/actual_token_context.rs` | Create query-only source context and minimal derived-token factory; private snapshot/default ACL/descriptor/identity equality. |
| `native/rdx-service/windows-native/src/service_acl/windows_impl/restricted_token_probe/medium/actual_token_owner.rs` | Create exclusive actual-child-token factory, same-held-object/epoch revalidation, one fixed DACL setter and strict readback. |
| `native/rdx-service/windows-native/src/service_acl/windows_impl/restricted_token_probe/medium/actual_token_control.rs` | Create fixed three-child sequential experiment, independent cleanup/preservation and ignored native test. |
| `native/rdx-service/windows-native/src/service_acl/windows_impl/restricted_token_probe/medium/actual_token_output.rs` | Create compact static-key boolean/closed-stage formatting; no SDK/private strings. |
| `native/rdx-service/windows-native/src/service_acl/windows_impl/restricted_token_probe/medium/child.rs` | Add only the new test module; expose no production API and change no creation/proof/cleanup behavior. |
| `scripts/windows-actual-token-control-evidence.mjs` | Create exact closed schema, ordered phase parser and completion/startup requirements. |
| `scripts/verify-windows-restricted-token-probe.mjs` | Add one fixed mode/test name/result field/CLI flag; preserve numeric Cargo failures and existing gates. |
| `test/windows-actual-token-control.test.mjs` | Create pure-Rust host driver, descriptor/epoch negatives, parser/privacy/cleanup regressions and actual-formatter bound. |
| `.github/workflows/build-installers.yml` | Add optional diagnostic step after fixture compilation; add one log to existing token artifact, excluded from installers. |

Read and reuse existing immutable helpers: `fixture.rs` (`Fixture::create`, `retained_payload`, `cleanup`, fixed `Variant::{Wait,Proof}`), `child.rs` (`OwnedChild::create`, `prove_child_quiet`, `wait`, `resume`, `terminate_and_reap`, `eligible`), `process_dacl_control.rs` (`PrivateDescriptor`, `source_default_dacl`), `process_descriptor.rs` (`Components::with_user_allow`, `preservation`, `bytes`, `ObjectRole::Token`), `token_acl_profile.rs`, `token_identity.rs`, `matrix_protocol.rs` (`launch_budget`). No changes to `owned_derived_token.rs`, `object_dacl_controls.rs` or their emitted evidence are planned.

New modules are children of `actual_token_control`, itself a child of `medium::child`. The current matrix's `SourceGuard`/`FreshDerivedToken` remain private and unchanged: they request source `WRITE_DAC` for their separate experiment and therefore must not be reused as the new mode's factory. Reuse bounded SDK readers and pure file modules with `#[path]` imports where private scopes require it; do not widen the matrix ownership API.

Planned interfaces (private test scope; none implement raw adoption, `From`, `Deref` or arbitrary mask/trustee setters):

```rust
// actual_token_protocol.rs
struct Admission {
    fresh: bool, image: bool, console: bool, properties: bool,
    identities_known: bool, same_held: bool,
    source_alias: bool, derived_alias: bool, epoch_fresh: bool,
    remaining_ms: u128,
}
enum ModelError { Admission, Epoch, State }
struct ControlModel { epoch: u64, prepared: Option<u64>, edited: bool, resumed: bool }
struct CleanupPolicy { unreaped: bool, cleanup_failed: bool }
impl CleanupPolicy {
    fn owned_child() -> Self;
    fn record_reap(&mut self, verified: bool);
    fn may_delete_or_release_fixture(&self) -> bool;
    fn may_launch(&self) -> bool;
}
impl ControlModel {
    fn suspended() -> Self;
    fn prepare(&mut self, facts: Admission) -> Result<u64, ModelError>;
    fn invalidate(&mut self);
    fn authorize_write(&mut self, epoch: u64) -> Result<(), ModelError>;
    fn authorize_resume(&mut self, exact_readback: bool, fresh_proof: bool) -> Result<(), ModelError>;
}

// actual_token_context.rs: fields remain private.
struct SourceContext;
struct MinimalDerivedToken;
impl SourceContext {
    fn capture() -> Result<Self, NativeError>;
    fn derive_medium(&self) -> Result<MinimalDerivedToken, NativeError>;
    fn unchanged(&self) -> Result<(), NativeError>;
}
impl MinimalDerivedToken {
    fn launch_token(&self) -> &OwnedHandle;
    fn unchanged(&self, source: &SourceContext) -> Result<(), NativeError>;
}

// actual_token_owner.rs: owns token; borrows the live guard/fixture/context.
struct OwnedActualChildToken<'a>;
impl<'a> OwnedActualChildToken<'a> {
    fn observe(child: &'a OwnedChild, fixture: &'a Fixture,
        source: &'a SourceContext, derived: &'a MinimalDerivedToken,
        remaining_ms: u128) -> Result<Self, NativeError>;
    fn add_fixed_user_allow(&mut self, remaining_ms: u128) -> Result<(), NativeError>;
    fn require_exact_readback(&self) -> Result<(), NativeError>;
    fn resume_verified(&mut self) -> Result<(), NativeError>;
}

// actual_token_control.rs
fn run_control() -> Result<(), NativeError>;
#[test]
#[ignore = "requires administrator on a disposable Windows verifier"]
fn native_actual_child_token_dacl_control();

// actual_token_output.rs
fn stage(phase: &'static str, status: &'static str, reason: Option<NativeError>);
fn facts(phase: &'static str, values: &[(&'static str, bool)]);
fn exit(phase: &'static str, category: &'static str);
```

`SourceContext` holds QUERY|READ_CONTROL observer, source snapshot/default ACL/object descriptor, private TokenId, console user/session and verified user SID. Its derivation handle is opened separately with only the exact five allowed rights after fresh equality with that observer. `MinimalDerivedToken` holds a newly created medium token with unchanged object/default ACL and full reduction snapshot; it never offers a DACL setter. `OwnedActualChildToken` retains a query-only actual-token observer, its exact valid identity and prewrite object/default ACL/complete snapshot, process/thread descriptors, the factory-owned write handle and a private `ControlModel`. All descriptors use live aligned storage and bounded validators.

## Task 1: Pure epoch/admission and preservation regressions

**Files:** Create `actual_token_protocol.rs` and `test/windows-actual-token-control.test.mjs` at the exact paths above. Consume existing pure descriptor, mandatory-label and opaque-identity modules.

- [ ] Write the following actual host-Rust model tests before implementing the model. They must compile the checked-in module with `rustc --test`; do not substitute source regex checks.

```rust
#[cfg(test)]
mod tests {
    use super::*;
    fn good() -> Admission {
        Admission { fresh:true, image:true, console:true, properties:true,
            identities_known:true, same_held:true, source_alias:false,
            derived_alias:false, epoch_fresh:true, remaining_ms:19_000 }
    }
    #[test]
    fn unknown_or_alias_never_authorizes_write() {
        for index in 0..10 {
            let mut facts=good();
            match index {
                0=>facts.fresh=false, 1=>facts.image=false,
                2=>facts.console=false, 3=>facts.properties=false,
                4=>facts.identities_known=false, 5=>facts.same_held=false,
                6=>facts.source_alias=true, 7=>facts.derived_alias=true,
                8=>facts.epoch_fresh=false, _=>facts.remaining_ms=18_999,
            }
            assert!(ControlModel::suspended().prepare(facts).is_err());
        }
    }
    #[test]
    fn changed_epoch_and_duplicate_write_are_refused() {
        let mut model=ControlModel::suspended();
        let epoch=model.prepare(good()).unwrap_or_else(|_|panic!("prepare"));
        model.invalidate();
        assert!(model.authorize_write(epoch).is_err());
        let epoch=model.prepare(good()).unwrap_or_else(|_|panic!("prepare"));
        assert!(model.authorize_write(epoch).is_ok());
        assert!(model.authorize_write(epoch).is_err());
    }
    #[test]
    fn no_resume_without_exact_isolation_and_last_fresh_proof() {
        for (exact,fresh) in [(false,true),(true,false),(false,false)] {
            let mut model=ControlModel::suspended();
            let epoch=model.prepare(good()).unwrap_or_else(|_|panic!("prepare"));
            assert!(model.authorize_write(epoch).is_ok());
            assert!(model.authorize_resume(exact,fresh).is_err());
        }
    }
}
```

- [ ] Establish genuine behavior RED with a COMPILING minimal unsafe admission stub in the new pure module, then discard it. Use the exact interface/types above and the following temporary implementation; this has no Windows handles or setter:

```rust
impl ControlModel {
    fn suspended()->Self {
        Self { epoch:0, prepared:None, edited:false, resumed:false }
    }
    fn prepare(&mut self,_facts:Admission)->Result<u64,ModelError> { Ok(self.epoch) }
    fn invalidate(&mut self) {}
    fn authorize_write(&mut self,_epoch:u64)->Result<(),ModelError> { Ok(()) }
    fn authorize_resume(&mut self,_exact:bool,_fresh:bool)->Result<(),ModelError> { Ok(()) }
}
```

Run `node --test --test-name-pattern='host native admission' test/windows-actual-token-control.test.mjs`; save `.tmp/windows-actual-token-model-red.txt`. REQUIRE successful `rustc --test` compilation followed by failing assertions for unchecked prerequisites/aliases, stale epoch, duplicate write and missing readback/fresh proof. Missing module, missing rustc or compilation error is a SETUP FAILURE, not behavior RED. Remove this temporary stub and implement the guarded model below. Descriptor and cleanup regressions likewise execute the actual pure functions consumed by the native factory/lifecycle, never a detached regex or unused replica.
- [ ] Implement `prepare` as the conjunction of all positive facts, known identities, no aliases, current suspended state and `launch_budget(remaining_ms)`; save current epoch. `invalidate` increments epoch and clears prepared admission. `authorize_write` requires the exact prepared epoch and not edited/resumed, consumes admission and records edited. `authorize_resume` requires edited, not resumed, exact readback and last fresh proof, then records resumed. No Windows handles enter this pure module.
- [ ] Add host descriptor tests using real `Components::with_user_allow`: preserve DENY byte/order and all non-DACL components, add exactly one canonical noninherit SDK TOKEN ACE even when an identical ACE already exists, reject generic/callback/truncated/unaligned ACL/SID forms. Mutate one owner/group/LABEL/control/default-ACL/property observation in each case and require refusal in the same native model/readback admission path.
- [ ] Run the host driver GREEN, including SDK-size/alignment unknown identity, known source/derived alias, stale epoch, insufficient reserve and duplicate write cases; save `.tmp/windows-actual-token-model-green.txt`. The model is used by the native factory, not a detached demonstration.
- [ ] Submit this pure boundary for root review; do not commit independently.

## Task 2: Minimal source/derived context and exclusive actual-token factory

**Files:** Create `actual_token_context.rs`, `actual_token_owner.rs`; consume the Task 1 model and existing source/token/fixture/descriptor helpers through private test imports.

- [ ] Capture source query observer BEFORE opening derivation rights: snapshot, canonical nullable default ACL, owner/group/DACL/LABEL/control descriptor, valid private TokenId, exact console user/session. Require the existing high-integrity elevated primary source and exact current-console user/session prerequisites; another account/session or unavailable prerequisite fails closed. Unknown metadata is fatal for this intervention, not asserted inequality.
- [ ] Open a second source handle with the exact five allowed rights, prove same held source identity and every snapshot/default/object component before CRT. Create only `LUA_TOKEN | DISABLE_MAX_PRIVILEGE`, then set medium on the fresh owned token using existing `set_medium`; verify all existing `eligible` reductions and privilege whitelist. Retain default ACL/object descriptor/full properties/identity; no source or derived DACL write.
- [ ] For a newly returned suspended child, call `prove_child_quiet`, privately compare fresh actual/derived complete snapshots, verify same console user/session and required medium reductions, and pin exact image/ancestor/hash/FileID. Capture actual process/thread SD and actual TOKEN_QUERY|READ_CONTROL snapshot/default ACL/object SD/TokenId. Require known actual TokenId different from source and derived before opening extra rights.
- [ ] Only that factory opens `TOKEN_QUERY | READ_CONTROL | WRITE_DAC` on `child.process`. Immediately own its returned handle, compare its exact valid TokenId with the retained query observer, require source/derived nonaliasing again, and prove its prewrite descriptor/default ACL/full snapshot equals the retained actual baseline.
- [ ] Revalidate source/derived descriptors/default ACLs/full properties and child image/medium/current console AFTER queries, then reopen only a QUERY actual-token observer to verify current primary TokenId equals the held write-token TokenId. Update/prepare the pure epoch model only after this check; there is no optional query or arbitrary callback between authorization and the single held-handle setter. After setting, recheck current primary identity so a replacement never reaches resume.
- [ ] Build expected SD from retained actual baseline and exact verified user using `with_user_allow(..., ObjectRole::Token)`. Preserve every old ACE/DENY/order and owner/group/LABEL/control. Pass aligned live `PrivateDescriptor` storage to exactly this API call:

```rust
unsafe {
    SetKernelObjectSecurity(
        self.write_token.0,
        DACL_SECURITY_INFORMATION,
        expected_storage.pointer(),
    )
}.map_err(map_native_error)?;
```

This snippet belongs only to `OwnedActualChildToken::add_fixed_user_allow`. Its private write handle can only come from the validated returned child's factory; no raw/source/derived adoption or public setter is provided.

- [ ] Before strict assertion, emit query-known and separate closed booleans for token-DACL-exact/one-addition/old-ACE-order/DENY preservation, owner/group/LABEL/control, actual-token-identity stable, full actual snapshot/default ACL, process/thread exact components, source/derived snapshot/default ACL/object SD preservation. Missing or false evidence fails isolation, closes the child through owned cleanup and never resumes it.
- [ ] The private `resume_verified` method rechecks the current actual primary TokenId equals the held token identity, exact treated SD and full snapshot/default ACL, source/derived unchanged, and lifecycle admission. It then calls `prove_child_quiet` and immediately `OwnedChild::resume` in the SAME method. No subsequent metadata query, logging/output callback or external caller operation can occur between last fresh proof and resume. Emit the resume-begin marker before entering this method and terminal outcome after it returns. ModifiedId remains an observation, never an API-origin or source-immutability proof.
- [ ] Cross-check x64 `--tests`, Clippy and host negatives. Neither compilation nor API creation alone is actual execution proof.

## Task 3: Fixed untreated/treatment/positive lifecycle and closed formatter

**Files:** Create `actual_token_control.rs`, `actual_token_output.rs`; modify only the module declaration in `child.rs`.

- [ ] Use one 90-second `Instant` deadline from setup and `launch_budget`'s existing 19-second threshold before each creation. Wait requests remain at most 10,000 ms and reap at most 3,000 ms; source mismatch, cleanup uncertainty or insufficient reserve forbids every later launch.
- [ ] Create one protected Wait fixture and one protected Proof fixture with existing `Fixture::create`; retain them and all their original pins until cleanup. Untreated and treatment Wait children use the SAME retained Wait executable/working root.
- [ ] Run untreated baseline: unchanged constructor, suspended image/medium/console/full-property/default-ACL/SD/identity proof, last fresh proof immediately before resume, bounded wait. Require exactly `status-dll-init-failed` as this experiment's matched baseline, reap only held owned child, and verify source/derived preservation before the next creation. An unexpectedly surviving/successful baseline is a closed failed control, not evidence that treatment helped.
- [ ] Run treatment Wait: same constructor/options; invoke Task 2's actual-token factory/one setter/exact isolation/fresh proof. After resume, require `wait(100)` to return `None` (alive), then terminate/reap the held owned child. Early zero, any loader/self-check/unknown exit, API refusal or timeout-cleanup failure fails the control.
- [ ] Run independent Proof child only after successful treatment Wait and cleanup: same strict actual-token treatment, isolation and final fresh proof; resume and require fixed fixture selfchecks/exit zero within at most 10,000 ms. Source-control exit 36 is never acceptable in this mode.
- [ ] Always attempt child reap, Proof fixture cleanup eligibility, Wait fixture cleanup eligibility, source preservation and derived preservation independently. Fixture cleanup methods must return a closed Busy/deferred outcome without deleting files or releasing retained pins whenever any owned child reap remains unverified; retain both fixtures in State and forbid every later launch. Preserve the first primary error; otherwise preserve the first cleanup/preservation error. Implement the decision without overwriting errors:

```rust
fn retain_first(first: &mut Option<NativeError>, result: Result<(), NativeError>) {
    if let Err(error)=result { first.get_or_insert(error); }
}
// Execute every cleanup operation before selecting the return value.
// A preceding cleanup error must not short-circuit the following call.
let mut cleanup_error=None;
retain_first(&mut cleanup_error, state.reap_owned_child());
retain_first(&mut cleanup_error, state.cleanup_proof_fixture());
retain_first(&mut cleanup_error, state.cleanup_wait_fixture());
retain_first(&mut cleanup_error, source.unchanged());
retain_first(&mut cleanup_error, derived.unchanged(&source));
match primary {
    Err(error)=>Err(error),
    Ok(())=>cleanup_error.map_or(Ok(()),Err),
}
```

Define these three private `State` methods in this task; each logs begin/fixed outcome/terminal separately and returns its own result. `State` owns `Option<OwnedChild>`, guarded `Option<Fixture>` for Wait and Proof and no borrowed process handle. A failed reap leaves child AND fixture ownership retained and prevents new launch. `cleanup_proof_fixture` and `cleanup_wait_fixture` first test that no unreaped child remains; otherwise return Busy/deferred with zero deletion or pin release. The attempt itself must not take/drop the Fixture.

Explicit State Drop order: retry bounded held-child reap FIRST. Only verified termination allows ordinary Fixture cleanup/Drop. If final reap is unresolved, retain/defer the child handles and both entire private fixture leases (including retained file pins), suppress their automatic cleanup/Drop, and fail closed. A private `ManuallyDrop`/deferred lease owner may deliberately retain these exact owned resources rather than delete or release them while child liveness is unknown. No other object/root may enter that owner. Process exit may eventually close OS handles; preserve the protected on-disk fixture for later owned cleanup and report only a fixed deferred outcome. This is an unresolved failure, never a successful cleanup or authority to discover/kill a PID.

Add this real host lifecycle negative; use the same pure cleanup policy from both State methods and their final RAII path:

```rust
#[test]
fn failed_reap_defers_fixture_deletion_and_release() {
    let mut policy=CleanupPolicy::owned_child();
    policy.record_reap(false);
    assert!(!policy.may_delete_or_release_fixture());
    assert!(!policy.may_launch());
    policy.record_reap(false); // Final RAII retry remains unresolved.
    assert!(!policy.may_delete_or_release_fixture());
    let mut deletions=0;
    let mut releases=0;
    if policy.may_delete_or_release_fixture() { deletions+=1; releases+=1; }
    assert!(deletions==0 && releases==0);
}
```

Define `CleanupPolicy` in `actual_token_protocol.rs`: `owned_child()` records one unreaped owned child; `record_reap(verified: bool)` changes to reaped only on true and keeps an unresolved false sticky until a later VERIFIED reap; `may_delete_or_release_fixture()` is true only without an unreaped child; `may_launch()` additionally requires no prior unresolved-cleanup failure. Its private State consumer counts real cleanup calls in the injected host lifecycle driver. Failed attempts never manufacture a reaped fact, and source/derived checks still run.

- [ ] Use only compiled phase names: `setup`, `derive`, `fixtures`, `baseline-create`, `baseline-proof`, `baseline-resume`, `baseline-wait`, `baseline-reap`, `treatment-create`, `treatment-observe`, `treatment-write`, `treatment-readback`, `treatment-resume`, `treatment-wait`, `treatment-reap`, `positive-create`, `positive-observe`, `positive-write`, `positive-readback`, `positive-resume`, `positive-wait`, `positive-reap`, `child-cleanup`, `proof-cleanup`, `wait-cleanup`, `source-check`, `derived-check`, `complete`. All successful-path phases must begin and end `ok`; sticky first failure is independent of later cleanup. Exit markers occur only in their active wait phase.
- [ ] Static boolean keys follow the exact Task 2/3 query/preservation properties with `baseline-`, `treatment-`, `positive-` subject prefixes; define the compiled list in `actual_token_output.rs` and import it into the host formatter driver. Closed error vocabulary is the existing 13 `NativeError` variants; closed exit vocabulary is existing `exit_status::category`. No arbitrary errors, PIDs, paths, SIDs, LUIDs, masks, ACL bytes or counts are output.
- [ ] Add host injection tests for each baseline/treatment/positive query/proof/write/readback/resume/wait failure and all three independent cleanup failures, including failed reap followed by zero actual fixture-deletion/pin-release calls and no later launch. Count simulated writes/resumes/reaps: failed prewrite proof yields zero writes/resumes; failed postwrite exact proof yields one owned write/zero resumes; later cleanup still runs and first error remains primary. Keep SDK actual runtime checks distinct from these deterministic lifecycle negatives.

## Task 4: Separate strict wrapper/schema/formatter and optional CI

**Files:** Create `scripts/windows-actual-token-control-evidence.mjs`, finish `test/windows-actual-token-control.test.mjs`; modify wrapper and Windows workflow only.

**Interfaces:** `actualTokenControlEvidence(input: readonly string[])` returns `{lines, complete, startupProof, firstFailure, reason}` from reconstructed compiled facts only. It never accepts ordinary/matrix/source proof. Wrapper mode is exactly `'actual-token-dacl-control'`, CLI flag exactly `--actual-token-dacl-control`, exact native filter `service_acl::windows_impl::restricted_token_probe::medium::child::actual_token_control::native_actual_child_token_dacl_control`.

- [ ] Begin with a deterministic all-positive transcript generated from the compiled new phase/key list. It includes untreated fixed DLL-init exit, treatment alive, positive zero, every exact preservation/reduction/query property, independent cleanup and exact one native named test success. Write RED mutations before parser implementation:

```javascript
// These values are generated from the compiled phase/key lists, never native evidence.
for (const mutate of [
    (text)=>text.replace('actual-source-distinct=true','actual-source-distinct=false'),
    (text)=>text.replace('actual-derived-distinct=true','actual-derived-distinct=false'),
    (text)=>text.replace('write-handle-same-instance=true','write-handle-same-instance=false'),
    (text)=>text.replace('epoch-fresh=true','epoch-fresh=false'),
    (text)=>text.replace('token-dacl-exact=true','token-dacl-exact=false'),
    (text)=>text.replace('phase=treatment-wait category=alive','phase=treatment-wait category=success'),
    (text)=>text.replace('phase=positive-wait category=success','phase=positive-wait category=status-dll-init-failed'),
    (text)=>text.replace('running 1 test','running 0 tests'),
    (text)=>text.replace('1 passed; 0 failed','0 passed; 0 failed'),
    (text)=>text.replace('status=begin','status=ok'),
]) {
    assert.equal(validateRestrictedTokenProbeOutput(mutate(proof()),'',{mode:'actual-token-dacl-control'}).passed,false)
}
```

`proof()` is the deterministic generator specified above; define its concrete phase/key arrays by reading the compiled output module, not a source-regex authorization surrogate. Additional mutations remove an entire phase, duplicate a fact/phase, move an exit after terminal, use unknown/native-private fields, contradict known/equality or relative ACE counts, cross modes, and append `failed` then `ok`. No malformed/truncated observation can authorize completion.

- [ ] Preserve actual numeric Cargo exit 101 under injected native failure; preserve execution-error classification without inventing an observed Cargo code. Test stderr containing a private sentinel disappears from every returned/printed result. Genuine nonzero, zero tests, wrong named test and missing facts remain fatal.
- [ ] Test exact successful transcript through the injected wrapper executor, requiring `--ignored --exact --nocapture --test-threads=2` and the exact fixed native name, not arbitrary caller filters. Add CLI rejection of extra flags and unknown mode strings.
- [ ] Compile and execute the actual checked-in new formatter on the host for every reachable successful phase/fact/exit, with CRLF and 4,096-byte Cargo reserve. Require `Buffer.byteLength(stdout.replaceAll('\n','\r\n')) + 4096 <= 65_536`; do not increase capture bounds or silently drop fields. Include partial-error/unwind cases, flush-before-terminal and grouped/individual parser-equivalence tests.
- [ ] Add optional Windows step after existing ordinary child/control steps, conditioned on `always()`, Windows platform and successful fixed fixture compilation. Set `continue-on-error: true`; invoke only the new fixed wrapper flag. Tee sanitized wrapper stdout to `out/verification/windows-token-actual-token-dacl-control.log`, capture `$LASTEXITCODE` immediately, then `exit $probeExitCode`.
- [ ] Include that one fixed log in the existing immediately uploaded `windows-token-diagnostics-${arch}` artifact with three-day retention, `if: always()`. Keep it separate from `installers-*`; ordinary failure still skips installer/release work. Add executable wrapper plus workflow source-contract tests for exit preservation and artifact separation.

## Task 5: Freeze, review and authoritative execution

- [ ] Run the complete scoped command and read exit/output; root owns full application tests and smoke. Use the rustup-managed 1.95.0 toolchain (including installed x86_64-pc-windows-msvc target and Clippy/rustfmt), not a standalone Homebrew Cargo. A missing toolchain/target is a setup failure, not behavior RED; do not install/change tooling without coordination:

```bash
node --test test/windows-*token-probe*.test.mjs test/windows-token-child-exit-contract.test.mjs test/windows-token-desktop-context.test.mjs test/windows-token-mandatory-context.test.mjs test/windows-token-library-context.test.mjs test/windows-token-object-context.test.mjs test/windows-source-token-control.test.mjs test/windows-token-effective-context.test.mjs test/windows-process-dacl-control.test.mjs test/windows-object-dacl-matrix.test.mjs test/windows-token-lineage-profile.test.mjs test/windows-token-matrix-output-bound.test.mjs test/windows-actual-token-control.test.mjs
rustup run 1.95.0 cargo check --manifest-path native/rdx-service/windows-native/Cargo.toml --locked --target x86_64-pc-windows-msvc --tests
rustup run 1.95.0 cargo clippy --manifest-path native/rdx-service/windows-native/Cargo.toml --locked --target x86_64-pc-windows-msvc --tests -- -D warnings
rustup run 1.95.0 cargo fmt --manifest-path native/rdx-service/windows-native/Cargo.toml -- --check
npm run format:check
git diff --check
```

- [ ] Save genuine RED/GREEN, host formatter bytes, native compile/Clippy/fmt and focused outputs in `.tmp/windows-actual-token-*`; create explicit SHA-256 manifest for owned files only. Verify every file below 1,000 lines and unchanged ordinary/matrix source semantics. Freeze and request root plus independent immutable-pin review before any commit.
- [ ] Root alone commits/pushes and collects both actual architecture logs. Require actual untouched baseline DLL-init failure, exact successful actual-token intervention, treatment 100 ms survival, independent Proof zero and all preservation/cleanup checks. API open/write success, synthetic pass, optional GitHub success or diagnostic completion alone is not successful startup proof.
- [ ] If treatment remains loader-failed, report exact established intervention plus fixed failure category, source/derived invariants and cleanup without claiming root cause. If isolation/readback fails, never resume and report that boundary. If both actual controls pass, root chooses a separate reviewed production design; this plan grants no production implementation permission.

## Primary API references

- [OpenProcessToken](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocesstoken): token-object DACL checks requested rights; owned returned handles require close. The fixed retained child process supplies required query rights.
- [Access-token object rights](https://learn.microsoft.com/en-us/windows/win32/secauthz/access-rights-for-access-token-objects): Get/SetKernelObjectSecurity operate on token-object SD; standard WRITE_DAC differs from TOKEN_ADJUST_DEFAULT and there is no token SYNCHRONIZE right.
- [SetKernelObjectSecurity](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-setkernelobjectsecurity): set only DACL_SECURITY_INFORMATION on the validated owned actual token; no file-system/security-information expansion.
- [TOKEN_STATISTICS](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-token_statistics): TokenId identifies the token instance; AuthenticationId is logon identity; ModifiedId is observational. Exact compiled size/alignment and known comparisons are prerequisites.
- [CreateRestrictedToken](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-createrestrictedtoken): returned rights follow the source handle. This mode's source handle omits WRITE_DAC and avoids source/derived DACL treatment.
- [CreateProcessAsUserW](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessasuserw): unchanged launch operation may temporarily enable caller privileges; source preservation is measured before/after, not assumed from API success.

## Review handoff

This file is PLAN ONLY. Root reviews identity/epoch admission, private actual-token ownership, descriptor fidelity, full-property/default-ACL preservation, first-error cleanup, exact schema and unchanged bounds before giving an implementation GO. No commit/push or execution choice is made by the worker. Host tests/cross-compilation planned here are not Windows runtime evidence; authoritative actual two-architecture results remain required.
