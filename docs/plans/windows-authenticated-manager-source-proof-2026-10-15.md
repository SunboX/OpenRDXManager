# Windows Authenticated Manager Source Proof Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans after root separately approves this plan. Steps use checkbox (`- [ ]`) syntax for tracking. This document authorizes PLAN ONLY: no implementation, Windows operation, VM resume, installation, workflow dispatch, commit or push.

**Goal:** Determine whether an unchanged primary token from an ordinary active-console process with the fixed installed Manager kernel path, alongside a separately pinned current installed runtime, permits the existing harmless child to execute under the intended elevated administrator/provisioner caller.

**Architecture:** A separate ignored native test acquires a retained, read-only Manager process/runtime/token lease, duplicates its primary token without reduction or setters, and proves a fixed suspended Wait child and then a fixed Proof child. Its ordinary-source predicate preserves the donor's complete properties, including legitimate disabled privileges; it does not change the existing maximum-reduction predicate, ordinary fatal gate or production behavior. Missing donor, insufficient rights or incomplete proof blocks execution rather than manufacturing a donor or adding delegation.

**Tech Stack:** Rust 2024, checked-in Windows SDK bindings, host-executed pure Rust tests, Node 22 strict diagnostic wrapper, existing argument-free Windows fixture PEs.

**Spec:** [Locally trusted installation](../specs/locally-trusted-installation-2026-10-12.md), [maintained installation plan](locally-trusted-installation-2026-10-12.md), and the explicit experiment constraints below. Prior evidence is summarized in ignored `.tmp/windows-c109-source-context-assessment.md`.

<!-- SPDX-FileCopyrightText: 2026 André Fiedler -->
<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->

## Evidence, prerequisite and interpretation

Exact observed source is `c10935a03e32d489ce729da6e323fea156afcae2`, [CI 38679023268](https://github.com/SunboX/OpenRDXManager/actions/runs/38679023268). Both Windows jobs fail; eight diagnostic transcript pairs are byte-identical. The debugger transcript SHA256 is `149a92b1eb5f2f73bdff77a050b045456883b21c50079d9e8aad0bc7d90e7a12`: matched DLL initialization failure, seven events, no exception, complete verified cleanup/source preservation, no startup proof. The actual-token-DACL control still fails after exact treatment. Neither load order nor broad access-check denial identifies the failing initializer.

The failing ordinary children use a synthetic medium token derived from an elevated/default CI source. A genuinely ordinary Manager source has not been tested. This experiment changes the source context as a whole; a successful result would demonstrate that route under the observed caller, not identify one causal token field, prove a production launcher, or authorize hardware operations.

**Mapped-image limit:** `QueryFullProcessImageNameW` establishes the retained donor's kernel-reported path. Separately opening that current pathname and verifying its FileID/hash against pinned enrollment proves the current on-disk runtime, not the bytes or generation already mapped into the running donor. Process creation time and TokenId do not close that gap. This narrowly scoped diagnostic can report kernel-path equality plus separately pinned current-runtime equality; it must not report exact mapped-image/current-generation authentication or production trusted-process authority. If exact mapped-generation proof is required for admission, it is unavailable here and execution stops. Do not expand process memory rights, add private APIs, or infer the missing identity. Root must review this diagnostic scope clarification before implementation.

**External blocking boundary:** actual execution requires an explicitly selected normal Windows desktop with a genuinely non-elevated active-console user, an already enrolled/protected exact installed Manager, and permission to run the private verifier as the intended elevated administrator. No such desktop/donor is established by this plan. The builtin-Administrator/default/no-linked-token CI environment cannot bootstrap the absent ordinary donor. A task's LUA label is insufficient. Do not install, repair, enroll, create an account, change UAC, resume the paused VM or launch Manager to satisfy this prerequisite without separate root coordination. If the installation is incomplete or the donor is unavailable, report that precise missing condition and stop.

Current production boundaries:

- `native/windows-client-addon/openrdx_windows_client.cc:636–639` explicitly requests `SECURITY_IDENTIFICATION`. It remains unchanged; identity is not delegated launch authority.
- `native/rdx-service/windows-native/src/endpoint.rs:665–702` checks kernel pipe PID/session and TokenUser SID with a temporary QUERY token; its image helper at line 848 queries the kernel path and compares separately opened current-file identities. That does not independently prove the already-mapped image generation. `ManagerEndpointConnection` at line 210 retains no client process/token capability. This experiment adds no endpoint command or protocol backdoor and does not claim the identity-only connection supplied a launch token.
- `service_acl/windows_impl/manager_token.rs:8–88` requires a live unelevated active-console Manager for provisioning. Its production checks remain unchanged.
- `native/rdx-service/windows-native/src/native/vds.rs:170–180` creates the existing privileged service subprocess. LocalService and that raw hardware worker remain unchanged. The caller here is an elevated interactive administrator/provisioner-role verifier, not LocalService; results cannot be transferred to LocalService without a separately reviewed proof.

## Global constraints

- All new native behavior is `#[cfg(test)]`, private, ignored and opt-in. No production CLI, NSIS, addon, renderer flag, service endpoint or hardware change.
- Preserve the 90-second native deadline, 19-second prelaunch reserve, 120-second wrapper deadline and 65,536-byte combined output bound. Discovery has a 5-second/4,096-record ceiling; query only exact-name image candidates, not unrelated process tokens. At most 32 matching candidate handles; overflow is unknown/failure, not truncation.
- Donor discovery takes no PID, path, username, session or token argument. Fixed native Manager kernel path, separately verified current installed enrollment/inventory and retained process identity own the diagnostic decision within the mapped-image limit above. Names/parent relationships are discovery hints only.
- Source process access is `PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE`; donor token observer is `TOKEN_QUERY | READ_CONTROL`; the separately opened duplication handle requests only `TOKEN_QUERY | TOKEN_DUPLICATE | READ_CONTROL`. No WRITE_DAC, ADJUST_DEFAULT, session setter, privilege enable, impersonation, ACL/owner/default-DACL change or alternate credentials.
- `DuplicateTokenEx` requests `TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | READ_CONTROL`, NULL security attributes, `TokenPrimary`, and the documented `SecurityImpersonation` argument. It does not impersonate a thread. No owner-setting descriptor or access fallback. Denied rights remain denied.
- No `CreateRestrictedToken`, integrity lowering, token reduction, linked-token substitution or setter. Preserve legitimate disabled ordinary-user privileges and all group/privilege bytes. No enabled classified administrative group, elevation, high integrity, UIAccess or SandboxInert may pass.
- The old `eligible`, `prove_child_quiet`, all existing constructors/modes and the fatal ordinary-child gate are unchanged. A new ordinary-source proof is private to this mode; it cannot authorize the old gate or production admission.
- Reuse EXACT unchanged `tests/fixtures/token-child.rs` builds (`Variant::Wait` and `Variant::Proof`). The fixture self-check already requires medium/non-elevation/active console/primary/UIAccess0/SandboxInert0 and does not impose the old parent's only-ChangeNotify ceiling. No fixture source, imports, environment, flags, CWD, desktop or stdio change.
- Only `OwnedChild::create` returned handles may be resumed, terminated or reaped. Never terminate, suspend, reset or close borrowed donor/source process authority. One live owned child maximum. Verified termination wait, not TerminateProcess success, establishes reap.
- Retain exact private fixture pins/leases on uncertain creation or unreaped child, including final Drop; return Busy/deferred cleanup and forbid later launch. Attempt independent donor/caller/copy observations after any failure. First primary error wins; independent cleanup results remain visible.
- Output contains compiled boolean fields, phase/status enums, fieldless NativeError categories and fixed exit classes only. No PID, path, SID/LUID, raw mask, handle, count, command line, environment, arbitrary error string or token/descriptor bytes.
- Every handwritten file stays below 1,000 lines with SPDX and function documentation. Root owns review, commits, pushes, packages and actual Windows execution.

## File map and private interfaces

Native base `N` is `native/rdx-service/windows-native/src/service_acl/windows_impl/restricted_token_probe/medium/`.

| Path | Planned responsibility |
| --- | --- |
| `N/manager_source_protocol.rs` | Pure, actually consumed acquisition/admission, deadline and lifecycle model with host tests. |
| `N/manager_source_context.rs` | Fixed bounded discovery, runtime/process/token retention, ordinary-source proof and duplicate factory; no raw adoption/setter API. |
| `N/manager_source_proof.rs` | Fixed Wait/Proof experiment, fresh child equality proof, independent preservation/cleanup and ignored native test. |
| `N/manager_source_output.rs` | Closed ordered phases/static booleans; actual formatter used by native test and host bound test. |
| `N/child.rs` | Module declaration only; existing implementation unchanged. |
| `native/rdx-service/windows-native/Cargo.toml` | Test-only `Win32_System_Diagnostics_ToolHelp` SDK feature if absent. |
| `scripts/windows-manager-source-evidence.mjs` | Strict ordered closed parser; no cross-mode authorization. |
| `scripts/verify-windows-restricted-token-probe.mjs` | One fixed `--manager-source-proof` mode/exact test name/result field; existing modes unchanged. |
| `test/windows-manager-source-proof.test.mjs` | Host Rust driver, discovery/admission/cleanup negatives, wrapper/parser/privacy/actual formatter tests. |

`N/manager_source_proof.rs` is a child module of `medium::child`, so it can reuse `OwnedChild::create`, `prove_image`, fixed fixture helpers, read-only `SourceSnapshot`, group classification and existing object/default-DACL/opaque identity readers without exporting production APIs. Do not reuse the old reduced-source factory or call its eligibility predicate. Do not relocate existing modules merely to organize this experiment.

```rust
// Private new types; fields have no Debug/From/Deref/raw-handle constructor.
enum Boundary { Unavailable, Ambiguous, Rights, Identity, SourcePolicy, Preservation }
#[derive(Clone, Copy)]
struct DonorFacts {
    runtime: bool, image: bool, instance: bool, live: bool,
    console_user: bool, console_session: bool, primary: bool,
    non_elevated: bool, medium: bool, no_enabled_admins: bool,
    ui_access_zero: bool, sandbox_inert_zero: bool, recognized_type: bool,
}
#[derive(Clone, Copy)]
struct Admission { donor: DonorFacts, duplicate_exact: bool, source_unchanged: bool,
    copy_unchanged: bool, fresh: bool, remaining_ms: u128 }
fn source_allowed(facts: &DonorFacts) -> bool;
fn may_launch(facts: &Admission) -> bool;
struct DonorLease;         // holds RuntimeLease, current on-disk image/ancestor pins,
                          // process+creation time, token observer+TokenId,
                          // full snapshot/default ACL/object SD and console identity
struct OrdinaryCopy;       // owns only DuplicateTokenEx output + private before state
impl DonorLease {
    fn acquire_fixed() -> Result<Self, NativeError>;
    fn duplicate_primary(&self) -> Result<OrdinaryCopy, NativeError>;
    fn revalidate(&self) -> Result<(), NativeError>;
}
impl OrdinaryCopy {
    fn launch_token(&self) -> &OwnedHandle;
    fn unchanged(&self, donor: &DonorLease) -> Result<(), NativeError>;
}
fn prove_ordinary_child(child: &OwnedChild, fixture: &Fixture,
    donor: &DonorLease, copy: &OrdinaryCopy) -> Result<(), NativeError>;
fn run_manager_source_proof() -> Result<(), NativeError>;
#[test]
#[ignore = "requires approved enrolled Windows desktop and ordinary installed Manager donor"]
fn native_authenticated_manager_source_proof();
```

The ordinary predicate requires every `DonorFacts` field true, plus complete source/copy/child snapshot equality. Here `image` means kernel-path equality plus separately pinned current-file identity, never mapped-generation identity. Administrative groups may be absent or deny-only; none of the existing classified administrative roles may be enabled. Privileges, enabled or disabled, must be exactly inherited with no addition or attribute change. This is a deliberately different experiment contract from maximum reduction, not a replacement for that security requirement. DefaultDACL/token-object SD of the donor remain exactly unchanged; duplicated-token SD is separately baselined and must stay unchanged, without requiring its new descriptor to equal the donor descriptor. TokenId must be known, the donor stable and copy distinct; AuthenticationId equality is observational and cannot substitute for identity. ModifiedId is recorded only through private known/equal booleans, not treated as ownership or API-origin evidence. `caller-user-equal` is a separate known observation: either true or false is valid initially; it is not an all-true admission field. Unknown equality or a later preservation/state change fails closed.

## Task 1: Retained donor and duplication proof, without launching

- [ ] Add host Rust tests against the actual new pure module. First run a compiling unsafe admission implementation `source_allowed(_: &DonorFacts)->bool { true }` and `may_launch(_: &Admission)->bool { true }`; prove genuine behavior RED, then discard it. Missing modules/compiler failures do not count as RED.

```rust
#[test]
fn donor_and_launch_unknowns_fail_closed() {
    let good = DonorFacts { runtime:true,image:true,instance:true,live:true,
        console_user:true,console_session:true,primary:true,non_elevated:true,
        medium:true,no_enabled_admins:true,ui_access_zero:true,
        sandbox_inert_zero:true,recognized_type:true };
    assert!(source_allowed(&good));
    let mut absent = good;
    absent.runtime = false;
    assert!(!source_allowed(&absent));
    let fresh = Admission { donor:good,duplicate_exact:true,source_unchanged:true,
        copy_unchanged:true,fresh:true,remaining_ms:19_000 };
    assert!(may_launch(&fresh));
    let stale = Admission { fresh:false, ..fresh };
    assert!(!may_launch(&stale));
    let exhausted = Admission { remaining_ms:18_999, ..fresh };
    assert!(!may_launch(&exhausted));
}
```

- [ ] Complete table-driven negatives for EACH false admission field, all duplicate/equality/query unknowns, no/ambiguous root candidate, discovery overflow/cycles, exited donor, changed creation time/TokenId/kernel path/current on-disk runtime generation, wrong donor user/session, preservation change, privilege attribute addition and caller service/non-elevated context. Include initial known `caller-user-equal=false` as a valid different-account UAC observation, then reject either party's later identity change. Native consumes this model; tests cannot be source-regex authorization.
- [ ] Capture the current caller's query-only token/full snapshot/default ACL/object SD/private identity first. Require elevated primary interactive administrator/provisioner-role context in the active console session, excluding service principals. Record caller-user-equals-donor privately as a boolean; different UAC administrator identity is not silently substituted for donor identity and is not assumed to have duplication/assignment rights.
- [ ] `verify_runtime_lease()` retains the installed enrollment, immutable complete runtime and protected ancestry before discovery. Retain an additional fixed Manager image handle, validated ACL/FileID/hash against the enrolled inventory. Do not use candidate enrollment, install preparation/history creation or `commit_enrollment` to manufacture trust.
- [ ] Take `CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)` without INHERIT, bounded as above. Only entries named exactly the fixed Manager basename are image candidates. Open matching candidates query/synchronize only, verify the kernel full path and separately pinned current image FileID, read process creation time/liveness and retain handles. These observations do not identify already-mapped bytes. No command-line parsing or renderer flags. Same-path descendants are excluded using the bounded retained candidate graph with parent creation time preceding child. A sole root is a discovery choice, not a main-process/authentication guarantee; ambiguous, incomplete, cyclic or changing graphs fail closed. Do not inspect unrelated process tokens. Do not output snapshot data.
- [ ] On the sole selected fixed-path candidate, open observer token QUERY|READ_CONTROL and read bounded complete snapshot, user/session/console, group classification, default ACL, object SD and exact SDK TokenStatistics. Require the ordinary predicate within its diagnostic scope. Requery the retained process/token and a second bounded discovery snapshot to reject replacement, exited/ambiguous root, console switch or changed current on-disk generation; do not label that mapped-generation validation.
- [ ] Open the separate minimal QUERY|DUPLICATE|READ_CONTROL handle from the SAME retained donor process; prove the same private TokenId and full snapshot before `DuplicateTokenEx`. New output immediately gets an owned guard; require new TokenPrimary, known distinct TokenId, same user/session/groups/privileges/integrity/elevation/UIAccess/Sandbox/type/elevation type, unchanged donor descriptor/default ACL, and baseline the copy's own descriptor/default ACL. Unknown or API denial emits a closed failed boundary; no access retry with broader rights.
- [ ] At this checkpoint, review the donor-only implementation and actual host negatives. Actual Windows rights/source facts remain pending the external donor prerequisite; do not report host or cross-compile results as donor availability.

## Task 2: Exact fixed child execution under that source context

- [ ] Add actually used lifecycle/model tests before wiring launch: uncertain creation forbids later launch and fixture deletion/release; verified held-handle reap permits cleanup; failed final reap preserves leases. Full 100 ms wait requires at least 3,100 ms remaining, not a shortened timeout. Reap failure or a change from either caller's or donor's own preservation baseline stops subsequent launches while all independent observations still execute. Initial caller and donor user inequality alone is valid, separately labeled different-account UAC evidence.
- [ ] Create protected private Wait and Proof fixtures with `Fixture::create(&actual_elevated_caller_sid, Variant::Wait)` and `Fixture::create(&actual_elevated_caller_sid, Variant::Proof)`, retaining ancestry/root/file identity/hash/ACL pins. Obtain that SID from the actual elevated caller token, never the ordinary donor; canonical runtime `FILE_SDDL` already grants builtin Users read/execute. Compile only the unchanged checked-in PE source; no installed payload file is modified. Capture source/copy/caller preservation baselines before fixtures/launch.
- [ ] Launch the fixed Wait PE with `OwnedChild::create` and the copied primary token: old exact flags, NULL process/thread attributes, fixed environment/desktop/CWD, no inherited handles or redirected stdio. Do not call a second API, shell, credentials or linked-token fallback. An API refusal is a rights/launch boundary result, not DLL failure. `CreateProcessAsUserW` can temporarily enable existing caller privileges; no explicit enablement occurs and post-call equality must be observed, never assumed.
- [ ] Before Resume, prove the owned child's exact precreation-pinned fixture image/ancestors, complete actual-child snapshot equals the ordinary copy/donor properties, independently ordinary-source policy, current donor TokenId/process instance/kernel path, current console/user, separately pinned current installed runtime generation, and unchanged caller/donor/copy descriptors/default ACL/full properties. The donor's mapped generation remains unavailable. Child TokenId may be a distinct known instance; equality of properties is not object ownership. Parent/group-role hints never replace these checks.
- [ ] Rerun final image/token/console/donor proof immediately before `OwnedChild::resume`; make final proof+resume inseparable, with no intervening output callback or optional query. Wait must remain alive for the full 100 ms, then terminate/reap only the held owned child and verify termination. Early self-check/loader/unknown exit remains a closed native failure.
- [ ] Only after verified reap and fresh independent source checks, launch the fixed Proof PE under the same copied source context and repeat every proof before Resume. Require bounded exit zero (10-second maximum), actual executing PE self-check success, held-handle reap and exact fixture cleanup. Neither a suspended proof nor CreateProcess success constitutes execution proof.
- [ ] Run ALL independent caller/donor/copy snapshots and cleanup operations, preserving first failure plus separate child-reap/Wait-fixture/Proof-fixture/source outcomes. Unknown creation or failed reap retains fixture leases through final RAII; the borrowed Manager is never terminated or reset. A success means this source-context experiment executed its harmless fixture, not production authorization or raw hardware permission.

## Task 3: Closed evidence, test gate and approved-desktop procedure

- [ ] Add a fixed `--manager-source-proof` wrapper mode selecting exactly `service_acl::windows_impl::restricted_token_probe::medium::child::manager_source_proof::native_authenticated_manager_source_proof` with `--ignored --exact --nocapture --test-threads=2`. No caller-supplied native arguments, donor selector or executable. Existing eight modes/result fields and their predicates remain unchanged.
- [ ] Phases in exact order: `caller`, `runtime`, `donor-discovery`, `donor-proof`, `duplicate`, `copy-proof`, `fixtures`, `wait-create`, `wait-proof`, `wait-resume`, `wait-observe`, `wait-reap`, `proof-create`, `proof-proof`, `proof-resume`, `proof-exit`, `proof-reap`, `wait-cleanup`, `proof-cleanup`, `caller-check`, `donor-check`, `copy-check`, `complete`. Each begun phase has exactly one terminal. On failure only independent cleanup/preservation phases may follow; first failure remains sticky. Closed exit classes reuse existing fixture status/loader categories; never print a raw status/error.
- [ ] Emit only compiled booleans appropriate to the current phase: `query-ok`, `known`, `available`, `unique`, `enrolled`, `image`, `instance`, `live`, `console-user`, `console-session`, `ordinary-medium`, `no-enabled-admins`, `ui-access-zero`, `sandbox-inert-zero`, `properties-equal`, `default-dacl-equal`, `descriptor-equal`, `copy-distinct`, `donor-same`, `caller-user-equal`, `created`, `creation-uncertain`, `fresh`, `timeout-alive`, `exit-zero`, `verified`, `deferred`, `experiment-complete`, `startup-proof`. Donor `image` retains the explicit kernel-path/current-file meaning, with no mapped-generation claim. Separate failed queries from negative known comparisons. `caller-user-equal` must be present and known but may be false in a valid transcript; add positive parser tests for both values. Completion/startup require every required phase and exact required observations, not optional GitHub status or a generic all-fields-true rule.
- [ ] Genuine parser RED: missing/zero/wrong test; numeric Cargo failure; signal/launch/buffer failure; no donor/unknown query; wrong or duplicate mode/field; orphan terminal/exit; skipped/out-of-order phase; failure then ok/begin; changed donor/caller/copy; incomplete cleanup; `startup-proof=true` without both actual waits/zero exit. Gate requires one exact named native success and `running 1 test`/one passed/zero failed/zero ignored plus complete valid native evidence; sanitized partial evidence cannot pass.
- [ ] Actual Rust formatter host test generates full success and each branch with CRLF plus 4 KiB Cargo reserve below 65,536 bytes; parser round-trip preserves every fixed field. Native errors and panic unwinding expose closed phase/error information only. No arbitrary stdout/stderr forwarding. Check old-mode tests are unchanged apart from explicit additive invocation/result-schema expectations.
- [ ] No GitHub job or acceptance normalization is added: the current builtin-Administrator CI cannot meet donor prerequisites. Keep its original fatal ordinary-child gate fatal. A later CI desktop/donor fixture would require separate reviewed authorization and real kernel source facts.

After root approves implementation AND the external machine/installation/donor condition, an operator can run these exact preparation commands from the repository in the intended elevated administrator terminal, leaving the already-open ordinary Manager alone:

```powershell
New-Item -ItemType Directory -Force -Path out/verification -ErrorAction Stop | Out-Null
rustc --edition=2024 native/rdx-service/windows-native/tests/fixtures/token-child.rs -o out/verification/openrdx-token-child.exe
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
rustc --edition=2024 --cfg token_fixture_hang native/rdx-service/windows-native/tests/fixtures/token-child.rs -o out/verification/openrdx-token-wait-child.exe
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
node scripts/verify-windows-restricted-token-probe.mjs --manager-source-proof
exit $LASTEXITCODE
```

These commands are a future procedure, not current authorization. They neither install the app nor create a donor. Normal and different-account UAC administrator cases must be labeled separately; inaccessible token or missing assignment privilege is a failed applicability result, not permission to enable privileges. No actual LocalService launch is covered.

## Verification and immutable review handoff

- [ ] Host focused verification runs the exact command below. Preserve all old gate assertions. Run the new pure model/actual formatter through that Node driver's `rustc --test` subprocess, recording real behavioral RED then GREEN.

```sh
node --test test/windows-manager-source-proof.test.mjs test/windows-debugger-control.test.mjs test/windows-actual-token-control.test.mjs test/windows-source-token-control.test.mjs test/windows-restricted-token-probe-gate.test.mjs test/windows-medium-token-probe-contract.test.mjs test/windows-process-dacl-control.test.mjs test/windows-object-dacl-matrix.test.mjs test/windows-token-matrix-output-bound.test.mjs test/windows-token-lineage-profile.test.mjs test/windows-token-probe-diagnostics.test.mjs test/windows-token-child-exit-contract.test.mjs test/windows-restricted-token-probe-contract.test.mjs test/windows-token-object-context.test.mjs test/windows-token-library-context.test.mjs test/windows-token-mandatory-context.test.mjs test/windows-token-desktop-context.test.mjs test/windows-token-effective-context.test.mjs test/windows-child-token-probe-contract.test.mjs
```

- [ ] Cross-check without new toolchain installation: `rustup run 1.95.0 cargo check --manifest-path native/rdx-service/windows-native/Cargo.toml --target x86_64-pc-windows-msvc --tests`; then the same `cargo clippy` invocation with `-- -D warnings`; then `cargo fmt --manifest-path native/rdx-service/windows-native/Cargo.toml -- --check`.
- [ ] Run `npm run format:check`, scoped `git diff --check`, handwritten line counts and a scoped diff ensuring production/old constructors/old fixture source/workflow are unchanged. Freeze exact source/test/Cargo hashes plus this plan, request root and independent review, and stop before commit/push or Windows execution.
- [ ] Report actual Windows evidence only after a separately approved run: exact source/machine architecture and sanitized caller/donor availability, query/duplicate rights, instance/full equality, child API/proof/wait/exit, all independent cleanup/preservation, transcript hash, and original gate still failing/passing separately. Never claim normal-desktop proof from the current elevated CI source.

## Primary API references

- [CreateToolhelp32Snapshot](https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-createtoolhelp32snapshot), [PROCESSENTRY32W](https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/ns-tlhelp32-processentry32w): read-only bounded process discovery; snapshot names/parent IDs are not authentication.
- [GetProcessTimes](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getprocesstimes), [OpenProcessToken](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocesstoken): retained process instance and DACL-constrained token opening; do not assume cross-account rights or enable SeDebug.
- [DuplicateTokenEx](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-duplicatetokenex): TOKEN_DUPLICATE source, DACL-checked output rights, primary copy and NULL/noninheritable attributes; explicit owner setting requires SeRestore and is excluded.
- [CreateProcessAsUserW](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessasuserw): QUERY/DUPLICATE/ASSIGN_PRIMARY token rights, token session, caller privileges, temporary API enablement and initialization not guaranteed by creation. A copied other-user token does not inherit the caller's restricted-own-token exemption by assumption.
- [Impersonation levels](https://learn.microsoft.com/en-us/windows/win32/secauthz/impersonation-levels): existing identification-only pipe supplies identity, not implicit execution delegation. This proof obtains any primary token through the separately checked retained process handle.
- [LocalService](https://learn.microsoft.com/en-us/windows/win32/services/localservice-account), [elevation types](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ne-winnt-token_elevation_type): documented account defaults do not prove installed service authority; Default means no linked token, not an available ordinary donor.
