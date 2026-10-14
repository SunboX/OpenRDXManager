# Windows Owned Debugger Control Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans after the root agent separately approves this frozen plan. Follow the checkbox steps and stop for immutable-patch review before CI. This is PLAN ONLY: no implementation, commit, push, workflow dispatch or system operation is authorized by this document.

**Goal:** Determine whether public debugger events expose a more specific initialization failure in the exact privately owned medium-token Wait fixture that currently exits with `STATUS_DLL_INIT_FAILED`.

**Architecture:** A separate ignored test first reproduces the untreated failure, reaps it, then creates the same protected Wait image with only `DEBUG_ONLY_THIS_PROCESS` added to the existing creation flags. Its creating thread runs a bounded public debug-event loop; a pure policy authorizes event continuation while separate ownership guards retain cleanup authority. Closed observations may narrow a failure, but never authorize ordinary startup, Manager authentication or release.

**Tech Stack:** Rust 2024, existing Windows SDK bindings, host-executed Rust policy/ownership tests, Node 22 closed parser tests and the existing optional Windows diagnostic artifact.

**Spec:** [Locally trusted installation plan](locally-trusted-installation-2026-10-12.md), [owned token control plan](windows-owned-token-control-2026-10-14.md), and the constraints and observed boundary below. The root agent's explicit debugger-control design request governs this separate experiment.

<!-- SPDX-FileCopyrightText: 2026 André Fiedler -->
<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->

## Constraints and measured boundary

- Test-only `#[cfg(test)]` scope. Preserve production, ordinary child creation and all seven existing diagnostics and transcript schemas.
- Existing native global deadline **90 seconds**, launch/reap reserve **19,000 ms**, wrapper deadline **120 seconds**, combined stdout/stderr bound **65,536 bytes**. No expansion. One live child; at most **128 debug events** and at most **10,000 ms** collecting debug events for that child, preserving at least **3,000 ms** for held-handle reap.
- Source derivation handle requests exactly `TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_ADJUST_DEFAULT | READ_CONTROL`; no source `WRITE_DAC`. Reuse the existing fresh owned reduced-medium derivation and full properties, source/default-DACL/object-descriptor checks. The existing medium integrity setter on that fresh derived token is the only token adjustment; no new setter.
- New creation differs only by `DEBUG_ONLY_THIS_PROCESS`. Keep `CREATE_SUSPENDED | CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT`, fixed image, NULL command line, NULL process/thread attributes, false handle inheritance, existing environment, `winsta0\\default`, working directory and zero standard-handle settings.
- No ACL setters, source writes, privilege enabling, impersonation, IFEO/registry/job changes, private NT APIs, attach, arbitrary PID lookup, memory/context writes, injected breakpoints, debug strings, stack dumps or symbol downloads. Do not use `DEBUG_PROCESS`, `DebugActiveProcess`, `DebugActiveProcessStop` or `DebugSetProcessKillOnExit(false)`.
- Raw SDK structures, names, addresses, IDs, token information and error values remain private and never implement public diagnostics/Debug. Output uses compiled booleans and fixed categories only.
- Every native Result error remains first; independent source/derived checks and all safe cleanup attempts still execute. Uncertain creation or unverified termination forbids later launch and retains the exact fixture, ancestor/image pins and leases, including final Drop.
- Handwritten files stay below 1,000 lines with SPDX and Rust/JSDoc documentation. Root owns maintained verification docs, review, commits, pushes and actual CI. No VM, hardware, account, service or global OS actions.

Actual source `2ab63185e665d454d2ceb636cdc55b1560521fa4`, run [38612326777](https://github.com/SunboX/OpenRDXManager/actions/runs/38612326777), produced byte-identical seven-log evidence on x64 and ARM64. The actual-token control log SHA-256 is `7ec0a4c6446ad342088bb91d87f9d8f418356dc787ca46230e49e85cde51e237`. Its exact actual-token DACL insertion/readback, complete properties/default ACL, source/derived and process/thread preservation all pass; the fully requested treatment Wait still exits early with `status-dll-init-failed`, before any positive child. Reap and fixture cleanup pass. Local comparison: `.tmp/windows-2ab-token-compare.json`; parsed evidence: `.tmp/windows-2ab-token-evidence.json`.

The first four old matrix rows establish process/thread interventions but not successful startup. The four supplied-token rows do not establish actual-child propagation. Actual-token-only is now established and insufficient; combinations with process/thread treatment remain unmeasured. None establishes a loader mechanism or a particular denied operation. This experiment adds no permission combination.

## Public API basis and limits

- [Creation flags](https://learn.microsoft.com/en-us/windows/win32/procthread/process-creation-flags): `DEBUG_ONLY_THIS_PROCESS` is supported by `CreateProcessAsUser` and debugs only the created process.
- [WaitForDebugEvent](https://learn.microsoft.com/en-us/windows/win32/api/debugapi/nf-debugapi-waitfordebugevent) and [debug events](https://learn.microsoft.com/en-us/windows/win32/debug/debugging-events): the creating thread waits/continues; events suspend the process. Image/DLL file handles need explicit closure; Windows closes event process/thread handles after exit continuation. Exit continuation precedes final termination-wait proof.
- [ContinueDebugEvent](https://learn.microsoft.com/en-us/windows/win32/api/debugapi/nf-debugapi-continuedebugevent): `DBG_CONTINUE` handles an exception, whereas `DBG_EXCEPTION_NOT_HANDLED` preserves exception dispatch. Handle only one verified initial first-chance NTDLL startup breakpoint. Pass every other exception unhandled, at either chance.
- [Debug privilege](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/debug-privilege): debugging one's own application need not enable SeDebugPrivilege. Actual API refusal is a closed diagnostic failure; never enable privileges to work around it. Existing CPAsUser temporary caller privilege behavior remains an observed source-state boundary, not an assumed immutability guarantee.
- [VirtualQueryEx](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualqueryex) can map a private exception PC to its image allocation base. [LOAD_DLL_DEBUG_INFO](https://learn.microsoft.com/en-us/windows/win32/api/minwinbase/ns-minwinbase-load_dll_debug_info) may contain a NULL file handle/name. [GetMappedFileNameW](https://learn.microsoft.com/en-us/windows/win32/api/psapi/nf-psapi-getmappedfilenamew), only at a retained event's base in this owned child, supplies a bounded private fallback name; it reads mapping metadata, not process memory.
- [Kill-on-debugger-exit](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-debugsetprocesskillonexit) defaults true. Leave that setting unchanged; do not rely on thread exit instead of verified owned reap.

The debug flag changes debugger state, timing and exception handling. Require the same DLL-init exit in baseline and debug sibling before labeling evidence reproduced. A loaded module, last-loaded module or exception location is not proof that its initializer caused failure. Public load events report mapping, not DllMain entry/return or all failed access checks. If only the generic exit appears, cause remains unknown. [Loader snaps](https://learn.microsoft.com/en-au/windows-hardware/drivers/debugger/show-loader-snaps) use registry/kernel/image flags and are excluded.

## File map and private interfaces

Native base `N = native/rdx-service/windows-native/src/service_acl/windows_impl/restricted_token_probe/medium/`; every native path below is relative to this exact directory.

| Path | Action |
| --- | --- |
| `N/debugger_protocol.rs` | New pure event/continuation, budget and cleanup state model used by the native loop; host Rust tests. |
| `N/debugger_owner.rs` | New fixed constructor and separate factory/debug-event handle ownership; no raw adoption or PID attach API. |
| `N/debugger_modules.rs` | New bounded private event-file/mapping classifier and exception allocation-base association. |
| `N/debugger_output.rs` | New compiled schema/formatter; static phase keys and 128 fixed event slots. |
| `N/debugger_control.rs` | New two-child lifecycle, actual event loop, preservation and ignored native test. |
| `N/child.rs` | Add only `#[path = "debugger_control.rs"] mod debugger_control;`; no existing constructor/proof/cleanup changes. |
| `native/rdx-service/windows-native/Cargo.toml` | Add Windows **dev-dependency** `windows` version `0.62.2` with only additional SDK features `Win32_System_Diagnostics_Debug` and `Win32_System_ProcessStatus`; do not expand production dependency features. Existing Memory/FileSystem/SystemInformation features suffice for read-only mapping helpers. |
| `scripts/windows-debugger-control-evidence.mjs` | New strict closed event/phase parser. |
| `scripts/verify-windows-restricted-token-probe.mjs` | Add one fixed mode/result field/exact test; preserve all old modes and numeric Cargo failures. |
| `test/windows-debugger-control.test.mjs` | New compiling used-model negatives, handle disposition, parser/privacy and actual-formatter tests. |
| `test/windows-medium-token-probe-contract.test.mjs` | Update only sanitized capture-step cardinality seven to eight. |
| `test/windows-restricted-token-probe-gate.test.mjs` | Add only empty `debuggerControl: []` to exact wrapper failure shapes. |
| `.github/workflows/build-installers.yml` | One optional step and eighth closed diagnostic log, retaining the existing fatal ordinary gate/artifact separation. |

Reuse `actual_token_context.rs` unchanged through a private `#[path] mod context`: `SourceContext::{capture,unchanged,derive_medium,observed}`, `MinimalDerivedToken::{launch_token,unchanged,observed}`, `TokenState::{read,preservation,identity,require_same}`, `read_child`. Import the same private descriptor helpers into the new parent scope so these readers compile without widening their existing module API. Reuse `Fixture::{create,retained_payload,cleanup}`, `Variant::Wait`, `prove_child_quiet`, `OwnedChild::{wait,resume,terminate_and_reap}` and `actual_token_protocol::wait_budget` unchanged. Do not reuse its write-admission model or any DACL setter.

Private pure interfaces to implement and consume in native code:

```rust
enum Module { None, Fixture, Ntdll, Kernel32, KernelBase, Advapi32, Ucrt, Vcruntime, Other, Unknown }
enum Exception { None, Breakpoint, AccessDenied, AccessViolation, InPageError, DllInitFailed, Other }
enum Exit { DllInitFailed, Success, SelfCheck, Other }
enum Kind {
    CreateProcess, CreateThread, ExitThread,
    Load { module: Module, base: usize }, Unload { base: usize },
    Exception { class: Exception, first: bool, module: Module, mapped: bool },
    ExitProcess { class: Exit }, DebugString, Rip,
}
struct Event { pid: u32, tid: u32, kind: Kind }
enum Continue { Handled, NotHandled }
enum ProtocolError { Foreign, Order, Bound, Pending, Budget, Reap, Unavailable }
struct EventPolicy; // Owns exact private PID/TID, known thread/base sets, pending event and slot.
impl EventPolicy {
    fn new(pid: u32, initial_tid: u32) -> Self;
    fn observe(&mut self, event: Event) -> Result<Continue, ProtocolError>;
    fn continued(&mut self) -> Result<(), ProtocolError>;
    fn exit_continued(&self) -> bool;
    fn reproduced(&self) -> bool;
}
enum Lease { Caller, OsUntilExit, Closed }
struct HandleLedger; // Numeric values private; no object authority is inferred from equal numbers.
impl HandleLedger {
    fn new(process: usize, thread: usize) -> Self;
    fn event_process(&mut self, process: usize, thread: usize) -> Result<(), ProtocolError>;
    fn continued_process_exit(&mut self);
    fn caller_closes(&self, handle: usize) -> bool;
}
struct Cleanup; // Starts uncertain BEFORE calling create; no later launch without verified reap.
impl Cleanup {
    fn uncertain_creation() -> Self;
    fn returned_child(&mut self);
    fn verified_reap(&mut self);
    fn may_launch(&self) -> bool;
    fn may_release_fixture(&self) -> bool;
}
fn event_wait_budget(remaining_ms: u128, observation_remaining_ms: u128) -> Option<u32>;
// SDK lifecycle only: start at Instant::now()+90s, require remaining>=19_000 before each create.
struct Deadline(std::time::Instant);
impl Deadline {
    fn new() -> Self;
    fn remaining(&self) -> u128;
    fn require_launch(&self) -> Result<(), NativeError>;
}
struct Observation { exit: Option<Exit>, reproduced: bool, changed: bool }
```

The SDK owner exposes only `DebugOwnedChild::create(&Fixture, &MinimalDerivedToken)`, `prove_and_resume(&mut self, &SourceContext, &MinimalDerivedToken)`, `run_events(&mut self, &mut EventPolicy, &Deadline)` and `reap(&mut self, &Deadline)`. It accepts no caller-supplied flags, image, token, descriptor, PID, environment or timeout. Only its fixed factory constructs it. `run_events` returns a closed `Observation { exit: Option<Exit>, reproduced: bool, changed: bool }`; it never returns SDK data or a startup authorization.

## Task 1: Used event policy and ownership model, genuine behavior RED

- [ ] Create the host driver in `test/windows-debugger-control.test.mjs`. Import the actual `debugger_protocol.rs` with `#[path]`, compile with `rustc --edition=2024 --test`, then execute with `--test-threads=2`. Missing source/compiler or compilation failure is setup failure, never behavior RED.
- [ ] First use a temporary **compiling** permissive policy implementation in the intended module: `observe` returns `Ok(Continue::Handled)` and cleanup release always returns true. Save its failing assertions; discard that stub before implementing the guarded model. Include these actual behavioral tests in the used module:

```rust
#[test]
fn foreign_and_orphan_events_are_refused() {
    let mut p = EventPolicy::new(11, 12);
    assert!(p.observe(Event { pid: 99, tid: 12, kind: Kind::CreateProcess }).is_err());
    assert!(p.observe(Event { pid: 11, tid: 12, kind: Kind::ExitProcess { class: Exit::DllInitFailed } }).is_err());
}
#[test]
fn only_known_initial_ntdll_breakpoint_is_handled() {
    let mut p = EventPolicy::new(11, 12);
    p.observe(Event { pid: 11, tid: 12, kind: Kind::CreateProcess }).unwrap(); p.continued().unwrap();
    p.observe(Event { pid: 11, tid: 12, kind: Kind::Load { module: Module::Ntdll, base: 4096 } }).unwrap(); p.continued().unwrap();
    assert!(matches!(p.observe(Event { pid: 11, tid: 12, kind: Kind::Exception { class: Exception::Breakpoint, first: true, module: Module::Ntdll, mapped: true } }), Ok(Continue::Handled)));
    p.continued().unwrap();
    assert!(matches!(p.observe(Event { pid: 11, tid: 12, kind: Kind::Exception { class: Exception::AccessDenied, first: true, module: Module::Ntdll, mapped: true } }), Ok(Continue::NotHandled)));
}
#[test]
fn unresolved_creation_and_reap_retain_fixture() {
    let mut c = Cleanup::uncertain_creation();
    assert!(!c.may_launch() && !c.may_release_fixture());
    c.returned_child();
    assert!(!c.may_launch() && !c.may_release_fixture());
    c.verified_reap();
    assert!(c.may_launch() && c.may_release_fixture());
}
#[test]
fn event_handle_alias_is_not_double_closed() {
    let mut h = HandleLedger::new(101, 102);
    h.event_process(101, 202).unwrap();
    assert!(!h.caller_closes(101));
    assert!(h.caller_closes(102));
    h.continued_process_exit();
    assert!(!h.caller_closes(101));
}
#[test]
fn budget_never_consumes_final_reap_reserve() {
    assert_eq!(event_wait_budget(3100, 100), Some(100));
    assert_eq!(event_wait_budget(3099, 100), None);
}
```

- [ ] Implement the used policy. Require first event exact CREATE_PROCESS with initial TID; reject foreign PID, zero/unknown live TID, duplicate creation, create-after-exit, reused live thread/base slot, unload of unknown base, exit-before-create, event after process exit, nested pending event, duplicate continuation, 129th event and expired budget. Add host negatives for each branch and sticky first failure. Register/remove thread IDs only from their matching CREATE/EXIT events; initial/last thread may end through EXIT_PROCESS without EXIT_THREAD.
- [ ] Startup breakpoint is handled at most once, first chance, known retained NTDLL mapping, initial thread, before other exception/exit; every other exception returns NotHandled. Unknown mapping never grants Handled. Nonexception events return Handled; RIP is a closed infrastructure failure. Debug strings are neither read nor printed, only their event presence observed.
- [ ] Add injected ownership tests for separately valued and equal PI/event handles, file close on classifier/policy/continue failure, Continue failure retaining pending state, verified exit continuation before held wait, failed reap causing zero fixture deletion/release, no later launch, and original error surviving independent preservation/cleanup failures. These exercise the actual ledger/cleanup model consumed by the factory, not source regexes.
- [ ] Run `node --test --test-name-pattern='host debugger policy' test/windows-debugger-control.test.mjs`; save compiling RED and final GREEN to `.tmp/windows-debugger-policy-{red,green}.txt`.

## Task 2: Fixed creator-thread debugger experiment

- [ ] Add the test-only SDK dev features and the new child submodule. Implement `DebugOwnedChild::create` as a fixed sibling constructor copied from current creation mechanics, with the sole option difference `| DEBUG_ONLY_THIS_PROCESS`; original methods and seven experiments stay unchanged. Set cleanup uncertainty before the call. Immediately retain returned handles before PID sanity checks or any fallible observer.
- [ ] Duplicate the returned process/thread handles with `DuplicateHandle(..., DUPLICATE_SAME_ACCESS)` for the dedicated held cleanup/proof guard while original handles remain live. Keep original PI handles in `HandleLedger`; event process/thread handles are OS-managed leases, never `OwnedHandle`. If an event handle numerically equals an original PI handle, transfer that original disposition to OS-until-exit; otherwise close the caller PI handle exactly once after final debug-event disposal. Distinct owned duplicates remain valid across OS event closure. Duplication/validation failure still retains original owned cleanup authority; do not discard ownership or infer termination from an API failure.
- [ ] The baseline uses unchanged `OwnedChild::create`. Both children share one retained `Fixture::create(&source.user, Variant::Wait)` and exact image/path/hash/FileID/ancestor/owner/DACL pins. Baseline fresh proof immediately precedes resume, requires observed DLL-init failure and verified held-handle reap before debug sibling launch. No positive Proof executable is created.
- [ ] Before debugging resume, recheck source and derived full state/default ACL/object descriptor and actual child's complete medium token/current console/image proof. Read actual token QUERY|READ_CONTROL only; no WRITE_DAC. Make final `prove_child_quiet` immediately adjacent to resume without output or observer callbacks between them. Repeat source/derived observations after creation and after cleanup independently.
- [ ] Implement the event loop on the same Rust thread that called CPAsUser. Use `WaitForDebugEventEx` with finite policy budgets, never INFINITE; no callbacks/APCs or helper-thread handoff. Accept only the fixed returned PID privately. Call Continue exactly once for each accepted event; preserve pending state on failure. Use `DBG_CONTINUE` for authorized startup breakpoint/nonexception events and `DBG_EXCEPTION_NOT_HANDLED` for every other exception.
- [ ] For image/DLL events, install an owned file guard before any validation/output. Compare image file identity/hash to the retained fixture. Classify DLLs only through their event file handle and fixed private paths from `GetSystemDirectoryW`: `ntdll.dll`, `kernel32.dll`, `kernelbase.dll`, `advapi32.dll`, `ucrtbase.dll`, `vcruntime140.dll`, `vcruntime140_1.dll`; merge the last two as Vcruntime. Others are Other/Unknown, never arbitrary output strings. Do not open the DLL or follow its reported path.
- [ ] A NULL event file handle remains valid unavailable evidence. To recognize the startup NTDLL mapping despite this documented case, use `GetMappedFileNameW` only at that event's retained base in the held child, with a fixed 32,768-u16 buffer and exact nontruncated return. Build the expected NT path from kernel `GetSystemDirectoryW` plus fixed-drive [QueryDosDeviceW](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-querydosdevicew), bounded to that same capacity; never query NULL/all drives. Reject ambiguous/multiple device targets as unknown. No environment lookup, directory scan, arbitrary path open or process-memory read. Match full paths, not basename/suffix. For exception PCs, `VirtualQueryEx` must return exact-size `MEM_IMAGE` metadata and an allocation base matching a live retained module event before reporting its category. Unknown comparison remains Unknown and cannot authorize handling a breakpoint. An AccessDenied exception category means that exact exception code was raised, not that a particular API or DACL check was denied.
- [ ] On EXIT_PROCESS, retain the closed event exit category, Continue it, then require the dedicated held process handle to signal and independently read its matching closed exit category. Only both DLL-init results plus untreated baseline permit `reproduced=true`. Different exit/survival is `changed=true`, `reproduced=false`, and fails this experiment without clearing the ordinary gate.
- [ ] On any error, retain the first error, request termination only through the held owned process handle, and continue/drain only this connection's matching events until EXIT is continued and the held handle signals, bounded by the reserved cleanup deadline/event cap. The primary loop and cleanup drain share the same total **128-event cap** and **65,536-byte combined output bound**: neither budget is reset or enlarged after cap exhaustion, continuation failure or another primary error. A pending event still occupies its original slot; any retry cannot create a duplicate transcript event or manufacture a successful continuation. If the remaining budget cannot safely drain/continue EXIT and prove held-handle termination, report failed/deferred cleanup and retain all fixture leases and unresolved ownership state. Never count TerminateProcess success or received-but-uncontinued EXIT as verified reap. No detach or kill-on-exit change. If final drain/reap fails or ownership is uncertain, retain the complete fixture/ancestor/image leases and unresolved child/event ownership state; report deferred cleanup and forbid further launch. Drop must perform child cleanup before any fixture Drop and suppress fixture release on unresolved termination.
- [ ] Add the exact ignored entrypoint `service_acl::windows_impl::restricted_token_probe::medium::child::debugger_control::native_owned_medium_debugger_control`, with reason `requires administrator on a disposable Windows verifier`. Infrastructure errors fail; diagnostic completion requires both matched DLL-init exits, valid bounded event sequence, full preservation and verified cleanup. Startup proof is always false.

## Task 3: Closed evidence, fixed wrapper and optional CI

- [ ] `debugger_output.rs` defines the exact ordered phases: `setup`, `fixture`, `baseline-create`, `baseline-proof`, `baseline-resume`, `baseline-wait`, `baseline-reap`, `debug-create`, `debug-proof`, `debug-resume`, `debug-events`, `debug-reap`, `fixture-cleanup`, `source-check`, `derived-check`, `complete`. Use begin then exactly one ok/failed terminal per phase; retain the first failed phase independently of later cleanup. After a primary failure, only remaining applicable cleanup/preservation phases may run; success requires the full ordered set. Native error vocabulary is exactly `UnsupportedPlatform,InvalidRequest,AccessDenied,Busy,ReadOnly,Cancelled,TimedOut,DeviceRemoved,NoMedia,EnumerationFailed,EvidenceIncomplete,ResourceLimit,Other`, not SDK strings.
- [ ] Emit static boolean facts by phase: setup `verified,source-minimal,derived-medium`; fixture `protected`; create phases `created,creation-uncertain`; proof phases `image,properties,console,source-preserved,derived-preserved`; resume `fresh`; waits `dll-init-failed`; reaps `verified,deferred`; fixture cleanup `verified,deferred`; preservation checks `query-ok,properties,default-dacl,object-descriptor,instance-known,instance-equal`; complete `experiment-complete,reproduced,debugger-changed-behavior,startup-proof`. Add `event-protocol,exit-continued,held-exit-match,files-closed` to debug-events. No private values/counts.
- [ ] Event lines occur only inside debug-events: `openrdx-token-debugger-event slot=e000 kind=load module=ntdll exception=none first=false continued=true`. Slots are exactly the compiled `e000` through `e127`, contiguous and unique; kinds are `create-process,create-thread,exit-thread,load,unload,exception,exit-process,debug-string,rip`; module and exception categories are the enum vocabularies above plus None for inapplicable fields. Require inapplicable fields to be None/false. Emit the captured exception before its continuation outcome; continuation failure emits `continued=false` then fails the phase. No failed/unknown observation can authorize pass.
- [ ] Define `debuggerControlEvidence(lines)` returning `{lines,complete,reproduced,changed,firstFailure,reason}`. Reject duplicate/missing/unknown facts, orphan terminals/events, out-of-order phases, slot gaps/duplicates/cap overflow, nonboolean values, cross-mode events, contradictory reproduced/changed/startup flags, sticky failure overwritten by later ok, completed true with missing cleanup or preservation, and reproduced true without both matching exits/continued event protocol. Unavailable exception location is observable Unknown, not an invented match or cause.
- [ ] In the wrapper add only mode `debugger-control`, CLI `--debugger-control`, result array `debuggerControl`, and the exact ignored test above. Preserve bounded capture, original observed numeric Cargo failure and execution-error distinction. Require `running 1 test`, exact named PASS, summary one passed/zero failed/zero ignored and all new completion requirements; zero/wrong tests, query-only facts or any old-mode success must fail. New diagnostic success never makes `child` or an existing control pass.
- [ ] Define the test helper `async function actualFormatterTranscript()` to compile a host Rust driver importing the actual `debugger_output.rs`, execute its maximum valid 128-event sequence and all phases, then add the fixed exact libtest name/count/summary. Return normalized LF text; use a separate CRLF conversion for the bound assertion. Include all fixed facts and both success/error cleanup branches, plus 4,096-byte Cargo reserve. Assert total below 65,536; never increase capture. Use these real parser mutation patterns after obtaining that transcript:

```js
const mode = 'debugger-control'
const baseline = await actualFormatterTranscript()
assert.equal(validateRestrictedTokenProbeOutput(baseline, '', { mode }).passed, true)
for (const mutation of [
    baseline.replace('slot=e001', 'slot=e000'),
    baseline.replace('continued=true', 'continued=false'),
    baseline.replace('source-preserved=true', 'source-preserved=false'),
    baseline.replace('reproduced=true', 'reproduced=false'),
    baseline.replace('startup-proof=false', 'startup-proof=true'),
    baseline.replace('phase=debug-events status=begin\n', ''),
    baseline.replace('phase=debug-events status=ok', 'phase=debug-events status=failed reason=Other\nopenrdx-token-debugger-stage phase=debug-events status=ok')
]) assert.equal(validateRestrictedTokenProbeOutput(mutation, '', { mode }).passed, false)
```

- [ ] First run these adversarial tests against a compiling permissive new parser and save genuine assertion RED; replace it with the strict parser, then save GREEN. Add native-exit 101, buffer/signal/timeout/launch, raw SID/path/address/debug-string rejection, missing/wrong/zero test and existing seven-mode regression tests. Check only reconstructed closed lines ever reach wrapper stdout.
- [ ] Add optional Windows step after fixture compilation and existing controls: `if: always() && matrix.platform == 'win' && steps.windows-token-fixtures.outcome == 'success'`, `continue-on-error: true`, pwsh `node scripts/verify-windows-restricted-token-probe.mjs --debugger-control | Tee-Object -FilePath out/verification/windows-token-debugger-control.log`, immediately `$probeExitCode = $LASTEXITCODE`, then `exit $probeExitCode`. Add this one log to the existing `windows-token-diagnostics-${arch}` upload with retention 3 days. Preserve `actions/upload-artifact@v7.0.1`, the ordinary fatal step and installer asset collection patterns.

## Task 4: Frozen verification and authoritative handoff

- [ ] Use rustup-managed Rust 1.95.0 (`PATH="$HOME/.cargo/bin:$PATH"` scoped to commands if necessary), the already installed `x86_64-pc-windows-msvc` target and Node 22. Do not install another toolchain or target. Run focused Node tests, including every existing diagnostic suite:

```sh
node --test test/windows-*token-probe*.test.mjs test/windows-token-child-exit-contract.test.mjs test/windows-token-desktop-context.test.mjs test/windows-token-mandatory-context.test.mjs test/windows-token-library-context.test.mjs test/windows-token-object-context.test.mjs test/windows-source-token-control.test.mjs test/windows-token-effective-context.test.mjs test/windows-process-dacl-control.test.mjs test/windows-object-dacl-matrix.test.mjs test/windows-token-lineage-profile.test.mjs test/windows-token-matrix-output-bound.test.mjs test/windows-actual-token-control.test.mjs test/windows-debugger-control.test.mjs
rustup run 1.95.0 cargo check --manifest-path native/rdx-service/windows-native/Cargo.toml --locked --tests --target x86_64-pc-windows-msvc
rustup run 1.95.0 cargo clippy --manifest-path native/rdx-service/windows-native/Cargo.toml --locked --tests --target x86_64-pc-windows-msvc -- -D warnings
rustup run 1.95.0 cargo fmt --manifest-path native/rdx-service/windows-native/Cargo.toml --check
npm run format:check
git diff --check
```

- [ ] Save genuine RED/GREEN, formatter bound, focused/native/Clippy/fmt output in `.tmp/windows-debugger-*`. Inspect only scoped diff; verify all new source files below 1,000 lines, existing constructor/ordinary modes/transcripts unchanged and no production dependency feature expansion. Freeze explicit SHA-256 manifest of the listed implementation paths and this plan; report exact commands and outcomes for root/independent review. Do not commit or push.
- [ ] After review, root alone commits/pushes. Actual x64 and ARM64 must execute this exact ignored test; host policy/parser tests and cross-compilation are not Windows runtime proof. Collect all eight sanitized logs and full native job logs; compare baseline/debug reproduction, exception/module observations, exit continuation, held reap, source/derived preservation and cleanup separately from GitHub continue-on-error conclusion.
- [ ] Report either a reproduced, narrower exception/location observation or an explicit unchanged unknown boundary. Do not infer cause from last load, map location, optional success or debug-altered survival. Production integration and any new permission combination require another reviewed design GO. Linked-token alternatives remain separate and unavailable for the currently observed no-linked-token context; this experiment does not query or use them.

## Self-review and root decisions

This plan covers creator-thread ownership, automatic versus caller handle closure including aliases, initial NTDLL-only breakpoint handling, safe exception continuation, bounded optional mapping, matched failure, full source/derived/image/console preservation, conservative creation uncertainty, first error and independent cleanup, fixed output/gate/CI separation and unchanged deadlines. The only extra public read-only APIs beyond the proposal's event loop are `GetMappedFileNameW` and fixed-drive `QueryDosDeviceW` to avoid treating the documented NULL first-DLL handle as evidence for a startup breakpoint. They access only owned-child mapping metadata/kernel system-path metadata; if classification is unavailable, handling is refused and no cause is claimed.

Root review must approve that bounded fallback and the explicit PI/event handle ledger before execution. There are no requested user/system actions, no hidden setup prerequisites and no authority to implement before that review. The plan is frozen only when its SHA-256 is reported to root.
