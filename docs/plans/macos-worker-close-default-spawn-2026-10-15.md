<!-- SPDX-FileCopyrightText: 2026 André Fiedler -->
<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->

# Task 3: supported close-default worker launch adaptation

The [helper location compatibility amendment](macos-worker-helper-location-2026-10-15.md) supersedes the single standalone helper target below. It retains this ownership and spawn contract while selecting one of two fixed wrappers from the authenticated runtime generation; no caller path or fallback is added.

Proposed narrow amendment for root and independent review before production changes. Task 3 remains the only implementation scope; worker routing (Task 4) and direct CLI authority (Task 5) remain unchanged. This document does not authorize root, service, installation or device actions.

## Observed requirement gap

The actual ordinary-user Rust `Command::spawn` probe in `.tmp/task3-fd-parent.rs` opens its own temporary file, clears that descriptor's `FD_CLOEXEC`, and launches `.tmp/task3-fd-child` with all three standard streams piped. The child only tests that supplied owned descriptor with `fcntl(F_GETFD)`. `.tmp/task3-fd-probe.log` records `fd-close-default child_exit=Some(37)` (exit 37 means inherited). This is behavioral RED for close-default, not evidence about root, launchctl, sessions or devices. It does not justify `pre_exec`, fork callbacks, guessed `std::process::Child` internals, or closing other parent descriptors.

Use public Darwin `posix_spawn` with `POSIX_SPAWN_CLOEXEC_DEFAULT` for the new GUI factory route. Keep the existing standard-library launch route until its separately reviewed tasks. A GUI launch failure never falls back to that route.

## Exact ownership interfaces

Add cohesive `native/macos/rdx_worker_spawn.{h,c}` and private Rust `worker_process.rs`. Keep ABI 4 unchanged; new records have their own version/size.

```c
typedef struct {
    uint32_t version;       /* 1 */
    uint32_t size;          /* 24, checked with sizeof/offset static assertions */
    int32_t pid;           /* actual successful posix_spawn result, positive */
    int32_t input_fd;      /* parent writes child's stdin */
    int32_t output_fd;     /* parent reads child's stdout */
    int32_t error_fd;      /* parent reads child's stderr */
} rdx_macos_worker_process;

rdx_macos_status rdx_macos_spawn_gui_worker(
    const rdx_macos_peer_session *verified_peer,
    rdx_macos_worker_process *out_process);
```

Initialize output to version/size plus PID/FD sentinels before setup; transfer a process and three descriptors only on success. Return a sanitized existing native status; preserve underlying errno privately where existing diagnostic mapping needs it. The function has no path, argv, environment, caller FD or caller PID parameter. Its peer record comes only from the retained native capability. Validate record layout, valid non-root UID/AUID/EUID and current root credentials before using the public audit-token UID getter. Fresh complete peer/generation checks remain the Rust factory's responsibility before spawn and before ACK. Do not treat a cached record alone as fresh authority.

The Rust FFI wrapper is private. Immediately after successful C return it constructs an armed, non-Clone/non-Copy `OwnedSpawnedChild` and three `OwnedFd`/`File` owners using public ownership conversion APIs. No fallible operation runs between receipt and arming this guard. Production C guarantees valid, distinct descriptors >=3 and actual positive PID on success; Rust checks record layout before use and owns returned resources during every subsequent validation failure. The C/Rust output layout is checked at compile time and in a focused ABI test. No public raw-PID constructor exists.

```rust
enum WorkerProcess { Standard(std::process::Child), Spawned(OwnedSpawnedChild) }
impl WorkerProcess {
    fn id(&self) -> u32;
    fn try_wait(&mut self) -> std::io::Result<Option<std::process::ExitStatus>>;
    fn kill(&mut self) -> std::io::Result<()>;
}
// Private Read/Write + AsRawFd adapters retain existing ChildStdin/Stdout/Stderr
// or newly owned Files. Each underlying pipe has exactly one owner.
```

This is an ownership adapter, not an emulated/forged standard-library Child. `MacScsiWorkerLease` and `StartupDiagnostics` retain these adapters and share their current IO, nonblocking proof, bounded stderr, kill/reap and Busy paths. The Standard branch delegates to today's methods. The Spawned branch supplies equivalent retained-process semantics through public `waitpid` and `kill`. No second reaper or detached cleanup task is added.

## Fixed spawn construction

After proving `current_exe()` is the fixed protected installed helper in the pinned generation, C launches only:

```text
/bin/launchctl asuser <decimal native verified UID> /Library/PrivilegedHelperTools/openrdx-hardware --openrdx-internal-macos-scsi-worker
```

The UID conversion uses a bounded decimal buffer; all other arguments are literals. Environment is exactly `LANG=C` and a terminator. No shell, PATH lookup, caller selectors, process search, group signalling or new audit-session mutation API is used. Parent and child context proof must still establish actual retained PID/PPID, service credentials/GIDs, and exact verified AUID/ASID before IOKit. A wrapper producing a grandchild fails proof.

Create three private pipe pairs. Normalize **every** end to >=3 with public `F_DUPFD_CLOEXEC`, retaining distinct descriptors; close the original end after successful duplication. Newly allocated low-numbered ends may temporarily occupy an originally missing standard slot, but close them during normalization and leave the parent's originally absent 0/1/2 absent. Never `dup2` into or otherwise replace parent standard streams. Close every owned end on partial failure. No parent lock/socket/source descriptor is modified or delegated.

Set `POSIX_SPAWN_CLOEXEC_DEFAULT | POSIX_SPAWN_SETSIGMASK | POSIX_SPAWN_SETSIGDEF`. The explicit default-disposition set is exactly `{SIGPIPE}`; leave other dispositions to normal exec inheritance rather than incidentally resetting ignored signals. Supply an explicit empty child signal mask. The actual stdlib-to-C fixture `.tmp/task3-signal-probe.log` passed with `stdlib_child_exit=Some(0) sigpipe_default=1 sigpipe_blocked=0`; SIGPIPE default agrees with current Command behavior. The fixed empty mask is intentional for the worker, and focused fixtures must verify it plus preservation of an unrelated ignored disposition. Later Rust runtime initialization can apply its own normal SIGPIPE policy. File actions duplicate child input/output/error ends to 0/1/2, then explicitly close all six original pipe ends. Close-default excludes unrelated descriptors even when their caller deliberately cleared CLOEXEC. Parent closes only its child-side ends after success. Apply parent nonblocking setup only to the three parent endpoints; native spawn leaves the child endpoints blocking, and the child role separately bounds its preflight without changing its existing command-loop blocking semantics. Destroy spawn actions/attributes on every path and retain the original setup/spawn failure over cleanup failures.

`posix_spawn`'s returned error value is authoritative, not ambient errno. A nonzero result provides no owned child and its output PID is undefined: never inspect or signal that value. Before a successful call there is no owned child PID to signal. A successful call hands off its actual PID even if the executable subsequently exits; the armed owner handles that normal early exit. Do not add fork/vfork callbacks, Objective-C work in an unsafe postfork child, or private process APIs.

## Single waiter, failure and deadline contract

Start the GUI route's single absolute 15-second initialization deadline **before spawn**. Nonblocking pipe setup, context request/proof, fresh validation, final ACK, INIT and READY all consume that same deadline. This tightens the maintained plan's previous after-setup start point as explicitly requested by root. Check deadline before/after synchronous native validation; this does not promise to interrupt a stuck Security call. There is no fresh timeout for each phase or partial transfer.

`OwnedSpawnedChild` is the sole waiter for its retained PID. It uses only `waitpid(owned_pid, ..., WNOHANG)`, caches a successful status and converts it with public `ExitStatusExt::from_raw`. Never use waitpid(-1), a SIGCHLD global reaper, or transfer this PID to another waiter. EINTR returns to a bounded caller loop (or a bounded internal retry checking its supplied absolute deadline); it cannot make cleanup or startup spin forever. A returned status ends signal authority permanently. A normally exited unreaped child remains our zombie, so its PID cannot be reused before our sole waiter reaps it.

Before signalling, poll this same owner; signal only an owned, unreaped child and only its exact positive PID. `ECHILD` means ownership/reaping is unproven: permanently disarm signal authority, return failure, and retain the existing process-wide `UNREAPED_WORKER` Busy refusal. Do not reinterpret ECHILD as successful capture release. Other wait/kill errors preserve the primary operation failure while bounded cleanup independently attempts proof. ESRCH alone is not reap proof. Cached/reaped/lost states never signal again. This relies on the enforced single-waiter design; no concurrent/global child reaper is introduced.

The armed owner survives missing pipes, fcntl failure, stale/revoked factory, all malformed/partial/EOF context frames, wrong child proof, failed final validation/ACK, deadline expiry and unwinding. After spawn, any failure closes owned pipes and follows today's exact-child SIGKILL plus at-most-500ms WNOHANG reap loop. Its RAII cleanup must be idempotent and share the existing Busy latch; it cannot independently repeat 500ms cleanup after the lease already attempted it. Uncertain termination keeps future workers disabled. Original protocol/result/error/Busy semantics and existing finite capture release remain unchanged. No reap failure can be hidden by a successful pipe ACK.

## Bounded validation before factory routing

1. Preserve the exact stdlib probe and its FD number as RED evidence. A standalone compile-time test harness exercises the same private C spawn primitive with a fixed harmless fixture executable; test-only target selection is absent from the production C ABI/build. On the same owned FD, public close-default spawn must report descriptor absent (GREEN). No root or launchctl eligibility is claimed by this fixture.
2. Exercise actual three-pipe transfer, fixed argv/environment, exit 37/status conversion, silent/partial IO absolute deadline, owned-child SIGTERM/SIGKILL and bounded reaping. Assert no extra inherited descriptors, including a deliberately non-CLOEXEC owned descriptor. Cross-check retained actual PID against the fixture's self-report.
3. In isolated fixture subprocesses, test all missing/present combinations of parent descriptors 0/1/2; confirm original standard-slot state is unchanged, all returned parent pipes are distinct and >=3, child standard streams work, and exact setup failures leak no pipe/child. Do not close the test runner's own standard streams.
4. Add injectable setup failures only in native test builds, covering each pipe/dup/action/attribute/spawn boundary; production never accepts caller descriptors or target selectors. Cover successful-spawn/later-fcntl failure through actual armed-owner cleanup, repeated try_wait, already-reaped kill refusal, EINTR deadline and ECHILD/lost-ownership no-signal/Busy behavior with focused syscall fixtures plus actual-child lifecycle tests.
5. Independently advance Task 3's pure context classifier/public self-audit and real private-pipe refusal tests while this adaptation is reviewed. Preserve existing direct worker tests and diagnostic record/EOF bounds. Do not route platform workers or direct CLI through the new launcher in Task 3.

Root and independent review must approve this amendment before production spawn adaptation. The actual installed GUI factory, signed/local runtime verification and selected-dock capture remain later acceptance gates.
