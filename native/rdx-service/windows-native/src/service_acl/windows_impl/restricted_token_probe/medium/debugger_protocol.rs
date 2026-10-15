// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Pure debugger event and cleanup admission; only the fixed owned factory supplies private IDs.
use std::collections::{HashMap, HashSet};

/// Compiled image categories, never an arbitrary path or SDK buffer.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Module {
    None,
    Fixture,
    Ntdll,
    Kernel32,
    KernelBase,
    Advapi32,
    Ucrt,
    Vcruntime,
    Other,
    Unknown,
}
/// Exact exception classification, not a claim about which API or access check failed.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Exception {
    None,
    Breakpoint,
    AccessDenied,
    AccessViolation,
    InPageError,
    DllInitFailed,
    Other,
}
/// Closed termination category; actual exit DWORD stays inside the SDK boundary.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Exit {
    DllInitFailed,
    Success,
    SelfCheck,
    Other,
}
/// Private modeled event metadata; raw identities deliberately lack Debug.
#[derive(Clone, Copy)]
pub(super) enum Kind {
    CreateProcess,
    CreateThread,
    ExitThread,
    Load {
        module: Module,
        base: usize,
    },
    Unload {
        base: usize,
    },
    Exception {
        class: Exception,
        first: bool,
        module: Module,
        mapped: bool,
    },
    ExitProcess {
        class: Exit,
    },
    DebugString,
    Rip,
}
/// Only the creating SDK thread can supply an event to this private policy.
pub(super) struct Event {
    pub(super) pid: u32,
    pub(super) tid: u32,
    pub(super) kind: Kind,
}
/// Handled is permitted for nonexceptions or one verified startup breakpoint only.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Continue {
    Handled,
    NotHandled,
}
/// Fieldless diagnostic policy failures contain no operating-system data.
#[derive(Clone, Copy, Debug)]
pub(super) enum ProtocolError {
    Foreign,
    Order,
    Bound,
    Pending,
    Unavailable,
}
/// Retains every accepted event until its actual SDK continuation succeeds.
pub(super) struct EventPolicy {
    pid: u32,
    initial: u32,
    threads: HashSet<u32>,
    modules: HashMap<usize, Module>,
    started: bool,
    pending: Option<Kind>,
    ended: Option<Exit>,
    exit_continued: bool,
    count: usize,
    exception_seen: bool,
    failed: bool,
}
impl EventPolicy {
    /// Constructs only for the private returned child's exact IDs.
    pub(super) fn new(pid: u32, initial_tid: u32) -> Self {
        Self {
            pid,
            initial: initial_tid,
            threads: HashSet::new(),
            modules: HashMap::new(),
            started: false,
            pending: None,
            ended: None,
            exit_continued: false,
            count: 0,
            exception_seen: false,
            failed: pid == 0 || initial_tid == 0,
        }
    }
    /// A rejected event permanently revokes this connection's continuation authority.
    fn reject<T>(&mut self, error: ProtocolError) -> Result<T, ProtocolError> {
        self.failed = true;
        Err(error)
    }
    /// Only this child's valid ordered bounded events obtain a continuation decision.
    pub(super) fn observe(&mut self, event: Event) -> Result<Continue, ProtocolError> {
        if self.failed {
            return Err(ProtocolError::Order);
        }
        if event.pid != self.pid || event.tid == 0 {
            return self.reject(ProtocolError::Foreign);
        }
        if self.pending.is_some() {
            return self.reject(ProtocolError::Pending);
        }
        if self.count >= 128 {
            return self.reject(ProtocolError::Bound);
        }
        if self.ended.is_some() {
            return self.reject(ProtocolError::Order);
        }
        if !self.started {
            if !matches!(event.kind, Kind::CreateProcess) || event.tid != self.initial {
                return self.reject(ProtocolError::Order);
            }
            self.started = true;
            self.threads.insert(event.tid);
        } else {
            match event.kind {
                Kind::CreateProcess => return self.reject(ProtocolError::Order),
                Kind::CreateThread => {
                    if !self.threads.insert(event.tid) {
                        return self.reject(ProtocolError::Order);
                    }
                }
                _ => {
                    if !self.threads.contains(&event.tid) {
                        return self.reject(ProtocolError::Foreign);
                    }
                }
            }
        }
        let decision = match event.kind {
            Kind::Load { module, base } => {
                if base == 0
                    || module == Module::None
                    || self.modules.insert(base, module).is_some()
                {
                    return self.reject(ProtocolError::Order);
                }
                Continue::Handled
            }
            Kind::Unload { base } => {
                if self.modules.remove(&base).is_none() {
                    return self.reject(ProtocolError::Order);
                }
                Continue::Handled
            }
            Kind::ExitThread => {
                self.threads.remove(&event.tid);
                Continue::Handled
            }
            Kind::Exception {
                class,
                first,
                module,
                mapped,
            } => {
                if class == Exception::None {
                    return self.reject(ProtocolError::Unavailable);
                }
                let startup = class == Exception::Breakpoint
                    && first
                    && module == Module::Ntdll
                    && mapped
                    && event.tid == self.initial
                    && !self.exception_seen
                    && self.modules.values().any(|v| *v == Module::Ntdll);
                self.exception_seen = true;
                if startup {
                    Continue::Handled
                } else {
                    Continue::NotHandled
                }
            }
            Kind::ExitProcess { class } => {
                self.ended = Some(class);
                Continue::Handled
            }
            Kind::Rip => return self.reject(ProtocolError::Unavailable),
            _ => Continue::Handled,
        };
        self.count += 1;
        self.pending = Some(event.kind);
        Ok(decision)
    }
    /// Advances only after the real ContinueDebugEvent call succeeds once.
    pub(super) fn continued(&mut self) -> Result<(), ProtocolError> {
        if self.failed {
            return Err(ProtocolError::Order);
        }
        let pending = match self.pending.take() {
            Some(pending) => pending,
            None => return self.reject(ProtocolError::Pending),
        };
        if matches!(pending, Kind::ExitProcess { .. }) {
            self.exit_continued = true;
            self.threads.clear()
        }
        Ok(())
    }
    /// An actual continuation failure is sticky and never a successful cleanup transition.
    pub(super) fn continuation_failed(&mut self) {
        self.failed = true;
    }
    /// Includes events consumed by cleanup; no reset or secondary event allowance exists.
    pub(super) fn slot(&self) -> usize {
        self.count.saturating_sub(1)
    }
    /// Requires continued EXIT, not just notification or termination request.
    pub(super) fn exit_continued(&self) -> bool {
        self.exit_continued && !self.failed
    }
    /// The debugger must independently reproduce the original exact failure category.
    pub(super) fn reproduced(&self) -> bool {
        self.exit_continued() && self.ended == Some(Exit::DllInitFailed)
    }
    /// Cleanup may only pump another event when no failed/pending/capped state remains.
    pub(super) fn can_wait(&self) -> bool {
        !self.failed && self.pending.is_none() && !self.exit_continued && self.count < 128
    }
}
/// Original PI disposition history is distinct from active OS thread-handle leases.
pub(super) struct HandleLedger {
    original: [usize; 2],
    pi_os_history: HashSet<usize>,
    process: Option<usize>,
    threads: HashMap<u32, usize>,
    registered: bool,
}
impl HandleLedger {
    /// Dedicated duplicates never enter the OS lease map; their guards alone close them.
    pub(super) fn new(process: usize, thread: usize) -> Self {
        Self {
            original: [process, thread],
            pi_os_history: HashSet::new(),
            process: None,
            threads: HashMap::new(),
            registered: false,
        }
    }
    /// Registers one CREATE process and its initial TID/handle lease.
    pub(super) fn event_process(
        &mut self,
        tid: u32,
        process: usize,
        thread: usize,
    ) -> Result<(), ProtocolError> {
        if self.registered || tid == 0 || process == 0 || thread == 0 || process == thread {
            return Err(ProtocolError::Order);
        }
        self.registered = true;
        self.process = Some(process);
        self.threads.insert(tid, thread);
        self.remember_original(process);
        self.remember_original(thread);
        Ok(())
    }
    /// Only active handle/TID collisions are refused; a successfully closed numeric slot may be reused.
    pub(super) fn event_thread(&mut self, tid: u32, thread: usize) -> Result<(), ProtocolError> {
        if !self.registered
            || tid == 0
            || thread == 0
            || self.threads.contains_key(&tid)
            || self.threads.values().any(|handle| *handle == thread)
            || self.process == Some(thread)
        {
            return Err(ProtocolError::Order);
        }
        self.threads.insert(tid, thread);
        self.remember_original(thread);
        Ok(())
    }
    /// Only original PI numeric slots need permanent auto-close disposition history.
    fn remember_original(&mut self, handle: usize) {
        if self.original.contains(&handle) {
            self.pi_os_history.insert(handle);
        }
    }
    /// Windows closes this lease only after the matching EXIT_THREAD SDK continuation succeeds.
    pub(super) fn thread_exit(&mut self, tid: u32, continued: bool) -> Result<(), ProtocolError> {
        if !continued {
            return Err(ProtocolError::Pending);
        }
        self.threads.remove(&tid).ok_or(ProtocolError::Order)?;
        Ok(())
    }
    /// Process EXIT continuation ends active leases but never erases original PI disposition history.
    pub(super) fn continued_process_exit(&mut self) {
        self.process = None;
        self.threads.clear();
    }
    /// Distinguishes originals from dedicated duplicates without inferring object authority.
    pub(super) fn is_original(&self, handle: usize) -> bool {
        self.original.contains(&handle)
    }
    /// An original ever auto-closed by Windows must never later close a reused numeric slot.
    pub(super) fn caller_closes(&self, handle: usize) -> bool {
        handle != 0 && self.original.contains(&handle) && !self.pi_os_history.contains(&handle)
    }
}
/// No possible child permits fixture release until held termination was proved.
pub(super) struct Cleanup {
    reaped: bool,
}
impl Cleanup {
    /// Conservative state exists before entering creation, including API error uncertainty.
    pub(super) fn uncertain_creation() -> Self {
        Self { reaped: false }
    }
    /// Returned handles alone never establish termination.
    pub(super) fn returned_child(&mut self) {
        self.reaped = false
    }
    /// Called only after held-handle wait succeeds AND all required exit events were continued.
    pub(super) fn verified_reap(&mut self) {
        self.reaped = true
    }
    /// No additional launch is allowed while ownership/liveness remains unresolved.
    pub(super) fn may_launch(&self) -> bool {
        self.reaped
    }
    /// No deletion, pin release or Fixture Drop is allowed while ownership is unresolved.
    pub(super) fn may_release_fixture(&self) -> bool {
        self.reaped
    }
    /// Actual fixture operations are never invoked while creation or held termination is unresolved.
    pub(super) fn cleanup_fixture<T>(
        &self,
        operation: impl FnOnce() -> T,
    ) -> Result<T, ProtocolError> {
        if !self.may_release_fixture() {
            return Err(ProtocolError::Order);
        }
        Ok(operation())
    }
}
/// Full requested finite poll budget must preserve the original 3s reap reserve.
pub(super) fn event_wait_budget(remaining_ms: u128, observation_remaining_ms: u128) -> Option<u32> {
    let requested = observation_remaining_ms.min(100);
    if requested == 0 || remaining_ms < requested + 3000 {
        return None;
    }
    Some(requested as u32)
}

/// Distinguishes a full natural observation window from interrupted/global/capped diagnostics.
pub(super) struct ObservationWindow {
    interrupted: bool,
}
/// Only a successfully emitted finite poll can choose the next expiry-loop action.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum ExpiryPoll {
    Continue,
    Survived,
}
impl ObservationWindow {
    /// Starts before the fixed ten-second observation period.
    pub(super) fn new() -> Self {
        Self { interrupted: false }
    }
    /// API, output and protocol failures cannot become survival observations.
    pub(super) fn interrupt(&mut self) {
        self.interrupted = true;
    }
    /// Every successful SDK poll checks its emitted evidence before choosing another transition.
    pub(super) fn poll_output(&mut self, output_failed: bool) -> Result<(), ProtocolError> {
        if output_failed || self.interrupted {
            self.interrupt();
            return Err(ProtocolError::Unavailable);
        }
        Ok(())
    }
    /// Expiry polls use the same output guard before continuation or survival classification.
    pub(super) fn expiry_poll(
        &mut self,
        queued: bool,
        output_failed: bool,
    ) -> Result<ExpiryPoll, ProtocolError> {
        self.poll_output(output_failed)?;
        Ok(if queued {
            ExpiryPoll::Continue
        } else {
            ExpiryPoll::Survived
        })
    }
    /// Only a full elapsed window with a valid uncapped protocol and intact reap reserve is survival evidence.
    pub(super) fn expired(&self, elapsed: bool, remaining_ms: u128, can_wait: bool) -> bool {
        !self.interrupted && elapsed && remaining_ms >= 3000 && can_wait
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    /// Fixed fake IDs are not kernel identity evidence.
    fn event(kind: Kind) -> Event {
        Event {
            pid: 11,
            tid: 12,
            kind,
        }
    }
    /// Starts a valid modeled creator sequence.
    fn started() -> EventPolicy {
        let mut p = EventPolicy::new(11, 12);
        p.observe(event(Kind::CreateProcess)).unwrap();
        p.continued().unwrap();
        p
    }
    #[test]
    fn foreign_and_orphan_events_are_refused() {
        assert!(
            EventPolicy::new(11, 12)
                .observe(Event {
                    pid: 99,
                    tid: 12,
                    kind: Kind::CreateProcess
                })
                .is_err()
        );
        assert!(
            EventPolicy::new(11, 12)
                .observe(event(Kind::ExitProcess {
                    class: Exit::DllInitFailed
                }))
                .is_err()
        );
    }
    #[test]
    fn only_known_initial_ntdll_breakpoint_is_handled() {
        let mut p = started();
        p.observe(event(Kind::Load {
            module: Module::Ntdll,
            base: 4096,
        }))
        .unwrap();
        p.continued().unwrap();
        assert!(matches!(
            p.observe(event(Kind::Exception {
                class: Exception::Breakpoint,
                first: true,
                module: Module::Ntdll,
                mapped: true
            })),
            Ok(Continue::Handled)
        ));
        p.continued().unwrap();
        assert!(matches!(
            p.observe(event(Kind::Exception {
                class: Exception::AccessDenied,
                first: true,
                module: Module::Ntdll,
                mapped: true
            })),
            Ok(Continue::NotHandled)
        ));
    }
    #[test]
    fn unknown_repeated_lastchance_breakpoints_remain_unhandled() {
        for (module, mapped, first) in [
            (Module::Unknown, false, true),
            (Module::Ntdll, true, false),
            (Module::Other, true, true),
        ] {
            let mut p = started();
            assert!(matches!(
                p.observe(event(Kind::Exception {
                    class: Exception::Breakpoint,
                    first,
                    module,
                    mapped
                })),
                Ok(Continue::NotHandled)
            ));
        }
        let mut p = started();
        p.observe(event(Kind::Load {
            module: Module::Ntdll,
            base: 4096,
        }))
        .unwrap();
        p.continued().unwrap();
        for expected in [Continue::Handled, Continue::NotHandled] {
            assert!(
                matches!(p.observe(event(Kind::Exception{class:Exception::Breakpoint,first:true,module:Module::Ntdll,mapped:true})),Ok(value) if value==expected)
            );
            p.continued().unwrap();
        }
    }
    #[test]
    fn pending_out_of_order_and_exhausted_events_are_refused() {
        let mut p = started();
        p.observe(event(Kind::DebugString)).unwrap();
        assert!(p.observe(event(Kind::DebugString)).is_err());
        let mut p = started();
        assert!(p.observe(event(Kind::CreateProcess)).is_err());
        let mut p = started();
        assert!(p.observe(event(Kind::Unload { base: 99 })).is_err());
        let mut p = started();
        assert!(
            p.observe(Event {
                pid: 11,
                tid: 99,
                kind: Kind::DebugString
            })
            .is_err()
        );
        let mut p = started();
        for _ in 1..128 {
            p.observe(event(Kind::DebugString)).unwrap();
            p.continued().unwrap();
        }
        assert!(p.observe(event(Kind::DebugString)).is_err());
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
        h.event_process(12, 101, 202).unwrap();
        assert!(!h.caller_closes(101));
        assert!(h.caller_closes(102));
        h.continued_process_exit();
        assert!(!h.caller_closes(101));
        let mut h = HandleLedger::new(101, 102);
        h.event_process(12, 201, 202).unwrap();
        assert!(h.caller_closes(101) && h.caller_closes(102));
    }
    #[test]
    fn full_budget_keeps_reap_reserve() {
        assert_eq!(event_wait_budget(3100, 100), Some(100));
        assert_eq!(event_wait_budget(3099, 100), None);
        assert_eq!(event_wait_budget(3000, 100), None);
        assert_eq!(event_wait_budget(19000, 0), None);
    }

    #[test]
    fn failed_or_duplicate_continuation_never_authorizes_exit_cleanup() {
        let mut p = started();
        p.observe(event(Kind::ExitProcess {
            class: Exit::DllInitFailed,
        }))
        .unwrap();
        assert!(!p.exit_continued() && !p.reproduced());
        p.continuation_failed();
        assert!(p.continued().is_err());
        assert!(!p.exit_continued() && !p.reproduced() && !p.can_wait());
        let mut p = started();
        assert!(p.continued().is_err());
        assert!(!p.can_wait());
    }

    #[test]
    fn thread_and_image_lifetimes_are_connection_local() {
        let mut p = started();
        p.observe(Event {
            pid: 11,
            tid: 13,
            kind: Kind::CreateThread,
        })
        .unwrap();
        p.continued().unwrap();
        p.observe(Event {
            pid: 11,
            tid: 13,
            kind: Kind::ExitThread,
        })
        .unwrap();
        p.continued().unwrap();
        assert!(
            p.observe(Event {
                pid: 11,
                tid: 13,
                kind: Kind::DebugString
            })
            .is_err()
        );
        let mut p = started();
        p.observe(event(Kind::Load {
            module: Module::Ntdll,
            base: 4096,
        }))
        .unwrap();
        p.continued().unwrap();
        assert!(
            p.observe(event(Kind::Load {
                module: Module::Kernel32,
                base: 4096
            }))
            .is_err()
        );
        assert!(!p.can_wait());
    }

    #[test]
    fn exhausted_primary_cap_cannot_be_reset_by_cleanup() {
        let mut p = started();
        for _ in 1..128 {
            p.observe(event(Kind::DebugString)).unwrap();
            p.continued().unwrap();
        }
        assert!(!p.can_wait());
        assert!(
            p.observe(event(Kind::ExitProcess {
                class: Exit::DllInitFailed
            }))
            .is_err()
        );
        assert!(!p.exit_continued() && !p.reproduced());
        assert!(p.continued().is_err());
        assert!(!p.can_wait());
    }

    #[test]
    fn creation_error_and_failed_reap_invoke_zero_fixture_operations() {
        let mut attempts = 0;
        let mut c = Cleanup::uncertain_creation();
        assert!(c.cleanup_fixture(|| attempts += 1).is_err());
        c.returned_child();
        assert!(c.cleanup_fixture(|| attempts += 1).is_err());
        assert!(attempts == 0 && !c.may_launch());
        c.verified_reap();
        c.cleanup_fixture(|| attempts += 1).unwrap();
        assert!(attempts == 1 && c.may_launch());
    }
    #[test]
    fn continued_thread_exit_retires_active_slot_without_losing_pi_history() {
        let mut h = HandleLedger::new(101, 102);
        h.event_process(12, 201, 102).unwrap();
        h.event_thread(13, 303).unwrap();
        assert!(h.event_thread(14, 303).is_err());
        h.thread_exit(13, true).unwrap();
        assert!(h.event_thread(14, 303).is_ok());
        h.thread_exit(12, true).unwrap();
        assert!(h.event_thread(15, 102).is_ok());
        assert!(!h.caller_closes(102));
        h.continued_process_exit();
        assert!(!h.caller_closes(102));
    }
    #[test]
    fn failed_thread_exit_continuation_keeps_live_lease() {
        let mut h = HandleLedger::new(101, 102);
        h.event_process(12, 201, 202).unwrap();
        h.event_thread(13, 303).unwrap();
        assert!(h.thread_exit(13, false).is_err());
        assert!(h.event_thread(14, 303).is_err());
        assert!(h.event_thread(13, 304).is_err());
    }
    #[test]
    fn full_window_survival_is_changed_only_without_interrupt_or_budget_failure() {
        let mut w = ObservationWindow::new();
        assert!(!w.expired(false, 19000, true));
        assert!(!w.expired(true, 2999, true));
        assert!(!w.expired(true, 19000, false));
        assert!(w.expired(true, 19000, true));
        w.interrupt();
        assert!(!w.expired(true, 19000, true));
    }

    #[test]
    fn expiry_poll_output_failure_cannot_continue_or_classify_survival() {
        for queued in [true, false] {
            let mut window = ObservationWindow::new();
            assert!(window.expired(true, 19000, true));
            assert!(window.expiry_poll(queued, true).is_err());
            assert!(!window.expired(true, 19000, true));
        }
        let mut window = ObservationWindow::new();
        assert!(matches!(
            window.expiry_poll(true, false),
            Ok(ExpiryPoll::Continue)
        ));
        assert!(matches!(
            window.expiry_poll(false, false),
            Ok(ExpiryPoll::Survived)
        ));
    }
}
