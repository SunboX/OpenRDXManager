// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Pure test-only ordinary-source admission; never production or reduced-token authority.

/// Closed discovery/admission boundaries; no private process or token value escapes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Boundary {
    Unavailable,
    Ambiguous,
    Identity,
    SourcePolicy,
    Preservation,
}

/// Independent current-caller facts; group query success never substitutes for interactive role.
#[derive(Clone, Copy)]
pub(super) struct CallerFacts {
    pub(super) query_known: bool,
    pub(super) elevated: bool,
    pub(super) high: bool,
    pub(super) primary: bool,
    pub(super) active_console_session: bool,
    pub(super) builtin_admin: bool,
    pub(super) not_service_principal: bool,
    pub(super) interactive_enabled: bool,
    pub(super) service_enabled: bool,
    pub(super) batch_enabled: bool,
}

/// Only enabled, non-deny-only membership supplies an actual caller role.
pub(super) fn enabled_group(attributes: u32) -> bool {
    attributes & 0x4 != 0 && attributes & 0x10 == 0
}

/// Caller is genuinely interactive, elevated and active-console; SERVICE/BATCH are disallowed roles.
pub(super) fn caller_allowed(f: &CallerFacts) -> bool {
    f.query_known
        && f.elevated
        && f.high
        && f.primary
        && f.active_console_session
        && f.builtin_admin
        && f.not_service_principal
        && f.interactive_enabled
        && !f.service_enabled
        && !f.batch_enabled
}

/// `image` means kernel path plus separately pinned current file, never mapped bytes.
#[derive(Clone, Copy)]
pub(super) struct DonorFacts {
    pub(super) runtime: bool,
    pub(super) image: bool,
    pub(super) instance: bool,
    pub(super) live: bool,
    pub(super) console_user: bool,
    pub(super) console_session: bool,
    pub(super) primary: bool,
    pub(super) non_elevated: bool,
    pub(super) medium: bool,
    pub(super) no_enabled_admins: bool,
    pub(super) ui_access_zero: bool,
    pub(super) sandbox_inert_zero: bool,
    pub(super) recognized_type: bool,
}

/// Preservation is separate from initial caller/donor identity equality, which may be false.
#[derive(Clone, Copy)]
pub(super) struct Admission {
    pub(super) donor: DonorFacts,
    pub(super) duplicate_exact: bool,
    pub(super) source_unchanged: bool,
    pub(super) copy_unchanged: bool,
    pub(super) fresh: bool,
    pub(super) remaining_ms: u128,
}

/// Private discovery model values are never formatted or treated as authentication.
#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) struct Candidate {
    pub(super) key: u32,
    pub(super) parent: u32,
    pub(super) born: u64,
}

/// Ordinary source contract preserves all legitimate privileges, requiring no enabled admin roles.
pub(super) fn source_allowed(f: &DonorFacts) -> bool {
    f.runtime
        && f.image
        && f.instance
        && f.live
        && f.console_user
        && f.console_session
        && f.primary
        && f.non_elevated
        && f.medium
        && f.no_enabled_admins
        && f.ui_access_zero
        && f.sandbox_inert_zero
        && f.recognized_type
}
/// Future child phase can consume only complete fresh source/copy evidence and full reserve.
pub(super) fn may_launch(f: &Admission) -> bool {
    source_allowed(&f.donor)
        && f.duplicate_exact
        && f.source_unchanged
        && f.copy_unchanged
        && f.fresh
        && f.remaining_ms >= 19_000
}
/// Exact-name candidate graph is a bounded selection hint, not mapped-image authentication.
pub(super) fn select_root(
    candidates: &[Candidate],
    records: usize,
    complete: bool,
    within_budget: bool,
) -> Result<usize, Boundary> {
    if !complete
        || !within_budget
        || records > 4096
        || candidates.len() > 32
        || candidates.len() > records
    {
        return Err(Boundary::Unavailable);
    }
    let mut root = None;
    for (index, candidate) in candidates.iter().enumerate() {
        if candidate.key == 0
            || candidate.born == 0
            || candidate.key == candidate.parent
            || candidates[..index]
                .iter()
                .any(|other| other.key == candidate.key)
        {
            return Err(Boundary::Identity);
        }
        if let Some(parent) = candidates
            .iter()
            .find(|other| other.key == candidate.parent)
        {
            if parent.born >= candidate.born {
                return Err(Boundary::Identity);
            }
        } else if root.replace(index).is_some() {
            return Err(Boundary::Ambiguous);
        }
    }
    root.ok_or(Boundary::Unavailable)
}
/// Initial different-account UAC is valid; unavailable equality or preservation failure is not.
pub(super) fn caller_observation(equal: Option<bool>, preserved: bool) -> bool {
    equal.is_some() && preserved
}

/// Same instance/logon/full properties/default ACL/descriptor; ModifiedId alone is observational.
pub(super) fn preserved(ids: [bool; 4], state: [bool; 3]) -> bool {
    ids[0] && ids[1] && ids[2] && state.iter().all(|value| *value)
}
/// New known object with exact inherited state; no reduction or privilege expansion is implied.
pub(super) fn duplicate_allowed(ids: [bool; 4], properties: bool, default: bool) -> bool {
    ids[0] && !ids[1] && ids[2] && properties && default
}
/// Every retained discovery hint stays equal and the selected root is still that same instance.
pub(super) fn same_discovery(
    before: &[Candidate],
    after: &[Candidate],
    selected: Candidate,
    root: usize,
) -> bool {
    before == after && after.get(root) == Some(&selected)
}

/// Accepts already evaluated independent observers; the first failure is never replaced.
pub(super) fn preservation_result<E, const N: usize>(results: [Result<(), E>; N]) -> Result<(), E> {
    results
        .into_iter()
        .find_map(Result::err)
        .map_or(Ok(()), Err)
}

/// Closed lifecycle failure, never a process/PID cleanup instruction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum LifeError {
    Busy,
    State,
    TimedOut,
}
/// One possible live factory-owned child; uncertainty permanently blocks later launches.
pub(super) struct Lifecycle {
    active: bool,
    unresolved: bool,
    blocked: bool,
    resumed: bool,
}
impl Lifecycle {
    /// Starts with no possible child and therefore safe fixture cleanup.
    pub(super) fn new() -> Self {
        Self {
            active: false,
            unresolved: false,
            blocked: false,
            resumed: false,
        }
    }
    /// Reserves ownership uncertainty before entering the existing constructor.
    pub(super) fn begin_creation(&mut self, remaining: u128) -> Result<(), LifeError> {
        if !self.may_launch() {
            return Err(LifeError::Busy);
        }
        if remaining < 19_000 {
            return Err(LifeError::TimedOut);
        }
        self.unresolved = true;
        self.resumed = false;
        Ok(())
    }
    /// Err may hide post-create cleanup; only a returned owned guard establishes known ownership.
    pub(super) fn record_creation(&mut self, created: bool) {
        if !self.unresolved || self.active || !created {
            self.blocked = true;
        }
        self.active = created;
    }
    /// Called only after inseparable fresh proof; repeated/missing proof cannot authorize Resume.
    pub(super) fn admit_resume(&mut self, fresh: bool) -> Result<(), LifeError> {
        if !self.active || !self.unresolved || self.blocked || self.resumed || !fresh {
            return Err(LifeError::State);
        }
        self.resumed = true;
        Ok(())
    }
    /// The caller supplies true only after held-handle termination WAIT succeeds.
    pub(super) fn record_reap(&mut self, verified: bool) {
        if verified {
            self.active = false;
            self.unresolved = false;
            self.resumed = false;
        } else {
            self.unresolved = true;
            self.blocked = true;
        }
    }
    /// A primary failure stops all subsequent launch attempts.
    pub(super) fn block(&mut self) {
        self.blocked = true;
    }
    /// Never opens a second child or revokes an earlier fatal outcome.
    pub(super) fn may_launch(&self) -> bool {
        !self.active && !self.unresolved && !self.blocked
    }
    /// Retains exact fixture leases whenever termination remains unknown.
    pub(super) fn unresolved(&self) -> bool {
        self.unresolved
    }
    /// Does not execute any delete/release callback while a possible child remains alive.
    pub(super) fn cleanup_fixture<T>(&self, operation: impl FnOnce() -> T) -> Option<T> {
        if self.unresolved {
            None
        } else {
            Some(operation())
        }
    }
}
/// Full requested observation plus three seconds of held-handle reap reserve, without capping.
pub(super) fn wait_budget(remaining: u128, requested: u32) -> Option<u32> {
    ((1..=10_000).contains(&requested) && remaining >= u128::from(requested) + 3000)
        .then_some(requested)
}

/// Reporting always executes, but a preexisting primary failure wins over a later writer failure.
pub(super) fn after_report<T, E>(
    primary: Result<T, E>,
    report: impl FnOnce(bool) -> Result<(), E>,
) -> Result<T, E> {
    let reported = report(primary.is_ok());
    let value = primary?;
    reported?;
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    /// Complete kernel observations; no source privilege count or SID is test output.
    fn good() -> DonorFacts {
        DonorFacts {
            runtime: true,
            image: true,
            instance: true,
            live: true,
            console_user: true,
            console_session: true,
            primary: true,
            non_elevated: true,
            medium: true,
            no_enabled_admins: true,
            ui_access_zero: true,
            sandbox_inert_zero: true,
            recognized_type: true,
        }
    }

    /// Full elevated caller in a real interactive console, independently from ordinary donor identity.
    fn caller() -> CallerFacts {
        CallerFacts {
            query_known: true,
            elevated: true,
            high: true,
            primary: true,
            active_console_session: true,
            builtin_admin: true,
            not_service_principal: true,
            interactive_enabled: true,
            service_enabled: false,
            batch_enabled: false,
        }
    }
    /// A console/admin token without enabled INTERACTIVE must not be called interactive.
    #[test]
    fn caller_requires_enabled_nondeny_interactive_role() {
        assert!(caller_allowed(&caller()));
        for attributes in [0, 0x2, 0x10, 0x14] {
            let facts = CallerFacts {
                interactive_enabled: enabled_group(attributes),
                ..caller()
            };
            assert!(!caller_allowed(&facts));
        }
        assert!(caller_allowed(&CallerFacts {
            interactive_enabled: enabled_group(0x4),
            ..caller()
        }));
    }
    /// SERVICE/BATCH tokens cannot use an active-console session to impersonate the intended caller role.
    #[test]
    fn caller_rejects_enabled_service_and_batch_roles() {
        for (service, batch) in [(0x4, 0), (0, 0x4), (0x4, 0x4)] {
            let facts = CallerFacts {
                service_enabled: enabled_group(service),
                batch_enabled: enabled_group(batch),
                ..caller()
            };
            assert!(!caller_allowed(&facts));
        }
        for attributes in [0, 0x2, 0x10, 0x14] {
            let facts = CallerFacts {
                service_enabled: enabled_group(attributes),
                batch_enabled: enabled_group(attributes),
                ..caller()
            };
            assert!(caller_allowed(&facts));
        }
    }
    /// Every original caller condition and query-known result remains mandatory after role refinement.
    #[test]
    fn caller_unknown_and_all_wrong_base_facts_fail_closed() {
        for field in 0..7 {
            let mut facts = caller();
            match field {
                0 => facts.query_known = false,
                1 => facts.elevated = false,
                2 => facts.high = false,
                3 => facts.primary = false,
                4 => facts.active_console_session = false,
                5 => facts.builtin_admin = false,
                _ => facts.not_service_principal = false,
            }
            assert!(!caller_allowed(&facts));
        }
    }
    /// All actual donor facts are independent mandatory inputs, including query-known facts.
    #[test]
    fn every_unknown_or_denied_source_fact_is_refused() {
        assert!(source_allowed(&good()));
        for field in 0..13 {
            let mut facts = good();
            match field {
                0 => facts.runtime = false,
                1 => facts.image = false,
                2 => facts.instance = false,
                3 => facts.live = false,
                4 => facts.console_user = false,
                5 => facts.console_session = false,
                6 => facts.primary = false,
                7 => facts.non_elevated = false,
                8 => facts.medium = false,
                9 => facts.no_enabled_admins = false,
                10 => facts.ui_access_zero = false,
                11 => facts.sandbox_inert_zero = false,
                _ => facts.recognized_type = false,
            }
            assert!(!source_allowed(&facts));
        }
    }
    /// Duplication/preservation/query failures and insufficient reserve cannot admit a later launch.
    #[test]
    fn duplicate_or_stale_evidence_never_admits_launch() {
        let valid = Admission {
            donor: good(),
            duplicate_exact: true,
            source_unchanged: true,
            copy_unchanged: true,
            fresh: true,
            remaining_ms: 19_000,
        };
        assert!(may_launch(&valid));
        for field in 0..6 {
            let mut facts = valid;
            match field {
                0 => facts.duplicate_exact = false,
                1 => facts.source_unchanged = false,
                2 => facts.copy_unchanged = false,
                3 => facts.fresh = false,
                4 => facts.remaining_ms = 18_999,
                _ => facts.donor.instance = false,
            }
            assert!(!may_launch(&facts));
        }
    }
    /// Different-account UAC observation is valid; unknown or changed own baseline is not.
    #[test]
    fn initial_unequal_caller_is_observation_not_rejection() {
        assert!(caller_observation(Some(false), true));
        assert!(caller_observation(Some(true), true));
        for observation in [None, Some(false), Some(true)] {
            assert!(!caller_observation(observation, false));
        }
        assert!(!caller_observation(None, true));
    }
    /// Root selection uses parent ordering only as a hint and refuses ambiguous or malformed graphs.
    #[test]
    fn bounded_discovery_requires_one_complete_acyclic_root() {
        let root = Candidate {
            key: 10,
            parent: 1,
            born: 100,
        };
        let child = Candidate {
            key: 11,
            parent: 10,
            born: 200,
        };
        assert!(select_root(&[root, child], 2, true, true) == Ok(0));
        assert!(select_root(&[child, root], 2, true, true) == Ok(1));
        for graph in [
            vec![],
            vec![root, root],
            vec![root, Candidate { key: 12, ..root }],
            vec![Candidate { parent: 10, ..root }],
            vec![root, Candidate { born: 99, ..child }],
            vec![Candidate { parent: 11, ..root }, child],
            vec![Candidate { key: 0, ..root }],
        ] {
            assert!(select_root(&graph, graph.len(), true, true).is_err());
        }
        assert!(select_root(&[root], 4097, true, true).is_err());
        assert!(select_root(&[root], 1, false, true).is_err());
        assert!(select_root(&[root], 1, true, false).is_err());
        assert!(select_root(&[root], 0, true, true).is_err());
        let overflow = (1..=33)
            .map(|key| Candidate {
                key,
                parent: 0,
                born: key as u64,
            })
            .collect::<Vec<_>>();
        assert!(select_root(&overflow, 33, true, true).is_err());
    }

    /// Known TokenId and all full state components are required; ModifiedId is observational only.
    #[test]
    fn source_state_changes_are_never_equivalent() {
        assert!(preserved([true; 4], [true; 3]));
        assert!(preserved([true, true, true, false], [true; 3]));
        for index in 0..6 {
            let mut ids = [true; 4];
            let mut state = [true; 3];
            if index < 3 {
                ids[index] = false;
            } else {
                state[index - 3] = false;
            }
            assert!(!preserved(ids, state));
        }
    }
    /// A duplicate must be known distinct with exact full properties/default ACL and same logon.
    #[test]
    fn copies_cannot_alias_or_expand_source_properties() {
        assert!(duplicate_allowed([true, false, true, false], true, true));
        for (ids, properties, default) in [
            ([false, false, true, true], true, true),
            ([true, true, true, true], true, true),
            ([true, false, false, true], true, true),
            ([true, false, true, true], false, true),
            ([true, false, true, true], true, false),
        ] {
            assert!(!duplicate_allowed(ids, properties, default));
        }
    }
    /// Fresh snapshot cannot hide donor PID reuse, changed parent/time, missing/extra process or wrong root.
    #[test]
    fn selected_generation_and_graph_are_revalidated_exactly() {
        let root = Candidate {
            key: 1,
            parent: 0,
            born: 10,
        };
        let child = Candidate {
            key: 2,
            parent: 1,
            born: 20,
        };
        assert!(same_discovery(&[root, child], &[root, child], root, 0));
        for changed in [
            Candidate { key: 3, ..root },
            Candidate { born: 11, ..root },
            Candidate { parent: 4, ..root },
        ] {
            assert!(!same_discovery(&[root, child], &[changed, child], root, 0));
        }
        assert!(!same_discovery(&[root, child], &[root], root, 0));
        assert!(!same_discovery(&[root], &[root, child], root, 0));
        assert!(!same_discovery(&[root, child], &[root, child], root, 1));
        assert!(!same_discovery(&[root, child], &[root, child], root, 2));
    }

    /// Every array expression executes independently, and its first failure remains primary.
    #[test]
    fn all_observers_execute_without_replacing_first_error() {
        let calls = std::cell::Cell::new(0);
        let observe = |value: Result<(), u8>| {
            calls.set(calls.get() + 1);
            value
        };
        let result = preservation_result([observe(Err(1)), observe(Ok(())), observe(Err(2))]);
        assert!(calls.get() == 3);
        assert!(result == Err(1));
        assert!(preservation_result::<u8, 2>([Ok(()), Ok(())]).is_ok());
    }
    /// Unknown constructor/reap retains fixtures without running delete/release callbacks.
    #[test]
    fn uncertain_creation_and_failed_reap_never_release_or_relaunch() {
        for known_child in [false, true] {
            let mut life = Lifecycle::new();
            let deletes = std::cell::Cell::new(0);
            assert!(life.begin_creation(19_000).is_ok());
            life.record_creation(known_child);
            life.record_reap(false);
            assert!(life.unresolved());
            assert!(!life.may_launch());
            assert!(life.begin_creation(19_000).is_err());
            assert!(
                life.cleanup_fixture(|| deletes.set(deletes.get() + 1))
                    .is_none()
            );
            assert!(deletes.get() == 0);
        }
    }
    /// Only verified held-handle termination permits cleanup; failed reap remains launch-sticky.
    #[test]
    fn held_reap_controls_cleanup_and_final_retry_never_reopens_launch() {
        let mut life = Lifecycle::new();
        assert!(life.begin_creation(19_000).is_ok());
        life.record_creation(true);
        assert!(life.admit_resume(true).is_ok());
        assert!(life.admit_resume(true).is_err());
        life.record_reap(false);
        life.record_reap(true);
        assert!(!life.unresolved());
        assert!(!life.may_launch());
        let deleted = std::cell::Cell::new(0);
        assert!(life.cleanup_fixture(|| deleted.set(1)).is_some());
        assert!(deleted.get() == 1);
    }
    /// Sequential successful children are allowed; proof failure and insufficient reserve deny.
    #[test]
    fn no_second_live_child_or_resume_without_fresh_proof() {
        let mut life = Lifecycle::new();
        assert!(life.admit_resume(true).is_err());
        assert!(life.begin_creation(18_999).is_err());
        assert!(life.begin_creation(19_000).is_ok());
        assert!(life.begin_creation(19_000).is_err());
        life.record_creation(true);
        assert!(life.admit_resume(false).is_err());
        life.block();
        assert!(life.admit_resume(true).is_err());
        life.record_reap(true);
        assert!(!life.may_launch());
        let mut clean = Lifecycle::new();
        for _ in 0..2 {
            assert!(clean.begin_creation(19_000).is_ok());
            clean.record_creation(true);
            assert!(clean.admit_resume(true).is_ok());
            clean.record_reap(true);
        }
    }
    /// Survival requires the whole duration plus reap reserve, never shortened or zero wait.
    #[test]
    fn fixed_wait_duration_is_never_capped() {
        assert!(wait_budget(3100, 100) == Some(100));
        assert!(wait_budget(3099, 100).is_none());
        assert!(wait_budget(13000, 10000) == Some(10000));
        assert!(wait_budget(12999, 10000).is_none());
        assert!(wait_budget(20000, 0).is_none());
        assert!(wait_budget(20000, 10001).is_none());
    }
    /// A diagnostic writer failure cannot replace a preexisting creation/proof/cleanup failure.
    #[test]
    fn original_error_survives_reporting_failure_and_report_always_runs() {
        let calls = std::cell::Cell::new(0);
        let result = after_report::<(), u8>(Err(1), |ok| {
            assert!(!ok);
            calls.set(1);
            Err(2)
        });
        assert!(result == Err(1));
        assert!(calls.get() == 1);
        assert!(
            after_report::<(), u8>(Ok(()), |ok| {
                assert!(ok);
                Err(2)
            }) == Err(2)
        );
        assert!(after_report::<u8, u8>(Ok(3), |_| Ok(())) == Ok(3));
    }
}
