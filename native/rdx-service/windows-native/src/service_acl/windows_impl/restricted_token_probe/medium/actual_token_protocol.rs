// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Pure test-only admission/epoch and cleanup policy, consumed by the owned native factory.
/// Kernel facts are supplied only by the fixed native observer; unknown identity never means nonalias.
pub(super) struct Admission {
    pub(super) fresh: bool,
    pub(super) image: bool,
    pub(super) console: bool,
    pub(super) properties: bool,
    pub(super) identities_known: bool,
    pub(super) same_held: bool,
    pub(super) source_alias: bool,
    pub(super) derived_alias: bool,
    pub(super) epoch_fresh: bool,
    pub(super) remaining_ms: u128,
}
/// Fixed lifecycle denial, never kernel identity output.
#[derive(Clone, Copy)]
pub(super) enum ModelError {
    Admission,
    Epoch,
    State,
}
/// The factory consumes each write admission once; resume is separate from untreated baseline.
pub(super) struct ControlModel {
    epoch: u64,
    prepared: Option<u64>,
    edited: bool,
    resumed: bool,
}
impl ControlModel {
    /// Starts a newly owned suspended child.
    pub(super) fn suspended() -> Self {
        Self {
            epoch: 0,
            prepared: None,
            edited: false,
            resumed: false,
        }
    }
    /// Requires complete fresh proof and enough reserve before recording one epoch.
    pub(super) fn prepare(&mut self, facts: Admission) -> Result<u64, ModelError> {
        if self.edited || self.resumed {
            return Err(ModelError::State);
        }
        if !(facts.fresh
            && facts.image
            && facts.console
            && facts.properties
            && facts.identities_known
            && facts.same_held
            && !facts.source_alias
            && !facts.derived_alias
            && facts.epoch_fresh
            && facts.remaining_ms >= 19_000)
        {
            return Err(ModelError::Admission);
        }
        self.prepared = Some(self.epoch);
        Ok(self.epoch)
    }
    /// Any subsequent observation expires the previous write ticket.
    pub(super) fn invalidate(&mut self) {
        self.epoch = self.epoch.saturating_add(1);
        self.prepared = None;
    }
    /// Consumes only the exact most recent prepared epoch, once.
    pub(super) fn authorize_write(&mut self, epoch: u64) -> Result<(), ModelError> {
        if self.edited || self.resumed {
            return Err(ModelError::State);
        }
        if self.prepared != Some(epoch) || self.epoch != epoch {
            return Err(ModelError::Epoch);
        }
        self.prepared = None;
        self.edited = true;
        Ok(())
    }
    /// Untreated baseline does not use this edited-child transition.
    pub(super) fn authorize_resume(&mut self, exact: bool, fresh: bool) -> Result<(), ModelError> {
        if !self.edited || self.resumed || !exact || !fresh {
            return Err(ModelError::State);
        }
        self.resumed = true;
        Ok(())
    }
}
/// Every exact comparison is kernel-observed; unavailable evidence is false admission.
pub(super) struct Isolation {
    pub(super) exact: bool,
    pub(super) addition: bool,
    pub(super) old_aces: bool,
    pub(super) denials: bool,
    pub(super) kept: [bool; 4],
    pub(super) same_instance: bool,
    pub(super) properties: bool,
    pub(super) default: bool,
    pub(super) process: bool,
    pub(super) thread: bool,
    pub(super) source: bool,
    pub(super) derived: bool,
}
/// Exact semantic isolation is conjunctive; no changed/unknown component is ignored.
pub(super) fn isolation(f: &Isolation) -> bool {
    f.exact
        && f.addition
        && f.old_aces
        && f.denials
        && f.kept.iter().all(|v| *v)
        && f.same_instance
        && f.properties
        && f.default
        && f.process
        && f.thread
        && f.source
        && f.derived
}
/// Full requested period plus 3s verified reap reserve is required; shorter timeouts prove nothing.
pub(super) fn wait_budget(remaining: u128, requested: u32) -> Option<u32> {
    if !(1..=10_000).contains(&requested) || remaining < requested as u128 + 3_000 {
        None
    } else {
        Some(requested)
    }
}
/// Cleanup state keeps deferred fixtures and blocks launches after any unresolved reap.
pub(super) struct CleanupPolicy {
    unreaped: bool,
    cleanup_failed: bool,
}
impl CleanupPolicy {
    /// Owns a newly returned child.
    pub(super) fn owned_child() -> Self {
        Self {
            unreaped: true,
            cleanup_failed: false,
        }
    }
    /// Only a verified held-handle termination wait releases fixture cleanup; failure remains launch-sticky.
    pub(super) fn record_reap(&mut self, verified: bool) {
        if verified {
            self.unreaped = false;
        } else {
            self.cleanup_failed = true;
        }
    }
    /// Deferred cleanup never invokes the deletion/pin-release closure while liveness is unknown.
    pub(super) fn cleanup_fixture<T>(&self, operation: impl FnOnce() -> T) -> Option<T> {
        if self.may_delete_or_release_fixture() {
            Some(operation())
        } else {
            None
        }
    }
    /// Unverified child liveness retains all fixture leases.
    pub(super) fn may_delete_or_release_fixture(&self) -> bool {
        !self.unreaped
    }
    /// An unresolved cleanup failure prohibits another launch even after a verified final retry.
    pub(super) fn may_launch(&self) -> bool {
        !self.unreaped && !self.cleanup_failed
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    /// Complete synthetic proof is distinct from actual kernel execution evidence.
    fn good() -> Admission {
        Admission {
            fresh: true,
            image: true,
            console: true,
            properties: true,
            identities_known: true,
            same_held: true,
            source_alias: false,
            derived_alias: false,
            epoch_fresh: true,
            remaining_ms: 19_000,
        }
    }
    /// Each missing prerequisite and either known alias refuses a write.
    #[test]
    fn unknown_or_alias_never_authorizes_write() {
        let mut rejected = Vec::new();
        for index in 0..10 {
            let mut facts = good();
            match index {
                0 => facts.fresh = false,
                1 => facts.image = false,
                2 => facts.console = false,
                3 => facts.properties = false,
                4 => facts.identities_known = false,
                5 => facts.same_held = false,
                6 => facts.source_alias = true,
                7 => facts.derived_alias = true,
                8 => facts.epoch_fresh = false,
                _ => facts.remaining_ms = 18_999,
            };
            rejected.push(ControlModel::suspended().prepare(facts).is_err());
        }
        assert!(rejected.iter().all(|value| *value));
    }
    /// A stale epoch and repeated mutation never reuse one admission.
    #[test]
    fn stale_and_duplicate_write_refused() {
        let mut model = ControlModel::suspended();
        let epoch = model.prepare(good()).unwrap_or_else(|_| panic!("prepare"));
        model.invalidate();
        assert!(model.authorize_write(epoch).is_err());
        let epoch = model.prepare(good()).unwrap_or_else(|_| panic!("prepare"));
        assert!(model.authorize_write(epoch).is_ok());
        assert!(model.authorize_write(epoch).is_err());
    }
    /// No edited-child resume without exact readback and last fresh proof; baseline uses a separate path.
    #[test]
    fn no_resume_without_isolation() {
        for (exact, fresh) in [(false, true), (true, false), (false, false)] {
            let mut model = ControlModel::suspended();
            let epoch = model.prepare(good()).unwrap_or_else(|_| panic!("prepare"));
            assert!(model.authorize_write(epoch).is_ok());
            assert!(model.authorize_resume(exact, fresh).is_err());
        }
        assert!(
            ControlModel::suspended()
                .authorize_resume(true, true)
                .is_err()
        );
    }
    /// Unverified termination preserves pins and forbids another creation even after a later verified retry.
    #[test]
    fn failed_reap_retains_fixtures() {
        let mut policy = CleanupPolicy::owned_child();
        policy.record_reap(false);
        assert!(!policy.may_delete_or_release_fixture());
        assert!(!policy.may_launch());
        policy.record_reap(false);
        let mut deletions = 0;
        let mut releases = 0;
        if policy.may_delete_or_release_fixture() {
            deletions += 1;
            releases += 1;
        }
        assert!(deletions == 0 && releases == 0);
        policy.record_reap(true);
        assert!(policy.may_delete_or_release_fixture());
        assert!(!policy.may_launch());
    }
    /// Constructor Err has uncertain ownership; cleanup closures and later creation must not run.
    #[test]
    fn uncertain_create_never_releases_or_launches() {
        let mut policy = CleanupPolicy::owned_child();
        let created: Result<(), ()> = Err(());
        assert!(created.is_err());
        let mut deleted = 0;
        let mut released = 0;
        let outcome = policy.cleanup_fixture(|| {
            deleted += 1;
            released += 1;
        });
        assert!(outcome.is_none() && deleted == 0 && released == 0 && !policy.may_launch());
        policy.record_reap(false);
        assert!(
            policy
                .cleanup_fixture(|| {
                    deleted += 1;
                })
                .is_none()
        );
        assert!(deleted == 0);
        let mut known = CleanupPolicy::owned_child();
        known.record_reap(true);
        assert!(
            known
                .cleanup_fixture(|| {
                    deleted += 1;
                    released += 1;
                })
                .is_some()
        );
        assert!(deleted == 1 && released == 1 && known.may_launch());
    }
    /// Each wrong/unknown original component/property prevents edited-child resume admission.
    #[test]
    fn every_readback_component_is_required() {
        for index in 0..15 {
            let mut facts = Isolation {
                exact: true,
                addition: true,
                old_aces: true,
                denials: true,
                kept: [true; 4],
                same_instance: true,
                properties: true,
                default: true,
                process: true,
                thread: true,
                source: true,
                derived: true,
            };
            match index {
                0 => facts.exact = false,
                1 => facts.addition = false,
                2 => facts.old_aces = false,
                3 => facts.denials = false,
                4..=7 => facts.kept[index - 4] = false,
                8 => facts.same_instance = false,
                9 => facts.properties = false,
                10 => facts.default = false,
                11 => facts.process = false,
                12 => facts.thread = false,
                13 => facts.source = false,
                _ => facts.derived = false,
            };
            assert!(!isolation(&facts));
        }
    }
    /// A timeout observation must cover the entire requested period plus held-handle reap reserve.
    #[test]
    fn wait_requires_whole_period() {
        assert!(wait_budget(3_100, 100) == Some(100));
        assert!(wait_budget(3_099, 100).is_none());
        assert!(wait_budget(13_000, 10_000) == Some(10_000));
        assert!(wait_budget(12_999, 10_000).is_none());
        assert!(wait_budget(50_000, 0).is_none());
        assert!(wait_budget(50_000, 10_001).is_none());
    }
}
