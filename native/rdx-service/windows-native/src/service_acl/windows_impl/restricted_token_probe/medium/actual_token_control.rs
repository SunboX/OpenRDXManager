// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Standalone opt-in actual owned token-object treatment, never ordinary authorization.
use super::process_dacl_control::process_descriptor::{Components, ObjectRole, token_acl_profile};
use super::process_dacl_control::{PrivateDescriptor, source_default_dacl};
use super::*;
#[path = "actual_token_context.rs"]
mod context;
#[path = "actual_token_output.rs"]
mod output;
#[path = "actual_token_owner.rs"]
mod owner;
#[path = "actual_token_protocol.rs"]
mod protocol;
use context::{MinimalDerivedToken, SourceContext, TokenState};
use owner::OwnedActualChildToken;
use protocol::{Admission, CleanupPolicy, ControlModel};
use std::time::{Duration, Instant};
use windows::Win32::Security::TOKEN_ALL_ACCESS;

/// Two treatment subjects share mechanics only; no caller-provided targets/rights.
#[derive(Clone, Copy)]
enum Subject {
    Treatment,
    Positive,
}
impl Subject {
    /// Exact compiled phase name for this subject's operation.
    fn phase(self, operation: &str) -> &'static str {
        match (self, operation) {
            (Self::Treatment, "create") => "treatment-create",
            (Self::Treatment, "observe") => "treatment-observe",
            (Self::Treatment, "write") => "treatment-write",
            (Self::Treatment, "readback") => "treatment-readback",
            (Self::Treatment, "resume") => "treatment-resume",
            (Self::Treatment, "wait") => "treatment-wait",
            (Self::Treatment, "reap") => "treatment-reap",
            (Self::Positive, "create") => "positive-create",
            (Self::Positive, "observe") => "positive-observe",
            (Self::Positive, "write") => "positive-write",
            (Self::Positive, "readback") => "positive-readback",
            (Self::Positive, "resume") => "positive-resume",
            (Self::Positive, "wait") => "positive-wait",
            (Self::Positive, "reap") => "positive-reap",
            _ => panic!("actual-token-phase"),
        }
    }
}
/// Identical native global budget and launch/reap reserve; never extends the outer wrapper.
struct Deadline(Instant);
impl Deadline {
    /// Starts before source/setup observations.
    fn new() -> Self {
        Self(Instant::now() + Duration::from_secs(90))
    }
    /// Returns only local budget, never output.
    fn remaining(&self) -> u128 {
        self.0.saturating_duration_since(Instant::now()).as_millis()
    }
    /// Reserves existing 10s wait plus three bounded 3s cleanup attempts.
    fn require_launch(&self) -> Result<(), NativeError> {
        if self.remaining() < 19_000 {
            return Err(NativeError::TimedOut);
        }
        Ok(())
    }
    /// Limits a wait without consuming the last 3s owned reap reserve.
    fn wait_ms(&self, requested: u32) -> Result<u32, NativeError> {
        protocol::wait_budget(self.remaining(), requested).ok_or(NativeError::TimedOut)
    }
}
/// Private fixed transition, original result cannot be masked by cleanup.
fn checkpoint<T>(
    phase: &'static str,
    operation: impl FnOnce() -> Result<T, NativeError>,
) -> Result<T, NativeError> {
    assert!(output::PHASES.contains(&phase), "actual-token-phase");
    output::clear_failure();
    output::stage(phase, "begin", None);
    let result = operation();
    let result = match result {
        Err(error) => Err(error),
        Ok(value) => {
            if output::failed() {
                Err(NativeError::Other)
            } else {
                Ok(value)
            }
        }
    };
    match &result {
        Ok(_) => output::stage(phase, "ok", None),
        Err(error) => output::stage(phase, "failed", Some(error)),
    };
    // Every cleanup still executes when stdout fails. Original native Result has precedence over IO.
    match result {
        Err(error) => Err(error),
        Ok(value) => {
            if output::failed() {
                Err(NativeError::Other)
            } else {
                Ok(value)
            }
        }
    }
}
/// Owns one possible child and both leases; unresolved child liveness suppresses Fixture Drop.
struct State {
    child: Option<OwnedChild>,
    wait: Option<Fixture>,
    proof: Option<Fixture>,
    policy: Option<CleanupPolicy>,
}
impl State {
    /// Empty setup has no child or fixture whose liveness could be unresolved.
    fn new() -> Self {
        Self {
            child: None,
            wait: None,
            proof: None,
            policy: None,
        }
    }
    /// Borrows the fixed live returned child only.
    fn child(&self) -> Result<&OwnedChild, NativeError> {
        self.child.as_ref().ok_or(NativeError::Other)
    }
    /// A previous failed reap blocks new launches permanently, even after a later final retry.
    fn create(
        &mut self,
        derived: &MinimalDerivedToken,
        subject: Option<Subject>,
        deadline: &Deadline,
    ) -> Result<(), NativeError> {
        if self.child.is_some() || self.policy.as_ref().is_some_and(|p| !p.may_launch()) {
            return Err(NativeError::Busy);
        }
        deadline.require_launch()?;
        let fixture = if matches!(subject, Some(Subject::Positive)) {
            self.proof.as_ref()
        } else {
            self.wait.as_ref()
        }
        .ok_or(NativeError::Other)?;
        // Conservative ownership starts before the existing constructor: Err may hide post-success PID/Drop failure.
        self.policy = Some(CleanupPolicy::owned_child());
        self.child = Some(OwnedChild::create(fixture, derived.launch_token())?);
        Ok(())
    }
    /// Constructor failure may hide guarded post-success cleanup; report that uncertainty explicitly.
    fn creation_uncertain(&self) -> bool {
        self.child.is_none()
            && self
                .policy
                .as_ref()
                .is_some_and(|p| !p.may_delete_or_release_fixture())
    }
    /// Only successful held-handle termination WAIT makes cleanup/release eligible.
    fn reap_owned_child(&mut self) -> Result<(), NativeError> {
        let result = match self.child.as_mut() {
            Some(child) => child.terminate_and_reap(),
            None => {
                if self
                    .policy
                    .as_ref()
                    .is_some_and(|p| !p.may_delete_or_release_fixture())
                {
                    Err(NativeError::Busy)
                } else {
                    Ok(())
                }
            }
        };
        if let Some(policy) = self.policy.as_mut() {
            policy.record_reap(result.is_ok());
        }
        if result.is_ok() {
            self.child.take();
        }
        result
    }
    /// Defers all fixture operations while a possible owned child has unverified termination.
    fn cleanup_fixture(&mut self, positive: bool) -> Result<(), NativeError> {
        let fixture = if positive {
            &mut self.proof
        } else {
            &mut self.wait
        };
        let mut cleanup = || {
            if let Some(owned) = fixture.as_mut() {
                owned.cleanup()?;
            }
            fixture.take();
            Ok(())
        };
        match self.policy.as_ref() {
            Some(policy) => policy
                .cleanup_fixture(cleanup)
                .unwrap_or(Err(NativeError::Busy)),
            None => cleanup(),
        }
    }
}
impl Drop for State {
    /// Retry child FIRST; unresolved termination deliberately retains exact handles/fixture pins, never deletes.
    fn drop(&mut self) {
        if self.reap_owned_child().is_err() {
            if let Some(child) = self.child.take() {
                std::mem::forget(child);
            }
            if let Some(fixture) = self.proof.take() {
                std::mem::forget(fixture);
            }
            if let Some(fixture) = self.wait.take() {
                std::mem::forget(fixture);
            }
        }
        // On verified termination normal field Drop may safely retry owned fixture cleanup.
    }
}
/// Retains original failure and attempts every independent cleanup/source/derived observation.
fn retain_first(first: &mut Option<NativeError>, result: Result<(), NativeError>) {
    if let Err(error) = result {
        first.get_or_insert(error);
    }
}
/// Fresh untreated proof uses a separate resume path, never the edited-child state machine.
fn baseline(
    state: &mut State,
    source: &SourceContext,
    derived: &MinimalDerivedToken,
    deadline: &Deadline,
) -> Result<(), NativeError> {
    checkpoint("baseline-create", || {
        let result = state.create(derived, None, deadline);
        output::facts(
            "baseline-create",
            &[
                ("created", result.is_ok()),
                ("creation-uncertain", state.creation_uncertain()),
            ],
        );
        result
    })?;
    let baseline_state = checkpoint("baseline-proof", || {
        let child = state.child()?;
        let fixture = state.wait.as_ref().ok_or(NativeError::Other)?;
        source.unchanged()?;
        derived.unchanged(source)?;
        prove_child_quiet(
            child,
            fixture,
            &source.state.snapshot,
            &source.console,
            source.session,
        )?;
        let actual = context::read_child(child)?;
        let expected = actual
            .descriptor
            .with_user_allow(source.user.bytes(), ObjectRole::Token)
            .map_err(|_| NativeError::Other)?;
        let profile = token_acl_profile::observe(
            &actual.descriptor,
            &actual.descriptor,
            &expected,
            source.user.bytes(),
        )
        .map_err(|_| NativeError::Other)?;
        let source_id = actual.identity(&source.state);
        let derived_id = actual.identity(&derived.state);
        let same = actual.snapshot == derived.observed()?.snapshot;
        output::facts(
            "baseline-proof",
            &[
                ("query-ok", true),
                ("image-proved", true),
                ("properties-equal", same),
                ("grant-absent", profile.grants[0][0]),
                ("identity-known", source_id[0] && derived_id[0]),
                ("actual-source-distinct", source_id[0] && !source_id[1]),
                ("actual-derived-distinct", derived_id[0] && !derived_id[1]),
                ("source-unchanged", source.unchanged().is_ok()),
                ("derived-unchanged", derived.unchanged(source).is_ok()),
            ],
        );
        if !(same
            && profile.grants[0][0]
            && source_id[0]
            && derived_id[0]
            && !source_id[1]
            && !derived_id[1])
        {
            return Err(NativeError::EvidenceIncomplete);
        }
        Ok((
            actual,
            PrivateDescriptor::read(child.process.0)?.components,
            PrivateDescriptor::read(child.thread.0)?.components,
        ))
    })?;
    checkpoint("baseline-resume", || {
        source.unchanged()?;
        derived.unchanged(source)?;
        context::read_child(state.child()?)?.require_same(&baseline_state.0)?;
        if PrivateDescriptor::read(state.child()?.process.0)?.components != baseline_state.1
            || PrivateDescriptor::read(state.child()?.thread.0)?.components != baseline_state.2
        {
            return Err(NativeError::AccessDenied);
        }
        deadline.require_launch()?;
        prove_child_quiet(
            state.child()?,
            state.wait.as_ref().ok_or(NativeError::Other)?,
            &source.state.snapshot,
            &source.console,
            source.session,
        )?;
        state.child()?.resume()?;
        output::facts("baseline-resume", &[("fresh-proof", true)]);
        Ok(())
    })?;
    checkpoint("baseline-wait", || {
        let exit = state
            .child
            .as_mut()
            .ok_or(NativeError::Other)?
            .wait(deadline.wait_ms(10_000)?)?;
        output::exit(
            "baseline-wait",
            exit.map(exit_status::category).unwrap_or("alive"),
        );
        let matched = exit == Some(0xc000_0142);
        output::facts("baseline-wait", &[("dll-init-failed", matched)]);
        if !matched {
            return Err(NativeError::EvidenceIncomplete);
        }
        Ok(())
    })?;
    checkpoint("baseline-reap", || {
        let result = state.reap_owned_child();
        output::facts("baseline-reap", &[("verified", result.is_ok())]);
        result?;
        source.unchanged()?;
        derived.unchanged(source)
    })
}
/// Treatment and positive subjects retain exactly the original constructor/options and independently owned tokens.
fn treatment(
    state: &mut State,
    source: &SourceContext,
    derived: &MinimalDerivedToken,
    deadline: &Deadline,
    subject: Subject,
) -> Result<(), NativeError> {
    checkpoint(subject.phase("create"), || {
        let result = state.create(derived, Some(subject), deadline);
        output::facts(
            subject.phase("create"),
            &[
                ("created", result.is_ok()),
                ("creation-uncertain", state.creation_uncertain()),
            ],
        );
        result
    })?;
    {
        let fixture = if matches!(subject, Subject::Positive) {
            state.proof.as_ref()
        } else {
            state.wait.as_ref()
        }
        .ok_or(NativeError::Other)?;
        let mut token = checkpoint(subject.phase("observe"), || {
            OwnedActualChildToken::observe(
                state.child()?,
                fixture,
                source,
                derived,
                deadline,
                subject,
            )
        })?;
        checkpoint(subject.phase("write"), || token.add_fixed_user_allow())?;
        checkpoint(subject.phase("readback"), || token.require_exact_readback())?;
        checkpoint(subject.phase("resume"), || {
            token.resume_verified()?;
            output::facts(
                subject.phase("resume"),
                &[("fresh-proof", true), ("resumed", true)],
            );
            Ok(())
        })?;
    }
    checkpoint(subject.phase("wait"), || {
        let requested = if matches!(subject, Subject::Positive) {
            10_000
        } else {
            100
        };
        let exit = state
            .child
            .as_mut()
            .ok_or(NativeError::Other)?
            .wait(deadline.wait_ms(requested)?)?;
        output::exit(
            subject.phase("wait"),
            exit.map(exit_status::category).unwrap_or("alive"),
        );
        let passed = if matches!(subject, Subject::Positive) {
            exit == Some(0)
        } else {
            exit.is_none()
        };
        output::facts(
            subject.phase("wait"),
            &[(
                if matches!(subject, Subject::Positive) {
                    "exit-zero"
                } else {
                    "timeout-alive"
                },
                passed,
            )],
        );
        if !passed {
            return Err(NativeError::EvidenceIncomplete);
        }
        Ok(())
    })?;
    checkpoint(subject.phase("reap"), || {
        let result = state.reap_owned_child();
        output::facts(subject.phase("reap"), &[("verified", result.is_ok())]);
        result?;
        source.unchanged()?;
        derived.unchanged(source)
    })
}
/// Final equality snapshots are independent even after another observation failed.
fn unchanged(
    phase: &'static str,
    observed: Result<TokenState, NativeError>,
    before: Option<&TokenState>,
) -> Result<(), NativeError> {
    output::facts(phase, &[("query-ok", observed.is_ok() && before.is_some())]);
    let observed = observed?;
    let before = before.ok_or(NativeError::EvidenceIncomplete)?;
    let kept = observed.preservation(before);
    let ids = observed.identity(before);
    output::facts(
        phase,
        &[
            ("properties-equal", kept[0]),
            ("default-dacl-equal", kept[1]),
            ("descriptor-equal", kept[2]),
            ("instance-known", ids[0]),
            ("instance-equal", ids[1]),
            ("logon-equal", ids[2]),
            ("modified-equal", ids[3]),
        ],
    );
    observed.require_same(before)
}
/// Fixed sequential control, no successful completion without independent zero-exit/cleanup proof.
fn run_control() -> Result<(), NativeError> {
    let deadline = Deadline::new();
    let mut state = State::new();
    let mut source = None;
    let mut derived = None;
    let primary = (|| {
        source = Some(checkpoint("setup", || {
            let context = SourceContext::capture()?;
            output::facts("setup", &[("verified", true)]);
            Ok(context)
        })?);
        let source = source.as_ref().ok_or(NativeError::Other)?;
        derived = Some(checkpoint("derive", || {
            let token = source.derive_medium()?;
            output::facts(
                "derive",
                &[
                    ("reduced-proved", true),
                    ("source-handle-exact", true),
                    ("source-minimal-rights", true),
                ],
            );
            Ok(token)
        })?);
        let derived = derived.as_ref().ok_or(NativeError::Other)?;
        checkpoint("fixtures", || {
            state.wait = Some(Fixture::create(&source.user, Variant::Wait)?);
            state.proof = Some(Fixture::create(&source.user, Variant::Proof)?);
            output::facts("fixtures", &[("protected", true)]);
            Ok(())
        })?;
        baseline(&mut state, source, derived, &deadline)?;
        treatment(&mut state, source, derived, &deadline, Subject::Treatment)?;
        treatment(&mut state, source, derived, &deadline, Subject::Positive)
    })();
    let mut cleanup = None;
    retain_first(
        &mut cleanup,
        checkpoint("child-cleanup", || {
            let result = state.reap_owned_child();
            output::facts(
                "child-cleanup",
                &[("verified", result.is_ok()), ("deferred", result.is_err())],
            );
            result
        }),
    );
    for (phase, positive) in [("proof-cleanup", true), ("wait-cleanup", false)] {
        retain_first(
            &mut cleanup,
            checkpoint(phase, || {
                let result = state.cleanup_fixture(positive);
                output::facts(
                    phase,
                    &[
                        ("verified", result.is_ok()),
                        ("deferred", matches!(result, Err(NativeError::Busy))),
                    ],
                );
                result
            }),
        );
    }
    retain_first(
        &mut cleanup,
        checkpoint("source-check", || {
            unchanged(
                "source-check",
                source
                    .as_ref()
                    .ok_or(NativeError::EvidenceIncomplete)
                    .and_then(SourceContext::observed),
                source.as_ref().map(|s| &s.state),
            )
        }),
    );
    retain_first(
        &mut cleanup,
        checkpoint("derived-check", || {
            unchanged(
                "derived-check",
                derived
                    .as_ref()
                    .ok_or(NativeError::EvidenceIncomplete)
                    .and_then(MinimalDerivedToken::observed),
                derived.as_ref().map(|d| &d.state),
            )
        }),
    );
    let result = match primary {
        Err(error) => Err(error),
        Ok(()) => cleanup.map_or(Ok(()), Err),
    };
    checkpoint("complete", || {
        output::facts(
            "complete",
            &[
                ("experiment-complete", result.is_ok()),
                ("startup-proof", result.is_ok()),
            ],
        );
        result
    })
}
/// Opt-in fixed test cannot clear ordinary medium-child admission or authorize production integration.
#[test]
#[ignore = "requires administrator on a disposable Windows verifier"]
fn native_actual_child_token_dacl_control() {
    assert!(run_control().is_ok(), "actual-token-control-failed");
}
