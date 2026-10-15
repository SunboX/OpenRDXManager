// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Optional matched debugger observation; completion never authorizes medium startup or Manager use.
use super::process_dacl_control::process_descriptor::Components;
use super::process_dacl_control::{PrivateDescriptor, source_default_dacl};
use super::*;
// Intentional private test-only reader reuse preserves the existing experiment's module/API bytes.
#[allow(clippy::duplicate_mod)]
#[path = "actual_token_context.rs"]
mod context;
#[path = "debugger_modules.rs"]
mod modules;
#[path = "debugger_output.rs"]
mod output;
#[path = "debugger_owner.rs"]
mod owner;
#[path = "debugger_protocol.rs"]
mod protocol;
// The fixed budget is reused without widening the original private write-admission module.
#[allow(clippy::duplicate_mod)]
#[path = "actual_token_protocol.rs"]
mod wait_protocol;
use context::{MinimalDerivedToken, SourceContext, TokenState};
use owner::DebugOwnedChild;
use protocol::Cleanup;
use std::time::{Duration, Instant};

/// One original global deadline shared by creation, natural observations and final cleanup.
struct Deadline(Instant);
impl Deadline {
    /// Starts before source and fixture preparation.
    fn new() -> Self {
        Self(Instant::now() + Duration::from_secs(90))
    }
    /// Local remaining budget never leaves this process.
    fn remaining(&self) -> u128 {
        self.0.saturating_duration_since(Instant::now()).as_millis()
    }
    /// Refuses each launch without the existing 19s wait/reap reserve.
    fn require_launch(&self) -> Result<(), NativeError> {
        if self.remaining() < 19_000 {
            Err(NativeError::TimedOut)
        } else {
            Ok(())
        }
    }
}
/// A first Result/IO failure survives every later independent cleanup operation.
fn checkpoint<T>(
    phase: &'static str,
    operation: impl FnOnce() -> Result<T, NativeError>,
) -> Result<T, NativeError> {
    output::clear_failure();
    output::stage(phase, "begin", None);
    let result = operation();
    let result = match result {
        Err(error) => Err(error),
        Ok(value) if !output::failed() => Ok(value),
        Ok(_) => Err(NativeError::Other),
    };
    match &result {
        Ok(_) => output::stage(phase, "ok", None),
        Err(error) => output::stage(phase, "failed", Some(error)),
    }
    match result {
        Err(error) => Err(error),
        Ok(value) if !output::failed() => Ok(value),
        Ok(_) => Err(NativeError::Other),
    }
}
/// Retains only the first cleanup error, independently of the primary experiment error.
fn retain_first(first: &mut Option<NativeError>, result: Result<(), NativeError>) {
    if let Err(error) = result {
        first.get_or_insert(error);
    }
}
/// One possible child and the exact retained fixture; no release until termination is proved.
struct State {
    deadline: Deadline,
    fixture: Option<Fixture>,
    baseline: Option<OwnedChild>,
    debug: Option<DebugOwnedChild>,
    cleanup: Option<Cleanup>,
    baseline_reap_seen: bool,
    reproduced: bool,
    changed: bool,
}
impl State {
    /// No setup ownership is inferred from merely entering the test.
    fn new() -> Self {
        Self {
            deadline: Deadline::new(),
            fixture: None,
            baseline: None,
            debug: None,
            cleanup: None,
            baseline_reap_seen: false,
            reproduced: false,
            changed: false,
        }
    }
    /// A new child always starts unresolved BEFORE its potentially successful SDK call.
    fn prepare_create(&mut self) -> Result<(), NativeError> {
        if self.baseline.is_some()
            || self.debug.is_some()
            || self.cleanup.as_ref().is_some_and(|c| !c.may_launch())
        {
            return Err(NativeError::Busy);
        }
        self.deadline.require_launch()?;
        self.cleanup = Some(Cleanup::uncertain_creation());
        Ok(())
    }
    /// Reaps only the retained untreated child; a constructor error never means known absence.
    fn reap_baseline(&mut self) -> Result<(), NativeError> {
        let result = match self.baseline.as_mut() {
            Some(child) => child.terminate_and_reap(),
            None => {
                if self.debug.is_none()
                    && self
                        .cleanup
                        .as_ref()
                        .is_some_and(|c| !c.may_release_fixture())
                {
                    Err(NativeError::Busy)
                } else {
                    Ok(())
                }
            }
        };
        if result.is_ok() {
            self.baseline.take();
            if self.debug.is_none() {
                if let Some(cleanup) = self.cleanup.as_mut() {
                    cleanup.verified_reap();
                }
            }
        }
        result
    }
    /// Event exit continuation and the held wait, not termination request, establish debug cleanup.
    fn reap_debug(&mut self) -> Result<(), NativeError> {
        let result = match self.debug.as_mut() {
            Some(child) => child.reap(&self.deadline),
            None => {
                if self
                    .cleanup
                    .as_ref()
                    .is_some_and(|c| !c.may_release_fixture())
                {
                    Err(NativeError::Busy)
                } else {
                    Ok(())
                }
            }
        };
        if result.is_ok() {
            self.debug.take();
            if let Some(cleanup) = self.cleanup.as_mut() {
                cleanup.verified_reap();
            }
        }
        result
    }
    /// No fixture deletion or lease release occurs while any possible child is unresolved.
    fn cleanup_fixture(&mut self) -> Result<(), NativeError> {
        if self.baseline.is_some() || self.debug.is_some() {
            return Err(NativeError::Busy);
        }
        let fixture = &mut self.fixture;
        let mut operation = || {
            if let Some(owned) = fixture.as_mut() {
                owned.cleanup()?;
            }
            fixture.take();
            Ok(())
        };
        match self.cleanup.as_ref() {
            Some(policy) => policy
                .cleanup_fixture(operation)
                .map_err(|_| NativeError::Busy)?,
            None => operation(),
        }
    }
}
impl Drop for State {
    /// Owned child cleanup precedes Fixture Drop; unresolved final cleanup retains exact pins/state.
    fn drop(&mut self) {
        let baseline = self.reap_baseline();
        let debug = self.reap_debug();
        if baseline.is_err()
            || debug.is_err()
            || self
                .cleanup
                .as_ref()
                .is_some_and(|c| !c.may_release_fixture())
        {
            if let Some(child) = self.baseline.take() {
                std::mem::forget(child);
            }
            if let Some(child) = self.debug.take() {
                std::mem::forget(child);
            }
            if let Some(fixture) = self.fixture.take() {
                std::mem::forget(fixture);
            }
        }
    }
}
/// Emits full properties only after exact immutable image, medium token and fresh console checks.
fn proof(
    child: &OwnedChild,
    fixture: &Fixture,
    source: &SourceContext,
    derived: &MinimalDerivedToken,
) -> Result<TokenState, NativeError> {
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
    if actual.snapshot != derived.observed()?.snapshot {
        return Err(NativeError::AccessDenied);
    }
    Ok(actual)
}
/// The same five fixed proof facts describe both subjects; unknowns never substitute for proof.
fn proof_facts(phase: &'static str) {
    output::facts(
        phase,
        &[
            ("image", true),
            ("properties", true),
            ("console", true),
            ("source-preserved", true),
            ("derived-preserved", true),
        ],
    );
}
/// Untreated baseline must reproduce the same exact failure before the new debugger flag is tried.
fn baseline(
    state: &mut State,
    source: &SourceContext,
    derived: &MinimalDerivedToken,
) -> Result<(), NativeError> {
    checkpoint("baseline-create", || {
        state.prepare_create()?;
        let result = OwnedChild::create(
            state.fixture.as_ref().ok_or(NativeError::Other)?,
            derived.launch_token(),
        );
        output::facts(
            "baseline-create",
            &[
                ("created", result.is_ok()),
                ("creation-uncertain", result.is_err()),
            ],
        );
        state.baseline = Some(result?);
        if let Some(cleanup) = state.cleanup.as_mut() {
            cleanup.returned_child();
        }
        Ok(())
    })?;
    let before = checkpoint("baseline-proof", || {
        let actual = proof(
            state.baseline.as_ref().ok_or(NativeError::Other)?,
            state.fixture.as_ref().ok_or(NativeError::Other)?,
            source,
            derived,
        )?;
        proof_facts("baseline-proof");
        Ok(actual)
    })?;
    checkpoint("baseline-resume", || {
        source.unchanged()?;
        derived.unchanged(source)?;
        let child = state.baseline.as_ref().ok_or(NativeError::Other)?;
        context::read_child(child)?.require_same(&before)?;
        state.deadline.require_launch()?;
        prove_child_quiet(
            child,
            state.fixture.as_ref().ok_or(NativeError::Other)?,
            &source.state.snapshot,
            &source.console,
            source.session,
        )?;
        child.resume()?;
        output::facts("baseline-resume", &[("fresh", true)]);
        Ok(())
    })?;
    checkpoint("baseline-wait", || {
        let requested = wait_protocol::wait_budget(state.deadline.remaining(), 10_000)
            .ok_or(NativeError::TimedOut)?;
        let matched = state
            .baseline
            .as_mut()
            .ok_or(NativeError::Other)?
            .wait(requested)?
            == Some(0xc000_0142);
        output::facts("baseline-wait", &[("dll-init-failed", matched)]);
        if !matched {
            return Err(NativeError::EvidenceIncomplete);
        }
        Ok(())
    })?;
    state.baseline_reap_seen = true;
    checkpoint("baseline-reap", || {
        let result = state.reap_baseline();
        output::facts(
            "baseline-reap",
            &[("verified", result.is_ok()), ("deferred", result.is_err())],
        );
        result
    })
}
/// The sole behavior difference is the private constructor's debug-only-this-process flag.
fn debug(
    state: &mut State,
    source: &SourceContext,
    derived: &MinimalDerivedToken,
) -> Result<(), NativeError> {
    checkpoint("debug-create", || {
        state.prepare_create()?;
        let result = DebugOwnedChild::create(
            state.fixture.as_ref().ok_or(NativeError::Other)?,
            derived,
            &state.deadline,
        );
        output::facts(
            "debug-create",
            &[
                ("created", result.is_ok()),
                ("creation-uncertain", result.is_err()),
            ],
        );
        state.debug = Some(result?);
        if let Some(cleanup) = state.cleanup.as_mut() {
            cleanup.returned_child();
        }
        Ok(())
    })?;
    checkpoint("debug-proof", || {
        state
            .debug
            .as_mut()
            .ok_or(NativeError::Other)?
            .capture_proof(
                state.fixture.as_ref().ok_or(NativeError::Other)?,
                source,
                derived,
            )?;
        proof_facts("debug-proof");
        Ok(())
    })?;
    checkpoint("debug-resume", || {
        state
            .debug
            .as_mut()
            .ok_or(NativeError::Other)?
            .prove_and_resume(
                state.fixture.as_ref().ok_or(NativeError::Other)?,
                source,
                derived,
            )?;
        output::facts("debug-resume", &[("fresh", true)]);
        Ok(())
    })?;
    let result = checkpoint("debug-events", || {
        state
            .debug
            .as_mut()
            .ok_or(NativeError::Other)?
            .run_events(&state.deadline)
    });
    if let Some(child) = state.debug.as_ref() {
        (state.reproduced, state.changed) = child.reproduction();
    }
    result
}
/// Independent preservation includes descriptors/default ACL and known primary TokenId, never raw identities.
fn preservation(
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
            ("properties", kept[0]),
            ("default-dacl", kept[1]),
            ("object-descriptor", kept[2]),
            ("instance-known", ids[0]),
            ("instance-equal", ids[1]),
        ],
    );
    observed.require_same(before)
}
/// Diagnostic completion requires reproduced failure and cleanup; it can NEVER establish startup success.
fn run_control() -> Result<(), NativeError> {
    output::start();
    let mut state = State::new();
    let mut source = None;
    let mut derived = None;
    let primary = (|| {
        checkpoint("setup", || {
            source = Some(SourceContext::capture()?);
            derived = Some(source.as_ref().ok_or(NativeError::Other)?.derive_medium()?);
            output::facts(
                "setup",
                &[
                    ("verified", true),
                    ("source-minimal", true),
                    ("derived-medium", true),
                ],
            );
            Ok(())
        })?;
        let source = source.as_ref().ok_or(NativeError::Other)?;
        let derived = derived.as_ref().ok_or(NativeError::Other)?;
        checkpoint("fixture", || {
            state.fixture = Some(Fixture::create(&source.user, Variant::Wait)?);
            output::facts("fixture", &[("protected", true)]);
            Ok(())
        })?;
        baseline(&mut state, source, derived)?;
        debug(&mut state, source, derived)
    })();
    let mut cleanup = None;
    if !state.baseline_reap_seen {
        state.baseline_reap_seen = true;
        retain_first(
            &mut cleanup,
            checkpoint("baseline-reap", || {
                let result = state.reap_baseline();
                output::facts(
                    "baseline-reap",
                    &[("verified", result.is_ok()), ("deferred", result.is_err())],
                );
                result
            }),
        );
    }
    retain_first(
        &mut cleanup,
        checkpoint("debug-reap", || {
            let result = state.reap_debug();
            output::facts(
                "debug-reap",
                &[("verified", result.is_ok()), ("deferred", result.is_err())],
            );
            result
        }),
    );
    retain_first(
        &mut cleanup,
        checkpoint("fixture-cleanup", || {
            let result = state.cleanup_fixture();
            output::facts(
                "fixture-cleanup",
                &[
                    ("verified", result.is_ok()),
                    ("deferred", matches!(result, Err(NativeError::Busy))),
                ],
            );
            result
        }),
    );
    retain_first(
        &mut cleanup,
        checkpoint("source-check", || {
            preservation(
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
            preservation(
                "derived-check",
                derived
                    .as_ref()
                    .ok_or(NativeError::EvidenceIncomplete)
                    .and_then(MinimalDerivedToken::observed),
                derived.as_ref().map(|s| &s.state),
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
                ("reproduced", state.reproduced),
                ("debugger-changed-behavior", state.changed),
                ("startup-proof", false),
            ],
        );
        result
    })
}
/// Optional ignored experiment cannot override original ordinary-medium startup or production authorization.
#[test]
#[ignore = "requires administrator on a disposable Windows verifier"]
fn native_owned_medium_debugger_control() {
    assert!(run_control().is_ok(), "debugger-control-failed");
}
