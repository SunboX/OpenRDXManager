// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Fixed ordinary-source harmless child experiment, never production Manager or LocalService authority.
use super::manager_source_context::{DonorLease, OrdinaryCopy};
use super::manager_source_output as output;
use super::manager_source_protocol::{self as policy, LifeError, Lifecycle};
use super::token_statistics::Statistics;
use super::*;
use std::io::Write;

/// Emits only a validated bounded static-vocabulary line; write failure never becomes success.
fn emit(line: Result<String, ()>) -> Result<(), NativeError> {
    std::io::stdout()
        .lock()
        .write_all(line.map_err(|_| NativeError::Other)?.as_bytes())
        .map_err(|_| NativeError::Other)
}
/// Forward phase stops before its operation if the initial marker could not be written.
fn checkpoint<T>(
    phase: &'static str,
    operation: impl FnOnce() -> Result<T, NativeError>,
) -> Result<T, NativeError> {
    emit(output::stage(phase, "begin", None))?;
    let result = operation();
    let reason = result.as_ref().err().map(|error| format!("{error:?}"));
    let terminal = emit(output::stage(
        phase,
        if result.is_ok() { "ok" } else { "failed" },
        reason.as_deref(),
    ));
    let value = result?;
    terminal?;
    Ok(value)
}
/// Independent cleanup still executes when its marker fails, and never replaces an earlier primary error.
fn cleanup_checkpoint(
    phase: &'static str,
    operation: impl FnOnce() -> Result<(), NativeError>,
) -> Result<(), NativeError> {
    let begin = emit(output::stage(phase, "begin", None));
    let result = operation();
    let reason = result.as_ref().err().map(|error| format!("{error:?}"));
    let terminal = emit(output::stage(
        phase,
        if result.is_ok() { "ok" } else { "failed" },
        reason.as_deref(),
    ));
    policy::preservation_result([begin, result, terminal])
}
/// Converts only pure lifecycle outcomes, without raw SDK or identity data.
fn lifecycle(error: LifeError) -> NativeError {
    match error {
        LifeError::Busy => NativeError::Busy,
        LifeError::State => NativeError::AccessDenied,
        LifeError::TimedOut => NativeError::TimedOut,
    }
}
/// Two compiled fixture roles only; no arbitrary command, executable or token selector.
#[derive(Clone, Copy)]
enum Subject {
    Wait,
    Proof,
}
impl Subject {
    /// Exact finite phase selection, including observation semantics for each fixed PE.
    fn phase(self, operation: &str) -> &'static str {
        match (self, operation) {
            (Self::Wait, "create") => "wait-create",
            (Self::Wait, "proof") => "wait-proof",
            (Self::Wait, "resume") => "wait-resume",
            (Self::Wait, "wait") => "wait-observe",
            (Self::Wait, "reap") => "wait-reap",
            (Self::Proof, "create") => "proof-create",
            (Self::Proof, "proof") => "proof-proof",
            (Self::Proof, "resume") => "proof-resume",
            (Self::Proof, "wait") => "proof-exit",
            (Self::Proof, "reap") => "proof-reap",
            _ => unreachable!("manager-source-fixed-phase"),
        }
    }
}
/// Exact ownership order: child termination is established before any fixture/pin is released.
struct Owner {
    child: Option<OwnedChild>,
    actual: Option<Statistics>,
    wait: Option<Fixture>,
    proof: Option<Fixture>,
    life: Lifecycle,
}
impl Owner {
    /// Empty setup has no possible child; fixture cleanup is initially safe.
    fn new() -> Self {
        Self {
            child: None,
            actual: None,
            wait: None,
            proof: None,
            life: Lifecycle::new(),
        }
    }
    /// Borrows only one of two fixed privately owned staged images.
    fn fixture(&self, subject: Subject) -> Result<&Fixture, NativeError> {
        match subject {
            Subject::Wait => self.wait.as_ref(),
            Subject::Proof => self.proof.as_ref(),
        }
        .ok_or(NativeError::Other)
    }
    /// Conservative uncertainty precedes the unchanged factory, including its guarded Err paths.
    fn create(
        &mut self,
        subject: Subject,
        donor: &mut DonorLease,
        copy: &OrdinaryCopy,
    ) -> Result<(), NativeError> {
        if self.child.is_some() || !self.life.may_launch() {
            return Err(NativeError::Busy);
        }
        policy::preservation_result([donor.quiet_fresh(), copy.quiet_unchanged()])?;
        let fixture = match subject {
            Subject::Wait => self.wait.as_ref(),
            Subject::Proof => self.proof.as_ref(),
        }
        .ok_or(NativeError::Other)?;
        self.life
            .begin_creation(donor.remaining_ms())
            .map_err(lifecycle)?;
        let created = OwnedChild::create(fixture, copy.launch_token());
        self.life.record_creation(created.is_ok());
        self.child = Some(created?);
        self.actual = None;
        Ok(())
    }
    /// Only the actual token of the retained returned process is queried, with TOKEN_QUERY only.
    fn token(&self) -> Result<OwnedHandle, NativeError> {
        let child = self.child.as_ref().ok_or(NativeError::Other)?;
        let mut raw = HANDLE::default();
        // SAFETY: factory-owned child remains retained; no read-control/setter/impersonation rights added.
        unsafe { OpenProcessToken(child.process.0, TOKEN_QUERY, &mut raw) }
            .map_err(map_native_error)?;
        Ok(OwnedHandle(raw))
    }
    /// Bounded per-property booleans precede a strict full-property assertion; unknown is not inequality.
    fn prove(
        &mut self,
        subject: Subject,
        donor: &mut DonorLease,
        copy: &OrdinaryCopy,
    ) -> Result<(), NativeError> {
        policy::preservation_result([donor.quiet_fresh(), copy.quiet_unchanged()])?;
        let child = self.child.as_ref().ok_or(NativeError::Other)?;
        prove_image(child, self.fixture(subject)?)?;
        let token = self.token()?;
        let values = policy::after_report(copy.actual_properties(&token, donor), |known| {
            emit(output::facts(
                subject.phase("proof"),
                &[("query-ok", known), ("image", true)],
            ))
        })?;
        let keys = [
            "user-equal",
            "session-equal",
            "elevation-equal",
            "integrity-equal",
            "ui-access-equal",
            "sandbox-inert-equal",
            "primary-equal",
            "elevation-type-equal",
            "groups-equal",
            "privileges-equal",
            "default-dacl-equal",
            "no-enabled-admins",
            "donor-properties-equal",
        ];
        policy::after_report(
            values
                .iter()
                .all(|value| *value)
                .then_some(())
                .ok_or(NativeError::EvidenceIncomplete),
            |_| {
                emit(output::facts(
                    subject.phase("proof"),
                    &keys.into_iter().zip(values).collect::<Vec<_>>(),
                ))
            },
        )?;
        let actual = Statistics::read(&token);
        let known = actual.query_ok && actual.layout_valid;
        policy::after_report(
            known.then_some(()).ok_or(NativeError::EvidenceIncomplete),
            |_| {
                emit(output::facts(
                    subject.phase("proof"),
                    &[("instance-known", known)],
                ))
            },
        )?;
        donor.console_current()?;
        self.actual = Some(actual);
        Ok(())
    }
    /// Fresh proof and Resume are one private transaction, without later metadata/output callbacks.
    fn resume_verified(
        &mut self,
        subject: Subject,
        donor: &mut DonorLease,
        copy: &OrdinaryCopy,
    ) -> Result<(), NativeError> {
        policy::preservation_result([donor.quiet_fresh(), copy.quiet_unchanged()])?;
        let child = self.child.as_ref().ok_or(NativeError::Other)?;
        prove_image(child, self.fixture(subject)?)?;
        let token = self.token()?;
        let properties = copy.actual_properties(&token, donor)?;
        let current = Statistics::read(&token);
        let original = self.actual.ok_or(NativeError::EvidenceIncomplete)?;
        let identity = current.compare(original);
        if !identity[0] || !identity[1] || !identity[2] || !properties.iter().all(|value| *value) {
            return Err(NativeError::EvidenceIncomplete);
        }
        donor.console_current()?;
        // Budget is part of final admission, not an optional observer: reserve the entire fixed wait/reap.
        policy::wait_budget(
            donor.remaining_ms(),
            if matches!(subject, Subject::Wait) {
                100
            } else {
                10_000
            },
        )
        .ok_or(NativeError::TimedOut)?;
        self.life.admit_resume(true).map_err(lifecycle)?;
        // The query token stays retained until after Resume; no intervening optional observer/output.
        child.resume()
    }
    /// WAIT success on the held owned process is the only positive reap proof.
    fn reap(&mut self) -> Result<(), NativeError> {
        let result = match self.child.as_mut() {
            Some(child) => child.terminate_and_reap(),
            None => {
                if self.life.unresolved() {
                    Err(NativeError::Busy)
                } else {
                    Ok(())
                }
            }
        };
        self.life.record_reap(result.is_ok());
        if result.is_ok() {
            self.child.take();
            self.actual = None;
        }
        result
    }
    /// No deletion/release callback runs while creation or termination remains unresolved.
    fn cleanup_fixture(&mut self, subject: Subject) -> Result<(), NativeError> {
        let fixture = match subject {
            Subject::Wait => &mut self.wait,
            Subject::Proof => &mut self.proof,
        };
        self.life
            .cleanup_fixture(|| {
                if let Some(fixture) = fixture.as_mut() {
                    fixture.cleanup()?;
                }
                fixture.take();
                Ok(())
            })
            .unwrap_or(Err(NativeError::Busy))
    }
}
impl Drop for Owner {
    /// Final retry reaps first; unresolved termination preserves exact private fixtures and handle leases.
    fn drop(&mut self) {
        if self.reap().is_err() {
            if let Some(child) = self.child.take() {
                std::mem::forget(child);
            }
            if let Some(fixture) = self.wait.take() {
                std::mem::forget(fixture);
            }
            if let Some(fixture) = self.proof.take() {
                std::mem::forget(fixture);
            }
        }
    }
}
/// Two sequential fixed children; full-duration survival and independent zero exit are distinct proofs.
fn run_subject(
    owner: &mut Owner,
    subject: Subject,
    donor: &mut DonorLease,
    copy: &OrdinaryCopy,
) -> Result<(), NativeError> {
    checkpoint(subject.phase("create"), || {
        let created = owner.create(subject, donor, copy);
        policy::after_report(created, |_| {
            emit(output::facts(
                subject.phase("create"),
                &[
                    ("created", owner.child.is_some()),
                    (
                        "creation-uncertain",
                        owner.child.is_none() && owner.life.unresolved(),
                    ),
                ],
            ))
        })
    })?;
    checkpoint(subject.phase("proof"), || owner.prove(subject, donor, copy))?;
    checkpoint(subject.phase("resume"), || {
        owner.resume_verified(subject, donor, copy)?;
        emit(output::facts(subject.phase("resume"), &[("fresh", true)]))
    })?;
    checkpoint(subject.phase("wait"), || {
        let requested = if matches!(subject, Subject::Wait) {
            100
        } else {
            10_000
        };
        let wait =
            policy::wait_budget(donor.remaining_ms(), requested).ok_or(NativeError::TimedOut)?;
        let exit = owner.child.as_mut().ok_or(NativeError::Other)?.wait(wait)?;
        let passed = if matches!(subject, Subject::Wait) {
            exit.is_none()
        } else {
            exit == Some(0)
        };
        policy::after_report(
            passed.then_some(()).ok_or(NativeError::EvidenceIncomplete),
            |_| {
                policy::preservation_result([
                    emit(output::exit(
                        subject.phase("wait"),
                        exit.map(exit_status::category).unwrap_or("alive"),
                    )),
                    emit(output::facts(
                        subject.phase("wait"),
                        &[(
                            if matches!(subject, Subject::Wait) {
                                "timeout-alive"
                            } else {
                                "exit-zero"
                            },
                            passed,
                        )],
                    )),
                ])
            },
        )
    })?;
    checkpoint(subject.phase("reap"), || {
        let result = owner.reap();
        policy::after_report(result, |verified| {
            emit(output::facts(
                subject.phase("reap"),
                &[
                    ("verified", verified),
                    ("deferred", owner.life.unresolved()),
                ],
            ))
        })?;
        policy::preservation_result([donor.quiet_fresh(), copy.quiet_unchanged()])
    })
}
/// Preserves the original failure while retaining every independent cleanup/preservation result.
fn retain(first: &mut Option<NativeError>, result: Result<(), NativeError>) {
    if let Err(error) = result {
        first.get_or_insert(error);
    }
}
/// Executes no source selection, path, account or worker operation supplied by a caller.
fn run_manager_source_proof() -> Result<(), NativeError> {
    let mut owner = Owner::new();
    let mut donor = None;
    let mut copy = None;
    let primary = (|| {
        donor = Some(checkpoint("donor-proof", || {
            let donor = DonorLease::acquire_fixed()?;
            emit(output::facts(
                "donor-proof",
                &[
                    ("available", true),
                    ("enrolled", true),
                    ("image", true),
                    ("ordinary-medium", true),
                    ("caller-user-equal", donor.caller_user_equal()),
                    ("mapped-generation-known", false),
                ],
            ))?;
            Ok(donor)
        })?);
        let donor = donor.as_mut().ok_or(NativeError::Other)?;
        copy = Some(checkpoint("duplicate", || {
            let copy = donor.duplicate_primary()?;
            emit(output::facts("duplicate", &[("copy-distinct", true)]))?;
            Ok(copy)
        })?);
        let copy = copy.as_ref().ok_or(NativeError::Other)?;
        checkpoint("copy-proof", || {
            policy::preservation_result([donor.quiet_fresh(), copy.quiet_unchanged()])?;
            emit(output::facts(
                "copy-proof",
                &[
                    ("properties-equal", true),
                    ("default-dacl-equal", true),
                    ("descriptor-equal", true),
                ],
            ))
        })?;
        checkpoint("fixtures", || {
            let caller = donor.caller_sid()?;
            owner.wait = Some(Fixture::create(&caller, Variant::Wait)?);
            owner.proof = Some(Fixture::create(&caller, Variant::Proof)?);
            emit(output::facts(
                "fixtures",
                &[("protected", true), ("caller-owned", true)],
            ))
        })?;
        run_subject(&mut owner, Subject::Wait, donor, copy)?;
        run_subject(&mut owner, Subject::Proof, donor, copy)
    })();
    if primary.is_err() {
        owner.life.block();
    }
    let mut failure = primary.err();
    retain(
        &mut failure,
        cleanup_checkpoint("child-cleanup", || {
            let result = owner.reap();
            let reported = emit(output::facts(
                "child-cleanup",
                &[
                    ("verified", result.is_ok()),
                    ("deferred", owner.life.unresolved()),
                ],
            ));
            policy::preservation_result([result, reported])
        }),
    );
    for (phase, subject) in [
        ("wait-cleanup", Subject::Wait),
        ("proof-cleanup", Subject::Proof),
    ] {
        retain(
            &mut failure,
            cleanup_checkpoint(phase, || {
                let result = owner.cleanup_fixture(subject);
                let reported = emit(output::facts(
                    phase,
                    &[
                        ("verified", result.is_ok()),
                        ("deferred", owner.life.unresolved()),
                    ],
                ));
                policy::preservation_result([result, reported])
            }),
        );
    }
    retain(
        &mut failure,
        cleanup_checkpoint("caller-check", || {
            let result = donor
                .as_ref()
                .ok_or(NativeError::EvidenceIncomplete)
                .and_then(DonorLease::caller_quiet);
            let reported = emit(output::facts(
                "caller-check",
                &[("verified", result.is_ok())],
            ));
            policy::preservation_result([result, reported])
        }),
    );
    retain(
        &mut failure,
        cleanup_checkpoint("donor-check", || {
            let result = donor
                .as_mut()
                .ok_or(NativeError::EvidenceIncomplete)
                .and_then(DonorLease::quiet_fresh);
            let reported = emit(output::facts(
                "donor-check",
                &[("verified", result.is_ok())],
            ));
            policy::preservation_result([result, reported])
        }),
    );
    retain(
        &mut failure,
        cleanup_checkpoint("copy-check", || {
            let result = copy
                .as_ref()
                .ok_or(NativeError::EvidenceIncomplete)
                .and_then(OrdinaryCopy::quiet_unchanged);
            let reported = emit(output::facts("copy-check", &[("verified", result.is_ok())]));
            policy::preservation_result([result, reported])
        }),
    );
    let completed = cleanup_checkpoint("complete", || {
        let completed = failure.is_none();
        let reported = emit(output::facts(
            "complete",
            &[
                ("experiment-complete", completed),
                ("startup-proof", completed),
            ],
        ));
        if let Some(error) = failure {
            return Err(error);
        }
        reported
    });
    policy::after_report(failure.map_or(Ok(()), Err), |_| completed)
}
/// Independent opt-in proof; no donor or rights means failure, never a skipped or normalized pass.
#[test]
#[ignore = "requires approved enrolled Windows desktop and ordinary installed Manager donor"]
fn native_authenticated_manager_source_proof() {
    let result = run_manager_source_proof();
    assert!(result.is_ok(), "manager-source-proof-failed");
}
