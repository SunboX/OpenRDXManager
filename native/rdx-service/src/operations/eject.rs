// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! High-level host-cache eject policy with mandatory departure reconciliation.

use std::panic::{AssertUnwindSafe, catch_unwind};

use crate::host::{DeviceSession, HostOperationError};
use crate::model::{DeviceIdentity, OperationKind};
use crate::transport::{CommandDispatch, TransportError};

use super::volume::{
    HostOperationFailure, HostOperationObserver, HostOperations, HostPrimitiveError,
    MutationCertainty, VolumeTopology, require_confirmation,
};
use super::{
    FailureAccumulator, OperationCompletion, OperationContext, OperationFailure, OperationIssue,
    OperationOwner, OperationProgressEvent, OperationReport, OperationStage,
};
use crate::model::ConfirmationToken;

/// Safely flushes/unmounts and ejects one exact selected cartridge.
///
/// This routine never invokes the forced primitive. One fresh exact-binding
/// preflight produces a one-shot proof consumed immediately by the combined
/// native unmount and host/mechanical eject authority.
///
/// # Errors
///
/// Rejects stale, absent, read-only, unsafe, busy, cancelled, timed-out, or
/// otherwise unprovable host state with explicit native certainty.
pub fn safe_eject(host: &mut impl HostOperations) -> Result<(), HostOperationFailure> {
    safe_eject_observed(host, &mut UnobservedEject)
}

/// Runs safe eject with a cancellation checkpoint before combined native dispatch.
pub(crate) fn safe_eject_observed(
    host: &mut impl HostOperations,
    observer: &mut impl HostOperationObserver,
) -> Result<(), HostOperationFailure> {
    require_eject_stage(observer, "host-unmounting", true)?;
    let binding = host.binding();
    observer.diagnostic("eject-preflight-enter");
    let preflight = fresh_eject_facts(host, &binding, "preflight");
    observer.diagnostic("eject-preflight-return");
    preflight?;
    require_eject_stage(observer, "host-unmounting", false)?;
    let mut unmount_succeeded = false;
    let mut after_unmount = || {
        unmount_succeeded = true;
        observer.reached("host-ejecting", false)
    };
    if let Err(failure) = host.safe_eject_exact(&binding, &mut after_unmount)
        && !(unmount_succeeded && failure.certainty == MutationCertainty::CompletionUnknown)
    {
        return Err(HostOperationFailure::from_primitive(
            if unmount_succeeded {
                "eject"
            } else {
                "unmount"
            },
            failure,
        ));
    }
    require_eject_stage(observer, "eject-readback", false)?;
    host.verify_eject_departure(&binding).map_err(|failure| {
        HostOperationFailure::from_primitive(
            "eject-readback",
            super::volume::PrimitiveFailure::completion_unknown(failure.error),
        )
    })
}

/// Force-ejects one exact cartridge only after an exact confirmation gate.
///
/// Forced eject intentionally skips host unmount and is never called as a
/// fallback from [`safe_eject`].
///
/// # Errors
///
/// Rejects an invalid confirmation, stale/absent/unsafe selected cartridge, or
/// any native force-eject failure with explicit certainty.
pub fn force_eject(
    host: &mut impl HostOperations,
    confirmation: &ConfirmationToken,
) -> Result<(), HostOperationFailure> {
    force_eject_observed(host, confirmation, &mut UnobservedEject)
}

/// Runs confirmed forced eject while reporting only reached non-cancellable stages.
pub(crate) fn force_eject_observed(
    host: &mut impl HostOperations,
    confirmation: &ConfirmationToken,
    observer: &mut impl HostOperationObserver,
) -> Result<(), HostOperationFailure> {
    require_eject_stage(observer, "host-ejecting", false)?;
    let binding = host.binding();
    require_confirmation(host, &binding, confirmation)?;
    fresh_eject_facts(host, &binding, "preflight")?;
    if let Err(failure) = host.eject_exact(&binding, true)
        && failure.certainty != MutationCertainty::CompletionUnknown
    {
        return Err(HostOperationFailure::from_primitive("force-eject", failure));
    }
    require_eject_stage(observer, "eject-readback", false)?;
    host.verify_eject_departure(&binding).map_err(|failure| {
        HostOperationFailure::from_primitive(
            "eject-readback",
            super::volume::PrimitiveFailure::completion_unknown(failure.error),
        )
    })
}

/// No-op observer retained by the synchronous public eject wrappers.
struct UnobservedEject;

impl HostOperationObserver for UnobservedEject {
    /// Always permits synchronous execution.
    fn reached(&mut self, _stage: &'static str, _cancellable: bool) -> bool {
        true
    }
}

/// Converts an observer decision into a safe pre-dispatch cancellation failure.
fn require_eject_stage(
    observer: &mut impl HostOperationObserver,
    stage: &'static str,
    cancellable: bool,
) -> Result<(), HostOperationFailure> {
    if observer.reached(stage, cancellable) {
        Ok(())
    } else {
        Err(HostOperationFailure::preflight(
            stage,
            HostPrimitiveError::Cancelled,
        ))
    }
}

/// Revalidates only the media and topology gates shared by both eject policies.
fn fresh_eject_facts(
    host: &mut impl HostOperations,
    binding: &super::volume::HostVolumeBinding,
    stage: &'static str,
) -> Result<(), HostOperationFailure> {
    let facts = host
        .revalidate(binding)
        .map_err(|failure| HostOperationFailure::from_primitive(stage, failure))?;
    if !facts.media_present {
        return Err(HostOperationFailure::preflight(
            stage,
            HostPrimitiveError::MediaMissing,
        ));
    }
    if facts.topology != VolumeTopology::Simple {
        return Err(HostOperationFailure::preflight(
            stage,
            HostPrimitiveError::UnsafeTopology,
        ));
    }
    Ok(())
}

#[cfg(test)]
mod observer_tests {
    use super::*;
    use crate::platform::fixtures::FixtureHost;

    /// Records only causally reached safe-eject stages.
    #[derive(Default)]
    struct RecordingObserver {
        diagnostics: Vec<&'static str>,
        stages: Vec<&'static str>,
    }

    impl HostOperationObserver for RecordingObserver {
        /// Retains one reached stage and always allows the operation to continue.
        fn reached(&mut self, stage: &'static str, _cancellable: bool) -> bool {
            self.stages.push(stage);
            true
        }

        /// Retains one closed diagnostic boundary for deterministic assertions.
        fn diagnostic(&mut self, code: &'static str) {
            self.diagnostics.push(code);
        }
    }

    /// Failure in the exact unmount primitive must not claim physical eject.
    #[test]
    fn safe_eject_publishes_eject_stage_only_after_unmount_success() {
        let mut host = FixtureHost::ready().with_unmount_rejection();
        let mut observer = RecordingObserver::default();

        let failure = safe_eject_observed(&mut host, &mut observer).unwrap_err();

        assert_eq!(failure.stage(), "unmount");
        assert_eq!(observer.stages, ["host-unmounting", "host-unmounting"]);
    }

    /// A rejected preflight still closes its diagnostic bracket without entering native eject.
    #[test]
    fn safe_eject_brackets_preflight_revalidation() {
        let mut host = FixtureHost::ready().with_media_swap_at_revalidation(1);
        let mut observer = RecordingObserver::default();

        let failure = safe_eject_observed(&mut host, &mut observer).unwrap_err();

        assert_eq!(failure.code(), "stale-device-revision");
        assert_eq!(
            observer.diagnostics,
            ["eject-preflight-enter", "eject-preflight-return"]
        );
    }

    /// An ambiguous native callback is success only after exact media departure is proven.
    #[test]
    fn safe_eject_reconciles_unknown_callback_with_departure_readback() {
        let mut host = FixtureHost::ready().with_eject_completion_unknown();
        let mut observer = RecordingObserver::default();

        safe_eject_observed(&mut host, &mut observer)
            .expect("fresh no-media readback resolves the callback ambiguity");

        assert_eq!(host.safe_eject_count(), 1);
        assert_eq!(
            observer.stages,
            [
                "host-unmounting",
                "host-unmounting",
                "host-ejecting",
                "eject-readback"
            ]
        );
    }

    /// Callback ambiguity remains a failure when departure cannot be proven.
    #[test]
    fn safe_eject_keeps_unknown_callback_failed_without_departure() {
        let mut host = FixtureHost::ready()
            .with_eject_completion_unknown()
            .with_eject_departure_unconfirmed();
        let mut observer = RecordingObserver::default();

        let failure = safe_eject_observed(&mut host, &mut observer).unwrap_err();

        assert_eq!(failure.stage(), "eject-readback");
        assert_eq!(
            failure.certainty(),
            super::super::volume::MutationCertainty::CompletionUnknown
        );
    }

    /// Confirmed force eject uses the same departure proof for an ambiguous callback.
    #[test]
    fn force_eject_reconciles_unknown_callback_with_departure_readback() {
        let mut host = FixtureHost::ready().with_eject_completion_unknown();
        let confirmation = host.issue_confirmation_token();
        let mut observer = RecordingObserver::default();

        force_eject_observed(&mut host, &confirmation, &mut observer)
            .expect("force-eject departure resolves the callback ambiguity");

        assert_eq!(host.force_eject_count(), 1);
        assert_eq!(observer.stages, ["host-ejecting", "eject-readback"]);
    }
}

/// Typed host cache policy selected by one trusted high-level eject request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostEjectPolicy {
    /// Flushes and unmounts through the host before requesting eject.
    Safe,
    /// Requests host eject without the safe unmount step after an explicit warning.
    Forced,
}

impl HostEjectPolicy {
    /// Returns the exact operation kind bound to this policy.
    #[must_use]
    pub const fn operation_kind(self) -> OperationKind {
        match self {
            Self::Safe => OperationKind::EjectSafe,
            Self::Forced => OperationKind::EjectForce,
        }
    }
}

/// Unforgeable safe-Rust evidence that exact-target departure was read back.
///
/// Native eject adapters obtain this capability only by completing
/// [`run_eject`]. Its private fields prevent a backend from manufacturing an
/// eject-success terminal without running the shared state machine.
#[derive(Debug, Eq, PartialEq)]
pub struct VerifiedEjectDeparture {
    owner: OperationOwner,
    policy: HostEjectPolicy,
}

impl VerifiedEjectDeparture {
    /// Returns the exact operation, identity, revision, and session owner.
    #[must_use]
    pub const fn owner(&self) -> &OperationOwner {
        &self.owner
    }

    /// Returns the typed host-cache policy used by the verified operation.
    #[must_use]
    pub const fn policy(&self) -> HostEjectPolicy {
        self.policy
    }
}

/// Typed terminal outcome for one shared eject operation.
#[derive(Debug, PartialEq)]
pub enum EjectOutcome {
    /// Host eject dispatched successfully and exact-target departure was verified.
    Succeeded {
        /// Complete graph-valid progress evidence.
        report: OperationReport,
        /// Non-forgeable exact-departure proof required by a success terminal.
        departure: VerifiedEjectDeparture,
    },
    /// Safe eject cancellation won before the host-eject mutation barrier.
    Cancelled {
        /// Complete pre-mutation cancellation evidence.
        report: OperationReport,
    },
}

/// Fresh post-eject observation for the exact requested device identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EjectReadback {
    /// Fresh discovery proves the exact target departed.
    Departed(DeviceIdentity),
    /// Fresh discovery proves the exact target remains present.
    Present(DeviceIdentity),
}

/// Fixed adapter error for a causal progress event that could not be published.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProgressPublicationError {
    _private: (),
}

impl ProgressPublicationError {
    /// Creates the only safe progress-publication failure signal.
    #[must_use]
    pub const fn unavailable() -> Self {
        Self { _private: () }
    }
}

/// Narrow path-free host adapter required by the eject state machine.
pub trait EjectHost {
    /// Flushes and unmounts the exact target under safe host cache policy.
    fn unmount(&mut self, target: &DeviceIdentity) -> Result<(), HostOperationError>;

    /// Requests eject for the exact target and reports explicit device-dispatch certainty.
    fn eject(&mut self, target: &DeviceIdentity, policy: HostEjectPolicy) -> CommandDispatch;

    /// Performs fresh discovery and reports exact-target departure or continued presence.
    fn readback(&mut self, target: &DeviceIdentity) -> Result<EjectReadback, HostOperationError>;
}

/// Runs one identity-bound eject and requires exact-target departure before success.
///
/// The forced policy changes only whether host unmount is requested. Both
/// policies repeat exact-session and media presence checks and preserve
/// dispatch certainty. Safe cancellation may complete before eject dispatch;
/// after dispatch begins, both policies require `eject-readback`
/// reconciliation.
///
/// # Errors
///
/// Returns [`OperationFailure`] with typed preflight, dispatch, and readback
/// evidence whenever exact departure cannot be proven.
pub fn run_eject(
    session: &mut DeviceSession,
    context: OperationContext,
    host: &mut impl EjectHost,
    policy: HostEjectPolicy,
) -> Result<EjectOutcome, OperationFailure> {
    run_eject_with_progress(session, context, host, policy, |_| Ok(()))
}

/// Runs one identity-bound eject while publishing each validated progress event causally.
///
/// The callback runs immediately after native validation and retention of each
/// event, before the operation can advance to the next host or device stage.
/// Returning [`ProgressPublicationError`] preserves a fixed publication failure
/// as native evidence and prevents any not-yet-started eject dispatch.
/// No application callback runs while the internal cancellation mutex is held.
/// The callback may synchronously request cancellation through its exact
/// [`super::CancellationHandle`]; an external thread's concurrent request does
/// not return until the in-flight event callback finishes. A callback error or
/// panic becomes fixed progress-publication evidence, and a post-dispatch
/// failure cannot skip mandatory exact-target readback.
///
/// # Errors
///
/// Returns [`OperationFailure`] with typed preflight, progress-publication,
/// dispatch, and readback evidence whenever exact departure cannot be proven.
pub fn run_eject_with_progress<F>(
    session: &mut DeviceSession,
    mut context: OperationContext,
    host: &mut impl EjectHost,
    policy: HostEjectPolicy,
    mut publish_progress: F,
) -> Result<EjectOutcome, OperationFailure>
where
    F: FnMut(&OperationProgressEvent) -> Result<(), ProgressPublicationError>,
{
    let mut failures = FailureAccumulator::default();
    let first_stage = match policy {
        HostEjectPolicy::Safe => OperationStage::HostUnmounting,
        HostEjectPolicy::Forced => OperationStage::HostEjecting,
    };
    if !require_context_binding(session, &context, policy, first_stage, &mut failures) {
        return Err(context.fail(failures));
    }
    record_emit(
        &mut context,
        first_stage,
        0.1,
        match policy {
            HostEjectPolicy::Safe => "operations.eject.unmounting",
            HostEjectPolicy::Forced => "operations.eject.ejecting",
        },
        &mut failures,
        &mut publish_progress,
    );
    if policy == HostEjectPolicy::Safe && context.cancellation_requested() {
        return finish_cancelled(context, failures);
    }

    let preflight_passed = if failures.has_failure() {
        false
    } else {
        match session.revalidate() {
            Ok(()) if session.device().media_present() => true,
            Ok(()) => {
                failures.record(first_stage, OperationIssue::MediaMissing);
                false
            }
            Err(error) => {
                failures.record(first_stage, OperationIssue::Host(error));
                false
            }
        }
    };

    if preflight_passed && policy == HostEjectPolicy::Safe && context.cancellation_requested() {
        return finish_cancelled(context, failures);
    }

    if preflight_passed && !failures.has_failure() && policy == HostEjectPolicy::Safe {
        let target = session.device().identity().clone();
        let unmount = catch_unwind(AssertUnwindSafe(|| host.unmount(&target)))
            .unwrap_or(Err(HostOperationError::AdapterPanic));
        if let Err(error) = unmount {
            failures.record(OperationStage::HostUnmounting, OperationIssue::Host(error));
        }
    }

    if policy == HostEjectPolicy::Safe && preflight_passed && !failures.has_failure() {
        // This compare-exchange is the mutation barrier: a prior request wins,
        // while every later request observes Closed before host eject begins.
        if context.close_cancellation() {
            return finish_cancelled(context, failures);
        }
        record_emit(
            &mut context,
            OperationStage::HostEjecting,
            0.6,
            "operations.eject.ejecting",
            &mut failures,
            &mut publish_progress,
        );
    }

    let dispatch = if preflight_passed && !failures.has_failure() {
        let target = session.device().identity().clone();
        Some(
            catch_unwind(AssertUnwindSafe(|| host.eject(&target, policy))).unwrap_or(
                CommandDispatch::CompletionUnknown(TransportError::AdapterPanic),
            ),
        )
    } else {
        None
    };
    if let Some(dispatch) = &dispatch
        && let Some(error) = dispatch.error().cloned()
    {
        failures.record(
            OperationStage::HostEjecting,
            OperationIssue::Dispatch {
                certainty: dispatch.certainty(),
                error,
            },
        );
    }

    if dispatch.is_some() {
        record_emit(
            &mut context,
            OperationStage::EjectReadback,
            1.0,
            "operations.eject.readback",
            &mut failures,
            &mut publish_progress,
        );
        let target = session.device().identity().clone();
        let readback = catch_unwind(AssertUnwindSafe(|| host.readback(&target)))
            .unwrap_or(Err(HostOperationError::AdapterPanic));
        match readback {
            Ok(EjectReadback::Departed(identity)) if identity == target => {
                if !matches!(dispatch, Some(CommandDispatch::Succeeded(_))) {
                    failures.record(
                        OperationStage::EjectReadback,
                        OperationIssue::EjectDispatchContradiction,
                    );
                }
            }
            Ok(EjectReadback::Present(identity)) if identity == target => failures.record(
                OperationStage::EjectReadback,
                OperationIssue::EjectTargetPresent,
            ),
            Ok(EjectReadback::Departed(_) | EjectReadback::Present(_)) => failures.record(
                OperationStage::EjectReadback,
                OperationIssue::DeviceIdentityChanged,
            ),
            Err(error) => {
                failures.record(OperationStage::EjectReadback, OperationIssue::Host(error))
            }
        }
    }

    if failures.has_failure() {
        Err(context.fail(failures))
    } else {
        let departure = VerifiedEjectDeparture {
            owner: context.owner().clone(),
            policy,
        };
        Ok(EjectOutcome::Succeeded {
            report: context.complete(OperationCompletion::Succeeded),
            departure,
        })
    }
}

/// Completes a pre-mutation cancellation unless prior invariant evidence failed.
fn finish_cancelled(
    context: OperationContext,
    failures: FailureAccumulator,
) -> Result<EjectOutcome, OperationFailure> {
    if failures.has_failure() {
        Err(context.fail(failures))
    } else {
        Ok(EjectOutcome::Cancelled {
            report: context.complete(OperationCompletion::Cancelled),
        })
    }
}

/// Requires the typed policy, exact identity, generation, and private session lineage.
fn require_context_binding(
    session: &DeviceSession,
    context: &OperationContext,
    policy: HostEjectPolicy,
    stage: OperationStage,
    failures: &mut FailureAccumulator,
) -> bool {
    let expected = policy.operation_kind();
    let actual = context.owner().kind();
    if actual != expected {
        failures.record(
            stage,
            OperationIssue::WrongOperationKind { expected, actual },
        );
        return false;
    }
    let device = session.device();
    if !session.is_active()
        || !context.owner().belongs_to(session)
        || context.owner().device() != device.identity()
        || context.owner().product_family() != device.product_family()
        || context.owner().generation().get() != device.generation().get()
    {
        failures.record(stage, OperationIssue::SessionBindingChanged);
        return false;
    }
    true
}

/// Emits a graph-valid event or preserves the impossible invariant as evidence.
fn record_emit<F>(
    context: &mut OperationContext,
    stage: OperationStage,
    fraction: f64,
    message_key: &'static str,
    failures: &mut FailureAccumulator,
    publish_progress: &mut F,
) where
    F: FnMut(&OperationProgressEvent) -> Result<(), ProgressPublicationError>,
{
    if let Err(issue) = context.emit_causally(stage, fraction, message_key, publish_progress) {
        failures.record(stage, issue);
    }
}
