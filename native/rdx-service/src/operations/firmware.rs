// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Deterministic modern firmware transfer, recovery, reconnect, and readback.

use crate::firmware::{FIRST_SIGNED_FIRMWARE_REVISION, InstallableFirmwareImage};
use crate::host::{DeviceSession, RecoveryLease, SessionDevice};
use crate::model::OperationKind;
use crate::protocol::write_buffer;
use crate::transport::{CommandDispatch, DispatchCertainty, TransportError};

use super::{
    FailureAccumulator, OperationCompletion, OperationContext, OperationFailure, OperationIssue,
    OperationReport, OperationStage,
};

const RECONNECT_ATTEMPTS: u8 = 15;
const MAX_TRANSFER_PROGRESS_EVENTS_PER_ATTEMPT: usize = 48;

#[derive(Debug)]
struct AttemptFailure {
    stage: OperationStage,
    issue: OperationIssue,
    retryable: bool,
}

impl AttemptFailure {
    /// Reports whether finalizer completion remains unknown regardless of resend policy.
    fn requires_finalizer_reconciliation(&self) -> bool {
        matches!(
            self.issue,
            OperationIssue::Dispatch {
                certainty: DispatchCertainty::CompletionUnknown,
                ..
            }
        )
    }
}

#[derive(Debug)]
struct TransferOutcome {
    completed: bool,
    rebound_candidate: bool,
    cleanup_lease: Option<RecoveryLease>,
}

impl TransferOutcome {
    /// Reports successful finalization that still requires post-mutation reconnect.
    fn completed() -> Self {
        Self {
            completed: true,
            rebound_candidate: false,
            cleanup_lease: None,
        }
    }

    /// Reports success already reconciled on a fresh candidate-revision lease.
    fn reconciled() -> Self {
        Self {
            completed: true,
            rebound_candidate: true,
            cleanup_lease: None,
        }
    }

    /// Reports failure before finalization where exact-lease cleanup may remain possible.
    fn failed(cleanup_lease: Option<RecoveryLease>) -> Self {
        Self {
            completed: false,
            rebound_candidate: false,
            cleanup_lease,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReconciledRevision {
    Candidate,
    Original,
}

/// Transfers one consumed exact-session authorization with one whole-file retry.
///
/// Mode-4 retry always starts from byte zero after a fresh same-lineage rebind.
/// Mode-5 uncertainty is reconciled through fresh installed-revision evidence
/// before a second and final mode-5 is considered. Once writing begins, the
/// public Phase 1 recovery stages are emitted through the readback barrier.
///
/// # Errors
///
/// Returns [`OperationFailure`] with the first unrecovered cause, bounded
/// cleanup evidence, and recovered attempt-one history kept separately.
pub fn run_firmware_update(
    session: &mut DeviceSession,
    mut context: OperationContext,
    image: InstallableFirmwareImage,
) -> Result<OperationReport, OperationFailure> {
    let mut failures = FailureAccumulator::default();
    if !require_context_binding(session, &context, &mut failures) {
        return Err(context.fail(failures));
    }
    record_emit(
        &mut context,
        OperationStage::FirmwareValidating,
        0.0,
        "operations.firmwareUpdate.validating",
        &mut failures,
    );
    if context.cancellation_requested() {
        return Ok(context.complete(OperationCompletion::Cancelled));
    }

    match session.revalidate() {
        Ok(()) if session.device().media_present() => failures.record(
            OperationStage::FirmwareValidating,
            OperationIssue::MediaPresent,
        ),
        Ok(()) if image.is_authorized_for(session) => {}
        Ok(()) => failures.record(
            OperationStage::FirmwareValidating,
            OperationIssue::FirmwareAuthorizationInvalidated,
        ),
        Err(error) => failures.record(
            OperationStage::FirmwareValidating,
            OperationIssue::Host(error),
        ),
    }
    if failures.has_failure() {
        return Err(context.fail(failures));
    }

    if context.close_cancellation() {
        record_emit(
            &mut context,
            OperationStage::FirmwareValidating,
            0.01,
            "operations.firmwareUpdate.cancelled",
            &mut failures,
        );
        return if failures.has_failure() {
            Err(context.fail(failures))
        } else {
            Ok(context.complete(OperationCompletion::Cancelled))
        };
    }

    record_attempt_emit(
        &mut context,
        0.05,
        "operations.firmwareUpdate.writing",
        1,
        &mut failures,
    );
    let transfer = transfer_with_retry(session, &mut context, &image, &mut failures);

    record_emit(
        &mut context,
        OperationStage::FirmwareFinalizing,
        0.85,
        "operations.firmwareUpdate.finalizing",
        &mut failures,
    );
    let cleanup_requires_reconnect = transfer
        .cleanup_lease
        .as_ref()
        .is_some_and(|lease| record_cleanup_finalize(session, lease, &image, &mut failures));

    record_emit(
        &mut context,
        OperationStage::DeviceReconnecting,
        0.92,
        "operations.firmwareUpdate.reconnecting",
        &mut failures,
    );
    let reconnect_required =
        (transfer.completed && !transfer.rebound_candidate) || cleanup_requires_reconnect;
    let rebound = if transfer.rebound_candidate {
        true
    } else if reconnect_required {
        match session.reconnect(RECONNECT_ATTEMPTS) {
            Ok(()) => true,
            Err(error) => {
                failures.record(
                    OperationStage::DeviceReconnecting,
                    OperationIssue::PostMutationRebind(error),
                );
                false
            }
        }
    } else {
        false
    };

    record_emit(
        &mut context,
        OperationStage::FirmwareReadback,
        1.0,
        "operations.firmwareUpdate.readback",
        &mut failures,
    );
    if rebound {
        match session.revalidate() {
            Ok(()) => record_revision_readback(session.device(), &image, &mut failures),
            Err(error) => failures.record(
                OperationStage::FirmwareReadback,
                OperationIssue::Host(error),
            ),
        }
    }

    if failures.has_failure() {
        Err(context.fail(failures))
    } else {
        Ok(context.complete(OperationCompletion::Succeeded))
    }
}

/// Executes at most two complete data attempts and evidence-gated finalization.
fn transfer_with_retry(
    session: &mut DeviceSession,
    context: &mut OperationContext,
    image: &InstallableFirmwareImage,
    failures: &mut FailureAccumulator,
) -> TransferOutcome {
    let first_lease = session.recovery_lease();
    let first = match transfer_data_attempt(session, context, image, 1, 0.05, 0.40) {
        Ok(()) => return finalize_with_reconciliation(session, context, image, 1, failures),
        Err(failure) => failure,
    };
    if !first.retryable {
        failures.record(first.stage, first.issue);
        return TransferOutcome::failed(Some(first_lease));
    }

    if let Err(issue) = prepare_retry(session, image) {
        failures.record(first.stage, first.issue);
        failures.record(OperationStage::FirmwareWriting, issue);
        return TransferOutcome::failed(None);
    }
    failures.record_attempt(1, first.stage, first.issue);
    record_attempt_emit(
        context,
        0.40,
        "operations.firmwareUpdate.retrying",
        2,
        failures,
    );
    let second_lease = session.recovery_lease();
    match transfer_data_attempt(session, context, image, 2, 0.40, 0.80) {
        Ok(()) => finalize_with_reconciliation(session, context, image, 2, failures),
        Err(failure) => {
            failures.record(failure.stage, failure.issue);
            TransferOutcome::failed(Some(second_lease))
        }
    }
}

/// Streams one complete mode-4 attempt without conflating mode-5 finalization.
fn transfer_data_attempt(
    session: &mut DeviceSession,
    context: &mut OperationContext,
    image: &InstallableFirmwareImage,
    attempt: u8,
    start_fraction: f64,
    end_fraction: f64,
) -> Result<(), AttemptFailure> {
    let chunk_count = image.chunks().len();
    for (index, chunk) in image.chunks().enumerate() {
        let command =
            write_buffer(0x04, chunk.offset(), chunk.bytes()).map_err(|error| AttemptFailure {
                stage: OperationStage::FirmwareWriting,
                issue: OperationIssue::ProtocolBuild(error),
                retryable: false,
            })?;
        require_dispatch_success(session.execute(&command), OperationStage::FirmwareWriting)?;
        if should_emit_transfer_progress(index, chunk_count) {
            let completed = (index + 1) as f64 / chunk_count as f64;
            context
                .emit_attempt(
                    OperationStage::FirmwareWriting,
                    start_fraction + (end_fraction - start_fraction) * completed,
                    "operations.firmwareUpdate.writing",
                    attempt,
                )
                .map_err(|issue| AttemptFailure {
                    stage: OperationStage::FirmwareWriting,
                    issue,
                    retryable: false,
                })?;
        }
    }
    Ok(())
}

/// Converts a dispatch into success or evidence-backed retry disposition.
fn require_dispatch_success(
    outcome: CommandDispatch,
    stage: OperationStage,
) -> Result<(), AttemptFailure> {
    let certainty = outcome.certainty();
    let Some(error) = outcome.error().cloned() else {
        return Ok(());
    };
    let retryable = permits_retry(certainty, &error);
    Err(AttemptFailure {
        stage,
        issue: OperationIssue::Dispatch { certainty, error },
        retryable,
    })
}

/// Selects retry only where completion and recovered error evidence permit it.
fn permits_retry(certainty: DispatchCertainty, error: &TransportError) -> bool {
    if error.is_firmware_signature_rejection() || !error.permits_firmware_retry() {
        return false;
    }
    matches!(
        certainty,
        DispatchCertainty::NotSent
            | DispatchCertainty::DefinitelyRejected
            | DispatchCertainty::CompletionUnknown
    )
}

/// Obtains a fresh same-lineage rebound lease before restarting from byte zero.
fn prepare_retry(
    session: &mut DeviceSession,
    image: &InstallableFirmwareImage,
) -> Result<(), OperationIssue> {
    session
        .reconnect(RECONNECT_ATTEMPTS)
        .map_err(OperationIssue::PostMutationRebind)?;
    if !image.is_authorized_after_rebind(session) {
        return Err(OperationIssue::FirmwareAuthorizationInvalidated);
    }
    validate_retry_device(session.device(), image)
}

/// Sends mode-5 once and reconciles every evidence-backed retry before resending.
fn finalize_with_reconciliation(
    session: &mut DeviceSession,
    context: &mut OperationContext,
    image: &InstallableFirmwareImage,
    attempt: u8,
    failures: &mut FailureAccumulator,
) -> TransferOutcome {
    let first = match dispatch_finalizer(session, image) {
        Ok(()) => return TransferOutcome::completed(),
        Err(failure) => failure,
    };
    if !first.retryable && !first.requires_finalizer_reconciliation() {
        failures.record(first.stage, first.issue);
        return TransferOutcome::failed(None);
    }

    match reconcile_finalizer(session, image) {
        Ok(ReconciledRevision::Candidate) => TransferOutcome::reconciled(),
        Ok(ReconciledRevision::Original) if first.retryable && attempt == 1 => {
            failures.record_attempt(1, first.stage, first.issue);
            record_attempt_emit(
                context,
                0.40,
                "operations.firmwareUpdate.retrying",
                2,
                failures,
            );
            match dispatch_finalizer(session, image) {
                Ok(()) => TransferOutcome::completed(),
                Err(second) => reconcile_last_finalizer(session, image, second, failures),
            }
        }
        Ok(ReconciledRevision::Original) => {
            failures.record(first.stage, first.issue);
            TransferOutcome::failed(None)
        }
        Err(issue) => {
            failures.record(first.stage, first.issue);
            failures.record(OperationStage::FirmwareFinalizing, issue);
            TransferOutcome::failed(None)
        }
    }
}

/// Reconciles the last permitted mode-5 without ever allowing a third dispatch.
fn reconcile_last_finalizer(
    session: &mut DeviceSession,
    image: &InstallableFirmwareImage,
    second: AttemptFailure,
    failures: &mut FailureAccumulator,
) -> TransferOutcome {
    if second.retryable || second.requires_finalizer_reconciliation() {
        match reconcile_finalizer(session, image) {
            Ok(ReconciledRevision::Candidate) => return TransferOutcome::reconciled(),
            Ok(ReconciledRevision::Original) => {}
            Err(issue) => {
                failures.record(second.stage, second.issue);
                failures.record(OperationStage::FirmwareFinalizing, issue);
                return TransferOutcome::failed(None);
            }
        }
    }
    failures.record(second.stage, second.issue);
    TransferOutcome::failed(None)
}

/// Builds and dispatches exactly one finalizer with explicit certainty evidence.
fn dispatch_finalizer(
    session: &mut DeviceSession,
    image: &InstallableFirmwareImage,
) -> Result<(), AttemptFailure> {
    let command = image.finalize_command().map_err(|error| AttemptFailure {
        stage: OperationStage::FirmwareFinalizing,
        issue: OperationIssue::ProtocolBuild(error),
        retryable: false,
    })?;
    require_dispatch_success(
        session.execute(&command),
        OperationStage::FirmwareFinalizing,
    )
}

/// Reconnects first, then classifies candidate, original, or unsafe revision drift.
fn reconcile_finalizer(
    session: &mut DeviceSession,
    image: &InstallableFirmwareImage,
) -> Result<ReconciledRevision, OperationIssue> {
    session
        .reconnect(RECONNECT_ATTEMPTS)
        .map_err(OperationIssue::PostMutationRebind)?;
    if !image.has_rebound_lineage(session) {
        return Err(OperationIssue::FirmwareAuthorizationInvalidated);
    }
    let device = session.device();
    if device.media_present() {
        return Err(OperationIssue::MediaPresent);
    }
    if device.installed_revision() == image.expected_revision()
        && image.expected_revision() != image.authorized_installed_revision()
    {
        return Ok(ReconciledRevision::Candidate);
    }
    if device.installed_revision() == image.authorized_installed_revision() {
        return Ok(ReconciledRevision::Original);
    }
    Err(OperationIssue::FirmwareAuthorizationInvalidated)
}

/// Validates family, media, and installed-revision policy after retry preparation.
fn validate_retry_device(
    device: &SessionDevice,
    image: &InstallableFirmwareImage,
) -> Result<(), OperationIssue> {
    if device.product_family() != image.product() {
        return Err(OperationIssue::ProductFamilyMismatch);
    }
    if device.media_present() {
        return Err(OperationIssue::MediaPresent);
    }
    if device.installed_revision().get() >= FIRST_SIGNED_FIRMWARE_REVISION
        && image.revision().get() < FIRST_SIGNED_FIRMWARE_REVISION
    {
        return Err(OperationIssue::FirmwareAuthorizationRejected {
            installed: device.installed_revision(),
            candidate: image.revision(),
        });
    }
    Ok(())
}

/// Best-effort finalizes parser state only on a retained exact data-transfer lease.
fn record_cleanup_finalize(
    session: &mut DeviceSession,
    recovery_lease: &RecoveryLease,
    image: &InstallableFirmwareImage,
    failures: &mut FailureAccumulator,
) -> bool {
    match image.finalize_command() {
        Ok(command) => {
            let outcome = session.execute_recovery(recovery_lease, &command);
            let requires_reconnect = matches!(
                outcome,
                CommandDispatch::Succeeded(_) | CommandDispatch::CompletionUnknown(_)
            );
            if let Some(error) = outcome.error().cloned() {
                failures.record(
                    OperationStage::FirmwareFinalizing,
                    OperationIssue::Dispatch {
                        certainty: outcome.certainty(),
                        error,
                    },
                );
            }
            requires_reconnect
        }
        Err(error) => {
            failures.record(
                OperationStage::FirmwareFinalizing,
                OperationIssue::ProtocolBuild(error),
            );
            false
        }
    }
}

/// Requires the exact operation kind and consumed-authorization session owner.
fn require_context_binding(
    session: &DeviceSession,
    context: &OperationContext,
    failures: &mut FailureAccumulator,
) -> bool {
    if context.owner().kind() != OperationKind::FirmwareUpdate {
        failures.record(
            OperationStage::FirmwareValidating,
            OperationIssue::WrongOperationKind {
                expected: OperationKind::FirmwareUpdate,
                actual: context.owner().kind(),
            },
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
        failures.record(
            OperationStage::FirmwareValidating,
            OperationIssue::SessionBindingChanged,
        );
        return false;
    }
    true
}

/// Records final same-device candidate-revision readback.
fn record_revision_readback(
    device: &SessionDevice,
    image: &InstallableFirmwareImage,
    failures: &mut FailureAccumulator,
) {
    if device.product_family() != image.product() {
        failures.record(
            OperationStage::FirmwareReadback,
            OperationIssue::ProductFamilyMismatch,
        );
    } else if device.installed_revision() != image.expected_revision() {
        failures.record(
            OperationStage::FirmwareReadback,
            OperationIssue::FirmwareRevisionMismatch {
                expected: image.expected_revision(),
                actual: device.installed_revision(),
            },
        );
    }
}

/// Selects at most a fixed number of monotonic chunk-completion events.
fn should_emit_transfer_progress(index: usize, chunk_count: usize) -> bool {
    if chunk_count == 0 || index >= chunk_count {
        return false;
    }
    let completed = index + 1;
    completed == chunk_count
        || completed * MAX_TRANSFER_PROGRESS_EVENTS_PER_ATTEMPT / chunk_count
            > index * MAX_TRANSFER_PROGRESS_EVENTS_PER_ATTEMPT / chunk_count
}

/// Emits an attempt-scoped writing event or records an invariant failure.
fn record_attempt_emit(
    context: &mut OperationContext,
    fraction: f64,
    message_key: &'static str,
    attempt: u8,
    failures: &mut FailureAccumulator,
) {
    if let Err(issue) = context.emit_attempt(
        OperationStage::FirmwareWriting,
        fraction,
        message_key,
        attempt,
    ) {
        failures.record(OperationStage::FirmwareWriting, issue);
    }
}

/// Emits a trusted event or records an impossible invariant without panicking.
fn record_emit(
    context: &mut OperationContext,
    stage: OperationStage,
    fraction: f64,
    message_key: &'static str,
    failures: &mut FailureAccumulator,
) {
    if let Err(issue) = context.emit(stage, fraction, message_key) {
        failures.record(stage, issue);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Proves a maximum-size retry cannot exhaust the operation event bound.
    #[test]
    fn maximum_transfer_progress_is_deterministically_bounded() {
        let chunk_count =
            crate::firmware::MAX_FIRMWARE_IMAGE_SIZE.div_ceil(crate::firmware::FIRMWARE_CHUNK_SIZE);
        let emitted = (0..chunk_count)
            .filter(|index| should_emit_transfer_progress(*index, chunk_count))
            .count();

        assert!(emitted <= MAX_TRANSFER_PROGRESS_EVENTS_PER_ATTEMPT);
        assert!(should_emit_transfer_progress(chunk_count - 1, chunk_count));
        assert!(2 * emitted + 6 <= super::super::MAX_OPERATION_EVENTS);
    }
}
