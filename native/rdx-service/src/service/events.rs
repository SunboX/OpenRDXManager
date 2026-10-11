// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Bounded operation-event channel and typed failure-evidence binding.

use std::sync::mpsc::{SyncSender, TrySendError};
use std::sync::{Arc, Mutex};

use crate::error::{
    AttemptEvidence, AttemptHistory, CleanupEvidence, ErrorCategory, FailureEvidence, RdxError,
    SenseSummary,
};
use crate::host::HostOperationError;
use crate::model::{
    MessageKey, OperationAttempt, OperationEvent, OperationKind, ReasonCode, SupportCorrelationId,
};
use crate::operations::{
    HostOperationFailure, OperationCompletion, OperationFailure, OperationFailureEvidence,
    OperationIssue, OperationOwner, OperationProgressEvent, OperationReport, OperationStage,
    VerifiedEjectDeparture,
};
use crate::platform::ValidatedDiscoveryReport;
use crate::transport::{DispatchCertainty, TransportError};

use super::crash::CrashAdmission;
use super::lifecycle::{first_stage, is_cancel_terminal};

mod host;

/// Stable failure from publishing into the bounded service event queue.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServiceEventError {
    /// The fixed pending-event capacity has already been reached.
    Saturated,
    /// The service loop has ended and cannot accept another event.
    Disconnected,
    /// A failed event did not match its typed native operation evidence.
    InvalidEvidence,
}

/// One public lifecycle event plus optional native failure evidence.
#[derive(Debug)]
pub(super) struct ServiceOperationSignal {
    pub(super) publication_sequence: u64,
    pub(super) event: OperationEvent,
    pub(super) failure: Option<OperationFailure>,
    pub(super) host_failure: Option<HostOperationFailure>,
    pub(super) host_operation: bool,
    pub(super) eject_departure: Option<VerifiedEjectDeparture>,
    pub(super) inventory_update: Option<ValidatedDiscoveryReport>,
}

/// Cloneable bounded event capability passed only to an accepted backend operation.
#[derive(Clone, Debug)]
pub struct ServiceEventSink {
    event_sender: SyncSender<Box<ServiceOperationSignal>>,
    crash_admission: CrashAdmission,
    publication_sequence: Arc<Mutex<u64>>,
}

impl ServiceEventSink {
    /// Creates an event capability around one bounded generation channel.
    pub(super) fn new(
        event_sender: SyncSender<Box<ServiceOperationSignal>>,
        crash_admission: CrashAdmission,
    ) -> Self {
        Self {
            event_sender,
            crash_admission,
            publication_sequence: Arc::new(Mutex::new(0)),
        }
    }

    /// Queues a started event derived only from an exact native reservation.
    ///
    /// # Errors
    ///
    /// Returns [`ServiceEventError::InvalidEvidence`] when the operation kind
    /// has no native stage graph, otherwise the fixed bounded queue errors.
    pub fn publish_started(&self, owner: &OperationOwner) -> Result<(), ServiceEventError> {
        let stage =
            ReasonCode::new(first_stage(owner.kind()).ok_or(ServiceEventError::InvalidEvidence)?)
                .map_err(|_| ServiceEventError::InvalidEvidence)?;
        self.publish_signal(ServiceOperationSignal {
            publication_sequence: 0,
            event: OperationEvent::Started {
                operation_id: owner.operation_id().clone(),
                kind: owner.kind(),
                device_id: owner.device().id.clone(),
                device_revision: owner.device().revision,
                stage,
                message_key: None,
            },
            failure: None,
            host_failure: None,
            host_operation: false,
            eject_departure: None,
            inventory_update: None,
        })
    }

    /// Queues one owner-derived native progress event without replay or caller fields.
    ///
    /// # Errors
    ///
    /// Returns [`ServiceEventError::InvalidEvidence`] only if an internally
    /// validated native stage or attempt cannot enter the strict service model,
    /// otherwise the same bounded queue errors as [`Self::publish_started`].
    pub fn publish_progress(
        &self,
        progress: &OperationProgressEvent,
    ) -> Result<(), ServiceEventError> {
        let owner = progress.owner();
        let stage = ReasonCode::new(progress.stage().as_str())
            .map_err(|_| ServiceEventError::InvalidEvidence)?;
        let attempt = progress
            .attempt()
            .map(OperationAttempt::new)
            .transpose()
            .map_err(|_| ServiceEventError::InvalidEvidence)?;
        self.publish_signal(ServiceOperationSignal {
            publication_sequence: 0,
            event: OperationEvent::Progress {
                operation_id: owner.operation_id().clone(),
                kind: owner.kind(),
                device_id: owner.device().id.clone(),
                device_revision: owner.device().revision,
                stage,
                progress: progress.fraction(),
                attempt,
                cancellation_state: progress.cancellation_state(),
                message_key: Some(progress.message_key().clone()),
            },
            failure: None,
            host_failure: None,
            host_operation: false,
            eject_departure: None,
            inventory_update: None,
        })
    }

    /// Queues a non-eject success or safe cancellation derived from a native report.
    ///
    /// Eject success requires [`Self::publish_eject_success`] because an
    /// ordinary success report does not prove exact-target departure.
    ///
    /// # Errors
    ///
    /// Returns [`ServiceEventError::InvalidEvidence`] for an empty or unsafe
    /// cancellation report or an eject success without departure proof,
    /// otherwise the fixed bounded queue errors.
    pub fn publish_report(&self, report: OperationReport) -> Result<(), ServiceEventError> {
        let event = report_event(&report)?;
        self.publish_signal(ServiceOperationSignal {
            publication_sequence: 0,
            event,
            failure: None,
            host_failure: None,
            host_operation: false,
            eject_departure: None,
            inventory_update: None,
        })
    }

    /// Queues an eject-success terminal only with exact departure evidence.
    ///
    /// # Errors
    ///
    /// Returns [`ServiceEventError::InvalidEvidence`] unless the terminal's
    /// operation, kind, device, and revision exactly match the unforgeable
    /// capability returned by the shared eject state machine.
    pub fn publish_eject_success(
        &self,
        report: OperationReport,
        departure: VerifiedEjectDeparture,
    ) -> Result<(), ServiceEventError> {
        if report.completion() != OperationCompletion::Succeeded
            || !matches!(
                report.owner().kind(),
                OperationKind::EjectSafe | OperationKind::EjectForce
            )
            || report.owner() != departure.owner()
            || departure.policy().operation_kind() != report.owner().kind()
            || report.events().last().map(OperationProgressEvent::stage)
                != Some(OperationStage::EjectReadback)
        {
            return Err(ServiceEventError::InvalidEvidence);
        }
        let event = success_event(&report)?;
        if !eject_departure_matches(&event, &departure) {
            return Err(ServiceEventError::InvalidEvidence);
        }
        self.publish_signal(ServiceOperationSignal {
            publication_sequence: 0,
            event,
            failure: None,
            host_failure: None,
            host_operation: false,
            eject_departure: Some(departure),
            inventory_update: None,
        })
    }

    /// Queues one failed terminal canonically derived from native operation evidence.
    ///
    /// # Errors
    ///
    /// Returns [`ServiceEventError::InvalidEvidence`] only if trusted native
    /// evidence cannot fit the strict renderer-safe contract, otherwise the
    /// fixed bounded queue errors.
    pub fn publish_failure(&self, failure: OperationFailure) -> Result<(), ServiceEventError> {
        let event = failure_event(&failure)?;
        self.publish_signal(ServiceOperationSignal {
            publication_sequence: 0,
            event,
            failure: Some(failure),
            host_failure: None,
            host_operation: false,
            eject_departure: None,
            inventory_update: None,
        })
    }

    /// Queues one already validated internal operation signal without blocking.
    fn publish_signal(&self, mut signal: ServiceOperationSignal) -> Result<(), ServiceEventError> {
        let mut publication_sequence = self
            .publication_sequence
            .lock()
            .map_err(|_| ServiceEventError::Disconnected)?;
        let next_sequence = publication_sequence
            .checked_add(1)
            .filter(|sequence| *sequence <= super::MAX_SAFE_JSON_INTEGER)
            .ok_or(ServiceEventError::InvalidEvidence)?;
        signal.publication_sequence = next_sequence;
        match self.event_sender.try_send(Box::new(signal)) {
            Ok(()) => {
                *publication_sequence = next_sequence;
                Ok(())
            }
            Err(TrySendError::Full(_)) => Err(ServiceEventError::Saturated),
            Err(TrySendError::Disconnected(_)) => Err(ServiceEventError::Disconnected),
        }
    }

    /// Captures the last FIFO publication included before a cancellation acknowledgement.
    ///
    /// The same mutex linearizes every successful publication, so cloned
    /// adapters cannot enqueue a causally later event inside this prefix.
    pub(super) fn cancellation_cutover(&self) -> Result<u64, ServiceEventError> {
        self.publication_sequence
            .lock()
            .map(|sequence| *sequence)
            .map_err(|_| ServiceEventError::Disconnected)
    }

    /// Reports an unreconciled backend failure without serializing diagnostics.
    ///
    /// # Errors
    ///
    /// The dedicated atomic control path is independent from event saturation;
    /// repeated crash reports coalesce. Reports after generation closure fail.
    /// The service exits without an ordinary operation terminal so Electron
    /// preserves active-operation ambiguity.
    pub fn report_crash(&self) -> Result<(), ServiceEventError> {
        self.crash_admission.report()
    }
}

/// Derives a non-eject success or exact safe-cancellation terminal.
fn report_event(report: &OperationReport) -> Result<OperationEvent, ServiceEventError> {
    match report.completion() {
        OperationCompletion::Succeeded
            if !matches!(
                report.owner().kind(),
                OperationKind::EjectSafe | OperationKind::EjectForce
            ) =>
        {
            success_event(report)
        }
        OperationCompletion::Succeeded => Err(ServiceEventError::InvalidEvidence),
        OperationCompletion::Cancelled => cancellation_event(report),
    }
}

/// Derives one success terminal from a complete native report owner.
fn success_event(report: &OperationReport) -> Result<OperationEvent, ServiceEventError> {
    let last = report
        .events()
        .last()
        .ok_or(ServiceEventError::InvalidEvidence)?;
    let owner = report.owner();
    if last.owner() != owner {
        return Err(ServiceEventError::InvalidEvidence);
    }
    Ok(OperationEvent::Succeeded {
        operation_id: owner.operation_id().clone(),
        kind: owner.kind(),
        device_id: owner.device().id.clone(),
        device_revision: owner.device().revision,
        stage: ReasonCode::new("complete").map_err(|_| ServiceEventError::InvalidEvidence)?,
        message_key: Some(last.message_key().clone()),
    })
}

/// Derives one cancellation terminal only from a state-machine-proven safe stage.
fn cancellation_event(report: &OperationReport) -> Result<OperationEvent, ServiceEventError> {
    let last = report
        .events()
        .last()
        .ok_or(ServiceEventError::InvalidEvidence)?;
    let owner = report.owner();
    if last.owner() != owner || !is_cancel_terminal(owner.kind(), last.stage().as_str()) {
        return Err(ServiceEventError::InvalidEvidence);
    }
    Ok(OperationEvent::Cancelled {
        operation_id: owner.operation_id().clone(),
        kind: owner.kind(),
        device_id: owner.device().id.clone(),
        device_revision: owner.device().revision,
        stage: ReasonCode::new(last.stage().as_str())
            .map_err(|_| ServiceEventError::InvalidEvidence)?,
        reason: Some(
            ReasonCode::new("cancelled-by-user").map_err(|_| ServiceEventError::InvalidEvidence)?,
        ),
        message_key: Some(last.message_key().clone()),
    })
}

/// Canonically derives one complete renderer-safe failed terminal.
fn failure_event(failure: &OperationFailure) -> Result<OperationEvent, ServiceEventError> {
    let owner = failure.owner();
    let primary = failure.primary();
    let summary = issue_summary(primary.issue());
    let cleanup = failure
        .cleanup()
        .iter()
        .map(failure_evidence)
        .collect::<Result<Vec<_>, _>>()?;
    let attempt_history = failure
        .attempt_history()
        .iter()
        .map(|attempt| {
            AttemptEvidence::new(
                attempt.attempt(),
                failure_evidence_from_parts(attempt.stage(), attempt.issue())?,
            )
            .map_err(|_| ServiceEventError::InvalidEvidence)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let error = RdxError {
        code: reason(&summary.code)?,
        message_key: MessageKey::new("errors.native.operation")
            .map_err(|_| ServiceEventError::InvalidEvidence)?,
        stage: reason(primary.stage().as_str())?,
        category: summary.category,
        retryable: false,
        dispatch_certainty: summary.dispatch_certainty,
        sense_summary: summary.sense_summary,
        support_correlation_id: SupportCorrelationId::new(format!(
            "support:{}",
            owner.operation_id().as_str()
        ))
        .map_err(|_| ServiceEventError::InvalidEvidence)?,
        cleanup_evidence: CleanupEvidence::new(cleanup)
            .map_err(|_| ServiceEventError::InvalidEvidence)?,
        attempt_history: AttemptHistory::new(attempt_history)
            .map_err(|_| ServiceEventError::InvalidEvidence)?,
    };
    Ok(OperationEvent::Failed {
        operation_id: owner.operation_id().clone(),
        kind: owner.kind(),
        device_id: owner.device().id.clone(),
        device_revision: owner.device().revision,
        stage: reason(failure.terminal_stage().as_str())?,
        error,
    })
}

/// Converts one native observation without losing certainty or safe sense.
fn failure_evidence(
    evidence: &OperationFailureEvidence,
) -> Result<FailureEvidence, ServiceEventError> {
    failure_evidence_from_parts(evidence.stage(), evidence.issue())
}

/// Converts one exact native stage and issue into flat renderer evidence.
fn failure_evidence_from_parts(
    stage: OperationStage,
    issue: &OperationIssue,
) -> Result<FailureEvidence, ServiceEventError> {
    let summary = issue_summary(issue);
    FailureEvidence::new(
        reason(stage.as_str())?,
        reason(&summary.code)?,
        summary.dispatch_certainty,
        summary.sense_summary,
    )
    .map_err(|_| ServiceEventError::InvalidEvidence)
}

/// Fully safe classification derived from one closed native issue enum.
struct IssueSummary {
    code: String,
    category: ErrorCategory,
    dispatch_certainty: Option<DispatchCertainty>,
    sense_summary: Option<SenseSummary>,
}

/// Maps a native issue to stable path-free renderer truth.
fn issue_summary(issue: &OperationIssue) -> IssueSummary {
    let (code, category) = match issue {
        OperationIssue::Dispatch {
            certainty: DispatchCertainty::CompletionUnknown,
            ..
        }
        | OperationIssue::PostMutationRebind(_)
        | OperationIssue::EjectDispatchContradiction => {
            ("operation-outcome-unknown", ErrorCategory::Transport)
        }
        OperationIssue::Dispatch {
            error: TransportError::CheckCondition(sense),
            ..
        } => (sense.code(), ErrorCategory::Transport),
        OperationIssue::Dispatch {
            error: TransportError::CompatibilityStagingSignature,
            ..
        } => ("firmware-signature-error", ErrorCategory::Transport),
        OperationIssue::Dispatch {
            error: TransportError::Timeout,
            ..
        } => ("transport-timeout", ErrorCategory::Transport),
        OperationIssue::Dispatch {
            error: TransportError::Unavailable,
            ..
        } => ("transport-unavailable", ErrorCategory::Transport),
        OperationIssue::Dispatch {
            error: TransportError::DeviceRemoved,
            ..
        } => ("device-removed", ErrorCategory::Transport),
        OperationIssue::Dispatch {
            error: TransportError::DataOutIncomplete,
            ..
        } => ("transport-data-out-incomplete", ErrorCategory::Transport),
        OperationIssue::Dispatch {
            error: TransportError::ResponseTooLarge { .. },
            ..
        } => ("transport-response-too-large", ErrorCategory::Transport),
        OperationIssue::Dispatch {
            error: TransportError::MissingFixtureResponse,
            ..
        } => ("transport-response-missing", ErrorCategory::Transport),
        OperationIssue::Dispatch {
            error: TransportError::AdapterPanic,
            ..
        } => ("transport-adapter-failure", ErrorCategory::Transport),
        OperationIssue::Dispatch {
            error: TransportError::InactiveSession,
            ..
        } => ("inactive-session", ErrorCategory::Transport),
        OperationIssue::Host(HostOperationError::CapabilityUnavailable) => {
            ("host-dependency-missing", ErrorCategory::Platform)
        }
        OperationIssue::Host(HostOperationError::DeviceUnavailable) => {
            ("device-unavailable", ErrorCategory::Platform)
        }
        OperationIssue::Host(HostOperationError::ReconnectTimeout) => {
            ("device-reconnect-timeout", ErrorCategory::Transport)
        }
        OperationIssue::Host(HostOperationError::Ambiguous) => {
            ("operation-outcome-unknown", ErrorCategory::Transport)
        }
        OperationIssue::Host(HostOperationError::DeviceIdentityChanged) => {
            ("device-identity-changed", ErrorCategory::Transport)
        }
        OperationIssue::Host(HostOperationError::ProductFamilyChanged) => {
            ("product-family-changed", ErrorCategory::Transport)
        }
        OperationIssue::Host(HostOperationError::StaleSessionGeneration) => {
            ("stale-session-generation", ErrorCategory::Transport)
        }
        OperationIssue::Host(HostOperationError::InactiveSession) => {
            ("inactive-session", ErrorCategory::Platform)
        }
        OperationIssue::Host(HostOperationError::AdapterPanic) => {
            ("host-adapter-failure", ErrorCategory::Transport)
        }
        OperationIssue::Host(HostOperationError::RecoveryAlreadyArmed) => {
            ("recovery-already-armed", ErrorCategory::Platform)
        }
        OperationIssue::WrongOperationKind { .. } => {
            ("operation-kind-mismatch", ErrorCategory::Platform)
        }
        OperationIssue::ProtocolBuild(_) => ("protocol-build-failure", ErrorCategory::Transport),
        OperationIssue::ProtocolParse(_) => ("protocol-response-invalid", ErrorCategory::Transport),
        OperationIssue::DeviceIdentityChanged => {
            ("device-identity-changed", ErrorCategory::Transport)
        }
        OperationIssue::SessionBindingChanged => {
            ("session-binding-changed", ErrorCategory::Transport)
        }
        OperationIssue::ProductFamilyMismatch => {
            ("product-family-mismatch", ErrorCategory::Platform)
        }
        OperationIssue::MediaPresent | OperationIssue::MediaMissing => {
            ("wrong-media-state", ErrorCategory::Platform)
        }
        OperationIssue::UnsupportedInterface => ("unsupported-interface", ErrorCategory::Platform),
        OperationIssue::FirmwareAuthorizationRejected { .. } => {
            ("firmware-authorization-rejected", ErrorCategory::Platform)
        }
        OperationIssue::FirmwareAuthorizationInvalidated => (
            "firmware-authorization-invalidated",
            ErrorCategory::Platform,
        ),
        OperationIssue::FirmwareRevisionMismatch { .. } => {
            ("firmware-revision-mismatch", ErrorCategory::Transport)
        }
        OperationIssue::ModeReadbackMismatch { .. } => {
            ("mode-readback-mismatch", ErrorCategory::Transport)
        }
        OperationIssue::EjectTargetPresent => {
            ("eject-readback-unverified", ErrorCategory::Transport)
        }
        OperationIssue::EventInvariant => ("operation-event-invariant", ErrorCategory::Transport),
        OperationIssue::ProgressPublication => {
            ("progress-publication-failure", ErrorCategory::Transport)
        }
    };
    let dispatch_certainty = match issue {
        OperationIssue::Dispatch { certainty, .. } => Some(*certainty),
        _ => None,
    };
    let sense_summary = match issue {
        OperationIssue::Dispatch {
            error: TransportError::CompatibilityStagingSignature,
            ..
        } => Some(SenseSummary {
            key: ReasonCode::new("firmware-signature-error").expect("trusted sense code is valid"),
            asc: Some(0x74),
            ascq: Some(0x08),
            message_key: MessageKey::new("errors.transport.scsi")
                .expect("trusted sense message key is valid"),
        }),
        OperationIssue::Dispatch {
            error: TransportError::CheckCondition(sense),
            ..
        } => Some(SenseSummary {
            key: ReasonCode::new(sense.code()).expect("trusted sense code is valid"),
            asc: Some(sense.asc()),
            ascq: Some(sense.ascq()),
            message_key: MessageKey::new("errors.transport.scsi")
                .expect("trusted sense message key is valid"),
        }),
        _ => None,
    };
    IssueSummary {
        code: code.to_owned(),
        category,
        dispatch_certainty,
        sense_summary,
    }
}

/// Creates one bounded reason from trusted closed-enum mapping output.
fn reason(value: &str) -> Result<ReasonCode, ServiceEventError> {
    ReasonCode::new(value).map_err(|_| ServiceEventError::InvalidEvidence)
}

/// Checks that one shared-state-machine capability owns the proposed terminal.
pub(super) fn eject_departure_matches(
    event: &OperationEvent,
    departure: &VerifiedEjectDeparture,
) -> bool {
    let OperationEvent::Succeeded {
        operation_id,
        kind,
        device_id,
        device_revision,
        ..
    } = event
    else {
        return false;
    };
    let owner = departure.owner();
    departure.policy().operation_kind() == *kind
        && owner.operation_id() == operation_id
        && owner.kind() == *kind
        && owner.device().id == *device_id
        && owner.device().revision == *device_revision
}

#[cfg(test)]
mod tests {
    use std::sync::mpsc;

    use serde_json::json;

    use crate::firmware::{FirmwareRevision, ProductFamily};
    use crate::host::{
        DeviceInterface, FixtureDevice, HostOperationError, SessionDevice, SessionGeneration,
    };
    use crate::model::{DeviceId, DeviceIdentity, DiscoveryRevision, OperationId, OperationKind};
    use crate::operations::{
        CancellationRequestResult, FailureAccumulator, OperationCompletion, OperationContext,
        OperationIssue, OperationStage,
    };
    use crate::protocol::SenseData;
    use crate::transport::{DispatchCertainty, TransportError};

    use super::{ServiceEventError, ServiceEventSink};
    use crate::service::crash::CrashAdmission;

    /// Creates one exact fixture-owned operation context.
    fn context(kind: OperationKind, suffix: &str) -> (FixtureDevice, OperationContext) {
        let fixture = FixtureDevice::new(SessionDevice::fixture(
            DeviceIdentity {
                id: DeviceId::new("rdx:service-proof").unwrap(),
                revision: DiscoveryRevision::new(7).unwrap(),
            },
            ProductFamily::Usb3Sata3,
            FirmwareRevision::new(283).unwrap(),
            DeviceInterface::Usb3,
            false,
            SessionGeneration::new(41).unwrap(),
        ));
        let session = fixture.open();
        let context = OperationContext::for_session(
            OperationId::new(format!("op:{suffix}")).unwrap(),
            kind,
            &session,
        )
        .unwrap();
        (fixture, context)
    }

    /// Creates one sink and returns its private proof-bearing signal receiver.
    fn sink() -> (
        ServiceEventSink,
        mpsc::Receiver<Box<super::ServiceOperationSignal>>,
    ) {
        let (sender, receiver) = mpsc::sync_channel(8);
        (
            ServiceEventSink::new(sender, CrashAdmission::new()),
            receiver,
        )
    }

    /// Proves one generation emits an exact started/progress/terminal sequence
    /// that continues across operation reservations without gaps or reuse.
    #[test]
    fn publication_sequence_is_exact_across_operation_terminals() {
        let (sink, receiver) = sink();
        for suffix in ["sequence-first", "sequence-second"] {
            let (_, mut operation) = context(OperationKind::SelfTest, suffix);
            sink.publish_started(operation.owner()).unwrap();
            operation
                .emit_causally(
                    OperationStage::DiagnosticRunning,
                    0.5,
                    "operations.selfTest.running",
                    &mut |event| sink.publish_progress(event),
                )
                .unwrap();
            operation
                .emit_causally(
                    OperationStage::DiagnosticCleanup,
                    1.0,
                    "operations.selfTest.cleanup",
                    &mut |event| sink.publish_progress(event),
                )
                .unwrap();
            sink.publish_report(operation.complete(OperationCompletion::Succeeded))
                .unwrap();
        }

        let signals = (0..8).map(|_| receiver.recv().unwrap()).collect::<Vec<_>>();
        assert_eq!(
            signals
                .iter()
                .map(|signal| signal.publication_sequence)
                .collect::<Vec<_>>(),
            (1..=8).collect::<Vec<_>>()
        );
        assert_eq!(
            signals
                .iter()
                .map(|signal| serde_json::to_value(&signal.event).unwrap()["state"].clone())
                .collect::<Vec<_>>(),
            [
                json!("started"),
                json!("progress"),
                json!("progress"),
                json!("succeeded"),
                json!("started"),
                json!("progress"),
                json!("progress"),
                json!("succeeded"),
            ]
        );
        assert_eq!(sink.cancellation_cutover().unwrap(), 8);
    }

    /// Proves success and safe cancellation terminals are derived from reports.
    #[test]
    fn reports_derive_non_eject_success_and_safe_cancellation_truth() {
        let (sink, receiver) = sink();
        let (_, mut success) = context(OperationKind::SelfTest, "report-success");
        success
            .emit(
                OperationStage::DiagnosticRunning,
                0.5,
                "operations.selfTest.running",
            )
            .unwrap();
        success
            .emit(
                OperationStage::DiagnosticCleanup,
                1.0,
                "operations.selfTest.cleanup",
            )
            .unwrap();
        sink.publish_report(success.complete(OperationCompletion::Succeeded))
            .unwrap();

        let (_, mut cancelled) = context(OperationKind::SelfTest, "report-cancelled");
        cancelled
            .emit(
                OperationStage::DiagnosticRunning,
                0.25,
                "operations.selfTest.running",
            )
            .unwrap();
        let owner = cancelled.owner().clone();
        assert_eq!(
            cancelled.cancellation_handle().request(&owner),
            CancellationRequestResult::Accepted
        );
        cancelled
            .emit(
                OperationStage::DiagnosticCleanup,
                1.0,
                "operations.selfTest.cleanup",
            )
            .unwrap();
        sink.publish_report(cancelled.complete(OperationCompletion::Cancelled))
            .unwrap();

        let (_, mut late_cancelled) = context(OperationKind::SelfTest, "report-late-cancelled");
        late_cancelled
            .emit(
                OperationStage::DiagnosticRunning,
                0.25,
                "operations.selfTest.running",
            )
            .unwrap();
        late_cancelled
            .emit(
                OperationStage::DiagnosticCleanup,
                1.0,
                "operations.selfTest.cleanup",
            )
            .unwrap();
        let owner = late_cancelled.owner().clone();
        assert_eq!(
            late_cancelled.cancellation_handle().request(&owner),
            CancellationRequestResult::Accepted
        );
        sink.publish_report(late_cancelled.complete(OperationCompletion::Cancelled))
            .unwrap();

        let success = receiver.recv().unwrap().event;
        let cancelled = receiver.recv().unwrap().event;
        let late_cancelled = receiver.recv().unwrap().event;
        assert_eq!(
            serde_json::to_value(success).unwrap(),
            json!({
                "state": "succeeded",
                "operationId": "op:report-success",
                "kind": "self-test",
                "deviceId": "rdx:service-proof",
                "deviceRevision": 7,
                "stage": "complete",
                "messageKey": "operations.selfTest.cleanup"
            })
        );
        assert_eq!(
            serde_json::to_value(cancelled).unwrap(),
            json!({
                "state": "cancelled",
                "operationId": "op:report-cancelled",
                "kind": "self-test",
                "deviceId": "rdx:service-proof",
                "deviceRevision": 7,
                "stage": "diagnostic-cleanup",
                "reason": "cancelled-by-user",
                "messageKey": "operations.selfTest.cleanup"
            })
        );
        assert!(matches!(
            late_cancelled,
            crate::model::OperationEvent::Cancelled { .. }
        ));
    }

    /// Proves every renderer failure field is canonical native evidence.
    #[test]
    fn failure_derivation_preserves_primary_cleanup_attempt_sense_and_certainty() {
        let (sink, receiver) = sink();
        let (_, mut context) = context(OperationKind::FirmwareUpdate, "canonical-failure");
        context
            .emit(
                OperationStage::FirmwareValidating,
                0.0,
                "operations.firmwareUpdate.validating",
            )
            .unwrap();
        context
            .emit_attempt(
                OperationStage::FirmwareWriting,
                0.25,
                "operations.firmwareUpdate.writing",
                1,
            )
            .unwrap();
        context
            .emit(
                OperationStage::FirmwareFinalizing,
                0.75,
                "operations.firmwareUpdate.finalizing",
            )
            .unwrap();
        context
            .emit(
                OperationStage::DeviceReconnecting,
                0.9,
                "operations.firmwareUpdate.reconnecting",
            )
            .unwrap();
        context
            .emit(
                OperationStage::FirmwareReadback,
                1.0,
                "operations.firmwareUpdate.readback",
            )
            .unwrap();

        let sense = SenseData::parse(&[
            0x70, 0, 0x05, 0, 0, 0, 0, 10, 0, 0, 0, 0, 0x24, 0, 0, 0, 0, 0,
        ])
        .unwrap();
        let mut failures = FailureAccumulator::default();
        failures.record_attempt(
            1,
            OperationStage::FirmwareWriting,
            OperationIssue::Dispatch {
                certainty: DispatchCertainty::NotSent,
                error: TransportError::Timeout,
            },
        );
        failures.record(
            OperationStage::FirmwareFinalizing,
            OperationIssue::Dispatch {
                certainty: DispatchCertainty::DefinitelyRejected,
                error: TransportError::CheckCondition(sense),
            },
        );
        failures.record(
            OperationStage::FirmwareReadback,
            OperationIssue::Host(HostOperationError::CapabilityUnavailable),
        );

        sink.publish_failure(context.fail(failures)).unwrap();
        let signal = receiver.recv().unwrap();
        assert!(signal.failure.is_some());
        assert_eq!(
            serde_json::to_value(signal.event).unwrap(),
            json!({
                "state": "failed",
                "operationId": "op:canonical-failure",
                "kind": "firmware-update",
                "deviceId": "rdx:service-proof",
                "deviceRevision": 7,
                "stage": "firmware-readback",
                "error": {
                    "code": "scsi-check-condition",
                    "messageKey": "errors.native.operation",
                    "stage": "firmware-finalizing",
                    "category": "transport",
                    "retryable": false,
                    "dispatchCertainty": "definitely-rejected",
                    "senseSummary": {
                        "key": "scsi-check-condition",
                        "asc": 36,
                        "ascq": 0,
                        "messageKey": "errors.transport.scsi"
                    },
                    "supportCorrelationId": "support:op:canonical-failure",
                    "cleanupEvidence": [{
                        "stage": "firmware-readback",
                        "code": "host-dependency-missing"
                    }],
                    "attemptHistory": [{
                        "attempt": 1,
                        "stage": "firmware-writing",
                        "code": "transport-timeout",
                        "dispatchCertainty": "not-sent"
                    }]
                }
            })
        );
    }

    /// Typed staging evidence retains uncertainty and only the fixed safe sense summary.
    #[test]
    fn compatibility_staging_signature_is_sanitized_without_claiming_completion() {
        let summary = super::issue_summary(&OperationIssue::Dispatch {
            certainty: DispatchCertainty::CompletionUnknown,
            error: TransportError::CompatibilityStagingSignature,
        });
        assert_eq!(summary.code, "operation-outcome-unknown");
        assert_eq!(
            summary.dispatch_certainty,
            Some(DispatchCertainty::CompletionUnknown)
        );
        let sense = summary.sense_summary.unwrap();
        assert_eq!(sense.key.as_str(), "firmware-signature-error");
        assert_eq!(sense.asc, Some(0x74));
        assert_eq!(sense.ascq, Some(8));
        assert_eq!(sense.message_key.as_str(), "errors.transport.scsi");
    }

    /// Proves an ordinary report cannot substitute for eject departure proof.
    #[test]
    fn eject_success_report_without_departure_proof_is_rejected() {
        let (sink, _receiver) = sink();
        let (_, mut context) = context(OperationKind::EjectSafe, "eject-forged");
        context
            .emit(
                OperationStage::HostUnmounting,
                0.25,
                "operations.eject.unmounting",
            )
            .unwrap();
        context
            .emit(
                OperationStage::HostEjecting,
                0.75,
                "operations.eject.ejecting",
            )
            .unwrap();
        context
            .emit(
                OperationStage::EjectReadback,
                1.0,
                "operations.eject.readback",
            )
            .unwrap();

        assert_eq!(
            sink.publish_report(context.complete(OperationCompletion::Succeeded)),
            Err(ServiceEventError::InvalidEvidence)
        );
    }
}
