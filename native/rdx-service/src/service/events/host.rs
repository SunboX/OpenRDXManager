// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Service-owned host operation lifecycle publication.

use crate::error::{AttemptHistory, CleanupEvidence, ErrorCategory, FailureEvidence, RdxError};
use crate::model::{
    CancellationState, DeviceIdentity, MediaState, MessageKey, OperationEvent, OperationId,
    OperationKind, Progress, ReasonCode, SupportCorrelationId,
};
use crate::operations::{CleanupState, HostOperationFailure, MutationCertainty};
use crate::platform::ValidatedDiscoveryReport;
use crate::transport::DispatchCertainty;

use super::{ServiceEventError, ServiceEventSink, ServiceOperationSignal};
use crate::service::lifecycle::{first_stage, operation_graph};

impl ServiceEventSink {
    /// Queues a safe pre-dispatch cancellation at the first host stage.
    ///
    /// # Errors
    ///
    /// Returns invalid evidence for a non-cancellable host kind, otherwise the
    /// bounded event-channel errors.
    pub(crate) fn publish_host_cancelled(
        &self,
        operation_id: &OperationId,
        kind: OperationKind,
        device: &DeviceIdentity,
    ) -> Result<(), ServiceEventError> {
        if !matches!(
            kind,
            OperationKind::SelfTest
                | OperationKind::LedTest
                | OperationKind::StatusRefresh
                | OperationKind::WriteReadTest
                | OperationKind::FirmwareUpdate
                | OperationKind::Format
                | OperationKind::EjectSafe
        ) {
            return Err(ServiceEventError::InvalidEvidence);
        }
        self.publish_host_cancelled_at(operation_id, kind, device, "queued")
    }

    /// Queues a cancellation at one service-validated currently reached stage.
    pub(crate) fn publish_host_cancelled_at(
        &self,
        operation_id: &OperationId,
        kind: OperationKind,
        device: &DeviceIdentity,
        stage: &str,
    ) -> Result<(), ServiceEventError> {
        if !matches!(
            kind,
            OperationKind::SelfTest
                | OperationKind::LedTest
                | OperationKind::StatusRefresh
                | OperationKind::WriteReadTest
                | OperationKind::FirmwareUpdate
                | OperationKind::Format
                | OperationKind::EjectSafe
        ) {
            return Err(ServiceEventError::InvalidEvidence);
        }
        let stage = ReasonCode::new(stage).map_err(|_| ServiceEventError::InvalidEvidence)?;
        self.publish_signal(ServiceOperationSignal {
            publication_sequence: 0,
            event: OperationEvent::Cancelled {
                operation_id: operation_id.clone(),
                kind,
                device_id: device.id.clone(),
                device_revision: device.revision,
                stage,
                reason: Some(
                    ReasonCode::new("cancelled-by-user")
                        .map_err(|_| ServiceEventError::InvalidEvidence)?,
                ),
                message_key: None,
            },
            failure: None,
            host_failure: None,
            host_operation: true,
            eject_departure: None,
            inventory_update: None,
        })
    }

    /// Queues one causally reached host stage with truthful cancellation state.
    pub(crate) fn publish_host_progress(
        &self,
        operation_id: &OperationId,
        kind: OperationKind,
        device: &DeviceIdentity,
        stage: &str,
        cancellation_state: CancellationState,
    ) -> Result<(), ServiceEventError> {
        let graph = operation_graph(kind)
            .filter(|_| is_host_operation(kind))
            .ok_or(ServiceEventError::InvalidEvidence)?;
        let index = graph
            .iter()
            .position(|candidate| *candidate == stage)
            .ok_or(ServiceEventError::InvalidEvidence)?;
        self.publish_signal(ServiceOperationSignal {
            publication_sequence: 0,
            event: OperationEvent::Progress {
                operation_id: operation_id.clone(),
                kind,
                device_id: device.id.clone(),
                device_revision: device.revision,
                stage: ReasonCode::new(stage).map_err(|_| ServiceEventError::InvalidEvidence)?,
                progress: Progress::new(index as f64 / graph.len().max(1) as f64)
                    .map_err(|_| ServiceEventError::InvalidEvidence)?,
                attempt: None,
                cancellation_state,
                message_key: None,
            },
            failure: None,
            host_failure: None,
            host_operation: true,
            eject_departure: None,
            inventory_update: None,
        })
    }

    /// Queues a started event for a service-owned host state machine.
    ///
    /// # Errors
    ///
    /// Returns invalid evidence for non-host kinds, otherwise bounded queue errors.
    pub(crate) fn publish_host_started(
        &self,
        operation_id: &OperationId,
        kind: OperationKind,
        device: &DeviceIdentity,
    ) -> Result<(), ServiceEventError> {
        if !is_host_operation(kind) {
            return Err(ServiceEventError::InvalidEvidence);
        }
        let stage = ReasonCode::new(first_stage(kind).ok_or(ServiceEventError::InvalidEvidence)?)
            .map_err(|_| ServiceEventError::InvalidEvidence)?;
        self.publish_signal(ServiceOperationSignal {
            publication_sequence: 0,
            event: OperationEvent::Started {
                operation_id: operation_id.clone(),
                kind,
                device_id: device.id.clone(),
                device_revision: device.revision,
                stage,
                message_key: None,
            },
            failure: None,
            host_failure: None,
            host_operation: true,
            eject_departure: None,
            inventory_update: None,
        })
    }

    /// Publishes only a terminal after an observer emitted every reached stage.
    pub(crate) fn publish_host_terminal(
        &self,
        operation_id: &OperationId,
        kind: OperationKind,
        device: &DeviceIdentity,
        terminal_stage: &str,
        result: Result<(), HostOperationFailure>,
    ) -> Result<(), ServiceEventError> {
        self.publish_host_terminal_with_inventory(
            operation_id,
            kind,
            device,
            terminal_stage,
            result,
            None,
        )
    }

    /// Publishes one host terminal with an optional verified post-operation inventory.
    pub(crate) fn publish_host_terminal_with_inventory(
        &self,
        operation_id: &OperationId,
        kind: OperationKind,
        device: &DeviceIdentity,
        terminal_stage: &str,
        result: Result<(), HostOperationFailure>,
        inventory_update: Option<ValidatedDiscoveryReport>,
    ) -> Result<(), ServiceEventError> {
        let graph = operation_graph(kind)
            .filter(|graph| graph.contains(&terminal_stage) && is_host_operation(kind))
            .ok_or(ServiceEventError::InvalidEvidence)?;
        match result {
            Ok(()) if graph.last().copied() == Some(terminal_stage) => {
                self.publish_host_success(operation_id, kind, device, inventory_update)
            }
            Ok(()) => Err(ServiceEventError::InvalidEvidence),
            Err(failure) if inventory_update.is_none() => {
                self.publish_host_failure(operation_id, kind, device, terminal_stage, failure)
            }
            Err(_) => Err(ServiceEventError::InvalidEvidence),
        }
    }

    /// Publishes one graph-complete host success owned by the service.
    fn publish_host_success(
        &self,
        operation_id: &OperationId,
        kind: OperationKind,
        device: &DeviceIdentity,
        inventory_update: Option<ValidatedDiscoveryReport>,
    ) -> Result<(), ServiceEventError> {
        if inventory_update.as_ref().is_some_and(|report| {
            !matches!(
                kind,
                OperationKind::EjectSafe
                    | OperationKind::EjectForce
                    | OperationKind::FirmwareUpdate
            ) || !report.snapshots().iter().any(|snapshot| {
                snapshot.id == device.id
                    && snapshot.media_state == MediaState::NoMedia
                    && snapshot.media.is_none()
            })
        }) {
            return Err(ServiceEventError::InvalidEvidence);
        }
        self.publish_signal(ServiceOperationSignal {
            publication_sequence: 0,
            event: OperationEvent::Succeeded {
                operation_id: operation_id.clone(),
                kind,
                device_id: device.id.clone(),
                device_revision: device.revision,
                stage: ReasonCode::new("complete")
                    .map_err(|_| ServiceEventError::InvalidEvidence)?,
                message_key: None,
            },
            failure: None,
            host_failure: None,
            host_operation: true,
            eject_departure: None,
            inventory_update,
        })
    }

    /// Publishes one host failure while retaining its native certainty for direct clients.
    fn publish_host_failure(
        &self,
        operation_id: &OperationId,
        kind: OperationKind,
        device: &DeviceIdentity,
        terminal_stage: &str,
        failure: HostOperationFailure,
    ) -> Result<(), ServiceEventError> {
        let primary_stage = host_failure_stage(kind, failure.stage());
        let dispatch_certainty = Some(match failure.certainty() {
            MutationCertainty::NotAttempted => DispatchCertainty::NotSent,
            MutationCertainty::DefinitelyRejected => DispatchCertainty::DefinitelyRejected,
            MutationCertainty::CompletionUnknown => DispatchCertainty::CompletionUnknown,
        });
        let cleanup_evidence = if failure.cleanup() == CleanupState::Complete {
            CleanupEvidence::default()
        } else {
            CleanupEvidence::new(vec![
                FailureEvidence::new(
                    ReasonCode::new(terminal_stage)
                        .map_err(|_| ServiceEventError::InvalidEvidence)?,
                    ReasonCode::new("cleanup-incomplete")
                        .map_err(|_| ServiceEventError::InvalidEvidence)?,
                    Some(DispatchCertainty::CompletionUnknown),
                    None,
                )
                .map_err(|_| ServiceEventError::InvalidEvidence)?,
            ])
            .map_err(|_| ServiceEventError::InvalidEvidence)?
        };
        let error = RdxError {
            code: ReasonCode::new(failure.code())
                .map_err(|_| ServiceEventError::InvalidEvidence)?,
            message_key: MessageKey::new("operation.failed")
                .map_err(|_| ServiceEventError::InvalidEvidence)?,
            stage: ReasonCode::new(primary_stage)
                .map_err(|_| ServiceEventError::InvalidEvidence)?,
            category: ErrorCategory::Platform,
            // Not-sent proves no mutation, not that the receiver is ready for replay.
            retryable: failure.certainty() == MutationCertainty::NotAttempted
                && !matches!(
                    failure.code(),
                    "firmware-receiver-readiness-unknown" | "firmware-power-cycle-required"
                ),
            dispatch_certainty,
            sense_summary: None,
            support_correlation_id: SupportCorrelationId::new(format!(
                "support:{}",
                operation_id.as_str()
            ))
            .map_err(|_| ServiceEventError::InvalidEvidence)?,
            cleanup_evidence,
            attempt_history: AttemptHistory::default(),
        };
        self.publish_signal(ServiceOperationSignal {
            publication_sequence: 0,
            event: OperationEvent::Failed {
                operation_id: operation_id.clone(),
                kind,
                device_id: device.id.clone(),
                device_revision: device.revision,
                stage: ReasonCode::new(terminal_stage)
                    .map_err(|_| ServiceEventError::InvalidEvidence)?,
                error,
            },
            failure: None,
            host_failure: Some(failure),
            host_operation: true,
            eject_departure: None,
            inventory_update: None,
        })
    }

    /// Publishes a status success carrying the authoritative inventory it read.
    pub(crate) fn publish_status_success(
        &self,
        operation_id: &OperationId,
        device: &DeviceIdentity,
        report: ValidatedDiscoveryReport,
    ) -> Result<(), ServiceEventError> {
        if !report
            .snapshots()
            .iter()
            .any(|snapshot| snapshot.id == device.id)
        {
            return Err(ServiceEventError::InvalidEvidence);
        }
        self.publish_signal(ServiceOperationSignal {
            publication_sequence: 0,
            event: OperationEvent::Succeeded {
                operation_id: operation_id.clone(),
                kind: OperationKind::StatusRefresh,
                device_id: device.id.clone(),
                device_revision: device.revision,
                stage: ReasonCode::new("complete")
                    .map_err(|_| ServiceEventError::InvalidEvidence)?,
                message_key: None,
            },
            failure: None,
            host_failure: None,
            host_operation: true,
            eject_departure: None,
            inventory_update: Some(report),
        })
    }
}

/// Restricts the direct host lifecycle surface to implemented worker operations.
fn is_host_operation(kind: OperationKind) -> bool {
    matches!(
        kind,
        OperationKind::SelfTest
            | OperationKind::LedTest
            | OperationKind::StatusRefresh
            | OperationKind::WriteReadTest
            | OperationKind::FirmwareUpdate
            | OperationKind::VolumeLabelSet
            | OperationKind::DriveLetterSet
            | OperationKind::DriveLetterReset
            | OperationKind::Format
            | OperationKind::DriveModeSet
            | OperationKind::SataModeSet
            | OperationKind::EjectSafe
            | OperationKind::EjectForce
    )
}

/// Maps private host state-machine stages into the fixed public lifecycle graph.
fn host_failure_stage(kind: OperationKind, stage: &str) -> &'static str {
    match kind {
        OperationKind::SelfTest => match stage {
            "diagnostic-cleanup" => "diagnostic-cleanup",
            _ => "diagnostic-running",
        },
        OperationKind::LedTest => match stage {
            "led-restoring" => "led-restoring",
            "led-readback" => "led-readback",
            _ => "led-testing",
        },
        OperationKind::StatusRefresh => "status-reading",
        OperationKind::WriteReadTest => match stage {
            "cleanup" => "host-cleanup",
            "compare" => "host-reading",
            _ => "host-writing",
        },
        OperationKind::VolumeLabelSet
        | OperationKind::DriveLetterSet
        | OperationKind::DriveLetterReset => {
            if stage == "preflight" {
                "host-volume-changing"
            } else {
                "host-volume-readback"
            }
        }
        OperationKind::Format => match stage {
            "confirmation" | "preflight" | "unmount" | "format-validating" => "format-validating",
            "layout" => "format-writing",
            "format" => "format-finalizing",
            _ => "format-readback",
        },
        OperationKind::DriveModeSet | OperationKind::SataModeSet => match stage {
            "device-reconnecting" => "device-reconnecting",
            "device-readback" => "device-readback",
            _ => "device-configuring",
        },
        OperationKind::FirmwareUpdate => match stage {
            "firmware-capturing" => "firmware-capturing",
            "firmware-compatibility-setup" => "firmware-compatibility-setup",
            "firmware-staging" => "firmware-staging",
            "firmware-awaiting-bootloader" => "firmware-awaiting-bootloader",
            "firmware-programming-bootstrap" => "firmware-programming-bootstrap",
            "firmware-awaiting-bootstrap" => "firmware-awaiting-bootstrap",
            "firmware-restoring-identity" => "firmware-restoring-identity",
            "firmware-writing" => "firmware-writing",
            "firmware-finalizing" => "firmware-finalizing",
            "device-reconnecting" => "device-reconnecting",
            "firmware-readback" => "firmware-readback",
            _ => "firmware-validating",
        },
        OperationKind::EjectSafe => match stage {
            "preflight" | "unmount" => "host-unmounting",
            "eject-readback" => "eject-readback",
            _ => "host-ejecting",
        },
        OperationKind::EjectForce if stage == "eject-readback" => "eject-readback",
        OperationKind::EjectForce => "host-ejecting",
        _ => "queued",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Finishing cleanup must not rewrite the stage where self-test actually failed.
    #[test]
    fn self_test_failure_stage_retains_primary_cause() {
        assert_eq!(
            host_failure_stage(OperationKind::SelfTest, "diagnostic-running"),
            "diagnostic-running"
        );
        assert_eq!(
            host_failure_stage(OperationKind::SelfTest, "diagnostic-cleanup"),
            "diagnostic-cleanup"
        );
        assert_eq!(
            host_failure_stage(OperationKind::SelfTest, "preflight"),
            "diagnostic-running"
        );
    }
}
