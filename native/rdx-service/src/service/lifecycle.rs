// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Exact native mirror of the main-process operation lifecycle policy.

use super::{ActiveOperation, OperationPhase, ServiceProtocolError};
use crate::model::{
    CancellationState, DeviceId, DiscoveryRevision, OperationEvent, OperationId, OperationKind,
};

/// Returns the complete Phase 1 coordinator stage graph for one native request.
pub(super) fn operation_graph(kind: OperationKind) -> Option<&'static [&'static str]> {
    match kind {
        OperationKind::Scan => None,
        OperationKind::StatusRefresh => Some(&["status-reading"]),
        OperationKind::AccessEnable | OperationKind::AccessDisable => {
            Some(&["access-changing", "access-readback"])
        }
        OperationKind::CredentialCreate
        | OperationKind::CredentialChange
        | OperationKind::CredentialDelete
        | OperationKind::CredentialReset
        | OperationKind::CredentialConfigure => Some(&[
            "credential-validating",
            "credential-writing",
            "credential-readback",
        ]),
        OperationKind::SelfTest => Some(&["diagnostic-running", "diagnostic-cleanup"]),
        OperationKind::LedTest => Some(&["led-testing", "led-restoring", "led-readback"]),
        OperationKind::WriteReadTest => Some(&["host-writing", "host-reading", "host-cleanup"]),
        OperationKind::FirmwareUpdate => Some(&[
            "firmware-validating",
            "firmware-capturing",
            "firmware-compatibility-setup",
            "firmware-staging",
            "firmware-awaiting-bootloader",
            "firmware-programming-bootstrap",
            "firmware-awaiting-bootstrap",
            "firmware-restoring-identity",
            "firmware-writing",
            "firmware-finalizing",
            "device-reconnecting",
            "firmware-readback",
        ]),
        OperationKind::VolumeLabelSet
        | OperationKind::DriveLetterSet
        | OperationKind::DriveLetterReset => {
            Some(&["host-volume-changing", "host-volume-readback"])
        }
        OperationKind::Format => Some(&[
            "format-validating",
            "format-writing",
            "format-finalizing",
            "format-readback",
        ]),
        OperationKind::DriveModeSet | OperationKind::SataModeSet => Some(&[
            "device-configuring",
            "device-reconnecting",
            "device-readback",
        ]),
        OperationKind::EjectSafe => Some(&["host-unmounting", "host-ejecting", "eject-readback"]),
        OperationKind::EjectForce => Some(&["host-ejecting", "eject-readback"]),
    }
}

/// Returns the first native lifecycle stage for a started operation.
pub(super) fn first_stage(kind: OperationKind) -> Option<&'static str> {
    operation_graph(kind).and_then(|graph| graph.first().copied())
}

/// Returns whether main and native both permit cancellation at one stage.
pub(super) fn is_cancellation_allowed(kind: OperationKind, stage: &str) -> bool {
    match kind {
        OperationKind::StatusRefresh => matches!(stage, "queued" | "outcome-unknown"),
        OperationKind::CredentialCreate
        | OperationKind::CredentialChange
        | OperationKind::CredentialDelete
        | OperationKind::CredentialReset
        | OperationKind::CredentialConfigure => matches!(
            stage,
            "queued" | "outcome-unknown" | "credential-validating"
        ),
        OperationKind::SelfTest => {
            matches!(stage, "queued" | "outcome-unknown" | "diagnostic-running")
        }
        OperationKind::LedTest => {
            matches!(stage, "queued" | "outcome-unknown" | "led-testing")
        }
        OperationKind::WriteReadTest => matches!(
            stage,
            "queued" | "outcome-unknown" | "host-writing" | "host-reading"
        ),
        OperationKind::FirmwareUpdate => {
            matches!(
                stage,
                "queued" | "outcome-unknown" | "firmware-validating" | "firmware-capturing"
            )
        }
        OperationKind::EjectSafe => {
            matches!(stage, "queued" | "outcome-unknown" | "host-unmounting")
        }
        OperationKind::Format => {
            matches!(stage, "queued" | "outcome-unknown" | "format-validating")
        }
        _ => false,
    }
}

/// Returns the first stage that creates a mandatory recovery obligation.
fn recovery_start(kind: OperationKind) -> Option<&'static str> {
    match kind {
        OperationKind::AccessEnable | OperationKind::AccessDisable => Some("access-changing"),
        OperationKind::CredentialCreate
        | OperationKind::CredentialChange
        | OperationKind::CredentialDelete
        | OperationKind::CredentialReset
        | OperationKind::CredentialConfigure => Some("credential-writing"),
        OperationKind::SelfTest => Some("diagnostic-running"),
        OperationKind::LedTest => Some("led-testing"),
        // Host state machines carry independent mutation and cleanup certainty,
        // so their terminal must remain at the last stage actually reached.
        OperationKind::WriteReadTest => None,
        OperationKind::FirmwareUpdate => Some("firmware-compatibility-setup"),
        OperationKind::VolumeLabelSet
        | OperationKind::DriveLetterSet
        | OperationKind::DriveLetterReset => None,
        OperationKind::Format => None,
        OperationKind::DriveModeSet | OperationKind::SataModeSet => Some("device-configuring"),
        OperationKind::EjectSafe | OperationKind::EjectForce => None,
        OperationKind::Scan | OperationKind::StatusRefresh => None,
    }
}

/// Returns whether a stage has reached or crossed its recovery barrier.
fn has_recovery_obligation(kind: OperationKind, stage: &str) -> bool {
    let Some(start) = recovery_start(kind) else {
        return false;
    };
    let Some(graph) = operation_graph(kind) else {
        return false;
    };
    let Some(start_index) = graph.iter().position(|candidate| *candidate == start) else {
        return false;
    };
    graph
        .iter()
        .position(|candidate| *candidate == stage)
        .is_some_and(|index| index >= start_index)
}

/// Returns whether one stage is an explicit post-cancel recovery stage.
fn is_recovery_stage(kind: OperationKind, stage: &str) -> bool {
    match kind {
        OperationKind::AccessEnable | OperationKind::AccessDisable => stage == "access-readback",
        OperationKind::CredentialCreate
        | OperationKind::CredentialChange
        | OperationKind::CredentialDelete
        | OperationKind::CredentialReset
        | OperationKind::CredentialConfigure => stage == "credential-readback",
        OperationKind::SelfTest => stage == "diagnostic-cleanup",
        OperationKind::LedTest => matches!(stage, "led-restoring" | "led-readback"),
        OperationKind::WriteReadTest => matches!(stage, "queued" | "host-writing"),
        OperationKind::FirmwareUpdate => matches!(
            stage,
            "firmware-finalizing" | "device-reconnecting" | "firmware-readback"
        ),
        OperationKind::VolumeLabelSet
        | OperationKind::DriveLetterSet
        | OperationKind::DriveLetterReset => stage == "host-volume-readback",
        OperationKind::Format => matches!(stage, "format-finalizing" | "format-readback"),
        OperationKind::DriveModeSet | OperationKind::SataModeSet => {
            matches!(stage, "device-reconnecting" | "device-readback")
        }
        OperationKind::EjectSafe | OperationKind::EjectForce => stage == "eject-readback",
        OperationKind::Scan | OperationKind::StatusRefresh => false,
    }
}

/// Returns the earliest outstanding recovery stage after the current stage.
fn next_recovery_stage(kind: OperationKind, current: &str) -> Option<&'static str> {
    let graph = operation_graph(kind)?;
    let current_index = graph
        .iter()
        .position(|candidate| *candidate == current)
        .map_or(-1, |index| index as isize);
    graph.iter().enumerate().find_map(|(index, stage)| {
        ((index as isize) > current_index && is_recovery_stage(kind, stage)).then_some(*stage)
    })
}

/// Returns whether a cancellation terminal matches main's per-kind policy.
pub(super) fn is_cancel_terminal(kind: OperationKind, stage: &str) -> bool {
    match kind {
        OperationKind::StatusRefresh => stage == "queued",
        OperationKind::CredentialCreate
        | OperationKind::CredentialChange
        | OperationKind::CredentialDelete
        | OperationKind::CredentialReset
        | OperationKind::CredentialConfigure => {
            matches!(stage, "queued" | "credential-validating")
        }
        OperationKind::SelfTest => stage == "diagnostic-cleanup",
        OperationKind::LedTest => stage == "led-readback",
        OperationKind::WriteReadTest => stage == "host-cleanup",
        OperationKind::FirmwareUpdate => {
            matches!(
                stage,
                "queued" | "firmware-validating" | "firmware-capturing" | "firmware-readback"
            )
        }
        OperationKind::EjectSafe => matches!(stage, "queued" | "host-unmounting"),
        OperationKind::Format => matches!(stage, "queued" | "format-validating"),
        _ => false,
    }
}

/// Extracts the exact common owner fields from any public operation event.
fn event_owner(
    event: &OperationEvent,
) -> (&OperationId, OperationKind, &DeviceId, DiscoveryRevision) {
    match event {
        OperationEvent::Queued {
            operation_id,
            kind,
            device_id,
            device_revision,
            ..
        }
        | OperationEvent::Started {
            operation_id,
            kind,
            device_id,
            device_revision,
            ..
        }
        | OperationEvent::Progress {
            operation_id,
            kind,
            device_id,
            device_revision,
            ..
        }
        | OperationEvent::Succeeded {
            operation_id,
            kind,
            device_id,
            device_revision,
            ..
        }
        | OperationEvent::Failed {
            operation_id,
            kind,
            device_id,
            device_revision,
            ..
        }
        | OperationEvent::Cancelled {
            operation_id,
            kind,
            device_id,
            device_revision,
            ..
        } => (operation_id, *kind, device_id, *device_revision),
    }
}

/// Checks complete operation, kind, device, and revision ownership.
pub(super) fn event_matches(active: &ActiveOperation, event: &OperationEvent) -> bool {
    let (operation_id, kind, device_id, device_revision) = event_owner(event);
    operation_id == &active.operation_id
        && kind == active.kind
        && device_id == &active.device_id
        && device_revision == active.device_revision
}

/// Validates one event against the exact current lifecycle and updates state.
pub(super) fn validate_event_lifecycle(
    active: &mut ActiveOperation,
    event: &OperationEvent,
    pre_request_grace: bool,
) -> Result<bool, ServiceProtocolError> {
    match event {
        OperationEvent::Queued { .. } => Err(ServiceProtocolError::BackendContract),
        OperationEvent::Started { stage, .. } => {
            let graph =
                operation_graph(active.kind).ok_or(ServiceProtocolError::BackendContract)?;
            if active.phase != OperationPhase::Accepted || stage.as_str() != graph[0] {
                return Err(ServiceProtocolError::BackendContract);
            }
            active.phase = OperationPhase::Running;
            active.stage = stage.as_str().to_owned();
            active.stage_index = 0;
            active.recovery_required = has_recovery_obligation(active.kind, stage.as_str());
            Ok(false)
        }
        OperationEvent::Progress {
            stage,
            progress,
            attempt,
            cancellation_state,
            ..
        } => {
            let graph =
                operation_graph(active.kind).ok_or(ServiceProtocolError::BackendContract)?;
            let next_index = graph
                .iter()
                .position(|candidate| *candidate == stage.as_str())
                .ok_or(ServiceProtocolError::BackendContract)?
                as isize;
            let sequential = active.phase == OperationPhase::Running
                && ((next_index >= active.stage_index && next_index <= active.stage_index + 1)
                    || (active.kind == OperationKind::FirmwareUpdate
                        && ((active.stage == "firmware-validating"
                            && stage.as_str() == "firmware-writing")
                            || (active.stage == "firmware-writing"
                                && stage.as_str() == "device-reconnecting"))));
            let recovery_jump = active.cancellation_requested
                && next_recovery_stage(active.kind, &active.stage) == Some(stage.as_str());
            if (!sequential && !recovery_jump) || progress.get() < active.progress {
                return Err(ServiceProtocolError::BackendContract);
            }
            let attempt_value = attempt.map_or(0, |value| value.get());
            if attempt.is_some()
                && (active.kind != OperationKind::FirmwareUpdate
                    || stage.as_str() != "firmware-writing"
                    || attempt_value < active.attempt
                    || attempt_value > active.attempt + 1
                    || (active.attempt == 0 && attempt_value != 1))
            {
                return Err(ServiceProtocolError::BackendContract);
            }
            if !cancellation_state_consistent(
                active,
                stage.as_str(),
                *cancellation_state,
                pre_request_grace,
            ) {
                return Err(ServiceProtocolError::BackendContract);
            }
            active.phase = OperationPhase::Running;
            active.stage = stage.as_str().to_owned();
            active.stage_index = next_index;
            active.progress = progress.get();
            if attempt.is_some() {
                active.attempt = attempt_value;
            }
            active.recovery_required |= has_recovery_obligation(active.kind, stage.as_str());
            if *cancellation_state == CancellationState::Closed
                || (!is_cancellation_allowed(active.kind, stage.as_str())
                    && !is_recovery_stage(active.kind, stage.as_str()))
            {
                active.cancellation_closed = true;
            }
            Ok(false)
        }
        OperationEvent::Succeeded { stage, .. } => {
            let graph =
                operation_graph(active.kind).ok_or(ServiceProtocolError::BackendContract)?;
            if active.phase != OperationPhase::Running
                || stage.as_str() != "complete"
                || active.stage_index != graph.len() as isize - 1
            {
                return Err(ServiceProtocolError::BackendContract);
            }
            Ok(true)
        }
        OperationEvent::Cancelled { stage, .. } => {
            let current_stage_matches = stage.as_str() == active.stage;
            let awaiting_start_stage_matches = active.phase == OperationPhase::Accepted
                && active
                    .cancellation_stage
                    .as_deref()
                    .is_some_and(|cancel_stage| cancel_stage == stage.as_str());
            if !active.cancellation_requested
                || active.cancellation_closed
                || (!current_stage_matches && !awaiting_start_stage_matches)
                || !is_cancel_terminal(active.kind, stage.as_str())
            {
                return Err(ServiceProtocolError::BackendContract);
            }
            Ok(true)
        }
        OperationEvent::Failed { stage, error, .. } => {
            if !failure_is_consistent(active, stage.as_str(), error) {
                return Err(ServiceProtocolError::BackendContract);
            }
            Ok(true)
        }
    }
}

/// Checks progress cancellation state against native and main-owned policy.
fn cancellation_state_consistent(
    active: &ActiveOperation,
    stage: &str,
    state: CancellationState,
    pre_request_grace: bool,
) -> bool {
    if active.cancellation_requested && !pre_request_grace {
        return state == CancellationState::Requested;
    }
    if state == CancellationState::Requested {
        return active.cancellation_requested;
    }
    if state == CancellationState::Cancellable {
        return !active.cancellation_closed && is_cancellation_allowed(active.kind, stage);
    }
    state == CancellationState::Closed
        && (active.cancellation_closed
            || !is_cancellation_allowed(active.kind, stage)
            // These host workers close cancellation at the current public
            // stage before entering their synchronous I/O primitive. Accept
            // that monotonic cutover without permitting cancellation to reopen.
            || (active.phase == OperationPhase::Running
                && active.stage == stage
                && matches!((active.kind, stage),
                    (OperationKind::EjectSafe, "host-unmounting")
                    | (OperationKind::WriteReadTest, "host-writing"))))
}

/// Validates terminal, primary, cleanup, and retry evidence ordering.
fn failure_is_consistent(
    active: &ActiveOperation,
    terminal_stage: &str,
    error: &crate::error::RdxError,
) -> bool {
    if terminal_stage != active.stage {
        return false;
    }
    if active.phase == OperationPhase::Accepted {
        return terminal_stage == "queued"
            && error.stage.as_str() == "queued"
            && error
                .cleanup_evidence
                .as_slice()
                .iter()
                .all(|evidence| evidence.stage().as_str() == "queued")
            && error.attempt_history.as_slice().is_empty();
    }
    let Some(graph) = operation_graph(active.kind) else {
        return false;
    };
    let Some(terminal_index) = graph.iter().position(|stage| *stage == terminal_stage) else {
        return false;
    };
    let Some(primary_index) = graph
        .iter()
        .position(|stage| *stage == error.stage.as_str())
    else {
        return false;
    };
    if primary_index > terminal_index {
        return false;
    }
    let mut previous = primary_index;
    for cleanup in error.cleanup_evidence.as_slice() {
        let Some(index) = graph
            .iter()
            .position(|stage| *stage == cleanup.stage().as_str())
        else {
            return false;
        };
        if index < previous || index > terminal_index {
            return false;
        }
        previous = index;
    }
    if active.kind != OperationKind::FirmwareUpdate && !error.attempt_history.as_slice().is_empty()
    {
        return false;
    }
    if (active.attempt == 2) != (error.attempt_history.as_slice().len() == 1) {
        return false;
    }
    for attempt in error.attempt_history.as_slice() {
        let Some(index) = graph
            .iter()
            .position(|stage| *stage == attempt.stage().as_str())
        else {
            return false;
        };
        if attempt.attempt() != 1 || index > primary_index {
            return false;
        }
    }
    !active.recovery_required
        || terminal_index == graph.len() - 1
        || is_incomplete_migration_failure(active, terminal_stage, error)
}

/// Admits interrupted migrations without inventing later write or readback stages.
/// Recovery remains required: only an explicit unknown result with independent
/// incomplete-cleanup evidence can end this otherwise unfinished stage graph.
fn is_incomplete_migration_failure(
    active: &ActiveOperation,
    terminal_stage: &str,
    error: &crate::error::RdxError,
) -> bool {
    use crate::transport::DispatchCertainty;

    active.kind == OperationKind::FirmwareUpdate
        && matches!(
            terminal_stage,
            "firmware-compatibility-setup"
                | "firmware-staging"
                | "firmware-awaiting-bootloader"
                | "firmware-programming-bootstrap"
                | "firmware-awaiting-bootstrap"
                | "firmware-restoring-identity"
        )
        && error.stage.as_str() == terminal_stage
        && error.dispatch_certainty == Some(DispatchCertainty::CompletionUnknown)
        && !error.retryable
        && error.cleanup_evidence.as_slice().iter().any(|evidence| {
            evidence.stage().as_str() == terminal_stage
                && evidence.code().as_str() == "cleanup-incomplete"
                && evidence.dispatch_certainty() == Some(DispatchCertainty::CompletionUnknown)
        })
}

#[cfg(test)]
#[path = "lifecycle_migration_tests.rs"]
mod migration_tests;

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use super::*;
    use crate::model::{FirmwareFileToken, OperationRequest, Progress, ReasonCode};

    /// Creates the exact owner fields shared by one cancellation-latch case.
    fn owner() -> (OperationId, DeviceId, DiscoveryRevision) {
        (
            OperationId::new("op:closed-latch").unwrap(),
            DeviceId::new("rdx:closed-latch").unwrap(),
            DiscoveryRevision::new(7).unwrap(),
        )
    }

    /// Creates a started event for one tested policy kind.
    fn started(kind: OperationKind, stage: &str) -> OperationEvent {
        let (operation_id, device_id, device_revision) = owner();
        OperationEvent::Started {
            operation_id,
            kind,
            device_id,
            device_revision,
            stage: ReasonCode::new(stage).unwrap(),
            message_key: None,
        }
    }

    /// Creates a progress event with an explicit cancellation state.
    fn progress(
        kind: OperationKind,
        stage: &str,
        value: f64,
        cancellation_state: CancellationState,
    ) -> OperationEvent {
        let (operation_id, device_id, device_revision) = owner();
        OperationEvent::Progress {
            operation_id,
            kind,
            device_id,
            device_revision,
            stage: ReasonCode::new(stage).unwrap(),
            progress: Progress::new(value).unwrap(),
            attempt: None,
            cancellation_state,
            message_key: None,
        }
    }

    /// Creates a cancellation terminal at one safe recovery boundary.
    fn cancelled(kind: OperationKind, stage: &str) -> OperationEvent {
        let (operation_id, device_id, device_revision) = owner();
        OperationEvent::Cancelled {
            operation_id,
            kind,
            device_id,
            device_revision,
            stage: ReasonCode::new(stage).unwrap(),
            reason: Some(ReasonCode::new("cancelled-by-user").unwrap()),
            message_key: None,
        }
    }

    /// Proves a pre-cutover closed state remains permanent through every safe recovery path.
    #[test]
    fn closed_cancellation_latch_survives_late_requested_recovery_per_kind() {
        let (_, device_id, device_revision) = owner();
        let scenarios = [
            (
                OperationKind::SelfTest,
                OperationRequest::SelfTest {
                    device_id: device_id.clone(),
                    device_revision,
                },
                "diagnostic-running",
                &["diagnostic-cleanup"][..],
            ),
            (
                OperationKind::LedTest,
                OperationRequest::LedTest {
                    device_id: device_id.clone(),
                    device_revision,
                },
                "led-testing",
                &["led-restoring", "led-readback"][..],
            ),
            (
                OperationKind::FirmwareUpdate,
                OperationRequest::FirmwareUpdate {
                    device_id,
                    device_revision,
                    firmware_file_token: FirmwareFileToken::new("firmware:closed-latch").unwrap(),
                },
                "firmware-validating",
                &[
                    "firmware-finalizing",
                    "device-reconnecting",
                    "firmware-readback",
                ][..],
            ),
        ];

        for (kind, request, initial_stage, recovery) in scenarios {
            let mut active = ActiveOperation::new_at(
                OperationId::new("op:closed-latch").unwrap(),
                &request,
                Instant::now(),
            )
            .unwrap();
            assert_eq!(
                validate_event_lifecycle(&mut active, &started(kind, initial_stage), false),
                Ok(false)
            );
            active.cancellation_requested = true;
            active.cancellation_stage = Some(initial_stage.to_owned());

            for (index, stage) in recovery.iter().enumerate() {
                let state = if index == 0 {
                    CancellationState::Closed
                } else {
                    CancellationState::Requested
                };
                let pre_request_grace = index == 0;
                let value = (index + 1) as f64 / recovery.len() as f64;
                assert_eq!(
                    validate_event_lifecycle(
                        &mut active,
                        &progress(kind, stage, value, state),
                        pre_request_grace
                    ),
                    Ok(false)
                );
                assert!(active.cancellation_closed);
            }

            assert_eq!(
                validate_event_lifecycle(
                    &mut active,
                    &cancelled(kind, recovery.last().unwrap()),
                    false
                ),
                Err(ServiceProtocolError::BackendContract)
            );
            assert!(active.cancellation_closed);
        }
    }

    /// Both firmware routes must reach actual final readback before a success is accepted.
    #[test]
    fn firmware_installation_lifecycle_retains_ownership_until_readback() {
        let kind = OperationKind::FirmwareUpdate;
        let (operation_id, device_id, device_revision) = owner();
        let request = OperationRequest::FirmwareUpdate {
            device_id: device_id.clone(),
            device_revision,
            firmware_file_token: FirmwareFileToken::new("firmware:installation").unwrap(),
        };
        let mut active =
            ActiveOperation::new_at(operation_id.clone(), &request, Instant::now()).unwrap();
        assert_eq!(
            validate_event_lifecycle(&mut active, &started(kind, "firmware-validating"), false),
            Ok(false)
        );
        let success = OperationEvent::Succeeded {
            operation_id,
            kind,
            device_id,
            device_revision,
            stage: ReasonCode::new("complete").unwrap(),
            message_key: None,
        };
        let graph = operation_graph(kind).unwrap();
        for (index, stage) in graph.iter().enumerate().skip(1) {
            assert!(validate_event_lifecycle(&mut active, &success, false).is_err());
            let cancellation = if index == 1 {
                CancellationState::Cancellable
            } else {
                CancellationState::Closed
            };
            assert_eq!(
                validate_event_lifecycle(
                    &mut active,
                    &progress(kind, stage, index as f64 / graph.len() as f64, cancellation),
                    false
                ),
                Ok(false),
                "{stage}"
            );
            assert_eq!(active.recovery_required, index >= 2, "{stage}");
            assert_eq!(is_cancellation_allowed(kind, stage), index == 1, "{stage}");
        }
        assert_eq!(
            validate_event_lifecycle(&mut active, &success, false),
            Ok(true)
        );
        assert!(is_cancel_terminal(kind, "firmware-capturing"));
    }

    /// Status refresh accepts cancellation only while queued and rejects it
    /// after the worker's atomic Started publication.
    #[test]
    fn status_refresh_cancellation_closes_at_started() {
        let (_, device_id, device_revision) = owner();
        let request = OperationRequest::StatusRefresh {
            device_id,
            device_revision,
        };
        let mut active = ActiveOperation::new_at(
            OperationId::new("op:status-start-boundary").unwrap(),
            &request,
            Instant::now(),
        )
        .unwrap();
        assert!(is_cancellation_allowed(
            OperationKind::StatusRefresh,
            "queued"
        ));
        assert_eq!(
            validate_event_lifecycle(
                &mut active,
                &started(OperationKind::StatusRefresh, "status-reading"),
                false,
            ),
            Ok(false)
        );
        assert!(!is_cancellation_allowed(
            OperationKind::StatusRefresh,
            "status-reading"
        ));
        assert!(!is_cancel_terminal(
            OperationKind::StatusRefresh,
            "status-reading"
        ));
    }

    /// Safe eject may close cancellation at the same public stage immediately
    /// before its irreversible host mutation without violating event order.
    #[test]
    fn safe_eject_accepts_same_stage_cancellation_close_before_dispatch() {
        let (_, device_id, device_revision) = owner();
        let request = OperationRequest::EjectSafe {
            device_id,
            device_revision,
        };
        let mut active = ActiveOperation::new_at(
            OperationId::new("op:eject-close-boundary").unwrap(),
            &request,
            Instant::now(),
        )
        .unwrap();

        assert_eq!(
            validate_event_lifecycle(
                &mut active,
                &started(OperationKind::EjectSafe, "host-unmounting"),
                false,
            ),
            Ok(false)
        );
        assert_eq!(
            validate_event_lifecycle(
                &mut active,
                &progress(
                    OperationKind::EjectSafe,
                    "host-unmounting",
                    0.0,
                    CancellationState::Closed,
                ),
                false,
            ),
            Ok(false)
        );
        assert!(active.cancellation_closed);
    }

    /// The production write/read worker closes cancellation before dispatching file I/O.
    #[test]
    fn write_read_accepts_cancellation_close_before_file_creation() {
        let (operation_id, device_id, device_revision) = owner();
        let request = OperationRequest::WriteReadTest {
            device_id,
            device_revision,
        };
        let mut active = ActiveOperation::new_at(operation_id, &request, Instant::now()).unwrap();
        assert_eq!(
            validate_event_lifecycle(
                &mut active,
                &started(OperationKind::WriteReadTest, "host-writing"),
                false
            ),
            Ok(false)
        );
        assert_eq!(
            validate_event_lifecycle(
                &mut active,
                &progress(
                    OperationKind::WriteReadTest,
                    "host-writing",
                    0.0,
                    CancellationState::Closed
                ),
                false
            ),
            Ok(false)
        );
        assert!(active.cancellation_closed);
        assert!(
            validate_event_lifecycle(
                &mut active,
                &progress(
                    OperationKind::WriteReadTest,
                    "host-reading",
                    0.5,
                    CancellationState::Cancellable
                ),
                false
            )
            .is_err(),
            "file I/O must never reopen cancellation"
        );
        assert_eq!(
            validate_event_lifecycle(
                &mut active,
                &progress(
                    OperationKind::WriteReadTest,
                    "host-reading",
                    0.5,
                    CancellationState::Closed
                ),
                false
            ),
            Ok(false)
        );
    }
}
