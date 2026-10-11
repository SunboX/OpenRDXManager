// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Offline regressions for interrupted migrations at the real publication boundary.

use std::sync::mpsc::{self, Receiver};
use std::time::Instant;

use super::{ActiveOperation, operation_graph, validate_event_lifecycle};
use crate::error::{CleanupEvidence, FailureEvidence};
use crate::model::{
    CancellationState, DeviceId, DeviceIdentity, DiscoveryRevision, FirmwareFileToken,
    OperationEvent, OperationId, OperationKind, OperationRequest, ReasonCode,
};
use crate::operations::{CleanupState, HostOperationFailure, HostPrimitiveError, PrimitiveFailure};
use crate::service::ServiceProtocolError;
use crate::service::crash::CrashAdmission;
use crate::service::events::{ServiceEventSink, ServiceOperationSignal};
use crate::transport::DispatchCertainty;

/// Holds a real publication channel and in-memory lifecycle without native device access.
struct MigrationFixture {
    active: ActiveOperation,
    sink: ServiceEventSink,
    receiver: Receiver<Box<ServiceOperationSignal>>,
    operation_id: OperationId,
    device: DeviceIdentity,
}

impl MigrationFixture {
    /// Publishes every causally reached stage through the same sink as the host worker.
    fn at(stage: &'static str) -> Self {
        let operation_id = OperationId::new("op:migration-terminal").unwrap();
        let device = DeviceIdentity {
            id: DeviceId::new("rdx:migration-terminal").unwrap(),
            revision: DiscoveryRevision::new(7).unwrap(),
        };
        let request = OperationRequest::FirmwareUpdate {
            device_id: device.id.clone(),
            device_revision: device.revision,
            firmware_file_token: FirmwareFileToken::new("firmware:migration-terminal").unwrap(),
        };
        let (sender, receiver) = mpsc::sync_channel(2);
        let mut fixture = Self {
            active: ActiveOperation::new_at(operation_id.clone(), &request, Instant::now())
                .unwrap(),
            sink: ServiceEventSink::new(sender, CrashAdmission::new()),
            receiver,
            operation_id,
            device,
        };
        fixture
            .sink
            .publish_host_started(
                &fixture.operation_id,
                OperationKind::FirmwareUpdate,
                &fixture.device,
            )
            .unwrap();
        fixture.accept_progress();
        for reached in operation_graph(OperationKind::FirmwareUpdate)
            .unwrap()
            .iter()
            .skip(1)
        {
            fixture
                .sink
                .publish_host_progress(
                    &fixture.operation_id,
                    OperationKind::FirmwareUpdate,
                    &fixture.device,
                    reached,
                    if *reached == "firmware-capturing" {
                        CancellationState::Cancellable
                    } else {
                        CancellationState::Closed
                    },
                )
                .unwrap();
            fixture.accept_progress();
            if *reached == stage {
                return fixture;
            }
        }
        panic!("fixture stage must belong to the firmware graph");
    }

    /// Consumes one real stage publication through the native protocol validator.
    fn accept_progress(&mut self) {
        let signal = self.receiver.try_recv().unwrap();
        assert_eq!(
            validate_event_lifecycle(&mut self.active, &signal.event, false),
            Ok(false)
        );
    }

    /// Produces the same explicit unknown-result terminal as migration failure handling.
    fn failure(&self, stage: &'static str, cause: HostPrimitiveError) -> OperationEvent {
        let failure = HostOperationFailure::from_primitive(
            stage,
            PrimitiveFailure::completion_unknown(cause),
        )
        .with_cleanup(CleanupState::CompletionUnknown);
        self.sink
            .publish_host_terminal(
                &self.operation_id,
                OperationKind::FirmwareUpdate,
                &self.device,
                stage,
                Err(failure),
            )
            .unwrap();
        self.receiver.try_recv().unwrap().event
    }
}

/// A failed factory readback after the second power cycle is a truthful terminal, not a service fault.
#[test]
fn restoration_readback_failure_publishes_terminal_without_later_stages() {
    let stage = "firmware-restoring-identity";
    let mut fixture = MigrationFixture::at(stage);
    let event = fixture.failure(stage, HostPrimitiveError::MigrationReadbackMismatch);
    assert_eq!(
        validate_event_lifecycle(&mut fixture.active, &event, false),
        Ok(true)
    );
    let OperationEvent::Failed {
        stage: terminal,
        error,
        ..
    } = &event
    else {
        panic!("restoration failure must remain a failure");
    };
    assert_eq!(terminal.as_str(), stage);
    assert_eq!(error.stage.as_str(), stage);
    assert_eq!(error.code.as_str(), "firmware-migration-readback-mismatch");
    assert_eq!(
        error.dispatch_certainty,
        Some(DispatchCertainty::CompletionUnknown)
    );
    assert!(!error.retryable);
    assert_eq!(fixture.active.stage, stage);
    assert!(fixture.active.recovery_required);
    assert!(fixture.active.cancellation_closed);
    assert!(
        fixture.receiver.try_recv().is_err(),
        "no invented later checks may be published"
    );
    #[cfg(feature = "fixtures")]
    {
        let mut backend = crate::service::cli::fixtures::FixtureBackend::default();
        let mut runtime = crate::service::ServiceRuntime::new(&mut backend, fixture.sink);
        runtime.active = Some(fixture.active);
        let envelope = runtime
            .handle_event(event)
            .expect("failure must not exit the service");
        assert_eq!(envelope["event"]["state"], "failed");
        assert_eq!(envelope["event"]["stage"], stage);
        assert_eq!(envelope["event"]["error"]["stage"], stage);
        assert!(
            runtime.active.is_none(),
            "the valid failed terminal releases operation ownership"
        );
    }
}

/// Every earlier postmutation migration boundary can fail without pretending to run final checks.
#[test]
fn rom_postmutation_failures_preserve_recovery_and_exact_stage() {
    for stage in [
        "firmware-compatibility-setup",
        "firmware-staging",
        "firmware-awaiting-bootloader",
        "firmware-programming-bootstrap",
        "firmware-awaiting-bootstrap",
    ] {
        let mut fixture = MigrationFixture::at(stage);
        let event = fixture.failure(stage, HostPrimitiveError::MigrationProgrammingFailed);
        assert_eq!(
            validate_event_lifecycle(&mut fixture.active, &event, false),
            Ok(true),
            "{stage}"
        );
        let OperationEvent::Failed { error, .. } = event else {
            panic!("migration must not synthesize success");
        };
        assert_eq!(error.stage.as_str(), stage);
        assert!(fixture.active.recovery_required, "{stage}");
        assert_eq!(fixture.active.stage, stage);
    }
}

/// An early terminal cannot silently clear or misrepresent unfinished recovery.
#[test]
fn early_migration_terminal_requires_explicit_unknown_cleanup_evidence() {
    let stage = "firmware-restoring-identity";
    for mutation in 0..8 {
        let mut fixture = MigrationFixture::at(stage);
        let mut event = fixture.failure(stage, HostPrimitiveError::MigrationReadbackMismatch);
        let OperationEvent::Failed { error, .. } = &mut event else {
            unreachable!();
        };
        match mutation {
            0 => error.cleanup_evidence = CleanupEvidence::default(),
            1 => error.dispatch_certainty = Some(DispatchCertainty::NotSent),
            2 => error.stage = ReasonCode::new("firmware-readback").unwrap(),
            3 => error.retryable = true,
            4 => error.stage = ReasonCode::new("firmware-validating").unwrap(),
            5..=7 => {
                error.cleanup_evidence = CleanupEvidence::new(vec![
                    FailureEvidence::new(
                        ReasonCode::new(if mutation == 5 {
                            "firmware-staging"
                        } else {
                            stage
                        })
                        .unwrap(),
                        ReasonCode::new(if mutation == 6 {
                            "cleanup-other"
                        } else {
                            "cleanup-incomplete"
                        })
                        .unwrap(),
                        Some(if mutation == 7 {
                            DispatchCertainty::NotSent
                        } else {
                            DispatchCertainty::CompletionUnknown
                        }),
                        None,
                    )
                    .unwrap(),
                ])
                .unwrap();
            }
            _ => unreachable!(),
        }
        assert_eq!(
            validate_event_lifecycle(&mut fixture.active, &event, false),
            Err(ServiceProtocolError::BackendContract),
            "mutation {mutation}"
        );
        assert!(fixture.active.recovery_required);
    }
}

/// The migration exception does not weaken later ordinary-update recovery stages.
#[test]
fn ordinary_firmware_failure_still_requires_final_readback() {
    for stage in [
        "firmware-writing",
        "firmware-finalizing",
        "device-reconnecting",
    ] {
        let mut fixture = MigrationFixture::at(stage);
        let event = fixture.failure(stage, HostPrimitiveError::MigrationProgrammingFailed);
        assert_eq!(
            validate_event_lifecycle(&mut fixture.active, &event, false),
            Err(ServiceProtocolError::BackendContract),
            "{stage}"
        );
    }
}
