// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

use super::*;
#[path = "hardware_test_platform.rs"]
mod mode_platform;
use crate::model::{DeviceId, DiscoveryRevision, Filesystem};
use crate::platform::{
    CandidateDevice, CandidateLease, CandidateMetadata, PlatformCapabilities, PlatformDeviceHandle,
};
use crate::transport::{CommandDispatch, TransportResponse};
use mode_platform::{
    ModePlatform, ModePlatformState, mode_device_identification, mode_standard_inquiry,
};
use std::sync::mpsc;

/// Installs only the validated deterministic fixture into the simulated worker.
/// This unit-test command is absent from every normal and fixture-feature service binary.
fn install_fixture_firmware(
    backend: &HardwareServiceBackend<ModePlatform>,
    token: FirmwareFileToken,
) {
    let (sender, receiver) = mpsc::sync_channel(1);
    backend
        .commands
        .send(WorkerCommand::InstallFixtureFirmware(token, sender))
        .unwrap();
    receiver.recv().unwrap().unwrap();
}

/// Creates one exact format request and its matching operation request.
fn requests(token: ConfirmationToken) -> (ConfirmationRequest, OperationRequest) {
    let device_id = DeviceId::new("rdx:confirmation-test").unwrap();
    let device_revision = DiscoveryRevision::new(7).unwrap();
    (
        ConfirmationRequest::Format {
            device_id: device_id.clone(),
            device_revision,
            filesystem: Filesystem::Exfat,
        },
        OperationRequest::Format {
            passphrase: None,
            device_id,
            device_revision,
            filesystem: Filesystem::Exfat,
            confirmation_token: token,
        },
    )
}

/// A matching token succeeds once and is absent on replay.
#[test]
fn confirmation_is_consumed_atomically_before_dispatch() {
    let token = ConfirmationToken::new("confirm:one-shot").unwrap();
    let proof = ConfirmationToken::new("confirm:binding-proof").unwrap();
    let (confirmation, operation) = requests(token.clone());
    let session = [0xA5; 16];
    let mut records = BTreeMap::from([(
        token.clone(),
        ConfirmationRecord {
            request: confirmation,
            binding_proof: proof.clone(),
            expires_at: Instant::now() + Duration::from_secs(1),
            service_session: session,
        },
    )]);

    assert!(consume_confirmation(&mut records, session, &operation, &token, &proof).is_ok());
    assert_eq!(
        consume_confirmation(&mut records, session, &operation, &token, &proof)
            .expect_err("replay is rejected")
            .as_str(),
        "confirmation-required"
    );
}

/// Wrong action, medium proof, session, and expiry all fail after removal.
#[test]
fn confirmation_rejects_every_binding_mismatch() {
    for mismatch in 0..4 {
        let token = ConfirmationToken::new(format!("confirm:mismatch-{mismatch}")).unwrap();
        let proof = ConfirmationToken::new("confirm:binding-proof").unwrap();
        let (confirmation, mut operation) = requests(token.clone());
        let session = [0x5A; 16];
        let mut record = ConfirmationRecord {
            request: confirmation,
            binding_proof: proof.clone(),
            expires_at: Instant::now() + Duration::from_secs(1),
            service_session: session,
        };
        let observed_proof = if mismatch == 1 {
            ConfirmationToken::new("confirm:swapped-medium").unwrap()
        } else {
            proof.clone()
        };
        let observed_session = if mismatch == 2 { [0x11; 16] } else { session };
        if mismatch == 0 {
            operation = OperationRequest::EjectForce {
                device_id: DeviceId::new("rdx:confirmation-test").unwrap(),
                device_revision: DiscoveryRevision::new(7).unwrap(),
                confirmation_token: token.clone(),
            };
        } else if mismatch == 3 {
            record.expires_at = Instant::now();
        }
        let mut records = BTreeMap::from([(token.clone(), record)]);
        assert!(
            consume_confirmation(
                &mut records,
                observed_session,
                &operation,
                &token,
                &observed_proof,
            )
            .is_err()
        );
        assert!(records.is_empty());
    }
}

/// A queued status refresh accepts cancellation before release and publishes
/// Cancelled without ever publishing Started.
#[test]
fn queued_status_refresh_cancellation_wins_the_release_checkpoint() {
    let control = Arc::new(OperationControl::new(OperationKind::StatusRefresh));
    let waiting = Arc::clone(&control);
    let operation_id = OperationId::new("op:status-refresh-queued-cancel").unwrap();
    let identity = DeviceIdentity {
        id: DeviceId::new("rdx:status-refresh-queued-cancel").unwrap(),
        revision: DiscoveryRevision::new(3).unwrap(),
    };
    let (event_sender, event_receiver) = mpsc::sync_channel(2);
    let crashes = super::super::crash::CrashAdmission::new();
    let events = ServiceEventSink::new(event_sender, crashes.clone());
    let (sender, receiver) = mpsc::sync_channel(0);
    let worker = std::thread::spawn(move || {
        let cancelled = waiting.wait_for_release().unwrap();
        if cancelled {
            events
                .publish_host_cancelled(&operation_id, OperationKind::StatusRefresh, &identity)
                .unwrap();
        }
        sender.send(cancelled).unwrap();
    });

    control.request_cancellation().unwrap();
    control.release().unwrap();

    assert!(receiver.recv_timeout(Duration::from_secs(1)).unwrap());
    worker.join().unwrap();
    let signals = event_receiver.try_iter().collect::<Vec<_>>();
    assert_eq!(signals.len(), 1);
    assert!(matches!(
        signals[0].event,
        crate::model::OperationEvent::Cancelled { .. }
    ));
    assert!(crashes.observe().is_ok());
}

/// Status refresh is a real revisioned worker operation with an exact lifecycle.
#[test]
fn status_refresh_routes_and_publishes_one_complete_terminal() {
    let device_id = DeviceId::new("rdx:status-refresh").unwrap();
    let revision = DiscoveryRevision::new(9).unwrap();
    let request = OperationRequest::StatusRefresh {
        device_id: device_id.clone(),
        device_revision: revision,
    };
    assert_eq!(operation_target(&request), Some((&device_id, revision)));
    assert_eq!(operation_kind(&request), OperationKind::StatusRefresh);

    let identity = DeviceIdentity {
        id: device_id,
        revision,
    };
    let operation_id = OperationId::new("op:status-refresh").unwrap();
    let (sender, receiver) = mpsc::sync_channel(4);
    let crashes = super::super::crash::CrashAdmission::new();
    let events = ServiceEventSink::new(sender, crashes.clone());
    events
        .publish_host_started(&operation_id, OperationKind::StatusRefresh, &identity)
        .unwrap();
    let vendor = crate::model::DisplayText::new("TANDBERG").unwrap();
    let product = crate::model::DisplayText::new("RDX").unwrap();
    let serial = crate::model::DisplayText::new("STATUSREFRESH").unwrap();
    let snapshot = crate::model::DeviceSnapshot {
        id: identity.id.clone(),
        revision,
        drive: crate::model::DriveStatus::from_identity(&vendor, &product, &serial),
        vendor,
        product,
        serial,
        media: None,
        media_state: crate::model::MediaState::NoMedia,
        capabilities: BTreeMap::new(),
    };
    events
        .publish_status_success(
            &operation_id,
            &identity,
            crate::platform::ValidatedDiscoveryReport::all_accepted(vec![snapshot]),
        )
        .unwrap();

    let signals = receiver.try_iter().collect::<Vec<_>>();
    assert_eq!(signals.len(), 2);
    assert!(matches!(
        signals[0].event,
        crate::model::OperationEvent::Started { .. }
    ));
    assert!(matches!(
        signals[1].event,
        crate::model::OperationEvent::Succeeded { .. }
    ));
    assert!(signals[1].inventory_update.is_some());
    assert!(crashes.observe().is_ok());
}

/// Proven page-0x34 setters must resolve an exact production operation target.
#[test]
fn mode_operations_route_to_the_registry_owned_worker() {
    let device_id = DeviceId::new("rdx:mode-service-route").unwrap();
    let revision = DiscoveryRevision::new(11).unwrap();
    let drive = OperationRequest::DriveModeSet {
        device_id: device_id.clone(),
        device_revision: revision,
        mode: crate::model::DriveMode::Fixed,
    };
    let sata = OperationRequest::SataModeSet {
        device_id: device_id.clone(),
        device_revision: revision,
        mode: crate::model::SataMode::ThreeGSixG,
    };

    assert_eq!(operation_target(&drive), Some((&device_id, revision)));
    assert_eq!(operation_target(&sata), Some((&device_id, revision)));
    assert_eq!(operation_kind(&drive), OperationKind::DriveModeSet);
    assert_eq!(operation_kind(&sata), OperationKind::SataModeSet);
}

/// Advertised device diagnostics must resolve through the production worker.
#[test]
fn diagnostic_operations_route_to_the_registry_owned_worker() {
    let device_id = DeviceId::new("rdx:diagnostic-service-route").unwrap();
    let revision = DiscoveryRevision::new(12).unwrap();
    let self_test = OperationRequest::SelfTest {
        device_id: device_id.clone(),
        device_revision: revision,
    };
    let led_test = OperationRequest::LedTest {
        device_id: device_id.clone(),
        device_revision: revision,
    };

    assert_eq!(operation_target(&self_test), Some((&device_id, revision)));
    assert_eq!(operation_target(&led_test), Some((&device_id, revision)));
    assert_eq!(operation_kind(&self_test), OperationKind::SelfTest);
    assert_eq!(operation_kind(&led_test), OperationKind::LedTest);
}

/// Post-eject discovery behavior exposed by the production-backend fixture.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PostEjectDiscovery {
    SameDockNoMedia,
    Empty,
    Error,
}

/// Shared physical state proving eject completion before the follow-up scan.
#[derive(Debug)]
struct EjectInventoryState {
    ejected: bool,
    ejects: usize,
    enumerations: usize,
    post_eject: PostEjectDiscovery,
}

/// Exact RDX dock whose post-eject discovery can be controlled independently.
struct EjectInventoryPlatform {
    state: Arc<Mutex<EjectInventoryState>>,
}

impl crate::platform::PlatformBackend for EjectInventoryPlatform {
    /// Reports both normal and separately confirmed force eject as available.
    fn capabilities(&self) -> PlatformCapabilities {
        PlatformCapabilities::try_new(true, true, true, true, true, false, false, false).unwrap()
    }

    /// Returns the same dock, a transient empty pass, or a whole-pass error after eject.
    fn enumerate_candidates(&mut self) -> Result<Vec<CandidateDevice>, PlatformError> {
        let mut state = self.state.lock().unwrap();
        state.enumerations += 1;
        if state.ejected {
            match state.post_eject {
                PostEjectDiscovery::SameDockNoMedia => {}
                PostEjectDiscovery::Empty => return Ok(Vec::new()),
                PostEjectDiscovery::Error => return Err(PlatformError::EnumerationFailed),
            }
        }
        Ok(vec![
            CandidateDevice::new(
                "eject-inventory-target",
                "/private/eject-inventory-target",
                CandidateMetadata::new(
                    Some("TANDBERG".to_owned()),
                    Some("RDX".to_owned()),
                    Some("MODETARGET".to_owned()),
                    Some(crate::host::DeviceInterface::Sata3),
                ),
            )
            .unwrap(),
        ])
    }

    /// Opens one lease whose host facts reflect the current cartridge state.
    fn open_candidate(
        &mut self,
        _candidate: &CandidateDevice,
    ) -> Result<CandidateLease, PlatformError> {
        Ok(CandidateLease::new(EjectInventoryHandle {
            state: Arc::clone(&self.state),
        }))
    }
}

/// Exact retained handle implementing the complete production safe/forced eject boundary.
struct EjectInventoryHandle {
    state: Arc<Mutex<EjectInventoryState>>,
}

impl PlatformDeviceHandle for EjectInventoryHandle {
    /// Supplies the same complete identity proof as the existing production fixture.
    fn execute(&mut self, command: &crate::protocol::Command) -> CommandDispatch {
        let bytes = match command.cdb() {
            [0x12, 0, 0, 0, 0xFE, 0] => mode_standard_inquiry(283),
            [0x12, 1, 0x83, 0, 0xFE, 0] => mode_device_identification(),
            [0x5A, 0, 0x31, 0, 0, 0, 0, 0, 0xFE, 0] => {
                vec![0x00, 0x0B, 0, 0, 0, 0, 0, 0, 0x31, 0x03, 0, 0, 0x18]
            }
            _ => return CommandDispatch::NotSent(crate::transport::TransportError::Unavailable),
        };
        CommandDispatch::Succeeded(TransportResponse::new(bytes).unwrap())
    }

    /// Reports exact media presence before eject and exact absence afterwards.
    fn host_volume_facts(
        &mut self,
    ) -> Result<crate::operations::HostVolumeFacts, crate::operations::PrimitiveFailure> {
        let media_present = !self.state.lock().unwrap().ejected;
        Ok(crate::operations::HostVolumeFacts {
            media_present,
            writable: media_present,
            mounted: media_present,
            free_bytes: if media_present { 300_000_000_000 } else { 0 },
            capacity_bytes: if media_present { 320_000_000_000 } else { 0 },
            filesystem: media_present.then_some(crate::operations::FileSystem::Ntfs),
            topology: crate::operations::VolumeTopology::Simple,
            media_fingerprint: media_present.then_some([0xA5; 32]),
        })
    }

    /// Completes safe unmount/eject only after the operation crosses its mutation barrier.
    fn safe_eject_exact(
        &mut self,
        after_unmount: &mut dyn FnMut() -> bool,
    ) -> Result<(), crate::operations::PrimitiveFailure> {
        if !after_unmount() {
            return Err(crate::operations::PrimitiveFailure::not_attempted(
                crate::operations::HostPrimitiveError::Cancelled,
            ));
        }
        let mut state = self.state.lock().unwrap();
        state.ejected = true;
        state.ejects += 1;
        Ok(())
    }

    /// Completes the separately confirmed force-eject primitive.
    fn eject_exact(&mut self, force: bool) -> Result<(), crate::operations::PrimitiveFailure> {
        assert!(force);
        let mut state = self.state.lock().unwrap();
        state.ejected = true;
        state.ejects += 1;
        Ok(())
    }

    /// Proves the exact operation handle observed physical departure.
    fn verify_eject_departure(&mut self) -> Result<(), crate::operations::PrimitiveFailure> {
        if self.state.lock().unwrap().ejected {
            Ok(())
        } else {
            Err(crate::operations::PrimitiveFailure::completion_unknown(
                crate::operations::HostPrimitiveError::Other,
            ))
        }
    }
}

/// Starts one safe or forced eject and returns its complete ordered worker signals.
fn run_production_eject_with_post_scan(
    kind: OperationKind,
    post_eject: PostEjectDiscovery,
) -> (
    HardwareServiceBackend<EjectInventoryPlatform>,
    Vec<super::super::events::ServiceOperationSignal>,
    Arc<Mutex<EjectInventoryState>>,
) {
    let state = Arc::new(Mutex::new(EjectInventoryState {
        ejected: false,
        ejects: 0,
        enumerations: 0,
        post_eject,
    }));
    let mut backend = HardwareServiceBackend::new(
        ServicePlatform::Darwin,
        EjectInventoryPlatform {
            state: Arc::clone(&state),
        },
    );
    let snapshot = backend.scan_devices().unwrap().remove(0);
    let request = match kind {
        OperationKind::EjectSafe => OperationRequest::EjectSafe {
            device_id: snapshot.id.clone(),
            device_revision: snapshot.revision,
        },
        OperationKind::EjectForce => {
            let confirmation_token = backend
                .issue_confirmation(ConfirmationRequest::EjectForce {
                    device_id: snapshot.id.clone(),
                    device_revision: snapshot.revision,
                })
                .unwrap();
            OperationRequest::EjectForce {
                device_id: snapshot.id.clone(),
                device_revision: snapshot.revision,
                confirmation_token,
            }
        }
        _ => unreachable!("fixture supports only eject operations"),
    };
    let operation_id = OperationId::new(match kind {
        OperationKind::EjectSafe => "op:post-eject-safe",
        OperationKind::EjectForce => "op:post-eject-force",
        _ => unreachable!("fixture supports only eject operations"),
    })
    .unwrap();
    let (sender, receiver) = mpsc::sync_channel(8);
    let crashes = super::super::crash::CrashAdmission::new();
    backend
        .start_operation(
            operation_id.clone(),
            request,
            ServiceEventSink::new(sender, crashes.clone()),
        )
        .unwrap();
    backend.release_operation(&operation_id).unwrap();
    let signals = receiver
        .iter()
        .take(5)
        .map(|signal| *signal)
        .collect::<Vec<_>>();
    assert!(crashes.observe().is_ok());
    (backend, signals, state)
}

/// Proven safe and force ejects publish only a retained same-dock NoMedia inventory.
#[test]
fn production_eject_success_publishes_same_dock_no_media_inventory() {
    for kind in [OperationKind::EjectSafe, OperationKind::EjectForce] {
        let (mut backend, signals, state) =
            run_production_eject_with_post_scan(kind, PostEjectDiscovery::SameDockNoMedia);
        let terminal = signals.last().expect("eject terminal is published");
        assert!(matches!(
            terminal.event,
            crate::model::OperationEvent::Succeeded { .. }
        ));
        let inventory = terminal
            .inventory_update
            .as_ref()
            .expect("same dock without media is attached before success");
        assert_eq!(inventory.snapshots().len(), 1);
        assert_eq!(
            inventory.snapshots()[0].media_state,
            crate::model::MediaState::NoMedia
        );
        assert!(inventory.snapshots()[0].media.is_none());
        let cached = backend.list_devices().unwrap();
        assert_eq!(cached, inventory.snapshots());
        let state = state.lock().unwrap();
        assert_eq!(state.ejects, 1);
        assert_eq!(state.enumerations, 2);
    }
}

/// Empty or failed post-eject scans cannot replace or accompany a proven success terminal.
#[test]
fn production_eject_success_suppresses_inconclusive_inventory() {
    for post_eject in [PostEjectDiscovery::Empty, PostEjectDiscovery::Error] {
        let (mut backend, signals, state) =
            run_production_eject_with_post_scan(OperationKind::EjectSafe, post_eject);
        let terminal = signals.last().expect("eject terminal is published");
        assert!(matches!(
            terminal.event,
            crate::model::OperationEvent::Succeeded { .. }
        ));
        assert!(terminal.inventory_update.is_none());
        let cached = backend.list_devices().unwrap();
        assert_eq!(cached.len(), 1);
        assert_eq!(cached[0].media_state, crate::model::MediaState::Present);
        let follow_up_id = OperationId::new(match post_eject {
            PostEjectDiscovery::Empty => "op:post-eject-empty-follow-up",
            PostEjectDiscovery::Error => "op:post-eject-error-follow-up",
            PostEjectDiscovery::SameDockNoMedia => unreachable!(),
        })
        .unwrap();
        let (sender, receiver) = mpsc::sync_channel(4);
        let crashes = super::super::crash::CrashAdmission::new();
        backend
            .start_operation(
                follow_up_id.clone(),
                OperationRequest::StatusRefresh {
                    device_id: cached[0].id.clone(),
                    device_revision: cached[0].revision,
                },
                ServiceEventSink::new(sender, crashes.clone()),
            )
            .expect("suppressed refresh preserves the displayed registry binding");
        backend.release_operation(&follow_up_id).unwrap();
        assert_eq!(receiver.iter().take(2).count(), 2);
        assert!(crashes.observe().is_ok());
        let state = state.lock().unwrap();
        assert!(state.ejected);
        assert_eq!(state.ejects, 1);
        assert_eq!(state.enumerations, 3);
    }
}

/// The production backend dispatches both proven setters, reconnects, and proves readback.
#[test]
fn production_backend_dispatches_mode_setters_and_readback() {
    let state = Arc::new(Mutex::new(ModePlatformState {
        drive_mode: 1,
        firmware_finalize_unknown: 0,
        firmware_revision: 283,
        firmware_target_revision: 283,
        firmware_target_drive_mode: None,
        firmware_reset_delay: 0,
        firmware_cache_discovery: false,
        firmware_activation_scans: None,
        firmware_rebind_failures: 0,
        post_reset_opens: None,
        firmware_probe_failures: 0,
        post_reset_inquiries: 0,
        firmware_nonretryable_failure: false,
        firmware_transfer_failures: 0,
        manufacturing_fault: Default::default(),
        #[cfg(unix)]
        manufacturing_backups: Vec::new(),
        sata_mode: 2,
        commands: Vec::new(),
    }));
    let mut backend = HardwareServiceBackend::new(
        ServicePlatform::Darwin,
        ModePlatform {
            state: Arc::clone(&state),
        },
    );
    let snapshot = backend.scan_devices().unwrap().remove(0);
    let (sender, receiver) = mpsc::sync_channel(16);
    let crashes = super::super::crash::CrashAdmission::new();
    let sink = ServiceEventSink::new(sender, crashes.clone());

    let operation_id = OperationId::new("op:drive-mode-production").unwrap();
    backend
        .start_operation(
            operation_id.clone(),
            OperationRequest::DriveModeSet {
                device_id: snapshot.id.clone(),
                device_revision: snapshot.revision,
                mode: crate::model::DriveMode::Fixed,
            },
            sink,
        )
        .unwrap();
    backend.release_operation(&operation_id).unwrap();
    let events = (0..4)
        .map(|_| receiver.recv_timeout(Duration::from_secs(2)).unwrap().event)
        .collect::<Vec<_>>();

    assert!(matches!(
        events.last(),
        Some(crate::model::OperationEvent::Succeeded { .. })
    ));
    assert!(backend.list_devices().unwrap()[0].revision > snapshot.revision);
    let state = state.lock().unwrap();
    assert_eq!(state.drive_mode, 2);
    assert!(state.commands.iter().any(|cdb| cdb.first() == Some(&0x55)));
    assert!(crashes.observe().is_ok());
    drop(state);

    let sata_state = Arc::new(Mutex::new(ModePlatformState {
        drive_mode: 2,
        firmware_finalize_unknown: 0,
        firmware_revision: 283,
        firmware_target_revision: 283,
        firmware_target_drive_mode: None,
        firmware_reset_delay: 0,
        firmware_cache_discovery: false,
        firmware_activation_scans: None,
        firmware_rebind_failures: 0,
        post_reset_opens: None,
        firmware_probe_failures: 0,
        post_reset_inquiries: 0,
        firmware_nonretryable_failure: false,
        firmware_transfer_failures: 0,
        manufacturing_fault: Default::default(),
        #[cfg(unix)]
        manufacturing_backups: Vec::new(),
        sata_mode: 2,
        commands: Vec::new(),
    }));
    let mut sata_backend = HardwareServiceBackend::new(
        ServicePlatform::Darwin,
        ModePlatform {
            state: Arc::clone(&sata_state),
        },
    );
    let snapshot = sata_backend.scan_devices().unwrap().remove(0);
    let (sender, receiver) = mpsc::sync_channel(16);
    let crashes = super::super::crash::CrashAdmission::new();
    let sink = ServiceEventSink::new(sender, crashes.clone());
    let operation_id = OperationId::new("op:sata-mode-production").unwrap();
    sata_backend
        .start_operation(
            operation_id.clone(),
            OperationRequest::SataModeSet {
                device_id: snapshot.id,
                device_revision: snapshot.revision,
                mode: crate::model::SataMode::ThreeGSixG,
            },
            sink,
        )
        .unwrap();
    sata_backend.release_operation(&operation_id).unwrap();
    let events = (0..4)
        .map(|_| receiver.recv_timeout(Duration::from_secs(2)).unwrap().event)
        .collect::<Vec<_>>();

    assert!(matches!(
        events.last(),
        Some(crate::model::OperationEvent::Succeeded { .. })
    ));
    let sata_state = sata_state.lock().unwrap();
    assert_eq!(sata_state.sata_mode, 3);
    assert!(
        sata_state
            .commands
            .iter()
            .any(|cdb| cdb == &[0x1D, 0x05, 0, 0, 0, 0])
    );
    assert!(crashes.observe().is_ok());
}

/// The production backend reaches both advertised diagnostics and their cleanup terminals.
#[test]
fn production_backend_dispatches_self_and_led_diagnostics() {
    let state = Arc::new(Mutex::new(ModePlatformState {
        drive_mode: 1,
        firmware_finalize_unknown: 0,
        firmware_revision: 283,
        firmware_target_revision: 283,
        firmware_target_drive_mode: None,
        firmware_reset_delay: 0,
        firmware_cache_discovery: false,
        firmware_activation_scans: None,
        firmware_rebind_failures: 0,
        post_reset_opens: None,
        firmware_probe_failures: 0,
        post_reset_inquiries: 0,
        firmware_nonretryable_failure: false,
        firmware_transfer_failures: 0,
        manufacturing_fault: Default::default(),
        #[cfg(unix)]
        manufacturing_backups: Vec::new(),
        sata_mode: 2,
        commands: Vec::new(),
    }));
    let mut backend = HardwareServiceBackend::new(
        ServicePlatform::Darwin,
        ModePlatform {
            state: Arc::clone(&state),
        },
    );
    let snapshot = backend.scan_devices().unwrap().remove(0);

    for (suffix, request) in [
        (
            "self-production",
            OperationRequest::SelfTest {
                device_id: snapshot.id.clone(),
                device_revision: snapshot.revision,
            },
        ),
        (
            "led-production",
            OperationRequest::LedTest {
                device_id: snapshot.id.clone(),
                device_revision: snapshot.revision,
            },
        ),
    ] {
        let (sender, receiver) = mpsc::sync_channel(8);
        let crashes = super::super::crash::CrashAdmission::new();
        let operation_id = OperationId::new(format!("op:{suffix}")).unwrap();
        backend
            .start_operation(
                operation_id.clone(),
                request,
                ServiceEventSink::new(sender, crashes.clone()),
            )
            .unwrap();
        backend.release_operation(&operation_id).unwrap();
        let terminal = (0..4).find_map(|_| {
            // The original LED sequence remains active for 7.8 seconds before restoration.
            let event = receiver
                .recv_timeout(Duration::from_secs(10))
                .unwrap()
                .event;
            matches!(
                event,
                crate::model::OperationEvent::Succeeded { .. }
                    | crate::model::OperationEvent::Failed { .. }
                    | crate::model::OperationEvent::Cancelled { .. }
            )
            .then_some(event)
        });
        assert!(matches!(
            terminal,
            Some(crate::model::OperationEvent::Succeeded { .. })
        ));
        assert!(crashes.observe().is_ok());
        // A terminal event precedes the worker's final active-control release.
        // Queue an exact rescan as a barrier before admitting the next test;
        // do not race that release or insert an arbitrary timing sleep.
        let refreshed = backend.scan_devices().unwrap();
        assert_eq!(refreshed.len(), 1);
        assert_eq!(refreshed[0].id, snapshot.id);
        assert_eq!(refreshed[0].revision, snapshot.revision);
    }

    let state = state.lock().unwrap();
    assert!(
        state
            .commands
            .iter()
            .any(|cdb| cdb == &[0x1D, 0x04, 0, 0, 0, 0])
    );
    assert_eq!(
        state
            .commands
            .iter()
            .filter(|cdb| cdb.as_slice() == [0x1D, 0, 0, 0, 8, 0])
            .count(),
        2
    );
}

/// Cancellation before release still publishes every mandatory diagnostic recovery stage.
#[test]
fn queued_production_diagnostics_cancel_with_sequential_recovery() {
    for (suffix, request_kind, expected_stages) in [
        (
            "self-queued-cancel",
            OperationKind::SelfTest,
            vec![
                "diagnostic-running",
                "diagnostic-cleanup",
                "diagnostic-cleanup",
            ],
        ),
        (
            "led-queued-cancel",
            OperationKind::LedTest,
            vec![
                "led-testing",
                "led-restoring",
                "led-readback",
                "led-readback",
            ],
        ),
    ] {
        let state = Arc::new(Mutex::new(ModePlatformState {
            drive_mode: 1,
            firmware_finalize_unknown: 0,
            firmware_revision: 283,
            firmware_target_revision: 283,
            firmware_target_drive_mode: None,
            firmware_reset_delay: 0,
            firmware_cache_discovery: false,
            firmware_activation_scans: None,
            firmware_rebind_failures: 0,
            post_reset_opens: None,
            firmware_probe_failures: 0,
            post_reset_inquiries: 0,
            firmware_nonretryable_failure: false,
            firmware_transfer_failures: 0,
            manufacturing_fault: Default::default(),
            #[cfg(unix)]
            manufacturing_backups: Vec::new(),
            sata_mode: 2,
            commands: Vec::new(),
        }));
        let mut backend = HardwareServiceBackend::new(
            ServicePlatform::Darwin,
            ModePlatform {
                state: Arc::clone(&state),
            },
        );
        let snapshot = backend.scan_devices().unwrap().remove(0);
        let request = match request_kind {
            OperationKind::SelfTest => OperationRequest::SelfTest {
                device_id: snapshot.id,
                device_revision: snapshot.revision,
            },
            OperationKind::LedTest => OperationRequest::LedTest {
                device_id: snapshot.id,
                device_revision: snapshot.revision,
            },
            _ => unreachable!(),
        };
        let operation_id = OperationId::new(format!("op:{suffix}")).unwrap();
        let (sender, receiver) = mpsc::sync_channel(8);
        let crashes = super::super::crash::CrashAdmission::new();
        backend
            .start_operation(
                operation_id.clone(),
                request,
                ServiceEventSink::new(sender, crashes.clone()),
            )
            .unwrap();
        backend.cancel_operation(&operation_id).unwrap();
        backend.release_operation(&operation_id).unwrap();

        let events = (0..expected_stages.len())
            .map(|_| receiver.recv_timeout(Duration::from_secs(2)).unwrap().event)
            .collect::<Vec<_>>();
        let stages = events
            .iter()
            .map(|event| match event {
                crate::model::OperationEvent::Started { stage, .. }
                | crate::model::OperationEvent::Progress { stage, .. }
                | crate::model::OperationEvent::Cancelled { stage, .. } => stage.as_str(),
                _ => "unexpected-terminal",
            })
            .collect::<Vec<_>>();
        assert_eq!(stages, expected_stages);
        assert!(matches!(
            events.last(),
            Some(crate::model::OperationEvent::Cancelled { .. })
        ));
        assert!(crashes.observe().is_ok());
        let commands = &state.lock().unwrap().commands;
        assert!(!commands.iter().any(|cdb| cdb == &[0x1D, 0x04, 0, 0, 0, 0]));
        assert_eq!(
            commands
                .iter()
                .filter(|cdb| cdb.as_slice() == [0x1D, 0, 0, 0, 8, 0])
                .count(),
            usize::from(request_kind == OperationKind::LedTest)
        );
    }
}

/// Parsed SCSI status is reduced to stable firmware categories without losing
/// the distinctions needed for recovery guidance.
#[test]
fn firmware_check_conditions_keep_their_sanitized_category() {
    for ((key, asc, ascq), expected) in [
        (
            (0x07, 0x74, 0x08),
            HostPrimitiveError::FirmwareSignatureRejected,
        ),
        (
            (0x05, 0x20, 0x00),
            HostPrimitiveError::FirmwareCommandUnsupported,
        ),
        (
            (0x05, 0x24, 0x00),
            HostPrimitiveError::FirmwareCommandInvalid,
        ),
        (
            (0x02, 0x04, 0x01),
            HostPrimitiveError::FirmwareDeviceNotReady,
        ),
        (
            (0x04, 0x44, 0x00),
            HostPrimitiveError::FirmwareHardwareFailure,
        ),
        (
            (0x07, 0x27, 0x00),
            HostPrimitiveError::FirmwareWriteProtected,
        ),
        (
            (0x06, 0x29, 0x00),
            HostPrimitiveError::FirmwareUnitAttention,
        ),
        (
            (0x05, 0x26, 0x00),
            HostPrimitiveError::FirmwareDeviceRejected,
        ),
    ] {
        let sense = crate::protocol::SenseData::parse(&[0x72, key, asc, ascq, 0, 0, 0, 0])
            .expect("test sense is a complete descriptor-format response");
        assert_eq!(
            firmware_failure::check_condition_cause(&sense),
            expected,
            "sense {key:02x}/{asc:02x}/{ascq:02x}"
        );
    }
}

#[path = "hardware_firmware_tests.rs"]
mod firmware_tests;

#[path = "hardware_firmware_inventory_tests.rs"]
mod firmware_inventory_tests;

#[path = "hardware_firmware_restore_tests.rs"]
mod firmware_restore_tests;

#[cfg(unix)]
#[path = "hardware_manufacturing_restore_tests.rs"]
mod manufacturing_restore_tests;
#[path = "hardware_manufacturing_tests.rs"]
mod manufacturing_tests;
