// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

use rdx_service::firmware::{FirmwareRevision, ProductFamily};
use rdx_service::host::{
    DeviceInterface, DeviceSession, FixtureDevice, HostOperationError, SessionDevice,
    SessionGeneration,
};
use rdx_service::model::{
    DeviceId, DeviceIdentity, DiscoveryRevision, DriveMode, OperationId, OperationKind, SataMode,
};
use rdx_service::operations::{
    CancellationRequestResult, OperationContext, OperationIssue, OperationStage, set_drive_mode,
    set_sata_mode,
};
use rdx_service::transport::{
    CommandDispatch, DispatchCertainty, TransportError, TransportResponse,
};

/// Builds one exact no-media SATA III session snapshot.
fn device(id: &str, revision: u64, generation: u64) -> SessionDevice {
    device_with(id, revision, generation, DeviceInterface::Sata3, false)
}

/// Builds one exact mode fixture with explicit interface and media state.
fn device_with(
    id: &str,
    revision: u64,
    generation: u64,
    interface: DeviceInterface,
    media_present: bool,
) -> SessionDevice {
    SessionDevice::fixture(
        DeviceIdentity {
            id: DeviceId::new(id).unwrap(),
            revision: DiscoveryRevision::new(revision).unwrap(),
        },
        ProductFamily::Usb3Sata3,
        FirmwareRevision::new(282).unwrap(),
        interface,
        media_present,
        SessionGeneration::new(generation).unwrap(),
    )
}

/// Builds one mode fixture with an explicit product family for rebind tests.
fn device_with_family(
    id: &str,
    revision: u64,
    generation: u64,
    family: ProductFamily,
) -> SessionDevice {
    SessionDevice::fixture(
        DeviceIdentity {
            id: DeviceId::new(id).unwrap(),
            revision: DiscoveryRevision::new(revision).unwrap(),
        },
        family,
        FirmwareRevision::new(282).unwrap(),
        DeviceInterface::Sata3,
        false,
        SessionGeneration::new(generation).unwrap(),
    )
}

/// Builds a literal page-0x34 response with unrelated sentinel bytes.
fn mode_page(operation_mode: u8, sata_speed: u8) -> Vec<u8> {
    vec![
        0x00,
        0x0D,
        0x7E,
        0x10,
        0x00,
        0x00,
        0x00,
        0x00,
        0xB4,
        0x05,
        0x55,
        0x66,
        0xA0 | operation_mode,
        0x77,
        sata_speed,
    ]
}

/// Queues one successful bounded data-in response.
fn queue_data(fixture: &FixtureDevice, bytes: Vec<u8>) {
    fixture.queue_dispatch(CommandDispatch::Succeeded(
        TransportResponse::new(bytes).unwrap(),
    ));
}

/// Opens one mode-operation fixture and exact session-derived context.
fn operation(
    kind: OperationKind,
    suffix: &str,
) -> (FixtureDevice, DeviceSession, OperationContext) {
    let fixture = FixtureDevice::new(device("rdx:mode", 7, 71));
    let session = fixture.open();
    let context = OperationContext::for_session(
        OperationId::new(format!("op:{suffix}")).unwrap(),
        kind,
        &session,
    )
    .unwrap();
    (fixture, session, context)
}

/// Opens one mode operation against an explicit fixture session snapshot.
fn operation_on(
    kind: OperationKind,
    suffix: &str,
    current: SessionDevice,
) -> (FixtureDevice, DeviceSession, OperationContext) {
    let fixture = FixtureDevice::new(current);
    let session = fixture.open();
    let context = OperationContext::for_session(
        OperationId::new(format!("op:{suffix}")).unwrap(),
        kind,
        &session,
    )
    .unwrap();
    (fixture, session, context)
}

/// Proves drive mode preserves unrelated bytes and reads only after a fresh rebound.
#[test]
fn drive_mode_preserves_page_rebinds_and_reads_back() {
    let (fixture, mut session, context) = operation(OperationKind::DriveModeSet, "drive");
    let before = mode_page(2, 3);
    queue_data(&fixture, before.clone());
    fixture.queue_dispatch(CommandDispatch::Succeeded(TransportResponse::empty()));
    fixture.queue_reconnect(Ok(device("rdx:mode", 8, 72)));
    queue_data(&fixture, mode_page(1, 3));

    set_drive_mode(&mut session, context, DriveMode::Removable).unwrap();

    let commands = fixture.commands();
    assert_eq!(
        commands
            .iter()
            .map(|call| call.command().cdb()[0])
            .collect::<Vec<_>>(),
        [0x5A, 0x55, 0x5A]
    );
    let mut expected = before;
    expected[0..3].fill(0);
    expected[12] = 0xA1;
    assert_eq!(commands[1].command().data_out(), expected);
    assert_eq!(commands[1].command().cdb()[1] & 0x01, 0x01);
    assert_ne!(
        commands[0].lease().generation(),
        commands[2].lease().generation()
    );
}

/// Proves SATA mutation preserves unrelated bytes and uses unsaved select plus reset.
#[test]
fn sata_mode_preserves_page_uses_unsaved_select_reset_and_readback() {
    let (fixture, mut session, context) = operation(OperationKind::SataModeSet, "sata-success");
    let before = mode_page(2, 2);
    queue_data(&fixture, before.clone());
    fixture.queue_dispatch(CommandDispatch::Succeeded(TransportResponse::empty()));
    fixture.queue_dispatch(CommandDispatch::Succeeded(TransportResponse::empty()));
    fixture.queue_reconnect(Ok(device("rdx:mode", 8, 72)));
    queue_data(&fixture, mode_page(2, 3));

    set_sata_mode(&mut session, context, SataMode::ThreeGSixG).unwrap();

    let commands = fixture.commands();
    assert_eq!(
        commands
            .iter()
            .map(|call| call.command().cdb()[0])
            .collect::<Vec<_>>(),
        [0x5A, 0x55, 0x1D, 0x5A]
    );
    let mut expected = before;
    expected[0..3].fill(0);
    expected[14] = 3;
    assert_eq!(commands[1].command().data_out(), expected);
    assert_eq!(commands[1].command().cdb()[1] & 0x01, 0);
}

/// Proves a no-op issues neither mutation, reset, reconnect, nor second read.
#[test]
fn mode_noop_uses_the_initial_fresh_read_as_proof() {
    let (fixture, mut session, context) = operation(OperationKind::SataModeSet, "noop");
    queue_data(&fixture, mode_page(2, 2));

    set_sata_mode(&mut session, context, SataMode::OnePointFiveGThreeG).unwrap();

    assert_eq!(fixture.commands().len(), 1);
    assert_eq!(fixture.reconnect_count(), 0);
}

/// Proves fresh no-media and SATA-interface gates prevent every device command.
#[test]
fn mode_preflight_rejects_media_and_non_sata_interface_without_commands() {
    let cases = [
        (
            OperationKind::DriveModeSet,
            device_with("rdx:mode", 7, 71, DeviceInterface::Sata3, true),
            OperationIssue::MediaPresent,
        ),
        (
            OperationKind::SataModeSet,
            device_with("rdx:mode", 7, 71, DeviceInterface::Usb3, false),
            OperationIssue::UnsupportedInterface,
        ),
    ];

    for (kind, current, expected) in cases {
        let (fixture, mut session, context) = operation_on(kind, "preflight", current);
        let failure = match kind {
            OperationKind::DriveModeSet => {
                set_drive_mode(&mut session, context, DriveMode::Removable).unwrap_err()
            }
            OperationKind::SataModeSet => {
                set_sata_mode(&mut session, context, SataMode::ThreeGSixG).unwrap_err()
            }
            _ => unreachable!("fixture contains only mode operations"),
        };

        assert_eq!(failure.primary().issue(), &expected);
        assert!(fixture.commands().is_empty());
    }
}

/// Proves configuration cancellation is closed before its first native stage.
#[test]
fn mode_operations_are_non_cancellable_before_command_dispatch() {
    let (fixture, mut session, context) = operation(OperationKind::DriveModeSet, "closed");
    let owner = context.owner().clone();
    assert_eq!(
        context.cancellation_handle().request(&owner),
        CancellationRequestResult::Closed
    );
    queue_data(&fixture, mode_page(1, 3));

    set_drive_mode(&mut session, context, DriveMode::Removable).unwrap();

    assert_eq!(fixture.commands().len(), 1);
}

/// Proves definite MODE SELECT rejection performs no reset, reconnect, or readback.
#[test]
fn sata_definite_rejection_does_not_reset_or_reconnect() {
    let (fixture, mut session, context) = operation(OperationKind::SataModeSet, "rejected");
    queue_data(&fixture, mode_page(2, 2));
    fixture.queue_dispatch(CommandDispatch::DefinitelyRejected(
        TransportError::CheckCondition(
            rdx_service::protocol::SenseData::parse(&[
                0x70, 0, 0x05, 0, 0, 0, 0, 10, 0, 0, 0, 0, 0x24, 0, 0, 0, 0, 0,
            ])
            .unwrap(),
        ),
    ));

    let failure = set_sata_mode(&mut session, context, SataMode::ThreeGSixG).unwrap_err();

    assert_eq!(fixture.commands().len(), 2);
    assert_eq!(fixture.reconnect_count(), 0);
    assert_eq!(failure.terminal_stage(), OperationStage::DeviceReadback);
    assert_eq!(
        failure.primary().issue(),
        &OperationIssue::Dispatch {
            certainty: DispatchCertainty::DefinitelyRejected,
            error: TransportError::CheckCondition(
                rdx_service::protocol::SenseData::parse(&[
                    0x70, 0, 0x05, 0, 0, 0, 0, 10, 0, 0, 0, 0, 0x24, 0, 0, 0, 0, 0,
                ])
                .unwrap(),
            ),
        }
    );
}

/// Proves a command proven not sent performs no reset, reconnect, or readback.
#[test]
fn sata_not_sent_does_not_reset_or_reconnect() {
    let (fixture, mut session, context) = operation(OperationKind::SataModeSet, "not-sent");
    queue_data(&fixture, mode_page(2, 2));
    fixture.queue_dispatch(CommandDispatch::NotSent(TransportError::Unavailable));

    let failure = set_sata_mode(&mut session, context, SataMode::ThreeGSixG).unwrap_err();

    assert_eq!(fixture.commands().len(), 2);
    assert_eq!(fixture.reconnect_count(), 0);
    assert_eq!(failure.primary().stage(), OperationStage::DeviceConfiguring);
    assert_eq!(
        failure.primary().issue(),
        &OperationIssue::Dispatch {
            certainty: DispatchCertainty::NotSent,
            error: TransportError::Unavailable,
        }
    );
}

/// Proves completion-unknown MODE SELECT justifies reset, rebind, and readback.
#[test]
fn sata_completion_unknown_runs_recovery_and_readback() {
    let (fixture, mut session, context) = operation(OperationKind::SataModeSet, "unknown");
    queue_data(&fixture, mode_page(2, 2));
    fixture.queue_dispatch(CommandDispatch::CompletionUnknown(TransportError::Timeout));
    fixture.queue_dispatch(CommandDispatch::Succeeded(TransportResponse::empty()));
    fixture.queue_reconnect(Ok(device("rdx:mode", 8, 72)));
    queue_data(&fixture, mode_page(2, 3));

    let failure = set_sata_mode(&mut session, context, SataMode::ThreeGSixG).unwrap_err();

    assert_eq!(fixture.reconnect_count(), 1);
    assert_eq!(
        fixture
            .commands()
            .iter()
            .map(|call| call.command().cdb()[0])
            .collect::<Vec<_>>(),
        [0x5A, 0x55, 0x1D, 0x5A]
    );
    assert_eq!(failure.primary().stage(), OperationStage::DeviceConfiguring);
    assert_eq!(failure.terminal_stage(), OperationStage::DeviceReadback);
}

/// Proves readback is skipped when same-device rebinding cannot be established.
#[test]
fn mode_reconnect_failure_prevents_stale_session_readback() {
    let (fixture, mut session, context) = operation(OperationKind::DriveModeSet, "rebind-fail");
    queue_data(&fixture, mode_page(2, 3));
    fixture.queue_dispatch(CommandDispatch::Succeeded(TransportResponse::empty()));
    fixture.queue_reconnect(Err(HostOperationError::ReconnectTimeout));

    let failure = set_drive_mode(&mut session, context, DriveMode::Removable).unwrap_err();

    assert_eq!(fixture.commands().len(), 2);
    assert_eq!(
        failure.primary().stage(),
        OperationStage::DeviceReconnecting
    );
    assert_eq!(failure.terminal_stage(), OperationStage::DeviceReadback);
    assert!(!session.is_active());
}

/// Proves a replacement lease for another ID is rejected before any readback.
#[test]
fn mode_wrong_device_rebind_prevents_readback() {
    let (fixture, mut session, context) = operation(OperationKind::DriveModeSet, "wrong-device");
    queue_data(&fixture, mode_page(2, 3));
    fixture.queue_dispatch(CommandDispatch::Succeeded(TransportResponse::empty()));
    fixture.queue_reconnect(Ok(device("rdx:other", 8, 72)));

    let failure = set_drive_mode(&mut session, context, DriveMode::Removable).unwrap_err();

    assert_eq!(fixture.commands().len(), 2);
    assert_eq!(fixture.reconnect_count(), 1);
    assert_eq!(
        failure.primary().issue(),
        &OperationIssue::PostMutationRebind(HostOperationError::DeviceIdentityChanged)
    );
    assert!(failure.primary().is_ambiguous());
    assert!(!session.is_active());
}

/// Proves every invalid post-mutation lease transition is classified ambiguous.
#[test]
fn post_mutation_identity_family_and_generation_rebind_failures_are_ambiguous() {
    let cases = [
        (
            device("rdx:other", 8, 72),
            HostOperationError::DeviceIdentityChanged,
        ),
        (
            device_with_family("rdx:mode", 8, 72, ProductFamily::Usb2Sata1),
            HostOperationError::ProductFamilyChanged,
        ),
        (
            device("rdx:mode", 8, 71),
            HostOperationError::StaleSessionGeneration,
        ),
    ];

    for (rebound, expected) in cases {
        let (fixture, mut session, context) =
            operation(OperationKind::DriveModeSet, "ambiguous-rebind");
        queue_data(&fixture, mode_page(2, 3));
        fixture.queue_dispatch(CommandDispatch::Succeeded(TransportResponse::empty()));
        fixture.queue_reconnect(Ok(rebound));

        let failure = set_drive_mode(&mut session, context, DriveMode::Removable).unwrap_err();

        assert_eq!(
            failure.primary().issue(),
            &OperationIssue::PostMutationRebind(expected)
        );
        assert!(failure.primary().is_ambiguous());
        assert_eq!(fixture.commands().len(), 2);
    }
}

/// Proves reset failure remains primary while successful select still justifies rebind.
#[test]
fn sata_reset_rejection_still_rebinds_after_successful_select() {
    let (fixture, mut session, context) = operation(OperationKind::SataModeSet, "reset-fail");
    queue_data(&fixture, mode_page(2, 2));
    fixture.queue_dispatch(CommandDispatch::Succeeded(TransportResponse::empty()));
    fixture.queue_dispatch(CommandDispatch::DefinitelyRejected(
        TransportError::Unavailable,
    ));
    fixture.queue_reconnect(Ok(device("rdx:mode", 8, 72)));
    queue_data(&fixture, mode_page(2, 3));

    let failure = set_sata_mode(&mut session, context, SataMode::ThreeGSixG).unwrap_err();

    assert_eq!(fixture.reconnect_count(), 1);
    assert_eq!(failure.primary().stage(), OperationStage::DeviceConfiguring);
    assert_eq!(
        failure.primary().issue(),
        &OperationIssue::Dispatch {
            certainty: DispatchCertainty::DefinitelyRejected,
            error: TransportError::Unavailable,
        }
    );
}
