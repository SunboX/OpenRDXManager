// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

use rdx_service::firmware::{FirmwareRevision, ProductFamily};
use rdx_service::host::{
    DeviceInterface, DeviceSession, FixtureDevice, HostOperationError, SessionDevice,
    SessionGeneration,
};
use rdx_service::model::{DeviceId, DeviceIdentity, DiscoveryRevision, OperationId, OperationKind};
use rdx_service::operations::{CancellationRequestResult, OperationContext};
use rdx_service::transport::{MAX_TRANSPORT_RESPONSE_LENGTH, TransportError, TransportResponse};

/// Builds one exact fixture discovery result.
fn device(id: &str, revision: u64, family: ProductFamily, generation: u64) -> SessionDevice {
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

/// Opens one device-owned fixture session and retains its control surface.
fn session() -> (FixtureDevice, DeviceSession) {
    let fixture = FixtureDevice::new(device("rdx:session", 7, ProductFamily::Usb3Sata3, 41));
    let session = fixture.open();
    (fixture, session)
}

/// Proves the device-bound response contract rejects unbounded adapter data.
#[test]
fn session_response_contract_is_bounded_before_operation_parsing() {
    assert_eq!(
        TransportResponse::new(vec![0; MAX_TRANSPORT_RESPONSE_LENGTH + 1]),
        Err(TransportError::ResponseTooLarge {
            maximum: MAX_TRANSPORT_RESPONSE_LENGTH,
            actual: MAX_TRANSPORT_RESPONSE_LENGTH + 1,
        })
    );
}

/// Proves operation ownership is derived from, rather than supplied beside, the lease.
#[test]
fn context_captures_the_exact_active_session_identity_and_generation() {
    let (_fixture, session) = session();

    let context = OperationContext::for_session(
        OperationId::new("op:session-owner").unwrap(),
        OperationKind::SelfTest,
        &session,
    )
    .unwrap();

    assert_eq!(context.owner().device(), session.device().identity());
    assert_eq!(context.owner().product_family(), ProductFamily::Usb3Sata3);
    assert_eq!(context.owner().generation().get(), 41);
}

/// Proves cancellation capability accepts only its exact immutable owner.
#[test]
fn cancellation_capability_rejects_another_session_owner() {
    let (_fixture, session) = session();
    let context = OperationContext::for_session(
        OperationId::new("op:session-owner").unwrap(),
        OperationKind::SelfTest,
        &session,
    )
    .unwrap();
    let other = OperationContext::for_session(
        OperationId::new("op:other-owner").unwrap(),
        OperationKind::SelfTest,
        &session,
    )
    .unwrap();
    let handle = context.cancellation_handle();

    assert_eq!(
        handle.request(other.owner()),
        CancellationRequestResult::NotOwner
    );
    assert_eq!(
        handle.request(context.owner()),
        CancellationRequestResult::Accepted
    );
    assert_eq!(
        handle.request(context.owner()),
        CancellationRequestResult::AlreadyRequested
    );
}

/// Proves identical public owner fields cannot substitute another session capability.
#[test]
fn cancellation_capability_rejects_an_unrelated_metadata_identical_session() {
    let first_fixture =
        FixtureDevice::new(device("rdx:identical", 7, ProductFamily::Usb3Sata3, 41));
    let first_session = first_fixture.open();
    let first = OperationContext::for_session(
        OperationId::new("op:identical-owner").unwrap(),
        OperationKind::SelfTest,
        &first_session,
    )
    .unwrap();
    let second_fixture =
        FixtureDevice::new(device("rdx:identical", 7, ProductFamily::Usb3Sata3, 41));
    let second_session = second_fixture.open();
    let second = OperationContext::for_session(
        OperationId::new("op:identical-owner").unwrap(),
        OperationKind::SelfTest,
        &second_session,
    )
    .unwrap();

    assert_eq!(
        first.cancellation_handle().request(second.owner()),
        CancellationRequestResult::NotOwner
    );
}

/// Proves an exact refresh keeps the same lease active.
#[test]
fn exact_refresh_preserves_the_active_bound_session() {
    let (fixture, mut session) = session();
    fixture.queue_refresh(Ok(device("rdx:session", 7, ProductFamily::Usb3Sata3, 41)));

    session.revalidate().unwrap();

    assert!(session.is_active());
    assert_eq!(session.device().identity().revision.get(), 7);
    assert_eq!(session.device().generation().get(), 41);
}

/// Proves stale/mismatched refresh evidence cannot leave an executable lease active.
#[test]
fn mismatched_refresh_invalidates_the_session() {
    let (fixture, mut session) = session();
    fixture.queue_refresh(Ok(device("rdx:other", 7, ProductFamily::Usb3Sata3, 41)));

    assert_eq!(
        session.revalidate(),
        Err(HostOperationError::DeviceIdentityChanged)
    );
    assert!(!session.is_active());
}

/// Proves revision and generation changes cannot pass active-lease revalidation.
#[test]
fn refresh_revision_or_generation_change_invalidates_the_lease() {
    for changed in [
        device("rdx:session", 8, ProductFamily::Usb3Sata3, 41),
        device("rdx:session", 7, ProductFamily::Usb3Sata3, 42),
    ] {
        let (fixture, mut session) = session();
        fixture.queue_refresh(Ok(changed));

        assert!(session.revalidate().is_err());
        assert!(!session.is_active());
    }
}

/// Proves reconnect creates a fresh lease only for the same physical family/device.
#[test]
fn reconnect_rebinds_only_a_fresh_same_device_session() {
    let (fixture, mut session) = session();
    fixture.queue_reconnect(Ok(device("rdx:session", 8, ProductFamily::Usb3Sata3, 42)));

    session.reconnect(15).unwrap();

    assert!(session.is_active());
    assert_eq!(session.device().identity().revision.get(), 8);
    assert_eq!(session.device().generation().get(), 42);
}

/// Proves a reconnect family mismatch leaves the prior lease invalidated.
#[test]
fn reconnect_family_mismatch_never_reactivates_the_old_lease() {
    let (fixture, mut session) = session();
    fixture.queue_reconnect(Ok(device("rdx:session", 8, ProductFamily::Usb2Sata1, 42)));

    assert_eq!(
        session.reconnect(15),
        Err(HostOperationError::ProductFamilyChanged)
    );
    assert!(!session.is_active());
}
