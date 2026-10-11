use std::path::PathBuf;

use rdx_service::firmware::{FirmwareImage, FirmwareRevision, ProductFamily};
use rdx_service::host::{
    DeviceInterface, DeviceSession, FixtureDevice, HostOperationError, SessionDevice,
    SessionGeneration,
};
use rdx_service::model::{DeviceId, DeviceIdentity, DiscoveryRevision, OperationId, OperationKind};
use rdx_service::operations::{
    OperationCompletion, OperationContext, OperationIssue, OperationStage, run_firmware_update,
};
use rdx_service::protocol::SenseData;
use rdx_service::transport::{CommandDispatch, DispatchCertainty, TransportError};
use std::sync::{Arc, Barrier};

/// Builds one exact no-media firmware fixture discovery result.
fn device(revision: u64, installed: u16, generation: u64) -> SessionDevice {
    SessionDevice::fixture(
        DeviceIdentity {
            id: DeviceId::new("rdx:firmware").unwrap(),
            revision: DiscoveryRevision::new(revision).unwrap(),
        },
        ProductFamily::Usb3Sata3,
        FirmwareRevision::new(installed).unwrap(),
        DeviceInterface::Sata3,
        false,
        SessionGeneration::new(generation).unwrap(),
    )
}

/// Builds one exact firmware fixture discovery result with media inserted.
fn device_with_media(revision: u64, installed: u16, generation: u64) -> SessionDevice {
    SessionDevice::fixture(
        DeviceIdentity {
            id: DeviceId::new("rdx:firmware").unwrap(),
            revision: DiscoveryRevision::new(revision).unwrap(),
        },
        ProductFamily::Usb3Sata3,
        FirmwareRevision::new(installed).unwrap(),
        DeviceInterface::Sata3,
        true,
        SessionGeneration::new(generation).unwrap(),
    )
}

/// Builds explicit identity/family evidence for unsafe-rebind tests.
fn device_with_identity_and_family(
    id: &str,
    revision: u64,
    installed: u16,
    generation: u64,
    family: ProductFamily,
) -> SessionDevice {
    SessionDevice::fixture(
        DeviceIdentity {
            id: DeviceId::new(id).unwrap(),
            revision: DiscoveryRevision::new(revision).unwrap(),
        },
        family,
        FirmwareRevision::new(installed).unwrap(),
        DeviceInterface::Sata3,
        false,
        SessionGeneration::new(generation).unwrap(),
    )
}

/// Counts only zero-length mode-5 parser finalizers.
fn finalizer_count(fixture: &FixtureDevice) -> usize {
    fixture
        .commands()
        .iter()
        .filter(|call| {
            let cdb = call.command().cdb();
            cdb[0] == 0x3B && cdb[1] == 0x05
        })
        .count()
}

/// Resolves the immutable signed 0283 evidence image.
fn firmware_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("original-inputs/RDX2E__STD__F-0283.bin")
}

/// Opens a fixture and creates a fresh non-reusable authorization/context pair.
fn authorized_operation() -> (
    FixtureDevice,
    DeviceSession,
    OperationContext,
    rdx_service::firmware::InstallableFirmwareImage,
) {
    let fixture = FixtureDevice::new(device(7, 282, 61));
    let mut session = fixture.open();
    let authorization = session
        .authorize_firmware(FirmwareImage::load(firmware_path(), ProductFamily::Usb3Sata3).unwrap())
        .unwrap();
    let context = OperationContext::for_session(
        OperationId::new("op:firmware").unwrap(),
        OperationKind::FirmwareUpdate,
        &session,
    )
    .unwrap();
    (fixture, session, context, authorization)
}

/// Builds the exact signature-rejection sense evidence.
fn signature_error() -> TransportError {
    TransportError::CheckCondition(
        SenseData::parse(&[
            0x70, 0, 0x07, 0, 0, 0, 0, 10, 0, 0, 0, 0, 0x74, 0x08, 0, 0, 0, 0,
        ])
        .unwrap(),
    )
}

/// Builds completion-unknown signature evidence for finalizer reconciliation.
fn uncertain_signature_dispatch() -> CommandDispatch {
    CommandDispatch::CompletionUnknown(signature_error())
}

/// Builds a nonretryable transport error for certainty-policy separation.
fn nonretryable_transport_error() -> TransportError {
    TransportError::ResponseTooLarge {
        maximum: 0x1000,
        actual: 0x1001,
    }
}

/// Proves transfer uses exact 4 KiB chunks and the full monotonic Phase 1 graph.
#[test]
fn firmware_success_uses_bound_authorization_chunks_rebind_and_readback() {
    let (fixture, mut session, context, authorization) = authorized_operation();
    fixture.queue_reconnect(Ok(device(8, 283, 62)));

    let report = run_firmware_update(&mut session, context, authorization).unwrap();

    let commands = fixture.commands();
    let transfer_lengths = commands
        .iter()
        .filter(|call| call.command().cdb()[0] == 0x3B && call.command().cdb()[1] == 0x04)
        .map(|call| call.command().data_out().len())
        .collect::<Vec<_>>();
    assert!(
        transfer_lengths[..transfer_lengths.len() - 1]
            .iter()
            .all(|length| *length == 0x1000)
    );
    assert!(*transfer_lengths.last().unwrap() <= 0x1000);
    assert_eq!(commands.last().unwrap().command().cdb()[1], 0x05);
    assert_eq!(
        report
            .events()
            .iter()
            .map(|event| event.stage())
            .fold(Vec::new(), |mut stages, stage| {
                if stages.last() != Some(&stage) {
                    stages.push(stage);
                }
                stages
            }),
        [
            OperationStage::FirmwareValidating,
            OperationStage::FirmwareWriting,
            OperationStage::FirmwareFinalizing,
            OperationStage::DeviceReconnecting,
            OperationStage::FirmwareReadback,
        ]
    );
    assert!(report.events().iter().all(|event| {
        event.stage() != OperationStage::FirmwareWriting || event.attempt() == Some(1)
    }));
}

/// Proves an authorization is rejected if fresh live installed evidence changed.
#[test]
fn firmware_authorization_is_bound_to_fresh_installed_revision_and_session() {
    let (fixture, mut session, context, authorization) = authorized_operation();
    fixture.queue_refresh(Ok(device(7, 281, 61)));

    let failure = run_firmware_update(&mut session, context, authorization).unwrap_err();

    assert_eq!(
        failure.primary().stage(),
        OperationStage::FirmwareValidating
    );
    assert_eq!(
        failure.primary().issue(),
        &OperationIssue::FirmwareAuthorizationInvalidated
    );
    assert!(fixture.commands().is_empty());
}

/// Proves identical public metadata cannot move an authorization to another session lineage.
#[test]
fn firmware_authorization_rejects_an_unrelated_identical_session_without_dispatch() {
    let first_fixture = FixtureDevice::new(device(7, 282, 61));
    let mut first_session = first_fixture.open();
    let authorization = first_session
        .authorize_firmware(FirmwareImage::load(firmware_path(), ProductFamily::Usb3Sata3).unwrap())
        .unwrap();
    let context = OperationContext::for_session(
        OperationId::new("op:firmware-unrelated").unwrap(),
        OperationKind::FirmwareUpdate,
        &first_session,
    )
    .unwrap();
    let second_fixture = FixtureDevice::new(device(7, 282, 61));
    let mut unrelated_session = second_fixture.open();

    let failure = run_firmware_update(&mut unrelated_session, context, authorization).unwrap_err();

    assert_eq!(
        failure.primary().issue(),
        &OperationIssue::SessionBindingChanged
    );
    assert!(first_fixture.commands().is_empty());
    assert!(second_fixture.commands().is_empty());
    assert_eq!(second_fixture.refresh_count(), 0);
}

/// Proves authorization capability binding is independent of operation-owner binding.
#[test]
fn firmware_authorization_capability_rejects_matching_context_from_an_unrelated_session() {
    let first_fixture = FixtureDevice::new(device(7, 282, 61));
    let mut first_session = first_fixture.open();
    let authorization = first_session
        .authorize_firmware(FirmwareImage::load(firmware_path(), ProductFamily::Usb3Sata3).unwrap())
        .unwrap();
    let second_fixture = FixtureDevice::new(device(7, 282, 61));
    let mut unrelated_session = second_fixture.open();
    let context = OperationContext::for_session(
        OperationId::new("op:authorization-unrelated").unwrap(),
        OperationKind::FirmwareUpdate,
        &unrelated_session,
    )
    .unwrap();

    let failure = run_firmware_update(&mut unrelated_session, context, authorization).unwrap_err();

    assert_eq!(
        failure.primary().issue(),
        &OperationIssue::FirmwareAuthorizationInvalidated
    );
    assert!(first_fixture.commands().is_empty());
    assert!(second_fixture.commands().is_empty());
    assert_eq!(second_fixture.refresh_count(), 1);
}

/// Proves media inserted after authorization blocks every firmware mutation.
#[test]
fn firmware_fresh_preflight_rejects_inserted_media() {
    let (fixture, mut session, context, authorization) = authorized_operation();
    fixture.queue_refresh(Ok(device_with_media(7, 282, 61)));

    let failure = run_firmware_update(&mut session, context, authorization).unwrap_err();

    assert_eq!(
        failure.primary().stage(),
        OperationStage::FirmwareValidating
    );
    assert_eq!(failure.primary().issue(), &OperationIssue::MediaPresent);
    assert!(fixture.commands().is_empty());
}

/// Proves cancellation before fresh validation completes without any mutation.
#[test]
fn firmware_preflight_cancellation_completes_before_writing() {
    let (fixture, mut session, context, authorization) = authorized_operation();
    let owner = context.owner().clone();
    assert_eq!(
        context.cancellation_handle().request(&owner),
        rdx_service::operations::CancellationRequestResult::Accepted
    );

    let report = run_firmware_update(&mut session, context, authorization).unwrap();

    assert_eq!(report.completion(), OperationCompletion::Cancelled);
    assert!(fixture.commands().is_empty());
    assert!(
        report
            .events()
            .iter()
            .all(|event| event.stage() == OperationStage::FirmwareValidating)
    );
}

/// Proves a recovered first transfer failure remains history when readback later fails.
#[test]
fn recovered_retry_error_is_history_and_readback_is_primary() {
    let (fixture, mut session, context, authorization) = authorized_operation();
    fixture.fail_dispatch_at_offset(
        0x3000,
        1,
        CommandDispatch::CompletionUnknown(TransportError::Timeout),
    );
    fixture.queue_reconnect(Ok(device(8, 282, 62)));
    fixture.queue_reconnect(Ok(device(9, 282, 63)));

    let failure = run_firmware_update(&mut session, context, authorization).unwrap_err();

    assert_eq!(failure.primary().stage(), OperationStage::FirmwareReadback);
    assert_eq!(failure.attempt_history().len(), 1);
    assert_eq!(failure.attempt_history()[0].attempt(), 1);
    assert_eq!(
        failure.attempt_history()[0].issue(),
        &OperationIssue::Dispatch {
            certainty: DispatchCertainty::CompletionUnknown,
            error: TransportError::Timeout,
        }
    );
    assert_eq!(
        fixture
            .firmware_offsets()
            .iter()
            .filter(|offset| **offset == 0)
            .count(),
        2
    );
}

/// Proves uncertain mode-5 completion is reconciled by candidate revision, not resent.
#[test]
fn uncertain_finalizer_candidate_revision_reconciles_without_a_second_mode5() {
    let (fixture, mut session, context, authorization) = authorized_operation();
    fixture.fail_dispatch_on_call(
        17,
        CommandDispatch::CompletionUnknown(TransportError::DeviceRemoved),
    );
    fixture.queue_reconnect(Ok(device(8, 283, 62)));
    let report = run_firmware_update(&mut session, context, authorization).unwrap();
    assert_eq!(report.completion(), OperationCompletion::Succeeded);
    assert_eq!(fixture.reconnect_count(), 1);
    assert_eq!(finalizer_count(&fixture), 1);
    assert_eq!(
        fixture
            .firmware_offsets()
            .iter()
            .filter(|offset| **offset == 0)
            .count(),
        1
    );
}

/// Proves original revision plus all fresh gates permits only a finalizer retry.
#[test]
fn uncertain_finalizer_original_revision_retries_mode5_without_rewriting_data() {
    let (fixture, mut session, context, authorization) = authorized_operation();
    fixture.fail_dispatch_on_call(
        17,
        CommandDispatch::CompletionUnknown(TransportError::DeviceRemoved),
    );
    fixture.queue_reconnect(Ok(device(8, 282, 62)));
    fixture.queue_reconnect(Ok(device(9, 283, 63)));

    let report = run_firmware_update(&mut session, context, authorization).unwrap();

    assert_eq!(report.completion(), OperationCompletion::Succeeded);
    assert_eq!(finalizer_count(&fixture), 2);
    assert_eq!(
        fixture
            .firmware_offsets()
            .iter()
            .filter(|offset| **offset == 0)
            .count(),
        1
    );
    assert!(report.events().iter().any(|event| {
        event.stage() == OperationStage::FirmwareWriting && event.attempt() == Some(2)
    }));
}

/// Proves finalizer uncertainty plus media drift is ambiguous and never finalized again.
#[test]
fn uncertain_finalizer_media_drift_blocks_retry_and_cleanup_finalize() {
    let (fixture, mut session, context, authorization) = authorized_operation();
    fixture.fail_dispatch_on_call(
        17,
        CommandDispatch::CompletionUnknown(TransportError::DeviceRemoved),
    );
    fixture.queue_reconnect(Ok(device_with_media(8, 282, 62)));

    let failure = run_firmware_update(&mut session, context, authorization).unwrap_err();

    assert_eq!(
        failure.primary().stage(),
        OperationStage::FirmwareFinalizing
    );
    assert!(failure.primary().is_ambiguous());
    assert!(
        failure
            .cleanup()
            .iter()
            .any(|evidence| evidence.issue() == &OperationIssue::MediaPresent)
    );
    assert_eq!(finalizer_count(&fixture), 1);
    assert_eq!(fixture.reconnect_count(), 1);
}

/// Proves identity, family, and unexpected-revision drift never retarget finalization.
#[test]
fn uncertain_finalizer_rebind_drift_never_dispatches_cleanup_to_the_rebound_device() {
    let cases = [
        (
            device_with_identity_and_family("rdx:other", 8, 282, 62, ProductFamily::Usb3Sata3),
            OperationIssue::PostMutationRebind(HostOperationError::DeviceIdentityChanged),
        ),
        (
            device_with_identity_and_family("rdx:firmware", 8, 282, 62, ProductFamily::Usb2Sata1),
            OperationIssue::PostMutationRebind(HostOperationError::ProductFamilyChanged),
        ),
        (
            device(8, 281, 62),
            OperationIssue::FirmwareAuthorizationInvalidated,
        ),
    ];

    for (rebound, expected_cleanup) in cases {
        let (fixture, mut session, context, authorization) = authorized_operation();
        fixture.fail_dispatch_on_call(
            17,
            CommandDispatch::CompletionUnknown(TransportError::DeviceRemoved),
        );
        fixture.queue_reconnect(Ok(rebound));

        let failure = run_firmware_update(&mut session, context, authorization).unwrap_err();

        assert!(failure.primary().is_ambiguous());
        assert!(
            failure
                .cleanup()
                .iter()
                .any(|evidence| evidence.issue() == &expected_cleanup)
        );
        assert_eq!(finalizer_count(&fixture), 1);
        assert_eq!(fixture.reconnect_count(), 1);
    }
}

/// Proves a second uncertain finalizer is reconciled but can never trigger a third mode-5.
#[test]
fn repeated_uncertain_finalizer_never_dispatches_mode5_a_third_time() {
    let (fixture, mut session, context, authorization) = authorized_operation();
    fixture.fail_dispatch_on_call(
        17,
        CommandDispatch::CompletionUnknown(TransportError::Timeout),
    );
    fixture.queue_reconnect(Ok(device(8, 282, 62)));
    fixture.fail_dispatch_on_call(
        18,
        CommandDispatch::CompletionUnknown(TransportError::Unavailable),
    );
    fixture.queue_reconnect(Ok(device(9, 282, 63)));

    let failure = run_firmware_update(&mut session, context, authorization).unwrap_err();

    assert_eq!(
        failure.primary().stage(),
        OperationStage::FirmwareFinalizing
    );
    assert_eq!(failure.attempt_history().len(), 1);
    assert_eq!(failure.attempt_history()[0].attempt(), 1);
    assert_eq!(finalizer_count(&fixture), 2);
    assert_eq!(fixture.reconnect_count(), 2);
}

/// Proves every whole-file retry obtains a fresh rebound lease before byte zero.
#[test]
fn generic_data_retry_requires_fresh_rebind_before_attempt_two() {
    let (fixture, mut session, context, authorization) = authorized_operation();
    fixture.fail_dispatch_at_offset(0x3000, 1, CommandDispatch::NotSent(TransportError::Timeout));
    fixture.queue_reconnect(Ok(device(8, 282, 62)));
    fixture.queue_reconnect(Ok(device(9, 283, 63)));

    let _report = run_firmware_update(&mut session, context, authorization).unwrap();

    assert_eq!(fixture.reconnect_count(), 2);
    assert_eq!(
        fixture
            .firmware_offsets()
            .iter()
            .filter(|offset| **offset == 0)
            .count(),
        2
    );
    let zero_leases = fixture
        .commands()
        .iter()
        .filter(|call| call.command().cdb()[0] == 0x3B && call.command().cdb()[1] == 0x04)
        .filter(|call| call.command().cdb()[3..6] == [0, 0, 0])
        .map(|call| call.lease().generation())
        .collect::<Vec<_>>();
    assert_eq!(
        zero_leases,
        [
            SessionGeneration::new(61).unwrap(),
            SessionGeneration::new(62).unwrap(),
        ]
    );
}

/// Proves finalizer retry preparation failure leaves the uncertain dispatch primary.
#[test]
fn finalize_retry_is_monotonic_and_reconnect_failure_is_primary() {
    let (fixture, mut session, context, authorization) = authorized_operation();
    fixture.fail_dispatch_on_call(
        17,
        CommandDispatch::CompletionUnknown(TransportError::Unavailable),
    );
    fixture.queue_reconnect(Err(HostOperationError::ReconnectTimeout));

    let failure = run_firmware_update(&mut session, context, authorization).unwrap_err();

    assert_eq!(
        failure.primary().stage(),
        OperationStage::FirmwareFinalizing
    );
    assert!(failure.primary().is_ambiguous());
    assert!(failure.attempt_history().is_empty());
    assert!(failure.cleanup().iter().any(|evidence| {
        evidence.issue()
            == &OperationIssue::PostMutationRebind(HostOperationError::ReconnectTimeout)
    }));
    assert!(!failure.events().iter().any(|event| {
        event.stage() == OperationStage::FirmwareWriting && event.attempt() == Some(2)
    }));
    assert!(!failure.events().iter().any(|event| {
        event.stage() == OperationStage::FirmwareFinalizing && event.attempt().is_some()
    }));
}

/// Proves a second unrecovered mode-5 failure is primary finalization evidence.
#[test]
fn repeated_finalize_failure_keeps_first_in_history_and_second_as_primary() {
    let (fixture, mut session, context, authorization) = authorized_operation();
    fixture.fail_dispatch_on_call(
        17,
        CommandDispatch::CompletionUnknown(TransportError::Timeout),
    );
    fixture.fail_dispatch_on_call(
        18,
        CommandDispatch::CompletionUnknown(TransportError::Unavailable),
    );
    fixture.queue_reconnect(Ok(device(8, 282, 62)));
    fixture.queue_reconnect(Ok(device(9, 282, 63)));

    let failure = run_firmware_update(&mut session, context, authorization).unwrap_err();

    assert_eq!(
        failure.primary().stage(),
        OperationStage::FirmwareFinalizing
    );
    assert_eq!(failure.attempt_history().len(), 1);
    assert_eq!(
        failure.attempt_history()[0].stage(),
        OperationStage::FirmwareFinalizing
    );
    assert_eq!(
        failure.primary().issue(),
        &OperationIssue::Dispatch {
            certainty: DispatchCertainty::CompletionUnknown,
            error: TransportError::Unavailable,
        }
    );
    assert_eq!(finalizer_count(&fixture), 2);
}

/// Proves signature sense is a definitive no-retry condition.
#[test]
fn firmware_signature_rejection_is_never_retried() {
    let (fixture, mut session, context, authorization) = authorized_operation();
    fixture.fail_dispatch_at_offset(
        0x3000,
        1,
        CommandDispatch::DefinitelyRejected(signature_error()),
    );
    fixture.queue_reconnect(Ok(device(8, 282, 62)));

    let failure = run_firmware_update(&mut session, context, authorization).unwrap_err();

    assert_eq!(failure.primary().stage(), OperationStage::FirmwareWriting);
    assert!(failure.attempt_history().is_empty());
    assert_eq!(
        fixture
            .firmware_offsets()
            .iter()
            .filter(|offset| **offset == 0)
            .count(),
        1
    );
}

/// Proves signature rejection at mode 5 never triggers reconciliation or a second finalizer.
#[test]
fn firmware_finalizer_signature_rejection_is_never_retried() {
    let (fixture, mut session, context, authorization) = authorized_operation();
    fixture.fail_dispatch_on_call(17, CommandDispatch::DefinitelyRejected(signature_error()));

    let failure = run_firmware_update(&mut session, context, authorization).unwrap_err();

    assert_eq!(
        failure.primary().stage(),
        OperationStage::FirmwareFinalizing
    );
    assert!(failure.attempt_history().is_empty());
    assert_eq!(finalizer_count(&fixture), 1);
    assert_eq!(fixture.reconnect_count(), 0);
}

/// Proves uncertain signature sense on the first finalizer accepts candidate readback.
#[test]
fn first_signature_uncertain_finalizer_candidate_revision_reconciles() {
    let (fixture, mut session, context, authorization) = authorized_operation();
    fixture.fail_dispatch_on_call(17, uncertain_signature_dispatch());
    fixture.queue_reconnect(Ok(device(8, 283, 62)));

    let report = run_firmware_update(&mut session, context, authorization).unwrap();

    assert_eq!(report.completion(), OperationCompletion::Succeeded);
    assert_eq!(fixture.reconnect_count(), 1);
    assert_eq!(finalizer_count(&fixture), 1);
}

/// Proves uncertain signature sense on the first finalizer cannot resend at original revision.
#[test]
fn first_signature_uncertain_finalizer_original_revision_never_resends() {
    let (fixture, mut session, context, authorization) = authorized_operation();
    fixture.fail_dispatch_on_call(17, uncertain_signature_dispatch());
    fixture.queue_reconnect(Ok(device(8, 282, 62)));

    let failure = run_firmware_update(&mut session, context, authorization).unwrap_err();

    assert_eq!(
        failure.primary().issue(),
        &OperationIssue::Dispatch {
            certainty: DispatchCertainty::CompletionUnknown,
            error: signature_error(),
        }
    );
    assert!(failure.primary().is_ambiguous());
    assert!(failure.attempt_history().is_empty());
    assert_eq!(fixture.reconnect_count(), 1);
    assert_eq!(finalizer_count(&fixture), 1);
}

/// Proves uncertain signature sense on the second finalizer accepts candidate readback.
#[test]
fn second_signature_uncertain_finalizer_candidate_revision_reconciles() {
    let (fixture, mut session, context, authorization) = authorized_operation();
    fixture.fail_dispatch_on_call(
        17,
        CommandDispatch::CompletionUnknown(TransportError::Timeout),
    );
    fixture.queue_reconnect(Ok(device(8, 282, 62)));
    fixture.fail_dispatch_on_call(18, uncertain_signature_dispatch());
    fixture.queue_reconnect(Ok(device(9, 283, 63)));

    let report = run_firmware_update(&mut session, context, authorization).unwrap();

    assert_eq!(report.completion(), OperationCompletion::Succeeded);
    assert_eq!(fixture.reconnect_count(), 2);
    assert_eq!(finalizer_count(&fixture), 2);
}

/// Proves uncertain signature sense on the second finalizer cannot dispatch a third mode 5.
#[test]
fn second_signature_uncertain_finalizer_original_revision_never_dispatches_third_mode5() {
    let (fixture, mut session, context, authorization) = authorized_operation();
    fixture.fail_dispatch_on_call(
        17,
        CommandDispatch::CompletionUnknown(TransportError::Timeout),
    );
    fixture.queue_reconnect(Ok(device(8, 282, 62)));
    fixture.fail_dispatch_on_call(18, uncertain_signature_dispatch());
    fixture.queue_reconnect(Ok(device(9, 282, 63)));

    let failure = run_firmware_update(&mut session, context, authorization).unwrap_err();

    assert_eq!(
        failure.primary().issue(),
        &OperationIssue::Dispatch {
            certainty: DispatchCertainty::CompletionUnknown,
            error: signature_error(),
        }
    );
    assert!(failure.primary().is_ambiguous());
    assert_eq!(failure.attempt_history().len(), 1);
    assert_eq!(failure.attempt_history()[0].attempt(), 1);
    assert_eq!(fixture.reconnect_count(), 2);
    assert_eq!(finalizer_count(&fixture), 2);
}

/// Proves nonretryable transport uncertainty still accepts candidate readback.
#[test]
fn nonretryable_uncertain_finalizer_candidate_revision_reconciles() {
    let (fixture, mut session, context, authorization) = authorized_operation();
    fixture.fail_dispatch_on_call(
        17,
        CommandDispatch::CompletionUnknown(nonretryable_transport_error()),
    );
    fixture.queue_reconnect(Ok(device(8, 283, 62)));

    let report = run_firmware_update(&mut session, context, authorization).unwrap();

    assert_eq!(report.completion(), OperationCompletion::Succeeded);
    assert_eq!(fixture.reconnect_count(), 1);
    assert_eq!(finalizer_count(&fixture), 1);
}

/// Proves nonretryable transport uncertainty fails at original revision without resend.
#[test]
fn nonretryable_uncertain_finalizer_original_revision_fails_without_resend() {
    let (fixture, mut session, context, authorization) = authorized_operation();
    fixture.fail_dispatch_on_call(
        17,
        CommandDispatch::CompletionUnknown(nonretryable_transport_error()),
    );
    fixture.queue_reconnect(Ok(device(8, 282, 62)));
    let failure = run_firmware_update(&mut session, context, authorization).unwrap_err();
    assert_eq!(
        failure.primary().issue(),
        &OperationIssue::Dispatch {
            certainty: DispatchCertainty::CompletionUnknown,
            error: nonretryable_transport_error(),
        }
    );
    assert!(failure.primary().is_ambiguous());
    assert_eq!(fixture.reconnect_count(), 1);
    assert_eq!(finalizer_count(&fixture), 1);
}

/// Proves device removal retries only after successful same-device rebinding.
#[test]
fn firmware_device_removed_requires_rebind_before_retry() {
    let (fixture, mut session, context, authorization) = authorized_operation();
    fixture.fail_dispatch_at_offset(
        0x3000,
        1,
        CommandDispatch::CompletionUnknown(TransportError::DeviceRemoved),
    );
    fixture.queue_reconnect(Ok(device(8, 282, 62)));
    fixture.queue_reconnect(Ok(device(9, 283, 63)));

    let report = run_firmware_update(&mut session, context, authorization).unwrap();

    assert_eq!(fixture.reconnect_count(), 2);
    assert_eq!(
        fixture
            .firmware_offsets()
            .iter()
            .filter(|offset| **offset == 0)
            .count(),
        2
    );
    assert!(
        report
            .events()
            .iter()
            .any(|event| event.attempt() == Some(2))
    );
}

/// Proves removal without a successful same-device rebound never starts attempt two.
#[test]
fn firmware_device_removed_rebind_failure_stops_before_retry() {
    let (fixture, mut session, context, authorization) = authorized_operation();
    fixture.fail_dispatch_at_offset(
        0x3000,
        1,
        CommandDispatch::CompletionUnknown(TransportError::DeviceRemoved),
    );
    fixture.queue_reconnect(Err(HostOperationError::ReconnectTimeout));

    let failure = run_firmware_update(&mut session, context, authorization).unwrap_err();

    assert_eq!(failure.primary().stage(), OperationStage::FirmwareWriting);
    assert_eq!(
        failure.primary().issue(),
        &OperationIssue::Dispatch {
            certainty: DispatchCertainty::CompletionUnknown,
            error: TransportError::DeviceRemoved,
        }
    );
    assert!(failure.attempt_history().is_empty());
    assert!(failure.cleanup().iter().any(|evidence| {
        evidence.issue()
            == &OperationIssue::PostMutationRebind(HostOperationError::ReconnectTimeout)
    }));
    assert_eq!(fixture.reconnect_count(), 1);
    assert_eq!(
        fixture
            .firmware_offsets()
            .iter()
            .filter(|offset| **offset == 0)
            .count(),
        1
    );
}

/// Proves supported generic certainty classes rebind, then restart exactly once.
#[test]
fn firmware_generic_retry_matrix_restarts_once_from_zero() {
    let unit_attention = TransportError::CheckCondition(
        SenseData::parse(&[
            0x70, 0, 0x06, 0, 0, 0, 0, 10, 0, 0, 0, 0, 0x29, 0, 0, 0, 0, 0,
        ])
        .unwrap(),
    );
    let cases = [
        CommandDispatch::NotSent(TransportError::Unavailable),
        CommandDispatch::DefinitelyRejected(unit_attention),
        CommandDispatch::CompletionUnknown(TransportError::Timeout),
        CommandDispatch::CompletionUnknown(TransportError::AdapterPanic),
    ];

    for dispatch in cases {
        let (fixture, mut session, context, authorization) = authorized_operation();
        fixture.fail_dispatch_at_offset(0x3000, 1, dispatch);
        fixture.queue_reconnect(Ok(device(8, 282, 62)));
        fixture.queue_reconnect(Ok(device(9, 283, 63)));

        let report = run_firmware_update(&mut session, context, authorization).unwrap();

        assert_eq!(report.completion(), OperationCompletion::Succeeded);
        assert_eq!(
            fixture
                .firmware_offsets()
                .iter()
                .filter(|offset| **offset == 0)
                .count(),
            2
        );
        assert!(
            report
                .events()
                .iter()
                .any(|event| event.attempt() == Some(2))
        );
    }
}

/// Proves generic retry rebind cannot silently change installed revision.
#[test]
fn firmware_retry_stops_if_live_authorization_evidence_changes() {
    let (fixture, mut session, context, authorization) = authorized_operation();
    fixture.fail_dispatch_at_offset(
        0x3000,
        1,
        CommandDispatch::CompletionUnknown(TransportError::Timeout),
    );
    fixture.queue_reconnect(Ok(device(8, 281, 62)));

    let failure = run_firmware_update(&mut session, context, authorization).unwrap_err();

    assert_eq!(failure.primary().stage(), OperationStage::FirmwareWriting);
    assert_eq!(
        failure.primary().issue(),
        &OperationIssue::Dispatch {
            certainty: DispatchCertainty::CompletionUnknown,
            error: TransportError::Timeout,
        }
    );
    assert!(failure.attempt_history().is_empty());
    assert!(
        failure.cleanup().iter().any(|evidence| {
            evidence.issue() == &OperationIssue::FirmwareAuthorizationInvalidated
        })
    );
    assert_eq!(finalizer_count(&fixture), 0);
    assert_eq!(
        fixture
            .firmware_offsets()
            .iter()
            .filter(|offset| **offset == 0)
            .count(),
        1
    );
}

/// Proves removed-device rebinding keeps the consumed installed-revision evidence exact.
#[test]
fn firmware_removed_device_retry_rejects_changed_installed_revision() {
    let (fixture, mut session, context, authorization) = authorized_operation();
    fixture.fail_dispatch_at_offset(
        0x3000,
        1,
        CommandDispatch::CompletionUnknown(TransportError::DeviceRemoved),
    );
    fixture.queue_reconnect(Ok(device(8, 281, 62)));

    let failure = run_firmware_update(&mut session, context, authorization).unwrap_err();

    assert_eq!(failure.primary().stage(), OperationStage::FirmwareWriting);
    assert_eq!(
        failure.primary().issue(),
        &OperationIssue::Dispatch {
            certainty: DispatchCertainty::CompletionUnknown,
            error: TransportError::DeviceRemoved,
        }
    );
    assert!(failure.attempt_history().is_empty());
    assert!(
        failure.cleanup().iter().any(|evidence| {
            evidence.issue() == &OperationIssue::FirmwareAuthorizationInvalidated
        })
    );
    assert_eq!(finalizer_count(&fixture), 0);
    assert_eq!(
        fixture
            .firmware_offsets()
            .iter()
            .filter(|offset| **offset == 0)
            .count(),
        1
    );
}

/// Proves a second failed whole-file attempt becomes primary, not retry history.
#[test]
fn firmware_second_transfer_failure_is_primary_after_one_history_record() {
    let (fixture, mut session, context, authorization) = authorized_operation();
    fixture.fail_dispatch_at_offset(
        0x3000,
        2,
        CommandDispatch::CompletionUnknown(TransportError::Timeout),
    );
    fixture.queue_reconnect(Ok(device(8, 282, 62)));

    let failure = run_firmware_update(&mut session, context, authorization).unwrap_err();

    assert_eq!(failure.primary().stage(), OperationStage::FirmwareWriting);
    assert_eq!(failure.attempt_history().len(), 1);
    assert_eq!(failure.attempt_history()[0].attempt(), 1);
    assert_eq!(
        failure.primary().issue(),
        &OperationIssue::Dispatch {
            certainty: DispatchCertainty::CompletionUnknown,
            error: TransportError::Timeout,
        }
    );
    assert_eq!(
        fixture
            .firmware_offsets()
            .iter()
            .filter(|offset| **offset == 0)
            .count(),
        2
    );
}

/// Proves cancellation loses once the first mutating firmware dispatch may begin.
#[test]
fn firmware_dispatch_race_closes_cancellation_before_mutation() {
    let (fixture, session, context, authorization) = authorized_operation();
    let owner = context.owner().clone();
    let cancellation = context.cancellation_handle();
    let entered = Arc::new(Barrier::new(2));
    let release = Arc::new(Barrier::new(2));
    fixture.block_dispatch_call(1, Arc::clone(&entered), Arc::clone(&release));
    fixture.queue_reconnect(Ok(device(8, 283, 62)));

    let report = std::thread::scope(|scope| {
        let worker = scope.spawn(move || {
            let mut session = session;
            run_firmware_update(&mut session, context, authorization).unwrap()
        });
        entered.wait();
        assert_eq!(
            cancellation.request(&owner),
            rdx_service::operations::CancellationRequestResult::Closed
        );
        release.wait();
        worker.join().unwrap()
    });

    assert_eq!(report.completion(), OperationCompletion::Succeeded);
}

/// Proves reconnect adapter panic is contained as the first unrecovered primary.
#[test]
fn firmware_reconnect_panic_is_contained_at_the_operation_boundary() {
    let (fixture, mut session, context, authorization) = authorized_operation();
    fixture.panic_on_reconnect_call(1);

    let failure = run_firmware_update(&mut session, context, authorization).unwrap_err();

    assert_eq!(
        failure.primary().stage(),
        OperationStage::DeviceReconnecting
    );
    assert_eq!(
        failure.primary().issue(),
        &OperationIssue::PostMutationRebind(HostOperationError::AdapterPanic)
    );
    assert_eq!(failure.terminal_stage(), OperationStage::FirmwareReadback);
    assert!(!session.is_active());
}
