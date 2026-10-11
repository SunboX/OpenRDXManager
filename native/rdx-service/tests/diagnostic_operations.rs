// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

use rdx_service::firmware::{FirmwareRevision, ProductFamily};
use rdx_service::host::{
    DeviceInterface, DeviceSession, FixtureDevice, HostOperationError, SessionDevice,
    SessionGeneration,
};
use rdx_service::model::{DeviceId, DeviceIdentity, DiscoveryRevision, OperationId, OperationKind};
use rdx_service::operations::{
    CancellationRequestResult, CancellationState, OperationCompletion, OperationContext,
    OperationIssue, OperationStage, run_led_test, run_self_test,
};
use rdx_service::transport::{
    CommandDispatch, DispatchCertainty, TransportError, TransportResponse,
};
use std::sync::{Arc, Barrier};

/// Builds one exact no-media SATA III fixture discovery result.
fn device(id: &str, revision: u64, generation: u64) -> SessionDevice {
    SessionDevice::fixture(
        DeviceIdentity {
            id: DeviceId::new(id).unwrap(),
            revision: DiscoveryRevision::new(revision).unwrap(),
        },
        ProductFamily::Usb3Sata3,
        FirmwareRevision::new(282).unwrap(),
        DeviceInterface::Sata3,
        false,
        SessionGeneration::new(generation).unwrap(),
    )
}

/// Opens one fixture session and context for a diagnostic operation.
fn operation(
    kind: OperationKind,
    suffix: &str,
) -> (FixtureDevice, DeviceSession, OperationContext) {
    let fixture = FixtureDevice::new(device("rdx:diagnostic", 7, 51));
    let session = fixture.open();
    let context = OperationContext::for_session(
        OperationId::new(format!("op:{suffix}")).unwrap(),
        kind,
        &session,
    )
    .unwrap();
    (fixture, session, context)
}

/// Proves self-test obtains fresh exact-session evidence before command dispatch.
#[test]
fn self_test_revalidates_the_bound_session_before_dispatch() {
    let (fixture, mut session, context) = operation(OperationKind::SelfTest, "self-fresh");
    let owner = context.owner().clone();

    let report = run_self_test(&mut session, context).unwrap();

    assert_eq!(report.completion(), OperationCompletion::Succeeded);
    assert_eq!(fixture.refresh_count(), 2);
    assert_eq!(fixture.commands().len(), 1);
    assert_eq!(
        fixture.commands()[0].command().cdb(),
        [0x1D, 0x04, 0, 0, 0, 0]
    );
    assert_eq!(
        report
            .events()
            .iter()
            .map(|event| event.stage())
            .collect::<Vec<_>>(),
        [
            OperationStage::DiagnosticRunning,
            OperationStage::DiagnosticCleanup
        ]
    );
    assert!(report.events().iter().all(|event| event.owner() == &owner));
    assert_eq!(
        report.events()[0].cancellation_state(),
        CancellationState::Cancellable
    );
    assert_eq!(
        report.events()[1].cancellation_state(),
        CancellationState::Closed
    );
    assert!(
        report
            .events()
            .windows(2)
            .all(|events| events[0].fraction() <= events[1].fraction())
    );
}

/// Proves stale preflight evidence prevents any diagnostic command.
#[test]
fn self_test_stale_preflight_invalidates_without_dispatch() {
    let (fixture, mut session, context) = operation(OperationKind::SelfTest, "self-stale");
    fixture.queue_refresh(Ok(device("rdx:other", 7, 51)));

    let failure = run_self_test(&mut session, context).unwrap_err();

    assert_eq!(failure.primary().stage(), OperationStage::DiagnosticRunning);
    assert_eq!(
        failure.primary().issue(),
        &OperationIssue::Host(HostOperationError::DeviceIdentityChanged)
    );
    assert_eq!(failure.terminal_stage(), OperationStage::DiagnosticCleanup);
    assert!(fixture.commands().is_empty());
    assert!(!session.is_active());
}

/// Proves renderer-visible metadata cannot substitute for a service-issued session capability.
#[test]
fn identical_metadata_from_an_unrelated_session_is_rejected_without_dispatch() {
    let first_fixture = FixtureDevice::new(device("rdx:diagnostic", 7, 51));
    let second_fixture = FixtureDevice::new(device("rdx:diagnostic", 7, 51));
    let first_session = first_fixture.open();
    let context = OperationContext::for_session(
        OperationId::new("op:unrelated-session").unwrap(),
        OperationKind::SelfTest,
        &first_session,
    )
    .unwrap();
    let mut unrelated_session = second_fixture.open();

    let failure = run_self_test(&mut unrelated_session, context).unwrap_err();

    assert_eq!(
        failure.primary().issue(),
        &OperationIssue::SessionBindingChanged
    );
    assert!(first_fixture.commands().is_empty());
    assert!(second_fixture.commands().is_empty());
    assert_eq!(second_fixture.refresh_count(), 0);
}

/// Proves exact-owner early cancellation still issues LED-off but never LED-on.
#[test]
fn led_early_cancellation_runs_off_cleanup_without_on() {
    let (fixture, mut session, context) = operation(OperationKind::LedTest, "led-cancel");
    let owner = context.owner().clone();
    assert_eq!(
        context.cancellation_handle().request(&owner),
        CancellationRequestResult::Accepted
    );

    let report = run_led_test(&mut session, context).unwrap();

    assert_eq!(report.completion(), OperationCompletion::Cancelled);
    assert_eq!(fixture.commands().len(), 1);
    assert_eq!(
        fixture.commands()[0].command().data_out(),
        [0x80, 0, 0, 4, 0, 0, 0, 1]
    );
}

/// Proves an adapter panic during LED-on is contained and followed by exact-lease OFF.
#[test]
fn led_on_adapter_panic_is_contained_and_restored() {
    let (fixture, mut session, context) = operation(OperationKind::LedTest, "led-panic");
    fixture.panic_on_dispatch_call(1);

    let failure = run_led_test(&mut session, context).unwrap_err();

    assert_eq!(
        failure.primary().issue(),
        &OperationIssue::Dispatch {
            certainty: DispatchCertainty::CompletionUnknown,
            error: TransportError::AdapterPanic,
        }
    );
    assert_eq!(fixture.commands().len(), 2);
    assert_eq!(
        fixture.commands()[0].lease().generation(),
        fixture.commands()[1].lease().generation()
    );
    assert!(!session.is_active());
    assert!(!session.has_pending_led_recovery());
}

/// Proves an adapter panic while waiting cannot escape or prevent exact-lease OFF.
#[test]
fn led_wait_adapter_panic_is_contained_and_restored() {
    let (fixture, mut session, context) = operation(OperationKind::LedTest, "led-wait-panic");
    fixture.panic_on_led_wait_call(1);

    let failure = run_led_test(&mut session, context).unwrap_err();

    assert_eq!(
        failure.primary().issue(),
        &OperationIssue::Host(HostOperationError::AdapterPanic)
    );
    assert_eq!(fixture.commands().len(), 2);
    assert_eq!(fixture.commands()[0].lease(), fixture.commands()[1].lease());
    assert!(!session.is_active());
    assert!(!session.has_pending_led_recovery());
}

/// Proves only outcomes that may have lit the LED arm persistent recovery.
#[test]
fn led_recovery_arm_follows_dispatch_certainty() {
    let cases = [
        (CommandDispatch::NotSent(TransportError::Timeout), false),
        (
            CommandDispatch::DefinitelyRejected(TransportError::Timeout),
            false,
        ),
        (
            CommandDispatch::CompletionUnknown(TransportError::Timeout),
            true,
        ),
    ];

    for (on_outcome, expected_guard) in cases {
        let (fixture, mut session, context) =
            operation(OperationKind::LedTest, "led-arm-certainty");
        fixture.queue_dispatch(on_outcome);
        fixture.queue_dispatch(CommandDispatch::NotSent(TransportError::Timeout));

        run_led_test(&mut session, context).unwrap_err();

        assert_eq!(session.has_pending_led_recovery(), expected_guard);
        assert_eq!(fixture.commands().len(), 2);
    }
}

/// Proves a second LED operation cannot replace a still-armed exact-lease guard.
#[test]
fn led_operation_rejects_and_preserves_an_existing_recovery_guard() {
    let (fixture, mut session, context) = operation(OperationKind::LedTest, "led-first-guard");
    fixture.queue_dispatch(CommandDispatch::Succeeded(TransportResponse::empty()));
    fixture.queue_dispatch(CommandDispatch::NotSent(TransportError::Timeout));
    run_led_test(&mut session, context).unwrap_err();
    assert!(session.has_pending_led_recovery());
    let commands_before = fixture.commands().len();
    let second_context = OperationContext::for_session(
        OperationId::new("op:led-existing-guard").unwrap(),
        OperationKind::LedTest,
        &session,
    )
    .unwrap();

    let failure = run_led_test(&mut session, second_context).unwrap_err();

    assert_eq!(
        failure.primary().issue(),
        &OperationIssue::Host(HostOperationError::RecoveryAlreadyArmed)
    );
    assert_eq!(fixture.commands().len(), commands_before);
    assert!(session.has_pending_led_recovery());
}

/// Proves reconnect cannot retarget a pending LED-off obligation to a new lease.
#[test]
fn reconnect_is_rejected_while_exact_led_recovery_is_armed() {
    let (fixture, mut session, context) = operation(OperationKind::LedTest, "led-rebind-guard");
    fixture.queue_dispatch(CommandDispatch::Succeeded(TransportResponse::empty()));
    fixture.queue_dispatch(CommandDispatch::NotSent(TransportError::Timeout));
    run_led_test(&mut session, context).unwrap_err();
    fixture.queue_reconnect(Ok(device("rdx:diagnostic", 8, 52)));

    assert_eq!(
        session.reconnect(15),
        Err(HostOperationError::RecoveryAlreadyArmed)
    );
    assert_eq!(fixture.reconnect_count(), 0);
    assert!(session.has_pending_led_recovery());
    assert_eq!(
        session.device().generation(),
        SessionGeneration::new(51).unwrap()
    );
}

/// Proves the active-lease poison policy follows dispatch certainty and adapter health.
#[test]
fn dispatch_certainty_and_error_poison_matrix_is_enforced() {
    let sense = rdx_service::protocol::SenseData::parse(&[
        0x70, 0, 0x05, 0, 0, 0, 0, 10, 0, 0, 0, 0, 0x24, 0, 0, 0, 0, 0,
    ])
    .unwrap();
    let cases = [
        (CommandDispatch::NotSent(TransportError::Timeout), true),
        (
            CommandDispatch::DefinitelyRejected(TransportError::CheckCondition(sense.clone())),
            true,
        ),
        (CommandDispatch::NotSent(TransportError::Unavailable), false),
        (
            CommandDispatch::CompletionUnknown(TransportError::Timeout),
            false,
        ),
        (
            CommandDispatch::CompletionUnknown(TransportError::CheckCondition(sense)),
            false,
        ),
        (
            CommandDispatch::CompletionUnknown(TransportError::DeviceRemoved),
            false,
        ),
        (
            CommandDispatch::CompletionUnknown(TransportError::AdapterPanic),
            false,
        ),
    ];

    for (outcome, expected_active) in cases {
        let (fixture, mut session, context) = operation(OperationKind::SelfTest, "dispatch-poison");
        fixture.queue_dispatch(outcome);

        run_self_test(&mut session, context).unwrap_err();

        assert_eq!(session.is_active(), expected_active);
        assert_eq!(fixture.commands().len(), 1);
    }
}

/// Proves cleanup failure remains distinct and graceful shutdown retries the guard.
#[test]
fn led_off_failure_preserves_primary_and_shutdown_retries_original_lease() {
    let (fixture, mut session, context) = operation(OperationKind::LedTest, "led-shutdown");
    fixture.queue_dispatch(CommandDispatch::Succeeded(TransportResponse::empty()));
    fixture.queue_dispatch(CommandDispatch::NotSent(TransportError::Unavailable));

    let failure = run_led_test(&mut session, context).unwrap_err();

    assert_eq!(failure.primary().stage(), OperationStage::LedRestoring);
    assert_eq!(failure.cleanup().len(), 1);
    assert_eq!(failure.cleanup()[0].stage(), OperationStage::LedReadback);
    assert_eq!(
        failure.cleanup()[0].issue(),
        &OperationIssue::Host(HostOperationError::InactiveSession)
    );
    assert!(session.has_pending_led_recovery());
    assert_eq!(
        session.graceful_shutdown().unwrap().certainty(),
        DispatchCertainty::Succeeded
    );
    assert!(!session.has_pending_led_recovery());
    assert_eq!(fixture.commands().len(), 3);
    assert!(
        fixture
            .commands()
            .iter()
            .all(|call| { call.lease().generation() == SessionGeneration::new(51).unwrap() })
    );
}

/// Proves a primary wait failure and LED-off cleanup failure are retained separately.
#[test]
fn led_wait_and_cleanup_failure_keep_primary_and_cleanup_evidence() {
    let (fixture, mut session, context) = operation(OperationKind::LedTest, "led-evidence");
    fixture.queue_led_wait(Err(HostOperationError::CapabilityUnavailable));
    fixture.queue_dispatch(CommandDispatch::Succeeded(TransportResponse::empty()));
    fixture.queue_dispatch(CommandDispatch::CompletionUnknown(
        TransportError::DeviceRemoved,
    ));

    let failure = run_led_test(&mut session, context).unwrap_err();

    assert_eq!(
        failure.primary().issue(),
        &OperationIssue::Host(HostOperationError::CapabilityUnavailable)
    );
    assert_eq!(failure.cleanup().len(), 2);
    assert_eq!(failure.cleanup()[0].stage(), OperationStage::LedRestoring);
    assert_eq!(
        failure.cleanup()[0].issue(),
        &OperationIssue::Dispatch {
            certainty: DispatchCertainty::CompletionUnknown,
            error: TransportError::DeviceRemoved,
        }
    );
    assert_eq!(
        failure.cleanup()[1].issue(),
        &OperationIssue::Host(HostOperationError::InactiveSession)
    );
    assert_eq!(failure.terminal_stage(), OperationStage::LedReadback);
    assert!(!session.is_active());
}

/// Proves a revalidation adapter panic cannot unwind past the operation boundary.
#[test]
fn self_test_revalidation_panic_is_contained_before_dispatch() {
    let (fixture, mut session, context) = operation(OperationKind::SelfTest, "self-panic");
    fixture.panic_on_refresh_call(1);

    let failure = run_self_test(&mut session, context).unwrap_err();

    assert_eq!(
        failure.primary().issue(),
        &OperationIssue::Host(HostOperationError::AdapterPanic)
    );
    assert!(fixture.commands().is_empty());
    assert!(!session.is_active());
}

/// Proves cancellation racing a completed LED-on waits for OFF and readback.
#[test]
fn led_cancellation_race_finishes_recovery_before_cancelled() {
    let (fixture, session, context) = operation(OperationKind::LedTest, "led-race");
    let owner = context.owner().clone();
    let cancellation = context.cancellation_handle();
    let entered = Arc::new(Barrier::new(2));
    let release = Arc::new(Barrier::new(2));
    fixture.block_dispatch_call(1, Arc::clone(&entered), Arc::clone(&release));

    let report = std::thread::scope(|scope| {
        let worker = scope.spawn(move || {
            let mut session = session;
            run_led_test(&mut session, context).unwrap()
        });
        entered.wait();
        assert_eq!(
            cancellation.request(&owner),
            CancellationRequestResult::Accepted
        );
        release.wait();
        worker.join().unwrap()
    });

    assert_eq!(report.completion(), OperationCompletion::Cancelled);
    assert_eq!(fixture.commands().len(), 2);
    assert_eq!(
        report.events().last().unwrap().stage(),
        OperationStage::LedReadback
    );
}

/// Proves dropping a session performs a final contained best-effort guard attempt.
#[test]
fn session_drop_retries_an_armed_led_recovery_guard() {
    let (fixture, mut session, context) = operation(OperationKind::LedTest, "led-drop");
    fixture.queue_dispatch(CommandDispatch::Succeeded(TransportResponse::empty()));
    fixture.queue_dispatch(CommandDispatch::NotSent(TransportError::Unavailable));

    run_led_test(&mut session, context).unwrap_err();
    assert!(session.has_pending_led_recovery());
    drop(session);

    assert_eq!(fixture.commands().len(), 3);
    assert_eq!(
        fixture.commands().last().unwrap().command().data_out(),
        [0x80, 0, 0, 4, 0, 0, 0, 1]
    );
}
