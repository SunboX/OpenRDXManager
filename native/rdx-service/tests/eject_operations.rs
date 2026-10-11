#![cfg(feature = "fixtures")]
// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Deterministic mutation-barrier and cancellation tests for shared eject.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Barrier, Mutex, mpsc};
use std::time::Duration;

use rdx_service::firmware::{FirmwareRevision, ProductFamily};
use rdx_service::host::{
    DeviceInterface, DeviceSession, FixtureDevice, HostOperationError, SessionDevice,
    SessionGeneration,
};
use rdx_service::model::{DeviceId, DeviceIdentity, DiscoveryRevision, OperationId, OperationKind};
use rdx_service::operations::{
    CancellationRequestResult, CancellationState, EjectHost, EjectOutcome, EjectReadback,
    HostEjectPolicy, OperationCompletion, OperationContext, OperationIssue, OperationStage,
    ProgressPublicationError, run_eject, run_eject_with_progress,
};
use rdx_service::transport::{CommandDispatch, TransportResponse};

/// Mutable observations and optional deterministic host barriers.
#[derive(Default)]
struct HostState {
    unmount_count: usize,
    eject_count: usize,
    readback_count: usize,
    unmount_block: Option<(Arc<Barrier>, Arc<Barrier>)>,
    eject_block: Option<(Arc<Barrier>, Arc<Barrier>)>,
}

/// Path-free host adapter that records the real shared operation's calls.
#[derive(Clone, Default)]
struct RecordingEjectHost {
    state: Arc<Mutex<HostState>>,
}

impl RecordingEjectHost {
    /// Installs a deterministic barrier around the safe unmount call.
    fn block_unmount(&self, entered: Arc<Barrier>, release: Arc<Barrier>) {
        self.state
            .lock()
            .expect("eject test state remains available")
            .unmount_block = Some((entered, release));
    }

    /// Installs a deterministic barrier after eject dispatch begins.
    fn block_eject(&self, entered: Arc<Barrier>, release: Arc<Barrier>) {
        self.state
            .lock()
            .expect("eject test state remains available")
            .eject_block = Some((entered, release));
    }

    /// Returns exact unmount, eject, and readback call counts.
    fn counts(&self) -> (usize, usize, usize) {
        let state = self
            .state
            .lock()
            .expect("eject test state remains available");
        (state.unmount_count, state.eject_count, state.readback_count)
    }
}

impl EjectHost for RecordingEjectHost {
    /// Records and optionally blocks one safe unmount.
    fn unmount(&mut self, _target: &DeviceIdentity) -> Result<(), HostOperationError> {
        let block = {
            let mut state = self
                .state
                .lock()
                .expect("eject test state remains available");
            state.unmount_count += 1;
            state.unmount_block.clone()
        };
        if let Some((entered, release)) = block {
            entered.wait();
            release.wait();
        }
        Ok(())
    }

    /// Records and optionally blocks one successful typed host eject.
    fn eject(&mut self, _target: &DeviceIdentity, _policy: HostEjectPolicy) -> CommandDispatch {
        let block = {
            let mut state = self
                .state
                .lock()
                .expect("eject test state remains available");
            state.eject_count += 1;
            state.eject_block.clone()
        };
        if let Some((entered, release)) = block {
            entered.wait();
            release.wait();
        }
        CommandDispatch::Succeeded(TransportResponse::empty())
    }

    /// Records fresh exact-target departure reconciliation.
    fn readback(&mut self, target: &DeviceIdentity) -> Result<EjectReadback, HostOperationError> {
        self.state
            .lock()
            .expect("eject test state remains available")
            .readback_count += 1;
        Ok(EjectReadback::Departed(target.clone()))
    }
}

/// Creates one exact media-present USB fixture session and eject context.
fn operation(
    kind: OperationKind,
    suffix: &str,
) -> (FixtureDevice, DeviceSession, OperationContext) {
    let fixture = FixtureDevice::new(SessionDevice::fixture(
        DeviceIdentity {
            id: DeviceId::new("rdx:eject-operation").expect("fixture device ID"),
            revision: DiscoveryRevision::new(11).expect("fixture revision"),
        },
        ProductFamily::Usb3Sata3,
        FirmwareRevision::new(282).expect("fixture firmware revision"),
        DeviceInterface::Usb3,
        true,
        SessionGeneration::new(31).expect("fixture generation"),
    ));
    let session = fixture.open();
    let context = OperationContext::for_session(
        OperationId::new(format!("op:{suffix}")).expect("fixture operation ID"),
        kind,
        &session,
    )
    .expect("fixture operation context");
    (fixture, session, context)
}

/// Extracts a cancelled report and rejects success-with-departure substitution.
fn cancelled_report(outcome: EjectOutcome) -> rdx_service::operations::OperationReport {
    match outcome {
        EjectOutcome::Cancelled { report } => report,
        EjectOutcome::Succeeded { .. } => {
            panic!("cancelled eject must not produce departure proof")
        }
    }
}

/// Extracts a successful report and proves the distinct departure capability exists.
fn succeeded_report(outcome: EjectOutcome) -> rdx_service::operations::OperationReport {
    match outcome {
        EjectOutcome::Succeeded { report, departure } => {
            assert_eq!(departure.policy(), HostEjectPolicy::Safe);
            report
        }
        EjectOutcome::Cancelled { .. } => panic!("post-barrier eject must not cancel"),
    }
}

/// Proves a lost first progress event stops before any host or device action.
#[test]
fn progress_publication_failure_stops_before_eject_preflight() {
    let (fixture, mut session, context) =
        operation(OperationKind::EjectSafe, "eject-progress-failure");
    let mut host = RecordingEjectHost::default();

    let failure = run_eject_with_progress(
        &mut session,
        context,
        &mut host,
        HostEjectPolicy::Safe,
        |_event| Err(ProgressPublicationError::unavailable()),
    )
    .expect_err("lost causal progress cannot produce eject success");

    assert_eq!(
        failure.primary().issue(),
        &OperationIssue::ProgressPublication
    );
    assert_eq!(fixture.refresh_count(), 0);
    assert_eq!(host.counts(), (0, 0, 0));
    assert_eq!(failure.events().len(), 1);
    assert_eq!(failure.events()[0].stage(), OperationStage::HostUnmounting);
}

/// Proves a progress consumer may synchronously cancel its exact operation.
#[test]
fn reentrant_cancellation_from_progress_callback_finishes_without_deadlock() {
    let (fixture, session, context) =
        operation(OperationKind::EjectSafe, "eject-progress-reentrant-cancel");
    let owner = context.owner().clone();
    let cancellation = context.cancellation_handle();
    let callback_cancellation = cancellation.clone();
    let callback_owner = owner.clone();
    let host = RecordingEjectHost::default();
    let observed = host.clone();
    let (result_sender, result_receiver) = mpsc::sync_channel(1);

    let worker = std::thread::spawn(move || {
        let mut session = session;
        let mut host = host;
        let mut callback_observation = None;
        let outcome = run_eject_with_progress(
            &mut session,
            context,
            &mut host,
            HostEjectPolicy::Safe,
            |event| {
                if callback_observation.is_none() {
                    callback_observation = Some((
                        event.stage(),
                        event.cancellation_state(),
                        callback_cancellation.request(&callback_owner),
                    ));
                }
                Ok(())
            },
        );
        result_sender
            .send((outcome, callback_observation))
            .expect("bounded regression receiver remains available");
    });

    let (outcome, callback_observation) = result_receiver
        .recv_timeout(Duration::from_secs(2))
        .expect("reentrant cancellation must not deadlock causal publication");
    worker.join().expect("reentrant cancellation worker joins");
    assert_eq!(
        callback_observation,
        Some((
            OperationStage::HostUnmounting,
            CancellationState::Cancellable,
            CancellationRequestResult::Accepted,
        ))
    );
    let report = cancelled_report(outcome.expect("reentrant cancellation is a typed outcome"));
    assert_eq!(report.completion(), OperationCompletion::Cancelled);
    assert_eq!(report.events().len(), 1);
    assert_eq!(
        report.events()[0].cancellation_state(),
        CancellationState::Cancellable
    );
    assert_eq!(fixture.refresh_count(), 0);
    assert_eq!(observed.counts(), (0, 0, 0));
    assert_eq!(
        cancellation.request(&owner),
        CancellationRequestResult::Closed
    );
}

/// Proves publication errors preserve reentrant cancellation and mutation certainty.
#[test]
fn publication_errors_preserve_reentrant_cancellation_before_and_after_dispatch() {
    let (early_fixture, mut early_session, early_context) = operation(
        OperationKind::EjectSafe,
        "eject-progress-reentrant-error-early",
    );
    let early_owner = early_context.owner().clone();
    let early_cancellation = early_context.cancellation_handle();
    let callback_cancellation = early_cancellation.clone();
    let callback_owner = early_owner.clone();
    let mut early_host = RecordingEjectHost::default();
    let mut early_request = None;

    let early_failure = run_eject_with_progress(
        &mut early_session,
        early_context,
        &mut early_host,
        HostEjectPolicy::Safe,
        |_event| {
            early_request = Some(callback_cancellation.request(&callback_owner));
            Err(ProgressPublicationError::unavailable())
        },
    )
    .expect_err("failed first publication cannot produce a cancellation terminal");

    assert_eq!(early_request, Some(CancellationRequestResult::Accepted));
    assert_eq!(
        early_failure.primary().issue(),
        &OperationIssue::ProgressPublication
    );
    assert_eq!(early_fixture.refresh_count(), 0);
    assert_eq!(early_host.counts(), (0, 0, 0));
    assert_eq!(
        early_cancellation.request(&early_owner),
        CancellationRequestResult::Closed
    );

    let (late_fixture, mut late_session, late_context) = operation(
        OperationKind::EjectSafe,
        "eject-progress-reentrant-error-late",
    );
    let late_owner = late_context.owner().clone();
    let late_cancellation = late_context.cancellation_handle();
    let callback_cancellation = late_cancellation.clone();
    let callback_owner = late_owner.clone();
    let mut late_host = RecordingEjectHost::default();
    let mut late_request = None;

    let late_failure = run_eject_with_progress(
        &mut late_session,
        late_context,
        &mut late_host,
        HostEjectPolicy::Safe,
        |event| {
            if event.stage() == OperationStage::EjectReadback {
                late_request = Some(callback_cancellation.request(&callback_owner));
                return Err(ProgressPublicationError::unavailable());
            }
            Ok(())
        },
    )
    .expect_err("lost post-dispatch publication cannot produce eject success");

    assert_eq!(late_request, Some(CancellationRequestResult::Closed));
    assert_eq!(
        late_failure.primary().issue(),
        &OperationIssue::ProgressPublication
    );
    assert_eq!(late_failure.terminal_stage(), OperationStage::EjectReadback);
    assert_eq!(late_fixture.refresh_count(), 1);
    assert_eq!(late_host.counts(), (1, 1, 1));
    assert_eq!(
        late_cancellation.request(&late_owner),
        CancellationRequestResult::Closed
    );
}

/// Proves a panicking first publisher becomes typed evidence without poisoning cancellation.
#[test]
fn publication_callback_panic_before_mutation_is_typed_and_closes_cancellation() {
    let (fixture, session, context) =
        operation(OperationKind::EjectSafe, "eject-progress-panic-early");
    let owner = context.owner().clone();
    let cancellation = context.cancellation_handle();
    let callback_cancellation = cancellation.clone();
    let callback_owner = owner.clone();
    let host = RecordingEjectHost::default();
    let observed = host.clone();

    let worker = std::thread::spawn(move || {
        let mut session = session;
        let mut host = host;
        let mut request_result = None;
        let outcome = run_eject_with_progress(
            &mut session,
            context,
            &mut host,
            HostEjectPolicy::Safe,
            |_event| {
                request_result = Some(callback_cancellation.request(&callback_owner));
                panic!("controlled progress callback panic");
            },
        );
        (outcome, request_result)
    });

    let (outcome, request_result) = worker
        .join()
        .expect("callback panic is contained by causal publication");
    let failure = outcome.expect_err("callback panic cannot produce eject success");
    assert_eq!(request_result, Some(CancellationRequestResult::Accepted));
    assert_eq!(
        failure.primary().issue(),
        &OperationIssue::ProgressPublication
    );
    assert_eq!(fixture.refresh_count(), 0);
    assert_eq!(observed.counts(), (0, 0, 0));
    assert_eq!(
        cancellation.request(&owner),
        CancellationRequestResult::Closed
    );
}

/// Proves a post-dispatch callback panic cannot skip exact-target readback.
#[test]
fn publication_callback_panic_after_dispatch_still_performs_readback() {
    let (fixture, session, context) =
        operation(OperationKind::EjectSafe, "eject-progress-panic-late");
    let owner = context.owner().clone();
    let cancellation = context.cancellation_handle();
    let callback_cancellation = cancellation.clone();
    let callback_owner = owner.clone();
    let host = RecordingEjectHost::default();
    let observed = host.clone();

    let worker = std::thread::spawn(move || {
        let mut session = session;
        let mut host = host;
        let mut request_result = None;
        let outcome = run_eject_with_progress(
            &mut session,
            context,
            &mut host,
            HostEjectPolicy::Safe,
            |event| {
                if event.stage() == OperationStage::EjectReadback {
                    request_result = Some(callback_cancellation.request(&callback_owner));
                    panic!("controlled post-dispatch callback panic");
                }
                Ok(())
            },
        );
        (outcome, request_result)
    });

    let (outcome, request_result) = worker
        .join()
        .expect("post-dispatch callback panic is contained");
    let failure = outcome.expect_err("post-dispatch callback panic cannot produce success");
    assert_eq!(request_result, Some(CancellationRequestResult::Closed));
    assert_eq!(
        failure.primary().issue(),
        &OperationIssue::ProgressPublication
    );
    assert_eq!(failure.terminal_stage(), OperationStage::EjectReadback);
    assert_eq!(fixture.refresh_count(), 1);
    assert_eq!(observed.counts(), (1, 1, 1));
    assert_eq!(
        cancellation.request(&owner),
        CancellationRequestResult::Closed
    );
}

/// Proves cancellation acceptance cannot overtake an in-flight causal event.
#[test]
fn cancellation_request_waits_for_causal_progress_publication() {
    for iteration in 0..32 {
        let (_fixture, session, context) = operation(
            OperationKind::EjectSafe,
            &format!("eject-progress-race-{iteration}"),
        );
        let owner = context.owner().clone();
        let cancellation = context.cancellation_handle();
        let progress_entered = Arc::new(Barrier::new(2));
        let progress_release = Arc::new(Barrier::new(2));
        let publication_returning = Arc::new(AtomicBool::new(false));
        let host = RecordingEjectHost::default();
        let (request_started_sender, request_started_receiver) = mpsc::sync_channel(0);
        let (request_sender, request_receiver) = mpsc::sync_channel(1);

        let (early_request, request_result, publication_had_returned, outcome) =
            std::thread::scope(|scope| {
                let publisher_entered = Arc::clone(&progress_entered);
                let publisher_release = Arc::clone(&progress_release);
                let publisher_returning = Arc::clone(&publication_returning);
                let worker = scope.spawn(move || {
                    let mut session = session;
                    let mut host = host;
                    let mut first_publication = true;
                    run_eject_with_progress(
                        &mut session,
                        context,
                        &mut host,
                        HostEjectPolicy::Safe,
                        |_event| {
                            if first_publication {
                                first_publication = false;
                                publisher_entered.wait();
                                publisher_release.wait();
                                publisher_returning.store(true, Ordering::Release);
                            }
                            Ok(())
                        },
                    )
                    .expect("causal publication race remains a typed outcome")
                });
                progress_entered.wait();
                let request_worker = scope.spawn(move || {
                    request_started_sender
                        .send(())
                        .expect("request-start receiver remains available");
                    let result = cancellation.request(&owner);
                    request_sender
                        .send((result, publication_returning.load(Ordering::Acquire)))
                        .expect("request observation receiver remains available");
                });
                request_started_receiver
                    .recv_timeout(Duration::from_secs(2))
                    .expect("request worker reaches cancellation call");
                let early_request = request_receiver
                    .recv_timeout(Duration::from_millis(25))
                    .ok();
                progress_release.wait();
                let (request_result, publication_had_returned) =
                    early_request.unwrap_or_else(|| {
                        request_receiver
                            .recv_timeout(Duration::from_secs(2))
                            .expect("request completes after causal publication")
                    });
                request_worker.join().expect("request worker joins");
                (
                    early_request,
                    request_result,
                    publication_had_returned,
                    worker.join().expect("eject worker joins"),
                )
            });

        assert!(
            early_request.is_none(),
            "iteration {iteration}: request must not return before publication"
        );
        assert!(
            publication_had_returned,
            "iteration {iteration}: acceptance overtook its Cancellable event"
        );
        assert_eq!(
            request_result,
            CancellationRequestResult::Accepted,
            "iteration {iteration}: the pre-release request must reserve cancellation"
        );
        let report = cancelled_report(outcome);
        assert_eq!(report.completion(), OperationCompletion::Cancelled);
        assert_eq!(
            report.events()[0].cancellation_state(),
            CancellationState::Cancellable
        );
    }
}

/// Proves accepted cancellation before preflight performs no host action or readback.
#[test]
fn safe_eject_honors_early_cancellation_before_unmount() {
    let (fixture, mut session, context) = operation(OperationKind::EjectSafe, "eject-early");
    let owner = context.owner().clone();
    let cancellation = context.cancellation_handle();
    assert_eq!(
        cancellation.request(&owner),
        CancellationRequestResult::Accepted
    );
    let mut host = RecordingEjectHost::default();

    let outcome = run_eject(&mut session, context, &mut host, HostEjectPolicy::Safe)
        .expect("early cancellation is a typed outcome");
    let report = cancelled_report(outcome);

    assert_eq!(report.completion(), OperationCompletion::Cancelled);
    assert_eq!(fixture.refresh_count(), 0);
    assert_eq!(host.counts(), (0, 0, 0));
    assert_eq!(report.events().len(), 1);
    assert_eq!(report.events()[0].stage(), OperationStage::HostUnmounting);
    assert_eq!(
        report.events()[0].cancellation_state(),
        CancellationState::Requested
    );
}

/// Proves cancellation accepted during preflight prevents the later unmount call.
#[test]
fn safe_eject_honors_cancellation_that_arrives_before_unmount() {
    let (fixture, session, context) = operation(OperationKind::EjectSafe, "eject-pre-unmount");
    let owner = context.owner().clone();
    let cancellation = context.cancellation_handle();
    let entered = Arc::new(Barrier::new(2));
    let release = Arc::new(Barrier::new(2));
    fixture.block_refresh_call(1, Arc::clone(&entered), Arc::clone(&release));
    let host = RecordingEjectHost::default();
    let observed = host.clone();

    let outcome = std::thread::scope(|scope| {
        let worker = scope.spawn(move || {
            let mut session = session;
            let mut host = host;
            run_eject(&mut session, context, &mut host, HostEjectPolicy::Safe)
                .expect("pre-unmount cancellation is a typed outcome")
        });
        entered.wait();
        assert_eq!(
            cancellation.request(&owner),
            CancellationRequestResult::Accepted
        );
        release.wait();
        worker.join().expect("eject worker joins")
    });
    let report = cancelled_report(outcome);

    assert_eq!(report.completion(), OperationCompletion::Cancelled);
    assert_eq!(fixture.refresh_count(), 1);
    assert_eq!(observed.counts(), (0, 0, 0));
}

/// Proves cancellation won during unmount closes before the eject mutation barrier.
#[test]
fn safe_eject_honors_cancellation_that_wins_during_unmount() {
    let (fixture, session, context) = operation(OperationKind::EjectSafe, "eject-unmount-race");
    let owner = context.owner().clone();
    let cancellation = context.cancellation_handle();
    let entered = Arc::new(Barrier::new(2));
    let release = Arc::new(Barrier::new(2));
    let host = RecordingEjectHost::default();
    host.block_unmount(Arc::clone(&entered), Arc::clone(&release));
    let observed = host.clone();

    let outcome = std::thread::scope(|scope| {
        let worker = scope.spawn(move || {
            let mut session = session;
            let mut host = host;
            run_eject(&mut session, context, &mut host, HostEjectPolicy::Safe)
                .expect("unmount cancellation is a typed outcome")
        });
        entered.wait();
        assert_eq!(
            cancellation.request(&owner),
            CancellationRequestResult::Accepted
        );
        release.wait();
        worker.join().expect("eject worker joins")
    });
    let report = cancelled_report(outcome);

    assert_eq!(report.completion(), OperationCompletion::Cancelled);
    assert_eq!(fixture.refresh_count(), 1);
    assert_eq!(observed.counts(), (1, 0, 0));
    assert_eq!(
        report.events().last().expect("unmount event").stage(),
        OperationStage::HostUnmounting
    );
}

/// Proves cancellation closes before dispatch and late requests cannot skip readback.
#[test]
fn safe_eject_closes_cancellation_before_dispatch_and_reconciles_late_requests() {
    let (fixture, session, context) = operation(OperationKind::EjectSafe, "eject-late");
    let owner = context.owner().clone();
    let cancellation = context.cancellation_handle();
    let entered = Arc::new(Barrier::new(2));
    let release = Arc::new(Barrier::new(2));
    let host = RecordingEjectHost::default();
    host.block_eject(Arc::clone(&entered), Arc::clone(&release));
    let observed = host.clone();

    let outcome = std::thread::scope(|scope| {
        let worker = scope.spawn(move || {
            let mut session = session;
            let mut host = host;
            run_eject(&mut session, context, &mut host, HostEjectPolicy::Safe)
                .expect("late cancellation cannot replace reconciliation")
        });
        entered.wait();
        assert_eq!(
            cancellation.request(&owner),
            CancellationRequestResult::Closed
        );
        release.wait();
        worker.join().expect("eject worker joins")
    });
    let report = succeeded_report(outcome);

    assert_eq!(report.completion(), OperationCompletion::Succeeded);
    assert_eq!(fixture.refresh_count(), 1);
    assert_eq!(observed.counts(), (1, 1, 1));
    assert_eq!(
        report
            .events()
            .iter()
            .map(|event| event.stage())
            .collect::<Vec<_>>(),
        [
            OperationStage::HostUnmounting,
            OperationStage::HostEjecting,
            OperationStage::EjectReadback,
        ]
    );
    assert_eq!(
        report.events()[1].cancellation_state(),
        CancellationState::Closed
    );
    assert_eq!(
        report.events()[2].cancellation_state(),
        CancellationState::Closed
    );
}

/// Proves forced policy is never cancellable and still performs mandatory readback.
#[test]
fn forced_eject_is_closed_from_its_first_stage() {
    let (fixture, mut session, context) = operation(OperationKind::EjectForce, "eject-forced");
    let owner = context.owner().clone();
    let cancellation = context.cancellation_handle();
    assert_eq!(
        cancellation.request(&owner),
        CancellationRequestResult::Closed
    );
    let mut host = RecordingEjectHost::default();

    let outcome = run_eject(&mut session, context, &mut host, HostEjectPolicy::Forced)
        .expect("forced eject completes with mandatory readback");
    let report = match outcome {
        EjectOutcome::Succeeded { report, departure } => {
            assert_eq!(departure.policy(), HostEjectPolicy::Forced);
            report
        }
        EjectOutcome::Cancelled { .. } => panic!("forced eject cannot be cancelled"),
    };

    assert_eq!(report.completion(), OperationCompletion::Succeeded);
    assert_eq!(fixture.refresh_count(), 1);
    assert_eq!(host.counts(), (0, 1, 1));
    assert_eq!(report.events()[0].stage(), OperationStage::HostEjecting);
    assert_eq!(
        report.events()[0].cancellation_state(),
        CancellationState::Closed
    );
}
