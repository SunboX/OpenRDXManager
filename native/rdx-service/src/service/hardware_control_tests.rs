// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

use super::*;
use crate::model::{DeviceId, DiscoveryRevision};

/// Closing an irreversible stage makes a later cancel request truthfully too late.
#[test]
fn irreversible_checkpoint_rejects_late_cancellation() {
    let control = OperationControl::new(OperationKind::Format);

    assert!(control.checkpoint_and_publish(true, || Ok(())).unwrap());
    assert!(control.checkpoint_and_publish(false, || Ok(())).unwrap());
    assert_eq!(
        control.request_cancellation().unwrap_err().as_str(),
        "operation-not-cancellable"
    );
}

/// Configuration setters remain non-cancellable from admission through readback.
#[test]
fn mode_configuration_never_opens_cancellation() {
    for kind in [OperationKind::DriveModeSet, OperationKind::SataModeSet] {
        let control = OperationControl::new(kind);
        assert_eq!(
            control.request_cancellation().unwrap_err().as_str(),
            "operation-not-cancellable"
        );
        assert!(control.checkpoint_and_publish(false, || Ok(())).unwrap());
        assert_eq!(
            control.request_cancellation().unwrap_err().as_str(),
            "operation-not-cancellable"
        );
    }
}

/// A status refresh closes cancellation in the same critical section as its
/// Started publication, so a racing request cannot be accepted after dispatch.
#[test]
fn status_refresh_start_barrier_rejects_racing_cancellation_before_dispatch() {
    use std::sync::Barrier;

    let control = Arc::new(OperationControl::new(OperationKind::StatusRefresh));
    let entered = Arc::new(Barrier::new(2));
    let release = Arc::new(Barrier::new(2));
    let worker_control = Arc::clone(&control);
    let worker_entered = Arc::clone(&entered);
    let worker_release = Arc::clone(&release);
    let started = std::thread::spawn(move || {
        worker_control
            .checkpoint_and_publish(false, || {
                worker_entered.wait();
                worker_release.wait();
                Ok(())
            })
            .unwrap()
    });
    entered.wait();
    let cancel_control = Arc::clone(&control);
    let (finished_sender, finished_receiver) = mpsc::sync_channel(0);
    let cancel = std::thread::spawn(move || {
        let result = cancel_control.request_cancellation();
        finished_sender.send(()).unwrap();
        result
    });

    assert!(finished_receiver.try_recv().is_err());
    release.wait();
    assert!(started.join().unwrap());
    finished_receiver
        .recv_timeout(Duration::from_secs(1))
        .unwrap();
    assert_eq!(
        cancel.join().unwrap().unwrap_err().as_str(),
        "operation-not-cancellable"
    );
}

/// A cancellation accepted behind a deterministic publication barrier is
/// observed before any later stage can publish Cancellable or Closed.
#[test]
fn accepted_cancellation_linearizes_before_later_stage_publication() {
    use std::sync::Barrier;

    let control = Arc::new(OperationControl::new(OperationKind::EjectSafe));
    let entered = Arc::new(Barrier::new(2));
    let release = Arc::new(Barrier::new(2));
    let published = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let worker_control = Arc::clone(&control);
    let worker_entered = Arc::clone(&entered);
    let worker_release = Arc::clone(&release);
    let worker_published = Arc::clone(&published);
    let stage = std::thread::spawn(move || {
        worker_control
            .checkpoint_and_publish(true, || {
                worker_entered.wait();
                worker_release.wait();
                worker_published.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                Ok(())
            })
            .unwrap()
    });
    entered.wait();
    let cancel_control = Arc::clone(&control);
    let (accepted, cancelled) = mpsc::sync_channel(0);
    let cancel = std::thread::spawn(move || {
        let result = cancel_control.request_cancellation();
        accepted.send(()).unwrap();
        result
    });
    assert!(cancelled.try_recv().is_err());
    release.wait();
    assert!(stage.join().unwrap());
    cancelled.recv_timeout(Duration::from_secs(1)).unwrap();
    assert!(cancel.join().unwrap().is_ok());
    assert_eq!(published.load(std::sync::atomic::Ordering::SeqCst), 1);

    assert!(
        !control
            .checkpoint_and_publish(false, || {
                published.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                Ok(())
            })
            .unwrap()
    );
    assert_eq!(published.load(std::sync::atomic::Ordering::SeqCst), 1);

    let operation_id = OperationId::new("op:cancel-linearized").unwrap();
    let identity = DeviceIdentity {
        id: DeviceId::new("rdx:cancel-linearized").unwrap(),
        revision: DiscoveryRevision::new(4).unwrap(),
    };
    let control = OperationControl::new(OperationKind::EjectSafe);
    let (sender, receiver) = mpsc::sync_channel(8);
    let crashes = super::super::crash::CrashAdmission::new();
    let events = ServiceEventSink::new(sender, crashes.clone());
    let mut observer = HostWorkerObserver {
        operation_id: &operation_id,
        kind: OperationKind::EjectSafe,
        identity: &identity,
        events: &events,
        control: &control,
        started: false,
        current_stage: None,
        publication_failed: false,
    };
    assert!(observer.reached("host-unmounting", true));
    control.request_cancellation().unwrap();
    assert!(!observer.reached("host-ejecting", false));
    events
        .publish_host_cancelled_at(
            &operation_id,
            OperationKind::EjectSafe,
            &identity,
            observer.current_stage.unwrap(),
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
        crate::model::OperationEvent::Cancelled { .. }
    ));
    assert!(crashes.observe().is_ok());
}
