// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Synthetic concurrency regressions; no platform adapter or hardware is called.

use super::*;

const BOOTLOADER: &str = "firmware-awaiting-bootloader";
const BOOTSTRAP: &str = "firmware-awaiting-bootstrap";

/// An early operator click is retained until the worker reaches its wait.
#[test]
fn continuation_accepts_ack_before_worker_wait_and_consumes_it_once() {
    let control = OperationControl::new(OperationKind::FirmwareUpdate);
    control.release().unwrap();
    control.arm_operator_wait(BOOTLOADER).unwrap();
    control.acknowledge_operator(BOOTLOADER).unwrap();
    assert!(control.acknowledge_operator(BOOTLOADER).is_err());
    assert!(
        control
            .wait_for_operator(BOOTLOADER, Duration::from_millis(10))
            .unwrap()
    );
    assert!(control.acknowledge_operator(BOOTLOADER).is_err());
    assert!(control.arm_operator_wait(BOOTLOADER).is_err());
    control.arm_operator_wait(BOOTSTRAP).unwrap();
    control.acknowledge_operator(BOOTSTRAP).unwrap();
    assert!(
        control
            .wait_for_operator(BOOTSTRAP, Duration::from_millis(10))
            .unwrap()
    );
    assert!(control.arm_operator_wait(BOOTSTRAP).is_err());
}

/// Invalid continuation states never acquire or advance a power-cycle gate.
#[test]
fn continuation_rejects_unarmed_wrong_stage_and_cancelled_operation() {
    let control = OperationControl::new(OperationKind::FirmwareUpdate);
    assert!(control.acknowledge_operator(BOOTLOADER).is_err());
    assert!(control.arm_operator_wait(BOOTSTRAP).is_err());
    assert!(control.arm_operator_wait("firmware-resetting").is_err());
    control.release().unwrap();
    control.arm_operator_wait(BOOTLOADER).unwrap();
    assert!(control.acknowledge_operator(BOOTSTRAP).is_err());
    assert!(control.acknowledge_operator("firmware-resetting").is_err());
    assert_eq!(
        control.request_cancellation().unwrap_err().as_str(),
        "operation-not-cancellable"
    );
    assert!(
        !control
            .wait_for_operator(BOOTLOADER, Duration::ZERO)
            .unwrap()
    );
    assert!(control.acknowledge_operator(BOOTLOADER).is_err());
    assert!(control.arm_operator_wait(BOOTSTRAP).is_err());
    let cancelled = OperationControl::new(OperationKind::FirmwareUpdate);
    cancelled.request_cancellation().unwrap();
    cancelled.release().unwrap();
    assert!(cancelled.arm_operator_wait(BOOTLOADER).is_err());
    for kind in [
        OperationKind::StatusRefresh,
        OperationKind::EjectSafe,
        OperationKind::SelfTest,
    ] {
        let control = OperationControl::new(kind);
        control.release().unwrap();
        assert!(control.arm_operator_wait(BOOTLOADER).is_err());
    }
}

/// A parked worker wakes through acknowledgment with cancellation kept closed.
#[test]
fn continuation_wakes_a_waiting_worker_without_opening_cancellation() {
    let control = Arc::new(OperationControl::new(OperationKind::FirmwareUpdate));
    control.release().unwrap();
    control.arm_operator_wait(BOOTLOADER).unwrap();
    let worker_control = Arc::clone(&control);
    let (started, waiting) = mpsc::sync_channel(0);
    let worker = thread::spawn(move || {
        started.send(()).unwrap();
        worker_control
            .wait_for_operator(BOOTLOADER, Duration::from_secs(1))
            .unwrap()
    });
    waiting.recv_timeout(Duration::from_secs(1)).unwrap();
    assert!(control.wait_until_operator_parked());
    control.acknowledge_operator(BOOTLOADER).unwrap();
    assert!(worker.join().unwrap());
    assert_eq!(
        control.request_cancellation().unwrap_err().as_str(),
        "operation-not-cancellable"
    );
    assert!(control.checkpoint_and_publish(true, || Ok(())).unwrap());
    assert_eq!(
        control.request_cancellation().unwrap_err().as_str(),
        "operation-not-cancellable"
    );
}

/// A platform marker whose methods must never run on the continuation fast path.
struct NoHardware;

impl PlatformBackend for NoHardware {
    /// Rejects an accidental platform capability query in this control-only test.
    fn capabilities(&self) -> crate::platform::PlatformCapabilities {
        panic!("no hardware")
    }
    /// Rejects any accidental device discovery.
    fn enumerate_candidates(
        &mut self,
    ) -> Result<Vec<crate::platform::CandidateDevice>, PlatformError> {
        panic!("no hardware")
    }
    /// Rejects any accidental native lease acquisition.
    fn open_candidate(
        &mut self,
        _: &crate::platform::CandidateDevice,
    ) -> Result<crate::platform::CandidateLease, PlatformError> {
        panic!("no hardware")
    }
}

/// A disconnected command queue cannot block the direct exact-owner control path.
#[test]
fn continuation_backend_uses_active_control_without_touching_worker_queue() {
    let control = Arc::new(OperationControl::new(OperationKind::FirmwareUpdate));
    control.release().unwrap();
    control.arm_operator_wait(BOOTLOADER).unwrap();
    let operation_id = OperationId::new("op:direct-continue").unwrap();
    let (commands, disconnected_worker) = mpsc::sync_channel(0);
    drop(disconnected_worker);
    let mut backend = HardwareServiceBackend::<NoHardware> {
        descriptor: ServiceDescriptor::native_available(
            ServicePlatform::Darwin,
            "continuation-test",
        )
        .unwrap(),
        commands,
        snapshots: Arc::new(Mutex::new(vec![])),
        active: Arc::new(Mutex::new(Some(ActiveHostOperation {
            operation_id: operation_id.clone(),
            control: Arc::clone(&control),
        }))),
        _backend: std::marker::PhantomData,
    };
    assert_eq!(
        backend
            .continue_operation(&OperationId::new("op:wrong-owner").unwrap(), BOOTLOADER)
            .unwrap_err()
            .as_str(),
        "operation-not-found"
    );
    assert_eq!(
        backend
            .continue_operation(&operation_id, BOOTSTRAP)
            .unwrap_err()
            .as_str(),
        "operation-not-continuable"
    );
    backend
        .continue_operation(&operation_id, BOOTLOADER)
        .unwrap();
    assert!(
        backend
            .continue_operation(&operation_id, BOOTLOADER)
            .is_err()
    );
    assert!(backend.active.lock().unwrap().is_some());
    assert!(
        control
            .wait_for_operator(BOOTLOADER, Duration::ZERO)
            .unwrap()
    );
    *backend.active.lock().unwrap() = None;
    assert_eq!(
        backend
            .continue_operation(&operation_id, BOOTSTRAP)
            .unwrap_err()
            .as_str(),
        "operation-not-found"
    );
}
