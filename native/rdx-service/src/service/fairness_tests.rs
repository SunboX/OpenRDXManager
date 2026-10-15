// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::Instant;

use serde_json::json;

use super::crash::CrashAdmission;
use super::events::ServiceOperationSignal;
use super::{
    ActiveOperation, InputSignal, MAX_BACKEND_EVENT_BATCH, MAX_OPERATION_SERVICE_EVENTS,
    MAX_PENDING_SERVICE_EVENTS, ServiceBackend, ServiceDescriptor, ServiceEventSink, ServiceExit,
    ServicePlatform, ServiceProtocolError, ServiceRejection, ServiceRuntime, drain_backend_signals,
    service_loop,
};
use crate::firmware::{FirmwareRevision, ProductFamily};
use crate::host::{DeviceInterface, FixtureDevice, SessionDevice, SessionGeneration};
use crate::model::{
    CancellationState, Capability, CapabilityState, DeviceId, DeviceIdentity, DeviceSnapshot,
    DiscoveryRevision, DisplayText, DriveStatus, MediaState, OperationEvent, OperationId,
    OperationKind, OperationRequest, Progress, ReasonCode,
};
use crate::operations::{
    CancellationHandle, CancellationRequestResult, OperationCompletion, OperationContext,
    OperationOwner, OperationStage,
};
use crate::platform::ValidatedDiscoveryReport;

/// Minimal backend whose control calls are visible to fairness assertions.
struct ControlBackend {
    cancel_count: Arc<AtomicUsize>,
    cancellation: Option<(CancellationHandle, OperationOwner)>,
    devices: Arc<Mutex<Vec<DeviceSnapshot>>>,
    shutdown_count: Arc<AtomicUsize>,
}

impl ServiceBackend for ControlBackend {
    /// Reports one native test generation.
    fn descriptor(&self) -> ServiceDescriptor {
        ServiceDescriptor::native_available(ServicePlatform::Darwin, "fairness-test").unwrap()
    }

    /// Returns one exact test inventory.
    fn list_devices(&mut self) -> Result<Vec<DeviceSnapshot>, ServiceRejection> {
        Ok(self.devices.lock().unwrap().clone())
    }

    /// Returns one exact test inventory.
    fn scan_devices(&mut self) -> Result<Vec<DeviceSnapshot>, ServiceRejection> {
        Ok(self.devices.lock().unwrap().clone())
    }

    /// Is not used because tests install the active reservation directly.
    fn start_operation(
        &mut self,
        _operation_id: OperationId,
        _request: OperationRequest,
        _events: ServiceEventSink,
    ) -> Result<(), ServiceRejection> {
        Ok(())
    }

    /// Records one bounded cancellation control call.
    fn cancel_operation(&mut self, _operation_id: &OperationId) -> Result<(), ServiceRejection> {
        self.cancel_count.fetch_add(1, Ordering::SeqCst);
        if let Some((cancellation, owner)) = &self.cancellation {
            assert_eq!(
                cancellation.request(owner),
                CancellationRequestResult::Accepted
            );
        }
        Ok(())
    }

    /// Records one bounded shutdown control call.
    fn shutdown(&mut self) -> Result<(), ServiceRejection> {
        self.shutdown_count.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

/// Creates the inventory identity shared by all internal lifecycle events.
fn device() -> DeviceSnapshot {
    let vendor = DisplayText::new("TANDBERG").unwrap();
    let product = DisplayText::new("RDX").unwrap();
    let serial = DisplayText::new("FAIRNESS").unwrap();
    DeviceSnapshot {
        id: DeviceId::new("rdx:fairness").unwrap(),
        revision: DiscoveryRevision::new(3).unwrap(),
        drive: DriveStatus::from_identity(&vendor, &product, &serial),
        vendor,
        product,
        serial,
        media: None,
        media_state: MediaState::NoMedia,
        capabilities: BTreeMap::from([(
            OperationKind::SelfTest,
            Capability {
                state: CapabilityState::Available,
                reason: None,
            },
        )]),
    }
}

/// Creates the shared self-test request.
fn request() -> OperationRequest {
    OperationRequest::SelfTest {
        device_id: DeviceId::new("rdx:fairness").unwrap(),
        device_revision: DiscoveryRevision::new(3).unwrap(),
    }
}

/// Creates one lifecycle event with the exact active owner.
fn event(state: &'static str) -> OperationEvent {
    let operation_id = OperationId::new("op:fairness").unwrap();
    let device_id = DeviceId::new("rdx:fairness").unwrap();
    let device_revision = DiscoveryRevision::new(3).unwrap();
    match state {
        "started" => OperationEvent::Started {
            operation_id,
            kind: OperationKind::SelfTest,
            device_id,
            device_revision,
            stage: ReasonCode::new("diagnostic-running").unwrap(),
            message_key: None,
        },
        "progress" => OperationEvent::Progress {
            operation_id,
            kind: OperationKind::SelfTest,
            device_id,
            device_revision,
            stage: ReasonCode::new("diagnostic-running").unwrap(),
            progress: Progress::new(0.1).unwrap(),
            attempt: None,
            cancellation_state: CancellationState::Cancellable,
            message_key: None,
        },
        _ => unreachable!("fairness test uses only nonterminal events"),
    }
}

/// Related runtime controls kept together for compact fairness setup.
struct RuntimeFixture {
    runtime: ServiceRuntime<ControlBackend>,
    sender: mpsc::SyncSender<Box<ServiceOperationSignal>>,
    receiver: mpsc::Receiver<Box<ServiceOperationSignal>>,
    crashes: CrashAdmission,
    cancel_count: Arc<AtomicUsize>,
    devices: Arc<Mutex<Vec<DeviceSnapshot>>>,
    shutdown_count: Arc<AtomicUsize>,
}

/// Creates a runtime with one already-started exact operation.
fn runtime() -> RuntimeFixture {
    let (sender, receiver) = mpsc::sync_channel(MAX_PENDING_SERVICE_EVENTS);
    let crashes = CrashAdmission::new();
    let cancel_count = Arc::new(AtomicUsize::new(0));
    let devices = Arc::new(Mutex::new(vec![device()]));
    let shutdown_count = Arc::new(AtomicUsize::new(0));
    let sink = ServiceEventSink::new(sender.clone(), crashes.clone());
    let mut runtime = ServiceRuntime::new(
        ControlBackend {
            cancel_count: Arc::clone(&cancel_count),
            cancellation: None,
            devices: Arc::clone(&devices),
            shutdown_count: Arc::clone(&shutdown_count),
        },
        sink,
    );
    runtime.handshaken = true;
    runtime.active = Some(
        ActiveOperation::new_at(
            OperationId::new("op:fairness").unwrap(),
            &request(),
            Instant::now(),
        )
        .unwrap(),
    );
    runtime.handle_event(event("started")).unwrap();
    RuntimeFixture {
        runtime,
        sender,
        receiver,
        crashes,
        cancel_count,
        devices,
        shutdown_count,
    }
}

/// Creates proof-bearing native progress for the exact fairness reservation.
fn operation_context() -> (FixtureDevice, OperationContext) {
    let fixture = FixtureDevice::new(SessionDevice::fixture(
        DeviceIdentity {
            id: DeviceId::new("rdx:fairness").unwrap(),
            revision: DiscoveryRevision::new(3).unwrap(),
        },
        ProductFamily::Usb3Sata3,
        FirmwareRevision::new(283).unwrap(),
        DeviceInterface::Usb3,
        false,
        SessionGeneration::new(41).unwrap(),
    ));
    let session = fixture.open();
    let context = OperationContext::for_session(
        OperationId::new("op:fairness").unwrap(),
        OperationKind::SelfTest,
        &session,
    )
    .unwrap();
    (fixture, context)
}

/// Wraps one internal event for the service signal queue.
fn signal() -> Box<ServiceOperationSignal> {
    Box::new(ServiceOperationSignal {
        publication_sequence: 0,
        event: event("progress"),
        failure: None,
        host_failure: None,
        host_operation: false,
        eject_departure: None,
        inventory_update: None,
    })
}

/// Counts complete length-framed output messages.
fn frame_count(bytes: &[u8]) -> usize {
    let mut cursor = 0;
    let mut count = 0;
    while cursor < bytes.len() {
        let length = u32::from_be_bytes(bytes[cursor..cursor + 4].try_into().unwrap()) as usize;
        cursor += 4 + length;
        count += 1;
    }
    count
}

/// Decodes complete controlled output frames for exact response assertions.
fn decode_frames(bytes: &[u8]) -> Vec<serde_json::Value> {
    let mut cursor = 0;
    let mut values = Vec::new();
    while cursor < bytes.len() {
        let length = u32::from_be_bytes(bytes[cursor..cursor + 4].try_into().unwrap()) as usize;
        cursor += 4;
        values.push(serde_json::from_slice(&bytes[cursor..cursor + length]).unwrap());
        cursor += length;
    }
    values
}

/// Proves a status refresh installs and publishes its authoritative inventory
/// before success, then remains compatible with a subsequent list request.
#[test]
fn status_refresh_inventory_precedes_terminal_and_updates_runtime_cache() {
    let RuntimeFixture {
        mut runtime,
        receiver,
        crashes,
        devices,
        ..
    } = runtime();
    let operation_id = OperationId::new("op:status-refresh-order").unwrap();
    let request = OperationRequest::StatusRefresh {
        device_id: DeviceId::new("rdx:fairness").unwrap(),
        device_revision: DiscoveryRevision::new(3).unwrap(),
    };
    runtime.active =
        Some(ActiveOperation::new_at(operation_id.clone(), &request, Instant::now()).unwrap());
    let identity = DeviceIdentity {
        id: DeviceId::new("rdx:fairness").unwrap(),
        revision: DiscoveryRevision::new(3).unwrap(),
    };
    let mut refreshed = device();
    refreshed.revision = DiscoveryRevision::new(4).unwrap();
    refreshed.drive.firmware_revision = Some(DisplayText::new("0290").unwrap());
    refreshed.drive.details.firmware_revision =
        crate::model::StatusField::reported(DisplayText::new("0290").unwrap());
    *devices.lock().unwrap() = vec![refreshed.clone()];
    let sink = runtime.event_sink.clone();
    sink.publish_host_started(&operation_id, OperationKind::StatusRefresh, &identity)
        .unwrap();
    sink.publish_status_success(
        &operation_id,
        &identity,
        ValidatedDiscoveryReport::all_accepted(vec![refreshed]),
    )
    .unwrap();
    let mut output = Vec::new();

    drain_backend_signals(&mut runtime, &receiver, &crashes, &mut output).unwrap();

    let frames = decode_frames(&output);
    assert_eq!(frames.len(), 3);
    assert_eq!(frames[0]["event"]["state"], "started");
    assert_eq!(frames[1]["event"]["type"], "list");
    assert_eq!(frames[1]["event"]["listRevision"], 1);
    assert_eq!(frames[1]["event"]["devices"][0]["revision"], 4);
    assert_eq!(
        frames[1]["event"]["devices"][0]["drive"]["firmwareRevision"],
        "0290"
    );
    assert_eq!(frames[2]["event"]["state"], "succeeded");

    let (messages, _) = runtime
        .handle_message(json!({
            "type":"request",
            "protocolVersion":1,
            "requestId":"request:1",
            "method":"devices-list",
            "payload":{}
        }))
        .unwrap();
    assert_eq!(messages[0]["result"]["ok"], true);
    assert_eq!(messages[0]["result"]["listRevision"], 1);
    assert_eq!(messages[0]["result"]["devices"][0]["revision"], 4);
}

/// Proves the reserved crash channel is observed after one fixed event quantum.
#[test]
fn fixed_drain_quantum_observes_reserved_crash_despite_a_full_producer() {
    let RuntimeFixture {
        mut runtime,
        sender,
        receiver,
        crashes,
        ..
    } = runtime();
    for _ in 0..MAX_PENDING_SERVICE_EVENTS {
        sender.try_send(signal()).unwrap();
    }
    crashes.report().unwrap();
    let mut output = Vec::new();

    assert_eq!(
        drain_backend_signals(&mut runtime, &receiver, &crashes, &mut output),
        Err(ServiceProtocolError::BackendContract)
    );
    assert_eq!(frame_count(&output), MAX_BACKEND_EVENT_BATCH);
    assert_eq!(
        receiver.try_iter().count(),
        MAX_PENDING_SERVICE_EVENTS - MAX_BACKEND_EVENT_BATCH
    );
}

/// Proves replayed valid progress exhausts a fixed total budget without a terminal.
#[test]
fn total_event_budget_terminates_valid_repeated_progress_without_a_fake_terminal() {
    let RuntimeFixture { mut runtime, .. } = runtime();
    for _ in 1..MAX_OPERATION_SERVICE_EVENTS {
        runtime.handle_event(event("progress")).unwrap();
    }

    assert_eq!(
        runtime.handle_event(event("progress")),
        Err(ServiceProtocolError::BackendContract)
    );
    assert!(runtime.active.is_some());
}

/// Proves an exact deadline cutoff retains ownership and emits no fake result.
#[test]
fn absolute_deadline_is_deterministic_and_preserves_active_ambiguity() {
    let RuntimeFixture { mut runtime, .. } = runtime();
    let deadline = runtime.active.as_ref().unwrap().deadline;

    assert_eq!(
        runtime.handle_event_at(event("progress"), deadline),
        Err(ServiceProtocolError::BackendContract)
    );
    assert!(runtime.active.is_some());
}

/// Proves an internal raw terminal cannot bypass report proof or cancellation ownership.
#[test]
fn forged_non_eject_success_and_safe_stage_cancellation_are_rejected() {
    let RuntimeFixture {
        runtime: mut forged_success,
        ..
    } = runtime();
    assert_eq!(
        forged_success.handle_event(OperationEvent::Succeeded {
            operation_id: OperationId::new("op:fairness").unwrap(),
            kind: OperationKind::SelfTest,
            device_id: DeviceId::new("rdx:fairness").unwrap(),
            device_revision: DiscoveryRevision::new(3).unwrap(),
            stage: ReasonCode::new("complete").unwrap(),
            message_key: None,
        }),
        Err(ServiceProtocolError::BackendContract)
    );
    assert!(forged_success.active.is_some());

    let RuntimeFixture {
        runtime: mut forged_cancellation,
        ..
    } = runtime();
    forged_cancellation
        .handle_event(OperationEvent::Progress {
            operation_id: OperationId::new("op:fairness").unwrap(),
            kind: OperationKind::SelfTest,
            device_id: DeviceId::new("rdx:fairness").unwrap(),
            device_revision: DiscoveryRevision::new(3).unwrap(),
            stage: ReasonCode::new("diagnostic-cleanup").unwrap(),
            progress: Progress::new(1.0).unwrap(),
            attempt: None,
            cancellation_state: CancellationState::Closed,
            message_key: None,
        })
        .unwrap();
    assert_eq!(
        forged_cancellation.handle_event(OperationEvent::Cancelled {
            operation_id: OperationId::new("op:fairness").unwrap(),
            kind: OperationKind::SelfTest,
            device_id: DeviceId::new("rdx:fairness").unwrap(),
            device_revision: DiscoveryRevision::new(3).unwrap(),
            stage: ReasonCode::new("diagnostic-cleanup").unwrap(),
            reason: Some(ReasonCode::new("cancelled-by-user").unwrap()),
            message_key: None,
        }),
        Err(ServiceProtocolError::BackendContract)
    );
    assert!(forged_cancellation.active.is_some());
}

/// Proves one event quantum cannot starve an already queued cancellation request.
#[test]
fn continuously_refilled_events_cannot_starve_cancel_control() {
    let RuntimeFixture {
        mut runtime,
        sender,
        receiver,
        crashes,
        cancel_count,
        ..
    } = runtime();
    for _ in 0..MAX_PENDING_SERVICE_EVENTS {
        sender.try_send(signal()).unwrap();
    }
    let mut output = Vec::new();
    drain_backend_signals(&mut runtime, &receiver, &crashes, &mut output).unwrap();
    let (messages, _) = runtime
        .handle_message(json!({
            "type":"request",
            "protocolVersion":1,
            "requestId":"request:1",
            "method":"operation-cancel",
            "payload":{"operationId":"op:fairness"}
        }))
        .unwrap();

    assert_eq!(cancel_count.load(Ordering::SeqCst), 1);
    assert_eq!(
        messages[0]["result"],
        json!({
            "ok": true,
            "cancellationCutover": 0
        })
    );
    assert_eq!(frame_count(&output), MAX_BACKEND_EVENT_BATCH);
}

/// Proves the cancel acknowledgement preserves the FIFO prefix published before it.
#[test]
fn cancellation_cutover_drains_a_full_pre_ack_backlog_then_reuses_ownership() {
    let RuntimeFixture {
        mut runtime,
        receiver,
        crashes,
        ..
    } = runtime();
    let (_fixture, mut context) = operation_context();
    let sink = runtime.event_sink.clone();
    for index in 1..=MAX_PENDING_SERVICE_EVENTS {
        context
            .emit_causally(
                OperationStage::DiagnosticRunning,
                index as f64 / (MAX_PENDING_SERVICE_EVENTS as f64 + 2.0),
                "operations.selfTest.running",
                &mut |progress| sink.publish_progress(progress),
            )
            .unwrap();
    }
    runtime.backend.cancellation = Some((context.cancellation_handle(), context.owner().clone()));
    let mut output = Vec::new();
    drain_backend_signals(&mut runtime, &receiver, &crashes, &mut output).unwrap();

    let (messages, _) = runtime
        .handle_message(json!({
            "type":"request",
            "protocolVersion":1,
            "requestId":"request:1",
            "method":"operation-cancel",
            "payload":{"operationId":"op:fairness"}
        }))
        .unwrap();
    assert_eq!(
        messages[0]["result"],
        json!({
            "ok": true,
            "cancellationCutover": MAX_PENDING_SERVICE_EVENTS
        })
    );
    context
        .emit_causally(
            OperationStage::DiagnosticCleanup,
            1.0,
            "operations.selfTest.cleanup",
            &mut |progress| sink.publish_progress(progress),
        )
        .unwrap();
    sink.publish_report(context.complete(OperationCompletion::Cancelled))
        .unwrap();

    while runtime.active.is_some() {
        drain_backend_signals(&mut runtime, &receiver, &crashes, &mut output).unwrap();
    }
    assert_eq!(frame_count(&output), MAX_PENDING_SERVICE_EVENTS + 2);
    assert_eq!(
        decode_frames(&output)
            .iter()
            .map(|message| message["publicationSequence"].as_u64())
            .collect::<Vec<_>>(),
        (1..=(MAX_PENDING_SERVICE_EVENTS as u64 + 2))
            .map(Some)
            .collect::<Vec<_>>()
    );
    runtime.devices = vec![device()];
    runtime.inventory_initialized = true;
    assert!(matches!(
        runtime
            .admit_operation(OperationId::new("op:fairness-reuse").unwrap(), request())
            .unwrap(),
        super::OperationAdmission::Accepted
    ));
}

/// Proves a backend cannot replay pre-request proof after its cancel acknowledgement.
#[test]
fn cancellation_cutover_rejects_post_ack_cancellable_replay() {
    let RuntimeFixture {
        mut runtime,
        receiver,
        crashes,
        ..
    } = runtime();
    let (_fixture, mut context) = operation_context();
    let sink = runtime.event_sink.clone();
    let mut stale_progress = None;
    context
        .emit_causally(
            OperationStage::DiagnosticRunning,
            0.25,
            "operations.selfTest.running",
            &mut |progress| {
                stale_progress = Some(progress.clone());
                sink.publish_progress(progress)
            },
        )
        .unwrap();
    let mut output = Vec::new();
    drain_backend_signals(&mut runtime, &receiver, &crashes, &mut output).unwrap();
    runtime.backend.cancellation = Some((context.cancellation_handle(), context.owner().clone()));
    runtime
        .handle_message(json!({
            "type":"request",
            "protocolVersion":1,
            "requestId":"request:1",
            "method":"operation-cancel",
            "payload":{"operationId":"op:fairness"}
        }))
        .unwrap();

    sink.publish_progress(&stale_progress.unwrap()).unwrap();
    assert_eq!(
        drain_backend_signals(&mut runtime, &receiver, &crashes, &mut output),
        Err(ServiceProtocolError::BackendContract)
    );
    assert!(runtime.active.is_some());
}

/// Proves a refill loop cannot prevent shutdown rejection followed by EOF exit.
#[test]
fn continuously_refilled_events_cannot_starve_shutdown_or_eof() {
    let RuntimeFixture {
        mut runtime,
        sender,
        receiver,
        crashes,
        shutdown_count,
        ..
    } = runtime();
    for _ in 0..MAX_PENDING_SERVICE_EVENTS {
        sender.try_send(signal()).unwrap();
    }
    let stop = Arc::new(AtomicBool::new(false));
    let producer_stop = Arc::clone(&stop);
    let producer = thread::spawn(move || {
        while !producer_stop.load(Ordering::Acquire) {
            let _ = sender.try_send(signal());
            thread::yield_now();
        }
    });
    let (input_sender, input_receiver) = mpsc::sync_channel(2);
    input_sender
        .send(InputSignal::Message(json!({
            "type":"request",
            "protocolVersion":1,
            "requestId":"request:1",
            "method":"service-shutdown",
            "payload":{}
        })))
        .unwrap();
    input_sender.send(InputSignal::End).unwrap();
    let mut output = Vec::new();

    let result = service_loop(
        &mut runtime,
        &input_receiver,
        &receiver,
        &crashes,
        &mut output,
        &super::session_admission::SessionAdmission::default(),
    );
    stop.store(true, Ordering::Release);
    producer.join().unwrap();

    assert_eq!(result, Ok(ServiceExit::EndOfInput));
    assert_eq!(shutdown_count.load(Ordering::SeqCst), 0);
    assert!(frame_count(&output) <= MAX_BACKEND_EVENT_BATCH * 3 + 1);
    assert!(decode_frames(&output).iter().any(|message| {
        message["requestId"] == "request:1"
            && message["result"] == json!({"ok":false,"reason":"operation-in-progress"})
    }));
}
