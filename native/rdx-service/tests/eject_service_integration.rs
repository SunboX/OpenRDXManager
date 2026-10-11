// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

use std::collections::{BTreeMap, VecDeque};
use std::io::{Cursor, Write};
use std::sync::{Arc, Barrier, Condvar, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use rdx_service::firmware::{FirmwareRevision, ProductFamily};
use rdx_service::host::{
    DeviceInterface, FixtureDevice, HostOperationError, SessionDevice, SessionGeneration,
};
use rdx_service::model::{
    Capability, CapabilityState, DeviceId, DeviceIdentity, DeviceSnapshot, DiscoveryRevision,
    DisplayText, Media, MediaState, MediaStatusDetails, OpaqueId, OperationId, OperationKind,
    OperationRequest, StatusField,
};
use rdx_service::operations::{
    CancellationHandle, CancellationRequestResult, EjectHost, EjectOutcome, EjectReadback,
    HostEjectPolicy, OperationContext, OperationOwner, ProgressPublicationError,
    run_eject_with_progress,
};
use rdx_service::service::{
    ServiceBackend, ServiceDescriptor, ServiceEventError, ServiceEventSink, ServiceExit,
    ServicePlatform, ServiceRejection, run_framed_service,
};
use rdx_service::transport::{CommandDispatch, TransportResponse};

const WAIT_LIMIT: Duration = Duration::from_secs(5);

/// Encodes one strict JSON object with the shared big-endian length prefix.
fn frame(value: serde_json::Value) -> Vec<u8> {
    let payload = serde_json::to_vec(&value).expect("test frame serializes");
    let mut bytes = Vec::with_capacity(payload.len() + 4);
    bytes.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    bytes.extend_from_slice(&payload);
    bytes
}

/// Concatenates controlled protocol frames into one deterministic input stream.
fn input(values: impl IntoIterator<Item = serde_json::Value>) -> Cursor<Vec<u8>> {
    Cursor::new(values.into_iter().flat_map(frame).collect())
}

/// Decodes all complete protocol frames from a controlled output buffer.
fn decode_frames(bytes: &[u8]) -> Vec<serde_json::Value> {
    let mut cursor = 0;
    let mut messages = Vec::new();
    while cursor < bytes.len() {
        let length = u32::from_be_bytes(
            bytes[cursor..cursor + 4]
                .try_into()
                .expect("complete frame header"),
        ) as usize;
        cursor += 4;
        messages.push(
            serde_json::from_slice(&bytes[cursor..cursor + length]).expect("complete JSON frame"),
        );
        cursor += length;
    }
    messages
}

/// Creates the exact protocol-version handshake request.
fn handshake() -> serde_json::Value {
    serde_json::json!({"type": "handshake-request", "protocolVersion": 1})
}

/// Creates one strict correlated service request.
fn request(id: u64, method: &str, payload: serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "type": "request",
        "protocolVersion": 1,
        "requestId": format!("request:{id}"),
        "method": method,
        "payload": payload
    })
}

/// Returns one operation-start request for the shared eject fixture.
fn eject_start(id: u64, operation_id: &str) -> serde_json::Value {
    request(
        id,
        "operation-start",
        serde_json::json!({
            "operationId": operation_id,
            "request": {
                "kind": "eject-safe",
                "deviceId": "rdx:eject-integration",
                "deviceRevision": 17
            }
        }),
    )
}

/// Returns one exact operation-cancellation request.
fn eject_cancel(id: u64, operation_id: &str) -> serde_json::Value {
    request(
        id,
        "operation-cancel",
        serde_json::json!({"operationId": operation_id}),
    )
}

/// Returns one successful or rejected response payload by exact request ID.
fn response_result<'a>(
    messages: &'a [serde_json::Value],
    request_id: &str,
) -> &'a serde_json::Value {
    &messages
        .iter()
        .find(|message| message["requestId"] == request_id)
        .expect("response exists")["result"]
}

/// Returns operation events in their exact framed publication order.
fn operation_events(messages: &[serde_json::Value]) -> Vec<&serde_json::Value> {
    messages
        .iter()
        .filter(|message| message["channel"] == "operation")
        .map(|message| &message["event"])
        .collect()
}

/// Finds the output position of one exact request response.
fn response_position(messages: &[serde_json::Value], request_id: &str) -> usize {
    messages
        .iter()
        .position(|message| message["requestId"] == request_id)
        .expect("response position exists")
}

/// Finds the output position of one exact operation event state and stage.
fn event_position(
    messages: &[serde_json::Value],
    operation_id: &str,
    state: &str,
    stage: &str,
) -> usize {
    messages
        .iter()
        .position(|message| {
            message["event"]["operationId"] == operation_id
                && message["event"]["state"] == state
                && message["event"]["stage"] == stage
        })
        .expect("event position exists")
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CancelBoundary {
    AfterFirstProgress,
    DuringPreflight,
    DuringUnmount,
    None,
    AfterDispatch,
}

#[derive(Debug, Default)]
struct GateState {
    entered: bool,
    released: bool,
    completed: bool,
    request_result: Option<CancellationRequestResult>,
}

/// Deterministic host-stage gate without arbitrary test sleeps.
#[derive(Debug, Default)]
struct HostGate {
    state: Mutex<GateState>,
    changed: Condvar,
}

impl HostGate {
    /// Marks the controlled host call entered and waits for explicit release.
    fn enter_and_wait(&self) {
        let mut state = self.state.lock().expect("host gate remains available");
        state.entered = true;
        self.changed.notify_all();
        let (state, timeout) = self
            .changed
            .wait_timeout_while(state, WAIT_LIMIT, |state| !state.released)
            .expect("host gate remains available");
        assert!(state.released, "host gate release timed out: {timeout:?}");
    }

    /// Waits until the worker is inside the controlled host call.
    fn wait_until_entered(&self) {
        let state = self.state.lock().expect("host gate remains available");
        let (state, timeout) = self
            .changed
            .wait_timeout_while(state, WAIT_LIMIT, |state| !state.entered)
            .expect("host gate remains available");
        assert!(state.entered, "host gate entry timed out: {timeout:?}");
    }

    /// Releases the controlled host call.
    fn release(&self) {
        let mut state = self.state.lock().expect("host gate remains available");
        state.released = true;
        self.changed.notify_all();
    }

    /// Records the result of an exact request made reentrantly by the publisher.
    fn record_request_result(&self, result: CancellationRequestResult) {
        let mut state = self.state.lock().expect("host gate remains available");
        state.request_result = Some(result);
        self.changed.notify_all();
    }

    /// Releases a publisher and awaits its bounded reentrant request result.
    fn release_and_wait_for_request(&self) -> CancellationRequestResult {
        let mut state = self.state.lock().expect("host gate remains available");
        state.released = true;
        self.changed.notify_all();
        let (state, timeout) = self
            .changed
            .wait_timeout_while(state, WAIT_LIMIT, |state| state.request_result.is_none())
            .expect("host gate remains available");
        state
            .request_result
            .unwrap_or_else(|| panic!("reentrant request timed out: {timeout:?}"))
    }

    /// Records that the worker published its terminal or crash signal.
    fn complete(&self) {
        let mut state = self.state.lock().expect("host gate remains available");
        state.completed = true;
        self.changed.notify_all();
    }

    /// Releases the controlled call and waits until terminal publication completes.
    fn release_and_wait_until_complete(&self) {
        let mut state = self.state.lock().expect("host gate remains available");
        state.released = true;
        self.changed.notify_all();
        let (state, timeout) = self
            .changed
            .wait_timeout_while(state, WAIT_LIMIT, |state| !state.completed)
            .expect("host gate remains available");
        assert!(
            state.completed,
            "host worker completion timed out: {timeout:?}"
        );
    }
}

#[derive(Debug, Default)]
struct HostAudit {
    unmounts: usize,
    ejects: usize,
    readbacks: usize,
    accepted_cancellations: usize,
}

/// Exact-target host fixture that blocks only at the selected lifecycle boundary.
struct ControlledEjectHost {
    boundary: CancelBoundary,
    gate: Option<Arc<HostGate>>,
    audit: Arc<Mutex<HostAudit>>,
}

impl EjectHost for ControlledEjectHost {
    /// Records safe unmount and exposes the early-cancellation race boundary.
    fn unmount(&mut self, _target: &DeviceIdentity) -> Result<(), HostOperationError> {
        self.audit
            .lock()
            .expect("host audit remains available")
            .unmounts += 1;
        if self.boundary == CancelBoundary::DuringUnmount {
            self.gate
                .as_ref()
                .expect("early-cancel gate exists")
                .enter_and_wait();
        }
        Ok(())
    }

    /// Records dispatch and exposes the post-mutation late-cancellation boundary.
    fn eject(&mut self, _target: &DeviceIdentity, _policy: HostEjectPolicy) -> CommandDispatch {
        self.audit
            .lock()
            .expect("host audit remains available")
            .ejects += 1;
        if self.boundary == CancelBoundary::AfterDispatch {
            self.gate
                .as_ref()
                .expect("late-cancel gate exists")
                .enter_and_wait();
        }
        CommandDispatch::Succeeded(TransportResponse::empty())
    }

    /// Records mandatory exact-target departure readback.
    fn readback(&mut self, target: &DeviceIdentity) -> Result<EjectReadback, HostOperationError> {
        self.audit
            .lock()
            .expect("host audit remains available")
            .readbacks += 1;
        Ok(EjectReadback::Departed(target.clone()))
    }
}

struct Scenario {
    boundary: CancelBoundary,
    gate: Option<Arc<HostGate>>,
    preflight_gate: Option<(Arc<Barrier>, Arc<Barrier>)>,
}

impl Scenario {
    /// Creates one run with exactly the requested deterministic boundary.
    fn at(boundary: CancelBoundary) -> Self {
        let gate = matches!(
            boundary,
            CancelBoundary::AfterFirstProgress
                | CancelBoundary::DuringUnmount
                | CancelBoundary::AfterDispatch
        )
        .then(|| Arc::new(HostGate::default()));
        let preflight_gate = (boundary == CancelBoundary::DuringPreflight)
            .then(|| (Arc::new(Barrier::new(2)), Arc::new(Barrier::new(2))));
        Self {
            boundary,
            gate,
            preflight_gate,
        }
    }
}

struct ActiveWorker {
    operation_id: OperationId,
    owner: OperationOwner,
    cancellation: CancellationHandle,
    boundary: CancelBoundary,
    gate: Option<Arc<HostGate>>,
    preflight_release: Option<Arc<Barrier>>,
    worker: JoinHandle<Result<(), ServiceRejection>>,
}

/// Asynchronous service adapter that delegates all eject semantics to
/// `run_eject_with_progress`.
struct AsyncEjectBackend {
    snapshot: DeviceSnapshot,
    device: FixtureDevice,
    scenarios: VecDeque<Scenario>,
    active: Option<ActiveWorker>,
    audit: Arc<Mutex<HostAudit>>,
}

impl AsyncEjectBackend {
    /// Creates a media-present exact-session backend with ordered run scenarios.
    fn new(
        scenarios: impl IntoIterator<Item = Scenario>,
    ) -> (Self, Arc<Mutex<HostAudit>>, FixtureDevice) {
        let identity = DeviceIdentity {
            id: DeviceId::new("rdx:eject-integration").expect("fixture device ID"),
            revision: DiscoveryRevision::new(17).expect("fixture revision"),
        };
        let vendor = DisplayText::new("TANDBERG").expect("fixture vendor");
        let product = DisplayText::new("RDX").expect("fixture product");
        let serial = DisplayText::new("SERVICEFIXTURE").expect("fixture serial");
        let snapshot = DeviceSnapshot {
            id: identity.id.clone(),
            revision: identity.revision,
            drive: rdx_service::model::DriveStatus::from_identity(&vendor, &product, &serial),
            vendor,
            product,
            serial,
            media: Some(Media {
                id: OpaqueId::new("media:eject-integration").expect("fixture media ID"),
                serial: None,
                label: None,
                capacity_bytes: None,
                used_bytes: None,
                writable: Some(true),
                encrypted: Some(false),
                filesystem: None,
                status: None,
                details: MediaStatusDetails {
                    write_protected: StatusField::reported(false),
                    encrypted: StatusField::reported(false),
                    ..MediaStatusDetails::default()
                },
            }),
            media_state: MediaState::Present,
            capabilities: BTreeMap::from([(
                OperationKind::EjectSafe,
                Capability {
                    state: CapabilityState::Available,
                    reason: None,
                },
            )]),
        };
        let device = FixtureDevice::new(SessionDevice::fixture(
            identity,
            ProductFamily::Usb3Sata3,
            FirmwareRevision::new(282).expect("fixture firmware revision"),
            DeviceInterface::Usb3,
            true,
            SessionGeneration::new(1).expect("fixture generation"),
        ));
        let audit = Arc::new(Mutex::new(HostAudit::default()));
        let observed_device = device.clone();
        (
            Self {
                snapshot,
                device,
                scenarios: scenarios.into_iter().collect(),
                active: None,
                audit: Arc::clone(&audit),
            },
            audit,
            observed_device,
        )
    }

    /// Joins one completed worker and preserves any safe backend rejection.
    fn join_worker(worker: ActiveWorker) -> Result<(), ServiceRejection> {
        worker
            .worker
            .join()
            .map_err(|_| rejection("worker-crash"))?
    }
}

impl ServiceBackend for AsyncEjectBackend {
    /// Reports a native-capable fixture generation.
    fn descriptor(&self) -> ServiceDescriptor {
        ServiceDescriptor::native_available(ServicePlatform::Darwin, "integration-test")
            .expect("fixture descriptor")
    }

    /// Returns the current exact fixture inventory.
    fn list_devices(&mut self) -> Result<Vec<DeviceSnapshot>, ServiceRejection> {
        Ok(vec![self.snapshot.clone()])
    }

    /// Returns a fresh exact copy of the fixture inventory.
    fn scan_devices(&mut self) -> Result<Vec<DeviceSnapshot>, ServiceRejection> {
        Ok(vec![self.snapshot.clone()])
    }

    /// Starts real shared eject work and waits only until its configured causal boundary.
    fn start_operation(
        &mut self,
        operation_id: OperationId,
        request: OperationRequest,
        events: ServiceEventSink,
    ) -> Result<(), ServiceRejection> {
        let OperationRequest::EjectSafe { .. } = request else {
            return Err(rejection("unsupported-operation"));
        };
        let scenario = self
            .scenarios
            .pop_front()
            .ok_or_else(|| rejection("missing-scenario"))?;
        if let Some((entered, release)) = &scenario.preflight_gate {
            self.device.block_refresh_call(
                self.device.refresh_count() + 1,
                Arc::clone(entered),
                Arc::clone(release),
            );
        }
        let mut session = self.device.open();
        let context =
            OperationContext::for_session(operation_id.clone(), OperationKind::EjectSafe, &session)
                .map_err(|_| rejection("session-unavailable"))?;
        events
            .publish_started(context.owner())
            .map_err(event_rejection)?;
        let owner = context.owner().clone();
        let cancellation = context.cancellation_handle();
        let callback_owner = owner.clone();
        let callback_cancellation = cancellation.clone();
        let gate = scenario.gate.clone();
        let worker_gate = scenario.gate.clone();
        let preflight_entered = scenario
            .preflight_gate
            .as_ref()
            .map(|(entered, _release)| Arc::clone(entered));
        let preflight_release = scenario
            .preflight_gate
            .as_ref()
            .map(|(_entered, release)| Arc::clone(release));
        let boundary = scenario.boundary;
        let audit = Arc::clone(&self.audit);
        let worker = thread::spawn(move || {
            let mut host = ControlledEjectHost {
                boundary,
                gate: worker_gate.clone(),
                audit,
            };
            let mut progress_failed = false;
            let mut first_progress = true;
            let outcome = run_eject_with_progress(
                &mut session,
                context,
                &mut host,
                HostEjectPolicy::Safe,
                |event| {
                    let published = events.publish_progress(event).map_err(|_| {
                        progress_failed = true;
                        ProgressPublicationError::unavailable()
                    });
                    if published.is_ok()
                        && first_progress
                        && boundary == CancelBoundary::AfterFirstProgress
                    {
                        first_progress = false;
                        let gate = worker_gate.as_ref().expect("first-progress gate exists");
                        gate.enter_and_wait();
                        gate.record_request_result(callback_cancellation.request(&callback_owner));
                    }
                    published
                },
            );
            let result = if progress_failed {
                events.report_crash().map_err(event_rejection)
            } else {
                publish_terminal(&events, outcome)
            };
            if let Some(gate) = worker_gate {
                gate.complete();
            }
            result
        });
        let active = ActiveWorker {
            operation_id,
            owner,
            cancellation,
            boundary,
            gate: gate.clone(),
            preflight_release,
            worker,
        };
        match boundary {
            CancelBoundary::None => Self::join_worker(active),
            CancelBoundary::DuringPreflight => {
                preflight_entered
                    .expect("preflight entry gate exists")
                    .wait();
                self.active = Some(active);
                Ok(())
            }
            CancelBoundary::AfterFirstProgress
            | CancelBoundary::DuringUnmount
            | CancelBoundary::AfterDispatch => {
                gate.expect("blocked host or publisher gate exists")
                    .wait_until_entered();
                self.active = Some(active);
                Ok(())
            }
        }
    }

    /// Requests exact-owner cancellation and releases only an early safe-point gate.
    fn cancel_operation(&mut self, operation_id: &OperationId) -> Result<(), ServiceRejection> {
        let Some(active) = self.active.take() else {
            return Err(rejection("operation-not-found"));
        };
        if &active.operation_id != operation_id {
            self.active = Some(active);
            return Err(rejection("operation-not-found"));
        }
        let request_result = if active.boundary == CancelBoundary::AfterFirstProgress {
            active
                .gate
                .as_ref()
                .expect("first-progress gate exists")
                .release_and_wait_for_request()
        } else {
            active.cancellation.request(&active.owner)
        };
        if request_result != CancellationRequestResult::Accepted {
            self.active = Some(active);
            return Err(rejection("operation-not-cancellable"));
        }
        self.audit
            .lock()
            .expect("host audit remains available")
            .accepted_cancellations += 1;
        match active.boundary {
            CancelBoundary::DuringPreflight => {
                active
                    .preflight_release
                    .as_ref()
                    .expect("preflight release gate exists")
                    .wait();
            }
            CancelBoundary::DuringUnmount => {
                active.gate.as_ref().expect("unmount gate exists").release()
            }
            CancelBoundary::AfterFirstProgress => {}
            CancelBoundary::None | CancelBoundary::AfterDispatch => {
                unreachable!("only cancellable blocked boundaries are joined here")
            }
        };
        Self::join_worker(active)
    }

    /// Joins a completed late-cancel worker before framed shutdown.
    fn shutdown(&mut self) -> Result<(), ServiceRejection> {
        match self.active.take() {
            Some(worker) => Self::join_worker(worker),
            None => Ok(()),
        }
    }
}

/// Publishes one terminal carrying real shared-operation evidence.
fn publish_terminal(
    events: &ServiceEventSink,
    outcome: Result<EjectOutcome, rdx_service::operations::OperationFailure>,
) -> Result<(), ServiceRejection> {
    match outcome {
        Ok(EjectOutcome::Succeeded { report, departure }) => events
            .publish_eject_success(report, departure)
            .map_err(event_rejection),
        Ok(EjectOutcome::Cancelled { report }) => {
            events.publish_report(report).map_err(event_rejection)
        }
        Err(failure) => events.publish_failure(failure).map_err(event_rejection),
    }
}

/// Creates one bounded service rejection for test-only adapter failures.
fn rejection(reason: &'static str) -> ServiceRejection {
    ServiceRejection::new(reason).expect("test rejection reason is valid")
}

/// Converts a bounded event-channel failure into one safe backend rejection.
fn event_rejection(_error: ServiceEventError) -> ServiceRejection {
    rejection("service-event-failure")
}

/// Captures frames and releases a late-cancel host gate after the rejection is written.
struct ReleasingWriter {
    bytes: Vec<u8>,
    decoded: usize,
    cancel_request_id: &'static str,
    gate: Arc<HostGate>,
    released: bool,
}

impl ReleasingWriter {
    /// Creates an empty writer bound to one late-cancellation response.
    fn new(cancel_request_id: &'static str, gate: Arc<HostGate>) -> Self {
        Self {
            bytes: Vec::new(),
            decoded: 0,
            cancel_request_id,
            gate,
            released: false,
        }
    }

    /// Releases the host only after a complete matching cancellation response exists.
    fn inspect_complete_frames(&mut self) {
        while self.decoded + 4 <= self.bytes.len() {
            let length = u32::from_be_bytes(
                self.bytes[self.decoded..self.decoded + 4]
                    .try_into()
                    .expect("complete header"),
            ) as usize;
            if self.decoded + 4 + length > self.bytes.len() {
                return;
            }
            let payload = &self.bytes[self.decoded + 4..self.decoded + 4 + length];
            let message: serde_json::Value =
                serde_json::from_slice(payload).expect("complete service JSON");
            self.decoded += 4 + length;
            if !self.released && message["requestId"] == self.cancel_request_id {
                self.released = true;
                self.gate.release_and_wait_until_complete();
            }
        }
    }
}

impl Write for ReleasingWriter {
    /// Appends service output without partial-write behavior.
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        self.bytes.extend_from_slice(buffer);
        Ok(buffer.len())
    }

    /// Flushes by observing complete frames and coordinating the late host release.
    fn flush(&mut self) -> std::io::Result<()> {
        self.inspect_complete_frames();
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ActionCounts {
    refreshes: usize,
    unmounts: usize,
    ejects: usize,
    readbacks: usize,
}

impl ActionCounts {
    /// Creates one literal action-count expectation.
    const fn new(refreshes: usize, unmounts: usize, ejects: usize, readbacks: usize) -> Self {
        Self {
            refreshes,
            unmounts,
            ejects,
            readbacks,
        }
    }
}

struct MatrixObservation {
    messages: Vec<serde_json::Value>,
    actions: ActionCounts,
    accepted_cancellations: usize,
    reuse_request_id: &'static str,
}

/// Runs one real framed-service boundary plus an uninterrupted ownership-reuse operation.
fn run_matrix(boundary: CancelBoundary) -> MatrixObservation {
    let first = Scenario::at(boundary);
    let late_gate = first.gate.clone();
    let (backend, audit, device) =
        AsyncEjectBackend::new([first, Scenario::at(CancelBoundary::None)]);
    let has_cancel_request = boundary != CancelBoundary::None;
    let reuse_request = if has_cancel_request { 4 } else { 3 };
    let shutdown_request = reuse_request + 1;
    let mut requests = vec![
        handshake(),
        request(1, "devices-list", serde_json::json!({})),
        eject_start(2, "op:matrix-first"),
    ];
    if has_cancel_request {
        requests.push(eject_cancel(3, "op:matrix-first"));
    }
    requests.push(eject_start(reuse_request, "op:matrix-reuse"));
    requests.push(request(
        shutdown_request,
        "service-shutdown",
        serde_json::json!({}),
    ));

    let (exit, messages) = if boundary == CancelBoundary::AfterDispatch {
        let mut output = ReleasingWriter::new(
            "request:3",
            late_gate.expect("post-dispatch writer gate exists"),
        );
        let exit = run_framed_service(backend, input(requests), &mut output)
            .expect("late matrix run preserves mandatory reconciliation");
        (exit, decode_frames(&output.bytes))
    } else {
        let mut output = Vec::new();
        let exit = run_framed_service(backend, input(requests), &mut output)
            .expect("matrix run preserves the service generation");
        (exit, decode_frames(&output))
    };
    assert_eq!(exit, ServiceExit::ShutdownRequested);
    let audit = audit.lock().expect("host audit remains available");
    MatrixObservation {
        messages,
        actions: ActionCounts::new(
            device.refresh_count(),
            audit.unmounts,
            audit.ejects,
            audit.readbacks,
        ),
        accepted_cancellations: audit.accepted_cancellations,
        reuse_request_id: if has_cancel_request {
            "request:4"
        } else {
            "request:3"
        },
    }
}

/// Returns one operation's exact state, stage, and cancellation-state sequence.
fn event_sequence<'a>(
    messages: &'a [serde_json::Value],
    operation_id: &str,
) -> Vec<(&'a str, &'a str, Option<&'a str>)> {
    operation_events(messages)
        .into_iter()
        .filter(|event| event["operationId"] == operation_id)
        .map(|event| {
            (
                event["state"].as_str().expect("event state"),
                event["stage"].as_str().expect("event stage"),
                event["cancellationState"].as_str(),
            )
        })
        .collect()
}

/// Asserts exact cancellation evidence, terminal ordering, action counts, and reuse.
fn assert_cancelled_boundary(boundary: CancelBoundary, expected_actions: ActionCounts) {
    let observation = run_matrix(boundary);
    assert_eq!(observation.actions, expected_actions);
    assert_eq!(observation.accepted_cancellations, 1);
    assert_eq!(
        response_result(&observation.messages, "request:2"),
        &serde_json::json!({"ok": true})
    );
    assert_eq!(
        response_result(&observation.messages, "request:3"),
        &serde_json::json!({"ok": true, "cancellationCutover": 3})
    );
    assert_eq!(
        event_sequence(&observation.messages, "op:matrix-first"),
        [
            ("started", "host-unmounting", None),
            ("progress", "host-unmounting", Some("cancellable")),
            ("cancelled", "host-unmounting", None),
        ]
    );
    assert!(
        event_position(
            &observation.messages,
            "op:matrix-first",
            "progress",
            "host-unmounting"
        ) < response_position(&observation.messages, "request:3")
    );
    assert!(
        response_position(&observation.messages, "request:3")
            < event_position(
                &observation.messages,
                "op:matrix-first",
                "cancelled",
                "host-unmounting"
            )
    );
    assert_reused_success(&observation);
}

/// Asserts exact success evidence, optional late rejection, action counts, and reuse.
fn assert_success_boundary(
    boundary: CancelBoundary,
    expected_actions: ActionCounts,
    rejection: Option<&str>,
) {
    let observation = run_matrix(boundary);
    assert_eq!(observation.actions, expected_actions);
    assert_eq!(observation.accepted_cancellations, 0);
    assert_eq!(
        response_result(&observation.messages, "request:2"),
        &serde_json::json!({"ok": true})
    );
    assert_eq!(
        event_sequence(&observation.messages, "op:matrix-first"),
        [
            ("started", "host-unmounting", None),
            ("progress", "host-unmounting", Some("cancellable")),
            ("progress", "host-ejecting", Some("closed")),
            ("progress", "eject-readback", Some("closed")),
            ("succeeded", "complete", None),
        ]
    );
    if let Some(reason) = rejection {
        assert_eq!(
            response_result(&observation.messages, "request:3"),
            &serde_json::json!({"ok": false, "reason": reason})
        );
        assert!(
            event_position(
                &observation.messages,
                "op:matrix-first",
                "progress",
                "host-ejecting"
            ) < response_position(&observation.messages, "request:3")
        );
        assert!(
            response_position(&observation.messages, "request:3")
                < event_position(
                    &observation.messages,
                    "op:matrix-first",
                    "progress",
                    "eject-readback"
                )
        );
    }
    assert_reused_success(&observation);
}

/// Asserts the next exact owner was admitted and completed its real eject sequence.
fn assert_reused_success(observation: &MatrixObservation) {
    assert_eq!(
        response_result(&observation.messages, observation.reuse_request_id),
        &serde_json::json!({"ok": true})
    );
    assert_eq!(
        event_sequence(&observation.messages, "op:matrix-reuse"),
        [
            ("started", "host-unmounting", None),
            ("progress", "host-unmounting", Some("cancellable")),
            ("progress", "host-ejecting", Some("closed")),
            ("progress", "eject-readback", Some("closed")),
            ("succeeded", "complete", None),
        ]
    );
}

/// Proves cancellation after first progress stops before fresh preflight.
#[test]
fn matrix_cancels_after_first_progress_before_preflight() {
    assert_cancelled_boundary(
        CancelBoundary::AfterFirstProgress,
        ActionCounts::new(1, 1, 1, 1),
    );
}

/// Proves cancellation accepted during blocked preflight stops before unmount.
#[test]
fn matrix_cancels_during_blocked_preflight() {
    assert_cancelled_boundary(
        CancelBoundary::DuringPreflight,
        ActionCounts::new(2, 1, 1, 1),
    );
}

/// Proves cancellation accepted during blocked unmount stops before dispatch.
#[test]
fn matrix_cancels_during_blocked_unmount() {
    assert_cancelled_boundary(CancelBoundary::DuringUnmount, ActionCounts::new(2, 2, 1, 1));
}

/// Proves the uninterrupted path succeeds and releases ownership for reuse.
#[test]
fn matrix_completes_without_cancellation() {
    assert_success_boundary(CancelBoundary::None, ActionCounts::new(2, 2, 2, 2), None);
}

/// Proves a late request is rejected after dispatch and cannot skip readback.
#[test]
fn matrix_rejects_cancellation_after_dispatch() {
    assert_success_boundary(
        CancelBoundary::AfterDispatch,
        ActionCounts::new(2, 2, 2, 2),
        Some("operation-not-cancellable"),
    );
}
