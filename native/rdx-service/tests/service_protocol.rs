// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

use std::collections::BTreeMap;
use std::io::{self, Cursor, Write};
use std::process::{Command, Stdio};
#[cfg(feature = "fixtures")]
use std::sync::atomic::AtomicBool;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, mpsc};
use std::time::Duration;

#[cfg(feature = "fixtures")]
use rdx_service::firmware::{FirmwareRevision, ProductFamily};
#[cfg(feature = "fixtures")]
use rdx_service::host::{
    DeviceInterface, DeviceSession, FixtureDevice, SessionDevice, SessionGeneration,
};
#[cfg(feature = "fixtures")]
use rdx_service::model::DeviceIdentity;
use rdx_service::model::{
    Capability, CapabilityState, DeviceId, DeviceSnapshot, DiscoveryRevision, DisplayText,
    MediaState, OperationId, OperationKind, OperationRequest,
};
#[cfg(feature = "fixtures")]
use rdx_service::operations::{CancellationRequestResult, OperationContext, run_self_test};
#[cfg(feature = "fixtures")]
use rdx_service::protocol::SenseData;
#[cfg(feature = "fixtures")]
use rdx_service::service::{MAX_PENDING_SERVICE_EVENTS, ServiceEventError};
use rdx_service::service::{
    NoDeviceBackend, ServiceBackend, ServiceDescriptor, ServiceEventSink, ServiceExecutionContext,
    ServiceExit, ServicePlatform, ServiceRejection, run_framed_service,
};

/// Service execution authority is explicit and cannot be inferred from an
/// environment variable or ordinary development stdio invocation.
#[test]
fn execution_context_distinguishes_development_from_authenticated_endpoint() {
    let development = ServiceExecutionContext::development_stdio();
    let endpoint = ServiceExecutionContext::authenticated_platform_endpoint(true);

    assert!(!development.endpoint_authenticated());
    assert!(!development.process_authorized());
    assert!(endpoint.endpoint_authenticated());
    assert!(endpoint.process_authorized());
}
#[cfg(feature = "fixtures")]
use rdx_service::transport::{CommandDispatch, TransportError};

/// Encodes one hand-checked JSON value with the shared four-byte big-endian prefix.
fn frame(value: serde_json::Value) -> Vec<u8> {
    let payload = serde_json::to_vec(&value).unwrap();
    let mut framed = Vec::with_capacity(payload.len() + 4);
    framed.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    framed.extend_from_slice(&payload);
    framed
}

/// Concatenates controlled request frames into one deterministic stdin stream.
fn input(values: impl IntoIterator<Item = serde_json::Value>) -> Cursor<Vec<u8>> {
    Cursor::new(values.into_iter().flat_map(frame).collect())
}

/// Decodes every complete service frame from a controlled stdout byte vector.
fn decode_frames(bytes: &[u8]) -> Vec<serde_json::Value> {
    let mut cursor = 0;
    let mut values = Vec::new();
    while cursor < bytes.len() {
        let header: [u8; 4] = bytes[cursor..cursor + 4].try_into().unwrap();
        let length = u32::from_be_bytes(header) as usize;
        cursor += 4;
        values.push(serde_json::from_slice(&bytes[cursor..cursor + length]).unwrap());
        cursor += length;
    }
    values
}

/// Returns one strict protocol-version handshake request.
fn handshake() -> serde_json::Value {
    serde_json::json!({"type": "handshake-request", "protocolVersion": 1})
}

/// Returns one strict correlated service request.
fn request(id: u64, method: &str, payload: serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "type": "request",
        "protocolVersion": 1,
        "requestId": format!("request:{id}"),
        "method": method,
        "payload": payload
    })
}

/// Extracts a successful outer response's strict public result by request ID.
fn result<'a>(messages: &'a [serde_json::Value], request_id: &str) -> &'a serde_json::Value {
    &messages
        .iter()
        .find(|message| message["requestId"] == request_id)
        .unwrap()["result"]
}

/// Shared writer that proves every emitted response or event is flushed immediately.
#[derive(Clone, Default)]
struct FlushCountingWriter {
    bytes: Arc<Mutex<Vec<u8>>>,
    flushes: Arc<AtomicUsize>,
}

impl Write for FlushCountingWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.bytes.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.flushes.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

/// Proves the native no-device mode exactly matches the existing JavaScript wire contract.
#[test]
fn no_device_service_handshakes_lists_scans_and_shuts_down_with_exact_frames() {
    let writer = FlushCountingWriter::default();
    let observed = writer.clone();
    let exit = run_framed_service(
        NoDeviceBackend::new(ServicePlatform::Darwin),
        input([
            handshake(),
            request(1, "devices-list", serde_json::json!({})),
            request(2, "devices-scan", serde_json::json!({"kind": "scan"})),
            request(
                3,
                "operation-start",
                serde_json::json!({
                    "operationId": "op:no-device",
                    "request": {"kind": "self-test", "deviceId": "rdx:absent", "deviceRevision": 1}
                }),
            ),
            request(
                4,
                "operation-cancel",
                serde_json::json!({"operationId": "op:no-device"}),
            ),
            request(
                5,
                "operation-confirmation-issue",
                serde_json::json!({
                    "kind": "format",
                    "deviceId": "rdx:absent",
                    "deviceRevision": 1,
                    "filesystem": "exfat"
                }),
            ),
            request(6, "service-shutdown", serde_json::json!({})),
        ]),
        writer,
    )
    .unwrap();
    let bytes = observed.bytes.lock().unwrap().clone();
    let messages = decode_frames(&bytes);

    assert_eq!(exit, ServiceExit::ShutdownRequested);
    assert_eq!(
        messages[0],
        serde_json::json!({
            "type": "handshake",
            "protocolVersion": 1,
            "serviceVersion": env!("CARGO_PKG_VERSION"),
            "platform": "darwin",
            "mode": "no-device",
            "privileged": false,
            "hardwareVerified": false,
            "platformCapability": {
                "state": "transport-unavailable",
                "reason": "platform-adapter-not-implemented"
            }
        })
    );
    assert_eq!(
        result(&messages, "request:1"),
        &serde_json::json!({"ok": true, "listRevision": 0, "devices": []})
    );
    assert_eq!(
        messages[2],
        serde_json::json!({
            "type": "event",
            "channel": "device",
            "event": {"type": "list", "listRevision": 1, "devices": []}
        })
    );
    assert_eq!(
        result(&messages, "request:2"),
        &serde_json::json!({"ok": true})
    );
    assert_eq!(
        result(&messages, "request:3"),
        &serde_json::json!({"ok": false, "reason": "transport-unavailable"})
    );
    assert_eq!(
        result(&messages, "request:4"),
        &serde_json::json!({"ok": false, "reason": "transport-unavailable"})
    );
    assert_eq!(
        result(&messages, "request:5"),
        &serde_json::json!({"ok": false, "reason": "confirmation-unavailable"})
    );
    assert_eq!(
        result(&messages, "request:6"),
        &serde_json::json!({"ok": true})
    );
    assert_eq!(observed.flushes.load(Ordering::SeqCst), messages.len());
    assert!(
        messages
            .iter()
            .all(|message| message.get("epoch").is_none())
    );
    assert_eq!(
        messages[0].get("hardwareVerified"),
        Some(&serde_json::json!(false))
    );
}

/// Proves an orderly stdin close needs no shutdown request and emits no diagnostic frame.
#[test]
fn clean_eof_after_handshake_exits_without_inventing_an_error_response() {
    let mut output = Vec::new();

    let exit = run_framed_service(
        NoDeviceBackend::new(ServicePlatform::Linux),
        input([handshake()]),
        &mut output,
    )
    .unwrap();

    assert_eq!(exit, ServiceExit::EndOfInput);
    assert_eq!(decode_frames(&output).len(), 1);
}

/// Reader that deliberately keeps stdin open after delivering complete frames.
struct OpenAfterFramesReader {
    bytes: Cursor<Vec<u8>>,
    release: Arc<(Mutex<bool>, Condvar)>,
}

impl io::Read for OpenAfterFramesReader {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        let read = self.bytes.read(output)?;
        if read != 0 {
            return Ok(read);
        }
        let (released, wake) = &*self.release;
        let mut released = released.lock().unwrap();
        while !*released {
            released = wake.wait(released).unwrap();
        }
        Ok(0)
    }
}

/// Proves an acknowledged shutdown does not depend on a later stdin EOF.
#[test]
fn explicit_shutdown_returns_while_the_input_stream_remains_open() {
    let release = Arc::new((Mutex::new(false), Condvar::new()));
    let reader = OpenAfterFramesReader {
        bytes: input([
            handshake(),
            request(1, "service-shutdown", serde_json::json!({})),
        ]),
        release: Arc::clone(&release),
    };
    let (completion, finished) = mpsc::channel();
    let worker = std::thread::spawn(move || {
        let mut output = Vec::new();
        completion
            .send(run_framed_service(
                NoDeviceBackend::new(ServicePlatform::Darwin),
                reader,
                &mut output,
            ))
            .unwrap();
    });

    let observed = finished.recv_timeout(Duration::from_secs(2));
    let (released, wake) = &*release;
    *released.lock().unwrap() = true;
    wake.notify_all();
    worker.join().unwrap();

    assert_eq!(observed.unwrap().unwrap(), ServiceExit::ShutdownRequested);
}

/// Proves an oversized length prefix is rejected before its declared payload is read.
#[test]
fn oversized_frames_are_rejected_before_payload_allocation() {
    let mut oversized = Vec::new();
    oversized.extend_from_slice(&65_537_u32.to_be_bytes());
    let mut output = Vec::new();

    assert!(
        run_framed_service(
            NoDeviceBackend::new(ServicePlatform::Darwin),
            Cursor::new(oversized),
            &mut output
        )
        .is_err()
    );
    assert!(output.is_empty());
}

/// Proves version, unknown-field, prototype-key, and request-ID violations are fatal.
#[test]
fn strict_envelopes_reject_wrong_versions_unknown_fields_prototype_keys_and_stale_ids() {
    let cases = [
        vec![serde_json::json!({"type": "handshake-request", "protocolVersion": 2})],
        vec![serde_json::json!({"type": "handshake-request", "protocolVersion": 1, "extra": true})],
        vec![
            serde_json::json!({"type": "handshake-request", "protocolVersion": 1, "constructor": {}}),
        ],
        vec![
            handshake(),
            request(
                1,
                "devices-scan",
                serde_json::json!({"kind": "scan", "__proto__": {"polluted": true}}),
            ),
        ],
        vec![
            handshake(),
            request(
                1,
                "operation-start",
                serde_json::json!({
                    "operationId": "op:invalid-scan",
                    "request": {"kind": "scan"}
                }),
            ),
        ],
        vec![
            handshake(),
            request(2, "devices-list", serde_json::json!({})),
            request(1, "devices-list", serde_json::json!({})),
        ],
    ];

    for values in cases {
        let mut output = Vec::new();
        assert!(
            run_framed_service(
                NoDeviceBackend::new(ServicePlatform::Darwin),
                input(values),
                &mut output
            )
            .is_err()
        );
    }
}

/// Builds a strict native-mode fixture device for ownership checks.
fn fixture_device() -> DeviceSnapshot {
    let mut capabilities = BTreeMap::new();
    capabilities.insert(
        OperationKind::SelfTest,
        Capability {
            state: CapabilityState::Available,
            reason: None,
        },
    );
    capabilities.insert(
        OperationKind::FirmwareUpdate,
        Capability {
            state: CapabilityState::Available,
            reason: None,
        },
    );
    let vendor = DisplayText::new("TANDBERG").unwrap();
    let product = DisplayText::new("RDX").unwrap();
    let serial = DisplayText::new("FIXTURE1").unwrap();
    DeviceSnapshot {
        id: DeviceId::new("rdx:fixture").unwrap(),
        revision: DiscoveryRevision::new(7).unwrap(),
        drive: rdx_service::model::DriveStatus::from_identity(&vendor, &product, &serial),
        vendor,
        product,
        serial,
        media: None,
        media_state: MediaState::NoMedia,
        capabilities,
    }
}

/// Creates exact native fixture ownership matching the protocol inventory.
#[cfg(feature = "fixtures")]
fn fixture_context(
    operation_id: OperationId,
    kind: OperationKind,
) -> (FixtureDevice, DeviceSession, OperationContext) {
    let fixture = FixtureDevice::new(SessionDevice::fixture(
        DeviceIdentity {
            id: DeviceId::new("rdx:fixture").unwrap(),
            revision: DiscoveryRevision::new(7).unwrap(),
        },
        ProductFamily::Usb3Sata3,
        FirmwareRevision::new(283).unwrap(),
        DeviceInterface::Usb3,
        false,
        SessionGeneration::new(41).unwrap(),
    ));
    let session = fixture.open();
    let context = OperationContext::for_session(operation_id, kind, &session).unwrap();
    (fixture, session, context)
}

/// Deliberately violates no-device inventory truth for containment testing.
struct ContradictoryNoDeviceBackend;

impl ServiceBackend for ContradictoryNoDeviceBackend {
    fn descriptor(&self) -> ServiceDescriptor {
        ServiceDescriptor::no_device(ServicePlatform::Darwin)
    }

    fn list_devices(&mut self) -> Result<Vec<DeviceSnapshot>, ServiceRejection> {
        Ok(vec![fixture_device()])
    }

    fn scan_devices(&mut self) -> Result<Vec<DeviceSnapshot>, ServiceRejection> {
        Ok(vec![fixture_device()])
    }

    fn start_operation(
        &mut self,
        _operation_id: OperationId,
        _request: OperationRequest,
        _events: ServiceEventSink,
    ) -> Result<(), ServiceRejection> {
        unreachable!("a contradictory no-device backend must fault before operation dispatch")
    }

    fn cancel_operation(&mut self, _operation_id: &OperationId) -> Result<(), ServiceRejection> {
        unreachable!("a contradictory no-device backend must fault before cancellation")
    }

    fn shutdown(&mut self) -> Result<(), ServiceRejection> {
        Ok(())
    }
}

/// Proves backend cross-field contradictions fault the generation without leaking data.
#[test]
fn contradictory_no_device_inventory_is_a_fatal_backend_contract_violation() {
    let mut output = Vec::new();
    let failure = run_framed_service(
        ContradictoryNoDeviceBackend,
        input([
            handshake(),
            request(1, "devices-list", serde_json::json!({})),
        ]),
        &mut output,
    );
    let messages = decode_frames(&output);

    assert!(failure.is_err());
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0]["type"], "handshake");
    assert!(
        !output
            .windows(b"rdx:fixture".len())
            .any(|bytes| bytes == b"rdx:fixture")
    );
}

/// Backend that leaves a self-test active until an exact cancellation arrives.
#[cfg(feature = "fixtures")]
struct HoldingBackend {
    active: Option<(
        OperationId,
        DeviceSession,
        OperationContext,
        ServiceEventSink,
    )>,
    devices: Vec<DeviceSnapshot>,
}

#[cfg(feature = "fixtures")]
impl HoldingBackend {
    /// Creates one native-capable backend with a single revisioned device.
    fn new() -> Self {
        Self {
            active: None,
            devices: vec![fixture_device()],
        }
    }
}

#[cfg(feature = "fixtures")]
impl ServiceBackend for HoldingBackend {
    fn descriptor(&self) -> ServiceDescriptor {
        ServiceDescriptor::native_available(ServicePlatform::Darwin, "0.1.0-test").unwrap()
    }

    fn list_devices(&mut self) -> Result<Vec<DeviceSnapshot>, ServiceRejection> {
        Ok(self.devices.clone())
    }

    fn scan_devices(&mut self) -> Result<Vec<DeviceSnapshot>, ServiceRejection> {
        Ok(self.devices.clone())
    }

    fn start_operation(
        &mut self,
        operation_id: OperationId,
        request: OperationRequest,
        events: ServiceEventSink,
    ) -> Result<(), ServiceRejection> {
        if !matches!(request, OperationRequest::SelfTest { .. }) {
            return Err(ServiceRejection::new("unsupported-operation").unwrap());
        }
        let (_fixture, session, context) =
            fixture_context(operation_id.clone(), OperationKind::SelfTest);
        events.publish_started(context.owner()).unwrap();
        self.active = Some((operation_id, session, context, events));
        Ok(())
    }

    fn cancel_operation(&mut self, operation_id: &OperationId) -> Result<(), ServiceRejection> {
        let Some((active_id, mut session, context, events)) = self.active.take() else {
            return Err(ServiceRejection::new("operation-not-found").unwrap());
        };
        if &active_id != operation_id {
            self.active = Some((active_id, session, context, events));
            return Err(ServiceRejection::new("operation-not-found").unwrap());
        }
        let owner = context.owner().clone();
        assert_eq!(
            context.cancellation_handle().request(&owner),
            CancellationRequestResult::Accepted
        );
        let report = run_self_test(&mut session, context).unwrap();
        events
            .publish_progress(report.events().last().unwrap())
            .unwrap();
        events.publish_report(report).unwrap();
        Ok(())
    }

    fn shutdown(&mut self) -> Result<(), ServiceRejection> {
        Ok(())
    }
}

/// Proves native ownership rejects stale revisions, concurrency, mismatched cancel IDs, and reuse.
#[cfg(feature = "fixtures")]
#[test]
fn operation_reservation_is_revisioned_single_owner_and_cancellation_exact() {
    let mut output = Vec::new();
    let exit = run_framed_service(
        HoldingBackend::new(),
        input([
            handshake(),
            request(1, "devices-list", serde_json::json!({})),
            request(
                2,
                "operation-start",
                serde_json::json!({
                    "operationId": "op:stale",
                    "request": {"kind": "self-test", "deviceId": "rdx:fixture", "deviceRevision": 6}
                }),
            ),
            request(
                3,
                "operation-start",
                serde_json::json!({
                    "operationId": "op:first",
                    "request": {"kind": "self-test", "deviceId": "rdx:fixture", "deviceRevision": 7}
                }),
            ),
            request(
                4,
                "operation-start",
                serde_json::json!({
                    "operationId": "op:second",
                    "request": {"kind": "self-test", "deviceId": "rdx:fixture", "deviceRevision": 7}
                }),
            ),
            request(
                5,
                "operation-cancel",
                serde_json::json!({"operationId": "op:other"}),
            ),
            request(6, "service-shutdown", serde_json::json!({})),
            request(
                7,
                "operation-cancel",
                serde_json::json!({"operationId": "op:first"}),
            ),
            request(
                8,
                "operation-start",
                serde_json::json!({
                    "operationId": "op:first",
                    "request": {"kind": "self-test", "deviceId": "rdx:fixture", "deviceRevision": 7}
                }),
            ),
            request(9, "service-shutdown", serde_json::json!({})),
        ]),
        &mut output,
    )
    .unwrap();
    let messages = decode_frames(&output);

    assert_eq!(exit, ServiceExit::ShutdownRequested);
    assert_eq!(
        result(&messages, "request:2"),
        &serde_json::json!({"ok": false, "reason": "stale-device-revision"})
    );
    assert_eq!(
        result(&messages, "request:3"),
        &serde_json::json!({"ok": true})
    );
    assert_eq!(
        result(&messages, "request:4"),
        &serde_json::json!({"ok": false, "reason": "operation-in-progress"})
    );
    assert_eq!(
        result(&messages, "request:5"),
        &serde_json::json!({"ok": false, "reason": "operation-not-found"})
    );
    assert_eq!(
        result(&messages, "request:6"),
        &serde_json::json!({"ok": false, "reason": "operation-in-progress"})
    );
    assert_eq!(
        result(&messages, "request:7"),
        &serde_json::json!({"ok": true, "cancellationCutover": 3})
    );
    assert_eq!(
        result(&messages, "request:8"),
        &serde_json::json!({"ok": false, "reason": "stale-operation-id"})
    );
    assert_eq!(
        result(&messages, "request:9"),
        &serde_json::json!({"ok": true})
    );

    let operation_events = messages
        .iter()
        .filter(|message| message["channel"] == "operation")
        .map(|message| message["event"]["state"].as_str().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(operation_events, ["started", "progress", "cancelled"]);
    assert_eq!(
        messages
            .iter()
            .filter(|message| message["channel"] == "operation")
            .map(|message| message["publicationSequence"].as_u64())
            .collect::<Vec<_>>(),
        [Some(1), Some(2), Some(3)]
    );
}

/// Backend that reports an unreconciled crash after publishing nonterminal evidence.
#[cfg(feature = "fixtures")]
struct CrashingBackend {
    devices: Vec<DeviceSnapshot>,
}

#[cfg(feature = "fixtures")]
impl ServiceBackend for CrashingBackend {
    fn descriptor(&self) -> ServiceDescriptor {
        ServiceDescriptor::native_available(ServicePlatform::Darwin, "0.1.0-test").unwrap()
    }

    fn list_devices(&mut self) -> Result<Vec<DeviceSnapshot>, ServiceRejection> {
        Ok(self.devices.clone())
    }

    fn scan_devices(&mut self) -> Result<Vec<DeviceSnapshot>, ServiceRejection> {
        Ok(self.devices.clone())
    }

    fn start_operation(
        &mut self,
        operation_id: OperationId,
        request: OperationRequest,
        events: ServiceEventSink,
    ) -> Result<(), ServiceRejection> {
        if !matches!(request, OperationRequest::SelfTest { .. }) {
            unreachable!("the crash fixture accepts only self-test")
        }
        let (_fixture, _session, context) = fixture_context(operation_id, OperationKind::SelfTest);
        events.publish_started(context.owner()).unwrap();
        events.report_crash().unwrap();
        Ok(())
    }

    fn cancel_operation(&mut self, _operation_id: &OperationId) -> Result<(), ServiceRejection> {
        Err(ServiceRejection::new("operation-not-cancellable").unwrap())
    }

    fn shutdown(&mut self) -> Result<(), ServiceRejection> {
        Ok(())
    }
}

/// Proves a backend crash emits no invented terminal that could release ownership.
#[cfg(feature = "fixtures")]
#[test]
fn active_backend_crash_ends_the_generation_without_an_operation_terminal() {
    let mut output = Vec::new();
    let failure = run_framed_service(
        CrashingBackend {
            devices: vec![fixture_device()],
        },
        input([
            handshake(),
            request(1, "devices-list", serde_json::json!({})),
            request(
                2,
                "operation-start",
                serde_json::json!({
                    "operationId": "op:crash",
                    "request": {"kind": "self-test", "deviceId": "rdx:fixture", "deviceRevision": 7}
                }),
            ),
        ]),
        &mut output,
    );
    let messages = decode_frames(&output);
    let operation_states = messages
        .iter()
        .filter_map(|message| message.get("event")?.get("state")?.as_str())
        .collect::<Vec<_>>();

    assert!(failure.is_err());
    assert_eq!(
        result(&messages, "request:2"),
        &serde_json::json!({"ok": true})
    );
    assert_eq!(operation_states, ["started"]);
}

/// Backend that emits a complete two-attempt firmware failure transcript.
#[cfg(feature = "fixtures")]
struct FailureBackend {
    devices: Vec<DeviceSnapshot>,
}

#[cfg(feature = "fixtures")]
impl FailureBackend {
    /// Creates the single-device failure fixture.
    fn new() -> Self {
        Self {
            devices: vec![fixture_device()],
        }
    }
}

#[cfg(feature = "fixtures")]
impl ServiceBackend for FailureBackend {
    fn descriptor(&self) -> ServiceDescriptor {
        ServiceDescriptor::native_available(ServicePlatform::Darwin, "0.1.0-test").unwrap()
    }

    fn list_devices(&mut self) -> Result<Vec<DeviceSnapshot>, ServiceRejection> {
        Ok(self.devices.clone())
    }

    fn scan_devices(&mut self) -> Result<Vec<DeviceSnapshot>, ServiceRejection> {
        Ok(self.devices.clone())
    }

    fn start_operation(
        &mut self,
        operation_id: OperationId,
        request: OperationRequest,
        events: ServiceEventSink,
    ) -> Result<(), ServiceRejection> {
        if !matches!(request, OperationRequest::SelfTest { .. }) {
            return Err(ServiceRejection::new("unsupported-operation").unwrap());
        }
        let (fixture, mut session, context) =
            fixture_context(operation_id, OperationKind::SelfTest);
        fixture.queue_dispatch(CommandDispatch::DefinitelyRejected(
            TransportError::CheckCondition(
                SenseData::parse(&[0x70, 0, 0x05, 0, 0, 0, 0, 6, 0, 0, 0, 0, 0x24, 0]).unwrap(),
            ),
        ));
        events.publish_started(context.owner()).unwrap();
        let failure = run_self_test(&mut session, context).unwrap_err();
        for progress in failure.events() {
            events.publish_progress(progress).unwrap();
        }
        events.publish_failure(failure).unwrap();
        Ok(())
    }

    fn cancel_operation(&mut self, _operation_id: &OperationId) -> Result<(), ServiceRejection> {
        Err(ServiceRejection::new("operation-not-cancellable").unwrap())
    }

    fn shutdown(&mut self) -> Result<(), ServiceRejection> {
        Ok(())
    }
}

/// Proves the service envelope preserves terminal, primary, cleanup, retry, and cancellation fields.
#[cfg(feature = "fixtures")]
#[test]
fn operation_events_preserve_the_lossless_cross_language_contract() {
    let mut output = Vec::new();
    let exit = run_framed_service(
        FailureBackend::new(),
        input([
            handshake(),
            request(1, "devices-list", serde_json::json!({})),
            request(
                2,
                "operation-start",
                serde_json::json!({
                    "operationId": "op:firmware",
                    "request": {
                    "kind": "self-test",
                    "deviceId": "rdx:fixture",
                    "deviceRevision": 7
                    }
                }),
            ),
            request(3, "service-shutdown", serde_json::json!({})),
        ]),
        &mut output,
    )
    .unwrap();
    let messages = decode_frames(&output);
    let failed = messages
        .iter()
        .find(|message| message["event"]["state"] == "failed")
        .unwrap();

    assert_eq!(exit, ServiceExit::ShutdownRequested);
    assert_eq!(failed["event"]["stage"], "diagnostic-cleanup");
    assert_eq!(failed["event"]["error"]["stage"], "diagnostic-running");
    assert_eq!(failed["event"]["error"]["code"], "scsi-check-condition");
    assert_eq!(
        failed["event"]["error"]["dispatchCertainty"],
        "definitely-rejected"
    );
    assert_eq!(failed["event"]["error"]["senseSummary"]["asc"], 36);
}

/// Backend that fills the bounded pending-event channel without blocking stdout.
#[cfg(feature = "fixtures")]
struct BurstBackend {
    devices: Vec<DeviceSnapshot>,
    saturated: Arc<AtomicBool>,
}

#[cfg(feature = "fixtures")]
impl ServiceBackend for BurstBackend {
    fn descriptor(&self) -> ServiceDescriptor {
        ServiceDescriptor::native_available(ServicePlatform::Darwin, "0.1.0-test").unwrap()
    }

    fn list_devices(&mut self) -> Result<Vec<DeviceSnapshot>, ServiceRejection> {
        Ok(self.devices.clone())
    }

    fn scan_devices(&mut self) -> Result<Vec<DeviceSnapshot>, ServiceRejection> {
        Ok(self.devices.clone())
    }

    fn start_operation(
        &mut self,
        operation_id: OperationId,
        request: OperationRequest,
        events: ServiceEventSink,
    ) -> Result<(), ServiceRejection> {
        if !matches!(request, OperationRequest::SelfTest { .. }) {
            return Err(ServiceRejection::new("unsupported-operation").unwrap());
        }
        let (_fixture, mut session, context) =
            fixture_context(operation_id, OperationKind::SelfTest);
        events.publish_started(context.owner()).unwrap();
        let report = run_self_test(&mut session, context).unwrap();
        let progress = report.events().first().unwrap();
        for _ in 1..MAX_PENDING_SERVICE_EVENTS {
            events.publish_progress(progress).unwrap();
        }
        let overflow = events.publish_progress(progress);
        self.saturated.store(
            overflow == Err(ServiceEventError::Saturated),
            Ordering::SeqCst,
        );
        Ok(())
    }

    fn cancel_operation(&mut self, _operation_id: &OperationId) -> Result<(), ServiceRejection> {
        Err(ServiceRejection::new("operation-not-cancellable").unwrap())
    }

    fn shutdown(&mut self) -> Result<(), ServiceRejection> {
        Ok(())
    }
}

/// Proves operation workers cannot create an unbounded pending-output queue.
#[cfg(feature = "fixtures")]
#[test]
fn operation_event_channel_has_a_stable_nonblocking_bound() {
    let saturated = Arc::new(AtomicBool::new(false));
    let backend = BurstBackend {
        devices: vec![fixture_device()],
        saturated: Arc::clone(&saturated),
    };
    let mut output = Vec::new();

    let exit = run_framed_service(
        backend,
        input([
            handshake(),
            request(1, "devices-list", serde_json::json!({})),
            request(
                2,
                "operation-start",
                serde_json::json!({
                    "operationId":"op:burst",
                    "request":{"kind":"self-test","deviceId":"rdx:fixture","deviceRevision":7}
                }),
            ),
        ]),
        &mut output,
    )
    .unwrap();

    assert_eq!(exit, ServiceExit::EndOfInput);
    assert!(saturated.load(Ordering::SeqCst));
    assert_eq!(
        decode_frames(&output)
            .iter()
            .filter(|message| message["channel"] == "operation")
            .count(),
        rdx_service::service::MAX_BACKEND_EVENT_BATCH * 2
    );
}

/// Proves process diagnostics stay off stdout and never echo hostile inputs.
#[test]
fn binary_diagnostics_are_static_bounded_and_protocol_stdout_stays_clean() {
    let binary = env!("CARGO_BIN_EXE_openrdx-hardware");
    let invalid = Command::new(binary)
        .args([
            "--service-mode",
            "stdio",
            "--protocol-version",
            "/dev/sg4-secret-token",
        ])
        .output()
        .unwrap();

    assert_eq!(invalid.status.code(), Some(2));
    assert!(invalid.stdout.is_empty());
    assert_eq!(
        String::from_utf8(invalid.stderr).unwrap(),
        "openrdx-hardware: invalid service arguments\n"
    );

    let mut child = Command::new(binary)
        .args(["--service-mode", "stdio", "--protocol-version", "1"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(&0_u32.to_be_bytes())
        .unwrap();
    let malformed = child.wait_with_output().unwrap();
    let diagnostic = String::from_utf8(malformed.stderr).unwrap();

    assert_eq!(malformed.status.code(), Some(3));
    assert!(malformed.stdout.is_empty());
    assert_eq!(diagnostic, "openrdx-hardware: service protocol failure\n");
    assert!(diagnostic.len() < 128);
    assert!(!diagnostic.contains("/dev/"));
    assert!(!diagnostic.contains("secret"));
}
