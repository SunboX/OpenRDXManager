// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

#[cfg(feature = "fixtures")]
use std::collections::BTreeMap;
use std::io::Cursor;
#[cfg(feature = "fixtures")]
use std::sync::{Arc, Mutex};

#[cfg(feature = "fixtures")]
use rdx_service::firmware::{FirmwareRevision, ProductFamily};
#[cfg(feature = "fixtures")]
use rdx_service::host::{
    DeviceInterface, DeviceSession, FixtureDevice, SessionDevice, SessionGeneration,
};
#[cfg(feature = "fixtures")]
use rdx_service::model::{
    Capability, CapabilityState, DeviceId, DeviceIdentity, DeviceSnapshot, DiscoveryRevision,
    DisplayText, MediaState, OperationId, OperationKind, OperationRequest,
};
#[cfg(feature = "fixtures")]
use rdx_service::operations::{OperationContext, run_self_test};
#[cfg(feature = "fixtures")]
use rdx_service::service::{
    MAX_BACKEND_EVENT_BATCH, MAX_PENDING_SERVICE_EVENTS, NoDeviceBackend, ServiceBackend,
    ServiceDescriptor, ServiceEventError, ServiceEventSink, ServiceExit, ServicePlatform,
    ServiceRejection, run_framed_service,
};
#[cfg(not(feature = "fixtures"))]
use rdx_service::service::{NoDeviceBackend, ServiceExit, ServicePlatform, run_framed_service};

/// Encodes one strict JSON object with the shared big-endian length prefix.
fn frame(value: serde_json::Value) -> Vec<u8> {
    let payload = serde_json::to_vec(&value).unwrap();
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
        let length = u32::from_be_bytes(bytes[cursor..cursor + 4].try_into().unwrap()) as usize;
        cursor += 4;
        messages.push(serde_json::from_slice(&bytes[cursor..cursor + length]).unwrap());
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

/// Returns one native fixture with the two capabilities exercised below.
#[cfg(feature = "fixtures")]
fn fixture_device() -> DeviceSnapshot {
    let capabilities = BTreeMap::from([
        (
            OperationKind::SelfTest,
            Capability {
                state: CapabilityState::Available,
                reason: None,
            },
        ),
        (
            OperationKind::FirmwareUpdate,
            Capability {
                state: CapabilityState::Available,
                reason: None,
            },
        ),
    ]);
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

/// Proves a new native generation accepts persistent client IDs and local gaps.
#[test]
fn request_ids_are_strictly_increasing_without_requiring_contiguity() {
    let mut output = Vec::new();
    let exit = run_framed_service(
        NoDeviceBackend::new(ServicePlatform::Darwin),
        input([
            handshake(),
            request(7, "devices-list", serde_json::json!({})),
            request(9, "devices-scan", serde_json::json!({"kind": "scan"})),
            request(12, "service-shutdown", serde_json::json!({})),
        ]),
        &mut output,
    )
    .unwrap();
    let messages = decode_frames(&output);

    assert_eq!(exit, ServiceExit::ShutdownRequested);
    assert!(
        messages
            .iter()
            .any(|message| message["requestId"] == "request:7")
    );
    assert!(
        messages
            .iter()
            .any(|message| message["requestId"] == "request:9")
    );
    assert!(
        messages
            .iter()
            .any(|message| message["requestId"] == "request:12")
    );
}

/// Proves native operation IDs mirror the JavaScript case and suffix bounds.
#[test]
fn operation_id_validator_matches_javascript_case_and_suffix_bounds() {
    for operation_id in [
        "op:a".to_owned(),
        "OP:A-:9".to_owned(),
        format!("op:{}", "a".repeat(60)),
    ] {
        let mut output = Vec::new();
        let exit = run_framed_service(
            NoDeviceBackend::new(ServicePlatform::Darwin),
            input([
                handshake(),
                request(
                    1,
                    "operation-start",
                    serde_json::json!({
                        "operationId": operation_id,
                        "request": {"kind": "self-test", "deviceId": "rdx:absent", "deviceRevision": 1}
                    }),
                ),
            ]),
            &mut output,
        )
        .unwrap();

        assert_eq!(exit, ServiceExit::EndOfInput);
        assert_eq!(
            decode_frames(&output).last().unwrap()["result"],
            serde_json::json!({"ok": false, "reason": "transport-unavailable"})
        );
    }

    for operation_id in ["op:".to_owned(), format!("op:{}", "a".repeat(61))] {
        let mut output = Vec::new();
        assert!(
            run_framed_service(
                NoDeviceBackend::new(ServicePlatform::Darwin),
                input([
                    handshake(),
                    request(
                        1,
                        "operation-start",
                        serde_json::json!({
                            "operationId": operation_id,
                            "request": {"kind": "self-test", "deviceId": "rdx:absent", "deviceRevision": 1}
                        }),
                    ),
                ]),
                &mut output,
            )
            .is_err()
        );
    }
}

/// Backend that fills the event queue before reporting an unreconciled crash.
#[cfg(feature = "fixtures")]
struct SaturatedCrashBackend {
    crash_reported: Arc<Mutex<Option<Result<(), ServiceEventError>>>>,
}

#[cfg(feature = "fixtures")]
impl ServiceBackend for SaturatedCrashBackend {
    fn descriptor(&self) -> ServiceDescriptor {
        ServiceDescriptor::native_available(ServicePlatform::Darwin, "review-test").unwrap()
    }

    fn list_devices(&mut self) -> Result<Vec<DeviceSnapshot>, ServiceRejection> {
        Ok(vec![fixture_device()])
    }

    fn scan_devices(&mut self) -> Result<Vec<DeviceSnapshot>, ServiceRejection> {
        Ok(vec![fixture_device()])
    }

    fn start_operation(
        &mut self,
        operation_id: OperationId,
        request: OperationRequest,
        events: ServiceEventSink,
    ) -> Result<(), ServiceRejection> {
        if !matches!(request, OperationRequest::SelfTest { .. }) {
            unreachable!();
        }
        let (_fixture, mut session, context) =
            fixture_context(operation_id, OperationKind::SelfTest);
        events.publish_started(context.owner()).unwrap();
        let report = run_self_test(&mut session, context).unwrap();
        let progress = report.events().first().unwrap();
        for _ in 1..MAX_PENDING_SERVICE_EVENTS {
            events.publish_progress(progress).unwrap();
        }
        *self.crash_reported.lock().unwrap() = Some(events.report_crash());
        Ok(())
    }

    fn cancel_operation(&mut self, _operation_id: &OperationId) -> Result<(), ServiceRejection> {
        Err(ServiceRejection::new("operation-not-cancellable").unwrap())
    }

    fn shutdown(&mut self) -> Result<(), ServiceRejection> {
        Ok(())
    }
}

/// Proves a full event queue cannot suppress an unreconciled backend crash.
#[cfg(feature = "fixtures")]
#[test]
fn backend_crash_has_a_reserved_non_droppable_control_path() {
    let crash_reported = Arc::new(Mutex::new(None));
    let mut output = Vec::new();
    let result = run_framed_service(
        SaturatedCrashBackend {
            crash_reported: Arc::clone(&crash_reported),
        },
        input([
            handshake(),
            request(1, "devices-list", serde_json::json!({})),
            request(
                2,
                "operation-start",
                serde_json::json!({
                    "operationId":"op:saturated-crash",
                    "request":{"kind":"self-test","deviceId":"rdx:fixture","deviceRevision":7}
                }),
            ),
        ]),
        &mut output,
    );

    assert_eq!(*crash_reported.lock().unwrap(), Some(Ok(())));
    assert!(result.is_err());
    assert_eq!(
        decode_frames(&output)
            .iter()
            .filter(|message| message["channel"] == "operation")
            .count(),
        MAX_BACKEND_EVENT_BATCH
    );
    assert!(decode_frames(&output).iter().all(|message| !matches!(
        message["event"]["state"].as_str(),
        Some("failed" | "cancelled" | "succeeded")
    )));
}

/// Backend that retains the crash capability beyond a clean generation boundary.
#[cfg(feature = "fixtures")]
struct RetainedSinkBackend {
    complete_operation: bool,
    retained: Arc<Mutex<Option<ServiceEventSink>>>,
}

#[cfg(feature = "fixtures")]
impl ServiceBackend for RetainedSinkBackend {
    fn descriptor(&self) -> ServiceDescriptor {
        ServiceDescriptor::native_available(ServicePlatform::Darwin, "review-test").unwrap()
    }

    fn list_devices(&mut self) -> Result<Vec<DeviceSnapshot>, ServiceRejection> {
        Ok(vec![fixture_device()])
    }

    fn scan_devices(&mut self) -> Result<Vec<DeviceSnapshot>, ServiceRejection> {
        Ok(vec![fixture_device()])
    }

    fn start_operation(
        &mut self,
        operation_id: OperationId,
        request: OperationRequest,
        events: ServiceEventSink,
    ) -> Result<(), ServiceRejection> {
        *self.retained.lock().unwrap() = Some(events.clone());
        if self.complete_operation {
            if !matches!(request, OperationRequest::SelfTest { .. }) {
                unreachable!();
            }
            let (_fixture, mut session, context) =
                fixture_context(operation_id, OperationKind::SelfTest);
            events.publish_started(context.owner()).unwrap();
            let report = run_self_test(&mut session, context).unwrap();
            for progress in report.events() {
                events.publish_progress(progress).unwrap();
            }
            events.publish_report(report).unwrap();
        }
        Ok(())
    }

    fn cancel_operation(&mut self, _operation_id: &OperationId) -> Result<(), ServiceRejection> {
        Err(ServiceRejection::new("operation-not-cancellable").unwrap())
    }

    fn shutdown(&mut self) -> Result<(), ServiceRejection> {
        Ok(())
    }
}

/// Proves EOF closes crash admission even while a backend retains its sink.
#[cfg(feature = "fixtures")]
#[test]
fn eof_disconnects_retained_crash_reporters() {
    let retained = Arc::new(Mutex::new(None));
    let mut output = Vec::new();
    let exit = run_framed_service(
        RetainedSinkBackend {
            complete_operation: false,
            retained: Arc::clone(&retained),
        },
        input([
            handshake(),
            request(1, "devices-list", serde_json::json!({})),
            request(
                2,
                "operation-start",
                serde_json::json!({
                    "operationId":"op:eof-close",
                    "request":{"kind":"self-test","deviceId":"rdx:fixture","deviceRevision":7}
                }),
            ),
        ]),
        &mut output,
    )
    .unwrap();

    assert_eq!(exit, ServiceExit::EndOfInput);
    assert_eq!(
        retained.lock().unwrap().as_ref().unwrap().report_crash(),
        Err(ServiceEventError::Disconnected)
    );
}

/// Proves acknowledged shutdown also closes crash admission before returning.
#[cfg(feature = "fixtures")]
#[test]
fn shutdown_disconnects_retained_crash_reporters() {
    let retained = Arc::new(Mutex::new(None));
    let mut output = Vec::new();
    let exit = run_framed_service(
        RetainedSinkBackend {
            complete_operation: true,
            retained: Arc::clone(&retained),
        },
        input([
            handshake(),
            request(1, "devices-list", serde_json::json!({})),
            request(
                2,
                "operation-start",
                serde_json::json!({
                    "operationId":"op:shutdown-close",
                    "request":{"kind":"self-test","deviceId":"rdx:fixture","deviceRevision":7}
                }),
            ),
            request(3, "service-shutdown", serde_json::json!({})),
        ]),
        &mut output,
    )
    .unwrap();

    assert_eq!(exit, ServiceExit::ShutdownRequested);
    assert_eq!(
        retained.lock().unwrap().as_ref().unwrap().report_crash(),
        Err(ServiceEventError::Disconnected)
    );
}
