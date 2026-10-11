// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

use std::collections::BTreeMap;
use std::io::Cursor;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use rdx_service::model::{
    Capability, CapabilityState, DeviceId, DeviceSnapshot, DiscoveryRevision, DisplayText,
    MediaState, OperationId, OperationKind, OperationRequest,
};
use rdx_service::platform::PlatformCapabilities;
use rdx_service::service::{
    ServiceBackend, ServiceDescriptor, ServiceEventSink, ServiceExit, ServicePlatform,
    ServiceRejection, run_framed_service,
};

/// Encodes one strict JSON value with the service's big-endian length prefix.
fn frame(value: serde_json::Value) -> Vec<u8> {
    let payload = serde_json::to_vec(&value).unwrap();
    let mut framed = Vec::with_capacity(payload.len() + 4);
    framed.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    framed.extend_from_slice(&payload);
    framed
}

/// Concatenates controlled request frames into one deterministic service input.
fn input(values: impl IntoIterator<Item = serde_json::Value>) -> Cursor<Vec<u8>> {
    Cursor::new(values.into_iter().flat_map(frame).collect())
}

/// Decodes every complete framed service message.
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

/// Returns one strict protocol handshake request.
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

/// Finds one public response result by request ID.
fn result<'a>(messages: &'a [serde_json::Value], request_id: &str) -> &'a serde_json::Value {
    &messages
        .iter()
        .find(|message| message["requestId"] == request_id)
        .unwrap()["result"]
}

/// Builds a discovered device whose self-test is otherwise available.
fn fixture_device() -> DeviceSnapshot {
    let mut capabilities = BTreeMap::new();
    capabilities.insert(
        OperationKind::SelfTest,
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

/// Discovery-capable development backend which must never receive a mutation.
struct UnprivilegedDiscoveredBackend {
    dispatches: Arc<AtomicUsize>,
}

impl ServiceBackend for UnprivilegedDiscoveredBackend {
    /// Reports native discovery/transport without privileged endpoint authority.
    fn descriptor(&self) -> ServiceDescriptor {
        ServiceDescriptor::from_platform_capabilities(
            ServicePlatform::Darwin,
            PlatformCapabilities::try_new(true, true, false, false, false, false, false, false)
                .unwrap(),
        )
    }

    /// Exposes a validated device whose advertised capability cannot grant authority.
    fn list_devices(&mut self) -> Result<Vec<DeviceSnapshot>, ServiceRejection> {
        Ok(vec![fixture_device()])
    }

    /// Returns the same bounded discovered device for a read-only refresh.
    fn scan_devices(&mut self) -> Result<Vec<DeviceSnapshot>, ServiceRejection> {
        Ok(vec![fixture_device()])
    }

    /// Records any forbidden service-side dispatch attempt.
    fn start_operation(
        &mut self,
        _operation_id: OperationId,
        _request: OperationRequest,
        _events: ServiceEventSink,
    ) -> Result<(), ServiceRejection> {
        self.dispatches.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    /// No operation can become active through the unprivileged boundary.
    fn cancel_operation(&mut self, _operation_id: &OperationId) -> Result<(), ServiceRejection> {
        Err(ServiceRejection::new("operation-not-found").unwrap())
    }

    /// Allows the framed fixture to terminate normally.
    fn shutdown(&mut self) -> Result<(), ServiceRejection> {
        Ok(())
    }
}

/// A device capability never substitutes for privileged endpoint authority.
#[test]
fn unprivileged_service_rejects_device_commands_before_backend_dispatch() {
    let dispatches = Arc::new(AtomicUsize::new(0));
    let mut output = Vec::new();
    let exit = run_framed_service(
        UnprivilegedDiscoveredBackend {
            dispatches: Arc::clone(&dispatches),
        },
        input([
            handshake(),
            request(
                1,
                "operation-start",
                serde_json::json!({
                    "operationId": "op:unprivileged-self-test",
                    "request": {
                        "kind": "self-test",
                        "deviceId": "rdx:fixture",
                        "deviceRevision": 7
                    }
                }),
            ),
            request(2, "service-shutdown", serde_json::json!({})),
        ]),
        &mut output,
    )
    .unwrap();
    let messages = decode_frames(&output);

    assert_eq!(exit, ServiceExit::ShutdownRequested);
    assert_eq!(messages[0]["privileged"], false);
    assert_eq!(
        messages[0]["platformCapability"]["state"],
        "insufficient-permission"
    );
    assert_eq!(
        result(&messages, "request:1"),
        &serde_json::json!({
            "ok": false,
            "reason": "privileged-service-unavailable"
        })
    );
    assert_eq!(dispatches.load(Ordering::SeqCst), 0);
}
