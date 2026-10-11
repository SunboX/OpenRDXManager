// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

use std::collections::BTreeMap;
use std::io::{self, Cursor, Write};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use rdx_service::model::{
    Capability, CapabilityState, DeviceId, DeviceSnapshot, DiscoveryRevision, DisplayText,
    MediaState, OperationId, OperationKind, OperationRequest,
};
use rdx_service::service::{
    ServiceBackend, ServiceDescriptor, ServiceEventSink, ServiceExit, ServicePlatform,
    ServiceRejection, run_framed_service,
};

/// Encodes one strict service frame.
fn frame(value: serde_json::Value) -> Vec<u8> {
    let payload = serde_json::to_vec(&value).unwrap();
    let mut framed = Vec::with_capacity(payload.len() + 4);
    framed.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    framed.extend_from_slice(&payload);
    framed
}

/// Returns one native-capable revisioned fixture device.
fn fixture_device() -> DeviceSnapshot {
    let vendor = DisplayText::new("TANDBERG").unwrap();
    let product = DisplayText::new("RDX").unwrap();
    let serial = DisplayText::new("ASYNC001").unwrap();
    DeviceSnapshot {
        id: DeviceId::new("rdx:async-fixture").unwrap(),
        revision: DiscoveryRevision::new(3).unwrap(),
        drive: rdx_service::model::DriveStatus::from_identity(&vendor, &product, &serial),
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

/// Writer exposing only its count of completed flush boundaries.
struct FlushWitness {
    bytes: Vec<u8>,
    flushes: Arc<AtomicUsize>,
}

impl Write for FlushWitness {
    /// Retains framed output bytes without interpreting them.
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    /// Records each completed framed flush.
    fn flush(&mut self) -> io::Result<()> {
        self.flushes.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

/// Backend retaining preparation until the runtime invokes the release hook.
struct DeferredBackend {
    pending: Option<OperationId>,
    flushes: Arc<AtomicUsize>,
    flushes_at_release: Arc<AtomicUsize>,
    released: Arc<AtomicBool>,
}

impl ServiceBackend for DeferredBackend {
    /// Advertises one test-only native service descriptor.
    fn descriptor(&self) -> ServiceDescriptor {
        ServiceDescriptor::native_available(ServicePlatform::Darwin, "0.1.0-test").unwrap()
    }

    /// Returns the stable fixture inventory.
    fn list_devices(&mut self) -> Result<Vec<DeviceSnapshot>, ServiceRejection> {
        Ok(vec![fixture_device()])
    }

    /// Returns the same stable fixture inventory.
    fn scan_devices(&mut self) -> Result<Vec<DeviceSnapshot>, ServiceRejection> {
        Ok(vec![fixture_device()])
    }

    /// Prepares but deliberately does not publish or dispatch.
    fn start_operation(
        &mut self,
        operation_id: OperationId,
        request: OperationRequest,
        _events: ServiceEventSink,
    ) -> Result<(), ServiceRejection> {
        assert!(matches!(request, OperationRequest::SelfTest { .. }));
        self.pending = Some(operation_id);
        Ok(())
    }

    /// Records the writer flush count at the causal release boundary.
    fn release_operation(&mut self, operation_id: &OperationId) -> Result<(), ServiceRejection> {
        assert_eq!(self.pending.take().as_ref(), Some(operation_id));
        self.flushes_at_release
            .store(self.flushes.load(Ordering::SeqCst), Ordering::SeqCst);
        self.released.store(true, Ordering::SeqCst);
        Ok(())
    }

    /// This non-running fixture has no cancellation implementation.
    fn cancel_operation(&mut self, _operation_id: &OperationId) -> Result<(), ServiceRejection> {
        Err(ServiceRejection::new("operation-not-cancellable").unwrap())
    }

    /// Performs no cleanup.
    fn shutdown(&mut self) -> Result<(), ServiceRejection> {
        Ok(())
    }
}

/// Acceptance is flushed before prepared work can be causally released.
#[test]
fn accepted_response_is_flushed_before_deferred_operation_release() {
    let flushes = Arc::new(AtomicUsize::new(0));
    let flushes_at_release = Arc::new(AtomicUsize::new(0));
    let released = Arc::new(AtomicBool::new(false));
    let backend = DeferredBackend {
        pending: None,
        flushes: Arc::clone(&flushes),
        flushes_at_release: Arc::clone(&flushes_at_release),
        released: Arc::clone(&released),
    };
    let writer = FlushWitness {
        bytes: Vec::new(),
        flushes,
    };
    let input = Cursor::new(
        [
            serde_json::json!({"type": "handshake-request", "protocolVersion": 1}),
            serde_json::json!({
                "type": "request", "protocolVersion": 1, "requestId": "request:1",
                "method": "devices-list", "payload": {}
            }),
            serde_json::json!({
                "type": "request", "protocolVersion": 1, "requestId": "request:2",
                "method": "operation-start", "payload": {
                    "operationId": "op:deferred",
                    "request": {"kind": "self-test", "deviceId": "rdx:async-fixture", "deviceRevision": 3}
                }
            }),
        ]
        .into_iter()
        .flat_map(frame)
        .collect::<Vec<_>>(),
    );

    let exit = run_framed_service(backend, input, writer).unwrap();

    assert_eq!(exit, ServiceExit::EndOfInput);
    assert!(released.load(Ordering::SeqCst));
    assert_eq!(flushes_at_release.load(Ordering::SeqCst), 3);
}
