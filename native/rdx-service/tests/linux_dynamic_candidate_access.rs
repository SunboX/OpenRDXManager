// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

use std::sync::{Arc, Mutex};

use rdx_service::platform::linux::{
    DeviceAccessEvidence, LinuxReadinessFacts, evaluate_linux_readiness,
};
use rdx_service::platform::{
    CandidateDevice, CandidateLease, CandidateMetadata, DeviceRegistry, PlatformBackend,
    PlatformCapabilities, PlatformDeviceHandle, PlatformError, discover_validated_devices,
};
use rdx_service::protocol::Command;
use rdx_service::service::{HardwareServiceBackend, ServiceBackend, ServicePlatform};
use rdx_service::transport::{CommandDispatch, TransportError, TransportResponse};

/// Candidate-local access state changed by the fixture between two service scans.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CandidateAccess {
    Denied,
    Accessible,
}

/// Shared dynamic access state and proof counters retained across scans.
struct DynamicState {
    access: CandidateAccess,
    open_attempts: usize,
    identity_dispatches: usize,
}

/// Long-lived Linux-like backend whose cached readiness starts with a denied candidate.
struct DynamicLinuxBackend {
    capabilities: PlatformCapabilities,
    state: Arc<Mutex<DynamicState>>,
}

impl DynamicLinuxBackend {
    /// Caches only the readiness result produced at service startup.
    fn denied_at_startup() -> Self {
        let readiness = evaluate_linux_readiness(LinuxReadinessFacts::new(
            true,
            true,
            true,
            true,
            DeviceAccessEvidence::Denied,
            true,
            true,
            true,
            true,
        ));
        let reported = readiness.capabilities();
        let capabilities = PlatformCapabilities::try_new(
            reported.discovery_available(),
            reported.transport_available(),
            reported.privileged(),
            false,
            false,
            false,
            false,
            reported.hardware_verified(),
        )
        .expect("fixture projection remains cross-field consistent");
        Self {
            capabilities,
            state: Arc::new(Mutex::new(DynamicState {
                access: CandidateAccess::Denied,
                open_attempts: 0,
                identity_dispatches: 0,
            })),
        }
    }

    /// Makes the same enumerated candidate accessible without restarting the backend.
    fn make_accessible(&self) {
        self.state
            .lock()
            .expect("dynamic state remains available")
            .access = CandidateAccess::Accessible;
    }

    /// Returns the current native-open and identity-command counters.
    fn counters(&self) -> (usize, usize) {
        let state = self.state.lock().expect("dynamic state remains available");
        (state.open_attempts, state.identity_dispatches)
    }
}

impl PlatformBackend for DynamicLinuxBackend {
    /// Returns the single readiness snapshot cached at backend construction.
    fn capabilities(&self) -> PlatformCapabilities {
        self.capabilities
    }

    /// Enumerates the current candidate afresh on every scan.
    fn enumerate_candidates(&mut self) -> Result<Vec<CandidateDevice>, PlatformError> {
        Ok(vec![
            CandidateDevice::new(
                "linux-dynamic-candidate",
                "/private/linux-dynamic-candidate",
                CandidateMetadata::new(None, None, None, None),
            )
            .expect("bounded fixture candidate"),
        ])
    }

    /// Performs a fresh candidate-local access attempt before returning a live lease.
    fn open_candidate(
        &mut self,
        candidate: &CandidateDevice,
    ) -> Result<CandidateLease, PlatformError> {
        if !self.capabilities.transport_available() {
            return Err(PlatformError::TransportUnavailable);
        }
        if candidate.token() != "linux-dynamic-candidate" {
            return Err(PlatformError::DeviceUnavailable);
        }
        let mut state = self.state.lock().expect("dynamic state remains available");
        state.open_attempts += 1;
        if state.access == CandidateAccess::Denied {
            return Err(PlatformError::AccessDenied);
        }
        drop(state);
        Ok(CandidateLease::new(DynamicLinuxHandle {
            state: Arc::clone(&self.state),
        }))
    }
}

/// Exact live handle which records only commands dispatched after access succeeds.
struct DynamicLinuxHandle {
    state: Arc<Mutex<DynamicState>>,
}

impl PlatformDeviceHandle for DynamicLinuxHandle {
    /// Answers only the three immutable service-owned identity probes.
    fn execute(&mut self, command: &Command) -> CommandDispatch {
        let bytes = match command.cdb() {
            [0x12, 0, 0, 0, 0xFE, 0] => standard_inquiry(),
            [0x12, 1, 0x83, 0, 0xFE, 0] => device_identification(),
            [0x5A, 0, 0x31, 0, 0, 0, 0, 0, 0xFE, 0] => capability_page(),
            _ => return CommandDispatch::NotSent(TransportError::Unavailable),
        };
        self.state
            .lock()
            .expect("dynamic state remains available")
            .identity_dispatches += 1;
        CommandDispatch::Succeeded(
            TransportResponse::new(bytes).expect("fixture response remains bounded"),
        )
    }
}

/// Builds one complete standard inquiry response for a supported USB 3 dock.
fn standard_inquiry() -> Vec<u8> {
    let mut bytes = vec![b' '; 43];
    bytes[0] = 0;
    bytes[4] = 38;
    bytes[8..16].copy_from_slice(b"TANDBERG");
    bytes[16..32].copy_from_slice(b"RDX             ");
    bytes[32..36].copy_from_slice(b"0283");
    bytes[36] = 0x35;
    bytes[37..40].copy_from_slice(b"RDX");
    bytes[40] = 2;
    bytes[41] = 0x08;
    bytes[42] = 0x10;
    bytes
}

/// Builds one fixed-layout VPD device-identification response.
fn device_identification() -> Vec<u8> {
    let mut bytes = vec![b' '; 42];
    bytes[0] = 0;
    bytes[1] = 0x83;
    bytes[2..4].copy_from_slice(&38_u16.to_be_bytes());
    bytes[8..16].copy_from_slice(b"TANDBERG");
    bytes[16..32].copy_from_slice(b"RDX             ");
    bytes[32..42].copy_from_slice(b"7820999743");
    bytes
}

/// Builds the smallest structurally complete RDX capability page.
fn capability_page() -> Vec<u8> {
    vec![0x00, 0x0B, 0, 0, 0, 0, 0, 0, 0x31, 0x03, 0, 0, 0x18]
}

/// A denied startup candidate cannot poison later scans in the same backend.
#[test]
fn denied_candidate_is_dropped_then_same_backend_validates_and_resolves() {
    let mut backend = DynamicLinuxBackend::denied_at_startup();
    let mut registry = DeviceRegistry::new();

    let first = discover_validated_devices(&mut backend, &mut registry)
        .expect("a candidate-local access denial leaves an authoritative empty scan");
    assert!(first.is_empty());
    assert!(registry.snapshots().is_empty());
    assert_eq!(backend.counters(), (1, 0));
    assert!(!backend.capabilities().hardware_verified());

    backend.make_accessible();
    let second = discover_validated_devices(&mut backend, &mut registry)
        .expect("the same backend retries and validates a newly accessible candidate");
    assert_eq!(second.len(), 1);
    assert_eq!(backend.counters(), (2, 3));

    let snapshot = second[0].clone();
    let resolved = registry
        .resolve(&mut backend, &snapshot.id, snapshot.revision)
        .expect("the newly published exact revision resolves through a fresh open");
    assert_eq!(resolved.id(), &snapshot.id);
    assert_eq!(resolved.revision(), snapshot.revision);
    drop(resolved);
    assert_eq!(backend.counters(), (3, 6));
}

/// The registry-owning service retries dynamic candidate access without restart.
#[test]
fn denied_candidate_then_accessible_candidate_publishes_in_same_service() {
    let backend = DynamicLinuxBackend::denied_at_startup();
    let state = Arc::clone(&backend.state);
    let mut service = HardwareServiceBackend::new(ServicePlatform::Linux, backend);
    let descriptor = service.descriptor();
    assert_eq!(descriptor.platform_capability_state(), "available");
    assert!(descriptor.privileged());
    assert!(!descriptor.hardware_verified());

    let first = service
        .scan_devices()
        .expect("candidate-local denial leaves the service scan authoritative and empty");
    assert!(first.is_empty());
    {
        let mut state = state.lock().expect("dynamic state remains available");
        assert_eq!((state.open_attempts, state.identity_dispatches), (1, 0));
        state.access = CandidateAccess::Accessible;
    }

    let second = service
        .scan_devices()
        .expect("the same service retries a newly accessible current candidate");
    assert_eq!(second.len(), 1);
    assert_eq!(
        service.list_devices().expect("published list is readable"),
        second
    );
    let state = state.lock().expect("dynamic state remains available");
    assert_eq!((state.open_attempts, state.identity_dispatches), (2, 3));
    drop(state);
    service
        .shutdown()
        .expect("fixture worker shuts down cleanly");
}
