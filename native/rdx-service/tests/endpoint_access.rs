// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

use std::io::{self, Read};
use std::time::{Duration, SystemTime};

use rdx_service::endpoint::{
    EndpointPlatform, HandshakeDeadlineReader, ObservedPeer, PeerPolicy, PeerVerification,
    ServiceEndpoint, macos_manager_designated_requirement_for_team,
};

const ACCEPTED_AT: SystemTime = SystemTime::UNIX_EPOCH;

#[test]
fn macos_manager_requirement_accepts_only_one_exact_signing_team() {
    assert_eq!(
        macos_manager_designated_requirement_for_team(Some("7UXAQ487HP")).unwrap(),
        "identifier \"com.openrdx.manager\" and anchor apple generic and certificate leaf[subject.OU] = \"7UXAQ487HP\""
    );
    for invalid in [
        None,
        Some(""),
        Some("lowercase1"),
        Some("SHORT"),
        Some("TOOLONG00001"),
        Some("BAD-TEAM01"),
    ] {
        assert_eq!(
            macos_manager_designated_requirement_for_team(invalid)
                .unwrap_err()
                .code(),
            "insufficient-permission"
        );
    }
}

fn verified_peer(user_id: u32, identity: &str) -> ObservedPeer {
    ObservedPeer::for_fixture(
        user_id,
        identity,
        PeerVerification::KernelCredentialsAndCodeIdentity,
        ACCEPTED_AT,
    )
}

#[test]
fn endpoint_rejects_a_peer_outside_the_configured_application_identity() {
    let policy = PeerPolicy::for_fixture_user(501, "com.openrdx.manager", ACCEPTED_AT);
    let peer = verified_peer(502, "untrusted.client");

    assert_eq!(
        policy.authorize(&peer, ACCEPTED_AT).unwrap_err().code(),
        "unauthorized-service-peer"
    );
}

#[test]
fn endpoint_rejects_identity_claims_without_native_code_verification() {
    let policy = PeerPolicy::for_fixture_user(501, "com.openrdx.manager", ACCEPTED_AT);
    let peer = ObservedPeer::for_fixture(
        501,
        "com.openrdx.manager",
        PeerVerification::KernelCredentialsOnly,
        ACCEPTED_AT,
    );

    assert_eq!(
        policy.authorize(&peer, ACCEPTED_AT).unwrap_err().code(),
        "unauthorized-service-peer"
    );
}

#[test]
fn endpoint_rejects_stale_or_future_peer_evidence() {
    let policy = PeerPolicy::for_fixture_user(501, "com.openrdx.manager", ACCEPTED_AT);
    let stale = ObservedPeer::for_fixture(
        501,
        "com.openrdx.manager",
        PeerVerification::KernelCredentialsAndCodeIdentity,
        ACCEPTED_AT + Duration::from_secs(2),
    );

    assert_eq!(
        policy
            .authorize(&stale, ACCEPTED_AT + Duration::from_secs(8))
            .unwrap_err()
            .code(),
        "stale-service-peer"
    );
    assert_eq!(
        policy.authorize(&stale, ACCEPTED_AT).unwrap_err().code(),
        "stale-service-peer"
    );
}

#[test]
fn endpoint_authorizes_only_fresh_exact_native_evidence() {
    let policy = PeerPolicy::for_fixture_user(501, "com.openrdx.manager", ACCEPTED_AT);
    let authorization = policy
        .authorize(&verified_peer(501, "com.openrdx.manager"), ACCEPTED_AT)
        .unwrap();

    assert_eq!(authorization.application_identity(), "com.openrdx.manager");
    assert_eq!(authorization.user_id(), 501);
}

#[test]
fn production_endpoints_are_fixed_and_never_stdio() {
    let windows = ServiceEndpoint::production(EndpointPlatform::Windows);
    let linux = ServiceEndpoint::production(EndpointPlatform::Linux);
    let macos = ServiceEndpoint::production(EndpointPlatform::MacOs);

    assert_eq!(windows.address(), r"\\.\pipe\OpenRDXHardwareService");
    assert_eq!(linux.address(), "/run/openrdx/openrdx-hardware.sock");
    assert_eq!(macos.address(), "/var/run/openrdx-hardware.sock");
    assert!(!windows.is_development_stdio());
    assert!(!linux.is_development_stdio());
    assert!(!macos.is_development_stdio());
    assert!(ServiceEndpoint::development_stdio().is_development_stdio());
}

#[test]
fn development_stdio_cannot_authorize_production_mutation() {
    assert_eq!(
        ServiceEndpoint::development_stdio()
            .require_production_mutation_authority()
            .unwrap_err()
            .code(),
        "insufficient-permission"
    );
    assert!(
        ServiceEndpoint::production(EndpointPlatform::MacOs)
            .require_production_mutation_authority()
            .is_ok()
    );
}

#[test]
fn platform_endpoint_contracts_are_fixed_bounded_and_local() {
    let linux = rdx_linux_native::systemd_endpoint_contract();
    assert_eq!(linux.manager_path, "/opt/OpenRDXManager/OpenRDXManager");
    assert_eq!(linux.socket_path, "/run/openrdx/openrdx-hardware.sock");
    assert_eq!(
        (linux.owner_uid, linux.group, linux.mode),
        (0, "openrdx", 0o660)
    );
    assert_eq!(linux.max_connections, 8);
    assert_eq!(
        (linux.accept_timeout_ms, linux.handshake_timeout_ms),
        (10_000, 2_000)
    );

    let windows = rdx_windows_native::named_pipe_endpoint_contract();
    assert_eq!(windows.pipe_name, r"\\.\pipe\OpenRDXHardwareService");
    assert_eq!(
        windows.principals,
        ["current-active-user", "administrators", "local-service"]
    );
    assert!(windows.reject_remote_clients);
    assert_eq!(
        (windows.max_instances, windows.max_frame_bytes),
        (8, 65_540)
    );
    assert_eq!(
        windows.manager_path,
        r"C:\Program Files\OpenRDXManager\OpenRDXManager.exe"
    );
    assert_eq!(
        (windows.accept_timeout_ms, windows.handshake_timeout_ms),
        (10_000, 2_000)
    );

    let macos = rdx_macos_native::launchd_endpoint_contract();
    assert_eq!(macos.socket_path, "/var/run/openrdx-hardware.sock");
    assert_eq!((macos.owner_uid, macos.mode), (0, 0o660));
    assert_eq!(macos.max_connections, 8);
    assert_eq!(
        (macos.accept_timeout_ms, macos.handshake_timeout_ms),
        (10_000, 2_000)
    );
}

#[derive(Debug)]
struct ChunkedTimedReader {
    bytes: Vec<u8>,
    offset: usize,
    chunk_bytes: usize,
    timeout_updates: Vec<Option<Duration>>,
}

impl Read for ChunkedTimedReader {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if self.offset == self.bytes.len() {
            return Ok(0);
        }
        let count = self
            .chunk_bytes
            .min(buffer.len())
            .min(self.bytes.len() - self.offset);
        buffer[..count].copy_from_slice(&self.bytes[self.offset..self.offset + count]);
        self.offset += count;
        Ok(count)
    }
}

#[test]
fn production_reader_applies_one_absolute_deadline_until_the_first_complete_frame() {
    let mut framed = (5_u32.to_be_bytes()).to_vec();
    framed.extend_from_slice(b"helloNEXT");
    let fixture = ChunkedTimedReader {
        bytes: framed,
        offset: 0,
        chunk_bytes: 2,
        timeout_updates: Vec::new(),
    };
    let mut reader =
        HandshakeDeadlineReader::new(fixture, Duration::from_secs(2), |fixture, timeout| {
            fixture.timeout_updates.push(timeout);
            Ok(())
        })
        .unwrap();
    let mut output = Vec::new();
    let mut chunk = [0_u8; 3];
    while output.len() < 13 {
        let count = reader.read(&mut chunk).unwrap();
        output.extend_from_slice(&chunk[..count]);
    }
    let fixture = reader.into_inner();

    assert_eq!(
        output,
        [5_u32.to_be_bytes().as_slice(), b"helloNEXT"].concat()
    );
    assert!(fixture.timeout_updates.first().unwrap().is_some());
    assert_eq!(
        fixture
            .timeout_updates
            .iter()
            .filter(|timeout| timeout.is_none())
            .count(),
        1
    );
    assert_eq!(fixture.timeout_updates.last(), Some(&None));
}

#[test]
fn macos_native_endpoint_rejects_an_unpinned_code_requirement_before_accept() {
    assert_eq!(
        rdx_macos_native::accept_launchd_manager_endpoint("identifier com.openrdx.manager")
            .unwrap_err(),
        rdx_macos_native::NativeError::InvalidRequest
    );
}

#[test]
fn macos_native_endpoint_rejects_broadened_or_malformed_requirements_before_accept() {
    let broadened = "identifier \"com.openrdx.manager\" and anchor apple generic and certificate leaf[subject.OU] = \"TESTTEAM01\" or identifier \"untrusted.client\"";
    let malformed = "identifier \"com.openrdx.manager\"  and anchor apple generic and certificate leaf[subject.OU] = \"TESTTEAM01\"";

    for requirement in [broadened, malformed] {
        assert_eq!(
            rdx_macos_native::accept_launchd_manager_endpoint(requirement).unwrap_err(),
            rdx_macos_native::NativeError::InvalidRequest
        );
    }
}

#[cfg(target_os = "macos")]
#[test]
fn macos_native_endpoint_requires_exact_launchd_socket_activation() {
    let requirement = "identifier \"com.openrdx.manager\" and anchor apple generic and certificate leaf[subject.OU] = \"TESTTEAM01\"";

    assert_eq!(
        rdx_macos_native::accept_launchd_manager_endpoint(requirement).unwrap_err(),
        rdx_macos_native::NativeError::TransportUnavailable
    );
}
