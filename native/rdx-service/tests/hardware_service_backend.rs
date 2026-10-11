// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

use rdx_service::platform::{
    CandidateDevice, CandidateLease, PlatformBackend, PlatformCapabilities, PlatformError,
};
use rdx_service::service::{HardwareServiceBackend, ServiceBackend};

/// Compile-only platform stub used to prove the real registry-owning backend is public.
struct StubPlatform;

impl PlatformBackend for StubPlatform {
    /// Exposes one discovery-only matrix; no native call is made by this type test.
    fn capabilities(&self) -> PlatformCapabilities {
        PlatformCapabilities::try_new(true, false, false, false, false, false, false, false)
            .expect("discovery-only fixture is consistent")
    }

    /// Returns an authoritative empty candidate generation.
    fn enumerate_candidates(&mut self) -> Result<Vec<CandidateDevice>, PlatformError> {
        Ok(Vec::new())
    }

    /// Cannot open a candidate because the fixture never enumerates one.
    fn open_candidate(
        &mut self,
        _candidate: &CandidateDevice,
    ) -> Result<CandidateLease, PlatformError> {
        Err(PlatformError::DeviceUnavailable)
    }
}

/// Production exposes a concrete service backend that owns platform and registry state.
#[test]
fn registry_owned_platform_backend_is_service_reachable() {
    fn assert_backend<T: ServiceBackend>() {}
    assert_backend::<HardwareServiceBackend<StubPlatform>>();
}
