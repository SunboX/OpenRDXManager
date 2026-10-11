// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Child-process fixture proving native adapter panic redaction at the real boundary.

use rdx_service::platform::{
    CandidateDevice, CandidateLease, DeviceRegistry, PlatformBackend, PlatformCapabilities,
    PlatformError, discover_validated_devices,
};
use rdx_service::service::install_process_panic_redaction;

/// Adapter which fails with deliberately sensitive payload and path text.
struct PanickingBackend;

impl PlatformBackend for PanickingBackend {
    fn capabilities(&self) -> PlatformCapabilities {
        PlatformCapabilities::try_new(true, true, true, false, false, false, false, false)
            .expect("panic fixture capabilities are consistent")
    }

    fn enumerate_candidates(&mut self) -> Result<Vec<CandidateDevice>, PlatformError> {
        panic!("adapter payload panic-secret at /private/device/panic-secret and /dev/sg9-secret")
    }

    fn open_candidate(
        &mut self,
        _candidate: &CandidateDevice,
    ) -> Result<CandidateLease, PlatformError> {
        unreachable!("enumeration always panics")
    }
}

/// Installs executable policy before deliberately invoking the panicking adapter.
fn main() {
    install_process_panic_redaction();
    let mut registry = DeviceRegistry::new();
    let _ = discover_validated_devices(&mut PanickingBackend, &mut registry);
}
