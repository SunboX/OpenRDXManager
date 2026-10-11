// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Portable hardware-absent service adapter.

use super::*;

/// Honest portable backend used until Phase 3 supplies an OS hardware adapter.
#[derive(Clone, Debug)]
pub struct NoDeviceBackend {
    descriptor: ServiceDescriptor,
}

impl NoDeviceBackend {
    /// Creates an empty, unprivileged, transport-unavailable backend.
    #[must_use]
    pub fn new(platform: ServicePlatform) -> Self {
        Self {
            descriptor: ServiceDescriptor::no_device(platform),
        }
    }

    /// Creates an empty operation backend carrying one truthful native matrix.
    ///
    /// The constructor changes handshake evidence only: device lists remain
    /// empty and every hardware operation remains rejected until later tasks
    /// wire a registry-owning backend.
    #[must_use]
    pub fn from_platform_capabilities(
        platform: ServicePlatform,
        capabilities: crate::platform::PlatformCapabilities,
    ) -> Self {
        Self {
            descriptor: ServiceDescriptor::from_platform_capabilities(platform, capabilities),
        }
    }
}

impl ServiceBackend for NoDeviceBackend {
    fn descriptor(&self) -> ServiceDescriptor {
        self.descriptor.clone()
    }

    fn list_devices(&mut self) -> Result<Vec<DeviceSnapshot>, ServiceRejection> {
        Ok(Vec::new())
    }

    fn scan_devices(&mut self) -> Result<Vec<DeviceSnapshot>, ServiceRejection> {
        Ok(Vec::new())
    }

    fn start_operation(
        &mut self,
        _operation_id: OperationId,
        _request: OperationRequest,
        _events: ServiceEventSink,
    ) -> Result<(), ServiceRejection> {
        Err(ServiceRejection::new("transport-unavailable")
            .expect("static no-device reason is valid"))
    }

    fn cancel_operation(&mut self, _operation_id: &OperationId) -> Result<(), ServiceRejection> {
        Err(ServiceRejection::new("transport-unavailable")
            .expect("static no-device reason is valid"))
    }

    fn shutdown(&mut self) -> Result<(), ServiceRejection> {
        Ok(())
    }
}
