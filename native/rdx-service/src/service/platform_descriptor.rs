// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Truthful mapping from platform readiness into the existing service handshake.

use crate::platform::PlatformCapabilities;

use super::{ServiceDescriptor, ServiceMode, ServicePlatform};

impl ServiceDescriptor {
    /// Maps one validated platform matrix into the strict service handshake.
    ///
    /// Discovery without raw transport, missing privilege, and absent physical
    /// acceptance proof remain explicit unavailable states. This constructor
    /// may be selected by an empty operation backend to publish discovery-only
    /// readiness before a later task wires the concrete registry owner.
    #[must_use]
    pub fn from_platform_capabilities(
        platform: ServicePlatform,
        capabilities: PlatformCapabilities,
    ) -> Self {
        let (mode, privileged, capability_state, capability_reason) =
            if !capabilities.discovery_available() {
                (
                    ServiceMode::NoDevice,
                    false,
                    "transport-unavailable",
                    Some("platform-adapter-not-implemented"),
                )
            } else if !capabilities.transport_available() {
                (
                    ServiceMode::Native,
                    false,
                    "transport-unavailable",
                    Some("raw-transport-unavailable"),
                )
            } else if !capabilities.privileged() {
                (
                    ServiceMode::Native,
                    false,
                    "insufficient-permission",
                    Some("privileged-service-unavailable"),
                )
            } else {
                (ServiceMode::Native, true, "available", None)
            };
        Self {
            platform,
            mode,
            privileged,
            service_version: env!("CARGO_PKG_VERSION").to_owned(),
            capability_state,
            capability_reason,
            hardware_verified: capabilities.hardware_verified(),
        }
    }

    /// Returns the bounded service readiness mode.
    #[must_use]
    pub const fn mode(&self) -> ServiceMode {
        self.mode
    }

    /// Returns whether the current service reports its privilege boundary ready.
    #[must_use]
    pub const fn privileged(&self) -> bool {
        self.privileged
    }

    /// Returns the stable platform capability state emitted in the handshake.
    #[must_use]
    pub const fn platform_capability_state(&self) -> &'static str {
        self.capability_state
    }

    /// Returns the optional stable platform capability reason.
    #[must_use]
    pub const fn platform_capability_reason(&self) -> Option<&'static str> {
        self.capability_reason
    }

    /// Returns whether this source implementation has physical-hardware verification evidence.
    #[must_use]
    pub const fn hardware_verified(&self) -> bool {
        self.hardware_verified
    }
}
