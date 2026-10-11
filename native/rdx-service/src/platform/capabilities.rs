// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Cross-platform readiness capabilities and sanitized platform failures.

use std::fmt::{Display, Formatter};

/// Sanitized platform/discovery failure with no locator or native error text.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PlatformError {
    /// The adapter returned an internally contradictory capability matrix.
    InconsistentCapabilities,
    /// Candidate enumeration is not available on this platform adapter.
    DiscoveryUnavailable,
    /// Safe raw discovery commands cannot be executed by this adapter.
    TransportUnavailable,
    /// The adapter could not enumerate a bounded candidate set.
    EnumerationFailed,
    /// Windows or another native adapter denied the required least access.
    AccessDenied,
    /// Sharing, locking, or device state made the exact device busy.
    DeviceBusy,
    /// A native synchronous operation was explicitly cancelled.
    OperationCancelled,
    /// A bounded native operation timed out.
    OperationTimedOut,
    /// Hotplug removed or replaced the exact selected OS instance.
    DeviceRemoved,
    /// The isolated native boundary returned an invalid or unsupported result.
    NativeBoundaryFailure,
    /// Enumeration exceeded the service's fixed resource limit.
    TooManyCandidates,
    /// A candidate token was empty, oversized, or path-shaped.
    InvalidCandidateToken,
    /// A service-owned locator was empty or exceeded its private bound.
    InvalidCandidateLocator,
    /// Two enumerated candidates referred to the same token or locator.
    DuplicateCandidate,
    /// Two validated candidates claimed the same physical serial.
    DuplicateDeviceSerial,
    /// Two validated identities produced the same opaque device ID.
    DuplicateDeviceId,
    /// A service-owned discovery revision could not advance safely.
    RevisionOverflow,
    /// The requested opaque device is not present in the current registry.
    DeviceUnavailable,
    /// The requested device revision no longer names the current binding.
    StaleDeviceRevision,
    /// A previously resolved registry generation is no longer current.
    StaleRegistryGeneration,
    /// A resolved capability came from another registry or locator binding.
    StaleDeviceBinding,
}

impl PlatformError {
    /// Returns a stable path-free error code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::InconsistentCapabilities => "inconsistent-platform-capabilities",
            Self::DiscoveryUnavailable => "discovery-unavailable",
            Self::TransportUnavailable => "transport-unavailable",
            Self::EnumerationFailed => "candidate-enumeration-failed",
            Self::AccessDenied => "platform-access-denied",
            Self::DeviceBusy => "device-busy",
            Self::OperationCancelled => "platform-operation-cancelled",
            Self::OperationTimedOut => "platform-operation-timeout",
            Self::DeviceRemoved => "device-removed",
            Self::NativeBoundaryFailure => "native-boundary-failure",
            Self::TooManyCandidates => "too-many-candidates",
            Self::InvalidCandidateToken => "invalid-candidate-token",
            Self::InvalidCandidateLocator => "invalid-candidate-locator",
            Self::DuplicateCandidate => "duplicate-candidate",
            Self::DuplicateDeviceSerial => "duplicate-device-serial",
            Self::DuplicateDeviceId => "duplicate-device-id",
            Self::RevisionOverflow => "discovery-revision-overflow",
            Self::DeviceUnavailable => "device-unavailable",
            Self::StaleDeviceRevision => "stale-device-revision",
            Self::StaleRegistryGeneration => "stale-registry-generation",
            Self::StaleDeviceBinding => "stale-device-binding",
        }
    }
}

impl Display for PlatformError {
    /// Formats only the stable sanitized code.
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for PlatformError {}

/// Cross-field-consistent readiness reported by one native platform adapter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PlatformCapabilities {
    pub(super) discovery: bool,
    pub(super) transport: bool,
    pub(super) privileged: bool,
    pub(super) safe_eject: bool,
    pub(super) force_eject: bool,
    pub(super) format: bool,
    pub(super) drive_letter: bool,
    pub(super) hardware_verified: bool,
}

impl PlatformCapabilities {
    /// Creates a capability matrix only when every dependent field is honest.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformError::InconsistentCapabilities`] when transport is
    /// claimed without discovery, a host mutation is claimed without transport
    /// and privilege, force eject exists without safe eject, or physical proof
    /// is claimed without a usable discovery transport.
    #[allow(clippy::too_many_arguments)]
    pub fn try_new(
        discovery: bool,
        transport: bool,
        privileged: bool,
        safe_eject: bool,
        force_eject: bool,
        format: bool,
        drive_letter: bool,
        hardware_verified: bool,
    ) -> Result<Self, PlatformError> {
        let mutations = safe_eject || force_eject || format || drive_letter;
        if (transport && !discovery)
            || (privileged && !transport)
            || (mutations && !(discovery && transport && privileged))
            || (force_eject && !safe_eject)
            || (hardware_verified && !(discovery && transport))
        {
            return Err(PlatformError::InconsistentCapabilities);
        }
        Ok(Self {
            discovery,
            transport,
            privileged,
            safe_eject,
            force_eject,
            format,
            drive_letter,
            hardware_verified,
        })
    }

    /// Returns whether OS candidate enumeration is available.
    #[must_use]
    pub const fn discovery_available(self) -> bool {
        self.discovery
    }

    /// Returns whether safe raw commands can validate enumerated candidates.
    #[must_use]
    pub const fn transport_available(self) -> bool {
        self.transport
    }

    /// Returns whether the constrained privileged service is ready.
    #[must_use]
    pub const fn privileged(self) -> bool {
        self.privileged
    }

    /// Returns whether the host exposes the non-forcing eject operation.
    #[must_use]
    pub const fn safe_eject_available(self) -> bool {
        self.safe_eject
    }

    /// Returns whether a separately confirmed force-eject path exists.
    #[must_use]
    pub const fn force_eject_available(self) -> bool {
        self.force_eject
    }

    /// Returns whether bounded host formatting is available.
    #[must_use]
    pub const fn format_available(self) -> bool {
        self.format
    }

    /// Returns whether the exact mounted-volume write/read diagnostic is available.
    ///
    /// Every native formatter adapter owns the same retained volume authority
    /// used by the diagnostic, so its software-readiness gate is identical.
    #[must_use]
    pub const fn write_read_available(self) -> bool {
        self.format
    }

    /// Returns whether drive-letter mutation is available on this platform.
    #[must_use]
    pub const fn drive_letter_available(self) -> bool {
        self.drive_letter
    }

    /// Returns whether physical hardware acceptance has been completed.
    #[must_use]
    pub const fn hardware_verified(self) -> bool {
        self.hardware_verified
    }
}
