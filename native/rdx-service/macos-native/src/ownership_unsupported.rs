// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Portable macOS ownership contract without importing Unix APIs on other hosts.

use crate::NativeError;

/// Immutable installation contract for the macOS ownership file.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HardwareOwnershipContract {
    /// Fixed root-controlled ownership file.
    pub path: &'static str,
    /// Required file owner.
    pub owner_uid: u32,
    /// Required private permission bits.
    pub mode: u32,
    /// Whether acquisition always fails immediately when another owner exists.
    pub nonblocking: bool,
    /// Whether symbolic-link traversal is rejected by the open itself.
    pub reject_symlinks: bool,
}

/// Unconstructible foreign-platform namespace; it never owns an OS resource.
#[derive(Debug)]
pub struct HardwareOwnershipNamespace {
    _private: (),
}

/// Unconstructible foreign-platform lease; no ownership can be synthesized.
#[derive(Debug)]
pub struct HardwareOwnershipGuard {
    _private: (),
}

/// Returns the macOS contract for portable capability and fixture tests.
#[must_use]
pub const fn hardware_ownership_contract() -> HardwareOwnershipContract {
    HardwareOwnershipContract {
        path: "/var/run/openrdx-hardware.lock",
        owner_uid: 0,
        mode: 0o600,
        nonblocking: true,
        reject_symlinks: true,
    }
}

/// Rejects initialization on a host without the macOS native boundary.
///
/// # Errors
/// Always returns `UnsupportedPlatform` without filesystem or hardware access.
pub fn initialize_hardware_ownership_namespace() -> Result<HardwareOwnershipNamespace, NativeError>
{
    Err(NativeError::UnsupportedPlatform)
}

/// Rejects acquisition on a host without the macOS native boundary.
///
/// # Errors
/// Always returns `UnsupportedPlatform` without filesystem or hardware access.
pub fn try_acquire_hardware_ownership() -> Result<HardwareOwnershipGuard, NativeError> {
    Err(NativeError::UnsupportedPlatform)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Foreign-platform tests must never activate a macOS ownership substitute.
    #[test]
    fn foreign_platform_cannot_acquire_ownership() {
        assert!(matches!(
            initialize_hardware_ownership_namespace(),
            Err(NativeError::UnsupportedPlatform)
        ));
        assert!(matches!(
            try_acquire_hardware_ownership(),
            Err(NativeError::UnsupportedPlatform)
        ));
    }
}
