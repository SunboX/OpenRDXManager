// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Fixed administrator-enrolled app and helper identity, independent of IPC input.

use crate::NativeError;
use rdx_local_trust::RuntimeInventory;
#[cfg(target_os = "macos")]
use std::path::Path;

/// Fixed complete sealed Manager runtime.
pub const MANAGER_ROOT: &str = "/Applications/OpenRDXManager.app";
/// Fixed installed root helper executable.
pub const HELPER_PATH: &str = "/Library/PrivilegedHelperTools/openrdx-hardware";
/// Enrolled app copy used to authenticate the installed standalone helper bytes.
pub const HELPER_INVENTORY_PATH: &str = "Contents/Library/LaunchServices/openrdx-hardware";

/// Reads only the fixed protected enrollment used to bootstrap the listener policy.
///
/// This validates the manifest's schema, pins, root ownership, permissions, ACLs,
/// ancestor protection and replacement identity. It does not authorize a session:
/// the listener must freshly verify all runtime and helper bytes before accepting.
///
/// # Errors
/// Returns access denied for absent, malformed or weakly protected enrollment.
pub fn read_installed_enrollment() -> Result<RuntimeInventory, NativeError> {
    #[cfg(target_os = "macos")]
    {
        rdx_local_trust::verify_enrollment(
            Path::new(rdx_local_trust::MACOS_ENROLLMENT_PATH),
            "macos",
        )
        .map_err(|_| NativeError::AccessDenied)
    }
    #[cfg(not(target_os = "macos"))]
    {
        Err(NativeError::UnsupportedPlatform)
    }
}

/// Verifies fixed enrollment, complete protected runtime, and root helper bytes.
///
/// # Errors
/// Returns access denied on missing enrollment, tampered resources, unexpected
/// inputs, non-root ownership, unsafe access controls, links or replacement races.
pub fn verify_installed_local_trust() -> Result<RuntimeInventory, NativeError> {
    #[cfg(target_os = "macos")]
    {
        let inventory = read_installed_enrollment()?;
        rdx_local_trust::verify_protected_runtime(Path::new(MANAGER_ROOT), &inventory)
            .map_err(|_| NativeError::AccessDenied)?;
        let helper = inventory
            .files
            .iter()
            .find(|file| file.path == HELPER_INVENTORY_PATH)
            .ok_or(NativeError::AccessDenied)?;
        rdx_local_trust::verify_protected_file(Path::new(HELPER_PATH), &helper.sha256, helper.size)
            .map_err(|_| NativeError::AccessDenied)?;
        Ok(inventory)
    }
    #[cfg(not(target_os = "macos"))]
    {
        Err(NativeError::UnsupportedPlatform)
    }
}
