// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Bounded local enrollment parsing and exact runtime content verification.
//! Content verification does not establish Windows ACL protection; callers must
//! retain their platform protection handles while performing it.

#[cfg(target_os = "macos")]
mod fuses;
mod inventory;
mod runtime;
#[cfg(target_os = "macos")]
mod signed_macos;
#[cfg(target_os = "macos")]
pub use signed_macos::verify_protected_signed_macos_runtime;
#[cfg(unix)]
mod unix;

pub use inventory::{
    MAX_ENTRIES, MAX_INVENTORY_BYTES, RuntimeFile, RuntimeInventory, RuntimeLink, parse_inventory,
};
pub use runtime::{runtime_handle_requirement, verify_runtime};
use std::{fmt, path::Path};
#[cfg(unix)]
pub use unix::{
    read_protected_inventory, verify_descriptor_acl, verify_protected_descriptor,
    verify_protected_directory, verify_protected_file, verify_protected_runtime,
    verify_protected_tree_ownership,
};

/// Fixed administrator-owned macOS enrollment, never supplied by a peer.
pub const MACOS_ENROLLMENT_PATH: &str =
    "/Library/Application Support/OpenRDXManager/LocalTrust/runtime.json";

/// Fail-closed trust error with a non-sensitive diagnostic.
#[derive(Debug)]
pub struct TrustError(pub String);

impl fmt::Display for TrustError {
    /// Render the diagnostic without including runtime content.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}
impl std::error::Error for TrustError {}

impl From<std::io::Error> for TrustError {
    /// Preserve filesystem failure context without treating it as trust.
    fn from(error: std::io::Error) -> Self {
        Self(error.to_string())
    }
}

/// Verify the fixed production enrollment before parsing its bounded content.
/// On Unix this requires macOS policy, root ownership, protected no-follow
/// ancestors and ACLs, and retained identities. Windows callers must use their
/// native owner/DACL/retained-handle adapter; this entrypoint refuses Windows.
pub fn verify_enrollment(path: &Path, platform: &str) -> Result<RuntimeInventory, TrustError> {
    if platform != "macos" || path != Path::new(MACOS_ENROLLMENT_PATH) {
        return Err(TrustError(
            "enrollment is not the fixed protected macOS location".into(),
        ));
    }
    #[cfg(unix)]
    {
        unix::read_protected_inventory(path, platform)
    }
    #[cfg(not(unix))]
    {
        Err(TrustError(
            "native protected enrollment adapter required".into(),
        ))
    }
}

/// Produce a trust denial from an invariant violation.
pub(crate) fn deny(message: &str) -> TrustError {
    TrustError(message.into())
}
