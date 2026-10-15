// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Closed helper selection from the existing canonical authenticated Manager requirement.

use crate::{NativeError, local_trust};
use rdx_local_trust::{RuntimeFile, RuntimeInventory};
use std::{ffi::CStr, path::Path};

/// Only an already validated pinned requirement selects an installed helper location.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum HelperLocation {
    LocalStandalone,
    SignedBundled,
}

impl HelperLocation {
    /// Rejects noncanonical requirements before assigning either fixed installation mode.
    pub(crate) fn from_requirement(requirement: &CStr) -> Result<Self, NativeError> {
        let text = requirement
            .to_str()
            .map_err(|_| NativeError::InvalidRequest)?;
        if !crate::manager_requirement_is_pinned(text) {
            return Err(NativeError::InvalidRequest);
        }
        Ok(
            if text.starts_with("identifier \"com.openrdx.manager\" and cdhash ") {
                Self::LocalStandalone
            } else {
                Self::SignedBundled
            },
        )
    }

    /// Returns one compiled path; no path or mode can be supplied through the public capability API.
    pub(crate) fn path(self) -> &'static Path {
        Path::new(match self {
            Self::LocalStandalone => local_trust::HELPER_PATH,
            Self::SignedBundled => {
                "/Applications/OpenRDXManager.app/Contents/Library/LaunchServices/openrdx-hardware"
            }
        })
    }

    /// Fails closed if this actual running service differs from its retained generation mode.
    pub(crate) fn verify_current_executable(self, executable: &Path) -> Result<(), NativeError> {
        if executable == self.path() {
            Ok(())
        } else {
            Err(NativeError::AccessDenied)
        }
    }

    /// Requires the bundled inventory entry in both modes; local mode also proves standalone bytes.
    pub(crate) fn verify_inventory(self, inventory: &RuntimeInventory) -> Result<(), NativeError> {
        self.verify_inventory_with(inventory, &ProtectedFileVerifier)
    }

    /// The private verifier has a single production implementation; fixture implementations are cfg(test).
    fn verify_inventory_with(
        self,
        inventory: &RuntimeInventory,
        verifier: &impl StandaloneVerifier,
    ) -> Result<(), NativeError> {
        let helper = inventory
            .files
            .iter()
            .find(|f| f.path == local_trust::HELPER_INVENTORY_PATH)
            .ok_or(NativeError::AccessDenied)?;
        match self {
            Self::LocalStandalone => verifier.verify(helper),
            Self::SignedBundled => Ok(()),
        }
    }
}

/// Production has only the fixed protected-file proof; tests cannot create a public factory.
trait StandaloneVerifier {
    /// Verifies only the compiled standalone helper against the already validated inventory entry.
    fn verify(&self, helper: &RuntimeFile) -> Result<(), NativeError>;
}
struct ProtectedFileVerifier;
impl StandaloneVerifier for ProtectedFileVerifier {
    /// Retains all protected-ancestor/ownership/hash checks of the original local standalone path.
    fn verify(&self, helper: &RuntimeFile) -> Result<(), NativeError> {
        rdx_local_trust::verify_protected_file(
            Path::new(local_trust::HELPER_PATH),
            &helper.sha256,
            helper.size,
        )
        .map_err(|_| NativeError::AccessDenied)
    }
}

#[cfg(test)]
#[path = "helper_location_tests.rs"]
mod tests;
