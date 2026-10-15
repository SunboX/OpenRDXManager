// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Complete private installed-runtime generation binding.

use crate::{NativeError, helper_location::HelperLocation, local_trust};
use rdx_local_trust::RuntimeInventory;
use std::ffi::CStr;

/// Content-equivalent inventories are one generation; UID or Manager cdhash alone is insufficient.
#[derive(Clone, Eq, PartialEq)]
pub(crate) struct RuntimeGeneration {
    helper_location: HelperLocation,
    schema_version: u32,
    platform: String,
    manager_cd_hash: String,
    helper_cd_hash: String,
    files: Vec<(String, u64, String)>,
    links: Vec<(String, String)>,
}

impl RuntimeGeneration {
    /// Verifies the selected fixed installation and its mode-specific protected helper evidence.
    pub(crate) fn capture(requirement: &CStr) -> Result<Self, NativeError> {
        let helper_location = HelperLocation::from_requirement(requirement)?;
        let requirement = requirement
            .to_str()
            .map_err(|_| NativeError::InvalidRequest)?;
        let inventory = if helper_location == HelperLocation::SignedBundled {
            rdx_local_trust::verify_protected_signed_macos_runtime_inventory()
                .map_err(|_| NativeError::AccessDenied)?
        } else {
            let inventory = local_trust::verify_installed_local_trust()?;
            if crate::local_manager_requirement(&inventory.manager_cd_hash)? != requirement {
                return Err(NativeError::AccessDenied);
            }
            inventory
        };
        helper_location.verify_inventory(&inventory)?;
        Ok(Self::from_inventory(helper_location, &inventory))
    }

    /// Compares canonical full metadata only after the current inventory passes real protection/hash proof.
    pub(crate) fn revalidate(&self, requirement: &CStr) -> Result<(), NativeError> {
        self.compare_current_generation(&Self::capture(requirement)?)
    }

    /// Complete generation comparison retains location as well as every file, link and code pin.
    fn compare_current_generation(&self, current: &Self) -> Result<(), NativeError> {
        if self == current {
            Ok(())
        } else {
            Err(NativeError::AccessDenied)
        }
    }

    /// Canonicalizes traversal ordering without dropping any complete inventory evidence.
    fn from_inventory(helper_location: HelperLocation, inventory: &RuntimeInventory) -> Self {
        let mut files: Vec<_> = inventory
            .files
            .iter()
            .map(|file| (file.path.clone(), file.size, file.sha256.clone()))
            .collect();
        let mut links: Vec<_> = inventory
            .links
            .iter()
            .map(|link| (link.path.clone(), link.target.clone()))
            .collect();
        files.sort_unstable();
        links.sort_unstable();
        Self {
            helper_location,
            schema_version: inventory.schema_version,
            platform: inventory.platform.clone(),
            manager_cd_hash: inventory.manager_cd_hash.clone(),
            helper_cd_hash: inventory.helper_cd_hash.clone(),
            files,
            links,
        }
    }

    /// Returns only the closed location retained in this fully verified installed generation.
    pub(crate) fn helper_location(&self) -> HelperLocation {
        self.helper_location
    }

    /// Supplies metadata for internal lifetime tests, never a production generation verifier.
    #[cfg(test)]
    pub(crate) fn fixture() -> Self {
        Self {
            helper_location: HelperLocation::LocalStandalone,
            schema_version: 1,
            platform: "macos".into(),
            manager_cd_hash: String::new(),
            helper_cd_hash: String::new(),
            files: Vec::new(),
            links: Vec::new(),
        }
    }
}

#[cfg(test)]
#[path = "runtime_generation_tests.rs"]
mod tests;
