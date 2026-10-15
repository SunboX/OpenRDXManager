// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Complete private installed-runtime generation binding.

use crate::{NativeError, local_trust};
use rdx_local_trust::RuntimeInventory;
use std::ffi::CStr;

/// Content-equivalent inventories are one generation; UID or Manager cdhash alone is insufficient.
#[derive(Clone, Eq, PartialEq)]
pub(crate) struct RuntimeGeneration {
    signed: bool,
    schema_version: u32,
    platform: String,
    manager_cd_hash: String,
    helper_cd_hash: String,
    files: Vec<(String, u64, String)>,
    links: Vec<(String, String)>,
}

impl RuntimeGeneration {
    /// Verifies the selected fixed installation and binds its standalone helper to bundled bytes.
    pub(crate) fn capture(requirement: &CStr) -> Result<Self, NativeError> {
        let requirement = requirement
            .to_str()
            .map_err(|_| NativeError::InvalidRequest)?;
        if !crate::manager_requirement_is_pinned(requirement) {
            return Err(NativeError::InvalidRequest);
        }
        let signed = !requirement.starts_with("identifier \"com.openrdx.manager\" and cdhash ");
        let inventory = if signed {
            rdx_local_trust::verify_protected_signed_macos_runtime_inventory()
                .map_err(|_| NativeError::AccessDenied)?
        } else {
            let inventory = local_trust::verify_installed_local_trust()?;
            if crate::local_manager_requirement(&inventory.manager_cd_hash)? != requirement {
                return Err(NativeError::AccessDenied);
            }
            inventory
        };
        let helper = inventory
            .files
            .iter()
            .find(|entry| entry.path == local_trust::HELPER_INVENTORY_PATH)
            .ok_or(NativeError::AccessDenied)?;
        rdx_local_trust::verify_protected_file(
            std::path::Path::new(local_trust::HELPER_PATH),
            &helper.sha256,
            helper.size,
        )
        .map_err(|_| NativeError::AccessDenied)?;
        Ok(Self::from_inventory(signed, &inventory))
    }

    /// Compares canonical full metadata only after the current inventory passes real protection/hash proof.
    pub(crate) fn revalidate(&self, requirement: &CStr) -> Result<(), NativeError> {
        if *self != Self::capture(requirement)? {
            return Err(NativeError::AccessDenied);
        }
        Ok(())
    }

    /// Canonicalizes traversal ordering without dropping any complete inventory evidence.
    fn from_inventory(signed: bool, inventory: &RuntimeInventory) -> Self {
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
            signed,
            schema_version: inventory.schema_version,
            platform: inventory.platform.clone(),
            manager_cd_hash: inventory.manager_cd_hash.clone(),
            helper_cd_hash: inventory.helper_cd_hash.clone(),
            files,
            links,
        }
    }

    /// Supplies metadata for internal lifetime tests, never a production generation verifier.
    #[cfg(test)]
    pub(crate) fn fixture() -> Self {
        Self {
            signed: false,
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
