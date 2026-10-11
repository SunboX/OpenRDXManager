// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! New recovery-attempt ownership without regenerating or altering original records.

use super::{MigrationError, PreparedMigration};

/// Validated original-bundle information explicitly permitted on the recovery UI.
#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MigrationRecoverySummary {
    /// Original schema-one identifier used for explicit selection, never a path.
    pub bundle_id: String,
    /// Validated twelve-digit unit serial intended for operator identification.
    pub serial: String,
    /// Plain display label containing only the validated serial.
    pub display_label: String,
    /// Captured supported vendor release, not a live device observation.
    pub source_version: &'static str,
    /// Exact pinned final release version.
    pub target_version: &'static str,
    /// Last journal event of the latest validated attempt by generated creation ID.
    pub last_state: super::MigrationEvent,
    /// That saved attempt ended in final verification; this is not current hardware state.
    pub completed: bool,
    /// The latest validated saved attempt lacks final completion evidence.
    pub recovery_needed: bool,
}

/// Available original summaries and bounded failures exclude all private raw records.
#[derive(serde::Serialize)]
#[serde(tag = "status", rename_all = "kebab-case")]
pub enum MigrationRecoveryInventoryEntry {
    /// A fully validated original remains selectable even after recorded completion.
    Available(MigrationRecoverySummary),
    /// Corrupt or incomplete recognized evidence has no trusted unit label.
    Unavailable {
        /// Bounded generated identifier only, even when contents are corrupt.
        #[serde(rename = "bundleId")]
        bundle_id: String,
        /// Fixed storage diagnostic; filesystem paths and decoder details are excluded.
        reason: &'static str,
    },
}

/// Lists validated original bundles without opening hardware or changing the root.
///
/// Privileged macOS only. A missing fixed root yields an empty inventory; unsafe
/// ancestry or excessive inventory fails with StorageUnavailable. Recognized corrupt
/// bundles yield bounded unavailable entries while other valid originals remain
/// available. Valid recovery copies update their origin's saved state but never
/// become selectable originals. Completion never disables explicit recovery: live
/// ROM identity and port authorization belong to the caller's separate operation.
pub fn recovery_inventory() -> Result<Vec<MigrationRecoveryInventoryEntry>, MigrationError> {
    #[cfg(target_os = "macos")]
    {
        if !super::storage::existing_fixed_root_available()? {
            return Ok(Vec::new());
        }
        super::storage::inventory::inventory(
            std::path::Path::new(super::RECOVERY_ROOT),
            super::FINAL_RELEASE_SHA256,
        )
    }
    #[cfg(not(target_os = "macos"))]
    {
        Err(MigrationError::StorageUnavailable)
    }
}

impl PreparedMigration {
    /// Creates an independent writable attempt from the original captured bundle.
    ///
    /// Only the existing fixed privileged macOS root is admitted. The original
    /// schema-one bundle is cold-validated first; all six files are then copied
    /// byte-for-byte into a new exclusively created private bundle. Its schema-two
    /// receipt binds the original identifier and receipt digest. The new journal
    /// starts Prepared/RecoveryResumed; original artifacts and journal never change.
    /// A recovery copy cannot itself be the origin: later attempts name the same
    /// original bundle. This grants no device, changed-port or ROM-write authority.
    /// Failures return the fixed StorageUnavailable code and preserve partial copies.
    pub fn begin_recovery_existing(bundle_id: &str) -> Result<Self, MigrationError> {
        #[cfg(target_os = "macos")]
        {
            super::storage::check_existing_fixed_root()?;
            Self::begin_recovery_inner(
                std::path::Path::new(super::RECOVERY_ROOT),
                bundle_id,
                super::FINAL_RELEASE_SHA256,
            )
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = bundle_id;
            Err(MigrationError::StorageUnavailable)
        }
    }

    /// Injects synthetic roots only internally; copying performs no profile generation.
    #[cfg(any(target_os = "macos", all(unix, test)))]
    pub(super) fn begin_recovery_inner(
        root: &std::path::Path,
        bundle_id: &str,
        release_digest: &str,
    ) -> Result<Self, MigrationError> {
        let original = Self::load_inner(root, bundle_id, release_digest)?;
        let (store, copied) = original.store.create_recovery()?;
        // These validated values describe the exact same six copied bytes. Do
        // not call prepare, Artifacts::new, build_package or personalize here.
        Ok(Self {
            capture: original.capture,
            package: original.package,
            bootstrap: copied.bootstrap,
            final_image: copied.final_image,
            directory: store.directory().to_path_buf(),
            store,
        })
    }
}
