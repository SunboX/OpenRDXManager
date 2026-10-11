// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Closed manufacturing backup requests and path-free saved-record summaries.

use crate::model::{DeviceId, DiscoveryRevision};
use serde::{Deserialize, Serialize};

/// Validated metadata only; raw factory bytes and filesystem paths stay service-owned.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BackupSummary {
    /// Immutable generated backup selection.
    pub backup_id: String,
    /// Creation time as Unix milliseconds.
    pub created_at: u64,
    /// Distinguishes a valid record from preserved erased evidence.
    pub state: String,
    /// Original device identity, which can differ after an erased record falls back.
    pub device_id: DeviceId,
    /// Original decimal unit serial, only when a valid record supplies it.
    pub serial: Option<String>,
}

/// Current exact-device capabilities and independently verified saved records.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BackupInventory {
    /// Zero-based inventory page.
    pub page: u32,
    /// More retained records can be selected on the next page.
    pub has_more: bool,
    /// Saved-record metadata, newest first.
    pub backups: Vec<BackupSummary>,
    /// Whether this current receiver can supply a complete manufacturing read.
    pub backup_supported: bool,
    /// Whether its non-mutating full-record capability probe succeeded.
    pub restore_supported: bool,
}

/// Private validated raw record with its original attribution.
pub struct BackupRecord {
    pub(crate) summary: BackupSummary,
    pub(crate) bytes: zeroize::Zeroizing<[u8; 256]>,
}

/// Explicit user association, including the original serial displayed beside the backup.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RestoreRequest {
    /// Current selected dock, potentially reporting a fallback identity after corruption.
    pub device_id: DeviceId,
    /// Current discovery generation.
    pub device_revision: DiscoveryRevision,
    /// Service-owned immutable saved record identifier.
    pub backup_id: String,
    /// Original ten-digit serial typed by the operator.
    pub confirmation_serial: String,
    /// Explicit physical-dock association.
    pub acknowledged: bool,
    /// Additional operator consent to replace an existing checksum-valid identity.
    #[serde(default)]
    pub allow_identity_change: bool,
}

/// One exact snapshot; revisions prevent applying an action after device replacement.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BackupRequest {
    /// Exact selected device.
    pub device_id: DeviceId,
    /// Revision displayed when the action was requested.
    pub device_revision: DiscoveryRevision,
    /// Optional explicit page; no cursor grants file authority.
    pub page: Option<u32>,
    /// Requires fresh stable reads before releasing an uncertain host reservation.
    pub reconcile: Option<bool>,
}

impl BackupInventory {
    /// Returns a bounded page while retaining access to earlier original recovery records.
    pub(crate) fn page(
        mut backups: Vec<BackupSummary>,
        page: u32,
        backup_supported: bool,
        restore_supported: bool,
    ) -> Result<Self, super::ServiceRejection> {
        if page > 31 {
            return Err(super::service_rejection("invalid-request"));
        }
        let start = page as usize * 128;
        let has_more = backups.len() > start + 128;
        let backups = if start >= backups.len() {
            Vec::new()
        } else {
            backups.drain(start..).take(128).collect()
        };
        Ok(Self {
            page,
            has_more,
            backups,
            backup_supported,
            restore_supported,
        })
    }
}

impl<B: super::ServiceBackend> super::ServiceRuntime<B> {
    /// Relocates local storage under the accepted desktop identity without opening any device.
    pub(super) fn prepare_manufacturing_folder(&mut self) -> serde_json::Value {
        if self.active.is_some() || self.backend.require_recovery_idle().is_err() {
            return super::action_failure("operation-in-progress");
        }
        #[cfg(any(target_os = "macos", target_os = "linux", windows))]
        if crate::migration::manufacturing_backup::prepare_storage(self.backup_owner).is_err() {
            return super::action_failure("manufacturing-storage-unavailable");
        }
        #[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
        let _ = self.backup_owner;
        serde_json::json!({"ok": true})
    }

    /// Parses the closed vocabulary before entering the sole hardware owner.
    pub(super) fn handle_manufacturing_request(
        &mut self,
        method: &str,
        payload: serde_json::Value,
    ) -> Result<serde_json::Value, super::ServiceProtocolError> {
        let result = if method == "manufacturing-restore" {
            let request = super::parse_payload::<RestoreRequest>(payload)?;
            if self.active.is_some() {
                return Ok(super::action_failure("operation-in-progress"));
            }
            self.backend.manufacturing_restore(request)
        } else {
            let request = super::parse_payload::<BackupRequest>(payload)?;
            if self.active.is_some() {
                return Ok(super::action_failure("operation-in-progress"));
            }
            self.backend
                .manufacturing_backup(request, method == "manufacturing-backup")
        };
        Ok(match result {
            Ok(inventory) => {
                serde_json::json!({"ok": true, "page": inventory.page, "hasMore": inventory.has_more, "backups": inventory.backups, "backupSupported": inventory.backup_supported, "restoreSupported": inventory.restore_supported})
            }
            Err(error) => super::action_failure(error.as_str()),
        })
    }
}
