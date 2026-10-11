// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Read-only inventory and explicitly invoked native controller bindings.

use super::*;
use crate::migration::{MigrationRecoveryInventoryEntry, recovery_inventory};
use crate::service::recovery::{list_recovery_targets, recover_selected_in_service};

/// Production authority comes only from the service entrypoint plus a fresh OS probe.
pub(super) struct NativeDriver {
    pub(super) context: ServiceExecutionContext,
}

impl Driver for NativeDriver {
    /// Never treats a native-looking backend descriptor as proof of elevation.
    fn authorize(&self) -> Result<(), RecoveryError> {
        if !self.context.hardware_authorized() || self.context.direct_cli_authorized() {
            return Err(RecoveryError::PrivilegeRequired);
        }
        #[cfg(target_os = "macos")]
        {
            if !rdx_macos_native::current_process_is_privileged_service() {
                return Err(RecoveryError::PrivilegeRequired);
            }
            Ok(())
        }
        #[cfg(not(target_os = "macos"))]
        {
            Err(RecoveryError::UnsupportedPlatform)
        }
    }

    /// Uses descriptor-only ROM discovery and existing-bundle readers, never provisioning.
    fn inventory(&self) -> Result<(Vec<Target>, Vec<Bundle>), RecoveryError> {
        self.authorize()?;
        let targets = list_recovery_targets()?
            .into_iter()
            .map(|target| Target {
                native_token: target.target_token,
                label: target.port_label,
            })
            .collect();
        let bundles = recovery_inventory()
            .map_err(|_| RecoveryError::StorageUnavailable)?
            .into_iter()
            .filter_map(|entry| match entry {
                MigrationRecoveryInventoryEntry::Available(summary) => Some(Bundle {
                    bundle_id: summary.bundle_id,
                    serial: summary.serial,
                    source_version: summary.source_version,
                    target_version: summary.target_version,
                    recovery_needed: summary.recovery_needed,
                }),
                MigrationRecoveryInventoryEntry::Unavailable { .. } => None,
            })
            .collect();
        Ok((targets, bundles))
    }

    /// Uses inherited whole-session ownership and independently revalidates selection/authority.
    fn recover(
        &self,
        selection: &RecoverySelection,
        observer: &mut dyn RecoveryObserver,
    ) -> Result<RecoveryOutcome, RecoveryError> {
        self.authorize()?;
        recover_selected_in_service(selection, observer, self.context)
    }
}
