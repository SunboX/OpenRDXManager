// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Manual capture and restore share the updater's exact lease and durable storage gates.

use super::*;
use crate::service::manufacturing::{BackupInventory, BackupRequest, RestoreRequest};

/// Converts private host failures to bounded path-free service failures.
fn rejection(error: HostPrimitiveError) -> ServiceRejection {
    service_rejection(error.code())
}

impl<B: PlatformBackend> HardwareWorker<B> {
    /// Lists saved records or captures the full record without any device write or reset.
    pub(super) fn manufacturing_backup(
        &mut self,
        request: BackupRequest,
        capture: bool,
    ) -> Result<BackupInventory, ServiceRejection> {
        let snapshot = self
            .registry
            .snapshot(&request.device_id)
            .ok_or_else(|| service_rejection("device-not-found"))?;
        if snapshot.revision != request.device_revision {
            return Err(service_rejection("stale-device-revision"));
        }
        if request.page.is_some_and(|page| page > 31) {
            return Err(service_rejection("invalid-request"));
        }
        if !capture
            && request.reconcile != Some(true)
            && snapshot.media_state == crate::model::MediaState::Present
        {
            // An inserted cartridge already forbids manufacturing operations.
            // Listing local files must not seize SCSI and unmount Finder's disk
            // each time live filesystem accounting advances the revision.
            let backups = self
                .platform
                .manufacturing_backups(&request.device_id)
                .map_err(rejection)?;
            return BackupInventory::page(backups, request.page.unwrap_or(0), false, false);
        }
        let mut resolved = self
            .registry
            .resolve(
                &mut self.platform,
                &request.device_id,
                request.device_revision,
            )
            .map_err(|_| service_rejection("stale-device-revision"))?;
        let backup_supported = resolved
            .firmware_facts()
            .is_ok_and(|(family, revision, media)| {
                family == ProductFamily::Usb3Sata3
                    && revision.has_openrdx_update_receiver()
                    && !media
            });
        // Unsupported probes can invalidate a retained native lease. A record-only
        // adapter has no restore authority, so never send its unmapped sector probe.
        let restore_supported = backup_supported
            && self.platform.supports_manufacturing_sector_read()
            && resolved.supports_manufacturing_restore();
        if request.reconcile == Some(true) {
            // Ordered complete reads must establish stable current data after an
            // uncertain write. This does not retrospectively claim restore success.
            let first = resolved
                .manufacturing_sector()
                .map_err(|_| service_rejection("manufacturing-outcome-unknown"))?;
            let second = resolved
                .manufacturing_sector()
                .map_err(|_| service_rejection("manufacturing-outcome-unknown"))?;
            if first != second {
                return Err(service_rejection("manufacturing-outcome-unknown"));
            }
        }
        if capture {
            if !backup_supported {
                return Err(service_rejection("manufacturing-unavailable"));
            }
            // Manual evidence also preserves corrupt records, which cannot be restored.
            if self.platform.supports_manufacturing_sector_read() {
                let sector = resolved.manufacturing_sector().map_err(rejection)?;
                self.platform
                    .backup_manufacturing_sector(&request.device_id, &sector)
                    .map_err(rejection)?;
                if resolved.manufacturing_sector().map_err(rejection)? != sector {
                    return Err(rejection(HostPrimitiveError::ManufacturingChanged));
                }
            } else {
                // A manual record backup needs no restore or whole-sector command
                // authority. Preserve all 256 bytes, including corrupt evidence,
                // through the same fixed reads as ordinary firmware preservation.
                let record = resolved.manufacturing_record().map_err(rejection)?;
                self.platform
                    .backup_manufacturing_record(&request.device_id, record.bytes())
                    .map_err(rejection)?;
                record
                    .verify(&resolved.manufacturing_record().map_err(rejection)?)
                    .map_err(rejection)?;
            }
        }
        let backups = self
            .platform
            .manufacturing_backups(&request.device_id)
            .map_err(rejection)?;
        BackupInventory::page(
            backups,
            if capture {
                0
            } else {
                request.page.unwrap_or(0)
            },
            backup_supported,
            restore_supported,
        )
    }

    /// Validates explicit original-identity consent, snapshots the current sector, then restores once.
    pub(super) fn manufacturing_restore(
        &mut self,
        request: RestoreRequest,
    ) -> Result<BackupInventory, ServiceRejection> {
        if !request.acknowledged
            || request.confirmation_serial.len() != 10
            || !request
                .confirmation_serial
                .bytes()
                .all(|byte| byte.is_ascii_digit())
            || request.backup_id.len() > 64
        {
            return Err(service_rejection("invalid-request"));
        }
        let saved = self
            .platform
            .load_manufacturing_backup(&request.backup_id)
            .map_err(rejection)?;
        if saved.summary.state != "valid"
            || saved.summary.serial.as_deref() != Some(request.confirmation_serial.as_str())
        {
            return Err(service_rejection("manufacturing-backup-mismatch"));
        }
        let mut resolved = self
            .registry
            .resolve(
                &mut self.platform,
                &request.device_id,
                request.device_revision,
            )
            .map_err(|_| service_rejection("stale-device-revision"))?;
        if !resolved.supports_manufacturing_restore() {
            return Err(rejection(
                HostPrimitiveError::ManufacturingRestoreUnsupported,
            ));
        }
        let current = resolved.manufacturing_sector().map_err(rejection)?;
        let current_state = crate::serial_record::state(&current);
        if current_state == crate::serial_record::RecordState::Valid
            && !request.allow_identity_change
            && (saved.summary.device_id != request.device_id
                || current[8..18] != saved.bytes[8..18])
        {
            return Err(service_rejection("manufacturing-backup-mismatch"));
        }
        // Obtain the post-backup inventory before mutation: an unrelated corrupt
        // directory must not turn a completed device restore into a false failure.
        self.platform
            .backup_manufacturing_sector(&request.device_id, &current)
            .map_err(rejection)?;
        let backups = self
            .platform
            .manufacturing_backups(&request.device_id)
            .map_err(rejection)?;
        resolved
            .restore_manufacturing_record(&current, &saved.bytes, request.allow_identity_change)
            .map_err(rejection)?;
        // The receiver deliberately retains runtime identity until a manual power cycle.
        BackupInventory::page(backups, 0, true, true)
    }
}
