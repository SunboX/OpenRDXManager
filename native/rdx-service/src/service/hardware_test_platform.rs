// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Re-enumerable simulated SATA III dock for production backend tests.

use super::*;

#[path = "hardware_manufacturing_fixture.rs"]
mod manufacturing_fixture;
pub(super) use manufacturing_fixture::ManufacturingFault;
#[cfg(unix)]
#[path = "hardware_manufacturing_restore_fixture.rs"]
pub(super) mod manufacturing_restore_fixture;

/// Shared page-0x34 state and command audit for the production-backend fixture.
#[derive(Debug)]
pub(super) struct ModePlatformState {
    pub(super) drive_mode: u8,
    pub(super) firmware_finalize_unknown: usize,
    pub(super) firmware_revision: u16,
    pub(super) firmware_target_revision: u16,
    pub(super) firmware_target_drive_mode: Option<u8>,
    pub(super) firmware_reset_delay: usize,
    pub(super) firmware_cache_discovery: bool,
    pub(super) firmware_activation_scans: Option<usize>,
    pub(super) firmware_rebind_failures: usize,
    pub(super) post_reset_opens: Option<usize>,
    pub(super) firmware_probe_failures: usize,
    pub(super) post_reset_inquiries: usize,
    pub(super) firmware_nonretryable_failure: bool,
    pub(super) firmware_transfer_failures: usize,
    pub(super) manufacturing_fault: ManufacturingFault,
    #[cfg(unix)]
    pub(super) manufacturing_backups: Vec<tempfile::TempDir>,
    pub(super) sata_mode: u8,
    pub(super) commands: Vec<Vec<u8>>,
}

impl ModePlatformState {
    /// Schedules a delayed simulated USB departure, or immediate vendor activation.
    fn begin_firmware_activation(&mut self) {
        if let Some(mode) = self.firmware_target_drive_mode {
            self.drive_mode = mode;
        }
        if self.firmware_reset_delay == 0 {
            self.firmware_revision = self.firmware_target_revision;
            if self.firmware_rebind_failures > 0 {
                self.post_reset_opens = Some(0);
            }
        } else {
            self.firmware_activation_scans = Some(self.firmware_reset_delay);
        }
    }
}

/// Re-enumerable exact SATA III platform used by the real registry-owned backend.
pub(super) struct ModePlatform {
    pub(super) state: Arc<Mutex<ModePlatformState>>,
}

impl crate::platform::PlatformBackend for ModePlatform {
    /// Synthetic fixtures exercise timeout failure without waiting for human USB reattachment.
    fn firmware_reconnect_timeout(&self) -> Duration {
        Duration::from_secs(15)
    }

    /// Windows fixtures exercise the real private storage writer under disposable roots.
    #[cfg(windows)]
    fn backup_manufacturing_record(
        &mut self,
        device_id: &crate::model::DeviceId,
        bytes: &[u8; 256],
    ) -> Result<(), crate::operations::HostPrimitiveError> {
        let unavailable = crate::operations::HostPrimitiveError::ManufacturingBackupUnavailable;
        if matches!(
            self.state.lock().unwrap().manufacturing_fault,
            ManufacturingFault::BackupUnavailable | ManufacturingFault::ErasedBackupUnavailable
        ) {
            return Err(unavailable);
        }
        let temporary = tempfile::tempdir().map_err(|_| unavailable)?;
        crate::migration::manufacturing_backup::persist_under(temporary.path(), device_id, bytes)
            .map_err(|_| unavailable)
    }
    /// Reports privileged command transport without unrelated host-volume mutations.
    fn capabilities(&self) -> PlatformCapabilities {
        PlatformCapabilities::try_new(true, true, true, true, false, false, false, false).unwrap()
    }

    /// Runs the real durable writer against private temporary storage, never /var/db.
    #[cfg(unix)]
    fn backup_manufacturing_record(
        &mut self,
        device_id: &crate::model::DeviceId,
        bytes: &[u8; 256],
    ) -> Result<(), crate::operations::HostPrimitiveError> {
        let unavailable = crate::operations::HostPrimitiveError::ManufacturingBackupUnavailable;
        let temporary = tempfile::tempdir().map_err(|_| unavailable)?;
        let root = temporary.path().canonicalize().map_err(|_| unavailable)?;
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))
            .map_err(|_| unavailable)?;
        let mut state = self.state.lock().unwrap();
        if matches!(
            state.manufacturing_fault,
            ManufacturingFault::BackupUnavailable | ManufacturingFault::ErasedBackupUnavailable
        ) {
            std::os::unix::fs::symlink(&root, root.join("manufacturing-backups"))
                .map_err(|_| unavailable)?;
        }
        let result = crate::migration::manufacturing_backup::persist_under(&root, device_id, bytes)
            .map_err(|_| unavailable);
        state.manufacturing_backups.push(temporary);
        result
    }

    /// Models macOS host-only refresh, which can hide a same-version restart.
    fn refresh_candidate_host_facts(
        &mut self,
        candidate: &CandidateDevice,
        previous: &CandidateDevice,
        previous_facts: Option<crate::operations::HostVolumeFacts>,
    ) -> Result<Option<crate::operations::HostVolumeFacts>, PlatformError> {
        if self.state.lock().unwrap().firmware_cache_discovery
            && candidate.token() == previous.token()
        {
            Ok(previous_facts)
        } else {
            Ok(None)
        }
    }

    /// Returns the same exact private reopen recipe for every reconnect poll.
    fn enumerate_candidates(&mut self) -> Result<Vec<CandidateDevice>, PlatformError> {
        let mut state = self.state.lock().unwrap();
        if let Some(opens) = state.post_reset_opens.as_mut() {
            // A new enumeration repairs the recipe; releasing its first probe
            // can invalidate it again before a second open of that same recipe.
            *opens = 0;
        }
        if let Some(remaining) = state.firmware_activation_scans {
            if remaining == 0 {
                state.firmware_revision = state.firmware_target_revision;
                state.firmware_activation_scans = None;
                state.post_reset_opens = Some(0);
            } else {
                state.firmware_activation_scans = Some(remaining - 1);
                if remaining == 1 {
                    return Ok(Vec::new());
                }
            }
        }
        Ok(vec![
            CandidateDevice::new(
                "mode-target",
                "/private/mode-target",
                CandidateMetadata::new(
                    Some("TANDBERG".to_owned()),
                    Some("RDX".to_owned()),
                    Some("MODETARGET".to_owned()),
                    Some(crate::host::DeviceInterface::Sata3),
                ),
            )
            .unwrap(),
        ])
    }

    /// Opens a fresh exact handle backed by the shared simulated dock state.
    fn open_candidate(
        &mut self,
        _candidate: &CandidateDevice,
    ) -> Result<CandidateLease, PlatformError> {
        let mut state = self.state.lock().unwrap();
        if let Some(opens) = state.post_reset_opens.as_mut() {
            *opens += 1;
            let resolving = *opens % 2 == 0;
            if resolving && state.firmware_rebind_failures > 0 {
                state.firmware_rebind_failures -= 1;
                return Err(PlatformError::DeviceRemoved);
            }
        }
        state.post_reset_inquiries = 0;
        drop(state);
        Ok(CandidateLease::new(ModeHandle {
            state: Arc::clone(&self.state),
        }))
    }
}

/// Exact retained command handle which applies only trusted mode-select payloads.
struct ModeHandle {
    state: Arc<Mutex<ModePlatformState>>,
}

impl PlatformDeviceHandle for ModeHandle {
    /// Responds to discovery/readback and applies the exact generated page-0x34 payload.
    fn execute(&mut self, command: &crate::protocol::Command) -> CommandDispatch {
        let mut state = self.state.lock().unwrap();
        state.commands.push(command.cdb().to_vec());
        if let Some(response) = manufacturing_fixture::response(&mut state, command.cdb()) {
            return response;
        }
        let bytes = match command.cdb() {
            [0x12, 0, 0, 0, 0xFE, 0] => {
                state.post_reset_inquiries += 1;
                if state.post_reset_opens.is_some()
                    && state.post_reset_inquiries == 2
                    && state.firmware_probe_failures > 0
                {
                    state.firmware_probe_failures -= 1;
                    return CommandDispatch::NotSent(crate::transport::TransportError::Unavailable);
                }
                mode_standard_inquiry(state.firmware_revision)
            }
            [0x12, 1, 0x83, 0, 0xFE, 0] => mode_device_identification(),
            [0x5A, 0, 0x31, 0, 0, 0, 0, 0, 0xFE, 0] => {
                vec![0x00, 0x0B, 0, 0, 0, 0, 0, 0, 0x31, 0x03, 0, 0, 0x18]
            }
            [0x5A, 0, 0x34, 0, 0, 0, 0, 0, 0xFE, 0] => vec![
                0x00,
                0x0D,
                0,
                0,
                0,
                0,
                0,
                0,
                0x34,
                0x05,
                0,
                0,
                state.drive_mode,
                0,
                state.sata_mode,
            ],
            [0x4D, 0, 0x20, 0, 0, 0, 0, 0, 0xFE, 0] => {
                vec![0x20, 0, 0, 8, 0, 5, 0, 4, 0, 0, 0, 0]
            }
            [0x55, _, 0, 0, 0, 0, 0, _, _, 0] => {
                let payload = command.data_out();
                state.drive_mode = payload[12] & 0x07;
                state.sata_mode = payload[14];
                Vec::new()
            }
            [0x1D, 0x05, 0, 0, 0, 0] => Vec::new(),
            [0x1D, 0x04, 0, 0, 0, 0] => Vec::new(),
            [0x1D, 0, 0, 0, 8, 0]
                if matches!(
                    command.data_out(),
                    [0x80, 0, 0, 4, 0, 0, 0, 0] | [0x80, 0, 0, 4, 0, 0, 0, 1]
                ) =>
            {
                Vec::new()
            }
            [0x3B, 0x04, _, _, _, _, _, _, _, _] if state.firmware_nonretryable_failure => {
                return CommandDispatch::NotSent(
                    crate::transport::TransportError::ResponseTooLarge {
                        maximum: 4096,
                        actual: 4097,
                    },
                );
            }
            [0x3B, 0x04, _, _, _, _, _, _, _, _] if state.firmware_transfer_failures > 0 => {
                state.firmware_transfer_failures -= 1;
                return CommandDispatch::NotSent(crate::transport::TransportError::Unavailable);
            }
            [0x3B, 0x04, _, _, _, _, _, _, _, _] => Vec::new(),
            [0x3B, 0x05, _, _, _, _, _, _, _, _] if state.firmware_finalize_unknown > 0 => {
                state.firmware_finalize_unknown -= 1;
                state.begin_firmware_activation();
                return CommandDispatch::CompletionUnknown(
                    crate::transport::TransportError::Unavailable,
                );
            }
            [0x3B, 0x05, _, _, _, _, _, _, _, _] => {
                state.begin_firmware_activation();
                Vec::new()
            }
            _ => return CommandDispatch::NotSent(crate::transport::TransportError::Unavailable),
        };
        CommandDispatch::Succeeded(TransportResponse::new(bytes).unwrap())
    }

    /// Proves the cartridge is absent before either configuration setter.
    fn host_volume_facts(
        &mut self,
    ) -> Result<crate::operations::HostVolumeFacts, crate::operations::PrimitiveFailure> {
        Ok(crate::operations::HostVolumeFacts {
            media_present: false,
            writable: false,
            mounted: false,
            free_bytes: 0,
            capacity_bytes: 0,
            filesystem: None,
            topology: crate::operations::VolumeTopology::Simple,
            media_fingerprint: None,
        })
    }
}

/// Builds a complete SATA III standard inquiry with drive-mode capability.
pub(super) fn mode_standard_inquiry(firmware_revision: u16) -> Vec<u8> {
    let mut bytes = vec![b' '; 43];
    bytes[0] = 0;
    bytes[4] = 38;
    bytes[8..16].copy_from_slice(b"TANDBERG");
    bytes[16..32].copy_from_slice(b"RDX             ");
    bytes[32..36].copy_from_slice(format!("{firmware_revision:04}").as_bytes());
    bytes[36] = 0x39;
    bytes[37..40].copy_from_slice(b"RDX");
    bytes[40] = 2;
    bytes[41] = 0x08;
    bytes[42] = 0x10;
    bytes
}

/// Builds the complete fixed-layout exact serial evidence.
pub(super) fn mode_device_identification() -> Vec<u8> {
    let mut bytes = vec![b' '; 42];
    bytes[0] = 0;
    bytes[1] = 0x83;
    bytes[2..4].copy_from_slice(&38_u16.to_be_bytes());
    bytes[8..16].copy_from_slice(b"TANDBERG");
    bytes[16..32].copy_from_slice(b"RDX             ");
    bytes[32..42].copy_from_slice(b"MODETARGET");
    bytes
}
