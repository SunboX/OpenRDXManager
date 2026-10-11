// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Synthetic sector transport plus real owner-private storage for restore worker tests.

use super::*;
use crate::migration::manufacturing_backup as manufacturing;
use crate::operations::{HostPrimitiveError, HostVolumeFacts, PrimitiveFailure, VolumeTopology};
use crate::protocol::Command;
use crate::service::manufacturing::{BackupRecord, BackupSummary};
use crate::transport::TransportError;

/// One boundary fault applied to otherwise complete live evidence.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) enum RestoreFault {
    #[default]
    None,
    Unsupported,
    PhysicalCartridge,
    MechanismBusy,
    ShortChunk,
    IdentityChanged,
    BackupUnavailable,
    ChangedAfterBackup,
    ReadbackMismatch,
    ReadbackUnavailable,
    UnknownWrite,
}

/// Private test-only device/storage state; all record content is synthetic.
pub(crate) struct RestoreState {
    pub(crate) root: tempfile::TempDir,
    pub(crate) sector: [u8; 4096],
    pub(crate) fault: RestoreFault,
    pub(crate) commands: Vec<Vec<u8>>,
    pub(crate) writes: usize,
    pub(crate) revision: u16,
    pub(crate) media_present: bool,
    pub(crate) opens: usize,
    pub(crate) record_only: bool,
}

impl RestoreState {
    /// Creates a valid synthetic serial record surrounded by recognizable neighboring bytes.
    pub(crate) fn new() -> Self {
        use std::os::unix::fs::PermissionsExt;
        let root = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let mut sector = [0xa5; 4096];
        sector[..256].fill(0);
        sector[8..18].copy_from_slice(b"0123456789");
        sector[..4].copy_from_slice(&[0x14, 0xf5, 0x9c, 0x7c]);
        Self {
            root,
            sector,
            fault: RestoreFault::None,
            commands: Vec::new(),
            writes: 0,
            revision: 109,
            media_present: false,
            opens: 0,
            record_only: false,
        }
    }
}

/// Re-enumerable platform that retains the production worker and registry implementation.
pub(crate) struct RestorePlatform {
    pub(crate) state: Arc<Mutex<RestoreState>>,
}

impl PlatformBackend for RestorePlatform {
    /// Models an adapter whose closed command boundary allows only record reads.
    fn supports_manufacturing_sector_read(&self) -> bool {
        !self.state.lock().unwrap().record_only
    }

    /// Exposes only the capabilities needed for exact identity and fresh media facts.
    fn capabilities(&self) -> PlatformCapabilities {
        PlatformCapabilities::try_new(true, true, true, true, false, false, false, false).unwrap()
    }

    /// Enumerates one synthetic, stable unit without opening physical devices.
    fn enumerate_candidates(&mut self) -> Result<Vec<CandidateDevice>, PlatformError> {
        Ok(vec![
            CandidateDevice::new(
                "restore-target",
                "/synthetic/restore-target",
                CandidateMetadata::new(
                    Some("TANDBERG".to_owned()),
                    Some("RDX".to_owned()),
                    Some("0123456789".to_owned()),
                    Some(crate::host::DeviceInterface::Sata3),
                ),
            )
            .unwrap(),
        ])
    }

    /// Opens only an in-memory transport handle for the exact selected fixture.
    fn open_candidate(
        &mut self,
        _candidate: &CandidateDevice,
    ) -> Result<CandidateLease, PlatformError> {
        self.state.lock().unwrap().opens += 1;
        Ok(CandidateLease::new(RestoreHandle {
            state: Arc::clone(&self.state),
        }))
    }

    /// Runs the real full-sector writer before optionally simulating subsequent device drift.
    fn backup_manufacturing_sector(
        &mut self,
        device_id: &DeviceId,
        sector: &[u8; 4096],
    ) -> Result<(), HostPrimitiveError> {
        let mut state = self.state.lock().unwrap();
        if state.fault == RestoreFault::BackupUnavailable {
            return Err(HostPrimitiveError::ManufacturingBackupUnavailable);
        }
        manufacturing::persist_sector_under(state.root.path(), device_id, sector)
            .map_err(|_| HostPrimitiveError::ManufacturingBackupUnavailable)?;
        if state.fault == RestoreFault::ChangedAfterBackup {
            state.sector[4095] ^= 1;
        }
        Ok(())
    }

    /// Persists fixed record captures without granting full-sector read or restore authority.
    fn backup_manufacturing_record(
        &mut self,
        device_id: &DeviceId,
        bytes: &[u8; 256],
    ) -> Result<(), HostPrimitiveError> {
        let mut state = self.state.lock().unwrap();
        if state.fault == RestoreFault::BackupUnavailable {
            return Err(HostPrimitiveError::ManufacturingBackupUnavailable);
        }
        manufacturing::persist_under(state.root.path(), device_id, bytes)
            .map_err(|_| HostPrimitiveError::ManufacturingBackupUnavailable)?;
        if state.fault == RestoreFault::ChangedAfterBackup {
            state.sector[255] ^= 1;
        }
        Ok(())
    }

    /// Lists real persisted metadata under the fixture-owned directory only.
    fn manufacturing_backups(
        &mut self,
        device_id: &DeviceId,
    ) -> Result<Vec<BackupSummary>, HostPrimitiveError> {
        let state = self.state.lock().unwrap();
        manufacturing::inventory_under(state.root.path(), device_id)
            .map_err(|_| HostPrimitiveError::ManufacturingBackupUnavailable)
    }

    /// Loads and validates the selected immutable synthetic backup through production storage.
    fn load_manufacturing_backup(
        &mut self,
        backup_id: &str,
    ) -> Result<BackupRecord, HostPrimitiveError> {
        let state = self.state.lock().unwrap();
        manufacturing::load_under(state.root.path(), backup_id)
            .map_err(|_| HostPrimitiveError::ManufacturingBackupUnavailable)
    }
}

/// In-memory device boundary; every higher-level check remains production code.
struct RestoreHandle {
    state: Arc<Mutex<RestoreState>>,
}

impl PlatformDeviceHandle for RestoreHandle {
    /// Answers fixed discovery, physical-bay, and sector operations, with one explicit mutation.
    fn execute(&mut self, command: &Command) -> CommandDispatch {
        let mut state = self.state.lock().unwrap();
        state.commands.push(command.cdb().to_vec());
        let bytes = match command.cdb() {
            [0x12, 0, 0, 0, 0xfe, 0] => {
                let changed = state.fault == RestoreFault::IdentityChanged
                    && state.commands.iter().any(|cdb| cdb[0] == 0xe7);
                mode_standard_inquiry(if changed { 108 } else { state.revision })
            }
            [0x12, 1, 0x83, 0, 0xfe, 0] => {
                let mut bytes = mode_device_identification();
                bytes[32..42].copy_from_slice(b"0123456789");
                bytes
            }
            [0x5a, 0, 0x31, 0, 0, 0, 0, 0, 0xfe, 0] => {
                vec![0, 0x0b, 0, 0, 0, 0, 0, 0, 0x31, 3, 0, 0, 0x18]
            }
            [0x5a, 0, 0x34, 0, 0, 0, 0, 0, 0xfe, 0] => {
                vec![0, 0x0d, 0, 0, 0, 0, 0, 0, 0x34, 5, 0, 0, 1, 0, 2]
            }
            [0x4d, 0, 0x20, 0, 0, 0, 0, 0, 0xfe, 0] => vec![0x20, 0, 0, 8, 0, 5, 0, 4, 0, 0, 0, 0],
            [0xe8, 0, 0, 0, 0, 128] => {
                let mut bytes = vec![0; 128];
                bytes[..4].copy_from_slice(b"RDXM");
                bytes[4] = 1;
                bytes[5] = u8::from(state.fault == RestoreFault::MechanismBusy);
                bytes[10] = if state.fault == RestoreFault::PhysicalCartridge {
                    0
                } else {
                    0x20
                };
                bytes
            }
            [0xe7, 0, 3, high, low, 128]
                if (0xe0..=0xef).contains(high) && matches!(low, 0 | 128) =>
            {
                let offset = usize::from(*high - 0xe0) * 256 + usize::from(*low);
                let length = if (state.fault == RestoreFault::ShortChunk
                    || (state.fault == RestoreFault::ReadbackUnavailable && state.writes != 0))
                    && offset == 3968
                {
                    127
                } else {
                    128
                };
                state.sector[offset..offset + length].to_vec()
            }
            [0x3b, 2, 0x4d, 0, 0, 1, 0, 0, 0, 0] => {
                if state.fault == RestoreFault::Unsupported {
                    return CommandDispatch::DefinitelyRejected(TransportError::CheckCondition(
                        crate::protocol::SenseData::parse(&[0x72, 5, 0x20, 0, 0, 0, 0, 0]).unwrap(),
                    ));
                }
                vec![]
            }
            [0x3b, 2, 0x4d, 0, 0, 0, 0, 2, 0x10, 0] => {
                let data = command.data_out();
                assert_eq!(data.len(), 528);
                assert_eq!(&data[..8], b"RDXMFG01");
                assert_eq!(
                    &data[8..12],
                    crate::serial_record::crc32(&state.sector).to_le_bytes()
                );
                assert_eq!(data[12..16], [0; 4]);
                assert_eq!(data[16..272], state.sector[..256]);
                require_durable_sector_backup(&state);
                state.writes += 1;
                state.sector[..256].copy_from_slice(&data[272..]);
                if state.fault == RestoreFault::ReadbackMismatch {
                    state.sector[4095] ^= 1;
                }
                if state.fault == RestoreFault::UnknownWrite {
                    return CommandDispatch::CompletionUnknown(TransportError::Timeout);
                }
                vec![]
            }
            _ => return CommandDispatch::NotSent(TransportError::Unavailable),
        };
        CommandDispatch::Succeeded(TransportResponse::new(bytes).unwrap())
    }

    /// Supplies fresh host media facts independently of physical-bay diagnostics.
    fn host_volume_facts(&mut self) -> Result<HostVolumeFacts, PrimitiveFailure> {
        let media_present = self.state.lock().unwrap().media_present;
        Ok(HostVolumeFacts {
            media_present,
            writable: false,
            mounted: false,
            free_bytes: 0,
            capacity_bytes: 0,
            filesystem: None,
            topology: VolumeTopology::Simple,
            media_fingerprint: media_present.then_some([0xA5; 32]),
        })
    }
}

/// Requires an actual complete pre-write sector file, including private permissions and neighbors.
fn require_durable_sector_backup(state: &RestoreState) {
    use std::os::unix::fs::MetadataExt;
    let parent = state.root.path().join("manufacturing-backups");
    assert!(
        std::fs::read_dir(parent).unwrap().any(|entry| {
            let path = entry.unwrap().path().join("sector.bin");
            std::fs::read(&path).is_ok_and(|bytes| {
                bytes == state.sector && path.metadata().unwrap().mode() & 0o7777 == 0o600
            })
        }),
        "complete exact sector must already be durably backed up before mutation"
    );
}
