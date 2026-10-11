// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Synthetic private-record failures at the physical command boundary.

use super::*;

/// One deterministic failure injected into the actual firmware worker transport.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ManufacturingFault {
    #[default]
    None,
    WriteLatched,
    ReadinessRejected,
    Erased,
    ErasedChangedAfterBackup,
    ErasedChangedAfterWrite,
    ErasedChangedAfterFinalizer,
    ValidErasedAfterWrite,
    ErasedBackupUnavailable,
    BackupUnavailable,
    InvalidChecksum,
    PartiallyErased,
    ShortFirst,
    ShortSecond,
    Rejected,
    Unknown,
    IdentityChanged,
    ChangedAfterWrite,
    ChangedAfterFinalizer,
    UnreadableAfterWrite,
    UnreadableOnceAfterWrite,
    UnreadableAfterFinalizer,
}

impl ManufacturingFault {
    /// Identifies fixtures whose complete captured baseline is erased.
    fn starts_erased(self) -> bool {
        matches!(
            self,
            Self::Erased
                | Self::ErasedChangedAfterBackup
                | Self::ErasedChangedAfterWrite
                | Self::ErasedChangedAfterFinalizer
                | Self::ErasedBackupUnavailable
        )
    }
}

/// Answers only the two fixed reads, leaving the actual registry/worker intact.
pub(super) fn response(state: &mut ModePlatformState, cdb: &[u8]) -> Option<CommandDispatch> {
    if matches!(cdb, [0x3b, 2, 0x4d | 0x53, 0, 0, 1, 0, 0, 0, 0]) {
        if state.manufacturing_fault == ManufacturingFault::ReadinessRejected
            || (cdb[2] == 0x53 && state.manufacturing_fault == ManufacturingFault::WriteLatched)
        {
            return Some(CommandDispatch::DefinitelyRejected(
                TransportError::CheckCondition(
                    crate::protocol::SenseData::parse(&[0x72, 5, 0x24, 0, 0, 0, 0, 0]).unwrap(),
                ),
            ));
        }
        return Some(CommandDispatch::Succeeded(TransportResponse::empty()));
    }
    #[cfg(unix)]
    if cdb.starts_with(&[0x3b, 4]) && state.commands.iter().any(|command| command[0] == 0xe7) {
        require_durable_backup(state);
    }
    let offset = match cdb {
        [0xe7, 0, 3, 0xe0, 0, 128] => 0,
        [0xe7, 0, 3, 0xe0, 128, 128] => 128,
        _ => return None,
    };
    let fault = state.manufacturing_fault;
    let wrote = state.commands.iter().any(|cdb| cdb.starts_with(&[0x3b, 4]));
    let finalized = state.commands.iter().any(|cdb| cdb.starts_with(&[0x3b, 5]));
    let reads_after_write = state
        .commands
        .iter()
        .position(|cdb| cdb.starts_with(&[0x3b, 4]))
        .map_or(0, |index| {
            state.commands[index + 1..]
                .iter()
                .filter(|cdb| cdb[0] == 0xe7)
                .count()
        });
    if fault == ManufacturingFault::Rejected {
        let sense = crate::protocol::SenseData::parse(&[0x72, 5, 0x20, 0, 0, 0, 0, 0]).unwrap();
        return Some(CommandDispatch::DefinitelyRejected(
            crate::transport::TransportError::CheckCondition(sense),
        ));
    }
    if fault == ManufacturingFault::Unknown
        || (fault == ManufacturingFault::UnreadableAfterWrite && wrote && !finalized)
        || (fault == ManufacturingFault::UnreadableOnceAfterWrite
            && wrote
            && !finalized
            && reads_after_write == 1)
        || (fault == ManufacturingFault::UnreadableAfterFinalizer && finalized)
    {
        return Some(CommandDispatch::CompletionUnknown(
            crate::transport::TransportError::Timeout,
        ));
    }
    // A nonzero final byte proves the guard compares the second half too. These
    // checksums are literal hand-derived four-lane sums, not production helpers.
    let mut bytes = [0u8; 256];
    bytes[..4].copy_from_slice(&[0x78, 0x56, 0x34, 0x13]);
    bytes[255] = 1;
    let changed_erased = (fault == ManufacturingFault::ErasedChangedAfterBackup
        && state.commands.iter().filter(|cdb| cdb[0] == 0xe7).count() > 2)
        || (fault == ManufacturingFault::ErasedChangedAfterWrite && wrote)
        || (fault == ManufacturingFault::ErasedChangedAfterFinalizer && finalized);
    if (fault.starts_erased() && !changed_erased)
        || (fault == ManufacturingFault::ValidErasedAfterWrite && wrote)
    {
        bytes.fill(255);
    } else if fault == ManufacturingFault::PartiallyErased {
        bytes.fill(255);
        bytes[255] = 0;
    } else if fault == ManufacturingFault::InvalidChecksum {
        bytes[0] ^= 1;
    } else if (fault == ManufacturingFault::ChangedAfterWrite && wrote)
        || (fault == ManufacturingFault::ChangedAfterFinalizer && finalized)
    {
        bytes[255] = 2;
        bytes[3] = 0x14;
    }
    if fault == ManufacturingFault::IdentityChanged && offset == 128 {
        state.firmware_revision = 106;
    }
    let length = if (fault == ManufacturingFault::ShortFirst && offset == 0)
        || (fault == ManufacturingFault::ShortSecond && offset == 128)
    {
        127
    } else {
        128
    };
    Some(CommandDispatch::Succeeded(
        TransportResponse::new(bytes[offset..offset + length].to_vec()).unwrap(),
    ))
}

/// A guarded mutation must find the real complete private backup already on disk.
#[cfg(unix)]
fn require_durable_backup(state: &ModePlatformState) {
    use std::os::unix::fs::MetadataExt;
    let root = state
        .manufacturing_backups
        .last()
        .expect("backup must precede every write")
        .path();
    let entries: Vec<_> = std::fs::read_dir(root.join("manufacturing-backups"))
        .unwrap()
        .collect();
    assert_eq!(entries.len(), 1);
    let path = entries[0]
        .as_ref()
        .unwrap()
        .path()
        .join("manufacturing.bin");
    let bytes = std::fs::read(&path).unwrap();
    assert_eq!(bytes.len(), 256);
    let mut expected = [0u8; 256];
    expected[..4].copy_from_slice(&[0x78, 0x56, 0x34, 0x13]);
    expected[255] = 1;
    if state.manufacturing_fault.starts_erased() {
        expected.fill(255);
    } else if state.manufacturing_fault == ManufacturingFault::InvalidChecksum {
        expected[0] ^= 1;
    } else if state.manufacturing_fault == ManufacturingFault::PartiallyErased {
        expected.fill(255);
        expected[255] = 0;
    }
    assert_eq!(bytes, expected);
    assert_eq!(path.metadata().unwrap().mode() & 0o7777, 0o600);
}
