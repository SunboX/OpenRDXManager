// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Windows backup metadata validation over the private native filesystem boundary.

use super::MigrationError;
use crate::model::DeviceId;
use crate::service::manufacturing::{BackupRecord, BackupSummary};
use rdx_windows_native::manufacturing_storage::{BackupFile, ManufacturingStore};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::Zeroizing;

static NEXT: AtomicU64 = AtomicU64::new(0);

/// Prepares the fixed privileged Windows store without reading or writing a dock.
pub(crate) fn prepare_storage(_owner: Option<u32>) -> Result<(), MigrationError> {
    ManufacturingStore::open().map(|_| ()).map_err(unavailable)
}

/// Lists bounded independently validated records, newest first, across saved identities.
pub(crate) fn inventory(
    _device: &DeviceId,
    _owner: Option<u32>,
) -> Result<Vec<BackupSummary>, MigrationError> {
    let store = ManufacturingStore::open().map_err(unavailable)?;
    let mut records = Vec::new();
    for name in store.names().map_err(unavailable)? {
        if let Ok(record) = read_backup(&store, &name) {
            records.push(record.summary);
        }
    }
    records.sort_by(|left, right| {
        right
            .created_at
            .cmp(&left.created_at)
            .then_with(|| right.backup_id.cmp(&left.backup_id))
    });
    Ok(records)
}

/// Resolves only a generated immutable ID through the trusted native store.
pub(crate) fn load(id: &str, _owner: Option<u32>) -> Result<BackupRecord, MigrationError> {
    read_backup(&ManufacturingStore::open().map_err(unavailable)?, id)
}

/// Persists the exact raw pre-update identity, including damaged recovery evidence.
pub(crate) fn persist(
    device: &DeviceId,
    bytes: &[u8; 256],
    _owner: Option<u32>,
) -> Result<(), MigrationError> {
    persist_record(device, bytes, None)
}

/// Persists every byte of the current erase sector before a guarded restore.
pub(crate) fn persist_sector(
    device: &DeviceId,
    sector: &[u8; 4096],
    _owner: Option<u32>,
) -> Result<(), MigrationError> {
    persist_record(
        device,
        sector[..256].try_into().map_err(unavailable)?,
        Some(sector),
    )
}

/// Creates one new bundle and independently validates its manifest and content after flush.
fn persist_record(
    device: &DeviceId,
    bytes: &[u8; 256],
    sector: Option<&[u8; 4096]>,
) -> Result<(), MigrationError> {
    let store = ManufacturingStore::open().map_err(unavailable)?;
    persist_in(&store, device, bytes, sector)
}

/// Test workers use the same private writer under a disposable current-user root.
#[cfg(test)]
pub(crate) fn persist_under(
    root: &std::path::Path,
    device: &DeviceId,
    bytes: &[u8; 256],
) -> Result<(), MigrationError> {
    let store = ManufacturingStore::open_for_test(&root.join("manufacturing-backups"))
        .map_err(unavailable)?;
    persist_in(&store, device, bytes, None)
}

/// Shares exact publication/readback with production and isolated native worker tests.
fn persist_in(
    store: &ManufacturingStore,
    device: &DeviceId,
    bytes: &[u8; 256],
    sector: Option<&[u8; 4096]>,
) -> Result<(), MigrationError> {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(unavailable)?
        .as_nanos();
    let id = format!(
        "record-{timestamp:x}-{:x}",
        NEXT.fetch_add(1, Ordering::Relaxed)
    );
    let manifest = serde_json::to_vec(&serde_json::json!({
        "schemaVersion": 1, "kind": "openrdx-raw-manufacturing-backup",
        "deviceId": device, "address": 253952, "bytes": 256,
        "sha256": digest(bytes), "sectorSha256": sector.map(|sector| digest(sector)),
    }))
    .map_err(unavailable)?;
    store
        .persist(&id, bytes, sector, &manifest)
        .map_err(unavailable)?;
    let reopened = read_backup(store, &id)?;
    if reopened.summary.device_id != *device || reopened.bytes.as_ref() != bytes {
        return Err(MigrationError::StorageUnavailable);
    }
    Ok(())
}

/// Strict manifest compatible with the existing macOS record format.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Manifest {
    schema_version: u32,
    kind: String,
    device_id: DeviceId,
    address: u32,
    bytes: usize,
    sha256: String,
    sector_sha256: Option<String>,
}

/// Validates complete saved bytes without using manifest fields as filesystem paths.
fn read_backup(store: &ManufacturingStore, id: &str) -> Result<BackupRecord, MigrationError> {
    let manifest = store.read(id, BackupFile::Manifest).map_err(unavailable)?;
    let bytes = Zeroizing::new(store.read(id, BackupFile::Record).map_err(unavailable)?);
    let metadata: Manifest = serde_json::from_slice(&manifest).map_err(unavailable)?;
    let sector = if metadata.sector_sha256.is_some() {
        Some(Zeroizing::new(
            store.read(id, BackupFile::Sector).map_err(unavailable)?,
        ))
    } else {
        None
    };
    validate_record(id, metadata, &bytes, sector.as_deref().map(Vec::as_slice))
}

/// Checks schema, dock binding, record/sector lengths and checksums independently.
fn validate_record(
    id: &str,
    manifest: Manifest,
    bytes: &[u8],
    sector: Option<&[u8]>,
) -> Result<BackupRecord, MigrationError> {
    let (timestamp, sequence) = id
        .strip_prefix("record-")
        .and_then(|tail| tail.split_once('-'))
        .ok_or(MigrationError::StorageUnavailable)?;
    let timestamp = u128::from_str_radix(timestamp, 16).map_err(unavailable)?;
    let sequence = u64::from_str_radix(sequence, 16).map_err(unavailable)?;
    if id != format!("record-{timestamp:x}-{sequence:x}")
        || manifest.schema_version != 1
        || manifest.kind != "openrdx-raw-manufacturing-backup"
        || manifest.address != 0x3e000
        || manifest.bytes != 256
        || bytes.len() != 256
        || manifest.sha256 != digest(bytes)
    {
        return Err(MigrationError::StorageUnavailable);
    }
    match (manifest.sector_sha256, sector) {
        (None, None) => {}
        (Some(expected), Some(sector))
            if sector.len() == 4096 && sector[..256] == *bytes && digest(sector) == expected => {}
        _ => return Err(MigrationError::StorageUnavailable),
    }
    let bytes: Zeroizing<[u8; 256]> = Zeroizing::new(bytes.try_into().map_err(unavailable)?);
    let state = if bytes.iter().all(|byte| *byte == 0xff) {
        "erased"
    } else if crate::firmware::manufacturing::ManufacturingRecord::validate(bytes.clone()).is_ok() {
        "valid"
    } else {
        "corrupt"
    };
    let serial = if state == "valid" && bytes[8..18].iter().all(u8::is_ascii_digit) {
        Some(
            std::str::from_utf8(&bytes[8..18])
                .map_err(unavailable)?
                .to_owned(),
        )
    } else {
        None
    };
    Ok(BackupRecord {
        bytes,
        summary: BackupSummary {
            backup_id: id.to_owned(),
            created_at: u64::try_from(timestamp / 1_000_000).map_err(unavailable)?,
            state: state.to_owned(),
            device_id: manifest.device_id,
            serial,
        },
    })
}

/// Computes exact lowercase digest text; callers never log record bytes.
fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

/// Drops all underlying paths, access-control details and raw-record diagnostics.
fn unavailable<T>(_: T) -> MigrationError {
    MigrationError::StorageUnavailable
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The actual temporary path may contain Windows' RUNNER~1 ancestor alias.
    /// Durable publication and independent readback must retain the real private ACL.
    #[test]
    fn private_backup_round_trips_under_the_real_windows_temporary_path() {
        let root = tempfile::tempdir().unwrap();
        let device = DeviceId::new("rdx:synthetic-windows-backup").unwrap();
        let bytes = [0xff; 256];
        persist_under(root.path(), &device, &bytes).unwrap();
        let store =
            ManufacturingStore::open_for_test(&root.path().join("manufacturing-backups")).unwrap();
        let names = store.names().unwrap();
        assert_eq!(names.len(), 1);
        let reopened = read_backup(&store, &names[0]).unwrap();
        assert_eq!(reopened.bytes.as_ref(), &bytes);
        assert_eq!(reopened.summary.device_id, device);
        assert_eq!(reopened.summary.state, "erased");
    }

    /// Builds a synthetic erased-record manifest without any real device data.
    fn manifest(bytes: &[u8]) -> Manifest {
        serde_json::from_value(serde_json::json!({
            "schemaVersion": 1, "kind": "openrdx-raw-manufacturing-backup",
            "deviceId": "rdx:test", "address": 253952, "bytes": 256,
            "sha256": digest(bytes), "sectorSha256": null,
        }))
        .unwrap()
    }

    /// Damaged records remain evidence but cannot be mislabeled as valid identity.
    #[test]
    fn validates_raw_record_and_rejects_changed_manifest_or_bytes() {
        let bytes = [0xff; 256];
        assert_eq!(
            validate_record("record-100000-0", manifest(&bytes), &bytes, None)
                .unwrap()
                .summary
                .state,
            "erased"
        );
        assert!(validate_record("record-100000-0", manifest(&bytes), &[0; 256], None).is_err());
        let mut wrong = manifest(&bytes);
        wrong.address += 1;
        assert!(validate_record("record-100000-0", wrong, &bytes, None).is_err());
        assert!(validate_record("record-0100000-0", manifest(&bytes), &bytes, None).is_err());
    }

    /// A sector must have exact length, matching prefix and independently matching digest.
    #[test]
    fn requires_complete_matching_sector() {
        let sector = [0xff; 4096];
        let mut metadata = manifest(&sector[..256]);
        metadata.sector_sha256 = Some(digest(&sector));
        assert!(validate_record("record-1-0", metadata, &sector[..256], Some(&sector)).is_ok());
        let mut metadata = manifest(&sector[..256]);
        metadata.sector_sha256 = Some(digest(&sector));
        assert!(validate_record("record-1-0", metadata, &sector[..256], None).is_err());
    }
}
