// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Durable raw backups kept outside the pinned migration-recovery inventory.

use super::*;
#[path = "manufacturing_user_storage.rs"]
mod user_storage;
use user_storage::{ensure_child, open_child, read_file, validate_directory, write_file};
#[cfg(target_os = "linux")]
#[path = "manufacturing_linux_storage.rs"]
mod linux_storage;

/// Uses the fixed root-owned Linux store; desktop ownership is not accepted.
#[cfg(target_os = "linux")]
fn service_directory(owner: Option<u32>) -> Result<File, MigrationError> {
    if owner.is_some() {
        return Err(MigrationError::StorageUnavailable);
    }
    linux_storage::service_directory()
}

/// Prepares the sole backup store without requiring a connected dock.
#[cfg(any(target_os = "macos", target_os = "linux"))]
pub(crate) fn prepare_storage(owner: Option<u32>) -> Result<(), MigrationError> {
    service_directory(owner).map(|_| ())
}

/// Lists a bounded, independently verified inventory for one exact dock.
#[cfg(any(target_os = "macos", target_os = "linux"))]
pub(crate) fn inventory(
    device_id: &crate::model::DeviceId,
    owner: Option<u32>,
) -> Result<Vec<crate::service::manufacturing::BackupSummary>, MigrationError> {
    inventory_parent(&service_directory(owner)?, device_id)
}

/// Uses one macOS desktop-owned store, relocating legacy records before any operation.
#[cfg(target_os = "macos")]
fn service_directory(owner: Option<u32>) -> Result<File, MigrationError> {
    if rustix::process::geteuid().as_raw() != 0 {
        return Err(MigrationError::StorageUnavailable);
    }
    let owner = owner.ok_or(MigrationError::StorageUnavailable)?;
    let service = user_storage::desktop_directory(owner)?;
    user_storage::move_legacy_backups(&service)?;
    Ok(service)
}

/// Loads a selected immutable record; the ID can never designate an arbitrary path.
#[cfg(any(target_os = "macos", target_os = "linux"))]
pub(crate) fn load(
    backup_id: &str,
    owner: Option<u32>,
) -> Result<crate::service::manufacturing::BackupRecord, MigrationError> {
    read_backup(&service_directory(owner)?, backup_id)
}

/// Strict on-disk metadata, retaining compatibility with existing automatic backups.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Manifest {
    schema_version: u32,
    kind: String,
    device_id: crate::model::DeviceId,
    address: u32,
    bytes: usize,
    sha256: String,
    sector_sha256: Option<String>,
}

/// Parses only canonical generated names and returns their creation time in milliseconds.
fn creation_time(name: &str) -> Result<u64, MigrationError> {
    let (timestamp, sequence) = name
        .strip_prefix("record-")
        .and_then(|value| value.split_once('-'))
        .ok_or(MigrationError::StorageUnavailable)?;
    let timestamp = u128::from_str_radix(timestamp, 16).map_err(storage_error)?;
    let sequence = u64::from_str_radix(sequence, 16).map_err(storage_error)?;
    if name != format!("record-{timestamp:x}-{sequence:x}") {
        return Err(MigrationError::StorageUnavailable);
    }
    u64::try_from(timestamp / 1_000_000).map_err(storage_error)
}

/// Checks private ownership, exact record length, digest and original dock binding.
fn read_backup(
    service: &File,
    backup_id: &str,
) -> Result<crate::service::manufacturing::BackupRecord, MigrationError> {
    let created_at = creation_time(backup_id)?;
    validate_owned_directory(service, service.metadata().map_err(storage_error)?.uid())?;
    let parent = open_child(service, "manufacturing-backups")?;
    let directory = open_child(&parent, backup_id)?;
    let manifest: Manifest =
        serde_json::from_slice(&read_file(&directory, "manifest.json", MAX_METADATA)?)
            .map_err(storage_error)?;
    let bytes = zeroize::Zeroizing::new(read_file(&directory, "manufacturing.bin", 256)?);
    if manifest.schema_version != 1
        || manifest.kind != "openrdx-raw-manufacturing-backup"
        || manifest.address != 0x3e000
        || manifest.bytes != 256
        || bytes.len() != 256
        || manifest.sha256 != digest(&bytes)
    {
        return Err(MigrationError::StorageUnavailable);
    }
    let bytes: zeroize::Zeroizing<[u8; 256]> =
        zeroize::Zeroizing::new(bytes.as_slice().try_into().map_err(storage_error)?);
    if let Some(expected) = manifest.sector_sha256 {
        let sector = zeroize::Zeroizing::new(read_file(&directory, "sector.bin", 4096)?);
        if sector.len() != 4096 || sector[..256] != bytes[..] || digest(&sector) != expected {
            return Err(MigrationError::StorageUnavailable);
        }
    }
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
                .map_err(storage_error)?
                .to_owned(),
        )
    } else {
        None
    };
    Ok(crate::service::manufacturing::BackupRecord {
        bytes,
        summary: crate::service::manufacturing::BackupSummary {
            backup_id: backup_id.to_owned(),
            created_at,
            state: state.to_owned(),
            device_id: manifest.device_id,
            serial,
        },
    })
}

/// Test-only exact identity lookup also proves that a filename alone is not dock authority.
#[cfg(test)]
fn load_parent(
    service: &File,
    device_id: &crate::model::DeviceId,
    backup_id: &str,
) -> Result<zeroize::Zeroizing<[u8; 256]>, MigrationError> {
    let record = read_backup(service, backup_id)?;
    if &record.summary.device_id != device_id {
        return Err(MigrationError::StorageUnavailable);
    }
    Ok(record.bytes)
}

/// Enumerates at most 4096 retained backups; the service paginates verified metadata.
fn inventory_parent(
    service: &File,
    _device_id: &crate::model::DeviceId,
) -> Result<Vec<crate::service::manufacturing::BackupSummary>, MigrationError> {
    validate_owned_directory(service, service.metadata().map_err(storage_error)?.uid())?;
    let parent = ensure_child(
        service,
        "manufacturing-backups",
        service.metadata().map_err(storage_error)?.uid(),
    )?;
    let mut entries = Vec::new();
    let mut count = 0;
    for entry in fs::Dir::read_from(&parent).map_err(storage_error)? {
        let entry = entry.map_err(storage_error)?;
        let name = entry.file_name().to_bytes();
        if name == b"." || name == b".." {
            continue;
        }
        count += 1;
        if count > 4096 {
            return Err(MigrationError::StorageUnavailable);
        }
        let Ok(name) = std::str::from_utf8(name) else {
            continue;
        };
        let Ok(record) = read_backup(service, name) else {
            continue;
        };
        entries.push(record.summary);
    }
    entries.sort_by(|left, right| {
        right
            .created_at
            .cmp(&left.created_at)
            .then_with(|| right.backup_id.cmp(&left.backup_id))
    });
    Ok(entries)
}

/// Persists only below checked platform-owned private ancestry.
#[cfg(any(target_os = "macos", target_os = "linux"))]
pub(crate) fn persist(
    device_id: &crate::model::DeviceId,
    bytes: &[u8; 256],
    owner: Option<u32>,
) -> Result<(), MigrationError> {
    if rustix::process::geteuid().as_raw() != 0 {
        return Err(MigrationError::StorageUnavailable);
    }
    let service = service_directory(owner)?;
    persist_parent(&service, device_id, bytes, None)
}

/// Saves the entire erase sector before a restore so interrupted writes retain all evidence.
#[cfg(any(target_os = "macos", target_os = "linux"))]
pub(crate) fn persist_sector(
    device_id: &crate::model::DeviceId,
    sector: &[u8; 4096],
    owner: Option<u32>,
) -> Result<(), MigrationError> {
    persist_parent(
        &service_directory(owner)?,
        device_id,
        sector[..256].try_into().map_err(storage_error)?,
        Some(sector),
    )
}

/// Anchors synthetic worker/storage tests in a real private temporary directory.
#[cfg(test)]
pub(crate) fn persist_under(
    root: &Path,
    device_id: &crate::model::DeviceId,
    bytes: &[u8; 256],
) -> Result<(), MigrationError> {
    persist_parent(&open_directory(root, true)?, device_id, bytes, None)
}

/// Synthetic worker tests use real durable storage without privileged system writes.
#[cfg(test)]
pub(crate) fn persist_sector_under(
    root: &Path,
    device_id: &crate::model::DeviceId,
    sector: &[u8; 4096],
) -> Result<(), MigrationError> {
    persist_parent(
        &open_directory(root, true)?,
        device_id,
        sector[..256].try_into().map_err(storage_error)?,
        Some(sector),
    )
}

/// Synthetic worker inventory uses the same independent file validation as production.
#[cfg(test)]
pub(crate) fn inventory_under(
    root: &Path,
    device_id: &crate::model::DeviceId,
) -> Result<Vec<crate::service::manufacturing::BackupSummary>, MigrationError> {
    inventory_parent(&open_directory(root, true)?, device_id)
}

/// Synthetic restore selection uses the same immutable artifact reader as production.
#[cfg(test)]
pub(crate) fn load_under(
    root: &Path,
    backup_id: &str,
) -> Result<crate::service::manufacturing::BackupRecord, MigrationError> {
    read_backup(&open_directory(root, true)?, backup_id)
}

/// Exclusively creates, syncs and independently reopens a complete private backup.
/// No serial or caller-controlled filename enters the pathname, and no existing
/// artifact is overwritten or repaired. Incomplete creation remains a failure.
fn persist_parent(
    service: &File,
    device_id: &crate::model::DeviceId,
    bytes: &[u8; 256],
    sector: Option<&[u8; 4096]>,
) -> Result<(), MigrationError> {
    let parent = ensure_child(
        service,
        "manufacturing-backups",
        service.metadata().map_err(storage_error)?.uid(),
    )?;
    validate_directory(&parent)?;
    // Never create an artifact that falls outside the bounded, pageable inventory.
    // Full storage blocks updates instead of silently discarding recovery history.
    let mut existing = 0;
    for entry in fs::Dir::read_from(&parent).map_err(storage_error)? {
        let entry = entry.map_err(storage_error)?;
        if ![b".".as_slice(), b"..".as_slice()].contains(&entry.file_name().to_bytes()) {
            existing += 1;
            if existing >= 4096 {
                return Err(MigrationError::StorageUnavailable);
            }
        }
    }
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(storage_error)?
        .as_nanos();
    let name = format!(
        "record-{timestamp:x}-{:x}",
        NEXT_BUNDLE.fetch_add(1, Ordering::Relaxed)
    );
    fs::mkdirat(&parent, name.as_str(), PRIVATE_DIRECTORY).map_err(storage_error)?;
    let directory = File::from(
        fs::openat(
            &parent,
            name.as_str(),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(storage_error)?,
    );
    fs::fchmod(&directory, PRIVATE_DIRECTORY).map_err(storage_error)?;
    user_storage::inherit_owner(&directory, &parent)?;
    validate_directory(&directory)?;
    let manifest = serde_json::to_vec(&serde_json::json!({
        "schemaVersion": 1,
        "kind": "openrdx-raw-manufacturing-backup",
        "deviceId": device_id,
        "address": 253952,
        "bytes": 256,
        "sha256": digest(bytes),
        "sectorSha256": sector.map(|bytes| digest(bytes)),
    }))
    .map_err(storage_error)?;
    write_file(&directory, "manufacturing.bin", bytes)?;
    if let Some(sector) = sector {
        write_file(&directory, "sector.bin", sector)?;
    }
    directory.sync_all().map_err(storage_error)?;
    write_file(&directory, "manifest.json", &manifest)?;
    directory.sync_all().map_err(storage_error)?;
    parent.sync_all().map_err(storage_error)?;
    drop(directory);
    let reopened = open_child(&parent, &name)?;
    if read_file(&reopened, "manufacturing.bin", 256)? != bytes
        || read_file(&reopened, "manifest.json", MAX_METADATA)? != manifest
    {
        return Err(MigrationError::StorageUnavailable);
    }
    if let Some(sector) = sector
        && read_file(&reopened, "sector.bin", 4096)? != sector
    {
        return Err(MigrationError::StorageUnavailable);
    }
    Ok(())
}

#[cfg(test)]
#[path = "manufacturing_tests.rs"]
mod tests;
