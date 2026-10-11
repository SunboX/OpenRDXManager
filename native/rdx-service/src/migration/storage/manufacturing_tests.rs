// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Real filesystem persistence tests, with no device or privileged-system writes.

use super::*;
use std::os::unix::fs::{PermissionsExt, symlink};

/// Relocation moves original files, removes the old inventory, and remains idempotent with Finder metadata.
#[test]
fn manufacturing_relocation_leaves_one_store_and_preserves_original_inodes() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().canonicalize().unwrap();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    let parent = open_directory(&root, true).unwrap();
    let writer = rustix::process::geteuid().as_raw();
    let owner = if writer == 0 { 501 } else { writer };
    let source = user_storage::ensure_child(&parent, "legacy", writer).unwrap();
    let target = user_storage::ensure_child(&parent, "desktop", owner).unwrap();
    let device = crate::model::DeviceId::new("rdx:synthetic-relocation").unwrap();
    let sector = [0x37; 4096];
    persist_parent(
        &source,
        &device,
        sector[..256].try_into().unwrap(),
        Some(&sector),
    )
    .unwrap();
    let id = inventory_parent(&source, &device)
        .unwrap()
        .remove(0)
        .backup_id;
    let old_path = root
        .join("legacy/manufacturing-backups")
        .join(&id)
        .join("sector.bin");
    let inode = std::fs::metadata(&old_path).unwrap().ino();
    user_storage::relocate_from(&source, &target).unwrap();
    assert!(!root.join("legacy/manufacturing-backups").exists());
    let path = root
        .join("desktop/manufacturing-backups")
        .join(&id)
        .join("sector.bin");
    assert_eq!(std::fs::metadata(&path).unwrap().ino(), inode);
    assert_eq!(std::fs::metadata(&path).unwrap().uid(), owner);
    assert_eq!(std::fs::read(&path).unwrap(), sector);
    assert_eq!(
        read_backup(&target, &id).unwrap().bytes.as_ref(),
        &sector[..256]
    );
    std::fs::write(
        root.join("desktop/manufacturing-backups/.DS_Store"),
        b"finder metadata",
    )
    .unwrap();
    user_storage::relocate_from(&source, &target).unwrap();
    assert_eq!(inventory_parent(&target, &device).unwrap().len(), 1);
}

/// Interrupted writes and partial source cleanup remain movable without losing retained evidence.
#[test]
fn manufacturing_relocation_resumes_partial_records_and_cleanup() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().canonicalize().unwrap();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    let parent = open_directory(&root, true).unwrap();
    let writer = rustix::process::geteuid().as_raw();
    let owner = if writer == 0 { 501 } else { writer };
    let source = user_storage::ensure_child(&parent, "legacy", writer).unwrap();
    let target = user_storage::ensure_child(&parent, "desktop", owner).unwrap();
    let old = user_storage::ensure_child(&source, "manufacturing-backups", writer).unwrap();
    let new = user_storage::ensure_child(&target, "manufacturing-backups", owner).unwrap();
    // A failed write left an empty manufacturing file and no manifest.
    let incomplete = user_storage::ensure_child(&old, "record-1-1", writer).unwrap();
    write_file(&incomplete, "manufacturing.bin", &[]).unwrap();
    // An interrupted cross-volume cleanup removed manufacturing.bin but not the other files.
    let remaining = user_storage::ensure_child(&old, "record-2-1", writer).unwrap();
    write_file(&remaining, "manifest.json", b"retained metadata").unwrap();
    let published = user_storage::ensure_child(&new, "record-2-1", writer).unwrap();
    write_file(&published, "manufacturing.bin", &[0x37; 256]).unwrap();
    write_file(&published, "manifest.json", b"retained metadata").unwrap();
    // Unpublished staging is removable only because the original still exists.
    let staging = user_storage::ensure_child(&new, "moving-record-1-1", writer).unwrap();
    write_file(&staging, "manufacturing.bin", &[]).unwrap();
    user_storage::relocate_from(&source, &target).unwrap();
    assert!(!root.join("legacy/manufacturing-backups").exists());
    assert!(
        !root
            .join("desktop/manufacturing-backups/moving-record-1-1")
            .exists()
    );
    let moved = root.join("desktop/manufacturing-backups/record-1-1/manufacturing.bin");
    assert!(std::fs::read(&moved).unwrap().is_empty());
    assert_eq!(std::fs::metadata(&moved).unwrap().uid(), owner);
    assert_eq!(
        std::fs::read(root.join("desktop/manufacturing-backups/record-2-1/manufacturing.bin"))
            .unwrap(),
        [0x37; 256]
    );
    assert_eq!(
        std::fs::read(root.join("desktop/manufacturing-backups/record-2-1/manifest.json")).unwrap(),
        b"retained metadata"
    );
    user_storage::relocate_from(&source, &target).unwrap();
}

/// Colliding records with different bytes stop relocation and preserve both originals.
#[test]
fn manufacturing_relocation_never_overwrites_conflicting_records() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().canonicalize().unwrap();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    let parent = open_directory(&root, true).unwrap();
    let owner = rustix::process::geteuid().as_raw();
    let source = user_storage::ensure_child(&parent, "legacy", owner).unwrap();
    let target = user_storage::ensure_child(&parent, "desktop", owner).unwrap();
    for (service, bytes) in [
        (&source, b"original".as_slice()),
        (&target, b"different".as_slice()),
    ] {
        let store = user_storage::ensure_child(service, "manufacturing-backups", owner).unwrap();
        let record = user_storage::ensure_child(&store, "record-1-1", owner).unwrap();
        write_file(&record, "manufacturing.bin", bytes).unwrap();
    }
    assert!(user_storage::relocate_from(&source, &target).is_err());
    assert_eq!(
        std::fs::read(root.join("legacy/manufacturing-backups/record-1-1/manufacturing.bin"))
            .unwrap(),
        b"original"
    );
    assert_eq!(
        std::fs::read(root.join("desktop/manufacturing-backups/record-1-1/manufacturing.bin"))
            .unwrap(),
        b"different"
    );
}

/// Desktop storage owns the actual durable records, including writes by an elevated service.
#[test]
fn manufacturing_desktop_owner_gets_private_original_files() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().canonicalize().unwrap();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    let parent = open_directory(&root, true).unwrap();
    let owner = if rustix::process::geteuid().is_root() {
        501
    } else {
        rustix::process::geteuid().as_raw()
    };
    let service = user_storage::ensure_child(&parent, "desktop", owner).unwrap();
    // Application-data parents may be searchable; only the backup subtree is private.
    fs::fchmod(&service, Mode::from_raw_mode(0o755)).unwrap();
    let device = crate::model::DeviceId::new("rdx:synthetic-desktop").unwrap();
    let sector = [0x37; 4096];
    persist_parent(
        &service,
        &device,
        sector[..256].try_into().unwrap(),
        Some(&sector),
    )
    .unwrap();
    let records = inventory_parent(&service, &device).unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(
        read_backup(&service, &records[0].backup_id)
            .unwrap()
            .bytes
            .as_ref(),
        &sector[..256]
    );
    let directory = root
        .join("desktop/manufacturing-backups")
        .join(&records[0].backup_id);
    assert_eq!(std::fs::metadata(&directory).unwrap().uid(), owner);
    assert_eq!(std::fs::metadata(&directory).unwrap().mode() & 0o777, 0o700);
    for name in ["manufacturing.bin", "manifest.json", "sector.bin"] {
        let info = std::fs::metadata(directory.join(name)).unwrap();
        assert_eq!(info.uid(), owner);
        assert_eq!(info.mode() & 0o777, 0o600);
    }
    if rustix::process::geteuid().is_root() {
        let file = File::open(directory.join("sector.bin")).unwrap();
        fs::fchown(&file, Some(rustix::process::Uid::ROOT), None).unwrap();
        assert!(read_backup(&service, &records[0].backup_id).is_err());
    }
}

/// Inventory exposes only validated metadata and loading is bound to the selected dock.
#[test]
fn manufacturing_inventory_and_restore_selection_validate_the_complete_backup() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().canonicalize().unwrap();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    let device = crate::model::DeviceId::new("rdx:synthetic-backup").unwrap();
    let other = crate::model::DeviceId::new("rdx:other-dock").unwrap();
    let mut bytes = [0; 256];
    bytes[..4].copy_from_slice(&[0x78, 0x56, 0x34, 0x12]);
    persist_under(&root, &device, &bytes).unwrap();
    let parent = open_directory(&root, true).unwrap();
    let entries = inventory_parent(&parent, &device).unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].state, "valid");
    let id = &entries[0].backup_id;
    assert_eq!(load_parent(&parent, &device, id).unwrap().as_ref(), &bytes);
    assert!(load_parent(&parent, &other, id).is_err());
    assert!(load_parent(&parent, &device, "../escape").is_err());
    std::fs::write(
        root.join("manufacturing-backups")
            .join(id)
            .join("manufacturing.bin"),
        [0xff; 256],
    )
    .unwrap();
    assert!(load_parent(&parent, &device, id).is_err());
    assert!(inventory_parent(&parent, &device).unwrap().is_empty());
}

/// Recovery evidence includes damaged current records and all surrounding erase-sector bytes.
#[test]
fn manufacturing_sector_backup_preserves_corruption_and_validates_neighbors() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().canonicalize().unwrap();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    let device = crate::model::DeviceId::new("rdx:synthetic-backup").unwrap();
    let sector = [0x37; 4096];
    persist_sector_under(&root, &device, &sector).unwrap();
    let entries = inventory_under(&root, &device).unwrap();
    assert_eq!(entries[0].state, "corrupt");
    assert_eq!(
        load_under(&root, &entries[0].backup_id)
            .unwrap()
            .bytes
            .as_ref(),
        &sector[..256]
    );
    let path = root
        .join("manufacturing-backups")
        .join(&entries[0].backup_id)
        .join("sector.bin");
    let mut changed = sector;
    changed[4095] ^= 1;
    std::fs::write(path, changed).unwrap();
    assert!(load_under(&root, &entries[0].backup_id).is_err());
}

/// Repeated captures cannot bury the only valid source beyond the selectable history.
#[test]
fn manufacturing_history_keeps_older_valid_sources_reachable() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().canonicalize().unwrap();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    let device = crate::model::DeviceId::new("rdx:synthetic-backup").unwrap();
    let mut valid = [0u8; 256];
    valid[..4].copy_from_slice(&[0x78, 0x56, 0x34, 0x12]);
    persist_under(&root, &device, &valid).unwrap();
    for _ in 0..128 {
        persist_under(&root, &device, &[0xff; 256]).unwrap();
    }
    let all = inventory_under(&root, &device).unwrap();
    assert_eq!(all.len(), 129);
    let first = crate::service::manufacturing::BackupInventory::page(all, 0, true, true).unwrap();
    assert!(first.has_more);
    assert_eq!(first.backups.len(), 128);
    let older = crate::service::manufacturing::BackupInventory::page(
        inventory_under(&root, &device).unwrap(),
        1,
        true,
        true,
    )
    .unwrap();
    assert!(!older.has_more);
    assert_eq!(older.backups[0].state, "valid");
    assert_eq!(
        load_under(&root, &older.backups[0].backup_id)
            .unwrap()
            .bytes
            .as_ref(),
        &valid
    );
}

/// Each update preserves an independent complete backup and its private identity metadata.
#[test]
fn manufacturing_backup_is_complete_private_and_never_overwritten() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().canonicalize().unwrap();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    let device_id = crate::model::DeviceId::new("rdx:synthetic-backup").unwrap();
    let mut bytes = [0; 256];
    bytes[..4].copy_from_slice(&[0x78, 0x56, 0x34, 0x13]);
    bytes[255] = 1;
    persist_under(&root, &device_id, &bytes).unwrap();
    persist_under(&root, &device_id, &bytes).unwrap();
    let parent = root.join("manufacturing-backups");
    assert_eq!(parent.metadata().unwrap().mode() & 0o7777, 0o700);
    let entries: Vec<_> = std::fs::read_dir(&parent).unwrap().collect();
    assert_eq!(entries.len(), 2);
    for entry in entries {
        let directory = entry.unwrap().path();
        assert_eq!(directory.metadata().unwrap().mode() & 0o7777, 0o700);
        assert_eq!(
            std::fs::read(directory.join("manufacturing.bin")).unwrap(),
            bytes
        );
        let manifest: serde_json::Value =
            serde_json::from_slice(&std::fs::read(directory.join("manifest.json")).unwrap())
                .unwrap();
        assert_eq!(manifest["deviceId"], "rdx:synthetic-backup");
        assert_eq!(manifest["address"], 253952);
        assert_eq!(manifest["bytes"], 256);
        assert_eq!(manifest["sha256"], digest(&bytes));
        for name in ["manufacturing.bin", "manifest.json"] {
            let metadata = directory.join(name).metadata().unwrap();
            assert_eq!(metadata.mode() & 0o7777, 0o600);
            assert_eq!(metadata.uid(), rustix::process::geteuid().as_raw());
            assert_eq!(metadata.nlink(), 1);
        }
    }
}

/// Unsafe existing parents/children and symlinks fail without changing existing data.
#[test]
fn manufacturing_backup_rejects_unsafe_storage_without_repair() {
    for variant in 0..4 {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().canonicalize().unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let child = root.join("manufacturing-backups");
        match variant {
            0 => std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o755)).unwrap(),
            1 => {
                std::fs::create_dir(&child).unwrap();
                std::fs::set_permissions(&child, std::fs::Permissions::from_mode(0o755)).unwrap();
            }
            2 => symlink(&root, &child).unwrap(),
            _ => std::fs::write(&child, b"existing private evidence").unwrap(),
        }
        let device_id = crate::model::DeviceId::new("rdx:synthetic-backup").unwrap();
        assert_eq!(
            persist_under(&root, &device_id, &[0; 256]),
            Err(MigrationError::StorageUnavailable)
        );
        if variant == 1 {
            assert_eq!(child.metadata().unwrap().mode() & 0o7777, 0o755);
        }
        if variant == 3 {
            assert_eq!(std::fs::read(child).unwrap(), b"existing private evidence");
        }
    }
}

/// A privileged retry repairs only an empty private directory left between mkdir and chown.
#[test]
fn manufacturing_desktop_creation_resumes_empty_root_owned_directory() {
    if !rustix::process::geteuid().is_root() {
        return;
    }
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().canonicalize().unwrap();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    let parent = open_directory(&root, true).unwrap();
    let desktop = user_storage::ensure_child(&parent, "desktop", 501).unwrap();
    fs::mkdirat(&desktop, "manufacturing-backups", PRIVATE_DIRECTORY).unwrap();
    let resumed = user_storage::ensure_child(&desktop, "manufacturing-backups", 501).unwrap();
    assert_eq!(resumed.metadata().unwrap().uid(), 501);
    assert_eq!(resumed.metadata().unwrap().mode() & 0o7777, 0o700);
    let nonempty = user_storage::ensure_child(&desktop, "nonempty", 0).unwrap();
    write_file(&nonempty, "manufacturing.bin", b"root-owned evidence").unwrap();
    assert!(user_storage::ensure_child(&desktop, "nonempty", 501).is_err());
    assert_eq!(nonempty.metadata().unwrap().uid(), 0);
}
