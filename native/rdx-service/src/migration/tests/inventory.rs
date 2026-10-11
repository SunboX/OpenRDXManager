// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Validated UI inventory tests use synthetic records and never read the fixed root.

use super::*;

/// Reads only synthetic files to detect any unintended inventory write.
fn snapshot(root: &std::path::Path) -> std::collections::BTreeMap<std::path::PathBuf, Vec<u8>> {
    let mut files = std::collections::BTreeMap::new();
    for entry in std::fs::read_dir(root).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            files.extend(snapshot(&path));
        } else {
            files.insert(path.clone(), std::fs::read(path).unwrap());
        }
    }
    files
}

/// Gets the test-only root, original identifier and synthetic release pin.
fn binding(prepared: &PreparedMigration) -> (std::path::PathBuf, String, String) {
    (
        prepared.artifact_directory().parent().unwrap().to_owned(),
        prepared
            .artifact_directory()
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned(),
        profile::digest(prepared.final_image()),
    )
}

/// Only validated original summaries expose the requested display serial and versions.
#[test]
fn inventory_exposes_closed_original_summary() {
    let (_temporary, mut original) = prepared_fixture();
    original.journal(MigrationEvent::RecoveryRequired).unwrap();
    let (root, name, release) = binding(&original);
    let before = snapshot(&root);
    let entries = storage::inventory::inventory(&root, &release).unwrap();
    assert_eq!(snapshot(&root), before);
    let json = serde_json::to_value(entries).unwrap();
    assert_eq!(
        json,
        serde_json::json!([{
            "status":"available", "bundleId":name, "serial":"000123456789",
            "displayLabel":"RDX 000123456789", "sourceVersion":"2.83", "targetVersion":"1.07",
            "lastState":"recovery-required", "completed":false, "recoveryNeeded":true
        }])
    );
}

/// Verified recovery copies update their original entry without becoming selectable origins.
#[test]
fn inventory_tracks_completed_copy_and_subsequent_failed_attempt() {
    let (_temporary, original) = prepared_fixture();
    let (root, name, release) = binding(&original);
    let mut resumed = PreparedMigration::begin_recovery_inner(&root, &name, &release).unwrap();
    resumed
        .journal(MigrationEvent::FinalUpdateVerified)
        .unwrap();
    let entries = storage::inventory::inventory(&root, &release).unwrap();
    assert_eq!(entries.len(), 1);
    let MigrationRecoveryInventoryEntry::Available(summary) = &entries[0] else {
        panic!("validated original");
    };
    assert_eq!(summary.bundle_id, name);
    assert!(summary.completed);
    assert!(!summary.recovery_needed);
    assert_eq!(summary.last_state, MigrationEvent::FinalUpdateVerified);
    let mut later = PreparedMigration::begin_recovery_inner(&root, &name, &release).unwrap();
    later.journal(MigrationEvent::RecoveryRequired).unwrap();
    let entries = storage::inventory::inventory(&root, &release).unwrap();
    let MigrationRecoveryInventoryEntry::Available(summary) = &entries[0] else {
        panic!("validated original");
    };
    assert!(summary.recovery_needed);
    assert!(!summary.completed);
}

/// Corrupt evidence yields a fixed reason without exposing unvalidated unit identity.
#[test]
fn inventory_contains_corrupt_bundle_failure_without_private_fields() {
    let (_temporary, original) = prepared_fixture();
    let (root, name, release) = binding(&original);
    std::fs::write(
        original.artifact_directory().join("capture.json"),
        b"private-corrupt-content",
    )
    .unwrap();
    let entries = storage::inventory::inventory(&root, &release).unwrap();
    assert_eq!(
        serde_json::to_value(entries).unwrap(),
        serde_json::json!([{
            "status":"unavailable", "bundleId":name, "reason":"migration-private-recovery-unavailable"
        }])
    );
}

/// One corrupt original cannot hide an independently validated different unit.
#[test]
fn inventory_preserves_valid_originals_beside_corrupt_entries() {
    let (_temporary, original) = prepared_fixture();
    let (root, _, release) = binding(&original);
    let mut source = capture();
    source.usb.serial = "000123456788".into();
    source.factory[16..26].copy_from_slice(&source.usb.serial.as_bytes()[2..]);
    let valid =
        PreparedMigration::prepare_inner(&root, source, original.final_image(), &release).unwrap();
    std::fs::write(
        original.artifact_directory().join("capture.json"),
        b"private-corrupt-content",
    )
    .unwrap();
    let entries = storage::inventory::inventory(&root, &release).unwrap();
    assert_eq!(entries.len(), 2);
    assert_eq!(
        entries
            .iter()
            .filter(|entry| matches!(entry, MigrationRecoveryInventoryEntry::Unavailable { .. }))
            .count(),
        1
    );
    let valid_name = valid
        .artifact_directory()
        .file_name()
        .unwrap()
        .to_str()
        .unwrap();
    assert!(entries.iter().any(|entry| matches!(entry, MigrationRecoveryInventoryEntry::Available(summary) if summary.bundle_id == valid_name && summary.serial == "000123456788")));
}

/// Missing fixed children are empty; unsafe existing directories are errors without repair.
#[test]
fn inventory_root_check_never_provisions_or_repairs() {
    use std::os::unix::fs::{PermissionsExt, symlink};
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().canonicalize().unwrap();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    let parent = std::fs::File::open(&root).unwrap();
    let owner = rustix::process::geteuid().as_raw();
    assert!(!storage::existing_root_under(&parent, owner).unwrap());
    assert!(std::fs::read_dir(&root).unwrap().next().is_none());
    storage::ensure_tree(&parent, owner).unwrap();
    assert!(storage::existing_root_under(&parent, owner).unwrap());
    let recovery = root.join("OpenRDXManager/recovery");
    std::fs::set_permissions(&recovery, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(storage::existing_root_under(&parent, owner).is_err());
    assert_eq!(
        std::fs::metadata(&recovery).unwrap().permissions().mode() & 0o7777,
        0o755
    );
    std::fs::remove_dir(&recovery).unwrap();
    symlink(&root, &recovery).unwrap();
    assert!(storage::existing_root_under(&parent, owner).is_err());
}

/// The original root inventory bound applies before extracting any UI identity.
#[test]
fn inventory_keeps_empty_and_excessive_roots_bounded() {
    use std::os::unix::fs::PermissionsExt;
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().canonicalize().unwrap();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert!(
        storage::inventory::inventory(&root, FINAL_RELEASE_SHA256)
            .unwrap()
            .is_empty()
    );
    for index in 0..65 {
        std::fs::create_dir(root.join(format!("migration-1-{index:x}"))).unwrap();
    }
    assert!(storage::inventory::inventory(&root, FINAL_RELEASE_SHA256).is_err());
}
