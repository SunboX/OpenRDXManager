// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Cold recovery inspection uses only synthetic private temporary artifacts.

use super::*;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Records every synthetic file so read-only loading can prove byte preservation.
fn files(root: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    let mut result = BTreeMap::new();
    for entry in std::fs::read_dir(root).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            result.extend(files(&path));
        } else {
            result.insert(path.clone(), std::fs::read(path).unwrap());
        }
    }
    result
}

/// Obtains only test-owned root/name/release facts without exposing unit fields.
fn binding(prepared: &PreparedMigration) -> (PathBuf, String, String) {
    (
        prepared
            .artifact_directory()
            .parent()
            .unwrap()
            .to_path_buf(),
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

/// Cold loading retains exact saved bytes and cannot append to the original journal.
#[test]
fn cold_load_preserves_every_artifact_and_closes_original_writer() {
    let (_temporary, mut original) = prepared_fixture();
    original.journal(MigrationEvent::RomResetAccepted).unwrap();
    let (root, name, release) = binding(&original);
    let before = files(&root);
    let mut loaded = PreparedMigration::load_inner(&root, &name, &release).unwrap();
    assert!(loaded.capture() == original.capture());
    assert_eq!(loaded.bootstrap(), original.bootstrap());
    assert_eq!(loaded.final_image(), original.final_image());
    assert_eq!(loaded.artifact_directory(), original.artifact_directory());
    assert_eq!(
        loaded.journal(MigrationEvent::RecoveryRequired),
        Err(MigrationError::StorageUnavailable)
    );
    assert_eq!(files(&root), before);
}

/// Status exposes only a bounded identifier, closed events and integrity boolean.
#[test]
fn cold_status_contains_no_unit_records_or_artifact_digests() {
    let (_temporary, mut original) = prepared_fixture();
    original
        .journal(MigrationEvent::AwaitingBootstrapPowerCycle)
        .unwrap();
    let (root, name, release) = binding(&original);
    let before = files(&root);
    let status = storage::loader::status(&root, &release).unwrap();
    assert_eq!(
        serde_json::to_value(&status).unwrap(),
        serde_json::json!([{
            "bundleId": name,
            "events": ["prepared", "awaiting-bootstrap-power-cycle"],
            "integrity": true
        }])
    );
    assert_eq!(files(&root), before);
}

/// A truncated journal is preserved and never yields trusted milestones.
#[test]
fn cold_status_retains_and_rejects_partial_journal() {
    let (_temporary, original) = prepared_fixture();
    let (root, name, release) = binding(&original);
    let journal = root.join(format!("{name}.journal.jsonl"));
    let mut bytes = std::fs::read(&journal).unwrap();
    bytes.pop();
    std::fs::write(journal, bytes).unwrap();
    let before = files(&root);
    assert!(PreparedMigration::load_inner(&root, &name, &release).is_err());
    let status = storage::loader::status(&root, &release).unwrap();
    assert_eq!(
        serde_json::to_value(status).unwrap(),
        serde_json::json!([{
            "bundleId": name, "events": [], "integrity": false
        }])
    );
    assert_eq!(files(&root), before);
}

/// A caller cannot convert the opaque identifier into a filesystem path.
#[test]
fn cold_loader_rejects_paths_and_noncanonical_bundle_ids() {
    let (_temporary, original) = prepared_fixture();
    let (root, name, release) = binding(&original);
    for invalid in [
        "",
        "..",
        "/private",
        "migration-a-b/c",
        "migration-00-0",
        "migration-A-0",
        "migration-1-00",
        "migration-1-0.receipt.json",
    ] {
        assert!(PreparedMigration::load_inner(&root, invalid, &release).is_err());
    }
    assert!(PreparedMigration::load_inner(&root, &name, FINAL_RELEASE_SHA256).is_err());
}

/// Every journal field, sequence and full-prefix hash is checked after a restart.
#[test]
fn cold_loader_rejects_tampered_journal_chains() {
    let mutations: &[fn(&str) -> String] = &[
        |text| text.replacen("\"schema_version\":1", "\"schema_version\":2", 1),
        |text| text.replacen("\"sequence\":1", "\"sequence\":2", 1),
        |text| text.replacen("prepared", "recovery-required", 1),
        |text| text.replacen("recovery-required", "prepared", 1),
        |text| text.replacen("recovery-required", "unknown-event", 1),
        |text| text.replacen("\"receipt_sha256\":\"", "\"receipt_sha256\":\"0", 1),
        |text| text.replacen("\"previous_sha256\":\"", "\"previous_sha256\":\"0", 1),
        |text| text.replacen("{", "{\"unknown\":1,", 1),
        |text| text.replacen("{", "{\"schema_version\":1,", 1),
        |text| format!("{text}\n"),
        |text| text.split_once('\n').unwrap().1.to_owned(),
    ];
    for mutate in mutations {
        let (_temporary, mut original) = prepared_fixture();
        original.journal(MigrationEvent::RecoveryRequired).unwrap();
        let (root, name, release) = binding(&original);
        let path = root.join(format!("{name}.journal.jsonl"));
        let text = std::fs::read_to_string(&path).unwrap();
        std::fs::write(path, mutate(&text)).unwrap();
        assert!(PreparedMigration::load_inner(&root, &name, &release).is_err());
        assert!(!storage::loader::status(&root, &release).unwrap()[0].integrity);
    }
}

/// Missing evidence remains discoverable as an incomplete set instead of disappearing.
#[test]
fn cold_status_reports_partial_sets_and_rejects_unknown_root_entries() {
    let (_temporary, original) = prepared_fixture();
    let (root, name, release) = binding(&original);
    std::fs::remove_file(root.join(format!("{name}.receipt.json"))).unwrap();
    let status = storage::loader::status(&root, &release).unwrap();
    assert_eq!(status.len(), 1);
    assert!(!status[0].integrity);
    assert!(status[0].events.is_empty());
    std::fs::write(root.join("unexpected-private-name"), b"synthetic").unwrap();
    assert!(storage::loader::status(&root, &release).is_err());
}

/// Cold inspection rejects symlinks, hardlinks and widened permissions without repair.
#[test]
fn cold_loader_rejects_aliased_and_nonprivate_evidence() {
    use std::os::unix::fs::{PermissionsExt, symlink};
    for mutation in 0..3 {
        let (_temporary, original) = prepared_fixture();
        let (root, name, release) = binding(&original);
        let path = original.artifact_directory().join("migration-package.bin");
        let external = root.parent().unwrap().join(format!("{name}-external"));
        match mutation {
            0 => {
                std::fs::rename(&path, &external).unwrap();
                symlink(&external, &path).unwrap();
            }
            1 => std::fs::hard_link(&path, &external).unwrap(),
            _ => std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap(),
        }
        assert!(PreparedMigration::load_inner(&root, &name, &release).is_err());
        assert!(!storage::loader::status(&root, &release).unwrap()[0].integrity);
        if mutation != 2 {
            std::fs::remove_file(external).unwrap();
        }
    }
}

/// Resource bounds hold for journals and root inventories before large allocations.
#[test]
fn cold_inspection_rejects_excessive_inventory_and_journal() {
    let (_temporary, original) = prepared_fixture();
    let (root, name, release) = binding(&original);
    let journal = root.join(format!("{name}.journal.jsonl"));
    std::fs::write(journal, vec![b'\n'; 65537]).unwrap();
    assert!(PreparedMigration::load_inner(&root, &name, &release).is_err());
    for index in 0..64 {
        std::fs::create_dir(root.join(format!("migration-1-{index:x}"))).unwrap();
    }
    assert!(storage::loader::status(&root, &release).is_err());
}

/// Every manifest-bound artifact is checked during an independent cold read.
#[test]
fn cold_loader_requires_original_receipt_and_every_artifact() {
    for relative in [
        "capture.json",
        "migration-package.bin",
        "migration-bootstrap.rom.bin",
        "OpenRDX-v1-07.bin",
        "migration-template.rom.bin",
        "bootstrap-build-evidence.json",
        "bundle.json",
    ] {
        let (_temporary, original) = prepared_fixture();
        let (root, name, release) = binding(&original);
        let path = original.artifact_directory().join(relative);
        let mut bytes = std::fs::read(&path).unwrap();
        bytes[0] ^= 1;
        std::fs::write(path, bytes).unwrap();
        assert!(PreparedMigration::load_inner(&root, &name, &release).is_err());
        assert!(!storage::loader::status(&root, &release).unwrap()[0].integrity);
    }
}

/// Receipt schema, bundle binding and canonical bytes cannot be substituted on restart.
#[test]
fn cold_loader_rejects_receipt_substitution() {
    for mutation in 0..4 {
        let (_temporary, original) = prepared_fixture();
        let (root, name, release) = binding(&original);
        let path = root.join(format!("{name}.receipt.json"));
        let text = std::fs::read_to_string(&path).unwrap();
        let changed = match mutation {
            0 => text.replacen("\"schema_version\":1", "\"schema_version\":2", 1),
            1 => text.replacen(&name, "migration-1-0", 1),
            2 => text.replacen("\"manifest_sha256\":\"", "\"manifest_sha256\":\"0", 1),
            _ => format!("{text}\n"),
        };
        std::fs::write(path, changed).unwrap();
        assert!(PreparedMigration::load_inner(&root, &name, &release).is_err());
        assert!(!storage::loader::status(&root, &release).unwrap()[0].integrity);
    }
}

/// A recovery attempt copies exact artifacts and has a separately writable journal.
#[test]
fn recovery_copy_preserves_original_and_binds_its_receipt() {
    let (_temporary, mut original) = prepared_fixture();
    original.journal(MigrationEvent::RecoveryRequired).unwrap();
    let (root, name, release) = binding(&original);
    let before = files(&root);
    let mut resumed = PreparedMigration::begin_recovery_inner(&root, &name, &release).unwrap();
    let (_, new_name, _) = binding(&resumed);
    assert_ne!(new_name, name);
    for (path, bytes) in before {
        assert_eq!(std::fs::read(path).unwrap(), bytes);
    }
    for entry in std::fs::read_dir(original.artifact_directory()).unwrap() {
        let entry = entry.unwrap();
        assert_eq!(
            std::fs::read(entry.path()).unwrap(),
            std::fs::read(resumed.artifact_directory().join(entry.file_name())).unwrap()
        );
    }
    let receipt: serde_json::Value = serde_json::from_slice(
        &std::fs::read(root.join(format!("{new_name}.receipt.json"))).unwrap(),
    )
    .unwrap();
    assert_eq!(receipt["schema_version"], 2);
    assert_eq!(receipt["sourceBundle"], name);
    assert_eq!(
        receipt["sourceReceiptSha256"],
        profile::digest(&std::fs::read(root.join(format!("{name}.receipt.json"))).unwrap())
    );
    let status = storage::loader::status(&root, &release).unwrap();
    let resumed_status = status
        .iter()
        .find(|item| item.bundle_id == new_name)
        .unwrap();
    assert!(resumed_status.integrity);
    assert_eq!(
        resumed_status.events,
        [MigrationEvent::Prepared, MigrationEvent::RecoveryResumed]
    );
    resumed.journal(MigrationEvent::RomObserved).unwrap();
    let loaded = PreparedMigration::load_inner(&root, &new_name, &release).unwrap();
    assert!(loaded.capture() == original.capture());
    assert_eq!(loaded.bootstrap(), original.bootstrap());
    assert_eq!(loaded.final_image(), original.final_image());
}

/// Flat provenance rejects copying a recovery copy; another attempt names the original.
#[test]
fn recovery_copy_requires_original_and_intact_evidence_before_creation() {
    let (_temporary, original) = prepared_fixture();
    let (root, name, release) = binding(&original);
    let resumed = PreparedMigration::begin_recovery_inner(&root, &name, &release).unwrap();
    let (_, new_name, _) = binding(&resumed);
    let before = files(&root);
    assert!(PreparedMigration::begin_recovery_inner(&root, &new_name, &release).is_err());
    assert_eq!(files(&root), before);
    let source_package = original.artifact_directory().join("migration-package.bin");
    std::fs::write(source_package, vec![0; 384]).unwrap();
    let changed = files(&root);
    assert!(PreparedMigration::begin_recovery_inner(&root, &name, &release).is_err());
    assert_eq!(files(&root), changed);
    assert!(PreparedMigration::load_inner(&root, &new_name, &release).is_err());
}

/// Rewrites only synthetic receipt/journal hashes to isolate provenance validation.
fn rewrite_test_provenance(root: &Path, name: &str, change: impl FnOnce(&mut serde_json::Value)) {
    let receipt_path = root.join(format!("{name}.receipt.json"));
    let mut receipt: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&receipt_path).unwrap()).unwrap();
    change(&mut receipt);
    let mut encoded = format!(
        "{{\"schema_version\":{},\"bundle\":{},\"manifest_sha256\":{}",
        receipt["schema_version"], receipt["bundle"], receipt["manifest_sha256"]
    );
    for key in ["sourceBundle", "sourceReceiptSha256"] {
        if let Some(value) = receipt.get(key) {
            encoded.push_str(&format!(",\"{key}\":{value}"));
        }
    }
    encoded.push('}');
    std::fs::write(receipt_path, &encoded).unwrap();
    let path = root.join(format!("{name}.journal.jsonl"));
    let old = std::fs::read_to_string(&path).unwrap();
    let mut journal = String::new();
    for (sequence, line) in old.lines().enumerate() {
        let entry: serde_json::Value = serde_json::from_str(line).unwrap();
        let next = format!(
            "{{\"schema_version\":1,\"sequence\":{sequence},\"event\":{},\"receipt_sha256\":\"{}\",\"previous_sha256\":\"{}\"}}\n",
            entry["event"],
            profile::digest(encoded.as_bytes()),
            profile::digest(journal.as_bytes())
        );
        journal.push_str(&next);
    }
    std::fs::write(path, journal).unwrap();
}

/// Coherently rehashed journals cannot hide invalid source bindings or schema shapes.
#[test]
fn recovery_loader_rejects_forged_provenance_and_nested_origins() {
    for mutation in 0..7 {
        let (_temporary, original) = prepared_fixture();
        let (root, name, release) = binding(&original);
        let resumed = PreparedMigration::begin_recovery_inner(&root, &name, &release).unwrap();
        let (_, new_name, _) = binding(&resumed);
        let other = PreparedMigration::begin_recovery_inner(&root, &name, &release).unwrap();
        let (_, other_name, _) = binding(&other);
        let other_receipt = std::fs::read(root.join(format!("{other_name}.receipt.json"))).unwrap();
        rewrite_test_provenance(&root, &new_name, |receipt| match mutation {
            0 => receipt["sourceBundle"] = serde_json::json!(new_name),
            1 => receipt["sourceBundle"] = serde_json::json!("migration-1-0"),
            2 => receipt["sourceReceiptSha256"] = serde_json::json!("0".repeat(64)),
            3 => receipt["schema_version"] = serde_json::json!(1),
            4 => {
                receipt.as_object_mut().unwrap().remove("sourceBundle");
            }
            5 => receipt["sourceBundle"] = serde_json::json!("../foreign"),
            _ => {
                receipt["sourceBundle"] = serde_json::json!(other_name);
                receipt["sourceReceiptSha256"] = serde_json::json!(profile::digest(&other_receipt));
            }
        });
        assert!(PreparedMigration::load_inner(&root, &new_name, &release).is_err());
    }
}

/// Partial creation cannot masquerade as a resumed attempt or alter its original.
#[test]
fn recovery_loader_requires_its_single_durable_resumed_marker() {
    let (_temporary, mut original) = prepared_fixture();
    let (root, name, release) = binding(&original);
    let resumed = PreparedMigration::begin_recovery_inner(&root, &name, &release).unwrap();
    let (_, new_name, _) = binding(&resumed);
    let path = root.join(format!("{new_name}.journal.jsonl"));
    let journal = std::fs::read_to_string(&path).unwrap();
    std::fs::write(&path, format!("{}\n", journal.lines().next().unwrap())).unwrap();
    assert!(PreparedMigration::load_inner(&root, &new_name, &release).is_err());
    assert_eq!(
        original.journal(MigrationEvent::RecoveryResumed),
        Err(MigrationError::StorageUnavailable)
    );
}
