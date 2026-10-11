// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Synthetic offline capture and filesystem regressions; no device access.

use super::*;

#[cfg(unix)]
mod inventory;
#[cfg(unix)]
mod loader;

/// Makes one wholly synthetic vendor capture, including opaque factory fields.
pub(super) fn capture() -> MigrationCapture {
    let mut inquiry = vec![0; 36];
    inquiry[4] = 31;
    inquiry[8..16].copy_from_slice(b"TANDBERG");
    inquiry[16..32].copy_from_slice(b"RDX             ");
    inquiry[32..36].copy_from_slice(b"0283");
    let mut factory = vec![0; 172];
    factory[16..26].copy_from_slice(b"0123456789");
    factory[28..32].copy_from_slice(&6u32.to_le_bytes());
    for (index, byte) in factory[32..170].iter_mut().enumerate() {
        *byte = index as u8;
    }
    factory[104..108].copy_from_slice(&56u32.to_le_bytes());
    factory[120..122].copy_from_slice(&56u16.to_le_bytes());
    let mut usb_response = vec![0; 32];
    usb_response[4..6].copy_from_slice(&0x1a5au16.to_le_bytes());
    usb_response[6..8].copy_from_slice(&6u16.to_le_bytes());
    usb_response[8..32].copy_from_slice(b"synthetic USB attributes");
    MigrationCapture {
        usb: MigrationUsbIdentity {
            serial: "000123456789".into(),
            location_id: 0x02000000,
            vendor_id: 0x1a5a,
            product_id: 6,
        },
        inquiry,
        factory,
        usb_response,
        drive_log: vec![0x20, 0, 0, 8, 0, 1, 0, 4, 0x01, 0x23, 0x45, 0x67],
        mode_sense: vec![0, 13, 0, 0, 0, 0, 0, 0, 0x34, 5, 0, 0, 2, 0, 0],
    }
}

/// Checks the exact exposed fields and independent Python package/bootstrap golden vectors.
#[test]
fn reconstructs_exact_synthetic_exposed_records() {
    let source = capture();
    let package = profile::build_package(&source, b"0283").expect("synthetic supported capture");
    assert_eq!(&package[..8], b"RDXMIG01");
    assert_eq!(&package[72..82], b"0123456789");
    assert_eq!(&package[108..180], &source.factory[32..104]);
    assert_eq!(&package[182..210], &source.usb_response[4..32]);
    assert_eq!(&package[212..278], &source.factory[104..170]);
    assert_eq!(&package[324..328], &0x01234567u32.to_le_bytes());
    assert_eq!(package[333], 2);
    // Golden vectors independently produced by build_migration_profile.py from
    // this synthetic fixture, not from production unit fields or Rust helpers.
    assert_eq!(
        profile::digest(&package),
        "76759d13ae9ef19e8e1be08783ec6240768b09658f9c589b18ff1da871554c6e"
    );
    assert_eq!(&package[64..68], &[0xfa, 0x46, 0x65, 0xa3]);
    assert_eq!(&package[320..324], &[0xdf, 0x9d, 0x57, 0x13]);
    assert_eq!(
        profile::digest(&profile::personalize(&package).unwrap()),
        "4ce46a6e65fc69629210c2e95a2dfb78fc0b33a9ab4f66a728621ca50781b260"
    );
    for (start, end) in [
        (106, 108),
        (180, 182),
        (210, 212),
        (278, 320),
        (328, 333),
        (334, 384),
    ] {
        assert!(package[start..end].iter().all(|byte| *byte == 0));
    }
}

/// Rejects source firmware and hardware layouts outside the researched family.
#[test]
fn rejects_other_source_revision_and_unknown_hardware() {
    let mut source = capture();
    source.inquiry[32..36].copy_from_slice(b"0107");
    assert_eq!(
        profile::build_package(&source, b"0283"),
        Err(MigrationError::InvalidCapture)
    );
    source = capture();
    source.factory[120] = 57;
    assert_eq!(
        profile::build_package(&source, b"0283"),
        Err(MigrationError::InvalidCapture)
    );
}

/// Exercises private durable preparation, journaling and complete synthetic readback.
#[test]
#[cfg(unix)]
fn independently_reopens_private_artifacts_and_journals() {
    use std::os::unix::fs::PermissionsExt;
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().canonicalize().unwrap();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    let final_image = vec![0x5a; 62110];
    let mut prepared = PreparedMigration::prepare_inner(
        &root,
        capture(),
        &final_image,
        &profile::digest(&final_image),
    )
    .unwrap_or_else(|error| panic!("synthetic preparation: {error}"));
    assert_eq!(prepared.final_image(), final_image);
    assert_eq!(
        std::fs::metadata(prepared.artifact_directory())
            .unwrap()
            .permissions()
            .mode()
            & 0o7777,
        0o700
    );
    for entry in std::fs::read_dir(prepared.artifact_directory()).unwrap() {
        assert_eq!(
            entry.unwrap().metadata().unwrap().permissions().mode() & 0o7777,
            0o600
        );
    }
    prepared.journal(MigrationEvent::SourceRevalidated).unwrap();
    prepared.journal(MigrationEvent::RecoveryRequired).unwrap();
    let mut readback = capture();
    readback.inquiry[32..36].copy_from_slice(b"0107");
    readback.usb.product_id = 5;
    prepared.verify_readback(&readback).unwrap();
    readback.factory[150] ^= 1;
    assert_eq!(
        prepared.verify_readback(&readback),
        Err(MigrationError::ReadbackMismatch)
    );
}

/// Rejects every selected identity, framing, layout and effective-state conflict.
#[test]
fn rejects_bounded_identity_layout_and_state_conflicts() {
    let mutations: &[fn(&mut MigrationCapture)] = &[
        |c| c.usb.serial.replace_range(0..1, "1"),
        |c| c.usb.serial = "00abcdefghij".into(),
        |c| c.usb.serial.push('0'),
        |c| c.usb.location_id = 0,
        |c| c.usb.vendor_id ^= 1,
        |c| c.usb.product_id ^= 1,
        |c| c.inquiry.truncate(35),
        |c| c.inquiry.resize(256, 0),
        |c| c.inquiry[4] = 30,
        |c| c.inquiry[4] = 32,
        |c| c.inquiry[8] = b'X',
        |c| c.inquiry[16] = b'X',
        |c| c.factory.truncate(171),
        |c| c.factory.push(0),
        |c| c.factory[0] = 1,
        |c| c.factory[26] = 1,
        |c| c.factory[170] = 1,
        |c| c.factory[16] = b'9',
        |c| c.factory[28] = 5,
        |c| c.factory[104] = 1,
        |c| c.factory[120] = 55,
        |c| c.usb_response.truncate(31),
        |c| c.usb_response.push(0),
        |c| c.usb_response[0] = 1,
        |c| c.usb_response[4] ^= 1,
        |c| c.usb_response[6] ^= 1,
        |c| c.drive_log.clear(),
        |c| c.drive_log[0] = 0x21,
        |c| c.drive_log[1] = 1,
        |c| c.drive_log[3] = 9,
        |c| c.drive_log[5] = 2,
        |c| c.drive_log[7] = 5,
        |c| c.drive_log[7] = 3,
        |c| c.mode_sense.clear(),
        |c| c.mode_sense[1] = 14,
        |c| c.mode_sense[6] = 1,
        |c| c.mode_sense[8] = 0x35,
        |c| c.mode_sense[9] = 4,
        |c| c.mode_sense[9] = 6,
        |c| c.mode_sense[12] = 0,
        |c| c.mode_sense[12] = 4,
    ];
    for (index, mutate) in mutations.iter().enumerate() {
        let mut source = capture();
        mutate(&mut source);
        assert_eq!(
            validate_source_capture(&source),
            Err(MigrationError::InvalidCapture),
            "mutation {index}"
        );
    }
}

/// Rejects ambiguous counters while retaining supported framing and compiled defaults.
#[test]
fn rejects_duplicate_load_counters_and_accepts_framed_extensions() {
    let mut source = capture();
    source.drive_log.extend_from_within(4..12);
    source.drive_log[3] = 16;
    assert_eq!(
        validate_source_capture(&source),
        Err(MigrationError::InvalidCapture)
    );
    source.drive_log[13] = 2;
    assert!(validate_source_capture(&source).is_ok());
    source.mode_sense.splice(8..8, [0; 8]);
    source.mode_sense[1] = 21;
    source.mode_sense[7] = 8;
    source.mode_sense[20] |= 0xf8;
    assert!(validate_source_capture(&source).is_ok());
    source.factory[104..108].fill(0);
    let package = profile::build_package(&source, b"0283").unwrap();
    assert_eq!(&package[212..216], &[0; 4]);
}

/// Requires the exact release pin and rejects damaged package headers, payloads and sums.
#[test]
fn pins_release_and_rejects_changed_packages() {
    assert_eq!(
        validate_final_image(&[]),
        Err(MigrationError::InvalidRelease)
    );
    assert_eq!(
        validate_final_image(&vec![0; 62110]),
        Err(MigrationError::InvalidRelease)
    );
    let original = profile::build_package(&capture(), b"0283").unwrap();
    for index in [0, 8, 12, 16, 20, 24, 28, 32, 64, 72, 320, 333, 383] {
        let mut package = original;
        package[index] ^= 1;
        assert!(matches!(
            profile::personalize(&package),
            Err(MigrationError::InvalidBootstrap)
        ));
    }
}

/// Creates an injectable private root and synthetic release only inside unit tests.
#[cfg(unix)]
pub(super) fn prepared_fixture() -> (tempfile::TempDir, PreparedMigration) {
    use std::os::unix::fs::PermissionsExt;
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().canonicalize().unwrap();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    let final_image = vec![0x5a; 62110];
    let prepared = PreparedMigration::prepare_inner(
        &root,
        capture(),
        &final_image,
        &profile::digest(&final_image),
    )
    .unwrap_or_else(|error| panic!("synthetic preparation: {error}"));
    (temporary, prepared)
}

/// Rejects additional inventory entries and corruption of a preserved package.
#[test]
#[cfg(unix)]
fn rejects_unexpected_bundle_files_and_corrupted_artifacts() {
    let (_temporary, prepared) = prepared_fixture();
    let extra = prepared.artifact_directory().join("unexpected");
    std::fs::write(&extra, b"unrequested").unwrap();
    assert!(prepared.store.reopen().is_err());
    std::fs::remove_file(extra).unwrap();
    let path = prepared.artifact_directory().join("migration-package.bin");
    let mut bytes = std::fs::read(&path).unwrap();
    bytes[72] ^= 1;
    std::fs::write(path, bytes).unwrap();
    assert!(prepared.store.reopen().is_err());
}

/// Requires intact durable evidence independently of matching postboot fields.
#[test]
#[cfg(unix)]
fn readback_reopens_receipt_bound_evidence() {
    let (_temporary, prepared) = prepared_fixture();
    let mut readback = capture();
    readback.inquiry[32..36].copy_from_slice(b"0107");
    readback.usb.product_id = 5;
    std::fs::write(prepared.artifact_directory().join("bundle.json"), b"{}").unwrap();
    assert!(prepared.verify_readback(&readback).is_err());
}

/// Rejects aliased evidence and any file whose private permissions were weakened.
#[test]
#[cfg(unix)]
fn rejects_symlink_and_hardlink_files_and_nonprivate_modes() {
    use std::os::unix::fs::{PermissionsExt, symlink};
    let (_temporary, prepared) = prepared_fixture();
    let path = prepared.artifact_directory().join("capture.json");
    let moved = prepared.artifact_directory().join("moved.json");
    std::fs::rename(&path, &moved).unwrap();
    symlink(&moved, &path).unwrap();
    assert!(prepared.store.reopen().is_err());
    std::fs::remove_file(&path).unwrap();
    std::fs::hard_link(&moved, &path).unwrap();
    assert!(prepared.store.reopen().is_err());
    std::fs::remove_file(&path).unwrap();
    std::fs::rename(&moved, &path).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(prepared.store.reopen().is_err());
}

/// Rejects unsafe root paths before creating any recovery artifacts.
#[test]
#[cfg(unix)]
fn rejects_symlink_ancestors_and_nonprivate_roots_before_creation() {
    use std::os::unix::fs::{PermissionsExt, symlink};
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().canonicalize().unwrap();
    let target = root.join("target");
    std::fs::create_dir(&target).unwrap();
    std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o700)).unwrap();
    let link = root.join("link");
    symlink(&target, &link).unwrap();
    let image = vec![0; 62110];
    assert!(
        PreparedMigration::prepare_inner(&link, capture(), &image, &profile::digest(&image))
            .is_err()
    );
    std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(
        PreparedMigration::prepare_inner(&target, capture(), &image, &profile::digest(&image))
            .is_err()
    );
    assert_eq!(std::fs::read_dir(&target).unwrap().count(), 0);
}

/// Permanently closes a tampered journal writer without overwriting its evidence.
#[test]
#[cfg(unix)]
fn journal_tampering_closes_writer_without_replacing_evidence() {
    let (_temporary, mut prepared) = prepared_fixture();
    let root = prepared.artifact_directory().parent().unwrap();
    let name = prepared
        .artifact_directory()
        .file_name()
        .unwrap()
        .to_str()
        .unwrap();
    let path = root.join(format!("{name}.journal.jsonl"));
    let original = std::fs::read(&path).unwrap();
    std::fs::write(&path, b"tampered\n").unwrap();
    assert_eq!(
        prepared.journal(MigrationEvent::RomSetupDispatching),
        Err(MigrationError::StorageUnavailable)
    );
    assert_eq!(std::fs::read(&path).unwrap(), b"tampered\n");
    std::fs::write(&path, original).unwrap();
    assert_eq!(
        prepared.journal(MigrationEvent::RomSetupDispatching),
        Err(MigrationError::StorageUnavailable)
    );
}

/// Prevents dispatch prerequisites from being journaled against damaged recovery data.
#[test]
#[cfg(unix)]
fn journal_refuses_dispatch_milestone_after_artifact_damage() {
    let (_temporary, mut prepared) = prepared_fixture();
    let bootstrap = prepared
        .artifact_directory()
        .join("migration-bootstrap.rom.bin");
    std::fs::write(bootstrap, b"damaged").unwrap();
    assert_eq!(
        prepared.journal(MigrationEvent::RomSetupDispatching),
        Err(MigrationError::StorageUnavailable)
    );
}

/// Checks separate private receipt and journal files and receipt-bound reopening.
#[test]
#[cfg(unix)]
fn receipt_is_separate_private_and_required_on_reopen() {
    use std::os::unix::fs::PermissionsExt;
    let (_temporary, prepared) = prepared_fixture();
    let root = prepared.artifact_directory().parent().unwrap();
    let name = prepared
        .artifact_directory()
        .file_name()
        .unwrap()
        .to_str()
        .unwrap();
    let receipt = root.join(format!("{name}.receipt.json"));
    let journal = root.join(format!("{name}.journal.jsonl"));
    assert_eq!(
        std::fs::metadata(&receipt).unwrap().permissions().mode() & 0o7777,
        0o600
    );
    assert_eq!(
        std::fs::metadata(journal).unwrap().permissions().mode() & 0o7777,
        0o600
    );
    std::fs::write(&receipt, b"{}").unwrap();
    assert!(prepared.store.reopen().is_err());
}

/// Rejects empty or oversized files before accepting recovery evidence.
#[test]
#[cfg(unix)]
fn bounded_artifact_read_rejects_growth_and_zero_length() {
    let (_temporary, prepared) = prepared_fixture();
    let package = prepared.artifact_directory().join("migration-package.bin");
    std::fs::write(&package, vec![0; 385]).unwrap();
    assert!(prepared.store.reopen().is_err());
    std::fs::write(&package, b"").unwrap();
    assert!(prepared.store.reopen().is_err());
}

/// Creates separate immutable bundles without replacing prior recovery material.
#[test]
#[cfg(unix)]
fn each_preparation_is_exclusive_and_preserves_previous_evidence() {
    let (_temporary, prepared) = prepared_fixture();
    let root = prepared.artifact_directory().parent().unwrap();
    let next = PreparedMigration::prepare_inner(
        root,
        capture(),
        prepared.final_image(),
        &profile::digest(prepared.final_image()),
    )
    .unwrap_or_else(|error| panic!("second synthetic preparation: {error}"));
    assert_ne!(next.artifact_directory(), prepared.artifact_directory());
    assert!(prepared.store.reopen().is_ok());
    assert!(next.store.reopen().is_ok());
}

/// Stops further acknowledgments at the journal event and byte bounds.
#[test]
#[cfg(unix)]
fn journal_stops_at_bounded_event_inventory() {
    let (_temporary, mut prepared) = prepared_fixture();
    for _ in 1..128 {
        prepared.journal(MigrationEvent::SourceRevalidated).unwrap();
    }
    assert_eq!(
        prepared.journal(MigrationEvent::RomSetupDispatching),
        Err(MigrationError::StorageUnavailable)
    );
    let root = prepared.artifact_directory().parent().unwrap();
    let name = prepared
        .artifact_directory()
        .file_name()
        .unwrap()
        .to_str()
        .unwrap();
    let bytes = std::fs::read(root.join(format!("{name}.journal.jsonl"))).unwrap();
    assert_eq!(bytes.iter().filter(|byte| **byte == b'\n').count(), 128);
    assert!(bytes.len() <= 65536);
}

/// Rejects postboot changes to identity, opaque fields, load count or effective mode.
#[test]
#[cfg(unix)]
fn readback_requires_revision_identity_location_and_every_preserved_field() {
    let (_temporary, prepared) = prepared_fixture();
    assert_eq!(
        prepared.verify_readback(&capture()),
        Err(MigrationError::ReadbackMismatch)
    );
    let mut baseline = capture();
    baseline.inquiry[32..36].copy_from_slice(b"0107");
    baseline.usb.product_id = 5;
    for mutate in [
        (|c: &mut MigrationCapture| c.usb.location_id ^= 1) as fn(&mut MigrationCapture),
        |c| c.inquiry[0] = 5,
        |c| c.usb.serial.replace_range(2..3, "9"),
        |c| c.usb_response[31] ^= 1,
        |c| c.factory[32] ^= 1,
        |c| c.factory[169] ^= 1,
        |c| c.drive_log[11] ^= 1,
        |c| c.mode_sense[12] = 3,
    ] {
        let mut changed = baseline.clone();
        mutate(&mut changed);
        assert_eq!(
            prepared.verify_readback(&changed),
            Err(MigrationError::ReadbackMismatch)
        );
    }
    prepared.verify_readback(&baseline).unwrap();
}

/// Creates owner-only recovery directories and retains existing evidence on repeated calls.
#[test]
#[cfg(unix)]
fn recovery_root_creation_is_private_and_idempotent() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let temporary = tempfile::tempdir().unwrap();
    let base = temporary.path().canonicalize().unwrap();
    std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o700)).unwrap();
    let directory = std::fs::File::open(&base).unwrap();
    let owner = rustix::process::geteuid().as_raw();
    storage::ensure_tree(&directory, owner).unwrap();
    let parent = base.join("OpenRDXManager");
    let root = parent.join("recovery");
    let before = std::fs::metadata(&root).unwrap();
    for path in [&parent, &root] {
        let metadata = std::fs::metadata(path).unwrap();
        assert_eq!(metadata.mode() & 0o7777, 0o700);
        assert_eq!(metadata.uid(), owner);
    }
    std::fs::write(root.join("retained-receipt"), b"synthetic").unwrap();
    storage::ensure_tree(&directory, owner).unwrap();
    assert_eq!(std::fs::metadata(&root).unwrap().ino(), before.ino());
    assert_eq!(
        std::fs::read(root.join("retained-receipt")).unwrap(),
        b"synthetic"
    );
}

/// Rejects unsafe existing ownership or permissions without changing them.
#[test]
#[cfg(unix)]
fn recovery_root_refuses_unsafe_existing_directories_without_chmod() {
    use std::os::unix::fs::PermissionsExt;
    let temporary = tempfile::tempdir().unwrap();
    let base = temporary.path().canonicalize().unwrap();
    std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o700)).unwrap();
    let directory = std::fs::File::open(&base).unwrap();
    let owner = rustix::process::geteuid().as_raw();
    let parent = base.join("OpenRDXManager");
    std::fs::create_dir(&parent).unwrap();
    std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o777)).unwrap();
    assert_eq!(
        storage::ensure_tree(&directory, owner),
        Err(MigrationError::StorageUnavailable)
    );
    assert_eq!(
        std::fs::metadata(&parent).unwrap().permissions().mode() & 0o7777,
        0o777
    );
    assert!(!parent.join("recovery").exists());
    std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o755)).unwrap();
    let root = parent.join("recovery");
    std::fs::create_dir(&root).unwrap();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert_eq!(
        storage::ensure_tree(&directory, owner),
        Err(MigrationError::StorageUnavailable)
    );
    assert_eq!(
        std::fs::metadata(&root).unwrap().permissions().mode() & 0o7777,
        0o755
    );
    assert_eq!(
        storage::ensure_tree(&directory, owner.wrapping_add(1)),
        Err(MigrationError::StorageUnavailable)
    );
}

/// Refuses symlink and regular-file directory substitutes without replacing them.
#[test]
#[cfg(unix)]
fn recovery_root_refuses_symlink_children_and_existing_files() {
    use std::os::unix::fs::{PermissionsExt, symlink};
    let temporary = tempfile::tempdir().unwrap();
    let base = temporary.path().canonicalize().unwrap();
    std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o700)).unwrap();
    let directory = std::fs::File::open(&base).unwrap();
    let owner = rustix::process::geteuid().as_raw();
    let outside = base.join("outside");
    std::fs::create_dir(&outside).unwrap();
    let parent = base.join("OpenRDXManager");
    symlink(&outside, &parent).unwrap();
    assert_eq!(
        storage::ensure_tree(&directory, owner),
        Err(MigrationError::StorageUnavailable)
    );
    assert!(!outside.join("recovery").exists());
    std::fs::remove_file(&parent).unwrap();
    std::fs::write(&parent, b"retain-existing-file").unwrap();
    assert_eq!(
        storage::ensure_tree(&directory, owner),
        Err(MigrationError::StorageUnavailable)
    );
    assert_eq!(std::fs::read(&parent).unwrap(), b"retain-existing-file");
}

/// Revalidates exact fresh source fields while allowing unrelated drive-log changes.
#[test]
#[cfg(unix)]
fn fresh_source_requires_exact_identity_and_preserved_fields() {
    let (_temporary, prepared) = prepared_fixture();
    let source = capture();
    prepared.verify_source(&source).unwrap();
    for mutate in [
        (|c: &mut MigrationCapture| c.usb.location_id ^= 1) as fn(&mut MigrationCapture),
        |c| c.inquiry[32..36].copy_from_slice(b"0107"),
        |c| c.usb.serial.replace_range(2..3, "9"),
        |c| c.usb_response[31] ^= 1,
        |c| c.factory[32] ^= 1,
        |c| c.factory[169] ^= 1,
        |c| c.drive_log[11] ^= 1,
        |c| c.mode_sense[12] = 3,
    ] {
        let mut changed = source.clone();
        mutate(&mut changed);
        assert_eq!(
            prepared.verify_source(&changed),
            Err(MigrationError::InvalidCapture)
        );
    }
    let mut irrelevant = source;
    irrelevant
        .drive_log
        .extend_from_slice(&[0, 2, 0, 4, 1, 2, 3, 4]);
    irrelevant.drive_log[3] = 16;
    prepared.verify_source(&irrelevant).unwrap();
    std::fs::write(prepared.artifact_directory().join("bundle.json"), b"{}").unwrap();
    assert_eq!(
        prepared.verify_source(&irrelevant),
        Err(MigrationError::StorageUnavailable)
    );
}

/// Retains a safely owned existing parent and creates its private recovery child.
#[test]
#[cfg(unix)]
fn recovery_root_reuses_safe_parent_without_changing_permissions() {
    use std::os::unix::fs::PermissionsExt;
    let temporary = tempfile::tempdir().unwrap();
    let base = temporary.path().canonicalize().unwrap();
    std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o700)).unwrap();
    let directory = std::fs::File::open(&base).unwrap();
    let owner = rustix::process::geteuid().as_raw();
    let parent = base.join("OpenRDXManager");
    std::fs::create_dir(&parent).unwrap();
    std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o755)).unwrap();
    storage::ensure_tree(&directory, owner).unwrap();
    assert_eq!(
        std::fs::metadata(&parent).unwrap().permissions().mode() & 0o7777,
        0o755
    );
    assert_eq!(
        std::fs::metadata(parent.join("recovery"))
            .unwrap()
            .permissions()
            .mode()
            & 0o7777,
        0o700
    );
}

/// Distinguishes the pinned receiver USB descriptor from preserved manufacturing identity.
#[test]
#[cfg(unix)]
fn readback_accepts_only_pinned_runtime_pid_while_preserving_record_pid() {
    let (_temporary, prepared) = prepared_fixture();
    let mut readback = capture();
    readback.inquiry[32..36].copy_from_slice(b"0107");
    readback.usb.product_id = 5;
    prepared.verify_readback(&readback).unwrap();
    for product_id in [0, 1, 6, 0x926b, 0xffff] {
        let mut foreign = readback.clone();
        foreign.usb.product_id = product_id;
        assert_eq!(
            prepared.verify_readback(&foreign),
            Err(MigrationError::ReadbackMismatch)
        );
    }
    readback.usb_response[6] = 5;
    assert_eq!(
        prepared.verify_readback(&readback),
        Err(MigrationError::ReadbackMismatch)
    );
    let mut source = capture();
    source.usb.product_id = 5;
    assert_eq!(
        validate_source_capture(&source),
        Err(MigrationError::InvalidCapture)
    );
}
