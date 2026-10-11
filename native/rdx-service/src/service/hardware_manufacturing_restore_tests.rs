// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Real hardware-worker backup/restore tests with synthetic SCSI and real private storage.

use super::*;
use crate::migration::manufacturing_backup as manufacturing;
use crate::service::manufacturing::{BackupInventory, BackupRequest, RestoreRequest};
use mode_platform::manufacturing_restore_fixture::{RestoreFault, RestorePlatform, RestoreState};

type RestoreBackend = HardwareServiceBackend<RestorePlatform>;

/// Starts the actual service worker and discovers one fully validated synthetic dock.
fn fixture() -> (
    RestoreBackend,
    crate::model::DeviceSnapshot,
    Arc<Mutex<RestoreState>>,
) {
    fixture_revision(109)
}

/// Discovers the actual advertised receiver revision before evaluating its capabilities.
fn fixture_revision(
    revision: u16,
) -> (
    RestoreBackend,
    crate::model::DeviceSnapshot,
    Arc<Mutex<RestoreState>>,
) {
    let state = Arc::new(Mutex::new(RestoreState::new()));
    state.lock().unwrap().revision = revision;
    let mut backend = HardwareServiceBackend::new(
        ServicePlatform::Darwin,
        RestorePlatform {
            state: Arc::clone(&state),
        },
    );
    let snapshot = backend.scan_devices().unwrap().remove(0);
    (backend, snapshot, state)
}

/// Released v1.10 must reach the real capability probe and permit verified backup/restore.
#[test]
fn manufacturing_restore_worker_supports_released_v110() {
    let (mut backend, snapshot, state) = fixture_revision(110);
    let id = capture(&mut backend, &snapshot);
    backend
        .manufacturing_restore(restore_request(&snapshot, &id))
        .unwrap();
    let state = state.lock().unwrap();
    assert_eq!(state.writes, 1);
    assert_no_reset(&state);
}

/// Selects the exact current revision without caller-controlled storage paths.
fn backup_request(snapshot: &crate::model::DeviceSnapshot) -> BackupRequest {
    BackupRequest {
        device_id: snapshot.id.clone(),
        device_revision: snapshot.revision,
        page: None,
        reconcile: None,
    }
}

/// Supplies complete explicit original-serial confirmation to the production worker.
fn restore_request(snapshot: &crate::model::DeviceSnapshot, backup_id: &str) -> RestoreRequest {
    RestoreRequest {
        device_id: snapshot.id.clone(),
        device_revision: snapshot.revision,
        backup_id: backup_id.to_owned(),
        confirmation_serial: "0123456789".to_owned(),
        acknowledged: true,
        allow_identity_change: false,
    }
}

/// Captures a saved source through the actual worker, then returns its immutable ID.
fn capture(backend: &mut RestoreBackend, snapshot: &crate::model::DeviceSnapshot) -> String {
    let inventory = backend
        .manufacturing_backup(backup_request(snapshot), true)
        .unwrap();
    assert!(inventory.backup_supported && inventory.restore_supported);
    assert_eq!(inventory.backups.len(), 1);
    inventory.backups[0].backup_id.clone()
}

/// Compares sanitized rejection codes without making private record types printable.
fn assert_rejected(result: Result<BackupInventory, ServiceRejection>, expected: &str) {
    match result {
        Err(error) => assert_eq!(error.as_str(), expected),
        Ok(_) => panic!("expected bounded rejection {expected}"),
    }
}

/// A restore helper must never issue unit reset or unrelated firmware-buffer commands.
fn assert_no_reset(state: &RestoreState) {
    assert!(
        !state
            .commands
            .iter()
            .any(|cdb| cdb.as_slice() == [0x1d, 5, 0, 0, 0, 0])
    );
    assert!(
        !state
            .commands
            .iter()
            .any(|cdb| cdb.starts_with(&[0x3b, 4]) || cdb.starts_with(&[0x3b, 5]))
    );
}

/// Raw valid, erased, and corrupt records are captured exactly and labeled in the inventory.
#[test]
fn manufacturing_restore_worker_manual_backup_preserves_all_record_states() {
    for expected_state in ["valid", "erased", "corrupt"] {
        let (mut backend, snapshot, state) = fixture();
        {
            let mut state = state.lock().unwrap();
            if expected_state == "erased" {
                state.sector[..256].fill(0xff);
            }
            if expected_state == "corrupt" {
                state.sector[0] ^= 1;
            }
        }
        let inventory = backend
            .manufacturing_backup(backup_request(&snapshot), true)
            .unwrap();
        assert_eq!(inventory.backups.len(), 1);
        assert_eq!(inventory.backups[0].state, expected_state);
        let state = state.lock().unwrap();
        let saved =
            manufacturing::load_under(state.root.path(), &inventory.backups[0].backup_id).unwrap();
        assert_eq!(&saved.bytes[..], &state.sector[..256]);
        assert_eq!(state.writes, 0);
        assert_no_reset(&state);
    }
}

/// Record-only receivers preserve valid, erased and corrupt evidence without sector reads.
#[test]
fn manual_backup_without_restore_support_uses_only_fixed_record_reads() {
    for expected_state in ["valid", "erased", "corrupt"] {
        let (mut backend, snapshot, state) = fixture_revision(111);
        {
            let mut state = state.lock().unwrap();
            state.fault = RestoreFault::Unsupported;
            state.record_only = true;
            if expected_state == "erased" {
                state.sector[..256].fill(0xff);
            } else if expected_state == "corrupt" {
                state.sector[0] ^= 1;
            }
        }
        let inventory = backend
            .manufacturing_backup(backup_request(&snapshot), true)
            .unwrap();
        assert!(inventory.backup_supported);
        assert!(!inventory.restore_supported);
        assert_eq!(inventory.backups[0].state, expected_state);
        let state = state.lock().unwrap();
        let saved =
            manufacturing::load_under(state.root.path(), &inventory.backups[0].backup_id).unwrap();
        assert_eq!(&saved.bytes[..], &state.sector[..256]);
        let reads: Vec<_> = state.commands.iter().filter(|cdb| cdb[0] == 0xe7).collect();
        assert_eq!(reads.len(), 4);
        assert!(reads.iter().all(|cdb| cdb[3] == 0xe0));
        assert!(!state.commands.iter().any(|cdb| cdb[0] == 0xe8));
        assert_eq!(state.writes, 0);
        assert_no_reset(&state);
    }
}

/// Host persistence failure or changed raw bytes must never produce a verified backup.
#[test]
fn record_only_manual_backup_requires_durable_storage_and_exact_readback() {
    for (fault, code) in [
        (
            RestoreFault::BackupUnavailable,
            "firmware-manufacturing-backup-unavailable",
        ),
        (
            RestoreFault::ChangedAfterBackup,
            "firmware-manufacturing-changed",
        ),
    ] {
        let (mut backend, snapshot, state) = fixture_revision(111);
        {
            let mut state = state.lock().unwrap();
            state.record_only = true;
            state.fault = fault;
        }
        assert_rejected(
            backend.manufacturing_backup(backup_request(&snapshot), true),
            code,
        );
        let state = state.lock().unwrap();
        assert_eq!(state.writes, 0);
        assert_no_reset(&state);
    }
}

/// The current sector is durably saved before one restore, and every neighboring byte survives.
#[test]
fn manufacturing_restore_worker_restores_once_and_verifies_complete_sector() {
    let (mut backend, snapshot, state) = fixture();
    let source = state.lock().unwrap().sector;
    let id = capture(&mut backend, &snapshot);
    let expected_neighbors = {
        let mut state = state.lock().unwrap();
        state.sector[255] = 2;
        state.sector[3] = 0x7e;
        state.sector[4095] = 0xd3;
        state.sector[256..].to_vec()
    };
    let inventory = backend
        .manufacturing_restore(restore_request(&snapshot, &id))
        .unwrap();
    assert_eq!(inventory.backups.len(), 2);
    let state = state.lock().unwrap();
    assert_eq!(state.sector[..256], source[..256]);
    assert_eq!(state.sector[256..], expected_neighbors);
    assert_eq!(state.writes, 1);
    assert_no_reset(&state);
}

/// Explicit original-serial consent recovers a damaged identity from a differently bound backup.
#[test]
fn manufacturing_restore_worker_allows_original_identity_recovery_only_from_damaged_current() {
    for erased in [false, true] {
        let (mut backend, snapshot, state) = fixture();
        let (id, desired) = {
            let mut state = state.lock().unwrap();
            let mut original = state.sector;
            original[8..18].copy_from_slice(b"9876543210");
            original[..4].copy_from_slice(&[0x17, 0xf2, 0x9e, 0x7a]);
            let original_id = DeviceId::new("rdx:original-unit").unwrap();
            manufacturing::persist_sector_under(state.root.path(), &original_id, &original)
                .unwrap();
            let id = manufacturing::inventory_under(state.root.path(), &original_id)
                .unwrap()
                .remove(0)
                .backup_id;
            state.sector[..256].fill(if erased { 0xff } else { 0xa5 });
            (id, original)
        };
        let mut request = restore_request(&snapshot, &id);
        request.confirmation_serial = "9876543210".to_owned();
        backend.manufacturing_restore(request).unwrap();
        let state = state.lock().unwrap();
        assert_eq!(state.sector, desired);
        assert_eq!(state.writes, 1);
        assert_no_reset(&state);
    }
}

/// A checksum-valid replacement identity is recoverable only with additional explicit consent.
#[test]
fn manufacturing_restore_worker_recovers_valid_replacement_identity_with_explicit_consent() {
    let (mut backend, snapshot, state) = fixture_revision(110);
    let (id, original) = {
        let state = state.lock().unwrap();
        let mut original = state.sector;
        original[8..18].copy_from_slice(b"9876543210");
        original[..4].copy_from_slice(&[0x17, 0xf2, 0x9e, 0x7a]);
        let original_id = DeviceId::new("rdx:original-unit").unwrap();
        manufacturing::persist_sector_under(state.root.path(), &original_id, &original).unwrap();
        let id = manufacturing::inventory_under(state.root.path(), &original_id)
            .unwrap()
            .remove(0)
            .backup_id;
        (id, original)
    };
    let mut ordinary = restore_request(&snapshot, &id);
    ordinary.confirmation_serial = "9876543210".to_owned();
    assert_rejected(
        backend.manufacturing_restore(ordinary),
        "manufacturing-backup-mismatch",
    );
    assert_eq!(state.lock().unwrap().writes, 0);
    let consent = serde_json::json!({
        "deviceId": snapshot.id,
        "deviceRevision": snapshot.revision,
        "backupId": id,
        "confirmationSerial": "9876543210",
        "acknowledged": true,
        "allowIdentityChange": true,
    });
    for (field, value, reason) in [
        ("acknowledged", serde_json::json!(false), "invalid-request"),
        (
            "confirmationSerial",
            serde_json::json!("0123456789"),
            "manufacturing-backup-mismatch",
        ),
        (
            "deviceRevision",
            serde_json::json!(snapshot.revision.get() + 1),
            "stale-device-revision",
        ),
    ] {
        let mut invalid = consent.clone();
        invalid[field] = value;
        assert_rejected(
            backend.manufacturing_restore(serde_json::from_value(invalid).unwrap()),
            reason,
        );
    }
    assert_eq!(state.lock().unwrap().writes, 0);
    backend
        .manufacturing_restore(serde_json::from_value(consent).unwrap())
        .unwrap();
    let state = state.lock().unwrap();
    assert_eq!(state.sector, original);
    assert_eq!(state.writes, 1);
    assert_no_reset(&state);
}

/// Unsupported receivers are still readable and never receive a restore mutation.
#[test]
fn manufacturing_restore_worker_unsupported_probe_keeps_backup_available() {
    let (mut backend, snapshot, state) = fixture();
    state.lock().unwrap().fault = RestoreFault::Unsupported;
    let inventory = backend
        .manufacturing_backup(backup_request(&snapshot), true)
        .unwrap();
    assert!(inventory.backup_supported);
    assert!(!inventory.restore_supported);
    let id = &inventory.backups[0].backup_id;
    assert_rejected(
        backend.manufacturing_restore(restore_request(&snapshot, id)),
        "firmware-manufacturing-restore-unsupported",
    );
    let state = state.lock().unwrap();
    assert_eq!(state.writes, 0);
    assert_no_reset(&state);
}

/// Stale revisions, missing acknowledgment, wrong serials, and invalid saved records never write.
#[test]
fn manufacturing_restore_worker_rejects_invalid_consent_binding_and_source() {
    let (mut backend, snapshot, state) = fixture();
    let id = capture(&mut backend, &snapshot);
    let mut request = restore_request(&snapshot, &id);
    request.acknowledged = false;
    assert_rejected(backend.manufacturing_restore(request), "invalid-request");
    let mut request = restore_request(&snapshot, &id);
    request.confirmation_serial = "9876543210".to_owned();
    assert_rejected(
        backend.manufacturing_restore(request),
        "manufacturing-backup-mismatch",
    );
    let mut request = restore_request(&snapshot, &id);
    request.device_revision = DiscoveryRevision::new(snapshot.revision.get() + 1).unwrap();
    assert_rejected(
        backend.manufacturing_restore(request),
        "stale-device-revision",
    );
    for corrupt in [false, true] {
        let backup_id = {
            let state = state.lock().unwrap();
            let mut sector = state.sector;
            if corrupt {
                sector[0] ^= 1;
            }
            let original = DeviceId::new("rdx:other-valid-device").unwrap();
            manufacturing::persist_sector_under(state.root.path(), &original, &sector).unwrap();
            manufacturing::inventory_under(state.root.path(), &original)
                .unwrap()
                .into_iter()
                .find(|entry| entry.device_id == original && (entry.state == "corrupt") == corrupt)
                .unwrap()
                .backup_id
        };
        assert_rejected(
            backend.manufacturing_restore(restore_request(&snapshot, &backup_id)),
            "manufacturing-backup-mismatch",
        );
    }
    assert_eq!(state.lock().unwrap().writes, 0);
}

/// A valid flash record cannot change the separately validated live device serial.
#[test]
fn manufacturing_restore_worker_valid_record_cannot_override_live_serial() {
    let (mut backend, snapshot, state) = fixture();
    {
        let mut state = state.lock().unwrap();
        state.sector[8..18].copy_from_slice(b"9876543210");
        state.sector[..4].copy_from_slice(&[0x17, 0xf2, 0x9e, 0x7a]);
    }
    let id = capture(&mut backend, &snapshot);
    let mut request = restore_request(&snapshot, &id);
    request.confirmation_serial = "9876543210".to_owned();
    assert_rejected(
        backend.manufacturing_restore(request),
        "firmware-manufacturing-invalid",
    );
    assert_eq!(state.lock().unwrap().writes, 0);
}

/// A failed durable backup or a changed fresh sector blocks the sole native write.
#[test]
fn manufacturing_restore_worker_backup_and_fresh_sector_gates_precede_mutation() {
    for (fault, code) in [
        (
            RestoreFault::BackupUnavailable,
            "firmware-manufacturing-backup-unavailable",
        ),
        (
            RestoreFault::ChangedAfterBackup,
            "firmware-manufacturing-changed",
        ),
    ] {
        let (mut backend, snapshot, state) = fixture();
        let id = capture(&mut backend, &snapshot);
        state.lock().unwrap().fault = fault;
        assert_rejected(
            backend.manufacturing_restore(restore_request(&snapshot, &id)),
            code,
        );
        let state = state.lock().unwrap();
        assert_eq!(state.writes, 0);
        assert_no_reset(&state);
    }
}

/// Ambiguous writes and mismatched neighbors cannot trigger a retry, reset, or success.
#[test]
fn manufacturing_restore_worker_readback_failure_and_unknown_completion_never_retry() {
    for (fault, code) in [
        (
            RestoreFault::ReadbackMismatch,
            "manufacturing-outcome-unknown",
        ),
        (
            RestoreFault::ReadbackUnavailable,
            "manufacturing-outcome-unknown",
        ),
        (RestoreFault::UnknownWrite, "manufacturing-outcome-unknown"),
    ] {
        let (mut backend, snapshot, state) = fixture();
        let id = capture(&mut backend, &snapshot);
        state.lock().unwrap().fault = fault;
        assert_rejected(
            backend.manufacturing_restore(restore_request(&snapshot, &id)),
            code,
        );
        let state = state.lock().unwrap();
        assert_eq!(state.writes, 1);
        assert_no_reset(&state);
    }
}

/// Physical cartridge presence, busy mechanics, incomplete sectors, and identity drift fail closed.
#[test]
fn manufacturing_restore_worker_capture_requires_complete_identity_and_empty_physical_bay() {
    for (fault, code) in [
        (RestoreFault::PhysicalCartridge, "media-must-be-ejected"),
        (RestoreFault::MechanismBusy, "volume-busy"),
        (
            RestoreFault::ShortChunk,
            "firmware-manufacturing-unreadable",
        ),
        (
            RestoreFault::IdentityChanged,
            "firmware-manufacturing-unreadable",
        ),
    ] {
        let (mut backend, snapshot, state) = fixture();
        state.lock().unwrap().fault = fault;
        assert_rejected(
            backend.manufacturing_backup(backup_request(&snapshot), true),
            code,
        );
        assert_eq!(state.lock().unwrap().writes, 0);
    }
}

/// Listing saved metadata with inserted media must not reacquire SCSI or unmount it.
#[test]
fn manufacturing_inventory_with_inserted_media_never_opens_the_device() {
    let (mut backend, snapshot, state) = fixture();
    let id = capture(&mut backend, &snapshot);
    state.lock().unwrap().media_present = true;
    let inserted = backend.scan_devices().unwrap().remove(0);
    assert_eq!(inserted.media_state, crate::model::MediaState::Present);
    let (opens, commands) = {
        let state = state.lock().unwrap();
        (state.opens, state.commands.len())
    };
    for _ in 0..3 {
        let inventory = backend
            .manufacturing_backup(backup_request(&inserted), false)
            .unwrap();
        assert_eq!(inventory.backups.len(), 1);
        assert_eq!(inventory.backups[0].backup_id, id);
        assert!(!inventory.backup_supported && !inventory.restore_supported);
    }
    let state = state.lock().unwrap();
    assert_eq!(state.opens, opens, "inventory must not unmount for SCSI");
    assert_eq!(state.commands.len(), commands);
    assert_eq!(state.writes, 0);
}

/// The local-inventory branch cannot admit capture or uncertain-write reconciliation.
#[test]
fn inserted_media_inventory_keeps_capture_and_reconciliation_live() {
    let (mut backend, _, state) = fixture();
    state.lock().unwrap().media_present = true;
    let snapshot = backend.scan_devices().unwrap().remove(0);
    let opens = state.lock().unwrap().opens;
    assert_rejected(
        backend.manufacturing_backup(backup_request(&snapshot), true),
        "manufacturing-unavailable",
    );
    let mut request = backup_request(&snapshot);
    request.reconcile = Some(true);
    assert_rejected(
        backend.manufacturing_backup(request, false),
        "manufacturing-outcome-unknown",
    );
    let state = state.lock().unwrap();
    assert!(state.opens >= opens + 2);
    assert_eq!(state.writes, 0);
}
