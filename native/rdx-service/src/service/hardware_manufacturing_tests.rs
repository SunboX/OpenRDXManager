// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Real worker manufacturing-preservation gates with a simulated SCSI boundary.

use super::*;
use mode_platform::ManufacturingFault;

/// Actual registration/worker/lifecycle rejects a latched receiver before any download or reset.
#[test]
fn receiver_interlock_stops_update_before_first_firmware_write() {
    for (installed, fault, expected, queries) in [
        (
            110,
            ManufacturingFault::WriteLatched,
            "firmware-receiver-readiness-unknown",
            2,
        ),
        (
            110,
            ManufacturingFault::ReadinessRejected,
            "firmware-receiver-readiness-unknown",
            1,
        ),
        (
            111,
            ManufacturingFault::WriteLatched,
            "firmware-receiver-readiness-unknown",
            2,
        ),
        (
            111,
            ManufacturingFault::ReadinessRejected,
            "firmware-receiver-readiness-unknown",
            1,
        ),
    ] {
        let (terminal, commands) = update(fault, installed, 0, 0);
        let crate::model::OperationEvent::Failed { error, stage, .. } = terminal else {
            panic!("receiver interlock allowed success");
        };
        assert_eq!(stage.as_str(), "firmware-validating");
        assert_eq!(error.code.as_str(), expected);
        assert!(
            !error.retryable,
            "Unresolved receiver state must not offer an immediate retry"
        );
        let buffer_commands: Vec<_> = commands.iter().filter(|cdb| cdb[0] == 0x3b).collect();
        assert_eq!(buffer_commands.len(), queries);
        assert!(
            buffer_commands
                .iter()
                .all(|cdb| cdb[1] == 2 && cdb[6..9] == [0; 3])
        );
        assert!(!commands.iter().any(|cdb| cdb[0] == 0xe6));
    }
}

/// Runs registration, admission, dispatch, and service lifecycle validation.
fn update(
    fault: ManufacturingFault,
    installed: u16,
    transfer_failures: usize,
    finalizer_unknown: usize,
) -> (crate::model::OperationEvent, Vec<Vec<u8>>) {
    let (terminal, commands, _) = update_with_transport_failure(
        fault,
        installed,
        transfer_failures,
        finalizer_unknown,
        false,
    );
    (terminal, commands)
}

/// Runs the same fixture with an optional nonretryable transfer rejection.
fn update_with_transport_failure(
    fault: ManufacturingFault,
    installed: u16,
    transfer_failures: usize,
    finalizer_unknown: usize,
    nonretryable_transfer: bool,
) -> (
    crate::model::OperationEvent,
    Vec<Vec<u8>>,
    Vec<crate::model::OperationEvent>,
) {
    let state = Arc::new(Mutex::new(ModePlatformState {
        drive_mode: 1,
        firmware_finalize_unknown: finalizer_unknown,
        firmware_revision: installed,
        firmware_target_revision: 109,
        firmware_target_drive_mode: None,
        firmware_reset_delay: if finalizer_unknown > 0 { 0 } else { 2 },
        firmware_cache_discovery: false,
        firmware_activation_scans: None,
        firmware_rebind_failures: 1_000,
        post_reset_opens: None,
        firmware_probe_failures: 0,
        post_reset_inquiries: 0,
        firmware_nonretryable_failure: nonretryable_transfer,
        firmware_transfer_failures: transfer_failures,
        manufacturing_fault: fault,
        #[cfg(unix)]
        manufacturing_backups: Vec::new(),
        sata_mode: 2,
        commands: Vec::new(),
    }));
    let mut backend = HardwareServiceBackend::new(
        ServicePlatform::Darwin,
        ModePlatform {
            state: Arc::clone(&state),
        },
    );
    let snapshot = backend.scan_devices().unwrap().remove(0);
    let (bytes, metadata) = crate::firmware::test_image_for_release("1.09");
    let token = FirmwareFileToken::new("firmware:manufacturing").unwrap();
    backend
        .begin_firmware_registration(token.clone(), "BIN".to_owned(), bytes.len(), Some(metadata))
        .unwrap();
    for (index, chunk) in bytes.chunks(4096).enumerate() {
        backend
            .append_firmware_registration(token.clone(), index * 4096, chunk.to_vec())
            .unwrap();
    }
    backend.commit_firmware_registration(token.clone()).unwrap();
    let (sender, receiver) = mpsc::sync_channel(32);
    let operation_id = OperationId::new("op:manufacturing").unwrap();
    let request = OperationRequest::FirmwareUpdate {
        device_id: snapshot.id,
        device_revision: snapshot.revision,
        firmware_file_token: token,
    };
    backend
        .start_operation(
            operation_id.clone(),
            request.clone(),
            ServiceEventSink::new(sender, crate::service::crash::CrashAdmission::new()),
        )
        .unwrap();
    backend.release_operation(&operation_id).unwrap();
    let mut events = Vec::new();
    let terminal = loop {
        let event = receiver
            .recv_timeout(Duration::from_secs(40))
            .unwrap()
            .event;
        events.push(event.clone());
        if matches!(
            event,
            crate::model::OperationEvent::Succeeded { .. }
                | crate::model::OperationEvent::Failed { .. }
        ) {
            break event;
        }
    };
    let mut runtime = crate::service::ServiceRuntime::new(
        backend,
        ServiceEventSink::new(
            mpsc::sync_channel(16).0,
            crate::service::crash::CrashAdmission::new(),
        ),
    );
    runtime.active = Some(crate::service::ActiveOperation::new(operation_id, &request).unwrap());
    for event in &events {
        runtime
            .handle_event(event.clone())
            .unwrap_or_else(|error| panic!("Rejected {event:?}: {error:?}"));
    }
    assert!(runtime.active.is_none());
    let commands = state.lock().unwrap().commands.clone();
    (terminal, commands, events)
}

/// Corrupt, incomplete, rejected, uncertain, or rebound data forbids any write.
#[test]
fn manufacturing_preflight_rejects_invalid_capture_before_every_mutation() {
    for (fault, code) in [
        #[cfg(any(unix, windows))]
        (
            ManufacturingFault::BackupUnavailable,
            "firmware-manufacturing-backup-unavailable",
        ),
        (
            ManufacturingFault::ShortFirst,
            "firmware-manufacturing-unreadable",
        ),
        (
            ManufacturingFault::ShortSecond,
            "firmware-manufacturing-unreadable",
        ),
        (
            ManufacturingFault::Rejected,
            "firmware-manufacturing-unreadable",
        ),
        (
            ManufacturingFault::Unknown,
            "firmware-manufacturing-unreadable",
        ),
        (
            ManufacturingFault::IdentityChanged,
            "firmware-manufacturing-unreadable",
        ),
    ] {
        let (terminal, commands) = update(fault, 107, 0, 0);
        let crate::model::OperationEvent::Failed { error, stage, .. } = terminal else {
            panic!("invalid record allowed success: {fault:?}");
        };
        assert_eq!(error.code.as_str(), code, "{fault:?}");
        assert_eq!(stage.as_str(), "firmware-validating");
        assert!(!commands.iter().any(|cdb| cdb[0] == 0x3b), "{fault:?}");
    }
}

/// Stable corrupt records must reach a receiver capable of restoring saved factory data.
#[test]
fn manufacturing_corrupt_baselines_can_upgrade_with_backup_and_exact_preservation() {
    for fault in [
        ManufacturingFault::InvalidChecksum,
        ManufacturingFault::PartiallyErased,
    ] {
        let (terminal, commands) = update(fault, 108, 0, 0);
        assert!(
            matches!(terminal, crate::model::OperationEvent::Succeeded { .. }),
            "{terminal:?}"
        );
        let first_write = commands.iter().position(|cdb| cdb[0] == 0x3b).unwrap();
        assert!(
            commands[..first_write]
                .iter()
                .filter(|cdb| cdb[0] == 0xe7)
                .count()
                >= 4
        );
    }
}

/// Byte changes forbid retry/finalization, and changed postboot data cannot succeed.
#[test]
fn manufacturing_changes_stop_retries_finalizers_and_success() {
    for (fault, transfer_failures, unknown, writes, code) in [
        (
            ManufacturingFault::ChangedAfterWrite,
            0,
            0,
            16,
            "firmware-manufacturing-changed",
        ),
        (
            ManufacturingFault::ChangedAfterWrite,
            1,
            0,
            1,
            "firmware-manufacturing-changed",
        ),
        (
            ManufacturingFault::ChangedAfterFinalizer,
            0,
            0,
            17,
            "firmware-manufacturing-changed",
        ),
        (
            ManufacturingFault::ChangedAfterFinalizer,
            0,
            1,
            17,
            "firmware-manufacturing-changed",
        ),
        (
            ManufacturingFault::UnreadableAfterFinalizer,
            0,
            0,
            17,
            "firmware-manufacturing-unreadable",
        ),
        (
            ManufacturingFault::UnreadableAfterWrite,
            0,
            0,
            16,
            "firmware-manufacturing-unreadable",
        ),
    ] {
        let (terminal, commands) = update(fault, 107, transfer_failures, unknown);
        let crate::model::OperationEvent::Failed { error, .. } = terminal else {
            panic!("changed record allowed success: {fault:?}");
        };
        assert_eq!(error.code.as_str(), code, "{fault:?}");
        assert_eq!(
            commands.iter().filter(|cdb| cdb[0] == 0x3b).count(),
            writes,
            "{fault:?}"
        );
    }
}

/// A receiver may briefly reject record reads after the last mode-4 transfer.
/// Read-only proof retries may settle, but the image transfer runs exactly once.
#[test]
fn transient_post_transfer_record_read_settles_without_replaying_firmware() {
    let (terminal, commands) = update(ManufacturingFault::UnreadableOnceAfterWrite, 107, 0, 0);
    assert!(
        matches!(terminal, crate::model::OperationEvent::Succeeded { .. }),
        "{terminal:?}\ncommands: {commands:?}"
    );
    let last_transfer = commands
        .iter()
        .rposition(|cdb| cdb.starts_with(&[0x3b, 0x04]))
        .unwrap();
    let finalizer = commands
        .iter()
        .position(|cdb| cdb.starts_with(&[0x3b, 0x05]))
        .unwrap();
    assert_eq!(
        commands[last_transfer + 1..finalizer]
            .iter()
            .filter(|cdb| cdb[0] == 0xe7)
            .count(),
        3,
        "one unreadable first-half capture must be followed by one complete retry"
    );
    assert_eq!(
        commands.iter().filter(|cdb| cdb[0] == 0x3b).count(),
        17,
        "the settling retry must not replay any firmware chunk"
    );
}

/// A failed transfer keeps its primary failure while cleanup record proof gets
/// one settled exact-device reopen and never replays or finalizes the image.
#[test]
fn transfer_failure_cleanup_settles_record_read_without_replaying_firmware() {
    let (terminal, commands, events) = update_with_transport_failure(
        ManufacturingFault::UnreadableOnceAfterWrite,
        107,
        0,
        0,
        true,
    );
    let crate::model::OperationEvent::Failed { error, .. } = terminal else {
        panic!("nonretryable transfer unexpectedly succeeded");
    };
    assert_eq!(error.code.as_str(), "firmware-transport-invalid");
    assert!(
        !events.iter().any(|event| matches!(
            event,
            crate::model::OperationEvent::Progress { stage, .. }
                if stage.as_str() == "firmware-finalizing"
        )),
        "a failed mode-4 transfer must not publish a finalizing stage"
    );
    assert_eq!(
        commands
            .iter()
            .filter(|cdb| cdb.starts_with(&[0x3b, 0x04]))
            .count(),
        1,
        "record settling must not replay the failed firmware transfer"
    );
    assert_eq!(
        commands
            .iter()
            .filter(|cdb| cdb.starts_with(&[0x3b, 0x05]))
            .count(),
        0,
        "recovered read-only evidence cannot authorize a finalizer after transfer failure"
    );
}

/// Readable identity data never permits mode-5 activation after either a
/// terminal first transfer failure or the failed complete retry.
#[test]
fn transfer_failure_with_valid_records_never_sends_finalizer() {
    for (transfer_failures, nonretryable, expected_code, expected_transfers) in [
        (0, true, "firmware-transport-invalid", 1),
        (2, false, "firmware-transport-unavailable", 2),
    ] {
        let (terminal, commands, events) = update_with_transport_failure(
            ManufacturingFault::None,
            107,
            transfer_failures,
            0,
            nonretryable,
        );
        let crate::model::OperationEvent::Failed { error, .. } = terminal else {
            panic!("failed transfer unexpectedly succeeded");
        };
        assert_eq!(error.code.as_str(), expected_code);
        assert!(
            !events.iter().any(|event| matches!(
                event,
                crate::model::OperationEvent::Progress { stage, .. }
                    if stage.as_str() == "firmware-finalizing"
            )),
            "a failed mode-4 transfer must not publish a finalizing stage"
        );
        assert_eq!(
            commands
                .iter()
                .filter(|cdb| cdb.starts_with(&[0x3b, 0x04]))
                .count(),
            expected_transfers
        );
        assert_eq!(
            commands
                .iter()
                .filter(|cdb| cdb.starts_with(&[0x3b, 0x05]))
                .count(),
            0,
            "a failed transfer must never authorize activation"
        );
    }
}

/// Valid records on each supported receiver are checked before writes and after activation.
#[test]
fn manufacturing_preservation_includes_released_receivers_and_retained_readback_lease() {
    for installed in [1, 106, 107, 108, 109, 110] {
        let (terminal, commands) = update(ManufacturingFault::None, installed, 0, 0);
        assert!(
            matches!(terminal, crate::model::OperationEvent::Succeeded { .. }),
            "{terminal:?}"
        );
        let first_write = commands.iter().position(|cdb| cdb[0] == 0x3b).unwrap();
        let finalizer = commands
            .iter()
            .position(|cdb| cdb.starts_with(&[0x3b, 5]))
            .unwrap();
        for observed in [
            &commands[..first_write],
            &commands[first_write..finalizer],
            &commands[finalizer + 1..],
        ] {
            assert!(
                observed
                    .iter()
                    .any(|cdb| cdb.as_slice() == [0xe7, 0, 3, 0xe0, 0, 128])
            );
            assert!(
                observed
                    .iter()
                    .any(|cdb| cdb.as_slice() == [0xe7, 0, 3, 0xe0, 128, 128])
            );
        }
    }
}

/// A fully erased dock can reach the release providing explicit serial repair.
#[test]
fn manufacturing_erased_108_can_install_109_with_backup_and_unchanged_readback() {
    for (failures, unknown, writes) in [(0, 0, 17), (1, 0, 18), (0, 1, 17)] {
        let (terminal, commands) = update(ManufacturingFault::Erased, 108, failures, unknown);
        assert!(
            matches!(terminal, crate::model::OperationEvent::Succeeded { .. }),
            "{terminal:?}"
        );
        assert_eq!(commands.iter().filter(|cdb| cdb[0] == 0x3b).count(), writes);
        let first = commands.iter().position(|cdb| cdb[0] == 0x3b).unwrap();
        let finalizer = commands
            .iter()
            .position(|cdb| cdb.starts_with(&[0x3b, 5]))
            .unwrap();
        for observed in [
            &commands[..first],
            &commands[first..finalizer],
            &commands[finalizer + 1..],
        ] {
            for offset in [0, 128] {
                assert!(
                    observed
                        .iter()
                        .any(|cdb| cdb.as_slice() == [0xe7, 0, 3, 0xe0, offset, 128])
                );
            }
        }
    }
}

/// Accepting a blank baseline never permits transitions between blank and valid data.
#[test]
fn manufacturing_erased_baseline_still_blocks_changes_and_backup_failure() {
    for (fault, failures, writes, code) in [
        (
            ManufacturingFault::ErasedChangedAfterBackup,
            0,
            0,
            "firmware-manufacturing-changed",
        ),
        (
            ManufacturingFault::ErasedChangedAfterWrite,
            0,
            16,
            "firmware-manufacturing-changed",
        ),
        (
            ManufacturingFault::ErasedChangedAfterWrite,
            1,
            1,
            "firmware-manufacturing-changed",
        ),
        (
            ManufacturingFault::ErasedChangedAfterFinalizer,
            0,
            17,
            "firmware-manufacturing-changed",
        ),
        (
            ManufacturingFault::ValidErasedAfterWrite,
            0,
            16,
            "firmware-manufacturing-changed",
        ),
        #[cfg(any(unix, windows))]
        (
            ManufacturingFault::ErasedBackupUnavailable,
            0,
            0,
            "firmware-manufacturing-backup-unavailable",
        ),
    ] {
        let (terminal, commands) = update(fault, 108, failures, 0);
        let crate::model::OperationEvent::Failed { error, .. } = terminal else {
            panic!("changed record allowed success: {fault:?}");
        };
        assert_eq!(error.code.as_str(), code, "{fault:?}");
        assert_eq!(
            commands.iter().filter(|cdb| cdb[0] == 0x3b).count(),
            writes,
            "{fault:?}"
        );
    }
}
