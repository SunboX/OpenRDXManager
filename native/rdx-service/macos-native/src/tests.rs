// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

use super::*;

fn host_result(
    status: u32,
    attempted: u8,
    completed: u8,
    rejection: u8,
    dissenter_status: i64,
) -> ffi::HostOperationResult {
    ffi::HostOperationResult {
        header: ffi::ResultHeader {
            abi_version: ffi::ABI_VERSION,
            kind: ffi::RESULT_HOST_OPERATION,
            status,
            reserved: 0,
        },
        attempted,
        completed,
        rejection,
        reserved: [0; 5],
        dissenter_status,
    }
}

/// Completed known dissenters are definite; timeout and unknown dissenters
/// remain ambiguous, and impossible native combinations fail closed.
#[test]
fn host_operation_certainty_matrix_is_fail_closed() {
    let cases = [
        (
            host_result(ffi::STATUS_OK, 1, 1, ffi::HOST_REJECTION_NONE, 0),
            ffi::STATUS_OK,
            HostOperationOutcome::Succeeded,
        ),
        (
            host_result(ffi::STATUS_BUSY, 1, 1, ffi::HOST_REJECTION_BUSY, -1),
            ffi::STATUS_BUSY,
            HostOperationOutcome::DefinitelyRejected(NativeError::Busy),
        ),
        (
            host_result(
                ffi::STATUS_ACCESS_DENIED,
                1,
                1,
                ffi::HOST_REJECTION_ACCESS_DENIED,
                -2,
            ),
            ffi::STATUS_ACCESS_DENIED,
            HostOperationOutcome::DefinitelyRejected(NativeError::AccessDenied),
        ),
        (
            host_result(ffi::STATUS_TIMED_OUT, 1, 0, ffi::HOST_REJECTION_NONE, 0),
            ffi::STATUS_TIMED_OUT,
            HostOperationOutcome::CompletionUnknown(NativeError::TimedOut),
        ),
        (
            host_result(10, 1, 1, ffi::HOST_REJECTION_NONE, -3),
            10,
            HostOperationOutcome::CompletionUnknown(NativeError::Other),
        ),
        (
            host_result(
                ffi::STATUS_INVALID_ARGUMENT,
                0,
                0,
                ffi::HOST_REJECTION_NONE,
                0,
            ),
            ffi::STATUS_INVALID_ARGUMENT,
            HostOperationOutcome::NotAttempted(NativeError::InvalidRequest),
        ),
        (
            host_result(ffi::STATUS_BUSY, 0, 1, ffi::HOST_REJECTION_BUSY, -1),
            ffi::STATUS_BUSY,
            HostOperationOutcome::CompletionUnknown(NativeError::Other),
        ),
        (
            host_result(
                ffi::STATUS_ACCESS_DENIED,
                1,
                1,
                ffi::HOST_REJECTION_BUSY,
                -1,
            ),
            ffi::STATUS_ACCESS_DENIED,
            HostOperationOutcome::CompletionUnknown(NativeError::Other),
        ),
    ];

    for (result, status, expected) in cases {
        assert_eq!(parse_host_operation_outcome(status, &result), expected);
    }
}

#[test]
fn stable_candidate_identity_survives_registry_rematch_but_rejects_serial_change() {
    let original = synthetic_candidate_for_test();
    let mut rebound = synthetic_candidate_for_test();
    rebound.record.registry_entry_id += 1;
    rebound.token = "macos-candidate-007".to_owned();
    assert!(original.stable_identity_matches(&rebound));

    rebound.record.serial[0] = b'X';
    assert!(!original.stable_identity_matches(&rebound));
    rebound.record.serial[0] = b'S';
    rebound.record.has_serial = 0;
    assert!(!original.stable_identity_matches(&rebound));
}

#[test]
fn rematch_identity_selects_only_the_same_unique_physical_device() {
    let original = synthetic_candidate_for_test();
    let identity = original.rematch_identity();
    let mut unrelated = synthetic_candidate_for_test();
    unrelated.record.registry_entry_id += 1;
    unrelated.record.serial[0] = b'X';
    unrelated.token = "macos-candidate-006".to_owned();
    let mut rebound = synthetic_candidate_for_test();
    rebound.record.registry_entry_id += 2;
    rebound.token = "macos-candidate-007".to_owned();

    let candidates = [unrelated, rebound];
    let selected = identity
        .select_unique(&candidates)
        .expect("one same-identity rematch is accepted");
    assert_eq!(selected.token(), "macos-candidate-007");

    let mut duplicate = synthetic_candidate_for_test();
    duplicate.record.registry_entry_id += 3;
    duplicate.token = "macos-candidate-008".to_owned();
    assert!(matches!(
        identity.select_unique(&[synthetic_candidate_for_test(), duplicate]),
        Err(NativeError::EvidenceIncomplete),
    ));
}

#[test]
fn media_identity_material_survives_registry_generation_changes() {
    let mut first = ffi::MediaRecord {
        registry_entry_id: 41,
        whole_registry_entry_id: 40,
        uuid: [0; ffi::UUID_BYTES],
    };
    first.uuid[..37].copy_from_slice(b"2542EAB0-0000-0004-0000-0000000989C0\0");
    let mut rebound = first;
    rebound.registry_entry_id = 141;
    rebound.whole_registry_entry_id = 140;

    assert_eq!(
        mapping_identity_material(&[first]),
        mapping_identity_material(&[rebound])
    );
    rebound.uuid[0] = b'3';
    assert_ne!(
        mapping_identity_material(&[first]),
        mapping_identity_material(&[rebound])
    );
}

#[test]
fn mounted_filesystem_discriminants_include_ntfs() {
    assert_eq!(mounted_filesystem_from_native(0), None);
    assert_eq!(
        mounted_filesystem_from_native(1),
        Some(MountedFilesystem::ExFat)
    );
    assert_eq!(
        mounted_filesystem_from_native(2),
        Some(MountedFilesystem::Ntfs)
    );
    assert_eq!(mounted_filesystem_from_native(3), None);
}
