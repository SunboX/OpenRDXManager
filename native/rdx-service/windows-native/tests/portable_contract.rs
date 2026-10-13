// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

use rdx_windows_native::{
    ArrivalDriveLetterPlan, NativeError, SafeDismountOutcome, ScsiOperation,
    ValidatedVolumeMutationLease, VolumeLeaseSet, WindowsDevice,
    available_drive_letters_from_state, plan_arrival_drive_letter,
};
#[cfg(not(windows))]
use rdx_windows_native::{available_drive_letters, enumerate_disk_candidates, probe_readiness};

/// Compile-checks that future host mutations receive an opaque pinned lease set.
#[allow(dead_code)]
fn pin_exact_volumes(device: &mut WindowsDevice) -> Result<VolumeLeaseSet<'_>, NativeError> {
    device.pin_volumes()
}

/// Compile-checks that success retains the opaque locked lease for Task 6.
#[allow(dead_code)]
fn safely_dismount_exact_volumes(leases: VolumeLeaseSet<'_>) -> SafeDismountOutcome<'_> {
    leases.dismount_for_safe_eject('E')
}

/// Compile-checks the only success payload without exposing native handles.
#[allow(dead_code)]
fn retain_locked_volumes(
    outcome: SafeDismountOutcome<'_>,
) -> Option<ValidatedVolumeMutationLease<'_>> {
    match outcome {
        SafeDismountOutcome::Ready(lease) => Some(lease),
        SafeDismountOutcome::NotAttempted(_) | SafeDismountOutcome::CompletionUnknown(_) => None,
    }
}

/// The private bridge rejects hostile command, transfer, sense, and timeout sizes.
#[test]
fn semantic_scsi_operations_fail_closed_before_ffi() {
    assert!(matches!(
        ScsiOperation::firmware_chunk(0, vec![0; 0x1001]),
        Err(NativeError::InvalidRequest)
    ));
    assert!(matches!(
        ScsiOperation::mode_select(false, vec![0; 9]),
        Err(NativeError::InvalidRequest)
    ));
    assert!(matches!(
        ScsiOperation::self_test().with_timeout_seconds(0),
        Err(NativeError::InvalidRequest)
    ));
    assert!(matches!(
        ScsiOperation::self_test().with_timeout_seconds(301),
        Err(NativeError::InvalidRequest)
    ));
}

#[test]
fn arrival_policy_distinguishes_foreign_collision_from_selected_old_letter() {
    assert_eq!(
        plan_arrival_drive_letter(0, 0, &[], 'R', false).unwrap(),
        ArrivalDriveLetterPlan::WaitForVolume
    );
    assert_eq!(
        plan_arrival_drive_letter(1, 1, &['R'], 'R', false).unwrap(),
        ArrivalDriveLetterPlan::AlreadyApplied
    );
    assert_eq!(
        plan_arrival_drive_letter(1, 0, &[], 'R', false).unwrap(),
        ArrivalDriveLetterPlan::ReplaceSelectedLetter('\0')
    );
    assert_eq!(
        plan_arrival_drive_letter(1, 1, &['E'], 'R', false).unwrap(),
        ArrivalDriveLetterPlan::ReplaceSelectedLetter('E')
    );
    assert_eq!(
        plan_arrival_drive_letter(1, 1, &['E'], 'R', true).unwrap(),
        ArrivalDriveLetterPlan::TargetCollision
    );
    assert_eq!(
        plan_arrival_drive_letter(1, 2, &['E'], 'R', false),
        Err(NativeError::EvidenceIncomplete)
    );
    assert_eq!(
        plan_arrival_drive_letter(2, 2, &['E', 'F'], 'R', false),
        Err(NativeError::EvidenceIncomplete)
    );
    assert_eq!(
        plan_arrival_drive_letter(1, 1, &['E'], 'C', false),
        Err(NativeError::InvalidRequest)
    );
}

/// Available-letter policy excludes Windows system letters, occupied mounts,
/// and every application-owned serial reservation without exposing paths.
#[test]
fn available_drive_letter_policy_uses_only_authoritative_bounded_facts() {
    let occupied = (1_u32 << ('E' as u32 - 'A' as u32)) | (1_u32 << ('R' as u32 - 'A' as u32));
    let letters = available_drive_letters_from_state(occupied, &['D', 'T'])
        .expect("bounded authoritative facts");

    assert_eq!(letters.first(), Some(&'F'));
    assert_eq!(letters.last(), Some(&'Z'));
    for unavailable in ['A', 'B', 'C', 'D', 'E', 'R', 'T'] {
        assert!(!letters.contains(&unavailable));
    }
    assert_eq!(letters.len(), 19);
    assert_eq!(
        available_drive_letters_from_state(0, &['C']),
        Err(NativeError::InvalidRequest)
    );
}

/// The Windows-only producer is pinned to the fixed application registry
/// namespace and the OS logical-drive bitmap; it accepts no caller path/root.
#[test]
fn available_drive_letter_source_contract_is_fixed_scope_and_fail_closed() {
    let source = include_str!("../src/drive_letter.rs");

    assert!(source.contains("GetLogicalDrives"));
    assert!(source.contains("SOFTWARE\\\\OpenRDXManager\\\\DriveLetters"));
    assert!(source.contains("available_drive_letters"));
    assert!(source.contains("ERROR_ACCESS_DENIED"));
    assert!(!source.contains("HKEY_CURRENT_USER"));
}

/// A non-Windows build keeps the real adapter target-gated and fail-closed.
#[cfg(not(windows))]
#[test]
fn non_windows_stub_never_claims_native_readiness() {
    let readiness = probe_readiness();

    assert!(!readiness.adapter_available());
    assert!(!readiness.service_installed());
    assert!(!readiness.service_running());
    assert!(!readiness.current_process_authorized());
    assert_eq!(
        enumerate_disk_candidates(),
        Err(NativeError::UnsupportedPlatform)
    );
    assert_eq!(
        available_drive_letters(),
        Err(NativeError::UnsupportedPlatform)
    );
}

/// Formatting identifies the exact VDS volume through authoritative GUID
/// pathnames and bounds all potentially blocking COM work in a reaped worker.
#[test]
fn vds_formatter_source_contract_is_exact_and_killable() {
    let source = include_str!("../src/native/vds.rs");

    assert!(source.contains("QueryVolumeGuidPathnames"));
    assert!(source.contains("canonical_volume_guid_path"));
    assert!(source.contains("--openrdx-internal-vds-worker"));
    assert!(source.contains("VDS_WORKER_TIMEOUT"));
    assert!(source.contains("child.kill()"));
    assert!(source.contains("child.wait()"));
    assert!(source.contains("operation.Cancel()"));
    assert!(!source.contains("WaitForServiceReady"));
    assert!(!source.contains("GetProperties()?.id"));
    assert!(!source.contains("for index in 0..self.count"));
    assert!(!source.contains("CoTaskMemFree(Some(path.as_ptr().cast()))"));
}

/// The disk preflight rejects both mounted and unmounted Windows system roles,
/// including registry-owned paging and crash-dump paths.
#[test]
fn windows_boot_protection_source_contract_is_fail_closed() {
    let source = include_str!("../src/native/layout.rs");

    for required in [
        "IOCTL_DISK_GET_DRIVE_LAYOUT_EX",
        "PARTITION_SYSTEM",
        "PARTITION_MSFT_RECOVERY",
        "PARTITION_WINDOWS_SYSTEM",
        "GPT_ATTRIBUTE_PLATFORM_REQUIRED",
        "PagingFiles",
        "DedicatedDumpFile",
        "MinidumpDir",
        "DumpFile",
    ] {
        assert!(source.contains(required), "missing {required}");
    }
    assert!(source.contains("NativeError::NoMedia"));
    for required in [
        "CREATE_DISK_GPT",
        "DRIVE_LAYOUT_INFORMATION_GPT",
        "PARTITION_INFORMATION_GPT",
        "MICROSOFT_BASIC_DATA",
        "partition_style_for_capacity",
    ] {
        assert!(source.contains(required), "missing {required}");
    }
    let capacity_preflight = source
        .find("partition_style_for_capacity(capacity)")
        .expect("capacity style preflight");
    let first_layout_ioctl = source
        .find("IOCTL_DISK_CREATE_DISK")
        .expect("first layout mutation");
    assert!(capacity_preflight < first_layout_ioctl);
    assert!(source.contains("sectors > u64::from(u32::MAX)"));
    assert!(source.contains("HostOperationOutcome::CompletionUnknown(error)"));
}

/// Requires final protected registry creation and readiness through sanitized diagnostics.
#[test]
fn registry_acl_is_created_final_and_gates_readiness() {
    let acl = include_str!("../src/registry_acl.rs");
    let readiness = include_str!("../src/native/readiness.rs");
    let provisioning = include_str!("../src/service_acl.rs");

    assert!(acl.contains("RegCreateKeyExW"));
    assert!(acl.contains("Some(&attributes)"));
    assert!(acl.contains("O:BAG:SYD:P"));
    assert!(acl.contains("RegGetKeySecurity"));
    assert!(acl.contains("RegQueryInfoKeyW"));
    assert!(acl.contains("rollback_new_empty_root"));
    assert!(readiness.contains("registry_acl_ready()"));
    assert!(provisioning.contains("provision_registry_acl()"));
    assert!(provisioning.contains("Stage::ManagerRegistry"));
    assert!(provisioning.contains("registry_acl_ready()"));
}
