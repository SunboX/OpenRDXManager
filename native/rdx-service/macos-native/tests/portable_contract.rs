// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

use rdx_macos_native::{
    MacDevice, MacScsiLease, NativeError, ScsiOperation, abi_layout_matches_c,
    enumerate_candidates, probe_readiness, resource_counters,
};
#[cfg(feature = "test-hooks")]
use rdx_macos_native::{
    candidate_prefilter_contract_is_enforced_for_test,
    disk_arbitration_callback_lifecycle_is_safe_for_test,
    disk_mapping_contract_is_enforced_for_test, eject_scsi_contract_is_enforced_for_test,
    exercise_production_failure_injections_for_test,
    exfat_retained_fd_contract_is_enforced_for_test, fail_next_matching_dictionary_for_test,
    hostile_ffi_inputs_are_rejected_for_test,
    media_presence_without_mapping_contract_is_enforced_for_test,
    probe_known_non_scsi_service_for_test, raw_media_authority_contract_is_enforced_for_test,
    scsi_authority_order_is_enforced_for_test, succeed_next_matching_without_iterator_for_test,
    synthetic_candidate_for_test, transport_release_mapping_invalidation_is_enforced_for_test,
    usb_bot_wire_contract_is_enforced_for_test, usb_host_exception_boundary_is_enforced_for_test,
    usb_host_release_order_is_enforced_for_test,
};
#[cfg(target_os = "macos")]
use std::sync::{Mutex, MutexGuard};

#[cfg(target_os = "macos")]
static NATIVE_TEST_LOCK: Mutex<()> = Mutex::new(());

/// Serializes process-global native ownership counters across this test binary.
#[cfg(target_os = "macos")]
fn native_test_guard() -> MutexGuard<'static, ()> {
    NATIVE_TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Every closed semantic constructor remains payload-redacted and rejects
/// values that cannot fit the C ABI's fixed transfer and timeout bounds.
#[test]
fn semantic_operations_are_closed_bounded_and_redacted() {
    assert_eq!(
        format!("{:?}", ScsiOperation::inquiry_standard()),
        "ScsiOperation(<private>)"
    );
    assert_eq!(
        ScsiOperation::firmware_chunk(0x01000000, vec![1]),
        Err(NativeError::InvalidRequest)
    );
    assert_eq!(
        ScsiOperation::firmware_chunk(0, Vec::new()),
        Err(NativeError::InvalidRequest)
    );
    assert_eq!(
        ScsiOperation::inquiry_standard().with_timeout_ms(0),
        Err(NativeError::InvalidRequest)
    );
}

/// The macOS 26 fallback accepts only exact USB BOT CBW and CSW wire records.
#[cfg(all(target_os = "macos", feature = "test-hooks"))]
#[test]
fn usb_bot_wire_contract_is_exact_and_fail_closed() {
    let _guard = native_test_guard();
    assert!(usb_bot_wire_contract_is_enforced_for_test());
}

/// The macOS physical eject semantic is the exact standard no-data CDB.
#[cfg(all(target_os = "macos", feature = "test-hooks"))]
#[test]
fn physical_eject_scsi_contract_is_exact() {
    let _guard = native_test_guard();
    assert!(eject_scsi_contract_is_enforced_for_test());
}

/// Native framework exceptions are contained before control returns to Rust.
#[cfg(all(target_os = "macos", feature = "test-hooks"))]
#[test]
fn usb_host_exceptions_do_not_cross_the_ffi_boundary() {
    let _guard = native_test_guard();
    assert!(usb_host_exception_boundary_is_enforced_for_test());
}

/// Bulk pipes must be released before their interface and captured device.
#[cfg(all(target_os = "macos", feature = "test-hooks"))]
#[test]
fn usb_host_release_is_strictly_child_before_parent() {
    let _guard = native_test_guard();
    assert!(usb_host_release_order_is_enforced_for_test());
}

/// Preparing to release USB BOT authority must discard the current generation's
/// Disk Arbitration objects without discarding stable RDX identity.
#[cfg(all(target_os = "macos", feature = "test-hooks"))]
#[test]
fn transport_release_preparation_discards_media_mapping_before_rematch() {
    let _guard = native_test_guard();
    assert!(transport_release_mapping_invalidation_is_enforced_for_test());
}

/// Safe Eject readback must prove presence without retaining Disk Arbitration
/// mapping objects or opening a raw whole-disk descriptor.
#[cfg(all(target_os = "macos", feature = "test-hooks"))]
#[test]
fn media_presence_readback_is_non_owning_and_fail_closed() {
    let _guard = native_test_guard();
    assert!(media_presence_without_mapping_contract_is_enforced_for_test());
}

/// The readback API exposes only the closed present/absent result.
#[allow(dead_code)]
fn non_owning_presence_type_contract(mut authority: MacDevice) {
    let _: Result<bool, NativeError> = authority.media_present_without_mapping();
}

/// The safe API keeps nonexclusive mapping authority separate from the lease
/// which is allowed to create and execute SCSI tasks.
#[allow(dead_code)]
fn split_authority_type_contract(mut authority: MacDevice, operation: ScsiOperation) {
    {
        let mapping = authority.pin_media().expect("mapping remains nonexclusive");
        let _ = mapping.media_count();
    }
    let mut scsi: MacScsiLease = authority
        .acquire_scsi()
        .expect("exclusive acquisition is explicit");
    let _ = scsi.execute(operation);
}

/// Normal transport preparation claims after unmount, while Safe Eject leaves
/// the disk unclaimed so its immediately following eject can proceed.
#[cfg(all(target_os = "macos", feature = "test-hooks"))]
#[test]
fn normal_unmount_claims_while_safe_eject_unmount_stays_unclaimed() {
    let _guard = native_test_guard();
    assert!(scsi_authority_order_is_enforced_for_test());
}

/// Reentrant, timed-out/late, and shutdown-abandoned callbacks retain heap
/// ownership until the final callback or registry release, without leaks.
#[cfg(all(target_os = "macos", feature = "test-hooks"))]
#[test]
fn disk_arbitration_callbacks_survive_timeout_late_delivery_and_shutdown() {
    let _guard = native_test_guard();
    let before = resource_counters();
    assert!(disk_arbitration_callback_lifecycle_is_safe_for_test());
    let after = resource_counters();

    assert!(after.da_context_allocations() - before.da_context_allocations() >= 32);
    assert_eq!(
        after.da_context_allocations() - before.da_context_allocations(),
        after.da_context_frees() - before.da_context_frees()
    );
    assert_eq!(
        after.da_contexts_outstanding(),
        before.da_contexts_outstanding()
    );
    assert!(after.balanced_since(before));
}

/// Exact whole-media association, UUID shape, duplicate rejection, and the
/// fixed mapping limit are enforced before any Disk Arbitration lease is kept.
#[cfg(all(target_os = "macos", feature = "test-hooks"))]
#[test]
fn disk_arbitration_mapping_contract_rejects_ambiguous_identity() {
    let _guard = native_test_guard();
    assert!(disk_mapping_contract_is_enforced_for_test());
    assert!(resource_counters().native_resources_balanced());
}

/// Same-name and same-capacity reuse cannot satisfy the retained raw-media
/// authority once registry entry, media UUID, or device number changes.
#[cfg(all(target_os = "macos", feature = "test-hooks"))]
#[test]
fn raw_media_open_revalidates_current_registry_and_device_identity() {
    let _guard = native_test_guard();
    assert!(raw_media_authority_contract_is_enforced_for_test());
}

/// The macOS formatter invalidates bounded primary and backup GPT metadata,
/// preserves pre-write certainty, and writes a structurally valid MBR/exFAT
/// image through an already-open descriptor without delegating path authority.
#[cfg(all(target_os = "macos", feature = "test-hooks"))]
#[test]
fn exfat_formatter_uses_only_the_retained_descriptor() {
    let _guard = native_test_guard();
    assert!(exfat_retained_fd_contract_is_enforced_for_test());
}

/// Rust and the compiler-built C bridge must agree on every shared struct size
/// and every field offset before a result pointer is dereferenced.
#[cfg(target_os = "macos")]
#[test]
fn c_and_rust_abi_layouts_match_exactly() {
    let _guard = native_test_guard();
    assert!(abi_layout_matches_c());
}

/// Startup readiness is non-invasive and cannot freeze later hotplug scans;
/// neither pass opens unrelated enumerated SCSI candidates for exclusivity.
#[cfg(target_os = "macos")]
#[test]
fn readiness_is_static_and_matching_allocation_retries_per_scan() {
    let _guard = native_test_guard();
    #[cfg(feature = "test-hooks")]
    fail_next_matching_dictionary_for_test();
    let before = resource_counters();
    let readiness = probe_readiness();
    let after_readiness = resource_counters();
    #[cfg(feature = "test-hooks")]
    {
        assert_eq!(
            enumerate_candidates().expect_err("matcher allocation failure must surface"),
            NativeError::ResourceLimit
        );
    }
    let later_candidates = enumerate_candidates().expect("later native scan remains enabled");
    drop(later_candidates);
    let after = resource_counters();

    assert!(readiness.discovery_available());
    assert!(readiness.safe_transport_available());
    assert!(readiness.service_metadata_present());
    assert!(!readiness.service_enabled());
    assert!(!readiness.current_process_authorized());
    assert_eq!(readiness.candidate_count(), 0);
    assert_eq!(
        after_readiness, before,
        "static readiness must not allocate or acquire native matcher state"
    );
    assert_eq!(after.plugin_acquisitions(), before.plugin_acquisitions());
    assert_eq!(
        after.interface_acquisitions(),
        before.interface_acquisitions()
    );
    assert_eq!(
        after.exclusive_acquisitions(),
        before.exclusive_acquisitions()
    );
    assert!(after.balanced_since(before));
}

/// Broad registry inspection rejects generic storage before plug-in/query/
/// exclusive access, while the documented Tandberg/RDX hint reaches the raw
/// INQUIRY path and still does not count as final RDX validation.
#[cfg(all(target_os = "macos", feature = "test-hooks"))]
#[test]
fn registry_identity_prefilter_is_non_mutating_and_not_final_admission() {
    let _guard = native_test_guard();
    let before = resource_counters();
    assert!(candidate_prefilter_contract_is_enforced_for_test());
    let after = resource_counters();

    assert_eq!(
        after.plugin_acquisitions(),
        before.plugin_acquisitions() + 1
    );
    assert_eq!(
        after.interface_acquisitions(),
        before.interface_acquisitions() + 1
    );
    assert_eq!(
        after.exclusive_acquisitions(),
        before.exclusive_acquisitions() + 1
    );
    assert!(after.balanced_since(before));
}

/// A real native enumeration owns and frees its one result allocation while
/// every iterator/service/CoreFoundation reference returns to zero.
#[cfg(target_os = "macos")]
#[test]
fn enumeration_frees_result_and_iokit_objects_exactly_once() {
    let _guard = native_test_guard();
    let before = resource_counters();
    let candidates = enumerate_candidates().expect("bounded native enumeration");
    for candidate in &candidates {
        assert_eq!(format!("{candidate:?}"), "MacCandidate(<private>)");
    }
    drop(candidates);
    let after = resource_counters();

    assert_eq!(after.result_allocations(), before.result_allocations() + 1);
    assert_eq!(after.result_frees(), before.result_frees() + 1);
    assert!(after.native_resources_balanced());
}

/// IOKit documents a null iterator as an authoritative empty successful match;
/// that result owns no iterator and must not touch any candidate transport.
#[cfg(all(target_os = "macos", feature = "test-hooks"))]
#[test]
fn successful_matching_without_iterator_is_an_owned_empty_enumeration() {
    let _guard = native_test_guard();
    succeed_next_matching_without_iterator_for_test();
    let before = resource_counters();
    let candidates = enumerate_candidates().expect("successful empty native match");
    let after = resource_counters();

    assert!(candidates.is_empty());
    assert_eq!(after.result_allocations(), before.result_allocations() + 1);
    assert_eq!(after.result_frees(), before.result_frees() + 1);
    assert_eq!(after.io_acquisitions(), before.io_acquisitions());
    assert_eq!(after.io_releases(), before.io_releases());
    assert_eq!(after.plugin_acquisitions(), before.plugin_acquisitions());
    assert_eq!(
        after.interface_acquisitions(),
        before.interface_acquisitions()
    );
    assert_eq!(
        after.exclusive_acquisitions(),
        before.exclusive_acquisitions()
    );
    assert!(after.balanced_since(before));
}

/// Null pointers, inconsistent lengths, oversized transfers, and invalid enum
/// discriminants fail before native dispatch or allocation leaks.
#[cfg(all(target_os = "macos", feature = "test-hooks"))]
#[test]
fn hostile_c_inputs_are_rejected_without_leaks() {
    let _guard = native_test_guard();
    let before = resource_counters();
    assert!(hostile_ffi_inputs_are_rejected_for_test());
    let after = resource_counters();
    assert!(after.native_resources_balanced());
    assert_eq!(after.live_results(), before.live_results());
}

/// Compile-time hooks fail the same result/plugin/query/exclusive/task/DA
/// helpers production calls and release every prior acquisition exactly once.
#[cfg(all(target_os = "macos", feature = "test-hooks"))]
#[test]
fn every_production_helper_failure_path_balances_native_ownership() {
    let _guard = native_test_guard();
    let before = resource_counters();
    assert!(exercise_production_failure_injections_for_test());
    let after = resource_counters();

    assert!(after.balanced_since(before));
    assert!(after.result_allocations() > before.result_allocations());
}

/// Registry-entry identity is necessary but not sufficient: a known platform
/// service which is not a SCSI peripheral never yields the SCSI task interface.
#[cfg(all(target_os = "macos", feature = "test-hooks"))]
#[test]
fn non_scsi_iokit_service_is_truthfully_unavailable() {
    let _guard = native_test_guard();
    assert_eq!(
        probe_known_non_scsi_service_for_test(),
        Err(NativeError::TransportUnavailable)
    );
    assert!(resource_counters().native_resources_balanced());
}

/// Candidate debug output is deterministic even with nonempty untrusted
/// identity hints and never exposes the retained registry entry identifier.
#[cfg(feature = "test-hooks")]
#[test]
fn candidate_debug_output_is_always_redacted() {
    let candidate = synthetic_candidate_for_test();

    assert_eq!(format!("{candidate:?}"), "MacCandidate(<private>)");
    assert_eq!(candidate.token(), "macos-candidate-000");
    assert_eq!(candidate.vendor(), Some("VENDOR"));
    assert!(!format!("{candidate:?}").contains("1311768467463790320"));
}

/// Shared historical error data cannot masquerade as fresh interface-init evidence.
#[cfg(all(target_os = "macos", feature = "test-hooks"))]
#[test]
fn interface_constructor_preserves_legacy_status_with_fresh_error_provenance() {
    let _guard = native_test_guard();
    assert!(rdx_macos_native::interface_error_provenance_is_enforced_for_test());
}
