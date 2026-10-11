// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Safe wrappers around C hooks compiled only for native boundary tests.

#[cfg(target_os = "macos")]
use super::status_result;
use super::{MacCandidate, NativeError, ffi};

/// Exercises native null, length, and enum validation through test-only hooks.
#[must_use]
pub fn hostile_ffi_inputs_are_rejected_for_test() -> bool {
    #[cfg(target_os = "macos")]
    {
        // SAFETY: this hook accepts no pointers and owns all injected values in C.
        unsafe { ffi::rdx_macos_test_hostile_inputs() }
    }
    #[cfg(not(target_os = "macos"))]
    {
        false
    }
}

/// Exercises compile-time failures in the exact helpers used by production.
#[must_use]
pub fn exercise_production_failure_injections_for_test() -> bool {
    #[cfg(target_os = "macos")]
    {
        // SAFETY: this hook accepts no pointers and contains its fake ownership.
        unsafe { ffi::rdx_macos_test_exercise_failure_injections() }
    }
    #[cfg(not(target_os = "macos"))]
    {
        false
    }
}

/// Exercises whole-media/UUID mapping acceptance through test-only hooks.
#[must_use]
pub fn disk_mapping_contract_is_enforced_for_test() -> bool {
    #[cfg(target_os = "macos")]
    {
        // SAFETY: this hook accepts no pointers and uses only stack records in C.
        unsafe { ffi::rdx_macos_test_disk_mapping_contract() }
    }
    #[cfg(not(target_os = "macos"))]
    {
        false
    }
}

/// Exercises exact registry, media UUID, and BSD device-number matching.
#[must_use]
pub fn raw_media_authority_contract_is_enforced_for_test() -> bool {
    #[cfg(target_os = "macos")]
    {
        // SAFETY: this hook accepts no pointers and compares fixed scalar evidence.
        unsafe { ffi::rdx_macos_test_raw_media_authority_contract() }
    }
    #[cfg(not(target_os = "macos"))]
    {
        false
    }
}

/// Formats and validates one app-owned temporary image through a retained fd.
#[must_use]
pub fn exfat_retained_fd_contract_is_enforced_for_test() -> bool {
    #[cfg(target_os = "macos")]
    {
        // SAFETY: this hook creates, unlinks, formats, validates, and closes one temp file.
        unsafe { ffi::rdx_macos_test_exfat_retained_fd_contract() }
    }
    #[cfg(not(target_os = "macos"))]
    {
        false
    }
}

/// Exercises mounted, explicitly unmounted, and drifted acquisition ordering.
#[must_use]
pub fn scsi_authority_order_is_enforced_for_test() -> bool {
    #[cfg(target_os = "macos")]
    {
        // SAFETY: the hook owns all synthetic state and exports no native handle.
        unsafe { ffi::rdx_macos_test_scsi_authority_order() }
    }
    #[cfg(not(target_os = "macos"))]
    {
        false
    }
}

/// Exercises reentrant, late, shutdown, concurrent, and bounded callback ownership.
#[must_use]
pub fn disk_arbitration_callback_lifecycle_is_safe_for_test() -> bool {
    #[cfg(target_os = "macos")]
    {
        // SAFETY: the hook owns and drains its bounded heap registry internally.
        unsafe { ffi::rdx_macos_test_da_callback_lifecycle() }
    }
    #[cfg(not(target_os = "macos"))]
    {
        false
    }
}

/// Exercises the production property prefilter and fake external IOKit edge.
#[must_use]
pub fn candidate_prefilter_contract_is_enforced_for_test() -> bool {
    #[cfg(target_os = "macos")]
    {
        // SAFETY: the hook owns fixed synthetic records and all fake acquisitions.
        unsafe { ffi::rdx_macos_test_candidate_prefilter_contract() }
    }
    #[cfg(not(target_os = "macos"))]
    {
        false
    }
}

/// Exercises fixed CBW/CSW encoding, residue, tag, and status validation.
#[must_use]
pub fn usb_bot_wire_contract_is_enforced_for_test() -> bool {
    #[cfg(target_os = "macos")]
    {
        // SAFETY: this hook accepts no pointers and uses only fixed stack buffers.
        unsafe { ffi::rdx_macos_test_usb_bot_wire_contract() }
    }
    #[cfg(not(target_os = "macos"))]
    {
        false
    }
}

/// Exercises the exact no-data START STOP UNIT physical-eject encoding.
#[must_use]
pub fn eject_scsi_contract_is_enforced_for_test() -> bool {
    #[cfg(target_os = "macos")]
    {
        // SAFETY: this hook accepts no pointers and uses fixed stack records.
        unsafe { ffi::rdx_macos_test_eject_scsi_contract() }
    }
    #[cfg(not(target_os = "macos"))]
    {
        false
    }
}

/// Exercises the Objective-C exception barrier used by every USB-host call.
#[must_use]
pub fn usb_host_exception_boundary_is_enforced_for_test() -> bool {
    #[cfg(target_os = "macos")]
    {
        // SAFETY: the hook raises and catches one local synthetic exception.
        unsafe { ffi::rdx_macos_test_usb_host_exception_contract() }
    }
    #[cfg(not(target_os = "macos"))]
    {
        false
    }
}

/// Exercises child-before-parent IOUSBHost teardown ordering.
#[must_use]
pub fn usb_host_release_order_is_enforced_for_test() -> bool {
    #[cfg(target_os = "macos")]
    {
        // SAFETY: the hook owns one synthetic Objective-C lease with nil handles.
        unsafe { ffi::rdx_macos_test_usb_host_release_order_contract() }
    }
    #[cfg(not(target_os = "macos"))]
    {
        false
    }
}

/// Exercises invalidation of media objects retained across a USB rematch.
#[must_use]
pub fn transport_release_mapping_invalidation_is_enforced_for_test() -> bool {
    #[cfg(target_os = "macos")]
    {
        // SAFETY: the hook owns one synthetic device and exports no native handle.
        unsafe { ffi::rdx_macos_test_transport_release_mapping_invalidation() }
    }
    #[cfg(not(target_os = "macos"))]
    {
        false
    }
}

/// Exercises non-owning whole-media presence readback and fail-closed errors.
#[must_use]
pub fn media_presence_without_mapping_contract_is_enforced_for_test() -> bool {
    #[cfg(target_os = "macos")]
    {
        // SAFETY: the hook owns synthetic devices and exports no native handle.
        unsafe { ffi::rdx_macos_test_media_presence_without_mapping_contract() }
    }
    #[cfg(not(target_os = "macos"))]
    {
        false
    }
}

/// Makes the next production scan's matching-dictionary allocation fail.
pub fn fail_next_matching_dictionary_for_test() {
    #[cfg(target_os = "macos")]
    {
        // SAFETY: the hook stores one closed test-only failure discriminant.
        unsafe { ffi::rdx_macos_test_fail_next_matching_dictionary() };
    }
}

/// Makes the next production scan observe successful matching with no iterator.
pub fn succeed_next_matching_without_iterator_for_test() {
    #[cfg(target_os = "macos")]
    {
        // SAFETY: the hook stores one closed test-only matching outcome.
        unsafe { ffi::rdx_macos_test_succeed_next_matching_without_iterator() };
    }
}

/// Probes a known non-SCSI registry service through test-only hooks.
///
/// # Errors
///
/// Returns the sanitized reason the service cannot become an RDX lease.
pub fn probe_known_non_scsi_service_for_test() -> Result<(), NativeError> {
    #[cfg(target_os = "macos")]
    {
        // SAFETY: this hook accepts no pointers and releases its IOKit service.
        status_result(unsafe { ffi::rdx_macos_test_probe_known_non_scsi() })
    }
    #[cfg(not(target_os = "macos"))]
    {
        Err(NativeError::UnsupportedPlatform)
    }
}

/// Returns one synthetic private candidate for deterministic redaction tests.
#[must_use]
pub fn synthetic_candidate_for_test() -> MacCandidate {
    let mut record = ffi::CandidateRecord {
        registry_entry_id: 0x1234_5678_9ABC_DEF0,
        peripheral_type: 0,
        has_vendor: 1,
        has_product: 1,
        has_revision: 1,
        has_serial: 1,
        ..ffi::CandidateRecord::default()
    };
    record.vendor[..6].copy_from_slice(b"VENDOR");
    record.product[..3].copy_from_slice(b"RDX");
    record.revision[..3].copy_from_slice(b"1.0");
    record.serial[..6].copy_from_slice(b"SECRET");
    MacCandidate {
        record,
        token: "macos-candidate-000".to_owned(),
    }
}

/// Runs the production formatter only against a caller-created virtual disk below 1 GiB.
/// Physical disks are rejected independently in the native test-only boundary.
#[must_use]
pub fn system_format_virtual_disk_for_test(
    bsd: &str,
    selector: u32,
    password: Option<&str>,
) -> bool {
    #[cfg(target_os = "macos")]
    {
        let Ok(name) = std::ffi::CString::new(bsd) else {
            return false;
        };
        let bytes = password.unwrap_or("").as_bytes();
        // SAFETY: both buffers remain borrowed during this synchronous test-only call.
        unsafe {
            ffi::rdx_macos_test_system_format(name.as_ptr(), selector, bytes.as_ptr(), bytes.len())
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (bsd, selector, password);
        false
    }
}
