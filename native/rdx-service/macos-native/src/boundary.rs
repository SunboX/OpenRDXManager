// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Fixed ABI validation and sanitized ownership/result conversion helpers.

use crate::SERVICE_METADATA;
#[cfg(target_os = "macos")]
use crate::{Completion, HostOperationOutcome, NativeError, ffi};
#[cfg(target_os = "macos")]
use std::{
    ffi::c_void,
    mem::{offset_of, size_of},
    ptr::NonNull,
};

/// Returns whether Rust and the compiler-built C bridge agree on ABI layout.
#[must_use]
pub fn abi_layout_matches_c() -> bool {
    #[cfg(target_os = "macos")]
    {
        let mut native = ffi::AbiLayout::default();
        // SAFETY: `native` is writable and has the exact fixed C layout.
        unsafe { ffi::rdx_macos_get_abi_layout(&mut native) };
        native.abi_version == ffi::ABI_VERSION
            && native.result_header_size == size_of::<ffi::ResultHeader>() as u64
            && native.result_header_status_offset == offset_of!(ffi::ResultHeader, status) as u64
            && native.candidate_size == size_of::<ffi::CandidateRecord>() as u64
            && native.candidate_registry_entry_id_offset
                == offset_of!(ffi::CandidateRecord, registry_entry_id) as u64
            && native.candidate_vendor_offset == offset_of!(ffi::CandidateRecord, vendor) as u64
            && native.candidate_serial_offset == offset_of!(ffi::CandidateRecord, serial) as u64
            && native.enumeration_size == size_of::<ffi::EnumerationResult>() as u64
            && native.enumeration_count_offset == offset_of!(ffi::EnumerationResult, count) as u64
            && native.enumeration_candidates_offset
                == offset_of!(ffi::EnumerationResult, candidates) as u64
            && native.readiness_size == size_of::<ffi::Readiness>() as u64
            && native.readiness_candidate_count_offset
                == offset_of!(ffi::Readiness, candidate_count) as u64
            && native.scsi_request_size == size_of::<ffi::ScsiRequest>() as u64
            && native.scsi_request_data_offset == offset_of!(ffi::ScsiRequest, data) as u64
            && native.scsi_result_size == size_of::<ffi::ScsiResult>() as u64
            && native.scsi_result_realized_transfer_offset
                == offset_of!(ffi::ScsiResult, realized_transfer_count) as u64
            && native.scsi_result_data_offset == offset_of!(ffi::ScsiResult, data) as u64
            && native.scsi_result_sense_offset == offset_of!(ffi::ScsiResult, sense) as u64
            && native.media_record_size == size_of::<ffi::MediaRecord>() as u64
            && native.media_record_uuid_offset == offset_of!(ffi::MediaRecord, uuid) as u64
            && native.mapping_result_size == size_of::<ffi::MappingResult>() as u64
            && native.mapping_result_media_offset == offset_of!(ffi::MappingResult, media) as u64
            && native.host_operation_result_size == size_of::<ffi::HostOperationResult>() as u64
            && native.host_operation_dissenter_offset
                == offset_of!(ffi::HostOperationResult, dissenter_status) as u64
            && native.resource_counters_size == size_of::<ffi::ResourceCounters>() as u64
            && native.resource_counters_device_frees_offset
                == offset_of!(ffi::ResourceCounters, device_frees) as u64
            && native.abi_layout_size == size_of::<ffi::AbiLayout>() as u64
    }
    #[cfg(not(target_os = "macos"))]
    {
        false
    }
}

#[cfg(target_os = "macos")]
pub(super) struct ResultOwner<T>(NonNull<T>);

#[cfg(target_os = "macos")]
impl<T> ResultOwner<T> {
    pub(super) fn new(pointer: *mut T) -> Option<Self> {
        NonNull::new(pointer).map(Self)
    }

    pub(super) unsafe fn as_ref(&self) -> &T {
        // SAFETY: C returned a uniquely owned, correctly aligned `T` allocation.
        unsafe { self.0.as_ref() }
    }
}

#[cfg(target_os = "macos")]
impl<T> Drop for ResultOwner<T> {
    fn drop(&mut self) {
        // SAFETY: this guard uniquely owns the C result and frees it once.
        unsafe { ffi::rdx_macos_free_result(self.0.as_ptr().cast::<c_void>()) };
    }
}

#[cfg(target_os = "macos")]
pub(super) fn valid_header(header: &ffi::ResultHeader, kind: u32, status: u32) -> bool {
    header.abi_version == ffi::ABI_VERSION
        && header.kind == kind
        && header.status == status
        && header.reserved == 0
}

#[cfg(target_os = "macos")]
pub(super) fn candidate_record_is_valid(record: &ffi::CandidateRecord) -> bool {
    record.registry_entry_id != 0
        && record.peripheral_type == 0
        && flags_are_valid(&[
            record.has_vendor,
            record.has_product,
            record.has_revision,
            record.has_serial,
        ])
        && record_text_is_valid(record.has_vendor, &record.vendor)
        && record_text_is_valid(record.has_product, &record.product)
        && record_text_is_valid(record.has_revision, &record.revision)
        && record_text_is_valid(record.has_serial, &record.serial)
}

pub(super) fn optional_record_text(flag: u8, text: &[u8]) -> Option<&str> {
    if flag != 1 {
        return None;
    }
    let end = text.iter().position(|value| *value == 0)?;
    if end == 0 {
        return None;
    }
    std::str::from_utf8(&text[..end]).ok()
}

#[cfg(target_os = "macos")]
pub(super) fn record_text_is_valid(flag: u8, text: &[u8]) -> bool {
    let Some(end) = text.iter().position(|value| *value == 0) else {
        return false;
    };
    let printable = text[..end]
        .iter()
        .all(|value| (0x20..=0x7E).contains(value));
    printable && (flag == 1 || end == 0)
}

#[cfg(target_os = "macos")]
pub(super) fn valid_uuid(uuid: &[u8; ffi::UUID_BYTES]) -> bool {
    let Some(end) = uuid.iter().position(|value| *value == 0) else {
        return false;
    };
    if end != 36 {
        return false;
    }
    uuid[..end].iter().enumerate().all(|(index, value)| {
        let value = *value;
        if matches!(index, 8 | 13 | 18 | 23) {
            value == b'-'
        } else {
            value.is_ascii_hexdigit()
        }
    })
}

#[cfg(target_os = "macos")]
pub(super) fn flags_are_valid(flags: &[u8]) -> bool {
    flags.iter().all(|value| *value <= 1)
}

pub(super) fn service_metadata_is_valid() -> bool {
    SERVICE_METADATA.contains("<string>com.openrdx.hardware</string>")
        && SERVICE_METADATA.contains("<key>BundleProgram</key>")
        && SERVICE_METADATA
            .contains("<string>Contents/Library/LaunchServices/openrdx-hardware</string>")
        && SERVICE_METADATA.contains("<string>root</string>")
        && SERVICE_METADATA.contains("<string>staff</string>")
        && SERVICE_METADATA.contains("<string>/var/run/openrdx-hardware.sock</string>")
        && SERVICE_METADATA.contains("<integer>432</integer>")
}

#[cfg(target_os = "macos")]
pub(super) fn attempted_failure(attempted: u8, error: NativeError) -> Completion {
    if attempted == 0 {
        Completion::NotAttempted(error)
    } else {
        Completion::AttemptedError(error)
    }
}

#[cfg(target_os = "macos")]
pub(super) fn parse_host_operation_outcome(
    status: u32,
    result: &ffi::HostOperationResult,
) -> HostOperationOutcome {
    let structurally_invalid = result.attempted > 1
        || result.completed > 1
        || result.rejection > ffi::HOST_REJECTION_ACCESS_DENIED
        || result.reserved.iter().any(|value| *value != 0);
    if structurally_invalid {
        return HostOperationOutcome::CompletionUnknown(NativeError::Other);
    }
    if result.attempted == 0 {
        if result.completed != 0
            || result.rejection != ffi::HOST_REJECTION_NONE
            || result.dissenter_status != 0
            || status == ffi::STATUS_OK
        {
            return HostOperationOutcome::CompletionUnknown(NativeError::Other);
        }
        return HostOperationOutcome::NotAttempted(status_error(status));
    }
    if result.completed == 0 {
        if result.rejection != ffi::HOST_REJECTION_NONE
            || result.dissenter_status != 0
            || status == ffi::STATUS_OK
        {
            return HostOperationOutcome::CompletionUnknown(NativeError::Other);
        }
        return HostOperationOutcome::CompletionUnknown(status_error(status));
    }
    if status == ffi::STATUS_OK {
        return if result.rejection == ffi::HOST_REJECTION_NONE && result.dissenter_status == 0 {
            HostOperationOutcome::Succeeded
        } else {
            HostOperationOutcome::CompletionUnknown(NativeError::Other)
        };
    }
    if result.dissenter_status == 0 {
        return HostOperationOutcome::CompletionUnknown(NativeError::Other);
    }
    match (result.rejection, status) {
        (ffi::HOST_REJECTION_BUSY, ffi::STATUS_BUSY) => {
            HostOperationOutcome::DefinitelyRejected(NativeError::Busy)
        }
        (ffi::HOST_REJECTION_ACCESS_DENIED, ffi::STATUS_ACCESS_DENIED) => {
            HostOperationOutcome::DefinitelyRejected(NativeError::AccessDenied)
        }
        (ffi::HOST_REJECTION_NONE, _) => {
            HostOperationOutcome::CompletionUnknown(status_error(status))
        }
        _ => HostOperationOutcome::CompletionUnknown(NativeError::Other),
    }
}

#[cfg(target_os = "macos")]
pub(super) fn status_result(status: u32) -> Result<(), NativeError> {
    if status == ffi::STATUS_OK {
        Ok(())
    } else {
        Err(status_error(status))
    }
}

#[cfg(target_os = "macos")]
pub(super) fn status_error(status: u32) -> NativeError {
    match status {
        ffi::STATUS_INVALID_ARGUMENT => NativeError::InvalidRequest,
        ffi::STATUS_TRANSPORT_UNAVAILABLE => NativeError::TransportUnavailable,
        ffi::STATUS_ACCESS_DENIED => NativeError::AccessDenied,
        ffi::STATUS_BUSY => NativeError::Busy,
        ffi::STATUS_TIMED_OUT => NativeError::TimedOut,
        ffi::STATUS_DEVICE_REMOVED => NativeError::DeviceRemoved,
        ffi::STATUS_ENUMERATION_FAILED => NativeError::EnumerationFailed,
        ffi::STATUS_RESOURCE_LIMIT => NativeError::ResourceLimit,
        ffi::STATUS_EVIDENCE_INCOMPLETE => NativeError::EvidenceIncomplete,
        _ => NativeError::Other,
    }
}

#[cfg(target_os = "macos")]
pub(super) trait ResultExt<T> {
    fn unwrap_err_or(self, fallback: NativeError) -> NativeError;
}

#[cfg(target_os = "macos")]
impl ResultExt<()> for Result<(), NativeError> {
    fn unwrap_err_or(self, fallback: NativeError) -> NativeError {
        self.err().unwrap_or(fallback)
    }
}
