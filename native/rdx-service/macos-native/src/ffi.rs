// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

#[cfg(target_os = "macos")]
use std::ffi::c_void;

pub(crate) const ABI_VERSION: u32 = 4;

/// Independent version-one session evidence; existing ABI-four records are unchanged.
#[cfg(target_os = "macos")]
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct PeerSessionRecord {
    pub(crate) version: u32,
    pub(crate) size: u32,
    pub(crate) audit_token: [u32; 8],
}
pub(crate) const MAX_CANDIDATES: usize = 128;
pub(crate) const MAX_TEXT_BYTES: usize = 128;
pub(crate) const MAX_TRANSFER_BYTES: usize = 4096;
pub(crate) const MAX_SENSE_BYTES: usize = 252;
pub(crate) const MAX_MEDIA: usize = 32;
pub(crate) const UUID_BYTES: usize = 37;
pub(crate) const MAX_MOUNT_PATH_BYTES: usize = 1024;

pub(crate) const STATUS_OK: u32 = 0;
pub(crate) const STATUS_INVALID_ARGUMENT: u32 = 1;
pub(crate) const STATUS_TRANSPORT_UNAVAILABLE: u32 = 2;
pub(crate) const STATUS_ACCESS_DENIED: u32 = 3;
pub(crate) const STATUS_BUSY: u32 = 4;
pub(crate) const STATUS_TIMED_OUT: u32 = 5;
pub(crate) const STATUS_DEVICE_REMOVED: u32 = 6;
pub(crate) const STATUS_ENUMERATION_FAILED: u32 = 7;
pub(crate) const STATUS_RESOURCE_LIMIT: u32 = 8;
pub(crate) const STATUS_EVIDENCE_INCOMPLETE: u32 = 9;

pub(crate) const RESULT_ENUMERATION: u32 = 1;
pub(crate) const RESULT_SCSI: u32 = 2;
pub(crate) const RESULT_MAPPING: u32 = 3;
pub(crate) const RESULT_HOST_OPERATION: u32 = 4;

pub(crate) const HOST_REJECTION_NONE: u8 = 0;
pub(crate) const HOST_REJECTION_BUSY: u8 = 1;
pub(crate) const HOST_REJECTION_ACCESS_DENIED: u8 = 2;
pub(crate) const FILESYSTEM_EXFAT: u32 = 1;

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub(crate) struct ResultHeader {
    pub(crate) abi_version: u32,
    pub(crate) kind: u32,
    pub(crate) status: u32,
    pub(crate) reserved: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct CandidateRecord {
    pub(crate) registry_entry_id: u64,
    pub(crate) peripheral_type: u32,
    pub(crate) has_vendor: u8,
    pub(crate) has_product: u8,
    pub(crate) has_revision: u8,
    pub(crate) has_serial: u8,
    pub(crate) vendor: [u8; MAX_TEXT_BYTES + 1],
    pub(crate) product: [u8; MAX_TEXT_BYTES + 1],
    pub(crate) revision: [u8; MAX_TEXT_BYTES + 1],
    pub(crate) serial: [u8; MAX_TEXT_BYTES + 1],
}

impl Default for CandidateRecord {
    fn default() -> Self {
        Self {
            registry_entry_id: 0,
            peripheral_type: 0,
            has_vendor: 0,
            has_product: 0,
            has_revision: 0,
            has_serial: 0,
            vendor: [0; MAX_TEXT_BYTES + 1],
            product: [0; MAX_TEXT_BYTES + 1],
            revision: [0; MAX_TEXT_BYTES + 1],
            serial: [0; MAX_TEXT_BYTES + 1],
        }
    }
}

#[repr(C)]
pub(crate) struct EnumerationResult {
    pub(crate) header: ResultHeader,
    pub(crate) count: u64,
    pub(crate) candidates: [CandidateRecord; MAX_CANDIDATES],
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub(crate) struct Readiness {
    pub(crate) abi_version: u32,
    pub(crate) status: u32,
    pub(crate) discovery_available: u8,
    pub(crate) safe_transport_available: u8,
    pub(crate) service_metadata_present: u8,
    pub(crate) service_enabled: u8,
    pub(crate) current_process_authorized: u8,
    pub(crate) reserved: [u8; 3],
    pub(crate) candidate_count: u64,
}

#[repr(C)]
pub(crate) struct ScsiRequest {
    pub(crate) abi_version: u32,
    pub(crate) operation: u32,
    pub(crate) timeout_ms: u32,
    pub(crate) data_length: u32,
    pub(crate) offset: u32,
    pub(crate) save_pages: u8,
    pub(crate) reserved: [u8; 3],
    pub(crate) data: [u8; MAX_TRANSFER_BYTES],
}

impl Default for ScsiRequest {
    fn default() -> Self {
        Self {
            abi_version: ABI_VERSION,
            operation: 0,
            timeout_ms: 0,
            data_length: 0,
            offset: 0,
            save_pages: 0,
            reserved: [0; 3],
            data: [0; MAX_TRANSFER_BYTES],
        }
    }
}

impl Drop for ScsiRequest {
    /// Clears owned outbound manufacturing and other private payload bytes after dispatch.
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.data.zeroize();
    }
}

#[repr(C)]
pub(crate) struct ScsiResult {
    pub(crate) header: ResultHeader,
    pub(crate) attempted: u8,
    pub(crate) scsi_status: u8,
    pub(crate) service_response: u8,
    pub(crate) reserved: u8,
    pub(crate) realized_transfer_count: u64,
    pub(crate) data_length: u32,
    pub(crate) sense_length: u32,
    pub(crate) data: [u8; MAX_TRANSFER_BYTES],
    pub(crate) sense: [u8; MAX_SENSE_BYTES],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct MediaRecord {
    pub(crate) registry_entry_id: u64,
    pub(crate) whole_registry_entry_id: u64,
    pub(crate) uuid: [u8; UUID_BYTES],
}

#[repr(C)]
pub(crate) struct MappingResult {
    pub(crate) header: ResultHeader,
    pub(crate) whole_registry_entry_id: u64,
    pub(crate) media_count: u64,
    pub(crate) mounted_media_count: u64,
    pub(crate) capacity_bytes: u64,
    pub(crate) free_bytes: u64,
    pub(crate) mounted_device_id: u64,
    pub(crate) mounted_filesystem: u32,
    pub(crate) reserved_filesystem: u32,
    pub(crate) writable: u8,
    pub(crate) reserved: [u8; 7],
    pub(crate) mounted_path: [u8; MAX_MOUNT_PATH_BYTES],
    pub(crate) media: [MediaRecord; MAX_MEDIA],
}

#[repr(C)]
pub(crate) struct HostOperationResult {
    pub(crate) header: ResultHeader,
    pub(crate) attempted: u8,
    pub(crate) completed: u8,
    pub(crate) rejection: u8,
    pub(crate) reserved: [u8; 5],
    pub(crate) dissenter_status: i64,
}

#[repr(C)]
#[derive(Default)]
pub(crate) struct AbiLayout {
    pub(crate) abi_version: u32,
    pub(crate) reserved: u32,
    pub(crate) result_header_size: u64,
    pub(crate) result_header_status_offset: u64,
    pub(crate) candidate_size: u64,
    pub(crate) candidate_registry_entry_id_offset: u64,
    pub(crate) candidate_vendor_offset: u64,
    pub(crate) candidate_serial_offset: u64,
    pub(crate) enumeration_size: u64,
    pub(crate) enumeration_count_offset: u64,
    pub(crate) enumeration_candidates_offset: u64,
    pub(crate) readiness_size: u64,
    pub(crate) readiness_candidate_count_offset: u64,
    pub(crate) scsi_request_size: u64,
    pub(crate) scsi_request_data_offset: u64,
    pub(crate) scsi_result_size: u64,
    pub(crate) scsi_result_realized_transfer_offset: u64,
    pub(crate) scsi_result_data_offset: u64,
    pub(crate) scsi_result_sense_offset: u64,
    pub(crate) media_record_size: u64,
    pub(crate) media_record_uuid_offset: u64,
    pub(crate) mapping_result_size: u64,
    pub(crate) mapping_result_media_offset: u64,
    pub(crate) host_operation_result_size: u64,
    pub(crate) host_operation_dissenter_offset: u64,
    pub(crate) resource_counters_size: u64,
    pub(crate) resource_counters_device_frees_offset: u64,
    pub(crate) abi_layout_size: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct ResourceCounters {
    pub(crate) result_allocations: u64,
    pub(crate) result_frees: u64,
    pub(crate) io_acquisitions: u64,
    pub(crate) io_releases: u64,
    pub(crate) cf_acquisitions: u64,
    pub(crate) cf_releases: u64,
    pub(crate) plugin_acquisitions: u64,
    pub(crate) plugin_releases: u64,
    pub(crate) interface_acquisitions: u64,
    pub(crate) interface_releases: u64,
    pub(crate) exclusive_acquisitions: u64,
    pub(crate) exclusive_releases: u64,
    pub(crate) task_acquisitions: u64,
    pub(crate) task_releases: u64,
    pub(crate) device_allocations: u64,
    pub(crate) device_frees: u64,
    pub(crate) scsi_lease_allocations: u64,
    pub(crate) scsi_lease_frees: u64,
    pub(crate) da_registry_allocations: u64,
    pub(crate) da_registry_frees: u64,
    pub(crate) da_context_allocations: u64,
    pub(crate) da_context_frees: u64,
    pub(crate) da_contexts_outstanding: u64,
}

#[repr(C)]
pub(crate) struct Device {
    _private: [u8; 0],
}

#[repr(C)]
pub(crate) struct ScsiLease {
    _private: [u8; 0],
}

#[cfg(target_os = "macos")]
// SAFETY: declarations mirror the compiler-checked C header; the safe wrapper
// validates the complete ABI layout before tests and owns every pointer result.
unsafe extern "C" {
    pub(crate) fn rdx_macos_peer_session_record_is_valid(record: *const PeerSessionRecord) -> bool;
    #[cfg(test)]
    pub(crate) fn rdx_macos_peer_session_metadata_matches(
        record: *const PeerSessionRecord,
        expected_uid: u32,
        session_id: u32,
        attributes: u32,
        console_uid_after: u32,
    ) -> bool;
    #[cfg(test)]
    pub(crate) fn rdx_macos_peer_session_same_token(
        left: *const PeerSessionRecord,
        right: *const PeerSessionRecord,
    ) -> bool;
    pub(crate) fn rdx_macos_peer_session_user_id(record: *const PeerSessionRecord) -> u32;
    pub(crate) fn rdx_macos_peer_session_audit_session_id(record: *const PeerSessionRecord) -> u32;
    pub(crate) fn rdx_macos_accept_launchd_manager_with_session(
        listener: std::ffi::c_int,
        requirement: *const std::ffi::c_char,
        socket: *mut std::ffi::c_int,
        session: *mut PeerSessionRecord,
    ) -> u32;
    pub(crate) fn rdx_macos_revalidate_manager_session(
        socket: std::ffi::c_int,
        requirement: *const std::ffi::c_char,
        session: *const PeerSessionRecord,
    ) -> u32;
    pub(crate) fn rdx_macos_log_endpoint_native_code(phase: *const std::ffi::c_char, code: i32);
    pub(crate) fn rdx_macos_log_endpoint_phase(
        phase: *const std::ffi::c_char,
        result: *const std::ffi::c_char,
    );
    pub(crate) fn rdx_macos_run_directory_is_protected() -> bool;
    pub(crate) fn rdx_macos_enumerate(output: *mut *mut EnumerationResult) -> u32;
    pub(crate) fn rdx_macos_probe_readiness(output: *mut Readiness) -> u32;
    pub(crate) fn rdx_macos_candidate_matches_rdx_hint(candidate: *const CandidateRecord) -> bool;
    pub(crate) fn rdx_macos_open_candidate(
        candidate: *const CandidateRecord,
        output: *mut *mut Device,
    ) -> u32;
    pub(crate) fn rdx_macos_release_device(device: *mut Device);
    pub(crate) fn rdx_macos_acquire_scsi(device: *mut Device, output: *mut *mut ScsiLease) -> u32;
    pub(crate) fn rdx_macos_release_scsi(lease: *mut ScsiLease);
    pub(crate) fn rdx_macos_invalidate_media_mapping(device: *mut Device);
    pub(crate) fn rdx_macos_execute_scsi(
        lease: *mut ScsiLease,
        request: *const ScsiRequest,
        output: *mut *mut ScsiResult,
    ) -> u32;
    pub(crate) fn rdx_macos_map_media(device: *mut Device, output: *mut *mut MappingResult) -> u32;
    pub(crate) fn rdx_macos_media_present_without_mapping(
        device: *mut Device,
        present: *mut u8,
    ) -> u32;
    pub(crate) fn rdx_macos_revalidate_media(device: *mut Device) -> u32;
    pub(crate) fn rdx_macos_confirm_unmounted_mapping(device: *mut Device) -> u32;
    pub(crate) fn rdx_macos_validate_mounted_fd(
        device: *mut Device,
        descriptor: std::ffi::c_int,
        expected_device_id: u64,
    ) -> bool;
    pub(crate) fn rdx_macos_system_format(
        device: *mut Device,
        selector: u32,
        password: *const u8,
        length: usize,
        output: *mut *mut HostOperationResult,
    ) -> u32;
    #[cfg(feature = "test-hooks")]
    pub(crate) fn rdx_macos_test_system_format(
        bsd: *const std::ffi::c_char,
        selector: u32,
        password: *const u8,
        length: usize,
    ) -> bool;
    pub(crate) fn rdx_macos_partition_and_format(
        device: *mut Device,
        filesystem: u32,
        mbr_signature: u32,
        output: *mut *mut HostOperationResult,
    ) -> u32;
    pub(crate) fn rdx_macos_unmount(
        device: *mut Device,
        timeout_ms: u32,
        output: *mut *mut HostOperationResult,
    ) -> u32;
    pub(crate) fn rdx_macos_unmount_for_eject(
        device: *mut Device,
        timeout_ms: u32,
        output: *mut *mut HostOperationResult,
    ) -> u32;
    pub(crate) fn rdx_macos_eject(
        device: *mut Device,
        timeout_ms: u32,
        output: *mut *mut HostOperationResult,
    ) -> u32;
    pub(crate) fn rdx_macos_activate_launchd_listener(
        requirement: *const std::ffi::c_char,
        listener: *mut std::ffi::c_int,
    ) -> u32;
    #[cfg(test)]
    pub(crate) fn rdx_macos_accept_launchd_manager_from_listener(
        listener: std::ffi::c_int,
        requirement_text: *const std::ffi::c_char,
        socket: *mut std::ffi::c_int,
        user_id: *mut u32,
    ) -> u32;
    pub(crate) fn rdx_macos_free_result(result: *mut c_void);
    pub(crate) fn rdx_macos_get_abi_layout(output: *mut AbiLayout);
    pub(crate) fn rdx_macos_get_resource_counters(output: *mut ResourceCounters);
    pub(crate) fn rdx_macos_enable_acquisition_diagnostics();
    pub(crate) fn rdx_macos_copy_usb_identity(
        device: *mut Device,
        location_id: *mut u32,
        vendor_id: *mut u16,
        product_id: *mut u16,
        serial: *mut u8,
    ) -> u32;

    #[cfg(feature = "test-hooks")]
    pub(crate) fn rdx_macos_test_hostile_inputs() -> bool;
    #[cfg(feature = "test-hooks")]
    pub(crate) fn rdx_macos_test_exercise_failure_injections() -> bool;
    #[cfg(feature = "test-hooks")]
    pub(crate) fn rdx_macos_test_disk_mapping_contract() -> bool;
    #[cfg(feature = "test-hooks")]
    pub(crate) fn rdx_macos_test_raw_media_authority_contract() -> bool;
    #[cfg(feature = "test-hooks")]
    pub(crate) fn rdx_macos_test_exfat_retained_fd_contract() -> bool;
    #[cfg(feature = "test-hooks")]
    pub(crate) fn rdx_macos_test_scsi_authority_order() -> bool;
    #[cfg(feature = "test-hooks")]
    pub(crate) fn rdx_macos_test_da_callback_lifecycle() -> bool;
    #[cfg(feature = "test-hooks")]
    pub(crate) fn rdx_macos_test_candidate_prefilter_contract() -> bool;
    #[cfg(feature = "test-hooks")]
    pub(crate) fn rdx_macos_test_usb_bot_wire_contract() -> bool;
    #[cfg(feature = "test-hooks")]
    pub(crate) fn rdx_macos_test_eject_scsi_contract() -> bool;
    #[cfg(all(feature = "test-hooks", test))]
    pub(crate) fn rdx_macos_test_factory_snapshot_scsi_contract() -> bool;
    #[cfg(all(feature = "test-hooks", test))]
    pub(crate) fn rdx_macos_test_acquisition_diagnostics_contract() -> bool;
    #[cfg(feature = "test-hooks")]
    pub(crate) fn rdx_macos_test_usb_host_exception_contract() -> bool;
    #[cfg(feature = "test-hooks")]
    pub(crate) fn rdx_macos_test_usb_host_release_order_contract() -> bool;
    #[cfg(feature = "test-hooks")]
    pub(crate) fn rdx_macos_test_interface_error_provenance_contract() -> bool;
    #[cfg(feature = "test-hooks")]
    pub(crate) fn rdx_macos_test_transport_release_mapping_invalidation() -> bool;
    #[cfg(feature = "test-hooks")]
    pub(crate) fn rdx_macos_test_media_presence_without_mapping_contract() -> bool;
    #[cfg(feature = "test-hooks")]
    pub(crate) fn rdx_macos_test_fail_next_matching_dictionary();
    #[cfg(feature = "test-hooks")]
    pub(crate) fn rdx_macos_test_succeed_next_matching_without_iterator();
    #[cfg(feature = "test-hooks")]
    pub(crate) fn rdx_macos_test_probe_known_non_scsi() -> u32;
}
