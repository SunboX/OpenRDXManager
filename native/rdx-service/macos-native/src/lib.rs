#![deny(unsafe_op_in_unsafe_fn)]
// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later
#![deny(missing_docs)]
#![cfg_attr(not(target_os = "macos"), allow(dead_code))]

//! Safe ownership boundary around the OpenRDX macOS C bridge.
//!
//! The parent service remains `forbid(unsafe_code)`. This crate owns every FFI
//! pointer and exposes only closed semantic operations, opaque candidate leases,
//! and path-free Disk Arbitration metadata.

use std::fmt::{Debug, Formatter};
#[cfg(target_os = "macos")]
use std::path::PathBuf;
#[cfg(target_os = "macos")]
use std::ptr::{self, NonNull};

mod boundary;
mod counters;
mod endpoint;
mod ffi;
mod host;
pub mod local_trust;
mod manufacturing_contract;
mod migration_usb;
mod outcomes;
#[cfg(target_os = "macos")]
mod ownership;
#[cfg(not(target_os = "macos"))]
#[path = "ownership_unsupported.rs"]
mod ownership;
mod recovery_tty;
mod rom;
mod rom_inventory;
mod scsi;
#[cfg(target_os = "macos")]
mod user_directory;
#[cfg(target_os = "macos")]
pub use user_directory::user_home_directory;
#[cfg(target_os = "macos")]
mod scsi_worker;
#[cfg(target_os = "macos")]
mod scsi_worker_io;
mod serial_contract;
#[cfg(feature = "test-hooks")]
mod test_support;
mod usb_identity;
mod volume_label;
#[cfg(feature = "test-hooks")]
pub use test_support::system_format_virtual_disk_for_test;

pub use boundary::abi_layout_matches_c;
use boundary::optional_record_text;
#[cfg(target_os = "macos")]
use boundary::service_metadata_is_valid;
#[cfg(target_os = "macos")]
use boundary::{
    ResultExt, ResultOwner, attempted_failure, candidate_record_is_valid, flags_are_valid,
    parse_host_operation_outcome, record_text_is_valid, status_error, status_result, valid_header,
    valid_uuid,
};

pub use counters::{ResourceCounters, resource_counters};
pub use endpoint::{
    LaunchdEndpointContract, LaunchdManagerEndpointListener, ManagerEndpointConnection,
    accept_launchd_manager_endpoint, activate_launchd_manager_endpoint, launchd_endpoint_contract,
    local_manager_requirement, log_endpoint_phase, manager_requirement_is_pinned,
};
pub use migration_usb::observe_migration_usb;
pub use outcomes::{FileTestOutcome, HostOperationOutcome, MountedFilesystem};
pub use ownership::{
    HardwareOwnershipGuard, HardwareOwnershipNamespace, hardware_ownership_contract,
    initialize_hardware_ownership_namespace, try_acquire_hardware_ownership,
};
pub use recovery_tty::discard_recovery_terminal_input;
pub use rom::{RomFailure, RomSession};
pub use rom_inventory::{RomCandidate, enumerate_rom_candidates};
pub use scsi::{ScsiOperation, enable_acquisition_diagnostics};
#[cfg(target_os = "macos")]
pub use scsi_worker::{MacScsiWorkerLease, run_scsi_worker, run_serial_scsi_worker};
#[cfg(feature = "test-hooks")]
pub use test_support::{
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
pub use usb_identity::MacUsbIdentity;

const SERVICE_METADATA: &str = include_str!("../../resources/macos/com.openrdx.hardware.plist");

/// Sanitized native-boundary failure with no registry ID, path, or native text.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeError {
    /// The current host is not macOS.
    UnsupportedPlatform,
    /// A bounded request or private record was malformed.
    InvalidRequest,
    /// The documented user-space SCSI task interface is unavailable.
    TransportUnavailable,
    /// The current process lacks the required access.
    AccessDenied,
    /// Sharing, exclusive access, or device state prevented the operation.
    Busy,
    /// The bounded native operation timed out.
    TimedOut,
    /// Hotplug removed or replaced the exact selected registry entry.
    DeviceRemoved,
    /// IOKit or Disk Arbitration enumeration failed safely.
    EnumerationFailed,
    /// A fixed native resource or output bound was exceeded.
    ResourceLimit,
    /// Complete identity, ancestry, or media evidence was unavailable.
    EvidenceIncomplete,
    /// Another sanitized native failure occurred.
    Other,
}

/// Pointer-free readiness facts copied from the native capability probe.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Readiness {
    discovery_available: bool,
    safe_transport_available: bool,
    service_metadata_present: bool,
    service_enabled: bool,
    current_process_authorized: bool,
    candidate_count: usize,
}

impl Readiness {
    /// Returns whether the linked IOKit discovery API initialized safely.
    #[must_use]
    pub const fn discovery_available(self) -> bool {
        self.discovery_available
    }

    /// Returns whether this global snapshot proved a safely usable task transport.
    ///
    /// Exact interface availability remains a candidate-local scan result, so
    /// non-invasive startup does not infer this fact from linked API support.
    #[must_use]
    pub const fn safe_transport_available(self) -> bool {
        self.safe_transport_available
    }

    /// Returns whether secure helper metadata is compiled into this package.
    #[must_use]
    pub const fn service_metadata_present(self) -> bool {
        self.service_metadata_present
    }

    /// Returns whether ServiceManagement proved the helper enabled at runtime.
    #[must_use]
    pub const fn service_enabled(self) -> bool {
        self.service_enabled
    }

    /// Returns whether this process proved current helper authority.
    #[must_use]
    pub const fn current_process_authorized(self) -> bool {
        self.current_process_authorized
    }

    /// Returns the non-snapshot readiness count, which is always zero.
    ///
    /// Inventory is dynamic and belongs to each explicit enumeration call.
    #[must_use]
    pub const fn candidate_count(self) -> usize {
        self.candidate_count
    }

    const fn unavailable() -> Self {
        Self {
            discovery_available: false,
            safe_transport_available: false,
            service_metadata_present: false,
            service_enabled: false,
            current_process_authorized: false,
            candidate_count: 0,
        }
    }
}

/// Non-cloneable exact IOKit registry-entry lease retained from enumeration.
pub struct MacCandidate {
    record: ffi::CandidateRecord,
    token: String,
}

/// Registry-generation-independent identity used only to reopen one enumerated device.
///
/// This value omits the transient registry entry ID and cannot itself authorize
/// native access. Reopening still requires one fresh, unique enumerated candidate.
pub struct MacRematchIdentity {
    record: ffi::CandidateRecord,
}

impl MacCandidate {
    /// Returns a bounded opaque enumeration token unrelated to a device path.
    #[must_use]
    pub fn token(&self) -> &str {
        &self.token
    }

    /// Returns the optional printable vendor hint retained for Task 1 validation.
    #[must_use]
    pub fn vendor(&self) -> Option<&str> {
        optional_record_text(self.record.has_vendor, &self.record.vendor)
    }

    /// Returns the optional printable product hint retained for Task 1 validation.
    #[must_use]
    pub fn product(&self) -> Option<&str> {
        optional_record_text(self.record.has_product, &self.record.product)
    }

    /// Returns the optional printable serial hint retained for Task 1 validation.
    #[must_use]
    pub fn serial(&self) -> Option<&str> {
        optional_record_text(self.record.has_serial, &self.record.serial)
    }

    /// Returns whether immutable registry properties match the documented hint.
    ///
    /// This narrow property-only prefilter is not RDX admission proof. The
    /// service must still validate raw INQUIRY and capability replies.
    #[must_use]
    pub fn matches_rdx_identity_hint(&self) -> bool {
        #[cfg(target_os = "macos")]
        {
            // SAFETY: the record is fixed-layout, immutable, and lives for the call.
            unsafe { ffi::rdx_macos_candidate_matches_rdx_hint(&self.record) }
        }
        #[cfg(not(target_os = "macos"))]
        {
            false
        }
    }

    /// Copies the immutable fields needed to select the same device after rematch.
    #[must_use]
    pub fn rematch_identity(&self) -> MacRematchIdentity {
        MacRematchIdentity {
            record: self.record,
        }
    }

    /// Compares the same unique stable identity accepted for native rematching.
    ///
    /// Registry entry IDs are intentionally excluded because the macOS storage
    /// stack assigns a new entry after USB capture is released. A missing serial
    /// fails closed, matching the native rebound policy.
    #[must_use]
    pub fn stable_identity_matches(&self, other: &Self) -> bool {
        self.rematch_identity().matches(other)
    }
}

impl MacRematchIdentity {
    /// Returns whether one fresh candidate has the same complete stable identity.
    fn matches(&self, candidate: &MacCandidate) -> bool {
        self.record.has_serial == 1
            && candidate.record.has_serial == 1
            && self.record.peripheral_type == candidate.record.peripheral_type
            && self.record.has_vendor == candidate.record.has_vendor
            && self.record.has_product == candidate.record.has_product
            && self.record.has_revision == candidate.record.has_revision
            && self.record.vendor == candidate.record.vendor
            && self.record.product == candidate.record.product
            && self.record.revision == candidate.record.revision
            && self.record.serial == candidate.record.serial
    }

    /// Selects exactly one same-identity candidate from a fresh enumeration.
    fn select_unique<'candidate>(
        &self,
        candidates: &'candidate [MacCandidate],
    ) -> Result<&'candidate MacCandidate, NativeError> {
        let mut matches = candidates
            .iter()
            .filter(|candidate| self.matches(candidate));
        let selected = matches.next().ok_or(NativeError::DeviceRemoved)?;
        if matches.next().is_some() {
            return Err(NativeError::EvidenceIncomplete);
        }
        Ok(selected)
    }
}

impl Debug for MacRematchIdentity {
    /// Redacts every copied device-identity field.
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("MacRematchIdentity(<private>)")
    }
}

impl Debug for MacCandidate {
    /// Redacts the registry entry ID and all untrusted properties.
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("MacCandidate(<private>)")
    }
}

/// Pointer-free completion copied from one synchronous `ExecuteTaskSync` call.
#[derive(Clone, Eq, PartialEq)]
pub enum Completion {
    /// Validation, allocation, or task setup failed before execution was invoked.
    NotAttempted(NativeError),
    /// Execution was invoked but no usable SCSI completion was proven.
    AttemptedError(NativeError),
    /// The task API returned bounded device status, data, and sense bytes.
    Device {
        /// Raw SCSI status returned by the task interface.
        scsi_status: u8,
        /// Raw Apple SCSI service response returned by the task interface.
        service_response: u8,
        /// Realized transfer count returned by the task interface.
        transferred_length: u32,
        /// Bounded copied transfer bytes.
        data: Vec<u8>,
        /// Native request-sense length retained separately from copied bytes.
        sense_reported_length: usize,
        /// Bounded copied request-sense bytes.
        sense: Vec<u8>,
    },
}

impl Debug for Completion {
    /// Reports stable status and lengths while redacting native buffers.
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotAttempted(error) => {
                formatter.debug_tuple("NotAttempted").field(error).finish()
            }
            Self::AttemptedError(error) => formatter
                .debug_tuple("AttemptedError")
                .field(error)
                .finish(),
            Self::Device {
                scsi_status,
                service_response,
                transferred_length,
                data,
                sense_reported_length,
                sense,
            } => formatter
                .debug_struct("Device")
                .field("scsi_status", scsi_status)
                .field("service_response", service_response)
                .field("transferred_length", transferred_length)
                .field("data_length", &data.len())
                .field("data", &"<private>")
                .field("sense_reported_length", sense_reported_length)
                .field("sense_copied_length", &sense.len())
                .field("sense", &"<private>")
                .finish(),
        }
    }
}

/// Opaque exact-device lease whose IOKit objects never leave this crate.
pub struct MacDevice {
    #[cfg(target_os = "macos")]
    inner: NonNull<ffi::Device>,
}

/// Opaque exclusive task authority obtained only from a pinned, unmounted device.
pub struct MacScsiLease {
    #[cfg(target_os = "macos")]
    inner: NonNull<ffi::ScsiLease>,
}

#[cfg(target_os = "macos")]
// SAFETY: C owns a unique, non-shareable device allocation. Safe methods require
// `&mut self`, and the bridge performs each IOKit call synchronously.
unsafe impl Send for MacDevice {}

#[cfg(target_os = "macos")]
// SAFETY: C uniquely owns the interface and exclusive-access allocation. Safe
// execution requires `&mut self` and the bridge performs calls synchronously.
unsafe impl Send for MacScsiLease {}

impl MacDevice {
    /// Atomically reopens and revalidates one exact enumeration lease.
    ///
    /// # Errors
    ///
    /// Returns a sanitized access, hotplug, busy, or safe-interface failure.
    pub fn open(candidate: &MacCandidate) -> Result<Self, NativeError> {
        if !candidate.matches_rdx_identity_hint() {
            return Err(NativeError::EvidenceIncomplete);
        }
        #[cfg(target_os = "macos")]
        {
            let mut output = ptr::null_mut();
            // SAFETY: `candidate.record` is a fully initialized fixed-layout value,
            // and `output` points to writable storage for the owned result pointer.
            let status = unsafe { ffi::rdx_macos_open_candidate(&candidate.record, &mut output) };
            let result = status_result(status);
            match (result, NonNull::new(output)) {
                (Ok(()), Some(inner)) => Ok(Self { inner }),
                (Ok(()), None) => Err(NativeError::Other),
                (Err(error), _) => {
                    if let Some(inner) = NonNull::new(output) {
                        // SAFETY: a non-null device returned by C is owned by this call.
                        unsafe { ffi::rdx_macos_release_device(inner.as_ptr()) };
                    }
                    Err(error)
                }
            }
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = candidate;
            Err(NativeError::UnsupportedPlatform)
        }
    }

    /// Obtains exclusive task authority after exact media mapping is unmounted.
    ///
    /// # Errors
    ///
    /// Returns `Busy` for mounted media, or a sanitized identity/interface
    /// failure. This method never requests an unmount itself.
    pub fn acquire_scsi(&mut self) -> Result<MacScsiLease, NativeError> {
        #[cfg(target_os = "macos")]
        {
            let mut output = ptr::null_mut();
            // SAFETY: the nonexclusive authority remains uniquely borrowed and
            // C either returns one separately owned lease or leaves null.
            let status = unsafe { ffi::rdx_macos_acquire_scsi(self.inner.as_ptr(), &mut output) };
            match (status_result(status), NonNull::new(output)) {
                (Ok(()), Some(inner)) => Ok(MacScsiLease { inner }),
                (Ok(()), None) => Err(NativeError::Other),
                (Err(error), maybe_inner) => {
                    if let Some(inner) = maybe_inner {
                        // SAFETY: unexpected non-null failure output remains owned here.
                        unsafe { ffi::rdx_macos_release_scsi(inner.as_ptr()) };
                    }
                    Err(error)
                }
            }
        }
        #[cfg(not(target_os = "macos"))]
        {
            Err(NativeError::UnsupportedPlatform)
        }
    }

    /// Discards Disk Arbitration objects before releasing rematching transport.
    ///
    /// The stable candidate identity remains retained so the next media pin can
    /// rebind to the same physical RDX device after USB BOT release.
    pub fn invalidate_media_mapping_for_rematch(&mut self) {
        #[cfg(target_os = "macos")]
        {
            // SAFETY: this unique device authority owns the retained mapping;
            // C releases it synchronously without changing candidate identity.
            unsafe { ffi::rdx_macos_invalidate_media_mapping(self.inner.as_ptr()) };
        }
    }

    /// Proves whether exact whole media is currently present without retaining
    /// Disk Arbitration mapping objects or opening a raw disk descriptor.
    ///
    /// # Errors
    ///
    /// Returns a sanitized hotplug, enumeration, identity-evidence, or native
    /// failure. Existing retained mapping or raw authority is rejected.
    pub fn media_present_without_mapping(&mut self) -> Result<bool, NativeError> {
        #[cfg(target_os = "macos")]
        {
            let mut present = 0_u8;
            // SAFETY: this unique device authority remains valid for the
            // synchronous probe, and `present` is writable one-byte storage.
            let status = unsafe {
                ffi::rdx_macos_media_present_without_mapping(self.inner.as_ptr(), &mut present)
            };
            status_result(status)?;
            match present {
                0 => Ok(false),
                1 => Ok(true),
                _ => Err(NativeError::Other),
            }
        }
        #[cfg(not(target_os = "macos"))]
        {
            Err(NativeError::UnsupportedPlatform)
        }
    }

    /// Opens one fresh same-device authority after storage-driver rematching.
    ///
    /// # Errors
    ///
    /// Returns a sanitized enumeration, absence, ambiguity, or open failure.
    pub fn open_after_storage_rematch(identity: &MacRematchIdentity) -> Result<Self, NativeError> {
        eprintln!("openrdx-hardware: trace eject-authority-enumerate-enter");
        let candidates = enumerate_candidates()?;
        eprintln!("openrdx-hardware: trace eject-authority-enumerate-return");
        let candidate = identity.select_unique(&candidates)?;
        eprintln!("openrdx-hardware: trace eject-authority-select-return");
        eprintln!("openrdx-hardware: trace eject-authority-open-enter");
        let authority = Self::open(candidate)?;
        eprintln!("openrdx-hardware: trace eject-authority-open-return");
        Ok(authority)
    }

    /// Unmounts the already pinned exact whole-media mapping without taking a
    /// second Disk Arbitration snapshot between authorization and mutation.
    #[must_use]
    pub fn unmount_pinned(&mut self, timeout_ms: u32) -> HostOperationOutcome {
        run_pinned_host_operation(self, timeout_ms, false, true)
    }

    /// Revalidates the pinned identity after proving that every retained
    /// volume is unmounted.
    ///
    /// # Errors
    ///
    /// Returns a sanitized busy, stale-identity, or native evidence failure.
    pub fn confirm_unmounted(&mut self) -> Result<(), NativeError> {
        #[cfg(target_os = "macos")]
        {
            // SAFETY: this unique authority owns the exact pinned mapping and
            // C accepts no caller-selected path or identity.
            let status = unsafe { ffi::rdx_macos_confirm_unmounted_mapping(self.inner.as_ptr()) };
            status_result(status)
        }
        #[cfg(not(target_os = "macos"))]
        {
            Err(NativeError::UnsupportedPlatform)
        }
    }

    /// Pins exact Disk Arbitration media identities for future host operations.
    ///
    /// # Errors
    ///
    /// Returns a bounded evidence or enumeration failure and never exposes a path.
    pub fn pin_media(&mut self) -> Result<MediaLeaseSet<'_>, NativeError> {
        #[cfg(target_os = "macos")]
        {
            let mut output = ptr::null_mut();
            // SAFETY: the device is uniquely borrowed and C initializes `output`.
            let status = unsafe { ffi::rdx_macos_map_media(self.inner.as_ptr(), &mut output) };
            let owner = ResultOwner::new(output).ok_or_else(|| status_error(status))?;
            // SAFETY: `owner` uniquely owns a C-allocated `MappingResult` until drop.
            let result = unsafe { owner.as_ref() };
            if !valid_header(&result.header, ffi::RESULT_MAPPING, status)
                || result.media_count as usize > ffi::MAX_MEDIA
                || result.mounted_media_count > result.media_count + 1
                || result.writable > 1
                || !matches!(result.mounted_filesystem, 0 | 1 | 2 | 3 | 7 | 11)
                || result.reserved_filesystem != 0
                || (result.whole_registry_entry_id != 0 && result.capacity_bytes == 0)
            {
                return Err(NativeError::Other);
            }
            status_result(status)?;
            let media_count = result.media_count as usize;
            for record in &result.media[..media_count] {
                if record.registry_entry_id == 0
                    || record.whole_registry_entry_id != result.whole_registry_entry_id
                    || !valid_uuid(&record.uuid)
                {
                    return Err(NativeError::EvidenceIncomplete);
                }
            }
            let mount_path = host::mapping_mount_path(result)?;
            if (result.mounted_media_count == 1) != mount_path.is_some()
                || (result.mounted_media_count == 0 && result.free_bytes != 0)
                || (result.mounted_media_count == 1) != (result.mounted_device_id != 0)
            {
                return Err(NativeError::EvidenceIncomplete);
            }
            let mutation_topology_safe = mount_path.as_ref().is_none_or(|path| {
                path.to_str().is_some_and(|path| {
                    path != "/"
                        && path != "/System"
                        && path != "/usr"
                        && path != "/var"
                        && path != "/private/var"
                        && path != "/System/Volumes"
                        && !path.starts_with("/System/Volumes/")
                })
            });
            let identity_material = mapping_identity_material(&result.media[..media_count]);
            Ok(MediaLeaseSet {
                device: self,
                media_count,
                mounted_media_count: result.mounted_media_count as usize,
                whole_media_present: result.whole_registry_entry_id != 0,
                writable: result.writable == 1,
                free_bytes: result.free_bytes,
                capacity_bytes: result.capacity_bytes,
                mutation_topology_safe,
                identity_material,
                mounted_device_id: result.mounted_device_id,
                mounted_filesystem: mounted_filesystem_from_native(result.mounted_filesystem),
                mount_path,
            })
        }
        #[cfg(not(target_os = "macos"))]
        {
            Err(NativeError::UnsupportedPlatform)
        }
    }
}

/// Builds rematch-stable cartridge material while native registry IDs remain
/// confined to same-generation mutation revalidation.
fn mapping_identity_material(records: &[ffi::MediaRecord]) -> Vec<u8> {
    let mut identity = Vec::with_capacity(8 + records.len() * ffi::UUID_BYTES);
    identity.extend_from_slice(&(records.len() as u64).to_be_bytes());
    for record in records {
        identity.extend_from_slice(&record.uuid);
    }
    identity
}

/// Decodes the closed native mounted-filesystem discriminant.
const fn mounted_filesystem_from_native(value: u32) -> Option<MountedFilesystem> {
    match value {
        1 => Some(MountedFilesystem::ExFat),
        2 => Some(MountedFilesystem::Ntfs),
        3 | 7 | 11 => Some(MountedFilesystem::MacOs(value)),
        _ => None,
    }
}

impl Debug for MacDevice {
    /// Redacts the native allocation and exact registry identity.
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("MacDevice(<private>)")
    }
}

#[cfg(target_os = "macos")]
impl Drop for MacScsiLease {
    /// Releases exclusive access, interface, plug-in, and retained service once.
    fn drop(&mut self) {
        // SAFETY: `inner` is uniquely owned from successful acquisition to drop.
        unsafe { ffi::rdx_macos_release_scsi(self.inner.as_ptr()) };
    }
}

impl Debug for MacScsiLease {
    /// Redacts the interface, registry identity, and exclusive state.
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("MacScsiLease(<private>)")
    }
}

/// Exact Disk Arbitration media leases tied to one open device lifetime.
pub struct MediaLeaseSet<'device> {
    device: &'device mut MacDevice,
    media_count: usize,
    mounted_media_count: usize,
    whole_media_present: bool,
    writable: bool,
    free_bytes: u64,
    capacity_bytes: u64,
    mutation_topology_safe: bool,
    identity_material: Vec<u8>,
    mounted_device_id: u64,
    mounted_filesystem: Option<MountedFilesystem>,
    #[cfg(target_os = "macos")]
    mount_path: Option<PathBuf>,
}

impl MediaLeaseSet<'_> {
    /// Returns the count of exact UUID-bearing child media leases.
    #[must_use]
    pub const fn media_count(&self) -> usize {
        self.media_count
    }

    /// Returns the exact number of mounted whole or child media records.
    #[must_use]
    pub const fn mounted_media_count(&self) -> usize {
        self.mounted_media_count
    }

    /// Returns whether one unique exact whole-media ancestor was retained.
    #[must_use]
    pub const fn whole_media_present(&self) -> bool {
        self.whole_media_present
    }

    /// Returns exact media write protection plus mounted free and total bytes.
    #[must_use]
    pub const fn volume_facts(&self) -> (bool, u64, u64) {
        (self.writable, self.free_bytes, self.capacity_bytes)
    }

    /// Revalidates the exact pinned media after proving every retained volume is unmounted.
    ///
    /// Disk Arbitration may report a stale callback generation after it has
    /// already completed the unmount. This boundary accepts only the exact
    /// retained identity with a freshly proven unmounted postcondition.
    ///
    /// # Errors
    ///
    /// Returns a sanitized busy, stale-identity, or native evidence failure.
    pub fn confirm_unmounted(&mut self) -> Result<(), NativeError> {
        #[cfg(target_os = "macos")]
        {
            // SAFETY: the unique mapping borrow retains every exact native
            // identity while C proves the current unmounted postcondition.
            let status =
                unsafe { ffi::rdx_macos_confirm_unmounted_mapping(self.device.inner.as_ptr()) };
            status_result(status)?;
            self.mounted_media_count = 0;
            self.free_bytes = 0;
            self.mounted_filesystem = None;
            self.mount_path = None;
            Ok(())
        }
        #[cfg(not(target_os = "macos"))]
        {
            Err(NativeError::UnsupportedPlatform)
        }
    }

    /// Reports whether the selected exact mount is not a root/system filesystem.
    #[must_use]
    pub const fn mutation_topology_safe(&self) -> bool {
        self.mutation_topology_safe
    }

    /// Returns bounded path-free Disk Arbitration and IOKit media identity material.
    #[must_use]
    pub fn identity_material(&self) -> &[u8] {
        &self.identity_material
    }

    /// Returns whether Disk Arbitration reports exFAT for the sole mounted volume.
    #[must_use]
    pub const fn mounted_filesystem_is_exfat(&self) -> bool {
        matches!(self.mounted_filesystem, Some(MountedFilesystem::ExFat))
    }

    /// Returns the recognized filesystem for the sole mounted volume.
    #[must_use]
    pub const fn mounted_filesystem(&self) -> Option<MountedFilesystem> {
        self.mounted_filesystem
    }

    /// Runs create-new/no-follow/write/fsync/reopen/read/unlink on the exact mount.
    #[must_use]
    pub fn write_read_file(&mut self, filename: &str, bytes: &[u8]) -> FileTestOutcome {
        #[cfg(target_os = "macos")]
        {
            self.write_read_file_native(filename, bytes)
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (filename, bytes);
            FileTestOutcome {
                operation: Err(NativeError::UnsupportedPlatform),
                operation_certainty: HostOperationOutcome::NotAttempted(
                    NativeError::UnsupportedPlatform,
                ),
                cleanup: HostOperationOutcome::NotAttempted(NativeError::UnsupportedPlatform),
            }
        }
    }

    /// Requests a bounded whole-disk unmount through Disk Arbitration.
    #[must_use]
    pub fn unmount(&mut self, timeout_ms: u32) -> HostOperationOutcome {
        self.run_host_operation(timeout_ms, false, true)
    }

    /// Requests the unmount half of Safe Eject without claiming the disk again.
    #[must_use]
    pub fn unmount_for_eject(&mut self, timeout_ms: u32) -> HostOperationOutcome {
        self.run_host_operation(timeout_ms, false, false)
    }

    /// Requests a bounded whole-disk eject through Disk Arbitration.
    #[must_use]
    pub fn eject(&mut self, timeout_ms: u32) -> HostOperationOutcome {
        self.run_host_operation(timeout_ms, true, false)
    }

    /// Runs one validated Disk Arbitration mutation for this pinned mapping.
    fn run_host_operation(
        &mut self,
        timeout_ms: u32,
        eject: bool,
        claim_after_unmount: bool,
    ) -> HostOperationOutcome {
        if timeout_ms == 0 || timeout_ms > 30_000 || !self.whole_media_present {
            return HostOperationOutcome::NotAttempted(NativeError::InvalidRequest);
        }
        run_pinned_host_operation(self.device, timeout_ms, eject, claim_after_unmount)
    }
}

/// Runs one bounded host operation against an already pinned exact mapping.
fn run_pinned_host_operation(
    device: &mut MacDevice,
    timeout_ms: u32,
    eject: bool,
    claim_after_unmount: bool,
) -> HostOperationOutcome {
    if timeout_ms == 0 || timeout_ms > 30_000 {
        return HostOperationOutcome::NotAttempted(NativeError::InvalidRequest);
    }
    #[cfg(target_os = "macos")]
    {
        let mut output = ptr::null_mut();
        // SAFETY: the exact mapped device is uniquely borrowed, timeout is
        // bounded, and C owns its run-loop callback plus result allocation.
        let status = unsafe {
            if eject {
                ffi::rdx_macos_eject(device.inner.as_ptr(), timeout_ms, &mut output)
            } else if claim_after_unmount {
                ffi::rdx_macos_unmount(device.inner.as_ptr(), timeout_ms, &mut output)
            } else {
                ffi::rdx_macos_unmount_for_eject(device.inner.as_ptr(), timeout_ms, &mut output)
            }
        };
        let Some(owner) = ResultOwner::new(output) else {
            return HostOperationOutcome::NotAttempted(
                status_result(status).unwrap_err_or(NativeError::Other),
            );
        };
        // SAFETY: owner uniquely owns a C `HostOperationResult` until drop.
        let result = unsafe { owner.as_ref() };
        if !valid_header(&result.header, ffi::RESULT_HOST_OPERATION, status) {
            return HostOperationOutcome::CompletionUnknown(NativeError::Other);
        }
        parse_host_operation_outcome(status, result)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (device, eject, claim_after_unmount);
        HostOperationOutcome::NotAttempted(NativeError::UnsupportedPlatform)
    }
}

impl Debug for MediaLeaseSet<'_> {
    /// Reports counts while redacting every native identity and object.
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("MediaLeaseSet")
            .field("media_count", &self.media_count)
            .field("whole_media_present", &self.whole_media_present)
            .field("identities", &"<private>")
            .finish()
    }
}

/// Probes static non-invasive IOKit discovery and packaged service metadata facts.
#[must_use]
pub fn probe_readiness() -> Readiness {
    #[cfg(target_os = "macos")]
    {
        let mut native = ffi::Readiness::default();
        // SAFETY: `native` is writable and has the exact fixed C layout.
        let status = unsafe { ffi::rdx_macos_probe_readiness(&mut native) };
        if status_result(status).is_err()
            || native.abi_version != ffi::ABI_VERSION
            || native.status != status
            || !flags_are_valid(&[
                native.discovery_available,
                native.safe_transport_available,
                native.service_metadata_present,
                native.service_enabled,
                native.current_process_authorized,
            ])
            || native.candidate_count as usize > ffi::MAX_CANDIDATES
        {
            return Readiness::unavailable();
        }
        let packaged_metadata = service_metadata_is_valid();
        Readiness {
            discovery_available: native.discovery_available == 1,
            safe_transport_available: native.safe_transport_available == 1,
            service_metadata_present: packaged_metadata,
            service_enabled: native.service_enabled == 1,
            current_process_authorized: native.current_process_authorized == 1,
            candidate_count: native.candidate_count as usize,
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        Readiness::unavailable()
    }
}

/// Proves the current endpoint process is running as the privileged service account.
#[must_use]
pub fn current_process_is_privileged_service() -> bool {
    #[cfg(target_os = "macos")]
    {
        // SAFETY: `geteuid` accepts no pointers and has no preconditions.
        unsafe { libc::geteuid() == 0 }
    }
    #[cfg(not(target_os = "macos"))]
    {
        false
    }
}

/// Enumerates bounded direct-access SCSI candidates without claiming RDX identity.
///
/// Enumeration copies registry properties only. The service applies the narrow
/// identity hint before any task plug-in, interface query, or exclusive access.
///
/// # Errors
///
/// Returns a sanitized native, ABI, duplicate-identity, or output-bound failure.
pub fn enumerate_candidates() -> Result<Vec<MacCandidate>, NativeError> {
    #[cfg(target_os = "macos")]
    {
        let mut output = ptr::null_mut();
        // SAFETY: C initializes or leaves null the writable result pointer.
        let status = unsafe { ffi::rdx_macos_enumerate(&mut output) };
        let owner = ResultOwner::new(output).ok_or_else(|| status_error(status))?;
        // SAFETY: `owner` uniquely owns a C `EnumerationResult` until drop.
        let result = unsafe { owner.as_ref() };
        if !valid_header(&result.header, ffi::RESULT_ENUMERATION, status)
            || result.count as usize > ffi::MAX_CANDIDATES
        {
            return Err(NativeError::Other);
        }
        status_result(status)?;
        let count = result.count as usize;
        let mut candidates = Vec::with_capacity(count);
        for (index, record) in result.candidates[..count].iter().copied().enumerate() {
            if !candidate_record_is_valid(&record)
                || candidates.iter().any(|candidate: &MacCandidate| {
                    candidate.record.registry_entry_id == record.registry_entry_id
                })
            {
                return Err(NativeError::EnumerationFailed);
            }
            candidates.push(MacCandidate {
                record,
                token: format!("macos-candidate-{index:03}"),
            });
        }
        Ok(candidates)
    }
    #[cfg(not(target_os = "macos"))]
    {
        Err(NativeError::UnsupportedPlatform)
    }
}

#[cfg(all(test, target_os = "macos"))]
mod tests;
