#![deny(unsafe_op_in_unsafe_fn)]
#![deny(missing_docs)]

//! Safe, package-private ownership boundary around OpenRDX Windows APIs.
//!
//! The parent service remains `forbid(unsafe_code)`. This crate owns every
//! Win32 handle and pointer, exposes no raw handle or device path, and accepts
//! only bounded requests built by the parent's trusted protocol layer.

use std::ffi::OsStr;
#[cfg(any(windows, test))]
use std::marker::PhantomData;

#[cfg(any(windows, test))]
const MAX_CDB_LENGTH: usize = 16;
const MAX_TRANSFER_LENGTH: usize = 0x1000;
#[cfg(any(windows, test))]
const MAX_SENSE_LENGTH: usize = 0xFC;
const MAX_TIMEOUT_SECONDS: u32 = 300;
const DEFAULT_TIMEOUT_SECONDS: u32 = 30;
const MAX_U24: u32 = 0x00FF_FFFF;
#[cfg(any(windows, test))]
const MAX_ADAPTER_ALIGNMENT_MASK: usize = 0x000F_FFFF;

mod drive_letter_policy;
mod endpoint;
#[cfg(any(windows, test))]
mod filesystem_facts;
mod host;
/// Fixed, ACL-verified Windows manufacturing backup storage.
#[cfg(windows)]
pub mod manufacturing_storage;
#[cfg(any(windows, test))]
mod media;
mod openrdx;
mod ownership;
mod readiness;
mod registry_acl;
#[cfg(any(windows, test))]
mod safe_eject;
mod service;
mod service_acl;
#[cfg(any(windows, test))]
mod spti_diagnostics;

#[cfg(windows)]
mod drive_letter;

pub use drive_letter_policy::{
    ArrivalDriveLetterPlan, available_drive_letters_from_state, plan_arrival_drive_letter,
};
pub use endpoint::{
    ManagerEndpointConnection, NamedPipeClientAccessContract, NamedPipeEndpointContract,
    NamedPipeManagerEndpointListener, named_pipe_client_access_contract,
    named_pipe_endpoint_contract,
};
pub use host::{SafeDismountOutcome, WindowsDevice};
pub use ownership::{
    HardwareOwnershipGuard, HardwareOwnershipNamespace, current_process_is_elevated,
    hardware_ownership_contract, initialize_hardware_ownership_namespace,
    try_acquire_hardware_ownership,
};

#[cfg(any(windows, test))]
mod mutation;

#[cfg(any(windows, test))]
mod identity;

#[cfg(any(windows, test))]
mod vds_status;
#[cfg(any(windows, test))]
mod volume;

#[cfg(windows)]
use identity::DecodedRecipe;
#[cfg(windows)]
use identity::query_volume_topology;
#[cfg(any(windows, test))]
use identity::{
    DeviceIdentityProof, StorageDeviceIdentity, VolumeExtent, VolumeMembership, VolumeTopology,
    classify_volume_probe, decode_recipe, volume_extent_buffer_length,
};
#[cfg(test)]
use mutation::execute_safe_dismount;
#[cfg(windows)]
use mutation::execute_safe_dismount_all;
#[cfg(any(windows, test))]
use mutation::{VolumeInventory, VolumeMutationIo, VolumeRecord};
pub use readiness::Readiness;
#[cfg(test)]
use readiness::exact_service_binary_path;
#[cfg(any(windows, test))]
use readiness::{
    AuthorityEvidence, ServiceIdentityEvidence, ServiceRuntimeEvidence, ServiceStatusQueryAction,
    ServiceStatusQueryResult, exact_endpoint_service_binary_path, service_status_query_action,
};
pub use registry_acl::{
    RegistryDaclContract, RegistryDaclEntry, RegistryDaclPrincipal,
    drive_letter_registry_dacl_contract,
};
pub use service::{
    WindowsServiceConnection, WindowsServiceLifecycle, WindowsServiceSnapshot, WindowsServiceState,
    run_windows_service_dispatcher,
};
pub use service_acl::{
    ManagerServiceAccessAction, ManagerServiceAccessCommand, ManagerServiceAccessOutcome,
    ServiceDaclContract, ServiceDaclEntry, ServiceDaclPrincipal, apply_manager_service_access,
    parse_manager_service_access_arguments, service_dacl_contract,
};

/// Enumerates assignable Windows letters without exposing registry or path data.
///
/// The Windows implementation reads only the logical-drive bitmap and the fixed
/// application-owned preference root. Other hosts fail closed.
///
/// # Errors
///
/// Returns a sanitized native error when host enumeration, access, or bounded
/// preference validation is incomplete.
pub fn available_drive_letters() -> Result<Vec<char>, NativeError> {
    #[cfg(windows)]
    {
        drive_letter::available_drive_letters()
    }
    #[cfg(not(windows))]
    {
        Err(NativeError::UnsupportedPlatform)
    }
}

/// Runs the Windows-only private killable VDS worker process mode.
///
/// This entry accepts only the fixed inherited-stdin binary protocol emitted
/// by the retained native service. It is not an Electron or CLI operation.
#[must_use]
pub fn run_internal_vds_worker() -> u8 {
    #[cfg(windows)]
    {
        native::run_internal_vds_worker()
    }
    #[cfg(not(windows))]
    {
        13
    }
}
#[cfg(any(windows, test))]
use volume::mount_paths_from_multi_sz;
#[cfg(test)]
use volume::volume_extents_contain_disk;
#[cfg(any(windows, test))]
use volume::volume_extents_from_bytes;
#[cfg(test)]
use volume::{canonical_volume_guid_paths_from_multi_sz, drive_letters_from_multi_sz};

/// Closes one opaque resource value without exposing it outside this crate.
#[cfg(any(windows, test))]
trait ResourceCloser<T> {
    /// Releases the exact resource once ownership ends.
    fn close(resource: T);
}

/// Non-cloneable ownership guard shared by real and injected native resources.
#[cfg(any(windows, test))]
struct ResourceGuard<T, C: ResourceCloser<T>> {
    resource: Option<T>,
    closer: PhantomData<C>,
}

#[cfg(any(windows, test))]
impl<T, C: ResourceCloser<T>> ResourceGuard<T, C> {
    /// Takes exclusive ownership of one resource value.
    fn new(resource: T) -> Self {
        Self {
            resource: Some(resource),
            closer: PhantomData,
        }
    }

    /// Copies an opaque scalar resource for one bounded native call.
    #[cfg_attr(not(windows), allow(dead_code))]
    fn copied(&self) -> T
    where
        T: Copy,
    {
        self.resource.expect("live resource guard")
    }
}

#[cfg(any(windows, test))]
impl<T, C: ResourceCloser<T>> Drop for ResourceGuard<T, C> {
    /// Releases a still-owned resource exactly once.
    fn drop(&mut self) {
        if let Some(resource) = self.resource.take() {
            C::close(resource);
        }
    }
}

/// Sanitized companion-boundary failure with no native message or path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeError {
    /// The current host is not Windows.
    UnsupportedPlatform,
    /// A bounded request or private recipe was malformed.
    InvalidRequest,
    /// The current process lacks required access.
    AccessDenied,
    /// Sharing, locking, or device state prevented the operation.
    Busy,
    /// The exact physical disk or mounted filesystem is read-only.
    ReadOnly,
    /// Synchronous I/O was explicitly cancelled.
    Cancelled,
    /// The bounded operation timed out.
    TimedOut,
    /// Hotplug removed or replaced the selected OS instance.
    DeviceRemoved,
    /// The retained exact physical device authoritatively reports no cartridge.
    NoMedia,
    /// SetupAPI or volume enumeration failed safely.
    EnumerationFailed,
    /// Complete volume topology or identity evidence was unavailable.
    EvidenceIncomplete,
    /// A bounded native allocation or output limit was exceeded.
    ResourceLimit,
    /// Another sanitized native failure occurred.
    Other,
}

/// Closed disk-layout family selected entirely from preflighted byte capacity.
#[cfg(any(windows, test))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DiskLayoutStyle {
    /// Legacy MBR below the vendor large-cartridge boundary.
    Mbr,
    /// GPT at and above the two-TiB boundary.
    Gpt,
}

/// Selects a representable layout before any disk mutation can be dispatched.
#[cfg(any(windows, test))]
fn partition_style_for_capacity(capacity: u64) -> Result<DiskLayoutStyle, NativeError> {
    const MINIMUM_CAPACITY: u64 = 2 * 1024 * 1024;
    const TWO_TIB: u64 = 2 * 1024 * 1024 * 1024 * 1024;
    if capacity <= MINIMUM_CAPACITY {
        Err(NativeError::EvidenceIncomplete)
    } else if capacity < TWO_TIB {
        Ok(DiskLayoutStyle::Mbr)
    } else {
        Ok(DiskLayoutStyle::Gpt)
    }
}

/// Closed mounted-volume file test with independent cleanup evidence.
pub struct FileTestOutcome {
    operation: Result<Vec<u8>, NativeError>,
    operation_certainty: HostOperationOutcome,
    cleanup: HostOperationOutcome,
}

/// Filesystem implementations admitted by the Windows VDS formatter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostFilesystem {
    /// Native NTFS format.
    Ntfs,
    /// Native quick exFAT format.
    ExFat,
}

impl FileTestOutcome {
    /// Moves exact readback or failure plus cleanup certainty to the safe parent.
    pub fn into_parts(
        self,
    ) -> (
        Result<Vec<u8>, NativeError>,
        HostOperationOutcome,
        HostOperationOutcome,
    ) {
        (self.operation, self.operation_certainty, self.cleanup)
    }
}

impl std::fmt::Debug for FileTestOutcome {
    /// Redacts file bytes and reports only length plus cleanup certainty.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("FileTestOutcome")
            .field(
                "readback_length",
                &self.operation.as_ref().map_or(0, Vec::len),
            )
            .field("operation_certainty", &self.operation_certainty)
            .field("cleanup", &self.cleanup)
            .finish()
    }
}

/// Internal certainty-preserving result of one closed semantic volume mutation.
#[cfg(any(windows, test))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum VolumeMutationOutcome {
    /// The complete guarded semantic operation finished successfully.
    Succeeded,
    /// Validation, complete enumeration, association, or locking failed first.
    NotAttempted(NativeError),
    /// The semantic mutation API was invoked but success could not be proven.
    CompletionUnknown(NativeError),
}

/// Certainty-preserving outcome of one closed Windows host mutation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostOperationOutcome {
    /// Complete fresh validation failed before a mutating Win32 call.
    NotAttempted(NativeError),
    /// A mutating Win32 call was invoked but completion could not be proven.
    CompletionUnknown(NativeError),
    /// The complete closed host operation succeeded.
    Succeeded,
}

/// Direction of one validated SCSI data phase.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg(any(windows, test))]
enum DataDirection {
    None,
    FromDevice,
    ToDevice,
}

/// Bounded direct-transfer limits reported by one storage adapter.
#[cfg(any(windows, test))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct AdapterConstraints {
    maximum_transfer_length: usize,
    alignment_mask: usize,
}

/// Allocation size and aligned data offset derived without pointer creation.
#[cfg(any(windows, test))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct TransferLayout {
    allocation_length: usize,
    data_offset: usize,
}

/// Parses the integer prefix of a bounded `STORAGE_ADAPTER_DESCRIPTOR`.
#[cfg(any(windows, test))]
fn parse_adapter_descriptor(bytes: &[u8]) -> Result<AdapterConstraints, NativeError> {
    const PREFIX_LENGTH: usize = 20;
    if bytes.len() < PREFIX_LENGTH {
        return Err(NativeError::EnumerationFailed);
    }
    let read = |offset: usize| {
        u32::from_le_bytes(
            bytes[offset..offset + 4]
                .try_into()
                .expect("fixed descriptor field is in bounds"),
        )
    };
    let version = read(0) as usize;
    let declared_size = read(4) as usize;
    if version < PREFIX_LENGTH
        || version > declared_size
        || declared_size < PREFIX_LENGTH
        || declared_size > bytes.len()
    {
        return Err(NativeError::EnumerationFailed);
    }
    let maximum_transfer_length = read(8) as usize;
    if maximum_transfer_length == 0 {
        return Err(NativeError::EnumerationFailed);
    }
    let alignment_mask = read(16) as usize;
    if alignment_mask > MAX_ADAPTER_ALIGNMENT_MASK {
        return Err(NativeError::ResourceLimit);
    }
    if !alignment_mask
        .checked_add(1)
        .is_some_and(usize::is_power_of_two)
    {
        return Err(NativeError::EnumerationFailed);
    }
    Ok(AdapterConstraints {
        maximum_transfer_length,
        alignment_mask,
    })
}

/// Derives a checked allocation and adapter-aligned offset for one direct buffer.
#[cfg(any(windows, test))]
fn aligned_transfer_layout(
    base_address: usize,
    length: usize,
    constraints: AdapterConstraints,
) -> Result<TransferLayout, NativeError> {
    if length == 0 || length > MAX_TRANSFER_LENGTH || length > constraints.maximum_transfer_length {
        return Err(NativeError::InvalidRequest);
    }
    let allocation_length = length
        .checked_add(constraints.alignment_mask)
        .ok_or(NativeError::ResourceLimit)?;
    let aligned_address = base_address
        .checked_add(constraints.alignment_mask)
        .map(|address| address & !constraints.alignment_mask)
        .ok_or(NativeError::ResourceLimit)?;
    let data_offset = aligned_address
        .checked_sub(base_address)
        .ok_or(NativeError::ResourceLimit)?;
    let data_end = data_offset
        .checked_add(length)
        .ok_or(NativeError::ResourceLimit)?;
    if data_end > allocation_length {
        return Err(NativeError::ResourceLimit);
    }
    Ok(TransferLayout {
        allocation_length,
        data_offset,
    })
}

/// One SetupAPI disk-interface candidate with no retained interface path.
#[derive(Clone, Eq, PartialEq)]
pub struct DiskCandidate {
    disk_number: u32,
    instance_id: String,
}

impl DiskCandidate {
    /// Creates one bounded native enumeration result.
    #[cfg(windows)]
    fn new(disk_number: u32, instance_id: String) -> Self {
        Self {
            disk_number,
            instance_id,
        }
    }

    /// Moves the disk number and Plug and Play instance into parent normalization.
    #[must_use]
    pub fn into_parts(self) -> (u32, String) {
        (self.disk_number, self.instance_id)
    }
}

impl std::fmt::Debug for DiskCandidate {
    /// Redacts instance identity from diagnostics.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DiskCandidate")
            .field("disk_number", &self.disk_number)
            .field("instance_id", &"<private>")
            .finish()
    }
}

/// Probes native Windows adapter, service, and token readiness.
#[must_use]
pub fn probe_readiness() -> Readiness {
    #[cfg(windows)]
    {
        native::probe_readiness()
    }
    #[cfg(not(windows))]
    {
        Readiness::unavailable()
    }
}

/// Enumerates present Windows disk interfaces without claiming RDX identity.
///
/// # Errors
///
/// Returns a sanitized native failure. On non-Windows hosts this always returns
/// [`NativeError::UnsupportedPlatform`].
pub fn enumerate_disk_candidates() -> Result<Vec<DiskCandidate>, NativeError> {
    #[cfg(windows)]
    {
        native::enumerate_disk_candidates()
    }
    #[cfg(not(windows))]
    {
        Err(NativeError::UnsupportedPlatform)
    }
}

#[cfg(windows)]
mod native;

/// Public semantic SCSI operation with no caller-supplied CDB surface.
///
/// Only exact protocol operations supported by OpenRDX can create this type.
/// Variable payloads and offsets are independently bounded before reaching FFI.
#[cfg_attr(not(windows), allow(dead_code))]
pub struct ScsiOperation {
    kind: ScsiOperationKind,
    timeout_seconds: u32,
}

#[cfg_attr(not(windows), allow(dead_code))]
enum ScsiOperationKind {
    SelfTest,
    LedTest(bool),
    UnitReset,
    InquiryStandard,
    InquiryDeviceIdentification,
    InquiryVpd { page: u8, allocation: u16 },
    LogSense(u8),
    ModeSense(u8),
    ModeSelect { save_pages: bool, data: Vec<u8> },
    SecurityIn(u16),
    OpenRdx(openrdx::Operation),
    FirmwareChunk { offset: u32, data: Vec<u8> },
    FirmwareFinalize { offset: u32 },
}

impl ScsiOperation {
    /// Creates the exact no-data SEND DIAGNOSTIC self-test operation.
    #[must_use]
    pub const fn self_test() -> Self {
        Self::new(ScsiOperationKind::SelfTest)
    }

    /// Creates the exact bounded LED diagnostic operation.
    #[must_use]
    pub const fn led_test(on: bool) -> Self {
        Self::new(ScsiOperationKind::LedTest(on))
    }

    /// Creates the exact no-data RDX unit-reset operation.
    #[must_use]
    pub const fn unit_reset() -> Self {
        Self::new(ScsiOperationKind::UnitReset)
    }

    /// Creates standard INQUIRY with the fixed OpenRDX allocation length.
    #[must_use]
    pub const fn inquiry_standard() -> Self {
        Self::new(ScsiOperationKind::InquiryStandard)
    }

    /// Creates device-identification VPD INQUIRY page `0x83`.
    #[must_use]
    pub const fn inquiry_device_identification() -> Self {
        Self::new(ScsiOperationKind::InquiryDeviceIdentification)
    }

    /// Creates cartridge-identification VPD INQUIRY page `0xC0`.
    #[must_use]
    pub const fn inquiry_media_identification() -> Self {
        Self::new(ScsiOperationKind::InquiryVpd {
            page: 0xC0,
            allocation: 0x00FE,
        })
    }

    /// Creates ATA identify-device cartridge VPD INQUIRY page `0xC2`.
    #[must_use]
    pub const fn inquiry_media_device() -> Self {
        Self::new(ScsiOperationKind::InquiryVpd {
            page: 0xC2,
            allocation: 0x0200,
        })
    }

    /// Creates standard temperature LOG SENSE page `0x0D`.
    #[must_use]
    pub const fn log_sense_temperature() -> Self {
        Self::new(ScsiOperationKind::LogSense(0x0D))
    }

    /// Creates the drive LOG SENSE page `0x20` operation.
    #[must_use]
    pub const fn log_sense_drive() -> Self {
        Self::new(ScsiOperationKind::LogSense(0x20))
    }

    /// Creates the cartridge LOG SENSE page `0x21` operation.
    #[must_use]
    pub const fn log_sense_cartridge() -> Self {
        Self::new(ScsiOperationKind::LogSense(0x21))
    }

    /// Creates the MODE SENSE page `0x31` operation.
    #[must_use]
    pub const fn mode_sense_capabilities() -> Self {
        Self::new(ScsiOperationKind::ModeSense(0x31))
    }

    /// Creates the MODE SENSE page `0x33` operation.
    #[must_use]
    pub const fn mode_sense_drive() -> Self {
        Self::new(ScsiOperationKind::ModeSense(0x33))
    }

    /// Creates the MODE SENSE page `0x34` operation.
    #[must_use]
    pub const fn mode_sense_sata() -> Self {
        Self::new(ScsiOperationKind::ModeSense(0x34))
    }

    /// Creates a structurally bounded MODE SELECT for a RDX page.
    ///
    /// # Errors
    ///
    /// Rejects oversized, truncated, inconsistent, or unsupported mode pages.
    pub fn mode_select(save_pages: bool, data: Vec<u8>) -> Result<Self, NativeError> {
        validate_mode_select(&data)?;
        Ok(Self::new(ScsiOperationKind::ModeSelect {
            save_pages,
            data,
        }))
    }

    /// Creates SECURITY PROTOCOL IN selector `0x0010`.
    #[must_use]
    pub const fn security_in_selector_0010() -> Self {
        Self::new(ScsiOperationKind::SecurityIn(0x0010))
    }

    /// Creates SECURITY PROTOCOL IN selector `0x0020`.
    #[must_use]
    pub const fn security_in_selector_0020() -> Self {
        Self::new(ScsiOperationKind::SecurityIn(0x0020))
    }

    /// Creates SECURITY PROTOCOL IN selector `0x0021`.
    #[must_use]
    pub const fn security_in_selector_0021() -> Self {
        Self::new(ScsiOperationKind::SecurityIn(0x0021))
    }

    /// Creates one bounded mode-4 firmware WRITE BUFFER transfer.
    ///
    /// # Errors
    ///
    /// Rejects empty or oversized payloads and offsets outside 24 bits.
    pub fn firmware_chunk(offset: u32, data: Vec<u8>) -> Result<Self, NativeError> {
        if offset > MAX_U24 || data.is_empty() || data.len() > MAX_TRANSFER_LENGTH {
            return Err(NativeError::InvalidRequest);
        }
        Ok(Self::new(ScsiOperationKind::FirmwareChunk { offset, data }))
    }

    /// Creates one no-data mode-5 firmware WRITE BUFFER finalize operation.
    ///
    /// # Errors
    ///
    /// Rejects an image length outside the exact 24-bit field.
    pub fn firmware_finalize(offset: u32) -> Result<Self, NativeError> {
        if offset > MAX_U24 {
            return Err(NativeError::InvalidRequest);
        }
        Ok(Self::new(ScsiOperationKind::FirmwareFinalize { offset }))
    }

    /// Replaces the fixed operation timeout with another bounded whole-second value.
    ///
    /// # Errors
    ///
    /// Rejects zero and values above five minutes before native dispatch.
    pub fn with_timeout_seconds(mut self, timeout_seconds: u32) -> Result<Self, NativeError> {
        if !(1..=MAX_TIMEOUT_SECONDS).contains(&timeout_seconds) {
            return Err(NativeError::InvalidRequest);
        }
        self.timeout_seconds = timeout_seconds;
        Ok(self)
    }

    const fn new(kind: ScsiOperationKind) -> Self {
        Self {
            kind,
            timeout_seconds: DEFAULT_TIMEOUT_SECONDS,
        }
    }

    #[cfg(any(windows, test))]
    fn into_request(self) -> Result<ScsiRequest, NativeError> {
        let (cdb, direction, data) = encode_operation(self.kind);
        ScsiRequest::new(
            &cdb,
            direction,
            data,
            self.timeout_seconds,
            MAX_SENSE_LENGTH,
        )
    }
}

impl std::fmt::Debug for ScsiOperation {
    /// Redacts all operation fields and payload bytes from diagnostics.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ScsiOperation(<private>)")
    }
}

/// Fully bounded request copied into the Windows-only FFI layer.
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg(any(windows, test))]
struct ScsiRequest {
    cdb: [u8; MAX_CDB_LENGTH],
    cdb_length: u8,
    direction: DataDirection,
    data: Vec<u8>,
    timeout_seconds: u32,
    sense_capacity: u8,
}

/// Pointer-free completion copied from one synchronous DeviceIoControl call.
#[derive(Clone, Eq, PartialEq)]
pub enum Completion {
    /// Validation or allocation failed before `DeviceIoControl` was invoked.
    NotAttempted(NativeError),
    /// `DeviceIoControl` was invoked but returned no usable SCSI completion.
    AttemptedError(NativeError),
    /// The port driver returned a SCSI status and bounded copied buffers.
    Device {
        /// Raw SCSI status byte returned by the device.
        scsi_status: u8,
        /// Updated SPTI transfer count.
        transferred_length: u32,
        /// Bounded direct data buffer copied out before native memory release.
        data: Vec<u8>,
        /// Updated request-sense count, retained separately from copied length.
        sense_reported_length: usize,
        /// At most the fixed request-sense capacity.
        sense: Vec<u8>,
    },
}

impl std::fmt::Debug for Completion {
    /// Formats only stable status and lengths while redacting native buffers.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
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
                transferred_length,
                data,
                sense_reported_length,
                sense,
            } => formatter
                .debug_struct("Device")
                .field("scsi_status", scsi_status)
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

/// Opaque pinned volume handles tied to the lifetime of one exact disk lease.
pub struct VolumeLeaseSet<'device> {
    drive_letters: Vec<char>,
    #[cfg_attr(not(windows), allow(dead_code))]
    mount_path_count: usize,
    #[cfg(windows)]
    inventory: VolumeInventory,
    #[cfg(windows)]
    leases: Vec<native::NativeVolumeLease>,
    device: &'device mut WindowsDevice,
}

/// Successful safe-dismount guard that keeps every exact volume handle locked.
///
/// The guard is intentionally non-cloneable and exposes neither handles nor
/// volume paths. Future physical-eject support consumes this type through a
/// closed companion operation; dropping it releases the native volume locks.
pub struct ValidatedVolumeMutationLease<'device> {
    volumes: VolumeLeaseSet<'device>,
}

impl std::fmt::Debug for WindowsDevice {
    /// Redacts the handle, physical-drive path, and instance recipe.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("WindowsDevice(<private>)")
    }
}

/// Encodes one closed semantic operation into a private CDB and transfer buffer.
#[cfg(any(windows, test))]
fn encode_operation(operation: ScsiOperationKind) -> (Vec<u8>, DataDirection, Vec<u8>) {
    match operation {
        ScsiOperationKind::SelfTest => (
            vec![0x1D, 0x04, 0, 0, 0, 0],
            DataDirection::None,
            Vec::new(),
        ),
        ScsiOperationKind::LedTest(on) => {
            let mut data = vec![0x80, 0, 0, 4];
            data.extend_from_slice(&u32::from(!on).to_be_bytes());
            (vec![0x1D, 0, 0, 0, 8, 0], DataDirection::ToDevice, data)
        }
        ScsiOperationKind::UnitReset => (
            vec![0x1D, 0x05, 0, 0, 0, 0],
            DataDirection::None,
            Vec::new(),
        ),
        ScsiOperationKind::InquiryStandard => (
            vec![0x12, 0, 0, 0, 0xFE, 0],
            DataDirection::FromDevice,
            vec![0; 0xFE],
        ),
        ScsiOperationKind::InquiryDeviceIdentification => (
            vec![0x12, 1, 0x83, 0, 0xFE, 0],
            DataDirection::FromDevice,
            vec![0; 0xFE],
        ),
        ScsiOperationKind::InquiryVpd { page, allocation } => {
            let [high, low] = allocation.to_be_bytes();
            (
                vec![0x12, 1, page, high, low, 0],
                DataDirection::FromDevice,
                vec![0; usize::from(allocation)],
            )
        }
        ScsiOperationKind::LogSense(page) => (
            vec![0x4D, 0, page, 0, 0, 0, 0, 0, 0xFE, 0],
            DataDirection::FromDevice,
            vec![0; 0xFE],
        ),
        ScsiOperationKind::ModeSense(page) => (
            vec![0x5A, 0, page, 0, 0, 0, 0, 0, 0xFE, 0],
            DataDirection::FromDevice,
            vec![0; 0xFE],
        ),
        ScsiOperationKind::ModeSelect { save_pages, data } => {
            let length = (data.len() as u16).to_be_bytes();
            (
                vec![
                    0x55,
                    0x10 | u8::from(save_pages),
                    0,
                    0,
                    0,
                    0,
                    0,
                    length[0],
                    length[1],
                    0,
                ],
                DataDirection::ToDevice,
                data,
            )
        }
        ScsiOperationKind::SecurityIn(selector) => {
            let selector = selector.to_be_bytes();
            (
                vec![
                    0xA2,
                    0x20,
                    selector[0],
                    selector[1],
                    0,
                    0,
                    0,
                    0,
                    0x10,
                    0,
                    0,
                    0,
                ],
                DataDirection::FromDevice,
                vec![0; MAX_TRANSFER_LENGTH],
            )
        }
        ScsiOperationKind::OpenRdx(operation) => openrdx::encode(operation),
        ScsiOperationKind::FirmwareChunk { offset, data } => {
            let offset = u24(offset);
            let length = u24(data.len() as u32);
            (
                vec![
                    0x3B, 0x04, 0, offset[0], offset[1], offset[2], length[0], length[1],
                    length[2], 0,
                ],
                DataDirection::ToDevice,
                data,
            )
        }
        ScsiOperationKind::FirmwareFinalize { offset } => {
            let offset = u24(offset);
            (
                vec![0x3B, 0x05, 0, offset[0], offset[1], offset[2], 0, 0, 0, 0],
                DataDirection::None,
                Vec::new(),
            )
        }
    }
}

/// Validates the variable MODE SELECT payload independently of the parent.
fn validate_mode_select(data: &[u8]) -> Result<(), NativeError> {
    if data.len() < 10 || data.len() > MAX_TRANSFER_LENGTH || data[..3] != [0, 0, 0] {
        return Err(NativeError::InvalidRequest);
    }
    let descriptor_length = usize::from(u16::from_be_bytes([data[6], data[7]]));
    let page_offset = 8_usize
        .checked_add(descriptor_length)
        .ok_or(NativeError::InvalidRequest)?;
    if page_offset + 2 > data.len() {
        return Err(NativeError::InvalidRequest);
    }
    let page_header = data[page_offset];
    let page = page_header & 0x3F;
    let minimum_body = match page {
        0x31 => 3,
        0x33 => 2,
        0x34 => 5,
        _ => return Err(NativeError::InvalidRequest),
    };
    if page_header & 0x40 != 0 {
        return Err(NativeError::InvalidRequest);
    }
    let body_length = usize::from(data[page_offset + 1]);
    let expected_length = page_offset
        .checked_add(2)
        .and_then(|length| length.checked_add(body_length))
        .ok_or(NativeError::InvalidRequest)?;
    if body_length < minimum_body || expected_length != data.len() {
        return Err(NativeError::InvalidRequest);
    }
    Ok(())
}

/// Encodes a prevalidated 24-bit field without widening the public surface.
#[cfg(any(windows, test))]
fn u24(value: u32) -> [u8; 3] {
    let bytes = value.to_be_bytes();
    [bytes[1], bytes[2], bytes[3]]
}

/// Bounds a native byte count before it can authorize a safe slice.
#[cfg(any(windows, test))]
fn bounded_returned_length(
    returned: u32,
    capacity: usize,
    minimum: usize,
) -> Result<usize, NativeError> {
    let returned = returned as usize;
    if returned < minimum || returned > capacity {
        return Err(NativeError::EnumerationFailed);
    }
    Ok(returned)
}

#[cfg(any(windows, test))]
impl ScsiRequest {
    /// Copies a trusted parent request after independently enforcing FFI bounds.
    ///
    /// # Errors
    ///
    /// Returns [`NativeError::InvalidRequest`] before FFI for any empty or
    /// oversized CDB, transfer, sense buffer, timeout, or inconsistent data phase.
    fn new(
        cdb: &[u8],
        direction: DataDirection,
        data: Vec<u8>,
        timeout_seconds: u32,
        sense_capacity: usize,
    ) -> Result<Self, NativeError> {
        let direction_is_consistent = match direction {
            DataDirection::None => data.is_empty(),
            DataDirection::FromDevice | DataDirection::ToDevice => !data.is_empty(),
        };
        if cdb.is_empty()
            || cdb.len() > MAX_CDB_LENGTH
            || data.len() > MAX_TRANSFER_LENGTH
            || !(1..=MAX_TIMEOUT_SECONDS).contains(&timeout_seconds)
            || sense_capacity > MAX_SENSE_LENGTH
            || !direction_is_consistent
        {
            return Err(NativeError::InvalidRequest);
        }

        let mut copied_cdb = [0_u8; MAX_CDB_LENGTH];
        copied_cdb[..cdb.len()].copy_from_slice(cdb);
        Ok(Self {
            cdb: copied_cdb,
            cdb_length: cdb.len() as u8,
            direction,
            data,
            timeout_seconds,
            sense_capacity: sense_capacity as u8,
        })
    }
}

#[cfg(test)]
mod tests;
