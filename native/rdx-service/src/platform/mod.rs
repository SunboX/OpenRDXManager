//! Service-owned platform discovery boundary and truthful capability model.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fmt::{Debug, Formatter};

use sha2::{Digest, Sha256};

use crate::firmware::ProductFamily;
use crate::host::DeviceInterface;
use crate::model::{
    Capability, CapabilityState, DriveLetter, DriveStatus, OperationKind, ReasonCode,
};
use crate::operations::{
    FileSystem, HostPrimitiveError, HostVolumeFacts, PrimitiveFailure, WriteReadPrimitiveResult,
};
use crate::protocol::{
    Command, InquiryPage, RdxFeaturePage, inquiry, log_sense, mode_sense, parse_log_page,
    parse_rdx_inquiry_identity,
};
use crate::transport::CommandDispatch;

mod capabilities;
mod capability_projection;
use capability_projection::device_capabilities;
mod discovery_report;
mod media_status;
mod registry;
mod status;

use media_status::{MediaStatusEvidence, media_status_evidence};
use status::{
    DriveLogProjection, ModeStatusProjection, cam_state_label, drive_error_label,
    drive_status_label, drive_status_projection, power_source_label,
};

/// Portable Linux SG layouts plus the target-gated native adapter.
pub mod linux;

/// Portable macOS SCSI-task semantics plus the target-gated native adapter.
pub mod macos;

/// Portable Windows request layouts plus the target-gated native adapter.
pub mod windows;

/// Deterministic path-free host-operation fixtures.
#[cfg(any(test, feature = "fixtures"))]
pub mod fixtures;

pub use capabilities::{PlatformCapabilities, PlatformError};
pub use discovery_report::{
    DiscoveryDiagnostics, ValidatedDiscoveryReport, discover_firmware_device_report,
    discover_post_eject_report, discover_validated_device_report, discover_validated_devices,
};
pub(crate) use discovery_report::{FirmwareDiscoveryBinding, discover_firmware_device_binding};
pub use registry::{DeviceRegistry, ResolvedDevice};

/// Maximum number of candidates admitted from one bounded enumeration pass.
pub const MAX_CANDIDATE_DEVICES: usize = 128;
/// Per-command deadline used by non-mutating identity and telemetry discovery.
const DISCOVERY_PROBE_TIMEOUT_MS: u32 = 2_000;
const MAX_CANDIDATE_TOKEN_LENGTH: usize = 64;
const MAX_LOCATOR_LENGTH: usize = 1_024;
const MAX_METADATA_LENGTH: usize = 128;

/// Untrusted OS-enumeration hints which never establish RDX identity.
pub struct CandidateMetadata {
    vendor: Option<String>,
    product: Option<String>,
    serial: Option<String>,
    interface: Option<DeviceInterface>,
}

impl CandidateMetadata {
    /// Retains OS hints for later exact comparison with device replies.
    #[must_use]
    pub fn new(
        vendor: Option<String>,
        product: Option<String>,
        serial: Option<String>,
        interface: Option<DeviceInterface>,
    ) -> Self {
        Self {
            vendor,
            product,
            serial,
            interface,
        }
    }
}

impl Debug for CandidateMetadata {
    /// Redacts untrusted metadata so control characters cannot reach diagnostics.
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("CandidateMetadata(<untrusted>)")
    }
}

/// One unvalidated OS candidate with a service-private atomic reopen recipe.
///
/// A concrete adapter may encode both its locator and OS instance identity in
/// the private value. The registry retains that exact recipe so path reuse by a
/// different OS instance is rejected before a handle is authorized.
pub struct CandidateDevice {
    token: String,
    locator: OsString,
    metadata: CandidateMetadata,
}

impl CandidateDevice {
    /// Creates one candidate while bounding its safe token and private reopen recipe.
    ///
    /// Metadata remains untrusted until exact device replies are parsed and
    /// cross-checked by [`discover_validated_devices`].
    ///
    /// # Errors
    ///
    /// Returns a sanitized token or locator error without echoing either input.
    pub fn new(
        token: impl Into<String>,
        locator: impl Into<OsString>,
        metadata: CandidateMetadata,
    ) -> Result<Self, PlatformError> {
        let token = token.into();
        let token_bytes = token.as_bytes();
        if token_bytes.is_empty()
            || token_bytes.len() > MAX_CANDIDATE_TOKEN_LENGTH
            || !token_bytes[0].is_ascii_alphabetic()
            || !token_bytes
                .iter()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b':' | b'-'))
        {
            return Err(PlatformError::InvalidCandidateToken);
        }
        let locator = locator.into();
        let locator_length = locator.as_encoded_bytes().len();
        if locator_length == 0 || locator_length > MAX_LOCATOR_LENGTH {
            return Err(PlatformError::InvalidCandidateLocator);
        }
        Ok(Self {
            token,
            locator,
            metadata,
        })
    }

    /// Returns the bounded path-free token used only to route adapter responses.
    #[must_use]
    pub fn token(&self) -> &str {
        &self.token
    }
}

impl Debug for CandidateDevice {
    /// Formats only the safe token and redacts locator plus untrusted metadata.
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CandidateDevice")
            .field("token", &self.token)
            .field("locator", &"<private>")
            .field("metadata", &"<untrusted>")
            .finish()
    }
}

/// Exact service-owned discovery probe identity.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum DiscoveryProbe {
    /// Standard INQUIRY with the RDX capability extension.
    StandardInquiry,
    /// Fixed-layout device-identification VPD page `0x83`.
    DeviceIdentification,
    /// Structurally validated RDX MODE SENSE page `0x31`.
    CapabilityPage,
    /// Optional current drive operation mode from MODE page `0x34`.
    OperationMode,
    /// Optional current drive telemetry from LOG page `0x20`.
    DriveStatus,
    /// Optional cartridge identity from VPD page `0xC0`.
    MediaIdentification,
    /// Optional cartridge HDD identity from VPD page `0xC2`.
    MediaDevice,
    /// Optional current cartridge telemetry from LOG page `0x21`.
    CartridgeStatus,
    /// Optional current cartridge temperature from LOG page `0x0D`.
    Temperature,
}

/// One immutable evidence-built command accepted by a discovery adapter.
pub struct DiscoveryCommand {
    probe: DiscoveryProbe,
    command: Command,
}

impl DiscoveryCommand {
    /// Returns the safe semantic probe identity.
    #[must_use]
    pub const fn probe(&self) -> DiscoveryProbe {
        self.probe
    }

    /// Returns the exact immutable command built by trusted protocol code.
    #[must_use]
    pub const fn command(&self) -> &Command {
        &self.command
    }
}

/// Exact-handle command boundary implemented by one OS-specific RAII owner.
///
/// Implementations must dispatch every command through the already-open handle
/// owned by `self`. They must never reopen a locator, select a different path,
/// or defer a command until after that handle is released. Dropping the
/// implementation must release its OS resource.
pub trait PlatformDeviceHandle: Send {
    /// Executes one immutable service-built command through this exact handle.
    fn execute(&mut self, command: &Command) -> CommandDispatch;

    /// Returns the actual USB parent bound to this exact capture-owning process.
    ///
    /// Firmware migration requires this evidence; platforms without that
    /// capability reject it without issuing device commands or rematching.
    fn migration_usb_identity(
        &mut self,
    ) -> Result<crate::migration::MigrationUsbIdentity, crate::migration::MigrationError> {
        Err(crate::migration::MigrationError::InvalidCapture)
    }

    /// Binds the validated dock serial preference key without exposing it to callers.
    fn bind_serial_mapping_key(&mut self, _serial_key: &str) -> Result<(), PrimitiveFailure> {
        Ok(())
    }

    /// Applies a stored Windows preference only during authoritative discovery.
    ///
    /// This internal hook is distinct from user-admitted set/reset operations.
    /// Other platforms and test adapters perform no arrival mutation.
    fn apply_drive_letter_preference_on_arrival(
        &mut self,
        _serial_key: &str,
    ) -> Result<(), PrimitiveFailure> {
        Ok(())
    }

    /// Returns fresh exact-volume facts through this already-open authority.
    fn host_volume_facts(&mut self) -> Result<HostVolumeFacts, PrimitiveFailure> {
        Err(PrimitiveFailure::not_attempted(
            HostPrimitiveError::UnsupportedPlatform,
        ))
    }

    /// Returns format-only facts; unsupported platforms keep their ordinary guard.
    fn host_format_volume_facts(&mut self) -> Result<HostVolumeFacts, PrimitiveFailure> {
        self.host_volume_facts()
    }

    /// Reads the selected mounted filesystem label without exposing its path.
    fn host_volume_label(&mut self) -> Result<Option<crate::model::VolumeLabel>, PrimitiveFailure> {
        Ok(None)
    }

    /// Renames the exact currently bound mounted filesystem.
    fn set_volume_label_exact(
        &mut self,
        _label: &crate::model::VolumeLabel,
    ) -> Result<(), PrimitiveFailure> {
        Err(PrimitiveFailure::not_attempted(
            HostPrimitiveError::UnsupportedPlatform,
        ))
    }

    /// Returns sorted truly free Windows letters without paths or registry data.
    fn available_drive_letters(&mut self) -> Result<Vec<DriveLetter>, PrimitiveFailure> {
        Err(PrimitiveFailure::not_attempted(
            HostPrimitiveError::UnsupportedPlatform,
        ))
    }

    /// Supplies an optional transient password to the exact native format authority.
    fn set_format_passphrase(
        &mut self,
        passphrase: Option<crate::model::FormatPassphrase>,
    ) -> Result<(), PrimitiveFailure> {
        if passphrase.is_some() {
            return Err(PrimitiveFailure::not_attempted(
                HostPrimitiveError::UnsupportedPlatform,
            ));
        }
        Ok(())
    }

    /// Checks exact host formatting dependencies without mutating volume state.
    fn preflight_format(&mut self, _filesystem: FileSystem) -> Result<(), PrimitiveFailure> {
        Err(PrimitiveFailure::not_attempted(
            HostPrimitiveError::UnsupportedPlatform,
        ))
    }

    /// Runs a closed exact mounted-volume write/read/cleanup test.
    fn write_read_file(
        &mut self,
        _filename: &str,
        _bytes: &[u8],
    ) -> Result<WriteReadPrimitiveResult, PrimitiveFailure> {
        Err(PrimitiveFailure::not_attempted(
            HostPrimitiveError::UnsupportedPlatform,
        ))
    }

    /// Flushes and unmounts all volumes belonging solely to this exact device.
    fn unmount_exact_volumes(&mut self) -> Result<(), PrimitiveFailure> {
        Err(PrimitiveFailure::not_attempted(
            HostPrimitiveError::UnsupportedPlatform,
        ))
    }

    /// Flushes/unmounts and ejects under one exact retained authority.
    fn safe_eject_exact(
        &mut self,
        _after_unmount: &mut dyn FnMut() -> bool,
    ) -> Result<(), PrimitiveFailure> {
        Err(PrimitiveFailure::not_attempted(
            HostPrimitiveError::UnsupportedPlatform,
        ))
    }

    /// Performs one normal or explicitly forced exact-device eject.
    fn eject_exact(&mut self, _force: bool) -> Result<(), PrimitiveFailure> {
        Err(PrimitiveFailure::not_attempted(
            HostPrimitiveError::UnsupportedPlatform,
        ))
    }

    /// Creates one simple exact-device partition layout.
    fn create_single_partition(&mut self, _mbr_signature: u32) -> Result<(), PrimitiveFailure> {
        Err(PrimitiveFailure::not_attempted(
            HostPrimitiveError::UnsupportedPlatform,
        ))
    }

    /// Formats the exact newly created partition.
    fn format_partition(&mut self, _filesystem: FileSystem) -> Result<(), PrimitiveFailure> {
        Err(PrimitiveFailure::not_attempted(
            HostPrimitiveError::UnsupportedPlatform,
        ))
    }

    /// Reports a combined format whose exact native filesystem readback completed.
    /// Default adapters still require separate partition formatting and proof.
    fn completed_format(&self) -> Option<FileSystem> {
        None
    }

    /// Persists one collision-free exact-serial Windows drive-letter preference.
    fn set_drive_letter_exact(
        &mut self,
        _serial_key: &str,
        _letter: char,
    ) -> Result<(), PrimitiveFailure> {
        Err(PrimitiveFailure::not_attempted(
            HostPrimitiveError::UnsupportedPlatform,
        ))
    }

    /// Removes only this application's current exact-serial Windows preference.
    fn reset_drive_letter_exact(&mut self, _serial_key: &str) -> Result<(), PrimitiveFailure> {
        Err(PrimitiveFailure::not_attempted(
            HostPrimitiveError::UnsupportedPlatform,
        ))
    }

    /// Waits for authoritative exact-device departure after eject dispatch.
    fn verify_eject_departure(&mut self) -> Result<(), PrimitiveFailure> {
        Err(PrimitiveFailure::not_attempted(
            HostPrimitiveError::UnsupportedPlatform,
        ))
    }

    /// Waits for one authoritative new exact filesystem after layout mutation.
    fn verify_format_rediscovery(
        &mut self,
        _filesystem: FileSystem,
        _previous_capacity: u64,
    ) -> Result<(), PrimitiveFailure> {
        Err(PrimitiveFailure::not_attempted(
            HostPrimitiveError::UnsupportedPlatform,
        ))
    }
}

/// Hashes bounded native media descriptors into one opaque service-private identity.
pub(crate) fn media_fingerprint(
    platform_tag: &[u8],
    capacity_bytes: u64,
    writable: bool,
    native_material: &[u8],
) -> [u8; 32] {
    use sha2::{Digest, Sha256};

    let mut digest = Sha256::new();
    digest.update(b"OpenRDXManager/media-identity/v1\0");
    digest.update(platform_tag);
    digest.update(capacity_bytes.to_be_bytes());
    digest.update([u8::from(writable)]);
    digest.update((native_material.len() as u64).to_be_bytes());
    digest.update(native_material);
    digest.finalize().into()
}

/// Non-cloneable, non-serializable lease used to validate one enumerated candidate.
///
/// The lease owns an OS-specific RAII handle but exposes neither that handle nor
/// its locator. All discovery probes are executed before the lease is dropped
/// or promoted to a live device lease.
pub struct CandidateLease {
    handle: Box<dyn PlatformDeviceHandle>,
}

impl CandidateLease {
    /// Wraps one newly opened OS handle for service-owned candidate validation.
    #[must_use]
    pub fn new(handle: impl PlatformDeviceHandle + 'static) -> Self {
        Self {
            handle: Box::new(handle),
        }
    }

    /// Promotes the same still-open handle after exact revalidation succeeds.
    fn promote(self) -> DeviceLease {
        DeviceLease {
            handle: self.handle,
        }
    }
}

impl Debug for CandidateLease {
    /// Redacts the adapter, OS handle, and locator from diagnostics.
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("CandidateLease(<private>)")
    }
}

/// Non-cloneable, non-serializable live lease retained from atomic resolution.
///
/// The public type communicates ownership to future adapters, while only the
/// registry-backed [`ResolvedDevice`] can hold or use an instance.
pub struct DeviceLease {
    handle: Box<dyn PlatformDeviceHandle>,
}

impl Debug for DeviceLease {
    /// Redacts the adapter, OS handle, and locator from diagnostics.
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("DeviceLease(<private>)")
    }
}

/// Narrow synchronous adapter boundary owned and serialized by the service actor.
///
/// The trait exposes private candidates only long enough to atomically open one
/// RAII handle. Commands are subsequently dispatched through that exact lease;
/// no API can recover a locator or reopen between probes.
pub trait PlatformBackend: Send {
    /// Bounds read-only reconnection after activation; never permits another image transfer.
    fn firmware_reconnect_timeout(&self) -> std::time::Duration {
        std::time::Duration::from_secs(120)
    }

    /// Whether the adapter can capture the whole erase sector for manual backups.
    fn supports_manufacturing_sector_read(&self) -> bool {
        true
    }

    /// Refreshes a cached candidate's label without taking raw SCSI authority.
    fn refresh_candidate_volume_label(
        &mut self,
        _candidate: &CandidateDevice,
        _facts: HostVolumeFacts,
    ) -> Result<Option<crate::model::VolumeLabel>, PlatformError> {
        Ok(None)
    }
    /// Owner accepted from the desktop session, never from renderer file paths.
    fn manufacturing_backup_owner(&self) -> Option<u32> {
        None
    }

    /// Returns one immutable, cross-field-consistent capability matrix.
    fn capabilities(&self) -> PlatformCapabilities;

    /// Lists only verified private backups belonging to the selected dock.
    fn manufacturing_backups(
        &mut self,
        _device_id: &crate::model::DeviceId,
    ) -> Result<
        Vec<crate::service::manufacturing::BackupSummary>,
        crate::operations::HostPrimitiveError,
    > {
        #[cfg(any(target_os = "macos", target_os = "linux", windows))]
        {
            crate::migration::manufacturing_backup::inventory(
                _device_id,
                self.manufacturing_backup_owner(),
            )
            .map_err(|_| crate::operations::HostPrimitiveError::ManufacturingBackupUnavailable)
        }
        #[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
        {
            Err(crate::operations::HostPrimitiveError::ManufacturingBackupUnavailable)
        }
    }

    /// Resolves only an immutable service-owned backup, never a supplied pathname.
    fn load_manufacturing_backup(
        &mut self,
        _backup_id: &str,
    ) -> Result<crate::service::manufacturing::BackupRecord, crate::operations::HostPrimitiveError>
    {
        #[cfg(any(target_os = "macos", target_os = "linux", windows))]
        {
            crate::migration::manufacturing_backup::load(
                _backup_id,
                self.manufacturing_backup_owner(),
            )
            .map_err(|_| crate::operations::HostPrimitiveError::ManufacturingBackupUnavailable)
        }
        #[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
        {
            Err(crate::operations::HostPrimitiveError::ManufacturingBackupUnavailable)
        }
    }

    /// Persists every byte of the current erase sector before full-record restore.
    fn backup_manufacturing_sector(
        &mut self,
        _device_id: &crate::model::DeviceId,
        _sector: &[u8; 4096],
    ) -> Result<(), crate::operations::HostPrimitiveError> {
        #[cfg(any(target_os = "macos", target_os = "linux", windows))]
        {
            crate::migration::manufacturing_backup::persist_sector(
                _device_id,
                _sector,
                self.manufacturing_backup_owner(),
            )
            .map_err(|_| crate::operations::HostPrimitiveError::ManufacturingBackupUnavailable)
        }
        #[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
        {
            Err(crate::operations::HostPrimitiveError::ManufacturingBackupUnavailable)
        }
    }

    /// Saves a raw pre-update record through the trusted host storage boundary.
    /// A platform without durable owner-private storage must reject the update.
    /// No renderer path, filename, or optional bypass is accepted.
    fn backup_manufacturing_record(
        &mut self,
        _device_id: &crate::model::DeviceId,
        _bytes: &[u8; 256],
    ) -> Result<(), crate::operations::HostPrimitiveError> {
        #[cfg(any(target_os = "macos", target_os = "linux", windows))]
        {
            crate::migration::manufacturing_backup::persist(
                _device_id,
                _bytes,
                self.manufacturing_backup_owner(),
            )
            .map_err(|_| crate::operations::HostPrimitiveError::ManufacturingBackupUnavailable)
        }
        #[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
        {
            Err(crate::operations::HostPrimitiveError::ManufacturingBackupUnavailable)
        }
    }

    /// Enumerates a bounded set of unvalidated candidates without opening mutations.
    ///
    /// The backend owns both static API support and dynamic scan errors; it must
    /// return [`PlatformError::DiscoveryUnavailable`] when enumeration is not
    /// implemented rather than relying on a cached capability pre-check.
    fn enumerate_candidates(&mut self) -> Result<Vec<CandidateDevice>, PlatformError>;

    /// Atomically opens one candidate into an exact non-shareable RAII lease.
    ///
    /// The implementation must verify that the private reopen recipe still
    /// names the enumerated OS instance while opening it. Path reuse or instance
    /// replacement must fail rather than silently opening the current occupant.
    ///
    /// # Errors
    ///
    /// Returns a sanitized failure without revealing the locator or native text.
    fn open_candidate(
        &mut self,
        candidate: &CandidateDevice,
    ) -> Result<CandidateLease, PlatformError>;

    /// Refreshes host-volume facts without reopening exclusive device transport.
    ///
    /// Backends may return fresh facts only when `candidate` and `previous`
    /// identify the same physical dock under their private authority. Returning
    /// `None` requests the complete protocol-validation path. Implementations
    /// must not unmount media or acquire exclusive SCSI/USB access here.
    ///
    /// # Errors
    ///
    /// Returns a sanitized candidate-local refresh failure.
    fn refresh_candidate_host_facts(
        &mut self,
        _candidate: &CandidateDevice,
        _previous: &CandidateDevice,
        _previous_facts: Option<HostVolumeFacts>,
    ) -> Result<Option<HostVolumeFacts>, PlatformError> {
        Ok(None)
    }

    /// Publishes backend-private reopen recipes staged by this scan.
    ///
    /// This is infallible because the registry has completed every fallible
    /// replacement check before the service invokes it.
    fn commit_candidate_refresh(&mut self) {}

    /// Discards backend-private reopen recipes staged by a failed scan.
    fn abort_candidate_refresh(&mut self) {}
}

/// Revalidates a candidate lease without reopening or changing its exact handle.
pub(super) fn revalidate_candidate_lease(
    lease: &mut CandidateLease,
    candidate: &CandidateDevice,
    platform: PlatformCapabilities,
) -> Option<ValidatedEvidence> {
    validate_open_handle(lease.handle.as_mut(), candidate, platform, true)
}

/// Revalidates a promoted lease without reopening or changing its exact handle.
pub(super) fn revalidate_device_lease(
    lease: &mut DeviceLease,
    candidate: &CandidateDevice,
    platform: PlatformCapabilities,
) -> Option<ValidatedEvidence> {
    validate_open_handle(lease.handle.as_mut(), candidate, platform, false)
}

/// Executes the complete exact proof set through one already-open handle.
fn validate_open_handle(
    handle: &mut dyn PlatformDeviceHandle,
    candidate: &CandidateDevice,
    platform: PlatformCapabilities,
    apply_arrival_preference: bool,
) -> Option<ValidatedEvidence> {
    let standard = execute_probe(
        handle,
        DiscoveryProbe::StandardInquiry,
        inquiry(InquiryPage::Standard),
    )?;
    let identification = execute_probe(
        handle,
        DiscoveryProbe::DeviceIdentification,
        inquiry(InquiryPage::DeviceIdentification),
    )?;
    let capability_bytes = execute_probe(
        handle,
        DiscoveryProbe::CapabilityPage,
        mode_sense(0x31).ok()?,
    )?;
    let identity = parse_rdx_inquiry_identity(&standard, &identification).ok()?;
    let capability_page = RdxFeaturePage::parse(&capability_bytes).ok()?;
    if capability_page.page_code() != 0x31 || !metadata_matches(&candidate.metadata, &identity) {
        return None;
    }
    let (interface, product_family) = product_mapping(identity.product_type())?;
    if candidate
        .metadata
        .interface
        .is_some_and(|hint| hint != interface)
    {
        return None;
    }
    if apply_arrival_preference
        && platform.drive_letter_available()
        && interface == DeviceInterface::Usb3
    {
        let serial_key = serial_mapping_key(identity.serial());
        handle
            .apply_drive_letter_preference_on_arrival(&serial_key)
            .ok()?;
    }
    let host_mutations_available = platform.safe_eject_available()
        || platform.force_eject_available()
        || platform.format_available()
        || platform.drive_letter_available();
    let host_facts = if host_mutations_available {
        let facts = handle.host_volume_facts().ok()?;
        if facts.media_present != facts.media_fingerprint.is_some() {
            return None;
        }
        Some(facts)
    } else {
        None
    };
    let available_drive_letters = if platform.drive_letter_available()
        && interface == DeviceInterface::Usb3
        && host_facts.is_some_and(|facts| !facts.media_present)
    {
        handle
            .available_drive_letters()
            .ok()
            .and_then(validate_available_drive_letters)
    } else {
        None
    };
    let capability_fingerprint = capability_fingerprint(
        identity.feature_mask_0(),
        identity.feature_mask_1(),
        capability_page.as_bytes(),
        platform,
    );
    let operation_mode_bytes = execute_probe(
        handle,
        DiscoveryProbe::OperationMode,
        mode_sense(0x34).ok()?,
    );
    let operation_page = operation_mode_bytes
        .as_deref()
        .and_then(|bytes| RdxFeaturePage::parse(bytes).ok());
    let operation_mode = operation_page
        .as_ref()
        .and_then(|page| operation_mode_label(page.operation_mode()?));
    let sata_mode = operation_page
        .as_ref()
        .and_then(|page| sata_mode_label(page.max_host_sata_speed()?));
    let drive_status_bytes =
        execute_probe(handle, DiscoveryProbe::DriveStatus, log_sense(0x20).ok()?);
    let drive_status_page = drive_status_bytes
        .as_deref()
        .and_then(|bytes| parse_log_page(bytes).ok());
    let power_source = drive_status_page
        .as_ref()
        .and_then(|page| page.find(0x0005)?.uint32())
        .and_then(power_source_label);
    let drive_status = drive_status_page
        .as_ref()
        .and_then(|page| page.find(0x0000)?.uint32())
        .and_then(drive_status_label);
    let drive_load_count = drive_status_page
        .as_ref()
        .and_then(|page| page.find(0x0001)?.uint32());
    let drive_errors = drive_status_page
        .as_ref()
        .and_then(|page| page.find(0x0002)?.uint32())
        .map(drive_error_label);
    let cam_state = drive_status_page
        .as_ref()
        .and_then(|page| page.find(0x0003)?.uint32())
        .and_then(cam_state_label);
    let mut drive = drive_status_projection(
        &identity,
        interface,
        product_family,
        ModeStatusProjection {
            operation_mode,
            sata_mode,
            response_available: operation_mode_bytes.is_some(),
        },
        DriveLogProjection {
            status: drive_status,
            load_count: drive_load_count,
            errors: drive_errors,
            cam_state,
            power_source,
            response_available: drive_status_bytes.is_some(),
        },
    );
    let mut media_status = if host_facts.is_some_and(|facts| facts.media_present) {
        let media_identification = execute_probe(
            handle,
            DiscoveryProbe::MediaIdentification,
            inquiry(InquiryPage::MediaIdentification),
        );
        let media_device = execute_probe(
            handle,
            DiscoveryProbe::MediaDevice,
            inquiry(InquiryPage::MediaDevice),
        );
        let cartridge_status = execute_probe(
            handle,
            DiscoveryProbe::CartridgeStatus,
            log_sense(0x21).ok()?,
        );
        let temperature = execute_probe(handle, DiscoveryProbe::Temperature, log_sense(0x0D).ok()?);
        media_status_evidence(
            media_identification,
            media_device,
            cartridge_status,
            temperature,
        )
    } else {
        MediaStatusEvidence::default()
    };
    drive.available_drive_letters = available_drive_letters;
    let volume_label = if host_facts.is_some_and(|facts| facts.mounted) {
        handle.host_volume_label().ok().flatten()
    } else {
        None
    };
    let capabilities = device_capabilities(
        identity.feature_mask_1() & 0x10 != 0,
        interface,
        platform,
        host_facts,
        sata_mode.is_some(),
        volume_label.is_some(),
    );
    media_status.volume_label = volume_label;
    Some(ValidatedEvidence {
        vendor: identity.vendor().to_owned(),
        product: identity.product().to_owned(),
        serial: identity.serial().to_owned(),
        revision: identity.revision().to_owned(),
        interface,
        product_family,
        capabilities,
        capability_fingerprint,
        host_facts,
        drive,
        media_status,
        drive_mode_supported: identity.feature_mask_1() & 0x10 != 0,
        sata_mode_reported: sata_mode.is_some(),
    })
}

/// Accepts only the bounded sorted unique D-Z projection promised to the renderer.
fn validate_available_drive_letters(letters: Vec<DriveLetter>) -> Option<Vec<DriveLetter>> {
    if letters.len() > 23
        || letters.iter().any(|letter| letter.get() < 'D')
        || letters
            .windows(2)
            .any(|pair| pair[0].get() >= pair[1].get())
    {
        return None;
    }
    Some(letters)
}

/// Maps only the supported operation-mode values from MODE page `0x34`.
const fn operation_mode_label(value: u8) -> Option<&'static str> {
    match value {
        0 => Some("Not configured"),
        1 => Some("Removable"),
        2 => Some("Fixed disk"),
        3 => Some("Remove device with cartridge"),
        _ => None,
    }
}

/// Maps only the two supported Manager SATA III link-mode values.
const fn sata_mode_label(value: u8) -> Option<&'static str> {
    match value {
        2 => Some("1.5g-3g"),
        3 => Some("3g-6g"),
        _ => None,
    }
}

/// Dispatches one immutable discovery command and retains only proven response bytes.
fn execute_probe(
    handle: &mut dyn PlatformDeviceHandle,
    probe: DiscoveryProbe,
    command: Command,
) -> Option<Vec<u8>> {
    let command = command.with_timeout_ms(DISCOVERY_PROBE_TIMEOUT_MS).ok()?;
    let command = DiscoveryCommand { probe, command };
    handle
        .execute(command.command())
        .response()
        .map(|response| response.data().to_vec())
}

/// Rejects duplicate safe tokens or exact private locators before any probe runs.
fn reject_duplicate_candidates(candidates: &[CandidateDevice]) -> Result<(), PlatformError> {
    for (index, candidate) in candidates.iter().enumerate() {
        if candidates[..index]
            .iter()
            .any(|earlier| earlier.token == candidate.token || earlier.locator == candidate.locator)
        {
            return Err(PlatformError::DuplicateCandidate);
        }
    }
    Ok(())
}

/// Requires every present OS hint to be printable, bounded, and exactly corroborated.
fn metadata_matches(
    metadata: &CandidateMetadata,
    identity: &crate::protocol::RdxInquiryIdentity,
) -> bool {
    hint_matches(metadata.vendor.as_deref(), identity.vendor())
        && hint_matches(metadata.product.as_deref(), identity.product())
        && hint_matches(metadata.serial.as_deref(), identity.serial())
}

/// Rejects hostile text shapes before spending any transport work on a candidate.
fn metadata_is_sane(metadata: &CandidateMetadata) -> bool {
    [
        metadata.vendor.as_deref(),
        metadata.product.as_deref(),
        metadata.serial.as_deref(),
    ]
    .into_iter()
    .all(|hint| hint.is_none_or(hint_is_sane))
}

/// Checks one optional untrusted text hint without normalizing hostile content.
fn hint_matches(hint: Option<&str>, exact: &str) -> bool {
    hint.is_none_or(|hint| hint_is_sane(hint) && hint == exact)
}

/// Accepts only bounded, trimmed, printable ASCII enumeration text.
fn hint_is_sane(hint: &str) -> bool {
    !hint.is_empty()
        && hint.len() <= MAX_METADATA_LENGTH
        && hint.trim() == hint
        && hint.bytes().all(|byte| (0x20..=0x7E).contains(&byte))
}

/// Maps only supported Manager product enumerations to Phase 2 session families.
fn product_mapping(product_type: u8) -> Option<(DeviceInterface, ProductFamily)> {
    match product_type {
        0..=6 => Some((DeviceInterface::Legacy, ProductFamily::Usb2Sata1)),
        0x35..=0x38 => Some((DeviceInterface::Usb3, ProductFamily::Usb3Sata3)),
        0x39 => Some((DeviceInterface::Sata3, ProductFamily::Usb3Sata3)),
        _ => None,
    }
}

/// Derives the fixed path-free serial registry key used only inside host adapters.
fn serial_mapping_key(serial: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(b"OpenRDXManager/dock-serial/v1\0");
    digest.update(serial.as_bytes());
    digest
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// Hashes exact capability evidence for replacement/authentication invalidation.
fn capability_fingerprint(
    mask_0: u8,
    mask_1: u8,
    page: &[u8],
    platform: PlatformCapabilities,
) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"OpenRDXManager/capability-evidence/v1\0");
    digest.update([mask_0, mask_1]);
    digest.update((page.len() as u64).to_be_bytes());
    digest.update(page);
    digest.update([
        u8::from(platform.discovery),
        u8::from(platform.transport),
        u8::from(platform.privileged),
        u8::from(platform.safe_eject),
        u8::from(platform.force_eject),
        u8::from(platform.format),
        u8::from(platform.drive_letter),
        u8::from(platform.hardware_verified),
    ]);
    digest.finalize().into()
}

/// Fully corroborated device input whose locator moves only into the registry.
pub(super) struct ValidatedCandidate {
    candidate: CandidateDevice,
    evidence: ValidatedEvidence,
    binding_continuity: bool,
}

/// Exact identity and capability proof captured from one still-open handle.
pub(super) struct ValidatedEvidence {
    vendor: String,
    product: String,
    serial: String,
    revision: String,
    interface: DeviceInterface,
    product_family: ProductFamily,
    capabilities: BTreeMap<OperationKind, Capability>,
    capability_fingerprint: [u8; 32],
    host_facts: Option<HostVolumeFacts>,
    drive: DriveStatus,
    media_status: MediaStatusEvidence,
    drive_mode_supported: bool,
    sata_mode_reported: bool,
}

#[cfg(test)]
mod tests;
