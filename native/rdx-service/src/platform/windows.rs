// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Portable Windows SPTI layouts and target-gated native adapter support.

use std::fmt::Write;

use crate::model::RiskClass;
use crate::protocol::{Command, DataDirection, MAX_SENSE_DATA_LENGTH, SenseData};
use crate::service::ServiceExecutionContext;
use crate::transport::{
    CommandDispatch, MAX_TRANSPORT_RESPONSE_LENGTH, TransportError, TransportResponse,
};

use super::{
    CandidateDevice, CandidateLease, CandidateMetadata, PlatformBackend, PlatformCapabilities,
    PlatformError,
};

#[cfg(any(windows, test))]
mod command_mapping;
#[cfg(any(windows, test))]
mod context;
#[cfg(any(windows, test))]
mod diagnostics;
mod semantic;
#[cfg(any(windows, test))]
use command_mapping::native_operation;
#[cfg(test)]
mod manufacturing_tests;

#[cfg(windows)]
mod host;

#[cfg(any(windows, test))]
use semantic::write_buffer_fields;
use semantic::{WindowsSemanticCommand, classify};

/// SPTI direction value for a transfer from the device.
pub const SCSI_IOCTL_DATA_IN: u8 = 1;
/// SPTI direction value for a transfer to the device.
pub const SCSI_IOCTL_DATA_OUT: u8 = 0;
/// SPTI direction value for a command without a data phase.
pub const SCSI_IOCTL_DATA_UNSPECIFIED: u8 = 2;
/// Request-sense bytes retained beside every Windows pass-through header.
pub const WINDOWS_SENSE_CAPACITY: usize = MAX_SENSE_DATA_LENGTH;

const MAX_WINDOWS_CDB_LENGTH: usize = 16;
const MAX_WINDOWS_INSTANCE_ID_UNITS: usize = 200;

/// Truthful native adapter, service, and process readiness inputs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct WindowsReadiness {
    adapter_available: bool,
    service_installed: bool,
    service_running: bool,
    current_process_authorized: bool,
}

impl WindowsReadiness {
    /// Creates a private readiness snapshot from the native authority probe.
    #[must_use]
    const fn new(
        adapter_available: bool,
        service_installed: bool,
        service_running: bool,
        current_process_authorized: bool,
    ) -> Self {
        Self {
            adapter_available,
            service_installed,
            service_running,
            current_process_authorized,
        }
    }

    /// Returns whether every prerequisite for privileged SPTI is present.
    const fn transport_ready(self) -> bool {
        self.adapter_available && self.current_process_authorized
    }
}

/// Service-owned Windows candidate and SPTI backend.
pub struct WindowsBackend {
    capabilities: PlatformCapabilities,
    native_active: bool,
}

impl WindowsBackend {
    /// Maps a private readiness snapshot without exposing an activation seam.
    #[must_use]
    fn from_readiness(readiness: WindowsReadiness, native_active: bool) -> Self {
        let discovery_ready = native_active && readiness.adapter_available;
        let transport_ready = native_active && readiness.transport_ready();
        let capabilities = PlatformCapabilities::try_new(
            discovery_ready,
            transport_ready,
            transport_ready,
            transport_ready,
            transport_ready,
            transport_ready,
            transport_ready,
            false,
        )
        .expect("the Windows readiness mapping is cross-field consistent");
        Self {
            capabilities,
            native_active,
        }
    }

    /// Builds an internal fixture while keeping production activation native-only.
    #[cfg(test)]
    #[must_use]
    fn from_test_readiness(readiness: WindowsReadiness, native_active: bool) -> Self {
        Self::from_readiness(readiness, native_active)
    }

    /// Probes and activates the target-gated native Windows adapter.
    #[must_use]
    pub fn native() -> Self {
        Self::native_with_context(ServiceExecutionContext::development_stdio())
    }

    /// Probes the target-gated adapter under explicit service or direct authority.
    #[must_use]
    pub fn native_with_context(context: ServiceExecutionContext) -> Self {
        #[cfg(windows)]
        {
            let native = rdx_windows_native::probe_readiness();
            Self::from_readiness(
                context::apply(
                    WindowsReadiness::new(
                        native.adapter_available(),
                        native.service_installed(),
                        native.service_running(),
                        native.current_process_authorized(),
                    ),
                    context,
                ),
                true,
            )
        }
        #[cfg(not(windows))]
        {
            let _ = context;
            Self::from_readiness(WindowsReadiness::new(false, false, false, false), false)
        }
    }
}

impl PlatformBackend for WindowsBackend {
    /// Returns the immutable readiness-derived capability matrix.
    fn capabilities(&self) -> PlatformCapabilities {
        self.capabilities
    }

    /// Enumerates only present SetupAPI disk-interface candidates.
    fn enumerate_candidates(&mut self) -> Result<Vec<CandidateDevice>, PlatformError> {
        if !self.capabilities.discovery_available() {
            return Err(PlatformError::DiscoveryUnavailable);
        }
        if !self.native_active {
            return Err(PlatformError::EnumerationFailed);
        }
        #[cfg(windows)]
        {
            rdx_windows_native::enumerate_disk_candidates()
                .map_err(map_native_platform_error)?
                .into_iter()
                .map(|candidate| {
                    let (disk_number, instance_id) = candidate.into_parts();
                    normalize_windows_candidate(disk_number, &instance_id)
                        .map_err(|_| PlatformError::EnumerationFailed)
                })
                .collect()
        }
        #[cfg(not(windows))]
        {
            Err(PlatformError::DiscoveryUnavailable)
        }
    }

    /// Revalidates and opens the exact private instance recipe into one lease.
    fn open_candidate(
        &mut self,
        candidate: &CandidateDevice,
    ) -> Result<CandidateLease, PlatformError> {
        if !self.capabilities.transport_available() || !self.native_active {
            return Err(PlatformError::TransportUnavailable);
        }
        #[cfg(windows)]
        {
            let device = rdx_windows_native::WindowsDevice::open(&candidate.locator)
                .map_err(map_native_platform_error)?;
            Ok(CandidateLease::new(WindowsDeviceHandle {
                device,
                serial_mapping_key: None,
            }))
        }
        #[cfg(not(windows))]
        {
            let _ = candidate;
            Err(PlatformError::TransportUnavailable)
        }
    }
}

#[cfg(windows)]
struct WindowsDeviceHandle {
    device: rdx_windows_native::WindowsDevice,
    serial_mapping_key: Option<String>,
}

/// Converts a pure SPTI result into the Phase 2 dispatch-certainty contract.
#[must_use]
pub fn convert_scsi_completion(
    packet: &ScsiPassThroughPacket,
    completion: NativeScsiCompletion,
) -> CommandDispatch {
    let risk = packet.risk;
    match parse_scsi_result(packet, completion) {
        Ok(result) => match TransportResponse::new(result.data().to_vec()) {
            Ok(response) => CommandDispatch::Succeeded(response),
            Err(error) => CommandDispatch::CompletionUnknown(error),
        },
        Err(WindowsResultError::CheckCondition(sense)) if risk == RiskClass::ReadOnly => {
            CommandDispatch::DefinitelyRejected(TransportError::CheckCondition(sense))
        }
        Err(WindowsResultError::CheckCondition(sense)) => {
            CommandDispatch::CompletionUnknown(TransportError::CheckCondition(sense))
        }
        Err(WindowsResultError::Win32 {
            attempted: false,
            failure,
        }) => CommandDispatch::NotSent(transport_error_for_windows_failure(failure)),
        Err(WindowsResultError::Win32 {
            attempted: true,
            failure,
        }) => CommandDispatch::CompletionUnknown(transport_error_for_windows_failure(failure)),
        Err(
            WindowsResultError::TransferredLengthOutOfBounds
            | WindowsResultError::ReturnedDataTooShort
            | WindowsResultError::SenseLengthOutOfBounds
            | WindowsResultError::SenseTruncated
            | WindowsResultError::MalformedSense
            | WindowsResultError::UnexpectedSense,
        ) => CommandDispatch::CompletionUnknown(TransportError::Unavailable),
        Err(WindowsResultError::ShortDataOut) => {
            CommandDispatch::CompletionUnknown(TransportError::DataOutIncomplete)
        }
        Err(WindowsResultError::ScsiStatus(_)) if risk == RiskClass::ReadOnly => {
            CommandDispatch::DefinitelyRejected(TransportError::Unavailable)
        }
        Err(WindowsResultError::ScsiStatus(_)) => {
            CommandDispatch::CompletionUnknown(TransportError::Unavailable)
        }
    }
}

/// Maps one sanitized native failure without changing dispatch certainty.
const fn transport_error_for_windows_failure(failure: WindowsIoFailure) -> TransportError {
    match failure {
        WindowsIoFailure::TimedOut => TransportError::Timeout,
        WindowsIoFailure::DeviceRemoved => TransportError::DeviceRemoved,
        WindowsIoFailure::AccessDenied
        | WindowsIoFailure::Busy
        | WindowsIoFailure::Cancelled
        | WindowsIoFailure::Other => TransportError::Unavailable,
    }
}

/// Maps one companion FFI failure into a platform-open error.
#[cfg(any(windows, test))]
fn map_native_platform_error(error: rdx_windows_native::NativeError) -> PlatformError {
    match error {
        rdx_windows_native::NativeError::AccessDenied => PlatformError::AccessDenied,
        rdx_windows_native::NativeError::Busy | rdx_windows_native::NativeError::ReadOnly => {
            PlatformError::DeviceBusy
        }
        rdx_windows_native::NativeError::Cancelled => PlatformError::OperationCancelled,
        rdx_windows_native::NativeError::TimedOut => PlatformError::OperationTimedOut,
        rdx_windows_native::NativeError::DeviceRemoved
        | rdx_windows_native::NativeError::NoMedia => PlatformError::DeviceRemoved,
        rdx_windows_native::NativeError::EnumerationFailed => PlatformError::EnumerationFailed,
        rdx_windows_native::NativeError::ResourceLimit => PlatformError::TooManyCandidates,
        rdx_windows_native::NativeError::UnsupportedPlatform
        | rdx_windows_native::NativeError::InvalidRequest
        | rdx_windows_native::NativeError::EvidenceIncomplete
        | rdx_windows_native::NativeError::Other => PlatformError::NativeBoundaryFailure,
    }
}

/// Maps a companion dispatch error without preserving a native code or message.
#[cfg(any(windows, test))]
fn map_native_io_failure(error: rdx_windows_native::NativeError) -> WindowsIoFailure {
    match error {
        rdx_windows_native::NativeError::AccessDenied => WindowsIoFailure::AccessDenied,
        rdx_windows_native::NativeError::Busy | rdx_windows_native::NativeError::ReadOnly => {
            WindowsIoFailure::Busy
        }
        rdx_windows_native::NativeError::Cancelled => WindowsIoFailure::Cancelled,
        rdx_windows_native::NativeError::TimedOut => WindowsIoFailure::TimedOut,
        rdx_windows_native::NativeError::DeviceRemoved
        | rdx_windows_native::NativeError::NoMedia => WindowsIoFailure::DeviceRemoved,
        rdx_windows_native::NativeError::UnsupportedPlatform
        | rdx_windows_native::NativeError::InvalidRequest
        | rdx_windows_native::NativeError::EvidenceIncomplete
        | rdx_windows_native::NativeError::EnumerationFailed
        | rdx_windows_native::NativeError::ResourceLimit
        | rdx_windows_native::NativeError::Other => WindowsIoFailure::Other,
    }
}

#[allow(dead_code)]
#[repr(C)]
struct PortableScsiPassThroughHeader {
    length: u16,
    scsi_status: u8,
    path_id: u8,
    target_id: u8,
    lun: u8,
    cdb_length: u8,
    sense_info_length: u8,
    data_in: u8,
    data_transfer_length: u32,
    timeout_value: u32,
    data_buffer_or_offset: usize,
    sense_info_offset: u32,
    cdb: [u8; MAX_WINDOWS_CDB_LENGTH],
}

/// Windows pass-through mechanism selected for one trusted command.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PassThroughKind {
    /// Direct pass-through for a bounded data-in or data-out transfer.
    Direct,
    /// Buffered pass-through for a command without a data phase.
    Buffered,
}

/// Sanitized failure while converting a trusted command to an SPTI request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WindowsRequestError {
    /// The CDB was empty or exceeded the Windows 16-byte field.
    InvalidCdbLength,
    /// The transfer exceeded the portable native-service response bound.
    TransferTooLarge,
}

/// Sanitized SetupAPI candidate-normalization failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WindowsCandidateError {
    /// The Plug and Play instance ID was empty, hostile, or oversized.
    InvalidInstanceId,
    /// The resulting service-owned candidate violated a shared platform bound.
    Platform(PlatformError),
}

/// Converts one SetupAPI disk instance into a path-free unvalidated candidate.
///
/// Enumeration establishes candidacy only. Exact RDX identity and capability
/// replies remain the registry's admission authority.
///
/// # Errors
///
/// Returns a sanitized error for hostile instance text or a shared candidate
/// bound violation. Neither the instance ID nor a physical-drive path escapes.
pub fn normalize_windows_candidate(
    disk_number: u32,
    instance_id: &str,
) -> Result<CandidateDevice, WindowsCandidateError> {
    let recipe = encode_instance_recipe(disk_number, instance_id)?;
    CandidateDevice::new(
        format!("windows-disk-{disk_number}"),
        recipe,
        CandidateMetadata::new(None, None, None, None),
    )
    .map_err(WindowsCandidateError::Platform)
}

/// Encodes an exact instance ID without retaining or publishing a device path.
fn encode_instance_recipe(
    disk_number: u32,
    instance_id: &str,
) -> Result<String, WindowsCandidateError> {
    let units = instance_id.encode_utf16().collect::<Vec<_>>();
    if units.is_empty()
        || units.len() > MAX_WINDOWS_INSTANCE_ID_UNITS
        || instance_id.trim() != instance_id
        || instance_id.chars().any(char::is_control)
    {
        return Err(WindowsCandidateError::InvalidInstanceId);
    }

    let mut recipe = format!("win1:{disk_number:08X}:");
    for unit in units {
        write!(&mut recipe, "{unit:04X}").expect("writing to a String cannot fail");
    }
    Ok(recipe)
}

/// Pointer-free completion copied out of the Windows-only native boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeScsiCompletion {
    win32_failure: Option<(bool, WindowsIoFailure)>,
    scsi_status: u8,
    transferred_length: u32,
    data: Vec<u8>,
    sense_reported_length: usize,
    sense: Vec<u8>,
}

/// Stable Win32 dispatch-failure classes with no native message or path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WindowsIoFailure {
    /// The current process or service lacks required device access.
    AccessDenied,
    /// Sharing, locking, or device state prevented dispatch.
    Busy,
    /// Synchronous I/O was explicitly cancelled.
    Cancelled,
    /// The bounded native request timed out.
    TimedOut,
    /// Hotplug removed the exact opened device.
    DeviceRemoved,
    /// Another sanitized Win32 dispatch failure occurred.
    Other,
}

impl NativeScsiCompletion {
    /// Creates one device completion for portable validation and conversion.
    #[must_use]
    pub fn device(
        scsi_status: u8,
        transferred_length: u32,
        data: Vec<u8>,
        sense_reported_length: usize,
        sense: Vec<u8>,
    ) -> Self {
        Self {
            win32_failure: None,
            scsi_status,
            transferred_length,
            data,
            sense_reported_length,
            sense,
        }
    }

    /// Creates a pre-call native failure that proves no device command was sent.
    #[must_use]
    pub fn not_attempted(failure: WindowsIoFailure) -> Self {
        Self {
            win32_failure: Some((false, failure)),
            scsi_status: 0,
            transferred_length: 0,
            data: Vec::new(),
            sense_reported_length: 0,
            sense: Vec::new(),
        }
    }

    /// Creates an API-invoked failure with no usable device SCSI completion.
    #[must_use]
    pub fn attempted_error(failure: WindowsIoFailure) -> Self {
        Self {
            win32_failure: Some((true, failure)),
            scsi_status: 0,
            transferred_length: 0,
            data: Vec::new(),
            sense_reported_length: 0,
            sense: Vec::new(),
        }
    }
}

/// Sanitized structural failure while validating a native SPTI completion.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WindowsResultError {
    /// Native failure preserving whether `DeviceIoControl` was already invoked.
    Win32 {
        /// Whether the synchronous native API call began.
        attempted: bool,
        /// Sanitized native failure class.
        failure: WindowsIoFailure,
    },
    /// Windows reported more transferred bytes than the request allocated.
    TransferredLengthOutOfBounds,
    /// A data-out operation transferred fewer bytes than the trusted payload.
    ShortDataOut,
    /// The copied data buffer was shorter than Windows' transferred count.
    ReturnedDataTooShort,
    /// The returned request-sense count exceeded the fixed control buffer.
    SenseLengthOutOfBounds,
    /// CHECK CONDITION did not include all request-sense bytes it reported.
    SenseTruncated,
    /// CHECK CONDITION returned sense bytes that fail the bounded parser.
    MalformedSense,
    /// GOOD status carried unexpected sense bytes and is not accepted as success.
    UnexpectedSense,
    /// The device rejected the command with bounded parsed request sense.
    CheckCondition(SenseData),
    /// The device returned a non-GOOD SCSI status.
    ScsiStatus(u8),
}

/// Proven successful SPTI response with explicit underrun evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParsedScsiResult {
    transferred_length: u32,
    residual_length: u32,
    data: Vec<u8>,
}

impl ParsedScsiResult {
    /// Returns the exact number of bytes Windows reports as transferred.
    #[must_use]
    pub const fn transferred_length(&self) -> u32 {
        self.transferred_length
    }

    /// Returns the untransferred portion of the requested data phase.
    #[must_use]
    pub const fn residual_length(&self) -> u32 {
        self.residual_length
    }

    /// Returns only bytes proven to have been transferred from the device.
    #[must_use]
    pub fn data(&self) -> &[u8] {
        &self.data
    }
}

/// Pure, pointer-free SPTI request description consumed by the native boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScsiPassThroughPacket {
    command: Command,
    semantic: WindowsSemanticCommand,
    risk: RiskClass,
    kind: PassThroughKind,
    cdb: [u8; MAX_WINDOWS_CDB_LENGTH],
    cdb_length: u8,
    data_direction: u8,
    transfer_length: u32,
    timeout_seconds: u32,
    header_length: usize,
    data_offset: usize,
    sense_offset: usize,
    total_control_length: usize,
    direction: DataDirection,
}

impl ScsiPassThroughPacket {
    /// Returns the direct or buffered pass-through mechanism.
    #[must_use]
    pub const fn kind(&self) -> PassThroughKind {
        self.kind
    }

    /// Returns only the initialized trusted CDB bytes.
    #[must_use]
    pub fn cdb(&self) -> &[u8] {
        &self.cdb[..usize::from(self.cdb_length)]
    }

    /// Returns the documented SPTI data-direction value.
    #[must_use]
    pub const fn data_direction(&self) -> u8 {
        self.data_direction
    }

    /// Returns the bounded transfer length encoded for Windows.
    #[must_use]
    pub const fn transfer_length(&self) -> u32 {
        self.transfer_length
    }

    /// Returns the non-zero SPTI timeout rounded up to whole seconds.
    #[must_use]
    pub const fn timeout_seconds(&self) -> u32 {
        self.timeout_seconds
    }

    /// Returns the native pointer-width SPTI header size.
    #[must_use]
    pub const fn header_length(&self) -> usize {
        self.header_length
    }

    /// Returns the buffered data offset, or zero when no buffer is embedded.
    #[must_use]
    pub const fn data_offset(&self) -> usize {
        self.data_offset
    }

    /// Returns the checked request-sense offset from the control-buffer start.
    #[must_use]
    pub const fn sense_offset(&self) -> usize {
        self.sense_offset
    }

    /// Returns the fixed bounded request-sense capacity.
    #[must_use]
    pub const fn sense_capacity(&self) -> usize {
        WINDOWS_SENSE_CAPACITY
    }

    /// Returns the complete bounded DeviceIoControl control-buffer length.
    #[must_use]
    pub const fn total_control_length(&self) -> usize {
        self.total_control_length
    }
}

/// Converts one immutable protocol-built command into a pointer-free SPTI request.
///
/// # Errors
///
/// Returns a bounded validation error if a future trusted builder creates a CDB
/// or transfer that does not fit the Windows request contract.
pub fn build_scsi_pass_through(
    command: &Command,
) -> Result<ScsiPassThroughPacket, WindowsRequestError> {
    if command.cdb().is_empty() || command.cdb().len() > MAX_WINDOWS_CDB_LENGTH {
        return Err(WindowsRequestError::InvalidCdbLength);
    }
    if command.data().len() > MAX_TRANSPORT_RESPONSE_LENGTH {
        return Err(WindowsRequestError::TransferTooLarge);
    }

    let mut cdb = [0_u8; MAX_WINDOWS_CDB_LENGTH];
    cdb[..command.cdb().len()].copy_from_slice(command.cdb());
    let (kind, data_direction) = match command.direction() {
        DataDirection::None => (PassThroughKind::Buffered, SCSI_IOCTL_DATA_UNSPECIFIED),
        DataDirection::FromDevice => (PassThroughKind::Direct, SCSI_IOCTL_DATA_IN),
        DataDirection::ToDevice => (PassThroughKind::Direct, SCSI_IOCTL_DATA_OUT),
    };
    let header_length = std::mem::size_of::<PortableScsiPassThroughHeader>();
    let sense_offset = header_length;
    let total_control_length = sense_offset + WINDOWS_SENSE_CAPACITY;

    let semantic = classify(command);
    Ok(ScsiPassThroughPacket {
        command: command.clone(),
        semantic,
        risk: semantic.risk(),
        kind,
        cdb,
        cdb_length: command.cdb().len() as u8,
        data_direction,
        transfer_length: command.data().len() as u32,
        timeout_seconds: command.timeout_ms().div_ceil(1_000),
        header_length,
        data_offset: 0,
        sense_offset,
        total_control_length,
        direction: command.direction(),
    })
}

/// Validates one copied native completion against its immutable request.
///
/// # Errors
///
/// Returns a structural or SCSI-status error without retaining unchecked bytes.
pub fn parse_scsi_result(
    packet: &ScsiPassThroughPacket,
    completion: NativeScsiCompletion,
) -> Result<ParsedScsiResult, WindowsResultError> {
    if let Some((attempted, failure)) = completion.win32_failure {
        return Err(WindowsResultError::Win32 { attempted, failure });
    }
    if completion.scsi_status == 0x02 {
        if completion.sense_reported_length > WINDOWS_SENSE_CAPACITY {
            return Err(WindowsResultError::SenseLengthOutOfBounds);
        }
        if completion.sense_reported_length == 0
            || completion.sense.len() < completion.sense_reported_length
        {
            return Err(WindowsResultError::SenseTruncated);
        }
        let sense = SenseData::parse(&completion.sense[..completion.sense_reported_length])
            .map_err(|_| WindowsResultError::MalformedSense)?;
        return Err(WindowsResultError::CheckCondition(sense));
    }
    if completion.scsi_status != 0 {
        return Err(WindowsResultError::ScsiStatus(completion.scsi_status));
    }
    if completion.sense_reported_length != 0 || !completion.sense.is_empty() {
        return Err(WindowsResultError::UnexpectedSense);
    }
    if completion.transferred_length > packet.transfer_length {
        return Err(WindowsResultError::TransferredLengthOutOfBounds);
    }
    if packet.direction == DataDirection::ToDevice
        && completion.transferred_length != packet.transfer_length
    {
        return Err(WindowsResultError::ShortDataOut);
    }
    let transferred = completion.transferred_length as usize;
    let data = if packet.direction == DataDirection::FromDevice {
        if completion.data.len() < transferred {
            return Err(WindowsResultError::ReturnedDataTooShort);
        }
        completion.data[..transferred].to_vec()
    } else {
        Vec::new()
    };

    Ok(ParsedScsiResult {
        transferred_length: completion.transferred_length,
        residual_length: packet.transfer_length - completion.transferred_length,
        data,
    })
}

#[cfg(test)]
mod tests {
    use crate::protocol::{
        InquiryPage, inquiry, led_test, log_sense, mode_select, mode_sense, security_in, self_test,
        unit_reset, write_buffer,
    };

    use super::{
        WindowsIoFailure, build_scsi_pass_through, encode_instance_recipe, map_native_io_failure,
        map_native_platform_error, native_operation,
    };

    /// The private lease recipe preserves the exact SetupAPI instance spelling.
    #[test]
    fn instance_recipe_preserves_exact_utf16_units() {
        let recipe = encode_instance_recipe(4, "Usb\\Rdx").expect("bounded instance ID");

        assert_eq!(recipe, "win1:00000004:005500730062005C005200640078");
    }

    /// Every protocol builder maps to the companion's closed semantic boundary.
    #[test]
    fn trusted_commands_map_to_semantic_native_operations() {
        let mut mode_page = vec![0_u8; 13];
        mode_page[0..2].copy_from_slice(&11_u16.to_be_bytes());
        mode_page[8] = 0x31;
        mode_page[9] = 3;
        let cases = vec![
            (self_test(), super::WindowsSemanticCommand::SelfTest),
            (led_test(true), super::WindowsSemanticCommand::LedOn),
            (led_test(false), super::WindowsSemanticCommand::LedOff),
            (unit_reset(), super::WindowsSemanticCommand::UnitReset),
            (
                inquiry(InquiryPage::Standard),
                super::WindowsSemanticCommand::InquiryStandard,
            ),
            (
                inquiry(InquiryPage::DeviceIdentification),
                super::WindowsSemanticCommand::InquiryDeviceIdentification,
            ),
            (
                log_sense(0x20).expect("proven LOG page"),
                super::WindowsSemanticCommand::LogSenseDrive,
            ),
            (
                log_sense(0x21).expect("proven LOG page"),
                super::WindowsSemanticCommand::LogSenseCartridge,
            ),
            (
                mode_sense(0x31).expect("proven MODE page"),
                super::WindowsSemanticCommand::ModeSenseCapabilities,
            ),
            (
                mode_sense(0x33).expect("proven MODE page"),
                super::WindowsSemanticCommand::ModeSenseDrive,
            ),
            (
                mode_sense(0x34).expect("proven MODE page"),
                super::WindowsSemanticCommand::ModeSenseSata,
            ),
            (
                mode_select(&mode_page, false).expect("bounded MODE SELECT"),
                super::WindowsSemanticCommand::ModeSelect,
            ),
            (
                security_in(0x0010).expect("proven selector"),
                super::WindowsSemanticCommand::SecurityIn0010,
            ),
            (
                security_in(0x0020).expect("proven selector"),
                super::WindowsSemanticCommand::SecurityIn0020,
            ),
            (
                security_in(0x0021).expect("proven selector"),
                super::WindowsSemanticCommand::SecurityIn0021,
            ),
            (
                write_buffer(0x04, 0x012345, &[0xA5; 17]).expect("bounded firmware chunk"),
                super::WindowsSemanticCommand::FirmwareChunk,
            ),
            (
                write_buffer(0x05, 0x012345, &[]).expect("bounded firmware finalize"),
                super::WindowsSemanticCommand::FirmwareFinalize,
            ),
        ];

        for (command, expected) in cases {
            let packet = build_scsi_pass_through(&command).expect("bounded SPTI request");
            assert_eq!(packet.semantic, expected);
            let operation = native_operation(&packet).expect("closed semantic operation");
            assert_eq!(format!("{operation:?}"), "ScsiOperation(<private>)");
        }
    }

    /// Companion failures retain platform-open and dispatch certainty distinctions.
    #[test]
    fn native_failures_map_to_stable_portable_classes() {
        assert_eq!(
            map_native_platform_error(rdx_windows_native::NativeError::AccessDenied).code(),
            "platform-access-denied"
        );
        assert_eq!(
            map_native_platform_error(rdx_windows_native::NativeError::DeviceRemoved).code(),
            "device-removed"
        );
        assert_eq!(
            map_native_io_failure(rdx_windows_native::NativeError::TimedOut),
            WindowsIoFailure::TimedOut
        );
        assert_eq!(
            map_native_io_failure(rdx_windows_native::NativeError::Cancelled),
            WindowsIoFailure::Cancelled
        );
    }

    /// Every semantic command retains its exact high-level certainty risk in the packet.
    #[test]
    fn trusted_commands_map_to_exact_risk_classes() {
        let mut mode_page = vec![0_u8; 13];
        mode_page[0..2].copy_from_slice(&11_u16.to_be_bytes());
        mode_page[8] = 0x31;
        mode_page[9] = 3;
        let cases = [
            (self_test(), crate::model::RiskClass::Routine),
            (led_test(true), crate::model::RiskClass::Routine),
            (led_test(false), crate::model::RiskClass::Routine),
            (unit_reset(), crate::model::RiskClass::Configuration),
            (
                inquiry(InquiryPage::Standard),
                crate::model::RiskClass::ReadOnly,
            ),
            (
                inquiry(InquiryPage::DeviceIdentification),
                crate::model::RiskClass::ReadOnly,
            ),
            (
                log_sense(0x20).expect("proven LOG page"),
                crate::model::RiskClass::ReadOnly,
            ),
            (
                log_sense(0x21).expect("proven LOG page"),
                crate::model::RiskClass::ReadOnly,
            ),
            (
                mode_sense(0x31).expect("proven MODE page"),
                crate::model::RiskClass::ReadOnly,
            ),
            (
                mode_sense(0x33).expect("proven MODE page"),
                crate::model::RiskClass::ReadOnly,
            ),
            (
                mode_sense(0x34).expect("proven MODE page"),
                crate::model::RiskClass::ReadOnly,
            ),
            (
                security_in(0x0010).expect("proven selector"),
                crate::model::RiskClass::ReadOnly,
            ),
            (
                security_in(0x0020).expect("proven selector"),
                crate::model::RiskClass::ReadOnly,
            ),
            (
                security_in(0x0021).expect("proven selector"),
                crate::model::RiskClass::ReadOnly,
            ),
            (
                mode_select(&mode_page, false).expect("bounded MODE SELECT"),
                crate::model::RiskClass::Configuration,
            ),
            (
                write_buffer(0x04, 0, &[0xA5]).expect("bounded firmware chunk"),
                crate::model::RiskClass::Critical,
            ),
            (
                write_buffer(0x05, 1, &[]).expect("bounded firmware finalize"),
                crate::model::RiskClass::Critical,
            ),
        ];

        for (command, expected) in cases {
            let packet = build_scsi_pass_through(&command).expect("bounded SPTI request");
            assert_eq!(packet.risk, expected);
        }
        assert_eq!(
            super::WindowsSemanticCommand::Unknown.risk(),
            crate::model::RiskClass::Critical
        );
    }

    /// Only active native construction may publish readiness-derived capabilities.
    #[test]
    fn inactive_readiness_fixture_cannot_publish_native_capabilities() {
        let readiness = super::WindowsReadiness::new(true, true, true, true);
        let inactive = super::WindowsBackend::from_test_readiness(readiness, false);

        assert!(!super::PlatformBackend::capabilities(&inactive).discovery_available());
        assert!(!super::PlatformBackend::capabilities(&inactive).transport_available());
        assert!(!super::PlatformBackend::capabilities(&inactive).privileged());
    }

    /// Running service metadata cannot substitute for current-process authority.
    #[test]
    fn active_backend_requires_current_process_authority_for_transport() {
        let unbound = super::WindowsBackend::from_test_readiness(
            super::WindowsReadiness::new(true, true, true, false),
            true,
        );
        let bound = super::WindowsBackend::from_test_readiness(
            super::WindowsReadiness::new(true, true, true, true),
            true,
        );

        assert!(super::PlatformBackend::capabilities(&unbound).discovery_available());
        assert!(!super::PlatformBackend::capabilities(&unbound).transport_available());
        assert!(!super::PlatformBackend::capabilities(&unbound).privileged());
        assert!(super::PlatformBackend::capabilities(&bound).transport_available());
        assert!(super::PlatformBackend::capabilities(&bound).privileged());
        assert!(super::PlatformBackend::capabilities(&bound).safe_eject_available());
        assert!(super::PlatformBackend::capabilities(&bound).force_eject_available());
        assert!(super::PlatformBackend::capabilities(&bound).format_available());
        assert!(super::PlatformBackend::capabilities(&bound).write_read_available());
        assert!(super::PlatformBackend::capabilities(&bound).drive_letter_available());
        assert!(!super::PlatformBackend::capabilities(&bound).hardware_verified());
    }
}
