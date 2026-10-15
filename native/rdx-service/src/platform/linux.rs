// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Portable Linux `SG_IO` semantics and target-gated native backend support.

use crate::model::RiskClass;
use crate::protocol::{Command, DataDirection, MAX_SENSE_DATA_LENGTH, SenseData};
use crate::transport::{
    CommandDispatch, MAX_TRANSPORT_RESPONSE_LENGTH, TransportError, TransportResponse,
};

use super::{
    CandidateDevice, CandidateLease, PlatformBackend, PlatformCapabilities, PlatformError,
};
use crate::service::ServiceExecutionContext;

#[cfg(target_os = "linux")]
use super::CandidateMetadata;

#[cfg(any(target_os = "linux", test))]
mod authority;
mod backend;
#[cfg(any(target_os = "linux", test))]
mod context;
#[cfg(all(test, target_os = "linux"))]
mod firmware_read_tests;
mod semantic;

#[cfg(target_os = "linux")]
mod host;

#[cfg(target_os = "linux")]
use authority::{PendingCandidateAuthority, StagedCandidateAuthority};
#[cfg(target_os = "linux")]
use semantic::LinuxSemanticCommand;
use semantic::classify;
#[cfg(target_os = "linux")]
use semantic::write_buffer_fields;

/// `SG_IO` direction for a command without a data phase.
pub const SG_DXFER_NONE: i32 = -1;
/// `SG_IO` direction for a transfer from host to device.
pub const SG_DXFER_TO_DEV: i32 = -2;
/// `SG_IO` direction for a transfer from device to host.
pub const SG_DXFER_FROM_DEV: i32 = -3;
/// `sg_io_hdr_t.info` result value for an unqualified completion.
pub const SG_INFO_OK: u32 = 0;
/// `sg_io_hdr_t.info` low-bit value indicating status to inspect.
pub const SG_INFO_CHECK: u32 = 1;
/// Linux driver-status value proving request-sense data accompanies CHECK CONDITION.
pub const DRIVER_SENSE: u16 = 0x08;
/// Fixed request-sense capacity owned beside every Linux request.
pub const LINUX_SENSE_CAPACITY: usize = MAX_SENSE_DATA_LENGTH;

const SG_INFO_OK_MASK: u32 = 0x01;
const SG_INFO_DIRECT_IO_MASK: u32 = 0x06;
const MAX_LINUX_CDB_LENGTH: usize = 16;

/// Transient access evidence observed for currently enumerated `scsi_generic` nodes.
///
/// This observation is candidate-local and must never be retained in the
/// backend readiness report. Every discovery scan opens and validates its
/// current candidates afresh.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeviceAccessEvidence {
    /// No candidate exists, so no exact file-descriptor access was proven.
    NoCandidate,
    /// At least one candidate exists but required read/write access was denied.
    Denied,
    /// The current process opened an exact candidate read/write with safe flags.
    ReadWrite,
}

/// Sanitized Linux prerequisite facts from the target-gated native probe.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LinuxReadinessFacts {
    sysfs_available: bool,
    udev_rules_installed: bool,
    ipc_group_configured: bool,
    current_ipc_group_member: bool,
    polkit_policy_installed: bool,
    service_installed: bool,
    service_running: bool,
    current_process_authorized: bool,
    direct_process_authorized: bool,
}

impl LinuxReadinessFacts {
    /// Creates pointer-free readiness facts for pure capability evaluation.
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub const fn new(
        sysfs_available: bool,
        udev_rules_installed: bool,
        ipc_group_configured: bool,
        current_ipc_group_member: bool,
        _device_access: DeviceAccessEvidence,
        polkit_policy_installed: bool,
        service_installed: bool,
        service_running: bool,
        current_process_authorized: bool,
    ) -> Self {
        Self {
            sysfs_available,
            udev_rules_installed,
            ipc_group_configured,
            current_ipc_group_member,
            polkit_policy_installed,
            service_installed,
            service_running,
            current_process_authorized,
            direct_process_authorized: false,
        }
    }

    /// Returns facts representing a non-Linux or otherwise unavailable host.
    const fn unavailable() -> Self {
        Self::new(
            false,
            false,
            false,
            false,
            DeviceAccessEvidence::NoCandidate,
            false,
            false,
            false,
            false,
        )
    }
}

/// First concrete Linux readiness prerequisite that is not satisfied.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LinuxReadinessIssue {
    /// `/sys/class/scsi_generic` is unavailable.
    SysfsUnavailable,
    /// No active constrained OpenRDX udev rule is installed.
    UdevRulesMissing,
    /// The IPC-only `openrdx` socket group is not configured.
    IpcGroupMissing,
    /// The current process has not inherited IPC socket group membership.
    CurrentIpcGroupMembershipMissing,
    /// The narrow OpenRDX polkit policy is not installed.
    PolkitPolicyMissing,
    /// The constrained privileged service is not installed.
    ServiceNotInstalled,
    /// The constrained privileged service is installed but not running.
    ServiceNotRunning,
    /// The current process is not the authorized service process.
    CurrentProcessUnauthorized,
    /// Every software prerequisite is proven; physical RDX acceptance is still absent.
    ReadyHardwareUnverified,
}

/// Pure readiness result with an honest platform capability matrix.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LinuxReadinessReport {
    issue: LinuxReadinessIssue,
    capabilities: PlatformCapabilities,
}

impl LinuxReadinessReport {
    /// Returns the concrete readiness outcome.
    #[must_use]
    pub const fn issue(self) -> LinuxReadinessIssue {
        self.issue
    }

    /// Returns the cross-field-consistent platform capability matrix.
    #[must_use]
    pub const fn capabilities(self) -> PlatformCapabilities {
        self.capabilities
    }
}

/// Evaluates native facts without exposing a backend activation constructor.
#[must_use]
pub fn evaluate_linux_readiness(facts: LinuxReadinessFacts) -> LinuxReadinessReport {
    let issue = if !facts.sysfs_available {
        LinuxReadinessIssue::SysfsUnavailable
    } else if !facts.udev_rules_installed {
        LinuxReadinessIssue::UdevRulesMissing
    } else if facts.direct_process_authorized {
        LinuxReadinessIssue::ReadyHardwareUnverified
    } else if !facts.ipc_group_configured {
        LinuxReadinessIssue::IpcGroupMissing
    } else if !facts.current_ipc_group_member {
        LinuxReadinessIssue::CurrentIpcGroupMembershipMissing
    } else if !facts.polkit_policy_installed {
        LinuxReadinessIssue::PolkitPolicyMissing
    } else if !facts.service_installed {
        LinuxReadinessIssue::ServiceNotInstalled
    } else if !facts.service_running {
        LinuxReadinessIssue::ServiceNotRunning
    } else if !facts.current_process_authorized {
        LinuxReadinessIssue::CurrentProcessUnauthorized
    } else {
        // Candidate existence, access, and busy state can change after service
        // startup. Only the authenticated endpoint and installed host
        // prerequisites are immutable readiness gates; exact access is proven
        // independently by every candidate-local open below.
        LinuxReadinessIssue::ReadyHardwareUnverified
    };
    let discovery = facts.sysfs_available;
    // An authoritative empty or candidate-local denied scan is not a static
    // transport failure. The accepted service endpoint retains authority for a
    // later hotplug or access-policy change in the same service process.
    let authorized = issue == LinuxReadinessIssue::ReadyHardwareUnverified;
    let capabilities = PlatformCapabilities::try_new(
        discovery, authorized, authorized, authorized, authorized, authorized, false, false,
    )
    .expect("Linux readiness mapping remains cross-field consistent");
    LinuxReadinessReport {
        issue,
        capabilities,
    }
}

#[cfg(test)]
mod readiness_tests {
    use super::*;

    /// Fully authorized software readiness exposes implemented Linux host
    /// operations without claiming physical hardware acceptance.
    #[test]
    fn ready_software_advertises_implemented_host_operations() {
        let capabilities = evaluate_linux_readiness(LinuxReadinessFacts::new(
            true,
            true,
            true,
            true,
            DeviceAccessEvidence::ReadWrite,
            true,
            true,
            true,
            true,
        ))
        .capabilities();

        assert!(capabilities.safe_eject_available());
        assert!(capabilities.force_eject_available());
        assert!(capabilities.format_available());
        assert!(capabilities.write_read_available());
        assert!(!capabilities.drive_letter_available());
        assert!(!capabilities.hardware_verified());
    }

    /// An authoritative empty cold scan must keep the installed privileged
    /// transport available so the same service can open a later hotplug.
    #[test]
    fn no_candidate_keeps_static_transport_ready_for_hotplug() {
        let report = evaluate_linux_readiness(LinuxReadinessFacts::new(
            true,
            true,
            true,
            true,
            DeviceAccessEvidence::NoCandidate,
            true,
            true,
            true,
            true,
        ));

        assert_eq!(report.issue(), LinuxReadinessIssue::ReadyHardwareUnverified);
        assert!(report.capabilities().discovery_available());
        assert!(report.capabilities().transport_available());
        assert!(report.capabilities().safe_eject_available());
        assert!(!report.capabilities().hardware_verified());
    }
}

/// Service-owned Linux candidate and `SG_IO` backend.
pub struct LinuxBackend {
    report: LinuxReadinessReport,
    native_active: bool,
    #[cfg(target_os = "linux")]
    pending: PendingCandidateAuthority<rdx_linux_native::ScsiGenericCandidate>,
    #[cfg(target_os = "linux")]
    staged: Option<StagedCandidateAuthority<rdx_linux_native::ScsiGenericCandidate>>,
}

impl LinuxBackend {
    /// Builds a backend from private readiness while keeping activation native-only.
    fn from_readiness(facts: LinuxReadinessFacts, native_active: bool) -> Self {
        let facts = if native_active {
            facts
        } else {
            LinuxReadinessFacts::unavailable()
        };
        Self {
            report: evaluate_linux_readiness(facts),
            native_active,
            #[cfg(target_os = "linux")]
            pending: PendingCandidateAuthority::default(),
            #[cfg(target_os = "linux")]
            staged: None,
        }
    }

    /// Probes and activates the target-gated native Linux adapter.
    #[must_use]
    pub fn native() -> Self {
        Self::native_with_context(ServiceExecutionContext::development_stdio())
    }

    /// Probes Linux resources under explicit accepted-systemd endpoint authority.
    #[must_use]
    pub fn native_with_context(context: ServiceExecutionContext) -> Self {
        #[cfg(target_os = "linux")]
        {
            let native = rdx_linux_native::probe_readiness();
            let access = match native.device_access() {
                rdx_linux_native::DeviceAccess::NoCandidate => DeviceAccessEvidence::NoCandidate,
                rdx_linux_native::DeviceAccess::Denied => DeviceAccessEvidence::Denied,
                rdx_linux_native::DeviceAccess::ReadWrite => DeviceAccessEvidence::ReadWrite,
            };
            Self::from_readiness(
                context::apply(
                    LinuxReadinessFacts::new(
                        native.sysfs_available(),
                        native.udev_rules_installed(),
                        native.ipc_group_configured(),
                        native.current_ipc_group_member(),
                        access,
                        native.polkit_policy_installed(),
                        context.endpoint_authenticated(),
                        context.endpoint_authenticated(),
                        context.endpoint_authenticated() && context.process_authorized(),
                    ),
                    &context,
                ),
                true,
            )
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = context;
            Self::from_readiness(LinuxReadinessFacts::unavailable(), false)
        }
    }

    /// Returns the concrete sanitized prerequisite outcome.
    #[must_use]
    pub const fn readiness_issue(&self) -> LinuxReadinessIssue {
        self.report.issue
    }
}

#[cfg(target_os = "linux")]
struct LinuxDeviceHandle {
    device: rdx_linux_native::LinuxDevice,
}

/// Converts only exact protocol-built commands into the companion's semantic API.
#[cfg(target_os = "linux")]
fn native_operation(
    packet: &SgIoPacket,
) -> Result<rdx_linux_native::ScsiOperation, rdx_linux_native::NativeError> {
    let command = &packet.command;
    let operation = match packet.semantic {
        LinuxSemanticCommand::SelfTest => rdx_linux_native::ScsiOperation::self_test(),
        LinuxSemanticCommand::LedOn => rdx_linux_native::ScsiOperation::led_test(true),
        LinuxSemanticCommand::LedOff => rdx_linux_native::ScsiOperation::led_test(false),
        LinuxSemanticCommand::UnitReset => rdx_linux_native::ScsiOperation::unit_reset(),
        LinuxSemanticCommand::OpenRdxManufacturingRecordFirst => {
            rdx_linux_native::ScsiOperation::openrdx_manufacturing_record_first()
        }
        LinuxSemanticCommand::OpenRdxManufacturingRecordSecond => {
            rdx_linux_native::ScsiOperation::openrdx_manufacturing_record_second()
        }
        LinuxSemanticCommand::OpenRdxManufacturingRestoreCapability => {
            rdx_linux_native::ScsiOperation::openrdx_manufacturing_restore_capability()
        }
        LinuxSemanticCommand::OpenRdxSerialCapability => {
            rdx_linux_native::ScsiOperation::openrdx_serial_capability()
        }
        LinuxSemanticCommand::InquiryStandard => {
            rdx_linux_native::ScsiOperation::inquiry_standard()
        }
        LinuxSemanticCommand::InquiryDeviceIdentification => {
            rdx_linux_native::ScsiOperation::inquiry_device_identification()
        }
        LinuxSemanticCommand::InquiryMediaIdentification => {
            rdx_linux_native::ScsiOperation::inquiry_media_identification()
        }
        LinuxSemanticCommand::InquiryMediaDevice => {
            rdx_linux_native::ScsiOperation::inquiry_media_device()
        }
        LinuxSemanticCommand::LogSenseTemperature => {
            rdx_linux_native::ScsiOperation::log_sense_temperature()
        }
        LinuxSemanticCommand::LogSenseDrive => rdx_linux_native::ScsiOperation::log_sense_drive(),
        LinuxSemanticCommand::LogSenseCartridge => {
            rdx_linux_native::ScsiOperation::log_sense_cartridge()
        }
        LinuxSemanticCommand::ModeSenseCapabilities => {
            rdx_linux_native::ScsiOperation::mode_sense_capabilities()
        }
        LinuxSemanticCommand::ModeSenseDrive => rdx_linux_native::ScsiOperation::mode_sense_drive(),
        LinuxSemanticCommand::ModeSenseSata => rdx_linux_native::ScsiOperation::mode_sense_sata(),
        LinuxSemanticCommand::SecurityIn0010 => {
            rdx_linux_native::ScsiOperation::security_in_selector_0010()
        }
        LinuxSemanticCommand::SecurityIn0020 => {
            rdx_linux_native::ScsiOperation::security_in_selector_0020()
        }
        LinuxSemanticCommand::SecurityIn0021 => {
            rdx_linux_native::ScsiOperation::security_in_selector_0021()
        }
        LinuxSemanticCommand::ModeSelect => rdx_linux_native::ScsiOperation::mode_select(
            command.cdb()[1] & 1 != 0,
            command.data().to_vec(),
        )?,
        LinuxSemanticCommand::FirmwareChunk => {
            let (_, offset) = write_buffer_fields(command)
                .ok_or(rdx_linux_native::NativeError::InvalidRequest)?;
            rdx_linux_native::ScsiOperation::firmware_chunk(offset, command.data().to_vec())?
        }
        LinuxSemanticCommand::FirmwareFinalize => {
            let (_, offset) = write_buffer_fields(command)
                .ok_or(rdx_linux_native::NativeError::InvalidRequest)?;
            rdx_linux_native::ScsiOperation::firmware_finalize(offset)?
        }
        LinuxSemanticCommand::Unknown => {
            return Err(rdx_linux_native::NativeError::InvalidRequest);
        }
    };
    operation.with_timeout_ms(packet.timeout_ms())
}

/// Pointer-width model of Linux's public `sg_io_hdr_t` ABI.
#[allow(dead_code)]
#[repr(C)]
struct PortableSgIoHeader {
    interface_id: i32,
    dxfer_direction: i32,
    cmd_len: u8,
    max_sense_len: u8,
    iovec_count: u16,
    dxfer_len: u32,
    dxferp: usize,
    cmdp: usize,
    sensep: usize,
    timeout: u32,
    flags: u32,
    pack_id: i32,
    user_ptr: usize,
    status: u8,
    masked_status: u8,
    message_status: u8,
    sense_len_written: u8,
    host_status: u16,
    driver_status: u16,
    residual: i32,
    duration: u32,
    info: u32,
}

/// Pure pointer-free request description consumed by the native Linux boundary.
pub struct SgIoPacket {
    command: Command,
    #[cfg(target_os = "linux")]
    semantic: LinuxSemanticCommand,
    risk: RiskClass,
    cdb: [u8; MAX_LINUX_CDB_LENGTH],
    command_length: u8,
    direction: i32,
    transfer_length: u32,
    timeout_ms: u32,
}

impl SgIoPacket {
    /// Returns the required v3 interface identifier.
    #[must_use]
    pub const fn interface_id(&self) -> i32 {
        b'S' as i32
    }
    /// Returns the signed Linux data-direction value.
    #[must_use]
    pub const fn direction(&self) -> i32 {
        self.direction
    }

    /// Returns only initialized trusted CDB bytes.
    #[must_use]
    pub fn cdb(&self) -> &[u8] {
        &self.cdb[..usize::from(self.command_length)]
    }

    /// Returns the exact trusted CDB length.
    #[must_use]
    pub const fn command_length(&self) -> u8 {
        self.command_length
    }

    /// Returns the bounded transfer-buffer length.
    #[must_use]
    pub const fn transfer_length(&self) -> u32 {
        self.transfer_length
    }

    /// Returns the exact bounded Linux timeout in milliseconds.
    #[must_use]
    pub const fn timeout_ms(&self) -> u32 {
        self.timeout_ms
    }

    /// Returns the fixed request-sense capacity.
    #[must_use]
    pub const fn sense_capacity(&self) -> usize {
        LINUX_SENSE_CAPACITY
    }

    /// Returns the target pointer-width `sg_io_hdr_t` size.
    #[must_use]
    pub const fn header_length(&self) -> usize {
        std::mem::size_of::<PortableSgIoHeader>()
    }
}

/// Sanitized request-conversion failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LinuxRequestError {
    /// The trusted CDB did not fit Linux's bounded command field.
    InvalidCdbLength,
    /// The trusted transfer exceeded the portable service bound.
    TransferTooLarge,
}

/// Converts one immutable protocol-built command into a pointer-free SG request.
///
/// # Errors
///
/// Returns a bounded validation error if a future trusted builder exceeds the
/// Linux request contract.
pub fn build_sg_io(command: &Command) -> Result<SgIoPacket, LinuxRequestError> {
    if command.cdb().is_empty() || command.cdb().len() > MAX_LINUX_CDB_LENGTH {
        return Err(LinuxRequestError::InvalidCdbLength);
    }
    if command.data().len() > MAX_TRANSPORT_RESPONSE_LENGTH {
        return Err(LinuxRequestError::TransferTooLarge);
    }
    let mut cdb = [0_u8; MAX_LINUX_CDB_LENGTH];
    cdb[..command.cdb().len()].copy_from_slice(command.cdb());
    let direction = match command.direction() {
        DataDirection::None => SG_DXFER_NONE,
        DataDirection::FromDevice => SG_DXFER_FROM_DEV,
        DataDirection::ToDevice => SG_DXFER_TO_DEV,
    };
    let semantic = classify(command);
    Ok(SgIoPacket {
        command: command.clone(),
        #[cfg(target_os = "linux")]
        semantic,
        risk: semantic.risk(),
        cdb,
        command_length: command.cdb().len() as u8,
        direction,
        transfer_length: command.data().len() as u32,
        timeout_ms: command.timeout_ms(),
    })
}

/// Exact status fields copied from a completed `sg_io_hdr_t`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SgIoStatus {
    status: u8,
    masked_status: u8,
    message_status: u8,
    host_status: u16,
    driver_status: u16,
    info: u32,
}

impl SgIoStatus {
    /// Creates one pointer-free native status record for portable validation.
    #[must_use]
    pub const fn new(
        status: u8,
        masked_status: u8,
        message_status: u8,
        host_status: u16,
        driver_status: u16,
        info: u32,
    ) -> Self {
        Self {
            status,
            masked_status,
            message_status,
            host_status,
            driver_status,
            info,
        }
    }

    /// Returns the exact all-zero GOOD completion shape.
    #[must_use]
    pub const fn good() -> Self {
        Self::new(0, 0, 0, 0, 0, SG_INFO_OK)
    }
}

/// Sanitized Linux syscall failure classes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LinuxIoFailure {
    /// Device access was denied.
    AccessDenied,
    /// Device or queue state was busy.
    Busy,
    /// A signal interrupted an invoked `SG_IO`; the request may remain active.
    Interrupted,
    /// The bounded native operation timed out.
    TimedOut,
    /// Hotplug removed the selected device.
    DeviceRemoved,
    /// Another sanitized syscall failure occurred.
    Other,
}

/// Pointer-free completion copied out of the Linux-only native boundary.
pub struct NativeSgCompletion {
    syscall_failure: Option<(bool, LinuxIoFailure)>,
    status: SgIoStatus,
    residual: i32,
    data: Vec<u8>,
    sense_reported_length: usize,
    sense: Vec<u8>,
}

impl NativeSgCompletion {
    /// Creates one completed `SG_IO` result for portable validation.
    #[must_use]
    pub fn device(
        status: SgIoStatus,
        residual: i32,
        data: Vec<u8>,
        sense_reported_length: usize,
        sense: Vec<u8>,
    ) -> Self {
        Self {
            syscall_failure: None,
            status,
            residual,
            data,
            sense_reported_length,
            sense,
        }
    }

    /// Creates a failure proven to precede the ioctl invocation.
    #[must_use]
    pub fn not_attempted(failure: LinuxIoFailure) -> Self {
        Self {
            syscall_failure: Some((false, failure)),
            status: SgIoStatus::good(),
            residual: 0,
            data: Vec::new(),
            sense_reported_length: 0,
            sense: Vec::new(),
        }
    }

    /// Creates a syscall failure after `ioctl(SG_IO)` was invoked.
    #[must_use]
    pub fn attempted_error(failure: LinuxIoFailure) -> Self {
        Self {
            syscall_failure: Some((true, failure)),
            status: SgIoStatus::good(),
            residual: 0,
            data: Vec::new(),
            sense_reported_length: 0,
            sense: Vec::new(),
        }
    }
}

impl std::fmt::Debug for NativeSgCompletion {
    /// Redacts data and sense bytes while preserving structural lengths.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NativeSgCompletion")
            .field("syscall_failure", &self.syscall_failure)
            .field("status", &self.status)
            .field("residual", &self.residual)
            .field("data_length", &self.data.len())
            .field("sense_reported_length", &self.sense_reported_length)
            .field("sense_copied_length", &self.sense.len())
            .finish_non_exhaustive()
    }
}

/// Sanitized structural or device failure while validating one completion.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LinuxResultError {
    /// Native failure preserving whether `ioctl` was already invoked.
    Syscall {
        /// Whether the synchronous kernel API call began.
        attempted: bool,
        /// Sanitized native failure class.
        failure: LinuxIoFailure,
    },
    /// The host adapter returned a non-zero status.
    HostStatus(u16),
    /// The low-level driver returned an unsupported status.
    DriverStatus(u16),
    /// The SCSI message status was not COMMAND COMPLETE.
    MessageStatus(u8),
    /// Masked status did not correspond exactly to raw SCSI status.
    MaskedStatusMismatch,
    /// The `info` field was unknown or contradicted the returned status.
    InconsistentInfo,
    /// Linux returned a negative signed residual.
    NegativeResidual,
    /// The residual exceeded the trusted transfer allocation.
    ResidualOutOfBounds,
    /// A successful data-out operation reported untransferred bytes.
    ShortDataOut,
    /// Copied data was shorter than the residual-derived transfer count.
    ReturnedDataTooShort,
    /// Reported request-sense length exceeded the fixed capacity.
    SenseLengthOutOfBounds,
    /// Copied request sense was shorter than the reported count.
    SenseTruncated,
    /// CHECK CONDITION request sense was malformed.
    MalformedSense,
    /// A non-CHECK completion carried request-sense bytes.
    UnexpectedSense,
    /// The device returned CHECK CONDITION with bounded parsed sense.
    CheckCondition(SenseData),
    /// The device returned another non-GOOD SCSI status.
    ScsiStatus(u8),
}

/// Proven successful SG response with residual-derived transfer evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParsedSgIoResult {
    transferred_length: u32,
    residual_length: u32,
    data: Vec<u8>,
}

impl ParsedSgIoResult {
    /// Returns the residual-derived transferred length.
    #[must_use]
    pub const fn transferred_length(&self) -> u32 {
        self.transferred_length
    }

    /// Returns the validated non-negative residual.
    #[must_use]
    pub const fn residual_length(&self) -> u32 {
        self.residual_length
    }

    /// Returns only data bytes proven transferred from the device.
    #[must_use]
    pub fn data(&self) -> &[u8] {
        &self.data
    }
}

/// Validates one copied Linux completion against its immutable request.
///
/// # Errors
///
/// Returns a sanitized syscall, status, residual, data, or sense error.
pub fn parse_sg_io(
    packet: &SgIoPacket,
    completion: NativeSgCompletion,
) -> Result<ParsedSgIoResult, LinuxResultError> {
    if let Some((attempted, failure)) = completion.syscall_failure {
        return Err(LinuxResultError::Syscall { attempted, failure });
    }
    let status = completion.status;
    if status.host_status != 0 {
        return Err(LinuxResultError::HostStatus(status.host_status));
    }
    if status.message_status != 0 {
        return Err(LinuxResultError::MessageStatus(status.message_status));
    }
    if status.driver_status != 0 && !(status.status == 0x02 && status.driver_status == DRIVER_SENSE)
    {
        return Err(LinuxResultError::DriverStatus(status.driver_status));
    }
    if status.masked_status != status.status >> 1 {
        return Err(LinuxResultError::MaskedStatusMismatch);
    }
    if !info_is_valid(status.info)
        || (status.info & SG_INFO_OK_MASK == SG_INFO_CHECK) != (status.status != 0)
    {
        return Err(LinuxResultError::InconsistentInfo);
    }
    if status.status == 0x02 {
        if status.driver_status != DRIVER_SENSE {
            return Err(LinuxResultError::DriverStatus(status.driver_status));
        }
        if completion.sense_reported_length > LINUX_SENSE_CAPACITY {
            return Err(LinuxResultError::SenseLengthOutOfBounds);
        }
        if completion.sense_reported_length == 0
            || completion.sense.len() < completion.sense_reported_length
        {
            return Err(LinuxResultError::SenseTruncated);
        }
        let sense = SenseData::parse(&completion.sense[..completion.sense_reported_length])
            .map_err(|_| LinuxResultError::MalformedSense)?;
        return Err(LinuxResultError::CheckCondition(sense));
    }
    if status.driver_status != 0 {
        return Err(LinuxResultError::DriverStatus(status.driver_status));
    }
    if status.status != 0 {
        if completion.sense_reported_length != 0 || !completion.sense.is_empty() {
            return Err(LinuxResultError::UnexpectedSense);
        }
        return Err(LinuxResultError::ScsiStatus(status.status));
    }
    if completion.sense_reported_length != 0 || !completion.sense.is_empty() {
        return Err(LinuxResultError::UnexpectedSense);
    }
    let residual =
        u32::try_from(completion.residual).map_err(|_| LinuxResultError::NegativeResidual)?;
    if residual > packet.transfer_length {
        return Err(LinuxResultError::ResidualOutOfBounds);
    }
    if packet.command.direction() == DataDirection::ToDevice && residual != 0 {
        return Err(LinuxResultError::ShortDataOut);
    }
    let transferred_length = packet.transfer_length - residual;
    let data = if packet.command.direction() == DataDirection::FromDevice {
        let transferred = transferred_length as usize;
        if completion.data.len() < transferred {
            return Err(LinuxResultError::ReturnedDataTooShort);
        }
        completion.data[..transferred].to_vec()
    } else {
        Vec::new()
    };
    Ok(ParsedSgIoResult {
        transferred_length,
        residual_length: residual,
        data,
    })
}

/// Accepts only documented low result and direct-I/O mode bits.
fn info_is_valid(info: u32) -> bool {
    if info & !(SG_INFO_OK_MASK | SG_INFO_DIRECT_IO_MASK) != 0 {
        return false;
    }
    !matches!(info & SG_INFO_DIRECT_IO_MASK, SG_INFO_DIRECT_IO_MASK)
}

/// Converts a pure SG result into the Phase 2 dispatch-certainty contract.
#[must_use]
pub fn convert_sg_completion(
    packet: &SgIoPacket,
    completion: NativeSgCompletion,
) -> CommandDispatch {
    match parse_sg_io(packet, completion) {
        Ok(result) => match TransportResponse::new(result.data().to_vec()) {
            Ok(response) => CommandDispatch::Succeeded(response),
            Err(error) => CommandDispatch::CompletionUnknown(error),
        },
        Err(LinuxResultError::CheckCondition(sense)) if packet.risk == RiskClass::ReadOnly => {
            CommandDispatch::DefinitelyRejected(TransportError::CheckCondition(sense))
        }
        Err(LinuxResultError::CheckCondition(sense)) => {
            CommandDispatch::CompletionUnknown(TransportError::CheckCondition(sense))
        }
        Err(LinuxResultError::Syscall {
            attempted: false,
            failure,
        }) => CommandDispatch::NotSent(transport_error_for_io_failure(failure)),
        Err(LinuxResultError::Syscall {
            attempted: true,
            failure,
        }) => CommandDispatch::CompletionUnknown(transport_error_for_io_failure(failure)),
        Err(LinuxResultError::ScsiStatus(_)) if packet.risk == RiskClass::ReadOnly => {
            CommandDispatch::DefinitelyRejected(TransportError::Unavailable)
        }
        Err(LinuxResultError::HostStatus(status)) => {
            CommandDispatch::CompletionUnknown(if status == 0x03 {
                TransportError::Timeout
            } else if matches!(status, 0x01 | 0x04) {
                TransportError::DeviceRemoved
            } else {
                TransportError::Unavailable
            })
        }
        Err(
            LinuxResultError::ScsiStatus(_)
            | LinuxResultError::DriverStatus(_)
            | LinuxResultError::MessageStatus(_)
            | LinuxResultError::MaskedStatusMismatch
            | LinuxResultError::InconsistentInfo
            | LinuxResultError::NegativeResidual
            | LinuxResultError::ResidualOutOfBounds
            | LinuxResultError::ShortDataOut
            | LinuxResultError::ReturnedDataTooShort
            | LinuxResultError::SenseLengthOutOfBounds
            | LinuxResultError::SenseTruncated
            | LinuxResultError::MalformedSense
            | LinuxResultError::UnexpectedSense,
        ) => CommandDispatch::CompletionUnknown(TransportError::Unavailable),
    }
}

/// Maps one sanitized syscall failure without changing dispatch certainty.
const fn transport_error_for_io_failure(failure: LinuxIoFailure) -> TransportError {
    match failure {
        LinuxIoFailure::TimedOut => TransportError::Timeout,
        LinuxIoFailure::DeviceRemoved => TransportError::DeviceRemoved,
        LinuxIoFailure::AccessDenied
        | LinuxIoFailure::Busy
        | LinuxIoFailure::Interrupted
        | LinuxIoFailure::Other => TransportError::Unavailable,
    }
}

/// Maps one companion failure into a platform-open error.
#[cfg(target_os = "linux")]
fn map_native_platform_error(error: rdx_linux_native::NativeError) -> PlatformError {
    match error {
        rdx_linux_native::NativeError::AccessDenied => PlatformError::AccessDenied,
        rdx_linux_native::NativeError::Busy => PlatformError::DeviceBusy,
        rdx_linux_native::NativeError::Interrupted => PlatformError::OperationCancelled,
        rdx_linux_native::NativeError::TimedOut => PlatformError::OperationTimedOut,
        rdx_linux_native::NativeError::DeviceRemoved | rdx_linux_native::NativeError::NoMedia => {
            PlatformError::DeviceRemoved
        }
        rdx_linux_native::NativeError::EnumerationFailed => PlatformError::EnumerationFailed,
        rdx_linux_native::NativeError::ResourceLimit => PlatformError::TooManyCandidates,
        rdx_linux_native::NativeError::UnsupportedPlatform
        | rdx_linux_native::NativeError::DependencyMissing
        | rdx_linux_native::NativeError::InvalidRequest
        | rdx_linux_native::NativeError::EvidenceIncomplete
        | rdx_linux_native::NativeError::Other => PlatformError::NativeBoundaryFailure,
    }
}

/// Maps a companion dispatch failure without retaining errno or native text.
#[cfg(target_os = "linux")]
fn map_native_io_failure(error: rdx_linux_native::NativeError) -> LinuxIoFailure {
    match error {
        rdx_linux_native::NativeError::AccessDenied => LinuxIoFailure::AccessDenied,
        rdx_linux_native::NativeError::Busy => LinuxIoFailure::Busy,
        rdx_linux_native::NativeError::Interrupted => LinuxIoFailure::Interrupted,
        rdx_linux_native::NativeError::TimedOut => LinuxIoFailure::TimedOut,
        rdx_linux_native::NativeError::DeviceRemoved | rdx_linux_native::NativeError::NoMedia => {
            LinuxIoFailure::DeviceRemoved
        }
        rdx_linux_native::NativeError::UnsupportedPlatform
        | rdx_linux_native::NativeError::DependencyMissing
        | rdx_linux_native::NativeError::InvalidRequest
        | rdx_linux_native::NativeError::EnumerationFailed
        | rdx_linux_native::NativeError::EvidenceIncomplete
        | rdx_linux_native::NativeError::ResourceLimit
        | rdx_linux_native::NativeError::Other => LinuxIoFailure::Other,
    }
}
