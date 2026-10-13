// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Portable macOS SCSI-task semantics and target-gated native backend support.

use crate::model::RiskClass;
use crate::protocol::{Command, DataDirection, MAX_SENSE_DATA_LENGTH, SenseData};
use crate::transport::{
    CommandDispatch, MAX_TRANSPORT_RESPONSE_LENGTH, TransportError, TransportResponse,
};

use super::{
    CandidateDevice, CandidateLease, PlatformBackend, PlatformCapabilities, PlatformError,
};
use crate::service::ServiceExecutionContext;

#[cfg(target_os = "macos")]
use super::CandidateMetadata;

#[cfg(any(target_os = "macos", test))]
mod authority;
#[cfg(any(target_os = "macos", test))]
mod context;
mod semantic;

#[cfg(target_os = "macos")]
mod host;
mod label;
#[cfg(any(target_os = "macos", test))]
mod label_rematch;
#[cfg(target_os = "macos")]
mod refresh;
#[cfg(any(target_os = "macos", test))]
mod scsi_handoff;

#[cfg(target_os = "macos")]
use authority::{PendingCandidateAuthority, StagedCandidateAuthority};
#[cfg(target_os = "macos")]
use refresh::{
    SafeEjectDepartureConfirmation, SafeEjectDepartureReadbackState, SafeEjectRematchState,
    capacity_refresh_requires_confirmation, enumerate_after_storage_rematch,
    host_facts_from_mapping, initial_mapping_complete, refresh_host_facts_without_transport,
    safe_eject_rematch_state, transient_storage_rematch_error,
};
#[cfg(target_os = "macos")]
use semantic::native_operation;
use semantic::{MacOsSemanticCommand, classify};
mod open_candidate;

/// Apple task-interface response proving target processing is complete.
pub const SCSI_SERVICE_RESPONSE_TASK_COMPLETE: u8 = 2;

/// Truthful native discovery, transport, metadata, and authority inputs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MacOsReadinessFacts {
    discovery_available: bool,
    safe_transport_available: bool,
    service_metadata_present: bool,
    service_enabled: bool,
    current_process_authorized: bool,
    direct_process_authorized: bool,
}

impl MacOsReadinessFacts {
    /// Creates one pointer-free readiness snapshot.
    #[must_use]
    pub const fn new(
        discovery_available: bool,
        safe_transport_available: bool,
        service_metadata_present: bool,
        service_enabled: bool,
        current_process_authorized: bool,
    ) -> Self {
        Self {
            discovery_available,
            safe_transport_available,
            service_metadata_present,
            service_enabled,
            current_process_authorized,
            direct_process_authorized: false,
        }
    }

    /// Returns facts for a non-macOS or otherwise inactive backend.
    const fn unavailable() -> Self {
        Self::new(false, false, false, false, false)
    }
}

/// First concrete macOS readiness prerequisite that is not satisfied.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MacOsReadinessIssue {
    /// IOKit SCSI candidate discovery did not complete safely.
    IOKitDiscoveryUnavailable,
    /// The current driver stack does not vend documented user SCSI tasks.
    PlatformPassThroughUnavailable,
    /// Secure ServiceManagement helper metadata is not packaged.
    ServiceMetadataMissing,
    /// Packaged metadata exists but the helper is not enabled.
    ServiceNotEnabled,
    /// The current process is not proven to be the authorized helper.
    PrivilegedServiceUnavailable,
    /// Software prerequisites are ready; physical hardware remains unverified.
    ReadyHardwareUnverified,
}

/// Pure readiness report with a cross-field-consistent capability matrix.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MacOsReadinessReport {
    issue: MacOsReadinessIssue,
    capabilities: PlatformCapabilities,
}

/// Sanitized result of probing one exact candidate during the current scan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MacOsCandidateProbeState {
    /// Registry properties did not match the documented RDX identity hint.
    PrefilterRejected,
    /// Nonexclusive mapping and exclusive task acquisition both succeeded.
    Reachable,
    /// Mounted media or another owner prevented exclusive task authority.
    Busy,
    /// The exact service does not vend the documented safe task interface.
    TransportUnavailable,
    /// Hotplug, incomplete evidence, or another sanitized failure rejected it.
    Unavailable,
}

/// Path-free candidate-local probe evidence retained for diagnostics.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MacOsCandidateProbeOutcome {
    token: String,
    state: MacOsCandidateProbeState,
}

impl MacOsCandidateProbeOutcome {
    /// Returns the bounded opaque enumeration token.
    #[must_use]
    pub fn token(&self) -> &str {
        &self.token
    }

    /// Returns the typed candidate-local transport result.
    #[must_use]
    pub const fn state(&self) -> MacOsCandidateProbeState {
        self.state
    }
}

impl MacOsReadinessReport {
    /// Returns the concrete sanitized readiness outcome.
    #[must_use]
    pub const fn issue(self) -> MacOsReadinessIssue {
        self.issue
    }

    /// Returns the immutable platform capability matrix.
    #[must_use]
    pub const fn capabilities(self) -> PlatformCapabilities {
        self.capabilities
    }
}

/// Evaluates native facts without exposing a production activation seam.
#[must_use]
pub fn evaluate_macos_readiness(facts: MacOsReadinessFacts) -> MacOsReadinessReport {
    let issue = if !facts.discovery_available {
        MacOsReadinessIssue::IOKitDiscoveryUnavailable
    } else if !facts.safe_transport_available {
        MacOsReadinessIssue::PlatformPassThroughUnavailable
    } else if facts.direct_process_authorized {
        MacOsReadinessIssue::ReadyHardwareUnverified
    } else if !facts.service_metadata_present {
        MacOsReadinessIssue::ServiceMetadataMissing
    } else if !facts.service_enabled {
        MacOsReadinessIssue::ServiceNotEnabled
    } else if !facts.current_process_authorized {
        MacOsReadinessIssue::PrivilegedServiceUnavailable
    } else {
        MacOsReadinessIssue::ReadyHardwareUnverified
    };
    let discovery = facts.discovery_available;
    let transport = discovery && facts.safe_transport_available;
    let privileged = transport
        && (facts.direct_process_authorized
            || (facts.service_enabled && facts.current_process_authorized));
    let capabilities = PlatformCapabilities::try_new(
        discovery, transport, privileged, privileged, false, privileged, false, false,
    )
    .expect("macOS readiness mapping remains cross-field consistent");
    MacOsReadinessReport {
        issue,
        capabilities,
    }
}

/// Service-owned IOKit candidate and synchronous SCSI-task backend.
pub struct MacOsBackend {
    last_open_failure: Option<super::DiscoveryFailure>,
    backup_owner: Option<u32>,
    report: MacOsReadinessReport,
    native_active: bool,
    candidate_outcomes: Vec<MacOsCandidateProbeOutcome>,
    #[cfg(target_os = "macos")]
    staged_candidate_outcomes: Vec<MacOsCandidateProbeOutcome>,
    #[cfg(target_os = "macos")]
    pending: PendingCandidateAuthority<rdx_macos_native::MacCandidate>,
    #[cfg(target_os = "macos")]
    staged: Option<StagedCandidateAuthority<rdx_macos_native::MacCandidate>>,
}

impl MacOsBackend {
    /// Builds an active or deliberately unavailable private backend.
    fn from_readiness(facts: MacOsReadinessFacts, native_active: bool) -> Self {
        let facts = if native_active {
            facts
        } else {
            MacOsReadinessFacts::unavailable()
        };
        Self {
            last_open_failure: None,
            backup_owner: None,
            report: evaluate_macos_readiness(facts),
            native_active,
            candidate_outcomes: Vec::new(),
            #[cfg(target_os = "macos")]
            staged_candidate_outcomes: Vec::new(),
            #[cfg(target_os = "macos")]
            pending: PendingCandidateAuthority::default(),
            #[cfg(target_os = "macos")]
            staged: None,
        }
    }

    /// Probes and activates the target-gated native macOS adapter.
    #[must_use]
    pub fn native() -> Self {
        Self::native_with_context(ServiceExecutionContext::development_stdio())
    }

    /// Probes the native adapter under explicit service endpoint authority.
    #[must_use]
    pub fn native_with_context(context: ServiceExecutionContext) -> Self {
        #[cfg(target_os = "macos")]
        {
            let native = rdx_macos_native::probe_readiness();
            let mut backend = Self::from_readiness(
                context::apply(
                    MacOsReadinessFacts::new(
                        native.discovery_available(),
                        native.safe_transport_available(),
                        native.service_metadata_present(),
                        native.service_metadata_present() && context.endpoint_authenticated(),
                        context.endpoint_authenticated() && context.process_authorized(),
                    ),
                    context,
                ),
                true,
            );
            backend.backup_owner = context.backup_owner();
            backend
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = context;
            Self::from_readiness(MacOsReadinessFacts::unavailable(), false)
        }
    }

    /// Returns the concrete sanitized native prerequisite outcome.
    #[must_use]
    pub const fn readiness_issue(&self) -> MacOsReadinessIssue {
        self.report.issue
    }

    /// Returns bounded path-free outcomes from the latest successful scan.
    #[must_use]
    pub fn candidate_probe_outcomes(&self) -> &[MacOsCandidateProbeOutcome] {
        &self.candidate_outcomes
    }

    /// Records one candidate result without retaining native error text.
    #[cfg(target_os = "macos")]
    fn record_staged_candidate_outcome(&mut self, token: &str, error: Option<PlatformError>) {
        if self.staged_candidate_outcomes.len() < super::MAX_CANDIDATE_DEVICES {
            self.staged_candidate_outcomes
                .push(MacOsCandidateProbeOutcome {
                    token: token.to_owned(),
                    state: error.map_or(MacOsCandidateProbeState::Reachable, candidate_probe_state),
                });
        }
    }

    /// Records one non-mutating property-prefilter rejection.
    #[cfg(target_os = "macos")]
    fn record_staged_prefilter_rejection(&mut self, token: &str) {
        if self.staged_candidate_outcomes.len() < super::MAX_CANDIDATE_DEVICES {
            self.staged_candidate_outcomes
                .push(MacOsCandidateProbeOutcome {
                    token: token.to_owned(),
                    state: MacOsCandidateProbeState::PrefilterRejected,
                });
        }
    }
}

impl PlatformBackend for MacOsBackend {
    /// Reads the current label through DA while preserving cached protocol proof.
    fn refresh_candidate_volume_label(
        &mut self,
        candidate: &CandidateDevice,
        facts: crate::operations::HostVolumeFacts,
    ) -> Result<Option<crate::model::VolumeLabel>, PlatformError> {
        self.refresh_volume_label(candidate, facts)
    }
    fn manufacturing_backup_owner(&self) -> Option<u32> {
        self.backup_owner
    }

    /// Returns the immutable readiness-derived capability matrix.
    fn capabilities(&self) -> PlatformCapabilities {
        self.report.capabilities
    }

    /// Enumerates only bounded direct-access SCSI registry candidates.
    fn enumerate_candidates(&mut self) -> Result<Vec<CandidateDevice>, PlatformError> {
        #[cfg(target_os = "macos")]
        {
            if !self.native_active {
                return Err(PlatformError::EnumerationFailed);
            }
            self.staged = None;
            self.staged_candidate_outcomes.clear();
            let mut staged = self.pending.stage_generation()?;
            let native = enumerate_after_storage_rematch(&self.pending)?;
            let mut result = Vec::with_capacity(native.len());
            for candidate in native {
                let token = candidate.token().to_owned();
                let vendor = candidate.vendor().map(str::to_owned);
                let product = candidate.product().map(str::to_owned);
                let locator = staged.retain(&token, candidate)?;
                result.push(
                    CandidateDevice::new(
                        token,
                        locator,
                        // The native recipe retains the USB enclosure serial for
                        // exact rebind checks. RDX VPD page 0x83 reports a
                        // different identity domain, so it must remain the sole
                        // public device-serial source after SCSI validation.
                        CandidateMetadata::new(vendor, product, None, None),
                    )
                    .map_err(|_| PlatformError::EnumerationFailed)?,
                );
            }
            self.staged = Some(staged);
            Ok(result)
        }
        #[cfg(not(target_os = "macos"))]
        {
            Err(PlatformError::DiscoveryUnavailable)
        }
    }

    /// Reopens the exact candidate through the unchanged native acquisition sequence.
    fn open_candidate(
        &mut self,
        candidate: &CandidateDevice,
    ) -> Result<CandidateLease, PlatformError> {
        self.open_registry_candidate(candidate)
    }

    /// Reads only the preceding open's fixed stage; no native call or probing.
    fn last_candidate_open_failure(&self) -> Option<super::DiscoveryFailure> {
        self.last_open_failure
    }

    /// Refreshes Disk Arbitration facts without unmounting or acquiring SCSI.
    fn refresh_candidate_host_facts(
        &mut self,
        candidate: &CandidateDevice,
        previous: &CandidateDevice,
        previous_facts: Option<crate::operations::HostVolumeFacts>,
    ) -> Result<Option<crate::operations::HostVolumeFacts>, PlatformError> {
        #[cfg(target_os = "macos")]
        {
            let refreshed = {
                let current = self
                    .staged
                    .as_ref()
                    .and_then(|recipes| recipes.reopen(&candidate.locator));
                let prior = self.pending.reopen(&previous.locator);
                match (current, prior) {
                    (Some(current), Some(prior)) if current.stable_identity_matches(prior) => Some(
                        refresh_host_facts_without_transport(current, previous_facts),
                    ),
                    _ => None,
                }
            };
            let Some(refreshed) = refreshed else {
                return Ok(None);
            };
            self.record_staged_candidate_outcome(
                candidate.token(),
                refreshed.as_ref().err().copied(),
            );
            refreshed.map(Some)
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (candidate, previous, previous_facts);
            Ok(None)
        }
    }

    /// Publishes the complete private recipe generation with registry success.
    fn commit_candidate_refresh(&mut self) {
        #[cfg(target_os = "macos")]
        if let Some(staged) = self.staged.take() {
            self.pending.commit_generation(staged);
            self.candidate_outcomes = std::mem::take(&mut self.staged_candidate_outcomes);
        }
    }

    /// Preserves current recipes and diagnostics when registry replacement fails.
    fn abort_candidate_refresh(&mut self) {
        #[cfg(target_os = "macos")]
        {
            self.staged = None;
            self.staged_candidate_outcomes.clear();
        }
    }
}

#[cfg(target_os = "macos")]
struct MacOsDeviceHandle {
    _authority: Option<rdx_macos_native::MacDevice>,
    rematch_identity: rdx_macos_native::MacRematchIdentity,
    scsi: Option<rdx_macos_native::MacScsiWorkerLease>,
    cached_host_facts: Option<crate::operations::HostVolumeFacts>,
    storage_unmounted_for_format: bool,
    safe_eject_dispatched: bool,
    pending_format: Option<crate::operations::FileSystem>,
    format_passphrase: Option<crate::model::FormatPassphrase>,
    combined_format_complete: bool,
}

/// Maps one companion open/enumeration error into a stable platform failure.
#[cfg(target_os = "macos")]
fn map_native_platform_error(error: rdx_macos_native::NativeError) -> PlatformError {
    match error {
        rdx_macos_native::NativeError::TransportUnavailable => PlatformError::TransportUnavailable,
        rdx_macos_native::NativeError::AccessDenied => PlatformError::AccessDenied,
        rdx_macos_native::NativeError::Busy => PlatformError::DeviceBusy,
        rdx_macos_native::NativeError::TimedOut => PlatformError::OperationTimedOut,
        rdx_macos_native::NativeError::DeviceRemoved => PlatformError::DeviceRemoved,
        rdx_macos_native::NativeError::EnumerationFailed => PlatformError::EnumerationFailed,
        rdx_macos_native::NativeError::ResourceLimit => PlatformError::TooManyCandidates,
        rdx_macos_native::NativeError::UnsupportedPlatform
        | rdx_macos_native::NativeError::InvalidRequest
        | rdx_macos_native::NativeError::EvidenceIncomplete
        | rdx_macos_native::NativeError::Other => PlatformError::NativeBoundaryFailure,
    }
}

/// Collapses native candidate failures into stable scan diagnostics.
#[cfg(any(target_os = "macos", test))]
const fn candidate_probe_state(error: PlatformError) -> MacOsCandidateProbeState {
    match error {
        PlatformError::DeviceBusy => MacOsCandidateProbeState::Busy,
        PlatformError::TransportUnavailable => MacOsCandidateProbeState::TransportUnavailable,
        _ => MacOsCandidateProbeState::Unavailable,
    }
}

/// Maps one companion dispatch error without retaining a native code or message.
#[cfg(target_os = "macos")]
fn map_native_io_failure(error: rdx_macos_native::NativeError) -> MacOsIoFailure {
    match error {
        rdx_macos_native::NativeError::AccessDenied => MacOsIoFailure::AccessDenied,
        rdx_macos_native::NativeError::Busy => MacOsIoFailure::Busy,
        rdx_macos_native::NativeError::TimedOut => MacOsIoFailure::TimedOut,
        rdx_macos_native::NativeError::DeviceRemoved => MacOsIoFailure::DeviceRemoved,
        _ => MacOsIoFailure::Other,
    }
}

/// Sanitized failure while building a bounded macOS SCSI task.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MacOsRequestError {
    /// The CDB was empty or exceeded Apple's sixteen-byte task field.
    InvalidCdbLength,
    /// The transfer exceeded the native service's fixed response bound.
    TransferTooLarge,
}

/// Pointer-free semantic packet retained for certainty-aware validation.
pub struct MacOsScsiTask {
    command: Command,
    semantic: MacOsSemanticCommand,
    risk: RiskClass,
    transfer_length: u32,
    timeout_ms: u32,
    direction: DataDirection,
}

impl MacOsScsiTask {
    /// Returns the conservative certainty risk for this semantic command.
    #[must_use]
    pub const fn risk(&self) -> RiskClass {
        self.risk
    }

    /// Returns the bounded data-phase length.
    #[must_use]
    pub const fn transfer_length(&self) -> u32 {
        self.transfer_length
    }

    /// Returns the non-zero bounded task timeout in milliseconds.
    #[must_use]
    pub const fn timeout_ms(&self) -> u32 {
        self.timeout_ms
    }
}

impl std::fmt::Debug for MacOsScsiTask {
    /// Redacts the command, semantic identity, payload, and timeout.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("MacOsScsiTask(<private>)")
    }
}

/// Converts one immutable protocol command into a bounded semantic task packet.
///
/// # Errors
///
/// Rejects CDBs or transfer lengths outside the fixed native bridge bounds.
pub fn build_scsi_task(command: &Command) -> Result<MacOsScsiTask, MacOsRequestError> {
    if command.cdb().is_empty() || command.cdb().len() > 16 {
        return Err(MacOsRequestError::InvalidCdbLength);
    }
    if command.data().len() > MAX_TRANSPORT_RESPONSE_LENGTH {
        return Err(MacOsRequestError::TransferTooLarge);
    }
    let semantic = classify(command);
    Ok(MacOsScsiTask {
        command: command.clone(),
        semantic,
        risk: semantic.risk(),
        transfer_length: command.data().len() as u32,
        timeout_ms: command.timeout_ms(),
        direction: command.direction(),
    })
}

/// Stable native dispatch-failure classes with no native message or identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MacOsIoFailure {
    /// The current process lacks required access.
    AccessDenied,
    /// Exclusive access or current device state prevented dispatch.
    Busy,
    /// The bounded synchronous task timed out.
    TimedOut,
    /// Hotplug removed the exact open registry service.
    DeviceRemoved,
    /// Another sanitized task failure occurred.
    Other,
}

/// Pointer-free completion copied out of the native companion.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeScsiTaskCompletion {
    native_failure: Option<(bool, MacOsIoFailure)>,
    scsi_status: u8,
    service_response: u8,
    transferred_length: u32,
    data: Vec<u8>,
    sense_reported_length: usize,
    sense: Vec<u8>,
}

impl NativeScsiTaskCompletion {
    /// Creates one task completion for pure validation and conversion.
    #[must_use]
    pub fn device(
        scsi_status: u8,
        service_response: u8,
        transferred_length: u32,
        data: Vec<u8>,
        sense_reported_length: usize,
        sense: Vec<u8>,
    ) -> Self {
        Self {
            native_failure: None,
            scsi_status,
            service_response,
            transferred_length,
            data,
            sense_reported_length,
            sense,
        }
    }

    /// Creates a pre-execution failure proving no device command was sent.
    #[must_use]
    pub fn not_attempted(failure: MacOsIoFailure) -> Self {
        Self::failed(false, failure)
    }

    /// Creates an invoked-task failure with unknown device completion.
    #[must_use]
    pub fn attempted_error(failure: MacOsIoFailure) -> Self {
        Self::failed(true, failure)
    }

    /// Creates one sanitized native failure without unchecked buffers.
    fn failed(attempted: bool, failure: MacOsIoFailure) -> Self {
        Self {
            native_failure: Some((attempted, failure)),
            scsi_status: 0,
            service_response: 0,
            transferred_length: 0,
            data: Vec::new(),
            sense_reported_length: 0,
            sense: Vec::new(),
        }
    }
}

/// Sanitized structural failure while validating a native task completion.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MacOsResultError {
    /// Native failure preserving whether execution was already invoked.
    Native {
        /// Whether `ExecuteTaskSync` began.
        attempted: bool,
        /// Sanitized native failure class.
        failure: MacOsIoFailure,
    },
    /// Apple did not return `TASK_COMPLETE`.
    ServiceResponse(u8),
    /// Realized transfer exceeded the immutable request allocation.
    TransferredLengthOutOfBounds,
    /// A data-out task realized fewer bytes than the trusted payload.
    ShortDataOut,
    /// Copied data was shorter than the realized transfer count.
    ReturnedDataTooShort,
    /// Reported request sense exceeded the fixed bridge buffer.
    SenseLengthOutOfBounds,
    /// CHECK CONDITION omitted reported request-sense bytes.
    SenseTruncated,
    /// CHECK CONDITION returned malformed bounded request sense.
    MalformedSense,
    /// GOOD status unexpectedly carried request-sense bytes.
    UnexpectedSense,
    /// The device rejected the command with bounded parsed request sense.
    CheckCondition(SenseData),
    /// The device returned another non-GOOD SCSI status.
    ScsiStatus(u8),
}

/// Proven successful SCSI-task response with underrun evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParsedMacOsScsiResult {
    transferred_length: u32,
    residual_length: u32,
    data: Vec<u8>,
}

impl ParsedMacOsScsiResult {
    /// Returns the exact realized transfer count.
    #[must_use]
    pub const fn transferred_length(&self) -> u32 {
        self.transferred_length
    }

    /// Returns the untransferred portion of the request data phase.
    #[must_use]
    pub const fn residual_length(&self) -> u32 {
        self.residual_length
    }

    /// Returns only bytes proven transferred from the device.
    #[must_use]
    pub fn data(&self) -> &[u8] {
        &self.data
    }
}

/// Validates one copied native completion against its immutable task packet.
///
/// # Errors
///
/// Returns a structural, native, or SCSI-status error without unchecked bytes.
pub fn parse_scsi_task_result(
    packet: &MacOsScsiTask,
    completion: NativeScsiTaskCompletion,
) -> Result<ParsedMacOsScsiResult, MacOsResultError> {
    if let Some((attempted, failure)) = completion.native_failure {
        return Err(MacOsResultError::Native { attempted, failure });
    }
    if completion.service_response != SCSI_SERVICE_RESPONSE_TASK_COMPLETE {
        return Err(MacOsResultError::ServiceResponse(
            completion.service_response,
        ));
    }
    if completion.scsi_status == 0x02 {
        if completion.sense_reported_length > MAX_SENSE_DATA_LENGTH {
            return Err(MacOsResultError::SenseLengthOutOfBounds);
        }
        if completion.sense_reported_length == 0
            || completion.sense.len() < completion.sense_reported_length
        {
            return Err(MacOsResultError::SenseTruncated);
        }
        let sense = SenseData::parse(&completion.sense[..completion.sense_reported_length])
            .map_err(|_| MacOsResultError::MalformedSense)?;
        return Err(MacOsResultError::CheckCondition(sense));
    }
    if completion.scsi_status != 0 {
        return Err(MacOsResultError::ScsiStatus(completion.scsi_status));
    }
    if completion.sense_reported_length != 0 || !completion.sense.is_empty() {
        return Err(MacOsResultError::UnexpectedSense);
    }
    if completion.transferred_length > packet.transfer_length {
        return Err(MacOsResultError::TransferredLengthOutOfBounds);
    }
    if packet.direction == DataDirection::ToDevice
        && completion.transferred_length != packet.transfer_length
    {
        return Err(MacOsResultError::ShortDataOut);
    }
    let transferred = completion.transferred_length as usize;
    let data = if packet.direction == DataDirection::FromDevice {
        if completion.data.len() < transferred {
            return Err(MacOsResultError::ReturnedDataTooShort);
        }
        completion.data[..transferred].to_vec()
    } else {
        Vec::new()
    };
    Ok(ParsedMacOsScsiResult {
        transferred_length: completion.transferred_length,
        residual_length: packet.transfer_length - completion.transferred_length,
        data,
    })
}

/// Converts a pure task result into the Phase 2 dispatch-certainty contract.
#[must_use]
pub fn convert_scsi_task_completion(
    packet: &MacOsScsiTask,
    completion: NativeScsiTaskCompletion,
) -> CommandDispatch {
    let risk = packet.risk;
    // Preserve exact data-phase evidence before parsing consumes the completion.
    // The parser still requires native success, TASK_COMPLETE and bounded sense;
    // a signature response alone cannot prove the documented staging tail arrived.
    let complete_staging_tail = packet.semantic == MacOsSemanticCommand::FirmwareChunk
        && packet.direction == DataDirection::ToDevice
        && packet.transfer_length == 670
        && packet.command.cdb() == [0x3b, 4, 0, 0, 0xf0, 0, 0, 2, 0x9e, 0]
        && completion.transferred_length == 670
        // Deferred sense describes an earlier command, not this final data phase.
        && completion.sense.first().is_some_and(|byte| matches!(byte & 0x7f, 0x70 | 0x72));
    match parse_scsi_task_result(packet, completion) {
        Ok(result) => match TransportResponse::new(result.data().to_vec()) {
            Ok(response) => CommandDispatch::Succeeded(response),
            Err(error) => CommandDispatch::CompletionUnknown(error),
        },
        Err(MacOsResultError::CheckCondition(sense)) if risk == RiskClass::ReadOnly => {
            CommandDispatch::DefinitelyRejected(TransportError::CheckCondition(sense))
        }
        Err(MacOsResultError::CheckCondition(sense))
            if complete_staging_tail
                && (sense.raw_key(), sense.asc(), sense.ascq()) == (7, 0x74, 8) =>
        {
            CommandDispatch::CompletionUnknown(TransportError::CompatibilityStagingSignature)
        }
        Err(MacOsResultError::CheckCondition(sense)) => {
            CommandDispatch::CompletionUnknown(TransportError::CheckCondition(sense))
        }
        Err(MacOsResultError::Native {
            attempted: false,
            failure,
        }) => CommandDispatch::NotSent(transport_error_for_failure(failure)),
        Err(MacOsResultError::Native {
            attempted: true,
            failure,
        }) => CommandDispatch::CompletionUnknown(transport_error_for_failure(failure)),
        Err(MacOsResultError::ScsiStatus(_)) if risk == RiskClass::ReadOnly => {
            CommandDispatch::DefinitelyRejected(TransportError::Unavailable)
        }
        Err(MacOsResultError::ScsiStatus(_)) => {
            CommandDispatch::CompletionUnknown(TransportError::Unavailable)
        }
        Err(
            MacOsResultError::ServiceResponse(_)
            | MacOsResultError::TransferredLengthOutOfBounds
            | MacOsResultError::ShortDataOut
            | MacOsResultError::ReturnedDataTooShort
            | MacOsResultError::SenseLengthOutOfBounds
            | MacOsResultError::SenseTruncated
            | MacOsResultError::MalformedSense
            | MacOsResultError::UnexpectedSense,
        ) => CommandDispatch::CompletionUnknown(TransportError::Unavailable),
    }
}

/// Maps one sanitized native failure without changing certainty.
const fn transport_error_for_failure(failure: MacOsIoFailure) -> TransportError {
    match failure {
        MacOsIoFailure::TimedOut => TransportError::Timeout,
        MacOsIoFailure::DeviceRemoved => TransportError::DeviceRemoved,
        MacOsIoFailure::AccessDenied | MacOsIoFailure::Busy | MacOsIoFailure::Other => {
            TransportError::Unavailable
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Fully authorized software readiness exposes implemented host operations
    /// while keeping physical hardware acceptance explicitly unverified.
    #[test]
    fn ready_software_advertises_implemented_host_operations() {
        let capabilities =
            evaluate_macos_readiness(MacOsReadinessFacts::new(true, true, true, true, true))
                .capabilities();

        assert!(capabilities.safe_eject_available());
        assert!(!capabilities.force_eject_available());
        assert!(capabilities.format_available());
        assert!(capabilities.write_read_available());
        assert!(!capabilities.drive_letter_available());
        assert!(!capabilities.hardware_verified());
    }

    /// Mounted and missing-interface candidates remain distinct scan outcomes.
    #[test]
    fn per_candidate_transport_failures_remain_typed() {
        assert_eq!(
            candidate_probe_state(PlatformError::DeviceBusy),
            MacOsCandidateProbeState::Busy
        );
        assert_eq!(
            candidate_probe_state(PlatformError::TransportUnavailable),
            MacOsCandidateProbeState::TransportUnavailable
        );
        assert_eq!(
            candidate_probe_state(PlatformError::DeviceRemoved),
            MacOsCandidateProbeState::Unavailable
        );
    }

    /// A stale readiness snapshot cannot suppress a later explicit native scan.
    #[cfg(target_os = "macos")]
    #[test]
    fn dynamic_scan_is_not_gated_by_cached_discovery_readiness() {
        let mut backend = MacOsBackend::from_readiness(MacOsReadinessFacts::unavailable(), true);
        rdx_macos_native::fail_next_matching_dictionary_for_test();

        assert_eq!(
            backend
                .enumerate_candidates()
                .expect_err("the injected matcher allocation must be reached"),
            PlatformError::TooManyCandidates
        );
    }
    /// Closed stage reads are inert and every open replaces stale evidence.
    #[test]
    fn closed_open_stage_is_current_and_read_only() {
        use crate::platform::{CandidateMetadata, DiscoveryFailure};
        let mut backend = MacOsBackend::from_readiness(MacOsReadinessFacts::unavailable(), false);
        let candidate = CandidateDevice::new(
            "private-token",
            "/private/recipe",
            CandidateMetadata::new(None, None, None, None),
        )
        .unwrap();
        assert_eq!(backend.last_candidate_open_failure(), None);
        backend.last_open_failure = Some(DiscoveryFailure::Unmount);
        assert!(matches!(
            backend.open_candidate(&candidate),
            Err(PlatformError::TransportUnavailable)
        ));
        for _ in 0..2 {
            assert_eq!(
                backend.last_candidate_open_failure(),
                Some(DiscoveryFailure::RegistryOpen)
            );
            assert!(backend.candidate_probe_outcomes().is_empty());
        }
    }
}
