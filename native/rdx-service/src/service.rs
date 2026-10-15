// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Bounded version-one stdin/stdout service protocol and no-device backend.

mod continuation;
mod contract;
mod crash;
mod direct;
mod events;
mod execution_context;
#[cfg(test)]
mod fairness_tests;
mod firmware_registration;
mod framing;
mod hardware;
mod inventory;
mod lifecycle;
/// Closed manufacturing backup and restore interface.
pub mod manufacturing;
mod messages;
mod no_device_backend;
mod platform_descriptor;
mod process_security;
mod recovery_session;
mod runtime_loop;
mod session_admission;

/// Stable high-level command-line parsing, output, and exit-code policy.
pub mod cli;
/// Explicit single-attempt recovery of one receipt-bound interrupted migration.
pub mod recovery;

use continuation::ContinuePayload;
use contract::{
    action_failure, action_success, capability_reason, operation_kind, operation_target,
    parse_payload, parse_request_id, reject_prototype_keys, response, valid_method_name,
    valid_operation_id,
};
use firmware_registration::decode_firmware_chunk;
use lifecycle::{event_matches, is_cancellation_allowed, validate_event_lifecycle};
use messages::{
    CancelPayload, EmptyPayload, FirmwareRegistrationBeginPayload,
    FirmwareRegistrationChunkPayload, FirmwareRegistrationTokenPayload, InboundMessage, ScanResult,
    StartPayload, service_rejection,
};
#[cfg(test)]
use runtime_loop::drain_backend_signals;
#[cfg(test)]
use runtime_loop::{InputSignal, service_loop};
pub use runtime_loop::{run_framed_service, run_framed_service_with_context};

pub use events::{ServiceEventError, ServiceEventSink};
pub use execution_context::ServiceExecutionContext;
pub use hardware::HardwareServiceBackend;
pub use no_device_backend::NoDeviceBackend;
pub use process_security::install_process_panic_redaction;

use std::collections::VecDeque;
use std::fmt;
use std::io;
use std::time::{Duration, Instant};

use serde_json::{Value, json};

use crate::model::{
    CapabilityState, ConfirmationRequest, ConfirmationToken, DeviceId, DeviceSnapshot,
    DiscoveryRevision, MediaState, OperationEvent, OperationId, OperationKind, OperationRequest,
};
use crate::platform::{DiscoveryDiagnostics, ValidatedDiscoveryReport};

/// Current local service protocol version shared with Electron main.
pub const SERVICE_PROTOCOL_VERSION: u32 = 1;
/// Maximum UTF-8 JSON payload bytes in one framed message.
pub const MAX_SERVICE_FRAME_BYTES: usize = 65_536;
/// Maximum decoded input messages waiting for the service loop.
pub const MAX_PENDING_SERVICE_REQUESTS: usize = 64;
/// Maximum native operation events waiting to be written to stdout.
pub const MAX_PENDING_SERVICE_EVENTS: usize = 64;
/// Maximum lifecycle events per operation, including start and terminal.
pub const MAX_OPERATION_SERVICE_EVENTS: usize = crate::operations::MAX_OPERATION_EVENTS + 2;
/// Maximum wall-clock lifetime of an accepted native operation.
pub const MAX_ACTIVE_OPERATION_DURATION: Duration = Duration::from_secs(30 * 60);
/// Maximum backend lifecycle events handled before checking crash and client input.
pub const MAX_BACKEND_EVENT_BATCH: usize = 8;

const MAX_DEVICES: usize = 128;
const MAX_RECENT_OPERATION_IDS: usize = 64;
const MAX_SAFE_JSON_INTEGER: u64 = 9_007_199_254_740_991;
const EVENT_POLL_INTERVAL: Duration = Duration::from_millis(10);

/// Host platform spelling required by the JavaScript handshake schema.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServicePlatform {
    /// Node's `darwin` platform.
    Darwin,
    /// Node's `win32` platform.
    Win32,
    /// Node's `linux` platform.
    Linux,
}

impl ServicePlatform {
    /// Resolves the current supported Rust target to its Node platform spelling.
    /// # Errors
    /// Returns a sanitized protocol error on an unsupported build target.
    pub fn current() -> Result<Self, ServiceProtocolError> {
        match std::env::consts::OS {
            "macos" => Ok(Self::Darwin),
            "windows" => Ok(Self::Win32),
            "linux" => Ok(Self::Linux),
            _ => Err(ServiceProtocolError::UnsupportedPlatform),
        }
    }

    /// Returns the exact bounded handshake value.
    const fn as_str(self) -> &'static str {
        match self {
            Self::Darwin => "darwin",
            Self::Win32 => "win32",
            Self::Linux => "linux",
        }
    }
}

/// Service readiness mode accepted by the Electron handshake validator.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServiceMode {
    /// A platform adapter is available for native hardware operations.
    Native,
    /// No platform adapter or physical-device access is claimed.
    NoDevice,
}

impl ServiceMode {
    /// Returns the exact bounded handshake value.
    const fn as_str(self) -> &'static str {
        match self {
            Self::Native => "native",
            Self::NoDevice => "no-device",
        }
    }
}

/// Immutable cross-field-consistent handshake description supplied by a backend.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServiceDescriptor {
    platform: ServicePlatform,
    mode: ServiceMode,
    privileged: bool,
    service_version: String,
    capability_state: &'static str,
    capability_reason: Option<&'static str>,
    hardware_verified: bool,
}

impl ServiceDescriptor {
    /// Creates the honest Phase 2 no-device descriptor for one supported platform.
    #[must_use]
    pub fn no_device(platform: ServicePlatform) -> Self {
        Self {
            platform,
            mode: ServiceMode::NoDevice,
            privileged: false,
            service_version: env!("CARGO_PKG_VERSION").to_owned(),
            capability_state: "transport-unavailable",
            capability_reason: Some("platform-adapter-not-implemented"),
            hardware_verified: false,
        }
    }

    /// Creates a native, privileged, transport-available descriptor.
    /// # Errors
    /// Returns an error when the service version is empty, untrimmed, or over
    /// the shared 64-byte handshake bound.
    pub fn native_available(
        platform: ServicePlatform,
        service_version: impl Into<String>,
    ) -> Result<Self, ServiceProtocolError> {
        let service_version = service_version.into();
        if service_version.is_empty()
            || service_version.len() > 64
            || service_version.trim() != service_version
        {
            return Err(ServiceProtocolError::BackendContract);
        }
        Ok(Self {
            platform,
            mode: ServiceMode::Native,
            privileged: true,
            service_version,
            capability_state: "available",
            capability_reason: None,
            hardware_verified: true,
        })
    }

    /// Builds the exact strict JavaScript handshake object.
    fn handshake(&self) -> Value {
        let mut capability = serde_json::Map::new();
        capability.insert(
            "state".to_owned(),
            Value::String(self.capability_state.to_owned()),
        );
        if let Some(reason) = self.capability_reason {
            capability.insert("reason".to_owned(), Value::String(reason.to_owned()));
        }
        json!({
            "type": "handshake",
            "protocolVersion": SERVICE_PROTOCOL_VERSION,
            "serviceVersion": self.service_version,
            "platform": self.platform.as_str(),
            "mode": self.mode.as_str(),
            "privileged": self.privileged,
            "hardwareVerified": self.hardware_verified,
            "platformCapability": capability
        })
    }
}

/// Bounded backend rejection that is safe to return as a public reason code.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServiceRejection(String);

impl ServiceRejection {
    /// Creates a lower-case kebab-case reason within the shared 128-byte bound.
    ///
    /// # Errors
    ///
    /// Returns an error for an empty, oversized, or non-kebab-case reason.
    pub fn new(reason: impl Into<String>) -> Result<Self, ServiceProtocolError> {
        let reason = reason.into();
        let bytes = reason.as_bytes();
        if bytes.is_empty()
            || bytes.len() > 128
            || !bytes[0].is_ascii_lowercase()
            || !bytes
                .iter()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
        {
            return Err(ServiceProtocolError::BackendContract);
        }
        Ok(Self(reason))
    }

    /// Returns the safe public reason.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// High-level backend boundary used by the framed service protocol.
///
/// No method accepts an OS path, raw command, CDB, or unrestricted parameter.
/// Encrypted formatting alone accepts a bounded transient, redacted password.
/// Firmware bytes cross only strict bounded registration methods and grant no path authority.
pub trait ServiceBackend {
    /// Returns one immutable cross-field-consistent handshake descriptor.
    fn descriptor(&self) -> ServiceDescriptor;

    /// Captures or lists manufacturing backups on the serialized hardware owner.
    fn manufacturing_backup(
        &mut self,
        _request: manufacturing::BackupRequest,
        _capture: bool,
    ) -> Result<manufacturing::BackupInventory, ServiceRejection> {
        Err(service_rejection("manufacturing-unavailable"))
    }

    /// Restores an explicitly selected original record, with pre-backup and exact readback.
    fn manufacturing_restore(
        &mut self,
        _request: manufacturing::RestoreRequest,
    ) -> Result<manufacturing::BackupInventory, ServiceRejection> {
        Err(service_rejection("manufacturing-unavailable"))
    }

    /// Proves that no prepared, queued, or completing native operation retains hardware.
    /// Backends without that independent proof cannot admit service recovery.
    fn require_recovery_idle(&mut self) -> Result<(), ServiceRejection> {
        Err(service_rejection("recovery-backend-unavailable"))
    }

    /// Returns the current strict renderer-safe discovery list.
    fn list_devices(&mut self) -> Result<Vec<DeviceSnapshot>, ServiceRejection>;

    /// Commits an operation's already validated public inventory in the service loop.
    /// Workers may retain private reconnect observations until this publication
    /// boundary. This callback performs no discovery or hardware commands.
    fn commit_operation_inventory(
        &mut self,
        _devices: &[DeviceSnapshot],
    ) -> Result<(), ServiceRejection> {
        Ok(())
    }

    /// Performs one non-overlapping discovery refresh and returns its full list.
    fn scan_devices(&mut self) -> Result<Vec<DeviceSnapshot>, ServiceRejection>;

    /// Performs one refresh and returns path-free candidate diagnostics when available.
    fn scan_report(&mut self) -> Result<ValidatedDiscoveryReport, ServiceRejection> {
        self.scan_devices()
            .map(ValidatedDiscoveryReport::all_accepted)
    }

    /// Issues one short-lived service-owned confirmation for an exact destructive action.
    ///
    /// The default rejects adapters that do not own current media evidence.
    fn issue_confirmation(
        &mut self,
        _request: ConfirmationRequest,
    ) -> Result<ConfirmationToken, ServiceRejection> {
        Err(service_rejection("confirmation-unavailable"))
    }

    /// Begins one bounded path-free modern firmware registration.
    fn begin_firmware_registration(
        &mut self,
        _file_token: crate::model::FirmwareFileToken,
        _extension: String,
        _total_bytes: usize,
        _open_rdx: Option<crate::firmware::OpenRdxImageMetadata>,
    ) -> Result<(), ServiceRejection> {
        Err(service_rejection("firmware-registration-unavailable"))
    }

    /// Appends one exact ordered decoded firmware chunk.
    fn append_firmware_registration(
        &mut self,
        _file_token: crate::model::FirmwareFileToken,
        _offset: usize,
        _bytes: Vec<u8>,
    ) -> Result<(), ServiceRejection> {
        Err(service_rejection("firmware-registration-unavailable"))
    }

    /// Validates and commits one complete one-shot firmware image.
    fn commit_firmware_registration(
        &mut self,
        _file_token: crate::model::FirmwareFileToken,
    ) -> Result<(), ServiceRejection> {
        Err(service_rejection("firmware-registration-unavailable"))
    }

    /// Drops one partial or committed registration after error or caller abort.
    fn abort_firmware_registration(
        &mut self,
        _file_token: &crate::model::FirmwareFileToken,
    ) -> Result<(), ServiceRejection> {
        Ok(())
    }

    /// Starts one exact revisioned high-level operation and retains its event sink.
    ///
    /// Asynchronous eject adapters must publish `started` and the first native
    /// progress event before returning, publish every later progress event from
    /// [`crate::operations::run_eject_with_progress`] as it is produced, and
    /// never replay retained report events after a cancellation acknowledgement.
    /// The acknowledgement snapshots a sink-owned FIFO cutover: publications
    /// already admitted through that sequence retain their pre-request state,
    /// while any later progress publication must carry `requested`.
    fn start_operation(
        &mut self,
        operation_id: OperationId,
        request: OperationRequest,
        events: ServiceEventSink,
    ) -> Result<(), ServiceRejection>;

    /// Releases one successfully prepared operation after its acceptance frame is flushed.
    ///
    /// Synchronous and legacy adapters may use the default because they already
    /// dispatch inside [`Self::start_operation`]. Production host adapters use
    /// this boundary to make client-visible acceptance causally precede native
    /// mutation dispatch.
    fn release_operation(&mut self, _operation_id: &OperationId) -> Result<(), ServiceRejection> {
        Ok(())
    }

    /// Requests cancellation only for the exact active operation identifier.
    fn cancel_operation(&mut self, operation_id: &OperationId) -> Result<(), ServiceRejection>;

    /// Acknowledges one exact firmware power-cycle stage through a direct control path.
    /// Implementations must reject unarmed, repeated, foreign-owner or wrong-stage requests.
    fn continue_operation(
        &mut self,
        _operation_id: &OperationId,
        _stage: &str,
    ) -> Result<(), ServiceRejection> {
        Err(service_rejection("operation-not-continuable"))
    }

    /// Performs backend-owned graceful cleanup before protocol shutdown.
    fn shutdown(&mut self) -> Result<(), ServiceRejection>;
}

/// Clean reason the framed service loop stopped.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServiceExit {
    /// The owning process closed stdin between complete frames.
    EndOfInput,
    /// A strict shutdown request completed while no operation was active.
    ShutdownRequested,
}

/// Sanitized protocol/runtime failure suitable for bounded stderr diagnostics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServiceProtocolError {
    /// An input or output stream failed.
    Io,
    /// A frame declared zero or more than the maximum payload size.
    InvalidFrameLength,
    /// A frame was truncated, invalid JSON, or not a JSON object.
    MalformedFrame,
    /// A strict version, field, identifier, ordering, or lifecycle rule failed.
    ProtocolViolation,
    /// A backend returned internally contradictory renderer-safe state.
    BackendContract,
    /// The current Rust build target has no published platform spelling.
    UnsupportedPlatform,
}

impl fmt::Display for ServiceProtocolError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Io => "service I/O failure",
            Self::InvalidFrameLength => "invalid service frame length",
            Self::MalformedFrame => "malformed service frame",
            Self::ProtocolViolation => "service protocol violation",
            Self::BackendContract => "service backend contract failure",
            Self::UnsupportedPlatform => "unsupported service platform",
        })
    }
}

impl std::error::Error for ServiceProtocolError {}

impl From<io::Error> for ServiceProtocolError {
    fn from(_error: io::Error) -> Self {
        Self::Io
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OperationPhase {
    Accepted,
    Running,
}

#[derive(Debug)]
struct ActiveOperation {
    operation_id: OperationId,
    kind: OperationKind,
    device_id: DeviceId,
    device_revision: DiscoveryRevision,
    phase: OperationPhase,
    operation_released: bool,
    stage: String,
    stage_index: isize,
    progress: f64,
    attempt: u8,
    cancellation_requested: bool,
    cancellation_cutover_sequence: Option<u64>,
    cancellation_closed: bool,
    cancellation_stage: Option<String>,
    continued_stages: u8,
    recovery_required: bool,
    event_count: usize,
    deadline: Instant,
}

impl ActiveOperation {
    /// Creates a service reservation at the shared queued boundary.
    fn new(
        operation_id: OperationId,
        request: &OperationRequest,
    ) -> Result<Self, ServiceProtocolError> {
        Self::new_at(operation_id, request, Instant::now())
    }

    /// Creates a reservation against an explicit monotonic instant for deterministic tests.
    fn new_at(
        operation_id: OperationId,
        request: &OperationRequest,
        started_at: Instant,
    ) -> Result<Self, ServiceProtocolError> {
        let kind = operation_kind(request);
        let Some((device_id, device_revision)) = operation_target(request) else {
            return Err(ServiceProtocolError::ProtocolViolation);
        };
        Ok(Self {
            operation_id,
            kind,
            device_id: device_id.clone(),
            device_revision,
            phase: OperationPhase::Accepted,
            operation_released: false,
            stage: "queued".to_owned(),
            stage_index: -1,
            progress: 0.0,
            attempt: 0,
            cancellation_requested: false,
            cancellation_cutover_sequence: None,
            cancellation_closed: !is_cancellation_allowed(kind, "queued"),
            cancellation_stage: None,
            continued_stages: 0,
            recovery_required: false,
            event_count: 0,
            deadline: started_at
                .checked_add(MAX_ACTIVE_OPERATION_DURATION)
                .ok_or(ServiceProtocolError::BackendContract)?,
        })
    }

    /// Rejects a service generation once either deterministic lifetime bound is exhausted.
    fn admit_event(&mut self, now: Instant) -> Result<(), ServiceProtocolError> {
        if now >= self.deadline || self.event_count >= MAX_OPERATION_SERVICE_EVENTS {
            return Err(ServiceProtocolError::BackendContract);
        }
        self.event_count += 1;
        Ok(())
    }

    /// Checks the absolute operation deadline independently of event arrival.
    fn check_deadline(&self, now: Instant) -> Result<(), ServiceProtocolError> {
        if now >= self.deadline {
            Err(ServiceProtocolError::BackendContract)
        } else {
            Ok(())
        }
    }
}

struct ServiceRuntime<B> {
    backup_owner: Option<u32>,
    backend: B,
    descriptor: ServiceDescriptor,
    devices: Vec<DeviceSnapshot>,
    discovery_diagnostics: DiscoveryDiagnostics,
    inventory_initialized: bool,
    list_revision: u64,
    handshaken: bool,
    last_request_id: u64,
    active: Option<ActiveOperation>,
    recent_operation_ids: VecDeque<String>,
    event_sink: ServiceEventSink,
    recovery: recovery_session::RecoverySession,
}

impl<B: ServiceBackend> ServiceRuntime<B> {
    /// Creates one empty generation around its backend and bounded event sink.
    fn new(backend: B, event_sink: ServiceEventSink) -> Self {
        Self::new_with_context(
            backend,
            event_sink,
            ServiceExecutionContext::development_stdio(),
        )
    }

    /// Keeps recovery startup authority separate from backend-reported descriptors.
    fn new_with_context(
        backend: B,
        event_sink: ServiceEventSink,
        context: ServiceExecutionContext,
    ) -> Self {
        let descriptor = backend.descriptor();
        Self {
            backup_owner: context.backup_owner(),
            backend,
            descriptor,
            devices: Vec::new(),
            discovery_diagnostics: DiscoveryDiagnostics::accepted(0),
            inventory_initialized: false,
            list_revision: 0,
            handshaken: false,
            last_request_id: 0,
            active: None,
            recent_operation_ids: VecDeque::new(),
            event_sink,
            recovery: recovery_session::RecoverySession::native(context),
        }
    }

    /// Handles one strict input object and returns immediate output plus stop state.
    fn handle_message(&mut self, value: Value) -> Result<(Vec<Value>, bool), ServiceProtocolError> {
        reject_prototype_keys(&value)?;
        if !value.is_object() {
            return Err(ServiceProtocolError::MalformedFrame);
        }
        let message: InboundMessage =
            serde_json::from_value(value).map_err(|_| ServiceProtocolError::MalformedFrame)?;
        match message {
            InboundMessage::Handshake { protocol_version } => {
                if self.handshaken || protocol_version != SERVICE_PROTOCOL_VERSION {
                    return Err(ServiceProtocolError::ProtocolViolation);
                }
                self.handshaken = true;
                Ok((vec![self.descriptor.handshake()], false))
            }
            InboundMessage::Request {
                protocol_version,
                request_id,
                method,
                payload,
            } => {
                if !self.handshaken || protocol_version != SERVICE_PROTOCOL_VERSION {
                    return Err(ServiceProtocolError::ProtocolViolation);
                }
                let numeric_request_id = parse_request_id(&request_id)?;
                if numeric_request_id <= self.last_request_id {
                    return Err(ServiceProtocolError::ProtocolViolation);
                }
                self.last_request_id = numeric_request_id;
                self.handle_request(request_id, &method, payload)
            }
        }
    }

    /// Routes one post-handshake request through its strict method payload.
    fn handle_request(
        &mut self,
        request_id: String,
        method: &str,
        payload: Value,
    ) -> Result<(Vec<Value>, bool), ServiceProtocolError> {
        if recovery_session::is_recovery_method(method) {
            let result = self.handle_recovery_request(method, payload)?;
            return Ok((vec![response(&request_id, result)], false));
        }
        if self.recovery.is_active() {
            if !valid_method_name(method) {
                return Err(ServiceProtocolError::ProtocolViolation);
            }
            return Ok((
                vec![response(
                    &request_id,
                    action_failure("recovery-in-progress"),
                )],
                false,
            ));
        }
        match method {
            "manufacturing-prepare-folder" => {
                parse_payload::<EmptyPayload>(payload)?;
                Ok((
                    vec![response(&request_id, self.prepare_manufacturing_folder())],
                    false,
                ))
            }
            "manufacturing-list" | "manufacturing-backup" | "manufacturing-restore" => {
                let result = self.handle_manufacturing_request(method, payload)?;
                Ok((vec![response(&request_id, result)], false))
            }
            "devices-list" => {
                parse_payload::<EmptyPayload>(payload)?;
                let result = self.list_devices()?;
                Ok((vec![response(&request_id, result)], false))
            }
            "devices-scan" => {
                let request = parse_payload::<OperationRequest>(payload)?;
                if request != OperationRequest::Scan {
                    return Err(ServiceProtocolError::ProtocolViolation);
                }
                let result = self.scan_devices()?;
                let mut messages = Vec::new();
                if let Some(event) = result.event {
                    messages.push(event);
                }
                messages.push(response(&request_id, result.result));
                Ok((messages, false))
            }
            "operation-start" => {
                let payload = parse_payload::<StartPayload>(payload)?;
                let result = self.start_operation(payload.operation_id, payload.request)?;
                Ok((vec![response(&request_id, result)], false))
            }
            "operation-confirmation-issue" => {
                let request = parse_payload::<ConfirmationRequest>(payload)?;
                let result = match self.backend.issue_confirmation(request) {
                    Ok(token) => json!({"ok": true, "confirmationToken": token}),
                    Err(error) => action_failure(error.as_str()),
                };
                Ok((vec![response(&request_id, result)], false))
            }
            "firmware-registration-begin" => {
                let payload = parse_payload::<FirmwareRegistrationBeginPayload>(payload)?;
                let total_bytes = usize::try_from(payload.total_bytes)
                    .map_err(|_| ServiceProtocolError::ProtocolViolation)?;
                let result = match self.backend.begin_firmware_registration(
                    payload.file_token,
                    payload.extension,
                    total_bytes,
                    payload.open_rdx,
                ) {
                    Ok(()) => action_success(),
                    Err(error) => action_failure(error.as_str()),
                };
                Ok((vec![response(&request_id, result)], false))
            }
            "firmware-registration-chunk" => {
                let payload = parse_payload::<FirmwareRegistrationChunkPayload>(payload)?;
                let offset = usize::try_from(payload.offset)
                    .map_err(|_| ServiceProtocolError::ProtocolViolation)?;
                let decoded = decode_firmware_chunk(&payload.bytes_base64);
                let result = match decoded {
                    Ok(bytes) => self.backend.append_firmware_registration(
                        payload.file_token.clone(),
                        offset,
                        bytes,
                    ),
                    Err(error) => {
                        let _ = self
                            .backend
                            .abort_firmware_registration(&payload.file_token);
                        Err(error)
                    }
                };
                let result = match result {
                    Ok(()) => action_success(),
                    Err(error) => action_failure(error.as_str()),
                };
                Ok((vec![response(&request_id, result)], false))
            }
            "firmware-registration-commit" => {
                let payload = parse_payload::<FirmwareRegistrationTokenPayload>(payload)?;
                let result = match self
                    .backend
                    .commit_firmware_registration(payload.file_token)
                {
                    Ok(()) => action_success(),
                    Err(error) => action_failure(error.as_str()),
                };
                Ok((vec![response(&request_id, result)], false))
            }
            "firmware-registration-abort" => {
                let payload = parse_payload::<FirmwareRegistrationTokenPayload>(payload)?;
                let result = match self
                    .backend
                    .abort_firmware_registration(&payload.file_token)
                {
                    Ok(()) => action_success(),
                    Err(error) => action_failure(error.as_str()),
                };
                Ok((vec![response(&request_id, result)], false))
            }
            "operation-cancel" => {
                let payload = parse_payload::<CancelPayload>(payload)?;
                let result = self.cancel_operation(payload.operation_id)?;
                Ok((vec![response(&request_id, result)], false))
            }
            "operation-continue" => {
                let payload = parse_payload::<ContinuePayload>(payload)?;
                let result = self.continue_operation(payload.operation_id, payload.stage)?;
                Ok((vec![response(&request_id, result)], false))
            }
            "service-shutdown" => {
                parse_payload::<EmptyPayload>(payload)?;
                if self.active.is_some() {
                    return Ok((
                        vec![response(
                            &request_id,
                            action_failure("operation-in-progress"),
                        )],
                        false,
                    ));
                }
                match self.backend.shutdown() {
                    Ok(()) => Ok((vec![response(&request_id, action_success())], true)),
                    Err(error) => Ok((
                        vec![response(&request_id, action_failure(error.as_str()))],
                        false,
                    )),
                }
            }
            _ if valid_method_name(method) => Ok((
                vec![response(&request_id, action_failure("unsupported-request"))],
                false,
            )),
            _ => Err(ServiceProtocolError::ProtocolViolation),
        }
    }

    /// Repeats service-owned identity, revision, capability, and concurrency checks.
    fn start_operation(
        &mut self,
        operation_id: OperationId,
        request: OperationRequest,
    ) -> Result<Value, ServiceProtocolError> {
        match self.admit_operation(operation_id, request)? {
            OperationAdmission::Accepted => Ok(action_success()),
            OperationAdmission::Rejected(error) => Ok(action_failure(error.as_str())),
        }
    }

    /// Applies the shared typed operation admission gates without wire serialization.
    fn admit_operation(
        &mut self,
        operation_id: OperationId,
        request: OperationRequest,
    ) -> Result<OperationAdmission, ServiceProtocolError> {
        if !valid_operation_id(&operation_id) {
            return Err(ServiceProtocolError::ProtocolViolation);
        }
        let kind = operation_kind(&request);
        if kind == OperationKind::Scan {
            return Err(ServiceProtocolError::ProtocolViolation);
        }
        if self.descriptor.mode == ServiceMode::NoDevice {
            return Ok(OperationAdmission::Rejected(service_rejection(
                "transport-unavailable",
            )));
        }
        if !self.descriptor.privileged && kind != OperationKind::StatusRefresh {
            return Ok(OperationAdmission::Rejected(service_rejection(
                "privileged-service-unavailable",
            )));
        }
        if self.active.is_some() {
            return Ok(OperationAdmission::Rejected(service_rejection(
                "operation-in-progress",
            )));
        }
        if self
            .recent_operation_ids
            .iter()
            .any(|seen| seen == operation_id.as_str())
        {
            return Ok(OperationAdmission::Rejected(service_rejection(
                "stale-operation-id",
            )));
        }
        let Some((device_id, device_revision)) = operation_target(&request) else {
            return Err(ServiceProtocolError::ProtocolViolation);
        };
        let Some(device) = self.devices.iter().find(|device| &device.id == device_id) else {
            return Ok(OperationAdmission::Rejected(service_rejection(
                "device-not-found",
            )));
        };
        if device.revision != device_revision {
            return Ok(OperationAdmission::Rejected(service_rejection(
                "stale-device-revision",
            )));
        }
        if matches!(kind, OperationKind::EjectSafe | OperationKind::EjectForce)
            && device.media_state != MediaState::Present
        {
            return Ok(OperationAdmission::Rejected(service_rejection(
                "wrong-media-state",
            )));
        }
        let Some(capability) = device.capabilities.get(&kind) else {
            return Ok(OperationAdmission::Rejected(service_rejection(
                "unsupported-operation",
            )));
        };
        if capability.state != CapabilityState::Available {
            return Ok(OperationAdmission::Rejected(service_rejection(
                capability.reason.as_ref().map_or_else(
                    || capability_reason(capability.state),
                    |reason| reason.as_str(),
                ),
            )));
        }

        self.active = Some(ActiveOperation::new(operation_id.clone(), &request)?);
        match self
            .backend
            .start_operation(operation_id.clone(), request, self.event_sink.clone())
        {
            Ok(()) => {
                if self.recent_operation_ids.len() == MAX_RECENT_OPERATION_IDS {
                    self.recent_operation_ids.pop_front();
                }
                self.recent_operation_ids
                    .push_back(operation_id.as_str().to_owned());
                Ok(OperationAdmission::Accepted)
            }
            Err(error) => {
                self.active = None;
                Ok(OperationAdmission::Rejected(error))
            }
        }
    }

    /// Requests cancellation only while the exact active lifecycle permits it.
    fn cancel_operation(
        &mut self,
        operation_id: OperationId,
    ) -> Result<Value, ServiceProtocolError> {
        if !valid_operation_id(&operation_id) {
            return Err(ServiceProtocolError::ProtocolViolation);
        }
        if self.descriptor.mode == ServiceMode::NoDevice {
            return Ok(action_failure("transport-unavailable"));
        }
        let Some(active) = self.active.as_mut() else {
            return Ok(action_failure("operation-not-found"));
        };
        if active.operation_id != operation_id {
            return Ok(action_failure("operation-not-found"));
        }
        if active.cancellation_requested
            || active.cancellation_closed
            || !is_cancellation_allowed(active.kind, &active.stage)
        {
            return Ok(action_failure("operation-not-cancellable"));
        }
        match self.backend.cancel_operation(&operation_id) {
            Ok(()) => {
                let cutover = self
                    .event_sink
                    .cancellation_cutover()
                    .map_err(|_| ServiceProtocolError::BackendContract)?;
                active.cancellation_requested = true;
                active.cancellation_cutover_sequence = Some(cutover);
                active.cancellation_stage = Some(active.stage.clone());
                Ok(json!({
                    "ok": true,
                    "cancellationCutover": cutover
                }))
            }
            Err(error) => Ok(action_failure(error.as_str())),
        }
    }

    /// Releases one prepared backend job exactly once after its response flush.
    fn release_prepared_operation(&mut self) -> Result<(), ServiceProtocolError> {
        let Some(active) = self.active.as_mut() else {
            return Ok(());
        };
        if active.operation_released {
            return Ok(());
        }
        self.backend
            .release_operation(&active.operation_id)
            .map_err(|_| ServiceProtocolError::BackendContract)?;
        active.operation_released = true;
        Ok(())
    }

    /// Validates one exact-owner backend event and returns its wire envelope.
    #[cfg(test)]
    fn handle_event(&mut self, event: OperationEvent) -> Result<Value, ServiceProtocolError> {
        self.handle_event_at(event, Instant::now())
    }

    /// Validates one event at an explicit monotonic instant for deterministic deadline tests.
    #[cfg(test)]
    fn handle_event_at(
        &mut self,
        event: OperationEvent,
        now: Instant,
    ) -> Result<Value, ServiceProtocolError> {
        self.handle_event_at_publication(event, None, now)
    }

    /// Validates one event with its private FIFO publication sequence.
    fn handle_event_at_publication(
        &mut self,
        event: OperationEvent,
        publication_sequence: Option<u64>,
        now: Instant,
    ) -> Result<Value, ServiceProtocolError> {
        let Some(active) = self.active.as_mut() else {
            return Err(ServiceProtocolError::BackendContract);
        };
        active.admit_event(now)?;
        if !event_matches(active, &event) {
            return Err(ServiceProtocolError::BackendContract);
        }
        let pre_request_grace = active.cancellation_requested
            && active
                .cancellation_cutover_sequence
                .zip(publication_sequence)
                .is_some_and(|(cutover, sequence)| sequence <= cutover);
        let terminal = validate_event_lifecycle(active, &event, pre_request_grace)?;
        let event =
            serde_json::to_value(event).map_err(|_| ServiceProtocolError::BackendContract)?;
        if terminal {
            self.active = None;
        }
        let mut envelope = json!({"type": "event", "channel": "operation", "event": event});
        if let Some(sequence) = publication_sequence {
            envelope
                .as_object_mut()
                .expect("trusted operation envelope is an object")
                .insert("publicationSequence".to_owned(), Value::from(sequence));
        }
        Ok(envelope)
    }
}

/// Typed result of applying the shared operation admission boundary.
enum OperationAdmission {
    Accepted,
    Rejected(ServiceRejection),
}
