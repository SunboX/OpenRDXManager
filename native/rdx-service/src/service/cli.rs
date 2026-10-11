// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Stable high-level `rdxctl` parsing, output, and exit-code policy.

use std::ffi::OsString;
use std::io::Write;
use std::time::Duration;

use serde::Serialize;

use crate::host::HostOperationError;
use crate::model::{DeviceId, DeviceSnapshot};
use crate::operations::{HostEjectPolicy, OperationFailure, OperationIssue, OperationStage};
use crate::transport::{DispatchCertainty, TransportError};

use super::direct::{
    DirectFailure, DirectOwnership, DirectService, acquire_direct_ownership,
    current_hardware_backend,
};
use super::{MAX_SERVICE_FRAME_BYTES, ServiceBackend, ServiceProtocolError, ServiceRejection};

const HELP: &str = "rdxctl - high-level OpenRDXManager device control\n\nUSAGE:\n  rdxctl --help\n  rdxctl --version\n  rdxctl --scan\n  rdxctl --eject <opaque-target> [--force]\n\nOPTIONS:\n  --help      Show this help without accessing hardware.\n  --version   Show the package version without accessing hardware.\n  --scan      Scan through the native service backend.\n  --eject     Eject one bounded opaque rdx: target.\n  --force     Change host eject policy and warn about cached-data risk.\n";
const FORCE_WARNING: &str = "{\"code\":\"cached-data-risk\",\"level\":\"warning\",\"message\":\"forced eject can lose cached data\"}\n";
const PRODUCTION_EVENT_TIMEOUT: Duration = Duration::from_secs(30);

/// Stable process outcomes documented for automation clients.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum CliExit {
    /// The requested informational or high-level operation completed.
    Success = 0,
    /// Arguments did not identify exactly one supported command.
    Usage = 2,
    /// The local service, host transport, or output channel failed.
    ServiceHost = 3,
    /// A terminal SCSI rejection was proven definitive.
    Device = 4,
    /// A prerequisite or capability gate rejected the operation.
    Prerequisite = 5,
    /// Completion was partial or cannot be established safely.
    PartialOrAmbiguous = 6,
}

impl CliExit {
    /// Returns the exact process status as an `i32` for test and process APIs.
    #[must_use]
    pub const fn code(self) -> i32 {
        self as i32
    }

    /// Returns the exact process status accepted by [`std::process::ExitCode`].
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ActionTag {
    Help,
    Version,
    Scan,
    Eject,
}

#[derive(Debug)]
enum CliCommand {
    Help,
    Version,
    Scan,
    Eject { target: DeviceId, force: bool },
}

impl CliCommand {
    /// Returns the command's mutually exclusive parser tag.
    fn tag(&self) -> ActionTag {
        match self {
            Self::Help => ActionTag::Help,
            Self::Version => ActionTag::Version,
            Self::Scan => ActionTag::Scan,
            Self::Eject { .. } => ActionTag::Eject,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum UsageError {
    NoCommand,
    DuplicateOption,
    MutuallyExclusive,
    ForceRequiresEject,
    MissingEjectTarget,
    InvalidTarget,
    UnexpectedPositional,
    UnknownOption,
}

impl UsageError {
    /// Returns one fixed target-free diagnostic message.
    fn message(self) -> &'static str {
        match self {
            Self::NoCommand => "exactly one command is required",
            Self::DuplicateOption => "duplicate options are not allowed",
            Self::MutuallyExclusive => "commands are mutually exclusive",
            Self::ForceRequiresEject => "--force requires --eject",
            Self::MissingEjectTarget => "--eject requires one opaque target",
            Self::InvalidTarget => "eject target must be a bounded opaque rdx: identifier",
            Self::UnexpectedPositional => "unexpected positional argument",
            Self::UnknownOption => "unknown or combined option",
        }
    }
}

#[derive(Debug)]
struct CliFailure {
    exit: CliExit,
    code: String,
    reason: Option<String>,
}

impl CliFailure {
    /// Creates one fixed path-free CLI failure after typed classification.
    fn new(exit: CliExit, code: impl Into<String>, reason: Option<impl Into<String>>) -> Self {
        Self {
            exit,
            code: code.into(),
            reason: reason.map(Into::into),
        }
    }

    /// Converts a pre-dispatch service rejection without ever defaulting to exit 4.
    fn from_rejection(rejection: ServiceRejection) -> Self {
        let code = rejection.as_str().to_owned();
        let exit = match code.as_str() {
            "service-unavailable" | "service-protocol-failure" | "host-transport-failure" => {
                CliExit::ServiceHost
            }
            "authentication-required"
            | "busy"
            | "device-not-found"
            | "evidence-incomplete"
            | "exclusive-ownership-unavailable"
            | "hardware-unverified"
            | "host-dependency-missing"
            | "insufficient-permission"
            | "operation-in-progress"
            | "stale-device-revision"
            | "stale-operation-id"
            | "transport-unavailable"
            | "unsupported-operation"
            | "unsupported-platform"
            | "unsupported-product"
            | "wrong-media-state" => CliExit::Prerequisite,
            _ => CliExit::ServiceHost,
        };
        Self::new(exit, code, None::<String>)
    }

    /// Converts an exact typed direct-runtime outcome into a stable CLI failure.
    fn from_direct(failure: DirectFailure) -> Self {
        match failure {
            DirectFailure::Capability { code, reason } => {
                Self::new(CliExit::Prerequisite, code, reason)
            }
            DirectFailure::Rejected(rejection) => Self::from_rejection(rejection),
            DirectFailure::Service(error) => Self::new(
                CliExit::ServiceHost,
                match error {
                    ServiceProtocolError::UnsupportedPlatform => "unsupported-host-platform",
                    _ => "service-runtime-failure",
                },
                None::<String>,
            ),
            DirectFailure::Operation { error, failure } => Self::new(
                operation_failure_exit(failure.as_ref()),
                error.code.as_str(),
                None::<String>,
            ),
            DirectFailure::HostOperation { error, failure } => Self::new(
                if failure.certainty() == crate::operations::MutationCertainty::CompletionUnknown {
                    CliExit::PartialOrAmbiguous
                } else {
                    CliExit::Prerequisite
                },
                error.code.as_str(),
                None::<String>,
            ),
            DirectFailure::Ambiguous(code) => {
                Self::new(CliExit::PartialOrAmbiguous, code, None::<String>)
            }
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ScanOutput<'a> {
    command: &'static str,
    devices: &'a [DeviceSnapshot],
    hardware_verified: bool,
    status: &'static str,
}

#[derive(Serialize)]
struct ErrorOutput<'a> {
    code: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<&'a str>,
    status: &'static str,
}

#[derive(Serialize)]
struct UsageOutput<'a> {
    code: &'static str,
    message: &'a str,
    status: &'static str,
}

/// Runs `rdxctl` against the production high-level backend and bounded writers.
///
/// Argument parsing completes before backend creation, so `--help`, `--version`,
/// and every usage error avoid native discovery or device access.
pub fn run<I, S, W, E>(arguments: I, stdout: &mut W, stderr: &mut E) -> CliExit
where
    I: IntoIterator<Item = S>,
    S: Into<OsString>,
    W: Write,
    E: Write,
{
    run_with_factory(
        arguments,
        stdout,
        stderr,
        current_hardware_backend,
        DirectOwnership::ProcessGlobal,
        PRODUCTION_EVENT_TIMEOUT,
    )
}

/// Parses the complete argument vector without accepting implicit combinations.
fn parse_arguments<I, S>(arguments: I) -> Result<CliCommand, UsageError>
where
    I: IntoIterator<Item = S>,
    S: Into<OsString>,
{
    let mut arguments = arguments.into_iter().map(Into::into);
    let mut command: Option<CliCommand> = None;
    let mut force = false;
    let mut force_seen = false;

    while let Some(argument) = arguments.next() {
        let Some(argument) = argument.to_str() else {
            return Err(UsageError::UnknownOption);
        };
        let candidate = match argument {
            "--help" => Some(CliCommand::Help),
            "--version" => Some(CliCommand::Version),
            "--scan" => Some(CliCommand::Scan),
            "--force" => {
                if force_seen {
                    return Err(UsageError::DuplicateOption);
                }
                force_seen = true;
                force = true;
                None
            }
            "--eject" => {
                if command
                    .as_ref()
                    .is_some_and(|value| value.tag() == ActionTag::Eject)
                {
                    return Err(UsageError::DuplicateOption);
                }
                let Some(target) = arguments.next() else {
                    return Err(UsageError::MissingEjectTarget);
                };
                let target = target.to_str().ok_or(UsageError::InvalidTarget)?;
                let target = DeviceId::new(target).map_err(|_| UsageError::InvalidTarget)?;
                Some(CliCommand::Eject {
                    target,
                    force: false,
                })
            }
            value if value.starts_with('-') => return Err(UsageError::UnknownOption),
            _ => return Err(UsageError::UnexpectedPositional),
        };

        if let Some(candidate) = candidate {
            if let Some(existing) = &command {
                return Err(if existing.tag() == candidate.tag() {
                    UsageError::DuplicateOption
                } else {
                    UsageError::MutuallyExclusive
                });
            }
            command = Some(candidate);
        }
    }

    if force && !matches!(command, Some(CliCommand::Eject { .. })) {
        return Err(UsageError::ForceRequiresEject);
    }
    match command {
        Some(CliCommand::Eject { target, .. }) => Ok(CliCommand::Eject { target, force }),
        Some(command) => Ok(command),
        None => Err(UsageError::NoCommand),
    }
}

/// Runs one parsed command and defers backend creation until an operation needs it.
fn run_with_factory<I, S, W, E, B, F>(
    arguments: I,
    stdout: &mut W,
    stderr: &mut E,
    create_backend: F,
    ownership: DirectOwnership,
    event_timeout: Duration,
) -> CliExit
where
    I: IntoIterator<Item = S>,
    S: Into<OsString>,
    W: Write,
    E: Write,
    B: ServiceBackend,
    F: FnOnce() -> Result<B, ServiceProtocolError>,
{
    let command = match parse_arguments(arguments) {
        Ok(command) => command,
        Err(error) => return write_usage(stderr, error),
    };
    match command {
        CliCommand::Help => write_text(stdout, HELP),
        CliCommand::Version => {
            write_text(stdout, concat!("rdxctl ", env!("CARGO_PKG_VERSION"), "\n"))
        }
        CliCommand::Scan => {
            let backend = match create_backend() {
                Ok(backend) => backend,
                Err(error) => {
                    return write_cli_failure(
                        stderr,
                        CliFailure::from_direct(DirectFailure::Service(error)),
                    );
                }
            };
            run_scan(DirectService::new(backend), stdout, stderr)
        }
        CliCommand::Eject { target, force } => {
            if force && write_text(stderr, FORCE_WARNING) != CliExit::Success {
                return CliExit::ServiceHost;
            }
            let _ownership = match acquire_direct_ownership(&ownership) {
                Ok(ownership) => ownership,
                Err(error) => return write_cli_failure(stderr, CliFailure::from_direct(error)),
            };
            let backend = match create_backend() {
                Ok(backend) => backend,
                Err(error) => {
                    return write_cli_failure(
                        stderr,
                        CliFailure::from_direct(DirectFailure::Service(error)),
                    );
                }
            };
            run_eject(
                DirectService::new(backend),
                &target,
                if force {
                    HostEjectPolicy::Forced
                } else {
                    HostEjectPolicy::Safe
                },
                event_timeout,
                stdout,
                stderr,
            )
        }
    }
}

/// Executes one shared high-level scan and writes a single bounded JSON line.
fn run_scan<B: ServiceBackend, W: Write, E: Write>(
    mut service: DirectService<B>,
    stdout: &mut W,
    stderr: &mut E,
) -> CliExit {
    let devices = match service.scan() {
        Ok(devices) => devices,
        Err(error) => return write_cli_failure(stderr, CliFailure::from_direct(error)),
    };
    write_json_line(
        stdout,
        &ScanOutput {
            command: "scan",
            devices: &devices,
            hardware_verified: false,
            status: "ok",
        },
    )
}

/// Executes one opaque-target host-policy eject without logging the target.
fn run_eject<B: ServiceBackend, W: Write, E: Write>(
    mut service: DirectService<B>,
    target: &DeviceId,
    policy: HostEjectPolicy,
    event_timeout: Duration,
    stdout: &mut W,
    stderr: &mut E,
) -> CliExit {
    match service.eject(target, policy, event_timeout) {
        Ok(()) => write_text(stdout, "{\"command\":\"eject\",\"status\":\"ok\"}\n"),
        Err(error) => write_cli_failure(stderr, CliFailure::from_direct(error)),
    }
}

/// Maps actual native failure evidence to one stable operation exit class.
fn operation_failure_exit(failure: &OperationFailure) -> CliExit {
    // Entering readback proves dispatch was attempted. Any missing readback
    // evidence is completion uncertainty, regardless of the host error kind.
    if failure.primary().stage() == OperationStage::EjectReadback
        || failure.primary().is_ambiguous()
        || failure
            .cleanup()
            .iter()
            .any(|evidence| evidence.is_ambiguous())
        || failure.cleanup().iter().any(|evidence| {
            evidence.stage() == OperationStage::EjectReadback
                && matches!(
                    evidence.issue(),
                    OperationIssue::Host(_)
                        | OperationIssue::DeviceIdentityChanged
                        | OperationIssue::SessionBindingChanged
                )
        })
    {
        return CliExit::PartialOrAmbiguous;
    }
    match failure.primary().issue() {
        OperationIssue::Dispatch {
            certainty: DispatchCertainty::DefinitelyRejected,
            error: TransportError::CheckCondition(_),
        } => CliExit::Device,
        OperationIssue::Dispatch {
            certainty: DispatchCertainty::CompletionUnknown,
            ..
        }
        | OperationIssue::PostMutationRebind(_)
        | OperationIssue::EjectTargetPresent
        | OperationIssue::EjectDispatchContradiction => CliExit::PartialOrAmbiguous,
        OperationIssue::Dispatch {
            certainty: DispatchCertainty::NotSent,
            error: TransportError::InactiveSession,
        } => CliExit::Prerequisite,
        OperationIssue::Dispatch { .. } => CliExit::ServiceHost,
        OperationIssue::Host(
            HostOperationError::CapabilityUnavailable
            | HostOperationError::DeviceIdentityChanged
            | HostOperationError::ProductFamilyChanged
            | HostOperationError::StaleSessionGeneration
            | HostOperationError::InactiveSession,
        )
        | OperationIssue::WrongOperationKind { .. }
        | OperationIssue::ProductFamilyMismatch
        | OperationIssue::MediaPresent
        | OperationIssue::MediaMissing
        | OperationIssue::UnsupportedInterface
        | OperationIssue::FirmwareAuthorizationRejected { .. }
        | OperationIssue::FirmwareAuthorizationInvalidated => CliExit::Prerequisite,
        OperationIssue::Host(_) | OperationIssue::ProgressPublication => CliExit::ServiceHost,
        OperationIssue::DeviceIdentityChanged
        | OperationIssue::SessionBindingChanged
        | OperationIssue::ProtocolBuild(_)
        | OperationIssue::ProtocolParse(_)
        | OperationIssue::FirmwareRevisionMismatch { .. }
        | OperationIssue::ModeReadbackMismatch { .. }
        | OperationIssue::EventInvariant => CliExit::PartialOrAmbiguous,
    }
}

/// Writes one fixed informational response and maps output failure to exit 3.
fn write_text<W: Write>(writer: &mut W, text: &str) -> CliExit {
    if text.len() > MAX_SERVICE_FRAME_BYTES
        || writer.write_all(text.as_bytes()).is_err()
        || writer.flush().is_err()
    {
        CliExit::ServiceHost
    } else {
        CliExit::Success
    }
}

/// Serializes one stable bounded JSON object followed by exactly one newline.
fn write_json_line<W: Write, T: Serialize>(writer: &mut W, value: &T) -> CliExit {
    let Ok(payload) = serde_json::to_vec(value) else {
        return CliExit::ServiceHost;
    };
    if payload.len() + 1 > MAX_SERVICE_FRAME_BYTES
        || writer.write_all(&payload).is_err()
        || writer.write_all(b"\n").is_err()
        || writer.flush().is_err()
    {
        CliExit::ServiceHost
    } else {
        CliExit::Success
    }
}

/// Writes one fixed target-free usage diagnostic.
fn write_usage<E: Write>(stderr: &mut E, error: UsageError) -> CliExit {
    let output = UsageOutput {
        code: "usage-error",
        message: error.message(),
        status: "error",
    };
    if write_json_line(stderr, &output) == CliExit::Success {
        CliExit::Usage
    } else {
        CliExit::ServiceHost
    }
}

/// Writes one typed CLI failure without accepting caller-controlled classification.
fn write_cli_failure<E: Write>(stderr: &mut E, error: CliFailure) -> CliExit {
    let exit = error.exit;
    let output = ErrorOutput {
        code: &error.code,
        reason: error.reason.as_deref(),
        status: "error",
    };
    if write_json_line(stderr, &output) == CliExit::Success {
        exit
    } else {
        CliExit::ServiceHost
    }
}

/// Feature-gated shared-service fixtures that cannot be selected by CLI input.
#[cfg(feature = "fixtures")]
pub mod fixtures;

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::ffi::OsString;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use super::{CliExit, DirectOwnership, run_with_factory};
    use crate::service::{NoDeviceBackend, ServicePlatform};

    /// Ownership rejection must occur before a second registry-owning backend exists.
    #[test]
    fn rejected_ownership_prevents_backend_construction() {
        let constructions = Cell::new(0);
        let mut output = Vec::new();
        let mut diagnostics = Vec::new();

        let exit = run_with_factory(
            [OsString::from("--eject"), OsString::from("rdx:test")],
            &mut output,
            &mut diagnostics,
            || {
                constructions.set(constructions.get() + 1);
                Ok(NoDeviceBackend::new(ServicePlatform::Darwin))
            },
            DirectOwnership::Unavailable,
            Duration::from_millis(10),
        );

        assert_eq!(exit, CliExit::Prerequisite);
        assert_eq!(constructions.get(), 0);
        assert!(output.is_empty());
    }

    /// A non-fixture build can cross ownership into backend construction once.
    #[test]
    fn acquired_process_owner_reaches_backend_construction() {
        let constructions = Cell::new(0);
        let ownership = Arc::new(Mutex::new(()));
        let mut output = Vec::new();
        let mut diagnostics = Vec::new();

        let exit = run_with_factory(
            [OsString::from("--eject"), OsString::from("rdx:test")],
            &mut output,
            &mut diagnostics,
            || {
                constructions.set(constructions.get() + 1);
                Ok(NoDeviceBackend::new(ServicePlatform::Darwin))
            },
            DirectOwnership::ProcessLocalTest(ownership),
            Duration::from_millis(10),
        );

        assert_eq!(exit, CliExit::Prerequisite);
        assert_eq!(constructions.get(), 1);
        assert!(output.is_empty());
    }

    /// Contended process ownership fails closed without constructing a registry.
    #[test]
    fn contended_process_owner_never_constructs_backend() {
        let ownership = Arc::new(Mutex::new(()));
        let held = ownership.lock().unwrap();
        let constructions = Cell::new(0);
        let mut output = Vec::new();
        let mut diagnostics = Vec::new();

        let exit = run_with_factory(
            [OsString::from("--eject"), OsString::from("rdx:test")],
            &mut output,
            &mut diagnostics,
            || {
                constructions.set(constructions.get() + 1);
                Ok(NoDeviceBackend::new(ServicePlatform::Darwin))
            },
            DirectOwnership::ProcessLocalTest(ownership.clone()),
            Duration::from_millis(10),
        );

        drop(held);
        assert_eq!(exit, CliExit::Prerequisite);
        assert_eq!(constructions.get(), 0);
        assert!(output.is_empty());
    }
}
