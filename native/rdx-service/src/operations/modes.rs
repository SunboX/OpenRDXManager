// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Byte-preserving drive-mode and SATA-mode configuration state machines.

use crate::host::{DeviceInterface, DeviceSession, SessionDevice};
use crate::model::{DriveMode, OperationKind, SataMode};
use crate::protocol::Command;
use crate::protocol::{RdxFeaturePage, mode_select, mode_sense, unit_reset};
use crate::transport::{CommandDispatch, DispatchCertainty, TransportError};

use super::{
    FailureAccumulator, OperationCompletion, OperationContext, OperationFailure, OperationIssue,
    OperationReport, OperationStage,
};
use super::{HostOperationFailure, HostPrimitiveError, MutationCertainty, PrimitiveFailure};

const RECONNECT_ATTEMPTS: u8 = 15;

/// Narrow registry-owned command surface used by the production service actor.
pub(crate) trait RegistryModeTarget {
    /// Returns the exact discovered interface family.
    fn configuration_interface(&self) -> DeviceInterface;

    /// Reports fresh registry-owned cartridge presence, or none without host evidence.
    fn configuration_media_present(&self) -> Option<bool>;

    /// Revalidates the same exact retained handle and device evidence.
    fn revalidate_configuration(&mut self) -> Result<(), PrimitiveFailure>;

    /// Executes one trusted configuration command on the active exact lease.
    fn execute_configuration(&mut self, command: &Command) -> CommandDispatch;

    /// Executes mandatory recovery on the retained lease after ambiguous mutation dispatch.
    fn execute_configuration_recovery(&mut self, command: &Command) -> CommandDispatch;
}

/// Result of the mutation phase before registry-owned rediscovery and readback.
pub(crate) struct RegistryModeMutation {
    failure: Option<HostOperationFailure>,
    requires_reconnect: bool,
}

impl RegistryModeMutation {
    /// Returns whether the setter succeeded or may have applied.
    pub(crate) const fn requires_reconnect(&self) -> bool {
        self.requires_reconnect
    }

    /// Returns the primary dispatch failure retained through mandatory recovery.
    pub(crate) fn into_failure(self) -> Option<HostOperationFailure> {
        self.failure
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ModeField {
    Drive,
    Sata,
}

impl ModeField {
    /// Returns the high-level operation kind owning this field.
    const fn operation_kind(self) -> OperationKind {
        match self {
            Self::Drive => OperationKind::DriveModeSet,
            Self::Sata => OperationKind::SataModeSet,
        }
    }

    /// Returns the field value from a validated page.
    fn value(self, page: &RdxFeaturePage) -> Result<u8, OperationIssue> {
        match self {
            Self::Drive => page.operation_mode(),
            Self::Sata => page.max_host_sata_speed(),
        }
        .ok_or(OperationIssue::EventInvariant)
    }

    /// Changes only this field while preserving every unrelated byte.
    fn set_value(self, page: &mut RdxFeaturePage, value: u8) -> Result<(), OperationIssue> {
        match self {
            Self::Drive => page.set_operation_mode(value),
            Self::Sata => page.set_max_host_sata_speed(value),
        }
        .map_err(OperationIssue::ProtocolParse)
    }

    /// Reports whether this field's setter sets MODE SELECT SP.
    const fn save_pages(self) -> bool {
        matches!(self, Self::Drive)
    }

    /// Reports whether the SATA unit-reset command is required.
    const fn sends_unit_reset(self) -> bool {
        matches!(self, Self::Sata)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MutationOutcome {
    NoChange,
    NotSent,
    DefinitelyRejected,
    CompletionUnknown,
    Succeeded,
}

impl MutationOutcome {
    /// Reports whether mutation completion justifies reset/rebind/readback recovery.
    const fn requires_rebind(self) -> bool {
        matches!(self, Self::CompletionUnknown | Self::Succeeded)
    }
}

/// Changes fixed/removable presentation through page `0x34` with saved-page semantics.
///
/// # Errors
///
/// Returns [`OperationFailure`] after the exact Phase 1 safe terminal, retaining
/// explicit dispatch certainty and any reconnect/readback cleanup evidence.
pub fn set_drive_mode(
    session: &mut DeviceSession,
    context: OperationContext,
    mode: DriveMode,
) -> Result<OperationReport, OperationFailure> {
    let value = match mode {
        DriveMode::Removable => 1,
        DriveMode::Fixed => 2,
    };
    run_mode_change(session, context, ModeField::Drive, value)
}

/// Changes the SATA III host-link field and conditionally sends reset.
///
/// # Errors
///
/// Returns [`OperationFailure`] after the exact Phase 1 safe terminal. Reset,
/// reconnect, and readback run only when MODE SELECT succeeded or may have applied.
pub fn set_sata_mode(
    session: &mut DeviceSession,
    context: OperationContext,
    mode: SataMode,
) -> Result<OperationReport, OperationFailure> {
    let value = match mode {
        SataMode::OnePointFiveGThreeG => 2,
        SataMode::ThreeGSixG => 3,
    };
    run_mode_change(session, context, ModeField::Sata, value)
}

/// Applies the exact drive-mode field on a registry-owned production lease.
pub(crate) fn configure_registry_drive_mode(
    target: &mut impl RegistryModeTarget,
    mode: DriveMode,
) -> Result<RegistryModeMutation, HostOperationFailure> {
    let value = match mode {
        DriveMode::Removable => 1,
        DriveMode::Fixed => 2,
    };
    configure_registry_mode(target, ModeField::Drive, value)
}

/// Applies the exact SATA field and mandatory unit reset on a production lease.
pub(crate) fn configure_registry_sata_mode(
    target: &mut impl RegistryModeTarget,
    mode: SataMode,
) -> Result<RegistryModeMutation, HostOperationFailure> {
    let value = match mode {
        SataMode::OnePointFiveGThreeG => 2,
        SataMode::ThreeGSixG => 3,
    };
    configure_registry_mode(target, ModeField::Sata, value)
}

/// Proves the requested field through a fresh exact registry lease after reconnect.
pub(crate) fn verify_registry_mode(
    target: &mut impl RegistryModeTarget,
    kind: OperationKind,
    expected: u8,
) -> Result<(), HostOperationFailure> {
    let field = match kind {
        OperationKind::DriveModeSet => ModeField::Drive,
        OperationKind::SataModeSet => ModeField::Sata,
        _ => {
            return Err(HostOperationFailure::preflight(
                "device-readback",
                HostPrimitiveError::Other,
            ));
        }
    };
    target
        .revalidate_configuration()
        .map_err(|failure| HostOperationFailure::from_primitive("device-readback", failure))?;
    let page = read_registry_page(target, "device-readback", true)?;
    if field.value(&page).ok() == Some(expected) {
        Ok(())
    } else {
        Err(HostOperationFailure::from_primitive(
            "device-readback",
            PrimitiveFailure::completion_unknown(HostPrimitiveError::DataMismatch),
        ))
    }
}

/// Runs the mutation phase while the original exact lease remains retained.
fn configure_registry_mode(
    target: &mut impl RegistryModeTarget,
    field: ModeField,
    expected: u8,
) -> Result<RegistryModeMutation, HostOperationFailure> {
    target
        .revalidate_configuration()
        .map_err(|failure| HostOperationFailure::from_primitive("device-configuring", failure))?;
    let media_present = target.configuration_media_present().ok_or_else(|| {
        HostOperationFailure::preflight("device-configuring", HostPrimitiveError::DependencyMissing)
    })?;
    if media_present {
        return Err(HostOperationFailure::preflight(
            "device-configuring",
            HostPrimitiveError::MediaPresent,
        ));
    }
    if field == ModeField::Sata && target.configuration_interface() != DeviceInterface::Sata3 {
        return Err(HostOperationFailure::preflight(
            "device-configuring",
            HostPrimitiveError::UnsupportedPlatform,
        ));
    }

    let mut page = read_registry_page(target, "device-configuring", false)?;
    if field.value(&page).ok() == Some(expected) {
        return Ok(RegistryModeMutation {
            failure: None,
            requires_reconnect: false,
        });
    }
    field.set_value(&mut page, expected).map_err(|_| {
        HostOperationFailure::preflight("device-configuring", HostPrimitiveError::Other)
    })?;
    let command = mode_select(page.as_bytes(), field.save_pages()).map_err(|_| {
        HostOperationFailure::preflight("device-configuring", HostPrimitiveError::Other)
    })?;
    let mutation = target.execute_configuration(&command);
    let requires_reconnect = matches!(
        mutation.certainty(),
        DispatchCertainty::Succeeded | DispatchCertainty::CompletionUnknown
    );
    let mut failure = dispatch_host_failure("device-configuring", &mutation, true);

    if requires_reconnect && field.sends_unit_reset() {
        let reset = unit_reset();
        let reset_dispatch = if mutation.certainty() == DispatchCertainty::CompletionUnknown {
            target.execute_configuration_recovery(&reset)
        } else {
            target.execute_configuration(&reset)
        };
        if failure.is_none() {
            failure = dispatch_host_failure("device-configuring", &reset_dispatch, true);
        }
    }
    if !requires_reconnect {
        return Err(failure.unwrap_or_else(|| {
            HostOperationFailure::preflight("device-configuring", HostPrimitiveError::Other)
        }));
    }
    Ok(RegistryModeMutation {
        failure,
        requires_reconnect,
    })
}

/// Executes and parses page `0x34` without releasing the exact registry lease.
fn read_registry_page(
    target: &mut impl RegistryModeTarget,
    stage: &'static str,
    after_mutation: bool,
) -> Result<RdxFeaturePage, HostOperationFailure> {
    let command = mode_sense(0x34)
        .map_err(|_| HostOperationFailure::preflight(stage, HostPrimitiveError::Other))?;
    let dispatch = target.execute_configuration(&command);
    match dispatch {
        CommandDispatch::Succeeded(response) => {
            RdxFeaturePage::parse(response.data()).map_err(|_| {
                let failure = if after_mutation {
                    PrimitiveFailure::completion_unknown(HostPrimitiveError::Other)
                } else {
                    PrimitiveFailure::not_attempted(HostPrimitiveError::Other)
                };
                HostOperationFailure::from_primitive(stage, failure)
            })
        }
        other => Err(dispatch_host_failure(stage, &other, after_mutation)
            .unwrap_or_else(|| HostOperationFailure::preflight(stage, HostPrimitiveError::Other))),
    }
}

/// Converts transport certainty into the closed host-operation failure contract.
fn dispatch_host_failure(
    stage: &'static str,
    dispatch: &CommandDispatch,
    after_mutation: bool,
) -> Option<HostOperationFailure> {
    let error = match dispatch.error() {
        Some(TransportError::Timeout) => HostPrimitiveError::TimedOut,
        Some(TransportError::DeviceRemoved | TransportError::Unavailable) => {
            HostPrimitiveError::StaleBinding
        }
        Some(_) => HostPrimitiveError::Other,
        None => return None,
    };
    let certainty = match dispatch.certainty() {
        DispatchCertainty::NotSent if after_mutation => MutationCertainty::CompletionUnknown,
        DispatchCertainty::NotSent => MutationCertainty::NotAttempted,
        DispatchCertainty::DefinitelyRejected => MutationCertainty::DefinitelyRejected,
        DispatchCertainty::CompletionUnknown | DispatchCertainty::Succeeded => {
            MutationCertainty::CompletionUnknown
        }
    };
    Some(HostOperationFailure::from_primitive(
        stage,
        PrimitiveFailure { error, certainty },
    ))
}

/// Runs MODE SENSE, byte-preserving selection, conditional rebind, and readback.
fn run_mode_change(
    session: &mut DeviceSession,
    mut context: OperationContext,
    field: ModeField,
    target: u8,
) -> Result<OperationReport, OperationFailure> {
    let mut failures = FailureAccumulator::default();
    if !require_context_binding(session, &context, field, &mut failures) {
        return Err(context.fail(failures));
    }
    record_emit(
        &mut context,
        OperationStage::DeviceConfiguring,
        0.1,
        "operations.deviceConfiguration.configuring",
        &mut failures,
    );

    let preflight_valid = match session.revalidate() {
        Ok(()) => match validate_preflight(session.device(), field) {
            Ok(()) => true,
            Err(issue) => {
                failures.record(OperationStage::DeviceConfiguring, issue);
                false
            }
        },
        Err(error) => {
            failures.record(
                OperationStage::DeviceConfiguring,
                OperationIssue::Host(error),
            );
            false
        }
    };

    let mut outcome = MutationOutcome::NotSent;
    let mut mutation_lease = None;
    if preflight_valid {
        match read_page(session) {
            Ok(mut page) => match field.value(&page) {
                Ok(current) if current == target => outcome = MutationOutcome::NoChange,
                Ok(_) => {
                    if let Err(issue) = field.set_value(&mut page, target) {
                        failures.record(OperationStage::DeviceConfiguring, issue);
                    } else {
                        mutation_lease = Some(session.recovery_lease());
                        outcome = execute_mode_select(session, &page, field, &mut failures);
                    }
                }
                Err(issue) => failures.record(OperationStage::DeviceConfiguring, issue),
            },
            Err(issue) => failures.record(OperationStage::DeviceConfiguring, issue),
        }
    }

    if outcome.requires_rebind() && field.sends_unit_reset() {
        let reset = unit_reset();
        let dispatch = if outcome == MutationOutcome::CompletionUnknown {
            mutation_lease.as_ref().map_or_else(
                || CommandDispatch::NotSent(crate::transport::TransportError::InactiveSession),
                |lease| session.execute_recovery(lease, &reset),
            )
        } else {
            session.execute(&reset)
        };
        record_dispatch_failure(dispatch, OperationStage::DeviceConfiguring, &mut failures);
    }

    record_emit(
        &mut context,
        OperationStage::DeviceReconnecting,
        0.75,
        if outcome.requires_rebind() {
            "operations.deviceConfiguration.reconnecting"
        } else {
            "operations.deviceConfiguration.noReconnect"
        },
        &mut failures,
    );
    let rebound = if outcome.requires_rebind() {
        match session.reconnect(RECONNECT_ATTEMPTS) {
            Ok(()) => true,
            Err(error) => {
                failures.record(
                    OperationStage::DeviceReconnecting,
                    OperationIssue::PostMutationRebind(error),
                );
                false
            }
        }
    } else {
        false
    };

    record_emit(
        &mut context,
        OperationStage::DeviceReadback,
        1.0,
        "operations.deviceConfiguration.readback",
        &mut failures,
    );
    if rebound {
        match read_page(session).and_then(|page| field.value(&page)) {
            Ok(actual) if actual == target => {}
            Ok(actual) => failures.record(
                OperationStage::DeviceReadback,
                OperationIssue::ModeReadbackMismatch {
                    expected: target,
                    actual,
                },
            ),
            Err(issue) => failures.record(OperationStage::DeviceReadback, issue),
        }
    }

    if failures.has_failure() {
        Err(context.fail(failures))
    } else {
        Ok(context.complete(OperationCompletion::Succeeded))
    }
}

/// Builds and dispatches one byte-preserving MODE SELECT command.
fn execute_mode_select(
    session: &mut DeviceSession,
    page: &RdxFeaturePage,
    field: ModeField,
    failures: &mut FailureAccumulator,
) -> MutationOutcome {
    let command = match mode_select(page.as_bytes(), field.save_pages()) {
        Ok(command) => command,
        Err(error) => {
            failures.record(
                OperationStage::DeviceConfiguring,
                OperationIssue::ProtocolBuild(error),
            );
            return MutationOutcome::NotSent;
        }
    };
    let dispatch = session.execute(&command);
    let outcome = match dispatch.certainty() {
        DispatchCertainty::NotSent => MutationOutcome::NotSent,
        DispatchCertainty::DefinitelyRejected => MutationOutcome::DefinitelyRejected,
        DispatchCertainty::CompletionUnknown => MutationOutcome::CompletionUnknown,
        DispatchCertainty::Succeeded => MutationOutcome::Succeeded,
    };
    record_dispatch_failure(dispatch, OperationStage::DeviceConfiguring, failures);
    outcome
}

/// Executes and parses one exact page-`0x34` MODE SENSE command.
fn read_page(session: &mut DeviceSession) -> Result<RdxFeaturePage, OperationIssue> {
    let command = mode_sense(0x34).map_err(OperationIssue::ProtocolBuild)?;
    let dispatch = session.execute(&command);
    let certainty = dispatch.certainty();
    match dispatch {
        CommandDispatch::Succeeded(response) => {
            RdxFeaturePage::parse(response.data()).map_err(OperationIssue::ProtocolParse)
        }
        CommandDispatch::NotSent(error)
        | CommandDispatch::DefinitelyRejected(error)
        | CommandDispatch::CompletionUnknown(error) => {
            Err(OperationIssue::Dispatch { certainty, error })
        }
    }
}

/// Records a non-success dispatch with its exact certainty.
fn record_dispatch_failure(
    dispatch: CommandDispatch,
    stage: OperationStage,
    failures: &mut FailureAccumulator,
) {
    let certainty = dispatch.certainty();
    if let Some(error) = dispatch.error().cloned() {
        failures.record(stage, OperationIssue::Dispatch { certainty, error });
    }
}

/// Validates no-media state and SATA applicability on fresh session evidence.
fn validate_preflight(device: &SessionDevice, field: ModeField) -> Result<(), OperationIssue> {
    if device.media_present() {
        return Err(OperationIssue::MediaPresent);
    }
    if field == ModeField::Sata && device.interface() != DeviceInterface::Sata3 {
        return Err(OperationIssue::UnsupportedInterface);
    }
    Ok(())
}

/// Requires operation kind plus exact context/session identity and generation.
fn require_context_binding(
    session: &DeviceSession,
    context: &OperationContext,
    field: ModeField,
    failures: &mut FailureAccumulator,
) -> bool {
    if context.owner().kind() != field.operation_kind() {
        failures.record(
            OperationStage::DeviceConfiguring,
            OperationIssue::WrongOperationKind {
                expected: field.operation_kind(),
                actual: context.owner().kind(),
            },
        );
        return false;
    }
    let device = session.device();
    if !session.is_active()
        || !context.owner().belongs_to(session)
        || context.owner().device() != device.identity()
        || context.owner().product_family() != device.product_family()
        || context.owner().generation().get() != device.generation().get()
    {
        failures.record(
            OperationStage::DeviceConfiguring,
            OperationIssue::SessionBindingChanged,
        );
        return false;
    }
    true
}

/// Emits a trusted event or records an impossible invariant without panicking.
fn record_emit(
    context: &mut OperationContext,
    stage: OperationStage,
    fraction: f64,
    message_key: &'static str,
    failures: &mut FailureAccumulator,
) {
    if let Err(issue) = context.emit(stage, fraction, message_key) {
        failures.record(stage, issue);
    }
}
