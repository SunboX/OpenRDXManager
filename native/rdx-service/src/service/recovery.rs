#![cfg_attr(not(target_os = "macos"), allow(dead_code))]
// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Closed, one-attempt recovery from a previously persisted migration bundle.
//!
//! Portable builds retain the pure state machine for deterministic tests while
//! the public recovery entry points reject before hardware access off macOS.

use crate::migration::MigrationEvent;

#[cfg(target_os = "macos")]
mod native;

/// Fixed recovery stages; no device identity, path or record bytes enter progress.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryStage {
    /// Validate the persisted source and acquire exclusive hardware ownership.
    Preparing,
    /// Identify the explicitly selected ROM loader at its current observed port.
    IdentifyingRom,
    /// Send the one erase-capable documented ROM setup report.
    SettingUpRom,
    /// Transfer the saved personalized bootstrap exactly once.
    ProgrammingBootstrap,
    /// Request reset only after complete bootstrap transfer.
    ResettingRom,
    /// Require a fresh explicit operator power-cycle acknowledgment.
    AwaitingPowerCycle,
    /// Check actual restored SPI records before the final release transfer.
    VerifyingBootstrap,
    /// Send the exact unmodified release through its normal receiver.
    TransferringFinalRelease,
    /// Commit the completely transferred final release once.
    ActivatingFinalRelease,
    /// Reopen and verify final revision, empty bay and raw records.
    VerifyingFinalRelease,
}

impl RecoveryStage {
    /// Returns a fixed progress token suitable for command-line or UI output.
    pub const fn code(self) -> &'static str {
        match self {
            Self::Preparing => "recovery-preparing",
            Self::IdentifyingRom => "recovery-identifying-rom",
            Self::SettingUpRom => "recovery-setting-up-rom",
            Self::ProgrammingBootstrap => "recovery-programming-bootstrap",
            Self::ResettingRom => "recovery-resetting-rom",
            Self::AwaitingPowerCycle => "recovery-awaiting-power-cycle",
            Self::VerifyingBootstrap => "recovery-verifying-bootstrap",
            Self::TransferringFinalRelease => "recovery-transferring-final-release",
            Self::ActivatingFinalRelease => "recovery-activating-final-release",
            Self::VerifyingFinalRelease => "recovery-verifying-final-release",
        }
    }
}

/// Closed failures; a failed attempt never implies that earlier hardware survived.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryError {
    /// Only a canonical generated bundle identifier is accepted.
    InvalidArguments,
    /// This recovery transport is implemented only on macOS.
    UnsupportedPlatform,
    /// Native process identity did not prove privileged helper authority.
    PrivilegeRequired,
    /// The process-global hardware owner could not be exclusively acquired.
    OwnershipUnavailable,
    /// Stored evidence or a required durable journal append failed validation.
    StorageUnavailable,
    /// The selected ROM loader's current port and enumeration epoch did not match.
    RomUnavailable,
    /// A setup, programming or reset attempt did not complete conclusively.
    RomOperationUnknown,
    /// No valid explicit operator acknowledgment arrived before the deadline.
    OperatorAcknowledgmentRequired,
    /// The selected route did not return with the saved USB identity.
    TargetUnavailable,
    /// Fresh revision, empty-bay or preserved-record checks failed.
    ReadbackMismatch,
    /// The final release transfer or activation did not receive full success.
    FinalUpdateUnknown,
    /// The progress or explicit operator-input channel failed.
    ObserverUnavailable,
}

impl RecoveryError {
    /// Returns a sanitized failure token without formatting an underlying error.
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidArguments => "recovery-invalid-arguments",
            Self::UnsupportedPlatform => "recovery-platform-unsupported",
            Self::PrivilegeRequired => "recovery-privilege-required",
            Self::OwnershipUnavailable => "recovery-hardware-owner-unavailable",
            Self::StorageUnavailable => "recovery-artifacts-unavailable",
            Self::RomUnavailable => "recovery-selected-rom-unavailable",
            Self::RomOperationUnknown => "recovery-rom-operation-unknown",
            Self::OperatorAcknowledgmentRequired => "recovery-operator-acknowledgment-required",
            Self::TargetUnavailable => "recovery-selected-target-unavailable",
            Self::ReadbackMismatch => "recovery-record-readback-mismatch",
            Self::FinalUpdateUnknown => "recovery-final-update-unknown",
            Self::ObserverUnavailable => "recovery-observer-unavailable",
        }
    }
}

/// Explicitly reviewed saved profile and current ROM target, with no image override.
///
/// Generic TI ROM has no per-unit identity. Calling recovery with this selection
/// attests that the operator associated the saved profile with this physical dock.
/// The target token binds only a current port/epoch; it is not hardware identity.
#[derive(Clone, Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RecoverySelection {
    /// Canonical identifier of the original immutable recovery bundle.
    pub bundle_id: String,
    /// Exact token from the current read-only ROM target inventory.
    pub target_token: String,
}

/// A read-only observed ROM route; it does not identify a saved physical unit.
#[derive(Clone, Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecoveryTarget {
    /// Opaque digest bound to the observed native location and enumeration epoch.
    pub target_token: String,
    /// Current observed USB location label, with no inferred unit identity.
    pub port_label: String,
}

/// Lists current ROM routes without claiming, programming, resetting or persisting.
///
/// A service should additionally wrap tokens in its own fresh session inventory
/// and require explicit profile/physical-target acknowledgment before recovery.
pub fn list_recovery_targets() -> Result<Vec<RecoveryTarget>, RecoveryError> {
    #[cfg(target_os = "macos")]
    {
        native::list_targets()
    }
    #[cfg(not(target_os = "macos"))]
    {
        Err(RecoveryError::UnsupportedPlatform)
    }
}

/// Performs an administrator-selected recovery on any freshly observed USB port.
///
/// The original receipt, capture and serial stay unchanged. Only this attempt's
/// route changes. Before erase, the caller must obtain the explicit physical-dock
/// association described by [`RecoverySelection`]. This standalone entry acquires
/// the global owner; the service uses its separate already-owned entry below.
pub fn recover_selected(
    selection: &RecoverySelection,
    observer: &mut dyn RecoveryObserver,
) -> Result<RecoveryOutcome, RecoveryError> {
    validate_selection(selection)?;
    #[cfg(target_os = "macos")]
    {
        native::recover_selected(selection, observer)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = observer;
        Err(RecoveryError::UnsupportedPlatform)
    }
}

/// Uses the caller's existing native service owner without reacquiring its lock.
///
/// The service must retain the session's HardwareOwnershipGuard and exclusive
/// operation admission through completion and teardown. It must validate its
/// authenticated start/selection acknowledgment before invoking this function.
/// Context is trusted startup evidence; no renderer payload can construct it.
pub(in crate::service) fn recover_selected_in_service(
    selection: &RecoverySelection,
    observer: &mut dyn RecoveryObserver,
    context: super::ServiceExecutionContext,
) -> Result<RecoveryOutcome, RecoveryError> {
    validate_selection(selection)?;
    if !context.hardware_authorized() || context.direct_cli_authorized() {
        return Err(RecoveryError::PrivilegeRequired);
    }
    #[cfg(target_os = "macos")]
    {
        native::recover_in_service(selection, observer, context)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = observer;
        Err(RecoveryError::UnsupportedPlatform)
    }
}

/// Rejects malformed receipt or target tokens before native or storage access.
fn validate_selection(selection: &RecoverySelection) -> Result<(), RecoveryError> {
    let token_valid = selection
        .target_token
        .strip_prefix("recovery-rom:")
        .is_some_and(|digest| {
            digest.len() == 64
                && digest
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        });
    if valid_bundle_id(&selection.bundle_id) && token_valid {
        Ok(())
    } else {
        Err(RecoveryError::InvalidArguments)
    }
}

/// Binds an opaque lookup token to actual native observations without unit claims.
fn target_token(location: u32, epoch: u64) -> String {
    use sha2::{Digest, Sha256};
    let mut digest = Sha256::new();
    digest.update(b"OpenRDXManager/recovery-rom-route/v1\0");
    digest.update(location.to_be_bytes());
    digest.update(epoch.to_be_bytes());
    format!("recovery-rom:{:x}", digest.finalize())
}

/// Requires exactly one fresh candidate matching the selected observed route.
fn select_observed_target<'a, T>(
    candidates: &'a [T],
    selected: &str,
    token: impl Fn(&T) -> String,
) -> Result<&'a T, RecoveryError> {
    let mut matching = candidates
        .iter()
        .filter(|candidate| token(candidate) == selected);
    let found = matching.next().ok_or(RecoveryError::RomUnavailable)?;
    if matching.next().is_some() {
        return Err(RecoveryError::RomUnavailable);
    }
    Ok(found)
}

/// Checks the saved serial's operational presence immediately before erase setup.
/// The native observer rejects that serial on another port. None permits setup
/// only in conjunction with the independently epoch-bound selected ROM session.
fn setup_after_absent_application(
    observe: impl FnOnce() -> Result<Option<u64>, RecoveryError>,
    setup: impl FnOnce() -> Result<(), RecoveryError>,
) -> Result<(), RecoveryError> {
    if observe()?.is_some() {
        return Err(RecoveryError::TargetUnavailable);
    }
    setup()
}

/// Observer for fixed progress and a nonblocking, separately armed operator reply.
pub trait RecoveryObserver {
    /// Checks session liveness during bounded waits and before another command.
    /// A service observer must reject a disconnected owner; no cleanup write follows.
    fn ensure_connected(&mut self) -> Result<(), RecoveryError> {
        Ok(())
    }

    /// Publishes and flushes one stage before any associated mutation.
    /// AwaitingPowerCycle must arm a new acknowledgment, never reuse an old reply.
    fn reached(&mut self, stage: RecoveryStage) -> Result<(), RecoveryError>;

    /// Polls the reply to the current explicit power-cycle prompt without blocking.
    /// Enumeration alone must never return true. EOF or malformed replies fail.
    fn operator_acknowledged(&mut self) -> Result<bool, RecoveryError>;
}

/// Completion requires final mode05 GOOD and fresh same-target record/revision proof.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryOutcome {
    /// The final release committed and its returned receiver/records were verified.
    FinalReleaseVerified,
}

/// Hardware boundary owned together with the independent writable recovery attempt.
trait RecoveryAttempt {
    /// Appends one durable closed event before the next dependent operation.
    fn journal(&mut self, event: MigrationEvent) -> Result<(), RecoveryError>;
    /// Opens and identifies only the selected current ROM location and epoch.
    fn identify_rom(&mut self) -> Result<(), RecoveryError>;
    /// Sends only the documented setup report once.
    fn setup_rom(&mut self) -> Result<(), RecoveryError>;
    /// Transfers only the saved personalized bootstrap once.
    fn program_rom(&mut self) -> Result<(), RecoveryError>;
    /// Resets only after a fully completed programming call.
    fn reset_rom(&mut self) -> Result<(), RecoveryError>;
    /// Releases native ownership without issuing any cleanup IO.
    fn release_rom(&mut self);
    /// Captures the USB observation epoch before publishing the operator prompt.
    fn arm_power_cycle(&mut self) -> Result<(), RecoveryError>;
    /// Requires an explicit acknowledgment and exact matching USB application.
    fn await_application(
        &mut self,
        observer: &mut dyn RecoveryObserver,
    ) -> Result<(), RecoveryError>;
    /// Verifies bootstrap, writes the release once, then verifies the new receiver.
    fn finish_release(&mut self, observer: &mut dyn RecoveryObserver) -> Result<(), RecoveryError>;
}

/// Runs the complete single-attempt ordering and marks any failure recovery-required.
fn run_sequence(
    attempt: &mut impl RecoveryAttempt,
    observer: &mut dyn RecoveryObserver,
) -> Result<RecoveryOutcome, RecoveryError> {
    let result = (|| {
        observer.reached(RecoveryStage::IdentifyingRom)?;
        observer.ensure_connected()?;
        attempt.identify_rom()?;
        attempt.journal(MigrationEvent::RomObserved)?;
        observer.reached(RecoveryStage::SettingUpRom)?;
        attempt.journal(MigrationEvent::RomSetupDispatching)?;
        observer.ensure_connected()?;
        attempt.setup_rom()?;
        attempt.journal(MigrationEvent::RomSetupAccepted)?;
        observer.reached(RecoveryStage::ProgrammingBootstrap)?;
        attempt.journal(MigrationEvent::RomTransferDispatching)?;
        observer.ensure_connected()?;
        attempt.program_rom()?;
        attempt.journal(MigrationEvent::RomTransferComplete)?;
        observer.reached(RecoveryStage::ResettingRom)?;
        attempt.journal(MigrationEvent::RomResetDispatching)?;
        observer.ensure_connected()?;
        attempt.reset_rom()?;
        attempt.journal(MigrationEvent::RomResetAccepted)?;
        attempt.release_rom();
        attempt.journal(MigrationEvent::AwaitingBootstrapPowerCycle)?;
        attempt.arm_power_cycle()?;
        observer.reached(RecoveryStage::AwaitingPowerCycle)?;
        attempt.await_application(observer)?;
        attempt.finish_release(observer)?;
        Ok(RecoveryOutcome::FinalReleaseVerified)
    })();
    if result.is_err() {
        // No explicit reset or finalization follows failure. Releasing a macOS
        // capture may itself reset/rematch USB; lease-local failures are also
        // journaled while that capture is still live, before its destruction.
        let _ = attempt.journal(MigrationEvent::RecoveryRequired);
    }
    result
}

/// Executes one administrator-requested recovery using only the saved bundle.
///
/// The caller supplies no device, image, address or physical-port override. Native
/// process authority and global ownership are required before bundle/device use.
/// Original artifacts and journal remain unchanged. A separate recovery copy
/// owns new events. Every mutation is one-attempt; uncertain results stop and
/// require recovery assessment. This function performs hardware IO only when
/// explicitly called on macOS, never on import, status queries, or invalid input.
///
/// # Errors
/// Returns only a fixed failure code. An error cannot prove that preceding
/// hardware operations had no effect, and does not authorize retry or reset.
pub fn recover_existing(
    bundle_id: &str,
    observer: &mut dyn RecoveryObserver,
) -> Result<RecoveryOutcome, RecoveryError> {
    if !valid_bundle_id(bundle_id) {
        return Err(RecoveryError::InvalidArguments);
    }
    #[cfg(target_os = "macos")]
    {
        native::recover(bundle_id, observer)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = observer;
        Err(RecoveryError::UnsupportedPlatform)
    }
}

/// Independently checks saved raw records on the exact returned application.
///
/// This acquires the shared hardware owner and a fresh target lease, but sends
/// only normal discovery/identity reads and the three fixed E7 reads. It neither
/// appends a journal nor claims which executable image booted. It sends no
/// mutation, automatic recovery or reset command, but releasing a macOS capture
/// can itself reset/rematch the USB device.
///
/// # Errors
/// Rejects invalid identifiers, missing authority, unsafe evidence or any changed
/// physical identity, revision, empty-bay condition or preserved record bytes.
pub fn verify_existing_records(bundle_id: &str) -> Result<(), RecoveryError> {
    if !valid_bundle_id(bundle_id) {
        return Err(RecoveryError::InvalidArguments);
    }
    #[cfg(target_os = "macos")]
    {
        native::verify_existing(bundle_id)
    }
    #[cfg(not(target_os = "macos"))]
    {
        Err(RecoveryError::UnsupportedPlatform)
    }
}

/// Rejects paths and noncanonical generated identifiers before any native access.
fn valid_bundle_id(name: &str) -> bool {
    let Some(value) = name.strip_prefix("migration-") else {
        return false;
    };
    let Some((timestamp, counter)) = value.split_once('-') else {
        return false;
    };
    let canonical = |part: &str, maximum: usize| {
        !part.is_empty()
            && part.len() <= maximum
            && (part == "0" || !part.starts_with('0'))
            && part
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    };
    canonical(timestamp, 32) && canonical(counter, 16)
}

/// Tracks the prompt's exact USB epoch without substituting enumeration for consent.
struct PowerCycleGate {
    baseline: Option<u64>,
    departed: bool,
    acknowledged: bool,
}

impl PowerCycleGate {
    /// Captures only the observation made before publishing the new prompt.
    /// An absent baseline permits operator attestation; it cannot independently
    /// distinguish a physical power cycle from a delayed automatic ROM reset.
    fn new(baseline: Option<u64>) -> Self {
        Self {
            baseline,
            departed: baseline.is_none(),
            acknowledged: false,
        }
    }

    /// Accepts a returned receiver only with a separately supplied operator reply.
    fn observe(&mut self, current: Option<u64>, acknowledged: bool) -> bool {
        self.acknowledged |= acknowledged;
        self.departed |= current.is_none();
        self.acknowledged && current.is_some() && (self.departed || current != self.baseline)
    }
}

/// Uses the normal validated image command builders, with no retries or cleanup IO.
fn transfer_once(
    image: &crate::firmware::FirmwareImage,
    dispatch: &mut impl FnMut(&crate::protocol::Command) -> crate::transport::CommandDispatch,
    journal: &mut impl FnMut(MigrationEvent) -> Result<(), RecoveryError>,
    observer: &mut dyn RecoveryObserver,
) -> Result<(), RecoveryError> {
    use crate::transport::CommandDispatch;
    observer.reached(RecoveryStage::TransferringFinalRelease)?;
    journal(MigrationEvent::FinalUpdateStarted)?;
    for chunk in image.registry_chunks() {
        observer.ensure_connected()?;
        let command = crate::protocol::write_buffer(4, chunk.offset(), chunk.bytes())
            .map_err(|_| RecoveryError::FinalUpdateUnknown)?;
        if !matches!(dispatch(&command), CommandDispatch::Succeeded(_)) {
            return Err(RecoveryError::FinalUpdateUnknown);
        }
    }
    journal(MigrationEvent::FinalTransferComplete)?;
    observer.reached(RecoveryStage::ActivatingFinalRelease)?;
    journal(MigrationEvent::FinalActivationDispatching)?;
    observer.ensure_connected()?;
    let command = image
        .registry_finalize_command()
        .map_err(|_| RecoveryError::FinalUpdateUnknown)?;
    if !matches!(dispatch(&command), CommandDispatch::Succeeded(_)) {
        return Err(RecoveryError::FinalUpdateUnknown);
    }
    journal(MigrationEvent::FinalActivationAccepted)
}

#[cfg(test)]
#[path = "recovery/tests.rs"]
mod tests;
