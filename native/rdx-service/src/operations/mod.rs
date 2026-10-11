// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Exact operation ownership, cancellation, events, and deterministic workflows.

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::{self, ThreadId};

use crate::firmware::{FirmwareRevision, ProductFamily};
use crate::host::{DeviceSession, HostOperationError, SessionCapabilityId};
use crate::model::{DeviceIdentity, OperationId, OperationKind, SafeJsonInteger};
use crate::model::{MessageKey, Progress};
use crate::protocol::{ProtocolBuildError, ProtocolParseError};
use crate::transport::{DispatchCertainty, TransportError};

pub use crate::progress::CancellationState;

mod diagnostics;
mod volume_label;
pub use volume_label::set_volume_label;
mod drive_letter;
mod eject;
mod firmware;
mod modes;
mod security;
mod stage_graph;
mod volume;

use stage_graph::{is_stage_transition_allowed, operation_graph};

pub use diagnostics::{run_led_test, run_self_test};
pub use drive_letter::{reset_drive_letter, set_drive_letter};
pub use eject::{
    EjectHost, EjectOutcome, EjectReadback, HostEjectPolicy, ProgressPublicationError,
    VerifiedEjectDeparture, force_eject, run_eject, run_eject_with_progress, safe_eject,
};
pub(crate) use eject::{force_eject_observed, safe_eject_observed};
pub use firmware::run_firmware_update;
pub(crate) use modes::{
    RegistryModeTarget, configure_registry_drive_mode, configure_registry_sata_mode,
    verify_registry_mode,
};
pub use modes::{set_drive_mode, set_sata_mode};
pub use security::{
    SecurityEvidenceRegistry, SecurityMutator, SecurityOperationError, execute_security_mutator,
};
pub use volume::{
    CleanupState, FileSystem, FormatResult, HostOperationFailure, HostOperations,
    HostPrimitiveError, HostVolumeBinding, HostVolumeFacts, MutationCertainty, PrimitiveFailure,
    VolumeTopology, WriteReadPrimitiveResult, WriteReadTestResult, partition_and_format,
    run_write_read_test,
};
pub(crate) use volume::{
    HostOperationObserver, partition_and_format_observed, run_write_read_test_observed,
};

const CANCELLATION_OPEN: u8 = 0;
const CANCELLATION_REQUESTED: u8 = 1;
const CANCELLATION_CLOSED: u8 = 2;

/// Maximum number of safe progress records retained by one deterministic run.
pub const MAX_OPERATION_EVENTS: usize = 128;
/// Maximum cleanup observations retained in one native operation failure.
pub const MAX_OPERATION_CLEANUP_EVIDENCE: usize = 16;
/// Maximum recovered attempt observations retained in one native failure.
pub const MAX_OPERATION_ATTEMPT_EVIDENCE: usize = 1;

/// Positive service generation bound to one exact operation reservation.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct OperationGeneration(SafeJsonInteger);

impl OperationGeneration {
    /// Creates a positive generation representable exactly by JavaScript.
    ///
    /// # Errors
    ///
    /// Returns an error for zero or a value above JavaScript's safe integer
    /// range.
    pub fn new(value: u64) -> Result<Self, &'static str> {
        if value == 0 {
            return Err("operation generation must be positive");
        }
        SafeJsonInteger::new(value).map(Self)
    }

    /// Returns the exact positive generation value.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0.get()
    }
}

/// Exact immutable reservation owner for one device operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OperationOwner {
    operation_id: OperationId,
    kind: OperationKind,
    device: DeviceIdentity,
    product_family: ProductFamily,
    generation: OperationGeneration,
    capability_id: SessionCapabilityId,
}

impl OperationOwner {
    /// Creates an owner whose identity, family, and generation come from one session.
    fn for_session(
        operation_id: OperationId,
        kind: OperationKind,
        session: &DeviceSession,
    ) -> Result<Self, HostOperationError> {
        if !session.is_active() {
            return Err(HostOperationError::InactiveSession);
        }
        Ok(Self {
            operation_id,
            kind,
            device: session.device().identity().clone(),
            product_family: session.device().product_family(),
            generation: OperationGeneration::new(session.device().generation().get())
                .map_err(|_| HostOperationError::StaleSessionGeneration)?,
            capability_id: session.capability_id().clone(),
        })
    }

    /// Returns the service-issued operation identifier.
    #[must_use]
    pub fn operation_id(&self) -> &OperationId {
        &self.operation_id
    }

    /// Returns the high-level operation kind owned by this reservation.
    #[must_use]
    pub const fn kind(&self) -> OperationKind {
        self.kind
    }

    /// Returns the exact accepted device ID and discovery revision.
    #[must_use]
    pub const fn device(&self) -> &DeviceIdentity {
        &self.device
    }

    /// Returns the trusted product family captured with the reservation.
    #[must_use]
    pub const fn product_family(&self) -> ProductFamily {
        self.product_family
    }

    /// Returns the service generation captured with the reservation.
    #[must_use]
    pub const fn generation(&self) -> OperationGeneration {
        self.generation
    }

    /// Reports whether this owner carries the private lineage of `session`.
    pub(crate) fn belongs_to(&self, session: &DeviceSession) -> bool {
        session.has_capability(&self.capability_id)
    }
}

/// Result of requesting cancellation for an exact owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CancellationRequestResult {
    /// The exact active owner accepted its first cancellation request.
    Accepted,
    /// The same exact owner had already requested cancellation.
    AlreadyRequested,
    /// The operation has crossed its final cancellation safe point.
    Closed,
    /// The supplied owner does not match this cancellation capability.
    NotOwner,
}

/// Exact lifecycle stages currently implemented by native operations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OperationStage {
    /// Self-test command activity.
    DiagnosticRunning,
    /// Self-test cancellation/failure reconciliation.
    DiagnosticCleanup,
    /// LED diagnostic activity while cancellation remains available.
    LedTesting,
    /// Mandatory LED-off restoration.
    LedRestoring,
    /// Device-ready readback after LED restoration.
    LedReadback,
    /// Firmware image and freshly selected-device validation.
    FirmwareValidating,
    /// Validated private source identity and factory-data capture.
    FirmwareCapturing,
    /// Compatibility authorization after cancellation closes.
    FirmwareCompatibilitySetup,
    /// Compatibility container transfer requiring the exact late staging result.
    FirmwareStaging,
    /// First operator power cycle after accepted staging.
    FirmwareAwaitingBootloader,
    /// Exact-location ROM bootstrap programming; power must remain connected.
    FirmwareProgrammingBootstrap,
    /// Second operator power cycle after bootstrap programming completes.
    FirmwareAwaitingBootstrap,
    /// Same-device restored identity verification before the final transfer.
    FirmwareRestoringIdentity,
    /// One or two whole-file firmware transfer attempts.
    FirmwareWriting,
    /// Mandatory firmware parser finalization/recovery.
    FirmwareFinalizing,
    /// Bounded rediscovery after a device reset or activation.
    DeviceReconnecting,
    /// Firmware revision and identity readback after reconnect.
    FirmwareReadback,
    /// MODE SENSE, byte-preserving mutation, and optional MODE SELECT.
    DeviceConfiguring,
    /// MODE SENSE readback after configuration/reconnect.
    DeviceReadback,
    /// Safe host cache flush and unmount before eject.
    HostUnmounting,
    /// Typed safe or forced host eject request.
    HostEjecting,
    /// Fresh exact-target departure reconciliation.
    EjectReadback,
}

impl OperationStage {
    /// Returns the exact kebab-case stage accepted by the operation coordinator.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DiagnosticRunning => "diagnostic-running",
            Self::DiagnosticCleanup => "diagnostic-cleanup",
            Self::LedTesting => "led-testing",
            Self::LedRestoring => "led-restoring",
            Self::LedReadback => "led-readback",
            Self::FirmwareValidating => "firmware-validating",
            Self::FirmwareCapturing => "firmware-capturing",
            Self::FirmwareCompatibilitySetup => "firmware-compatibility-setup",
            Self::FirmwareStaging => "firmware-staging",
            Self::FirmwareAwaitingBootloader => "firmware-awaiting-bootloader",
            Self::FirmwareProgrammingBootstrap => "firmware-programming-bootstrap",
            Self::FirmwareAwaitingBootstrap => "firmware-awaiting-bootstrap",
            Self::FirmwareRestoringIdentity => "firmware-restoring-identity",
            Self::FirmwareWriting => "firmware-writing",
            Self::FirmwareFinalizing => "firmware-finalizing",
            Self::DeviceReconnecting => "device-reconnecting",
            Self::FirmwareReadback => "firmware-readback",
            Self::DeviceConfiguring => "device-configuring",
            Self::DeviceReadback => "device-readback",
            Self::HostUnmounting => "host-unmounting",
            Self::HostEjecting => "host-ejecting",
            Self::EjectReadback => "eject-readback",
        }
    }
}

/// Sanitized operation issue that cannot contain a path, CDB, payload, or secret.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OperationIssue {
    /// The operation was invoked with a context for another high-level kind.
    WrongOperationKind {
        /// Operation kind required by the state machine.
        expected: OperationKind,
        /// Operation kind bound to the supplied owner.
        actual: OperationKind,
    },
    /// An internal command failed with explicit device-dispatch certainty.
    Dispatch {
        /// Evidence-backed certainty used by mutation state machines.
        certainty: DispatchCertainty,
        /// Sanitized path-free transport cause.
        error: TransportError,
    },
    /// A host operation failed with bounded structured evidence.
    Host(HostOperationError),
    /// Rebinding after a mutation failed, so the resulting device state is unknown.
    PostMutationRebind(HostOperationError),
    /// An evidence-bounded command could not be constructed.
    ProtocolBuild(ProtocolBuildError),
    /// A bounded MODE response failed strict parsing.
    ProtocolParse(ProtocolParseError),
    /// Fresh discovery no longer matched the exact accepted device revision.
    DeviceIdentityChanged,
    /// The active command lease no longer matches the context generation/family.
    SessionBindingChanged,
    /// The live selected device and authorized image belong to different families.
    ProductFamilyMismatch,
    /// A no-media operation found an inserted cartridge during fresh preflight.
    MediaPresent,
    /// An eject operation found no cartridge during fresh preflight.
    MediaMissing,
    /// The selected interface cannot perform the requested configuration.
    UnsupportedInterface,
    /// Fresh installed revision policy rejected the previously authorized candidate.
    FirmwareAuthorizationRejected {
        /// Fresh installed revision.
        installed: FirmwareRevision,
        /// Candidate image revision.
        candidate: FirmwareRevision,
    },
    /// Fresh live evidence no longer matched the consumed session authorization.
    FirmwareAuthorizationInvalidated,
    /// Post-reconnect firmware revision did not match the transferred candidate.
    FirmwareRevisionMismatch {
        /// Candidate revision expected after a successful update.
        expected: FirmwareRevision,
        /// Fresh revision reported after reconnect.
        actual: FirmwareRevision,
    },
    /// Post-reconnect MODE SENSE did not match the requested field value.
    ModeReadbackMismatch {
        /// Requested numeric mode value.
        expected: u8,
        /// Fresh numeric mode value.
        actual: u8,
    },
    /// Fresh eject readback proves the exact target remains present.
    EjectTargetPresent,
    /// Eject dispatch and exact-target departure evidence contradict each other.
    EjectDispatchContradiction,
    /// Trusted operation code attempted an invalid stage/event transition.
    EventInvariant,
    /// A required causal progress event could not reach its bounded consumer.
    ProgressPublication,
}

impl OperationIssue {
    /// Reports whether completion or target identity cannot be proven.
    #[must_use]
    pub const fn is_ambiguous(&self) -> bool {
        match self {
            Self::Dispatch { certainty, error } => {
                matches!(certainty, DispatchCertainty::CompletionUnknown) || error.is_ambiguous()
            }
            Self::Host(error) => error.is_ambiguous(),
            Self::PostMutationRebind(_) => true,
            Self::DeviceIdentityChanged
            | Self::SessionBindingChanged
            | Self::EjectDispatchContradiction => true,
            Self::WrongOperationKind { .. }
            | Self::ProtocolBuild(_)
            | Self::ProtocolParse(_)
            | Self::ProductFamilyMismatch
            | Self::MediaPresent
            | Self::MediaMissing
            | Self::UnsupportedInterface
            | Self::FirmwareAuthorizationRejected { .. }
            | Self::FirmwareAuthorizationInvalidated
            | Self::FirmwareRevisionMismatch { .. }
            | Self::ModeReadbackMismatch { .. }
            | Self::EjectTargetPresent
            | Self::EventInvariant
            | Self::ProgressPublication => false,
        }
    }
}

/// One strict bounded progress event owned by an exact reservation.
#[derive(Clone, Debug, PartialEq)]
pub struct OperationProgressEvent {
    owner: OperationOwner,
    stage: OperationStage,
    fraction: Progress,
    message_key: MessageKey,
    cancellation_state: CancellationState,
    attempt: Option<u8>,
}

impl OperationProgressEvent {
    /// Returns the exact operation/device/revision/generation owner.
    #[must_use]
    pub const fn owner(&self) -> &OperationOwner {
        &self.owner
    }

    /// Returns the exact Phase 1 lifecycle stage.
    #[must_use]
    pub const fn stage(&self) -> OperationStage {
        self.stage
    }

    /// Returns the validated global operation progress fraction.
    #[must_use]
    pub const fn fraction(&self) -> Progress {
        self.fraction
    }

    /// Returns the bounded trusted localization key.
    #[must_use]
    pub const fn message_key(&self) -> &MessageKey {
        &self.message_key
    }

    /// Returns cancellation availability at the instant this event was emitted.
    #[must_use]
    pub const fn cancellation_state(&self) -> CancellationState {
        self.cancellation_state
    }

    /// Returns the one-based firmware transfer attempt substate when present.
    #[must_use]
    pub const fn attempt(&self) -> Option<u8> {
        self.attempt
    }
}

/// Safe non-failure completion of an operation report.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OperationCompletion {
    /// Every required command and recovery/readback step succeeded.
    Succeeded,
    /// Exact-owner cancellation completed at its declared safe terminal.
    Cancelled,
}

/// Successful or safely cancelled operation evidence.
#[derive(Clone, Debug, PartialEq)]
pub struct OperationReport {
    owner: Box<OperationOwner>,
    completion: OperationCompletion,
    events: Box<[OperationProgressEvent]>,
}

impl OperationReport {
    /// Returns the exact non-forgeable reservation that produced this report.
    #[must_use]
    pub const fn owner(&self) -> &OperationOwner {
        &self.owner
    }

    /// Returns whether the operation succeeded or cancelled safely.
    #[must_use]
    pub const fn completion(&self) -> OperationCompletion {
        self.completion
    }

    /// Returns all strict bounded progress events in lifecycle order.
    #[must_use]
    pub fn events(&self) -> &[OperationProgressEvent] {
        &self.events
    }
}

/// One primary or cleanup failure at an exact lifecycle stage.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OperationFailureEvidence {
    stage: OperationStage,
    issue: OperationIssue,
}

/// One recovered firmware attempt kept separate from the primary cause.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OperationAttemptFailureEvidence {
    attempt: u8,
    evidence: OperationFailureEvidence,
}

impl OperationAttemptFailureEvidence {
    /// Returns the one-based whole-file transfer attempt.
    #[must_use]
    pub const fn attempt(&self) -> u8 {
        self.attempt
    }

    /// Returns the stage where the recovered attempt failure was observed.
    #[must_use]
    pub const fn stage(&self) -> OperationStage {
        self.evidence.stage
    }

    /// Returns the sanitized recovered issue.
    #[must_use]
    pub const fn issue(&self) -> &OperationIssue {
        &self.evidence.issue
    }
}

impl OperationFailureEvidence {
    /// Returns the lifecycle stage where this evidence was observed.
    #[must_use]
    pub const fn stage(&self) -> OperationStage {
        self.stage
    }

    /// Returns sanitized structured issue evidence.
    #[must_use]
    pub const fn issue(&self) -> &OperationIssue {
        &self.issue
    }

    /// Reports whether this evidence leaves completion or identity uncertain.
    #[must_use]
    pub const fn is_ambiguous(&self) -> bool {
        self.issue.is_ambiguous()
    }
}

/// Failed operation evidence retaining both its primary and cleanup failures.
#[derive(Clone, Debug, PartialEq)]
pub struct OperationFailure {
    owner: Box<OperationOwner>,
    events: Box<[OperationProgressEvent]>,
    terminal_stage: OperationStage,
    primary: OperationFailureEvidence,
    cleanup: Box<[OperationFailureEvidence]>,
    attempt_history: Box<[OperationAttemptFailureEvidence]>,
}

impl OperationFailure {
    /// Returns the exact non-forgeable reservation that produced this failure.
    #[must_use]
    pub const fn owner(&self) -> &OperationOwner {
        &self.owner
    }

    /// Returns strict progress emitted before the safe failure terminal.
    #[must_use]
    pub fn events(&self) -> &[OperationProgressEvent] {
        &self.events
    }

    /// Returns the final graph stage reached after mandatory recovery.
    #[must_use]
    pub const fn terminal_stage(&self) -> OperationStage {
        self.terminal_stage
    }

    /// Returns the first failure that caused the operation to fail.
    #[must_use]
    pub const fn primary(&self) -> &OperationFailureEvidence {
        &self.primary
    }

    /// Returns later cleanup/recovery failures without replacing the primary.
    #[must_use]
    pub fn cleanup(&self) -> &[OperationFailureEvidence] {
        &self.cleanup
    }

    /// Returns recovered retry failures that never replaced the primary cause.
    #[must_use]
    pub fn attempt_history(&self) -> &[OperationAttemptFailureEvidence] {
        &self.attempt_history
    }
}

#[derive(Debug, Default)]
pub(crate) struct FailureAccumulator {
    primary: Option<OperationFailureEvidence>,
    cleanup: Vec<OperationFailureEvidence>,
    attempt_history: Vec<OperationAttemptFailureEvidence>,
}

impl FailureAccumulator {
    /// Records the first issue as primary and every later issue as cleanup evidence.
    pub(crate) fn record(&mut self, stage: OperationStage, issue: OperationIssue) {
        let evidence = OperationFailureEvidence { stage, issue };
        if self.primary.is_none() {
            self.primary = Some(evidence);
        } else if self.cleanup.len() < MAX_OPERATION_CLEANUP_EVIDENCE {
            self.cleanup.push(evidence);
        }
    }

    /// Records a recovered retry failure without promoting it to primary cause.
    pub(crate) fn record_attempt(
        &mut self,
        attempt: u8,
        stage: OperationStage,
        issue: OperationIssue,
    ) {
        if attempt == 1
            && matches!(
                stage,
                OperationStage::FirmwareWriting | OperationStage::FirmwareFinalizing
            )
            && self.attempt_history.len() < MAX_OPERATION_ATTEMPT_EVIDENCE
        {
            self.attempt_history.push(OperationAttemptFailureEvidence {
                attempt,
                evidence: OperationFailureEvidence { stage, issue },
            });
        }
    }

    /// Reports whether any failure evidence has been recorded.
    pub(crate) fn has_failure(&self) -> bool {
        self.primary.is_some()
    }
}

#[derive(Debug)]
struct CancellationControl {
    owner: OperationOwner,
    state: AtomicU8,
    transition: Mutex<PublicationTransition>,
    publication_finished: Condvar,
}

#[derive(Debug, Default)]
struct PublicationTransition {
    publisher: Option<ThreadId>,
}

/// Cloneable, exact-owner cancellation capability safe for another thread.
#[derive(Clone, Debug)]
pub struct CancellationHandle {
    control: Arc<CancellationControl>,
}

impl CancellationHandle {
    /// Requests cancellation only when `owner` exactly matches and the final
    /// safe point has not been crossed. A request from the active progress
    /// callback is reentrant; another thread reserves its result but does not
    /// return until that callback finishes publishing its current event.
    #[must_use]
    pub fn request(&self, owner: &OperationOwner) -> CancellationRequestResult {
        if &self.control.owner != owner {
            return CancellationRequestResult::NotOwner;
        }
        let Ok(mut transition) = self.control.transition.lock() else {
            self.control
                .state
                .store(CANCELLATION_CLOSED, Ordering::Release);
            return CancellationRequestResult::Closed;
        };
        // Reserve the cancellation before waiting so the operation cannot race
        // past its safe point as soon as the publisher releases the event.
        let result = match self.control.state.compare_exchange(
            CANCELLATION_OPEN,
            CANCELLATION_REQUESTED,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => CancellationRequestResult::Accepted,
            Err(CANCELLATION_REQUESTED) => CancellationRequestResult::AlreadyRequested,
            Err(_) => CancellationRequestResult::Closed,
        };
        let requester = thread::current().id();
        // The callback thread has already received this event and cannot wait
        // for itself. Every other caller waits for the publication boundary.
        while transition
            .publisher
            .is_some_and(|publisher| publisher != requester)
        {
            let Ok(next) = self.control.publication_finished.wait(transition) else {
                self.control
                    .state
                    .store(CANCELLATION_CLOSED, Ordering::Release);
                return CancellationRequestResult::Closed;
            };
            transition = next;
        }
        result
    }
}

/// Operation-owned context that binds identity, generation, cancellation, and events.
#[derive(Debug)]
pub struct OperationContext {
    control: Arc<CancellationControl>,
    events: Vec<OperationProgressEvent>,
    last_stage_index: Option<usize>,
    last_fraction: f64,
    last_attempt: u8,
}

impl OperationContext {
    /// Creates an operation context from one active identity-bound session.
    ///
    /// # Errors
    ///
    /// Returns [`HostOperationError::InactiveSession`] when no exact lease is active.
    pub fn for_session(
        operation_id: OperationId,
        kind: OperationKind,
        session: &DeviceSession,
    ) -> Result<Self, HostOperationError> {
        OperationOwner::for_session(operation_id, kind, session).map(Self::new)
    }

    /// Creates a context whose initial cancellation window matches the Phase 1
    /// lifecycle policy for the operation's first native stage.
    #[must_use]
    fn new(owner: OperationOwner) -> Self {
        let cancellation_is_open = matches!(
            owner.kind,
            OperationKind::StatusRefresh
                | OperationKind::CredentialCreate
                | OperationKind::CredentialChange
                | OperationKind::CredentialDelete
                | OperationKind::CredentialReset
                | OperationKind::CredentialConfigure
                | OperationKind::SelfTest
                | OperationKind::LedTest
                | OperationKind::WriteReadTest
                | OperationKind::FirmwareUpdate
                | OperationKind::EjectSafe
        );
        Self {
            control: Arc::new(CancellationControl {
                owner,
                state: AtomicU8::new(if cancellation_is_open {
                    CANCELLATION_OPEN
                } else {
                    CANCELLATION_CLOSED
                }),
                transition: Mutex::new(PublicationTransition::default()),
                publication_finished: Condvar::new(),
            }),
            events: Vec::new(),
            last_stage_index: None,
            last_fraction: 0.0,
            last_attempt: 0,
        }
    }

    /// Returns the exact immutable owner attached to this context.
    #[must_use]
    pub fn owner(&self) -> &OperationOwner {
        &self.control.owner
    }

    /// Returns a cancellation capability bound to this exact owner.
    #[must_use]
    pub fn cancellation_handle(&self) -> CancellationHandle {
        CancellationHandle {
            control: Arc::clone(&self.control),
        }
    }

    /// Reports whether an exact-owner cancellation request won the current safe-point race.
    pub(crate) fn cancellation_requested(&self) -> bool {
        self.control.state.load(Ordering::Acquire) == CANCELLATION_REQUESTED
    }

    /// Atomically closes cancellation and reports whether a prior request won.
    pub(crate) fn close_cancellation(&self) -> bool {
        let Ok(_transition) = self.control.transition.lock() else {
            self.control
                .state
                .store(CANCELLATION_CLOSED, Ordering::Release);
            return false;
        };
        match self.control.state.compare_exchange(
            CANCELLATION_OPEN,
            CANCELLATION_CLOSED,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) | Err(CANCELLATION_CLOSED) => false,
            Err(CANCELLATION_REQUESTED) => true,
            Err(_) => false,
        }
    }

    /// Emits one graph-valid, bounded, monotonic, owner-complete progress event.
    pub(crate) fn emit(
        &mut self,
        stage: OperationStage,
        fraction: f64,
        message_key: &'static str,
    ) -> Result<(), OperationIssue> {
        self.emit_with_attempt(stage, fraction, message_key, None)
    }

    /// Emits one monotonic firmware-writing attempt substate event.
    pub(crate) fn emit_attempt(
        &mut self,
        stage: OperationStage,
        fraction: f64,
        message_key: &'static str,
        attempt: u8,
    ) -> Result<(), OperationIssue> {
        self.emit_with_attempt(stage, fraction, message_key, Some(attempt))
    }

    /// Validates, retains, and publishes one event before cancellation may be accepted.
    pub(crate) fn emit_causally<F, E>(
        &mut self,
        stage: OperationStage,
        fraction: f64,
        message_key: &'static str,
        publish: &mut F,
    ) -> Result<(), OperationIssue>
    where
        F: FnMut(&OperationProgressEvent) -> Result<(), E>,
    {
        let control = Arc::clone(&self.control);
        let Ok(mut transition) = control.transition.lock() else {
            return Err(OperationIssue::EventInvariant);
        };
        self.emit_with_attempt_locked(stage, fraction, message_key, None)?;
        transition.publisher = Some(thread::current().id());
        // Application code must never run under the cancellation mutex. The
        // in-flight thread identity keeps synchronous callback cancellation safe.
        drop(transition);
        let event = self
            .events
            .last()
            .expect("successful emit retains exactly one validated event");
        let publication = catch_unwind(AssertUnwindSafe(|| publish(event)));
        let Ok(mut transition) = control.transition.lock() else {
            control.state.store(CANCELLATION_CLOSED, Ordering::Release);
            control.publication_finished.notify_all();
            return Err(OperationIssue::EventInvariant);
        };
        transition.publisher = None;
        control.publication_finished.notify_all();
        match publication {
            Ok(Ok(())) => Ok(()),
            Ok(Err(_)) | Err(_) => Err(OperationIssue::ProgressPublication),
        }
    }

    /// Validates and stores one ordinary or attempt-scoped progress event.
    fn emit_with_attempt(
        &mut self,
        stage: OperationStage,
        fraction: f64,
        message_key: &'static str,
        attempt: Option<u8>,
    ) -> Result<(), OperationIssue> {
        let control = Arc::clone(&self.control);
        let Ok(_transition) = control.transition.lock() else {
            return Err(OperationIssue::EventInvariant);
        };
        self.emit_with_attempt_locked(stage, fraction, message_key, attempt)
    }

    /// Validates and stores one event while its cancellation transition is held.
    fn emit_with_attempt_locked(
        &mut self,
        stage: OperationStage,
        fraction: f64,
        message_key: &'static str,
        attempt: Option<u8>,
    ) -> Result<(), OperationIssue> {
        let graph = operation_graph(self.owner().kind()).ok_or(OperationIssue::EventInvariant)?;
        let stage_index = graph
            .iter()
            .position(|candidate| *candidate == stage)
            .ok_or(OperationIssue::EventInvariant)?;
        let invalid_attempt = attempt.is_some_and(|attempt| {
            self.owner().kind() != OperationKind::FirmwareUpdate
                || stage != OperationStage::FirmwareWriting
                || !(1..=2).contains(&attempt)
                || attempt < self.last_attempt
                || attempt > self.last_attempt + 1
                || (self.last_attempt == 0 && attempt != 1)
        });
        if self.events.len() >= MAX_OPERATION_EVENTS
            || (self.last_stage_index.is_none() && stage_index != 0)
            || self.last_stage_index.is_some_and(|last| {
                !is_stage_transition_allowed(self.owner().kind(), graph[last], stage)
            })
            || fraction < self.last_fraction
            || invalid_attempt
        {
            return Err(OperationIssue::EventInvariant);
        }
        let fraction = Progress::new(fraction).map_err(|_| OperationIssue::EventInvariant)?;
        let message_key =
            MessageKey::new(message_key).map_err(|_| OperationIssue::EventInvariant)?;
        self.events.push(OperationProgressEvent {
            owner: self.owner().clone(),
            stage,
            fraction,
            message_key,
            cancellation_state: self.cancellation_state(),
            attempt,
        });
        self.last_stage_index = Some(stage_index);
        self.last_fraction = fraction.get();
        if let Some(attempt) = attempt {
            self.last_attempt = attempt;
        }
        Ok(())
    }

    /// Converts successful state and retained events into a public report.
    pub(crate) fn complete(self, completion: OperationCompletion) -> OperationReport {
        self.control
            .state
            .store(CANCELLATION_CLOSED, Ordering::Release);
        OperationReport {
            owner: Box::new(self.control.owner.clone()),
            completion,
            events: self.events.into_boxed_slice(),
        }
    }

    /// Converts retained primary/cleanup evidence and events into a safe failure.
    pub(crate) fn fail(self, failures: FailureAccumulator) -> OperationFailure {
        self.control
            .state
            .store(CANCELLATION_CLOSED, Ordering::Release);
        let primary = failures
            .primary
            .expect("trusted operation records a primary failure before fail");
        let terminal_stage = self
            .events
            .last()
            .map_or(primary.stage, |event| event.stage);
        OperationFailure {
            owner: Box::new(self.control.owner.clone()),
            events: self.events.into_boxed_slice(),
            terminal_stage,
            primary,
            cleanup: failures.cleanup.into_boxed_slice(),
            attempt_history: failures.attempt_history.into_boxed_slice(),
        }
    }

    /// Returns the cancellation state attached to the next progress event.
    fn cancellation_state(&self) -> CancellationState {
        match self.control.state.load(Ordering::Acquire) {
            CANCELLATION_OPEN => CancellationState::Cancellable,
            CANCELLATION_REQUESTED => CancellationState::Requested,
            _ => CancellationState::Closed,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host::{DeviceInterface, FixtureDevice, SessionDevice, SessionGeneration};
    use crate::model::{DeviceId, DiscoveryRevision};

    /// Builds one exact self-test context for private invariant tests.
    fn self_test_context() -> OperationContext {
        let fixture = FixtureDevice::new(SessionDevice::fixture(
            DeviceIdentity {
                id: DeviceId::new("rdx:invariant").expect("test device ID"),
                revision: DiscoveryRevision::new(1).expect("test revision"),
            },
            ProductFamily::Usb3Sata3,
            FirmwareRevision::new(282).expect("test firmware revision"),
            DeviceInterface::Sata3,
            false,
            SessionGeneration::new(1).expect("test generation"),
        ));
        OperationContext::for_session(
            OperationId::new("op:invariant").expect("test operation ID"),
            OperationKind::SelfTest,
            &fixture.open(),
        )
        .expect("active fixture session")
    }

    /// Proves a context cannot begin after the first policy-owned stage.
    #[test]
    fn event_validation_rejects_a_skipped_first_stage() {
        let mut context = self_test_context();

        assert_eq!(
            context.emit(
                OperationStage::DiagnosticCleanup,
                0.5,
                "operations.selfTest.cleanup",
            ),
            Err(OperationIssue::EventInvariant)
        );
    }

    /// Proves an impossible poisoned gate closes cancellation and rejects later events.
    #[test]
    fn poisoned_publication_gate_fails_closed_without_waiting() {
        let mut context = self_test_context();
        let owner = context.owner().clone();
        let cancellation = context.cancellation_handle();
        let control = Arc::clone(&context.control);
        let poisoner = std::thread::spawn(move || {
            let _transition = control
                .transition
                .lock()
                .expect("fresh transition gate is available");
            panic!("controlled transition poison");
        });
        assert!(poisoner.join().is_err());

        assert_eq!(
            cancellation.request(&owner),
            CancellationRequestResult::Closed
        );
        assert_eq!(
            context.emit(
                OperationStage::DiagnosticRunning,
                0.1,
                "operations.selfTest.running",
            ),
            Err(OperationIssue::EventInvariant)
        );
    }
}
