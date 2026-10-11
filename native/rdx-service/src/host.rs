// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Host-owned device revalidation, reconnect, timing, and deterministic fixtures.

#[cfg(any(test, feature = "fixtures"))]
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Arc;
#[cfg(any(test, feature = "fixtures"))]
use std::sync::{Barrier, Mutex};

use crate::firmware::{
    FirmwareImage, FirmwareImageError, FirmwareRevision, InstallableFirmwareImage, ProductFamily,
};
use crate::model::{DeviceIdentity, SafeJsonInteger};
#[cfg(any(test, feature = "fixtures"))]
use crate::protocol::DataDirection;
use crate::protocol::{Command, led_test};
#[cfg(any(test, feature = "fixtures"))]
use crate::transport::TransportResponse;
use crate::transport::{CommandDispatch, TransportError};

/// Current physical interface family established by trusted discovery.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeviceInterface {
    /// USB 3 generation RDX dock.
    Usb3,
    /// SATA III generation RDX dock.
    Sata3,
    /// Legacy USB 2 or SATA I product.
    Legacy,
}

/// Sanitized host-operation failure with no path, command, or native message.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostOperationError {
    /// The selected device is not currently discoverable.
    DeviceUnavailable,
    /// The bounded reconnect attempt limit expired.
    ReconnectTimeout,
    /// A required platform capability is unavailable.
    CapabilityUnavailable,
    /// The host cannot prove whether a requested action completed.
    Ambiguous,
    /// Fresh evidence identified a different device or discovery revision.
    DeviceIdentityChanged,
    /// Reconnect evidence identified a different product family.
    ProductFamilyChanged,
    /// Reconnect evidence did not advance the session generation.
    StaleSessionGeneration,
    /// No command-capable lease is currently active.
    InactiveSession,
    /// A platform adapter panicked and was contained at the session boundary.
    AdapterPanic,
    /// A prior LED operation still owns mandatory exact-lease recovery.
    RecoveryAlreadyArmed,
}

impl HostOperationError {
    /// Reports whether host completion is unknown rather than a definite failure.
    #[must_use]
    pub const fn is_ambiguous(self) -> bool {
        matches!(
            self,
            Self::Ambiguous | Self::ReconnectTimeout | Self::AdapterPanic
        )
    }
}

/// Fresh live-session firmware authorization failure.
#[derive(Debug)]
pub enum FirmwareAuthorizationError {
    /// Fresh exact-device revalidation failed.
    Host(HostOperationError),
    /// Image metadata and the live session belong to different product families.
    ProductFamilyMismatch,
    /// Firmware update requires an empty drive.
    MediaPresent,
    /// Installed-revision authorization policy rejected the image.
    Image(FirmwareImageError),
}

/// Positive generation token owned by one exact command-capable device lease.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct SessionGeneration(SafeJsonInteger);

impl SessionGeneration {
    /// Creates a positive generation representable exactly by JavaScript.
    ///
    /// # Errors
    ///
    /// Returns an error for zero or a value outside the safe-integer range.
    pub fn new(value: u64) -> Result<Self, &'static str> {
        if value == 0 {
            return Err("session generation must be positive");
        }
        SafeJsonInteger::new(value).map(Self)
    }

    /// Returns the exact positive generation token.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0.get()
    }
}

/// Private, service-issued lineage shared only by leases from one opened session.
///
/// Pointer identity is intentional: renderer-visible metadata and predictable
/// generation values can never manufacture or substitute this capability.
#[derive(Clone)]
pub(crate) struct SessionCapabilityId(Arc<SessionCapabilityMarker>);

#[derive(Debug)]
struct SessionCapabilityMarker;

impl SessionCapabilityId {
    /// Issues one fresh unforgeable capability for a newly opened session.
    #[cfg(any(test, feature = "fixtures"))]
    fn issue() -> Self {
        Self(Arc::new(SessionCapabilityMarker))
    }
}

impl std::fmt::Debug for SessionCapabilityId {
    /// Redacts the private capability from logs and diagnostics.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("SessionCapabilityId(<private>)")
    }
}

impl PartialEq for SessionCapabilityId {
    /// Compares the allocation identity rather than the marker value.
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

impl Eq for SessionCapabilityId {}

/// Complete path-free evidence bound to one command-capable device session.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionDevice {
    identity: DeviceIdentity,
    product_family: ProductFamily,
    installed_revision: FirmwareRevision,
    interface: DeviceInterface,
    media_present: bool,
    generation: SessionGeneration,
}

impl SessionDevice {
    /// Creates one deterministic fixture session snapshot.
    ///
    /// This constructor exists only for the crate's own unit tests or when the
    /// explicit `fixtures` feature is enabled. Production adapters issue
    /// sessions through their service-owned binding path instead.
    #[cfg(any(test, feature = "fixtures"))]
    #[must_use]
    pub fn fixture(
        identity: DeviceIdentity,
        product_family: ProductFamily,
        installed_revision: FirmwareRevision,
        interface: DeviceInterface,
        media_present: bool,
        generation: SessionGeneration,
    ) -> Self {
        Self {
            identity,
            product_family,
            installed_revision,
            interface,
            media_present,
            generation,
        }
    }

    /// Returns the exact opaque device ID and discovery revision.
    #[must_use]
    pub const fn identity(&self) -> &DeviceIdentity {
        &self.identity
    }

    /// Returns the trusted product family bound to this session.
    #[must_use]
    pub const fn product_family(&self) -> ProductFamily {
        self.product_family
    }

    /// Returns the freshly reported installed firmware revision.
    #[must_use]
    pub const fn installed_revision(&self) -> FirmwareRevision {
        self.installed_revision
    }

    /// Returns the trusted physical interface family.
    #[must_use]
    pub const fn interface(&self) -> DeviceInterface {
        self.interface
    }

    /// Reports whether media was present in the fresh snapshot.
    #[must_use]
    pub const fn media_present(&self) -> bool {
        self.media_present
    }

    /// Returns the exact command-session generation token.
    #[must_use]
    pub const fn generation(&self) -> SessionGeneration {
        self.generation
    }
}

/// Host-side discovery capabilities that belong to the same device adapter.
trait SessionHost: Send {
    /// Returns fresh evidence for the currently active exact lease.
    fn revalidate(&mut self, current: &SessionDevice) -> Result<SessionDevice, HostOperationError>;

    /// Waits boundedly for a replacement lease after invalidating `current`.
    fn reconnect(
        &mut self,
        current: &SessionDevice,
        attempts: u8,
    ) -> Result<SessionDevice, HostOperationError>;

    /// Dispatches one internal command to the exact supplied lease.
    fn dispatch(&mut self, lease: &SessionDevice, command: &Command) -> CommandDispatch;

    /// Waits for the application-owned visible LED phase.
    fn wait_for_led_phase(&mut self, lease: &SessionDevice) -> Result<(), HostOperationError>;
}

/// Non-cloneable command-session owner binding host evidence to one adapter.
pub struct DeviceSession {
    backend: Box<dyn SessionHost>,
    device: SessionDevice,
    capability_id: SessionCapabilityId,
    active: bool,
    recovery_lease_available: bool,
    led_recovery: Option<RecoveryLease>,
}

/// Private exact-lease recovery capability retained before a risky dispatch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RecoveryLease {
    device: SessionDevice,
    capability_id: SessionCapabilityId,
}

impl std::fmt::Debug for DeviceSession {
    /// Formats only safe session evidence and never adapter internals.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DeviceSession")
            .field("device", &self.device)
            .field("active", &self.active)
            .field("led_recovery_armed", &self.led_recovery.is_some())
            .finish_non_exhaustive()
    }
}

impl DeviceSession {
    /// Returns the last exact path-free binding, including when invalidated.
    #[must_use]
    pub const fn device(&self) -> &SessionDevice {
        &self.device
    }

    /// Reports whether this lease may execute internal commands.
    #[must_use]
    pub const fn is_active(&self) -> bool {
        self.active
    }

    /// Returns the private session lineage for trusted operation bindings only.
    pub(crate) fn capability_id(&self) -> &SessionCapabilityId {
        &self.capability_id
    }

    /// Reports whether a trusted binding belongs to this exact session lineage.
    pub(crate) fn has_capability(&self, capability_id: &SessionCapabilityId) -> bool {
        self.capability_id == *capability_id
    }

    /// Revalidates the exact current ID, revision, family, and generation.
    ///
    /// A mismatch or contained adapter panic invalidates the lease.
    ///
    /// # Errors
    ///
    /// Returns sanitized host evidence when fresh exact binding cannot be proven.
    pub fn revalidate(&mut self) -> Result<(), HostOperationError> {
        if !self.active {
            return Err(HostOperationError::InactiveSession);
        }
        let result = match catch_unwind(AssertUnwindSafe(|| self.backend.revalidate(&self.device)))
        {
            Ok(result) => result,
            Err(_) => {
                self.active = false;
                return Err(HostOperationError::AdapterPanic);
            }
        };
        let fresh = match result {
            Ok(fresh) => fresh,
            Err(error) => {
                self.active = false;
                return Err(error);
            }
        };
        if fresh.identity != self.device.identity {
            self.active = false;
            return Err(HostOperationError::DeviceIdentityChanged);
        }
        if fresh.product_family != self.device.product_family {
            self.active = false;
            return Err(HostOperationError::ProductFamilyChanged);
        }
        if fresh.generation != self.device.generation {
            self.active = false;
            return Err(HostOperationError::StaleSessionGeneration);
        }
        self.device = fresh;
        Ok(())
    }

    /// Invalidates the current lease and rebinds only a fresh same-device session.
    ///
    /// # Errors
    ///
    /// Returns sanitized reconnect, identity, family, generation, or adapter evidence.
    pub fn reconnect(&mut self, attempts: u8) -> Result<(), HostOperationError> {
        if self.led_recovery.is_some() {
            return Err(HostOperationError::RecoveryAlreadyArmed);
        }
        let previous = self.device.clone();
        self.active = false;
        self.recovery_lease_available = false;
        let result = catch_unwind(AssertUnwindSafe(|| {
            self.backend.reconnect(&previous, attempts)
        }))
        .map_err(|_| HostOperationError::AdapterPanic)?;
        let fresh = result?;
        if fresh.identity.id != previous.identity.id
            || fresh.identity.revision < previous.identity.revision
        {
            return Err(HostOperationError::DeviceIdentityChanged);
        }
        if fresh.product_family != previous.product_family {
            return Err(HostOperationError::ProductFamilyChanged);
        }
        if fresh.generation <= previous.generation {
            return Err(HostOperationError::StaleSessionGeneration);
        }
        self.device = fresh;
        self.active = true;
        self.recovery_lease_available = true;
        Ok(())
    }

    /// Freshly validates and consumes an image into an exact-session authorization.
    ///
    /// # Errors
    ///
    /// Returns structured host, family, media, or installed-revision policy evidence.
    pub fn authorize_firmware(
        &mut self,
        image: FirmwareImage,
    ) -> Result<InstallableFirmwareImage, FirmwareAuthorizationError> {
        self.revalidate()
            .map_err(FirmwareAuthorizationError::Host)?;
        if image.product() != self.device.product_family() {
            return Err(FirmwareAuthorizationError::ProductFamilyMismatch);
        }
        if self.device.media_present() {
            return Err(FirmwareAuthorizationError::MediaPresent);
        }
        image
            .authorize_for_session(
                self.device.installed_revision(),
                self.device.identity().clone(),
                self.device.product_family(),
                self.device.generation(),
                self.capability_id.clone(),
            )
            .map_err(FirmwareAuthorizationError::Image)
    }

    /// Executes one evidence-built internal command through the active binding.
    ///
    /// Adapter panics are contained as completion-unknown dispatches. A removal
    /// invalidates normal execution, while recovery may still address a stored
    /// original lease.
    pub(crate) fn execute(&mut self, command: &Command) -> CommandDispatch {
        if !self.active {
            return CommandDispatch::NotSent(TransportError::InactiveSession);
        }
        let lease = self.recovery_lease();
        let outcome = self.dispatch_to_lease(&lease, command);
        if dispatch_poisons_lease(&outcome) {
            self.active = false;
        }
        outcome
    }

    /// Captures the private exact current lease for later bounded recovery.
    pub(crate) fn recovery_lease(&self) -> RecoveryLease {
        RecoveryLease {
            device: self.device.clone(),
            capability_id: self.capability_id.clone(),
        }
    }

    /// Best-effort dispatches only to a retained still-exact recovery lease.
    pub(crate) fn execute_recovery(
        &mut self,
        lease: &RecoveryLease,
        command: &Command,
    ) -> CommandDispatch {
        if !self.recovery_lease_available
            || !self.has_capability(&lease.capability_id)
            || lease.device != self.device
        {
            return CommandDispatch::NotSent(TransportError::InactiveSession);
        }
        let outcome = self.dispatch_to_lease(lease, command);
        if dispatch_poisons_lease(&outcome) {
            self.active = false;
        }
        outcome
    }

    /// Waits for the LED visibility phase through the same identity-bound adapter.
    pub(crate) fn wait_for_led_phase(&mut self) -> Result<(), HostOperationError> {
        if !self.active {
            return Err(HostOperationError::InactiveSession);
        }
        let result = catch_unwind(AssertUnwindSafe(|| {
            self.backend.wait_for_led_phase(&self.device)
        }))
        .unwrap_or(Err(HostOperationError::AdapterPanic));
        if matches!(result, Err(HostOperationError::AdapterPanic)) {
            self.active = false;
        }
        result
    }

    /// Arms recovery against the exact lease that received a possibly-applied LED-on.
    pub(crate) fn arm_led_recovery(&mut self) -> Result<(), HostOperationError> {
        if self.led_recovery.is_some() {
            return Err(HostOperationError::RecoveryAlreadyArmed);
        }
        self.led_recovery = Some(self.recovery_lease());
        Ok(())
    }

    /// Sends LED-off to the stored original lease, or the current lease before LED-on.
    pub(crate) fn restore_led_off(&mut self) -> CommandDispatch {
        let target = self
            .led_recovery
            .clone()
            .unwrap_or_else(|| self.recovery_lease());
        let outcome = self.execute_recovery(&target, &led_test(false));
        if target.device == self.device && dispatch_poisons_lease(&outcome) {
            self.active = false;
        }
        if matches!(outcome, CommandDispatch::Succeeded(_)) {
            self.led_recovery = None;
        }
        outcome
    }

    /// Reports whether graceful shutdown still owes an LED-off recovery command.
    #[must_use]
    pub const fn has_pending_led_recovery(&self) -> bool {
        self.led_recovery.is_some()
    }

    /// Performs one best-effort LED-off attempt for a service-owned recovery guard.
    ///
    /// Returns `None` when no recovery is armed. Failed attempts remain armed so
    /// dropping the service can make one final contained attempt.
    pub fn graceful_shutdown(&mut self) -> Option<CommandDispatch> {
        self.led_recovery.as_ref()?;
        Some(self.restore_led_off())
    }

    /// Dispatches to an exact stored lease while containing adapter panics.
    fn dispatch_to_lease(&mut self, lease: &RecoveryLease, command: &Command) -> CommandDispatch {
        catch_unwind(AssertUnwindSafe(|| {
            self.backend.dispatch(&lease.device, command)
        }))
        .unwrap_or(CommandDispatch::CompletionUnknown(
            TransportError::AdapterPanic,
        ))
    }
}

/// Defines when normal command execution must abandon its exact active lease.
///
/// Completion-unknown can hide a mutation or reset. Adapter panic, removal,
/// and unavailability invalidate transport health even when an adapter labels
/// the command as not sent or definitely rejected. Definite device rejection
/// and a proven pre-send timeout retain the lease.
fn dispatch_poisons_lease(outcome: &CommandDispatch) -> bool {
    matches!(outcome, CommandDispatch::CompletionUnknown(_))
        || matches!(
            outcome.error(),
            Some(
                TransportError::Unavailable
                    | TransportError::DeviceRemoved
                    | TransportError::AdapterPanic
            )
        )
}

impl Drop for DeviceSession {
    /// Makes one contained best-effort recovery attempt before adapter teardown.
    fn drop(&mut self) {
        let _ = self.graceful_shutdown();
    }
}

/// One fixture command record including its exact target lease evidence.
#[cfg(any(test, feature = "fixtures"))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FixtureCommand {
    lease: SessionDevice,
    command: Command,
}

#[cfg(any(test, feature = "fixtures"))]
impl FixtureCommand {
    /// Returns the exact lease targeted by this dispatch.
    #[must_use]
    pub const fn lease(&self) -> &SessionDevice {
        &self.lease
    }

    /// Returns the immutable internal command received by the fixture.
    #[must_use]
    pub const fn command(&self) -> &Command {
        &self.command
    }
}

#[cfg(any(test, feature = "fixtures"))]
#[derive(Debug)]
struct FixtureDeviceState {
    current: SessionDevice,
    refreshes: VecDeque<Result<SessionDevice, HostOperationError>>,
    reconnects: VecDeque<Result<SessionDevice, HostOperationError>>,
    dispatches: VecDeque<CommandDispatch>,
    led_waits: VecDeque<Result<(), HostOperationError>>,
    commands: Vec<FixtureCommand>,
    panic_dispatch_calls: BTreeSet<usize>,
    panic_refresh_calls: BTreeSet<usize>,
    panic_reconnect_calls: BTreeSet<usize>,
    panic_led_wait_calls: BTreeSet<usize>,
    blocked_refresh_calls: BTreeMap<usize, (Arc<Barrier>, Arc<Barrier>)>,
    blocked_dispatch_calls: BTreeMap<usize, (Arc<Barrier>, Arc<Barrier>)>,
    dispatch_failures: BTreeMap<usize, CommandDispatch>,
    offset_failure: Option<(u32, usize, CommandDispatch)>,
    dispatch_count: usize,
    refresh_count: usize,
    reconnect_count: usize,
    led_wait_count: usize,
}

/// Cloneable deterministic control surface for one identity-bound fixture adapter.
#[cfg(any(test, feature = "fixtures"))]
#[derive(Clone, Debug)]
pub struct FixtureDevice {
    state: Arc<Mutex<FixtureDeviceState>>,
}

#[cfg(any(test, feature = "fixtures"))]
impl FixtureDevice {
    /// Creates a fixture whose session and discovery evidence share one state owner.
    #[must_use]
    pub fn new(current: SessionDevice) -> Self {
        Self {
            state: Arc::new(Mutex::new(FixtureDeviceState {
                current,
                refreshes: VecDeque::new(),
                reconnects: VecDeque::new(),
                dispatches: VecDeque::new(),
                led_waits: VecDeque::new(),
                commands: Vec::new(),
                panic_dispatch_calls: BTreeSet::new(),
                panic_refresh_calls: BTreeSet::new(),
                panic_reconnect_calls: BTreeSet::new(),
                panic_led_wait_calls: BTreeSet::new(),
                blocked_refresh_calls: BTreeMap::new(),
                blocked_dispatch_calls: BTreeMap::new(),
                dispatch_failures: BTreeMap::new(),
                offset_failure: None,
                dispatch_count: 0,
                refresh_count: 0,
                reconnect_count: 0,
                led_wait_count: 0,
            })),
        }
    }

    /// Opens a non-cloneable active session bound to this exact fixture backend.
    #[must_use]
    pub fn open(&self) -> DeviceSession {
        let current = self
            .state
            .lock()
            .expect("fixture device mutex remains available")
            .current
            .clone();
        DeviceSession {
            backend: Box::new(FixtureSessionHost {
                state: Arc::clone(&self.state),
            }),
            device: current,
            capability_id: SessionCapabilityId::issue(),
            active: true,
            recovery_lease_available: true,
            led_recovery: None,
        }
    }

    /// Queues one exact refresh result.
    pub fn queue_refresh(&self, result: Result<SessionDevice, HostOperationError>) {
        self.state
            .lock()
            .expect("fixture device mutex remains available")
            .refreshes
            .push_back(result);
    }

    /// Queues one exact reconnect result.
    pub fn queue_reconnect(&self, result: Result<SessionDevice, HostOperationError>) {
        self.state
            .lock()
            .expect("fixture device mutex remains available")
            .reconnects
            .push_back(result);
    }

    /// Queues one exact command-dispatch outcome.
    pub fn queue_dispatch(&self, outcome: CommandDispatch) {
        self.state
            .lock()
            .expect("fixture device mutex remains available")
            .dispatches
            .push_back(outcome);
    }

    /// Queues one exact LED visibility-wait result.
    pub fn queue_led_wait(&self, result: Result<(), HostOperationError>) {
        self.state
            .lock()
            .expect("fixture device mutex remains available")
            .led_waits
            .push_back(result);
    }

    /// Configures one one-based dispatch call to panic after recording the command.
    pub fn panic_on_dispatch_call(&self, call: usize) {
        assert!(call > 0, "fixture call numbers are one-based");
        self.state
            .lock()
            .expect("fixture device mutex remains available")
            .panic_dispatch_calls
            .insert(call);
    }

    /// Configures one one-based refresh call to panic outside the fixture lock.
    pub fn panic_on_refresh_call(&self, call: usize) {
        assert!(call > 0, "fixture call numbers are one-based");
        self.state
            .lock()
            .expect("fixture device mutex remains available")
            .panic_refresh_calls
            .insert(call);
    }

    /// Configures one one-based reconnect call to panic outside the fixture lock.
    pub fn panic_on_reconnect_call(&self, call: usize) {
        assert!(call > 0, "fixture call numbers are one-based");
        self.state
            .lock()
            .expect("fixture device mutex remains available")
            .panic_reconnect_calls
            .insert(call);
    }

    /// Configures one one-based LED-wait call to panic outside the fixture lock.
    pub fn panic_on_led_wait_call(&self, call: usize) {
        assert!(call > 0, "fixture call numbers are one-based");
        self.state
            .lock()
            .expect("fixture device mutex remains available")
            .panic_led_wait_calls
            .insert(call);
    }

    /// Blocks one dispatch between recording and result delivery for race tests.
    pub fn block_dispatch_call(&self, call: usize, entered: Arc<Barrier>, release: Arc<Barrier>) {
        assert!(call > 0, "fixture call numbers are one-based");
        self.state
            .lock()
            .expect("fixture device mutex remains available")
            .blocked_dispatch_calls
            .insert(call, (entered, release));
    }

    /// Blocks one refresh after call admission and before evidence delivery.
    pub fn block_refresh_call(&self, call: usize, entered: Arc<Barrier>, release: Arc<Barrier>) {
        assert!(call > 0, "fixture call numbers are one-based");
        self.state
            .lock()
            .expect("fixture device mutex remains available")
            .blocked_refresh_calls
            .insert(call, (entered, release));
    }

    /// Configures one exact outcome for a one-based dispatch call number.
    pub fn fail_dispatch_on_call(&self, call: usize, outcome: CommandDispatch) {
        assert!(call > 0, "fixture call numbers are one-based");
        self.state
            .lock()
            .expect("fixture device mutex remains available")
            .dispatch_failures
            .insert(call, outcome);
    }

    /// Configures a bounded number of outcomes for one mode-4 firmware offset.
    pub fn fail_dispatch_at_offset(&self, offset: u32, times: usize, outcome: CommandDispatch) {
        self.state
            .lock()
            .expect("fixture device mutex remains available")
            .offset_failure = Some((offset, times, outcome));
    }

    /// Returns cloned safe command records in exact dispatch order.
    #[must_use]
    pub fn commands(&self) -> Vec<FixtureCommand> {
        self.state
            .lock()
            .expect("fixture device mutex remains available")
            .commands
            .clone()
    }

    /// Returns the number of fresh-revalidation calls made by the session.
    #[must_use]
    pub fn refresh_count(&self) -> usize {
        self.state
            .lock()
            .expect("fixture device mutex remains available")
            .refresh_count
    }

    /// Returns every mode-4 firmware offset in exact dispatch order.
    #[must_use]
    pub fn firmware_offsets(&self) -> Vec<u32> {
        self.commands()
            .iter()
            .filter_map(|call| firmware_data_offset(call.command()))
            .collect()
    }

    /// Returns the number of bounded reconnect attempts made by the session.
    #[must_use]
    pub fn reconnect_count(&self) -> usize {
        self.state
            .lock()
            .expect("fixture device mutex remains available")
            .reconnect_count
    }
}

#[cfg(any(test, feature = "fixtures"))]
#[derive(Debug)]
struct FixtureSessionHost {
    state: Arc<Mutex<FixtureDeviceState>>,
}

#[cfg(any(test, feature = "fixtures"))]
impl SessionHost for FixtureSessionHost {
    /// Returns the queued or current fixture refresh evidence.
    fn revalidate(
        &mut self,
        _current: &SessionDevice,
    ) -> Result<SessionDevice, HostOperationError> {
        let mut state = self
            .state
            .lock()
            .expect("fixture device mutex remains available");
        state.refresh_count += 1;
        let call = state.refresh_count;
        if state.panic_refresh_calls.remove(&call) {
            drop(state);
            panic!("controlled fixture refresh panic");
        }
        if let Some((entered, release)) = state.blocked_refresh_calls.remove(&call) {
            drop(state);
            entered.wait();
            release.wait();
            state = self
                .state
                .lock()
                .expect("fixture device mutex remains available");
        }
        state
            .refreshes
            .pop_front()
            .unwrap_or_else(|| Ok(state.current.clone()))
    }

    /// Returns queued reconnect evidence and adopts it only as fixture current state.
    fn reconnect(
        &mut self,
        _current: &SessionDevice,
        _attempts: u8,
    ) -> Result<SessionDevice, HostOperationError> {
        let mut state = self
            .state
            .lock()
            .expect("fixture device mutex remains available");
        state.reconnect_count += 1;
        let call = state.reconnect_count;
        if state.panic_reconnect_calls.remove(&call) {
            drop(state);
            panic!("controlled fixture reconnect panic");
        }
        let result = state
            .reconnects
            .pop_front()
            .unwrap_or(Err(HostOperationError::ReconnectTimeout));
        if let Ok(device) = &result {
            state.current = device.clone();
        }
        result
    }

    /// Records the exact target lease and returns a queued or deterministic result.
    fn dispatch(&mut self, lease: &SessionDevice, command: &Command) -> CommandDispatch {
        let mut state = self
            .state
            .lock()
            .expect("fixture device mutex remains available");
        state.dispatch_count += 1;
        let call = state.dispatch_count;
        state.commands.push(FixtureCommand {
            lease: lease.clone(),
            command: command.clone(),
        });
        if state.panic_dispatch_calls.remove(&call) {
            drop(state);
            panic!("controlled fixture adapter panic");
        }
        if let Some((entered, release)) = state.blocked_dispatch_calls.remove(&call) {
            drop(state);
            entered.wait();
            release.wait();
            state = self
                .state
                .lock()
                .expect("fixture device mutex remains available");
        }
        if let Some(outcome) = state.dispatch_failures.remove(&call) {
            return outcome;
        }
        if let Some(offset) = firmware_data_offset(command)
            && let Some((failed_offset, remaining, outcome)) = state.offset_failure.as_mut()
            && offset == *failed_offset
            && *remaining > 0
        {
            *remaining -= 1;
            return outcome.clone();
        }
        if let Some(outcome) = state.dispatches.pop_front() {
            return outcome;
        }
        if command.direction() == DataDirection::FromDevice {
            CommandDispatch::NotSent(TransportError::MissingFixtureResponse)
        } else {
            CommandDispatch::Succeeded(TransportResponse::empty())
        }
    }

    /// Returns the queued or successful fixture LED wait result.
    fn wait_for_led_phase(&mut self, _lease: &SessionDevice) -> Result<(), HostOperationError> {
        let mut state = self
            .state
            .lock()
            .expect("fixture device mutex remains available");
        state.led_wait_count += 1;
        let call = state.led_wait_count;
        if state.panic_led_wait_calls.remove(&call) {
            drop(state);
            panic!("controlled fixture LED-wait panic");
        }
        state.led_waits.pop_front().unwrap_or(Ok(()))
    }
}

/// Extracts the absolute offset from an internal mode-4 WRITE BUFFER command.
#[cfg(any(test, feature = "fixtures"))]
fn firmware_data_offset(command: &Command) -> Option<u32> {
    let cdb = command.cdb();
    (cdb.len() == 10 && cdb[0] == 0x3B && cdb[1] == 0x04)
        .then(|| (u32::from(cdb[3]) << 16) | (u32::from(cdb[4]) << 8) | u32::from(cdb[5]))
}
