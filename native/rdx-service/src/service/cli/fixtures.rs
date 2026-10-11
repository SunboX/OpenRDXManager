// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Feature-gated direct-runtime fixtures with real eject state-machine evidence.

use std::collections::{BTreeMap, VecDeque};
use std::ffi::OsString;
use std::io::Write;
use std::sync::{Arc, Barrier, Mutex};
use std::time::Duration;

use crate::firmware::{FirmwareRevision, ProductFamily};
use crate::host::{
    DeviceInterface, FixtureDevice, HostOperationError, SessionDevice, SessionGeneration,
};
use crate::model::{
    Capability, CapabilityState, ConfirmationRequest, ConfirmationToken, DeviceIdentity,
    DeviceSnapshot, DiscoveryRevision, DisplayText, DriveStatus, Media, MediaState,
    MediaStatusDetails, OpaqueId, OperationId, OperationKind, OperationRequest, StatusField,
};
use crate::operations::{
    EjectHost, EjectOutcome, EjectReadback, HostEjectPolicy, OperationCompletion, OperationContext,
    OperationStage, ProgressPublicationError, run_eject_with_progress,
};
use crate::transport::{CommandDispatch, TransportResponse};

use super::{CliExit, DirectOwnership, run_with_factory};
use crate::service::{
    ServiceBackend, ServiceDescriptor, ServiceEventSink, ServicePlatform, ServiceRejection,
};

const FIXTURE_EVENT_TIMEOUT: Duration = Duration::from_millis(100);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TerminalBehavior {
    Complete,
    Missing,
    Crash,
    BareSuccess,
}

#[derive(Debug)]
struct FixtureEjectState {
    unmounts: VecDeque<Result<(), HostOperationError>>,
    dispatches: VecDeque<CommandDispatch>,
    readbacks: VecDeque<Result<EjectReadback, HostOperationError>>,
    unmount_count: usize,
    eject_count: usize,
    readback_count: usize,
    policies: Vec<HostEjectPolicy>,
    block: Option<(Arc<Barrier>, Arc<Barrier>)>,
}

impl Default for FixtureEjectState {
    /// Creates a successful exact-departure fixture.
    fn default() -> Self {
        Self {
            unmounts: VecDeque::new(),
            dispatches: VecDeque::new(),
            readbacks: VecDeque::new(),
            unmount_count: 0,
            eject_count: 0,
            readback_count: 0,
            policies: Vec::new(),
            block: None,
        }
    }
}

#[derive(Clone, Debug)]
struct FixtureEjectHost {
    state: Arc<Mutex<FixtureEjectState>>,
}

impl EjectHost for FixtureEjectHost {
    /// Records one safe-policy unmount and returns its queued host outcome.
    fn unmount(&mut self, _target: &DeviceIdentity) -> Result<(), HostOperationError> {
        let mut state = self
            .state
            .lock()
            .expect("fixture eject mutex remains available");
        state.unmount_count += 1;
        state.unmounts.pop_front().unwrap_or(Ok(()))
    }

    /// Records one typed eject dispatch and optionally blocks for ownership tests.
    fn eject(&mut self, _target: &DeviceIdentity, policy: HostEjectPolicy) -> CommandDispatch {
        let (outcome, block) = {
            let mut state = self
                .state
                .lock()
                .expect("fixture eject mutex remains available");
            state.eject_count += 1;
            state.policies.push(policy);
            (
                state
                    .dispatches
                    .pop_front()
                    .unwrap_or_else(|| CommandDispatch::Succeeded(TransportResponse::empty())),
                state.block.clone(),
            )
        };
        if let Some((entered, release)) = block {
            entered.wait();
            release.wait();
        }
        outcome
    }

    /// Records one mandatory reconciliation and returns its queued observation.
    fn readback(&mut self, target: &DeviceIdentity) -> Result<EjectReadback, HostOperationError> {
        let mut state = self
            .state
            .lock()
            .expect("fixture eject mutex remains available");
        state.readback_count += 1;
        state
            .readbacks
            .pop_front()
            .unwrap_or_else(|| Ok(EjectReadback::Departed(target.clone())))
    }
}

/// Deterministic shared service backend used only by the explicit fixtures feature.
#[derive(Debug)]
pub struct FixtureBackend {
    accesses: usize,
    scan_calls: usize,
    start_calls: usize,
    devices: Vec<DeviceSnapshot>,
    session: FixtureDevice,
    eject_state: Arc<Mutex<FixtureEjectState>>,
    terminal_behavior: TerminalBehavior,
    ownership: Arc<Mutex<()>>,
    pending_confirmation: Option<(ConfirmationRequest, ConfirmationToken)>,
}

impl Default for FixtureBackend {
    /// Creates one media-present device with both eject capabilities available.
    fn default() -> Self {
        Self::new(true, true)
    }
}

impl FixtureBackend {
    /// Creates one internally consistent fixture inventory and exact session.
    fn new(media_present: bool, publish_device: bool) -> Self {
        let identity = DeviceIdentity {
            id: crate::model::DeviceId::new("rdx:fixture").expect("fixture device ID"),
            revision: DiscoveryRevision::new(7).expect("fixture revision"),
        };
        let media = media_present.then(|| Media {
            id: OpaqueId::new("media:fixture").expect("fixture media ID"),
            serial: None,
            label: None,
            capacity_bytes: None,
            used_bytes: None,
            writable: Some(true),
            encrypted: Some(false),
            filesystem: None,
            status: None,
            details: MediaStatusDetails {
                write_protected: StatusField::reported(false),
                encrypted: StatusField::reported(false),
                ..MediaStatusDetails::default()
            },
        });
        let capabilities = BTreeMap::from([
            (
                OperationKind::EjectSafe,
                Capability {
                    state: CapabilityState::Available,
                    reason: None,
                },
            ),
            (
                OperationKind::EjectForce,
                Capability {
                    state: CapabilityState::Available,
                    reason: None,
                },
            ),
        ]);
        let vendor = DisplayText::new("TANDBERG").expect("fixture vendor");
        let product = DisplayText::new("RDX").expect("fixture product");
        let serial = DisplayText::new("FIXTURE1").expect("fixture serial");
        let snapshot = DeviceSnapshot {
            id: identity.id.clone(),
            revision: identity.revision,
            drive: DriveStatus::from_identity(&vendor, &product, &serial),
            vendor,
            product,
            serial,
            media,
            media_state: if media_present {
                MediaState::Present
            } else {
                MediaState::NoMedia
            },
            capabilities,
        };
        let session = FixtureDevice::new(SessionDevice::fixture(
            identity,
            ProductFamily::Usb3Sata3,
            FirmwareRevision::new(282).expect("fixture firmware revision"),
            DeviceInterface::Usb3,
            media_present,
            SessionGeneration::new(1).expect("fixture generation"),
        ));
        Self {
            accesses: 0,
            scan_calls: 0,
            start_calls: 0,
            devices: if publish_device {
                vec![snapshot]
            } else {
                Vec::new()
            },
            session,
            eject_state: Arc::new(Mutex::new(FixtureEjectState::default())),
            terminal_behavior: TerminalBehavior::Complete,
            ownership: Arc::new(Mutex::new(())),
            pending_confirmation: None,
        }
    }

    /// Creates an empty native inventory for direct scan coverage.
    #[must_use]
    pub fn empty_inventory() -> Self {
        Self::new(true, false)
    }

    /// Creates a device whose fresh inventory has no ejectable media.
    #[must_use]
    pub fn without_media() -> Self {
        Self::new(false, true)
    }

    /// Creates a fixture whose post-inventory session revision has changed.
    #[must_use]
    pub fn with_changed_session_revision() -> Self {
        let fixture = Self::default();
        fixture.session.queue_refresh(Ok(SessionDevice::fixture(
            DeviceIdentity {
                id: fixture.devices[0].id.clone(),
                revision: DiscoveryRevision::new(8).expect("changed fixture revision"),
            },
            ProductFamily::Usb3Sata3,
            FirmwareRevision::new(282).expect("fixture firmware revision"),
            DeviceInterface::Usb3,
            true,
            SessionGeneration::new(1).expect("fixture generation"),
        )));
        fixture
    }

    /// Creates a fixture with one fresh force-eject capability state.
    #[must_use]
    pub fn with_force_capability(state: CapabilityState) -> Self {
        let mut fixture = Self::default();
        fixture.devices[0]
            .capabilities
            .get_mut(&OperationKind::EjectForce)
            .expect("fixture force capability")
            .state = state;
        fixture
    }

    /// Creates a fixture whose safe unmount produces one actual host failure.
    #[must_use]
    pub fn with_unmount_failure(error: HostOperationError) -> Self {
        let fixture = Self::default();
        fixture
            .eject_state
            .lock()
            .expect("fixture eject mutex remains available")
            .unmounts
            .push_back(Err(error));
        fixture
    }

    /// Creates a fixture whose eject returns one explicit dispatch outcome.
    #[must_use]
    pub fn with_eject_dispatch(dispatch: CommandDispatch) -> Self {
        let fixture = Self::default();
        fixture
            .eject_state
            .lock()
            .expect("fixture eject mutex remains available")
            .dispatches
            .push_back(dispatch);
        fixture
    }

    /// Makes fresh readback prove that the exact target remains present.
    pub fn keep_target_present(&self) {
        let identity = self.devices[0].identity();
        self.eject_state
            .lock()
            .expect("fixture eject mutex remains available")
            .readbacks
            .push_back(Ok(EjectReadback::Present(identity)));
    }

    /// Queues one host failure for the next mandatory eject readback.
    pub fn fail_next_readback(&self, error: HostOperationError) {
        self.eject_state
            .lock()
            .expect("fixture eject mutex remains available")
            .readbacks
            .push_back(Err(error));
    }

    /// Creates a fixture whose mandatory departure readback fails.
    #[must_use]
    pub fn with_readback_failure(error: HostOperationError) -> Self {
        let fixture = Self::default();
        fixture
            .eject_state
            .lock()
            .expect("fixture eject mutex remains available")
            .readbacks
            .push_back(Err(error));
        fixture
    }

    /// Creates a backend that accepts work but emits no terminal.
    #[must_use]
    pub fn without_terminal() -> Self {
        Self {
            terminal_behavior: TerminalBehavior::Missing,
            ..Self::default()
        }
    }

    /// Creates a backend that reports an unreconciled crash after acceptance.
    #[must_use]
    pub fn with_crash() -> Self {
        Self {
            terminal_behavior: TerminalBehavior::Crash,
            ..Self::default()
        }
    }

    /// Creates a backend that tries to publish success without shared evidence.
    #[must_use]
    pub fn bare_success_without_readback() -> Self {
        Self {
            terminal_behavior: TerminalBehavior::BareSuccess,
            ..Self::default()
        }
    }

    /// Creates a successful fixture that pauses inside the host eject call.
    #[must_use]
    pub fn blocking_eject(entered: Arc<Barrier>, release: Arc<Barrier>) -> Self {
        let fixture = Self::default();
        fixture
            .eject_state
            .lock()
            .expect("fixture eject mutex remains available")
            .block = Some((entered, release));
        fixture
    }

    /// Creates a fixture in the same process-local ownership domain as `other`.
    #[must_use]
    pub fn sharing_ownership(other: &Self) -> Self {
        Self {
            ownership: Arc::clone(&other.ownership),
            ..Self::default()
        }
    }

    /// Returns how often command execution instantiated this backend.
    #[must_use]
    pub const fn access_count(&self) -> usize {
        self.accesses
    }

    /// Returns how often the shared discovery refresh ran.
    #[must_use]
    pub const fn scan_count(&self) -> usize {
        self.scan_calls
    }

    /// Returns how often shared operation admission reached the backend.
    #[must_use]
    pub const fn start_count(&self) -> usize {
        self.start_calls
    }

    /// Returns how often exact-session fresh revalidation ran.
    #[must_use]
    pub fn refresh_count(&self) -> usize {
        self.session.refresh_count()
    }

    /// Returns how often safe unmount ran.
    #[must_use]
    pub fn unmount_count(&self) -> usize {
        self.eject_state
            .lock()
            .expect("fixture eject mutex remains available")
            .unmount_count
    }

    /// Returns how often typed host eject ran.
    #[must_use]
    pub fn eject_count(&self) -> usize {
        self.eject_state
            .lock()
            .expect("fixture eject mutex remains available")
            .eject_count
    }

    /// Returns how often exact departure readback ran.
    #[must_use]
    pub fn readback_count(&self) -> usize {
        self.eject_state
            .lock()
            .expect("fixture eject mutex remains available")
            .readback_count
    }

    /// Returns typed host cache policies observed in dispatch order.
    #[must_use]
    pub fn policies(&self) -> Vec<HostEjectPolicy> {
        self.eject_state
            .lock()
            .expect("fixture eject mutex remains available")
            .policies
            .clone()
    }
}

impl ServiceBackend for &mut FixtureBackend {
    /// Reports a native-capable descriptor confined to the fixture feature.
    fn descriptor(&self) -> ServiceDescriptor {
        ServiceDescriptor::native_available(
            ServicePlatform::current().expect("fixture runs on supported host"),
            env!("CARGO_PKG_VERSION"),
        )
        .expect("fixture descriptor is valid")
    }

    /// Returns the fixture's current bounded inventory without refreshing it.
    fn list_devices(&mut self) -> Result<Vec<DeviceSnapshot>, ServiceRejection> {
        Ok(self.devices.clone())
    }

    /// Records and returns one fresh fixture inventory refresh.
    fn scan_devices(&mut self) -> Result<Vec<DeviceSnapshot>, ServiceRejection> {
        self.scan_calls += 1;
        Ok(self.devices.clone())
    }

    /// Issues one fixture-only token through the same exact action matcher as production.
    fn issue_confirmation(
        &mut self,
        request: ConfirmationRequest,
    ) -> Result<ConfirmationToken, ServiceRejection> {
        let token = ConfirmationToken::new("confirm:fixture-service-owned")
            .map_err(|_| ServiceRejection::new("confirmation-unavailable").expect("reason"))?;
        self.pending_confirmation = Some((request, token.clone()));
        Ok(token)
    }

    /// Runs accepted eject work through the shared native operation state machine.
    fn start_operation(
        &mut self,
        operation_id: OperationId,
        request: OperationRequest,
        events: ServiceEventSink,
    ) -> Result<(), ServiceRejection> {
        if let OperationRequest::EjectForce {
            confirmation_token, ..
        } = &request
        {
            let Some((confirmation, issued_token)) = self.pending_confirmation.take() else {
                return Err(ServiceRejection::new("confirmation-required").expect("reason"));
            };
            if &issued_token != confirmation_token || !confirmation.matches_operation(&request) {
                return Err(ServiceRejection::new("confirmation-required").expect("reason"));
            }
        }
        self.start_calls += 1;
        let (kind, policy) = match request {
            OperationRequest::EjectSafe { .. } => (OperationKind::EjectSafe, HostEjectPolicy::Safe),
            OperationRequest::EjectForce { .. } => {
                (OperationKind::EjectForce, HostEjectPolicy::Forced)
            }
            _ => return Err(ServiceRejection::new("unsupported-operation").expect("reason")),
        };
        let mut session = self.session.open();
        let context = OperationContext::for_session(operation_id.clone(), kind, &session)
            .map_err(|_| ServiceRejection::new("session-unavailable").expect("reason"))?;
        events
            .publish_started(context.owner())
            .map_err(|_| ServiceRejection::new("service-event-failure").expect("reason"))?;
        match self.terminal_behavior {
            TerminalBehavior::Missing => return Ok(()),
            TerminalBehavior::Crash => {
                events
                    .report_crash()
                    .map_err(|_| ServiceRejection::new("service-event-failure").expect("reason"))?;
                return Ok(());
            }
            TerminalBehavior::BareSuccess => {
                let mut context = context;
                for (stage, fraction) in [
                    (OperationStage::HostUnmounting, 0.25),
                    (OperationStage::HostEjecting, 0.75),
                    (OperationStage::EjectReadback, 1.0),
                ] {
                    context
                        .emit(stage, fraction, "operations.eject.progress")
                        .expect("fixture progress is valid");
                }
                if events
                    .publish_report(context.complete(OperationCompletion::Succeeded))
                    .is_err()
                {
                    events.report_crash().map_err(|_| {
                        ServiceRejection::new("service-event-failure").expect("reason")
                    })?;
                }
                return Ok(());
            }
            TerminalBehavior::Complete => {}
        }
        let mut host = FixtureEjectHost {
            state: Arc::clone(&self.eject_state),
        };
        let mut progress_publication_failed = false;
        let outcome = run_eject_with_progress(&mut session, context, &mut host, policy, |event| {
            events.publish_progress(event).map_err(|_| {
                progress_publication_failed = true;
                ProgressPublicationError::unavailable()
            })
        });
        if progress_publication_failed {
            events
                .report_crash()
                .map_err(|_| ServiceRejection::new("service-event-failure").expect("reason"))?;
            return Ok(());
        }
        match outcome {
            Ok(EjectOutcome::Succeeded { report, departure }) => events
                .publish_eject_success(report, departure)
                .map_err(|_| ServiceRejection::new("service-event-failure").expect("reason")),
            Ok(EjectOutcome::Cancelled { report }) => events
                .publish_report(report)
                .map_err(|_| ServiceRejection::new("service-event-failure").expect("reason")),
            Err(failure) => events
                .publish_failure(failure)
                .map_err(|_| ServiceRejection::new("service-event-failure").expect("reason")),
        }
    }

    /// Rejects cancellation because the synchronous CLI fixture exposes no owner handle.
    fn cancel_operation(&mut self, _operation_id: &OperationId) -> Result<(), ServiceRejection> {
        Err(ServiceRejection::new("operation-not-cancellable").expect("reason"))
    }

    /// Completes fixture shutdown without external resources.
    fn shutdown(&mut self) -> Result<(), ServiceRejection> {
        Ok(())
    }
}

/// Runs production parsing/output with an explicit shared service fixture.
///
/// The fixture is available only with `fixtures` and cannot be selected through
/// arguments, environment variables, files, or the production binary.
pub fn run_with_fixture<I, S, W, E>(
    arguments: I,
    backend: &mut FixtureBackend,
    stdout: &mut W,
    stderr: &mut E,
) -> CliExit
where
    I: IntoIterator<Item = S>,
    S: Into<OsString>,
    W: Write,
    E: Write,
{
    let ownership = DirectOwnership::ProcessLocalFixture(Arc::clone(&backend.ownership));
    run_with_factory(
        arguments,
        stdout,
        stderr,
        || {
            backend.accesses += 1;
            Ok(backend)
        },
        ownership,
        FIXTURE_EVENT_TIMEOUT,
    )
}
