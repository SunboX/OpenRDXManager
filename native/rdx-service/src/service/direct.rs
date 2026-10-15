// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Direct high-level service runtime used by non-framed trusted clients.

use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
#[cfg(any(feature = "fixtures", test))]
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::error::RdxError;
use crate::model::{ConfirmationRequest, OperationId, OperationRequest};
use crate::model::{DeviceId, DeviceSnapshot};
use crate::operations::{HostEjectPolicy, HostOperationFailure, OperationFailure};

use super::crash::CrashAdmission;
use super::events::{ServiceOperationSignal, eject_departure_matches};
use super::{
    HardwareServiceBackend, MAX_PENDING_SERVICE_EVENTS, OperationAdmission, ServiceBackend,
    ServiceDescriptor, ServiceEventSink, ServiceMode, ServiceProtocolError, ServiceRejection,
    ServiceRuntime, service_rejection,
};

#[cfg(target_os = "linux")]
type CurrentPlatformBackend = crate::platform::linux::LinuxBackend;
#[cfg(target_os = "macos")]
type CurrentPlatformBackend = crate::platform::macos::MacOsBackend;
#[cfg(windows)]
type CurrentPlatformBackend = crate::platform::windows::WindowsBackend;
#[cfg(target_os = "linux")]
type CurrentHardwareOwnershipGuard = rdx_linux_native::HardwareOwnershipGuard;
#[cfg(target_os = "macos")]
type CurrentHardwareOwnershipGuard = rdx_macos_native::HardwareOwnershipGuard;
#[cfg(windows)]
type CurrentHardwareOwnershipGuard = rdx_windows_native::HardwareOwnershipGuard;
#[cfg(target_os = "linux")]
type CurrentNativeError = rdx_linux_native::NativeError;
#[cfg(target_os = "macos")]
type CurrentNativeError = rdx_macos_native::NativeError;
#[cfg(windows)]
type CurrentNativeError = rdx_windows_native::NativeError;

/// Ownership capability available to one direct service runtime.
#[derive(Clone, Debug)]
pub(super) enum DirectOwnership {
    /// Acquires the installed operating-system ownership boundary.
    ProcessGlobal,
    /// Explicit missing ownership used to prove fail-closed ordering.
    #[cfg(test)]
    Unavailable,
    /// Feature-gated fixture arbitration within this one test process.
    #[cfg(feature = "fixtures")]
    ProcessLocalFixture(Arc<Mutex<()>>),
    /// Non-feature test owner proving acquisition precedes backend construction.
    #[cfg(test)]
    ProcessLocalTest(Arc<Mutex<()>>),
}

/// Retained ownership whose lifetime encloses one complete direct backend.
#[derive(Debug)]
pub(super) struct DirectOwnershipGuard<'owner> {
    _process_global: Option<CurrentHardwareOwnershipGuard>,
    #[cfg(any(feature = "fixtures", test))]
    _process_local: Option<std::sync::MutexGuard<'owner, ()>>,
    _lifetime: std::marker::PhantomData<&'owner ()>,
}

/// Typed direct-runtime failure preserving the layer that produced it.
#[derive(Debug)]
pub(super) enum DirectFailure {
    /// The immutable backend descriptor rejects hardware access.
    Capability {
        code: &'static str,
        reason: Option<&'static str>,
    },
    /// Shared admission or backend preflight rejected before dispatch.
    Rejected(ServiceRejection),
    /// Service, inventory, or local runtime contract failed before dispatch.
    Service(ServiceProtocolError),
    /// A graph-valid terminal retained actual native operation evidence.
    Operation {
        error: Box<RdxError>,
        failure: Box<OperationFailure>,
    },
    /// A service-owned host state machine retained its native stage certainty.
    HostOperation {
        error: Box<RdxError>,
        failure: HostOperationFailure,
    },
    /// Accepted work lost its terminal or violated lifecycle ownership.
    Ambiguous(&'static str),
}

/// One direct service generation around the same backend and lifecycle as framing.
pub(super) struct DirectService<B> {
    runtime: ServiceRuntime<B>,
    events: Receiver<Box<ServiceOperationSignal>>,
    crashes: CrashAdmission,
}

impl<B: ServiceBackend> DirectService<B> {
    /// Creates one direct runtime with the same bounded event and crash channels.
    pub(super) fn new(backend: B) -> Self {
        let (event_sender, events) =
            mpsc::sync_channel::<Box<ServiceOperationSignal>>(MAX_PENDING_SERVICE_EVENTS);
        let crashes = CrashAdmission::new();
        let event_sink = ServiceEventSink::new(event_sender, crashes.clone());
        Self {
            runtime: ServiceRuntime::new(backend, event_sink),
            events,
            crashes,
        }
    }

    /// Performs one shared bounded discovery refresh and returns its full inventory.
    pub(super) fn scan(&mut self) -> Result<Vec<DeviceSnapshot>, DirectFailure> {
        match self
            .runtime
            .refresh_inventory()
            .map_err(DirectFailure::Service)?
        {
            Ok(()) => Ok(self.runtime.devices.clone()),
            Err(error) => Err(DirectFailure::Rejected(error)),
        }
    }

    /// Runs one typed eject through shared admission and lifecycle validation.
    pub(super) fn eject(
        &mut self,
        target: &DeviceId,
        policy: HostEjectPolicy,
        event_timeout: Duration,
    ) -> Result<(), DirectFailure> {
        if self.runtime.descriptor.mode == ServiceMode::NoDevice
            || self.runtime.descriptor.capability_state != "available"
        {
            return Err(descriptor_failure(&self.runtime.descriptor));
        }
        let devices = self.scan()?;
        let Some(device) = devices.iter().find(|device| &device.id == target) else {
            return Err(DirectFailure::Rejected(service_rejection(
                "device-not-found",
            )));
        };
        let request = match policy {
            HostEjectPolicy::Safe => OperationRequest::EjectSafe {
                device_id: device.id.clone(),
                device_revision: device.revision,
            },
            HostEjectPolicy::Forced => OperationRequest::EjectForce {
                device_id: device.id.clone(),
                device_revision: device.revision,
                confirmation_token: self
                    .runtime
                    .backend
                    .issue_confirmation(ConfirmationRequest::EjectForce {
                        device_id: device.id.clone(),
                        device_revision: device.revision,
                    })
                    .map_err(DirectFailure::Rejected)?,
            },
        };
        let operation_id =
            OperationId::new("op:rdxctl-eject").expect("trusted CLI operation identifier is valid");
        let deadline = Instant::now()
            .checked_add(event_timeout)
            .ok_or(DirectFailure::Ambiguous("operation-deadline-overflow"))?;
        match self
            .runtime
            .admit_operation(operation_id, request)
            .map_err(DirectFailure::Service)?
        {
            OperationAdmission::Accepted => {
                self.runtime
                    .release_prepared_operation()
                    .map_err(DirectFailure::Service)?;
                self.await_terminal_until(deadline)
            }
            OperationAdmission::Rejected(error) => Err(DirectFailure::Rejected(error)),
        }
    }

    /// Awaits one exact terminal against one operation-wide absolute deadline.
    fn await_terminal_until(&mut self, deadline: Instant) -> Result<(), DirectFailure> {
        self.await_terminal_until_with_clock(deadline, Instant::now)
    }

    /// Awaits a terminal using an injected monotonic clock for deterministic refill tests.
    fn await_terminal_until_with_clock<F>(
        &mut self,
        deadline: Instant,
        mut now: F,
    ) -> Result<(), DirectFailure>
    where
        F: FnMut() -> Instant,
    {
        loop {
            if self.crashes.observe().is_err() {
                return Err(DirectFailure::Ambiguous("backend-crash"));
            }
            let observed_at = now();
            if observed_at >= deadline {
                return Err(DirectFailure::Ambiguous("operation-deadline-exceeded"));
            }
            let signal = match self
                .events
                .recv_timeout(deadline.saturating_duration_since(observed_at))
            {
                Ok(signal) => signal,
                Err(RecvTimeoutError::Timeout | RecvTimeoutError::Disconnected) => {
                    return Err(DirectFailure::Ambiguous("missing-operation-terminal"));
                }
            };
            let ServiceOperationSignal {
                publication_sequence,
                event,
                failure,
                host_failure,
                host_operation,
                eject_departure,
                inventory_update: _,
            } = *signal;
            let terminal_event = event.clone();
            let verified_departure = eject_departure
                .as_ref()
                .is_some_and(|departure| eject_departure_matches(&terminal_event, departure));
            if self
                .runtime
                .handle_event_at_publication(event, Some(publication_sequence), now())
                .is_err()
            {
                return Err(DirectFailure::Ambiguous("invalid-operation-lifecycle"));
            }
            match terminal_event {
                crate::model::OperationEvent::Succeeded { .. }
                    if verified_departure || host_operation =>
                {
                    return Ok(());
                }
                crate::model::OperationEvent::Succeeded { .. } => {
                    return Err(DirectFailure::Ambiguous("missing-departure-evidence"));
                }
                crate::model::OperationEvent::Failed { error, .. } => {
                    if let Some(host_failure) = host_failure {
                        return Err(DirectFailure::HostOperation {
                            error: Box::new(error),
                            failure: host_failure,
                        });
                    }
                    let Some(failure) = failure else {
                        return Err(DirectFailure::Ambiguous("missing-terminal-evidence"));
                    };
                    return Err(DirectFailure::Operation {
                        error: Box::new(error),
                        failure: Box::new(failure),
                    });
                }
                crate::model::OperationEvent::Cancelled { .. } => {
                    return Err(DirectFailure::Ambiguous("unexpected-cancellation"));
                }
                crate::model::OperationEvent::Queued { .. }
                | crate::model::OperationEvent::Started { .. }
                | crate::model::OperationEvent::Progress { .. } => {}
            }
        }
    }
}

/// Acquires one native or test ownership domain without waiting.
pub(super) fn acquire_direct_ownership(
    ownership: &DirectOwnership,
) -> Result<DirectOwnershipGuard<'_>, DirectFailure> {
    match ownership {
        DirectOwnership::ProcessGlobal => acquire_current_hardware_ownership()
            .map(|guard| DirectOwnershipGuard {
                _process_global: Some(guard),
                #[cfg(any(feature = "fixtures", test))]
                _process_local: None,
                _lifetime: std::marker::PhantomData,
            })
            .map_err(map_ownership_failure),
        #[cfg(test)]
        DirectOwnership::Unavailable => Err(DirectFailure::Rejected(service_rejection(
            "exclusive-ownership-unavailable",
        ))),
        #[cfg(feature = "fixtures")]
        DirectOwnership::ProcessLocalFixture(owner) => owner
            .try_lock()
            .map(|guard| DirectOwnershipGuard {
                _process_global: None,
                _process_local: Some(guard),
                _lifetime: std::marker::PhantomData,
            })
            .map_err(|error| match error {
                std::sync::TryLockError::WouldBlock => {
                    DirectFailure::Rejected(service_rejection("operation-in-progress"))
                }
                std::sync::TryLockError::Poisoned(_) => {
                    DirectFailure::Service(ServiceProtocolError::BackendContract)
                }
            }),
        #[cfg(test)]
        DirectOwnership::ProcessLocalTest(owner) => owner
            .try_lock()
            .map(|guard| DirectOwnershipGuard {
                _process_global: None,
                _process_local: Some(guard),
                _lifetime: std::marker::PhantomData,
            })
            .map_err(|error| match error {
                std::sync::TryLockError::WouldBlock => {
                    DirectFailure::Rejected(service_rejection("operation-in-progress"))
                }
                std::sync::TryLockError::Poisoned(_) => {
                    DirectFailure::Service(ServiceProtocolError::BackendContract)
                }
            }),
    }
}

/// Acquires the current platform's one fixed production ownership boundary.
fn acquire_current_hardware_ownership() -> Result<CurrentHardwareOwnershipGuard, CurrentNativeError>
{
    #[cfg(target_os = "linux")]
    {
        rdx_linux_native::try_acquire_hardware_ownership()
    }
    #[cfg(target_os = "macos")]
    {
        rdx_macos_native::try_acquire_hardware_ownership()
    }
    #[cfg(windows)]
    {
        rdx_windows_native::try_acquire_hardware_ownership()
    }
}

/// Converts native ownership evidence without exposing paths or kernel text.
fn map_ownership_failure(error: CurrentNativeError) -> DirectFailure {
    match error {
        CurrentNativeError::Busy => {
            DirectFailure::Rejected(service_rejection("operation-in-progress"))
        }
        CurrentNativeError::AccessDenied => DirectFailure::Capability {
            code: "insufficient-permission",
            reason: Some("privileged-service-unavailable"),
        },
        _ => DirectFailure::Rejected(service_rejection("exclusive-ownership-unavailable")),
    }
}

/// Returns the exact honest no-device descriptor failure.
fn descriptor_failure(descriptor: &ServiceDescriptor) -> DirectFailure {
    DirectFailure::Capability {
        code: descriptor.capability_state,
        reason: descriptor.capability_reason,
    }
}

/// Creates the current registry-owning production direct hardware backend.
pub(super) fn current_hardware_backend()
-> Result<HardwareServiceBackend<CurrentPlatformBackend>, ServiceProtocolError> {
    let platform = super::ServicePlatform::current()?;
    #[cfg(target_os = "linux")]
    let backend = crate::platform::linux::LinuxBackend::native_with_context(
        super::ServiceExecutionContext::privileged_direct_cli(
            rdx_linux_native::current_process_is_privileged_service(),
        ),
    );
    #[cfg(target_os = "macos")]
    let backend = {
        let authorized = rdx_macos_native::current_process_is_privileged_service();
        let context = super::ServiceExecutionContext::privileged_direct_cli(authorized);
        let context = if authorized {
            context.with_macos_direct_worker_factory(
                rdx_macos_native::MacDirectWorkerFactory::for_current_privileged_process()
                    .map_err(|_| ServiceProtocolError::BackendContract)?,
            )
        } else {
            context
        };
        crate::platform::macos::MacOsBackend::native_with_context(context)
    };
    #[cfg(windows)]
    let backend = crate::platform::windows::WindowsBackend::native_with_context(
        super::ServiceExecutionContext::privileged_direct_cli(
            rdx_windows_native::current_process_is_elevated(),
        ),
    );
    Ok(HardwareServiceBackend::new(platform, backend))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::mpsc;
    use std::thread;
    use std::time::{Duration, Instant};

    use crate::model::{
        CancellationState, DeviceId, DiscoveryRevision, OperationEvent, OperationId, OperationKind,
        OperationRequest, Progress, ReasonCode,
    };

    use super::{DirectFailure, DirectService};
    use crate::service::crash::CrashAdmission;
    use crate::service::events::{ServiceEventSink, ServiceOperationSignal};
    use crate::service::{
        ActiveOperation, MAX_PENDING_SERVICE_EVENTS, NoDeviceBackend, ServicePlatform,
        ServiceRuntime,
    };

    /// Creates one replayable valid progress signal for the direct deadline test.
    fn progress_signal(
        operation_id: &OperationId,
        device_id: &DeviceId,
        device_revision: DiscoveryRevision,
    ) -> Box<ServiceOperationSignal> {
        Box::new(ServiceOperationSignal {
            publication_sequence: 0,
            event: OperationEvent::Progress {
                operation_id: operation_id.clone(),
                kind: OperationKind::SelfTest,
                device_id: device_id.clone(),
                device_revision,
                stage: ReasonCode::new("diagnostic-running").unwrap(),
                progress: Progress::new(0.1).unwrap(),
                attempt: None,
                cancellation_state: CancellationState::Cancellable,
                message_key: None,
            },
            failure: None,
            host_failure: None,
            host_operation: false,
            eject_departure: None,
            inventory_update: None,
        })
    }

    /// Proves a continuously refilling producer cannot reset the direct deadline.
    #[test]
    fn continuously_refilling_events_do_not_reset_absolute_deadline() {
        let (sender, events) = mpsc::sync_channel(MAX_PENDING_SERVICE_EVENTS);
        let crashes = CrashAdmission::new();
        let sink = ServiceEventSink::new(sender.clone(), crashes.clone());
        let mut runtime = ServiceRuntime::new(NoDeviceBackend::new(ServicePlatform::Darwin), sink);
        let operation_id = OperationId::new("op:deadline").unwrap();
        let device_id = DeviceId::new("rdx:deadline").unwrap();
        let device_revision = DiscoveryRevision::new(1).unwrap();
        let started_at = Instant::now();
        let deadline = started_at + Duration::from_secs(10);
        let request = OperationRequest::SelfTest {
            device_id: device_id.clone(),
            device_revision,
        };
        runtime.active =
            Some(ActiveOperation::new_at(operation_id.clone(), &request, started_at).unwrap());
        runtime
            .handle_event(OperationEvent::Started {
                operation_id: operation_id.clone(),
                kind: OperationKind::SelfTest,
                device_id: device_id.clone(),
                device_revision,
                stage: ReasonCode::new("diagnostic-running").unwrap(),
                message_key: None,
            })
            .unwrap();
        for _ in 0..MAX_PENDING_SERVICE_EVENTS {
            sender
                .try_send(progress_signal(&operation_id, &device_id, device_revision))
                .unwrap();
        }
        let mut service = DirectService {
            runtime,
            events,
            crashes,
        };
        let stop = Arc::new(AtomicBool::new(false));
        let producer_stop = Arc::clone(&stop);
        let refilled = Arc::new(AtomicBool::new(false));
        let producer_refilled = Arc::clone(&refilled);
        let producer_sender = sender.clone();
        let producer_operation_id = operation_id.clone();
        let producer_device_id = device_id.clone();
        let producer = thread::spawn(move || {
            while !producer_stop.load(Ordering::Acquire) {
                if producer_sender
                    .try_send(progress_signal(
                        &producer_operation_id,
                        &producer_device_id,
                        device_revision,
                    ))
                    .is_ok()
                {
                    producer_refilled.store(true, Ordering::Release);
                    return true;
                }
                thread::yield_now();
            }
            false
        });
        let mut clock_calls = 0;
        let result = service.await_terminal_until_with_clock(deadline, || {
            clock_calls += 1;
            if clock_calls == 1 {
                started_at
            } else {
                while !refilled.load(Ordering::Acquire) {
                    thread::yield_now();
                }
                deadline
            }
        });
        stop.store(true, Ordering::Release);
        assert!(producer.join().unwrap());

        assert!(matches!(
            result,
            Err(DirectFailure::Ambiguous("operation-deadline-exceeded"))
        ));
        assert_eq!(
            service.events.try_iter().count(),
            MAX_PENDING_SERVICE_EVENTS
        );
    }
}
