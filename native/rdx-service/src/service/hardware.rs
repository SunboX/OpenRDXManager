// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Registry-owning production backend for native host operations.

#[path = "hardware/worker_command.rs"]
mod worker_command;
use worker_command::{ActiveHostOperation, WorkerCommand};

#[path = "hardware/backend_adapter.rs"]
mod backend_adapter;
#[path = "hardware/control.rs"]
mod control;
use control::OperationControl;
#[path = "hardware/confirmations.rs"]
mod confirmation_worker;
#[path = "hardware/diagnostics.rs"]
mod diagnostic_worker;
#[path = "hardware/firmware_failure.rs"]
mod firmware_failure;
#[path = "hardware/firmware_interlock.rs"]
mod firmware_interlock;
#[path = "hardware/firmware_transfer.rs"]
mod firmware_transfer;
#[path = "hardware/firmware.rs"]
mod firmware_worker;
#[path = "hardware/contracts.rs"]
mod hardware_contracts;
#[path = "hardware/manufacturing.rs"]
mod manufacturing_worker;
#[cfg(target_os = "macos")]
#[path = "hardware/migration.rs"]
mod migration_worker;
#[path = "hardware/modes.rs"]
mod mode_worker;

use std::collections::BTreeMap;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::mpsc::{self, SyncSender};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use rsa::rand_core::{OsRng, RngCore};
use zeroize::Zeroize;

use crate::firmware::{FirmwareImage, MAX_FIRMWARE_IMAGE_SIZE, ProductFamily};
use crate::model::{
    CancellationState, ConfirmationRequest, ConfirmationToken, DeviceIdentity, DeviceSnapshot,
    FirmwareFileToken, OperationId, OperationKind, OperationRequest,
};
use crate::operations::{
    CleanupState, FileSystem, HostOperationFailure, HostOperationObserver, HostPrimitiveError,
    PrimitiveFailure, configure_registry_drive_mode, configure_registry_sata_mode,
    force_eject_observed, partition_and_format_observed, reset_drive_letter,
    run_write_read_test_observed, safe_eject_observed, set_drive_letter, verify_registry_mode,
};
use crate::platform::{
    DeviceRegistry, PlatformBackend, PlatformError, ResolvedDevice, ValidatedDiscoveryReport,
    discover_post_eject_report, discover_validated_device_report,
};
use crate::protocol::{self_test, write_buffer};
use crate::transport::{CommandDispatch, DispatchCertainty, TransportError};

use super::{
    ServiceBackend, ServiceDescriptor, ServiceEventSink, ServicePlatform, ServiceRejection,
    service_rejection,
};
use confirmation_worker::{ConfirmationRecord, consume_confirmation};
use diagnostic_worker::{run_production_led_test, run_production_self_test};
use firmware_worker::{FirmwareRegistration, RegisteredFirmwareImage};
use hardware_contracts::{
    cancelled_host_failure, operation_kind, operation_target, platform_rejection,
};

const CONFIRMATION_LIFETIME: Duration = Duration::from_secs(60);
const MAX_PENDING_CONFIRMATIONS: usize = 32;
const MAX_PENDING_WORKER_COMMANDS: usize = 4;

/// Clears an active slot only when it still belongs to the completed operation.
fn clear_matching_active(active: &Mutex<Option<ActiveHostOperation>>, operation_id: &OperationId) {
    if let Ok(mut active) = active.lock()
        && active
            .as_ref()
            .is_some_and(|operation| &operation.operation_id == operation_id)
    {
        *active = None;
    }
}

/// Production service backend owning exact discovery, media, and confirmation state.
pub struct HardwareServiceBackend<B> {
    descriptor: ServiceDescriptor,
    commands: SyncSender<WorkerCommand>,
    snapshots: Arc<Mutex<Vec<DeviceSnapshot>>>,
    active: Arc<Mutex<Option<ActiveHostOperation>>>,
    _backend: std::marker::PhantomData<fn() -> B>,
}

/// Registry and platform authority owned exclusively by the bounded worker.
struct HardwareWorker<B> {
    platform: B,
    registry: DeviceRegistry,
    confirmations: BTreeMap<ConfirmationToken, ConfirmationRecord>,
    firmware_registrations: BTreeMap<FirmwareFileToken, FirmwareRegistration>,
    firmware_images: BTreeMap<FirmwareFileToken, RegisteredFirmwareImage>,
    service_session: [u8; 16],
    snapshots: Arc<Mutex<Vec<DeviceSnapshot>>>,
    active: Arc<Mutex<Option<ActiveHostOperation>>>,
}

/// Publishes causal stages and linearizes every supported cancellation boundary.
struct HostWorkerObserver<'operation> {
    operation_id: &'operation OperationId,
    kind: OperationKind,
    identity: &'operation DeviceIdentity,
    events: &'operation ServiceEventSink,
    control: &'operation OperationControl,
    started: bool,
    current_stage: Option<&'static str>,
    publication_failed: bool,
}

impl<B: PlatformBackend + 'static> HardwareServiceBackend<B> {
    /// Creates one service session around a concrete current-platform adapter.
    #[must_use]
    pub fn new(platform: ServicePlatform, backend: B) -> Self {
        let descriptor =
            ServiceDescriptor::from_platform_capabilities(platform, backend.capabilities());
        let snapshots = Arc::new(Mutex::new(Vec::new()));
        let active = Arc::new(Mutex::new(None));
        let (commands, receiver) = mpsc::sync_channel(MAX_PENDING_WORKER_COMMANDS);
        let mut service_session = [0_u8; 16];
        OsRng.fill_bytes(&mut service_session);
        let worker = HardwareWorker {
            platform: backend,
            registry: DeviceRegistry::new(),
            confirmations: BTreeMap::new(),
            firmware_registrations: BTreeMap::new(),
            firmware_images: BTreeMap::new(),
            service_session,
            snapshots: Arc::clone(&snapshots),
            active: Arc::clone(&active),
        };
        // The worker owns every native locator and registry lease. It is
        // intentionally detached on abnormal EOF so process shutdown cannot
        // manufacture a terminal while a bounded native call remains in flight.
        let _worker = thread::Builder::new()
            .name("openrdx-host-worker".to_owned())
            .spawn(move || worker.run(receiver));
        Self {
            descriptor,
            commands,
            snapshots,
            active,
            _backend: std::marker::PhantomData,
        }
    }

    /// Sends one command or rejects a crashed/disconnected authority worker.
    fn send_command(&self, command: WorkerCommand) -> Result<(), ServiceRejection> {
        self.commands
            .send(command)
            .map_err(|_| service_rejection("backend-worker-unavailable"))
    }

    /// Clears only the matching active control after preparation rejection.
    fn clear_active(&self, operation_id: &OperationId) {
        clear_matching_active(&self.active, operation_id);
    }

    /// Rejects registration while any operation owns the exclusive worker.
    fn require_registration_idle(&self) -> Result<(), ServiceRejection> {
        if self
            .active
            .lock()
            .map_err(|_| service_rejection("backend-worker-unavailable"))?
            .is_some()
        {
            return Err(service_rejection("operation-in-progress"));
        }
        Ok(())
    }
}

impl HostOperationObserver for HostWorkerObserver<'_> {
    /// Publishes the reached stage before allowing the shared operation to advance.
    fn reached(&mut self, stage: &'static str, cancellable: bool) -> bool {
        let first = !self.started;
        let publication = self.control.checkpoint_and_publish(cancellable, || {
            if first {
                self.events
                    .publish_host_started(self.operation_id, self.kind, self.identity)
            } else {
                self.events.publish_host_progress(
                    self.operation_id,
                    self.kind,
                    self.identity,
                    stage,
                    if cancellable {
                        CancellationState::Cancellable
                    } else {
                        CancellationState::Closed
                    },
                )
            }
        });
        match publication {
            Ok(true) => {
                self.started = true;
                self.current_stage = Some(stage);
                true
            }
            Ok(false) => false,
            Err(_) => {
                self.publication_failed = true;
                false
            }
        }
    }

    /// Publishes only service-authored closed diagnostics to the parent stderr pipe.
    fn diagnostic(&mut self, code: &'static str) {
        eprintln!("openrdx-hardware: trace {code}");
    }
}

impl<B: PlatformBackend> HardwareWorker<B> {
    /// Owns and serializes all registry and platform commands until graceful shutdown.
    fn run(mut self, receiver: mpsc::Receiver<WorkerCommand>) {
        while let Ok(command) = receiver.recv() {
            match command {
                WorkerCommand::ManufacturingRestore { request, reply } => {
                    let result =
                        catch_unwind(AssertUnwindSafe(|| self.manufacturing_restore(request)))
                            .unwrap_or_else(|_| {
                                Err(service_rejection("backend-worker-unavailable"))
                            });
                    let _ = reply.send(result);
                }
                WorkerCommand::ManufacturingBackup {
                    request,
                    capture,
                    reply,
                } => {
                    let result = catch_unwind(AssertUnwindSafe(|| {
                        self.manufacturing_backup(request, capture)
                    }))
                    .unwrap_or_else(|_| Err(service_rejection("backend-worker-unavailable")));
                    let _ = reply.send(result);
                }
                WorkerCommand::Scan(reply) => {
                    let result = catch_unwind(AssertUnwindSafe(|| self.scan_devices()))
                        .unwrap_or_else(|_| Err(service_rejection("backend-worker-unavailable")));
                    let _ = reply.send(result);
                }
                WorkerCommand::IssueConfirmation(request, reply) => {
                    let result =
                        catch_unwind(AssertUnwindSafe(|| self.issue_bound_confirmation(request)))
                            .unwrap_or_else(|_| {
                                Err(service_rejection("backend-worker-unavailable"))
                            });
                    let _ = reply.send(result);
                }
                WorkerCommand::BeginFirmwareRegistration {
                    file_token,
                    extension,
                    total_bytes,
                    open_rdx,
                    reply,
                } => {
                    let result = self.begin_firmware_registration(
                        file_token,
                        extension,
                        total_bytes,
                        open_rdx,
                    );
                    let _ = reply.send(result);
                }
                WorkerCommand::AppendFirmwareRegistration {
                    file_token,
                    offset,
                    bytes,
                    reply,
                } => {
                    let result = self.append_firmware_registration(file_token, offset, bytes);
                    let _ = reply.send(result);
                }
                WorkerCommand::CommitFirmwareRegistration(file_token, reply) => {
                    let result = self.commit_firmware_registration(file_token);
                    let _ = reply.send(result);
                }
                WorkerCommand::AbortFirmwareRegistration(file_token, reply) => {
                    self.abort_firmware_registration(&file_token);
                    let _ = reply.send(Ok(()));
                }
                WorkerCommand::Prepare {
                    operation_id,
                    request,
                    events,
                    control,
                    reply,
                } => {
                    let crash_events = events.clone();
                    let result = catch_unwind(AssertUnwindSafe(|| {
                        self.prepare_and_execute(
                            operation_id.clone(),
                            request,
                            events,
                            &control,
                            reply,
                        )
                    }));
                    self.clear_active(&operation_id);
                    if result.is_err() {
                        let _ = crash_events.report_crash();
                    }
                }
                WorkerCommand::Shutdown(reply) => {
                    self.confirmations.clear();
                    self.clear_firmware_registrations();
                    let _ = reply.send(Ok(()));
                    return;
                }
            }
        }
    }

    /// Replaces authoritative discovery state and its lock-free public snapshot cache.
    fn scan_devices(&mut self) -> Result<ValidatedDiscoveryReport, ServiceRejection> {
        let report = discover_validated_device_report(&mut self.platform, &mut self.registry)
            .map_err(platform_rejection)?;
        *self
            .snapshots
            .lock()
            .map_err(|_| service_rejection("backend-worker-unavailable"))? =
            report.snapshots().to_vec();
        Ok(report)
    }

    /// Refreshes after proven eject without exposing an empty or media-present transient pass.
    fn scan_post_eject_inventory(
        &mut self,
        device: &DeviceIdentity,
    ) -> Option<ValidatedDiscoveryReport> {
        let report = catch_unwind(AssertUnwindSafe(|| {
            discover_post_eject_report(&mut self.platform, &mut self.registry, &device.id)
        }))
        .ok()?
        .ok()??;
        *self.snapshots.lock().ok()? = report.snapshots().to_vec();
        Some(report)
    }

    /// Validates and consumes authority, acknowledges preparation, then awaits causal release.
    fn prepare_and_execute(
        &mut self,
        operation_id: OperationId,
        request: OperationRequest,
        events: ServiceEventSink,
        control: &OperationControl,
        reply: SyncSender<Result<(), ServiceRejection>>,
    ) {
        let (device_id, revision) = match operation_target(&request) {
            Some(target) => target,
            None => {
                let _ = reply.send(Err(service_rejection("unsupported-operation")));
                return;
            }
        };
        let identity = DeviceIdentity {
            id: device_id.clone(),
            revision,
        };
        let kind = operation_kind(&request);
        if kind == OperationKind::StatusRefresh {
            let current = self.registry.snapshot(device_id);
            let valid_target = current
                .as_ref()
                .is_some_and(|snapshot| snapshot.revision == revision);
            if !valid_target {
                let reason = if current.is_some() {
                    "stale-device-revision"
                } else {
                    "device-not-found"
                };
                let _ = reply.send(Err(service_rejection(reason)));
                return;
            }
            if reply.send(Ok(())).is_err() {
                return;
            }
            let cancelled = match control.wait_for_release() {
                Ok(cancelled) => cancelled,
                Err(_) => {
                    let _ = events.report_crash();
                    return;
                }
            };
            if cancelled {
                self.clear_active(&operation_id);
                if events
                    .publish_host_cancelled(&operation_id, kind, &identity)
                    .is_err()
                {
                    let _ = events.report_crash();
                }
                return;
            }
            match control.checkpoint_and_publish(false, || {
                events.publish_host_started(&operation_id, kind, &identity)
            }) {
                Ok(true) => {}
                Ok(false) => {
                    self.clear_active(&operation_id);
                    if events
                        .publish_host_cancelled(&operation_id, kind, &identity)
                        .is_err()
                    {
                        let _ = events.report_crash();
                    }
                    return;
                }
                Err(_) => {
                    let _ = events.report_crash();
                    return;
                }
            }
            let refreshed = self.scan_devices().and_then(|report| {
                let selected_present = report
                    .snapshots()
                    .iter()
                    .any(|snapshot| snapshot.id == identity.id)
                    .then_some(report);
                selected_present.ok_or_else(|| service_rejection("device-not-found"))
            });
            match refreshed {
                Ok(report) => {
                    self.clear_active(&operation_id);
                    if events
                        .publish_status_success(&operation_id, &identity, report)
                        .is_err()
                    {
                        let _ = events.report_crash();
                    }
                }
                Err(_) => {
                    let result = Err(HostOperationFailure::preflight(
                        "status-reading",
                        crate::operations::HostPrimitiveError::Other,
                    ));
                    self.clear_active(&operation_id);
                    if events
                        .publish_host_terminal(
                            &operation_id,
                            kind,
                            &identity,
                            "status-reading",
                            result,
                        )
                        .is_err()
                    {
                        let _ = events.report_crash();
                    }
                }
            }
            return;
        }
        if kind == OperationKind::FirmwareUpdate {
            self.prepare_and_execute_firmware(
                operation_id,
                &request,
                &events,
                control,
                reply,
                &identity,
            );
            return;
        }
        if matches!(
            kind,
            OperationKind::DriveModeSet | OperationKind::SataModeSet
        ) {
            let current = self.registry.snapshot(device_id);
            if current
                .as_ref()
                .is_none_or(|snapshot| snapshot.revision != revision)
            {
                let _ = reply.send(Err(service_rejection(if current.is_some() {
                    "stale-device-revision"
                } else {
                    "device-not-found"
                })));
                return;
            }
            if reply.send(Ok(())).is_err() {
                return;
            }
            if control.wait_for_release().is_err() {
                let _ = events.report_crash();
                return;
            }
            let mut observer = HostWorkerObserver {
                operation_id: &operation_id,
                kind,
                identity: &identity,
                events: &events,
                control,
                started: false,
                current_stage: None,
                publication_failed: false,
            };
            let result = self.execute_mode_operation(&request, &mut observer);
            if observer.publication_failed {
                let _ = events.report_crash();
                return;
            }
            let terminal_stage = observer.current_stage.unwrap_or("device-configuring");
            self.clear_active(&operation_id);
            if events
                .publish_host_terminal(&operation_id, kind, &identity, terminal_stage, result)
                .is_err()
            {
                let _ = events.report_crash();
            }
            return;
        }
        let active = Arc::clone(&self.active);
        let mut resolved = match self
            .registry
            .resolve(&mut self.platform, device_id, revision)
        {
            Ok(resolved) => resolved,
            Err(error) => {
                let _ = reply.send(Err(platform_rejection(error)));
                return;
            }
        };

        let internal_confirmation = match &request {
            OperationRequest::Format {
                confirmation_token, ..
            }
            | OperationRequest::EjectForce {
                confirmation_token, ..
            } => {
                let binding_proof = match resolved.issue_host_mutation_confirmation() {
                    Ok(proof) => proof,
                    Err(error) => {
                        let _ = reply.send(Err(platform_rejection(error)));
                        return;
                    }
                };
                if let Err(error) = consume_confirmation(
                    &mut self.confirmations,
                    self.service_session,
                    &request,
                    confirmation_token,
                    &binding_proof,
                ) {
                    let _ = reply.send(Err(error));
                    return;
                }
                Some(binding_proof)
            }
            _ => None,
        };

        if reply.send(Ok(())).is_err() {
            return;
        }
        let cancelled = match control.wait_for_release() {
            Ok(cancelled) => cancelled,
            Err(_) => {
                let _ = events.report_crash();
                return;
            }
        };
        if cancelled && !matches!(kind, OperationKind::SelfTest | OperationKind::LedTest) {
            clear_matching_active(&active, &operation_id);
            if events
                .publish_host_cancelled(&operation_id, kind, &identity)
                .is_err()
            {
                let _ = events.report_crash();
            }
            return;
        }
        let mut observer = HostWorkerObserver {
            operation_id: &operation_id,
            kind,
            identity: &identity,
            events: &events,
            control,
            started: false,
            current_stage: None,
            publication_failed: false,
        };
        let result: Result<(), HostOperationFailure> = match request {
            OperationRequest::SelfTest { .. } => {
                run_production_self_test(&mut resolved, &mut observer)
            }
            OperationRequest::LedTest { .. } => {
                run_production_led_test(&mut resolved, &mut observer)
            }
            OperationRequest::WriteReadTest { .. } => {
                run_write_read_test_observed(&mut resolved, &mut observer).map(|_| ())
            }
            OperationRequest::VolumeLabelSet { label, .. } => {
                if !observer.reached("host-volume-changing", false) {
                    Err(cancelled_host_failure("host-volume-changing"))
                } else {
                    let outcome = crate::operations::set_volume_label(&mut resolved, &label);
                    if outcome
                        .as_ref()
                        .map_or_else(|failure| failure.stage() != "preflight", |_| true)
                    {
                        let _ = observer.reached("host-volume-readback", false);
                    }
                    outcome
                }
            }
            OperationRequest::DriveLetterSet { letter, .. } => {
                if !observer.reached("host-volume-changing", false) {
                    Err(cancelled_host_failure("host-volume-changing"))
                } else {
                    let outcome = set_drive_letter(&mut resolved, letter);
                    if match &outcome {
                        Ok(()) => true,
                        Err(failure) => failure.stage() != "preflight",
                    } {
                        let _ = observer.reached("host-volume-readback", false);
                    }
                    outcome
                }
            }
            OperationRequest::DriveLetterReset { .. } => {
                if !observer.reached("host-volume-changing", false) {
                    Err(cancelled_host_failure("host-volume-changing"))
                } else {
                    let outcome = reset_drive_letter(&mut resolved);
                    if match &outcome {
                        Ok(()) => true,
                        Err(failure) => failure.stage() != "preflight",
                    } {
                        let _ = observer.reached("host-volume-readback", false);
                    }
                    outcome
                }
            }
            OperationRequest::Format {
                filesystem,
                passphrase,
                ..
            } => {
                if filesystem.encrypted() != passphrase.is_some() {
                    Err(crate::operations::HostOperationFailure::preflight(
                        "preflight",
                        crate::operations::HostPrimitiveError::DependencyMissing,
                    ))
                } else {
                    match resolved.set_format_passphrase(passphrase) {
                        Err(failure) => {
                            Err(crate::operations::HostOperationFailure::from_primitive(
                                "preflight",
                                failure,
                            ))
                        }
                        Ok(()) => partition_and_format_observed(
                            &mut resolved,
                            FileSystem::try_from(filesystem).expect("closed filesystem enum"),
                            internal_confirmation
                                .as_ref()
                                .expect("format admission consumed an internal confirmation"),
                            &mut observer,
                        )
                        .map(|_| ()),
                    }
                }
            }
            OperationRequest::EjectSafe { .. } => safe_eject_observed(&mut resolved, &mut observer),
            OperationRequest::EjectForce { .. } => force_eject_observed(
                &mut resolved,
                internal_confirmation
                    .as_ref()
                    .expect("forced eject admission consumed an internal confirmation"),
                &mut observer,
            ),
            _ => return,
        };
        if observer.publication_failed {
            let _ = events.report_crash();
            return;
        }
        let terminal_stage = observer.current_stage.unwrap_or("queued");
        let inventory_update = if result.is_ok()
            && terminal_stage == "eject-readback"
            && matches!(kind, OperationKind::EjectSafe | OperationKind::EjectForce)
        {
            // Discovery must not race the exact live lease that proved eject.
            drop(resolved);
            self.scan_post_eject_inventory(&identity)
        } else {
            None
        };
        if result
            .as_ref()
            .is_err_and(|failure| failure.code() == "cancelled")
        {
            clear_matching_active(&active, &operation_id);
            if events
                .publish_host_cancelled_at(&operation_id, kind, &identity, terminal_stage)
                .is_err()
            {
                let _ = events.report_crash();
            }
        } else {
            clear_matching_active(&active, &operation_id);
            if events
                .publish_host_terminal_with_inventory(
                    &operation_id,
                    kind,
                    &identity,
                    terminal_stage,
                    result,
                    inventory_update,
                )
                .is_err()
            {
                let _ = events.report_crash();
            }
        }
    }

    /// Clears the matching operation control before publishing a terminal event.
    ///
    /// The run loop repeats this after execution as a fallback for admission,
    /// publication, and crash paths that return without a terminal event.
    fn clear_active(&self, operation_id: &OperationId) {
        clear_matching_active(&self.active, operation_id);
    }
}

#[cfg(test)]
#[path = "hardware/continuation_tests.rs"]
mod continuation_tests;
#[cfg(test)]
#[path = "hardware_control_tests.rs"]
mod control_tests;
#[cfg(test)]
#[path = "hardware_tests.rs"]
mod tests;
