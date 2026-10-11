// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Framed-service adapter to the private native worker and public inventory.

use super::*;

impl<B: PlatformBackend + 'static> ServiceBackend for HardwareServiceBackend<B> {
    /// Retains the ordinary worker reservation through complete durable backup and readback.
    fn manufacturing_backup(
        &mut self,
        request: crate::service::manufacturing::BackupRequest,
        capture: bool,
    ) -> Result<crate::service::manufacturing::BackupInventory, ServiceRejection> {
        self.require_registration_idle()?;
        let (reply, result) = mpsc::sync_channel(0);
        self.send_command(WorkerCommand::ManufacturingBackup {
            request,
            capture,
            reply,
        })?;
        result
            .recv()
            .map_err(|_| service_rejection("backend-worker-unavailable"))?
    }
    /// Runs exactly one restore; the actor cannot accept competing work before its result.
    fn manufacturing_restore(
        &mut self,
        request: crate::service::manufacturing::RestoreRequest,
    ) -> Result<crate::service::manufacturing::BackupInventory, ServiceRejection> {
        self.require_registration_idle()?;
        let (reply, result) = mpsc::sync_channel(0);
        self.send_command(WorkerCommand::ManufacturingRestore { request, reply })?;
        result
            .recv()
            .map_err(|_| service_rejection("backend-worker-unavailable"))?
    }
    /// Returns immutable current-platform readiness and verification metadata.
    fn descriptor(&self) -> ServiceDescriptor {
        self.descriptor.clone()
    }

    /// Includes preparation reservations and the worker tail after terminal publication.
    /// All non-operation worker requests synchronously await their replies; the
    /// service loop cannot admit recovery while those commands remain queued.
    fn require_recovery_idle(&mut self) -> Result<(), ServiceRejection> {
        self.require_registration_idle()
    }

    /// Returns the current path-free revisioned registry set.
    fn list_devices(&mut self) -> Result<Vec<DeviceSnapshot>, ServiceRejection> {
        self.snapshots
            .lock()
            .map(|snapshots| snapshots.clone())
            .map_err(|_| service_rejection("backend-worker-unavailable"))
    }

    /// Updates only the public cache at the service's ordered event boundary.
    fn commit_operation_inventory(
        &mut self,
        devices: &[DeviceSnapshot],
    ) -> Result<(), ServiceRejection> {
        *self
            .snapshots
            .lock()
            .map_err(|_| service_rejection("backend-worker-unavailable"))? = devices.to_vec();
        Ok(())
    }

    /// Replaces the registry from one authoritative native discovery generation.
    fn scan_devices(&mut self) -> Result<Vec<DeviceSnapshot>, ServiceRejection> {
        self.scan_report()
            .map(ValidatedDiscoveryReport::into_snapshots)
    }

    /// Returns the authoritative native snapshot with path-free rejection counts.
    fn scan_report(&mut self) -> Result<ValidatedDiscoveryReport, ServiceRejection> {
        let (reply, result) = mpsc::sync_channel(0);
        self.send_command(WorkerCommand::Scan(reply))?;
        result
            .recv()
            .map_err(|_| service_rejection("backend-worker-unavailable"))?
    }

    /// Issues one random, bounded, current-media destructive confirmation.
    fn issue_confirmation(
        &mut self,
        request: ConfirmationRequest,
    ) -> Result<ConfirmationToken, ServiceRejection> {
        if self
            .active
            .lock()
            .map_err(|_| service_rejection("backend-worker-unavailable"))?
            .is_some()
        {
            return Err(service_rejection("operation-in-progress"));
        }
        let (reply, result) = mpsc::sync_channel(0);
        self.send_command(WorkerCommand::IssueConfirmation(request, reply))?;
        result
            .recv()
            .map_err(|_| service_rejection("backend-worker-unavailable"))?
    }

    /// Begins a bounded path-free image registration while no operation owns hardware.
    fn begin_firmware_registration(
        &mut self,
        file_token: FirmwareFileToken,
        extension: String,
        total_bytes: usize,
        open_rdx: Option<crate::firmware::OpenRdxImageMetadata>,
    ) -> Result<(), ServiceRejection> {
        self.require_registration_idle()?;
        let (reply, result) = mpsc::sync_channel(0);
        self.send_command(WorkerCommand::BeginFirmwareRegistration {
            file_token,
            extension,
            total_bytes,
            open_rdx,
            reply,
        })?;
        result
            .recv()
            .map_err(|_| service_rejection("backend-worker-unavailable"))?
    }

    /// Appends one exact ordered firmware chunk while hardware remains idle.
    fn append_firmware_registration(
        &mut self,
        file_token: FirmwareFileToken,
        offset: usize,
        bytes: Vec<u8>,
    ) -> Result<(), ServiceRejection> {
        self.require_registration_idle()?;
        let (reply, result) = mpsc::sync_channel(0);
        self.send_command(WorkerCommand::AppendFirmwareRegistration {
            file_token,
            offset,
            bytes,
            reply,
        })?;
        result
            .recv()
            .map_err(|_| service_rejection("backend-worker-unavailable"))?
    }

    /// Validates one complete modern image while hardware remains idle.
    fn commit_firmware_registration(
        &mut self,
        file_token: FirmwareFileToken,
    ) -> Result<(), ServiceRejection> {
        self.require_registration_idle()?;
        let (reply, result) = mpsc::sync_channel(0);
        self.send_command(WorkerCommand::CommitFirmwareRegistration(file_token, reply))?;
        result
            .recv()
            .map_err(|_| service_rejection("backend-worker-unavailable"))?
    }

    /// Drops one partial or committed image without touching hardware.
    fn abort_firmware_registration(
        &mut self,
        file_token: &FirmwareFileToken,
    ) -> Result<(), ServiceRejection> {
        let (reply, result) = mpsc::sync_channel(0);
        self.send_command(WorkerCommand::AbortFirmwareRegistration(
            file_token.clone(),
            reply,
        ))?;
        result
            .recv()
            .map_err(|_| service_rejection("backend-worker-unavailable"))?
    }

    /// Executes only implemented service-owned host operation state machines.
    fn start_operation(
        &mut self,
        operation_id: OperationId,
        request: OperationRequest,
        events: ServiceEventSink,
    ) -> Result<(), ServiceRejection> {
        let control = Arc::new(OperationControl::new(operation_kind(&request)));
        {
            let mut active = self
                .active
                .lock()
                .map_err(|_| service_rejection("backend-worker-unavailable"))?;
            if active.is_some() {
                return Err(service_rejection("operation-in-progress"));
            }
            *active = Some(ActiveHostOperation {
                operation_id: operation_id.clone(),
                control: Arc::clone(&control),
            });
        }
        let (reply, result) = mpsc::sync_channel(0);
        if let Err(error) = self.send_command(WorkerCommand::Prepare {
            operation_id: operation_id.clone(),
            request,
            events,
            control,
            reply,
        }) {
            self.clear_active(&operation_id);
            return Err(error);
        }
        match result.recv() {
            Ok(Ok(())) => Ok(()),
            Ok(Err(error)) => {
                self.clear_active(&operation_id);
                Err(error)
            }
            Err(_) => {
                self.clear_active(&operation_id);
                Err(service_rejection("backend-worker-unavailable"))
            }
        }
    }

    /// Releases only the exact prepared operation after its response is flushed.
    fn release_operation(&mut self, operation_id: &OperationId) -> Result<(), ServiceRejection> {
        let active = self
            .active
            .lock()
            .map_err(|_| service_rejection("backend-worker-unavailable"))?
            .clone()
            .ok_or_else(|| service_rejection("operation-not-found"))?;
        if &active.operation_id != operation_id {
            return Err(service_rejection("operation-not-found"));
        }
        active.control.release()
    }

    /// Requests cancellation through the independent exact-operation control path.
    fn cancel_operation(&mut self, operation_id: &OperationId) -> Result<(), ServiceRejection> {
        let active = self
            .active
            .lock()
            .map_err(|_| service_rejection("backend-worker-unavailable"))?
            .clone()
            .ok_or_else(|| service_rejection("operation-not-found"))?;
        if &active.operation_id != operation_id {
            return Err(service_rejection("operation-not-found"));
        }
        active.control.request_cancellation()
    }

    /// Acknowledges the exact live control directly while its hardware worker waits.
    fn continue_operation(
        &mut self,
        operation_id: &OperationId,
        stage: &str,
    ) -> Result<(), ServiceRejection> {
        let active = self
            .active
            .lock()
            .map_err(|_| service_rejection("backend-worker-unavailable"))?;
        let operation = active
            .as_ref()
            .ok_or_else(|| service_rejection("operation-not-found"))?;
        if &operation.operation_id != operation_id {
            return Err(service_rejection("operation-not-found"));
        }
        // Do not enqueue behind the blocking hardware worker or release its
        // global reservation. The exact owner stays locked through admission.
        operation.control.acknowledge_operator(stage)
    }

    /// Clears pending one-shot authority before the authenticated session closes.
    fn shutdown(&mut self) -> Result<(), ServiceRejection> {
        if self
            .active
            .lock()
            .map_err(|_| service_rejection("backend-worker-unavailable"))?
            .is_some()
        {
            return Err(service_rejection("operation-in-progress"));
        }
        let (reply, result) = mpsc::sync_channel(0);
        self.send_command(WorkerCommand::Shutdown(reply))?;
        result
            .recv()
            .map_err(|_| service_rejection("backend-worker-unavailable"))?
    }
}

#[cfg(test)]
mod recovery_admission_tests {
    use super::*;

    /// A platform whose methods cannot be consulted by admission or cleanup checks.
    struct NoHardware;
    impl PlatformBackend for NoHardware {
        /// Rejects accidental native capability discovery.
        fn capabilities(&self) -> crate::platform::PlatformCapabilities {
            panic!("no native access")
        }
        /// Rejects accidental native enumeration.
        fn enumerate_candidates(
            &mut self,
        ) -> Result<Vec<crate::platform::CandidateDevice>, PlatformError> {
            panic!("no native access")
        }
        /// Rejects accidental capture acquisition.
        fn open_candidate(
            &mut self,
            _: &crate::platform::CandidateDevice,
        ) -> Result<crate::platform::CandidateLease, PlatformError> {
            panic!("no native access")
        }
    }

    /// A retained worker reservation excludes recovery even without a runtime active event.
    #[test]
    fn recovery_admission_requires_worker_cleanup_without_enqueuing_commands() {
        let (commands, receiver) = mpsc::sync_channel(1);
        let active = Arc::new(Mutex::new(Some(ActiveHostOperation {
            operation_id: OperationId::new("op:cleanup-pending").unwrap(),
            control: Arc::new(OperationControl::new(OperationKind::FirmwareUpdate)),
        })));
        let mut backend = HardwareServiceBackend::<NoHardware> {
            descriptor: ServiceDescriptor::native_available(ServicePlatform::Darwin, "test")
                .unwrap(),
            commands,
            snapshots: Arc::new(Mutex::new(vec![])),
            active: Arc::clone(&active),
            _backend: std::marker::PhantomData,
        };
        assert_eq!(
            backend.require_recovery_idle().unwrap_err().as_str(),
            "operation-in-progress"
        );
        assert!(matches!(
            receiver.try_recv(),
            Err(mpsc::TryRecvError::Empty)
        ));
        *active.lock().unwrap() = None;
        backend.require_recovery_idle().unwrap();
        assert!(matches!(
            receiver.try_recv(),
            Err(mpsc::TryRecvError::Empty)
        ));
    }
}
