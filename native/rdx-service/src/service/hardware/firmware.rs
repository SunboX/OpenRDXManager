//! Bounded path-free firmware registration and registry-owned update execution.

use super::firmware_transfer::{
    firmware_dispatch_failure, firmware_preflight_failure, firmware_reconnect_failure,
    transfer_registry_firmware,
};
use super::*;

pub(super) const FIRMWARE_REGISTRATION_LIFETIME: Duration = Duration::from_secs(5 * 60);
pub(super) const MAX_FIRMWARE_REGISTRATIONS: usize = 2;
const FIRMWARE_RECORD_SETTLE_ATTEMPTS: usize = 15;
const FIRMWARE_RECORD_SETTLE_INTERVAL: Duration = Duration::from_millis(100);
const FIRMWARE_RECORD_REOPEN_DELAY: Duration = Duration::from_millis(1_500);

/// Commit evidence available while waiting for the exact dock after mode-5.
#[derive(Clone, Copy)]
enum FirmwareFinalizerState {
    /// GOOD confirms OpenRDX image validation and boot-vector commit. The
    /// timestamp allows its five 100-ms reset ticks plus host settling time.
    Acknowledged(Instant),
    /// The first failed reply may still permit the existing bounded retry.
    AwaitingReconciliation,
    /// The finalizer retry is exhausted; unchanged firmware cannot prove it.
    Exhausted,
}

/// Exact post-finalizer facts and the private discovery pass that supplied them.
struct FirmwareReadback {
    facts: (ProductFamily, crate::firmware::FirmwareRevision, bool),
    inventory: ValidatedDiscoveryReport,
}

/// One bounded raw registration that is zeroed on every rejection path.
pub(super) struct FirmwareRegistration {
    pub(super) bytes: Vec<u8>,
    pub(super) expires_at: Instant,
    pub(super) total_bytes: usize,
    pub(super) open_rdx: Option<crate::firmware::OpenRdxImageMetadata>,
}

impl Drop for FirmwareRegistration {
    /// Clears partial bytes even when the worker exits unexpectedly.
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

/// One validated modern image awaiting exact one-shot operation admission.
pub(super) struct RegisteredFirmwareImage {
    pub(super) expires_at: Instant,
    pub(super) image: FirmwareImage,
}

impl<B: PlatformBackend> HardwareWorker<B> {
    /// Consumes one registered image and owns its complete released lifecycle.
    pub(super) fn prepare_and_execute_firmware(
        &mut self,
        operation_id: OperationId,
        request: &OperationRequest,
        events: &ServiceEventSink,
        control: &OperationControl,
        reply: SyncSender<Result<(), ServiceRejection>>,
        identity: &DeviceIdentity,
    ) {
        self.expire_firmware_registrations(Instant::now());
        let (device_id, revision, file_token) = match request {
            OperationRequest::FirmwareUpdate {
                device_id,
                device_revision,
                firmware_file_token,
            } => (device_id, *device_revision, firmware_file_token),
            _ => unreachable!("firmware kind has firmware request"),
        };
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
        let Some(registered) = self.firmware_images.remove(file_token) else {
            let _ = reply.send(Err(service_rejection("firmware-image-not-registered")));
            return;
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
        if cancelled {
            self.clear_active(&operation_id);
            if events
                .publish_host_cancelled(&operation_id, OperationKind::FirmwareUpdate, identity)
                .is_err()
            {
                let _ = events.report_crash();
            }
            return;
        }
        let mut observer = HostWorkerObserver {
            operation_id: &operation_id,
            kind: OperationKind::FirmwareUpdate,
            identity,
            events,
            control,
            started: false,
            current_stage: None,
            publication_failed: false,
        };
        let mut result =
            self.execute_firmware_operation(device_id, revision, &registered.image, &mut observer);
        if matches!(
            observer.current_stage,
            Some("firmware-writing" | "firmware-finalizing")
        ) && !observer.publication_failed
        {
            result = result.map_err(|failure| {
                self.complete_failed_firmware_checks(device_id, &mut observer, failure)
            });
        }
        if observer.publication_failed {
            let _ = events.report_crash();
            return;
        }
        let terminal_stage = observer.current_stage.unwrap_or("firmware-validating");
        let (result, inventory) = match result {
            Ok(report) => (Ok(()), Some(report)),
            Err(failure) => (Err(failure), None),
        };
        if result
            .as_ref()
            .is_err_and(|failure| failure.code() == "cancelled")
        {
            self.clear_active(&operation_id);
            if events
                .publish_host_cancelled_at(
                    &operation_id,
                    OperationKind::FirmwareUpdate,
                    identity,
                    terminal_stage,
                )
                .is_err()
            {
                let _ = events.report_crash();
            }
        } else {
            self.clear_active(&operation_id);
            if events
                .publish_host_terminal_with_inventory(
                    &operation_id,
                    OperationKind::FirmwareUpdate,
                    identity,
                    terminal_stage,
                    result,
                    inventory,
                )
                .is_err()
            {
                let _ = events.report_crash();
            }
        }
    }

    /// Starts one modern image registration with strict size and capacity bounds.
    pub(super) fn begin_firmware_registration(
        &mut self,
        file_token: FirmwareFileToken,
        extension: String,
        total_bytes: usize,
        open_rdx: Option<crate::firmware::OpenRdxImageMetadata>,
    ) -> Result<(), ServiceRejection> {
        self.expire_firmware_registrations(Instant::now());
        self.abort_firmware_registration(&file_token);
        if extension != "BIN" {
            return Err(service_rejection(if extension == "BIP" {
                "legacy-bip-format-unproven"
            } else {
                "firmware-file-type-unsupported"
            }));
        }
        if total_bytes == 0 || total_bytes > MAX_FIRMWARE_IMAGE_SIZE {
            return Err(service_rejection("firmware-registration-invalid"));
        }
        if self.firmware_registrations.len() + self.firmware_images.len()
            >= MAX_FIRMWARE_REGISTRATIONS
        {
            return Err(service_rejection(
                "firmware-registration-capacity-exhausted",
            ));
        }
        self.firmware_registrations.insert(
            file_token,
            FirmwareRegistration {
                bytes: Vec::with_capacity(total_bytes),
                expires_at: Instant::now() + FIRMWARE_REGISTRATION_LIFETIME,
                total_bytes,
                open_rdx,
            },
        );
        Ok(())
    }

    /// Appends only the exact next non-empty bounded chunk or destroys the registration.
    pub(super) fn append_firmware_registration(
        &mut self,
        file_token: FirmwareFileToken,
        offset: usize,
        mut bytes: Vec<u8>,
    ) -> Result<(), ServiceRejection> {
        self.expire_firmware_registrations(Instant::now());
        let valid = self
            .firmware_registrations
            .get(&file_token)
            .is_some_and(|registration| {
                offset == registration.bytes.len()
                    && !bytes.is_empty()
                    && bytes.len() <= 4_096
                    && registration.bytes.len().saturating_add(bytes.len())
                        <= registration.total_bytes
            });
        if !valid {
            bytes.zeroize();
            self.abort_firmware_registration(&file_token);
            return Err(service_rejection("firmware-registration-invalid"));
        }
        self.firmware_registrations
            .get_mut(&file_token)
            .expect("validated registration remains present")
            .bytes
            .append(&mut bytes);
        Ok(())
    }

    /// Parses and commits one complete modern image under its one-shot token.
    pub(super) fn commit_firmware_registration(
        &mut self,
        file_token: FirmwareFileToken,
    ) -> Result<(), ServiceRejection> {
        self.expire_firmware_registrations(Instant::now());
        let Some(mut registration) = self.firmware_registrations.remove(&file_token) else {
            return Err(service_rejection("firmware-registration-invalid"));
        };
        if registration.bytes.len() != registration.total_bytes {
            registration.bytes.zeroize();
            return Err(service_rejection("firmware-registration-incomplete"));
        }
        let bytes = std::mem::take(&mut registration.bytes);
        let image = match registration.open_rdx.as_ref() {
            Some(metadata) => FirmwareImage::from_openrdx_bytes(bytes, metadata),
            None => FirmwareImage::from_bytes(bytes, ProductFamily::Usb3Sata3),
        }
        .map_err(|_| service_rejection("firmware-image-invalid"))?;
        self.firmware_images.insert(
            file_token,
            RegisteredFirmwareImage {
                expires_at: Instant::now() + FIRMWARE_REGISTRATION_LIFETIME,
                image,
            },
        );
        Ok(())
    }

    /// Removes and zeroes any partial registration and drops a committed image.
    pub(super) fn abort_firmware_registration(&mut self, file_token: &FirmwareFileToken) {
        if let Some(mut registration) = self.firmware_registrations.remove(file_token) {
            registration.bytes.zeroize();
        }
        self.firmware_images.remove(file_token);
    }

    /// Expires registrations without extending their original lifetime.
    pub(super) fn expire_firmware_registrations(&mut self, now: Instant) {
        let expired =
            self.firmware_registrations
                .iter()
                .filter_map(|(token, registration)| {
                    (now >= registration.expires_at).then_some(token.clone())
                })
                .chain(self.firmware_images.iter().filter_map(|(token, image)| {
                    (now >= image.expires_at).then_some(token.clone())
                }))
                .collect::<Vec<_>>();
        for token in expired {
            self.abort_firmware_registration(&token);
        }
    }

    /// Clears every path-free image registration during graceful shutdown.
    pub(super) fn clear_firmware_registrations(&mut self) {
        let tokens = self
            .firmware_registrations
            .keys()
            .chain(self.firmware_images.keys())
            .cloned()
            .collect::<Vec<_>>();
        for token in tokens {
            self.abort_firmware_registration(&token);
        }
    }

    /// Executes the evidence-backed modern mode-4/mode-5 updater on exact registry leases.
    pub(super) fn execute_firmware_operation(
        &mut self,
        device_id: &crate::model::DeviceId,
        revision: crate::model::DiscoveryRevision,
        image: &FirmwareImage,
        observer: &mut HostWorkerObserver<'_>,
    ) -> Result<ValidatedDiscoveryReport, HostOperationFailure> {
        if !observer.reached("firmware-validating", true) {
            return Err(cancelled_host_failure("firmware-validating"));
        }
        let mut resolved = self
            .registry
            .resolve(&mut self.platform, device_id, revision)
            .map_err(|_| firmware_preflight_failure("firmware-validating"))?;
        #[allow(unused_mut)]
        let (family, mut installed, media_present) = resolved
            .firmware_facts()
            .map_err(|_| firmware_preflight_failure("firmware-validating"))?;
        if media_present {
            return Err(HostOperationFailure::preflight(
                "firmware-validating",
                HostPrimitiveError::MediaPresent,
            ));
        }
        // The first-install path owns its complete record-preserving ROM route;
        // ordinary receiver updates continue directly to image authorization.
        #[allow(unused_mut)]
        let mut preservation: Option<crate::migration::PreparedMigration> = None;
        #[cfg(target_os = "macos")]
        if migration_worker::eligible(image, family, installed) {
            let mut prepared = migration_worker::prepare_and_stage(&mut resolved, image, observer)?;
            // Keep source capture alive until the requested physical power cycle.
            // Dropping it earlier can rematch/reset the macOS USB storage stack.
            let mut rom = migration_worker::await_rom(&mut prepared, observer)?;
            drop(resolved);
            migration_worker::program_bootstrap(&mut prepared, &mut rom, observer)?;
            drop(rom);
            let binding =
                migration_worker::await_bootstrap(self, device_id, &mut prepared, observer)?;
            let revision = binding
                .report
                .snapshots()
                .iter()
                .find(|snapshot| &snapshot.id == device_id)
                .map(|snapshot| snapshot.revision)
                .ok_or_else(firmware_reconnect_failure)?;
            resolved = self
                .registry
                .resolve_retained_firmware_lease(
                    device_id,
                    revision,
                    self.platform.capabilities(),
                    binding.lease.ok_or_else(firmware_reconnect_failure)?,
                )
                .map_err(|_| firmware_reconnect_failure())?;
            if !observer.reached("firmware-restoring-identity", false) {
                return Err(migration_worker::failed(
                    "firmware-restoring-identity",
                    HostPrimitiveError::MigrationReadbackMismatch,
                ));
            }
            verify_migration_records(
                &mut resolved,
                &mut prepared,
                crate::migration::MigrationEvent::BootstrapReadbackVerified,
                "firmware-restoring-identity",
            )?;
            let (returned_family, returned_revision, returned_media) = resolved
                .firmware_facts()
                .map_err(|_| firmware_reconnect_failure())?;
            if returned_family != family || returned_revision.get() != 107 || returned_media {
                return Err(migration_worker::failed(
                    "firmware-restoring-identity",
                    HostPrimitiveError::MigrationReadbackMismatch,
                ));
            }
            installed = returned_revision;
            preservation = Some(prepared);
        }
        image
            .authorize_for_registry(installed, family)
            .map_err(|error| {
                // Report the missing Manager installation route separately from
                // host failures. The reported revision is not a cross-firmware
                // version comparison and does not prove migration impossible.
                if matches!(
                    error,
                    crate::firmware::FirmwareImageError::OpenRdxReceiverRequired
                ) {
                    HostOperationFailure::preflight(
                        "firmware-validating",
                        HostPrimitiveError::OpenRdxInstallationUnsupported,
                    )
                } else {
                    firmware_preflight_failure("firmware-validating")
                }
            })?;

        // Every ordinary update, including a vendor-image restore, must have a
        // durable baseline before the first write. First installation already
        // saved its original exposed factory data in the verified migration bundle.
        let manufacturing =
            if preservation.is_none() {
                Some(resolved.manufacturing_record().map_err(|cause| {
                    HostOperationFailure::preflight("firmware-validating", cause)
                })?)
            } else {
                None
            };
        if let Some(record) = manufacturing.as_ref() {
            self.platform
                .backup_manufacturing_record(device_id, record.bytes())
                .map_err(|cause| HostOperationFailure::preflight("firmware-validating", cause))?;
            // Storage can take time; require the same bytes on this same lease
            // again immediately before crossing the first mutation boundary.
            resolved
                .manufacturing_record()
                .and_then(|fresh| record.verify(&fresh))
                .map_err(|cause| HostOperationFailure::preflight("firmware-validating", cause))?;
        }

        firmware_interlock::require_ready(&mut resolved, installed)?;
        if !observer.reached("firmware-writing", false) {
            return Err(cancelled_host_failure("firmware-writing"));
        }
        if let Some(prepared) = preservation.as_mut() {
            prepared
                .journal(crate::migration::MigrationEvent::FinalUpdateStarted)
                .map_err(|_| {
                    migration_record_failure(
                        "firmware-writing",
                        HostPrimitiveError::MigrationRecoveryUnavailable,
                    )
                })?;
        }
        observer.diagnostic("firmware-transfer-attempt-one");
        if let Err((first_failure, retryable)) =
            transfer_registry_firmware(&mut resolved, image, observer)
        {
            if !retryable {
                if let Err(failure) = check_manufacturing_records(
                    &mut resolved,
                    manufacturing.as_ref(),
                    "firmware-finalizing",
                ) {
                    if failure.code() != "firmware-manufacturing-unreadable" {
                        return Err(failure);
                    }
                    drop(resolved);
                    let _settled = reopen_settled_manufacturing_records(
                        &mut self.registry,
                        &mut self.platform,
                        device_id,
                        revision,
                        manufacturing.as_ref(),
                        "firmware-finalizing",
                        failure,
                    )?;
                    // A fresh lease can recover read-only evidence, but it
                    // cannot prove the failed image transfer was complete.
                    // Preserve the primary failure without finalizing.
                    return Err(first_failure);
                }
                // A complete mode-4 transfer is the only evidence that permits
                // mode-5 activation. Readable identity data cannot prove that
                // an incomplete or rejected transfer staged a valid image.
                return Err(first_failure);
            }
            drop(resolved);
            let retry_revision = self.rediscover_firmware_device(device_id)?;
            resolved = self
                .registry
                .resolve(&mut self.platform, device_id, retry_revision)
                .map_err(|_| firmware_reconnect_failure())?;
            let (retry_family, retry_installed, retry_media_present) = resolved
                .firmware_facts()
                .map_err(|_| firmware_reconnect_failure())?;
            if retry_family != family || retry_installed != installed || retry_media_present {
                return Err(firmware_reconnect_failure());
            }
            if let Some(prepared) = preservation.as_mut() {
                check_migration_records(&mut resolved, prepared, "firmware-writing")?;
            }
            check_manufacturing_records(&mut resolved, manufacturing.as_ref(), "firmware-writing")?;
            observer.diagnostic("firmware-transfer-attempt-two");
            if let Err((second_failure, _)) =
                transfer_registry_firmware(&mut resolved, image, observer)
            {
                if let Err(failure) = check_manufacturing_records(
                    &mut resolved,
                    manufacturing.as_ref(),
                    "firmware-finalizing",
                ) {
                    if failure.code() != "firmware-manufacturing-unreadable" {
                        return Err(failure);
                    }
                    drop(resolved);
                    let _settled = reopen_settled_manufacturing_records(
                        &mut self.registry,
                        &mut self.platform,
                        device_id,
                        retry_revision,
                        manufacturing.as_ref(),
                        "firmware-finalizing",
                        failure,
                    )?;
                    // Never turn identity readback evidence into permission
                    // to finalize an image whose second transfer failed.
                    return Err(second_failure);
                }
                // Never send mode 5 after either complete transfer attempt
                // failed, even when the identity record remains readable.
                return Err(second_failure);
            }
        }

        if !observer.reached("firmware-finalizing", false) {
            return Err(cancelled_host_failure("firmware-finalizing"));
        }
        if let Err(failure) = check_manufacturing_records(
            &mut resolved,
            manufacturing.as_ref(),
            "firmware-finalizing",
        ) {
            if failure.code() != "firmware-manufacturing-unreadable" {
                return Err(failure);
            }
            // An uncertain command deliberately poisons its transport lease.
            // Reopen and fully revalidate this exact registry binding before
            // retrying only the read-only record proof.
            drop(resolved);
            resolved = reopen_settled_manufacturing_records(
                &mut self.registry,
                &mut self.platform,
                device_id,
                revision,
                manufacturing.as_ref(),
                "firmware-finalizing",
                failure,
            )?;
        }
        let finalizer = image
            .registry_finalize_command()
            .map_err(|_| firmware_preflight_failure("firmware-finalizing"))?;
        let first_finalizer = resolved.execute_firmware(&finalizer);
        let first_finalizer_failure =
            firmware_dispatch_failure("firmware-finalizing", &first_finalizer);
        drop(resolved);

        if !observer.reached("device-reconnecting", false) {
            return Err(cancelled_host_failure("device-reconnecting"));
        }
        let readback = self.reconcile_firmware_finalizer(
            device_id,
            image,
            (family, installed),
            &finalizer,
            first_finalizer_failure,
            (preservation.as_mut(), manufacturing.as_ref()),
        );
        // Verification also has an explicit failed outcome when no exact
        // rebound handle is available. Preserve the reconnect cause while
        // completing this final check instead of violating the service graph.
        if !observer.reached("firmware-readback", false) {
            return Err(cancelled_host_failure("firmware-readback"));
        }
        let readback = readback?;
        let (readback_family, readback_revision, readback_media_present) = readback.facts;
        if readback_family != family
            || readback_media_present
            || readback_revision != image.expected_revision()
        {
            return Err(firmware_preflight_failure("firmware-readback"));
        }
        Ok(readback.inventory)
    }

    /// Completes explicit verification after a failed transfer without replaying it.
    /// No finalizer is sent or published because a complete mode-4 transfer was
    /// not established. Read-only discovery and readback remain mandatory.
    /// The original error and incomplete recovery remain failures even if an
    /// inquiry happens to report the candidate version after partial transfer.
    fn complete_failed_firmware_checks(
        &mut self,
        device_id: &crate::model::DeviceId,
        observer: &mut HostWorkerObserver<'_>,
        failure: HostOperationFailure,
    ) -> HostOperationFailure {
        let failure = failure.with_cleanup(CleanupState::CompletionUnknown);
        if !observer.reached("device-reconnecting", false) {
            return failure;
        }
        let revision = self.rediscover_firmware_device(device_id);
        if !observer.reached("firmware-readback", false) {
            return failure;
        }
        if let Ok(revision) = revision
            && let Ok(mut rebound) = self
                .registry
                .resolve(&mut self.platform, device_id, revision)
        {
            // This is verification only: failed image transfer is never retried
            // or converted to success by seeing a matching revision here.
            let _ = rebound.firmware_facts();
        }
        failure
    }

    /// Verifies a post-finalizer binding while retaining its discovery capture.
    /// Releasing that probe can invalidate its native reopen recipe. A failed
    /// probe or identity check requires a fresh scan, never another image write.
    /// Revision, family and empty-bay facts are read through the same validated
    /// lease. Only an unresolved failed finalizer permits its one bounded retry.
    fn reconcile_firmware_finalizer(
        &mut self,
        device_id: &crate::model::DeviceId,
        image: &FirmwareImage,
        receiver: (ProductFamily, crate::firmware::FirmwareRevision),
        finalizer: &crate::protocol::Command,
        mut finalizer_failure: Option<(HostOperationFailure, bool)>,
        preservation: (
            Option<&mut crate::migration::PreparedMigration>,
            Option<&crate::firmware::manufacturing::ManufacturingRecord>,
        ),
    ) -> Result<FirmwareReadback, HostOperationFailure> {
        let (mut preservation, manufacturing) = preservation;
        let (family, installed) = receiver;
        let mut finalized_at = Instant::now();
        let reconnect_window = self
            .platform
            .firmware_reconnect_timeout()
            .min(Duration::from_secs(120));
        let mut deadline = finalized_at + reconnect_window;
        let mut retry_available = true;
        let mut activation_observed = false;
        let mut manufacturing_attempts = 0;
        loop {
            let finalizer_state = match finalizer_failure {
                None => FirmwareFinalizerState::Acknowledged(finalized_at + Duration::from_secs(1)),
                Some(_) if retry_available => FirmwareFinalizerState::AwaitingReconciliation,
                Some(_) => FirmwareFinalizerState::Exhausted,
            };
            let (binding, activated) = self.rediscover_after_finalizer(
                device_id,
                image,
                installed,
                finalizer_state,
                activation_observed,
                deadline,
            )?;
            activation_observed |= activated;
            let crate::platform::FirmwareDiscoveryBinding { report, lease } = binding;
            let lease = lease.ok_or_else(firmware_reconnect_failure)?;
            let revision = report
                .snapshots()
                .iter()
                .find(|snapshot| &snapshot.id == device_id)
                .map(|snapshot| snapshot.revision)
                .ok_or_else(firmware_reconnect_failure)?;
            let mut rebound = match self.registry.resolve_retained_firmware_lease(
                device_id,
                revision,
                self.platform.capabilities(),
                lease,
            ) {
                Ok(rebound) => rebound,
                Err(_) if Instant::now() < deadline => {
                    thread::sleep(Duration::from_millis(100));
                    continue;
                }
                Err(_) => return Err(firmware_reconnect_failure()),
            };
            let facts = match rebound.firmware_facts() {
                Ok(facts) => facts,
                Err(_) if Instant::now() < deadline => {
                    drop(rebound);
                    thread::sleep(Duration::from_millis(100));
                    continue;
                }
                Err(_) => return Err(firmware_reconnect_failure()),
            };
            let (rebound_family, rebound_installed, media_present) = facts;
            if rebound_family != family || media_present {
                return Err(firmware_reconnect_failure());
            }
            // Both success and the one permitted mode-5 retry require fresh raw
            // equality on this retained discovery lease. Never retry a changed unit.
            // Vendor firmware has no established raw-record readback command.
            // Its pre-update backup and pre-finalizer checks still remain mandatory.
            // An unexpected receiver revision must not gain this exception.
            if rebound_installed.has_openrdx_update_receiver()
                || rebound_installed != image.expected_revision()
            {
                manufacturing_attempts += 1;
                match check_manufacturing_records(&mut rebound, manufacturing, "firmware-readback")
                {
                    Err(failure)
                        if failure.code() == "firmware-manufacturing-unreadable"
                            && manufacturing_attempts < FIRMWARE_RECORD_SETTLE_ATTEMPTS
                            && Instant::now() < deadline =>
                    {
                        // The outer loop reacquires and fully validates a fresh
                        // retained discovery lease before the next read.
                        drop(rebound);
                        thread::sleep(FIRMWARE_RECORD_SETTLE_INTERVAL);
                        continue;
                    }
                    result => result?,
                }
            }
            if let Some((failure, retryable)) = finalizer_failure {
                if rebound_installed == image.expected_revision()
                    && (activation_observed || image.expected_revision() != installed)
                {
                    if let Some(prepared) = preservation.as_deref_mut() {
                        verify_migration_records(
                            &mut rebound,
                            prepared,
                            crate::migration::MigrationEvent::FinalUpdateVerified,
                            "firmware-readback",
                        )?;
                    }
                    return Ok(FirmwareReadback {
                        facts,
                        inventory: report,
                    });
                }
                if !retry_available || !retryable || rebound_installed != installed {
                    return Err(failure);
                }
                if let Some(prepared) = preservation.as_deref_mut() {
                    check_migration_records(&mut rebound, prepared, "device-reconnecting")?;
                }
                retry_available = false;
                finalizer_failure = firmware_dispatch_failure(
                    "firmware-finalizing",
                    &rebound.execute_firmware(finalizer),
                );
                activation_observed = false;
                finalized_at = Instant::now();
                deadline = finalized_at + reconnect_window;
                continue;
            }
            if let Some(prepared) = preservation.as_deref_mut() {
                verify_migration_records(
                    &mut rebound,
                    prepared,
                    crate::migration::MigrationEvent::FinalUpdateVerified,
                    "firmware-readback",
                )?;
            }
            return Ok(FirmwareReadback {
                facts,
                inventory: report,
            });
        }
    }

    /// Returns a fresh binding and whether receiver activation was observed.
    /// Waits for an installed OpenRDX receiver's delayed activation rather than
    /// accepting its pre-reset inquiry, including restoration of a vendor image.
    /// The receiver acknowledges mode-5 before its five-tick delayed USB reset.
    /// A changed firmware revision or clean departure/return proves activation.
    /// macOS can hide a brief reset while rematching its storage stack. A GOOD
    /// commit reply also permits same-release readback after the receiver's
    /// reset delay. This does not claim an observed departure: the caller must
    /// retain the probe and verify exact identity, empty media state and revision.
    /// Cached snapshots alone and failed probes never prove successful readback.
    /// After a failed finalizer only, unchanged firmware may return after the
    /// deadline so the existing bounded finalizer retry can make its decision.
    fn rediscover_after_finalizer(
        &mut self,
        device_id: &crate::model::DeviceId,
        image: &FirmwareImage,
        installed: crate::firmware::FirmwareRevision,
        finalizer: FirmwareFinalizerState,
        activation_observed: bool,
        deadline: Instant,
    ) -> Result<(crate::platform::FirmwareDiscoveryBinding, bool), HostOperationFailure> {
        if !installed.has_openrdx_update_receiver() {
            return self
                .rediscover_firmware_binding(device_id)
                .map(|report| (report, false));
        }
        let mut departed = activation_observed;
        let mut last_visible = None;
        loop {
            // Never hold an earlier exclusive USB probe while opening the next.
            drop(last_visible.take());
            if let Ok(binding) = self.scan_firmware_binding(device_id) {
                if let Some(snapshot) = binding
                    .report
                    .snapshots()
                    .iter()
                    .find(|snapshot| &snapshot.id == device_id)
                {
                    let reported = snapshot
                        .drive
                        .firmware_revision
                        .as_ref()
                        .and_then(|revision| revision.as_str().parse::<u16>().ok());
                    if departed || reported.is_some_and(|revision| revision != installed.get()) {
                        return Ok((binding, true));
                    }
                    if matches!(finalizer, FirmwareFinalizerState::Acknowledged(readback_after)
                        if Instant::now() >= readback_after
                            && installed == image.expected_revision()
                            && reported == Some(image.expected_revision().get()))
                    {
                        // GOOD is commit evidence in the OpenRDX receiver. Do
                        // not require observing a reset hidden by OS discovery,
                        // and do not call this cached revision fresh readback.
                        return Ok((binding, false));
                    }
                    last_visible = Some(binding);
                } else if binding.report.diagnostics().rejections().is_empty() {
                    departed = true;
                }
            }
            if Instant::now() >= deadline {
                break;
            }
            thread::sleep(Duration::from_millis(100));
        }
        if matches!(finalizer, FirmwareFinalizerState::AwaitingReconciliation)
            && let Some(binding) = last_visible
        {
            return Ok((binding, false));
        }
        Err(firmware_reconnect_failure())
    }

    /// Keeps the exact target probe alive until the readback decision is complete.
    pub(super) fn scan_firmware_binding(
        &mut self,
        device_id: &crate::model::DeviceId,
    ) -> Result<crate::platform::FirmwareDiscoveryBinding, ServiceRejection> {
        crate::platform::discover_firmware_device_binding(
            &mut self.platform,
            &mut self.registry,
            device_id,
        )
        .map_err(platform_rejection)
    }

    /// Performs bounded discovery for a vendor finalizer while retaining its probe.
    fn rediscover_firmware_binding(
        &mut self,
        device_id: &crate::model::DeviceId,
    ) -> Result<crate::platform::FirmwareDiscoveryBinding, HostOperationFailure> {
        for _ in 0..15 {
            if let Ok(binding) = self.scan_firmware_binding(device_id)
                && binding.lease.is_some()
            {
                return Ok(binding);
            }
        }
        Err(firmware_reconnect_failure())
    }

    /// Refreshes private reconnect evidence without changing public inventory.
    /// The service loop publishes the verified report with the success terminal;
    /// a concurrent devices-list must keep seeing its last announced revision.
    fn scan_firmware_devices(
        &mut self,
        device_id: &crate::model::DeviceId,
    ) -> Result<ValidatedDiscoveryReport, ServiceRejection> {
        crate::platform::discover_firmware_device_report(
            &mut self.platform,
            &mut self.registry,
            device_id,
        )
        .map_err(platform_rejection)
    }

    /// Performs bounded rediscovery and returns the exact same opaque device revision.
    fn rediscover_firmware_device(
        &mut self,
        device_id: &crate::model::DeviceId,
    ) -> Result<crate::model::DiscoveryRevision, HostOperationFailure> {
        self.rediscover_firmware_report(device_id)?
            .snapshots()
            .iter()
            .find(|snapshot| &snapshot.id == device_id)
            .map(|snapshot| snapshot.revision)
            .ok_or_else(firmware_reconnect_failure)
    }

    /// Retains a complete private discovery report for exact-device reconciliation.
    fn rediscover_firmware_report(
        &mut self,
        device_id: &crate::model::DeviceId,
    ) -> Result<ValidatedDiscoveryReport, HostOperationFailure> {
        for _ in 0..15 {
            if let Ok(report) = self.scan_firmware_devices(device_id)
                && report
                    .snapshots()
                    .iter()
                    .any(|snapshot| &snapshot.id == device_id)
            {
                return Ok(report);
            }
        }
        Err(firmware_reconnect_failure())
    }
}

/// Requires raw byte equality before any retry/finalizer and after activation.
fn check_manufacturing_records(
    resolved: &mut ResolvedDevice<'_>,
    expected: Option<&crate::firmware::manufacturing::ManufacturingRecord>,
    stage: &'static str,
) -> Result<(), HostOperationFailure> {
    if let Some(expected) = expected {
        resolved
            .manufacturing_record()
            .and_then(|actual| expected.verify(&actual))
            .map_err(|cause| migration_record_failure(stage, cause))?;
    }
    Ok(())
}

/// Reopens an exact registry binding once after an uncertain manufacturing read.
/// Every successful reopen repeats the complete identity and capability proof
/// before another read-only record capture. Changed or invalid bytes fail
/// immediately, and no firmware transfer or finalizer command is replayed.
fn reopen_settled_manufacturing_records<'registry, B: PlatformBackend>(
    registry: &'registry mut DeviceRegistry,
    platform: &mut B,
    device_id: &crate::model::DeviceId,
    revision: crate::model::DiscoveryRevision,
    expected: Option<&crate::firmware::manufacturing::ManufacturingRecord>,
    stage: &'static str,
    last_failure: HostOperationFailure,
) -> Result<ResolvedDevice<'registry>, HostOperationFailure> {
    thread::sleep(FIRMWARE_RECORD_REOPEN_DELAY);
    let mut reopened = registry
        .resolve(platform, device_id, revision)
        .map_err(|_| last_failure)?;
    check_manufacturing_records(&mut reopened, expected, stage)?;
    Ok(reopened)
}

/// Requires fresh same-lease identity and record proof before migration success.
fn verify_migration_records(
    resolved: &mut ResolvedDevice<'_>,
    prepared: &mut crate::migration::PreparedMigration,
    event: crate::migration::MigrationEvent,
    stage: &'static str,
) -> Result<(), HostOperationFailure> {
    check_migration_records(resolved, prepared, stage)?;
    prepared.journal(event).map_err(|_| {
        migration_record_failure(stage, HostPrimitiveError::MigrationRecoveryUnavailable)
    })
}

/// A record failure after staging cannot imply that the source firmware survived.
fn migration_record_failure(
    stage: &'static str,
    cause: HostPrimitiveError,
) -> HostOperationFailure {
    HostOperationFailure::from_primitive(stage, PrimitiveFailure::completion_unknown(cause))
        .with_cleanup(CleanupState::CompletionUnknown)
}

/// Revalidates the original migration binding before any retry on a new lease.
///
/// Ordinary DeviceId identity is insufficient: the persisted physical port and
/// every preserved exposed field must still match before another mutation.
fn check_migration_records(
    resolved: &mut ResolvedDevice<'_>,
    prepared: &mut crate::migration::PreparedMigration,
    stage: &'static str,
) -> Result<(), HostOperationFailure> {
    let result = resolved
        .migration_readback()
        .and_then(|capture| prepared.verify_records(&capture));
    if result.is_err() {
        let _ = prepared.journal(crate::migration::MigrationEvent::RecoveryRequired);
        return Err(migration_record_failure(
            stage,
            HostPrimitiveError::MigrationReadbackMismatch,
        ));
    }
    Ok(())
}
