// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Service host-operation adapter for this platform.

use super::*;

impl MacOsDeviceHandle {
    /// Returns the currently live macOS authority for one host operation.
    ///
    /// # Errors
    ///
    /// Returns a stale-binding failure while an authority handoff is incomplete.
    fn authority_mut(
        &mut self,
    ) -> Result<&mut rdx_macos_native::MacDevice, crate::operations::PrimitiveFailure> {
        self._authority.as_mut().ok_or_else(|| {
            crate::operations::PrimitiveFailure::not_attempted(
                crate::operations::HostPrimitiveError::StaleBinding,
            )
        })
    }

    /// Starts a disposable capture owner after releasing every parent-side IOKit client.
    ///
    /// # Errors
    ///
    /// Returns a sanitized spawn, rematch, or native capture failure.
    fn start_scsi_worker(&mut self) -> Result<(), rdx_macos_native::NativeError> {
        if self.scsi.is_some() {
            return Ok(());
        }
        if let Some(authority) = self._authority.as_mut() {
            // A prior label/host read returned the disk to macOS storage.
            // Capture cannot be reacquired until that exact disk is unmounted.
            self.cached_host_facts = Some(super::scsi_handoff::prepare_capture(
                authority,
                self.cached_host_facts,
                self.storage_unmounted_for_format,
            )?);
            authority.invalidate_media_mapping_for_rematch();
        }
        self._authority = None;
        self.scsi = Some(rdx_macos_native::MacScsiWorkerLease::spawn(
            &self.rematch_identity,
        )?);
        Ok(())
    }

    /// Surrenders child-owned USB capture without exposing that lifecycle to the parent.
    ///
    /// # Errors
    ///
    /// Returns a certainty-preserving host failure if the child cannot be released.
    fn release_scsi_worker(&mut self) -> Result<(), crate::operations::PrimitiveFailure> {
        let Some(worker) = self.scsi.take() else {
            return Ok(());
        };
        worker
            .release_for_storage_rematch()
            .map_err(macos_host_not_attempted)
    }

    /// Reopens one unique same-device authority after the storage driver rematches.
    ///
    /// # Errors
    ///
    /// Returns a stale-binding or sanitized native failure after the bounded deadline.
    fn reopen_authority_after_storage_rematch(
        &mut self,
    ) -> Result<(), crate::operations::PrimitiveFailure> {
        if self._authority.is_some() {
            return Ok(());
        }
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
        loop {
            match rdx_macos_native::MacDevice::open_after_storage_rematch(&self.rematch_identity) {
                Ok(authority) => {
                    self._authority = Some(authority);
                    return Ok(());
                }
                Err(error)
                    if std::time::Instant::now() < deadline
                        && transient_storage_rematch_error(error) => {}
                Err(error) => return Err(macos_host_not_attempted(error)),
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
    }

    /// Moves from child-owned SCSI capture to parent-owned Disk Arbitration access.
    ///
    /// # Errors
    ///
    /// Returns a sanitized child-release or same-device rematch failure.
    fn prepare_host_authority(&mut self) -> Result<(), crate::operations::PrimitiveFailure> {
        self.release_scsi_worker()?;
        self.reopen_authority_after_storage_rematch()
    }
}

impl crate::platform::PlatformDeviceHandle for MacOsDeviceHandle {
    /// Reads the native label after returning storage authority to the host.
    fn host_volume_label(
        &mut self,
    ) -> Result<Option<crate::model::VolumeLabel>, crate::operations::PrimitiveFailure> {
        let expected = self.cached_host_facts.ok_or_else(|| {
            macos_host_not_attempted(rdx_macos_native::NativeError::EvidenceIncomplete)
        })?;
        self.prepare_host_authority()?;
        // The SCSI lease temporarily unmounts storage. Reading the label before
        // automount completes spuriously changes rename capability and rejects
        // the entire binding, including unrelated format confirmations.
        let label = super::label_rematch::read_remounted_label(
            self.authority_mut()?,
            expected,
            std::time::Instant::now() + std::time::Duration::from_secs(3),
            || std::thread::sleep(std::time::Duration::from_millis(100)),
        )
        .map_err(macos_host_not_attempted)?;
        let label = crate::model::VolumeLabel::new(label).map_err(|_| {
            macos_host_not_attempted(rdx_macos_native::NativeError::EvidenceIncomplete)
        })?;
        if self.storage_unmounted_for_format {
            // Protocol revalidation can remount storage while reading the
            // label. Restore our known format-owned unmount before returning
            // authority to a host boundary; the formatter requires it.
            let mut mapping = self
                .authority_mut()?
                .pin_media()
                .map_err(macos_host_not_attempted)?;
            map_macos_host_outcome(mapping.unmount(30_000))?;
        }
        Ok(Some(label))
    }

    /// Renames the exact mounted cartridge and preserves native outcome certainty.
    fn set_volume_label_exact(
        &mut self,
        label: &crate::model::VolumeLabel,
    ) -> Result<(), crate::operations::PrimitiveFailure> {
        self.cached_host_facts = None;
        self.prepare_host_authority()?;
        map_macos_host_outcome(self.authority_mut()?.set_volume_label(label.as_str()))
    }
    /// Reads the USB identity retained by the same exclusive SCSI worker.
    fn migration_usb_identity(
        &mut self,
    ) -> Result<crate::migration::MigrationUsbIdentity, crate::migration::MigrationError> {
        self.start_scsi_worker()
            .map_err(|_| crate::migration::MigrationError::InvalidCapture)?;
        let identity = self
            .scsi
            .as_mut()
            .ok_or(crate::migration::MigrationError::InvalidCapture)?
            .usb_identity()
            .map_err(|_| crate::migration::MigrationError::InvalidCapture)?;
        Ok(crate::migration::MigrationUsbIdentity {
            serial: identity.serial().to_owned(),
            location_id: identity.location_id(),
            vendor_id: identity.vendor_id(),
            product_id: identity.product_id(),
        })
    }

    /// Executes one trusted immutable command through the same exact IOKit lease.
    fn execute(&mut self, command: &Command) -> CommandDispatch {
        let packet = match build_scsi_task(command) {
            Ok(packet) => packet,
            Err(_) => return CommandDispatch::NotSent(TransportError::Unavailable),
        };
        let operation = match native_operation(&packet) {
            Ok(operation) => operation,
            Err(_) => return CommandDispatch::NotSent(TransportError::Unavailable),
        };
        if self.start_scsi_worker().is_err() {
            return CommandDispatch::NotSent(TransportError::Unavailable);
        }
        let Some(scsi) = self.scsi.as_mut() else {
            return CommandDispatch::NotSent(TransportError::Unavailable);
        };
        let completion = match scsi.execute(operation) {
            rdx_macos_native::Completion::NotAttempted(error) => {
                NativeScsiTaskCompletion::not_attempted(map_native_io_failure(error))
            }
            rdx_macos_native::Completion::AttemptedError(error) => {
                NativeScsiTaskCompletion::attempted_error(map_native_io_failure(error))
            }
            rdx_macos_native::Completion::Device {
                scsi_status,
                service_response,
                transferred_length,
                data,
                sense_reported_length,
                sense,
            } => NativeScsiTaskCompletion::device(
                scsi_status,
                service_response,
                transferred_length,
                data,
                sense_reported_length,
                sense,
            ),
        };
        convert_scsi_task_completion(&packet, completion)
    }

    /// Returns fresh path-free Disk Arbitration media facts.
    fn host_volume_facts(
        &mut self,
    ) -> Result<crate::operations::HostVolumeFacts, crate::operations::PrimitiveFailure> {
        if self.scsi.is_some() {
            if let Some(facts) = self.cached_host_facts {
                // The protocol identity is revalidated through this same
                // exclusive lease before every host boundary. Reuse the host
                // snapshot bound to that lease so reading facts cannot release
                // the authority needed by the immediate operation preflight.
                return Ok(facts);
            }
        }
        let previous = self.cached_host_facts;
        self.cached_host_facts = None;
        self.prepare_host_authority()?;
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
        let mapping = loop {
            match self.authority_mut()?.pin_media() {
                Ok(mapping) => break mapping,
                Err(rdx_macos_native::NativeError::DeviceRemoved)
                | Err(rdx_macos_native::NativeError::EvidenceIncomplete)
                    if std::time::Instant::now() < deadline =>
                {
                    std::thread::sleep(std::time::Duration::from_millis(100));
                }
                Err(error) => return Err(macos_host_not_attempted(error)),
            }
        };
        let (writable, free_bytes, capacity_bytes) = mapping.volume_facts();
        let media_fingerprint = mapping.whole_media_present().then(|| {
            crate::platform::media_fingerprint(
                b"macos-da-iokit-v1",
                capacity_bytes,
                writable,
                mapping.identity_material(),
            )
        });
        let facts = crate::operations::HostVolumeFacts {
            media_present: mapping.whole_media_present(),
            writable,
            mounted: mapping.mounted_media_count() > 0,
            free_bytes,
            capacity_bytes,
            filesystem: mapping
                .mounted_filesystem()
                .map(|filesystem| match filesystem {
                    rdx_macos_native::MountedFilesystem::ExFat => {
                        crate::operations::FileSystem::ExFat
                    }
                    rdx_macos_native::MountedFilesystem::MacOs(selector) => {
                        crate::operations::FileSystem::MacOs(match selector {
                            3 => crate::model::Filesystem::Fat,
                            7 => crate::model::Filesystem::Hfs,
                            _ => crate::model::Filesystem::Apfs,
                        })
                    }
                    rdx_macos_native::MountedFilesystem::Ntfs => {
                        crate::operations::FileSystem::Ntfs
                    }
                }),
            media_fingerprint,
            topology: if mapping.mutation_topology_safe() {
                crate::operations::VolumeTopology::Simple
            } else {
                crate::operations::VolumeTopology::BootOrSystem
            },
        };
        drop(mapping);
        self.cached_host_facts = Some(
            super::scsi_handoff::capture_facts(previous, facts, self.storage_unmounted_for_format)
                .map_err(macos_host_not_attempted)?,
        );
        Ok(facts)
    }

    /// Runs exact mount-relative native file I/O with independent cleanup evidence.
    fn write_read_file(
        &mut self,
        filename: &str,
        bytes: &[u8],
    ) -> Result<crate::operations::WriteReadPrimitiveResult, crate::operations::PrimitiveFailure>
    {
        self.prepare_host_authority()?;
        let mut mapping = self
            .authority_mut()?
            .pin_media()
            .map_err(macos_host_not_attempted)?;
        let (operation, operation_certainty, cleanup) =
            mapping.write_read_file(filename, bytes).into_parts();
        Ok(crate::operations::WriteReadPrimitiveResult {
            operation: operation.map_err(|_| {
                map_macos_host_outcome(operation_certainty)
                    .expect_err("failed operation has failure certainty")
            }),
            cleanup: map_macos_host_outcome(cleanup),
        })
    }

    /// Keeps the transient encryption secret on this unique native lease only.
    fn set_format_passphrase(
        &mut self,
        passphrase: Option<crate::model::FormatPassphrase>,
    ) -> Result<(), crate::operations::PrimitiveFailure> {
        self.format_passphrase = passphrase;
        Ok(())
    }

    /// Checks native formatting support, capacity, and password before any unmount.
    fn preflight_format(
        &mut self,
        filesystem: crate::operations::FileSystem,
    ) -> Result<(), crate::operations::PrimitiveFailure> {
        use crate::operations::{FileSystem, HostPrimitiveError, PrimitiveFailure};
        let selected = match filesystem {
            FileSystem::Ntfs | FileSystem::Linux(_) => {
                return Err(PrimitiveFailure::not_attempted(
                    HostPrimitiveError::DependencyMissing,
                ));
            }
            FileSystem::ExFat => crate::model::Filesystem::Exfat,
            FileSystem::MacOs(selected) => selected,
        };
        if selected.encrypted() != self.format_passphrase.is_some()
            || selected.macos_selector().is_none()
        {
            return Err(PrimitiveFailure::not_attempted(
                HostPrimitiveError::DependencyMissing,
            ));
        }
        self.prepare_host_authority()?;
        let mapping = self
            .authority_mut()?
            .pin_media()
            .map_err(macos_host_not_attempted)?;
        let capacity = mapping.volume_facts().2;
        let invalid_size = match selected {
            crate::model::Filesystem::Fat12 => capacity > 32 * 1024 * 1024,
            crate::model::Filesystem::Fat16 => capacity > 2 * 1024 * 1024 * 1024,
            crate::model::Filesystem::Fat | crate::model::Filesystem::Fat32 => {
                capacity > 2 * 1024 * 1024 * 1024 * 1024
            }
            _ => false,
        };
        if !mapping.whole_media_present()
            || !mapping.mutation_topology_safe()
            || capacity == 0
            || invalid_size
        {
            return Err(PrimitiveFailure::not_attempted(
                HostPrimitiveError::UnsafeTopology,
            ));
        }
        self.pending_format = Some(filesystem);
        self.combined_format_complete = false;
        Ok(())
    }

    /// Unmounts the exact whole disk through retained Disk Arbitration identity.
    fn unmount_exact_volumes(&mut self) -> Result<(), crate::operations::PrimitiveFailure> {
        self.prepare_host_authority()?;
        let mut mapping = self
            .authority_mut()?
            .pin_media()
            .map_err(macos_host_not_attempted)?;
        map_macos_host_outcome(mapping.unmount(30_000))?;
        self.storage_unmounted_for_format = self.pending_format.is_some();
        Ok(())
    }

    /// Unmounts and ejects the exact cartridge through Disk Arbitration.
    fn safe_eject_exact(
        &mut self,
        after_unmount: &mut dyn FnMut() -> bool,
    ) -> Result<(), crate::operations::PrimitiveFailure> {
        let Some(expected_media_fingerprint) = self
            .cached_host_facts
            .and_then(|facts| facts.media_fingerprint)
        else {
            return Err(crate::operations::PrimitiveFailure::not_attempted(
                crate::operations::HostPrimitiveError::StaleBinding,
            ));
        };
        if self.scsi.is_none() {
            return Err(crate::operations::PrimitiveFailure::not_attempted(
                crate::operations::HostPrimitiveError::StaleBinding,
            ));
        }

        self.safe_eject_dispatched = false;
        self.prepare_host_authority()?;
        eprintln!("openrdx-hardware: trace eject-media-rematch-enter");
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
        let mut mapping = loop {
            match self.authority_mut()?.pin_media() {
                Ok(mapping) => {
                    let facts = host_facts_from_mapping(&mapping);
                    match safe_eject_rematch_state(
                        expected_media_fingerprint,
                        mapping.whole_media_present(),
                        mapping.media_count(),
                        facts.media_fingerprint,
                    ) {
                        SafeEjectRematchState::Ready => break mapping,
                        SafeEjectRematchState::Stale => {
                            eprintln!("openrdx-hardware: trace eject-media-rematch-stale");
                            return Err(crate::operations::PrimitiveFailure::not_attempted(
                                crate::operations::HostPrimitiveError::StaleBinding,
                            ));
                        }
                        SafeEjectRematchState::Waiting => drop(mapping),
                    }
                }
                Err(error)
                    if std::time::Instant::now() < deadline
                        && transient_storage_rematch_error(error) => {}
                Err(error) => return Err(macos_host_not_attempted(error)),
            }
            if std::time::Instant::now() >= deadline {
                eprintln!("openrdx-hardware: trace eject-media-rematch-timed-out");
                return Err(crate::operations::PrimitiveFailure::not_attempted(
                    crate::operations::HostPrimitiveError::TimedOut,
                ));
            }
            self._authority = None;
            std::thread::sleep(std::time::Duration::from_millis(100));
            self.reopen_authority_after_storage_rematch()?;
        };
        eprintln!("openrdx-hardware: trace eject-media-rematch-return");
        eprintln!("openrdx-hardware: trace eject-da-unmount-enter");
        map_macos_host_outcome(mapping.unmount_for_eject(30_000))?;
        eprintln!("openrdx-hardware: trace eject-da-unmount-return");
        eprintln!("openrdx-hardware: trace eject-stage-advance-enter");
        if !after_unmount() {
            return Err(crate::operations::PrimitiveFailure::completion_unknown(
                crate::operations::HostPrimitiveError::Cancelled,
            ));
        }
        eprintln!("openrdx-hardware: trace eject-stage-advance-return");
        eprintln!("openrdx-hardware: trace eject-da-eject-enter");
        let eject_result = map_macos_host_outcome(mapping.eject(30_000));
        eprintln!("openrdx-hardware: trace eject-da-eject-return");
        if eject_result.is_ok()
            || eject_result.as_ref().is_err_and(|failure| {
                failure.certainty == crate::operations::MutationCertainty::CompletionUnknown
            })
        {
            self.safe_eject_dispatched = true;
        }
        eject_result
    }

    /// Ejects through Disk Arbitration; macOS exposes no separately proven force API.
    fn eject_exact(&mut self, force: bool) -> Result<(), crate::operations::PrimitiveFailure> {
        if force {
            return Err(crate::operations::PrimitiveFailure::not_attempted(
                crate::operations::HostPrimitiveError::UnsupportedPlatform,
            ));
        }
        self.prepare_host_authority()?;
        let mut mapping = self
            .authority_mut()?
            .pin_media()
            .map_err(macos_host_not_attempted)?;
        map_macos_host_outcome(mapping.eject(30_000))
    }

    /// Runs Apple's format and readback pipeline on the exact retained cartridge.
    fn create_single_partition(
        &mut self,
        _mbr_signature: u32,
    ) -> Result<(), crate::operations::PrimitiveFailure> {
        use crate::operations::{FileSystem, HostPrimitiveError, PrimitiveFailure};
        let selected = match self.pending_format {
            Some(FileSystem::ExFat) => crate::model::Filesystem::Exfat,
            Some(FileSystem::MacOs(selected)) => selected,
            _ => {
                return Err(PrimitiveFailure::not_attempted(
                    HostPrimitiveError::DependencyMissing,
                ));
            }
        };
        self.prepare_host_authority()?;
        let password = self.format_passphrase.take();
        let outcome = self.authority_mut()?.system_format(
            selected.macos_selector().expect("preflight selector"),
            password
                .as_ref()
                .map(crate::model::FormatPassphrase::as_str),
        );
        map_macos_host_outcome(outcome)?;
        self.combined_format_complete = true;
        Ok(())
    }

    /// Confirms the native combined layout, filesystem, and readback completed.
    fn completed_format(&self) -> Option<crate::operations::FileSystem> {
        self.combined_format_complete
            .then_some(self.pending_format)
            .flatten()
    }

    /// Acknowledges only the filesystem whose native combined readback completed.
    fn format_partition(
        &mut self,
        filesystem: crate::operations::FileSystem,
    ) -> Result<(), crate::operations::PrimitiveFailure> {
        if self.pending_format == Some(filesystem) && self.combined_format_complete {
            Ok(())
        } else {
            Err(crate::operations::PrimitiveFailure::not_attempted(
                crate::operations::HostPrimitiveError::StaleBinding,
            ))
        }
    }

    /// Waits until Disk Arbitration can no longer map the exact retained media.
    fn verify_eject_departure(&mut self) -> Result<(), crate::operations::PrimitiveFailure> {
        if !self.safe_eject_dispatched {
            return Err(crate::operations::PrimitiveFailure::completion_unknown(
                crate::operations::HostPrimitiveError::StaleBinding,
            ));
        }
        eprintln!("openrdx-hardware: trace eject-readback-enter");
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        let mut reported_waiting = false;
        let mut departure_confirmation = SafeEjectDepartureConfirmation::default();
        loop {
            let observation = self.authority_mut()?.media_present_without_mapping();
            match departure_confirmation.observe(observation) {
                SafeEjectDepartureReadbackState::Departed => {
                    eprintln!("openrdx-hardware: trace eject-readback-departed");
                    return Ok(());
                }
                SafeEjectDepartureReadbackState::Failed(error) => {
                    eprintln!("openrdx-hardware: trace eject-readback-failed");
                    return Err(crate::operations::PrimitiveFailure::completion_unknown(
                        map_macos_host_error(error),
                    ));
                }
                SafeEjectDepartureReadbackState::Waiting
                    if std::time::Instant::now() >= deadline =>
                {
                    eprintln!("openrdx-hardware: trace eject-readback-timed-out");
                    return Err(crate::operations::PrimitiveFailure::completion_unknown(
                        crate::operations::HostPrimitiveError::TimedOut,
                    ));
                }
                SafeEjectDepartureReadbackState::Waiting => {
                    if !reported_waiting {
                        eprintln!("openrdx-hardware: trace eject-readback-waiting");
                        reported_waiting = true;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(50));
                }
            }
        }
    }

    /// Consumes the native result only after exact filesystem/encryption readback.
    fn verify_format_rediscovery(
        &mut self,
        filesystem: crate::operations::FileSystem,
        _previous_capacity: u64,
    ) -> Result<(), crate::operations::PrimitiveFailure> {
        if self.pending_format == Some(filesystem) && self.combined_format_complete {
            self.pending_format = None;
            self.combined_format_complete = false;
            self.cached_host_facts = None;
            Ok(())
        } else {
            Err(crate::operations::PrimitiveFailure::completion_unknown(
                crate::operations::HostPrimitiveError::StaleBinding,
            ))
        }
    }
}

/// Maps pre-dispatch macOS native evidence into the shared host contract.
#[cfg(target_os = "macos")]
fn macos_host_not_attempted(
    error: rdx_macos_native::NativeError,
) -> crate::operations::PrimitiveFailure {
    crate::operations::PrimitiveFailure::not_attempted(map_macos_host_error(error))
}

/// Maps one Disk Arbitration completion without losing dispatch certainty.
#[cfg(target_os = "macos")]
fn map_macos_host_outcome(
    outcome: rdx_macos_native::HostOperationOutcome,
) -> Result<(), crate::operations::PrimitiveFailure> {
    use rdx_macos_native::HostOperationOutcome;

    match outcome {
        HostOperationOutcome::Succeeded => Ok(()),
        HostOperationOutcome::NotAttempted(error) => Err(
            crate::operations::PrimitiveFailure::not_attempted(map_macos_host_error(error)),
        ),
        HostOperationOutcome::DefinitelyRejected(error) => Err(
            crate::operations::PrimitiveFailure::definitely_rejected(map_macos_host_error(error)),
        ),
        HostOperationOutcome::CompletionUnknown(error) => Err(
            crate::operations::PrimitiveFailure::completion_unknown(map_macos_host_error(error)),
        ),
    }
}

/// Maps sanitized macOS native errors into shared host-operation causes.
#[cfg(target_os = "macos")]
const fn map_macos_host_error(
    error: rdx_macos_native::NativeError,
) -> crate::operations::HostPrimitiveError {
    use crate::operations::HostPrimitiveError;
    use rdx_macos_native::NativeError;

    match error {
        NativeError::Busy => HostPrimitiveError::Busy,
        NativeError::TimedOut => HostPrimitiveError::TimedOut,
        NativeError::DeviceRemoved | NativeError::EvidenceIncomplete => {
            HostPrimitiveError::StaleBinding
        }
        NativeError::UnsupportedPlatform | NativeError::TransportUnavailable => {
            HostPrimitiveError::UnsupportedPlatform
        }
        NativeError::AccessDenied
        | NativeError::InvalidRequest
        | NativeError::EnumerationFailed
        | NativeError::ResourceLimit
        | NativeError::Other => HostPrimitiveError::Other,
    }
}
