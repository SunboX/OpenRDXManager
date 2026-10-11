// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Closed safe/force eject, formatting, file test, and drive-letter facade.

use super::*;

impl WindowsDevice {
    /// Reads the label only through a sole mounted retained volume GUID.
    pub fn volume_label(&mut self) -> Result<String, NativeError> {
        #[cfg(windows)]
        {
            self.inner.volume_label()
        }
        #[cfg(not(windows))]
        {
            Err(NativeError::UnsupportedPlatform)
        }
    }
    /// Reads the filesystem without publishing a native volume path.
    pub fn volume_filesystem(&mut self) -> Result<String, NativeError> {
        #[cfg(windows)]
        {
            self.inner.volume_filesystem()
        }
        #[cfg(not(windows))]
        {
            Err(NativeError::UnsupportedPlatform)
        }
    }
    /// Renames the current mounted cartridge and verifies native readback.
    pub fn set_volume_label(&mut self, label: &str) -> HostOperationOutcome {
        #[cfg(windows)]
        {
            self.inner.set_volume_label(label)
        }
        #[cfg(not(windows))]
        {
            let _ = label;
            HostOperationOutcome::NotAttempted(NativeError::UnsupportedPlatform)
        }
    }

    /// Flushes, locks, dismounts, and ejects exactly one mounted selected volume.
    ///
    /// The closed companion operation retains every exact volume lock across the
    /// physical-disk eject call. It never retries through a force path.
    #[must_use]
    pub fn safe_eject(&mut self) -> HostOperationOutcome {
        self.safe_eject_observed(&mut || true)
    }

    /// Flushes, locks, dismounts, and ejects with a causal post-unmount callback.
    ///
    /// The callback runs while exact volume locks remain retained and
    /// immediately before physical eject dispatch.
    #[must_use]
    pub fn safe_eject_observed(
        &mut self,
        after_unmount: &mut dyn FnMut() -> bool,
    ) -> HostOperationOutcome {
        #[cfg(windows)]
        {
            let volumes = match self.pin_volumes() {
                Ok(volumes) => volumes,
                Err(error) => return HostOperationOutcome::NotAttempted(error),
            };
            if volumes.mount_path_count == 0 {
                if !after_unmount() {
                    return HostOperationOutcome::CompletionUnknown(NativeError::Cancelled);
                }
                return volumes.eject_if_unmounted();
            }
            match volumes.dismount_all_exact() {
                SafeDismountOutcome::Ready(lease) => {
                    if !after_unmount() {
                        HostOperationOutcome::CompletionUnknown(NativeError::Cancelled)
                    } else {
                        lease.eject()
                    }
                }
                SafeDismountOutcome::NotAttempted(error) => {
                    HostOperationOutcome::NotAttempted(error)
                }
                SafeDismountOutcome::CompletionUnknown(error) => {
                    HostOperationOutcome::CompletionUnknown(error)
                }
            }
        }
        #[cfg(not(windows))]
        {
            let _ = after_unmount;
            HostOperationOutcome::NotAttempted(NativeError::UnsupportedPlatform)
        }
    }

    /// Flushes, locks, and dismounts the exact selected volumes without ejecting.
    #[must_use]
    pub fn unmount_all(&mut self) -> HostOperationOutcome {
        #[cfg(windows)]
        {
            let volumes = match self.pin_volumes() {
                Ok(volumes) => volumes,
                Err(error) => return HostOperationOutcome::NotAttempted(error),
            };
            if volumes.mount_path_count == 0 {
                return HostOperationOutcome::Succeeded;
            }
            match volumes.dismount_all_exact() {
                SafeDismountOutcome::Ready(_lease) => HostOperationOutcome::Succeeded,
                SafeDismountOutcome::NotAttempted(error) => {
                    HostOperationOutcome::NotAttempted(error)
                }
                SafeDismountOutcome::CompletionUnknown(error) => {
                    HostOperationOutcome::CompletionUnknown(error)
                }
            }
        }
        #[cfg(not(windows))]
        {
            HostOperationOutcome::NotAttempted(NativeError::UnsupportedPlatform)
        }
    }

    /// Requests physical eject without a host unmount after an external confirmation gate.
    #[must_use]
    pub fn force_eject(&mut self) -> HostOperationOutcome {
        #[cfg(windows)]
        {
            match self.inner.eject_media() {
                VolumeMutationOutcome::Succeeded => HostOperationOutcome::Succeeded,
                VolumeMutationOutcome::NotAttempted(error) => {
                    HostOperationOutcome::NotAttempted(error)
                }
                VolumeMutationOutcome::CompletionUnknown(error) => {
                    HostOperationOutcome::CompletionUnknown(error)
                }
            }
        }
        #[cfg(not(windows))]
        {
            HostOperationOutcome::NotAttempted(NativeError::UnsupportedPlatform)
        }
    }

    /// Returns exact write-protection, mounted, free-byte, and capacity facts.
    ///
    /// # Errors
    ///
    /// Fails closed when volume membership or a sole mounted target cannot be proven.
    pub fn volume_facts(&mut self) -> Result<(bool, bool, u64, u64, bool), NativeError> {
        #[cfg(windows)]
        {
            self.inner.volume_facts()
        }
        #[cfg(not(windows))]
        {
            Err(NativeError::UnsupportedPlatform)
        }
    }

    /// Returns format-only facts for a proven inactive EFI-plus-Apple data layout.
    ///
    /// # Errors
    /// Fails closed on incomplete Windows system-role or retained disk evidence.
    pub fn format_volume_facts(&mut self) -> Result<(bool, bool, u64, u64, bool), NativeError> {
        #[cfg(windows)]
        {
            self.inner.format_volume_facts()
        }
        #[cfg(not(windows))]
        {
            Err(NativeError::UnsupportedPlatform)
        }
    }

    /// Returns path-free kernel media-change material for the retained disk.
    ///
    /// # Errors
    ///
    /// Returns a sanitized no-media, stale-authority, or native query failure.
    pub fn media_identity_material(&mut self) -> Result<Vec<u8>, NativeError> {
        #[cfg(windows)]
        {
            self.inner.media_identity_material()
        }
        #[cfg(not(windows))]
        {
            Err(NativeError::UnsupportedPlatform)
        }
    }

    /// Runs exact-volume create-new/reparse-safe write, flush, reopen, read, and cleanup.
    #[must_use]
    pub fn write_read_file(&mut self, filename: &str, bytes: &[u8]) -> FileTestOutcome {
        #[cfg(windows)]
        {
            self.inner.write_read_file(filename, bytes)
        }
        #[cfg(not(windows))]
        {
            let _ = (filename, bytes);
            FileTestOutcome {
                operation: Err(NativeError::UnsupportedPlatform),
                operation_certainty: HostOperationOutcome::NotAttempted(
                    NativeError::UnsupportedPlatform,
                ),
                cleanup: HostOperationOutcome::NotAttempted(NativeError::UnsupportedPlatform),
            }
        }
    }

    /// Checks the Windows VDS formatter before any unmount or layout mutation.
    ///
    /// # Errors
    ///
    /// Returns a sanitized pre-dispatch dependency or authority failure.
    pub fn preflight_format(&mut self, filesystem: HostFilesystem) -> Result<(), NativeError> {
        #[cfg(windows)]
        {
            self.inner.preflight_format(filesystem)
        }
        #[cfg(not(windows))]
        {
            let _ = filesystem;
            Err(NativeError::UnsupportedPlatform)
        }
    }

    /// Applies a single-partition MBR layout through exact physical-disk IOCTLs.
    #[must_use]
    pub fn create_single_partition(&mut self, mbr_signature: u32) -> HostOperationOutcome {
        #[cfg(windows)]
        {
            self.inner.create_single_partition(mbr_signature)
        }
        #[cfg(not(windows))]
        {
            let _ = mbr_signature;
            HostOperationOutcome::NotAttempted(NativeError::UnsupportedPlatform)
        }
    }

    /// Formats the exact newly discovered sole volume through VDS FormatEx2.
    #[must_use]
    pub fn format_partition(&mut self, filesystem: HostFilesystem) -> HostOperationOutcome {
        #[cfg(windows)]
        {
            self.inner.format_partition(filesystem)
        }
        #[cfg(not(windows))]
        {
            let _ = filesystem;
            HostOperationOutcome::NotAttempted(NativeError::UnsupportedPlatform)
        }
    }

    /// Persists one collision-free preference under the exact validated serial key.
    #[must_use]
    pub fn set_drive_letter(&mut self, serial_key: &str, letter: char) -> HostOperationOutcome {
        #[cfg(windows)]
        {
            if let Err(error) = self.inner.revalidate_exact() {
                return HostOperationOutcome::NotAttempted(error);
            }
            let scanned = match self.inner.pin_volumes() {
                Ok((letters, _mounts, _inventory, leases)) => (letters, leases),
                Err(error) => return HostOperationOutcome::NotAttempted(error),
            };
            if scanned.0.iter().any(|current| *current != letter) {
                return HostOperationOutcome::NotAttempted(NativeError::Busy);
            }
            let ([] | [_]) = scanned.1.as_slice() else {
                return HostOperationOutcome::NotAttempted(NativeError::EvidenceIncomplete);
            };
            let Some(volume) = scanned.1.first() else {
                return drive_letter::set_preference(serial_key, letter);
            };
            if !volume.has_drive_letter(letter) {
                let outcome = volume.set_drive_letter(letter);
                if outcome != HostOperationOutcome::Succeeded {
                    return outcome;
                }
            }
            let key = match String::from_utf16(
                &volume.volume_key()[..volume.volume_key().len().saturating_sub(1)],
            ) {
                Ok(key) => key,
                Err(_) => {
                    return HostOperationOutcome::CompletionUnknown(
                        NativeError::EvidenceIncomplete,
                    );
                }
            };
            drive_letter::set_bound_preference(serial_key, letter, &key, true)
        }
        #[cfg(not(windows))]
        {
            let _ = (serial_key, letter);
            HostOperationOutcome::NotAttempted(NativeError::UnsupportedPlatform)
        }
    }

    /// Removes only the application-owned preference for the exact validated serial key.
    #[must_use]
    pub fn reset_drive_letter(&mut self, serial_key: &str) -> HostOperationOutcome {
        #[cfg(windows)]
        {
            if let Err(error) = self.inner.revalidate_exact() {
                return HostOperationOutcome::NotAttempted(error);
            }
            let preference = match drive_letter::preference(serial_key) {
                Ok(Some(preference)) => preference,
                Ok(None) => return HostOperationOutcome::Succeeded,
                Err(error) => return HostOperationOutcome::NotAttempted(error),
            };
            let scanned = match self.inner.pin_volumes() {
                Ok((_letters, _mounts, _inventory, leases)) => leases,
                Err(error) => return HostOperationOutcome::NotAttempted(error),
            };
            let ([] | [_]) = scanned.as_slice() else {
                return HostOperationOutcome::NotAttempted(NativeError::EvidenceIncomplete);
            };
            if let Some(volume) = scanned.first()
                && volume.has_drive_letter(preference.letter)
            {
                let current = match String::from_utf16(
                    &volume.volume_key()[..volume.volume_key().len().saturating_sub(1)],
                ) {
                    Ok(current) => current,
                    Err(_) => {
                        return HostOperationOutcome::NotAttempted(NativeError::EvidenceIncomplete);
                    }
                };
                if preference.volume_key.as_deref() != Some(current.as_str()) {
                    return HostOperationOutcome::NotAttempted(NativeError::InvalidRequest);
                }
                if let Err(error) = volume.reset_drive_letter(preference.letter) {
                    return HostOperationOutcome::CompletionUnknown(error);
                }
            }
            drive_letter::reset_preference(serial_key)
        }
        #[cfg(not(windows))]
        {
            let _ = serial_key;
            HostOperationOutcome::NotAttempted(NativeError::UnsupportedPlatform)
        }
    }

    /// Applies one stored app-owned preference on this validated media arrival.
    pub fn apply_drive_letter_preference(&mut self, serial_key: &str) -> HostOperationOutcome {
        #[cfg(windows)]
        {
            let preference = match drive_letter::preference(serial_key) {
                Ok(Some(preference)) => preference,
                Ok(None) => return HostOperationOutcome::Succeeded,
                Err(error) => return HostOperationOutcome::NotAttempted(error),
            };
            let scanned = match self.inner.pin_volumes() {
                Ok((letters, mounts, _inventory, leases)) => (letters, mounts, leases),
                Err(error) => return HostOperationOutcome::NotAttempted(error),
            };
            let selected_owns_target = scanned
                .2
                .first()
                .is_some_and(|volume| volume.has_drive_letter(preference.letter));
            let collision = match drive_letter::target_reserved_elsewhere(
                serial_key,
                preference.letter,
                selected_owns_target,
            ) {
                Ok(collision) => collision,
                Err(error) => return HostOperationOutcome::NotAttempted(error),
            };
            let plan = match crate::plan_arrival_drive_letter(
                scanned.2.len(),
                scanned.1,
                &scanned.0,
                preference.letter,
                collision,
            ) {
                Ok(plan) => plan,
                Err(error) => return HostOperationOutcome::CompletionUnknown(error),
            };
            let volume = match plan {
                crate::ArrivalDriveLetterPlan::WaitForVolume => {
                    return HostOperationOutcome::Succeeded;
                }
                crate::ArrivalDriveLetterPlan::TargetCollision => {
                    return HostOperationOutcome::NotAttempted(NativeError::Busy);
                }
                crate::ArrivalDriveLetterPlan::AlreadyApplied
                | crate::ArrivalDriveLetterPlan::ReplaceSelectedLetter(_) => scanned
                    .2
                    .first()
                    .expect("arrival plan proves one retained volume"),
            };
            if let crate::ArrivalDriveLetterPlan::ReplaceSelectedLetter(old) = plan {
                if old != '\0' && volume.reset_drive_letter(old).is_err() {
                    return HostOperationOutcome::CompletionUnknown(NativeError::Other);
                }
                let outcome = volume.set_drive_letter(preference.letter);
                if outcome != HostOperationOutcome::Succeeded {
                    return match outcome {
                        HostOperationOutcome::Succeeded => unreachable!(),
                        HostOperationOutcome::NotAttempted(error)
                        | HostOperationOutcome::CompletionUnknown(error) => {
                            HostOperationOutcome::CompletionUnknown(error)
                        }
                    };
                }
            }
            let key = match String::from_utf16(
                &volume.volume_key()[..volume.volume_key().len().saturating_sub(1)],
            ) {
                Ok(key) => key,
                Err(_) => return HostOperationOutcome::CompletionUnknown(NativeError::Other),
            };
            crate::drive_letter_policy::arrival_binding_outcome(
                plan,
                drive_letter::set_bound_preference(serial_key, preference.letter, &key, true),
            )
        }
        #[cfg(not(windows))]
        {
            let _ = serial_key;
            HostOperationOutcome::NotAttempted(NativeError::UnsupportedPlatform)
        }
    }

    /// Waits for authoritative exact-cartridge absence after eject dispatch.
    ///
    /// # Errors
    ///
    /// Returns a sanitized timeout or stale-authority failure.
    pub fn verify_eject_departure(&mut self) -> Result<(), NativeError> {
        #[cfg(windows)]
        {
            self.inner.verify_eject_departure()
        }
        #[cfg(not(windows))]
        {
            Err(NativeError::UnsupportedPlatform)
        }
    }

    /// Proves a single exact newly formatted and mounted volume.
    ///
    /// # Errors
    ///
    /// Returns a sanitized timeout, filesystem, topology, or identity failure.
    pub fn verify_format_rediscovery(
        &mut self,
        filesystem: HostFilesystem,
        previous_capacity: u64,
    ) -> Result<(), NativeError> {
        #[cfg(windows)]
        {
            self.inner
                .verify_format_rediscovery(filesystem, previous_capacity)
        }
        #[cfg(not(windows))]
        {
            let _ = (filesystem, previous_capacity);
            Err(NativeError::UnsupportedPlatform)
        }
    }
}

impl ValidatedVolumeMutationLease<'_> {
    /// Returns the number of exact volume handles kept locked by this guard.
    #[must_use]
    pub fn volume_count(&self) -> usize {
        self.volumes.volume_count()
    }
}

impl std::fmt::Debug for ValidatedVolumeMutationLease<'_> {
    /// Reports only a count while redacting handles and native identities.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ValidatedVolumeMutationLease")
            .field("volume_count", &self.volume_count())
            .field("handles", &"<private>")
            .finish()
    }
}

/// Certainty-preserving result of one closed safe-dismount operation.
#[must_use]
pub enum SafeDismountOutcome<'device> {
    /// Every target volume is dismounted while its exact lock remains held.
    Ready(ValidatedVolumeMutationLease<'device>),
    /// Validation failed before a dismount API was invoked.
    NotAttempted(NativeError),
    /// A dismount API was invoked but success could not be proven.
    CompletionUnknown(NativeError),
}

impl std::fmt::Debug for SafeDismountOutcome<'_> {
    /// Formats only certainty and sanitized errors or guard metadata.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ready(lease) => formatter.debug_tuple("Ready").field(lease).finish(),
            Self::NotAttempted(error) => {
                formatter.debug_tuple("NotAttempted").field(error).finish()
            }
            Self::CompletionUnknown(error) => formatter
                .debug_tuple("CompletionUnknown")
                .field(error)
                .finish(),
        }
    }
}

impl<'device> VolumeLeaseSet<'device> {
    /// Returns informational mount letters while authorization remains handle-based.
    #[must_use]
    pub fn drive_letters(&self) -> &[char] {
        &self.drive_letters
    }

    /// Returns the number of live pinned volume handles in this lease set.
    #[must_use]
    pub fn volume_count(&self) -> usize {
        #[cfg(windows)]
        {
            self.leases.len()
        }
        #[cfg(not(windows))]
        {
            0
        }
    }

    /// Consumes this exclusive lease set and safely dismounts its selected volume.
    ///
    /// The native boundary fresh-enumerates every volume twice, compares the
    /// complete canonical inventory, proves the selected mount association,
    /// locks all target handles, revalidates the parent, and only then dismounts.
    /// Success returns an opaque guard that keeps those locks held.
    pub fn dismount_for_safe_eject(
        self,
        selected_drive_letter: char,
    ) -> SafeDismountOutcome<'device> {
        if !selected_drive_letter.is_ascii_uppercase() {
            return SafeDismountOutcome::NotAttempted(NativeError::InvalidRequest);
        }
        self.dismount_all_exact()
    }

    /// Consumes the lease set and dismounts every exact target mount association.
    fn dismount_all_exact(self) -> SafeDismountOutcome<'device> {
        #[cfg(windows)]
        {
            let outcome = self
                .device
                .inner
                .dismount_for_safe_eject(&self.leases, &self.inventory);
            match outcome {
                VolumeMutationOutcome::Succeeded => {
                    SafeDismountOutcome::Ready(ValidatedVolumeMutationLease { volumes: self })
                }
                VolumeMutationOutcome::NotAttempted(error) => {
                    SafeDismountOutcome::NotAttempted(error)
                }
                VolumeMutationOutcome::CompletionUnknown(error) => {
                    SafeDismountOutcome::CompletionUnknown(error)
                }
            }
        }
        #[cfg(not(windows))]
        {
            let _ = self.device;
            SafeDismountOutcome::NotAttempted(NativeError::UnsupportedPlatform)
        }
    }

    /// Ejects already-unmounted media while retaining and revalidating every exact volume lease.
    ///
    /// This is the safe-eject no-mount branch, not a force fallback. It refuses
    /// any mount association and keeps the complete retained lease set alive
    /// across the physical-disk eject request.
    #[must_use]
    pub fn eject_if_unmounted(self) -> HostOperationOutcome {
        #[cfg(windows)]
        {
            if self.mount_path_count != 0 {
                return HostOperationOutcome::NotAttempted(NativeError::Busy);
            }
            if let Err(error) = self.device.inner.revalidate_volume_leases(&self.leases) {
                return HostOperationOutcome::NotAttempted(error);
            }
            match self.device.inner.prepared_safe_eject(&self.leases) {
                VolumeMutationOutcome::Succeeded => HostOperationOutcome::Succeeded,
                VolumeMutationOutcome::NotAttempted(error) => {
                    HostOperationOutcome::NotAttempted(error)
                }
                VolumeMutationOutcome::CompletionUnknown(error) => {
                    HostOperationOutcome::CompletionUnknown(error)
                }
            }
        }
        #[cfg(not(windows))]
        {
            let _ = self;
            HostOperationOutcome::NotAttempted(NativeError::UnsupportedPlatform)
        }
    }
}

impl std::fmt::Debug for VolumeLeaseSet<'_> {
    /// Reports only counts while redacting handles and native identities.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("VolumeLeaseSet")
            .field("drive_letter_count", &self.drive_letters.len())
            .field("volume_count", &self.volume_count())
            .field("handles", &"<private>")
            .finish()
    }
}

/// Exact physical-drive lease whose raw handle and path never leave this crate.
pub struct WindowsDevice {
    #[cfg(windows)]
    inner: native::NativeDevice,
}

impl WindowsDevice {
    /// Atomically revalidates and opens one exact service-owned instance recipe.
    ///
    /// # Errors
    ///
    /// Returns a sanitized access, hotplug, busy, or recipe failure. Caller-
    /// supplied physical-drive and interface paths are never accepted.
    pub fn open(recipe: &OsStr) -> Result<Self, NativeError> {
        #[cfg(windows)]
        {
            native::NativeDevice::open(recipe).map(|inner| Self { inner })
        }
        #[cfg(not(windows))]
        {
            let _ = recipe;
            Err(NativeError::UnsupportedPlatform)
        }
    }

    /// Executes one bounded request synchronously through this exact lease.
    #[must_use]
    pub fn execute(&mut self, operation: ScsiOperation) -> Completion {
        #[cfg(windows)]
        {
            match operation.into_request() {
                Ok(request) => self.inner.execute(request),
                Err(error) => Completion::NotAttempted(error),
            }
        }
        #[cfg(not(windows))]
        {
            let _ = operation;
            Completion::NotAttempted(NativeError::UnsupportedPlatform)
        }
    }

    /// Pins current exact volumes while retaining this disk lease by lifetime.
    ///
    /// # Errors
    ///
    /// Returns a bounded enumeration failure and never publishes a volume path.
    pub fn pin_volumes(&mut self) -> Result<VolumeLeaseSet<'_>, NativeError> {
        #[cfg(windows)]
        {
            let (drive_letters, mount_path_count, inventory, leases) = self.inner.pin_volumes()?;
            Ok(VolumeLeaseSet {
                drive_letters,
                mount_path_count,
                inventory,
                leases,
                device: self,
            })
        }
        #[cfg(not(windows))]
        {
            Err(NativeError::UnsupportedPlatform)
        }
    }
}

impl ValidatedVolumeMutationLease<'_> {
    /// Consumes retained volume locks only after the exact physical eject call.
    #[must_use]
    #[cfg_attr(not(windows), allow(dead_code))]
    fn eject(self) -> HostOperationOutcome {
        #[cfg(windows)]
        {
            match self
                .volumes
                .device
                .inner
                .prepared_safe_eject(&self.volumes.leases)
            {
                VolumeMutationOutcome::Succeeded => HostOperationOutcome::Succeeded,
                VolumeMutationOutcome::NotAttempted(error) => {
                    HostOperationOutcome::NotAttempted(error)
                }
                VolumeMutationOutcome::CompletionUnknown(error) => {
                    HostOperationOutcome::CompletionUnknown(error)
                }
            }
        }
        #[cfg(not(windows))]
        {
            HostOperationOutcome::NotAttempted(NativeError::UnsupportedPlatform)
        }
    }
}
