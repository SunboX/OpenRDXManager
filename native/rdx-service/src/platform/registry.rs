// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Opaque identity derivation and exclusive service-owned locator registry.

#[path = "registry/binding.rs"]
mod binding;
#[path = "registry/diagnostics.rs"]
mod diagnostic_lease;
#[path = "registry/format.rs"]
mod format_lease;
#[path = "registry/migration.rs"]
mod migration_lease;
#[path = "registry/presentation.rs"]
mod presentation;

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::ffi::OsStr;
use std::fmt::{Debug, Formatter};

use sha2::{Digest, Sha256};

use crate::firmware::{FirmwareRevision, ProductFamily};
use crate::host::DeviceInterface;
use crate::model::{
    Capability, ConfirmationToken, DeviceId, DeviceSnapshot, DiscoveryRevision, DisplayText,
    DriveStatus, MediaState, OperationKind,
};
use crate::operations::{
    FileSystem, HostOperations, HostPrimitiveError, HostVolumeBinding, HostVolumeFacts,
    PrimitiveFailure, RegistryModeTarget, WriteReadPrimitiveResult,
};
use crate::protocol::Command;
use crate::transport::{CommandDispatch, DispatchCertainty, TransportError};

use super::{
    CandidateDevice, DeviceLease, MediaStatusEvidence, PlatformBackend, PlatformCapabilities,
    PlatformError, ValidatedCandidate, ValidatedEvidence, device_capabilities,
    revalidate_candidate_lease, revalidate_device_lease,
};
use presentation::renderer_media;

const MAX_RETIRED_DEVICE_IDS: usize = 256;
type DeviceIdDeriver = fn(&str, &str, &str) -> Result<DeviceId, PlatformError>;

/// Service-owned registry of validated devices and private OS locators.
pub struct DeviceRegistry {
    entries: BTreeMap<DeviceId, RegistryEntry>,
    generation: DiscoveryRevision,
    revision_clock: u64,
    retired_ids: VecDeque<DeviceId>,
    id_deriver: DeviceIdDeriver,
}

impl DeviceRegistry {
    /// Creates an empty registry at generation zero.
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
            generation: DiscoveryRevision::new(0).expect("zero is a safe revision"),
            revision_clock: 0,
            retired_ids: VecDeque::new(),
            id_deriver: derive_device_id,
        }
    }

    /// Returns the current service-owned replacement-set generation.
    #[must_use]
    pub const fn generation(&self) -> DiscoveryRevision {
        self.generation
    }

    /// Returns a path-free, deterministically ordered snapshot list.
    #[must_use]
    pub fn snapshots(&self) -> Vec<DeviceSnapshot> {
        self.entries
            .values()
            .map(|entry| entry.snapshot.clone())
            .collect()
    }

    /// Returns one path-free snapshot by opaque ID.
    #[must_use]
    pub fn snapshot(&self, id: &DeviceId) -> Option<DeviceSnapshot> {
        self.entries.get(id).map(|entry| entry.snapshot.clone())
    }

    /// Checks one still-staged replacement set for the selected dock with no media.
    ///
    /// This performs only the same deterministic identity derivation used by
    /// registry replacement. It does not move private locators, advance
    /// revisions, retire IDs, or otherwise mutate authoritative state.
    pub(super) fn staged_set_retains_device_without_media(
        &self,
        validated: &[ValidatedCandidate],
        device_id: &DeviceId,
    ) -> Result<bool, PlatformError> {
        for candidate in validated {
            let id = (self.id_deriver)(
                &candidate.evidence.vendor,
                &candidate.evidence.product,
                &candidate.evidence.serial,
            )?;
            if &id != device_id {
                continue;
            }
            return Ok(candidate
                .evidence
                .host_facts
                .is_some_and(|facts| !facts.media_present && facts.media_fingerprint.is_none()));
        }
        Ok(false)
    }

    /// Atomically replaces the complete validated set after ambiguity checks.
    pub(super) fn replace_validated(
        &mut self,
        validated: Vec<ValidatedCandidate>,
    ) -> Result<Vec<DeviceSnapshot>, PlatformError> {
        let prepared = self.prepare(validated)?;
        let changed_ids = prepared
            .iter()
            .filter(|(id, candidate)| {
                !self
                    .entries
                    .get(id)
                    .is_some_and(|entry| entry.matches(candidate))
            })
            .map(|(id, _)| id.clone())
            .collect::<BTreeSet<_>>();
        let removed_ids = self
            .entries
            .keys()
            .filter(|id| !prepared.contains_key(*id))
            .cloned()
            .collect::<Vec<_>>();

        if changed_ids.is_empty() && removed_ids.is_empty() {
            for (id, candidate) in prepared {
                self.entries
                    .get_mut(&id)
                    .expect("unchanged prepared entry remains present")
                    .refresh_candidate(candidate.candidate);
            }
            return Ok(self.snapshots());
        }

        // Complete all fallible arithmetic before moving a single old entry.
        let generation = next_revision(self.generation.get())?;
        let changed_count =
            u64::try_from(changed_ids.len()).map_err(|_| PlatformError::RevisionOverflow)?;
        let final_clock = self
            .revision_clock
            .checked_add(changed_count)
            .ok_or(PlatformError::RevisionOverflow)?;
        DiscoveryRevision::new(final_clock).map_err(|_| PlatformError::RevisionOverflow)?;

        let mut old_entries = std::mem::take(&mut self.entries);
        let mut entries = BTreeMap::new();
        let mut next_device_revision = self.revision_clock;
        for (id, candidate) in prepared {
            if !changed_ids.contains(&id) {
                let mut entry = old_entries
                    .remove(&id)
                    .expect("unchanged preflight entry remains present");
                entry.refresh_candidate(candidate.candidate);
                entries.insert(id, entry);
                continue;
            }
            next_device_revision += 1;
            let revision = DiscoveryRevision::new(next_device_revision)
                .expect("revision range was preflight-validated");
            entries.insert(id.clone(), RegistryEntry::new(id, revision, candidate));
        }

        for id in removed_ids {
            remember_retired_id(&mut self.retired_ids, id);
        }
        self.entries = entries;
        self.generation = generation;
        self.revision_clock = final_clock;
        Ok(self.snapshots())
    }

    /// Converts validated inputs into fully checked, deterministic registry inputs.
    fn prepare(
        &self,
        validated: Vec<ValidatedCandidate>,
    ) -> Result<BTreeMap<DeviceId, PreparedCandidate>, PlatformError> {
        let mut serials = BTreeSet::new();
        let mut prepared = BTreeMap::new();
        for candidate in validated {
            if !serials.insert(candidate.evidence.serial.clone()) {
                return Err(PlatformError::DuplicateDeviceSerial);
            }
            let id = (self.id_deriver)(
                &candidate.evidence.vendor,
                &candidate.evidence.product,
                &candidate.evidence.serial,
            )?;
            let candidate = PreparedCandidate::try_from(candidate)?;
            if prepared.insert(id, candidate).is_some() {
                return Err(PlatformError::DuplicateDeviceId);
            }
        }
        Ok(prepared)
    }
}

impl Default for DeviceRegistry {
    /// Creates the same empty registry as [`DeviceRegistry::new`].
    fn default() -> Self {
        Self::new()
    }
}

impl Debug for DeviceRegistry {
    /// Formats only safe counts and generation, never entries or locators.
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DeviceRegistry")
            .field("generation", &self.generation)
            .field("device_count", &self.entries.len())
            .finish()
    }
}

/// Non-cloneable authorization and live handle for one exact registry binding.
///
/// Its exclusive registry borrow prevents a discovery replacement from making
/// the authorization stale while an operation retains the lease.
pub struct ResolvedDevice<'registry> {
    entry: &'registry RegistryEntry,
    registry_generation: DiscoveryRevision,
    platform: PlatformCapabilities,
    lease: DeviceLease,
    media_fingerprint: Option<[u8; 32]>,
    active: bool,
    led_recovery_armed: bool,
    resolution_host_facts: Option<HostVolumeFacts>,
    safe_eject_preflight: Option<HostVolumeBinding>,
    #[cfg(target_os = "linux")]
    pending_format_unmount: Option<HostVolumeBinding>,
    #[cfg(any(windows, target_os = "linux"))]
    pending_format_layout: Option<HostVolumeBinding>,
}

impl ResolvedDevice<'_> {
    /// Returns the safe opaque device ID.
    #[must_use]
    pub const fn id(&self) -> &DeviceId {
        &self.entry.snapshot.id
    }

    /// Returns the exact device revision accepted during resolution.
    #[must_use]
    pub const fn revision(&self) -> DiscoveryRevision {
        self.entry.snapshot.revision
    }

    /// Returns the exact registry generation accepted during resolution.
    #[must_use]
    pub const fn registry_generation(&self) -> DiscoveryRevision {
        self.registry_generation
    }

    /// Issues the sole exact bounded confirmation token for this dock and cartridge binding.
    ///
    /// # Errors
    ///
    /// Returns stale binding after session invalidation or when no cartridge was captured.
    pub fn issue_host_mutation_confirmation(
        &self,
    ) -> Result<crate::model::ConfirmationToken, PlatformError> {
        if !self.active || self.media_fingerprint.is_none() {
            return Err(PlatformError::StaleDeviceBinding);
        }
        Ok(self.host_binding().issue_confirmation_token())
    }

    /// Revalidates exact identity and capability evidence on this same live handle.
    ///
    /// Any transport failure or evidence drift permanently invalidates this
    /// resolution. The method never reopens the private locator.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformError::StaleDeviceBinding`] after removal, path reuse,
    /// partial proof, or changed identity/capability evidence.
    pub fn revalidate_identity(&mut self) -> Result<(), PlatformError> {
        // Any intervening identity operation invalidates a one-shot eject
        // preflight, even when that operation ultimately confirms the device.
        self.resolution_host_facts = None;
        self.safe_eject_preflight = None;
        self.clear_format_continuations();
        if !self.active {
            return Err(PlatformError::StaleDeviceBinding);
        }
        let Some(evidence) =
            revalidate_device_lease(&mut self.lease, &self.entry.candidate, self.platform)
        else {
            self.active = false;
            return Err(PlatformError::StaleDeviceBinding);
        };
        if !self.entry.matches_evidence(&evidence) {
            self.active = false;
            return Err(PlatformError::StaleDeviceBinding);
        }
        Ok(())
    }

    /// Returns fresh registry-owned firmware authorization evidence.
    pub(crate) fn firmware_facts(
        &mut self,
    ) -> Result<(ProductFamily, FirmwareRevision, bool), PlatformError> {
        self.revalidate_identity()?;
        let revision = self
            .entry
            .revision_text
            .parse::<u16>()
            .ok()
            .and_then(|value| FirmwareRevision::new(value).ok())
            .ok_or(PlatformError::StaleDeviceBinding)?;
        let media_present = self
            .entry
            .host_facts
            .map(|facts| facts.media_present)
            .ok_or(PlatformError::StaleDeviceBinding)?;
        Ok((self.entry.product_family, revision, media_present))
    }

    /// Executes one evidence-built firmware command on this retained exact lease.
    pub(crate) fn execute_firmware(&mut self, command: &Command) -> CommandDispatch {
        if !self.active {
            return CommandDispatch::NotSent(TransportError::InactiveSession);
        }
        let outcome = self.lease.handle.execute(command);
        if outcome.certainty() == DispatchCertainty::CompletionUnknown
            || matches!(
                outcome.error(),
                Some(
                    TransportError::Unavailable
                        | TransportError::DeviceRemoved
                        | TransportError::AdapterPanic
                )
            )
        {
            self.active = false;
        }
        outcome
    }

    /// Builds the private host-operation binding from exact retained registry evidence.
    fn host_binding(&self) -> HostVolumeBinding {
        let mut digest = Sha256::new();
        digest.update(b"OpenRDXManager/dock-serial/v1\0");
        digest.update(self.entry.snapshot.serial.as_str().as_bytes());
        HostVolumeBinding::new(
            self.entry.snapshot.revision.get(),
            digest.finalize().into(),
            self.media_fingerprint,
        )
    }

    /// Rejects a stale supplied private host binding before any native call.
    fn require_host_binding(&self, expected: &HostVolumeBinding) -> Result<(), PrimitiveFailure> {
        if *expected == self.host_binding() && self.active {
            Ok(())
        } else {
            Err(PrimitiveFailure::not_attempted(
                HostPrimitiveError::StaleBinding,
            ))
        }
    }

    /// Revalidates the private binding plus full protocol identity before a native boundary.
    fn revalidate_host_binding(
        &mut self,
        expected: &HostVolumeBinding,
    ) -> Result<(), PrimitiveFailure> {
        self.require_host_binding(expected)?;
        self.revalidate_identity()
            .map_err(|_| PrimitiveFailure::not_attempted(HostPrimitiveError::StaleBinding))?;
        let facts = self.lease.handle.host_volume_facts()?;
        if facts.media_fingerprint != expected.media_fingerprint() {
            self.active = false;
            return Err(PrimitiveFailure::not_attempted(
                HostPrimitiveError::StaleBinding,
            ));
        }
        Ok(())
    }
}

impl HostOperations for ResolvedDevice<'_> {
    /// Captures private exact registry and medium-generation evidence.
    fn binding(&self) -> HostVolumeBinding {
        self.host_binding()
    }

    /// Applies platform-specific format proof under the retained exact lease.
    fn revalidate_format(
        &mut self,
        expected: &HostVolumeBinding,
    ) -> Result<HostVolumeFacts, PrimitiveFailure> {
        self.format_facts(expected)
    }

    /// Revalidates full device protocol identity and native volume authority.
    fn revalidate(
        &mut self,
        expected: &HostVolumeBinding,
    ) -> Result<HostVolumeFacts, PrimitiveFailure> {
        self.require_host_binding(expected)?;
        if let Some(facts) = self.resolution_host_facts.take() {
            if facts.media_fingerprint != expected.media_fingerprint() {
                self.active = false;
                return Err(PrimitiveFailure::not_attempted(
                    HostPrimitiveError::StaleBinding,
                ));
            }
            // Resolution opened, fully validated, and retained this exact
            // non-shareable lease immediately before the operation. Reusing
            // that one-shot proof avoids a duplicate macOS USB-BOT probe set
            // that can disturb the captured transport before Safe Eject.
            self.safe_eject_preflight = Some(expected.clone());
            return Ok(facts);
        }
        self.revalidate_identity()
            .map_err(|_| PrimitiveFailure::not_attempted(HostPrimitiveError::StaleBinding))?;
        let facts = self.lease.handle.host_volume_facts()?;
        if facts.media_fingerprint != expected.media_fingerprint() {
            self.active = false;
            return Err(PrimitiveFailure::not_attempted(
                HostPrimitiveError::StaleBinding,
            ));
        }
        // The combined native safe-eject boundary consumes this exact proof.
        // Repeating the complete SCSI proof set there can disrupt an exclusive
        // macOS transport lease before Disk Arbitration receives the request.
        self.safe_eject_preflight = Some(expected.clone());
        Ok(facts)
    }

    /// Validates a token derived from private exact binding evidence.
    fn confirmation_matches(
        &self,
        expected: &HostVolumeBinding,
        confirmation: &ConfirmationToken,
    ) -> bool {
        if self.require_host_binding(expected).is_err() {
            return false;
        }
        expected.matches_confirmation(confirmation)
    }

    /// Waits for exact selected-device departure through the retained platform authority.
    fn verify_eject_departure(
        &mut self,
        expected: &HostVolumeBinding,
    ) -> Result<(), PrimitiveFailure> {
        self.require_host_binding(expected)?;
        self.lease.handle.verify_eject_departure()
    }

    /// Waits for and proves the new exact filesystem topology after format.
    fn verify_format_rediscovery(
        &mut self,
        expected: &HostVolumeBinding,
        filesystem: FileSystem,
        previous_capacity: u64,
    ) -> Result<(), PrimitiveFailure> {
        self.require_host_binding(expected)?;
        self.lease
            .handle
            .verify_format_rediscovery(filesystem, previous_capacity)
    }

    /// Checks native filesystem tooling before any unmount.
    fn preflight_format(
        &mut self,
        expected: &HostVolumeBinding,
        filesystem: FileSystem,
    ) -> Result<(), PrimitiveFailure> {
        self.revalidate_host_binding(expected)?;
        self.lease.handle.preflight_format(filesystem)
    }

    /// Runs one closed exact-volume filesystem diagnostic.
    fn write_read_file(
        &mut self,
        expected: &HostVolumeBinding,
        filename: &str,
        bytes: &[u8],
    ) -> Result<WriteReadPrimitiveResult, PrimitiveFailure> {
        self.revalidate_host_binding(expected)?;
        self.lease.handle.write_read_file(filename, bytes)
    }

    /// Flushes and unmounts only volumes retained beneath this live device.
    fn unmount_exact_volumes(
        &mut self,
        expected: &HostVolumeBinding,
    ) -> Result<(), PrimitiveFailure> {
        self.unmount_format_volumes(expected)
    }

    /// Flushes/unmounts and ejects while retaining one exact platform authority.
    fn safe_eject_exact(
        &mut self,
        expected: &HostVolumeBinding,
        after_unmount: &mut dyn FnMut() -> bool,
    ) -> Result<(), PrimitiveFailure> {
        let preflight = self.safe_eject_preflight.take();
        self.require_host_binding(expected)?;
        if preflight.as_ref() != Some(expected) {
            return Err(PrimitiveFailure::not_attempted(
                HostPrimitiveError::StaleBinding,
            ));
        }
        self.lease.handle.safe_eject_exact(after_unmount)
    }

    /// Ejects only through the retained exact platform authority.
    fn eject_exact(
        &mut self,
        expected: &HostVolumeBinding,
        force: bool,
    ) -> Result<(), PrimitiveFailure> {
        self.revalidate_host_binding(expected)?;
        self.lease.handle.eject_exact(force)
    }

    /// Applies one simple layout only through the retained exact authority.
    fn create_single_partition(
        &mut self,
        expected: &HostVolumeBinding,
        mbr_signature: u32,
    ) -> Result<(), PrimitiveFailure> {
        self.create_format_layout(expected, mbr_signature)
    }

    /// Formats only the exact newly created partition.
    fn format_partition(
        &mut self,
        expected: &HostVolumeBinding,
        filesystem: FileSystem,
    ) -> Result<(), PrimitiveFailure> {
        self.finish_format_layout(expected, filesystem)
    }

    /// Invalidates this registry resolution after an attempted layout mutation.
    fn invalidate_for_rediscovery(&mut self) {
        self.active = false;
    }

    /// Revalidates the dock and medium before renaming its sole mounted volume.
    fn set_volume_label_exact(
        &mut self,
        expected: &HostVolumeBinding,
        label: &crate::model::VolumeLabel,
    ) -> Result<(), PrimitiveFailure> {
        self.revalidate_host_binding(expected)?;
        self.lease.handle.set_volume_label_exact(label)
    }

    /// Persists an exact-serial Windows preference through the retained authority.
    fn set_drive_letter_exact(
        &mut self,
        expected: &HostVolumeBinding,
        letter: char,
    ) -> Result<(), PrimitiveFailure> {
        self.revalidate_host_binding(expected)?;
        self.lease
            .handle
            .set_drive_letter_exact(&expected.serial_mapping_key(), letter)
    }

    /// Removes only this application's exact-serial preference.
    fn reset_drive_letter_exact(
        &mut self,
        expected: &HostVolumeBinding,
    ) -> Result<(), PrimitiveFailure> {
        self.revalidate_host_binding(expected)?;
        self.lease
            .handle
            .reset_drive_letter_exact(&expected.serial_mapping_key())
    }
}

impl RegistryModeTarget for ResolvedDevice<'_> {
    /// Returns the interface established by complete current discovery evidence.
    fn configuration_interface(&self) -> DeviceInterface {
        self.entry.interface
    }

    /// Reports cartridge presence from the exact registry snapshot.
    fn configuration_media_present(&self) -> Option<bool> {
        self.entry.host_facts.map(|facts| facts.media_present)
    }

    /// Revalidates identity and capability evidence on the retained handle.
    fn revalidate_configuration(&mut self) -> Result<(), PrimitiveFailure> {
        self.revalidate_identity()
            .map_err(|_| PrimitiveFailure::not_attempted(HostPrimitiveError::StaleBinding))
    }

    /// Executes one trusted mode command and invalidates ambiguous normal dispatch.
    fn execute_configuration(&mut self, command: &Command) -> CommandDispatch {
        if !self.active {
            return CommandDispatch::NotSent(TransportError::InactiveSession);
        }
        let outcome = self.lease.handle.execute(command);
        if outcome.certainty() == DispatchCertainty::CompletionUnknown
            || matches!(
                outcome.error(),
                Some(
                    TransportError::Unavailable
                        | TransportError::DeviceRemoved
                        | TransportError::AdapterPanic
                )
            )
        {
            self.active = false;
        }
        outcome
    }

    /// Executes mandatory same-handle recovery even after ambiguous MODE SELECT.
    fn execute_configuration_recovery(&mut self, command: &Command) -> CommandDispatch {
        self.lease.handle.execute(command)
    }
}

impl Debug for ResolvedDevice<'_> {
    /// Formats only safe public binding metadata and redacts locator identity.
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ResolvedDevice")
            .field("id", &self.entry.snapshot.id)
            .field("revision", &self.entry.snapshot.revision)
            .field("registry_generation", &self.registry_generation)
            .field("active", &self.active)
            .field("locator_binding", &"<private>")
            .finish()
    }
}

struct RegistryEntry {
    snapshot: DeviceSnapshot,
    candidate: CandidateDevice,
    locator_fingerprint: [u8; 32],
    capability_fingerprint: [u8; 32],
    revision_text: String,
    interface: DeviceInterface,
    product_family: ProductFamily,
    host_facts: Option<HostVolumeFacts>,
    media_status: MediaStatusEvidence,
    drive_mode_supported: bool,
    sata_mode_reported: bool,
}

impl RegistryEntry {
    /// Moves a validated locator into a new exact registry binding.
    fn new(id: DeviceId, revision: DiscoveryRevision, candidate: PreparedCandidate) -> Self {
        let locator_fingerprint = locator_fingerprint(&candidate.candidate.locator);
        let media = candidate
            .host_facts
            .and_then(|facts| renderer_media(facts, &candidate.media_status));
        let media_state = if media.is_some() {
            MediaState::Present
        } else {
            MediaState::NoMedia
        };
        Self {
            snapshot: DeviceSnapshot {
                id,
                revision,
                vendor: candidate.vendor,
                product: candidate.product,
                serial: candidate.serial,
                drive: candidate.drive.clone(),
                media,
                media_state,
                capabilities: candidate.capabilities,
            },
            candidate: candidate.candidate,
            locator_fingerprint,
            capability_fingerprint: candidate.capability_fingerprint,
            revision_text: candidate.revision_text,
            interface: candidate.interface,
            product_family: candidate.product_family,
            host_facts: candidate.host_facts,
            media_status: candidate.media_status,
            drive_mode_supported: candidate.drive_mode_supported,
            sata_mode_reported: candidate.sata_mode_reported,
        }
    }

    /// Reports exact continuity without normalizing a locator or capability field.
    fn matches(&self, candidate: &PreparedCandidate) -> bool {
        (candidate.binding_continuity
            || (self.candidate.locator == candidate.candidate.locator
                && self.locator_fingerprint == locator_fingerprint(&candidate.candidate.locator)))
            && self.snapshot.vendor == candidate.vendor
            && self.snapshot.product == candidate.product
            && self.snapshot.serial == candidate.serial
            && self.snapshot.capabilities == candidate.capabilities
            && self.capability_fingerprint == candidate.capability_fingerprint
            && self.revision_text == candidate.revision_text
            && self.interface == candidate.interface
            && self.product_family == candidate.product_family
            && self.host_facts == candidate.host_facts
            && self.media_status == candidate.media_status
            && self.drive_mode_supported == candidate.drive_mode_supported
            && self.sata_mode_reported == candidate.sata_mode_reported
            && self.snapshot.drive == candidate.drive
    }

    /// Compares fresh same-handle proof with every authorization-relevant field.
    fn matches_evidence(&self, evidence: &ValidatedEvidence) -> bool {
        self.snapshot.vendor.as_str() == evidence.vendor
            && self.snapshot.product.as_str() == evidence.product
            && self.snapshot.serial.as_str() == evidence.serial
            && self.snapshot.capabilities == evidence.capabilities
            && self.capability_fingerprint == evidence.capability_fingerprint
            && self.revision_text == evidence.revision
            && self.interface == evidence.interface
            && self.product_family == evidence.product_family
            && host_binding_matches(self.host_facts, evidence.host_facts)
            && self.media_status.identity == evidence.media_status.identity
            && self.drive_mode_supported == evidence.drive_mode_supported
            && self.sata_mode_reported == evidence.sata_mode_reported
            && drive_binding_matches(&self.snapshot.drive, &evidence.drive)
    }

    /// Refreshes a routing recipe whose exact binding evidence did not change.
    fn refresh_candidate(&mut self, candidate: CandidateDevice) {
        self.locator_fingerprint = locator_fingerprint(&candidate.locator);
        self.candidate = candidate;
    }

    /// Reconstructs private validated evidence for a non-disruptive host refresh.
    fn validated_evidence(&self) -> ValidatedEvidence {
        ValidatedEvidence {
            vendor: self.snapshot.vendor.as_str().to_owned(),
            product: self.snapshot.product.as_str().to_owned(),
            serial: self.snapshot.serial.as_str().to_owned(),
            revision: self.revision_text.clone(),
            interface: self.interface,
            product_family: self.product_family,
            capabilities: self.snapshot.capabilities.clone(),
            capability_fingerprint: self.capability_fingerprint,
            host_facts: self.host_facts,
            drive: self.snapshot.drive.clone(),
            media_status: self.media_status.clone(),
            drive_mode_supported: self.drive_mode_supported,
            sata_mode_reported: self.sata_mode_reported,
        }
    }
}

/// Compares only host facts that identify the same safe operation target.
/// Free space is intentionally excluded because filesystem accounting is live
/// telemetry and may change between discovery and same-handle revalidation.
fn host_binding_matches(
    previous: Option<HostVolumeFacts>,
    current: Option<HostVolumeFacts>,
) -> bool {
    match (previous, current) {
        (Some(previous), Some(current)) => {
            previous.media_present == current.media_present
                && previous.writable == current.writable
                && previous.mounted == current.mounted
                && previous.capacity_bytes == current.capacity_bytes
                && previous.filesystem == current.filesystem
                && previous.topology == current.topology
                && previous.media_fingerprint == current.media_fingerprint
        }
        (None, None) => true,
        _ => false,
    }
}

/// Compares stable drive configuration while excluding health counters and
/// other mutable status-page telemetry from binding identity.
fn drive_binding_matches(previous: &DriveStatus, current: &DriveStatus) -> bool {
    previous.firmware_revision == current.firmware_revision
        && previous.product_type == current.product_type
        && previous.connection_type == current.connection_type
        && previous.operation_mode == current.operation_mode
        && previous.sata_mode == current.sata_mode
}

struct PreparedCandidate {
    candidate: CandidateDevice,
    binding_continuity: bool,
    vendor: DisplayText,
    product: DisplayText,
    serial: DisplayText,
    revision_text: String,
    interface: DeviceInterface,
    product_family: ProductFamily,
    capabilities: BTreeMap<OperationKind, Capability>,
    capability_fingerprint: [u8; 32],
    host_facts: Option<HostVolumeFacts>,
    drive: DriveStatus,
    media_status: MediaStatusEvidence,
    drive_mode_supported: bool,
    sata_mode_reported: bool,
}

impl TryFrom<ValidatedCandidate> for PreparedCandidate {
    type Error = PlatformError;

    /// Converts validated text into the renderer-safe bounded model atomically.
    fn try_from(candidate: ValidatedCandidate) -> Result<Self, Self::Error> {
        let ValidatedCandidate {
            candidate,
            evidence,
            binding_continuity,
        } = candidate;
        Ok(Self {
            candidate,
            binding_continuity,
            vendor: DisplayText::new(evidence.vendor)
                .map_err(|_| PlatformError::StaleDeviceBinding)?,
            product: DisplayText::new(evidence.product)
                .map_err(|_| PlatformError::StaleDeviceBinding)?,
            serial: DisplayText::new(evidence.serial)
                .map_err(|_| PlatformError::StaleDeviceBinding)?,
            revision_text: evidence.revision,
            interface: evidence.interface,
            product_family: evidence.product_family,
            capabilities: evidence.capabilities,
            capability_fingerprint: evidence.capability_fingerprint,
            host_facts: evidence.host_facts,
            drive: evidence.drive,
            media_status: evidence.media_status,
            drive_mode_supported: evidence.drive_mode_supported,
            sata_mode_reported: evidence.sata_mode_reported,
        })
    }
}

/// Advances one service-owned revision within the JSON-safe integer range.
fn next_revision(current: u64) -> Result<DiscoveryRevision, PlatformError> {
    current
        .checked_add(1)
        .and_then(|value| DiscoveryRevision::new(value).ok())
        .ok_or(PlatformError::RevisionOverflow)
}

/// Adds one retired ID to a deduplicated bounded replay-rejection window.
fn remember_retired_id(retired: &mut VecDeque<DeviceId>, id: DeviceId) {
    if let Some(index) = retired.iter().position(|known| known == &id) {
        retired.remove(index);
    }
    retired.push_back(id);
    if retired.len() > MAX_RETIRED_DEVICE_IDS {
        retired.pop_front();
    }
}

/// Creates a deterministic SHA-256 ID without serial or path disclosure.
fn derive_device_id(vendor: &str, product: &str, serial: &str) -> Result<DeviceId, PlatformError> {
    let mut digest = Sha256::new();
    digest.update(b"OpenRDXManager/device-id/v1\0");
    update_field(&mut digest, vendor.as_bytes());
    update_field(&mut digest, product.as_bytes());
    update_field(&mut digest, serial.as_bytes());
    let bytes: [u8; 32] = digest.finalize().into();
    let mut encoded = String::with_capacity(68);
    encoded.push_str("rdx:");
    for byte in bytes {
        use std::fmt::Write as _;
        write!(&mut encoded, "{byte:02x}").expect("writing to String cannot fail");
    }
    DeviceId::new(encoded).map_err(|_| PlatformError::DuplicateDeviceId)
}

/// Adds an unambiguous length-prefixed identity field to a digest.
fn update_field(digest: &mut Sha256, field: &[u8]) {
    digest.update((field.len() as u64).to_be_bytes());
    digest.update(field);
}

/// Hashes one private locator only for internal exact-binding comparisons.
fn locator_fingerprint(locator: &OsStr) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"OpenRDXManager/private-locator/v1\0");
    digest.update((locator.as_encoded_bytes().len() as u64).to_be_bytes());
    digest.update(locator.as_encoded_bytes());
    digest.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::{CandidateDevice, CandidateMetadata};

    const MAX_SAFE_JSON_INTEGER: u64 = 9_007_199_254_740_991;

    /// Builds one already-corroborated input for private registry invariants.
    fn validated(token: &str, locator: &str, serial: &str) -> ValidatedCandidate {
        let vendor = DisplayText::new("TANDBERG").unwrap();
        let product = DisplayText::new("RDX").unwrap();
        let serial_text = DisplayText::new(serial).unwrap();
        ValidatedCandidate {
            candidate: CandidateDevice::new(
                token,
                locator,
                CandidateMetadata::new(None, None, None, Some(DeviceInterface::Usb3)),
            )
            .expect("bounded registry fixture"),
            evidence: ValidatedEvidence {
                vendor: "TANDBERG".to_owned(),
                product: "RDX".to_owned(),
                serial: serial.to_owned(),
                revision: "0283".to_owned(),
                interface: DeviceInterface::Usb3,
                product_family: ProductFamily::Usb3Sata3,
                capabilities: BTreeMap::new(),
                capability_fingerprint: [0x31; 32],
                host_facts: None,
                drive: DriveStatus::from_identity(&vendor, &product, &serial_text),
                media_status: MediaStatusEvidence::default(),
                drive_mode_supported: true,
                sata_mode_reported: false,
            },
            binding_continuity: false,
        }
    }

    /// Forces distinct proven identities into the same safe opaque namespace.
    fn colliding_id(
        _vendor: &str,
        _product: &str,
        _serial: &str,
    ) -> Result<DeviceId, PlatformError> {
        DeviceId::new("rdx:forced-collision").map_err(|_| PlatformError::DuplicateDeviceId)
    }

    /// A theoretical digest collision fails closed and leaves the old set untouched.
    #[test]
    fn duplicate_opaque_id_is_rejected_atomically() {
        let mut registry = DeviceRegistry::new();
        registry.id_deriver = colliding_id;

        assert_eq!(
            registry.replace_validated(vec![
                validated("candidate-a", "/private/a", "7820999743"),
                validated("candidate-b", "/private/b", "7820999744"),
            ]),
            Err(PlatformError::DuplicateDeviceId)
        );
        assert!(registry.snapshots().is_empty());
        assert_eq!(registry.generation().get(), 0);
    }

    /// Generation overflow rejects removal without partially clearing the registry.
    #[test]
    fn generation_overflow_preserves_the_existing_binding() {
        let mut registry = DeviceRegistry::new();
        let original = registry
            .replace_validated(vec![validated("candidate-a", "/private/a", "7820999743")])
            .expect("initial registry fixture");
        registry.generation =
            DiscoveryRevision::new(MAX_SAFE_JSON_INTEGER).expect("maximum JSON-safe generation");

        assert_eq!(
            registry.replace_validated(Vec::new()),
            Err(PlatformError::RevisionOverflow)
        );
        assert_eq!(registry.snapshots(), original);
        assert_eq!(registry.generation().get(), MAX_SAFE_JSON_INTEGER);
    }

    /// Device-revision overflow rejects replacement before moving private locators.
    #[test]
    fn device_revision_overflow_preserves_the_existing_binding() {
        let mut registry = DeviceRegistry::new();
        let original = registry
            .replace_validated(vec![validated("candidate-a", "/private/a", "7820999743")])
            .expect("initial registry fixture");
        let original_generation = registry.generation();
        registry.revision_clock = MAX_SAFE_JSON_INTEGER;

        assert_eq!(
            registry.replace_validated(vec![validated("candidate-b", "/private/b", "7820999744",)]),
            Err(PlatformError::RevisionOverflow)
        );
        assert_eq!(registry.snapshots(), original);
        assert_eq!(registry.generation(), original_generation);
    }
}
