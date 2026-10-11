// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Cached discovery proof and exact live-handle binding.

use super::*;
use crate::platform::CandidateLease;

impl DeviceRegistry {
    /// Identifies a freshly probed target using the normal public ID derivation.
    pub(in crate::platform) fn evidence_identifies_device(
        &self,
        evidence: &ValidatedEvidence,
        device_id: &DeviceId,
    ) -> Result<bool, PlatformError> {
        Ok(&(self.id_deriver)(&evidence.vendor, &evidence.product, &evidence.serial)? == device_id)
    }

    /// Reuses protocol proof only when the backend proves physical-dock continuity.
    pub(in crate::platform) fn refresh_candidate_evidence<B: PlatformBackend>(
        &self,
        backend: &mut B,
        candidate: &CandidateDevice,
        platform: PlatformCapabilities,
        fresh_device: Option<&DeviceId>,
    ) -> Result<Option<ValidatedEvidence>, PlatformError> {
        for entry in self.entries.values() {
            let Some(host_facts) = backend.refresh_candidate_host_facts(
                candidate,
                &entry.candidate,
                entry.host_facts,
            )?
            else {
                continue;
            };
            if host_facts.media_present != host_facts.media_fingerprint.is_some() {
                return Err(PlatformError::StaleDeviceBinding);
            }
            if entry.host_facts.and_then(|facts| facts.media_fingerprint)
                != host_facts.media_fingerprint
            {
                return Ok(None);
            }
            // A firmware write invalidates protocol/configuration proof even
            // when macOS retains the same physical dock and media mapping.
            if fresh_device == Some(&entry.snapshot.id) {
                return Ok(None);
            }
            let mut evidence = entry.validated_evidence();
            evidence.host_facts = Some(host_facts);
            evidence.media_status.volume_label = if host_facts.mounted {
                backend.refresh_candidate_volume_label(candidate, host_facts)?
            } else {
                None
            };
            evidence.capabilities = device_capabilities(
                evidence.drive_mode_supported,
                evidence.interface,
                platform,
                evidence.host_facts,
                evidence.sata_mode_reported,
                evidence.media_status.volume_label.is_some(),
            );
            return Ok(Some(evidence));
        }
        Ok(None)
    }

    /// Opens and revalidates a current ID/revision into one live exact-handle lease.
    ///
    /// The returned value exclusively borrows this registry, so replacement,
    /// removal, or another resolution cannot race its use. Identity and
    /// capability probes run on the same handle retained by the resolution.
    ///
    /// # Errors
    ///
    /// Returns a sanitized unavailable, stale-revision, open, or binding failure.
    pub fn resolve<'registry, B: PlatformBackend>(
        &'registry mut self,
        backend: &mut B,
        id: &DeviceId,
        revision: DiscoveryRevision,
    ) -> Result<ResolvedDevice<'registry>, PlatformError> {
        let Some(entry) = self.entries.get(id) else {
            return if self.retired_ids.contains(id) {
                Err(PlatformError::StaleDeviceRevision)
            } else {
                Err(PlatformError::DeviceUnavailable)
            };
        };
        if entry.snapshot.revision != revision {
            return Err(PlatformError::StaleDeviceRevision);
        }
        let platform = backend.capabilities();
        if !platform.discovery_available() {
            return Err(PlatformError::DiscoveryUnavailable);
        }
        // Candidate-local open/revalidation is authoritative; a global startup
        // probe cannot safely open every service and therefore cannot gate a
        // later hotplugged exact recipe.
        let candidate_lease = backend.open_candidate(&entry.candidate)?;
        self.resolve_retained_firmware_lease(id, revision, platform, candidate_lease)
    }

    /// Revalidates a discovery lease without releasing and reopening its USB capture.
    /// This retains the exact handle through firmware readback. Every identity,
    /// capability, and media check from ordinary resolution remains mandatory.
    pub(crate) fn resolve_retained_firmware_lease(
        &mut self,
        id: &DeviceId,
        revision: DiscoveryRevision,
        platform: PlatformCapabilities,
        mut candidate_lease: CandidateLease,
    ) -> Result<ResolvedDevice<'_>, PlatformError> {
        let entry = self
            .entries
            .get(id)
            .ok_or(PlatformError::DeviceUnavailable)?;
        if entry.snapshot.revision != revision {
            return Err(PlatformError::StaleDeviceRevision);
        }
        if !platform.discovery_available() {
            return Err(PlatformError::DiscoveryUnavailable);
        }
        let evidence = revalidate_candidate_lease(&mut candidate_lease, &entry.candidate, platform)
            .ok_or(PlatformError::StaleDeviceBinding)?;
        if !entry.matches_evidence(&evidence) {
            return Err(PlatformError::StaleDeviceBinding);
        }
        let mut lease = candidate_lease.promote();
        let serial_key = crate::platform::serial_mapping_key(entry.snapshot.serial.as_str());
        lease
            .handle
            .bind_serial_mapping_key(&serial_key)
            .map_err(|_| PlatformError::StaleDeviceBinding)?;
        let host_mutations_available = platform.safe_eject_available()
            || platform.force_eject_available()
            || platform.format_available()
            || platform.drive_letter_available();
        let resolution_host_facts = if host_mutations_available {
            // Same-handle validation already captured the authoritative host
            // facts. A duplicate native read can release an exclusive macOS
            // SCSI lease and permit automount before the operation begins.
            Some(
                evidence
                    .host_facts
                    .ok_or(PlatformError::StaleDeviceBinding)?,
            )
        } else {
            // Discovery-only adapters have no host-volume contract. Their live
            // protocol lease must remain usable, while confirmation issuance
            // and every host mutation still fail closed without a fingerprint.
            None
        };
        let media_fingerprint = resolution_host_facts.and_then(|facts| facts.media_fingerprint);
        Ok(ResolvedDevice {
            entry,
            registry_generation: self.generation,
            platform,
            lease,
            media_fingerprint,
            active: true,
            led_recovery_armed: false,
            resolution_host_facts,
            safe_eject_preflight: None,
            #[cfg(target_os = "linux")]
            pending_format_unmount: None,
            #[cfg(any(windows, target_os = "linux"))]
            pending_format_layout: None,
        })
    }
}
