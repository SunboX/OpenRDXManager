// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Format-only transitions under the exact resolved dock and cartridge lease.

use super::*;

impl ResolvedDevice<'_> {
    /// Clears mutation continuations before any ordinary identity revalidation.
    pub(super) fn clear_format_continuations(&mut self) {
        #[cfg(target_os = "linux")]
        {
            self.pending_format_unmount = None;
        }
        #[cfg(any(windows, target_os = "linux"))]
        {
            self.pending_format_layout = None;
        }
    }

    /// Records only an exact successful Linux unmount performed by this lease.
    pub(super) fn unmount_format_volumes(
        &mut self,
        expected: &HostVolumeBinding,
    ) -> Result<(), PrimitiveFailure> {
        self.revalidate_host_binding(expected)?;
        self.lease.handle.unmount_exact_volumes()?;
        #[cfg(target_os = "linux")]
        {
            self.pending_format_unmount = Some(expected.clone());
        }
        Ok(())
    }

    /// Arms a one-shot continuation only after this lease wrote its layout.
    pub(super) fn create_format_layout(
        &mut self,
        expected: &HostVolumeBinding,
        signature: u32,
    ) -> Result<(), PrimitiveFailure> {
        #[cfg(target_os = "linux")]
        if self.pending_format_unmount.is_some() {
            self.revalidate_unmounted_format(expected)?;
        } else {
            self.revalidate_host_binding(expected)?;
        }
        #[cfg(not(target_os = "linux"))]
        self.revalidate_host_binding(expected)?;
        #[cfg(target_os = "linux")]
        {
            // The unmount proof authorizes one layout dispatch, including failed dispatches.
            self.pending_format_unmount = None;
            self.pending_format_layout = None;
        }
        self.lease.handle.create_single_partition(signature)?;
        #[cfg(any(windows, target_os = "linux"))]
        {
            self.pending_format_layout = Some(expected.clone());
        }
        Ok(())
    }

    /// Consumes the exact layout continuation, or acknowledges a combined native format.
    pub(super) fn finish_format_layout(
        &mut self,
        expected: &HostVolumeBinding,
        filesystem: FileSystem,
    ) -> Result<(), PrimitiveFailure> {
        if self.lease.handle.completed_format() == Some(filesystem) {
            // macOS already verified its combined layout/filesystem operation.
            self.require_host_binding(expected)?;
        } else {
            #[cfg(any(windows, target_os = "linux"))]
            self.revalidate_created_layout(expected)?;
            #[cfg(not(any(windows, target_os = "linux")))]
            self.revalidate_host_binding(expected)?;
        }
        self.lease.handle.format_partition(filesystem)
    }

    /// Consumes the one-shot layout proof before checking the changed host topology.
    #[cfg(any(windows, target_os = "linux"))]
    fn revalidate_created_layout(
        &mut self,
        expected: &HostVolumeBinding,
    ) -> Result<(), PrimitiveFailure> {
        let continuation = self.pending_format_layout.take();
        #[cfg(target_os = "linux")]
        {
            self.pending_format_unmount = None;
        }
        if continuation.as_ref() != Some(expected) {
            self.active = false;
            return Err(PrimitiveFailure::not_attempted(
                HostPrimitiveError::StaleBinding,
            ));
        }
        self.revalidate_format_transition(expected).map(|_| ())
    }

    /// Accepts the expected unmounted state only after our exact successful unmount.
    #[cfg(target_os = "linux")]
    fn revalidate_unmounted_format(
        &mut self,
        expected: &HostVolumeBinding,
    ) -> Result<HostVolumeFacts, PrimitiveFailure> {
        if self.pending_format_unmount.as_ref() != Some(expected) {
            self.active = false;
            return Err(PrimitiveFailure::not_attempted(
                HostPrimitiveError::StaleBinding,
            ));
        }
        self.revalidate_format_transition(expected)
    }

    /// Allows our mount/layout changes while retaining full dock, medium and configuration proof.
    #[cfg(any(windows, target_os = "linux"))]
    fn revalidate_format_transition(
        &mut self,
        expected: &HostVolumeBinding,
    ) -> Result<HostVolumeFacts, PrimitiveFailure> {
        self.resolution_host_facts = None;
        self.safe_eject_preflight = None;
        let result = (|| {
            self.require_host_binding(expected)?;
            let mut evidence =
                revalidate_device_lease(&mut self.lease, &self.entry.candidate, self.platform)
                    .ok_or_else(|| {
                        PrimitiveFailure::not_attempted(HostPrimitiveError::StaleBinding)
                    })?;
            let facts = evidence
                .host_facts
                .ok_or_else(|| PrimitiveFailure::not_attempted(HostPrimitiveError::StaleBinding))?;
            let same_medium = self.entry.host_facts.is_some_and(|before| {
                before.media_present
                    && facts.media_present
                    && before.writable
                    && facts.writable
                    && before.capacity_bytes == facts.capacity_bytes
                    && before.media_fingerprint.is_some()
                    && before.media_fingerprint == facts.media_fingerprint
                    && facts.topology == crate::operations::VolumeTopology::Simple
            });
            if !same_medium {
                return Err(PrimitiveFailure::not_attempted(
                    HostPrimitiveError::StaleBinding,
                ));
            }
            #[cfg(target_os = "linux")]
            if facts.mounted || facts.filesystem.is_some() {
                // Automount or an external filesystem transition is not our continuation.
                return Err(PrimitiveFailure::not_attempted(
                    HostPrimitiveError::StaleBinding,
                ));
            }
            // Only host facts changed by our successful unmount/layout are normalized.
            // Native topology proof and all protocol identity/configuration fields stay live.
            evidence.host_facts = self.entry.host_facts;
            evidence.capabilities = device_capabilities(
                evidence.drive_mode_supported,
                evidence.interface,
                self.platform,
                evidence.host_facts,
                evidence.sata_mode_reported,
                self.entry.media_status.volume_label.is_some(),
            );
            if !self.entry.matches_evidence(&evidence) {
                return Err(PrimitiveFailure::not_attempted(
                    HostPrimitiveError::StaleBinding,
                ));
            }
            Ok(facts)
        })();
        if result.is_err() {
            self.active = false;
            self.clear_format_continuations();
        }
        result
    }

    /// Sets the transient formatting secret only on this retained device lease.
    pub(crate) fn set_format_passphrase(
        &mut self,
        passphrase: Option<crate::model::FormatPassphrase>,
    ) -> Result<(), PrimitiveFailure> {
        self.lease.handle.set_format_passphrase(passphrase)
    }

    /// Retains ordinary macOS and unsupported-platform format revalidation.
    #[cfg(not(any(windows, target_os = "linux")))]
    pub(super) fn format_facts(
        &mut self,
        expected: &HostVolumeBinding,
    ) -> Result<HostVolumeFacts, PrimitiveFailure> {
        self.revalidate(expected)
    }

    /// Uses ordinary proof until our successful unmount authorizes the narrow continuation.
    #[cfg(target_os = "linux")]
    pub(super) fn format_facts(
        &mut self,
        expected: &HostVolumeBinding,
    ) -> Result<HostVolumeFacts, PrimitiveFailure> {
        if self.pending_format_unmount.is_some() {
            self.revalidate_unmounted_format(expected)
        } else {
            self.revalidate(expected)
        }
    }

    /// Rechecks protocol/medium identity with a fresh format-only native topology proof.
    #[cfg(windows)]
    pub(super) fn format_facts(
        &mut self,
        expected: &HostVolumeBinding,
    ) -> Result<HostVolumeFacts, PrimitiveFailure> {
        self.require_host_binding(expected)?;
        // Discovery's ordinary facts are never a format-exception capability.
        self.resolution_host_facts = None;
        self.revalidate_identity()
            .map_err(|_| PrimitiveFailure::not_attempted(HostPrimitiveError::StaleBinding))?;
        let facts = self.lease.handle.host_format_volume_facts()?;
        if facts.media_fingerprint != expected.media_fingerprint() {
            self.active = false;
            return Err(PrimitiveFailure::not_attempted(
                HostPrimitiveError::StaleBinding,
            ));
        }
        Ok(facts)
    }
}
