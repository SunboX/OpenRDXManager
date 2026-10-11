// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Linux discovery staging and exact operation lease reopening.

use super::*;

impl PlatformBackend for LinuxBackend {
    /// Linux authorizes only the two fixed factory-record reads, not sector capture.
    fn supports_manufacturing_sector_read(&self) -> bool {
        false
    }

    /// Returns the immutable readiness-derived capability matrix.
    fn capabilities(&self) -> PlatformCapabilities {
        self.report.capabilities
    }

    /// Enumerates only bounded `/sys/class/scsi_generic/sg*` candidates.
    fn enumerate_candidates(&mut self) -> Result<Vec<CandidateDevice>, PlatformError> {
        if !self.report.capabilities.discovery_available() {
            return Err(PlatformError::DiscoveryUnavailable);
        }
        if !self.native_active {
            return Err(PlatformError::EnumerationFailed);
        }
        #[cfg(target_os = "linux")]
        {
            self.staged = Some(self.pending.stage_generation()?);
            let candidates = rdx_linux_native::enumerate_scsi_generic_candidates()
                .map_err(map_native_platform_error)?;
            let mut result = Vec::with_capacity(candidates.len());
            for candidate in candidates {
                let token = candidate.token().to_owned();
                let locator = self
                    .staged
                    .as_mut()
                    .expect("staged generation")
                    .retain(&token, candidate)?;
                result.push(
                    CandidateDevice::new(
                        token,
                        locator,
                        CandidateMetadata::new(None, None, None, None),
                    )
                    .map_err(|_| PlatformError::EnumerationFailed)?,
                );
            }
            Ok(result)
        }
        #[cfg(not(target_os = "linux"))]
        {
            Err(PlatformError::DiscoveryUnavailable)
        }
    }

    /// Revalidates and opens the exact sysfs/device-number recipe into one lease.
    fn open_candidate(
        &mut self,
        candidate: &CandidateDevice,
    ) -> Result<CandidateLease, PlatformError> {
        if !self.report.capabilities.transport_available() || !self.native_active {
            return Err(PlatformError::TransportUnavailable);
        }
        #[cfg(target_os = "linux")]
        {
            let retained = self
                .staged
                .as_ref()
                .and_then(|staged| staged.reopen(&candidate.locator))
                .or_else(|| self.pending.reopen(&candidate.locator))
                .ok_or(PlatformError::DeviceRemoved)?;
            if retained.token() != candidate.token() {
                return Err(PlatformError::DeviceRemoved);
            }
            let device = rdx_linux_native::LinuxDevice::reopen(retained)
                .map_err(map_native_platform_error)?;
            Ok(CandidateLease::new(LinuxDeviceHandle { device }))
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = candidate;
            Err(PlatformError::TransportUnavailable)
        }
    }

    /// Publishes exact reopen recipes only after discovery commits its registry.
    fn commit_candidate_refresh(&mut self) {
        #[cfg(target_os = "linux")]
        if let Some(staged) = self.staged.take() {
            self.pending.commit_generation(staged);
        }
    }

    /// A failed scan leaves the previous committed operation authority intact.
    fn abort_candidate_refresh(&mut self) {
        #[cfg(target_os = "linux")]
        {
            self.staged = None;
        }
    }
}
