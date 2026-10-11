// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Non-capturing label refresh for an already validated physical dock.
use super::*;

impl MacOsBackend {
    /// Reads a label between matching exact media fingerprints without unmounting.
    pub(super) fn refresh_volume_label(
        &mut self,
        candidate: &CandidateDevice,
        facts: crate::operations::HostVolumeFacts,
    ) -> Result<Option<crate::model::VolumeLabel>, PlatformError> {
        #[cfg(target_os = "macos")]
        {
            let retained = self
                .staged
                .as_ref()
                .and_then(|recipes| recipes.reopen(&candidate.locator))
                .ok_or(PlatformError::DeviceRemoved)?;
            let mut authority =
                rdx_macos_native::MacDevice::open(retained).map_err(map_native_platform_error)?;
            let mapping = authority.pin_media().map_err(map_native_platform_error)?;
            if host_facts_from_mapping(&mapping).media_fingerprint != facts.media_fingerprint {
                return Err(PlatformError::StaleDeviceBinding);
            }
            drop(mapping);
            let label = authority
                .volume_label()
                .ok()
                .and_then(|label| crate::model::VolumeLabel::new(label).ok());
            let mapping = authority.pin_media().map_err(map_native_platform_error)?;
            if host_facts_from_mapping(&mapping).media_fingerprint != facts.media_fingerprint {
                return Err(PlatformError::StaleDeviceBinding);
            }
            Ok(label)
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (candidate, facts);
            Ok(None)
        }
    }
}
