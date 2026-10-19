// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Exact volume-GUID label reads and writes; no drive-letter retargeting.
use super::*;
use windows::Win32::Storage::FileSystem::{GetVolumeInformationW, SetVolumeLabelW};

/// Reads a bounded label and filesystem from one retained volume GUID.
fn information(lease: &NativeVolumeLease) -> Result<(String, String), NativeError> {
    lease.revalidate()?;
    let mut label = [0u16; 33];
    let mut filesystem = [0u16; 64];
    // SAFETY: the pinned key is NUL-terminated; both buffers have bounded storage.
    unsafe {
        GetVolumeInformationW(
            PCWSTR(lease.volume_key().as_ptr()),
            Some(&mut label),
            None,
            None,
            None,
            Some(&mut filesystem),
        )
    }
    .map_err(map_windows_error)?;
    let text = |units: &[u16]| -> Result<String, NativeError> {
        let end = units
            .iter()
            .position(|unit| *unit == 0)
            .ok_or(NativeError::ResourceLimit)?;
        String::from_utf16(&units[..end]).map_err(|_| NativeError::InvalidRequest)
    };
    Ok((text(&label)?, text(&filesystem)?))
}

impl NativeDevice {
    /// Reads only the sole mounted volume belonging to the retained physical disk.
    pub(crate) fn volume_label(&self) -> Result<String, NativeError> {
        let (_, mounts, _, leases) = self.pin_volume_metadata()?;
        let [lease] = leases.as_slice() else {
            return Err(NativeError::EvidenceIncomplete);
        };
        if mounts == 0 {
            return Err(NativeError::NoMedia);
        }
        let (label, _) = information(lease)?;
        self.revalidate_volume_leases(&leases)?;
        Ok(label)
    }

    /// Reads the filesystem from the sole retained mounted volume.
    pub(crate) fn volume_filesystem(&self) -> Result<String, NativeError> {
        let (_, mounts, _, leases) = self.pin_volume_metadata()?;
        let [lease] = leases.as_slice() else {
            return Err(NativeError::EvidenceIncomplete);
        };
        if mounts == 0 {
            return Err(NativeError::NoMedia);
        }
        let (_, filesystem) = information(lease)?;
        self.revalidate_volume_leases(&leases)?;
        Ok(filesystem)
    }

    /// Revalidates disk, topology, medium and GUID around the one native rename.
    pub(crate) fn set_volume_label(&self, label: &str) -> HostOperationOutcome {
        let prepare = || -> Result<_, NativeError> {
            if label.encode_utf16().count() > 32
                || label
                    .chars()
                    .any(|c| c.is_control() || "\\/:*?\"<>|".contains(c))
            {
                return Err(NativeError::InvalidRequest);
            }
            let (writable, mounted, _, _, safe) = self.volume_facts()?;
            if !writable {
                return Err(NativeError::ReadOnly);
            }
            if !mounted || !safe {
                return Err(NativeError::EvidenceIncomplete);
            }
            let medium = self.media_identity_material()?;
            let (_, mounts, _, leases) = self.pin_volumes()?;
            let [lease] = leases.as_slice() else {
                return Err(NativeError::EvidenceIncomplete);
            };
            if mounts == 0 {
                return Err(NativeError::NoMedia);
            }
            let (_, filesystem) = information(lease)?;
            let maximum = if filesystem.eq_ignore_ascii_case("NTFS") {
                32
            } else if filesystem.eq_ignore_ascii_case("exFAT") {
                11
            } else {
                return Err(NativeError::UnsupportedPlatform);
            };
            if label.encode_utf16().count() > maximum {
                return Err(NativeError::InvalidRequest);
            }
            self.revalidate_volume_leases(&leases)?;
            if self.media_identity_material()? != medium {
                return Err(NativeError::DeviceRemoved);
            }
            Ok((leases, medium))
        };
        let (leases, medium) = match prepare() {
            Ok(value) => value,
            Err(error) => return HostOperationOutcome::NotAttempted(error),
        };
        let label_units = label.encode_utf16().chain(Some(0)).collect::<Vec<_>>();
        // SAFETY: the exact pinned volume GUID and validated label are NUL-terminated.
        if let Err(error) = unsafe {
            SetVolumeLabelW(
                PCWSTR(leases[0].volume_key().as_ptr()),
                PCWSTR(label_units.as_ptr()),
            )
        } {
            return HostOperationOutcome::CompletionUnknown(map_windows_error(error));
        }
        let verify = || -> Result<(), NativeError> {
            self.revalidate_volume_leases(&leases)?;
            if self.media_identity_material()? != medium || information(&leases[0])?.0 != label {
                return Err(NativeError::DeviceRemoved);
            }
            Ok(())
        };
        match verify() {
            Ok(()) => HostOperationOutcome::Succeeded,
            Err(error) => HostOperationOutcome::CompletionUnknown(error),
        }
    }
}
