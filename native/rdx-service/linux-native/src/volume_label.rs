// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Bounded label payloads and exact mounted-filesystem operations.

use crate::{HostFilesystem, HostOperationOutcome, LinuxDevice, NativeError, VolumeLeaseSet};

impl LinuxDevice {
    /// Reads the sole exact mounted volume's native label.
    ///
    /// # Errors
    /// Rejects unknown filesystems and ambiguous or stale mounts.
    pub fn volume_label(&mut self) -> Result<String, NativeError> {
        #[cfg(target_os = "linux")]
        {
            self.inner.volume_label()
        }
        #[cfg(not(target_os = "linux"))]
        {
            Err(NativeError::UnsupportedPlatform)
        }
    }

    /// Renames the retained exact mount and verifies label and cartridge identity.
    #[must_use]
    pub fn set_volume_label(&mut self, label: &str) -> HostOperationOutcome {
        #[cfg(target_os = "linux")]
        {
            self.inner.set_volume_label(label)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = label;
            HostOperationOutcome::NotAttempted(NativeError::UnsupportedPlatform)
        }
    }
}

impl VolumeLeaseSet<'_> {
    /// Returns the sole exact mounted on-disk filesystem personality.
    #[must_use]
    pub fn mounted_filesystem(&self) -> Option<HostFilesystem> {
        #[cfg(target_os = "linux")]
        {
            self._leases.mounted_filesystem()
        }
        #[cfg(not(target_os = "linux"))]
        {
            None
        }
    }
}

/// Encodes the kernel's fixed FSLABEL_MAX buffer after filesystem-specific checks.
pub(crate) fn payload(label: &str, filesystem: HostFilesystem) -> Result<[u8; 256], NativeError> {
    let maximum = match filesystem {
        HostFilesystem::ExFat | HostFilesystem::Fat16 | HostFilesystem::Fat32 => 11,
        _ => 32,
    };
    let byte_limit = match filesystem {
        HostFilesystem::Ext2 | HostFilesystem::Ext3 | HostFilesystem::Ext4 => 16,
        HostFilesystem::Xfs => 12,
        _ => 255,
    };
    if label.len() > byte_limit
        || label.encode_utf16().count() > maximum
        || label
            .chars()
            .any(|c| c.is_control() || "\\/:*?\"<>|".contains(c))
    {
        return Err(NativeError::InvalidRequest);
    }
    let mut buffer = [0; 256];
    buffer[..label.len()].copy_from_slice(label.as_bytes());
    Ok(buffer)
}

#[cfg(test)]
mod tests {
    use super::*;
    /// Rejects unsafe or oversized names while permitting clear and bounded Unicode.
    #[test]
    fn native_bounded_payload_policy() {
        for label in ["", "Backup ä", "😀😀"] {
            assert!(payload(label, HostFilesystem::ExFat).is_ok());
        }
        for label in ["bad/name", "bad\nname", "😀😀😀😀😀😀"] {
            assert!(payload(label, HostFilesystem::ExFat).is_err());
        }
    }
}

#[cfg(test)]
mod linux_limits {
    use super::*;
    /// Linux filesystems limit bytes; multibyte names must never be silently truncated.
    #[test]
    fn label_payload_enforces_on_disk_byte_limits() {
        for (fs, limit) in [
            (HostFilesystem::Ext2, 16),
            (HostFilesystem::Ext3, 16),
            (HostFilesystem::Ext4, 16),
            (HostFilesystem::Xfs, 12),
        ] {
            assert!(payload(&"ä".repeat(limit / 2), fs).is_ok());
            assert!(payload(&"ä".repeat(limit / 2 + 1), fs).is_err());
        }
        for fs in [HostFilesystem::Fat16, HostFilesystem::Fat32] {
            assert!(payload("ELEVENCHARS", fs).is_ok());
            assert!(payload("TWELVECHARS!", fs).is_err());
        }
    }
}
