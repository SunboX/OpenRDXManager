// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Volume attributes read and written through a retained exact mount descriptor.

use super::*;
use unicode_normalization::UnicodeNormalization;

impl MacDevice {
    /// Reads the sole validated native volume label and rename capability.
    ///
    /// # Errors
    /// Rejects unsupported, ambiguous, or stale Disk Arbitration mappings.
    pub fn volume_label(&mut self) -> Result<String, NativeError> {
        #[cfg(target_os = "macos")]
        {
            let mapping = self.pin_media()?;
            let directory = mapping.label_directory()?;
            let label = native::read_label(directory.as_raw_fd())?;
            mapping.validate_label_directory(directory.as_raw_fd())?;
            Ok(label)
        }
        #[cfg(not(target_os = "macos"))]
        {
            Err(NativeError::UnsupportedPlatform)
        }
    }

    /// Changes only a retained exact mounted volume's name and verifies readback.
    #[must_use]
    pub fn set_volume_label(&mut self, label: &str) -> HostOperationOutcome {
        #[cfg(target_os = "macos")]
        {
            native::rename(self, label)
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = label;
            HostOperationOutcome::NotAttempted(NativeError::UnsupportedPlatform)
        }
    }
}

#[cfg(target_os = "macos")]
use std::os::fd::AsRawFd;

/// Builds the ATTR_VOL_NAME reference and UTF-8 name with Darwin's 4-byte alignment.
fn payload(label: &str, maximum: usize) -> Result<Vec<u8>, NativeError> {
    if label.encode_utf16().count() > maximum
        || label
            .chars()
            .any(|c| c.is_control() || "\\/:*?\"<>|".contains(c))
    {
        return Err(NativeError::InvalidRequest);
    }
    let mut buffer = Vec::with_capacity(9 + label.len());
    buffer.extend_from_slice(&8_i32.to_ne_bytes());
    buffer.extend_from_slice(&(label.len() as u32 + 1).to_ne_bytes());
    buffer.extend_from_slice(label.as_bytes());
    buffer.push(0);
    // Darwin consumes variable-length attribute data in 4-byte units. The
    // reference counts only the name and NUL; omitting trailing padding makes
    // HFS+ reject names such as Backup_02 with EINVAL before changing them.
    buffer.resize(buffer.len().next_multiple_of(4), 0);
    Ok(buffer)
}

/// Decodes a bounded Darwin attrreference without dereferencing driver offsets.
fn decode(buffer: &[u8]) -> Result<String, NativeError> {
    if buffer.len() < 12 {
        return Err(NativeError::EvidenceIncomplete);
    }
    let total = u32::from_ne_bytes(buffer[..4].try_into().unwrap()) as usize;
    let offset = i32::from_ne_bytes(buffer[4..8].try_into().unwrap());
    let length = u32::from_ne_bytes(buffer[8..12].try_into().unwrap()) as usize;
    let start = 4_i64 + i64::from(offset);
    let start = usize::try_from(start).map_err(|_| NativeError::EvidenceIncomplete)?;
    let end = start
        .checked_add(length)
        .ok_or(NativeError::EvidenceIncomplete)?;
    if total > buffer.len() || start < 12 || end > total || length == 0 {
        return Err(NativeError::EvidenceIncomplete);
    }
    let bytes = &buffer[start..end];
    if bytes.last() != Some(&0) {
        return Err(NativeError::EvidenceIncomplete);
    }
    let label =
        std::str::from_utf8(&bytes[..length - 1]).map_err(|_| NativeError::EvidenceIncomplete)?;
    let label: String = label.nfc().collect();
    if label.encode_utf16().count() > 32 || label.chars().any(char::is_control) {
        return Err(NativeError::EvidenceIncomplete);
    }
    Ok(label)
}

#[cfg(target_os = "macos")]
mod native {
    use super::*;
    use std::ffi::CString;
    use std::mem::MaybeUninit;
    use std::os::fd::{FromRawFd, OwnedFd};
    use std::os::unix::ffi::OsStrExt;

    impl MediaLeaseSet<'_> {
        /// Opens the DA-derived root and validates it against retained IOMedia.
        pub(super) fn label_directory(&self) -> Result<OwnedFd, NativeError> {
            if self.mounted_media_count != 1
                || !self.mutation_topology_safe
                || !matches!(
                    self.mounted_filesystem,
                    Some(MountedFilesystem::ExFat | MountedFilesystem::MacOs(7 | 11))
                )
            {
                return Err(NativeError::UnsupportedPlatform);
            }
            let path = self
                .mount_path
                .as_ref()
                .ok_or(NativeError::EvidenceIncomplete)?;
            let path = CString::new(path.as_os_str().as_bytes())
                .map_err(|_| NativeError::EvidenceIncomplete)?;
            // SAFETY: a DA-derived NUL-terminated path; flags reject a final symlink.
            let fd = unsafe {
                libc::open(
                    path.as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
            };
            if fd < 0 {
                return Err(last_error());
            }
            // SAFETY: fd is a new uniquely owned descriptor.
            let directory = unsafe { OwnedFd::from_raw_fd(fd) };
            self.validate_label_directory(fd)?;
            Ok(directory)
        }

        /// Checks the pinned DA graph and retained filesystem root identity.
        pub(super) fn validate_label_directory(&self, fd: i32) -> Result<(), NativeError> {
            // SAFETY: the unique mapping keeps the native device allocation live.
            status_result(unsafe { ffi::rdx_macos_revalidate_media(self.device.inner.as_ptr()) })?;
            let mut stat = MaybeUninit::<libc::stat>::uninit();
            let mut fs = MaybeUninit::<libc::statfs>::uninit();
            // SAFETY: fd is retained; exact writable outputs are initialized on success.
            if unsafe {
                libc::fstat(fd, stat.as_mut_ptr()) != 0 || libc::fstatfs(fd, fs.as_mut_ptr()) != 0
            } {
                return Err(last_error());
            }
            // SAFETY: both successful calls initialized the complete outputs.
            let (stat, fs) = unsafe { (stat.assume_init(), fs.assume_init()) };
            if stat.st_dev as u64 != self.mounted_device_id || fs.f_blocks == 0 {
                return Err(NativeError::DeviceRemoved);
            }
            // SAFETY: native validation compares the retained fd to the exact IOMedia records.
            if !unsafe {
                ffi::rdx_macos_validate_mounted_fd(
                    self.device.inner.as_ptr(),
                    fd,
                    self.mounted_device_id,
                )
            } {
                return Err(NativeError::DeviceRemoved);
            }
            Ok(())
        }
    }

    /// Initializes the closed volume-attribute request; all other groups stay empty.
    fn attributes(bits: u32) -> libc::attrlist {
        libc::attrlist {
            bitmapcount: libc::ATTR_BIT_MAP_COUNT,
            reserved: 0,
            commonattr: 0,
            volattr: libc::ATTR_VOL_INFO | bits,
            dirattr: 0,
            fileattr: 0,
            forkattr: 0,
        }
    }

    /// Checks the driver's declared volume-rename capability before reading the name.
    pub(super) fn read_label(fd: i32) -> Result<String, NativeError> {
        let mut attributes = attributes(libc::ATTR_VOL_CAPABILITIES);
        let mut capabilities = [0_u32; 9];
        // SAFETY: exact attrlist and 36-byte output match length + vol_capabilities_attr_t.
        if unsafe {
            libc::fgetattrlist(
                fd,
                (&mut attributes as *mut libc::attrlist).cast(),
                capabilities.as_mut_ptr().cast(),
                36,
                0,
            )
        } != 0
        {
            return Err(last_error());
        }
        let index = libc::VOL_CAPABILITIES_INTERFACES;
        if capabilities[0] != 36
            || capabilities[1 + index] & capabilities[5 + index] & libc::VOL_CAP_INT_VOL_RENAME == 0
        {
            return Err(NativeError::UnsupportedPlatform);
        }
        let mut attributes = self::attributes(libc::ATTR_VOL_NAME);
        let mut buffer = [0_u8; 512];
        // SAFETY: bounded writable storage and live retained filesystem fd.
        if unsafe {
            libc::fgetattrlist(
                fd,
                (&mut attributes as *mut libc::attrlist).cast(),
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                0,
            )
        } != 0
        {
            return Err(last_error());
        }
        decode(&buffer)
    }

    /// Writes once, then verifies the same mounted authority and the returned label.
    pub(super) fn rename(device: &mut MacDevice, label: &str) -> HostOperationOutcome {
        let mapping = match device.pin_media() {
            Ok(value) => value,
            Err(error) => return HostOperationOutcome::NotAttempted(error),
        };
        let maximum = if matches!(
            mapping.mounted_filesystem,
            Some(MountedFilesystem::ExFat | MountedFilesystem::MacOs(3))
        ) {
            11
        } else {
            32
        };
        let prepared = (|| {
            if !mapping.writable {
                return Err(NativeError::AccessDenied);
            }
            let buffer = payload(label, maximum)?;
            let directory = mapping.label_directory()?;
            read_label(directory.as_raw_fd())?;
            let mut fs = MaybeUninit::<libc::statfs>::uninit();
            // SAFETY: the directory is retained and fs is complete writable output.
            if unsafe { libc::fstatfs(directory.as_raw_fd(), fs.as_mut_ptr()) } != 0 {
                return Err(last_error());
            }
            // SAFETY: successful fstatfs initialized the complete output.
            if unsafe { fs.assume_init() }.f_flags & libc::MNT_RDONLY as u32 != 0 {
                return Err(NativeError::AccessDenied);
            }
            mapping.validate_label_directory(directory.as_raw_fd())?;
            Ok((buffer, directory))
        })();
        let (mut buffer, directory) = match prepared {
            Ok(value) => value,
            Err(error) => return HostOperationOutcome::NotAttempted(error),
        };
        let mut attributes = attributes(libc::ATTR_VOL_NAME);
        // SAFETY: exact fd, complete attrreference payload, closed volume-name request.
        if unsafe {
            libc::fsetattrlist(
                directory.as_raw_fd(),
                (&mut attributes as *mut libc::attrlist).cast(),
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                0,
            )
        } != 0
        {
            let errno = std::io::Error::last_os_error().raw_os_error();
            return if matches!(
                errno,
                Some(libc::ENOTSUP | libc::EPERM | libc::EACCES | libc::EROFS | libc::EINVAL)
            ) {
                HostOperationOutcome::DefinitelyRejected(last_error())
            } else {
                HostOperationOutcome::CompletionUnknown(last_error())
            };
        }
        let verified = (|| {
            // SAFETY: directory remains retained and fsync has no pointer parameters.
            if unsafe { libc::fsync(directory.as_raw_fd()) } != 0 {
                return Err(last_error());
            }
            mapping.validate_label_directory(directory.as_raw_fd())?;
            if !read_label(directory.as_raw_fd())?.chars().eq(label.nfc()) {
                return Err(NativeError::EvidenceIncomplete);
            }
            Ok(())
        })();
        match verified {
            Ok(()) => HostOperationOutcome::Succeeded,
            Err(error) => HostOperationOutcome::CompletionUnknown(error),
        }
    }

    /// Sanitizes syscall failure without exposing native paths or labels.
    fn last_error() -> NativeError {
        match std::io::Error::last_os_error().raw_os_error() {
            Some(libc::ENOTSUP) => NativeError::UnsupportedPlatform,
            Some(libc::EPERM | libc::EACCES | libc::EROFS) => NativeError::AccessDenied,
            Some(libc::EINVAL) => NativeError::InvalidRequest,
            Some(libc::ENODEV | libc::ENOENT) => NativeError::DeviceRemoved,
            _ => NativeError::Other,
        }
    }

    /// Exercises the production attribute buffer on a disposable HFS+ volume.
    #[test]
    #[ignore = "creates and renames a disposable HFS+ disk image"]
    fn hfs_image_accepts_the_volume_name_payload() {
        use std::fs::File;
        use std::process::Command;

        let temporary = tempfile::tempdir().unwrap();
        let image = temporary.path().join("rename.sparseimage");
        let mount = temporary.path().join("mount");
        std::fs::create_dir(&mount).unwrap();
        assert!(
            Command::new("/usr/bin/hdiutil")
                .args([
                    "create",
                    "-size",
                    "64m",
                    "-fs",
                    "HFS+",
                    "-volname",
                    "Rename_Test",
                    "-type",
                    "SPARSE"
                ])
                .arg(&image)
                .output()
                .unwrap()
                .status
                .success()
        );
        assert!(
            Command::new("/usr/bin/hdiutil")
                .arg("attach")
                .arg(&image)
                .args(["-nobrowse", "-mountpoint"])
                .arg(&mount)
                .output()
                .unwrap()
                .status
                .success()
        );
        let result = (|| {
            let directory = File::open(&mount).unwrap();
            let mut buffer = payload("Backup_02", 32).unwrap();
            let mut request = attributes(libc::ATTR_VOL_NAME);
            // SAFETY: a root fd on our disposable image and the production payload.
            let written = unsafe {
                libc::fsetattrlist(
                    directory.as_raw_fd(),
                    (&mut request as *mut libc::attrlist).cast(),
                    buffer.as_mut_ptr().cast(),
                    buffer.len(),
                    0,
                )
            };
            if written != 0 {
                return Err(std::io::Error::last_os_error().to_string());
            }
            read_label(directory.as_raw_fd()).map_err(|error| format!("{error:?}"))
        })();
        // Release all descriptors before detaching, including on a failed write.
        assert!(
            Command::new("/usr/bin/hdiutil")
                .arg("detach")
                .arg(&mount)
                .output()
                .unwrap()
                .status
                .success()
        );
        assert_eq!(result, Ok("Backup_02".to_owned()));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Darwin rejects an unaligned name buffer even when its reference is valid.
    #[test]
    fn volume_name_payload_includes_required_alignment_padding() {
        assert_eq!(
            payload("Backup_02", 32).unwrap(),
            [
                8, 0, 0, 0, 10, 0, 0, 0, b'B', b'a', b'c', b'k', b'u', b'p', b'_', b'0', b'2', 0,
                0, 0
            ]
        );
        assert_eq!(
            payload("", 32).unwrap(),
            [8, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0]
        );
    }

    #[test]
    fn attribute_payload_and_malformed_references() {
        for label in ["", "Backup ä", "😀😀"] {
            let payload = payload(label, 11).unwrap();
            let mut returned = Vec::new();
            returned.extend_from_slice(&(payload.len() as u32 + 4).to_ne_bytes());
            returned.extend(payload);
            assert_eq!(decode(&returned).unwrap(), label);
            returned[4..8].copy_from_slice(&(-8_i32).to_ne_bytes());
            assert!(decode(&returned).is_err());
        }
        assert!(payload("bad/name", 32).is_err());
        assert!(payload("😀".repeat(17).as_str(), 32).is_err());
        assert!(decode(&[0; 12]).is_err());
        let encoded = payload("Cafe\u{301}", 32).unwrap();
        let mut returned = (encoded.len() as u32 + 4).to_ne_bytes().to_vec();
        returned.extend(encoded);
        assert_eq!(decode(&returned).unwrap(), "Café");
        let encoded = payload(&"e\u{301}".repeat(32), 64).unwrap();
        let mut returned = (encoded.len() as u32 + 4).to_ne_bytes().to_vec();
        returned.extend(encoded);
        assert_eq!(decode(&returned).unwrap(), "é".repeat(32));
    }
}
