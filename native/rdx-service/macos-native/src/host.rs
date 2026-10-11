// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Closed macOS host formatting and mounted-volume I/O operations.

#[cfg(target_os = "macos")]
use std::ffi::CString;
#[cfg(target_os = "macos")]
use std::mem::MaybeUninit;
#[cfg(target_os = "macos")]
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
#[cfg(target_os = "macos")]
use std::os::unix::ffi::OsStrExt;

use super::*;

impl MacDevice {
    /// Checks retained-fd exFAT capacity and exact current mapping.
    ///
    /// # Errors
    ///
    /// Rejects NTFS because current macOS has no supported native NTFS formatter,
    /// and rejects capacities outside the closed internal MBR/GPT formatter.
    pub fn preflight_exfat_format(&mut self) -> Result<(), NativeError> {
        #[cfg(target_os = "macos")]
        {
            let mapping = self.pin_media()?;
            let capacity = mapping.volume_facts().2;
            let maximum = (u64::from(u32::MAX) - 2) * 128 * 512;
            if !mapping.whole_media_present()
                || !mapping.mutation_topology_safe()
                || capacity < 32 * 1024 * 1024
                || capacity > maximum
            {
                return Err(NativeError::EvidenceIncomplete);
            }
            Ok(())
        }
        #[cfg(not(target_os = "macos"))]
        {
            Err(NativeError::UnsupportedPlatform)
        }
    }

    /// Executes a closed Apple formatter against the retained exact whole disk.
    /// The password is borrowed only for the private anonymous stdin pipe.
    pub fn system_format(&mut self, selector: u32, password: Option<&str>) -> HostOperationOutcome {
        if !(selector == 1 || (3..=14).contains(&selector)) {
            return HostOperationOutcome::NotAttempted(NativeError::InvalidRequest);
        }
        #[cfg(target_os = "macos")]
        {
            let bytes = password.unwrap_or("").as_bytes();
            let mut output = ptr::null_mut();
            // SAFETY: device and borrowed bytes remain live for the bounded synchronous call.
            let status = unsafe {
                ffi::rdx_macos_system_format(
                    self.inner.as_ptr(),
                    selector,
                    bytes.as_ptr(),
                    bytes.len(),
                    &mut output,
                )
            };
            let Some(owner) = ResultOwner::new(output) else {
                return HostOperationOutcome::NotAttempted(
                    status_result(status).unwrap_err_or(NativeError::Other),
                );
            };
            // SAFETY: the unique owner retains the complete C result.
            let result = unsafe { owner.as_ref() };
            if !valid_header(&result.header, ffi::RESULT_HOST_OPERATION, status) {
                return HostOperationOutcome::CompletionUnknown(NativeError::Other);
            }
            parse_host_operation_outcome(status, result)
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = password;
            HostOperationOutcome::NotAttempted(NativeError::UnsupportedPlatform)
        }
    }

    /// Writes one closed capacity-selected MBR/GPT plus exFAT layout through the retained fd.
    #[must_use]
    pub fn partition_and_format_exfat(&mut self, mbr_signature: u32) -> HostOperationOutcome {
        if mbr_signature == 0 {
            return HostOperationOutcome::NotAttempted(NativeError::InvalidRequest);
        }
        #[cfg(target_os = "macos")]
        {
            let mut output = ptr::null_mut();
            // SAFETY: the unique device owns its exact mapping, the filesystem
            // selector is closed, and C owns the synchronous result allocation.
            let status = unsafe {
                ffi::rdx_macos_partition_and_format(
                    self.inner.as_ptr(),
                    ffi::FILESYSTEM_EXFAT,
                    mbr_signature,
                    &mut output,
                )
            };
            let Some(owner) = ResultOwner::new(output) else {
                return HostOperationOutcome::NotAttempted(
                    status_result(status).unwrap_err_or(NativeError::Other),
                );
            };
            // SAFETY: owner uniquely owns one C HostOperationResult until drop.
            let result = unsafe { owner.as_ref() };
            if !valid_header(&result.header, ffi::RESULT_HOST_OPERATION, status) {
                return HostOperationOutcome::CompletionUnknown(NativeError::Other);
            }
            parse_host_operation_outcome(status, result)
        }
        #[cfg(not(target_os = "macos"))]
        {
            HostOperationOutcome::NotAttempted(NativeError::UnsupportedPlatform)
        }
    }
}

impl MacScsiLease {
    /// Executes one bounded semantic SCSI operation through exclusive authority.
    #[must_use]
    pub fn execute(&mut self, operation: ScsiOperation) -> Completion {
        #[cfg(target_os = "macos")]
        {
            self.execute_request(operation.into_request())
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = operation;
            Completion::NotAttempted(NativeError::UnsupportedPlatform)
        }
    }

    /// Executes one already validated fixed-layout request from the private worker protocol.
    #[cfg(target_os = "macos")]
    pub(crate) fn execute_request(&mut self, request: ffi::ScsiRequest) -> Completion {
        let mut output = ptr::null_mut();
        // SAFETY: both values are live fixed-layout objects and C initializes
        // or leaves null the separately owned result pointer.
        let status =
            unsafe { ffi::rdx_macos_execute_scsi(self.inner.as_ptr(), &request, &mut output) };
        let Some(owner) = ResultOwner::new(output) else {
            return Completion::NotAttempted(
                status_result(status).unwrap_err_or(NativeError::Other),
            );
        };
        // SAFETY: `owner` uniquely owns a C-allocated `ScsiResult` until drop.
        let result = unsafe { owner.as_ref() };
        if !valid_header(&result.header, ffi::RESULT_SCSI, status)
            || result.attempted > 1
            || result.data_length as usize > ffi::MAX_TRANSFER_BYTES
            || result.sense_length as usize > ffi::MAX_SENSE_BYTES
            || result.realized_transfer_count > u64::from(u32::MAX)
        {
            return attempted_failure(result.attempted, NativeError::Other);
        }
        if status != ffi::STATUS_OK {
            return attempted_failure(result.attempted, status_error(status));
        }
        if result.attempted != 1 {
            return Completion::NotAttempted(NativeError::Other);
        }
        let data_length = result.data_length as usize;
        let sense_length = result.sense_length as usize;
        Completion::Device {
            scsi_status: result.scsi_status,
            service_response: result.service_response,
            transferred_length: result.realized_transfer_count as u32,
            data: result.data[..data_length].to_vec(),
            sense_reported_length: sense_length,
            sense: result.sense[..sense_length].to_vec(),
        }
    }
}

#[cfg(target_os = "macos")]
impl Drop for MacDevice {
    /// Releases exclusive access, interface, plug-in, service, and media exactly once.
    fn drop(&mut self) {
        // SAFETY: `inner` is uniquely owned from successful open until this drop.
        unsafe { ffi::rdx_macos_release_device(self.inner.as_ptr()) };
    }
}

impl MediaLeaseSet<'_> {
    /// Performs the native exact-file operation while the DA mapping stays borrowed.
    #[cfg(target_os = "macos")]
    pub(super) fn write_read_file_native(
        &mut self,
        filename: &str,
        bytes: &[u8],
    ) -> FileTestOutcome {
        if self.mounted_media_count != 1
            || !self.writable
            || bytes.is_empty()
            || bytes.len() > 4 * 1024 * 1024
            || !valid_test_filename(filename)
        {
            return FileTestOutcome {
                operation: Err(NativeError::InvalidRequest),
                operation_certainty: HostOperationOutcome::NotAttempted(
                    NativeError::InvalidRequest,
                ),
                cleanup: HostOperationOutcome::NotAttempted(NativeError::InvalidRequest),
            };
        }
        // SAFETY: the unique device borrow keeps the exact mapping alive for this call.
        let status = unsafe { ffi::rdx_macos_revalidate_media(self.device.inner.as_ptr()) };
        if let Err(error) = status_result(status) {
            return FileTestOutcome {
                operation: Err(error),
                operation_certainty: HostOperationOutcome::NotAttempted(error),
                cleanup: HostOperationOutcome::NotAttempted(error),
            };
        }
        let Some(path) = self.mount_path.as_ref() else {
            return FileTestOutcome {
                operation: Err(NativeError::EvidenceIncomplete),
                operation_certainty: HostOperationOutcome::NotAttempted(
                    NativeError::EvidenceIncomplete,
                ),
                cleanup: HostOperationOutcome::NotAttempted(NativeError::EvidenceIncomplete),
            };
        };
        let path = match CString::new(path.as_os_str().as_bytes()) {
            Ok(path) => path,
            Err(_) => {
                return FileTestOutcome {
                    operation: Err(NativeError::EvidenceIncomplete),
                    operation_certainty: HostOperationOutcome::NotAttempted(
                        NativeError::EvidenceIncomplete,
                    ),
                    cleanup: HostOperationOutcome::NotAttempted(NativeError::EvidenceIncomplete),
                };
            }
        };
        let filename = CString::new(filename).expect("validated ASCII basename");
        // SAFETY: the DA-derived path is NUL-terminated and flags require no mode.
        let directory = unsafe {
            libc::open(
                path.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if directory < 0 {
            let error = last_file_error();
            return FileTestOutcome {
                operation: Err(error),
                operation_certainty: HostOperationOutcome::NotAttempted(error),
                cleanup: HostOperationOutcome::NotAttempted(error),
            };
        }
        // SAFETY: `directory` is a new uniquely owned descriptor.
        let directory = unsafe { OwnedFd::from_raw_fd(directory) };
        let mut identity = MaybeUninit::<libc::stat>::uninit();
        let mut filesystem = MaybeUninit::<libc::statfs>::uninit();
        // SAFETY: directory is live and both outputs are exact writable storage.
        let exact_mount = unsafe {
            libc::fstat(directory.as_raw_fd(), identity.as_mut_ptr()) == 0
                && libc::fstatfs(directory.as_raw_fd(), filesystem.as_mut_ptr()) == 0
        };
        if !exact_mount {
            let error = last_file_error();
            return FileTestOutcome {
                operation: Err(error),
                operation_certainty: HostOperationOutcome::NotAttempted(error),
                cleanup: HostOperationOutcome::NotAttempted(error),
            };
        }
        // SAFETY: both successful calls initialized their complete outputs.
        let identity = unsafe { identity.assume_init() };
        // SAFETY: successful fstatfs initialized the complete structure.
        let filesystem = unsafe { filesystem.assume_init() };
        if identity.st_dev as u64 != self.mounted_device_id
            || filesystem.f_blocks == 0
            || filesystem.f_bsize == 0
            || filesystem.f_flags & libc::MNT_RDONLY as u32 != 0
        {
            return FileTestOutcome {
                operation: Err(NativeError::EvidenceIncomplete),
                operation_certainty: HostOperationOutcome::NotAttempted(
                    NativeError::EvidenceIncomplete,
                ),
                cleanup: HostOperationOutcome::NotAttempted(NativeError::EvidenceIncomplete),
            };
        }
        // SAFETY: directory is retained by OwnedFd and the unique mapping owns
        // the exact DA/IOMedia records used for the current-device comparison.
        if !unsafe {
            ffi::rdx_macos_validate_mounted_fd(
                self.device.inner.as_ptr(),
                directory.as_raw_fd(),
                self.mounted_device_id,
            )
        } {
            return FileTestOutcome {
                operation: Err(NativeError::EvidenceIncomplete),
                operation_certainty: HostOperationOutcome::NotAttempted(
                    NativeError::EvidenceIncomplete,
                ),
                cleanup: HostOperationOutcome::NotAttempted(NativeError::EvidenceIncomplete),
            };
        }
        // SAFETY: exact device and DA media objects remain uniquely borrowed.
        let status = unsafe { ffi::rdx_macos_revalidate_media(self.device.inner.as_ptr()) };
        if let Err(error) = status_result(status) {
            return FileTestOutcome {
                operation: Err(error),
                operation_certainty: HostOperationOutcome::NotAttempted(error),
                cleanup: HostOperationOutcome::NotAttempted(error),
            };
        }
        let (mut operation, mut operation_certainty, created) =
            write_close_reopen_read(directory.as_raw_fd(), &filename, bytes);
        let cleanup = if !created {
            HostOperationOutcome::Succeeded
        } else {
            // SAFETY: exact retained directory and validated single basename.
            let removed =
                unsafe { libc::unlinkat(directory.as_raw_fd(), filename.as_ptr(), 0) } == 0;
            // SAFETY: directory owns a live descriptor and fsync has no pointers.
            let synced = removed && unsafe { libc::fsync(directory.as_raw_fd()) } == 0;
            if synced {
                HostOperationOutcome::Succeeded
            } else {
                HostOperationOutcome::CompletionUnknown(last_file_error())
            }
        };
        // SAFETY: exact device and DA media objects remain uniquely borrowed.
        let status = unsafe { ffi::rdx_macos_revalidate_media(self.device.inner.as_ptr()) };
        if operation.is_ok() {
            if let Err(error) = status_result(status) {
                operation = Err(error);
                operation_certainty = HostOperationOutcome::CompletionUnknown(error);
            }
        }
        FileTestOutcome {
            operation,
            operation_certainty,
            cleanup,
        }
    }
}

/// Converts the sole bounded FFI mount path without exposing it publicly.
#[cfg(target_os = "macos")]
pub(super) fn mapping_mount_path(
    result: &ffi::MappingResult,
) -> Result<Option<PathBuf>, NativeError> {
    let Some(end) = result.mounted_path.iter().position(|byte| *byte == 0) else {
        return Err(NativeError::EvidenceIncomplete);
    };
    if end == 0 {
        return Ok(None);
    }
    if result.mounted_path[end + 1..].iter().any(|byte| *byte != 0) {
        return Err(NativeError::EvidenceIncomplete);
    }
    Ok(Some(PathBuf::from(std::ffi::OsStr::from_bytes(
        &result.mounted_path[..end],
    ))))
}

/// Accepts only the parent service's cryptographically random app basename.
#[cfg(target_os = "macos")]
fn valid_test_filename(filename: &str) -> bool {
    let prefix = ".openrdx-write-read-";
    let suffix = ".tmp";
    filename.len() == prefix.len() + 32 + suffix.len()
        && filename.starts_with(prefix)
        && filename.ends_with(suffix)
        && filename[prefix.len()..filename.len() - suffix.len()]
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

/// Performs one exact create/write/flush/close/reopen/read sequence.
#[cfg(target_os = "macos")]
fn write_close_reopen_read(
    directory: libc::c_int,
    filename: &CString,
    bytes: &[u8],
) -> (Result<Vec<u8>, NativeError>, HostOperationOutcome, bool) {
    // SAFETY: directory is retained, the basename is validated, and O_EXCL plus
    // O_NOFOLLOW forbid replacement and final-component symlink traversal.
    let raw = unsafe {
        libc::openat(
            directory,
            filename.as_ptr(),
            libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_WRONLY,
            0o600,
        )
    };
    if raw < 0 {
        let error = last_file_error();
        return (
            Err(error),
            HostOperationOutcome::CompletionUnknown(error),
            false,
        );
    }
    // SAFETY: `raw` is a new uniquely owned descriptor.
    let file = unsafe { OwnedFd::from_raw_fd(raw) };
    if let Err(error) = write_all(file.as_raw_fd(), bytes) {
        return (
            Err(error),
            HostOperationOutcome::CompletionUnknown(error),
            true,
        );
    }
    // SAFETY: file owns a live descriptor and fsync has no pointer arguments.
    if unsafe { libc::fsync(file.as_raw_fd()) } != 0 {
        let error = last_file_error();
        return (
            Err(error),
            HostOperationOutcome::CompletionUnknown(error),
            true,
        );
    }
    drop(file);
    // SAFETY: same retained directory and basename; create is deliberately omitted.
    let raw = unsafe {
        libc::openat(
            directory,
            filename.as_ptr(),
            libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_RDONLY,
        )
    };
    if raw < 0 {
        let error = last_file_error();
        return (
            Err(error),
            HostOperationOutcome::CompletionUnknown(error),
            true,
        );
    }
    // SAFETY: `raw` is a new uniquely owned descriptor.
    let file = unsafe { OwnedFd::from_raw_fd(raw) };
    let operation = read_exact(file.as_raw_fd(), bytes.len());
    let certainty = if operation.is_ok() {
        HostOperationOutcome::Succeeded
    } else {
        HostOperationOutcome::CompletionUnknown(*operation.as_ref().expect_err("failed readback"))
    };
    (operation, certainty, true)
}

/// Writes every byte, retrying only interrupted syscalls.
#[cfg(target_os = "macos")]
fn write_all(fd: libc::c_int, mut bytes: &[u8]) -> Result<(), NativeError> {
    while !bytes.is_empty() {
        // SAFETY: bytes is initialized for its exact bounded length.
        let written = unsafe { libc::write(fd, bytes.as_ptr().cast(), bytes.len()) };
        if written > 0 {
            bytes = &bytes[written as usize..];
        } else if written < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR)
        {
            continue;
        } else {
            return Err(last_file_error());
        }
    }
    Ok(())
}

/// Reads the exact expected length and rejects truncation or trailing bytes.
#[cfg(target_os = "macos")]
fn read_exact(fd: libc::c_int, length: usize) -> Result<Vec<u8>, NativeError> {
    let mut output = vec![0_u8; length];
    let mut offset = 0;
    while offset < length {
        // SAFETY: output suffix is writable for the exact remaining length.
        let read = unsafe { libc::read(fd, output[offset..].as_mut_ptr().cast(), length - offset) };
        if read > 0 {
            offset += read as usize;
        } else if read < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
            continue;
        } else {
            return Err(NativeError::Other);
        }
    }
    let mut trailing = [0_u8; 1];
    // SAFETY: trailing is valid writable storage for one byte.
    if unsafe { libc::read(fd, trailing.as_mut_ptr().cast(), 1) } != 0 {
        return Err(NativeError::Other);
    }
    Ok(output)
}

/// Sanitizes the current filesystem errno without retaining native text.
#[cfg(target_os = "macos")]
fn last_file_error() -> NativeError {
    match std::io::Error::last_os_error().raw_os_error() {
        Some(libc::EACCES | libc::EPERM) => NativeError::AccessDenied,
        Some(libc::EBUSY | libc::EEXIST) => NativeError::Busy,
        Some(libc::ENODEV | libc::ENOENT) => NativeError::DeviceRemoved,
        _ => NativeError::Other,
    }
}
