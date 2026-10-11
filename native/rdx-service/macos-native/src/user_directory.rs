// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! OS account lookup for the already authenticated desktop user.

use crate::NativeError;
use std::path::PathBuf;

/// Resolves a non-root account's home through the macOS account database, never environment paths.
#[cfg(target_os = "macos")]
pub fn user_home_directory(owner: u32) -> Result<PathBuf, NativeError> {
    use std::os::unix::ffi::OsStrExt;
    if owner == 0 {
        return Err(NativeError::Other);
    }
    let mut buffer = vec![0_u8; 65_536];
    let mut entry = std::mem::MaybeUninit::<libc::passwd>::uninit();
    let mut result = std::ptr::null_mut();
    // SAFETY: All output pointers are writable for the supplied bounds; returned
    // strings remain within buffer until copied below. getpwuid_r is thread-safe.
    let status = unsafe {
        libc::getpwuid_r(
            owner,
            entry.as_mut_ptr(),
            buffer.as_mut_ptr().cast(),
            buffer.len(),
            &mut result,
        )
    };
    if status != 0 || result.is_null() {
        return Err(NativeError::Other);
    }
    // SAFETY: The successful lookup initialized entry and its NUL-terminated home.
    let entry = unsafe { entry.assume_init() };
    if entry.pw_uid != owner || entry.pw_dir.is_null() {
        return Err(NativeError::Other);
    }
    // SAFETY: pw_dir points to the successful lookup's live NUL-terminated buffer.
    let bytes = unsafe { std::ffi::CStr::from_ptr(entry.pw_dir) }.to_bytes();
    let path = PathBuf::from(std::ffi::OsStr::from_bytes(bytes));
    if !path.is_absolute() {
        return Err(NativeError::Other);
    }
    Ok(path)
}
