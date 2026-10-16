// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Current Manager role proof bound to the fixed retained administrator enrollment.

use super::{RuntimeLease, open};
use crate::NativeError;
use crate::service_identity_access::{MANAGER_IMAGE, manager_identity_matches};
use std::fs::File;
use std::os::windows::ffi::OsStringExt;
use std::os::windows::io::AsRawHandle;
use std::path::Path;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::Storage::FileSystem::{BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle};
use windows::Win32::System::Threading::{
    GetCurrentProcess, PROCESS_NAME_WIN32, QueryFullProcessImageNameW,
};
use windows::core::PWSTR;

impl RuntimeLease {
    /// Rejects copies, hardlink aliases, Node and other runtime executables before a grant.
    ///
    /// Proves the current kernel path and separately pinned on-disk file generation;
    /// it does not assert historical identity of already mapped executable pages.
    pub(crate) fn verify_current_manager_process(&self) -> Result<(), NativeError> {
        let mut image = vec![0_u16; 32_768];
        let mut length = image.len() as u32;
        // SAFETY: only our process pseudohandle is queried into bounded writable storage.
        unsafe {
            QueryFullProcessImageNameW(
                GetCurrentProcess(),
                PROCESS_NAME_WIN32,
                PWSTR(image.as_mut_ptr()),
                &mut length,
            )
        }
        .map_err(|_| NativeError::AccessDenied)?;
        if length == 0 || length as usize >= image.len() {
            return Err(NativeError::AccessDenied);
        }
        image.truncate(length as usize);
        let current_path = std::env::current_exe().map_err(|_| NativeError::AccessDenied)?;
        let kernel_path = std::ffi::OsString::from_wide(&image);
        let expected = open(Path::new(MANAGER_IMAGE), false)?;
        let current = open(&current_path, false)?;
        let kernel = open(Path::new(&kernel_path), false)?;
        let expected = identity(&expected)?;
        let mut pinned = false;
        for file in &self._files {
            if identity(file)? == expected {
                pinned = true;
                break;
            }
        }
        if !manager_identity_matches(
            &image,
            identity(&current)?,
            identity(&kernel)?,
            expected,
            pinned,
        ) {
            return Err(NativeError::AccessDenied);
        }
        Ok(())
    }
}

/// Reads the stable volume/file-index identity from a retained no-follow file handle.
fn identity(file: &File) -> Result<[u32; 3], NativeError> {
    let mut information = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: File owns a live handle; information is exact initialized output storage.
    unsafe { GetFileInformationByHandle(HANDLE(file.as_raw_handle()), &mut information) }
        .map_err(|_| NativeError::AccessDenied)?;
    Ok([
        information.dwVolumeSerialNumber,
        information.nFileIndexHigh,
        information.nFileIndexLow,
    ])
}
