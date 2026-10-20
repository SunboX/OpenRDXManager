// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Live device-object DACL updates through an already validated volume handle.
use super::*;
use windows::Win32::Security::Authorization::SetSecurityInfo;

/// Changes only a live DACL after exact readback comparison, preserving owner/group.
pub(super) fn replace(handle: HANDLE, expected: &str, desired: &str) -> Result<(), NativeError> {
    if current_device_policy(handle)? != expected {
        return Err(NativeError::AccessDenied);
    }
    let text = wide_null(OsStr::new(desired));
    let mut descriptor = PSECURITY_DESCRIPTOR::default();
    // SAFETY: bounded journal text is NUL-terminated; allocation is owned below.
    unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            PCWSTR(text.as_ptr()),
            SDDL_REVISION_1,
            &mut descriptor,
            None,
        )
    }
    .map_err(map_windows_error)?;
    let descriptor = Allocation(descriptor.0);
    let mut present = false.into();
    let mut defaulted = false.into();
    let mut dacl = std::ptr::null_mut();
    // SAFETY: descriptor remains owned and all outputs are valid storage.
    unsafe {
        GetSecurityDescriptorDacl(
            PSECURITY_DESCRIPTOR(descriptor.0),
            &mut present,
            &mut dacl,
            &mut defaulted,
        )
    }
    .map_err(map_windows_error)?;
    if !present.as_bool() || dacl.is_null() || !unsafe { IsValidAcl(dacl).as_bool() } {
        return Err(NativeError::AccessDenied);
    }
    // SAFETY: this is the retained exact target volume device, opened WRITE_DAC;
    // no filesystem paths, file contents, owner, group or SACL are changed.
    unsafe {
        SetSecurityInfo(
            handle,
            SE_KERNEL_OBJECT,
            DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(dacl),
            None,
        )
    }
    .ok()
    .map_err(map_windows_error)?;
    if current_device_policy(handle)? != desired {
        return Err(NativeError::AccessDenied);
    }
    Ok(())
}
