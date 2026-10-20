// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Live device-object DACL updates through an already validated volume handle.
use super::*;
use windows::Win32::Security::Authorization::SetSecurityInfo;
use windows::Win32::Storage::FileSystem::{
    FILE_ALL_ACCESS, FILE_GENERIC_EXECUTE, FILE_GENERIC_READ, FILE_GENERIC_WRITE,
};

/// Expands file-object generic ACE masks exactly as Windows does on a live volume.
/// Owner, group, ACE order, SIDs and non-generic permissions remain unchanged.
pub(super) fn canonical(desired: &str) -> Result<String, NativeError> {
    let text = wide_null(OsStr::new(desired));
    let mut descriptor = PSECURITY_DESCRIPTOR::default();
    // SAFETY: bounded journal text is NUL-terminated; LocalAlloc ownership is retained.
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
    // SAFETY: Windows constructed this owned descriptor and output pointers are valid.
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
    let mapping = GENERIC_MAPPING {
        GenericRead: FILE_GENERIC_READ.0,
        GenericWrite: FILE_GENERIC_WRITE.0,
        GenericExecute: FILE_GENERIC_EXECUTE.0,
        GenericAll: FILE_ALL_ACCESS.0,
    };
    // SAFETY: valid ACL belongs to our mutable LocalAlloc buffer. Only common
    // allow/deny ACE masks are changed; unknown ACE layouts fail closed.
    for index in 0..u32::from(unsafe { (*dacl).AceCount }) {
        let mut ace = std::ptr::null_mut();
        unsafe { GetAce(dacl, index, &mut ace) }.map_err(map_windows_error)?;
        let header = unsafe { &*ace.cast::<ACE_HEADER>() };
        if !matches!(header.AceType, 0 | 1)
            || usize::from(header.AceSize) < size_of::<ACCESS_ALLOWED_ACE>()
        {
            return Err(NativeError::EvidenceIncomplete);
        }
        unsafe { MapGenericMask(&mut (*ace.cast::<ACCESS_ALLOWED_ACE>()).Mask, &mapping) };
    }
    descriptor_text(PSECURITY_DESCRIPTOR(descriptor.0))
}

/// Adds the fixed service grant with masks matching live file-object readback.
pub(super) fn grant(previous: &str) -> Result<String, NativeError> {
    canonical(&grant_service(previous)?)
}

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

#[cfg(test)]
mod tests {
    use super::*;

    /// Kernel generic mapping must not turn a successful grant into a readback failure.
    #[test]
    fn live_volume_policy_maps_generic_masks_and_preserves_existing_permissions() {
        let generic = "O:BAG:SYD:(D;;GW;;;WD)(A;;GWGR;;;SY)(A;;FA;;;BA)";
        let expected = "O:BAG:SYD:(D;;FW;;;WD)(A;;0x12019f;;;SY)(A;;FA;;;BA)";
        let mapped = canonical(generic).unwrap();
        assert_eq!(mapped, canonical(expected).unwrap());
        assert_eq!(canonical(&mapped).unwrap(), mapped);
        assert!(canonical("O:BAG:SYD:NO_ACCESS_CONTROL").is_err());
    }
}
