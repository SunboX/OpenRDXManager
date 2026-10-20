// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! LSA access accepts neither caller-selected identities nor privilege names.
use crate::NativeError;
use std::mem::size_of;
use windows::Win32::Foundation::{NTSTATUS, STATUS_OBJECT_NAME_NOT_FOUND};
use windows::Win32::Security::Authentication::Identity::{
    LSA_HANDLE, LSA_OBJECT_ATTRIBUTES, LSA_UNICODE_STRING, LsaAddAccountRights, LsaClose,
    LsaEnumerateAccountRights, LsaFreeMemory, LsaOpenPolicy, LsaRemoveAccountRights,
    POLICY_CREATE_ACCOUNT, POLICY_LOOKUP_NAMES,
};
use windows::Win32::Security::{GetLengthSid, IsValidSid, LookupAccountNameW, PSID, SID_NAME_USE};
use windows::core::{PCWSTR, PWSTR};

struct Policy(LSA_HANDLE);
impl Drop for Policy {
    /// Releases the owned local policy handle on every return path.
    fn drop(&mut self) {
        let _ = unsafe { LsaClose(self.0) };
    }
}
struct Rights(*mut LSA_UNICODE_STRING);
impl Drop for Rights {
    /// Releases only the bounded LSA-owned enumeration allocation.
    fn drop(&mut self) {
        if !self.0.is_null() {
            let _ = unsafe { LsaFreeMemory(Some(self.0.cast())) };
        }
    }
}

/// Sanitizes LSA status without exposing account or policy contents.
fn checked(status: NTSTATUS) -> Result<(), NativeError> {
    if status.0 == 0 {
        Ok(())
    } else {
        Err(NativeError::AccessDenied)
    }
}

/// Opens local LSA policy for fixed-account lookup and, only when needed, enrollment.
fn open(write: bool) -> Result<Policy, NativeError> {
    let attributes = LSA_OBJECT_ATTRIBUTES {
        Length: size_of::<LSA_OBJECT_ATTRIBUTES>() as u32,
        ..Default::default()
    };
    let mut handle = LSA_HANDLE::default();
    let access = POLICY_LOOKUP_NAMES | if write { POLICY_CREATE_ACCOUNT } else { 0 };
    // SAFETY: fixed local system, initialized attributes and owned output handle.
    checked(unsafe { LsaOpenPolicy(None, &attributes, access as u32, &mut handle) })?;
    Ok(Policy(handle))
}

/// Resolves only the compiled service identity; LocalService is never a grant target.
fn service_sid() -> Result<[u32; 17], NativeError> {
    let name: Vec<u16> = "NT SERVICE\\OpenRDXHardwareService"
        .encode_utf16()
        .chain([0])
        .collect();
    let mut sid = [0_u32; 17];
    let mut length = size_of::<[u32; 17]>() as u32;
    let mut domain = [0_u16; 256];
    let mut domain_length = domain.len() as u32;
    let mut usage = SID_NAME_USE::default();
    // SAFETY: fixed local name and bounded aligned output buffers.
    unsafe {
        LookupAccountNameW(
            PCWSTR::null(),
            PCWSTR(name.as_ptr()),
            Some(PSID(sid.as_mut_ptr().cast())),
            &mut length,
            Some(PWSTR(domain.as_mut_ptr())),
            &mut domain_length,
            &mut usage,
        )
    }
    .map_err(|_| NativeError::AccessDenied)?;
    let pointer = PSID(sid.as_mut_ptr().cast());
    // SAFETY: successful lookup filled the bounded aligned SID allocation.
    if !(32..=68).contains(&length)
        || domain_length >= 256
        || !unsafe { IsValidSid(pointer).as_bool() }
        || unsafe { GetLengthSid(pointer) } != 32
    {
        return Err(NativeError::AccessDenied);
    }
    let bytes = unsafe { std::slice::from_raw_parts(sid.as_ptr().cast::<u8>(), 12) };
    if bytes != [1, 6, 0, 0, 0, 0, 0, 5, 80, 0, 0, 0] {
        return Err(NativeError::AccessDenied);
    }
    Ok(sid)
}

/// Reads whether the fixed service SID already owns the one volume-maintenance right.
pub(crate) fn has_service_right() -> Result<bool, NativeError> {
    let policy = open(false)?;
    let mut sid = service_sid()?;
    let mut pointer = std::ptr::null_mut();
    let mut count = 0;
    // SAFETY: fixed validated SID and initialized LSA-owned output allocation.
    let status = unsafe {
        LsaEnumerateAccountRights(
            policy.0,
            PSID(sid.as_mut_ptr().cast()),
            &mut pointer,
            &mut count,
        )
    };
    let rights = Rights(pointer);
    if status == STATUS_OBJECT_NAME_NOT_FOUND {
        return Ok(false);
    }
    checked(status)?;
    if count > 256 || (count > 0 && pointer.is_null()) {
        return Err(NativeError::EvidenceIncomplete);
    }
    if count == 0 {
        return Ok(false);
    }
    // SAFETY: successful LSA enumeration owns count entries until Rights drops.
    for right in unsafe { std::slice::from_raw_parts(rights.0, count as usize) } {
        if right.Length % 2 != 0
            || right.Length > right.MaximumLength
            || right.Length > 1024
            || right.Buffer.is_null()
        {
            return Err(NativeError::EvidenceIncomplete);
        }
        let name =
            unsafe { std::slice::from_raw_parts(right.Buffer.0, usize::from(right.Length / 2)) };
        if name.iter().copied().eq(super::RIGHT.encode_utf16()) {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Changes exactly one right on the fixed service SID, preserving all other policy.
/// The caller must durably journal the prior presence before calling with true.
pub(crate) fn set_service_right(present: bool) -> Result<(), NativeError> {
    let policy = open(true)?;
    let mut sid = service_sid()?;
    let mut name: Vec<u16> = super::RIGHT.encode_utf16().chain([0]).collect();
    let right = LSA_UNICODE_STRING {
        Length: ((name.len() - 1) * 2) as u16,
        MaximumLength: (name.len() * 2) as u16,
        Buffer: PWSTR(name.as_mut_ptr()),
    };
    // SAFETY: all buffers remain live; false never requests removal of all rights.
    checked(unsafe {
        if present {
            LsaAddAccountRights(policy.0, PSID(sid.as_mut_ptr().cast()), &[right])
        } else {
            LsaRemoveAccountRights(
                policy.0,
                PSID(sid.as_mut_ptr().cast()),
                false,
                Some(&[right]),
            )
        }
    })?;
    if has_service_right()? != present {
        return Err(NativeError::AccessDenied);
    }
    Ok(())
}
