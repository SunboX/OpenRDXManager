// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Current-process and current-primary-token DACL adapter; no caller-selected objects.

use super::{CurrentObjects, Descriptor, NativeError, Object, grant_query_access};
use windows::Win32::Foundation::{CloseHandle, HANDLE, HLOCAL, LocalFree};
use windows::Win32::Security::Authorization::{GetSecurityInfo, SE_KERNEL_OBJECT, SetSecurityInfo};
use windows::Win32::Security::{
    ACL, DACL_SECURITY_INFORMATION, GROUP_SECURITY_INFORMATION, GetSecurityDescriptorLength,
    IsValidAcl, IsValidSecurityDescriptor, LABEL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION,
    PSECURITY_DESCRIPTOR, TOKEN_QUERY, TOKEN_READ_CONTROL, TOKEN_WRITE_DAC,
};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

pub(super) mod manager;

/// Owns only this process's primary token. The process pseudohandle is never closed.
struct OwnObjects {
    token: Option<HANDLE>,
}

impl OwnObjects {
    /// Opens the current primary token with query/security rights, without privilege changes.
    fn open() -> Result<Self, NativeError> {
        let mut token = HANDLE::default();
        // SAFETY: GetCurrentProcess identifies only our process; token is initialized
        // output storage and the returned handle is immediately RAII-owned.
        unsafe {
            OpenProcessToken(
                GetCurrentProcess(),
                TOKEN_QUERY | TOKEN_READ_CONTROL | TOKEN_WRITE_DAC,
                &mut token,
            )
        }
        .map_err(|_| NativeError::AccessDenied)?;
        Ok(Self { token: Some(token) })
    }

    /// Creates a process-only adapter; the Manager never opens a token for mutation.
    fn process_only() -> Self {
        Self { token: None }
    }

    /// Selects only the current pseudohandle or this adapter's retained primary token.
    fn handle(&self, object: Object) -> Result<HANDLE, NativeError> {
        match object {
            // SAFETY: the pseudohandle has no pointer or ownership preconditions.
            Object::Process => Ok(unsafe { GetCurrentProcess() }),
            Object::PrimaryToken => self.token.ok_or(NativeError::AccessDenied),
        }
    }
}

impl Drop for OwnObjects {
    /// Closes the sole owned token handle on every success/failure path.
    fn drop(&mut self) {
        // SAFETY: this non-invalid token handle is owned exactly once.
        if let Some(token) = self.token {
            let _ = unsafe { CloseHandle(token) };
        }
    }
}

/// Owns exactly one LocalAlloc-backed security descriptor from GetSecurityInfo.
struct Allocation(PSECURITY_DESCRIPTOR);

impl Drop for Allocation {
    /// Frees the Windows-owned descriptor after every bounded read or validation failure.
    fn drop(&mut self) {
        // SAFETY: GetSecurityInfo returned this allocation; no other owner frees it.
        let _ = unsafe { LocalFree(Some(HLOCAL(self.0.0))) };
    }
}

impl CurrentObjects for OwnObjects {
    /// Reads owner/group/control/DACL and mandatory label without requesting SACL privilege.
    fn read(&self, object: Object) -> Result<Descriptor, NativeError> {
        let mut descriptor = PSECURITY_DESCRIPTOR::default();
        // SAFETY: handle is our live object, output storage is initialized. LABEL
        // retrieves the mandatory label with READ_CONTROL; audit SACLs are not queried.
        unsafe {
            GetSecurityInfo(
                self.handle(object)?,
                SE_KERNEL_OBJECT,
                OWNER_SECURITY_INFORMATION
                    | GROUP_SECURITY_INFORMATION
                    | DACL_SECURITY_INFORMATION
                    | LABEL_SECURITY_INFORMATION,
                None,
                None,
                None,
                None,
                Some(&mut descriptor),
            )
        }
        .ok()
        .map_err(|_| NativeError::AccessDenied)?;
        let allocation = Allocation(descriptor);
        if allocation.0.0.is_null()
            // SAFETY: this complete allocation was returned by GetSecurityInfo.
            || !unsafe { IsValidSecurityDescriptor(allocation.0).as_bool() }
        {
            return Err(NativeError::AccessDenied);
        }
        // SAFETY: the descriptor was just checked by the system validator.
        let length = unsafe { GetSecurityDescriptorLength(allocation.0) } as usize;
        if !(20..=65_536).contains(&length) {
            return Err(NativeError::ResourceLimit);
        }
        // SAFETY: Windows owns a complete descriptor of this validated bounded length;
        // the allocation remains live throughout the pointer-free parser call.
        let bytes = unsafe { std::slice::from_raw_parts(allocation.0.0.cast::<u8>(), length) };
        Descriptor::parse(bytes)
    }

    /// Writes only DACL_SECURITY_INFORMATION, preserving owner/group/protection and MIC.
    fn set_dacl(&self, object: Object, descriptor: &Descriptor) -> Result<(), NativeError> {
        let bytes = descriptor.dacl();
        // ACL needs DWORD alignment even though its validated representation is bytes.
        let mut storage = vec![0_usize; bytes.len().div_ceil(std::mem::size_of::<usize>())];
        // SAFETY: storage is aligned and its byte capacity covers bytes.len().
        unsafe {
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), storage.as_mut_ptr().cast(), bytes.len())
        };
        let dacl = storage.as_ptr().cast::<ACL>();
        // SAFETY: the complete aligned ACL remains retained through both synchronous calls.
        if !unsafe { IsValidAcl(dacl).as_bool() } {
            return Err(NativeError::AccessDenied);
        }
        // No protected/unprotected, owner, group, label, or TokenDefaultDacl setter
        // is requested. Exact readback rejects any unexpected kernel transformation.
        unsafe {
            SetSecurityInfo(
                self.handle(object)?,
                SE_KERNEL_OBJECT,
                DACL_SECURITY_INFORMATION,
                None,
                None,
                Some(dacl),
                None,
            )
        }
        .ok()
        .map_err(|_| NativeError::AccessDenied)
    }
}

/// Grants the fixed metadata-query contract only after the private SCM startup proof.
///
/// No PID, path, SID, mask, raw handle, or privilege choice crosses this boundary.
/// Failure leaves START_PENDING unadmitted; the SCM callback retires this generation.
pub(crate) fn prepare_current_service_identity_queries() -> Result<(), NativeError> {
    grant_query_access(&OwnObjects::open()?)
}

#[cfg(test)]
mod tests;
