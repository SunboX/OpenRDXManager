// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Enables one enrolled privilege only on an owned current-thread token.
use crate::NativeError;
use std::marker::PhantomData;
use std::rc::Rc;
use windows::Win32::Foundation::{CloseHandle, ERROR_NO_TOKEN, GetLastError, HANDLE};
use windows::Win32::Security::{
    AdjustTokenPrivileges, DuplicateTokenEx, LUID_AND_ATTRIBUTES, LookupPrivilegeValueW,
    RevertToSelf, SE_PRIVILEGE_ENABLED, SecurityImpersonation, TOKEN_ADJUST_PRIVILEGES,
    TOKEN_DUPLICATE, TOKEN_IMPERSONATE, TOKEN_PRIVILEGES, TOKEN_QUERY, TokenImpersonation,
};
use windows::Win32::System::Threading::{
    GetCurrentProcess, GetCurrentThread, OpenProcessToken, OpenThreadToken, SetThreadToken,
};
use windows::core::PCWSTR;

struct Token(HANDLE);
impl Drop for Token {
    /// Closes this owned token without affecting another thread's authority.
    fn drop(&mut self) {
        let _ = unsafe { CloseHandle(self.0) };
    }
}

/// Non-sendable scope whose lifetime bounds privilege enablement on this thread.
pub(crate) struct VolumePrivilege {
    _token: Token,
    _thread: PhantomData<Rc<()>>,
}

impl VolumePrivilege {
    /// Copies only our primary identity and enables only the fixed enrolled right.
    /// Unexpected impersonation or a missing right fails before any device mutation.
    pub(crate) fn acquire() -> Result<Self, NativeError> {
        let mut thread_token = HANDLE::default();
        // A foreign client token must never flow into a hardware operation. Nested
        // privilege scopes are intentionally refused, rather than discarding one.
        match unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, true, &mut thread_token) } {
            Ok(()) => {
                drop(Token(thread_token));
                return Err(NativeError::AccessDenied);
            }
            Err(error) if error.code().0 as u32 == 0x8007_0000 | ERROR_NO_TOKEN.0 => {}
            Err(_) => return Err(NativeError::AccessDenied),
        }
        let mut primary = HANDLE::default();
        unsafe {
            OpenProcessToken(
                GetCurrentProcess(),
                TOKEN_DUPLICATE | TOKEN_QUERY,
                &mut primary,
            )
        }
        .map_err(|_| NativeError::AccessDenied)?;
        let primary = Token(primary);
        let mut copied = HANDLE::default();
        unsafe {
            DuplicateTokenEx(
                primary.0,
                TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES | TOKEN_IMPERSONATE,
                None,
                SecurityImpersonation,
                TokenImpersonation,
                &mut copied,
            )
        }
        .map_err(|_| NativeError::AccessDenied)?;
        let copied = Token(copied);
        let name: Vec<u16> = super::RIGHT.encode_utf16().chain([0]).collect();
        let mut entry = LUID_AND_ATTRIBUTES {
            Attributes: SE_PRIVILEGE_ENABLED,
            ..Default::default()
        };
        unsafe { LookupPrivilegeValueW(PCWSTR::null(), PCWSTR(name.as_ptr()), &mut entry.Luid) }
            .map_err(|_| NativeError::AccessDenied)?;
        let privileges = TOKEN_PRIVILEGES {
            PrivilegeCount: 1,
            Privileges: [entry],
        };
        unsafe { AdjustTokenPrivileges(copied.0, false, Some(&privileges), 0, None, None) }
            .map_err(|_| NativeError::AccessDenied)?;
        // AdjustTokenPrivileges can succeed while reporting NOT_ALL_ASSIGNED.
        if unsafe { GetLastError() }.0 != 0 {
            return Err(NativeError::AccessDenied);
        }
        unsafe { SetThreadToken(None, Some(copied.0)) }.map_err(|_| NativeError::AccessDenied)?;
        Ok(Self {
            _token: copied,
            _thread: PhantomData,
        })
    }
}

impl Drop for VolumePrivilege {
    /// Restores no-impersonation authority; failure cannot safely continue the service.
    fn drop(&mut self) {
        if unsafe { RevertToSelf() }.is_err() {
            std::process::abort();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A pre-existing thread identity is refused and remains owned by its caller.
    #[test]
    fn volume_privilege_scope_preserves_an_existing_thread_token() {
        let mut primary = HANDLE::default();
        unsafe {
            OpenProcessToken(
                GetCurrentProcess(),
                TOKEN_DUPLICATE | TOKEN_QUERY,
                &mut primary,
            )
        }
        .unwrap();
        let primary = Token(primary);
        let mut copied = HANDLE::default();
        unsafe {
            DuplicateTokenEx(
                primary.0,
                TOKEN_QUERY | TOKEN_IMPERSONATE,
                None,
                SecurityImpersonation,
                TokenImpersonation,
                &mut copied,
            )
        }
        .unwrap();
        let copied = Token(copied);
        unsafe { SetThreadToken(None, Some(copied.0)) }.unwrap();
        let denied = matches!(VolumePrivilege::acquire(), Err(NativeError::AccessDenied));
        let mut observed = HANDLE::default();
        let retained =
            unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, true, &mut observed) };
        // Always revert before assertions so a failed regression cannot leak identity.
        unsafe { RevertToSelf() }.unwrap();
        if retained.is_ok() {
            drop(Token(observed));
        }
        assert!(denied);
        assert!(retained.is_ok());
    }

    /// Both denied acquisition and successful scope exit leave the thread unprivileged.
    #[test]
    fn volume_privilege_scope_does_not_leak_a_thread_token() {
        let scope = VolumePrivilege::acquire();
        if let Ok(scope) = scope {
            assert!(matches!(
                VolumePrivilege::acquire(),
                Err(NativeError::AccessDenied)
            ));
            drop(scope);
        }
        let mut token = HANDLE::default();
        let error = unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, true, &mut token) }
            .expect_err("no retained impersonation token");
        assert_eq!(error.code().0 as u32, 0x8007_0000 | ERROR_NO_TOKEN.0);
    }
}
