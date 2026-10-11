// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Exact protected descriptor checks; existing unsafe ACLs are never repaired.

use crate::NativeError;
use std::mem::size_of;
use windows::Win32::Foundation::{HANDLE, HLOCAL, LocalFree};
use windows::Win32::Security::Authorization::{
    ConvertSecurityDescriptorToStringSecurityDescriptorW,
    ConvertStringSecurityDescriptorToSecurityDescriptorW, GetSecurityInfo, SDDL_REVISION_1,
    SE_FILE_OBJECT,
};
use windows::Win32::Security::{
    DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
    SECURITY_ATTRIBUTES,
};
use windows::core::{PCWSTR, PWSTR};

/// Privileged service/admin store: no ordinary user, inherited or creator ACEs.
const STORAGE_SDDL: &str = "O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;LS)";

/// LocalAlloc owner used for Windows descriptors and descriptor text.
struct LocalAllocation(*mut std::ffi::c_void);

impl Drop for LocalAllocation {
    /// Releases the allocation supplied by the Windows security API.
    fn drop(&mut self) {
        // SAFETY: conversion/GetSecurityInfo returned this LocalAlloc allocation.
        let _ = unsafe { LocalFree(Some(HLOCAL(self.0))) };
    }
}

/// Retained private creation descriptor and its canonical verification form.
pub(super) struct Policy {
    descriptor: LocalAllocation,
    accepted: Vec<String>,
}

impl Policy {
    /// Constructs the sole production storage policy, not caller-selected SDDL.
    pub(super) fn production() -> Result<Self, NativeError> {
        let sid = Self::current_sid()?;
        // Service-created records must remain readable after a switch between
        // installed LocalService and elevated administration, without accepting
        // an ordinary user's ownership or broadening the exact protected DACL.
        let owner = match sid.as_str() {
            "S-1-5-19" => "LS",
            "S-1-5-18" => "SY",
            _ => "BA",
        };
        let mut policy = Self::from_sddl(&STORAGE_SDDL.replacen("O:BA", &format!("O:{owner}"), 1))?;
        policy.accepted.clear();
        for owner in ["BA", "SY", "LS"] {
            let descriptor =
                Self::from_sddl(&STORAGE_SDDL.replacen("O:BA", &format!("O:{owner}"), 1))?;
            policy.accepted.extend(descriptor.accepted);
        }
        Ok(policy)
    }

    /// Parses trusted policy text and obtains Windows' canonical representation.
    fn from_sddl(sddl: &str) -> Result<Self, NativeError> {
        let wide: Vec<u16> = sddl.encode_utf16().chain([0]).collect();
        let mut descriptor = PSECURITY_DESCRIPTOR::default();
        // SAFETY: terminated input and live output; ownership moves into RAII.
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                PCWSTR(wide.as_ptr()),
                SDDL_REVISION_1,
                &mut descriptor,
                None,
            )
        }
        .map_err(|_| NativeError::AccessDenied)?;
        let descriptor = LocalAllocation(descriptor.0);
        let canonical = descriptor_text(PSECURITY_DESCRIPTOR(descriptor.0))?;
        Ok(Self {
            descriptor,
            accepted: vec![canonical],
        })
    }

    /// Borrows this exact descriptor for one non-inheritable file creation.
    pub(super) fn attributes(&self) -> SECURITY_ATTRIBUTES {
        SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: self.descriptor.0,
            bInheritHandle: false.into(),
        }
    }

    /// Verifies owner and entire protected DACL through the already-open handle.
    pub(super) fn verify(&self, handle: HANDLE) -> Result<(), NativeError> {
        let mut descriptor = PSECURITY_DESCRIPTOR::default();
        // SAFETY: the borrowed handle stays live and the API allocates output.
        let result = unsafe {
            GetSecurityInfo(
                handle,
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                None,
                None,
                None,
                None,
                Some(&mut descriptor),
            )
        };
        result.ok().map_err(|_| NativeError::AccessDenied)?;
        let descriptor = LocalAllocation(descriptor.0);
        if !self
            .accepted
            .contains(&descriptor_text(PSECURITY_DESCRIPTOR(descriptor.0))?)
        {
            return Err(NativeError::AccessDenied);
        }
        Ok(())
    }

    /// Test-only private user store; production cannot supply an owner or SDDL.
    #[cfg(any(test, feature = "test-hooks"))]
    pub(super) fn current_user() -> Result<Self, NativeError> {
        let sid = Self::current_sid()?;
        Self::from_sddl(&format!("O:{sid}D:P(A;;FA;;;{sid})"))
    }

    /// Reads only this process's principal; no caller SID or impersonation is accepted.
    fn current_sid() -> Result<String, NativeError> {
        use windows::Win32::Security::Authorization::ConvertSidToStringSidW;
        use windows::Win32::Security::{GetTokenInformation, TOKEN_QUERY, TOKEN_USER, TokenUser};
        use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
        let mut token = HANDLE::default();
        // SAFETY: process pseudo-handle is valid and output is owned immediately.
        unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) }
            .map_err(|_| NativeError::AccessDenied)?;
        let token = super::OwnedHandle(token);
        let mut buffer = vec![0usize; 8192];
        let mut returned = 0;
        // SAFETY: pointer-aligned 64 KiB storage bounds the TOKEN_USER result.
        unsafe {
            GetTokenInformation(
                token.0,
                TokenUser,
                Some(buffer.as_mut_ptr().cast()),
                (buffer.len() * size_of::<usize>()) as u32,
                &mut returned,
            )
        }
        .map_err(|_| NativeError::AccessDenied)?;
        // SAFETY: successful token query supplies an aligned TOKEN_USER header.
        let user = unsafe { &*buffer.as_ptr().cast::<TOKEN_USER>() };
        let mut sid = PWSTR::null();
        // SAFETY: TOKEN_USER owns the live SID during conversion.
        unsafe { ConvertSidToStringSidW(user.User.Sid, &mut sid) }
            .map_err(|_| NativeError::AccessDenied)?;
        let text = LocalAllocation(sid.0.cast());
        // SAFETY: successful conversion returns terminated UTF-16.
        let sid =
            unsafe { PWSTR(text.0.cast()).to_string() }.map_err(|_| NativeError::AccessDenied)?;
        Ok(sid)
    }
}

/// Canonicalizes only owner and DACL, excluding paths, token data and SACLs.
fn descriptor_text(descriptor: PSECURITY_DESCRIPTOR) -> Result<String, NativeError> {
    let mut text = PWSTR::null();
    // SAFETY: descriptor is API-produced, output ownership is retained below.
    unsafe {
        ConvertSecurityDescriptorToStringSecurityDescriptorW(
            descriptor,
            SDDL_REVISION_1,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut text,
            None,
        )
    }
    .map_err(|_| NativeError::AccessDenied)?;
    let text = LocalAllocation(text.0.cast());
    // SAFETY: conversion returns a terminated UTF-16 LocalAlloc string.
    unsafe { PWSTR(text.0.cast()).to_string() }.map_err(|_| NativeError::AccessDenied)
}
