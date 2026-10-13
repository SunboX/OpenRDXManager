// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Kernel-only Manager token checks with closed policy denial diagnostics.
use super::*;

/// Derives and validates the exact active-console user SID from a pinned process.
pub(super) fn manager_sid(process: &OwnedHandle, process_id: u32) -> Result<OwnedSid, NativeError> {
    let mut token = HANDLE::default();
    // SAFETY: process is query-owned, TOKEN_QUERY is read-only, and output is writable.
    diagnostic(
        Stage::ManagerUserQuery,
        unsafe { OpenProcessToken(process.0, TOKEN_QUERY, &mut token) }.map_err(map_native_error),
    )?;
    let token = OwnedHandle(token);
    // Setup pins a live, unelevated Manager rather than granting the
    // administrator's installer token interactive service rights.
    let mut elevation = windows::Win32::Security::TOKEN_ELEVATION::default();
    let mut returned_elevation = 0;
    diagnostic(
        Stage::ManagerUserQuery,
        unsafe {
            GetTokenInformation(
                token.0,
                windows::Win32::Security::TokenElevation,
                Some((&mut elevation as *mut windows::Win32::Security::TOKEN_ELEVATION).cast()),
                size_of::<windows::Win32::Security::TOKEN_ELEVATION>() as u32,
                &mut returned_elevation,
            )
        }
        .map_err(map_native_error),
    )?;
    if returned_elevation as usize != size_of::<windows::Win32::Security::TOKEN_ELEVATION>()
        || elevation.TokenIsElevated != 0
    {
        return diagnostic(Stage::ManagerUserElevation, Err(NativeError::AccessDenied));
    }
    let mut token_session = u32::MAX;
    let mut returned = 0_u32;
    // SAFETY: output is exact writable u32 storage for TokenSessionId.
    diagnostic(
        Stage::ManagerUserQuery,
        unsafe {
            GetTokenInformation(
                token.0,
                TokenSessionId,
                Some((&mut token_session as *mut u32).cast()),
                size_of::<u32>() as u32,
                &mut returned,
            )
        }
        .map_err(map_native_error),
    )?;
    let mut process_session = u32::MAX;
    // SAFETY: output points to initialized writable scalar storage.
    diagnostic(
        Stage::ManagerUserQuery,
        unsafe { ProcessIdToSessionId(process_id, &mut process_session) }.map_err(map_native_error),
    )?;
    // SAFETY: this query has no pointer or ownership preconditions.
    if returned as usize != size_of::<u32>()
        || token_session != process_session
        || token_session != unsafe { WTSGetActiveConsoleSessionId() }
    {
        return diagnostic(Stage::ManagerUserSession, Err(NativeError::AccessDenied));
    }
    let sid = diagnostic(Stage::ManagerUserQuery, token_user_sid(&token))?;
    for forbidden in [
        WinLocalSystemSid,
        WinLocalServiceSid,
        WinNetworkServiceSid,
        WinBuiltinAdministratorsSid,
    ] {
        if sid.bytes() == well_known_sid(forbidden)?.bytes() {
            return diagnostic(Stage::ManagerUserPrincipal, Err(NativeError::AccessDenied));
        }
    }
    Ok(sid)
}

#[cfg(test)]
mod tests {
    use super::*;
    /// Checks the real elevated creator's denial without enrolling any user or changing service policy.
    #[test]
    #[ignore = "requires elevated process on a disposable Windows verifier"]
    fn native_manager_token_rejects_elevated_creator() {
        let pid = std::process::id();
        let process = open_manager_process(pid).unwrap();
        assert!(matches!(
            manager_sid(&process, pid),
            Err(NativeError::AccessDenied)
        ));
    }
}
