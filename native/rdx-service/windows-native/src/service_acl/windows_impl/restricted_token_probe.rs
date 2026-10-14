// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Opt-in, never-launched token-reduction observations on a disposable verifier.
//! Successful queries do not prove a derived token is eligible for Manager launch.
mod medium;
use super::*;
use std::mem::offset_of;
use windows::Win32::Foundation::LUID;
use windows::Win32::Security::{
    CreateRestrictedToken, DISABLE_MAX_PRIVILEGE, LUA_TOKEN, LUID_AND_ATTRIBUTES,
    LookupPrivilegeValueW, SE_CHANGE_NOTIFY_NAME, SE_PRIVILEGE_ENABLED, SID_AND_ATTRIBUTES,
    TOKEN_DUPLICATE, TOKEN_ELEVATION, TOKEN_GROUPS, TOKEN_INFORMATION_CLASS, TOKEN_MANDATORY_LABEL,
    TOKEN_PRIVILEGES, TokenElevation, TokenGroups, TokenIntegrityLevel, TokenPrivileges,
};
use windows::Win32::System::Threading::GetCurrentProcess;

/// Caps kernel-owned variable queries; no raw token contents are logged.
const MAX_PROBE_BYTES: usize = 65_536;
/// Documented group flags, avoiding a new production Windows feature dependency.
const GROUP_ENABLED: u32 = 0x4;
const GROUP_DENY_ONLY: u32 = 0x10;

/// One aligned, bounded kernel response, retaining its actual returned length.
struct TokenBuffer {
    storage: Vec<usize>,
    length: usize,
}
impl TokenBuffer {
    /// Queries one variable-length token class without modifying either token.
    fn read(token: &OwnedHandle, class: TOKEN_INFORMATION_CLASS) -> Result<Self, NativeError> {
        let mut needed = 0;
        // SAFETY: documented sizing query has no output buffer.
        let sizing = unsafe { GetTokenInformation(token.0, class, None, 0, &mut needed) };
        if !is_error(&sizing, ERROR_INSUFFICIENT_BUFFER)
            || !(size_of::<u32>()..=MAX_PROBE_BYTES).contains(&(needed as usize))
        {
            return Err(NativeError::Other);
        }
        let mut storage = vec![0_usize; (needed as usize).div_ceil(size_of::<usize>())];
        let capacity = storage.len() * size_of::<usize>();
        // SAFETY: aligned live storage is writable for the declared bounded capacity.
        unsafe {
            GetTokenInformation(
                token.0,
                class,
                Some(storage.as_mut_ptr().cast()),
                capacity as u32,
                &mut needed,
            )
        }
        .map_err(map_native_error)?;
        if !(size_of::<u32>()..=capacity).contains(&(needed as usize)) {
            return Err(NativeError::Other);
        }
        Ok(Self {
            storage,
            length: needed as usize,
        })
    }

    /// Reads only an initialized fixed header within the actual response.
    fn header<T: Copy>(&self) -> Result<T, NativeError> {
        if size_of::<T>() > self.length {
            return Err(NativeError::Other);
        }
        // SAFETY: size checked and read_unaligned imposes no stronger alignment.
        Ok(unsafe { self.storage.as_ptr().cast::<T>().read_unaligned() })
    }

    /// Copies a bounded flexible-array table, rejecting count/size overflow first.
    fn entries<T: Copy>(&self, offset: usize, count: u32) -> Result<Vec<T>, NativeError> {
        let end = (count as usize)
            .checked_mul(size_of::<T>())
            .and_then(|size| offset.checked_add(size));
        if end.is_none_or(|end| end > self.length) {
            return Err(NativeError::Other);
        }
        let mut entries = Vec::with_capacity(count as usize);
        for index in 0..count as usize {
            // SAFETY: checked total table bounds and unaligned copied reads preserve ownership.
            entries.push(unsafe {
                self.storage
                    .as_ptr()
                    .cast::<u8>()
                    .add(offset + index * size_of::<T>())
                    .cast::<T>()
                    .read_unaligned()
            });
        }
        Ok(entries)
    }

    /// Copies one embedded SID only after the existing strict allocation bounds checks.
    fn sid(&self, sid: PSID) -> Result<OwnedSid, NativeError> {
        copy_bounded_sid(sid, self.storage.as_ptr() as usize, self.length)
    }
}

/// Reads an exact-sized scalar; mismatched sizes fail without logging its value.
fn scalar(token: &OwnedHandle, class: TOKEN_INFORMATION_CLASS) -> Result<u32, NativeError> {
    let mut value = 0_u32;
    let mut returned = 0;
    // SAFETY: output is initialized writable scalar storage of the declared exact size.
    unsafe {
        GetTokenInformation(
            token.0,
            class,
            Some((&mut value as *mut u32).cast()),
            size_of::<u32>() as u32,
            &mut returned,
        )
    }
    .map_err(map_native_error)?;
    if returned as usize != size_of::<u32>() {
        return Err(NativeError::Other);
    }
    Ok(value)
}

/// Copies bounded token privilege entries without exposing privilege identifiers.
fn privileges(token: &OwnedHandle) -> Result<Vec<LUID_AND_ATTRIBUTES>, NativeError> {
    let buffer = TokenBuffer::read(token, TokenPrivileges)?;
    let count = buffer.header::<u32>()?;
    buffer.entries(offset_of!(TOKEN_PRIVILEGES, Privileges), count)
}

/// Reports builtin/domain administrative role groups; arbitrary custom groups are not classified.
fn administrative_groups(token: &OwnedHandle) -> Result<(bool, bool), NativeError> {
    use windows::Win32::Security::{
        IsWellKnownSid, WinAccountDomainAdminsSid, WinAccountEnterpriseAdminsSid,
        WinAccountSchemaAdminsSid, WinBuiltinAccountOperatorsSid, WinBuiltinBackupOperatorsSid,
        WinBuiltinPrintOperatorsSid, WinBuiltinSystemOperatorsSid,
    };
    let buffer = TokenBuffer::read(token, TokenGroups)?;
    let groups = buffer
        .entries::<SID_AND_ATTRIBUTES>(offset_of!(TOKEN_GROUPS, Groups), buffer.header::<u32>()?)?;
    let mut builtin_deny_only = false;
    let mut no_enabled_admins = true;
    for group in groups {
        let sid = buffer.sid(group.Sid)?;
        // SAFETY: SID is an owned validated copy for these read-only classifiers.
        let builtin =
            unsafe { IsWellKnownSid(sid.pointer(), WinBuiltinAdministratorsSid).as_bool() };
        if builtin {
            builtin_deny_only =
                group.Attributes & GROUP_DENY_ONLY != 0 && group.Attributes & GROUP_ENABLED == 0;
        }
        for role in [
            WinBuiltinAdministratorsSid,
            WinAccountDomainAdminsSid,
            WinAccountEnterpriseAdminsSid,
            WinAccountSchemaAdminsSid,
            WinBuiltinAccountOperatorsSid,
            WinBuiltinBackupOperatorsSid,
            WinBuiltinPrintOperatorsSid,
            WinBuiltinSystemOperatorsSid,
        ] {
            // SAFETY: owned SID remains live throughout synchronous classification.
            if unsafe { IsWellKnownSid(sid.pointer(), role).as_bool() }
                && group.Attributes & GROUP_ENABLED != 0
            {
                no_enabled_admins = false;
            }
        }
    }
    Ok((builtin_deny_only, no_enabled_admins))
}

/// Reads the validated mandatory-label RID internally; only fixed comparisons are emitted.
fn integrity(token: &OwnedHandle) -> Result<u32, NativeError> {
    let buffer = TokenBuffer::read(token, TokenIntegrityLevel)?;
    let label = buffer.header::<TOKEN_MANDATORY_LABEL>()?;
    let sid = buffer.sid(label.Label.Sid)?;
    let bytes = sid.bytes();
    // Mandatory integrity SIDs are S-1-16 with exactly one subauthority.
    if bytes.len() != 12 || bytes[0] != 1 || bytes[1] != 1 || bytes[2..8] != [0, 0, 0, 0, 0, 16] {
        return Err(NativeError::Other);
    }
    Ok(u32::from_le_bytes(
        bytes[8..12].try_into().map_err(|_| NativeError::Other)?,
    ))
}

/// Compares privilege identities internally, never printing their numeric values.
fn same_privilege(left: &LUID, right: &LUID) -> bool {
    left.LowPart == right.LowPart && left.HighPart == right.HighPart
}

/// Creates one derived token and queries it; neither handle is used to launch or impersonate.
fn observe_reduction() -> Result<(), NativeError> {
    let mut handle = HANDLE::default();
    // SAFETY: current-process pseudo handle is borrowed; only token query/duplicate access is requested.
    unsafe {
        OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_QUERY | TOKEN_DUPLICATE,
            &mut handle,
        )
    }
    .map_err(map_native_error)?;
    let source = OwnedHandle(handle);
    println!("openrdx-token-probe source-open=true");
    let mut handle = HANDLE::default();
    // Microsoft specifies LUA_TOKEN and DISABLE_MAX_PRIVILEGE; this does not promise medium integrity.
    // https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-createrestrictedtoken
    // SAFETY: source is owned; no caller SID/privilege tables or restricting identities are supplied.
    unsafe {
        CreateRestrictedToken(
            source.0,
            LUA_TOKEN | DISABLE_MAX_PRIVILEGE,
            None,
            None,
            None,
            &mut handle,
        )
    }
    .map_err(map_native_error)?;
    let derived = OwnedHandle(handle);
    println!("openrdx-token-probe derived-created=true");
    // Both handles are guarded before any subsequent fallible query or assertion.
    let same_user = token_user_sid(&source)?.bytes() == token_user_sid(&derived)?.bytes();
    let source_session = scalar(&source, TokenSessionId)?;
    let derived_session = scalar(&derived, TokenSessionId)?;
    let source_elevated = scalar(&source, TokenElevation)? != 0;
    let derived_elevated = scalar(&derived, TokenElevation)? != 0;
    let (source_admin_deny_only, source_no_enabled_admins) = administrative_groups(&source)?;
    let (admin_deny_only, no_enabled_admins) = administrative_groups(&derived)?;
    let source_privileges = privileges(&source)?;
    let derived_privileges = privileges(&derived)?;
    let mut change_notify = LUID::default();
    // SAFETY: fixed documented name and writable LUID; no token privilege adjustment occurs.
    unsafe { LookupPrivilegeValueW(None, SE_CHANGE_NOTIFY_NAME, &mut change_notify) }
        .map_err(map_native_error)?;
    let enabled_whitelist = derived_privileges.iter().all(|entry| {
        entry.Attributes & SE_PRIVILEGE_ENABLED == Default::default()
            || same_privilege(&entry.Luid, &change_notify)
    });
    let present_whitelist = derived_privileges
        .iter()
        .all(|entry| same_privilege(&entry.Luid, &change_notify));
    let privileges_reduced = derived_privileges.len() < source_privileges.len();
    let no_added_privileges = derived_privileges.iter().all(|entry| {
        source_privileges
            .iter()
            .any(|source_entry| same_privilege(&entry.Luid, &source_entry.Luid))
    });
    let source_integrity = integrity(&source)?;
    let derived_integrity = integrity(&derived)?;
    // No SID/session/RID/privilege identifier or candidate eligibility is output.
    println!(
        "openrdx-token-probe query-ok=true same-user={same_user} same-session={} source-active-console={} derived-active-console={} source-elevated={source_elevated} derived-elevated={derived_elevated}",
        source_session == derived_session,
        source_session == unsafe { WTSGetActiveConsoleSessionId() },
        derived_session == unsafe { WTSGetActiveConsoleSessionId() }
    );
    println!(
        "openrdx-token-probe source-admin-deny-only={source_admin_deny_only} source-no-enabled-admins={source_no_enabled_admins} admin-deny-only={admin_deny_only} no-enabled-admins={no_enabled_admins} enabled-privilege-whitelist={enabled_whitelist} present-privilege-whitelist={present_whitelist} privileges-reduced={privileges_reduced} no-added-privileges={no_added_privileges}"
    );
    println!(
        "openrdx-token-probe source-integrity-low={} source-integrity-medium={} source-integrity-high={} source-integrity-system={} integrity-low={} integrity-medium={} integrity-high={} integrity-system={} integrity-reduced={}",
        source_integrity == 0x1000,
        source_integrity == 0x2000,
        source_integrity == 0x3000,
        source_integrity == 0x4000,
        derived_integrity == 0x1000,
        derived_integrity == 0x2000,
        derived_integrity == 0x3000,
        derived_integrity == 0x4000,
        derived_integrity < source_integrity
    );
    // Assertions compare booleans only; failure never Debug-prints token identity material.
    assert!(same_user, "derived-token-user-mismatch");
    assert!(
        source_session == derived_session,
        "derived-token-session-mismatch"
    );
    Ok(())
}

/// Opt-in experiment: ineligible kernel facts remain observations, never a security-fix claim.
#[test]
#[ignore = "requires administrator on a disposable Windows verifier"]
fn native_restricted_token_observations() {
    assert!(
        size_of::<TOKEN_ELEVATION>() == size_of::<u32>(),
        "elevation-layout-mismatch"
    );
    let observed = observe_reduction();
    if observed.is_err() {
        println!("openrdx-token-probe query-ok=false");
    }
    assert!(observed.is_ok(), "restricted-token-query-failed");
}

/// Malformed count/length fixtures cannot permit out-of-bounds native table reads.
#[test]
fn token_table_bounds_reject_overflow_and_truncation() {
    let buffer = TokenBuffer {
        storage: vec![0; 2],
        length: 4,
    };
    assert!(buffer.entries::<SID_AND_ATTRIBUTES>(8, u32::MAX).is_err());
    assert!(buffer.entries::<SID_AND_ATTRIBUTES>(8, 1).is_err());
    assert!(buffer.header::<TOKEN_MANDATORY_LABEL>().is_err());
    assert!(buffer.entries::<u32>(4, 0).is_ok());
}
