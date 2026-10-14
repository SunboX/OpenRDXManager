// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Medium-label token reduction and a separate opt-in owned-child verifier.
mod child;
use super::*;
use windows::Win32::Security::{
    LookupAccountNameW, SID_NAME_USE, SetTokenInformation, TOKEN_ADJUST_DEFAULT,
    TokenElevationType, TokenSandBoxInert, TokenType, TokenUIAccess, WinMediumLabelSid,
};
use windows::Win32::System::RemoteDesktop::{
    WTS_INFO_CLASS, WTSDomainName, WTSFreeMemory, WTSQuerySessionInformationW, WTSUserName,
};

/// Snapshot identity material stays private and never implements Debug.
#[derive(PartialEq)]
struct SourceSnapshot {
    user: Vec<u8>,
    session: u32,
    elevation: u32,
    integrity: u32,
    ui_access: u32,
    sandbox_inert: u32,
    token_type: u32,
    elevation_type: u32,
    groups: Vec<(Vec<u8>, u32)>,
    privileges: Vec<LUID_AND_ATTRIBUTES>,
}
impl SourceSnapshot {
    /// Copies all queried source properties to prove the original token is unchanged.
    fn read(source: &OwnedHandle) -> Result<Self, NativeError> {
        let buffer = TokenBuffer::read(source, TokenGroups)?;
        let groups = buffer
            .entries::<SID_AND_ATTRIBUTES>(
                offset_of!(TOKEN_GROUPS, Groups),
                buffer.header::<u32>()?,
            )?
            .iter()
            .map(|entry| Ok((buffer.sid(entry.Sid)?.bytes().to_vec(), entry.Attributes)))
            .collect::<Result<Vec<_>, NativeError>>()?;
        Ok(Self {
            user: token_user_sid(source)?.bytes().to_vec(),
            session: scalar(source, TokenSessionId)?,
            elevation: scalar(source, TokenElevation)?,
            integrity: integrity(source)?,
            ui_access: scalar(source, TokenUIAccess)?,
            sandbox_inert: scalar(source, TokenSandBoxInert)?,
            token_type: scalar(source, TokenType)?,
            elevation_type: scalar(source, TokenElevationType)?,
            groups,
            privileges: privileges(source)?,
        })
    }
}

/// Frees a WTS-owned string even when validation or UTF-16 conversion fails.
struct SessionText(PWSTR);
impl Drop for SessionText {
    /// Releases exactly this query's returned allocation.
    fn drop(&mut self) {
        // SAFETY: non-null pointer is exclusively owned from a successful WTS query.
        if !self.0.is_null() {
            unsafe { WTSFreeMemory(self.0.0.cast()) };
        }
    }
}

/// Reads one bounded local console property without logging account names.
fn console_text(session: u32, class: WTS_INFO_CLASS) -> Result<String, NativeError> {
    let mut pointer = PWSTR::null();
    let mut bytes = 0;
    // SAFETY: writable outputs receive one WTS allocation and its initialized length.
    unsafe { WTSQuerySessionInformationW(None, session, class, &mut pointer, &mut bytes) }
        .map_err(map_native_error)?;
    let owned = SessionText(pointer);
    if pointer.is_null() || !(2..=1024).contains(&bytes) || bytes % 2 != 0 {
        return Err(NativeError::Other);
    }
    // SAFETY: successful query reports bounded initialized UTF-16 storage.
    let units = unsafe { std::slice::from_raw_parts(pointer.0, bytes as usize / 2) };
    let end = units
        .iter()
        .position(|unit| *unit == 0)
        .filter(|end| *end > 0)
        .ok_or(NativeError::Other)?;
    let result = String::from_utf16(&units[..end]).map_err(|_| NativeError::Other);
    drop(owned);
    result
}

/// Resolves only Windows' active local console account to an internally owned SID.
fn console_sid(session: u32) -> Result<OwnedSid, NativeError> {
    let account = wide_null(OsStr::new(&format!(
        r"{}\{}",
        console_text(session, WTSDomainName)?,
        console_text(session, WTSUserName)?
    )));
    let mut sid_bytes = 0;
    let mut domain_units = 0;
    let mut kind = SID_NAME_USE::default();
    // SAFETY: documented sizing query uses fixed local system and kernel-provided account name.
    let sizing = unsafe {
        LookupAccountNameW(
            None,
            PCWSTR(account.as_ptr()),
            None,
            &mut sid_bytes,
            None,
            &mut domain_units,
            &mut kind,
        )
    };
    if !is_error(&sizing, ERROR_INSUFFICIENT_BUFFER)
        || !(8..=SECURITY_MAX_SID_SIZE).contains(&sid_bytes)
        || domain_units > 1024
    {
        return Err(NativeError::Other);
    }
    let mut sid = vec![0_usize; (sid_bytes as usize).div_ceil(size_of::<usize>())];
    let mut domain = vec![0_u16; domain_units as usize];
    let capacity = sid.len() * size_of::<usize>();
    sid_bytes = capacity as u32;
    // SAFETY: SID and domain buffers are writable for their bounded declared capacities.
    unsafe {
        LookupAccountNameW(
            None,
            PCWSTR(account.as_ptr()),
            Some(PSID(sid.as_mut_ptr().cast())),
            &mut sid_bytes,
            Some(PWSTR(domain.as_mut_ptr())),
            &mut domain_units,
            &mut kind,
        )
    }
    .map_err(map_native_error)?;
    if sid_bytes as usize > capacity || domain_units as usize > domain.len() || kind.0 != 1 {
        return Err(NativeError::Other);
    }
    copy_bounded_sid(
        PSID(sid.as_mut_ptr().cast()),
        sid.as_ptr() as usize,
        sid_bytes as usize,
    )
}

/// Sets only an owned derived token's mandatory label using contiguous bounded storage.
fn set_medium(derived: &OwnedHandle) -> Result<(), NativeError> {
    let medium = well_known_sid(WinMediumLabelSid)?;
    let length = size_of::<TOKEN_MANDATORY_LABEL>() + medium.bytes().len();
    if length > MAX_PROBE_BYTES {
        return Err(NativeError::ResourceLimit);
    }
    let mut storage = vec![0_usize; length.div_ceil(size_of::<usize>())];
    let start = storage.as_mut_ptr().cast::<u8>();
    // SAFETY: disjoint validated SID bytes fit the bounded aligned buffer after its fixed header.
    unsafe {
        std::ptr::copy_nonoverlapping(
            medium.bytes().as_ptr(),
            start.add(size_of::<TOKEN_MANDATORY_LABEL>()),
            medium.bytes().len(),
        )
    };
    let label = TOKEN_MANDATORY_LABEL {
        Label: SID_AND_ATTRIBUTES {
            // SAFETY: pointer addresses the just-copied valid medium SID in live owned storage.
            Sid: PSID(unsafe { start.add(size_of::<TOKEN_MANDATORY_LABEL>()).cast() }),
            Attributes: 0x20, // Documented SE_GROUP_INTEGRITY, no group privilege adjustment.
        },
    };
    // SAFETY: aligned storage contains writable space for the fixed header before the SID.
    unsafe { start.cast::<TOKEN_MANDATORY_LABEL>().write(label) };
    // SetTokenInformation changes only its supplied derived token; no source/session adjustment.
    // https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-settokeninformation
    // SAFETY: label and embedded SID are contiguous, initialized and live for the exact bounded length.
    unsafe { SetTokenInformation(derived.0, TokenIntegrityLevel, start.cast(), length as u32) }
        .map_err(map_native_error)
}

/// Measures actual post-reduction properties; success does not prove a launched process.
fn observe_medium() -> Result<(), NativeError> {
    let mut handle = HANDLE::default();
    // SAFETY: borrowed current-process handle; rights enable modifying only the later derived label.
    unsafe {
        OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ADJUST_DEFAULT,
            &mut handle,
        )
    }
    .map_err(map_native_error)?;
    let source = OwnedHandle(handle);
    let source_before = SourceSnapshot::read(&source)?;
    // SAFETY: no pointer preconditions; session/account are queried read-only.
    let console_session = unsafe { WTSGetActiveConsoleSessionId() };
    if console_session == u32::MAX {
        return Err(NativeError::AccessDenied);
    }
    let console_user = console_sid(console_session)?;
    let mut handle = HANDLE::default();
    // SAFETY: guarded source and no caller-provided tables; approved flags match raw baseline.
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
    set_medium(&derived)?;
    let source_after = SourceSnapshot::read(&source)?;
    let observed = SourceSnapshot::read(&derived)?;
    let (admin_deny_only, no_enabled_admins) = administrative_groups(&derived)?;
    let mut change_notify = LUID::default();
    // SAFETY: read-only fixed privilege lookup, no enablement or token privilege adjustment.
    unsafe { LookupPrivilegeValueW(None, SE_CHANGE_NOTIFY_NAME, &mut change_notify) }
        .map_err(map_native_error)?;
    let present_whitelist = observed
        .privileges
        .iter()
        .all(|entry| same_privilege(&entry.Luid, &change_notify));
    let enabled_whitelist = observed.privileges.iter().all(|entry| {
        entry.Attributes & SE_PRIVILEGE_ENABLED == Default::default()
            || same_privilege(&entry.Luid, &change_notify)
    });
    let no_added = observed.privileges.iter().all(|entry| {
        source_before
            .privileges
            .iter()
            .any(|source_entry| same_privilege(&entry.Luid, &source_entry.Luid))
    });
    let source_unchanged = source_before == source_after;
    let same_user = source_before.user == observed.user;
    let same_session = source_before.session == observed.session;
    let source_console_user = source_before.user == console_user.bytes();
    let derived_console_user = observed.user == console_user.bytes();
    // SAFETY: read-only console session recheck detects switches across the token operation.
    let console_unchanged = console_session == unsafe { WTSGetActiveConsoleSessionId() }
        && console_user.bytes() == console_sid(console_session)?.bytes();
    println!(
        "openrdx-token-probe source-open=true derived-created=true query-ok=true medium-set-ok=true source-unchanged={source_unchanged} same-user={same_user} same-session={same_session} source-active-console={} derived-active-console={} source-console-user-match={source_console_user} derived-console-user-match={derived_console_user}",
        source_before.session == console_session && console_unchanged,
        observed.session == console_session && console_unchanged
    );
    println!(
        "openrdx-token-probe source-elevated={} derived-elevated={} source-integrity-high={} admin-deny-only={admin_deny_only} no-enabled-admins={no_enabled_admins} enabled-privilege-whitelist={enabled_whitelist} present-privilege-whitelist={present_whitelist} privileges-reduced={} no-added-privileges={no_added}",
        source_before.elevation != 0,
        observed.elevation != 0,
        source_before.integrity == 0x3000,
        observed.privileges.len() < source_before.privileges.len()
    );
    println!(
        "openrdx-token-probe integrity-medium={} integrity-high={} integrity-reduced={} ui-access-zero={} sandbox-inert-zero={} primary-token={} elevation-type-known={} elevation-type-default={} elevation-type-limited={} elevation-type-full={}",
        observed.integrity == 0x2000,
        observed.integrity == 0x3000,
        observed.integrity < source_before.integrity,
        observed.ui_access == 0,
        observed.sandbox_inert == 0,
        observed.token_type == 1,
        (1..=3).contains(&observed.elevation_type),
        observed.elevation_type == 1,
        observed.elevation_type == 3,
        observed.elevation_type == 2
    );
    assert!(source_unchanged, "original-token-changed");
    assert!(same_user && same_session, "derived-token-identity-mismatch");
    Ok(())
}

/// Explicit experiment only: kernel token proof is distinct from future child-process proof.
#[test]
#[ignore = "requires administrator on a disposable Windows verifier"]
fn native_medium_restricted_token_observations() {
    let observed = observe_medium();
    if observed.is_err() {
        println!("openrdx-token-probe query-ok=false");
    }
    assert!(observed.is_ok(), "medium-token-query-failed");
}
