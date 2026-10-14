// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Owned harmless child proof, independent of production Manager authorization.
use super::*;
#[path = "fixture.rs"]
mod fixture;
use fixture::{Fixture, Variant};
use windows::Win32::Foundation::{DuplicateHandle, WAIT_OBJECT_0, WAIT_TIMEOUT};
use windows::Win32::Security::TOKEN_ASSIGN_PRIMARY;
use windows::Win32::System::Threading::{
    CREATE_NO_WINDOW, CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT, CreateProcessAsUserW,
    PROCESS_INFORMATION, ResumeThread, STARTUPINFOW, TerminateProcess, WaitForSingleObject,
};

/// Distinct ownership: never accepts a borrowed process, PID lookup or source handle.
struct OwnedChild {
    process: OwnedHandle,
    thread: OwnedHandle,
    reaped: bool,
}
impl OwnedChild {
    /// Creates only the exact privately staged fixture, suspended with no inherited handles.
    fn create(fixture: &Fixture, derived: &OwnedHandle) -> Result<Self, NativeError> {
        let application = wide_null(fixture.executable.as_os_str());
        let directory = wide_null(fixture.root.as_os_str());
        let mut desktop = wide_null(OsStr::new(r"winsta0\default"));
        let environment: Vec<u16> = "SystemRoot=C:\\Windows\0WINDIR=C:\\Windows\0\0"
            .encode_utf16()
            .collect();
        let startup = STARTUPINFOW {
            cb: size_of::<STARTUPINFOW>() as u32,
            lpDesktop: PWSTR(desktop.as_mut_ptr()),
            ..Default::default()
        };
        let mut info = PROCESS_INFORMATION::default();
        // CPAsUser may temporarily enable required caller privileges; unchanged source
        // across this call is an observed fact only, never an assumed guarantee.
        // https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessasuserw
        // SAFETY: all buffers are live; explicit fixed image, no command arguments or inherited handles.
        unsafe {
            CreateProcessAsUserW(
                Some(derived.0),
                PCWSTR(application.as_ptr()),
                None,
                None,
                None,
                false,
                CREATE_SUSPENDED | CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT,
                Some(environment.as_ptr().cast()),
                PCWSTR(directory.as_ptr()),
                &startup,
                &mut info,
            )
        }
        .map_err(map_native_error)?;
        let process = OwnedHandle(info.hProcess);
        let thread = OwnedHandle(info.hThread);
        if info.dwProcessId == 0 || info.dwProcessId == std::process::id() {
            return Err(NativeError::Other);
        }
        Ok(Self {
            process,
            thread,
            reaped: false,
        })
    }

    /// Resumes only this returned initial thread after complete suspended proof.
    fn resume(&self) -> Result<(), NativeError> {
        // SAFETY: owned initial thread was created suspended exactly once.
        if unsafe { ResumeThread(self.thread.0) } != 1 {
            return Err(NativeError::Other);
        }
        Ok(())
    }

    /// Bounds execution/reaping using the retained owned process handle, never a PID.
    fn wait(&mut self, timeout_ms: u32) -> Result<Option<bool>, NativeError> {
        if !(1..=10_000).contains(&timeout_ms) {
            return Err(NativeError::InvalidRequest);
        }
        // SAFETY: process is an owned successful creation handle with synchronization access.
        let observed = unsafe { WaitForSingleObject(self.process.0, timeout_ms) };
        if observed == WAIT_TIMEOUT {
            return Ok(None);
        }
        if observed != WAIT_OBJECT_0 {
            return Err(NativeError::Other);
        }
        self.reaped = true;
        let mut code = u32::MAX;
        // SAFETY: completed owned process and writable scalar output.
        unsafe { GetExitCodeProcess(self.process.0, &mut code) }.map_err(map_native_error)?;
        Ok(Some(code == 0))
    }

    /// Terminates/reaps only this owned child on a failed proof or deadline.
    fn terminate_and_reap(&mut self) -> Result<(), NativeError> {
        // SAFETY: only this guard's created child handle is ever supplied.
        if unsafe { WaitForSingleObject(self.process.0, 0) } != WAIT_OBJECT_0 {
            // SAFETY: owned child process; neither source nor borrowed handles can reach this method.
            unsafe { TerminateProcess(self.process.0, 19) }.map_err(map_native_error)?;
        }
        // SAFETY: owned handle remains valid until this method and guard drop complete.
        if unsafe { WaitForSingleObject(self.process.0, 3_000) } != WAIT_OBJECT_0 {
            return Err(NativeError::Other);
        }
        self.reaped = true;
        Ok(())
    }
}
impl Drop for OwnedChild {
    /// Preserves the original error while best-effort reaping the owned child on every failure path.
    fn drop(&mut self) {
        if !self.reaped {
            let _ = self.terminate_and_reap();
        }
    }
}

/// Private token predicates use copied facts; identities never implement Debug or leave the process.
fn eligible(
    token: &SourceSnapshot,
    source: &SourceSnapshot,
    console: &OwnedSid,
    session: u32,
    admin_deny_only: bool,
    no_enabled_admins: bool,
) -> Result<bool, NativeError> {
    let mut notify = LUID::default();
    // SAFETY: fixed read-only privilege identifier query, no adjustments.
    unsafe { LookupPrivilegeValueW(None, SE_CHANGE_NOTIFY_NAME, &mut notify) }
        .map_err(map_native_error)?;
    Ok(token.user == source.user
        && token.user == console.bytes()
        && token.session == source.session
        && token.session == session
        && token.elevation == 0
        && token.integrity == 0x2000
        && token.ui_access == 0
        && token.sandbox_inert == 0
        && token.token_type == 1
        && matches!(token.elevation_type, 1 | 3)
        && admin_deny_only
        && no_enabled_admins
        && token
            .privileges
            .iter()
            .all(|entry| same_privilege(&entry.Luid, &notify)))
}

/// Verifies exact protected image and all kernel token facts while the primary thread is suspended.
fn prove_child_quiet(
    child: &OwnedChild,
    fixture: &Fixture,
    source: &SourceSnapshot,
    console: &OwnedSid,
    session: u32,
) -> Result<(), NativeError> {
    let mut image = vec![0_u16; 32_768];
    let mut length = image.len() as u32;
    // SAFETY: owned process and bounded writable UTF-16 image query.
    unsafe {
        QueryFullProcessImageNameW(
            child.process.0,
            PROCESS_NAME_WIN32,
            PWSTR(image.as_mut_ptr()),
            &mut length,
        )
    }
    .map_err(map_native_error)?;
    if length == 0 || length as usize >= image.len() {
        return Err(NativeError::Other);
    }
    let image = PathBuf::from(OsString::from_wide(&image[..length as usize]));
    let mut pin = crate::local_trust::windows::open(&image, false)?;
    crate::local_trust::validate_runtime_acl(&crate::local_trust::windows::evidence(&pin)?)?;
    if file_identity(&image)? != fixture.identity || fixture::hash(&mut pin)? != fixture.digest {
        return Err(NativeError::AccessDenied);
    }
    let mut handle = HANDLE::default();
    // SAFETY: pinned owned child process; new output owns a query-only token handle.
    unsafe { OpenProcessToken(child.process.0, TOKEN_QUERY, &mut handle) }
        .map_err(map_native_error)?;
    let token = OwnedHandle(handle);
    let observed = SourceSnapshot::read(&token)?;
    let (deny_only, no_admins) = administrative_groups(&token)?;
    if !eligible(&observed, source, console, session, deny_only, no_admins)? {
        return Err(NativeError::AccessDenied);
    }
    // SAFETY: only read-only local console rechecks, no session or account changes.
    if session != unsafe { WTSGetActiveConsoleSessionId() }
        || console.bytes() != console_sid(session)?.bytes()
    {
        return Err(NativeError::AccessDenied);
    }
    Ok(())
}
/// Emits positive boolean facts only after exact kernel proof of the suspended child.
fn prove_child(
    child: &OwnedChild,
    fixture: &Fixture,
    source: &SourceSnapshot,
    console: &OwnedSid,
    session: u32,
) -> Result<(), NativeError> {
    prove_child_quiet(child, fixture, source, console, session)?;
    println!(
        "openrdx-token-probe child-image-match=true child-same-user=true child-same-session=true child-console-user-match=true child-active-console=true child-elevated=false child-admin-deny-only=true child-no-enabled-admins=true child-present-privilege-whitelist=true child-medium=true child-ui-access-zero=true child-sandbox-inert-zero=true child-primary=true child-suspended-proof=true"
    );
    Ok(())
}

/// Pure copied-property negatives never change a real account, session or token.
fn negative_predicates(
    source: &SourceSnapshot,
    derived: &OwnedHandle,
    console: &OwnedSid,
    session: u32,
) -> Result<(), NativeError> {
    let mut observed = SourceSnapshot::read(derived)?;
    let (deny_only, no_admins) = administrative_groups(derived)?;
    assert!(eligible(
        &observed, source, console, session, deny_only, no_admins
    )?);
    assert!(!eligible(
        &observed, source, console, session, false, no_admins
    )?);
    assert!(!eligible(
        &observed, source, console, session, deny_only, false
    )?);
    let privileges = std::mem::replace(&mut observed.privileges, source.privileges.clone());
    assert!(!eligible(
        &observed, source, console, session, deny_only, no_admins
    )?);
    observed.privileges = privileges;
    let user = std::mem::replace(&mut observed.user, vec![0]);
    assert!(!eligible(
        &observed, source, console, session, deny_only, no_admins
    )?);
    observed.user = user;
    assert!(!eligible(
        &observed,
        source,
        console,
        u32::MAX,
        deny_only,
        no_admins
    )?);
    for (integrity, ui, inert, elevation) in [
        (0x3000, 0, 0, 0),
        (0x2000, 1, 0, 0),
        (0x2000, 0, 1, 0),
        (0x2000, 0, 0, 1),
    ] {
        observed.integrity = integrity;
        observed.ui_access = ui;
        observed.sandbox_inert = inert;
        observed.elevation = elevation;
        assert!(!eligible(
            &observed, source, console, session, deny_only, no_admins
        )?);
    }
    Ok(())
}

/// Executes one owned harmless child only after token-only and suspended-image proof.
fn observe_child() -> Result<(), NativeError> {
    let mut handle = HANDLE::default();
    // SAFETY: only the current source token is duplicated; assignment/default rights serve the derived token.
    unsafe {
        OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ADJUST_DEFAULT | TOKEN_ASSIGN_PRIMARY,
            &mut handle,
        )
    }
    .map_err(map_native_error)?;
    let source = OwnedHandle(handle);
    let original = SourceSnapshot::read(&source)?;
    let administrator = token_user_sid(&source)?;
    // SAFETY: no pointer preconditions; invalid/no-console context fails closed.
    let session = unsafe { WTSGetActiveConsoleSessionId() };
    if session == u32::MAX {
        return Err(NativeError::AccessDenied);
    }
    let console = console_sid(session)?;
    if original.user != console.bytes()
        || original.session != session
        || original.elevation == 0
        || original.integrity != 0x3000
    {
        return Err(NativeError::AccessDenied);
    }
    let mut handle = HANDLE::default();
    // SAFETY: no supplied SID/privilege tables, approved reduction flags only.
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
    negative_predicates(&original, &derived, &console, session)?;
    let mut fixture = Fixture::create(&administrator, Variant::Proof)?;
    let mut query_handle = HANDLE::default();
    // SAFETY: borrowed current-process handles; duplicate has only query rights and is owned.
    unsafe {
        DuplicateHandle(
            GetCurrentProcess(),
            derived.0,
            GetCurrentProcess(),
            &mut query_handle,
            TOKEN_QUERY.0,
            false,
            Default::default(),
        )
    }
    .map_err(map_native_error)?;
    let query_only = OwnedHandle(query_handle);
    // It is still a restricted derived token; never pass the elevated source to child creation.
    assert!(
        OwnedChild::create(&fixture, &query_only).is_err(),
        "missing-assign-rights-accepted"
    );
    // Actual suspended creation plus deliberate failed-proof cleanup, without executing that child.
    let mut negative = OwnedChild::create(&fixture, &derived)?;
    let mut mismatched_source = SourceSnapshot::read(&source)?;
    mismatched_source.user = vec![0];
    assert!(
        prove_child(&negative, &fixture, &mismatched_source, &console, session).is_err(),
        "wrong-source-accepted"
    );
    negative.terminate_and_reap()?;
    drop(negative);
    let mut wait_fixture = Fixture::create(&administrator, Variant::Wait)?;
    let mut timeout_child = OwnedChild::create(&wait_fixture, &derived)?;
    // The timeout variant has separate pinned bytes; validate its token/image without emitting duplicate facts.
    prove_child_quiet(&timeout_child, &wait_fixture, &original, &console, session)?;
    timeout_child.resume()?;
    assert!(
        timeout_child.wait(100)?.is_none(),
        "timeout-fixture-ended-before-deadline"
    );
    timeout_child.terminate_and_reap()?;
    drop(timeout_child);
    wait_fixture.cleanup()?;
    let mut child = OwnedChild::create(&fixture, &derived)?;
    let observed_source_unchanged = original == SourceSnapshot::read(&source)?;
    prove_child(&child, &fixture, &original, &console, session)?;
    child.resume()?;
    if child.wait(10_000)? != Some(true) {
        return Err(NativeError::Other);
    }
    drop(child);
    fixture.cleanup()?;
    println!(
        "openrdx-token-probe source-open=true derived-created=true query-ok=true fixture-protected=true child-created=true child-resumed=true child-exited=true child-exit-zero=true owned-child-cleanup=true negative-proof-reaped=true timeout-reaped=true api-error-rejected=true source-unchanged-after-create={observed_source_unchanged}"
    );
    Ok(())
}

/// Opt-in child execution proof is separate from installed Manager authentication and enrollment.
#[test]
#[ignore = "requires administrator on a disposable Windows verifier"]
fn native_medium_restricted_child_observations() {
    let result = observe_child();
    if result.is_err() {
        println!("openrdx-token-probe query-ok=false");
    }
    assert!(result.is_ok(), "owned-child-proof-failed");
}
