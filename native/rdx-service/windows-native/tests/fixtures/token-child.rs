// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Private, argument-free Windows verification PE. No output, writes or launcher.
use std::ffi::c_void;
use std::mem::size_of;
use std::process::ExitCode;
#[path = "token-child-status.rs"]
mod exit_status;
use exit_status::SelfCheckFailure;

type Handle = *mut c_void;
/// SDK TOKEN_MANDATORY_LABEL header with pointer-width alignment.
#[repr(C)]
struct MandatoryLabel {
    sid: Handle,
    attributes: u32,
}
#[link(name = "kernel32")]
unsafe extern "system" {
    /// Borrows the current process pseudo-handle; never closes it.
    fn GetCurrentProcess() -> Handle;
    /// Returns the current process identifier internally, never as output.
    fn GetCurrentProcessId() -> u32;
    /// Reads a process session into caller-owned DWORD storage.
    fn ProcessIdToSessionId(process: u32, session: *mut u32) -> i32;
    /// Closes only successfully opened owned query-token handles.
    fn CloseHandle(handle: Handle) -> i32;
    /// Reads the active console session without changing desktop/account state.
    /// The documented import library is Kernel32.lib, not Wtsapi32.lib.
    /// https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-wtsgetactiveconsolesessionid
    fn WTSGetActiveConsoleSessionId() -> u32;
}
#[link(name = "advapi32")]
unsafe extern "system" {
    /// Opens the current token with read-only TOKEN_QUERY access.
    fn OpenProcessToken(process: Handle, access: u32, token: *mut Handle) -> i32;
    /// Reads one documented token class into bounded caller-owned storage.
    fn GetTokenInformation(
        token: Handle,
        class: u32,
        buffer: *mut c_void,
        capacity: u32,
        returned: *mut u32,
    ) -> i32;
}

/// Owns only this process' successfully opened query token.
struct Token(Handle);
impl Drop for Token {
    /// Closes this query handle without closing the borrowed process pseudo-handle.
    fn drop(&mut self) {
        // SAFETY: Token exists only after successful token opening.
        unsafe { CloseHandle(self.0) };
    }
}

/// Reads one exact scalar; no raw values are emitted.
fn scalar(token: &Token, class: u32) -> Option<u32> {
    let mut value = 0;
    let mut returned = 0;
    // SAFETY: initialized scalar storage is writable for its exact size.
    let success = unsafe {
        GetTokenInformation(
            token.0,
            class,
            (&mut value as *mut u32).cast(),
            4,
            &mut returned,
        )
    };
    (success != 0 && returned == 4).then_some(value)
}

/// Reads a bounded mandatory-label SID and checks exactly medium integrity.
fn medium(token: &Token) -> bool {
    let mut storage = vec![0_usize; 512];
    let capacity = storage.len() * size_of::<usize>();
    let mut returned = 0;
    // SAFETY: aligned writable storage has the declared bounded capacity.
    if unsafe {
        GetTokenInformation(
            token.0,
            25,
            storage.as_mut_ptr().cast(),
            capacity as u32,
            &mut returned,
        )
    } == 0
        || returned as usize > capacity
        || (returned as usize) < size_of::<MandatoryLabel>()
    {
        return false;
    }
    let start = storage.as_ptr() as usize;
    let end = start + returned as usize;
    // SAFETY: aligned response contains the complete initialized SDK header.
    let label = unsafe { storage.as_ptr().cast::<MandatoryLabel>().read() };
    if label.attributes & 0x20 == 0 {
        return false;
    }
    let sid = label.sid as usize;
    if sid < start || sid.checked_add(12).is_none_or(|limit| limit > end) || sid % 4 != 0 {
        return false;
    }
    // SAFETY: the complete 12-byte SID is bounded inside initialized response bytes.
    let bytes = unsafe { std::slice::from_raw_parts(sid as *const u8, 12) };
    bytes[0] == 1
        && bytes[1] == 1
        && bytes[2..8] == [0, 0, 0, 0, 0, 16]
        && bytes[8..12] == [0, 32, 0, 0]
}

/// Independently queries the actual executing child's token and session.
fn verify_self() -> Result<(), SelfCheckFailure> {
    let mut handle = std::ptr::null_mut();
    // SAFETY: process pseudo-handle is borrowed; only TOKEN_QUERY is requested.
    if unsafe { OpenProcessToken(GetCurrentProcess(), 8, &mut handle) } == 0 {
        return Err(SelfCheckFailure::TokenOpen);
    }
    let token = Token(handle);
    let mut process_session = u32::MAX;
    // SAFETY: output is initialized writable scalar storage; no external process is selected.
    if unsafe { ProcessIdToSessionId(GetCurrentProcessId(), &mut process_session) } == 0 {
        return Err(SelfCheckFailure::ProcessSession);
    }
    // SAFETY: read-only query has no pointer or resource ownership preconditions.
    let console = unsafe { WTSGetActiveConsoleSessionId() };
    if console == u32::MAX || process_session != console {
        return Err(SelfCheckFailure::ConsoleSession);
    }
    for (class, expected, failure) in [
        (12, console, SelfCheckFailure::TokenSession),
        (20, 0, SelfCheckFailure::Elevation),
        (26, 0, SelfCheckFailure::UiAccess),
        (15, 0, SelfCheckFailure::SandboxInert),
        (8, 1, SelfCheckFailure::Primary),
    ] {
        if scalar(&token, class) != Some(expected) {
            return Err(failure);
        }
    }
    if !medium(&token) {
        return Err(SelfCheckFailure::Integrity);
    }
    Ok(())
}

/// Returns only a fixed status, with no identity or protocol output.
fn main() -> ExitCode {
    if let Err(failure) = verify_self() {
        return ExitCode::from(failure as u8);
    }
    // The second fixed CI build deliberately hangs for bounded terminate/reap proof.
    #[cfg(token_fixture_hang)]
    loop {
        std::thread::sleep(std::time::Duration::from_secs(30));
    }
    #[cfg(not(token_fixture_hang))]
    ExitCode::SUCCESS
}
