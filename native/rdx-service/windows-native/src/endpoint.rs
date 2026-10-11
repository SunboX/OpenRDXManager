// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Safe wrapper around the protected local Windows named-pipe endpoint.

use std::fmt::{Debug, Formatter};
use std::io::{Read, Write};

use std::time::Duration;
#[cfg(windows)]
use std::time::Instant;

#[cfg(windows)]
use std::mem::{size_of, zeroed};

use crate::NativeError;

/// Portable installation contract for the protected local named pipe.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NamedPipeEndpointContract {
    /// Fixed local pipe name.
    pub pipe_name: &'static str,
    /// Exact protected-DACL principals.
    pub principals: [&'static str; 3],
    /// Whether the kernel rejects remote clients.
    pub reject_remote_clients: bool,
    /// Bounded server instance count.
    pub max_instances: u32,
    /// Maximum framed bytes including the prefix.
    pub max_frame_bytes: u32,
    /// Fixed installed manager identity path.
    pub manager_path: &'static str,
    /// Maximum wait for one local manager connection.
    pub accept_timeout_ms: u32,
    /// Absolute maximum wait for the first complete protocol frame.
    pub handshake_timeout_ms: u32,
}

/// Numeric access-mask contract granted to the unprivileged manager client.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NamedPipeClientAccessContract {
    /// Exact client access mask emitted in the current-user ACE.
    pub mask: u32,
    /// Read-side data access bit.
    pub read_data: u32,
    /// Write-side data access bit.
    pub write_data: u32,
    /// Synchronization access bit required for bounded synchronous I/O.
    pub synchronize: u32,
    /// Server-only instance-creation bit, which must remain absent.
    pub create_pipe_instance: u32,
    /// Generic-write bit, which maps to server instance creation for pipes.
    pub generic_write: u32,
}

/// Returns the exact individual rights granted to the interactive client.
#[must_use]
pub const fn named_pipe_client_access_contract() -> NamedPipeClientAccessContract {
    const FILE_READ_DATA: u32 = 0x0001;
    const FILE_WRITE_DATA: u32 = 0x0002;
    const FILE_READ_ATTRIBUTES: u32 = 0x0080;
    const FILE_WRITE_ATTRIBUTES: u32 = 0x0100;
    const SYNCHRONIZE: u32 = 0x0010_0000;
    const FILE_CREATE_PIPE_INSTANCE: u32 = 0x0004;
    const GENERIC_WRITE: u32 = 0x4000_0000;
    NamedPipeClientAccessContract {
        mask: FILE_READ_DATA
            | FILE_WRITE_DATA
            | FILE_READ_ATTRIBUTES
            | FILE_WRITE_ATTRIBUTES
            | SYNCHRONIZE,
        read_data: FILE_READ_DATA,
        write_data: FILE_WRITE_DATA,
        synchronize: SYNCHRONIZE,
        create_pipe_instance: FILE_CREATE_PIPE_INSTANCE,
        generic_write: GENERIC_WRITE,
    }
}

/// Builds the protected descriptor from one kernel-resolved SID string.
#[cfg(any(windows, test))]
pub(crate) fn protected_pipe_sddl(user_sid_text: &str) -> String {
    let client_mask = named_pipe_client_access_contract().mask;
    format!("D:P(A;;0x{client_mask:08X};;;{user_sid_text})(A;;GA;;;BA)(A;;GA;;;LS)")
}

/// Returns the target-independent Windows endpoint installation contract.
#[must_use]
pub const fn named_pipe_endpoint_contract() -> NamedPipeEndpointContract {
    NamedPipeEndpointContract {
        pipe_name: r"\\.\pipe\OpenRDXHardwareService",
        principals: ["current-active-user", "administrators", "local-service"],
        reject_remote_clients: true,
        max_instances: 8,
        max_frame_bytes: 65_540,
        manager_path: r"C:\Program Files\OpenRDXManager\OpenRDXManager.exe",
        accept_timeout_ms: 10_000,
        handshake_timeout_ms: 2_000,
    }
}

#[cfg(windows)]
use windows::Win32::Foundation::{
    CloseHandle, DUPLICATE_SAME_ACCESS, DuplicateHandle, ERROR_NO_DATA, ERROR_PIPE_CONNECTED,
    ERROR_PIPE_LISTENING, GENERIC_READ, HANDLE, HLOCAL, LocalFree,
};
#[cfg(windows)]
use windows::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
#[cfg(windows)]
use windows::Win32::Security::{
    GetTokenInformation, LookupAccountNameW, PSECURITY_DESCRIPTOR, PSID, RevertToSelf,
    SECURITY_ATTRIBUTES, SID_NAME_USE, TOKEN_QUERY, TOKEN_USER, TokenUser,
};
#[cfg(windows)]
use windows::Win32::Storage::FileSystem::{
    BY_HANDLE_FILE_INFORMATION, CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_FLAG_FIRST_PIPE_INSTANCE,
    FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, GetFileInformationByHandle,
    OPEN_EXISTING, PIPE_ACCESS_DUPLEX, ReadFile, WriteFile,
};
#[cfg(windows)]
use windows::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, GetNamedPipeClientProcessId, GetNamedPipeClientSessionId,
    ImpersonateNamedPipeClient, PIPE_NOWAIT, PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS,
    PIPE_TYPE_BYTE, SetNamedPipeHandleState,
};
#[cfg(windows)]
use windows::Win32::System::RemoteDesktop::{
    WTSDomainName, WTSFreeMemory, WTSGetActiveConsoleSessionId, WTSQuerySessionInformationW,
    WTSUserName,
};
#[cfg(windows)]
use windows::Win32::System::Threading::{
    GetCurrentProcess, GetCurrentThread, OpenProcess, OpenThreadToken, PROCESS_NAME_WIN32,
    PROCESS_QUERY_LIMITED_INFORMATION, QueryFullProcessImageNameW,
};
#[cfg(windows)]
use windows::core::{PCWSTR, PWSTR};

#[cfg(windows)]
const PIPE_NAME: &str = r"\\.\pipe\OpenRDXHardwareService";
#[cfg(windows)]
const MANAGER_PATH: &str = r"C:\Program Files\OpenRDXManager\OpenRDXManager.exe";
#[cfg(windows)]
const MAX_ENDPOINT_BYTES: u32 = 65_536 + 4;
#[cfg(windows)]
const ACCEPT_TIMEOUT: Duration = Duration::from_secs(10);

#[cfg(windows)]
struct TemporaryHandle(HANDLE);

#[cfg(windows)]
impl TemporaryHandle {
    fn raw(&self) -> HANDLE {
        self.0
    }
}

#[cfg(windows)]
impl Drop for TemporaryHandle {
    /// Closes one exact temporary kernel handle once.
    fn drop(&mut self) {
        // SAFETY: this guard owns one valid non-pseudo handle exactly once.
        let _ = unsafe { CloseHandle(self.0) };
    }
}

#[cfg(windows)]
struct LocalDescriptor(PSECURITY_DESCRIPTOR);

#[cfg(windows)]
impl Drop for LocalDescriptor {
    /// Releases one LocalAlloc-owned security descriptor once.
    fn drop(&mut self) {
        // SAFETY: conversion returned this LocalAlloc-owned descriptor.
        let _ = unsafe { LocalFree(Some(HLOCAL(self.0.0))) };
    }
}

#[cfg(windows)]
struct EndpointAuthority {
    descriptor: LocalDescriptor,
    session_id: u32,
    user_sid: Vec<u8>,
}

#[cfg(windows)]
struct PendingPipe(HANDLE);

#[cfg(windows)]
impl PendingPipe {
    /// Transfers the connected handle without closing it.
    fn into_raw(self) -> HANDLE {
        let owned = std::mem::ManuallyDrop::new(self);
        owned.0
    }
}

#[cfg(windows)]
impl Drop for PendingPipe {
    /// Releases the pending namespace-owning instance once.
    fn drop(&mut self) {
        // SAFETY: this guard owns one valid pipe handle exactly once.
        let _ = unsafe { CloseHandle(self.0) };
    }
}

/// One exact accepted Windows manager connection with retained pipe ownership.
pub struct ManagerEndpointConnection {
    #[cfg(windows)]
    handle: HANDLE,
    #[cfg(windows)]
    read_deadline: Option<Instant>,
    session_id: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg(any(windows, test))]
pub(crate) enum PipeInstancePolicy {
    /// The generation's first pipe proves exclusive name ownership.
    FirstExclusive,
    /// Later bounded instances coexist with an accepted reader clone.
    Additional,
}

/// Portable state machine mirroring rolling namespace ownership.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg(any(windows, test))]
pub(crate) struct NamespaceOwnership {
    first: bool,
    pending: bool,
    stopped: bool,
}

#[cfg(any(windows, test))]
impl NamespaceOwnership {
    /// Starts with one exclusive pending instance already retained.
    pub(crate) const fn new() -> Self {
        Self {
            first: true,
            pending: true,
            stopped: false,
        }
    }

    /// Returns the creation policy represented by the retained instance.
    pub(crate) const fn pending_policy(&self) -> PipeInstancePolicy {
        if self.first {
            PipeInstancePolicy::FirstExclusive
        } else {
            PipeInstancePolicy::Additional
        }
    }

    /// Proves that one pending instance still owns the namespace.
    pub(crate) const fn authority_retained(&self) -> bool {
        self.pending && !self.stopped
    }

    /// Records creation of the next pending instance before transfer.
    pub(crate) fn roll_after_accept(&mut self) -> Result<(), NativeError> {
        if self.stopped || !self.pending {
            return Err(NativeError::Cancelled);
        }
        self.first = false;
        Ok(())
    }

    /// Models the kernel's competing first-instance rejection.
    #[cfg(test)]
    pub(crate) const fn competing_claim(&self) -> Result<(), NativeError> {
        if self.authority_retained() {
            Err(NativeError::AccessDenied)
        } else {
            Ok(())
        }
    }

    /// Closes namespace admission for this service generation.
    pub(crate) fn stop(&mut self) {
        self.pending = false;
        self.stopped = true;
    }
}

/// Process-lifetime named-pipe factory retaining first-instance ownership.
pub struct NamedPipeManagerEndpointListener {
    #[cfg(windows)]
    authority: EndpointAuthority,
    #[cfg(windows)]
    pending: Option<PendingPipe>,
    #[cfg(windows)]
    ownership: NamespaceOwnership,
}

impl Debug for NamedPipeManagerEndpointListener {
    /// Redacts the native pipe, descriptor, and user identity.
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("NamedPipeManagerEndpointListener(<private>)")
    }
}

impl NamedPipeManagerEndpointListener {
    /// Creates and retains the authoritative first pipe instance.
    ///
    /// # Errors
    ///
    /// Returns a sanitized authority or native failure without publishing a
    /// partially protected endpoint.
    pub fn bind() -> Result<Self, NativeError> {
        #[cfg(windows)]
        {
            let authority = endpoint_authority()?;
            let ownership = NamespaceOwnership::new();
            let pending = create_pending_pipe(&authority, ownership.pending_policy())?;
            Ok(Self {
                authority,
                pending: Some(pending),
                ownership,
            })
        }
        #[cfg(not(windows))]
        {
            Err(NativeError::UnsupportedPlatform)
        }
    }

    /// Creates and authenticates the next protected named-pipe instance.
    ///
    /// # Errors
    ///
    /// Returns a sanitized service-authority, timeout, peer, or native failure.
    pub fn accept(&mut self) -> Result<ManagerEndpointConnection, NativeError> {
        self.accept_until(|| false)
    }

    /// Accepts one manager while polling a service-owned stop signal.
    ///
    /// Only an observed stop returns `Cancelled`; a true accept timeout remains
    /// `TimedOut`, allowing the SCM runner to distinguish lifecycle shutdown.
    ///
    /// # Errors
    ///
    /// Returns a sanitized service-authority, timeout, cancellation, peer, or
    /// native failure.
    pub fn accept_until<F>(
        &mut self,
        stop_requested: F,
    ) -> Result<ManagerEndpointConnection, NativeError>
    where
        F: Fn() -> bool,
    {
        #[cfg(windows)]
        {
            let pending = self.pending.as_ref().ok_or(NativeError::Cancelled)?;
            accept_native(pending, &self.authority, &stop_requested)?;
            if stop_requested() {
                self.ownership.stop();
                return Err(NativeError::Cancelled);
            }
            let connected = self.pending.take().ok_or(NativeError::Cancelled)?;
            let next = create_pending_pipe(&self.authority, PipeInstancePolicy::Additional)?;
            self.pending = Some(next);
            self.ownership.roll_after_accept()?;
            debug_assert!(self.ownership.authority_retained());
            Ok(ManagerEndpointConnection {
                handle: connected.into_raw(),
                read_deadline: None,
                session_id: self.authority.session_id,
            })
        }
        #[cfg(not(windows))]
        {
            let _ = stop_requested;
            Err(NativeError::UnsupportedPlatform)
        }
    }
}

#[cfg(windows)]
// SAFETY: the wrapper has unique ownership of one duplicated kernel handle.
// Reads and writes require `&mut self`, and moving ownership to the framed
// reader thread cannot create concurrent access to this handle value.
unsafe impl Send for ManagerEndpointConnection {}

impl ManagerEndpointConnection {
    /// Returns the kernel-reported interactive session identifier.
    #[must_use]
    pub const fn session_id(&self) -> u32 {
        self.session_id
    }

    /// Configures or clears an absolute userspace pipe-read deadline.
    ///
    /// The accepted pipe is kernel-configured as nonblocking, so each read can
    /// honor this deadline even though synchronous named pipes do not expose a
    /// per-handle read-timeout option.
    ///
    /// # Errors
    ///
    /// Returns `InvalidInput` if the duration cannot form a future instant, or
    /// `Unsupported` on non-Windows targets.
    pub fn set_read_timeout(&mut self, timeout: Option<Duration>) -> std::io::Result<()> {
        #[cfg(windows)]
        {
            self.read_deadline = timeout
                .map(|duration| {
                    Instant::now()
                        .checked_add(duration)
                        .ok_or(std::io::ErrorKind::InvalidInput)
                })
                .transpose()?;
            Ok(())
        }
        #[cfg(not(windows))]
        {
            let _ = timeout;
            Err(std::io::ErrorKind::Unsupported.into())
        }
    }

    /// Duplicates the exact authenticated pipe for framed reader/writer ownership.
    ///
    /// # Errors
    ///
    /// Returns a sanitized native failure if handle duplication fails.
    pub fn try_clone(&self) -> Result<Self, NativeError> {
        #[cfg(windows)]
        {
            // SAFETY: GetCurrentProcess returns a non-owning pseudo-handle.
            let process = unsafe { GetCurrentProcess() };
            let mut duplicate = HANDLE::default();
            // SAFETY: source handle is live, target process is current, and the
            // returned duplicate transfers to the new connection wrapper.
            unsafe {
                DuplicateHandle(
                    process,
                    self.handle,
                    process,
                    &mut duplicate,
                    0,
                    false,
                    DUPLICATE_SAME_ACCESS,
                )
            }
            .map_err(|_| NativeError::Other)?;
            Ok(Self {
                handle: duplicate,
                read_deadline: self.read_deadline,
                session_id: self.session_id,
            })
        }
        #[cfg(not(windows))]
        {
            Err(NativeError::UnsupportedPlatform)
        }
    }
}

impl Debug for ManagerEndpointConnection {
    /// Redacts the native handle and peer identity.
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ManagerEndpointConnection(<private>)")
    }
}

impl Drop for ManagerEndpointConnection {
    /// Closes the exact owned pipe handle once.
    fn drop(&mut self) {
        #[cfg(windows)]
        // SAFETY: this object owns the valid pipe handle exactly once.
        let _ = unsafe { CloseHandle(self.handle) };
    }
}

impl Read for ManagerEndpointConnection {
    /// Reads one bounded chunk from the authenticated pipe.
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        #[cfg(windows)]
        {
            if buffer.is_empty() {
                return Ok(0);
            }
            loop {
                let mut read = 0_u32;
                // SAFETY: handle is live and Windows bounds writes to the supplied slice.
                match unsafe { ReadFile(self.handle, Some(buffer), Some(&mut read), None) } {
                    Ok(()) => return Ok(read as usize),
                    Err(error) if error.code() == ERROR_NO_DATA.to_hresult() => {
                        let pause = if let Some(deadline) = self.read_deadline {
                            let remaining = deadline
                                .checked_duration_since(Instant::now())
                                .ok_or(std::io::ErrorKind::TimedOut)?;
                            remaining.min(Duration::from_millis(5))
                        } else {
                            Duration::from_millis(5)
                        };
                        if pause.is_zero() {
                            return Err(std::io::ErrorKind::TimedOut.into());
                        }
                        std::thread::sleep(pause);
                    }
                    Err(_) => return Err(std::io::ErrorKind::Other.into()),
                }
            }
        }
        #[cfg(not(windows))]
        {
            let _ = buffer;
            Err(std::io::ErrorKind::Unsupported.into())
        }
    }
}

impl Write for ManagerEndpointConnection {
    /// Writes one bounded chunk to the authenticated pipe.
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        #[cfg(windows)]
        {
            let mut written = 0_u32;
            // SAFETY: handle is live and Windows reads only the supplied slice.
            unsafe { WriteFile(self.handle, Some(buffer), Some(&mut written), None) }
                .map(|()| written as usize)
                .map_err(|_| std::io::ErrorKind::Other.into())
        }
        #[cfg(not(windows))]
        {
            let _ = buffer;
            Err(std::io::ErrorKind::Unsupported.into())
        }
    }

    /// Flush is a no-op because every protocol frame uses synchronous writes.
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(windows)]
fn endpoint_authority() -> Result<EndpointAuthority, NativeError> {
    if !crate::probe_readiness().current_process_authorized() {
        return Err(NativeError::AccessDenied);
    }
    // SAFETY: this query has no pointer arguments and returns a scalar session ID.
    let session_id = unsafe { WTSGetActiveConsoleSessionId() };
    if session_id == u32::MAX {
        return Err(NativeError::AccessDenied);
    }
    let account = active_account_name(session_id)?;
    let user_sid = lookup_account_sid(&account)?;
    let user_sid_text = sid_string(PSID(user_sid.as_ptr().cast_mut().cast()))?;
    let sddl = protected_pipe_sddl(&user_sid_text);
    let sddl_wide = wide_null(&sddl);
    let mut descriptor = PSECURITY_DESCRIPTOR::default();
    // SAFETY: the SDDL is NUL-terminated and the returned allocation is owned.
    unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            PCWSTR(sddl_wide.as_ptr()),
            SDDL_REVISION_1,
            &mut descriptor,
            None,
        )
    }
    .map_err(|_| NativeError::AccessDenied)?;
    Ok(EndpointAuthority {
        descriptor: LocalDescriptor(descriptor),
        session_id,
        user_sid,
    })
}

#[cfg(windows)]
fn create_pending_pipe(
    authority: &EndpointAuthority,
    instance: PipeInstancePolicy,
) -> Result<PendingPipe, NativeError> {
    let attributes = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: authority.descriptor.0.0,
        bInheritHandle: false.into(),
    };
    let pipe_name = wide_null(PIPE_NAME);
    // SAFETY: all arguments are initialized; the descriptor remains live for
    // creation and is released immediately after the kernel copies the DACL.
    let access = match instance {
        PipeInstancePolicy::FirstExclusive => PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
        PipeInstancePolicy::Additional => PIPE_ACCESS_DUPLEX,
    };
    let handle = unsafe {
        CreateNamedPipeW(
            PCWSTR(pipe_name.as_ptr()),
            access,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_NOWAIT | PIPE_REJECT_REMOTE_CLIENTS,
            8,
            MAX_ENDPOINT_BYTES,
            MAX_ENDPOINT_BYTES,
            2_000,
            Some(&attributes),
        )
    };
    if handle.is_invalid() {
        return Err(NativeError::AccessDenied);
    }
    Ok(PendingPipe(handle))
}

#[cfg(windows)]
fn accept_native<F>(
    pending: &PendingPipe,
    authority: &EndpointAuthority,
    stop_requested: &F,
) -> Result<(), NativeError>
where
    F: Fn() -> bool,
{
    wait_for_manager(pending.0, stop_requested)?;
    authenticate_client(
        pending.0,
        authority.session_id,
        authority.user_sid.as_slice(),
    )?;
    let mode = PIPE_READMODE_BYTE | PIPE_NOWAIT;
    // SAFETY: the authenticated connected pipe handle is live and mode points
    // to one initialized scalar retained for the duration of this call.
    unsafe { SetNamedPipeHandleState(pending.0, Some(&mode), None, None) }
        .map_err(|_| NativeError::Other)?;
    Ok(())
}

#[cfg(windows)]
fn wait_for_manager<F>(handle: HANDLE, stop_requested: &F) -> Result<(), NativeError>
where
    F: Fn() -> bool,
{
    let deadline = Instant::now() + ACCEPT_TIMEOUT;
    loop {
        if stop_requested() {
            return Err(NativeError::Cancelled);
        }
        // SAFETY: the pipe is nonblocking and no overlapped pointer is supplied.
        match unsafe { ConnectNamedPipe(handle, None) } {
            Ok(()) => return Ok(()),
            Err(error) if error.code() == ERROR_PIPE_CONNECTED.to_hresult() => return Ok(()),
            Err(error)
                if error.code() == ERROR_PIPE_LISTENING.to_hresult()
                    || error.code() == ERROR_NO_DATA.to_hresult() =>
            {
                let remaining = deadline
                    .checked_duration_since(Instant::now())
                    .ok_or(NativeError::TimedOut)?;
                std::thread::sleep(remaining.min(Duration::from_millis(5)));
            }
            Err(_) => return Err(NativeError::Other),
        }
    }
}

#[cfg(windows)]
fn authenticate_client(
    handle: HANDLE,
    expected_session: u32,
    expected_sid: &[u8],
) -> Result<(), NativeError> {
    let mut session_id = u32::MAX;
    let mut process_id = 0_u32;
    // SAFETY: output scalars are valid and the pipe handle is connected.
    unsafe { GetNamedPipeClientSessionId(handle, &mut session_id) }
        .map_err(|_| NativeError::AccessDenied)?;
    // SAFETY: same as the preceding query.
    unsafe { GetNamedPipeClientProcessId(handle, &mut process_id) }
        .map_err(|_| NativeError::AccessDenied)?;
    if session_id != expected_session || process_id == 0 || !manager_process_matches(process_id)? {
        return Err(NativeError::AccessDenied);
    }
    // SAFETY: connected local pipe is valid for bounded impersonation.
    unsafe { ImpersonateNamedPipeClient(handle) }.map_err(|_| NativeError::AccessDenied)?;
    let guard = ImpersonationGuard;
    let mut token = HANDLE::default();
    // SAFETY: the current thread is impersonating and output owns one token.
    unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, true, &mut token) }
        .map_err(|_| NativeError::AccessDenied)?;
    let token = TemporaryHandle(token);
    let result = token_user_sid(token.raw()).and_then(|actual| {
        // SAFETY: both SIDs point into live owned byte buffers for this call.
        unsafe {
            windows::Win32::Security::EqualSid(
                PSID(actual.as_ptr().cast_mut().cast()),
                PSID(expected_sid.as_ptr().cast_mut().cast()),
            )
        }
        .map_err(|_| NativeError::AccessDenied)
    });
    drop(guard);
    result
}

#[cfg(windows)]
struct ImpersonationGuard;

#[cfg(windows)]
impl Drop for ImpersonationGuard {
    /// Reverts the pipe impersonation on every exit path.
    fn drop(&mut self) {
        // SAFETY: this guard exists only after successful impersonation.
        let _ = unsafe { RevertToSelf() };
    }
}

#[cfg(windows)]
fn active_account_name(session_id: u32) -> Result<String, NativeError> {
    let user = query_session_text(session_id, WTSUserName)?;
    let domain = query_session_text(session_id, WTSDomainName)?;
    if user.is_empty() || domain.is_empty() {
        return Err(NativeError::AccessDenied);
    }
    Ok(format!(r"{domain}\{user}"))
}

#[cfg(windows)]
fn query_session_text(
    session_id: u32,
    class: windows::Win32::System::RemoteDesktop::WTS_INFO_CLASS,
) -> Result<String, NativeError> {
    let mut buffer = PWSTR::null();
    let mut bytes = 0_u32;
    // SAFETY: WTS allocates one output buffer and reports its exact byte length.
    unsafe { WTSQuerySessionInformationW(None, session_id, class, &mut buffer, &mut bytes) }
        .map_err(|_| NativeError::AccessDenied)?;
    if buffer.is_null() || !(2..=1024).contains(&bytes) {
        if !buffer.is_null() {
            // SAFETY: WTS owns this non-null allocation.
            unsafe { WTSFreeMemory(buffer.0.cast()) };
        }
        return Err(NativeError::AccessDenied);
    }
    // SAFETY: WTS reports a bounded initialized UTF-16 buffer including NUL.
    let units = unsafe { std::slice::from_raw_parts(buffer.0, bytes as usize / 2) };
    let result = units
        .iter()
        .position(|unit| *unit == 0)
        .ok_or(NativeError::AccessDenied)
        .and_then(|end| String::from_utf16(&units[..end]).map_err(|_| NativeError::AccessDenied));
    // SAFETY: WTS owns this allocation and it is freed exactly once.
    unsafe { WTSFreeMemory(buffer.0.cast()) };
    result
}

#[cfg(windows)]
fn lookup_account_sid(account: &str) -> Result<Vec<u8>, NativeError> {
    let account = wide_null(account);
    let mut sid_bytes = 0_u32;
    let mut domain_units = 0_u32;
    let mut use_kind = SID_NAME_USE::default();
    // SAFETY: the first call intentionally queries exact output lengths.
    let _ = unsafe {
        LookupAccountNameW(
            PCWSTR::null(),
            PCWSTR(account.as_ptr()),
            None,
            &mut sid_bytes,
            None,
            &mut domain_units,
            &mut use_kind,
        )
    };
    if sid_bytes == 0 || sid_bytes > 1024 || domain_units > 256 {
        return Err(NativeError::AccessDenied);
    }
    let mut sid = vec![0_u8; sid_bytes as usize];
    let mut domain = vec![0_u16; domain_units as usize];
    // SAFETY: buffers match the exact lengths returned by the query call.
    unsafe {
        LookupAccountNameW(
            PCWSTR::null(),
            PCWSTR(account.as_ptr()),
            Some(PSID(sid.as_mut_ptr().cast())),
            &mut sid_bytes,
            Some(PWSTR(domain.as_mut_ptr())),
            &mut domain_units,
            &mut use_kind,
        )
    }
    .map_err(|_| NativeError::AccessDenied)?;
    Ok(sid)
}

#[cfg(windows)]
fn sid_string(sid: PSID) -> Result<String, NativeError> {
    let mut text = PWSTR::null();
    // SAFETY: SID points to a validated account buffer; output is LocalAlloc-owned.
    unsafe { ConvertSidToStringSidW(sid, &mut text) }.map_err(|_| NativeError::AccessDenied)?;
    let mut length = 0_usize;
    // SAFETY: conversion guarantees a NUL-terminated string; bound contains corruption.
    while length < 256 && unsafe { *text.0.add(length) } != 0 {
        length += 1;
    }
    let result = if length == 256 {
        Err(NativeError::AccessDenied)
    } else {
        // SAFETY: the bounded scan established initialized units through length.
        String::from_utf16(unsafe { std::slice::from_raw_parts(text.0, length) })
            .map_err(|_| NativeError::AccessDenied)
    };
    // SAFETY: ConvertSidToStringSidW returns a LocalAlloc-owned pointer.
    let _ = unsafe { LocalFree(Some(HLOCAL(text.0.cast()))) };
    result
}

#[cfg(windows)]
fn token_user_sid(token: HANDLE) -> Result<Vec<u8>, NativeError> {
    let mut bytes = 0_u32;
    // SAFETY: first call queries the required bounded token buffer length.
    let _ = unsafe { GetTokenInformation(token, TokenUser, None, 0, &mut bytes) };
    if bytes < size_of::<TOKEN_USER>() as u32 || bytes > 4096 {
        return Err(NativeError::AccessDenied);
    }
    let mut buffer = vec![0_u8; bytes as usize];
    // SAFETY: buffer matches the queried length and token is live.
    unsafe {
        GetTokenInformation(
            token,
            TokenUser,
            Some(buffer.as_mut_ptr().cast()),
            bytes,
            &mut bytes,
        )
    }
    .map_err(|_| NativeError::AccessDenied)?;
    // SAFETY: GetTokenInformation initialized at least one complete TOKEN_USER.
    let token_user = unsafe { &*buffer.as_ptr().cast::<TOKEN_USER>() };
    // SAFETY: TOKEN_USER contains the kernel-validated SID pointer.
    let sid_length =
        unsafe { windows::Win32::Security::GetLengthSid(token_user.User.Sid) } as usize;
    if sid_length == 0 || sid_length > 1024 {
        return Err(NativeError::AccessDenied);
    }
    // SAFETY: TOKEN_USER SID points within the still-live token buffer.
    Ok(unsafe { std::slice::from_raw_parts(token_user.User.Sid.0.cast(), sid_length) }.to_vec())
}

#[cfg(windows)]
fn manager_process_matches(process_id: u32) -> Result<bool, NativeError> {
    // SAFETY: access is query-only and PID came from the connected pipe.
    let process = TemporaryHandle(
        unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, process_id) }
            .map_err(|_| NativeError::AccessDenied)?,
    );
    let mut image = vec![0_u16; 32_768];
    let mut image_length = image.len() as u32;
    // SAFETY: output buffer is bounded and process handle is live.
    let query = unsafe {
        QueryFullProcessImageNameW(
            process.raw(),
            PROCESS_NAME_WIN32,
            PWSTR(image.as_mut_ptr()),
            &mut image_length,
        )
    };
    query.map_err(|_| NativeError::AccessDenied)?;
    if image_length == 0 || image_length as usize >= image.len() {
        return Err(NativeError::AccessDenied);
    }
    image[image_length as usize] = 0;
    let peer = TemporaryHandle(open_identity_file(PCWSTR(image.as_ptr()))?);
    let expected_path = wide_null(MANAGER_PATH);
    let expected = TemporaryHandle(open_identity_file(PCWSTR(expected_path.as_ptr()))?);
    let result = file_identity(peer.raw())? == file_identity(expected.raw())?;
    Ok(result)
}

#[cfg(windows)]
fn open_identity_file(path: PCWSTR) -> Result<HANDLE, NativeError> {
    // SAFETY: path is NUL-terminated and access is query/read-only with no mutation.
    let handle = unsafe {
        CreateFileW(
            path,
            GENERIC_READ.0,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            None,
        )
    }
    .map_err(|_| NativeError::AccessDenied)?;
    Ok(handle)
}

#[cfg(windows)]
fn file_identity(handle: HANDLE) -> Result<(u32, u32, u32), NativeError> {
    // SAFETY: zero is a valid initial state for this output-only Win32 structure.
    let mut information: BY_HANDLE_FILE_INFORMATION = unsafe { zeroed() };
    // SAFETY: output is initialized writable storage and handle is live.
    unsafe { GetFileInformationByHandle(handle, &mut information) }
        .map_err(|_| NativeError::AccessDenied)?;
    Ok((
        information.dwVolumeSerialNumber,
        information.nFileIndexHigh,
        information.nFileIndexLow,
    ))
}

#[cfg(windows)]
fn wide_null(value: &str) -> Vec<u16> {
    value.encode_utf16().chain([0]).collect()
}
