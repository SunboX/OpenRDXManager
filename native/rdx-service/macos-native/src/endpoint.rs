// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Safe ownership wrapper for the launchd socket and native peer verifier.

use std::fmt::{Debug, Formatter};
use std::io::{Read, Write};

#[cfg(target_os = "macos")]
use std::ffi::CString;
#[cfg(target_os = "macos")]
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
#[cfg(target_os = "macos")]
use std::os::unix::net::UnixStream;
use std::time::Duration;

use crate::NativeError;

const MAX_REQUIREMENT_BYTES: usize = 2048;

/// Portable installation and process-lifetime launchd endpoint contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LaunchdEndpointContract {
    /// Fixed root-owned socket path.
    pub socket_path: &'static str,
    /// Required socket owner UID.
    pub owner_uid: u32,
    /// Exact socket permission bits.
    pub mode: u32,
    /// Maximum sequential connections in one service process generation.
    pub max_connections: u32,
    /// Maximum wait for each manager accept.
    pub accept_timeout_ms: u32,
    /// Absolute maximum wait for the first complete protocol frame.
    pub handshake_timeout_ms: u32,
}

/// Returns the signed compatibility namespace and shared launchd lifecycle bounds.
/// Local service activation selects its separate fixed socket from verified policy.
#[must_use]
pub const fn launchd_endpoint_contract() -> LaunchdEndpointContract {
    LaunchdEndpointContract {
        socket_path: "/var/run/openrdx-hardware.sock",
        owner_uid: 0,
        mode: 0o660,
        max_connections: 8,
        accept_timeout_ms: 10_000,
        handshake_timeout_ms: 2_000,
    }
}

/// Exact accepted manager connection after native credentials and code identity.
pub struct ManagerEndpointConnection {
    #[cfg(target_os = "macos")]
    stream: UnixStream,
    user_id: u32,
}

/// One retained launchd listener with one canonical code requirement.
pub struct LaunchdManagerEndpointListener {
    #[cfg(target_os = "macos")]
    listener: OwnedFd,
    #[cfg(target_os = "macos")]
    requirement: CString,
}

impl Debug for LaunchdManagerEndpointListener {
    /// Redacts the listener descriptor and signing policy.
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("LaunchdManagerEndpointListener(<private>)")
    }
}

impl LaunchdManagerEndpointListener {
    /// Accepts one peer while retaining the exact launchd listener for reuse.
    ///
    /// # Errors
    ///
    /// Returns a sanitized timeout, credential, code identity, or native error.
    pub fn accept(&self) -> Result<ManagerEndpointConnection, NativeError> {
        #[cfg(target_os = "macos")]
        {
            log_endpoint_phase("session-runtime-verification-start", None);
            if self
                .requirement
                .to_bytes()
                .starts_with(b"identifier \"com.openrdx.manager\" and cdhash ")
            {
                let inventory = crate::local_trust::verify_installed_local_trust()?;
                let expected = local_manager_requirement(&inventory.manager_cd_hash)?;
                if self.requirement.to_bytes() != expected.as_bytes() {
                    return Err(NativeError::AccessDenied);
                }
            } else {
                // Team authenticity is proven against the accepted audit token
                // below. Before admission, independently refuse older/unfused
                // signed apps and user-owned/writable or redirected runtimes.
                // Native peer validation then checks the whole nested seal and
                // refuses sealed local markers on this distinct signed route.
                rdx_local_trust::verify_protected_signed_macos_runtime()
                    .map_err(|_| NativeError::AccessDenied)?;
            }
            log_endpoint_phase("session-runtime-verification-ok", None);
            let mut socket = -1;
            let mut user_id = 0_u32;
            // SAFETY: the listener and requirement are owned and live, and C
            // transfers exactly one accepted descriptor only on STATUS_OK.
            let status = unsafe {
                crate::ffi::rdx_macos_accept_launchd_manager_from_listener(
                    self.listener.as_raw_fd(),
                    self.requirement.as_ptr(),
                    &mut socket,
                    &mut user_id,
                )
            };
            connection_from_status(status, socket, user_id)
        }
        #[cfg(not(target_os = "macos"))]
        {
            Err(NativeError::UnsupportedPlatform)
        }
    }
}

impl ManagerEndpointConnection {
    /// Returns the kernel-reported effective peer user identifier.
    #[must_use]
    pub const fn user_id(&self) -> u32 {
        self.user_id
    }

    /// Configures or clears the native read timeout for handshake enforcement.
    ///
    /// # Errors
    ///
    /// Returns a native I/O error if the socket option cannot be updated.
    pub fn set_read_timeout(&mut self, timeout: Option<Duration>) -> std::io::Result<()> {
        #[cfg(target_os = "macos")]
        {
            self.stream.set_read_timeout(timeout)
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = timeout;
            Err(std::io::ErrorKind::Unsupported.into())
        }
    }

    /// Clones the owned stream for the framed reader/writer split.
    ///
    /// # Errors
    ///
    /// Returns a sanitized native failure when descriptor duplication fails.
    pub fn try_clone(&self) -> Result<Self, NativeError> {
        #[cfg(target_os = "macos")]
        {
            self.stream
                .try_clone()
                .map(|stream| Self {
                    stream,
                    user_id: self.user_id,
                })
                .map_err(|_| NativeError::Other)
        }
        #[cfg(not(target_os = "macos"))]
        {
            Err(NativeError::UnsupportedPlatform)
        }
    }
}

impl Debug for ManagerEndpointConnection {
    /// Redacts the socket descriptor and native peer details.
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ManagerEndpointConnection(<private>)")
    }
}

impl Read for ManagerEndpointConnection {
    /// Reads framed bytes from the exact authenticated connection.
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        #[cfg(target_os = "macos")]
        {
            self.stream.read(buffer)
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = buffer;
            Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "unsupported platform",
            ))
        }
    }
}

impl Write for ManagerEndpointConnection {
    /// Writes framed bytes to the exact authenticated connection.
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        #[cfg(target_os = "macos")]
        {
            self.stream.write(buffer)
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = buffer;
            Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "unsupported platform",
            ))
        }
    }

    /// Flushes framed bytes to the exact authenticated connection.
    fn flush(&mut self) -> std::io::Result<()> {
        #[cfg(target_os = "macos")]
        {
            self.stream.flush()
        }
        #[cfg(not(target_os = "macos"))]
        {
            Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "unsupported platform",
            ))
        }
    }
}

/// Adopts one launchd-activated socket and accepts an exact signed manager.
///
/// The requirement pins either the signed team or protected enrolled cdhash.
/// The C boundary binds validation to the accepted socket audit token and fixed
/// executable path; local sessions also verify the protected complete runtime.
///
/// # Errors
///
/// Returns a sanitized invalid configuration, missing activation, access, or
/// native failure. The accepted descriptor is closed on every error path.
pub fn accept_launchd_manager_endpoint(
    designated_requirement: &str,
) -> Result<ManagerEndpointConnection, NativeError> {
    activate_launchd_manager_endpoint(designated_requirement)?.accept()
}

/// Adopts the exact launchd listener once with canonical signing policy.
///
/// # Errors
///
/// Returns invalid request before activation unless the requirement has the
/// exact pinned grammar, or a sanitized activation/native failure.
pub fn activate_launchd_manager_endpoint(
    designated_requirement: &str,
) -> Result<LaunchdManagerEndpointListener, NativeError> {
    if !manager_requirement_is_pinned(designated_requirement) {
        return Err(NativeError::InvalidRequest);
    }
    #[cfg(target_os = "macos")]
    {
        let requirement =
            CString::new(designated_requirement).map_err(|_| NativeError::InvalidRequest)?;
        let mut listener = -1;
        // SAFETY: canonical requirement is owned and live, output references
        // one initialized scalar; C selects only its fixed local/signed socket.
        // C transfers sole listener ownership only on STATUS_OK and closes
        // all failure paths.
        let status = unsafe {
            crate::ffi::rdx_macos_activate_launchd_listener(requirement.as_ptr(), &mut listener)
        };
        if status != crate::ffi::STATUS_OK {
            return Err(crate::status_error(status));
        }
        if listener < 0 {
            return Err(NativeError::Other);
        }
        // SAFETY: successful C activation transfers sole descriptor ownership.
        let listener = unsafe { OwnedFd::from_raw_fd(listener) };
        Ok(LaunchdManagerEndpointListener {
            listener,
            requirement,
        })
    }
    #[cfg(not(target_os = "macos"))]
    {
        Err(NativeError::UnsupportedPlatform)
    }
}

#[cfg(target_os = "macos")]
fn connection_from_status(
    status: u32,
    socket: std::ffi::c_int,
    user_id: u32,
) -> Result<ManagerEndpointConnection, NativeError> {
    if status != crate::ffi::STATUS_OK {
        log_endpoint_native_code("accepted-native-status", status as i32);
        return Err(crate::status_error(status));
    }
    if socket < 0 {
        log_endpoint_native_code("accepted-invalid-descriptor", socket);
        return Err(NativeError::Other);
    }
    // SAFETY: successful C accept transfers sole ownership of this descriptor.
    let stream = unsafe { UnixStream::from_raw_fd(socket) };
    stream
        .set_read_timeout(Some(Duration::from_secs(300)))
        .map_err(|error| {
            log_endpoint_native_code("accepted-read-timeout", error.raw_os_error().unwrap_or(-1));
            NativeError::Other
        })?;
    stream
        .set_write_timeout(Some(Duration::from_secs(30)))
        .map_err(|error| {
            log_endpoint_native_code("accepted-write-timeout", error.raw_os_error().unwrap_or(-1));
            NativeError::Other
        })?;
    Ok(ManagerEndpointConnection { stream, user_id })
}

/// Accepts only canonical signed-team or locally enrolled generation requirements.
pub fn manager_requirement_is_pinned(requirement: &str) -> bool {
    const LOCAL_PREFIX: &str = "identifier \"com.openrdx.manager\" and cdhash H\"";
    if let Some(hash) = requirement
        .strip_prefix(LOCAL_PREFIX)
        .and_then(|text| text.strip_suffix('"'))
    {
        return valid_cdhash(hash);
    }
    const PREFIX: &str = "identifier \"com.openrdx.manager\" and anchor apple generic and certificate leaf[subject.OU] = \"";
    let Some(team_identifier) = requirement
        .strip_prefix(PREFIX)
        .and_then(|suffix| suffix.strip_suffix('"'))
    else {
        return false;
    };
    requirement.len() <= MAX_REQUIREMENT_BYTES
        && team_identifier.len() == 10
        && team_identifier
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
}

/// Constructs the sole accepted ad-hoc manager requirement from protected enrollment.
///
/// # Errors
/// Returns invalid request for any non-canonical twenty-byte CodeDirectory hash.
pub fn local_manager_requirement(cdhash: &str) -> Result<String, NativeError> {
    if !valid_cdhash(cdhash) {
        return Err(NativeError::InvalidRequest);
    }
    Ok(format!(
        "identifier \"com.openrdx.manager\" and cdhash H\"{cdhash}\""
    ))
}

/// Accepts only the lower-case hexadecimal canonical enrollment format.
fn valid_cdhash(hash: &str) -> bool {
    hash.len() == 40
        && hash
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Record a fixed service startup/accept phase in macOS unified logging.
/// Only bounded internal phase/error text is emitted; no identity pins or paths.
pub fn log_endpoint_phase(phase: &str, error: Option<NativeError>) {
    #[cfg(target_os = "macos")]
    {
        if phase.len() > 64 {
            return;
        }
        let Ok(phase) = CString::new(phase) else {
            return;
        };
        let result = CString::new(error.map_or_else(|| "ok".into(), |error| format!("{error:?}")))
            .expect("sanitized error has no NUL");
        // SAFETY: both bounded owned strings outlive this synchronous log call.
        unsafe {
            crate::ffi::rdx_macos_log_endpoint_phase(phase.as_ptr(), result.as_ptr());
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (phase, error);
    }
}

/// Record numeric native failures without leaking raw operating-system messages.
#[cfg(target_os = "macos")]
fn log_endpoint_native_code(phase: &str, code: i32) {
    if phase.len() > 64 {
        return;
    }
    let Ok(phase) = CString::new(phase) else {
        return;
    };
    // SAFETY: the bounded internal string remains owned until the log returns.
    unsafe {
        crate::ffi::rdx_macos_log_endpoint_native_code(phase.as_ptr(), code);
    }
}
