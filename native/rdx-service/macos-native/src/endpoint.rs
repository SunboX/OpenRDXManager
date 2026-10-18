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
    #[cfg(target_os = "macos")]
    session_state: std::sync::Arc<crate::worker_factory::PeerSessionState>,
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
            let generation = crate::endpoint_diagnostics::observe_phase(
                crate::endpoint_diagnostics::AdmissionPhase::RuntimeCapture,
                || crate::runtime_generation::RuntimeGeneration::capture(&self.requirement),
                &mut log_endpoint_phase,
            )?;
            let mut socket = -1;
            let mut session = crate::peer_session::PeerSession::output_record();
            // SAFETY: the listener and requirement are owned and live, and C
            // transfers exactly one accepted descriptor only on STATUS_OK.
            let status = unsafe {
                crate::ffi::rdx_macos_accept_launchd_manager_with_session(
                    self.listener.as_raw_fd(),
                    self.requirement.as_ptr(),
                    &mut socket,
                    &mut session,
                )
            };
            let connection = connection_from_status(
                status,
                socket,
                session,
                self.requirement.clone(),
                generation,
            )?;
            // The accepted token's live strict seal proof brackets the signed runtime snapshot.
            connection.revalidate_peer_session()?;
            Ok(connection)
        }
        #[cfg(not(target_os = "macos"))]
        {
            Err(NativeError::UnsupportedPlatform)
        }
    }
}

impl ManagerEndpointConnection {
    /// Creates the sole revocable lifetime owner across all clones of this accepted connection.
    /// # Errors
    /// Returns access denied when an owner was already minted or the state is revoked.
    #[cfg(target_os = "macos")]
    pub fn begin_worker_session(&mut self) -> Result<crate::MacManagerSessionLease, NativeError> {
        self.session_state.begin()
    }

    /// Rechecks protected runtime and live exact authenticated peer/session evidence.
    ///
    /// # Errors
    /// Returns sanitized failure on peer exit, ineligible session, protected-runtime
    /// verification or pinned Manager requirement mismatch.
    /// This does not create a worker capability or prolong the framed connection lifetime.
    pub fn revalidate_peer_session(&self) -> Result<(), NativeError> {
        #[cfg(target_os = "macos")]
        {
            self.session_state
                .revalidate_peer_observed(&mut log_endpoint_phase)
        }
        #[cfg(not(target_os = "macos"))]
        {
            Err(NativeError::UnsupportedPlatform)
        }
    }

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
                    session_state: std::sync::Arc::clone(&self.session_state),
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
    session: crate::ffi::PeerSessionRecord,
    requirement: CString,
    generation: crate::runtime_generation::RuntimeGeneration,
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
    // Adopt the descriptor before validating the record so every malformed result closes it.
    let peer_session = crate::peer_session::PeerSession::from_record(session)?;
    let user_id = peer_session.user_id();
    let session_state = std::sync::Arc::new(crate::worker_factory::PeerSessionState::new(
        stream.try_clone().map_err(|_| NativeError::Other)?,
        peer_session,
        requirement,
        generation,
    ));
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
    Ok(ManagerEndpointConnection {
        stream,
        user_id,
        session_state,
    })
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

#[cfg(all(test, target_os = "macos"))]
mod session_result_tests {
    use super::*;
    use std::os::fd::IntoRawFd;

    /// A malformed successful C record must close its transferred descriptor before returning.
    #[test]
    fn peer_session_malformed_record_closes_transferred_socket() {
        let (socket, mut peer) = UnixStream::pair().unwrap();
        let requirement = CString::new("private-test-requirement").unwrap();
        let result = connection_from_status(
            crate::ffi::STATUS_OK,
            socket.into_raw_fd(),
            crate::peer_session::PeerSession::output_record(),
            requirement,
            crate::runtime_generation::RuntimeGeneration::fixture(),
        );
        assert_eq!(result.unwrap_err(), NativeError::AccessDenied);
        peer.set_nonblocking(true).unwrap();
        assert_eq!(peer.read(&mut [0; 1]).unwrap(), 0);
    }

    /// Stream duplication retains the full private record and does not expose it through Debug.
    #[test]
    fn peer_session_stream_clone_retains_private_evidence() {
        let (socket, _peer) = UnixStream::pair().unwrap();
        let record = crate::ffi::PeerSessionRecord {
            version: 1,
            size: 40,
            audit_token: [502, 502, 20, 502, 20, 123, 100_014, 7],
        };
        let mut connection = connection_from_status(
            crate::ffi::STATUS_OK,
            socket.into_raw_fd(),
            record,
            CString::new("private-test-requirement").unwrap(),
            crate::runtime_generation::RuntimeGeneration::fixture(),
        )
        .unwrap();
        let mut copy = connection.try_clone().unwrap();
        assert_eq!(copy.user_id(), 502);
        assert_eq!(copy.user_id(), connection.user_id());
        assert!(std::sync::Arc::ptr_eq(
            &copy.session_state,
            &connection.session_state
        ));
        let owner = connection.begin_worker_session().unwrap();
        assert!(copy.begin_worker_session().is_err());
        let factory = owner.factory();
        drop(owner);
        assert_eq!(factory.ensure_active(), Err(NativeError::AccessDenied));
        assert_eq!(format!("{copy:?}"), "ManagerEndpointConnection(<private>)");
    }
}
