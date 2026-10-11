// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Safe wrapper around systemd socket activation and Linux peer credentials.

use std::fmt::{Debug, Formatter};
use std::io::{Read, Write};

#[cfg(target_os = "linux")]
use std::ffi::CString;
#[cfg(target_os = "linux")]
use std::mem::{size_of, zeroed};
#[cfg(target_os = "linux")]
use std::os::fd::{AsRawFd, FromRawFd};
#[cfg(target_os = "linux")]
use std::os::unix::net::{UnixListener, UnixStream};
use std::time::Duration;
#[cfg(target_os = "linux")]
use std::time::Instant;

use crate::NativeError;

// Pin the installed regular executable, not a desktop/alternatives symlink.
// Both portable packaging evidence and the native O_NOFOLLOW open use this value.
const MANAGER_PATH: &str = "/opt/OpenRDXManager/OpenRDXManager";

/// Portable installation contract for the systemd endpoint.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SystemdEndpointContract {
    /// Fixed socket path.
    pub socket_path: &'static str,
    /// Required owner UID.
    pub owner_uid: u32,
    /// Dedicated group name.
    pub group: &'static str,
    /// Exact filesystem permission bits.
    pub mode: u32,
    /// Bounded concurrent connection count.
    pub max_connections: u32,
    /// Fixed root-installed manager identity path.
    pub manager_path: &'static str,
    /// Maximum wait for one manager connection.
    pub accept_timeout_ms: u32,
    /// Absolute maximum wait for the first complete protocol frame.
    pub handshake_timeout_ms: u32,
}

/// Returns the target-independent Linux endpoint installation contract.
#[must_use]
pub const fn systemd_endpoint_contract() -> SystemdEndpointContract {
    SystemdEndpointContract {
        socket_path: "/run/openrdx/openrdx-hardware.sock",
        owner_uid: 0,
        group: "openrdx",
        mode: 0o660,
        max_connections: 8,
        manager_path: MANAGER_PATH,
        accept_timeout_ms: 10_000,
        handshake_timeout_ms: 2_000,
    }
}

#[cfg(target_os = "linux")]
const ENDPOINT_PATH: &str = "/run/openrdx/openrdx-hardware.sock";
#[cfg(target_os = "linux")]
const SYSTEMD_LISTEN_FD: libc::c_int = 3;
#[cfg(target_os = "linux")]
const SO_PEERPIDFD: libc::c_int = 77;
#[cfg(target_os = "linux")]
const ACCEPT_TIMEOUT: Duration = Duration::from_secs(10);

#[cfg(target_os = "linux")]
struct EndpointFd(libc::c_int);

#[cfg(target_os = "linux")]
impl EndpointFd {
    fn raw(&self) -> libc::c_int {
        self.0
    }
}

#[cfg(target_os = "linux")]
impl Drop for EndpointFd {
    /// Closes the exact endpoint evidence descriptor once without retrying close.
    fn drop(&mut self) {
        // SAFETY: this guard owns one nonnegative descriptor exactly once.
        let _ = unsafe { libc::close(self.0) };
    }
}

/// One exact accepted Linux manager connection with retained stream ownership.
pub struct ManagerEndpointConnection {
    #[cfg(target_os = "linux")]
    stream: UnixStream,
    user_id: u32,
}

/// One exact retained systemd listener serving a bounded process generation.
pub struct SystemdManagerEndpointListener {
    #[cfg(target_os = "linux")]
    listener: UnixListener,
}

impl Debug for SystemdManagerEndpointListener {
    /// Redacts the native listener descriptor.
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("SystemdManagerEndpointListener(<private>)")
    }
}

impl SystemdManagerEndpointListener {
    /// Accepts and authenticates one manager while retaining socket activation.
    ///
    /// # Errors
    ///
    /// Returns a sanitized timeout, permission, identity, or native failure.
    pub fn accept(&self) -> Result<ManagerEndpointConnection, NativeError> {
        #[cfg(target_os = "linux")]
        {
            accept_native(&self.listener)
        }
        #[cfg(not(target_os = "linux"))]
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
        #[cfg(target_os = "linux")]
        {
            self.stream.set_read_timeout(timeout)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = timeout;
            Err(std::io::ErrorKind::Unsupported.into())
        }
    }

    /// Clones the exact accepted stream for framed read/write ownership.
    ///
    /// # Errors
    ///
    /// Returns a sanitized native failure if descriptor duplication fails.
    pub fn try_clone(&self) -> Result<Self, NativeError> {
        #[cfg(target_os = "linux")]
        {
            self.stream
                .try_clone()
                .map(|stream| Self {
                    stream,
                    user_id: self.user_id,
                })
                .map_err(|_| NativeError::Other)
        }
        #[cfg(not(target_os = "linux"))]
        {
            Err(NativeError::UnsupportedPlatform)
        }
    }
}

impl Debug for ManagerEndpointConnection {
    /// Redacts native descriptors and peer details.
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ManagerEndpointConnection(<private>)")
    }
}

impl Read for ManagerEndpointConnection {
    /// Reads framed bytes from the authenticated local connection.
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        #[cfg(target_os = "linux")]
        {
            self.stream.read(buffer)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = buffer;
            Err(std::io::ErrorKind::Unsupported.into())
        }
    }
}

impl Write for ManagerEndpointConnection {
    /// Writes framed bytes to the authenticated local connection.
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        #[cfg(target_os = "linux")]
        {
            self.stream.write(buffer)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = buffer;
            Err(std::io::ErrorKind::Unsupported.into())
        }
    }

    /// Flushes framed bytes to the authenticated local connection.
    fn flush(&mut self) -> std::io::Result<()> {
        #[cfg(target_os = "linux")]
        {
            self.stream.flush()
        }
        #[cfg(not(target_os = "linux"))]
        {
            Err(std::io::ErrorKind::Unsupported.into())
        }
    }
}

/// Adopts the one exact systemd listener and authenticates one manager peer.
///
/// Activation claims are accepted only in a root process and must match the
/// current PID, exact fd count/name, root-owned mode-0660 socket, configured
/// `openrdx` group, live kernel pidfd, peer group membership, and the fixed
/// root-owned manager executable inode.
///
/// # Errors
///
/// Returns a sanitized activation, permission, identity, or native failure.
pub fn accept_systemd_manager_endpoint() -> Result<ManagerEndpointConnection, NativeError> {
    activate_systemd_manager_endpoint()?.accept()
}

/// Adopts the exact systemd activation descriptor once for sequential accepts.
///
/// # Errors
///
/// Returns a sanitized activation or metadata failure without accepting a peer.
pub fn activate_systemd_manager_endpoint() -> Result<SystemdManagerEndpointListener, NativeError> {
    #[cfg(target_os = "linux")]
    {
        validate_activation()?;
        // SAFETY: validation proves fd 3 is the sole exact systemd AF_UNIX
        // listener; ownership transfers exactly once to this RAII wrapper.
        let listener = unsafe { UnixListener::from_raw_fd(SYSTEMD_LISTEN_FD) };
        // SAFETY: activation occurs before service runtime threads start; clearing
        // claims prevents a second adoption of the same owned descriptor.
        unsafe {
            std::env::remove_var("LISTEN_PID");
            std::env::remove_var("LISTEN_FDS");
            std::env::remove_var("LISTEN_FDNAMES");
        }
        Ok(SystemdManagerEndpointListener { listener })
    }
    #[cfg(not(target_os = "linux"))]
    {
        Err(NativeError::UnsupportedPlatform)
    }
}

#[cfg(target_os = "linux")]
fn accept_native(listener: &UnixListener) -> Result<ManagerEndpointConnection, NativeError> {
    wait_for_manager(listener)?;
    let (stream, _) = listener.accept().map_err(|_| NativeError::Other)?;
    let user_id = authenticate_peer(&stream)?;
    stream
        .set_read_timeout(Some(Duration::from_secs(300)))
        .map_err(|_| NativeError::Other)?;
    stream
        .set_write_timeout(Some(Duration::from_secs(30)))
        .map_err(|_| NativeError::Other)?;
    Ok(ManagerEndpointConnection { stream, user_id })
}

#[cfg(target_os = "linux")]
fn validate_activation() -> Result<(), NativeError> {
    // SAFETY: `geteuid` has no pointer arguments or memory side effects.
    if unsafe { libc::geteuid() } != 0
        || std::env::var("LISTEN_PID")
            .ok()
            .and_then(|value| value.parse::<u32>().ok())
            != Some(std::process::id())
        || std::env::var("LISTEN_FDS").ok().as_deref() != Some("1")
        || std::env::var("LISTEN_FDNAMES").ok().as_deref() != Some("Listener")
    {
        return Err(NativeError::AccessDenied);
    }
    let status = stat_fd(SYSTEMD_LISTEN_FD)?;
    if status.st_mode & libc::S_IFMT != libc::S_IFSOCK {
        return Err(NativeError::EvidenceIncomplete);
    }
    let path_status = stat_path(ENDPOINT_PATH)?;
    let directory_status = stat_path("/run/openrdx")?;
    let group_id = configured_group_id()?;
    if path_status.st_mode & libc::S_IFMT != libc::S_IFSOCK
        || path_status.st_uid != 0
        || path_status.st_gid != group_id
        || path_status.st_mode & 0o777 != 0o660
        || directory_status.st_mode & libc::S_IFMT != libc::S_IFDIR
        || directory_status.st_uid != 0
        || directory_status.st_gid != group_id
        || directory_status.st_mode & 0o777 != 0o750
    {
        return Err(NativeError::AccessDenied);
    }
    // SAFETY: zero initializes the output-only sockaddr storage.
    let mut address: libc::sockaddr_un = unsafe { zeroed() };
    let mut address_length = size_of::<libc::sockaddr_un>() as libc::socklen_t;
    // SAFETY: address and length are valid writable storage for this descriptor.
    if unsafe {
        libc::getsockname(
            SYSTEMD_LISTEN_FD,
            (&mut address as *mut libc::sockaddr_un).cast(),
            &mut address_length,
        )
    } != 0
        || address.sun_family != libc::AF_UNIX as libc::sa_family_t
        || !unix_address_matches(&address, ENDPOINT_PATH.as_bytes())
    {
        return Err(NativeError::EvidenceIncomplete);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn wait_for_manager(listener: &UnixListener) -> Result<(), NativeError> {
    let deadline = Instant::now() + ACCEPT_TIMEOUT;
    loop {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .ok_or(NativeError::TimedOut)?;
        let milliseconds = remaining.as_millis().clamp(1, libc::c_int::MAX as u128) as libc::c_int;
        let mut descriptor = libc::pollfd {
            fd: listener.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: descriptor is initialized writable storage for one borrowed fd.
        let result = unsafe { libc::poll(&mut descriptor, 1, milliseconds) };
        if result > 0 && descriptor.revents & libc::POLLIN != 0 {
            return Ok(());
        }
        if result == 0 {
            return Err(NativeError::TimedOut);
        }
        if result < 0 && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
            continue;
        }
        return Err(NativeError::Other);
    }
}

#[cfg(target_os = "linux")]
fn authenticate_peer(stream: &UnixStream) -> Result<u32, NativeError> {
    // SAFETY: zero initializes the output-only peer credential storage.
    let mut credentials: libc::ucred = unsafe { zeroed() };
    let mut credentials_length = size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: getsockopt writes one bounded ucred to initialized storage.
    if unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut credentials as *mut libc::ucred).cast(),
            &mut credentials_length,
        )
    } != 0
        || credentials_length as usize != size_of::<libc::ucred>()
        || credentials.pid <= 0
    {
        return Err(NativeError::AccessDenied);
    }
    let mut raw_pidfd = -1;
    let mut pidfd_length = size_of::<libc::c_int>() as libc::socklen_t;
    // SAFETY: Linux writes one owned pidfd scalar for the accepted peer.
    if unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            SO_PEERPIDFD,
            (&mut raw_pidfd as *mut libc::c_int).cast(),
            &mut pidfd_length,
        )
    } != 0
        || raw_pidfd < 0
    {
        return Err(NativeError::AccessDenied);
    }
    let pidfd = EndpointFd(raw_pidfd);
    let result = if pidfd_is_live(pidfd.raw()) {
        authenticate_live_process(credentials).and_then(|()| {
            pidfd_is_live(pidfd.raw())
                .then_some(())
                .ok_or(NativeError::AccessDenied)
        })
    } else {
        Err(NativeError::AccessDenied)
    };
    result.map(|()| credentials.uid)
}

#[cfg(target_os = "linux")]
fn pidfd_is_live(pidfd: libc::c_int) -> bool {
    let mut descriptor = libc::pollfd {
        fd: pidfd,
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: descriptor is valid writable storage for a nonblocking single-fd poll.
    (unsafe { libc::poll(&mut descriptor, 1, 0) }) == 0 && descriptor.revents == 0
}

#[cfg(target_os = "linux")]
fn authenticate_live_process(credentials: libc::ucred) -> Result<(), NativeError> {
    let expected = open_path(
        MANAGER_PATH,
        libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
    )?;
    let peer_path = CString::new(format!("/proc/{}/exe", credentials.pid))
        .map_err(|_| NativeError::EvidenceIncomplete)?;
    let peer = open_c_path(&peer_path, libc::O_PATH | libc::O_CLOEXEC)?;
    let expected_status = stat_fd(expected.raw())?;
    let peer_status = stat_fd(peer.raw())?;
    let group_id = configured_group_id()?;
    if expected_status.st_mode & libc::S_IFMT != libc::S_IFREG
        || expected_status.st_uid != 0
        || expected_status.st_mode & 0o022 != 0
        || expected_status.st_dev != peer_status.st_dev
        || expected_status.st_ino != peer_status.st_ino
        || !process_has_group(credentials.pid, group_id)?
    {
        return Err(NativeError::AccessDenied);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn process_has_group(pid: libc::pid_t, group_id: libc::gid_t) -> Result<bool, NativeError> {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status"))
        .map_err(|_| NativeError::EvidenceIncomplete)?;
    if status.len() > 65_536 {
        return Err(NativeError::ResourceLimit);
    }
    Ok(status
        .lines()
        .find_map(|line| line.strip_prefix("Groups:"))
        .is_some_and(|groups| {
            groups
                .split_ascii_whitespace()
                .any(|group| group.parse::<u32>() == Ok(group_id))
        }))
}

#[cfg(target_os = "linux")]
fn open_path(path: &str, flags: libc::c_int) -> Result<EndpointFd, NativeError> {
    let path = CString::new(path).map_err(|_| NativeError::EvidenceIncomplete)?;
    open_c_path(&path, flags)
}

#[cfg(target_os = "linux")]
fn open_c_path(path: &CString, flags: libc::c_int) -> Result<EndpointFd, NativeError> {
    // SAFETY: path is NUL-terminated and the return descriptor is caller-owned.
    let descriptor = unsafe { libc::open(path.as_ptr(), flags) };
    if descriptor < 0 {
        Err(NativeError::AccessDenied)
    } else {
        Ok(EndpointFd(descriptor))
    }
}

#[cfg(target_os = "linux")]
fn stat_fd(descriptor: libc::c_int) -> Result<libc::stat, NativeError> {
    // SAFETY: zero initializes the output-only stat storage.
    let mut status: libc::stat = unsafe { zeroed() };
    // SAFETY: status is valid writable storage and descriptor is borrowed.
    if unsafe { libc::fstat(descriptor, &mut status) } == 0 {
        Ok(status)
    } else {
        Err(NativeError::EvidenceIncomplete)
    }
}

#[cfg(target_os = "linux")]
fn stat_path(path: &str) -> Result<libc::stat, NativeError> {
    let path = CString::new(path).map_err(|_| NativeError::EvidenceIncomplete)?;
    // SAFETY: zero initializes the output-only stat storage.
    let mut status: libc::stat = unsafe { zeroed() };
    // SAFETY: path is NUL-terminated and status is valid writable storage.
    if unsafe { libc::lstat(path.as_ptr(), &mut status) } == 0 {
        Ok(status)
    } else {
        Err(NativeError::EvidenceIncomplete)
    }
}

#[cfg(target_os = "linux")]
fn unix_address_matches(address: &libc::sockaddr_un, expected: &[u8]) -> bool {
    expected.len() < address.sun_path.len()
        && address.sun_path[..expected.len()]
            .iter()
            .zip(expected)
            .all(|(actual, expected)| *actual as u8 == *expected)
        && address.sun_path[expected.len()] == 0
}

#[cfg(target_os = "linux")]
fn configured_group_id() -> Result<u32, NativeError> {
    let contents = std::fs::read("/etc/group").map_err(|_| NativeError::AccessDenied)?;
    if contents.len() > 1024 * 1024 {
        return Err(NativeError::ResourceLimit);
    }
    crate::readiness::configured_group_gid(&contents).ok_or(NativeError::AccessDenied)
}
