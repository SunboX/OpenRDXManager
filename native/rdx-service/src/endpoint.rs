// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Fixed privileged endpoint selection and accept-time peer authorization.

use std::fmt::{Display, Formatter};
use std::io::{self, Read};
use std::time::{Duration, Instant, SystemTime};

#[cfg(target_os = "macos")]
use std::fs::File;
#[cfg(target_os = "macos")]
use std::os::unix::fs::MetadataExt;

use crate::service::MAX_SERVICE_FRAME_BYTES;

const MAX_APPLICATION_IDENTITY_BYTES: usize = 128;
const MAX_PEER_EVIDENCE_AGE: Duration = Duration::from_secs(5);
#[cfg(target_os = "macos")]
const MACOS_MANAGER_REQUIREMENT_PATH: &str =
    "/Library/PrivilegedHelperTools/com.openrdx.manager.requirement";

const MACOS_MANAGER_REQUIREMENT_PREFIX: &str = "identifier \"com.openrdx.manager\" and anchor apple generic and certificate leaf[subject.OU] = \"";

/// Constructs the one accepted manager requirement from a signing team.
///
/// # Errors
///
/// Returns insufficient permission unless the team is exactly ten upper-case
/// ASCII letters or digits.
pub fn macos_manager_designated_requirement_for_team(
    team_identifier: Option<&str>,
) -> Result<String, EndpointAccessError> {
    let Some(team_identifier) = team_identifier else {
        return Err(EndpointAccessError::InsufficientPermission);
    };
    if team_identifier.len() != 10
        || !team_identifier
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
    {
        return Err(EndpointAccessError::InsufficientPermission);
    }
    Ok(format!(
        "{MACOS_MANAGER_REQUIREMENT_PREFIX}{team_identifier}\""
    ))
}

/// Returns the manager requirement embedded by the controlled package build.
///
/// # Errors
///
/// Returns insufficient permission when this binary was not built for one
/// exact signed manager team.
pub fn embedded_macos_manager_designated_requirement() -> Result<String, EndpointAccessError> {
    macos_manager_designated_requirement_for_team(option_env!("OPENRDX_MANAGER_TEAM_ID"))
}

/// A framed endpoint reader that enforces one absolute first-frame deadline.
///
/// The timeout callback configures the native transport before each partial
/// read. Once the complete four-byte length prefix and first bounded payload
/// have arrived, the native timeout is cleared exactly once. Subsequent frames
/// retain the service protocol's existing behavior.
pub struct HandshakeDeadlineReader<R, F> {
    inner: R,
    set_timeout: F,
    deadline: Instant,
    prefix: [u8; 4],
    prefix_bytes: usize,
    observed_bytes: usize,
    first_frame_bytes: Option<usize>,
    established: bool,
}

impl<R, F> HandshakeDeadlineReader<R, F>
where
    R: Read,
    F: FnMut(&mut R, Option<Duration>) -> io::Result<()>,
{
    /// Creates one reader and immediately arms its absolute handshake timeout.
    ///
    /// # Errors
    ///
    /// Returns `InvalidInput` for a zero timeout, or propagates a native timeout
    /// configuration failure before any endpoint bytes are consumed.
    pub fn new(mut inner: R, timeout: Duration, mut set_timeout: F) -> io::Result<Self> {
        if timeout.is_zero() {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let deadline = Instant::now()
            .checked_add(timeout)
            .ok_or(io::ErrorKind::InvalidInput)?;
        set_timeout(&mut inner, Some(timeout))?;
        Ok(Self {
            inner,
            set_timeout,
            deadline,
            prefix: [0; 4],
            prefix_bytes: 0,
            observed_bytes: 0,
            first_frame_bytes: None,
            established: false,
        })
    }

    /// Returns the owned reader after endpoint processing completes.
    #[must_use]
    pub fn into_inner(self) -> R {
        self.inner
    }

    /// Accounts for newly read bytes and clears the timeout after frame one.
    fn observe(&mut self, bytes: &[u8]) -> io::Result<()> {
        let old_observed = self.observed_bytes;
        self.observed_bytes = self.observed_bytes.saturating_add(bytes.len());
        if self.prefix_bytes < self.prefix.len() {
            let needed = self.prefix.len() - self.prefix_bytes;
            let count = needed.min(bytes.len());
            self.prefix[self.prefix_bytes..self.prefix_bytes + count]
                .copy_from_slice(&bytes[..count]);
            self.prefix_bytes += count;
            if self.prefix_bytes == self.prefix.len() {
                let payload_bytes = u32::from_be_bytes(self.prefix) as usize;
                if payload_bytes == 0 || payload_bytes > MAX_SERVICE_FRAME_BYTES {
                    return Err(io::ErrorKind::InvalidData.into());
                }
                self.first_frame_bytes = Some(self.prefix.len() + payload_bytes);
            }
        }
        if !self.established
            && self
                .first_frame_bytes
                .is_some_and(|frame_bytes| self.observed_bytes >= frame_bytes)
        {
            (self.set_timeout)(&mut self.inner, None)?;
            self.established = true;
        }
        debug_assert!(self.observed_bytes >= old_observed);
        Ok(())
    }
}

impl<R, F> Read for HandshakeDeadlineReader<R, F>
where
    R: Read,
    F: FnMut(&mut R, Option<Duration>) -> io::Result<()>,
{
    /// Reads bytes while maintaining the remaining absolute handshake timeout.
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if !self.established {
            let remaining = self
                .deadline
                .checked_duration_since(Instant::now())
                .ok_or(io::ErrorKind::TimedOut)?;
            if remaining.is_zero() {
                return Err(io::ErrorKind::TimedOut.into());
            }
            (self.set_timeout)(&mut self.inner, Some(remaining))?;
        }
        let count = self.inner.read(buffer)?;
        if count > 0 && !self.established {
            self.observe(&buffer[..count])?;
        }
        Ok(count)
    }
}

/// Supported native service endpoint families.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EndpointPlatform {
    /// Local Windows named pipe.
    Windows,
    /// Root-owned systemd Unix socket.
    Linux,
    /// Root-owned launchd Unix socket.
    MacOs,
}

/// Main-owned endpoint selection with no caller-provided native address.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServiceEndpoint {
    /// Explicit development/test-only stdin/stdout transport.
    DevelopmentStdio,
    /// Windows service named pipe.
    WindowsNamedPipe,
    /// Linux systemd socket.
    LinuxUnixSocket,
    /// macOS launchd socket.
    MacOsUnixSocket,
}

impl ServiceEndpoint {
    /// Selects the explicitly non-privileged development transport.
    #[must_use]
    pub const fn development_stdio() -> Self {
        Self::DevelopmentStdio
    }

    /// Selects the fixed privileged endpoint for one supported platform.
    #[must_use]
    pub const fn production(platform: EndpointPlatform) -> Self {
        match platform {
            EndpointPlatform::Windows => Self::WindowsNamedPipe,
            EndpointPlatform::Linux => Self::LinuxUnixSocket,
            EndpointPlatform::MacOs => Self::MacOsUnixSocket,
        }
    }

    /// Returns the fixed diagnostic address without accepting a caller path.
    #[must_use]
    pub const fn address(self) -> &'static str {
        match self {
            Self::DevelopmentStdio => "stdio",
            Self::WindowsNamedPipe => r"\\.\pipe\OpenRDXHardwareService",
            Self::LinuxUnixSocket => "/run/openrdx/openrdx-hardware.sock",
            Self::MacOsUnixSocket => "/var/run/openrdx-hardware.sock",
        }
    }

    /// Reports whether this endpoint is the explicit non-production transport.
    #[must_use]
    pub const fn is_development_stdio(self) -> bool {
        matches!(self, Self::DevelopmentStdio)
    }

    /// Rejects production mutation authority on the stdio development endpoint.
    ///
    /// # Errors
    ///
    /// Returns `insufficient-permission` for development stdio.
    pub const fn require_production_mutation_authority(self) -> Result<(), EndpointAccessError> {
        if self.is_development_stdio() {
            Err(EndpointAccessError::InsufficientPermission)
        } else {
            Ok(())
        }
    }
}

/// Native assurance attached to peer evidence at socket/pipe accept time.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PeerVerification {
    /// Only kernel credentials were proven; application identity is not trusted.
    KernelCredentialsOnly,
    /// Kernel credentials and platform code identity were both proven.
    KernelCredentialsAndCodeIdentity,
}

/// Pointer-free evidence copied from a native accept-time verifier.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObservedPeer {
    user_id: u32,
    application_identity: Box<str>,
    verification: PeerVerification,
    observed_at: SystemTime,
}

impl ObservedPeer {
    /// Creates deterministic evidence for policy tests and native-wrapper tests.
    ///
    /// This constructor is not an authorization source. Production accepters
    /// must populate the same record only after native credential and code-signing
    /// checks; [`PeerPolicy::authorize`] independently rejects weak evidence.
    #[must_use]
    pub fn for_fixture(
        user_id: u32,
        application_identity: &str,
        verification: PeerVerification,
        observed_at: SystemTime,
    ) -> Self {
        Self {
            user_id,
            application_identity: application_identity.into(),
            verification,
            observed_at,
        }
    }
}

/// Exact user/application policy evaluated once for an accepted connection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PeerPolicy {
    user_id: u32,
    application_identity: Box<str>,
    configured_at: SystemTime,
}

impl PeerPolicy {
    /// Creates a deterministic policy used by accept-boundary fixtures.
    ///
    /// Invalid application identities remain fail-closed during authorization.
    #[must_use]
    pub fn for_fixture_user(
        user_id: u32,
        application_identity: &str,
        configured_at: SystemTime,
    ) -> Self {
        Self {
            user_id,
            application_identity: application_identity.into(),
            configured_at,
        }
    }

    /// Authorizes exact fresh native evidence for the configured application.
    ///
    /// # Errors
    ///
    /// Rejects missing/weak identity, user or application mismatch, malformed
    /// policy text, future observations, and observations older than five seconds.
    pub fn authorize(
        &self,
        peer: &ObservedPeer,
        accepted_at: SystemTime,
    ) -> Result<PeerAuthorization, EndpointAccessError> {
        let age = accepted_at
            .duration_since(peer.observed_at)
            .map_err(|_| EndpointAccessError::StalePeer)?;
        if peer.observed_at < self.configured_at || age > MAX_PEER_EVIDENCE_AGE {
            return Err(EndpointAccessError::StalePeer);
        }
        if !valid_application_identity(&self.application_identity)
            || peer.verification != PeerVerification::KernelCredentialsAndCodeIdentity
            || peer.user_id != self.user_id
            || peer.application_identity != self.application_identity
        {
            return Err(EndpointAccessError::UnauthorizedPeer);
        }
        Ok(PeerAuthorization {
            user_id: peer.user_id,
            application_identity: peer.application_identity.clone(),
        })
    }
}

/// Non-serializable authorization retained for one accepted connection only.
#[derive(Debug, Eq, PartialEq)]
pub struct PeerAuthorization {
    user_id: u32,
    application_identity: Box<str>,
}

impl PeerAuthorization {
    /// Returns the kernel-proven user identifier.
    #[must_use]
    pub const fn user_id(&self) -> u32 {
        self.user_id
    }

    /// Returns the native-verified application identity.
    #[must_use]
    pub fn application_identity(&self) -> &str {
        &self.application_identity
    }
}

/// Sanitized endpoint authorization failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EndpointAccessError {
    /// Peer credentials or code identity did not match policy.
    UnauthorizedPeer,
    /// Peer evidence was not contemporaneous with connection acceptance.
    StalePeer,
    /// The selected transport is not a privileged production endpoint.
    InsufficientPermission,
}

impl EndpointAccessError {
    /// Returns the path-free renderer-safe failure code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::UnauthorizedPeer => "unauthorized-service-peer",
            Self::StalePeer => "stale-service-peer",
            Self::InsufficientPermission => "insufficient-permission",
        }
    }
}

impl Display for EndpointAccessError {
    /// Formats only the sanitized stable code.
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for EndpointAccessError {}

/// Loads the root-provisioned manager designated requirement from a fixed path.
///
/// The already-open file must be a root-owned, single-link regular file with
/// mode `0600`; the read is bounded and returned text is trimmed once.
///
/// # Errors
///
/// Returns a sanitized authorization failure for absent, ambiguous, oversized,
/// non-UTF-8, or weakly protected requirement evidence.
#[cfg(target_os = "macos")]
pub fn load_macos_manager_designated_requirement() -> Result<String, EndpointAccessError> {
    let file = File::open(MACOS_MANAGER_REQUIREMENT_PATH)
        .map_err(|_| EndpointAccessError::InsufficientPermission)?;
    let metadata = file
        .metadata()
        .map_err(|_| EndpointAccessError::InsufficientPermission)?;
    if !metadata.is_file()
        || metadata.uid() != 0
        || metadata.nlink() != 1
        || metadata.mode() & 0o777 != 0o600
    {
        return Err(EndpointAccessError::InsufficientPermission);
    }
    let mut bounded = String::new();
    file.take((MAX_APPLICATION_IDENTITY_BYTES as u64 * 16) + 1)
        .read_to_string(&mut bounded)
        .map_err(|_| EndpointAccessError::InsufficientPermission)?;
    if bounded.len() > MAX_APPLICATION_IDENTITY_BYTES * 16 {
        return Err(EndpointAccessError::InsufficientPermission);
    }
    let requirement = bounded.trim();
    if requirement.is_empty() || requirement.len() != bounded.trim_end().len() {
        return Err(EndpointAccessError::InsufficientPermission);
    }
    Ok(requirement.to_owned())
}

/// Validates one bounded reverse-domain application identifier.
fn valid_application_identity(identity: &str) -> bool {
    !identity.is_empty()
        && identity.len() <= MAX_APPLICATION_IDENTITY_BYTES
        && identity
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
        && identity.contains('.')
}
