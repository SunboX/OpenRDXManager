// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Revocable authority owned by one authenticated Manager connection.

use crate::{NativeError, peer_session::PeerSession, runtime_generation::RuntimeGeneration};
use std::{
    ffi::CString,
    fmt,
    os::{fd::AsRawFd, unix::net::UnixStream},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
};

/// Accepted immutable kernel/code/generation evidence shared by stream clones, never caller-created.
pub(crate) struct PeerSessionState {
    stream: UnixStream,
    peer: PeerSession,
    requirement: CString,
    generation: RuntimeGeneration,
    credentials: [u32; 5],
    claimed: AtomicBool,
    active: Mutex<bool>,
}

impl PeerSessionState {
    /// Retains a separate close-on-exec socket descriptor so IO clones cannot replace peer evidence.
    pub(crate) fn new(
        stream: UnixStream,
        peer: PeerSession,
        requirement: CString,
        generation: RuntimeGeneration,
    ) -> Self {
        Self {
            stream,
            peer,
            requirement,
            generation,
            credentials: credentials(),
            claimed: AtomicBool::new(false),
            active: Mutex::new(true),
        }
    }

    /// Mints at most one unique lifetime owner across every reader/writer clone.
    pub(crate) fn begin(self: &Arc<Self>) -> Result<MacManagerSessionLease, NativeError> {
        self.claimed
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| NativeError::AccessDenied)?;
        let factory = MacWorkerFactory {
            state: Arc::clone(self),
        };
        factory.ensure_active()?;
        Ok(MacManagerSessionLease { factory })
    }

    /// Brackets the full protected runtime snapshot with fresh token-bound live code/session proof.
    pub(crate) fn revalidate_peer(&self) -> Result<(), NativeError> {
        self.peer
            .revalidate(self.stream.as_raw_fd(), &self.requirement)?;
        self.generation.revalidate(&self.requirement)?;
        self.peer
            .revalidate(self.stream.as_raw_fd(), &self.requirement)
    }
}

/// Sole owner of one accepted Manager connection's worker authority.
/// This type is deliberately neither Clone nor Copy; dropping it will end the connection authority.
pub struct MacManagerSessionLease {
    factory: MacWorkerFactory,
}

impl MacManagerSessionLease {
    /// Returns a shared handle whose lifetime never extends this owner's authority.
    #[must_use]
    pub fn factory(&self) -> MacWorkerFactory {
        self.factory.clone()
    }

    /// Permanently closes admission without interrupting existing finite native operations.
    pub fn revoke(&self) {
        self.factory.revoke();
    }
}

impl Drop for MacManagerSessionLease {
    /// Unique owner teardown invalidates every retained factory handle permanently.
    fn drop(&mut self) {
        self.revoke();
    }
}

/// Nonforgeable shared worker authority for exactly one accepted connection.
#[derive(Clone)]
pub struct MacWorkerFactory {
    state: Arc<PeerSessionState>,
}

impl MacWorkerFactory {
    /// Checks only the short shared admission gate; performs no code, filesystem or device IO.
    /// # Errors
    /// Returns access denied after revocation or a poisoned gate.
    pub fn ensure_active(&self) -> Result<(), NativeError> {
        let active = self
            .state
            .active
            .lock()
            .map_err(|_| NativeError::AccessDenied)?;
        if !*active {
            return Err(NativeError::AccessDenied);
        }
        Ok(())
    }

    /// Permanently closes admission, including when a native verifier is stalled outside the gate.
    pub fn revoke(&self) {
        *self
            .state
            .active
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = false;
    }

    /// Revalidates this live exact peer and full generation without holding the admission mutex.
    /// # Errors
    /// Returns access denied for revoked authority, changed service credentials or failed native proof.
    pub fn revalidate(&self) -> Result<(), NativeError> {
        self.revalidate_with(|state| {
            if state.credentials != credentials()
                || state.credentials[0] != 0
                || state.credentials[1] != 0
            {
                return Err(NativeError::AccessDenied);
            }
            state.revalidate_peer()
        })
    }

    /// Keeps expensive proof outside the gate; the second check refuses a concurrently revoked result.
    fn revalidate_with(
        &self,
        verify: impl FnOnce(&PeerSessionState) -> Result<(), NativeError>,
    ) -> Result<(), NativeError> {
        self.ensure_active()?;
        if let Err(error) = verify(&self.state) {
            // Once invalid evidence has been observed, restoring files/session
            // metadata cannot resurrect the old connection's authority.
            self.revoke();
            return Err(error);
        }
        self.ensure_active()
    }
}

impl fmt::Debug for MacWorkerFactory {
    /// Redacts all descriptors, credentials, code pins and session metadata.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("MacWorkerFactory(<private>)")
    }
}

impl PartialEq for MacWorkerFactory {
    /// Equality means the same revocable connection state, never UID equivalence.
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.state, &other.state)
    }
}
impl Eq for MacWorkerFactory {}

/// Captures actual service credentials and PID, preventing reuse in a changed or forked process.
fn credentials() -> [u32; 5] {
    // SAFETY: these public getters have no pointer arguments or preconditions.
    unsafe {
        [
            libc::getuid(),
            libc::geteuid(),
            libc::getgid(),
            libc::getegid(),
            libc::getpid() as u32,
        ]
    }
}

#[cfg(test)]
#[path = "worker_factory_tests.rs"]
mod tests;
