// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Private full-token evidence retained only after native Manager authentication.

use crate::{NativeError, ffi};

/// Unexported evidence, never a standalone authorization capability.
#[derive(Clone)]
pub(crate) struct PeerSession {
    record: ffi::PeerSessionRecord,
}

impl PeerSession {
    /// Allocates a complete expected output header without fabricating authenticated evidence.
    pub(crate) fn output_record() -> ffi::PeerSessionRecord {
        ffi::PeerSessionRecord {
            version: 1,
            size: std::mem::size_of::<ffi::PeerSessionRecord>() as u32,
            audit_token: [0; 8],
        }
    }

    /// Checks the separately versioned FFI header before retaining private evidence.
    pub(crate) fn from_record(record: ffi::PeerSessionRecord) -> Result<Self, NativeError> {
        // SAFETY: a complete initialized independent record remains live during C validation.
        if !unsafe { ffi::rdx_macos_peer_session_record_is_valid(&record) } {
            return Err(NativeError::AccessDenied);
        }
        Ok(Self { record })
    }

    /// Derives the effective desktop owner without exporting the private token.
    pub(crate) fn user_id(&self) -> u32 {
        // SAFETY: the previously validated complete record remains owned and unchanged.
        unsafe { ffi::rdx_macos_peer_session_user_id(&self.record) }
    }

    /// Returns private audit-session generation for the fixed worker's context expectation only.
    pub(crate) fn audit_session_id(&self) -> u32 {
        // SAFETY: previously validated complete record remains owned and unchanged.
        unsafe { ffi::rdx_macos_peer_session_audit_session_id(&self.record) }
    }

    /// Borrows full retained evidence only for the closed native launcher, never an external caller.
    pub(crate) fn record(&self) -> &ffi::PeerSessionRecord {
        &self.record
    }

    /// Revalidates live exact peer code and session; never treats cached socket metadata as liveness.
    pub(crate) fn revalidate(
        &self,
        socket: std::os::fd::RawFd,
        requirement: &std::ffi::CStr,
    ) -> Result<(), NativeError> {
        // SAFETY: socket is borrowed from the retained connection; record and C string are owned.
        let status = unsafe {
            ffi::rdx_macos_revalidate_manager_session(socket, requirement.as_ptr(), &self.record)
        };
        crate::status_result(status)
    }
}

#[cfg(test)]
#[path = "peer_session_tests.rs"]
mod tests;
