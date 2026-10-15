// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Private, fixed-width child context evidence; this module never opens a device.

use crate::{NativeError, peer_session::PeerSession};

pub(super) const CONTEXT_BYTES: usize = 72;
pub(super) const EXPECTATION_BYTES: usize = 40;

/// Private public-API observations; never serialized into public diagnostics or Debug output.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub(super) struct WorkerContext {
    version: u32,
    size: u32,
    uid: u32,
    euid: u32,
    gid: u32,
    egid: u32,
    pid: u32,
    ppid: u32,
    auid: u32,
    audit_euid: u32,
    audit_egid: u32,
    audit_ruid: u32,
    audit_rgid: u32,
    audit_pid: u32,
    asid: u32,
    pid_version: u32,
    session: u32,
    attributes: u32,
}

/// Fixed private GUI expectation, derived only from native capability and actual service/child.
#[derive(Clone, Copy)]
pub(super) struct WorkerExpectation {
    uid: u32,
    asid: u32,
    pid: u32,
    ppid: u32,
    gid: u32,
    egid: u32,
}

impl WorkerExpectation {
    /// Internal synthetic policy fixture only; cannot authenticate a peer or enter the GUI factory.
    #[cfg(test)]
    pub(super) fn fixture_for_pid(pid: u32) -> Self {
        Self {
            uid: 502,
            asid: 100_014,
            pid,
            ppid: std::process::id(),
            gid: 20,
            egid: 20,
        }
    }
    /// Derives expectations solely from native connection evidence and actual service/owned child.
    pub(super) fn gui(
        peer: &PeerSession,
        credentials: [u32; 5],
        pid: u32,
    ) -> Result<Self, NativeError> {
        if credentials[0] != 0 || credentials[1] != 0 {
            return Err(NativeError::AccessDenied);
        }
        let expected = Self {
            uid: peer.user_id(),
            asid: peer.audit_session_id(),
            pid,
            ppid: credentials[4],
            gid: credentials[2],
            egid: credentials[3],
        };
        expected.validate()?;
        Ok(expected)
    }

    /// Rejects malformed internal requests; this shape check cannot grant a native capability.
    fn validate(&self) -> Result<(), NativeError> {
        if self.uid == 0
            || self.uid >= u32::MAX - 1
            || self.asid == 0
            || self.asid >= u32::MAX - 1
            || self.pid == 0
            || self.pid > i32::MAX as u32
            || self.ppid == 0
            || self.ppid > i32::MAX as u32
        {
            return Err(NativeError::AccessDenied);
        }
        Ok(())
    }

    /// Encodes only the fixed private request; peer metadata never reaches public diagnostics.
    pub(super) fn encode(&self) -> Vec<u8> {
        encode_words(&[
            1,
            EXPECTATION_BYTES as u32,
            1,
            self.uid,
            self.uid,
            self.asid,
            self.ppid,
            self.gid,
            self.egid,
            self.pid,
        ])
    }

    /// Reads a strict fixed request without accepting arbitrary modes or credential selectors.
    pub(super) fn decode(bytes: &[u8]) -> Result<Self, NativeError> {
        let words = decode_words::<10>(bytes)?;
        if words[..3] != [1, EXPECTATION_BYTES as u32, 1] || words[3] != words[4] {
            return Err(NativeError::InvalidRequest);
        }
        let expected = Self {
            uid: words[3],
            asid: words[5],
            ppid: words[6],
            gid: words[7],
            egid: words[8],
            pid: words[9],
        };
        expected.validate()?;
        Ok(expected)
    }

    /// Checks proof against this fixed request and the actual retained process, not a reported PID.
    pub(super) fn verify(
        &self,
        observed: &WorkerContext,
        owned_child_pid: u32,
    ) -> Result<(), NativeError> {
        verify_child_context(self, observed, owned_child_pid)
    }
}

impl WorkerContext {
    /// Synthetic policy/pipe fixture only; cannot satisfy a production native capability check.
    #[cfg(test)]
    pub(super) fn matching_fixture(expected: &WorkerExpectation) -> Self {
        let actual = Self::current().expect("ordinary self-only audit fixture");
        Self {
            version: 1,
            size: CONTEXT_BYTES as u32,
            uid: 0,
            euid: 0,
            gid: expected.gid,
            egid: expected.egid,
            pid: actual.pid,
            ppid: actual.ppid,
            auid: expected.uid,
            audit_euid: 0,
            audit_egid: expected.egid,
            audit_ruid: 0,
            audit_rgid: expected.gid,
            audit_pid: actual.audit_pid,
            asid: expected.asid,
            pid_version: actual.pid_version,
            session: expected.asid,
            attributes: 0x6030,
        }
    }
    /// Obtains this actual process's full public audit/session/credential observations before IOKit.
    pub(super) fn current() -> Result<Self, NativeError> {
        let mut output = Self::default();
        // SAFETY: the initialized output has the independently compiler-checked 72-byte C layout.
        crate::status_result(unsafe { rdx_macos_copy_worker_context(&mut output) })?;
        if output.version != 1 || output.size != CONTEXT_BYTES as u32 {
            return Err(NativeError::AccessDenied);
        }
        Ok(output)
    }

    /// Encodes closed-width private observations without unsafe memory serialization or raw text.
    pub(super) fn encode(&self) -> Vec<u8> {
        encode_words(&[
            self.version,
            self.size,
            self.uid,
            self.euid,
            self.gid,
            self.egid,
            self.pid,
            self.ppid,
            self.auid,
            self.audit_euid,
            self.audit_egid,
            self.audit_ruid,
            self.audit_rgid,
            self.audit_pid,
            self.asid,
            self.pid_version,
            self.session,
            self.attributes,
        ])
    }

    /// Rejects any length/version drift before retaining observations from the owned private pipe.
    pub(super) fn decode(bytes: &[u8]) -> Result<Self, NativeError> {
        let words = decode_words::<18>(bytes)?;
        if words[0] != 1 || words[1] != CONTEXT_BYTES as u32 {
            return Err(NativeError::InvalidRequest);
        }
        Ok(Self {
            version: words[0],
            size: words[1],
            uid: words[2],
            euid: words[3],
            gid: words[4],
            egid: words[5],
            pid: words[6],
            ppid: words[7],
            auid: words[8],
            audit_euid: words[9],
            audit_egid: words[10],
            audit_ruid: words[11],
            audit_rgid: words[12],
            audit_pid: words[13],
            asid: words[14],
            pid_version: words[15],
            session: words[16],
            attributes: words[17],
        })
    }
}

/// Serializes only explicit little-endian words, never C padding or caller strings.
fn encode_words(words: &[u32]) -> Vec<u8> {
    words.iter().flat_map(|word| word.to_le_bytes()).collect()
}

/// Checks length before fixed-width decoding; malformed records cannot allocate from a caller size.
fn decode_words<const N: usize>(bytes: &[u8]) -> Result<[u32; N], NativeError> {
    if bytes.len() != N * 4 {
        return Err(NativeError::InvalidRequest);
    }
    Ok(std::array::from_fn(|index| {
        u32::from_le_bytes(
            bytes[index * 4..index * 4 + 4]
                .try_into()
                .expect("fixed word"),
        )
    }))
}

// SAFETY: declaration mirrors the independent fixed C record; no system ownership crosses this call.
unsafe extern "C" {
    fn rdx_macos_copy_worker_context(output: *mut WorkerContext) -> u32;
}

/// Validates the independent output layout before any child proof is admitted.
fn verify_child_context(
    expected: &WorkerExpectation,
    observed: &WorkerContext,
    owned_child_pid: u32,
) -> Result<(), NativeError> {
    if observed.version != 1 || observed.size != std::mem::size_of::<WorkerContext>() as u32 {
        return Err(NativeError::AccessDenied);
    }
    expected.validate()?;
    if owned_child_pid != expected.pid
        || observed.pid != owned_child_pid
        || observed.audit_pid != owned_child_pid
        || observed.ppid != expected.ppid
        || observed.pid_version == 0
        || observed.uid != 0
        || observed.euid != 0
        || observed.audit_euid != 0
        || observed.audit_ruid != 0
        || observed.gid != expected.gid
        || observed.egid != expected.egid
        || observed.audit_rgid != expected.gid
        || observed.audit_egid != expected.egid
        || observed.auid != expected.uid
        || observed.asid != expected.asid
        || observed.session != expected.asid
        || observed.attributes & 0x10 == 0
        || observed.attributes & (1 | 0x1000) != 0
    {
        return Err(NativeError::AccessDenied);
    }
    Ok(())
}

#[cfg(test)]
#[path = "worker_context_tests.rs"]
mod tests;
