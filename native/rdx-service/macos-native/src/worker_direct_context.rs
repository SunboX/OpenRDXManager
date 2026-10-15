// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Direct process policy is separate from authenticated graphical-session eligibility.

use super::*;

pub(crate) const DIRECT_EXPECTATION_BYTES: usize = 88;
pub(crate) const FRAME_DIRECT_CONTEXT_REQUEST: u8 = 13;

/// Retained native process observations; no public field or caller-provided constructor.
#[derive(Clone)]
pub(crate) struct DirectBaseline(WorkerContext);

impl DirectBaseline {
    /// Captures actual public kernel/session data only after the independent native privilege probe.
    pub(crate) fn capture() -> Result<Self, NativeError> {
        if !crate::current_process_is_privileged_service() {
            return Err(NativeError::AccessDenied);
        }
        Self::from_observed(WorkerContext::current()?)
    }

    /// Accepts only independently self-consistent actual privileged process observations.
    fn from_observed(observed: WorkerContext) -> Result<Self, NativeError> {
        if observed.version != 1
            || observed.size != CONTEXT_BYTES as u32
            || observed.uid != 0
            || observed.euid != 0
            || observed.audit_ruid != 0
            || observed.audit_euid != 0
            || observed.audit_rgid != observed.gid
            || observed.audit_egid != observed.egid
            || observed.pid == 0
            || observed.pid > i32::MAX as u32
            || observed.ppid == 0
            || observed.ppid > i32::MAX as u32
            || observed.audit_pid != observed.pid
            || observed.pid_version == 0
            || observed.asid == 0
            || observed.asid >= u32::MAX - 1
            || observed.session != observed.asid
            || observed.auid == u32::MAX - 1
        {
            return Err(NativeError::AccessDenied);
        }
        // Anonymous root AUID=FFFFFFFF and graphical terminal AUIDs are both legitimate direct modes.
        Ok(Self(observed))
    }

    /// Revalidates this same actual process, audit generation and entire session/credential baseline.
    pub(crate) fn revalidate(&self) -> Result<(), NativeError> {
        let current = Self::capture()?;
        self.revalidate_observed(current.0)
    }

    /// Compares one new native observation to the complete retained immutable baseline.
    fn revalidate_observed(&self, current: WorkerContext) -> Result<(), NativeError> {
        let current = Self::from_observed(current)?;
        if current.0.encode() != self.0.encode() {
            return Err(NativeError::AccessDenied);
        }
        Ok(())
    }

    /// Binds only an actual successful spawn PID to the retained caller baseline.
    pub(crate) fn expectation(&self, pid: u32) -> Result<DirectExpectation, NativeError> {
        if pid == 0 || pid > i32::MAX as u32 || pid == self.0.pid {
            return Err(NativeError::AccessDenied);
        }
        Ok(DirectExpectation {
            baseline: self.clone(),
            pid,
        })
    }
}

/// Exact child expectation derived from a retained direct process baseline and successful spawn.
pub(crate) struct DirectExpectation {
    baseline: DirectBaseline,
    pid: u32,
}

impl DirectExpectation {
    /// Synthetic root fields test framing only; no production factory can consume this constructor.
    #[cfg(test)]
    pub(crate) fn fixture_for_pid(pid: u32, anonymous: bool) -> Self {
        let mut parent = WorkerContext::current().unwrap();
        parent.uid = 0;
        parent.euid = 0;
        parent.audit_ruid = 0;
        parent.audit_euid = 0;
        if anonymous {
            parent.auid = u32::MAX;
            parent.attributes = 1;
        }
        DirectBaseline::from_observed(parent)
            .unwrap()
            .expectation(pid)
            .unwrap()
    }

    /// Retains real child PID/PPID/pid-version but labels synthetic authority/session fields explicitly.
    #[cfg(test)]
    pub(crate) fn matching_fixture(&self) -> WorkerContext {
        let mut child = self.baseline.0;
        let actual = WorkerContext::current().unwrap();
        child.pid = actual.pid;
        child.audit_pid = actual.audit_pid;
        child.pid_version = actual.pid_version;
        child.ppid = actual.ppid;
        child
    }

    /// Decodes only the separately versioned direct request, without selecting a public role or path.
    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, NativeError> {
        if bytes.len() != DIRECT_EXPECTATION_BYTES {
            return Err(NativeError::InvalidRequest);
        }
        let header = decode_words::<4>(&bytes[..16])?;
        if header[..3] != [1, DIRECT_EXPECTATION_BYTES as u32, 2] {
            return Err(NativeError::InvalidRequest);
        }
        DirectBaseline::from_observed(WorkerContext::decode(&bytes[16..])?)?.expectation(header[3])
    }
}

impl ContextExpectation for DirectExpectation {
    /// Distinct closed frame kind prevents any GUI/direct request ambiguity.
    fn request_kind(&self) -> u8 {
        FRAME_DIRECT_CONTEXT_REQUEST
    }

    /// Parent observations remain private and fixed width; no strings or caller arguments exist.
    fn encode(&self) -> Vec<u8> {
        let mut bytes = encode_words(&[1, DIRECT_EXPECTATION_BYTES as u32, 2, self.pid]);
        bytes.extend_from_slice(&self.baseline.0.encode());
        bytes
    }

    /// Proves actual retained child and unchanged root/GID/audit/session context before any IOKit.
    fn verify(&self, observed: &WorkerContext, owned_child_pid: u32) -> Result<(), NativeError> {
        let child = DirectBaseline::from_observed(*observed)?;
        let parent = self.baseline.0;
        if owned_child_pid != self.pid
            || child.0.pid != owned_child_pid
            || child.0.ppid != parent.pid
            || child.0.auid != parent.auid
            || child.0.gid != parent.gid
            || child.0.egid != parent.egid
            || child.0.asid != parent.asid
            || child.0.session != parent.session
            || child.0.attributes != parent.attributes
        {
            return Err(NativeError::AccessDenied);
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "worker_direct_context_tests.rs"]
mod tests;
