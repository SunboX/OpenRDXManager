// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Portable readiness evidence and fail-closed authority evaluation.

#[cfg(any(windows, test))]
const MIN_SERVICE_STATUS_PROCESS_BYTES: usize = 9 * std::mem::size_of::<u32>();
#[cfg(any(windows, test))]
const MAX_SERVICE_STATUS_PROCESS_BYTES: usize = 8_192;

/// Sanitized result class from one `QueryServiceStatusEx` call.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg(any(windows, test))]
pub(super) enum ServiceStatusQueryResult {
    Success,
    InsufficientBuffer,
    Failure,
}

/// Safe next action after one service-status query.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg(any(windows, test))]
pub(super) enum ServiceStatusQueryAction {
    Accept,
    Retry(usize),
    Reject,
}

/// Trusts bytes-needed only for a documented insufficient-buffer failure.
#[cfg(any(windows, test))]
pub(super) fn service_status_query_action(
    result: ServiceStatusQueryResult,
    bytes_needed: u32,
    supplied_capacity: usize,
) -> ServiceStatusQueryAction {
    match result {
        ServiceStatusQueryResult::Success => ServiceStatusQueryAction::Accept,
        ServiceStatusQueryResult::InsufficientBuffer => {
            let required = bytes_needed as usize;
            if supplied_capacity >= MIN_SERVICE_STATUS_PROCESS_BYTES
                && required > supplied_capacity
                && required <= MAX_SERVICE_STATUS_PROCESS_BYTES
            {
                ServiceStatusQueryAction::Retry(required)
            } else {
                ServiceStatusQueryAction::Reject
            }
        }
        ServiceStatusQueryResult::Failure => ServiceStatusQueryAction::Reject,
    }
}

/// One runtime status snapshot returned by `QueryServiceStatusEx`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg(any(windows, test))]
pub(super) struct ServiceRuntimeEvidence {
    pub(super) running: bool,
    pub(super) process_id: u32,
    pub(super) own_process: bool,
}

/// Registration/configuration evidence for the expected Windows service.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg(any(windows, test))]
pub(super) struct ServiceIdentityEvidence {
    pub(super) installed: bool,
    pub(super) current_pid: u32,
    pub(super) status_before: ServiceRuntimeEvidence,
    pub(super) status_after: ServiceRuntimeEvidence,
    pub(super) config_stable: bool,
    pub(super) demand_start: bool,
    pub(super) binary_matches: bool,
    pub(super) token_local_service: bool,
}

#[cfg(any(windows, test))]
impl ServiceIdentityEvidence {
    /// Returns whether both runtime snapshots prove one unchanged running process.
    const fn stable_running(self) -> bool {
        self.status_before.running == self.status_after.running
            && self.status_before.process_id == self.status_after.process_id
            && self.status_before.own_process == self.status_after.own_process
            && self.status_before.running
            && self.status_before.process_id != 0
    }

    /// Returns whether the configured service is the current executing process.
    const fn current_process_bound(self) -> bool {
        self.installed
            && self.stable_running()
            && self.current_pid != 0
            && self.status_before.process_id == self.current_pid
            && self.status_before.own_process
            && self.config_stable
            && self.demand_start
            && self.binary_matches
            && self.token_local_service
    }
}

/// Independent proofs from the service controller and direct device-access path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg(any(windows, test))]
pub(super) struct AuthorityEvidence {
    pub(super) service: ServiceIdentityEvidence,
    pub(super) process_elevated: bool,
    pub(super) exact_device_access: bool,
}

#[cfg(any(windows, test))]
impl AuthorityEvidence {
    /// Requires a bound service process or both proofs for direct process access.
    pub(super) const fn current_process_authorized(self) -> bool {
        self.service.current_process_bound() || (self.process_elevated && self.exact_device_access)
    }
}

/// Extracts one argument-free local absolute Windows executable path.
#[cfg(any(windows, test))]
pub(super) fn exact_service_binary_path(command_line: &str) -> Option<&str> {
    let path = if command_line.starts_with('"') && command_line.ends_with('"') {
        let inner = &command_line[1..command_line.len().checked_sub(1)?];
        if inner.is_empty() || inner.contains('"') {
            return None;
        }
        inner
    } else {
        if command_line.is_empty() || command_line.chars().any(char::is_whitespace) {
            return None;
        }
        command_line
    };
    if path.chars().any(char::is_control) {
        return None;
    }

    let bytes = path.as_bytes();
    let drive_absolute = |candidate: &[u8]| {
        candidate.len() >= 3
            && candidate[0].is_ascii_alphabetic()
            && candidate[1] == b':'
            && candidate[2] == b'\\'
    };
    let extended_local =
        bytes.len() >= 7 && bytes[..4] == *b"\\\\?\\" && drive_absolute(&bytes[4..]);
    (drive_absolute(bytes) || extended_local).then_some(path)
}

/// Extracts the local service binary only with the exact production endpoint arguments.
#[cfg(any(windows, test))]
pub(super) fn exact_endpoint_service_binary_path(command_line: &str) -> Option<&str> {
    const ENDPOINT_ARGUMENTS: &str = " --service-mode named-pipe --protocol-version 1";
    exact_service_binary_path(command_line.strip_suffix(ENDPOINT_ARGUMENTS)?)
}

/// Native-adapter metadata separated from current-process dispatch authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Readiness {
    adapter_available: bool,
    service_installed: bool,
    service_running: bool,
    current_process_authorized: bool,
}

impl Readiness {
    /// Creates readiness only from independently evaluated native evidence.
    #[cfg(any(windows, test))]
    pub(super) const fn from_authority(
        adapter_available: bool,
        evidence: AuthorityEvidence,
    ) -> Self {
        Self {
            adapter_available,
            service_installed: evidence.service.installed,
            service_running: evidence.service.stable_running(),
            current_process_authorized: evidence.current_process_authorized(),
        }
    }

    /// Creates the target-gated non-Windows result.
    #[cfg(not(windows))]
    pub(super) const fn unavailable() -> Self {
        Self {
            adapter_available: false,
            service_installed: false,
            service_running: false,
            current_process_authorized: false,
        }
    }

    /// Returns whether SetupAPI disk-interface enumeration is operational.
    #[must_use]
    pub const fn adapter_available(self) -> bool {
        self.adapter_available
    }

    /// Returns whether the constrained service is registered.
    #[must_use]
    pub const fn service_installed(self) -> bool {
        self.service_installed
    }

    /// Returns whether the registered constrained service is running.
    #[must_use]
    pub const fn service_running(self) -> bool {
        self.service_running
    }

    /// Returns whether this exact process owns proven dispatch authority.
    #[must_use]
    pub const fn current_process_authorized(self) -> bool {
        self.current_process_authorized
    }
}
