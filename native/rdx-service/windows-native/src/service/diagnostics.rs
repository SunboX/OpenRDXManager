// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Closed service-status breadcrumbs; no identity, path, frame, or native text.

use std::cell::Cell;

use crate::NativeError;

/// Fixed failing boundaries encoded in the SCM's service-specific exit status.
#[derive(Clone, Copy)]
#[repr(u8)]
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) enum Stage {
    RuntimeTrust = 1,
    StartupAuthority = 2,
    ServiceProcess = 3,
    ServiceQueryAccess = 4,
    PipeAuthority = 5,
    FirstPipe = 6,
    ConnectionTrust = 7,
    ConnectionWait = 8,
    ClientSession = 9,
    ClientProcess = 10,
    ClientImpersonation = 11,
    ClientToken = 12,
    ClientUser = 13,
    RunningAuthority = 15,
    NextPipe = 16,
    NamespaceRoll = 17,
    PipeClone = 18,
    PipeMode = 19,
    Runner = 20,
}

thread_local! {
    /// Only the registered callback's thread owns its current failure breadcrumb.
    static FAILURE: Cell<Option<u32>> = const { Cell::new(None) };
}

/// Starts a registered generation or a new bounded accept attempt without stale state.
pub(crate) fn begin_attempt() {
    FAILURE.set(None);
}

/// Records only the first failed boundary while returning its original result unchanged.
pub(crate) fn record<T>(stage: Stage, result: Result<T, NativeError>) -> Result<T, NativeError> {
    if let Err(error) = &result {
        // An empty accept interval is handled by the runner as normal idle.
        // It must not survive into a subsequent STOP/admission race.
        if matches!(
            (stage, *error),
            (Stage::ConnectionWait, NativeError::TimedOut)
        ) {
            return result;
        }
        FAILURE.with(|failure| {
            if failure.get().is_none() {
                failure.set(Some(encode(stage, *error)));
            }
        });
    }
    result
}

/// Returns a closed breadcrumb, falling back to the runner's actual sanitized error.
pub(crate) fn failure_code(error: NativeError) -> u32 {
    FAILURE
        .get()
        .unwrap_or_else(|| encode(Stage::Runner, error))
}

/// Emits a service-specific code only for Windows' ERROR_SERVICE_SPECIFIC_ERROR.
pub(crate) const fn status_exit_codes(win32: u32, specific: u32) -> (u32, u32) {
    (win32, if win32 == 1066 { specific } else { 0 })
}

/// Encodes only explicit stage/error identifiers in the private 0x5244xxxx range.
fn encode(stage: Stage, error: NativeError) -> u32 {
    let reason = match error {
        NativeError::UnsupportedPlatform => 1,
        NativeError::InvalidRequest => 2,
        NativeError::AccessDenied => 3,
        NativeError::Busy => 4,
        NativeError::ReadOnly => 5,
        NativeError::Cancelled => 6,
        NativeError::TimedOut => 7,
        NativeError::DeviceRemoved => 8,
        NativeError::NoMedia => 9,
        NativeError::EnumerationFailed => 10,
        NativeError::EvidenceIncomplete => 11,
        NativeError::ResourceLimit => 12,
        NativeError::Other => 13,
    };
    0x5244_0000 | ((stage as u32) << 8) | reason
}

#[cfg(test)]
mod tests {
    use super::{Stage, begin_attempt, failure_code, record, status_exit_codes};
    use crate::NativeError;

    /// Capturing a failure must preserve its exact authorization outcome.
    #[test]
    fn first_failed_boundary_survives_outer_error_mapping() {
        begin_attempt();
        assert_eq!(
            record::<()>(Stage::ClientImpersonation, Err(NativeError::AccessDenied)),
            Err(NativeError::AccessDenied)
        );
        assert_eq!(
            record::<()>(Stage::Runner, Err(NativeError::Other)),
            Err(NativeError::Other)
        );
        assert_eq!(failure_code(NativeError::Other), 0x5244_0b03);
    }

    /// An idle poll or previous connection cannot mislabel the next attempt.
    #[test]
    fn next_attempt_clears_old_failure_and_success_is_transparent() {
        begin_attempt();
        let _ = record::<()>(Stage::ClientUser, Err(NativeError::AccessDenied));
        begin_attempt();
        assert_eq!(record(Stage::ClientProcess, Ok(42)), Ok(42));
        assert_eq!(failure_code(NativeError::Other), 0x5244_140d);
    }

    /// A handled idle timeout cannot mask an unrelated terminal admission failure.
    #[test]
    fn idle_timeout_does_not_label_a_following_stop_race() {
        begin_attempt();
        assert_eq!(
            record::<()>(Stage::ConnectionWait, Err(NativeError::TimedOut)),
            Err(NativeError::TimedOut)
        );
        // STOP can race with the runner's next begin_connection before the next
        // accept resets state. That failure must retain its own runner reason.
        assert_eq!(failure_code(NativeError::AccessDenied), 0x5244_1403);
    }

    /// SCM reports no stale diagnostic on clean retirement or non-service errors.
    #[test]
    fn only_service_specific_failure_publishes_a_breadcrumb() {
        assert_eq!(status_exit_codes(0, 0x5244_0b03), (0, 0));
        assert_eq!(status_exit_codes(5, 0x5244_0b03), (5, 0));
        assert_eq!(status_exit_codes(1066, 0x5244_0b03), (1066, 0x5244_0b03));
    }

    /// An unrelated control/worker thread cannot overwrite the SCM thread's failure.
    #[test]
    fn failure_ownership_is_thread_local() {
        begin_attempt();
        let _ = record::<()>(Stage::ClientToken, Err(NativeError::AccessDenied));
        let other = std::thread::spawn(|| {
            begin_attempt();
            let _ = record::<()>(Stage::ClientProcess, Err(NativeError::DeviceRemoved));
            failure_code(NativeError::Other)
        })
        .join()
        .unwrap();
        assert_eq!(other, 0x5244_0a08);
        assert_eq!(failure_code(NativeError::Other), 0x5244_0c03);
    }
}
