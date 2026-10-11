// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Private safe-eject preparation after exact-volume dismount and retained locks.

use super::{
    Completion, DEFAULT_TIMEOUT_SECONDS, DataDirection, MAX_SENSE_LENGTH, NativeError, ScsiRequest,
    VolumeMutationOutcome,
};

/// Closed steps available only inside the already-validated safe-eject lease.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum SafeEjectStep {
    AllowWindowsRemoval,
    AllowDeviceRemoval,
    Eject,
}

/// Exact retained authority; no caller-selected command, policy, or forced path.
pub(super) trait SafeEjectIo {
    /// Revalidates the same physical disk and every retained target volume.
    fn revalidate(&mut self) -> Result<(), NativeError>;

    /// Performs one fixed native step once and preserves its original failure.
    fn execute(&mut self, step: SafeEjectStep) -> Result<(), NativeError>;
}

/// Prepares and ejects once, preserving locks owned by the caller throughout.
///
/// Original Windows Manager 2.0.1.54 FUN_00444ef0 clears the OS removal lock
/// and sends SCPAMediaRemoval(false) before FUN_00445040 ejects. Neither step
/// is a substitute for the caller's successful flush/lock/dismount. Once a
/// preparation call runs, even later identity failure is completion-unknown.
pub(super) fn run_prepared_safe_eject(io: &mut impl SafeEjectIo) -> VolumeMutationOutcome {
    for (index, step) in [
        SafeEjectStep::AllowWindowsRemoval,
        SafeEjectStep::AllowDeviceRemoval,
        SafeEjectStep::Eject,
    ]
    .into_iter()
    .enumerate()
    {
        if let Err(error) = io.revalidate() {
            return if index == 0 {
                VolumeMutationOutcome::NotAttempted(error)
            } else {
                VolumeMutationOutcome::CompletionUnknown(error)
            };
        }
        if let Err(error) = io.execute(step) {
            return VolumeMutationOutcome::CompletionUnknown(error);
        }
    }
    VolumeMutationOutcome::Succeeded
}

/// Builds only the six-byte ALLOW MEDIUM REMOVAL command, privately.
pub(super) fn allow_device_removal_request() -> ScsiRequest {
    ScsiRequest::new(
        &[0x1e, 0, 0, 0, 0, 0],
        DataDirection::None,
        Vec::new(),
        DEFAULT_TIMEOUT_SECONDS,
        MAX_SENSE_LENGTH,
    )
    .expect("fixed no-data allow-removal request is bounded")
}

/// Requires a complete, sense-free no-data GOOD result before permitting eject.
pub(super) fn validate_allow_device_removal(completion: Completion) -> Result<(), NativeError> {
    match completion {
        Completion::NotAttempted(error) | Completion::AttemptedError(error) => Err(error),
        Completion::Device {
            scsi_status: 0,
            transferred_length: 0,
            data,
            sense_reported_length: 0,
            sense,
        } if data.is_empty() && sense.is_empty() => Ok(()),
        Completion::Device {
            scsi_status: 0x08, ..
        } => Err(NativeError::Busy),
        Completion::Device { .. } => Err(NativeError::EvidenceIncomplete),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Deterministic transport that fails one boundary without accessing hardware.
    #[derive(Default)]
    struct Fixture {
        calls: Vec<&'static str>,
        fail_at: Option<usize>,
    }

    impl Fixture {
        /// Records a causal call and optionally fails before any later step.
        fn call(&mut self, name: &'static str) -> Result<(), NativeError> {
            self.calls.push(name);
            if self.fail_at == Some(self.calls.len()) {
                Err(NativeError::DeviceRemoved)
            } else {
                Ok(())
            }
        }
    }

    impl SafeEjectIo for Fixture {
        /// Injects an exact-binding failure at each independent revalidation.
        fn revalidate(&mut self) -> Result<(), NativeError> {
            self.call("revalidate")
        }

        /// Records only the closed allow/allow/eject operations; no retry surface.
        fn execute(&mut self, step: SafeEjectStep) -> Result<(), NativeError> {
            self.call(match step {
                SafeEjectStep::AllowWindowsRemoval => "allow-windows",
                SafeEjectStep::AllowDeviceRemoval => "allow-device",
                SafeEjectStep::Eject => "eject",
            })
        }
    }

    /// The two distinct removal locks must be released before a single eject.
    #[test]
    fn both_allow_steps_precede_eject_with_independent_identity_checks() {
        let mut io = Fixture::default();
        assert_eq!(
            run_prepared_safe_eject(&mut io),
            VolumeMutationOutcome::Succeeded
        );
        assert_eq!(
            io.calls,
            [
                "revalidate",
                "allow-windows",
                "revalidate",
                "allow-device",
                "revalidate",
                "eject"
            ]
        );
    }

    /// Every failed boundary stops immediately; post-preparation failures stay ambiguous.
    #[test]
    fn failures_never_reach_a_later_step_or_retry() {
        let expected = [
            "revalidate",
            "allow-windows",
            "revalidate",
            "allow-device",
            "revalidate",
            "eject",
        ];
        for fail_at in 1..=expected.len() {
            let mut io = Fixture {
                fail_at: Some(fail_at),
                ..Fixture::default()
            };
            let outcome = run_prepared_safe_eject(&mut io);
            assert_eq!(io.calls, expected[..fail_at]);
            assert_eq!(
                outcome,
                if fail_at == 1 {
                    VolumeMutationOutcome::NotAttempted(NativeError::DeviceRemoved)
                } else {
                    VolumeMutationOutcome::CompletionUnknown(NativeError::DeviceRemoved)
                }
            );
        }
    }

    /// The private builder cannot select PREVENT, another command, or a data payload.
    #[test]
    fn allow_command_is_exact_bounded_and_has_no_data_phase() {
        let request = allow_device_removal_request();
        assert_eq!(request.cdb_length, 6);
        assert_eq!(&request.cdb[..6], &[0x1e, 0, 0, 0, 0, 0]);
        assert!(request.cdb[6..].iter().all(|byte| *byte == 0));
        assert_eq!(request.direction, DataDirection::None);
        assert!(request.data.is_empty());
        assert_eq!(request.timeout_seconds, 30);
        assert_eq!(usize::from(request.sense_capacity), MAX_SENSE_LENGTH);
    }

    /// Produces a valid no-data response to mutate one field at a time in tests.
    fn good() -> Completion {
        Completion::Device {
            scsi_status: 0,
            transferred_length: 0,
            data: vec![],
            sense_reported_length: 0,
            sense: vec![],
        }
    }

    /// GOOD without exact zero data/sense counts is insufficient evidence to eject.
    #[test]
    fn malformed_or_failed_allow_completions_cannot_authorize_eject() {
        assert_eq!(validate_allow_device_removal(good()), Ok(()));
        for index in 0..5 {
            let mut completion = good();
            if let Completion::Device {
                scsi_status,
                transferred_length,
                data,
                sense_reported_length,
                sense,
            } = &mut completion
            {
                match index {
                    0 => *scsi_status = 2,
                    1 => *transferred_length = 1,
                    2 => data.push(0),
                    3 => *sense_reported_length = 1,
                    _ => sense.push(0),
                }
            }
            assert_eq!(
                validate_allow_device_removal(completion),
                Err(NativeError::EvidenceIncomplete)
            );
        }
        for completion in [
            Completion::NotAttempted(NativeError::AccessDenied),
            Completion::AttemptedError(NativeError::AccessDenied),
        ] {
            assert_eq!(
                validate_allow_device_removal(completion),
                Err(NativeError::AccessDenied)
            );
        }
        let mut busy = good();
        if let Completion::Device { scsi_status, .. } = &mut busy {
            *scsi_status = 8;
        }
        assert_eq!(validate_allow_device_removal(busy), Err(NativeError::Busy));
    }
}
