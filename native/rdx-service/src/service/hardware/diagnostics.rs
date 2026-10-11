// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Production diagnostic routing through one registry-owned device lease.

use super::*;

impl HostWorkerObserver<'_> {
    /// Publishes one non-skippable cleanup/readback stage after cancellation closes.
    fn reached_recovery(&mut self, stage: &'static str) -> bool {
        let first = !self.started;
        let publication = self.control.recovery_publish(|| {
            if first {
                self.events
                    .publish_host_started(self.operation_id, self.kind, self.identity)?;
            }
            self.events.publish_host_progress(
                self.operation_id,
                self.kind,
                self.identity,
                stage,
                CancellationState::Closed,
            )
        });
        match publication {
            Ok(()) => {
                self.started = true;
                self.current_stage = Some(stage);
                true
            }
            Err(_) => {
                self.publication_failed = true;
                false
            }
        }
    }
}

/// Runs the exact self-test command through the registry-owned lease.
pub(super) fn run_production_self_test(
    device: &mut ResolvedDevice<'_>,
    observer: &mut HostWorkerObserver<'_>,
) -> Result<(), HostOperationFailure> {
    let mut primary = if observer.reached("diagnostic-running", true) {
        device
            .revalidate_identity()
            .map_err(|_| diagnostic_preflight_failure("diagnostic-running"))
            .and_then(|()| {
                diagnostic_dispatch_failure(
                    "diagnostic-running",
                    &device.execute_firmware(&self_test()),
                )
                .map_or(Ok(()), Err)
            })
            .err()
    } else {
        Some(cancelled_host_failure("diagnostic-running"))
    };

    if observer.reached_recovery("diagnostic-cleanup")
        && device.revalidate_identity().is_err()
        && primary.is_none()
    {
        primary = Some(diagnostic_preflight_failure("diagnostic-cleanup"));
    }
    if primary.is_none() && observer.control.cancellation_requested().unwrap_or(true) {
        primary = Some(cancelled_host_failure("diagnostic-cleanup"));
    }
    primary.map_or(Ok(()), Err)
}

/// Runs the LED-on/off sequence and always restores normal ownership.
pub(super) fn run_production_led_test(
    device: &mut ResolvedDevice<'_>,
    observer: &mut HostWorkerObserver<'_>,
) -> Result<(), HostOperationFailure> {
    let mut primary = if observer.reached("led-testing", true) {
        device
            .revalidate_identity()
            .map_err(|_| diagnostic_preflight_failure("led-testing"))
            .and_then(|()| {
                diagnostic_dispatch_failure("led-testing", &device.execute_led_on())
                    .map_or(Ok(()), Err)
            })
            .err()
    } else {
        Some(cancelled_host_failure("led-testing"))
    };

    // Firmware owns the color sequence while diagnostic mode is enabled.
    // Do not restore normal LED control before the original Manager's interval.
    if primary.is_none() {
        wait_for_led_sequence(observer.control, thread::sleep);
    }
    observer.reached_recovery("led-restoring");
    if let Some(cleanup_failure) =
        diagnostic_dispatch_failure("led-restoring", &device.restore_led_control())
    {
        let cleanup = cleanup_state_from_certainty(cleanup_failure.certainty());
        primary = Some(primary.unwrap_or(cleanup_failure).with_cleanup(cleanup));
    }
    observer.reached_recovery("led-readback");
    if device.revalidate_identity().is_err() && primary.is_none() {
        primary = Some(diagnostic_preflight_failure("led-readback"));
    }
    if primary.is_none() && observer.control.cancellation_requested().unwrap_or(true) {
        primary = Some(cancelled_host_failure("led-readback"));
    }
    primary.map_or(Ok(()), Err)
}

/// Keeps diagnostic mode active until its visual sequence finishes or cancellation is accepted.
/// The wait callback permits deterministic timing verification without real hardware or delays.
fn wait_for_led_sequence(control: &OperationControl, mut wait: impl FnMut(Duration)) {
    // Both original Managers tick every 300 ms, add four to progress starting
    // at zero, and send LED-off only when progress exceeds 100: 26 ticks.
    // Check the service latch each tick so cancellation reaches cleanup promptly.
    for _ in 0..26 {
        if control.cancellation_requested().unwrap_or(true) {
            break;
        }
        wait(Duration::from_millis(300));
    }
}

/// Maps one diagnostic command result into bounded service failure evidence.
fn diagnostic_dispatch_failure(
    stage: &'static str,
    outcome: &CommandDispatch,
) -> Option<HostOperationFailure> {
    let error = outcome.error()?;
    let cause = if matches!(
        error,
        crate::transport::TransportError::CheckCondition(sense)
            if sense.raw_key() == 2 && sense.asc() == 0x3a
    ) {
        // Preserve the dock's no-medium report even when discovery still has
        // a cartridge snapshot. This must not turn into success or a retry.
        HostPrimitiveError::MediaMissing
    } else if matches!(error, crate::transport::TransportError::Timeout) {
        HostPrimitiveError::TimedOut
    } else if matches!(error, crate::transport::TransportError::InactiveSession) {
        HostPrimitiveError::StaleBinding
    } else {
        HostPrimitiveError::Other
    };
    let failure = match outcome.certainty() {
        DispatchCertainty::Succeeded => return None,
        DispatchCertainty::NotSent => PrimitiveFailure::not_attempted(cause),
        DispatchCertainty::DefinitelyRejected => PrimitiveFailure::definitely_rejected(cause),
        DispatchCertainty::CompletionUnknown => PrimitiveFailure::completion_unknown(cause),
    };
    Some(HostOperationFailure::from_primitive(stage, failure))
}

/// Creates one exact-identity diagnostic preflight failure.
fn diagnostic_preflight_failure(stage: &'static str) -> HostOperationFailure {
    HostOperationFailure::preflight(stage, HostPrimitiveError::StaleBinding)
}

/// Converts command certainty into independent LED restoration evidence.
fn cleanup_state_from_certainty(certainty: crate::operations::MutationCertainty) -> CleanupState {
    match certainty {
        crate::operations::MutationCertainty::DefinitelyRejected => {
            CleanupState::DefinitelyRejected
        }
        crate::operations::MutationCertainty::NotAttempted
        | crate::operations::MutationCertainty::CompletionUnknown => {
            CleanupState::CompletionUnknown
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A dock's no-medium response retains its cause, original stage and uncertainty.
    #[test]
    fn diagnostic_no_media_preserves_dispatch_evidence() {
        let sense = crate::protocol::SenseData::parse(&[0x72, 2, 0x3a, 0, 0, 0, 0, 0]).unwrap();
        let outcome = CommandDispatch::CompletionUnknown(
            crate::transport::TransportError::CheckCondition(sense),
        );
        let failure = diagnostic_dispatch_failure("diagnostic-running", &outcome).unwrap();
        assert_eq!(failure.code(), "media-required");
        assert_eq!(failure.stage(), "diagnostic-running");
        assert_eq!(
            failure.certainty(),
            crate::operations::MutationCertainty::CompletionUnknown
        );
    }

    /// Original Windows and macOS Manager stop LED diagnostics after 26 300-ms timer ticks.
    #[test]
    fn led_sequence_waits_for_the_original_managers_complete_visual_cycle() {
        let control = OperationControl::new(OperationKind::LedTest);
        let mut waits = Vec::new();
        wait_for_led_sequence(&control, |duration| waits.push(duration));
        assert_eq!(waits, vec![Duration::from_millis(300); 26]);
        assert_eq!(waits.iter().sum::<Duration>(), Duration::from_millis(7800));
    }

    /// Accepted cancellation exits the visual interval at the next tick so cleanup can run.
    #[test]
    fn led_sequence_stops_waiting_when_cancelled_mid_cycle() {
        let control = OperationControl::new(OperationKind::LedTest);
        let mut waits = Vec::new();
        wait_for_led_sequence(&control, |duration| {
            waits.push(duration);
            if waits.len() == 2 {
                control.request_cancellation().unwrap();
            }
        });
        assert_eq!(waits, vec![Duration::from_millis(300); 2]);
        assert!(control.cancellation_requested().unwrap());
    }

    /// A queued cancellation proceeds straight to restoration without starting a visual delay.
    #[test]
    fn led_sequence_skips_waiting_when_already_cancelled() {
        let control = OperationControl::new(OperationKind::LedTest);
        control.request_cancellation().unwrap();
        wait_for_led_sequence(&control, |_| panic!("cancelled LED test must not wait"));
    }
}
