// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Exact-lease diagnostic commands and LED cleanup recovery.

use super::*;
use crate::protocol::led_test;

impl ResolvedDevice<'_> {
    /// Sends LED-on while retaining an exact-lease cleanup obligation.
    pub(crate) fn execute_led_on(&mut self) -> CommandDispatch {
        if !self.active {
            return CommandDispatch::NotSent(TransportError::InactiveSession);
        }
        self.led_recovery_armed = true;
        let outcome = self.execute_retained(&led_test(true));
        if matches!(
            outcome.certainty(),
            DispatchCertainty::NotSent | DispatchCertainty::DefinitelyRejected
        ) {
            self.led_recovery_armed = false;
        }
        outcome
    }

    /// Restores normal LED ownership through the same retained native lease.
    pub(crate) fn restore_led_control(&mut self) -> CommandDispatch {
        self.led_recovery_armed = true;
        let outcome = self.execute_retained(&led_test(false));
        if outcome.certainty() == DispatchCertainty::Succeeded {
            self.led_recovery_armed = false;
        }
        outcome
    }

    /// Executes recovery even after an ambiguous LED-on invalidated normal use.
    fn execute_retained(&mut self, command: &Command) -> CommandDispatch {
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.lease.handle.execute(command)
        }))
        .unwrap_or(CommandDispatch::CompletionUnknown(
            TransportError::AdapterPanic,
        ));
        if outcome.certainty() == DispatchCertainty::CompletionUnknown
            || matches!(
                outcome.error(),
                Some(
                    TransportError::Unavailable
                        | TransportError::DeviceRemoved
                        | TransportError::AdapterPanic
                )
            )
        {
            self.active = false;
        }
        outcome
    }
}

impl Drop for ResolvedDevice<'_> {
    /// Makes one final contained LED-off attempt when an operation unwinds or exits early.
    fn drop(&mut self) {
        if self.led_recovery_armed {
            let _ = self.execute_retained(&led_test(false));
        }
    }
}
