// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};

use super::{ServiceEventError, ServiceProtocolError};

const RUNNING: u8 = 0;
const CRASHED: u8 = 1;
const CLOSED: u8 = 2;

/// Shared crash admission whose close transition is atomic with crash observation.
#[derive(Clone, Debug)]
pub(super) struct CrashAdmission {
    state: Arc<AtomicU8>,
}

/// Service-loop guard that closes crash admission on every return path.
pub(super) struct CrashDisconnectGuard<'a> {
    admission: &'a CrashAdmission,
}

impl Drop for CrashDisconnectGuard<'_> {
    fn drop(&mut self) {
        self.admission.disconnect();
    }
}

impl CrashAdmission {
    /// Creates an open generation with no accepted crash report.
    pub(super) fn new() -> Self {
        Self {
            state: Arc::new(AtomicU8::new(RUNNING)),
        }
    }

    /// Creates a guard that disconnects reporters when the loop unwinds.
    pub(super) fn disconnect_guard(&self) -> CrashDisconnectGuard<'_> {
        CrashDisconnectGuard { admission: self }
    }

    /// Atomically accepts one crash, coalesces repeats, or rejects a closed generation.
    pub(super) fn report(&self) -> Result<(), ServiceEventError> {
        loop {
            match self.state.load(Ordering::Acquire) {
                RUNNING => {
                    if self
                        .state
                        .compare_exchange(RUNNING, CRASHED, Ordering::AcqRel, Ordering::Acquire)
                        .is_ok()
                    {
                        return Ok(());
                    }
                }
                CRASHED => return Ok(()),
                CLOSED => return Err(ServiceEventError::Disconnected),
                _ => unreachable!("crash admission uses only declared states"),
            }
        }
    }

    /// Observes an already accepted crash without closing further admission.
    pub(super) fn observe(&self) -> Result<(), ServiceProtocolError> {
        match self.state.load(Ordering::Acquire) {
            CRASHED => Err(ServiceProtocolError::BackendContract),
            RUNNING | CLOSED => Ok(()),
            _ => unreachable!("crash admission uses only declared states"),
        }
    }

    /// Atomically closes admission and reports whether a crash won the race.
    pub(super) fn close(&self) -> Result<(), ServiceProtocolError> {
        match self.state.swap(CLOSED, Ordering::AcqRel) {
            CRASHED => Err(ServiceProtocolError::BackendContract),
            RUNNING | CLOSED => Ok(()),
            _ => unreachable!("crash admission uses only declared states"),
        }
    }

    /// Closes admission after every service-loop exit, including I/O failures.
    pub(super) fn disconnect(&self) {
        self.state.store(CLOSED, Ordering::Release);
    }
}

#[cfg(test)]
mod tests {
    use std::sync::mpsc;
    use std::thread;

    use super::CrashAdmission;
    use crate::service::{ServiceEventError, ServiceProtocolError};

    #[test]
    fn gated_report_before_close_is_observed_and_later_reports_disconnect() {
        let admission = CrashAdmission::new();
        assert_eq!(admission.observe(), Ok(()));
        let reporter = admission.clone();
        let (release_sender, release_receiver) = mpsc::sync_channel(0);
        let (result_sender, result_receiver) = mpsc::sync_channel(0);
        let worker = thread::spawn(move || {
            release_receiver.recv().unwrap();
            result_sender.send(reporter.report()).unwrap();
        });

        release_sender.send(()).unwrap();
        assert_eq!(result_receiver.recv().unwrap(), Ok(()));
        assert_eq!(
            admission.close(),
            Err(ServiceProtocolError::BackendContract)
        );
        assert_eq!(admission.report(), Err(ServiceEventError::Disconnected));
        worker.join().unwrap();
    }

    #[test]
    fn gated_close_before_report_rejects_late_crash() {
        let admission = CrashAdmission::new();
        let reporter = admission.clone();
        let (release_sender, release_receiver) = mpsc::sync_channel(0);
        let worker = thread::spawn(move || {
            release_receiver.recv().unwrap();
            reporter.report()
        });

        assert_eq!(admission.close(), Ok(()));
        release_sender.send(()).unwrap();
        assert_eq!(worker.join().unwrap(), Err(ServiceEventError::Disconnected));
    }
}
