// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Exact-operation release, cancellation and operator acknowledgment gates.

use crate::model::OperationKind;
use crate::service::continuation::ContinuationStage;
use crate::service::{ServiceEventError, ServiceRejection, service_rejection};
use std::sync::{Condvar, Mutex};
use std::time::{Duration, Instant};

#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
const MAX_OPERATOR_WAIT: Duration = Duration::from_secs(300);

/// A gate can advance only through the two checkpoints in their declared order.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
enum OperatorGate {
    Disabled,
    Ready(ContinuationStage),
    Pending {
        stage: ContinuationStage,
        deadline: Instant,
        acknowledged: bool,
    },
    Finished,
}

/// Mutex-linearized gate preventing release and cancellation races.
pub(super) struct OperationControl {
    state: Mutex<OperationControlState>,
    released: Condvar,
    operator_acknowledged: Condvar,
}

/// Private mutable state protected by [`OperationControl::state`].
struct OperationControlState {
    released: bool,
    cancellation_open: bool,
    cancellation_requested: bool,
    operator_started: bool,
    operator: OperatorGate,
    #[cfg(test)]
    operator_waiting: bool,
}

impl OperationControl {
    /// Arms the next supported power-cycle stage before its observer publication.
    ///
    /// Only a released firmware operation may arm Bootloader then Bootstrap,
    /// once each. This closes cancellation and starts a five-minute deadline.
    /// Invalid state/order returns `operation-not-continuable`; a poisoned
    /// control returns the fixed `backend-worker-unavailable` rejection.
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    pub(super) fn arm_operator_wait(&self, stage: &str) -> Result<(), ServiceRejection> {
        let stage = ContinuationStage::parse(stage)
            .ok_or_else(|| service_rejection("operation-not-continuable"))?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| service_rejection("backend-worker-unavailable"))?;
        if !state.released
            || state.cancellation_requested
            || !matches!(state.operator, OperatorGate::Ready(expected) if expected == stage)
        {
            return Err(service_rejection("operation-not-continuable"));
        }
        state.operator = OperatorGate::Pending {
            stage,
            deadline: Instant::now() + MAX_OPERATOR_WAIT,
            acknowledged: false,
        };
        state.operator_started = true;
        state.cancellation_open = false;
        Ok(())
    }

    /// Accepts one matching acknowledgment before expiry without a worker command.
    ///
    /// The backend holds the exact active-owner reservation around this call.
    /// Duplicate, unarmed, wrong-stage and expired requests leave the gate intact;
    /// successful admission wakes its worker without opening cancellation.
    pub(super) fn acknowledge_operator(&self, stage: &str) -> Result<(), ServiceRejection> {
        let stage = ContinuationStage::parse(stage)
            .ok_or_else(|| service_rejection("operation-not-continuable"))?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| service_rejection("backend-worker-unavailable"))?;
        match &mut state.operator {
            OperatorGate::Pending {
                stage: expected,
                deadline,
                acknowledged,
            } if *expected == stage && !*acknowledged && Instant::now() < *deadline => {
                *acknowledged = true;
                self.operator_acknowledged.notify_all();
                Ok(())
            }
            _ => Err(service_rejection("operation-not-continuable")),
        }
    }

    /// Waits at most five minutes from arming for the exact stage acknowledgment.
    ///
    /// A shorter caller timeout is honored. Success consumes the acknowledgment;
    /// timeout permanently closes this gate and returns false. Neither outcome
    /// releases global operation ownership. Invalid state returns a fixed error.
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    pub(super) fn wait_for_operator(
        &self,
        stage: &str,
        timeout: Duration,
    ) -> Result<bool, ServiceRejection> {
        let stage = ContinuationStage::parse(stage)
            .ok_or_else(|| service_rejection("operation-not-continuable"))?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| service_rejection("backend-worker-unavailable"))?;
        let deadline = Instant::now() + timeout.min(MAX_OPERATOR_WAIT);
        loop {
            let remaining = match state.operator {
                OperatorGate::Pending {
                    stage: expected,
                    acknowledged: true,
                    ..
                } if expected == stage => {
                    state.operator = match stage {
                        ContinuationStage::Bootloader => {
                            OperatorGate::Ready(ContinuationStage::Bootstrap)
                        }
                        ContinuationStage::Bootstrap => OperatorGate::Finished,
                    };
                    return Ok(true);
                }
                OperatorGate::Pending {
                    stage: expected,
                    deadline: armed_deadline,
                    ..
                } if expected == stage => deadline
                    .min(armed_deadline)
                    .saturating_duration_since(Instant::now()),
                _ => return Err(service_rejection("operation-not-continuable")),
            };
            if remaining.is_zero() {
                state.operator = OperatorGate::Finished;
                return Ok(false);
            }
            #[cfg(test)]
            {
                state.operator_waiting = true;
                self.operator_acknowledged.notify_all();
            }
            let (next, _) = self
                .operator_acknowledged
                .wait_timeout(state, remaining)
                .map_err(|_| service_rejection("backend-worker-unavailable"))?;
            state = next;
            #[cfg(test)]
            {
                state.operator_waiting = false;
            }
        }
    }

    /// Synchronizes a synthetic test with the worker's actual condition-variable wait.
    #[cfg(test)]
    pub(super) fn wait_until_operator_parked(&self) -> bool {
        let state = self.state.lock().unwrap();
        let (state, _) = self
            .operator_acknowledged
            .wait_timeout_while(state, Duration::from_secs(1), |state| {
                !state.operator_waiting
            })
            .unwrap();
        state.operator_waiting
    }

    /// Creates an unreleased gate with cancellation open only for safe pre-dispatch kinds.
    pub(super) fn new(kind: OperationKind) -> Self {
        Self {
            state: Mutex::new(OperationControlState {
                released: false,
                cancellation_open: matches!(
                    kind,
                    OperationKind::SelfTest
                        | OperationKind::LedTest
                        | OperationKind::StatusRefresh
                        | OperationKind::WriteReadTest
                        | OperationKind::FirmwareUpdate
                        | OperationKind::Format
                        | OperationKind::EjectSafe
                ),
                cancellation_requested: false,
                operator_started: false,
                #[cfg(test)]
                operator_waiting: false,
                operator: if kind == OperationKind::FirmwareUpdate {
                    OperatorGate::Ready(ContinuationStage::Bootloader)
                } else {
                    OperatorGate::Disabled
                },
            }),
            released: Condvar::new(),
            operator_acknowledged: Condvar::new(),
        }
    }

    /// Releases a prepared operation exactly once after response flush.
    pub(super) fn release(&self) -> Result<(), ServiceRejection> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| service_rejection("backend-worker-unavailable"))?;
        if state.released {
            return Err(service_rejection("operation-already-released"));
        }
        state.released = true;
        self.released.notify_one();
        Ok(())
    }

    /// Atomically accepts cancellation only while the worker still checks it.
    pub(super) fn request_cancellation(&self) -> Result<(), ServiceRejection> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| service_rejection("backend-worker-unavailable"))?;
        if !state.cancellation_open || state.cancellation_requested {
            return Err(service_rejection("operation-not-cancellable"));
        }
        state.cancellation_requested = true;
        state.cancellation_open = false;
        Ok(())
    }

    /// Waits for causal release and reports a cancellation already accepted while queued.
    pub(super) fn wait_for_release(&self) -> Result<bool, ServiceRejection> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| service_rejection("backend-worker-unavailable"))?;
        while !state.released {
            state = self
                .released
                .wait(state)
                .map_err(|_| service_rejection("backend-worker-unavailable"))?;
        }
        Ok(state.cancellation_requested)
    }

    /// Linearizes one causal publication with the cancellation latch.
    pub(super) fn checkpoint_and_publish(
        &self,
        cancellable: bool,
        publish: impl FnOnce() -> Result<(), ServiceEventError>,
    ) -> Result<bool, ServiceEventError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| ServiceEventError::Disconnected)?;
        if state.cancellation_requested {
            return Ok(false);
        }
        // Publication remains inside the same epoch as the latch check. A
        // cancellation accepted after this point is therefore necessarily
        // ordered after this event; one accepted before it suppresses the event.
        publish()?;
        state.cancellation_open = cancellable && !state.operator_started;
        Ok(true)
    }

    /// Publishes a mandatory recovery stage even after cancellation was accepted.
    pub(super) fn recovery_publish(
        &self,
        publish: impl FnOnce() -> Result<(), ServiceEventError>,
    ) -> Result<(), ServiceEventError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| ServiceEventError::Disconnected)?;
        publish()?;
        state.cancellation_open = false;
        Ok(())
    }

    /// Reports whether cancellation was accepted before the recovery barrier.
    pub(super) fn cancellation_requested(&self) -> Result<bool, ServiceRejection> {
        self.state
            .lock()
            .map(|state| state.cancellation_requested)
            .map_err(|_| service_rejection("backend-worker-unavailable"))
    }
}
