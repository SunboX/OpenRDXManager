// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Deterministic self-test and LED-test state machines.

use crate::host::DeviceSession;
use crate::model::OperationKind;
use crate::protocol::{led_test, self_test};
use crate::transport::CommandDispatch;

use super::{
    FailureAccumulator, OperationCompletion, OperationContext, OperationFailure, OperationIssue,
    OperationReport, OperationStage,
};

/// Runs SEND DIAGNOSTIC only after fresh exact-session validation and cleanup.
///
/// Cancellation is accepted while diagnostic activity remains safe. Every
/// command outcome still reaches the Phase 1 diagnostic-cleanup barrier.
///
/// # Errors
///
/// Returns [`OperationFailure`] with a separate primary cause, cleanup
/// evidence, and terminal stage.
pub fn run_self_test(
    session: &mut DeviceSession,
    mut context: OperationContext,
) -> Result<OperationReport, OperationFailure> {
    let mut failures = FailureAccumulator::default();
    if !require_kind_and_session(
        session,
        &context,
        OperationKind::SelfTest,
        OperationStage::DiagnosticRunning,
        &mut failures,
    ) {
        return Err(context.fail(failures));
    }
    record_emit(
        &mut context,
        OperationStage::DiagnosticRunning,
        0.1,
        "operations.selfTest.running",
        &mut failures,
    );

    if !context.cancellation_requested() {
        if let Err(error) = session.revalidate() {
            failures.record(
                OperationStage::DiagnosticRunning,
                OperationIssue::Host(error),
            );
        } else if let Some(issue) = dispatch_issue(session.execute(&self_test())) {
            failures.record(OperationStage::DiagnosticRunning, issue);
        }
    }
    let cancelled = context.close_cancellation();

    record_emit(
        &mut context,
        OperationStage::DiagnosticCleanup,
        1.0,
        "operations.selfTest.cleanup",
        &mut failures,
    );
    if let Err(error) = session.revalidate() {
        failures.record(
            OperationStage::DiagnosticCleanup,
            OperationIssue::Host(error),
        );
    }

    finish(context, failures, cancelled)
}

/// Runs LED-on only after fresh validation and always performs LED-off recovery.
///
/// A service-owned recovery guard retains the exact original lease whenever
/// LED-on is attempted. Adapter panics are converted to completion-unknown
/// evidence, and OFF is attempted for success, failure, removal, or cancellation.
///
/// # Errors
///
/// Returns [`OperationFailure`] with primary and cleanup evidence preserved in
/// observation order. Failed OFF leaves the guard armed for graceful shutdown.
pub fn run_led_test(
    session: &mut DeviceSession,
    mut context: OperationContext,
) -> Result<OperationReport, OperationFailure> {
    let mut failures = FailureAccumulator::default();
    if !require_kind_and_session(
        session,
        &context,
        OperationKind::LedTest,
        OperationStage::LedTesting,
        &mut failures,
    ) {
        return Err(context.fail(failures));
    }
    record_emit(
        &mut context,
        OperationStage::LedTesting,
        0.1,
        "operations.ledTest.testing",
        &mut failures,
    );

    let guard_was_already_armed = session.has_pending_led_recovery();
    if guard_was_already_armed {
        failures.record(
            OperationStage::LedTesting,
            OperationIssue::Host(crate::host::HostOperationError::RecoveryAlreadyArmed),
        );
    }

    if !guard_was_already_armed && !context.cancellation_requested() {
        if let Err(error) = session.revalidate() {
            failures.record(OperationStage::LedTesting, OperationIssue::Host(error));
        } else {
            let outcome = session.execute(&led_test(true));
            if matches!(
                outcome,
                CommandDispatch::Succeeded(_) | CommandDispatch::CompletionUnknown(_)
            ) && let Err(error) = session.arm_led_recovery()
            {
                failures.record(OperationStage::LedTesting, OperationIssue::Host(error));
            }
            if let Some(issue) = dispatch_issue(outcome) {
                failures.record(OperationStage::LedTesting, issue);
            } else if let Err(error) = session.wait_for_led_phase() {
                failures.record(OperationStage::LedTesting, OperationIssue::Host(error));
            }
        }
    }
    let cancelled = context.close_cancellation();

    record_emit(
        &mut context,
        OperationStage::LedRestoring,
        0.75,
        "operations.ledTest.restoring",
        &mut failures,
    );
    if !guard_was_already_armed {
        if let Some(issue) = dispatch_issue(session.restore_led_off()) {
            failures.record(OperationStage::LedRestoring, issue);
        }
    }

    record_emit(
        &mut context,
        OperationStage::LedReadback,
        1.0,
        "operations.ledTest.readback",
        &mut failures,
    );
    if let Err(error) = session.revalidate() {
        failures.record(OperationStage::LedReadback, OperationIssue::Host(error));
    }

    finish(context, failures, cancelled)
}

/// Requires the exact kind and the context's complete session binding.
fn require_kind_and_session(
    session: &DeviceSession,
    context: &OperationContext,
    expected: OperationKind,
    stage: OperationStage,
    failures: &mut FailureAccumulator,
) -> bool {
    let actual = context.owner().kind();
    if actual != expected {
        failures.record(
            stage,
            OperationIssue::WrongOperationKind { expected, actual },
        );
        return false;
    }
    let device = session.device();
    if !session.is_active()
        || !context.owner().belongs_to(session)
        || context.owner().device() != device.identity()
        || context.owner().product_family() != device.product_family()
        || context.owner().generation().get() != device.generation().get()
    {
        failures.record(stage, OperationIssue::SessionBindingChanged);
        return false;
    }
    true
}

/// Converts every non-success dispatch into explicit certainty/cause evidence.
fn dispatch_issue(outcome: CommandDispatch) -> Option<OperationIssue> {
    let certainty = outcome.certainty();
    outcome
        .error()
        .cloned()
        .map(|error| OperationIssue::Dispatch { certainty, error })
}

/// Emits a trusted event or records the impossible invariant as evidence.
fn record_emit(
    context: &mut OperationContext,
    stage: OperationStage,
    fraction: f64,
    message_key: &'static str,
    failures: &mut FailureAccumulator,
) {
    if let Err(issue) = context.emit(stage, fraction, message_key) {
        failures.record(stage, issue);
    }
}

/// Returns failure before cancellation, otherwise the requested safe completion.
fn finish(
    context: OperationContext,
    failures: FailureAccumulator,
    cancelled: bool,
) -> Result<OperationReport, OperationFailure> {
    if failures.has_failure() {
        Err(context.fail(failures))
    } else if cancelled {
        Ok(context.complete(OperationCompletion::Cancelled))
    } else {
        Ok(context.complete(OperationCompletion::Succeeded))
    }
}
