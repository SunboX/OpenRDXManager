// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Non-mutating receiver readiness, before the first mode-4 download command.

use super::*;
use crate::firmware::FirmwareRevision;
use crate::protocol::{
    Command, openrdx_manufacturing_restore_capability, openrdx_serial_capability,
};

/// Checks the reviewed 1.10/1.11 interlocks on the same preserved identity-bound lease.
/// Older/migration receivers retain their existing protocol; no unknown query is sent.
/// No reset, mutation, retry, or clearing of a device safety latch is performed.
pub(super) fn require_ready(
    resolved: &mut ResolvedDevice<'_>,
    installed: FirmwareRevision,
) -> Result<(), HostOperationFailure> {
    if !matches!(installed.get(), 110 | 111) {
        return Ok(());
    }
    let result = check_queries(|command| resolved.execute_firmware(command));
    resolved.revalidate_identity().map_err(|_| {
        HostOperationFailure::preflight("firmware-validating", HostPrimitiveError::StaleBinding)
    })?;
    result.map_err(|cause| HostOperationFailure::preflight("firmware-validating", cause))
}

/// Requires two successful no-data queries without attributing a rejection to a prior write.
fn check_queries(
    mut execute: impl FnMut(&Command) -> CommandDispatch,
) -> Result<(), HostPrimitiveError> {
    let unknown = HostPrimitiveError::FirmwareReceiverReadinessUnknown;
    let manufacturing = execute(&openrdx_manufacturing_restore_capability());
    if !manufacturing
        .response()
        .is_some_and(|response| response.data().is_empty())
    {
        return Err(unknown);
    }
    // Manufacturing GOOD confirms query support; it does not inspect mutation
    // latches or download state. Serial GOOD below checks the manufacturing latch,
    // but does not itself exclude a pending download, activation or serial mutation.
    // The released 1.10 latch lacks a TI COFF boot initializer. A nonzero latch
    // therefore does not prove a prior write, and power cycling need not clear it.
    match execute(&openrdx_serial_capability()) {
        CommandDispatch::Succeeded(response) if response.data().is_empty() => Ok(()),
        _ => Err(unknown),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{DataDirection, SenseData};
    use crate::transport::TransportResponse;

    /// Produces only a bounded synthetic CHECK CONDITION response.
    fn rejected(asc: u8) -> CommandDispatch {
        CommandDispatch::DefinitelyRejected(TransportError::CheckCondition(
            SenseData::parse(&[0x72, 5, asc, 0, 0, 0, 0, 0]).unwrap(),
        ))
    }

    /// Rejections stop transfer but cannot prove mutation history or recommend a reboot.
    #[test]
    fn interlock_requires_exact_read_only_evidence() {
        for (first, second, expected, count) in [
            (
                CommandDispatch::Succeeded(TransportResponse::empty()),
                rejected(0x24),
                Err(HostPrimitiveError::FirmwareReceiverReadinessUnknown),
                2,
            ),
            (
                CommandDispatch::Succeeded(TransportResponse::empty()),
                CommandDispatch::Succeeded(TransportResponse::empty()),
                Ok(()),
                2,
            ),
            (
                rejected(0x24),
                rejected(0x24),
                Err(HostPrimitiveError::FirmwareReceiverReadinessUnknown),
                1,
            ),
            (
                CommandDispatch::Succeeded(TransportResponse::empty()),
                rejected(0x20),
                Err(HostPrimitiveError::FirmwareReceiverReadinessUnknown),
                2,
            ),
            (
                CommandDispatch::Succeeded(TransportResponse::empty()),
                CommandDispatch::CompletionUnknown(TransportError::Timeout),
                Err(HostPrimitiveError::FirmwareReceiverReadinessUnknown),
                2,
            ),
            (
                CommandDispatch::Succeeded(TransportResponse::new(vec![1]).unwrap()),
                rejected(0x24),
                Err(HostPrimitiveError::FirmwareReceiverReadinessUnknown),
                1,
            ),
        ] {
            let mut calls = 0;
            let result = check_queries(|command| {
                calls += 1;
                assert_eq!(command.direction(), DataDirection::None);
                assert!(command.data().is_empty());
                assert_eq!(
                    command.cdb(),
                    if calls == 1 {
                        [0x3b, 2, 0x4d, 0, 0, 1, 0, 0, 0, 0]
                    } else {
                        [0x3b, 2, 0x53, 0, 0, 1, 0, 0, 0, 0]
                    }
                );
                if calls == 1 {
                    first.clone()
                } else {
                    second.clone()
                }
            });
            assert_eq!(result, expected);
            assert_eq!(calls, count);
        }
    }
}
