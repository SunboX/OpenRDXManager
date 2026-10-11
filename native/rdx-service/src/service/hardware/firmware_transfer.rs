// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Private firmware chunk dispatch, bounded diagnostics and failure policy.

use super::*;

/// Streams one complete mode-4 attempt from byte zero on one retained lease.
pub(super) fn transfer_registry_firmware(
    resolved: &mut crate::platform::ResolvedDevice<'_>,
    image: &FirmwareImage,
    observer: &mut impl HostOperationObserver,
) -> Result<(), (HostOperationFailure, bool)> {
    transfer_firmware_image(image, observer, |command| {
        resolved.execute_firmware(command)
    })
}

/// Streams immutable chunks through a private dispatch boundary, recording only
/// fixed failure position/cause codes, never payload, paths, serials or raw sense.
fn transfer_firmware_image(
    image: &FirmwareImage,
    observer: &mut impl HostOperationObserver,
    mut execute: impl FnMut(&crate::protocol::Command) -> CommandDispatch,
) -> Result<(), (HostOperationFailure, bool)> {
    let mut chunks = image.registry_chunks().peekable();
    while let Some(chunk) = chunks.next() {
        let command = write_buffer(0x04, chunk.offset(), chunk.bytes())
            .map_err(|_| (firmware_preflight_failure("firmware-writing"), false))?;
        let outcome = execute(&command);
        if let Some(failure) = firmware_dispatch_failure("firmware-writing", &outcome) {
            observer.diagnostic(if chunk.offset() == 0 {
                "firmware-transfer-first-chunk-failed"
            } else if chunks.peek().is_none() {
                "firmware-transfer-final-chunk-failed"
            } else {
                "firmware-transfer-intermediate-chunk-failed"
            });
            observer.diagnostic(failure.0.code());
            observer.diagnostic(if failure.1 {
                "firmware-transfer-retry-eligible"
            } else {
                "firmware-transfer-retry-suppressed"
            });
            return Err(failure);
        }
    }
    observer.diagnostic("firmware-transfer-complete");
    Ok(())
}

/// Converts exact dispatch evidence into a sanitized failure and retry disposition.
pub(super) fn firmware_dispatch_failure(
    stage: &'static str,
    outcome: &CommandDispatch,
) -> Option<(HostOperationFailure, bool)> {
    let error = outcome.error()?;
    let cause = match error {
        TransportError::Timeout => HostPrimitiveError::TimedOut,
        TransportError::DeviceRemoved => HostPrimitiveError::StaleBinding,
        TransportError::CheckCondition(sense) => firmware_failure::check_condition_cause(sense),
        TransportError::CompatibilityStagingSignature => {
            HostPrimitiveError::FirmwareSignatureRejected
        }
        TransportError::DataOutIncomplete => HostPrimitiveError::FirmwareTransferIncomplete,
        TransportError::Unavailable | TransportError::InactiveSession => {
            HostPrimitiveError::FirmwareTransportUnavailable
        }
        TransportError::ResponseTooLarge { .. }
        | TransportError::MissingFixtureResponse
        | TransportError::AdapterPanic => HostPrimitiveError::FirmwareTransportInvalid,
    };
    let failure = match outcome.certainty() {
        DispatchCertainty::Succeeded => return None,
        DispatchCertainty::NotSent => PrimitiveFailure::not_attempted(cause),
        DispatchCertainty::DefinitelyRejected => PrimitiveFailure::definitely_rejected(cause),
        DispatchCertainty::CompletionUnknown => PrimitiveFailure::completion_unknown(cause),
    };
    let retryable = error.permits_firmware_retry()
        && !error.is_firmware_signature_rejection()
        && matches!(
            outcome.certainty(),
            DispatchCertainty::NotSent
                | DispatchCertainty::DefinitelyRejected
                | DispatchCertainty::CompletionUnknown
        );
    Some((
        HostOperationFailure::from_primitive(stage, failure),
        retryable,
    ))
}

/// Creates one sanitized image/identity/policy preflight failure.
pub(super) fn firmware_preflight_failure(stage: &'static str) -> HostOperationFailure {
    HostOperationFailure::preflight(stage, HostPrimitiveError::Other)
}

/// Creates one completion-unknown reconnect/readback failure.
pub(super) fn firmware_reconnect_failure() -> HostOperationFailure {
    HostOperationFailure::from_primitive(
        "device-reconnecting",
        PrimitiveFailure::completion_unknown(HostPrimitiveError::FirmwareReconnectFailed),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::TransportResponse;

    /// Post-transfer verification failure must not masquerade as stale admission.
    #[test]
    fn reconnect_failure_preserves_unknown_completion_with_a_specific_cause() {
        let failure = firmware_reconnect_failure();
        assert_eq!(failure.code(), "firmware-reconnect-failed");
        assert_eq!(failure.stage(), "device-reconnecting");
        assert_eq!(
            failure.certainty(),
            crate::operations::MutationCertainty::CompletionUnknown
        );
        assert_eq!(
            HostPrimitiveError::StaleBinding.code(),
            "stale-device-revision"
        );
    }

    /// Collects fixed breadcrumbs without device, logger or lifecycle side effects.
    #[derive(Default)]
    struct Trace(Vec<&'static str>);

    impl HostOperationObserver for Trace {
        /// Chunk dispatch must not manufacture lifecycle transitions.
        fn reached(&mut self, _stage: &'static str, _cancellable: bool) -> bool {
            panic!("transfer diagnostics cannot advance lifecycle");
        }

        /// Retains only the service's closed diagnostic vocabulary.
        fn diagnostic(&mut self, code: &'static str) {
            self.0.push(code);
        }
    }

    /// Exact invalid-field sense stops at the rejected chunk and forbids retry.
    #[test]
    fn invalid_fields_stop_transfer_and_report_bounded_position() {
        let (bytes, metadata) = crate::firmware::openrdx_test_image();
        let image = FirmwareImage::from_openrdx_bytes(bytes, &metadata).unwrap();
        let last = image.registry_chunks().count() - 1;
        for (failed_index, expected_position) in [
            (0, "firmware-transfer-first-chunk-failed"),
            (3, "firmware-transfer-intermediate-chunk-failed"),
            (last, "firmware-transfer-final-chunk-failed"),
        ] {
            let mut trace = Trace::default();
            let mut dispatched = 0;
            let result = transfer_firmware_image(&image, &mut trace, |command| {
                assert_eq!(&command.cdb()[..3], &[0x3B, 0x04, 0]);
                let index = dispatched;
                dispatched += 1;
                if index == failed_index {
                    CommandDispatch::DefinitelyRejected(TransportError::CheckCondition(
                        crate::protocol::SenseData::parse(&[0x72, 0x05, 0x24, 0, 0, 0, 0, 0])
                            .unwrap(),
                    ))
                } else {
                    CommandDispatch::Succeeded(TransportResponse::empty())
                }
            });
            let (failure, retryable) = result.unwrap_err();
            assert_eq!(failure.code(), "firmware-command-invalid");
            assert_eq!(failure.stage(), "firmware-writing");
            assert!(!retryable);
            assert_eq!(dispatched, failed_index + 1);
            assert_eq!(
                trace.0,
                [
                    expected_position,
                    "firmware-command-invalid",
                    "firmware-transfer-retry-suppressed"
                ]
            );
        }
    }

    /// A fully accepted transfer emits one summary, not unbounded per-chunk logs.
    #[test]
    fn complete_transfer_preserves_exact_bytes_and_emits_one_summary() {
        let (bytes, metadata) = crate::firmware::openrdx_test_image();
        let image = FirmwareImage::from_openrdx_bytes(bytes.clone(), &metadata).unwrap();
        let mut sent = Vec::new();
        let mut trace = Trace::default();
        transfer_firmware_image(&image, &mut trace, |command| {
            assert_eq!(&command.cdb()[..3], &[0x3B, 0x04, 0]);
            let offset =
                u32::from_be_bytes([0, command.cdb()[3], command.cdb()[4], command.cdb()[5]]);
            assert_eq!(offset as usize, sent.len());
            sent.extend_from_slice(command.data_out());
            CommandDispatch::Succeeded(TransportResponse::empty())
        })
        .unwrap();
        assert_eq!(sent, bytes);
        assert_eq!(trace.0, ["firmware-transfer-complete"]);
    }
}
