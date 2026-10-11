// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

use rdx_service::error::{
    AttemptEvidence, AttemptHistory, CleanupEvidence, ErrorCategory, FailureEvidence, RdxError,
};
use rdx_service::model::{
    DeviceId, DiscoveryRevision, MessageKey, OperationEvent, OperationId, OperationKind,
    ReasonCode, SupportCorrelationId,
};
use rdx_service::transport::DispatchCertainty;

/// Builds one safe bounded evidence record.
fn evidence(stage: &str, code: &str) -> FailureEvidence {
    FailureEvidence::new(
        ReasonCode::new(stage).unwrap(),
        ReasonCode::new(code).unwrap(),
        Some(DispatchCertainty::CompletionUnknown),
        None,
    )
    .unwrap()
}

/// Proves native serialization retains terminal, primary, cleanup, and retry evidence.
#[test]
fn failed_event_serializes_the_lossless_strict_terminal_contract() {
    let event = OperationEvent::Failed {
        operation_id: OperationId::new("op:failure").unwrap(),
        kind: OperationKind::FirmwareUpdate,
        device_id: DeviceId::new("rdx:failure").unwrap(),
        device_revision: DiscoveryRevision::new(7).unwrap(),
        stage: ReasonCode::new("firmware-readback").unwrap(),
        error: RdxError {
            code: ReasonCode::new("firmware-revision-mismatch").unwrap(),
            message_key: MessageKey::new("errors.firmware.revisionMismatch").unwrap(),
            stage: ReasonCode::new("firmware-writing").unwrap(),
            category: ErrorCategory::Transport,
            retryable: false,
            dispatch_certainty: None,
            sense_summary: None,
            support_correlation_id: SupportCorrelationId::new("support:failure").unwrap(),
            cleanup_evidence: CleanupEvidence::new(vec![evidence(
                "firmware-finalizing",
                "transport-timeout",
            )])
            .unwrap(),
            attempt_history: AttemptHistory::new(vec![
                AttemptEvidence::new(1, evidence("firmware-writing", "transport-unavailable"))
                    .unwrap(),
            ])
            .unwrap(),
        },
    };

    assert_eq!(
        serde_json::to_value(event).unwrap(),
        serde_json::json!({
            "state": "failed",
            "operationId": "op:failure",
            "kind": "firmware-update",
            "deviceId": "rdx:failure",
            "deviceRevision": 7,
            "stage": "firmware-readback",
            "error": {
                "code": "firmware-revision-mismatch",
                "messageKey": "errors.firmware.revisionMismatch",
                "stage": "firmware-writing",
                "category": "transport",
                "retryable": false,
                "supportCorrelationId": "support:failure",
                "cleanupEvidence": [{
                    "stage": "firmware-finalizing",
                    "code": "transport-timeout",
                    "dispatchCertainty": "completion-unknown"
                }],
                "attemptHistory": [{
                    "attempt": 1,
                    "stage": "firmware-writing",
                    "code": "transport-unavailable",
                    "dispatchCertainty": "completion-unknown"
                }]
            }
        })
    );
}

/// Proves native deserialization rejects evidence beyond the shared bounds.
#[test]
fn failure_evidence_deserialization_is_bounded() {
    let cleanup =
        vec![serde_json::json!({"stage":"firmware-finalizing","code":"transport-timeout"}); 17];
    let failure = serde_json::json!({
        "state": "failed",
        "operationId": "op:failure",
        "kind": "firmware-update",
        "deviceId": "rdx:failure",
        "deviceRevision": 7,
        "stage": "firmware-readback",
        "error": {
            "code": "firmware-revision-mismatch",
            "messageKey": "errors.firmware.revisionMismatch",
            "stage": "firmware-writing",
            "category": "transport",
            "retryable": false,
            "supportCorrelationId": "support:failure",
            "cleanupEvidence": cleanup,
            "attemptHistory": []
        }
    });

    assert!(serde_json::from_value::<OperationEvent>(failure).is_err());
}

/// Proves retry evidence is both bounded and monotonic at native deserialization.
#[test]
fn attempt_history_rejects_overflow_regression_and_out_of_range_attempts() {
    let record = serde_json::json!({
        "attempt": 1,
        "stage": "firmware-writing",
        "code": "transport-timeout"
    });
    assert!(
        serde_json::from_value::<AttemptHistory>(serde_json::json!([
            record.clone(),
            record.clone(),
            record.clone(),
            record.clone(),
            record.clone()
        ]))
        .is_err()
    );
    assert!(
        serde_json::from_value::<AttemptHistory>(serde_json::json!([
            {"attempt": 2, "stage": "firmware-writing", "code": "transport-timeout"},
            {"attempt": 1, "stage": "firmware-writing", "code": "transport-unavailable"}
        ]))
        .is_err()
    );
    assert!(
        serde_json::from_value::<AttemptEvidence>(serde_json::json!({
            "attempt": 3,
            "stage": "firmware-writing",
            "code": "transport-timeout"
        }))
        .is_err()
    );
}

/// Proves failure evidence can never claim a successfully completed dispatch.
#[test]
fn failure_evidence_rejects_succeeded_dispatch_certainty() {
    assert!(
        serde_json::from_value::<FailureEvidence>(serde_json::json!({
            "stage": "firmware-finalizing",
            "code": "transport-timeout",
            "dispatchCertainty": "succeeded"
        }))
        .is_err()
    );
}

/// Proves the complete terminal error cannot claim successful primary dispatch.
#[test]
fn rdx_error_rejects_succeeded_primary_dispatch_certainty() {
    assert!(
        serde_json::from_value::<RdxError>(serde_json::json!({
            "code": "transport-timeout",
            "messageKey": "errors.transport.timeout",
            "stage": "diagnostic-running",
            "category": "transport",
            "retryable": false,
            "dispatchCertainty": "succeeded",
            "supportCorrelationId": "support:primary-succeeded",
            "cleanupEvidence": [],
            "attemptHistory": []
        }))
        .is_err()
    );
}

/// Proves strict canonical round trips preserve independently validated nested evidence.
#[test]
fn rdx_error_round_trip_is_strict_without_weakening_nested_evidence() {
    let canonical = serde_json::json!({
        "code": "transport-timeout",
        "messageKey": "errors.transport.timeout",
        "stage": "firmware-finalizing",
        "category": "transport",
        "retryable": true,
        "dispatchCertainty": "definitely-rejected",
        "supportCorrelationId": "support:strict-roundtrip",
        "cleanupEvidence": [{
            "stage": "firmware-finalizing",
            "code": "cleanup-failed",
            "dispatchCertainty": "completion-unknown"
        }],
        "attemptHistory": [{
            "attempt": 1,
            "stage": "firmware-writing",
            "code": "transport-timeout",
            "dispatchCertainty": "not-sent"
        }]
    });
    let parsed = serde_json::from_value::<RdxError>(canonical.clone()).unwrap();
    assert_eq!(serde_json::to_value(parsed).unwrap(), canonical);

    let mut unknown_field = canonical.clone();
    unknown_field["unexpected"] = serde_json::json!(true);
    let mut unknown_certainty = canonical.clone();
    unknown_certainty["dispatchCertainty"] = serde_json::json!("maybe-sent");
    let mut invalid_nested_success = canonical.clone();
    invalid_nested_success["attemptHistory"][0]["dispatchCertainty"] =
        serde_json::json!("succeeded");
    let mut missing_history = canonical;
    missing_history
        .as_object_mut()
        .unwrap()
        .remove("attemptHistory");

    for invalid in [
        unknown_field,
        unknown_certainty,
        invalid_nested_success,
        missing_history,
    ] {
        assert!(serde_json::from_value::<RdxError>(invalid).is_err());
    }
}

/// Proves retry history is only recovered attempt one at a firmware retry stage.
#[test]
fn attempt_evidence_rejects_attempt_two_and_non_retry_stages() {
    assert!(
        serde_json::from_value::<AttemptEvidence>(serde_json::json!({
            "attempt": 2,
            "stage": "firmware-writing",
            "code": "transport-timeout"
        }))
        .is_err()
    );
    assert!(
        serde_json::from_value::<AttemptEvidence>(serde_json::json!({
            "attempt": 1,
            "stage": "device-reconnecting",
            "code": "transport-timeout"
        }))
        .is_err()
    );
    assert!(
        serde_json::from_value::<AttemptHistory>(serde_json::json!([
            {"attempt": 1, "stage": "firmware-writing", "code": "transport-timeout"},
            {"attempt": 1, "stage": "firmware-finalizing", "code": "transport-unavailable"}
        ]))
        .is_err()
    );
}
