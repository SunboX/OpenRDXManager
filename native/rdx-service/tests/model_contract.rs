// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

use rdx_service::model::{
    ConfirmationToken, CredentialHandle, CredentialId, FirmwareFileToken, MediaStatusDetails,
    OperationId, ReasonCode, SafeJsonInteger, SupportCorrelationId,
};

const CROSS_LANGUAGE_CONTRACT: &str =
    include_str!("../../../test/fixtures/native-model-contract.json");
use rdx_service::{
    Capability, CapabilityState, DeviceId, DeviceSnapshot, DiscoveryRevision, Media,
    OperationEvent, OperationKind, OperationRequest, RdxError, RiskClass, SenseSummary,
};

/// Adds one unknown field to an object fixture without treating the field name as a literal key.
fn with_unknown_field(mut value: serde_json::Value, key: &str) -> serde_json::Value {
    value
        .as_object_mut()
        .unwrap()
        .insert(key.to_owned(), serde_json::json!("/dev/sg4"));
    value
}

/// Builds one complete production-shaped snapshot for cross-field rejection tests.
fn strict_device_snapshot_value() -> serde_json::Value {
    let unavailable =
        |reason: &str| serde_json::json!({"availability": "unavailable", "reason": reason});
    serde_json::json!({
        "id": "rdx:strict",
        "revision": 7,
        "vendor": "TANDBERG",
        "product": "RDX",
        "serial": "STRICT1",
        "drive": {
            "firmwareRevision": "0283",
            "details": {
                "oemName": unavailable("not-reported"),
                "serialNumber": {"availability": "reported", "value": "STRICT1"},
                "product": {"availability": "reported", "value": "RDX"},
                "vendor": {"availability": "reported", "value": "TANDBERG"},
                "firmwareRevision": {"availability": "reported", "value": "0283"},
                "bornOnDate": unavailable("not-reported"),
                "productType": unavailable("not-reported"),
                "connectionType": unavailable("not-reported"),
                "operationMode": unavailable("not-reported"),
                "sataMode": unavailable("not-reported"),
                "status": unavailable("not-reported"),
                "loadCount": unavailable("not-reported"),
                "errors": unavailable("not-reported"),
                "camState": unavailable("not-reported"),
                "policy": unavailable("not-reported"),
                "powerSource": unavailable("not-reported"),
                "supportStatus": unavailable("not-reported"),
                "senseSummary": unavailable("no-safe-sense-available")
            }
        },
        "media": {
            "id": "media:strict",
            "capacityBytes": 1000,
            "usedBytes": 400,
            "writable": true,
            "details": {
                "vendor": unavailable("not-reported"),
                "model": unavailable("not-reported"),
                "serialNumber": unavailable("not-reported"),
                "status": unavailable("not-reported"),
                "loadCount": unavailable("not-reported"),
                "hddFirmware": unavailable("not-reported"),
                "cartridgeType": unavailable("not-reported"),
                "writeProtected": {"availability": "reported", "value": false},
                "temperatureCelsius": unavailable("not-reported"),
                "capacityBytes": {"availability": "reported", "value": 1000},
                "usedBytes": {"availability": "reported", "value": 400},
                "freeBytes": {"availability": "reported", "value": 600},
                "mounted": {"availability": "reported", "value": true},
                "bytesRead": unavailable("not-reported"),
                "bytesWritten": unavailable("not-reported"),
                "encrypted": unavailable("not-reported"),
                "supportStatus": unavailable("not-reported"),
                "senseSummary": unavailable("no-safe-sense-available")
            }
        },
        "mediaState": "present",
        "capabilities": {}
    })
}

/// Rejects missing reason coverage and contradictory legacy/detail duplicates
/// at the native production snapshot boundary.
#[test]
fn service_snapshots_require_complete_consistent_status_details() {
    let complete = strict_device_snapshot_value();
    assert!(serde_json::from_value::<DeviceSnapshot>(complete.clone()).is_ok());

    let mut missing_drive_details = complete.clone();
    missing_drive_details["drive"]
        .as_object_mut()
        .unwrap()
        .remove("details");
    assert!(serde_json::from_value::<DeviceSnapshot>(missing_drive_details).is_err());

    let mut contradictory_firmware = complete.clone();
    contradictory_firmware["drive"]["firmwareRevision"] = serde_json::json!("9999");
    assert!(serde_json::from_value::<DeviceSnapshot>(contradictory_firmware).is_err());

    let mut contradictory_writable = complete.clone();
    contradictory_writable["media"]["writable"] = serde_json::json!(false);
    assert!(serde_json::from_value::<DeviceSnapshot>(contradictory_writable).is_err());

    let mut missing_media_reason = complete;
    missing_media_reason["media"]["details"]
        .as_object_mut()
        .unwrap()
        .remove("senseSummary");
    assert!(serde_json::from_value::<DeviceSnapshot>(missing_media_reason).is_err());
}

/// Rejects an operating-system path at the public operation request boundary.
#[test]
fn operation_request_does_not_deserialize_an_os_path() {
    let json = r#"{"kind":"self-test","deviceId":"rdx:1","deviceRevision":2,"osPath":"/dev/sg4"}"#;

    assert!(serde_json::from_str::<OperationRequest>(json).is_err());
}

/// Keeps the native public progress contract aligned with firmware retry substate.
#[test]
fn progress_events_accept_only_the_two_bounded_firmware_attempts() {
    let event = serde_json::json!({
        "state": "progress",
        "operationId": "op:firmware-attempt",
        "kind": "firmware-update",
        "deviceId": "rdx:1",
        "deviceRevision": 2,
        "stage": "firmware-writing",
        "progress": 0.4,
        "attempt": 2,
        "cancellationState": "closed",
        "messageKey": "operations.firmwareUpdate.retrying"
    });

    assert_eq!(
        serde_json::to_value(serde_json::from_value::<OperationEvent>(event.clone()).unwrap())
            .unwrap(),
        event
    );
    let mut invalid = event.clone();
    invalid["attempt"] = serde_json::json!(3);
    assert!(serde_json::from_value::<OperationEvent>(invalid).is_err());
    let mut missing_cancellation = event;
    missing_cancellation
        .as_object_mut()
        .unwrap()
        .remove("cancellationState");
    assert!(serde_json::from_value::<OperationEvent>(missing_cancellation).is_err());
}

/// Preserves the JavaScript contract's kebab-case capability strings.
#[test]
fn capability_states_serialize_with_shared_kebab_case_strings() {
    let states = [
        CapabilityState::Available,
        CapabilityState::Busy,
        CapabilityState::UnsupportedProduct,
        CapabilityState::UnsupportedPlatform,
        CapabilityState::WrongMediaState,
        CapabilityState::AuthenticationRequired,
        CapabilityState::InsufficientPermission,
        CapabilityState::HostDependencyMissing,
        CapabilityState::EvidenceIncomplete,
        CapabilityState::TransportUnavailable,
        CapabilityState::HardwareUnverified,
    ];
    let operations = [
        OperationKind::Scan,
        OperationKind::StatusRefresh,
        OperationKind::AccessEnable,
        OperationKind::AccessDisable,
        OperationKind::CredentialCreate,
        OperationKind::CredentialChange,
        OperationKind::CredentialDelete,
        OperationKind::CredentialReset,
        OperationKind::CredentialConfigure,
        OperationKind::SelfTest,
        OperationKind::LedTest,
        OperationKind::WriteReadTest,
        OperationKind::FirmwareUpdate,
        OperationKind::VolumeLabelSet,
        OperationKind::DriveLetterSet,
        OperationKind::DriveLetterReset,
        OperationKind::Format,
        OperationKind::DriveModeSet,
        OperationKind::SataModeSet,
        OperationKind::EjectSafe,
        OperationKind::EjectForce,
    ];

    assert_eq!(
        serde_json::to_value(states).unwrap(),
        serde_json::json!([
            "available",
            "busy",
            "unsupported-product",
            "unsupported-platform",
            "wrong-media-state",
            "authentication-required",
            "insufficient-permission",
            "host-dependency-missing",
            "evidence-incomplete",
            "transport-unavailable",
            "hardware-unverified"
        ])
    );
    assert_eq!(
        serde_json::to_value(operations).unwrap(),
        serde_json::json!([
            "scan",
            "status-refresh",
            "access-enable",
            "access-disable",
            "credential-create",
            "credential-change",
            "credential-delete",
            "credential-reset",
            "credential-configure",
            "self-test",
            "led-test",
            "write-read-test",
            "firmware-update",
            "volume-label-set",
            "drive-letter-set",
            "drive-letter-reset",
            "format",
            "drive-mode-set",
            "sata-mode-set",
            "eject-safe",
            "eject-force"
        ])
    );
}

/// Accepts a high-level self-test request using the shared external enum value.
#[test]
fn operation_request_deserializes_a_high_level_kebab_case_variant() {
    let json = r#"{"kind":"self-test","deviceId":"rdx:1","deviceRevision":2}"#;

    assert!(serde_json::from_str::<OperationRequest>(json).is_ok());
}

/// Rejects device snapshots whose derived media state contradicts their media payload.
#[test]
fn device_snapshot_rejects_inconsistent_media_state_and_unknown_path() {
    let inconsistent = r#"{"id":"rdx:1","revision":2,"vendor":"TANDBERG","product":"RDX","serial":"1","media":null,"mediaState":"present","capabilities":{"self-test":{"state":"available"}}}"#;
    let with_path = r#"{"id":"rdx:1","revision":2,"vendor":"TANDBERG","product":"RDX","serial":"1","media":null,"mediaState":"no-media","capabilities":{"self-test":{"state":"available"}},"osPath":"/dev/sg4"}"#;

    assert!(serde_json::from_str::<DeviceSnapshot>(inconsistent).is_err());
    assert!(serde_json::from_str::<DeviceSnapshot>(with_path).is_err());
}

/// Rejects high-level request values that JavaScript schemas reject before native dispatch.
#[test]
fn operation_request_rejects_invalid_drive_letter() {
    let json = r#"{"kind":"drive-letter-set","deviceId":"rdx:1","deviceRevision":2,"letter":"q"}"#;

    assert!(serde_json::from_str::<OperationRequest>(json).is_err());
}

/// Rejects discovery revisions outside JavaScript's exact safe-integer range.
#[test]
fn operation_request_rejects_revision_beyond_the_shared_safe_integer_range() {
    let json = r#"{"kind":"self-test","deviceId":"rdx:1","deviceRevision":9007199254740992}"#;

    assert!(serde_json::from_str::<OperationRequest>(json).is_err());
}

/// Serializes optional lifecycle fields by omission because the JavaScript schema rejects nulls.
#[test]
fn operation_event_omits_absent_optional_fields_and_rejects_raw_cdbs() {
    let event = OperationEvent::Queued {
        operation_id: OperationId::new("op:1").unwrap(),
        kind: OperationKind::SelfTest,
        device_id: DeviceId::new("rdx:1").unwrap(),
        device_revision: DiscoveryRevision::new(2).unwrap(),
        stage: ReasonCode::new("queued").unwrap(),
        message_key: None,
    };
    let raw_cdb = r#"{"state":"failed","operationId":"op:1","kind":"self-test","deviceId":"rdx:1","deviceRevision":2,"error":{"code":"transport-timeout","messageKey":"errors.transport.timeout","stage":"command-dispatch","category":"transport","retryable":true,"supportCorrelationId":"support:1"},"rawCdb":"1d0400000000"}"#;

    assert_eq!(
        serde_json::to_value(event).unwrap(),
        serde_json::json!({
            "state": "queued",
            "operationId": "op:1",
            "kind": "self-test",
            "deviceId": "rdx:1",
            "deviceRevision": 2,
            "stage": "queued"
        })
    );
    assert!(serde_json::from_str::<OperationEvent>(raw_cdb).is_err());
}

/// Accepts the exact enum strings and serialized model shapes consumed by JavaScript.
#[test]
fn cross_language_fixture_deserializes_with_native_models() {
    let fixture: serde_json::Value = serde_json::from_str(CROSS_LANGUAGE_CONTRACT).unwrap();

    assert_eq!(
        fixture["capabilityStates"],
        serde_json::to_value([
            CapabilityState::Available,
            CapabilityState::Busy,
            CapabilityState::UnsupportedProduct,
            CapabilityState::UnsupportedPlatform,
            CapabilityState::WrongMediaState,
            CapabilityState::AuthenticationRequired,
            CapabilityState::InsufficientPermission,
            CapabilityState::HostDependencyMissing,
            CapabilityState::EvidenceIncomplete,
            CapabilityState::TransportUnavailable,
            CapabilityState::HardwareUnverified,
        ])
        .unwrap()
    );
    assert_eq!(
        fixture["operationKinds"],
        serde_json::to_value([
            OperationKind::Scan,
            OperationKind::StatusRefresh,
            OperationKind::AccessEnable,
            OperationKind::AccessDisable,
            OperationKind::CredentialCreate,
            OperationKind::CredentialChange,
            OperationKind::CredentialDelete,
            OperationKind::CredentialReset,
            OperationKind::CredentialConfigure,
            OperationKind::SelfTest,
            OperationKind::LedTest,
            OperationKind::WriteReadTest,
            OperationKind::FirmwareUpdate,
            OperationKind::VolumeLabelSet,
            OperationKind::DriveLetterSet,
            OperationKind::DriveLetterReset,
            OperationKind::Format,
            OperationKind::DriveModeSet,
            OperationKind::SataModeSet,
            OperationKind::EjectSafe,
            OperationKind::EjectForce,
        ])
        .unwrap()
    );
    assert!(
        serde_json::from_value::<OperationRequest>(fixture["operationRequest"].clone()).is_ok()
    );
    for request in fixture["operationRequests"].as_array().unwrap() {
        let parsed = serde_json::from_value::<OperationRequest>(request.clone()).unwrap();
        assert_eq!(serde_json::to_value(parsed).unwrap(), *request);
    }
    for key in [
        "operationEvent",
        "firmwareRetryEvent",
        "operationFailureEvent",
    ] {
        let parsed = serde_json::from_value::<OperationEvent>(fixture[key].clone()).unwrap();
        assert_eq!(serde_json::to_value(parsed).unwrap(), fixture[key]);
    }
}

/// Prevents renderer-visible numeric values from exceeding JavaScript's exact integer range.
#[test]
fn renderer_safe_numbers_are_fallible_and_never_serialize_out_of_range() {
    const MAXIMUM_SAFE_INTEGER: u64 = 9_007_199_254_740_991;
    let details = serde_json::to_value(MediaStatusDetails::default()).unwrap();

    assert_eq!(
        SafeJsonInteger::new(MAXIMUM_SAFE_INTEGER).unwrap().get(),
        MAXIMUM_SAFE_INTEGER
    );
    assert!(SafeJsonInteger::new(MAXIMUM_SAFE_INTEGER + 1).is_err());
    assert!(DiscoveryRevision::new(MAXIMUM_SAFE_INTEGER + 1).is_err());
    assert!(
        serde_json::from_value::<Media>(serde_json::json!({
            "id": "media:1",
            "capacityBytes": 9_007_199_254_740_992_u64,
            "usedBytes": 9_007_199_254_740_992_u64,
            "details": details
        }))
        .is_err()
    );
    let maximum_media = serde_json::json!({
        "id": "media:1",
        "capacityBytes": MAXIMUM_SAFE_INTEGER,
        "usedBytes": MAXIMUM_SAFE_INTEGER,
        "details": serde_json::to_value(MediaStatusDetails::default()).unwrap()
    });
    assert_eq!(
        serde_json::to_value(serde_json::from_value::<Media>(maximum_media.clone()).unwrap())
            .unwrap(),
        maximum_media
    );
}

/// Matches the distinct JavaScript maximum lengths and RDX device-ID syntax exactly.
#[test]
fn opaque_identifier_types_enforce_their_distinct_contract_limits() {
    let identifier_64 = format!("a{}", "b".repeat(63));
    let identifier_65 = format!("a{}", "b".repeat(64));
    let identifier_128 = format!("a{}", "b".repeat(127));
    let identifier_129 = format!("a{}", "b".repeat(128));

    assert!(DeviceId::new("rdx:").is_err());
    assert!(DeviceId::new("rdx:1").is_ok());
    assert!(OperationId::new(identifier_64.clone()).is_ok());
    assert!(OperationId::new(identifier_65.clone()).is_err());
    assert!(CredentialHandle::new(identifier_64.clone()).is_ok());
    assert!(CredentialHandle::new(identifier_65.clone()).is_err());
    assert!(CredentialId::new(identifier_64.clone()).is_ok());
    assert!(CredentialId::new(identifier_65.clone()).is_err());
    assert!(ConfirmationToken::new(identifier_64.clone()).is_ok());
    assert!(ConfirmationToken::new(identifier_65.clone()).is_err());
    assert!(FirmwareFileToken::new(identifier_64).is_ok());
    assert!(FirmwareFileToken::new(identifier_65).is_err());
    assert!(SupportCorrelationId::new(identifier_128).is_ok());
    assert!(SupportCorrelationId::new(identifier_129).is_err());
}

/// Rejects nested raw-command, path, and prototype-control keys at every renderer-visible boundary.
#[test]
fn nested_models_deny_renderer_hostile_unknown_fields() {
    for key in [
        "osPath",
        "rawCommand",
        "rawCdb",
        "__proto__",
        "constructor",
        "prototype",
    ] {
        assert!(
            serde_json::from_value::<Capability>(with_unknown_field(
                serde_json::json!({"state": "available"}),
                key
            ))
            .is_err()
        );
        assert!(
            serde_json::from_value::<Media>(with_unknown_field(
                serde_json::json!({"id": "media:1"}),
                key
            ))
            .is_err()
        );
        assert!(
            serde_json::from_value::<SenseSummary>(with_unknown_field(
                serde_json::json!({"key": "not-ready", "messageKey": "errors.sense.notReady"}),
                key
            ))
            .is_err()
        );
        assert!(serde_json::from_value::<RdxError>(with_unknown_field(
            serde_json::json!({"code": "transport-timeout", "messageKey": "errors.transport.timeout", "stage": "diagnostic-running", "category": "transport", "retryable": true, "supportCorrelationId": "support:1", "cleanupEvidence": [], "attemptHistory": []}),
            key
        ))
        .is_err());

        let mut event = serde_json::json!({"state": "failed", "operationId": "op:1", "kind": "self-test", "deviceId": "rdx:1", "deviceRevision": 2, "stage": "diagnostic-cleanup", "error": {"code": "transport-timeout", "messageKey": "errors.transport.timeout", "stage": "diagnostic-running", "category": "transport", "retryable": true, "supportCorrelationId": "support:1", "cleanupEvidence": [], "attemptHistory": []}});
        event["error"]
            .as_object_mut()
            .unwrap()
            .insert(key.to_owned(), serde_json::json!("/dev/sg4"));
        assert!(serde_json::from_value::<OperationEvent>(event).is_err());
        assert!(serde_json::from_value::<OperationEvent>(with_unknown_field(
            serde_json::json!({"state": "failed", "operationId": "op:1", "kind": "self-test", "deviceId": "rdx:1", "deviceRevision": 2, "stage": "diagnostic-cleanup", "error": {"code": "transport-timeout", "messageKey": "errors.transport.timeout", "stage": "diagnostic-running", "category": "transport", "retryable": true, "supportCorrelationId": "support:1", "cleanupEvidence": [], "attemptHistory": []}}),
            key
        ))
        .is_err());
    }
}

/// Maps every published operation to the JavaScript safety policy's exact risk class.
#[test]
fn operation_risk_classes_match_the_cross_language_contract() {
    let fixture: serde_json::Value = serde_json::from_str(CROSS_LANGUAGE_CONTRACT).unwrap();
    let operations: Vec<OperationKind> =
        serde_json::from_value(fixture["operationKinds"].clone()).unwrap();
    let expected_risks: Vec<RiskClass> =
        serde_json::from_value(fixture["riskClasses"].clone()).unwrap();

    assert_eq!(
        serde_json::to_value([
            RiskClass::ReadOnly,
            RiskClass::Routine,
            RiskClass::Configuration,
            RiskClass::Critical,
            RiskClass::Destructive,
        ])
        .unwrap(),
        serde_json::json!([
            "read-only",
            "routine",
            "configuration",
            "critical",
            "destructive"
        ])
    );
    assert_eq!(operations.len(), expected_risks.len());
    for (operation, expected_risk) in operations.into_iter().zip(expected_risks) {
        assert_eq!(operation.risk_class(), expected_risk);
    }
}
