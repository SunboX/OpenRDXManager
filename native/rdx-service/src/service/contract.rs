// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Strict JSON, request, inventory, and cross-language contract helpers.

use std::collections::BTreeSet;

use serde::Deserialize;
use serde_json::{Value, json};

use crate::model::{
    CapabilityState, DeviceId, DeviceSnapshot, DiscoveryRevision, OperationId, OperationKind,
    OperationRequest,
};

use super::{MAX_DEVICES, MAX_SAFE_JSON_INTEGER, ServiceMode, ServiceProtocolError};

/// Rejects JavaScript prototype-control keys anywhere in one JSON value.
pub(super) fn reject_prototype_keys(value: &Value) -> Result<(), ServiceProtocolError> {
    match value {
        Value::Object(object) => {
            for (key, nested) in object {
                if matches!(key.as_str(), "__proto__" | "constructor" | "prototype") {
                    return Err(ServiceProtocolError::ProtocolViolation);
                }
                reject_prototype_keys(nested)?;
            }
        }
        Value::Array(values) => {
            for nested in values {
                reject_prototype_keys(nested)?;
            }
        }
        _ => {}
    }
    Ok(())
}

/// Strictly parses one method-specific payload.
pub(super) fn parse_payload<T: for<'de> Deserialize<'de>>(
    payload: Value,
) -> Result<T, ServiceProtocolError> {
    serde_json::from_value(payload).map_err(|_| ServiceProtocolError::ProtocolViolation)
}

/// Parses exactly `request:<positive 1..16 digit integer>`.
pub(super) fn parse_request_id(value: &str) -> Result<u64, ServiceProtocolError> {
    let Some(digits) = value.strip_prefix("request:") else {
        return Err(ServiceProtocolError::ProtocolViolation);
    };
    if digits.is_empty()
        || digits.len() > 16
        || digits.starts_with('0')
        || !digits.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(ServiceProtocolError::ProtocolViolation);
    }
    digits
        .parse::<u64>()
        .ok()
        .filter(|number| *number <= MAX_SAFE_JSON_INTEGER)
        .ok_or(ServiceProtocolError::ProtocolViolation)
}

/// Mirrors JavaScript's case-insensitive `op:` namespace and 1..60 suffix.
pub(super) fn valid_operation_id(value: &OperationId) -> bool {
    let bytes = value.as_str().as_bytes();
    let Some(prefix) = bytes.get(..3) else {
        return false;
    };
    let suffix = &bytes[3..];
    prefix.eq_ignore_ascii_case(b"op:")
        && !suffix.is_empty()
        && suffix.len() <= 60
        && suffix
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b':' | b'-'))
}

/// Validates an unknown method name before returning a stable unsupported result.
pub(super) fn valid_method_name(value: &str) -> bool {
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 64
        && bytes[0].is_ascii_lowercase()
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
}

/// Builds one exact outer success response around a method-specific public result.
pub(super) fn response(request_id: &str, result: Value) -> Value {
    json!({"type": "response", "requestId": request_id, "ok": true, "result": result})
}

/// Builds the strict empty action success result.
pub(super) fn action_success() -> Value {
    json!({"ok": true})
}

/// Builds one bounded action failure result.
pub(super) fn action_failure(reason: &str) -> Value {
    json!({"ok": false, "reason": reason})
}

/// Verifies inventory bounds, identities, media consistency, and no-device truth.
pub(super) fn validate_inventory(
    devices: &[DeviceSnapshot],
    mode: ServiceMode,
) -> Result<(), ServiceProtocolError> {
    if devices.len() > MAX_DEVICES || (mode == ServiceMode::NoDevice && !devices.is_empty()) {
        return Err(ServiceProtocolError::BackendContract);
    }
    let mut ids = BTreeSet::new();
    for device in devices {
        if !device.has_consistent_media_state()
            || !device.has_consistent_status_details()
            || !ids.insert(device.id.as_str())
        {
            return Err(ServiceProtocolError::BackendContract);
        }
    }
    Ok(())
}

/// Returns the exact high-level kind carried by an operation request.
pub(super) fn operation_kind(request: &OperationRequest) -> OperationKind {
    match request {
        OperationRequest::Scan => OperationKind::Scan,
        OperationRequest::StatusRefresh { .. } => OperationKind::StatusRefresh,
        OperationRequest::AccessEnable { .. } => OperationKind::AccessEnable,
        OperationRequest::AccessDisable { .. } => OperationKind::AccessDisable,
        OperationRequest::CredentialCreate { .. } => OperationKind::CredentialCreate,
        OperationRequest::CredentialChange { .. } => OperationKind::CredentialChange,
        OperationRequest::CredentialDelete { .. } => OperationKind::CredentialDelete,
        OperationRequest::CredentialReset { .. } => OperationKind::CredentialReset,
        OperationRequest::CredentialConfigure { .. } => OperationKind::CredentialConfigure,
        OperationRequest::SelfTest { .. } => OperationKind::SelfTest,
        OperationRequest::LedTest { .. } => OperationKind::LedTest,
        OperationRequest::WriteReadTest { .. } => OperationKind::WriteReadTest,
        OperationRequest::FirmwareUpdate { .. } => OperationKind::FirmwareUpdate,
        OperationRequest::VolumeLabelSet { .. } => OperationKind::VolumeLabelSet,
        OperationRequest::DriveLetterSet { .. } => OperationKind::DriveLetterSet,
        OperationRequest::DriveLetterReset { .. } => OperationKind::DriveLetterReset,
        OperationRequest::Format { .. } => OperationKind::Format,
        OperationRequest::DriveModeSet { .. } => OperationKind::DriveModeSet,
        OperationRequest::SataModeSet { .. } => OperationKind::SataModeSet,
        OperationRequest::EjectSafe { .. } => OperationKind::EjectSafe,
        OperationRequest::EjectForce { .. } => OperationKind::EjectForce,
    }
}

/// Returns the exact opaque identity/revision target or none for Scan.
pub(super) fn operation_target(
    request: &OperationRequest,
) -> Option<(&DeviceId, DiscoveryRevision)> {
    match request {
        OperationRequest::Scan => None,
        OperationRequest::StatusRefresh {
            device_id,
            device_revision,
        }
        | OperationRequest::AccessEnable {
            device_id,
            device_revision,
            ..
        }
        | OperationRequest::AccessDisable {
            device_id,
            device_revision,
        }
        | OperationRequest::CredentialCreate {
            device_id,
            device_revision,
            ..
        }
        | OperationRequest::CredentialChange {
            device_id,
            device_revision,
            ..
        }
        | OperationRequest::CredentialDelete {
            device_id,
            device_revision,
            ..
        }
        | OperationRequest::CredentialReset {
            device_id,
            device_revision,
            ..
        }
        | OperationRequest::CredentialConfigure {
            device_id,
            device_revision,
            ..
        }
        | OperationRequest::SelfTest {
            device_id,
            device_revision,
        }
        | OperationRequest::LedTest {
            device_id,
            device_revision,
        }
        | OperationRequest::WriteReadTest {
            device_id,
            device_revision,
        }
        | OperationRequest::FirmwareUpdate {
            device_id,
            device_revision,
            ..
        }
        | OperationRequest::VolumeLabelSet {
            device_id,
            device_revision,
            ..
        }
        | OperationRequest::DriveLetterSet {
            device_id,
            device_revision,
            ..
        }
        | OperationRequest::DriveLetterReset {
            device_id,
            device_revision,
        }
        | OperationRequest::Format {
            device_id,
            device_revision,
            ..
        }
        | OperationRequest::DriveModeSet {
            device_id,
            device_revision,
            ..
        }
        | OperationRequest::SataModeSet {
            device_id,
            device_revision,
            ..
        }
        | OperationRequest::EjectSafe {
            device_id,
            device_revision,
        }
        | OperationRequest::EjectForce {
            device_id,
            device_revision,
            ..
        } => Some((device_id, *device_revision)),
    }
}

/// Maps a non-available capability state to its exact shared external spelling.
pub(super) fn capability_reason(state: CapabilityState) -> &'static str {
    match state {
        CapabilityState::Available => "available",
        CapabilityState::Busy => "busy",
        CapabilityState::UnsupportedProduct => "unsupported-product",
        CapabilityState::UnsupportedPlatform => "unsupported-platform",
        CapabilityState::WrongMediaState => "wrong-media-state",
        CapabilityState::AuthenticationRequired => "authentication-required",
        CapabilityState::InsufficientPermission => "insufficient-permission",
        CapabilityState::HostDependencyMissing => "host-dependency-missing",
        CapabilityState::EvidenceIncomplete => "evidence-incomplete",
        CapabilityState::TransportUnavailable => "transport-unavailable",
        CapabilityState::HardwareUnverified => "hardware-unverified",
    }
}
