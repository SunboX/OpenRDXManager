// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Bounded operation routing and platform failure mapping.

use super::*;

/// Returns the exact target for one implemented host operation.
pub(super) fn operation_target(
    request: &OperationRequest,
) -> Option<(&crate::model::DeviceId, crate::model::DiscoveryRevision)> {
    match request {
        OperationRequest::SelfTest {
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
        | OperationRequest::DriveLetterReset {
            device_id,
            device_revision,
        }
        | OperationRequest::EjectSafe {
            device_id,
            device_revision,
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
        | OperationRequest::Format {
            device_id,
            device_revision,
            ..
        }
        | OperationRequest::EjectForce {
            device_id,
            device_revision,
            ..
        }
        | OperationRequest::StatusRefresh {
            device_id,
            device_revision,
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
        | OperationRequest::FirmwareUpdate {
            device_id,
            device_revision,
            ..
        } => Some((device_id, *device_revision)),
        _ => None,
    }
}

/// Returns the public kind for one implemented host operation.
pub(super) fn operation_kind(request: &OperationRequest) -> OperationKind {
    match request {
        OperationRequest::SelfTest { .. } => OperationKind::SelfTest,
        OperationRequest::LedTest { .. } => OperationKind::LedTest,
        OperationRequest::WriteReadTest { .. } => OperationKind::WriteReadTest,
        OperationRequest::VolumeLabelSet { .. } => OperationKind::VolumeLabelSet,
        OperationRequest::DriveLetterSet { .. } => OperationKind::DriveLetterSet,
        OperationRequest::DriveLetterReset { .. } => OperationKind::DriveLetterReset,
        OperationRequest::Format { .. } => OperationKind::Format,
        OperationRequest::EjectSafe { .. } => OperationKind::EjectSafe,
        OperationRequest::EjectForce { .. } => OperationKind::EjectForce,
        OperationRequest::StatusRefresh { .. } => OperationKind::StatusRefresh,
        OperationRequest::DriveModeSet { .. } => OperationKind::DriveModeSet,
        OperationRequest::SataModeSet { .. } => OperationKind::SataModeSet,
        OperationRequest::FirmwareUpdate { .. } => OperationKind::FirmwareUpdate,
        _ => OperationKind::Scan,
    }
}

/// Maps private platform failures to bounded path-free service reason codes.
pub(super) fn platform_rejection(error: PlatformError) -> ServiceRejection {
    service_rejection(match error {
        PlatformError::StaleDeviceRevision | PlatformError::StaleDeviceBinding => {
            "stale-device-revision"
        }
        PlatformError::DeviceUnavailable | PlatformError::DeviceRemoved => "device-not-found",
        PlatformError::AccessDenied => "privileged-service-unavailable",
        PlatformError::DeviceBusy => "volume-busy",
        PlatformError::OperationCancelled => "operation-cancelled",
        PlatformError::OperationTimedOut => "operation-timeout",
        PlatformError::DiscoveryUnavailable | PlatformError::TransportUnavailable => {
            "transport-unavailable"
        }
        _ => "native-operation-failed",
    })
}

/// Creates the only internal cancellation failure before native mutation dispatch.
pub(super) fn cancelled_host_failure(stage: &'static str) -> HostOperationFailure {
    HostOperationFailure::preflight(stage, crate::operations::HostPrimitiveError::Cancelled)
}
