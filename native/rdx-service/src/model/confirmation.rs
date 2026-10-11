// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Service-owned destructive confirmation request model.

use serde::{Deserialize, Serialize};

use super::{DeviceId, DiscoveryRevision, Filesystem, OperationKind, OperationRequest};

/// Narrow destructive-action confirmation request accepted only by the native service.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum ConfirmationRequest {
    /// Requests one format confirmation bound to the exact filesystem option.
    Format {
        /// Opaque service-issued device ID.
        device_id: DeviceId,
        /// Exact revision whose current media fingerprint is confirmed.
        device_revision: DiscoveryRevision,
        /// Exact filesystem included in the destructive confirmation.
        filesystem: Filesystem,
    },
    /// Requests one force-eject confirmation for the exact current cartridge.
    EjectForce {
        /// Opaque service-issued device ID.
        device_id: DeviceId,
        /// Exact revision whose current media fingerprint is confirmed.
        device_revision: DiscoveryRevision,
    },
}

impl ConfirmationRequest {
    /// Returns the exact opaque target identity bound to this confirmation.
    #[must_use]
    pub const fn target(&self) -> (&DeviceId, DiscoveryRevision) {
        match self {
            Self::Format {
                device_id,
                device_revision,
                ..
            }
            | Self::EjectForce {
                device_id,
                device_revision,
            } => (device_id, *device_revision),
        }
    }

    /// Returns the destructive operation kind bound to this confirmation.
    #[must_use]
    pub const fn operation_kind(&self) -> OperationKind {
        match self {
            Self::Format { .. } => OperationKind::Format,
            Self::EjectForce { .. } => OperationKind::EjectForce,
        }
    }

    /// Checks whether one start request exactly matches this confirmed action and options.
    #[must_use]
    pub fn matches_operation(&self, request: &OperationRequest) -> bool {
        match (self, request) {
            (
                Self::Format {
                    device_id,
                    device_revision,
                    filesystem,
                },
                OperationRequest::Format {
                    device_id: request_id,
                    device_revision: request_revision,
                    filesystem: request_filesystem,
                    ..
                },
            ) => {
                device_id == request_id
                    && device_revision == request_revision
                    && filesystem == request_filesystem
            }
            (
                Self::EjectForce {
                    device_id,
                    device_revision,
                },
                OperationRequest::EjectForce {
                    device_id: request_id,
                    device_revision: request_revision,
                    ..
                },
            ) => device_id == request_id && device_revision == request_revision,
            _ => false,
        }
    }
}
