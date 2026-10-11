// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Internal strict protocol message shapes kept separate from runtime policy.

use super::ServiceRejection;
use serde::Deserialize;
use serde_json::Value;

use crate::model::{FirmwareFileToken, OperationId, OperationRequest};

/// One strict inbound handshake or correlated request.
#[derive(Deserialize)]
#[serde(tag = "type", deny_unknown_fields)]
pub(super) enum InboundMessage {
    /// Initial protocol-version handshake.
    #[serde(rename = "handshake-request")]
    Handshake {
        /// Requested protocol version.
        #[serde(rename = "protocolVersion")]
        protocol_version: u32,
    },
    /// One post-handshake named request.
    #[serde(rename = "request")]
    Request {
        /// Requested protocol version.
        #[serde(rename = "protocolVersion")]
        protocol_version: u32,
        /// Strict monotonic decimal request identifier.
        #[serde(rename = "requestId")]
        request_id: String,
        /// Bounded named service method.
        method: String,
        /// Method-specific strict payload.
        payload: Value,
    },
}

/// Strict empty request payload.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct EmptyPayload {}

/// Strict operation start payload.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct StartPayload {
    /// Caller-generated operation identifier.
    pub(super) operation_id: OperationId,
    /// Exact high-level operation request.
    pub(super) request: OperationRequest,
}

/// Strict cancellation payload.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct CancelPayload {
    /// Exact operation identifier to cancel.
    pub(super) operation_id: OperationId,
}

/// Strict firmware registration header.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct FirmwareRegistrationBeginPayload {
    /// Opaque one-shot file token shared with the eventual operation.
    pub(super) file_token: FirmwareFileToken,
    /// Evidence-backed modern container extension without a path.
    pub(super) extension: String,
    /// Exact bounded image byte count.
    pub(super) total_bytes: u64,
    /// Optional bounded release facts for the separate OpenRDX integrity path.
    pub(super) open_rdx: Option<crate::firmware::OpenRdxImageMetadata>,
}

/// Strict ordered firmware registration chunk.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct FirmwareRegistrationChunkPayload {
    /// Opaque registration owner.
    pub(super) file_token: FirmwareFileToken,
    /// Exact next byte offset.
    pub(super) offset: u64,
    /// Canonical base64 encoding of at most one 4-KiB chunk.
    pub(super) bytes_base64: String,
}

/// Strict firmware registration token payload.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct FirmwareRegistrationTokenPayload {
    /// Opaque registration owner.
    pub(super) file_token: FirmwareFileToken,
}

/// Service response and optional preceding discovery event.
pub(super) struct ScanResult {
    /// Full-list event emitted after a successful scan.
    pub(super) event: Option<Value>,
    /// Correlated scan response.
    pub(super) result: Value,
}

/// Creates one trusted static service rejection.
pub(super) fn service_rejection(reason: impl Into<String>) -> ServiceRejection {
    ServiceRejection::new(reason).expect("trusted service rejection is valid")
}
