#![forbid(unsafe_code)]
// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later
#![deny(missing_docs)]

//! Portable, renderer-safe RDX service contracts.

mod progress;

/// Fixed privileged endpoint selection and accept-time peer authorization.
pub mod endpoint;
/// Structured error types safe to serialize across the native-service boundary.
pub mod error;
/// One-shot, read-only vendor-0283 factory snapshot collection for offline research.
pub mod factory_snapshot;
/// Immutable, evidence-backed modern firmware image validation and chunking.
pub mod firmware;
/// Host-owned identity, reconnect, timing, and deterministic fixture operations.
pub mod host;
/// Offline semantic-record migration preparation and private recovery evidence.
pub mod migration;
/// Strict portable device, capability, request, and event model types.
pub mod model;
/// High-level deterministic operation ownership and state machines.
pub mod operations;
/// Service-owned platform discovery, capability, and identity registry boundary.
pub mod platform;
/// Exact, platform-neutral RDX command builders and endian helpers.
pub mod protocol;
/// Pure manufacturing-record serial validation, offline reconstruction, and sector evidence.
pub mod serial_record;
/// Bounded version-one stdin/stdout service protocol and no-device backend.
pub mod service;
/// Explicit command-dispatch certainty and bounded response contracts.
pub mod transport;

/// Re-exports the renderer-safe structured native-service error contract.
pub use error::{
    AttemptEvidence, AttemptHistory, CleanupEvidence, ErrorCategory, FailureEvidence, RdxError,
    SenseSummary,
};
/// Re-exports portable device, capability, operation, and revision model types.
pub use model::{
    Capability, CapabilityState, DeviceId, DeviceIdentity, DeviceSnapshot, DiscoveryRevision,
    Media, MediaState, OperationAttempt, OperationEvent, OperationKind, OperationRequest,
    RiskClass,
};
/// Re-exports the renderer-safe progress cancellation state.
pub use progress::CancellationState;
