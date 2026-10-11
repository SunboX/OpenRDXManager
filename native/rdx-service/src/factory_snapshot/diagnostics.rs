// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Closed, bounded failure metadata without any device-derived values.

use std::io::Write;

use serde::Serialize;

use super::SnapshotError;

/// Fixed collection boundaries; no target, registry ID, path or response bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(super) enum SnapshotStage {
    Arguments,
    OutputPreflight,
    EnumerateCandidates,
    OpenCandidate,
    ReadUsbIdentity,
    SelectDevice,
    PinMedia,
    RevalidateUsbIdentity,
    AcquireScsi,
    InquiryInitial,
    ReadFactoryInfo,
    ReadUsbIdentityBuffer,
    ReadDriveLog,
    ReadModeSense,
    InquiryFinal,
    WriteOutput,
    #[cfg(not(target_os = "macos"))]
    Platform,
}

/// Every existing native error retains its exact sanitized semantic identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(super) enum NativeFailureKind {
    UnsupportedPlatform,
    InvalidRequest,
    TransportUnavailable,
    AccessDenied,
    Busy,
    TimedOut,
    DeviceRemoved,
    EnumerationFailed,
    ResourceLimit,
    EvidenceIncomplete,
    Other,
}

/// One classified failure with a required fixed stage, never raw native text.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct SnapshotFailure {
    pub(super) error: SnapshotError,
    pub(super) stage: SnapshotStage,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct FailureOutput {
    status: &'static str,
    code: &'static str,
    stage: SnapshotStage,
    #[serde(skip_serializing_if = "Option::is_none")]
    native_error: Option<NativeFailureKind>,
}

impl SnapshotError {
    /// Attaches one exact boundary without discarding the classified native error.
    pub(super) const fn at(self, stage: SnapshotStage) -> SnapshotFailure {
        SnapshotFailure { error: self, stage }
    }
}

impl SnapshotFailure {
    /// Writes one bounded JSON line composed entirely of fixed diagnostic values.
    pub(super) fn write_to(self, output: &mut impl Write) -> std::io::Result<()> {
        let native_error = match self.error {
            SnapshotError::Native(kind) => Some(kind),
            _ => None,
        };
        serde_json::to_writer(
            &mut *output,
            &FailureOutput {
                status: "error",
                code: self.error.code(),
                stage: self.stage,
                native_error,
            },
        )?;
        output.write_all(b"\n")?;
        output.flush()
    }
}
