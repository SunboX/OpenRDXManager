// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Pointer-free result types shared by native host operations.

use std::fmt::{Debug, Formatter};

use crate::NativeError;

/// Closed mounted-volume file test with independent cleanup evidence.
pub struct FileTestOutcome {
    pub(crate) operation: Result<Vec<u8>, NativeError>,
    pub(crate) operation_certainty: HostOperationOutcome,
    pub(crate) cleanup: HostOperationOutcome,
}

impl FileTestOutcome {
    /// Moves exact readback or failure plus cleanup certainty to the safe parent.
    pub fn into_parts(
        self,
    ) -> (
        Result<Vec<u8>, NativeError>,
        HostOperationOutcome,
        HostOperationOutcome,
    ) {
        (self.operation, self.operation_certainty, self.cleanup)
    }
}

impl Debug for FileTestOutcome {
    /// Redacts bytes and reports only exact result length plus cleanup certainty.
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("FileTestOutcome")
            .field(
                "readback_length",
                &self.operation.as_ref().map_or(0, Vec::len),
            )
            .field("operation_certainty", &self.operation_certainty)
            .field("cleanup", &self.cleanup)
            .finish()
    }
}

/// Recognized filesystem reported for the sole mounted cartridge volume.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MountedFilesystem {
    /// Cross-platform exFAT volume.
    ExFat,
    /// Windows NTFS volume.
    Ntfs,
    /// Native macOS FAT, HFS+, or APFS family.
    MacOs(u32),
}

/// Certainty-preserving result of one Disk Arbitration host operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostOperationOutcome {
    /// Validation or mapping failed before the Disk Arbitration call.
    NotAttempted(NativeError),
    /// A completed callback returned a sanitized known denial or busy dissent.
    DefinitelyRejected(NativeError),
    /// The callback-based API was invoked but success could not be proven.
    CompletionUnknown(NativeError),
    /// Disk Arbitration completed without a dissenter.
    Succeeded,
}
