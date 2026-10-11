// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Normal host unmount ordering and certainty, independent of D-Bus transport.

use crate::{HostOperationOutcome, NativeError};

/// Exact target checks and one normal, non-forced host unmount request.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) trait HostUnmountOps {
    /// Checks the selected kernel mounts and retained block identity.
    fn revalidate(&self) -> Result<(), NativeError>;
    /// Drops this service's filesystem references before the host busy check.
    fn release_mount_handles(&mut self);
    /// Requests normal unmount once, with no forced or lazy fallback.
    fn unmount_once(&mut self) -> HostOperationOutcome;
    /// Proves all selected mounts are absent and block identity is unchanged.
    fn verify_unmounted(&self) -> Result<(), NativeError>;
}

/// Rechecks identity after dropping self-owned busy references and before dispatch.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) fn execute_host_unmount(ops: &mut impl HostUnmountOps) -> HostOperationOutcome {
    if let Err(error) = ops.revalidate() {
        return HostOperationOutcome::NotAttempted(error);
    }
    ops.release_mount_handles();
    if let Err(error) = ops.revalidate() {
        return HostOperationOutcome::NotAttempted(error);
    }
    let outcome = ops.unmount_once();
    if outcome != HostOperationOutcome::Succeeded {
        return outcome;
    }
    match ops.verify_unmounted() {
        Ok(()) => HostOperationOutcome::Succeeded,
        Err(error) => HostOperationOutcome::CompletionUnknown(error),
    }
}
