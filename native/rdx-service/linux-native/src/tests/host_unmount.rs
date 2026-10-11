// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Host-unmount dispatch must release self-pins and preserve external busy errors.

use crate::host_unmount::{HostUnmountOps, execute_host_unmount};
use crate::{HostOperationOutcome, NativeError};
use std::cell::Cell;

/// Controlled host requests with independent service and external filesystem users.
struct Fixture {
    own_handles: usize,
    external_busy: bool,
    changed_after_release: bool,
    mounts_remain: bool,
    checks: Cell<usize>,
    dispatches: usize,
}

impl Fixture {
    /// Starts with the service's directory and mount-tree references open.
    fn ready() -> Self {
        Self {
            own_handles: 2,
            external_busy: false,
            changed_after_release: false,
            mounts_remain: false,
            checks: Cell::new(0),
            dispatches: 0,
        }
    }
}

impl HostUnmountOps for Fixture {
    /// Simulates an exact target replacement at the release boundary.
    fn revalidate(&self) -> Result<(), NativeError> {
        self.checks.set(self.checks.get() + 1);
        if self.own_handles == 0 && self.changed_after_release {
            Err(NativeError::DeviceRemoved)
        } else {
            Ok(())
        }
    }

    /// Drops only this service's filesystem users.
    fn release_mount_handles(&mut self) {
        self.own_handles = 0;
    }

    /// Models the kernel busy check while counting every dispatched request.
    fn unmount_once(&mut self) -> HostOperationOutcome {
        self.dispatches += 1;
        if self.own_handles != 0 || self.external_busy {
            HostOperationOutcome::DefinitelyRejected(NativeError::Busy)
        } else {
            HostOperationOutcome::Succeeded
        }
    }

    /// A positive host reply still requires authoritative kernel absence.
    fn verify_unmounted(&self) -> Result<(), NativeError> {
        if self.mounts_remain {
            Err(NativeError::EvidenceIncomplete)
        } else {
            Ok(())
        }
    }
}

/// A normal unmount must not be blocked by the service's own retained handles.
#[test]
fn normal_unmount_releases_self_pins_before_the_host_busy_check() {
    let mut ops = Fixture::ready();
    assert_eq!(
        execute_host_unmount(&mut ops),
        HostOperationOutcome::Succeeded
    );
    assert_eq!(ops.checks.get(), 2);
    assert_eq!(ops.dispatches, 1);
}

/// Genuine external users remain busy with no retry or forced fallback.
#[test]
fn external_busy_rejection_does_not_retry_or_authorize_eject() {
    let mut ops = Fixture::ready();
    ops.external_busy = true;
    assert_eq!(
        execute_host_unmount(&mut ops),
        HostOperationOutcome::DefinitelyRejected(NativeError::Busy)
    );
    assert_eq!(ops.dispatches, 1);
}

/// Closing our descriptors must not turn stale evidence into mutation authority.
#[test]
fn replacement_after_releasing_self_pins_blocks_host_dispatch() {
    let mut ops = Fixture::ready();
    ops.changed_after_release = true;
    assert_eq!(
        execute_host_unmount(&mut ops),
        HostOperationOutcome::NotAttempted(NativeError::DeviceRemoved)
    );
    assert_eq!(ops.dispatches, 0);
}

/// Host success with any selected mount still present is completion unknown.
#[test]
fn host_reply_requires_kernel_unmount_readback() {
    let mut ops = Fixture::ready();
    ops.mounts_remain = true;
    assert_eq!(
        execute_host_unmount(&mut ops),
        HostOperationOutcome::CompletionUnknown(NativeError::EvidenceIncomplete)
    );
}
