// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Layout authorization distinguishes mount associations from exclusive volume locks.

use super::{FakeVolumeMutationIo, complete_volume_inventory};
use crate::mutation::execute_locked_layout;
use crate::{HostOperationOutcome, NativeError};
use std::cell::Cell;

/// A normal drive-letter association survives dismount and must not veto locked layout.
#[test]
fn layout_accepts_existing_mount_association_only_after_exact_lock_and_dismount() {
    let inventory = complete_volume_inventory(false);
    let mut io = FakeVolumeMutationIo::new([Ok(inventory.clone()), Ok(inventory.clone())]);
    let writes = Cell::new(0);
    assert_eq!(
        execute_locked_layout(&mut io, &inventory, || {
            writes.set(writes.get() + 1);
            HostOperationOutcome::Succeeded
        }),
        HostOperationOutcome::Succeeded
    );
    assert_eq!(writes.get(), 1);
    assert_eq!(
        io.events,
        [
            "parent", "scan", "parent", "scan", "retained", "parent", "lock", "retained", "parent",
            "dismount", "retained", "parent"
        ]
    );
}

/// Open files that prevent exclusivity still block dismount and every layout write.
#[test]
fn busy_volume_lock_prevents_layout_dispatch() {
    let inventory = complete_volume_inventory(false);
    let mut io = FakeVolumeMutationIo::new([Ok(inventory.clone()), Ok(inventory.clone())]);
    io.lock_result = Err(NativeError::Busy);
    assert_eq!(
        execute_locked_layout(&mut io, &inventory, || panic!("busy volume reached layout")),
        HostOperationOutcome::NotAttempted(NativeError::Busy)
    );
    assert!(!io.events.contains(&"dismount"));
}

/// A volume remap detected by the second scan never reaches locks or layout.
#[test]
fn changed_inventory_prevents_layout_dispatch() {
    let inventory = complete_volume_inventory(false);
    let mut io =
        FakeVolumeMutationIo::new([Ok(inventory.clone()), Err(NativeError::DeviceRemoved)]);
    assert_eq!(
        execute_locked_layout(&mut io, &inventory, || panic!(
            "stale volume reached layout"
        )),
        HostOperationOutcome::NotAttempted(NativeError::DeviceRemoved)
    );
    assert!(!io.events.contains(&"lock"));
}

/// A failed dismount retains its uncertainty and never dispatches partition IOCTLs.
#[test]
fn failed_dismount_prevents_layout_dispatch_and_preserves_uncertainty() {
    let inventory = complete_volume_inventory(false);
    let mut io = FakeVolumeMutationIo::new([Ok(inventory.clone()), Ok(inventory.clone())]);
    io.dismount_result = Err(NativeError::TimedOut);
    assert_eq!(
        execute_locked_layout(&mut io, &inventory, || panic!(
            "failed dismount reached layout"
        )),
        HostOperationOutcome::CompletionUnknown(NativeError::TimedOut)
    );
    assert_eq!(io.events.last(), Some(&"dismount"));
}

/// Exact handle identity is required before locks, after locks and after dismount.
#[test]
fn stale_retained_handle_at_each_gate_prevents_layout_dispatch() {
    let inventory = complete_volume_inventory(false);
    for gate in 0..3 {
        let mut io = FakeVolumeMutationIo::new([Ok(inventory.clone()), Ok(inventory.clone())]);
        io.retained_results = (0..=gate)
            .map(|i| {
                if i == gate {
                    Err(NativeError::DeviceRemoved)
                } else {
                    Ok(())
                }
            })
            .collect();
        assert_eq!(
            execute_locked_layout(&mut io, &inventory, || panic!(
                "stale retained handle reached layout"
            )),
            HostOperationOutcome::NotAttempted(NativeError::DeviceRemoved)
        );
        assert_eq!(io.events.contains(&"dismount"), gate == 2);
    }
}

/// Once the layout closure is dispatched its mutation certainty cannot be downgraded.
#[test]
fn layout_write_failure_keeps_completion_unknown() {
    let inventory = complete_volume_inventory(false);
    let mut io = FakeVolumeMutationIo::new([Ok(inventory.clone()), Ok(inventory.clone())]);
    let writes = Cell::new(0);
    assert_eq!(
        execute_locked_layout(&mut io, &inventory, || {
            writes.set(writes.get() + 1);
            HostOperationOutcome::CompletionUnknown(NativeError::TimedOut)
        }),
        HostOperationOutcome::CompletionUnknown(NativeError::TimedOut)
    );
    assert_eq!(writes.get(), 1);
}
