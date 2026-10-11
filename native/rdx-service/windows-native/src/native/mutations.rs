// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Closed semantic Windows volume mutations behind complete fresh validation.

use super::super::{
    NativeError, VolumeInventory, VolumeMutationIo, VolumeMutationOutcome,
    execute_safe_dismount_all,
};
use super::{NativeDevice, NativeVolumeLease, revalidate_present_identity, volumes};

struct SafeDismountIo<'a> {
    device: &'a NativeDevice,
    leases: &'a [NativeVolumeLease],
    disk_number: u32,
}

impl VolumeMutationIo for SafeDismountIo<'_> {
    /// Revalidates SetupAPI identity and the same physical handle together.
    fn revalidate_parent(&mut self) -> Result<(), NativeError> {
        revalidate_present_identity(&self.device.identity, &self.device.handle).map(|_| ())
    }

    /// Fresh-enumerates every volume and drops temporary target handles after inspection.
    fn scan_complete(&mut self) -> Result<VolumeInventory, NativeError> {
        volumes::pin_disk_volumes(self.disk_number).map(|scanned| scanned.inventory)
    }

    /// Rechecks every original retained handle immediately before locking.
    fn revalidate_retained_volumes(&mut self) -> Result<(), NativeError> {
        self.leases
            .iter()
            .try_for_each(NativeVolumeLease::revalidate)
    }

    /// Locks every retained target handle before any volume is dismounted.
    fn lock_retained_volumes(&mut self) -> Result<(), NativeError> {
        self.leases.iter().try_for_each(NativeVolumeLease::lock)
    }

    /// Dismounts only the exact already-locked target handles.
    fn dismount_retained_volumes(&mut self) -> Result<(), NativeError> {
        self.leases.iter().try_for_each(NativeVolumeLease::dismount)
    }
}

/// Runs one consuming, non-callback safe dismount through the typed coordinator.
pub(super) fn dismount_for_safe_eject(
    device: &NativeDevice,
    leases: &[NativeVolumeLease],
    inventory: &VolumeInventory,
) -> VolumeMutationOutcome {
    let mut io = SafeDismountIo {
        device,
        leases,
        disk_number: device.identity.disk_number(),
    };
    execute_safe_dismount_all(&mut io, inventory)
}

/// Keeps all exact volume locks owned by the caller alive through layout IOCTLs.
pub(super) fn execute_locked_layout(
    device: &NativeDevice,
    leases: &[NativeVolumeLease],
    inventory: &VolumeInventory,
    dispatch: impl FnOnce() -> super::super::HostOperationOutcome,
) -> super::super::HostOperationOutcome {
    let mut io = SafeDismountIo {
        device,
        leases,
        disk_number: device.identity.disk_number(),
    };
    super::super::mutation::execute_locked_layout(&mut io, inventory, dispatch)
}
