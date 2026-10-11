// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Exact retained block checks and UDisks2 normal filesystem unmount.

use super::udisks::UDisksUnmount;
use super::*;
use crate::host_unmount::{HostUnmountOps, execute_host_unmount};

/// Retained block authority plus a verified root-owned host filesystem object.
struct LinuxHostUnmount<'a> {
    leases: &'a mut NativeVolumeLeases,
    host: UDisksUnmount,
}

impl NativeVolumeLeases {
    /// Unmounts through the host without moving shared mounts or retaining self-pins.
    pub(crate) fn unmount_all(&mut self) -> HostOperationOutcome {
        if let Err(error) = self.validate_unmount_target() {
            return HostOperationOutcome::NotAttempted(error);
        }
        let Some(first) = self._mount_snapshot.first() else {
            return HostOperationOutcome::Succeeded;
        };
        let Some(&device) = self._mount_bindings.get(&first.mount_id()) else {
            return HostOperationOutcome::NotAttempted(NativeError::EvidenceIncomplete);
        };
        if !self.mutation_topology_safe()
            || self
                ._mount_snapshot
                .iter()
                .any(|mount| self._mount_bindings.get(&mount.mount_id()) != Some(&device))
        {
            return HostOperationOutcome::NotAttempted(NativeError::EvidenceIncomplete);
        }
        let points = self
            ._mount_snapshot
            .iter()
            .map(|mount| mount.mount_point().to_vec())
            .collect();
        let host = match UDisksUnmount::prepare(device, points) {
            Ok(host) => host,
            Err(error) => return HostOperationOutcome::NotAttempted(error),
        };
        execute_host_unmount(&mut LinuxHostUnmount { leases: self, host })
    }

    /// Reads the complete current kernel mount set for only the retained graph.
    pub(super) fn current_mounts(&self) -> Result<Vec<MountRecord>, NativeError> {
        let records = parse_mountinfo(&read_bounded(
            Path::new("/proc/self/mountinfo"),
            MAX_MOUNTINFO_BYTES,
        )?)?;
        let numbers = self
            ._topology
            .bindings()
            .iter()
            .map(BlockBinding::device_number)
            .collect();
        let (selected, bindings) = super::btrfs::selected_mounts(&records, &numbers)?;
        if !selected.is_empty() && bindings != self._mount_bindings {
            return Err(NativeError::DeviceRemoved);
        }
        Ok(selected)
    }

    /// Rechecks block-instance authority even after filesystem references close.
    pub(super) fn validate_block_authorities(&self) -> Result<(), NativeError> {
        let roots = SysfsRoots::native()?;
        for authority in &self._block_authorities {
            authority.revalidate(&roots)?;
        }
        Ok(())
    }

    /// Requires current mount IDs, unchanged block identity, and exact opened roots.
    fn validate_unmount_target(&self) -> Result<(), NativeError> {
        self.validate_block_authorities()?;
        if self.current_mounts()? != self._mount_snapshot {
            return Err(NativeError::DeviceRemoved);
        }
        for retained in &self._mount_fds {
            if !self._mount_snapshot.iter().any(|mount| {
                mount.mount_id() == retained.mount_id
                    && mount.mount_point() == retained.restore.mount_point
            }) {
                return Err(NativeError::DeviceRemoved);
            }
            // The parent/leaf is used only for a read-only identity check;
            // UDisks receives the block object, never this mountpoint pathname.
            let child = openat_owned(
                &retained.restore.parent,
                &retained.restore.leaf,
                libc::O_PATH | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )?;
            let original = fstat_owned(&retained.directory)?;
            for fd in [&child, &retained.tree] {
                let current = fstat_owned(fd)?;
                if current.st_dev != original.st_dev
                    || current.st_ino != original.st_ino
                    || file_type(current.st_mode) != file_type(original.st_mode)
                {
                    return Err(NativeError::DeviceRemoved);
                }
            }
        }
        Ok(())
    }
}

impl HostUnmountOps for LinuxHostUnmount<'_> {
    /// Repeats the exact kernel and block checks immediately before host dispatch.
    fn revalidate(&self) -> Result<(), NativeError> {
        self.leases.validate_unmount_target()
    }

    /// These O_PATH and open_tree descriptors count as active filesystem users.
    fn release_mount_handles(&mut self) {
        self.leases._mount_fds.clear();
    }

    /// Calls the exact verified daemon object with force explicitly disabled.
    fn unmount_once(&mut self) -> HostOperationOutcome {
        self.host.unmount()
    }

    /// A successful daemon reply cannot authorize eject while mounts remain.
    fn verify_unmounted(&self) -> Result<(), NativeError> {
        self.leases.validate_block_authorities()?;
        if self.leases.current_mounts()?.is_empty() {
            Ok(())
        } else {
            Err(NativeError::EvidenceIncomplete)
        }
    }
}
