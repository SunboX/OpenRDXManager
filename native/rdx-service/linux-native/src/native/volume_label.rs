// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Linux labels through exact root-owned filesystem objects and retained mounts.

use super::*;
use crate::volume_label::payload;

const SET_LABEL: libc::Ioctl = libc::_IOW::<[u8; 256]>(0x94, 50);

impl NativeDevice {
    /// Reads the current filesystem label without publishing a volume pathname.
    pub(crate) fn volume_label(&mut self) -> Result<String, NativeError> {
        let identity = self.media_identity_material()?;
        let leases = self.pin_volumes()?;
        let label = leases.read_label()?;
        leases.validate_label_target()?;
        if self.media_identity_material()? != identity {
            return Err(NativeError::DeviceRemoved);
        }
        Ok(label)
    }

    /// Renames the exact mounted filesystem and verifies cartridge continuity.
    pub(crate) fn set_volume_label(&mut self, label: &str) -> HostOperationOutcome {
        let prepared = (|| {
            let identity = self.media_identity_material()?;
            let leases = self.pin_volumes()?;
            leases.read_label()?;
            leases.validate_label_target()?;
            if self.media_identity_material()? != identity {
                return Err(NativeError::DeviceRemoved);
            }
            Ok((identity, leases))
        })();
        let (identity, leases) = match prepared {
            Ok(prepared) => prepared,
            Err(error) => return HostOperationOutcome::NotAttempted(error),
        };
        let outcome = leases.set_label(label);
        if outcome != HostOperationOutcome::Succeeded {
            return outcome;
        }
        let verified = (|| {
            leases.validate_label_target()?;
            if leases.read_label()? != label || self.media_identity_material()? != identity {
                return Err(NativeError::EvidenceIncomplete);
            }
            Ok(())
        })();
        match verified {
            Ok(()) => HostOperationOutcome::Succeeded,
            Err(error) => HostOperationOutcome::CompletionUnknown(error),
        }
    }
}

impl NativeVolumeLeases {
    /// Recognizes the actual disk format, including FAT width and ext versions.
    pub(crate) fn mounted_filesystem(&self) -> Option<HostFilesystem> {
        let [mount] = self._mount_snapshot.as_slice() else {
            return None;
        };
        let physical = *self._mount_bindings.get(&mount.mount_id())?;
        self.validate_block_authorities().ok()?;
        let host = super::udisks::UDisksUnmount::prepare_format(physical).ok()?;
        let selected = host.read_filesystem().ok()?;
        self.validate_block_authorities().ok()?;
        selected
            .mount_matches(mount.filesystem_type())
            .then_some(selected)
    }

    /// Reads all recognized Linux filesystem labels, including an empty label.
    pub(super) fn read_label(&self) -> Result<String, NativeError> {
        self.label_host()?.read_label()
    }

    /// Dispatches only a bounded supported mounted-filesystem label change.
    pub(super) fn set_label(&self, label: &str) -> HostOperationOutcome {
        let prepared = (|| {
            let host = self.label_host()?;
            let selected = self
                .mounted_filesystem()
                .ok_or(NativeError::UnsupportedPlatform)?;
            if matches!(
                selected,
                HostFilesystem::F2fs | HostFilesystem::Fat16 | HostFilesystem::Fat32
            ) {
                return Err(NativeError::UnsupportedPlatform);
            }
            let buffer = payload(label, selected)?;
            if !self.media_facts()?.0 || !self.mounted_facts()?.0 {
                return Err(NativeError::AccessDenied);
            }
            self.validate_label_target()?;
            Ok((host, selected, buffer))
        })();
        let (host, selected, buffer) = match prepared {
            Ok(prepared) => prepared,
            Err(error) => return HostOperationOutcome::NotAttempted(error),
        };
        if !matches!(
            selected,
            HostFilesystem::Ntfs
                | HostFilesystem::ExFat
                | HostFilesystem::Xfs
                | HostFilesystem::Btrfs
        ) {
            return host.set_label(label);
        }
        // These drivers support mounted-label ioctls. NTFS tools require an
        // unmount; the host XFS clear path can store literal "--" instead of empty.
        // Open the retained mount for the kernel operation and refresh daemon evidence.
        let fd = match self.readable_mount_fd() {
            Ok(fd) => fd,
            Err(error) => return HostOperationOutcome::NotAttempted(error),
        };
        // SAFETY: the verified readable mount and complete fixed input remain owned.
        if unsafe { libc::ioctl(fd.copied(), SET_LABEL, buffer.as_ptr()) } != 0 {
            return HostOperationOutcome::CompletionUnknown(last_native_error());
        }
        // SAFETY: fd remains owned; syncfs takes no pointers.
        if unsafe { libc::syncfs(fd.copied()) } != 0 {
            return HostOperationOutcome::CompletionUnknown(last_native_error());
        }
        if let Err(error) = self.validate_label_target() {
            return HostOperationOutcome::CompletionUnknown(error);
        }
        host.rescan_label(label)
    }

    /// Resolves the sole physical mounted block, independently of its display name.
    fn label_host(&self) -> Result<super::udisks::UDisksUnmount, NativeError> {
        self.validate_label_target()?;
        self.mounted_filesystem()
            .ok_or(NativeError::UnsupportedPlatform)?;
        let [mount] = self._mount_snapshot.as_slice() else {
            return Err(NativeError::EvidenceIncomplete);
        };
        let physical = *self
            ._mount_bindings
            .get(&mount.mount_id())
            .ok_or(NativeError::EvidenceIncomplete)?;
        super::udisks::UDisksUnmount::prepare(physical, vec![mount.mount_point().to_vec()])
    }

    /// Requires one safe retained mount with fresh block and mount identity.
    fn validate_label_target(&self) -> Result<(), NativeError> {
        if self._mount_fds.len() != 1 || !self.mutation_topology_safe() {
            return Err(NativeError::EvidenceIncomplete);
        }
        if self.current_mounts()? != self._mount_snapshot {
            return Err(NativeError::DeviceRemoved);
        }
        self.validate_block_authorities()
    }

    /// Opens the retained directory itself for ioctls; O_PATH cannot execute them.
    fn readable_mount_fd(&self) -> Result<OwnedFd, NativeError> {
        self.validate_label_target()?;
        let retained = &self._mount_fds[0].directory;
        let fd = open_owned(
            &CString::new(format!("/proc/self/fd/{}", retained.copied()))
                .map_err(|_| NativeError::EvidenceIncomplete)?,
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )?;
        let before = fstat_owned(retained)?;
        let after = fstat_owned(&fd)?;
        if before.st_dev != after.st_dev || before.st_ino != after.st_ino {
            return Err(NativeError::DeviceRemoved);
        }
        self.validate_label_target()?;
        Ok(fd)
    }
}
