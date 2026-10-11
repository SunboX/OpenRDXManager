// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Retained exact block identity and sysfs authorities.

use super::*;

/// Retained canonical block sysfs, device, and optional BDI authorities.
pub(super) struct RetainedBlockAuthority {
    pub(super) node: BlockNodeProof,
    sysfs_instance: RetainedSysfsInstance,
    pub(super) block_fd: OwnedFd,
    bdi_instance: Option<RetainedSysfsInstance>,
}

impl RetainedBlockAuthority {
    /// Opens every authority only after the current class proof matches, then
    /// revalidates the retained instances before allowing mount discovery.
    pub(super) fn open(roots: &SysfsRoots, node: &BlockNodeProof) -> Result<Self, NativeError> {
        let before = resolve_block_node(roots, node).map_err(|_| NativeError::DeviceRemoved)?;
        if before != *node {
            return Err(NativeError::DeviceRemoved);
        }
        let sysfs_fd = open_sysfs_relative(roots, node.relative_path())?;
        let sysfs_proof = sysfs_instance_proof(&fstat_owned(&sysfs_fd)?);
        let block_fd = open_exact_block(node.name(), node.device_number())?;
        let bdi_instance = node
            .bdi()
            .map(|bdi| {
                let fd = open_sysfs_relative(roots, bdi.relative_path())?;
                let proof = sysfs_instance_proof(&fstat_owned(&fd)?);
                Ok(RetainedSysfsInstance { fd, proof })
            })
            .transpose()?;
        let authority = Self {
            node: node.clone(),
            sysfs_instance: RetainedSysfsInstance {
                fd: sysfs_fd,
                proof: sysfs_proof,
            },
            block_fd,
            bdi_instance,
        };
        authority.revalidate(roots)?;
        Ok(authority)
    }

    /// Reopens both current class-derived sysfs targets and compares them to
    /// the retained inodes and still-open exact block descriptor.
    pub(super) fn revalidate(&self, roots: &SysfsRoots) -> Result<(), NativeError> {
        let before =
            resolve_block_node(roots, &self.node).map_err(|_| NativeError::DeviceRemoved)?;
        let node_retained_now = sysfs_instance_proof(&fstat_owned(&self.sysfs_instance.fd)?);
        let block_stat = fstat_owned(&self.block_fd)?;
        let opened_block = OpenedBlockProof::new(
            file_type(block_stat.st_mode) == libc::S_IFBLK,
            device_number(block_stat.st_rdev),
        );
        let current_node_fd = open_sysfs_relative(roots, self.node.relative_path())?;
        let node_current_path = sysfs_instance_proof(&fstat_owned(&current_node_fd)?);
        let (bdi_at_open, bdi_retained_now, bdi_current_path) =
            match (self.node.bdi(), self.bdi_instance.as_ref()) {
                (Some(binding), Some(retained)) => {
                    let retained_now = sysfs_instance_proof(&fstat_owned(&retained.fd)?);
                    let current_fd = open_sysfs_relative(roots, binding.relative_path())?;
                    let current = sysfs_instance_proof(&fstat_owned(&current_fd)?);
                    (Some(retained.proof), Some(retained_now), Some(current))
                }
                (None, None) => (None, None, None),
                _ => return Err(NativeError::DeviceRemoved),
            };
        let after =
            resolve_block_node(roots, &self.node).map_err(|_| NativeError::DeviceRemoved)?;
        if before != self.node
            || !retained_block_authority_is_current(
                &self.node,
                &after,
                self.sysfs_instance.proof,
                node_retained_now,
                node_current_path,
                opened_block,
                bdi_at_open,
                bdi_retained_now,
                bdi_current_path,
            )
        {
            return Err(NativeError::DeviceRemoved);
        }
        Ok(())
    }
}
