// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Exact portable block-topology proof types.

use std::path::PathBuf;

use std::fs;
use std::path::Path;

use crate::NativeError;
use crate::identity::{
    DeviceNumber, SysfsInstanceProof, SysfsRoots, read_device_number,
    read_positive_decimal_attribute, reject_partition_marker, require_block_subsystem,
    resolve_sysfs_path, retained_sysfs_instance_is_current, subsystem_target,
    validate_real_directory,
};

const MAX_RETAINED_VOLUME_HANDLES: usize = 512;

/// Exact backing-device-info instance bound to one whole-disk device number.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct BdiBinding {
    pub(crate) relative_path: PathBuf,
}

#[cfg(target_os = "linux")]
impl BdiBinding {
    /// Returns the exact BDI target relative to `/sys/devices`.
    pub(crate) fn relative_path(&self) -> &Path {
        &self.relative_path
    }
}

/// File-type and device-number proof copied from one opened block descriptor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct OpenedBlockProof {
    block_device: bool,
    device_number: DeviceNumber,
}

impl OpenedBlockProof {
    /// Creates one pointer-free opened block-descriptor proof.
    pub(crate) const fn new(block_device: bool, device_number: DeviceNumber) -> Self {
        Self {
            block_device,
            device_number,
        }
    }
}

/// Exact block device discovered beneath one SCSI-device ancestor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct BlockBinding {
    pub(crate) name: String,
    pub(crate) device_number: DeviceNumber,
}

impl BlockBinding {
    /// Returns the validated kernel block name.
    #[cfg(test)]
    pub(crate) fn name(&self) -> &str {
        &self.name
    }

    /// Returns the exact block-device major/minor pair.
    pub(crate) const fn device_number(&self) -> DeviceNumber {
        self.device_number
    }
}

/// Exact fail-closed block topology retained beside opened volume handles.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct BlockTopology {
    pub(crate) scsi_device_relative: PathBuf,
    pub(crate) bindings: Vec<BlockBinding>,
    pub(crate) nodes: Vec<BlockNodeProof>,
}

impl BlockTopology {
    /// Returns only the proven direct disk and partition bindings.
    pub(crate) fn bindings(&self) -> &[BlockBinding] {
        &self.bindings
    }

    /// Returns every exact retained whole-disk and partition sysfs proof.
    pub(crate) fn nodes(&self) -> &[BlockNodeProof] {
        &self.nodes
    }
}

/// Private exact sysfs evidence for one direct block node.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct BlockNodeProof {
    pub(crate) name: String,
    pub(crate) relative_path: PathBuf,
    pub(crate) device_number: DeviceNumber,
    pub(crate) partition: Option<u32>,
    pub(crate) bdi: Option<BdiBinding>,
}

#[cfg(target_os = "linux")]
impl BlockNodeProof {
    /// Returns the validated kernel block name.
    pub(crate) fn name(&self) -> &str {
        &self.name
    }

    /// Returns the canonical node path relative to `/sys/devices`.
    pub(crate) fn relative_path(&self) -> &Path {
        &self.relative_path
    }

    /// Returns the exact opened block-device major/minor pair.
    pub(crate) const fn device_number(&self) -> DeviceNumber {
        self.device_number
    }

    /// Returns the exact optional whole-disk BDI proof.
    pub(crate) fn bdi(&self) -> Option<&BdiBinding> {
        self.bdi.as_ref()
    }
}

/// Resolves a whole disk's BDI link and exact class alias to the same real
/// `/sys/devices/virtual/bdi/<major>:<minor>` instance.
pub(crate) fn validate_bdi_binding(
    roots: &SysfsRoots,
    disk: &Path,
    device_number: DeviceNumber,
) -> Result<BdiBinding, NativeError> {
    let expected = roots
        .devices_root()
        .join("virtual/bdi")
        .join(device_number.sysfs_key());
    let disk_link = disk.join("bdi");
    require_symlink(&disk_link)?;
    let target = resolve_sysfs_path(roots, &disk_link)?;
    if target != expected {
        return Err(NativeError::EnumerationFailed);
    }
    validate_real_directory(&target, roots.devices_root())?;
    let class_root = roots.sys_root().join("class/bdi");
    validate_real_directory(&class_root, roots.sys_root())?;
    let class_alias = class_root.join(device_number.sysfs_key());
    require_symlink(&class_alias)?;
    if resolve_sysfs_path(roots, &class_alias)? != expected
        || subsystem_target(roots, &target)?.as_deref() != Some(class_root.as_path())
    {
        return Err(NativeError::EnumerationFailed);
    }

    Ok(BdiBinding {
        relative_path: target
            .strip_prefix(roots.devices_root())
            .map_err(|_| NativeError::EnumerationFailed)?
            .to_path_buf(),
    })
}

/// Rebuilds one block proof through its exact `/sys/class/block/<name>` alias
/// and current canonical sysfs attributes.
pub(crate) fn resolve_block_node(
    roots: &SysfsRoots,
    expected: &BlockNodeProof,
) -> Result<BlockNodeProof, NativeError> {
    let class_root = roots.sys_root().join("class/block");
    validate_real_directory(&class_root, roots.sys_root())?;
    let class_alias = class_root.join(&expected.name);
    require_symlink(&class_alias)?;
    let current_path = resolve_sysfs_path(roots, &class_alias)?;
    let expected_path = roots.devices_root().join(&expected.relative_path);
    if current_path != expected_path {
        return Err(NativeError::EnumerationFailed);
    }
    validate_real_directory(&current_path, roots.devices_root())?;
    require_block_subsystem(roots, &current_path)?;
    let device_number = read_device_number(&current_path.join("dev"))?;
    let (partition, bdi) = match expected.partition {
        Some(expected_partition) => {
            let partition = read_positive_decimal_attribute(&current_path.join("partition"))?
                .ok_or(NativeError::EnumerationFailed)?;
            if partition != expected_partition || current_path.join("bdi").exists() {
                return Err(NativeError::EnumerationFailed);
            }
            (Some(partition), None)
        }
        None => {
            reject_partition_marker(&current_path)?;
            let bdi = validate_bdi_binding(roots, &current_path, device_number)?;
            (None, Some(bdi))
        }
    };
    Ok(BlockNodeProof {
        name: expected.name.clone(),
        relative_path: expected.relative_path.clone(),
        device_number,
        partition,
        bdi,
    })
}

/// Requires one retained block node, its block descriptor, optional BDI, and
/// current class-derived proof to describe the exact same instances.
#[allow(clippy::too_many_arguments)]
pub(crate) fn retained_block_authority_is_current(
    expected: &BlockNodeProof,
    current: &BlockNodeProof,
    node_at_open: SysfsInstanceProof,
    node_retained_now: SysfsInstanceProof,
    node_current_path: SysfsInstanceProof,
    opened_block: OpenedBlockProof,
    bdi_at_open: Option<SysfsInstanceProof>,
    bdi_retained_now: Option<SysfsInstanceProof>,
    bdi_current_path: Option<SysfsInstanceProof>,
) -> bool {
    let bdi_is_current = match (
        &expected.bdi,
        bdi_at_open,
        bdi_retained_now,
        bdi_current_path,
    ) {
        (Some(_), Some(at_open), Some(retained_now), Some(current_path)) => {
            retained_sysfs_instance_is_current(at_open, retained_now, current_path)
        }
        (None, None, None, None) => true,
        _ => false,
    };
    expected == current
        && retained_sysfs_instance_is_current(node_at_open, node_retained_now, node_current_path)
        && opened_block.block_device
        && opened_block.device_number == expected.device_number
        && bdi_is_current
}

/// Counts every retained block-sysfs, block-device, disk-BDI, and mount handle
/// and rejects the complete pin before exceeding its fixed process budget.
pub(crate) fn retained_volume_handle_count(
    nodes: &[BlockNodeProof],
    mount_count: usize,
) -> Result<usize, NativeError> {
    let block_handles = nodes.iter().try_fold(0_usize, |count, node| {
        count.checked_add(2 + usize::from(node.bdi.is_some()))
    });
    let total = block_handles
        .and_then(|count| count.checked_add(mount_count))
        .ok_or(NativeError::ResourceLimit)?;
    if total > MAX_RETAINED_VOLUME_HANDLES {
        return Err(NativeError::ResourceLimit);
    }
    Ok(total)
}

/// Requires one kernel identity edge to be an actual symbolic link.
fn require_symlink(path: &Path) -> Result<(), NativeError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| NativeError::EnumerationFailed)?;
    if !metadata.file_type().is_symlink() {
        return Err(NativeError::EnumerationFailed);
    }
    Ok(())
}
