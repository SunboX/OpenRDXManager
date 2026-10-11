// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Kernel-proven single-device Btrfs membership for anonymous mount dev_t values.

use super::*;
use std::collections::BTreeMap;

// Linux UAPI: _IOR(0x94, 31, struct btrfs_ioctl_fs_info_args[1024]).
const BTRFS_IOC_FS_INFO: libc::c_ulong = 0x8400_941f;

/// Selects exact ordinary and Btrfs mounts, retaining their physical block binding.
pub(super) fn selected_mounts(
    records: &[MountRecord],
    devices: &BTreeSet<DeviceNumber>,
) -> Result<(Vec<MountRecord>, BTreeMap<u64, DeviceNumber>), NativeError> {
    let mut mount_devices = devices.clone();
    let mut bindings = BTreeMap::new();
    for record in records {
        if record.filesystem_type() != b"btrfs" {
            if devices.contains(&record.device_number()) {
                bindings.insert(record.mount_id(), record.device_number());
            }
            continue;
        }
        // Btrfs mountinfo uses an anonymous dev_t, so matching only the block
        // device would hide a mounted cartridge from normal unmount and eject.
        let directory = open_record_mount(record)?;
        let path =
            CString::new(record.mount_point()).map_err(|_| NativeError::EvidenceIncomplete)?;
        let reader = open_owned(
            &path,
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )?;
        let opened = fstat_owned(&reader)?;
        let retained = fstat_owned(&directory)?;
        if opened.st_dev != retained.st_dev || opened.st_ino != retained.st_ino {
            return Err(NativeError::DeviceRemoved);
        }
        let before = fs_info(&reader)?;
        let members = membership(&before)?;
        let after = fs_info(&reader)?;
        if before != after || membership(&after)? != members {
            return Err(NativeError::DeviceRemoved);
        }
        let Some(physical) = select_single_member(before.1, &members, devices)? else {
            continue;
        };
        if record.root() != b"/" {
            return Err(NativeError::EvidenceIncomplete);
        }
        mount_devices.insert(record.device_number());
        bindings.insert(record.mount_id(), physical);
    }
    let selected = canonical_mounts_for_devices(records, &mount_devices)?;
    if selected
        .iter()
        .any(|mount| !bindings.contains_key(&mount.mount_id()))
    {
        return Err(NativeError::EvidenceIncomplete);
    }
    Ok((selected, bindings))
}

/// Pins the exact mount ID even when Btrfs reports a different inode dev_t.
pub(super) fn open_record_mount(record: &MountRecord) -> Result<OwnedFd, NativeError> {
    if record.filesystem_type() != b"btrfs" {
        return open_exact_mount(record.mount_point(), record.device_number());
    }
    let path = CString::new(record.mount_point()).map_err(|_| NativeError::EvidenceIncomplete)?;
    let fd = open_owned(
        &path,
        libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
    )?;
    // Btrfs allocates anonymous dev_t values per subvolume. fdinfo identifies
    // the actual opened mount independently of that filesystem-specific value.
    let information = read_bounded(
        Path::new(&format!("/proc/self/fdinfo/{}", fd.copied())),
        4096,
    )?;
    let text = std::str::from_utf8(&information).map_err(|_| NativeError::EvidenceIncomplete)?;
    let id = text
        .lines()
        .find_map(|line| line.strip_prefix("mnt_id:"))
        .and_then(|value| value.trim().parse::<u64>().ok());
    if id != Some(record.mount_id()) {
        return Err(NativeError::DeviceRemoved);
    }
    Ok(fd)
}

/// Requires a complete single-device filesystem when any member is selected.
fn select_single_member(
    declared: u64,
    members: &BTreeSet<DeviceNumber>,
    selected: &BTreeSet<DeviceNumber>,
) -> Result<Option<DeviceNumber>, NativeError> {
    if declared != members.len() as u64 || declared == 0 {
        return Err(NativeError::EvidenceIncomplete);
    }
    if members.is_disjoint(selected) {
        return Ok(None);
    }
    if declared != 1 {
        return Err(NativeError::EvidenceIncomplete);
    }
    Ok(members.first().copied())
}

/// Reads the fixed kernel FSID and total device count through the opened mount.
fn fs_info(fd: &OwnedFd) -> Result<([u8; 16], u64), NativeError> {
    let mut buffer = [0_u8; 1024];
    // SAFETY: the request writes exactly the 1024-byte live output buffer.
    if unsafe { libc::ioctl(fd.copied(), BTRFS_IOC_FS_INFO, buffer.as_mut_ptr()) } != 0 {
        return Err(NativeError::EvidenceIncomplete);
    }
    let count = u64::from_ne_bytes(buffer[8..16].try_into().expect("fixed UAPI count"));
    let id = buffer[16..32].try_into().expect("fixed UAPI FSID");
    Ok((id, count))
}

/// Resolves every kernel membership symlink to its exact sysfs block dev_t.
fn membership(info: &([u8; 16], u64)) -> Result<BTreeSet<DeviceNumber>, NativeError> {
    if info.1 == 0 || info.1 > crate::MAX_CANDIDATES as u64 {
        return Err(NativeError::EvidenceIncomplete);
    }
    let hex = info
        .0
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let uuid = format!(
        "{}-{}-{}-{}-{}",
        &hex[..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..]
    );
    let roots = SysfsRoots::native()?;
    let directory = roots.sys_root().join("fs/btrfs").join(uuid).join("devices");
    let entries = fs::read_dir(directory).map_err(|_| NativeError::EvidenceIncomplete)?;
    let mut members = BTreeSet::new();
    for entry in entries {
        let entry = entry.map_err(|_| NativeError::EvidenceIncomplete)?;
        let canonical = fs::canonicalize(entry.path()).map_err(|_| NativeError::DeviceRemoved)?;
        if !canonical.starts_with(roots.devices_root()) || members.len() >= crate::MAX_CANDIDATES {
            return Err(NativeError::EvidenceIncomplete);
        }
        let number = crate::identity::read_device_number(&canonical.join("dev"))?;
        let class = fs::canonicalize(roots.sys_root().join("dev/block").join(number.sysfs_key()))
            .map_err(|_| NativeError::DeviceRemoved)?;
        if class != canonical || !members.insert(number) {
            return Err(NativeError::EvidenceIncomplete);
        }
    }
    if members.len() as u64 != info.1 {
        return Err(NativeError::EvidenceIncomplete);
    }
    Ok(members)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Shared, missing and inconsistent Btrfs members cannot authorize mutation.
    #[test]
    fn membership_requires_complete_single_physical_device() {
        let selected = BTreeSet::from([DeviceNumber::new(8, 17)]);
        assert_eq!(
            select_single_member(1, &selected, &selected),
            Ok(selected.first().copied())
        );
        let unrelated = BTreeSet::from([DeviceNumber::new(8, 1)]);
        assert_eq!(select_single_member(1, &unrelated, &selected), Ok(None));
        let shared = BTreeSet::from([DeviceNumber::new(8, 17), DeviceNumber::new(8, 1)]);
        assert!(select_single_member(2, &shared, &selected).is_err());
        assert!(select_single_member(2, &selected, &selected).is_err());
        assert!(select_single_member(0, &BTreeSet::new(), &selected).is_err());
    }
}
