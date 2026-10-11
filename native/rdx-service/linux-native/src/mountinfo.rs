// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Bounded byte-oriented `/proc/self/mountinfo` parsing.

use std::collections::BTreeSet;

use crate::NativeError;
use crate::identity::DeviceNumber;

/// Maximum bytes accepted in one mountinfo line.
pub(crate) const MAX_MOUNTINFO_LINE_BYTES: usize = 16_384;
const MAX_MOUNTINFO_BYTES: usize = 4 * 1024 * 1024;
const MAX_MOUNT_RECORDS: usize = 4_096;
const MAX_MOUNT_FIELD_BYTES: usize = 4_096;

/// One exact mountinfo association with byte-preserving decoded paths.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct MountRecord {
    mount_id: u64,
    parent_id: u64,
    device_number: DeviceNumber,
    root: Vec<u8>,
    mount_point: Vec<u8>,
    mount_options: Vec<u8>,
    optional_fields: Vec<Vec<u8>>,
    filesystem_type: Vec<u8>,
    mount_source: Vec<u8>,
    super_options: Vec<u8>,
}

impl MountRecord {
    /// Returns the exact kernel mount ID from this snapshot.
    #[cfg(target_os = "linux")]
    pub(crate) const fn mount_id(&self) -> u64 {
        self.mount_id
    }

    /// Returns the exact block-device major/minor pair.
    pub(crate) const fn device_number(&self) -> DeviceNumber {
        self.device_number
    }

    /// Returns the decoded mount root bytes.
    #[cfg(any(target_os = "linux", test))]
    pub(crate) fn root(&self) -> &[u8] {
        &self.root
    }

    /// Returns the decoded mount-point bytes.
    pub(crate) fn mount_point(&self) -> &[u8] {
        &self.mount_point
    }

    /// Reports an explicit `rw` mount option without normalizing other fields.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub(crate) fn is_writable(&self) -> bool {
        self.mount_options
            .split(|byte| *byte == b',')
            .any(|option| option == b"rw")
    }

    /// Returns the exact kernel-reported filesystem type bytes.
    #[cfg(target_os = "linux")]
    pub(crate) fn filesystem_type(&self) -> &[u8] {
        &self.filesystem_type
    }
}

/// Parses a complete bounded mountinfo snapshot without invoking a shell.
pub(crate) fn parse_mountinfo(input: &[u8]) -> Result<Vec<MountRecord>, NativeError> {
    if input.len() > MAX_MOUNTINFO_BYTES {
        return Err(NativeError::ResourceLimit);
    }
    let mut records = Vec::new();
    let mut mount_ids = BTreeSet::new();
    for line in input.split(|byte| *byte == b'\n') {
        if line.is_empty() {
            continue;
        }
        if line.len() > MAX_MOUNTINFO_LINE_BYTES {
            return Err(NativeError::ResourceLimit);
        }
        if records.len() == MAX_MOUNT_RECORDS {
            return Err(NativeError::ResourceLimit);
        }
        let record = parse_line(line)?;
        if !mount_ids.insert(record.mount_id) {
            return Err(NativeError::EnumerationFailed);
        }
        records.push(record);
    }
    Ok(records)
}

/// Parses one mountinfo line and validates its separator and mandatory fields.
fn parse_line(line: &[u8]) -> Result<MountRecord, NativeError> {
    let fields = line.split(|byte| *byte == b' ').collect::<Vec<_>>();
    if fields.iter().any(|field| field.is_empty()) {
        return Err(NativeError::EnumerationFailed);
    }
    let separators = fields
        .iter()
        .enumerate()
        .filter(|(_, field)| **field == b"-")
        .map(|(index, _)| index)
        .collect::<Vec<_>>();
    let [separator] = separators.as_slice() else {
        return Err(NativeError::EnumerationFailed);
    };
    if *separator < 6 || fields.len() != *separator + 4 {
        return Err(NativeError::EnumerationFailed);
    }
    let mount_id = parse_decimal(fields[0])?;
    let parent_id = parse_decimal(fields[1])?;
    let device_number = parse_device_number(fields[2])?;
    let root = decode_mount_field(fields[3])?;
    let mount_point = decode_mount_field(fields[4])?;
    let mount_options = decode_mount_field(fields[5])?;
    let filesystem_type = decode_mount_field(fields[*separator + 1])?;
    // nsfs renders a namespace root as kind:[inode], not a filesystem path.
    // Preserve these records so unrelated Snap mounts cannot erase inventory.
    let root_is_valid = is_normalized_absolute_path(&root)
        || (filesystem_type == b"nsfs" && is_namespace_root(&root));
    if !root_is_valid || !is_normalized_absolute_path(&mount_point) {
        return Err(NativeError::EnumerationFailed);
    }
    let optional_fields = fields[6..*separator]
        .iter()
        .map(|field| decode_mount_field(field))
        .collect::<Result<Vec<_>, _>>()?;
    let mount_source = decode_mount_field(fields[*separator + 2])?;
    let super_options = decode_mount_field(fields[*separator + 3])?;
    Ok(MountRecord {
        mount_id,
        parent_id,
        device_number,
        root,
        mount_point,
        mount_options,
        optional_fields,
        filesystem_type,
        mount_source,
        super_options,
    })
}

/// Accepts only a known kernel namespace type and positive bounded inode.
fn is_namespace_root(root: &[u8]) -> bool {
    let Some(separator) = root.iter().position(|byte| *byte == b':') else {
        return false;
    };
    if !matches!(
        &root[..separator],
        b"mnt" | b"net" | b"pid" | b"uts" | b"ipc" | b"user" | b"cgroup" | b"time"
    ) {
        return false;
    }
    let Some(inode) = root[separator + 1..]
        .strip_prefix(b"[")
        .and_then(|value| value.strip_suffix(b"]"))
    else {
        return false;
    };
    parse_decimal(inode).is_ok_and(|inode| inode != 0)
}

/// Rejects traversal and ambiguous separators in a kernel-reported path.
fn is_normalized_absolute_path(path: &[u8]) -> bool {
    if path == b"/" {
        return true;
    }
    path.starts_with(b"/")
        && !path.ends_with(b"/")
        && path[1..]
            .split(|byte| *byte == b'/')
            .all(|component| !component.is_empty() && component != b"." && component != b"..")
}

/// Parses one non-empty unsigned decimal field.
fn parse_decimal(field: &[u8]) -> Result<u64, NativeError> {
    if field.is_empty() || !field.iter().all(u8::is_ascii_digit) {
        return Err(NativeError::EnumerationFailed);
    }
    let text = std::str::from_utf8(field).map_err(|_| NativeError::EnumerationFailed)?;
    text.parse::<u64>()
        .map_err(|_| NativeError::EnumerationFailed)
}

/// Parses an exact unsigned `major:minor` field.
fn parse_device_number(field: &[u8]) -> Result<DeviceNumber, NativeError> {
    if field.iter().filter(|byte| **byte == b':').count() != 1 {
        return Err(NativeError::EnumerationFailed);
    }
    let separator = field
        .iter()
        .position(|byte| *byte == b':')
        .ok_or(NativeError::EnumerationFailed)?;
    let major = u32::try_from(parse_decimal(&field[..separator])?)
        .map_err(|_| NativeError::EnumerationFailed)?;
    let minor = u32::try_from(parse_decimal(&field[separator + 1..])?)
        .map_err(|_| NativeError::EnumerationFailed)?;
    Ok(DeviceNumber::new(major, minor))
}

/// Decodes only mountinfo's documented octal escapes.
fn decode_mount_field(field: &[u8]) -> Result<Vec<u8>, NativeError> {
    if field.is_empty() || field.len() > MAX_MOUNT_FIELD_BYTES {
        return Err(NativeError::ResourceLimit);
    }
    let mut decoded = Vec::with_capacity(field.len());
    let mut index = 0_usize;
    while index < field.len() {
        let byte = field[index];
        if byte == 0 || byte == b'\n' {
            return Err(NativeError::EnumerationFailed);
        }
        if byte != b'\\' {
            decoded.push(byte);
            index += 1;
            continue;
        }
        let Some(escape) = field.get(index + 1..index + 4) else {
            return Err(NativeError::EnumerationFailed);
        };
        let value = match escape {
            b"040" => b' ',
            b"011" => b'\t',
            b"012" => b'\n',
            b"134" => b'\\',
            _ => return Err(NativeError::EnumerationFailed),
        };
        decoded.push(value);
        index += 4;
    }
    if decoded.len() > MAX_MOUNT_FIELD_BYTES || decoded.contains(&0) {
        return Err(NativeError::ResourceLimit);
    }
    Ok(decoded)
}

/// Selects mounts whose exact major/minor pair belongs to the bound block set.
pub(crate) fn mounts_for_devices<'records>(
    records: &'records [MountRecord],
    devices: &BTreeSet<DeviceNumber>,
) -> Vec<&'records MountRecord> {
    records
        .iter()
        .filter(|record| devices.contains(&record.device_number))
        .collect()
}

/// Selects and canonically orders one exact mount snapshot for a block set.
/// Stacked records at one selected mount point are ambiguous and fail closed.
pub(crate) fn canonical_mounts_for_devices(
    records: &[MountRecord],
    devices: &BTreeSet<DeviceNumber>,
) -> Result<Vec<MountRecord>, NativeError> {
    let mut selected = mounts_for_devices(records, devices)
        .into_iter()
        .cloned()
        .collect::<Vec<_>>();
    let mut mount_points = BTreeSet::new();
    for record in &selected {
        if !mount_points.insert(record.mount_point.clone()) {
            return Err(NativeError::EvidenceIncomplete);
        }
    }
    if records.iter().any(|record| {
        mount_points.contains(&record.mount_point) && !devices.contains(&record.device_number)
    }) {
        return Err(NativeError::EvidenceIncomplete);
    }
    selected.sort();
    Ok(selected)
}
