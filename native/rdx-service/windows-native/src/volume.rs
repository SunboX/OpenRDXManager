// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Portable, pointer-free Windows volume buffer parsing.

use super::{NativeError, VolumeExtent, volume_extent_buffer_length};

/// Parses native volume-extent disk numbers with checked pointer-width arithmetic.
#[cfg(test)]
pub(super) fn volume_extent_disk_numbers(
    bytes: &[u8],
    extent_offset: usize,
    extent_stride: usize,
) -> Result<Vec<u32>, NativeError> {
    if bytes.len() < std::mem::size_of::<u32>()
        || extent_offset < std::mem::size_of::<u32>()
        || extent_stride < 4
    {
        return Err(NativeError::EnumerationFailed);
    }
    let count = u32::from_le_bytes(
        bytes[..4]
            .try_into()
            .map_err(|_| NativeError::EnumerationFailed)?,
    ) as usize;
    let required = extent_offset
        .checked_add(
            count
                .checked_mul(extent_stride)
                .ok_or(NativeError::ResourceLimit)?,
        )
        .ok_or(NativeError::ResourceLimit)?;
    if count == 0 || required > bytes.len() {
        return Err(NativeError::EnumerationFailed);
    }
    let mut disk_numbers = Vec::with_capacity(count);
    for index in 0..count {
        let start = extent_offset
            .checked_add(
                index
                    .checked_mul(extent_stride)
                    .ok_or(NativeError::ResourceLimit)?,
            )
            .ok_or(NativeError::ResourceLimit)?;
        let end = start.checked_add(4).ok_or(NativeError::ResourceLimit)?;
        let current = u32::from_le_bytes(
            bytes
                .get(start..end)
                .ok_or(NativeError::EnumerationFailed)?
                .try_into()
                .map_err(|_| NativeError::EnumerationFailed)?,
        );
        disk_numbers.push(current);
    }
    Ok(disk_numbers)
}

/// Parses every field of a bounded ordered Windows extent array.
pub(super) fn volume_extents_from_bytes(
    bytes: &[u8],
    extent_offset: usize,
    extent_stride: usize,
    disk_number_offset: usize,
    starting_offset_offset: usize,
    extent_length_offset: usize,
) -> Result<Vec<VolumeExtent>, NativeError> {
    if bytes.len() < std::mem::size_of::<u32>()
        || disk_number_offset
            .checked_add(4)
            .is_none_or(|end| end > extent_stride)
        || starting_offset_offset
            .checked_add(8)
            .is_none_or(|end| end > extent_stride)
        || extent_length_offset
            .checked_add(8)
            .is_none_or(|end| end > extent_stride)
    {
        return Err(NativeError::EnumerationFailed);
    }
    let count = u32::from_le_bytes(
        bytes[..4]
            .try_into()
            .map_err(|_| NativeError::EnumerationFailed)?,
    );
    let required = volume_extent_buffer_length(count, extent_offset, extent_stride, usize::MAX)?;
    if required > bytes.len() {
        return Err(NativeError::EnumerationFailed);
    }

    let mut extents = Vec::with_capacity(count as usize);
    for index in 0..count as usize {
        let base = extent_offset
            .checked_add(
                index
                    .checked_mul(extent_stride)
                    .ok_or(NativeError::ResourceLimit)?,
            )
            .ok_or(NativeError::ResourceLimit)?;
        let read_u32 = |offset: usize| -> Result<u32, NativeError> {
            let start = base.checked_add(offset).ok_or(NativeError::ResourceLimit)?;
            let end = start.checked_add(4).ok_or(NativeError::ResourceLimit)?;
            Ok(u32::from_le_bytes(
                bytes
                    .get(start..end)
                    .ok_or(NativeError::EnumerationFailed)?
                    .try_into()
                    .map_err(|_| NativeError::EnumerationFailed)?,
            ))
        };
        let read_i64 = |offset: usize| -> Result<i64, NativeError> {
            let start = base.checked_add(offset).ok_or(NativeError::ResourceLimit)?;
            let end = start.checked_add(8).ok_or(NativeError::ResourceLimit)?;
            Ok(i64::from_le_bytes(
                bytes
                    .get(start..end)
                    .ok_or(NativeError::EnumerationFailed)?
                    .try_into()
                    .map_err(|_| NativeError::EnumerationFailed)?,
            ))
        };
        extents.push(VolumeExtent {
            disk_number: read_u32(disk_number_offset)?,
            starting_offset: read_i64(starting_offset_offset)?,
            extent_length: read_i64(extent_length_offset)?,
        });
    }
    Ok(extents)
}

/// Reports whether any validated native volume extent names one disk.
#[cfg(test)]
pub(super) fn volume_extents_contain_disk(
    bytes: &[u8],
    extent_offset: usize,
    extent_stride: usize,
    disk_number: u32,
) -> Result<bool, NativeError> {
    volume_extent_disk_numbers(bytes, extent_offset, extent_stride)
        .map(|numbers| numbers.contains(&disk_number))
}

/// Parses a bounded Windows MULTI_SZ and retains only root drive letters.
#[cfg(test)]
pub(super) fn drive_letters_from_multi_sz(buffer: &[u16]) -> Result<Vec<char>, NativeError> {
    let paths = mount_paths_from_multi_sz(buffer)?;
    let mut letters = paths
        .iter()
        .filter_map(|path| {
            (path.len() == 3 && path[1] == ':' as u16 && path[2] == '\\' as u16)
                .then(|| char::from_u32(u32::from(path[0])))
                .flatten()
                .filter(char::is_ascii_alphabetic)
                .map(|letter| letter.to_ascii_uppercase())
        })
        .collect::<Vec<_>>();
    letters.sort_unstable();
    letters.dedup();
    Ok(letters)
}

/// Parses every bounded absolute Windows volume mount path from one MULTI_SZ.
pub(super) fn mount_paths_from_multi_sz(buffer: &[u16]) -> Result<Vec<Vec<u16>>, NativeError> {
    if buffer.is_empty() || buffer.last() != Some(&0) {
        return Err(NativeError::EnumerationFailed);
    }
    if buffer[0] == 0 {
        return if buffer.iter().all(|unit| *unit == 0) {
            Ok(Vec::new())
        } else {
            Err(NativeError::EnumerationFailed)
        };
    }
    if buffer.len() < 2 || buffer[buffer.len() - 2] != 0 {
        return Err(NativeError::EnumerationFailed);
    }

    let mut paths = Vec::new();
    let mut start = 0;
    while start < buffer.len() - 1 {
        let relative_end = buffer[start..]
            .iter()
            .position(|unit| *unit == 0)
            .ok_or(NativeError::EnumerationFailed)?;
        if relative_end == 0 {
            if buffer[start..].iter().any(|unit| *unit != 0) {
                return Err(NativeError::EnumerationFailed);
            }
            break;
        }
        let path = &buffer[start..start + relative_end];
        if path.len() < 3
            || path[1] != ':' as u16
            || path[2] != '\\' as u16
            || path.last() != Some(&('\\' as u16))
            || char::from_u32(u32::from(path[0])).is_none_or(|letter| !letter.is_ascii_alphabetic())
        {
            return Err(NativeError::EnumerationFailed);
        }
        paths.push(path.to_vec());
        start = start
            .checked_add(relative_end + 1)
            .ok_or(NativeError::ResourceLimit)?;
    }
    paths.sort_unstable();
    paths.dedup();
    Ok(paths)
}

/// Parses and canonicalizes an authoritative VDS volume-GUID MULTI_SZ.
#[cfg(test)]
pub(super) fn canonical_volume_guid_paths_from_multi_sz(
    buffer: &[u16],
) -> Result<Vec<String>, NativeError> {
    let paths = nul_terminated_strings(buffer)?;
    paths
        .iter()
        .map(|path| canonical_volume_guid_path(path))
        .collect()
}

/// Canonicalizes one exact `\\?\Volume{GUID}\` UTF-16 pathname.
pub(super) fn canonical_volume_guid_path(path: &[u16]) -> Result<String, NativeError> {
    let value = String::from_utf16(path).map_err(|_| NativeError::EnumerationFailed)?;
    let upper = value.to_ascii_uppercase();
    let bytes = upper.as_bytes();
    if bytes.len() != 49
        || !upper.starts_with(r"\\?\VOLUME{")
        || !upper.ends_with("}\\")
        || ![19, 24, 29, 34].iter().all(|index| bytes[*index] == b'-')
        || bytes[11..47]
            .iter()
            .enumerate()
            .any(|(index, byte)| !matches!(index, 8 | 13 | 18 | 23) && !byte.is_ascii_hexdigit())
    {
        return Err(NativeError::EnumerationFailed);
    }
    Ok(upper)
}

/// Splits one bounded well-formed MULTI_SZ without interpreting its path grammar.
#[cfg(test)]
fn nul_terminated_strings(buffer: &[u16]) -> Result<Vec<Vec<u16>>, NativeError> {
    if buffer.len() < 2 || buffer.last() != Some(&0) || buffer[buffer.len() - 2] != 0 {
        return Err(NativeError::EnumerationFailed);
    }
    let mut strings = Vec::new();
    let mut start = 0_usize;
    while start < buffer.len() - 1 {
        let length = buffer[start..]
            .iter()
            .position(|unit| *unit == 0)
            .ok_or(NativeError::EnumerationFailed)?;
        if length == 0 {
            if buffer[start..].iter().any(|unit| *unit != 0) {
                return Err(NativeError::EnumerationFailed);
            }
            break;
        }
        strings.push(buffer[start..start + length].to_vec());
        start = start
            .checked_add(length + 1)
            .ok_or(NativeError::ResourceLimit)?;
    }
    Ok(strings)
}
