// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Bounded Windows string and native-error helpers for service DACL operations.

use std::ffi::OsStr;
use std::mem::{align_of, size_of};
use std::os::windows::ffi::OsStrExt;

use windows::Win32::Foundation::ERROR_ACCESS_DENIED;
use windows::core::Error;

use crate::NativeError;

/// Copies one bounded NUL-terminated UTF-16 string from config storage.
pub(super) fn bounded_wide(
    storage: &[usize],
    returned_bytes: usize,
    pointer: *mut u16,
) -> Result<Vec<u16>, NativeError> {
    if pointer.is_null() {
        return Ok(Vec::new());
    }
    let start = storage.as_ptr() as usize;
    let end = start
        .checked_add(returned_bytes)
        .ok_or(NativeError::ResourceLimit)?;
    let address = pointer as usize;
    if address < start || address >= end || address % align_of::<u16>() != 0 {
        return Err(NativeError::Other);
    }
    let available = (end - address) / size_of::<u16>();
    // SAFETY: pointer is aligned and bounded for the computed available units.
    let units = unsafe { std::slice::from_raw_parts(pointer, available) };
    let terminator = units
        .iter()
        .position(|unit| *unit == 0)
        .ok_or(NativeError::Other)?;
    Ok(units[..terminator].to_vec())
}

/// Copies a complete bounded double-NUL-terminated dependency multi-string.
pub(super) fn bounded_multi_wide(
    storage: &[usize],
    returned_bytes: usize,
    pointer: *mut u16,
) -> Result<Vec<u16>, NativeError> {
    if pointer.is_null() {
        return Ok(Vec::new());
    }
    let start = storage.as_ptr() as usize;
    let end = start
        .checked_add(returned_bytes)
        .ok_or(NativeError::ResourceLimit)?;
    let address = pointer as usize;
    if address < start || address >= end || address % align_of::<u16>() != 0 {
        return Err(NativeError::Other);
    }
    let available = (end - address) / size_of::<u16>();
    // SAFETY: pointer is aligned and bounded for the computed available units.
    let units = unsafe { std::slice::from_raw_parts(pointer, available) };
    let end_index = units
        .windows(2)
        .position(|pair| pair == [0, 0])
        .ok_or(NativeError::Other)?;
    Ok(units[..end_index].to_vec())
}

/// Converts one local OS string to exact NUL-terminated UTF-16.
pub(super) fn wide_null(value: &OsStr) -> Vec<u16> {
    value.encode_wide().chain(std::iter::once(0)).collect()
}

/// Recognizes one exact HRESULT-wrapped Win32 error code.
pub(super) fn is_error(
    result: &windows::core::Result<()>,
    code: windows::Win32::Foundation::WIN32_ERROR,
) -> bool {
    result.as_ref().err().is_some_and(|error| {
        let raw = error.code().0 as u32;
        raw & 0xFFFF_0000 == 0x8007_0000 && raw & 0xFFFF == code.0
    })
}

/// Maps only access denial distinctly and discards every native message.
pub(super) fn map_native_error(error: Error) -> NativeError {
    let raw = error.code().0 as u32;
    if raw & 0xFFFF_0000 == 0x8007_0000 && raw & 0xFFFF == ERROR_ACCESS_DENIED.0 {
        NativeError::AccessDenied
    } else {
        NativeError::Other
    }
}
