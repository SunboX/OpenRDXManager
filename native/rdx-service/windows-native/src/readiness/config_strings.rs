// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Bounded parsing for pointers returned inside QUERY_SERVICE_CONFIG storage.

use std::mem::{align_of, size_of};

/// Only documented optional fields may represent an empty value with a NULL pointer.
#[derive(Clone, Copy)]
pub(crate) enum ConfigStringKind {
    Required,
    OptionalEmpty,
}

/// Copies one in-buffer UTF-16 value after bounding its complete storage and terminator.
/// A non-NULL optional pointer receives the same validation as a required pointer.
pub(crate) fn bounded_config_string(
    storage: &[usize],
    header_bytes: usize,
    pointer: *const u16,
    kind: ConfigStringKind,
) -> Option<String> {
    if pointer.is_null() {
        return match kind {
            ConfigStringKind::OptionalEmpty => Some(String::new()),
            ConfigStringKind::Required => None,
        };
    }
    let base = storage.as_ptr() as usize;
    let end = base.checked_add(storage.len().checked_mul(size_of::<usize>())?)?;
    let address = pointer as usize;
    let strings_start = base.checked_add(header_bytes)?;
    if address < strings_start || address >= end || address % align_of::<u16>() != 0 {
        return None;
    }
    let units = end.checked_sub(address)?.checked_div(size_of::<u16>())?;
    if units == 0 {
        return None;
    }
    // SAFETY: pointer alignment and range were proven against live storage;
    // units is bounded to the remaining whole UTF-16 elements.
    let text = unsafe {
        std::slice::from_raw_parts(
            storage
                .as_ptr()
                .cast::<u8>()
                .add(address - base)
                .cast::<u16>(),
            units,
        )
    };
    let terminator = text.iter().position(|unit| *unit == 0)?;
    String::from_utf16(&text[..terminator]).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Windows represents omitted load-order-group/dependency lists as NULL.
    #[test]
    fn documented_optional_null_is_an_empty_configuration_value() {
        let storage = [0usize; 8];
        assert_eq!(
            bounded_config_string(
                &storage,
                16,
                std::ptr::null(),
                ConfigStringKind::OptionalEmpty
            ),
            Some(String::new())
        );
    }

    /// Required names and command paths never accept an absent native pointer.
    #[test]
    fn required_null_cannot_become_an_empty_configuration_value() {
        let storage = [0usize; 8];
        assert_eq!(
            bounded_config_string(&storage, 16, std::ptr::null(), ConfigStringKind::Required),
            None
        );
    }

    /// Aligned in-buffer text is decoded, while incomplete or malformed text fails closed.
    #[test]
    fn actual_buffers_require_bounded_terminated_valid_utf16() {
        let mut storage = [usize::MAX; 8];
        let pointer = storage.as_mut_ptr().cast::<u16>();
        // SAFETY: indices 8..12 are within this aligned initialized allocation.
        unsafe {
            pointer.add(8).write(b'O' as u16);
            pointer.add(9).write(b'K' as u16);
            pointer.add(10).write(0);
        }
        let text = unsafe { pointer.add(8) };
        assert_eq!(
            bounded_config_string(&storage, 16, text, ConfigStringKind::Required).as_deref(),
            Some("OK")
        );
        assert_eq!(
            bounded_config_string(&storage, 16, pointer, ConfigStringKind::OptionalEmpty),
            None
        );
        assert_eq!(
            bounded_config_string(
                &storage,
                16,
                (text as usize + 1) as *const u16,
                ConfigStringKind::OptionalEmpty
            ),
            None
        );
        assert_eq!(
            bounded_config_string(
                &storage,
                16,
                (storage.as_ptr() as usize + size_of_val(&storage)) as *const u16,
                ConfigStringKind::OptionalEmpty
            ),
            None
        );
        // SAFETY: these writes remain inside the same live storage.
        unsafe {
            pointer.add(8).write(0xd800);
            pointer.add(9).write(0);
        }
        assert_eq!(
            bounded_config_string(&storage, 16, text, ConfigStringKind::Required),
            None
        );
        storage.fill(usize::MAX);
        assert_eq!(
            bounded_config_string(&storage, 16, text, ConfigStringKind::Required),
            None
        );
    }
}
