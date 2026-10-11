// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Application-owned exact-serial Windows drive-letter preference storage.

use windows::Win32::Foundation::{
    ERROR_ACCESS_DENIED, ERROR_FILE_NOT_FOUND, ERROR_NO_MORE_ITEMS, ERROR_SUCCESS,
};
use windows::Win32::Storage::FileSystem::GetLogicalDrives;
use windows::Win32::System::Registry::{
    HKEY, HKEY_LOCAL_MACHINE, KEY_ENUMERATE_SUB_KEYS, KEY_QUERY_VALUE, KEY_SET_VALUE,
    REG_OPTION_NON_VOLATILE, REG_SZ, RegCloseKey, RegCreateKeyExW, RegDeleteTreeW, RegEnumKeyExW,
    RegOpenKeyExW, RegQueryValueExW, RegSetValueExW,
};
use windows::core::{PCWSTR, PWSTR};

use crate::{HostOperationOutcome, NativeError, available_drive_letters_from_state};

const ROOT: &str = "SOFTWARE\\OpenRDXManager\\DriveLetters";
const OWNER: &str = "OpenRDXManager-v1";
const MAX_PREFERENCE_KEYS: u32 = 256;

/// Exact application-owned preference read under one validated serial key.
pub(crate) struct Preference {
    pub(crate) letter: char,
    pub(crate) volume_key: Option<String>,
}

struct RegistryKey(HKEY);

impl Drop for RegistryKey {
    /// Closes the exact registry key once.
    fn drop(&mut self) {
        // SAFETY: this guard uniquely owns a successful registry handle.
        let _ = unsafe { RegCloseKey(self.0) };
    }
}

/// Persists a collision-free uppercase letter under one bounded serial hash.
pub(crate) fn set_preference(serial_key: &str, letter: char) -> HostOperationOutcome {
    persist_preference(serial_key, letter, None, false)
}

/// Persists an exact currently applied volume mapping after native verification.
pub(crate) fn set_bound_preference(
    serial_key: &str,
    letter: char,
    volume_key: &str,
    already_owned: bool,
) -> HostOperationOutcome {
    persist_preference(serial_key, letter, Some(volume_key), already_owned)
}

/// Writes one exact preference and optional current-volume ownership proof.
fn persist_preference(
    serial_key: &str,
    letter: char,
    volume_key: Option<&str>,
    already_owned: bool,
) -> HostOperationOutcome {
    if !valid_serial_key(serial_key) || !letter.is_ascii_uppercase() || letter < 'D' {
        return HostOperationOutcome::NotAttempted(NativeError::InvalidRequest);
    }
    // SAFETY: GetLogicalDrives has no pointer arguments or preconditions.
    if sibling_reserves_letter(serial_key, letter).unwrap_or(true)
        || (!already_owned && drive_mask_contains(unsafe { GetLogicalDrives() }, letter))
    {
        return HostOperationOutcome::NotAttempted(NativeError::Busy);
    }
    let path = wide(&format!("{ROOT}\\{serial_key}"));
    let mut raw = HKEY::default();
    // SAFETY: path is NUL-terminated and raw points to writable handle storage.
    let status = unsafe {
        RegCreateKeyExW(
            HKEY_LOCAL_MACHINE,
            PCWSTR(path.as_ptr()),
            None,
            PCWSTR::null(),
            REG_OPTION_NON_VOLATILE,
            KEY_QUERY_VALUE | KEY_SET_VALUE,
            None,
            &mut raw,
            None,
        )
    };
    if status != ERROR_SUCCESS {
        return HostOperationOutcome::NotAttempted(map_status(status));
    }
    let key = RegistryKey(raw);
    // Recheck after acquiring the exact preference key to reduce collision races.
    // SAFETY: GetLogicalDrives has no pointer arguments or preconditions.
    if sibling_reserves_letter(serial_key, letter).unwrap_or(true)
        || (!already_owned && drive_mask_contains(unsafe { GetLogicalDrives() }, letter))
    {
        return HostOperationOutcome::NotAttempted(NativeError::Busy);
    }
    let owner_name = wide("Owner");
    let letter_name = wide("DriveLetter");
    let owner = wide_bytes(OWNER);
    let value = wide_bytes(&letter.to_string());
    // SAFETY: key is live and all names/data remain valid for synchronous calls.
    if unsafe {
        RegSetValueExW(
            key.0,
            PCWSTR(owner_name.as_ptr()),
            None,
            REG_SZ,
            Some(&owner),
        )
    } != ERROR_SUCCESS
    {
        return HostOperationOutcome::CompletionUnknown(NativeError::Other);
    }
    // SAFETY: same live exact key and bounded NUL-terminated value bytes.
    let status = unsafe {
        RegSetValueExW(
            key.0,
            PCWSTR(letter_name.as_ptr()),
            None,
            REG_SZ,
            Some(&value),
        )
    };
    if status != ERROR_SUCCESS {
        return HostOperationOutcome::CompletionUnknown(map_status(status));
    }
    if let Some(volume_key) = volume_key {
        let volume_name = wide("VolumeKey");
        let volume_value = wide_bytes(volume_key);
        // SAFETY: same live key and bounded exact volume-GUID string value.
        let status = unsafe {
            RegSetValueExW(
                key.0,
                PCWSTR(volume_name.as_ptr()),
                None,
                REG_SZ,
                Some(&volume_value),
            )
        };
        if status != ERROR_SUCCESS {
            return HostOperationOutcome::CompletionUnknown(map_status(status));
        }
    }
    HostOperationOutcome::Succeeded
}

/// Rejects a letter already preferred by another exact app-owned dock serial.
fn sibling_reserves_letter(serial_key: &str, letter: char) -> Result<bool, NativeError> {
    let root_path = wide(ROOT);
    let mut raw = HKEY::default();
    // SAFETY: fixed app root is NUL-terminated and raw is writable handle storage.
    let status = unsafe {
        RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            PCWSTR(root_path.as_ptr()),
            None,
            KEY_QUERY_VALUE | KEY_ENUMERATE_SUB_KEYS,
            &mut raw,
        )
    };
    if status == ERROR_FILE_NOT_FOUND {
        return Ok(false);
    }
    if status != ERROR_SUCCESS {
        return Err(map_status(status));
    }
    let root = RegistryKey(raw);
    for index in 0..256_u32 {
        let mut name = [0_u16; 65];
        let mut length = 64_u32;
        // SAFETY: root is live and name/length are exact bounded writable storage.
        let status = unsafe {
            RegEnumKeyExW(
                root.0,
                index,
                Some(PWSTR(name.as_mut_ptr())),
                &mut length,
                None,
                None,
                None,
                None,
            )
        };
        if status == ERROR_NO_MORE_ITEMS {
            return Ok(false);
        }
        if status != ERROR_SUCCESS || length as usize > 64 {
            return Err(map_status(status));
        }
        let sibling = String::from_utf16(&name[..length as usize])
            .map_err(|_| NativeError::InvalidRequest)?;
        if sibling == serial_key || !valid_serial_key(&sibling) {
            continue;
        }
        let child_path = wide(&format!("{ROOT}\\{sibling}"));
        let mut child_raw = HKEY::default();
        // SAFETY: validated child path is NUL-terminated and output is writable.
        if unsafe {
            RegOpenKeyExW(
                HKEY_LOCAL_MACHINE,
                PCWSTR(child_path.as_ptr()),
                None,
                KEY_QUERY_VALUE,
                &mut child_raw,
            )
        } != ERROR_SUCCESS
        {
            return Err(NativeError::Other);
        }
        let child = RegistryKey(child_raw);
        let letter_text = letter.to_string();
        if query_string(&child, "Owner").as_deref() == Some(OWNER)
            && query_string(&child, "DriveLetter").as_deref() == Some(letter_text.as_str())
        {
            return Ok(true);
        }
    }
    Err(NativeError::ResourceLimit)
}

/// Enumerates truly assignable drive letters from the fixed host authorities.
pub(crate) fn available_drive_letters() -> Result<Vec<char>, NativeError> {
    // SAFETY: GetLogicalDrives has no pointer arguments or preconditions. A zero
    // bitmap is its documented failure value, not proof that all letters are free.
    let occupied_mask = unsafe { GetLogicalDrives() };
    if occupied_mask == 0 {
        return Err(NativeError::EnumerationFailed);
    }
    available_drive_letters_from_state(occupied_mask, &reserved_letters()?)
}

/// Reads every valid application-owned preference under the one fixed root.
fn reserved_letters() -> Result<Vec<char>, NativeError> {
    let root_path = wide(ROOT);
    let mut raw = HKEY::default();
    // SAFETY: fixed app root is NUL-terminated and raw is writable handle storage.
    let status = unsafe {
        RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            PCWSTR(root_path.as_ptr()),
            None,
            KEY_QUERY_VALUE | KEY_ENUMERATE_SUB_KEYS,
            &mut raw,
        )
    };
    if status == ERROR_FILE_NOT_FOUND {
        return Ok(Vec::new());
    }
    if status != ERROR_SUCCESS {
        return Err(map_status(status));
    }
    let root = RegistryKey(raw);
    let mut letters = Vec::new();
    for index in 0..MAX_PREFERENCE_KEYS {
        let mut name = [0_u16; 65];
        let mut length = 64_u32;
        // SAFETY: root is live and name/length are exact bounded writable storage.
        let status = unsafe {
            RegEnumKeyExW(
                root.0,
                index,
                Some(PWSTR(name.as_mut_ptr())),
                &mut length,
                None,
                None,
                None,
                None,
            )
        };
        if status == ERROR_NO_MORE_ITEMS {
            return Ok(letters);
        }
        if status != ERROR_SUCCESS || length as usize > 64 {
            return Err(map_status(status));
        }
        let serial = String::from_utf16(&name[..length as usize])
            .map_err(|_| NativeError::InvalidRequest)?;
        if !valid_serial_key(&serial) {
            continue;
        }
        let child_path = wide(&format!("{ROOT}\\{serial}"));
        let mut child_raw = HKEY::default();
        // SAFETY: validated child path is NUL-terminated and output is writable.
        let status = unsafe {
            RegOpenKeyExW(
                HKEY_LOCAL_MACHINE,
                PCWSTR(child_path.as_ptr()),
                None,
                KEY_QUERY_VALUE,
                &mut child_raw,
            )
        };
        if status != ERROR_SUCCESS {
            return Err(map_status(status));
        }
        let child = RegistryKey(child_raw);
        let owner = query_string(&child, "Owner").ok_or(NativeError::EvidenceIncomplete)?;
        if owner != OWNER {
            continue;
        }
        let letter_text =
            query_string(&child, "DriveLetter").ok_or(NativeError::EvidenceIncomplete)?;
        let mut characters = letter_text.chars();
        let letter = characters.next().ok_or(NativeError::EvidenceIncomplete)?;
        if characters.next().is_some() || !letter.is_ascii_uppercase() || letter < 'D' {
            return Err(NativeError::EvidenceIncomplete);
        }
        if !letters.contains(&letter) {
            letters.push(letter);
        }
    }
    Err(NativeError::ResourceLimit)
}

/// Reads only an exact application-owned preference for one validated serial key.
pub(crate) fn preference(serial_key: &str) -> Result<Option<Preference>, NativeError> {
    if !valid_serial_key(serial_key) {
        return Err(NativeError::InvalidRequest);
    }
    let path = wide(&format!("{ROOT}\\{serial_key}"));
    let mut raw = HKEY::default();
    // SAFETY: path is NUL-terminated and raw is writable handle storage.
    let status = unsafe {
        RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            PCWSTR(path.as_ptr()),
            None,
            KEY_QUERY_VALUE,
            &mut raw,
        )
    };
    if status == ERROR_FILE_NOT_FOUND {
        return Ok(None);
    }
    if status != ERROR_SUCCESS {
        return Err(map_status(status));
    }
    let key = RegistryKey(raw);
    if query_string(&key, "Owner").as_deref() != Some(OWNER) {
        return Err(NativeError::InvalidRequest);
    }
    let letter = query_string(&key, "DriveLetter")
        .and_then(|value| value.chars().next().filter(|_| value.chars().count() == 1))
        .filter(|letter| letter.is_ascii_uppercase() && *letter >= 'D')
        .ok_or(NativeError::InvalidRequest)?;
    Ok(Some(Preference {
        letter,
        volume_key: query_string(&key, "VolumeKey"),
    }))
}

/// Proves whether a preferred target is owned outside the exact selected volume.
pub(crate) fn target_reserved_elsewhere(
    serial_key: &str,
    letter: char,
    selected_owns_target: bool,
) -> Result<bool, NativeError> {
    if !valid_serial_key(serial_key) || !letter.is_ascii_uppercase() || letter < 'D' {
        return Err(NativeError::InvalidRequest);
    }
    // SAFETY: GetLogicalDrives has no pointer arguments or preconditions.
    Ok(sibling_reserves_letter(serial_key, letter)?
        || (!selected_owns_target && drive_mask_contains(unsafe { GetLogicalDrives() }, letter)))
}

/// Removes only a key carrying the exact application owner marker.
pub(crate) fn reset_preference(serial_key: &str) -> HostOperationOutcome {
    if !valid_serial_key(serial_key) {
        return HostOperationOutcome::NotAttempted(NativeError::InvalidRequest);
    }
    let relative = format!("{ROOT}\\{serial_key}");
    let path = wide(&relative);
    let mut raw = HKEY::default();
    // SAFETY: path is NUL-terminated and raw is writable handle storage.
    let status = unsafe {
        RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            PCWSTR(path.as_ptr()),
            None,
            KEY_QUERY_VALUE,
            &mut raw,
        )
    };
    if status == ERROR_FILE_NOT_FOUND {
        return HostOperationOutcome::Succeeded;
    }
    if status != ERROR_SUCCESS {
        return HostOperationOutcome::NotAttempted(map_status(status));
    }
    let key = RegistryKey(raw);
    if query_string(&key, "Owner").as_deref() != Some(OWNER) {
        return HostOperationOutcome::NotAttempted(NativeError::InvalidRequest);
    }
    drop(key);
    // SAFETY: root is predefined and relative names only the validated app subtree.
    let status = unsafe { RegDeleteTreeW(HKEY_LOCAL_MACHINE, PCWSTR(path.as_ptr())) };
    if status == ERROR_SUCCESS || status == ERROR_FILE_NOT_FOUND {
        HostOperationOutcome::Succeeded
    } else {
        HostOperationOutcome::CompletionUnknown(map_status(status))
    }
}

/// Queries one bounded REG_SZ value and rejects every other type/shape.
fn query_string(key: &RegistryKey, name: &str) -> Option<String> {
    let name = wide(name);
    let mut kind = Default::default();
    let mut length = 0_u32;
    // SAFETY: key/name are live and length/type are writable sizing storage.
    if unsafe {
        RegQueryValueExW(
            key.0,
            PCWSTR(name.as_ptr()),
            None,
            Some(&mut kind),
            None,
            Some(&mut length),
        )
    } != ERROR_SUCCESS
        || kind != REG_SZ
        || length == 0
        || length > 512
        || length % 2 != 0
    {
        return None;
    }
    let mut bytes = vec![0_u8; length as usize];
    // SAFETY: bytes has exactly the sized writable capacity returned above.
    if unsafe {
        RegQueryValueExW(
            key.0,
            PCWSTR(name.as_ptr()),
            None,
            Some(&mut kind),
            Some(bytes.as_mut_ptr()),
            Some(&mut length),
        )
    } != ERROR_SUCCESS
    {
        return None;
    }
    let units = bytes
        .chunks_exact(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
        .take_while(|unit| *unit != 0)
        .collect::<Vec<_>>();
    String::from_utf16(&units).ok()
}

/// Validates the fixed lowercase SHA-256 serial mapping key.
fn valid_serial_key(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

/// Reports whether one uppercase letter is currently assigned by Windows.
fn drive_mask_contains(mask: u32, letter: char) -> bool {
    let index = letter as u32 - 'A' as u32;
    mask & (1_u32 << index) != 0
}

/// Produces one NUL-terminated UTF-16 string.
fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Produces little-endian REG_SZ bytes including a UTF-16 NUL.
fn wide_bytes(value: &str) -> Vec<u8> {
    wide(value).into_iter().flat_map(u16::to_le_bytes).collect()
}

/// Maps only stable registry status classes without retaining native text.
fn map_status(status: windows::Win32::Foundation::WIN32_ERROR) -> NativeError {
    if status == ERROR_ACCESS_DENIED {
        NativeError::AccessDenied
    } else if status == ERROR_FILE_NOT_FOUND {
        NativeError::DeviceRemoved
    } else {
        NativeError::Other
    }
}
