// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Positive RDX-only permission admission and safe previous-policy restoration.
use crate::NativeError;
/// Validates the complete standard/VPD identity pair before device ACL setup.
///
/// # Errors
/// Unknown disks, truncated/mismatching replies and unsupported product markers fail.
pub fn rdx_permission_identity(standard: &[u8], vpd: &[u8]) -> Result<String, NativeError> {
    if standard.len() < 43
        || standard.len() > 254
        || standard[0] & 0x1f != 0
        || standard[4] as usize + 5 != standard.len()
        || &standard[37..40] != b"RDX"
        || !matches!(standard[36], 0..=6 | 0x35..=0x39)
        || vpd.len() < 42
        || vpd.len() > 254
        || vpd[0] & 0x1f != 0
        || vpd[1] != 0x83
        || u16::from_be_bytes([vpd[2], vpd[3]]) as usize + 4 != vpd.len()
        || standard[8..32] != vpd[8..32]
        || standard[8..16].iter().all(|v| *v == b' ')
        || standard[16..32].iter().all(|v| *v == b' ')
    {
        return Err(NativeError::EvidenceIncomplete);
    }
    for bytes in [&standard[8..32], &vpd[32..42]] {
        if bytes.iter().any(|v| !(0x20..=0x7e).contains(v)) {
            return Err(NativeError::EvidenceIncomplete);
        }
    }
    let serial = std::str::from_utf8(&vpd[32..42])
        .map_err(|_| NativeError::EvidenceIncomplete)?
        .trim();
    if serial.is_empty() {
        return Err(NativeError::EvidenceIncomplete);
    }
    Ok(serial.to_owned())
}
/// Requires exact current instance, dock identity and our recorded installed policy.
/// A later administrator ACL change is always preserved rather than overwritten.
#[must_use]
pub fn safe_device_acl_restore(
    recorded_instance: &str,
    recorded_serial: &str,
    installed: &str,
    current_instance: &str,
    current_serial: &str,
    current: &str,
) -> bool {
    !recorded_instance.is_empty()
        && !recorded_serial.is_empty()
        && !installed.is_empty()
        && recorded_instance == current_instance
        && recorded_serial == current_serial
        && installed == current
}

/// Permits repair only from our installed descriptor or exactly recorded prior state.
/// An interrupted setup may have persisted its journal before applying the ACL.
#[must_use]
pub fn safe_device_acl_repair(
    recorded_instance: &str,
    recorded_serial: &str,
    installed: &str,
    previous: Option<&str>,
    current_instance: &str,
    current_serial: &str,
    current: Option<&str>,
) -> bool {
    !recorded_instance.is_empty()
        && !recorded_serial.is_empty()
        && !installed.is_empty()
        && recorded_instance == current_instance
        && recorded_serial == current_serial
        && (current == Some(installed) || current == previous)
}
