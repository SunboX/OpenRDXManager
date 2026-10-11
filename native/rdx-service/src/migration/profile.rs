#![cfg_attr(not(target_os = "macos"), allow(dead_code))]
// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Exact version-six exposed-record reconstruction.
//!
//! The 48 unexposed manufacturing bytes and 55 unexposed state bytes are zero.
//! Effective mode one cannot distinguish an original saved mode zero from one.
//! All exposed fields, including opaque factory bytes and independently captured
//! product enumeration zero or 56, are retained without interpretation.
//! The pure reconstruction stays compiled for cross-platform fixtures even
//! though only the macOS recovery transport consumes the embedded bootstrap.

use super::{MigrationCapture, MigrationError};
use sha2::{Digest, Sha256};

/// Reviewed source-built template, containing no per-device records.
pub(super) const TEMPLATE: &[u8] =
    include_bytes!("../../resources/migration/openrdx-migration-template.rom.bin");
/// Pins executable bytes independently of the personalized semantic slot.
pub(super) const TEMPLATE_SHA256: &str =
    "4ed054e7d257fb67d0690fb9e168081d67aaafca01c99d1c3bca52d6ce686cf8";
/// Fixed wire header through the SHA-256 field.
const HEADER: [u8; 32] = [
    b'R', b'D', b'X', b'M', b'I', b'G', b'0', b'1', 1, 0, 64, 0, 128, 1, 0, 0, 0, 224, 3, 0, 0, 1,
    0, 0, 0, 240, 3, 0, 64, 0, 0, 0,
];

/// Returns a stable digest without exposing captured fields.
pub(super) fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

/// Computes four independent byte sums with the specified initial lanes.
fn lane_checksum(record: &[u8]) -> [u8; 4] {
    let mut lanes = [0x78u8, 0x56, 0x34, 0x12];
    for (index, value) in record[4..].iter().enumerate() {
        lanes[index % 4] = lanes[index % 4].wrapping_add(*value);
    }
    lanes
}

/// Reads a little-endian four-byte field after its enclosing length was checked.
fn little_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(
        bytes[offset..offset + 4]
            .try_into()
            .expect("bounded wire field"),
    )
}

/// Reads a big-endian two-byte field after its enclosing length was checked.
fn big_u16(bytes: &[u8], offset: usize) -> usize {
    u16::from_be_bytes([bytes[offset], bytes[offset + 1]]) as usize
}

/// Requires complete, unambiguous load count and effective mode framing.
fn state(capture: &MigrationCapture) -> Result<(u32, u8), MigrationError> {
    let invalid = MigrationError::InvalidCapture;
    let log = &capture.drive_log;
    if !(4..=254).contains(&log.len())
        || log[0] & 0x7f != 0x20
        || log[1] != 0
        || big_u16(log, 2) + 4 != log.len()
    {
        return Err(invalid);
    }
    let mut offset = 4;
    let mut count = None;
    while offset < log.len() {
        if offset + 4 > log.len() {
            return Err(invalid);
        }
        let end = offset + 4 + usize::from(log[offset + 3]);
        if end > log.len() {
            return Err(invalid);
        }
        if big_u16(log, offset) == 1 {
            if log[offset + 3] != 4 || count.is_some() {
                return Err(invalid);
            }
            count = Some(u32::from_be_bytes(
                log[offset + 4..end].try_into().map_err(|_| invalid)?,
            ));
        }
        offset = end;
    }
    let mode = &capture.mode_sense;
    if !(15..=254).contains(&mode.len()) || big_u16(mode, 0) + 2 != mode.len() {
        return Err(invalid);
    }
    let page = 8 + big_u16(mode, 6);
    if page + 7 > mode.len()
        || mode[page] & 0x7f != 0x34
        || mode[page + 1] < 5
        || page + 2 + usize::from(mode[page + 1]) != mode.len()
    {
        return Err(invalid);
    }
    let operation_mode = mode[page + 4] & 7;
    if !(1..=3).contains(&operation_mode) {
        return Err(invalid);
    }
    Ok((count.ok_or(invalid)?, operation_mode))
}

/// Validates the actual bounded raw capture before any field indexing or storage.
fn validate(capture: &MigrationCapture, revision: &[u8; 4]) -> Result<(), MigrationError> {
    let invalid = MigrationError::InvalidCapture;
    // The pinned bootstrap source usb_chap9.c hardcodes runtime PID 0005.
    // Its preserved READ BUFFER identity record remains the captured PID 0006.
    // source-inputs.json pins that file to d68248dc...d49406; do not conflate
    // runtime enumeration with the manufacturing-record fields below.
    let runtime_product = match revision {
        b"0283" => 6,
        b"0107" => 5,
        _ => return Err(invalid),
    };
    let identity = &capture.usb;
    if identity.serial.len() != 12
        || !identity.serial.starts_with("00")
        || !identity.serial.bytes().all(|byte| byte.is_ascii_digit())
        || identity.location_id == 0
        || identity.vendor_id != 0x1a5a
        || identity.product_id != runtime_product
    {
        return Err(invalid);
    }
    let inquiry = &capture.inquiry;
    let max_inquiry = if revision == b"0107" { 254 } else { 255 };
    if !(36..=max_inquiry).contains(&inquiry.len())
        || capture.factory.len() != 172
        || capture.usb_response.len() != 32
    {
        return Err(invalid);
    }
    let product_end = inquiry[16..32]
        .iter()
        .rposition(|byte| *byte != b' ' && *byte != 0)
        .map_or(16, |position| 17 + position);
    if inquiry[32..36] != *revision
        || inquiry[4] < 31
        || usize::from(inquiry[4]) + 5 > inquiry.len()
        || &inquiry[8..16] != b"TANDBERG"
        || &inquiry[16..product_end] != b"RDX"
        || (revision == b"0107" && inquiry[0] & 31 != 0)
    {
        return Err(invalid);
    }
    let factory = &capture.factory;
    let usb = &capture.usb_response;
    if factory[16..26] != identity.serial.as_bytes()[2..]
        || little_u32(factory, 28) != 6
        || factory[..16]
            .iter()
            .chain(&factory[26..28])
            .chain(&factory[170..])
            .any(|byte| *byte != 0)
        || usb[..4] != [0; 4]
        || usb[4..8] != [0x5a, 0x1a, 6, 0]
        || !matches!(little_u32(factory, 104), 0 | 56)
        || factory[120..122] != [56, 0]
    {
        return Err(invalid);
    }
    Ok(())
}

/// Builds the fixed package from a bounded source response set.
pub(super) fn build_package(
    capture: &MigrationCapture,
    revision: &[u8; 4],
) -> Result<[u8; 384], MigrationError> {
    validate(capture, revision)?;
    let (load_count, mode) = state(capture)?;
    let mut package = [0u8; 384];
    package[..32].copy_from_slice(&HEADER);
    let unit = &mut package[64..320];
    unit[4..8].copy_from_slice(&capture.factory[28..32]);
    unit[8..18].copy_from_slice(&capture.factory[16..26]);
    unit[18..42].copy_from_slice(&capture.inquiry[8..32]);
    unit[44..116].copy_from_slice(&capture.factory[32..104]);
    unit[118..146].copy_from_slice(&capture.usb_response[4..32]);
    unit[148..214].copy_from_slice(&capture.factory[104..170]);
    let checksum = lane_checksum(unit);
    unit[..4].copy_from_slice(&checksum);
    let state = &mut package[320..];
    state[4..8].copy_from_slice(&load_count.to_le_bytes());
    state[13] = mode;
    let checksum = lane_checksum(state);
    state[..4].copy_from_slice(&checksum);
    let hash = Sha256::digest(&package[64..]);
    package[32..64].copy_from_slice(&hash);
    Ok(package)
}

/// Checks the profile format before it can be embedded into executable bytes.
fn validate_package(package: &[u8; 384]) -> Result<(), MigrationError> {
    if package[..32] != HEADER
        || package[32..64] != Sha256::digest(&package[64..])[..]
        || package[64..68] != lane_checksum(&package[64..320])
        || package[320..324] != lane_checksum(&package[320..])
        || little_u32(package, 68) != 6
        || !(1..=3).contains(&package[333])
        || !package[72..82].iter().all(|byte| byte.is_ascii_digit())
    {
        return Err(MigrationError::InvalidBootstrap);
    }
    Ok(())
}

/// Personalizes exactly one blank slot in the pinned executable, repairing its sum.
pub(super) fn personalize(package: &[u8; 384]) -> Result<Vec<u8>, MigrationError> {
    validate_package(package)?;
    if digest(TEMPLATE) != TEMPLATE_SHA256
        || !(14..=65535).contains(&TEMPLATE.len())
        || TEMPLATE[..9] != [0x60, 0x92, 1, 0, 0, 0, 0, 0, 2]
        || little_u32(TEMPLATE, 9) as usize != TEMPLATE.len() - 14
    {
        return Err(MigrationError::InvalidBootstrap);
    }
    let runtime = &TEMPLATE[13..TEMPLATE.len() - 1];
    let sum = |bytes: &[u8]| bytes.iter().fold(0u8, |sum, byte| sum.wrapping_add(*byte));
    if TEMPLATE[TEMPLATE.len() - 1] != sum(runtime) {
        return Err(MigrationError::InvalidBootstrap);
    }
    let mut placeholder = [0; 384];
    placeholder[..8].copy_from_slice(b"RDXMIG01");
    let mut offsets = runtime
        .windows(384)
        .enumerate()
        .filter_map(|(index, window)| (window == placeholder).then_some(index));
    let offset = offsets.next().ok_or(MigrationError::InvalidBootstrap)? + 13;
    if offsets.next().is_some() {
        return Err(MigrationError::InvalidBootstrap);
    }
    let mut result = TEMPLATE.to_vec();
    result[offset..offset + 384].copy_from_slice(package);
    let end = result.len() - 1;
    result[end] = sum(&result[13..end]);
    Ok(result)
}
