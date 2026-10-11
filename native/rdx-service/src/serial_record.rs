// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Fixed manufacturing record layout and complete-sector compare-and-set evidence.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

type Result<T> = std::result::Result<T, &'static str>;

/// Exact byte count required for durable manufacturing-sector evidence.
pub const SECTOR_LENGTH: usize = 4096;
/// Complete manufacturing sector, including all neighboring records.
pub type Sector = [u8; SECTOR_LENGTH];

/// Checksum state does not imply the original factory data can be recovered.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RecordState {
    /// The complete record passes the stock four-lane checksum.
    Valid,
    /// Every byte of the 256-byte record is erased.
    Erased,
    /// The record is partly written or has an invalid checksum.
    Corrupt,
}

/// Validates decimal text without integer conversion, preserving leading zeroes.
pub fn validate_usb_serial(serial: &str) -> Result<()> {
    if serial.len() == 12
        && serial.starts_with("00")
        && serial.bytes().all(|byte| byte.is_ascii_digit())
    {
        Ok(())
    } else {
        Err("serial-invalid-usb-serial")
    }
}

/// Returns the stock four-lane wrapping checksum of bytes 4 through 255.
fn checksum(record: &[u8]) -> [u8; 4] {
    let mut lanes = [0x78_u8, 0x56, 0x34, 0x12];
    for (index, byte) in record.iter().enumerate().take(256).skip(4) {
        lanes[index & 3] = lanes[index & 3].wrapping_add(*byte);
    }
    lanes
}

/// Distinguishes erased records before testing their stock checksum.
pub fn state(sector: &Sector) -> RecordState {
    if sector[..256].iter().all(|byte| *byte == 0xff) {
        RecordState::Erased
    } else if sector[..4] == checksum(sector) {
        RecordState::Valid
    } else {
        RecordState::Corrupt
    }
}

/// Reports only a valid decimal serial; never emits opaque manufacturing fields.
pub fn record_usb_serial(sector: &Sector) -> Option<String> {
    if state(sector) != RecordState::Valid || !sector[8..18].iter().all(u8::is_ascii_digit) {
        return None;
    }
    Some(format!("00{}", std::str::from_utf8(&sector[8..18]).ok()?))
}

/// Produces exact receiver reconstruction defaults, preserving all sector neighbors.
pub fn expected_sector(sector: &Sector, usb_serial: &str, reconstruct: bool) -> Result<Sector> {
    validate_usb_serial(usb_serial)?;
    let mut expected = *sector;
    match (state(sector), reconstruct) {
        (RecordState::Valid, false) => {}
        (RecordState::Erased, true) => {
            expected[..256].fill(0);
            expected[4..8].copy_from_slice(&6_u32.to_le_bytes());
            expected[0x12..0x1a].copy_from_slice(b"TANDBERG");
            expected[0x1a..0x2a].copy_from_slice(b"RDX             ");
            expected[0x30..0x34].copy_from_slice(&1_u32.to_le_bytes());
            expected[0x76..0x78].copy_from_slice(&0x1a5a_u16.to_le_bytes());
            expected[0x78..0x7a].copy_from_slice(&6_u16.to_le_bytes());
            expected[0x7a..0x82].copy_from_slice(b"TANDBERG");
            expected[0x82..0x92].copy_from_slice(b"RDX             ");
            expected[0x9c..0xa4].copy_from_slice(b"10102010");
            expected[0xa4..0xa6].copy_from_slice(&0x38_u16.to_le_bytes());
        }
        (RecordState::Corrupt, _) => return Err("serial-record-corrupt"),
        (RecordState::Erased, false) => {
            return Err("serial-erased-requires-explicit-reconstruction");
        }
        _ => return Err("serial-reconstruction-requires-erased-record"),
    }
    expected[8..18].copy_from_slice(&usb_serial.as_bytes()[2..]);
    let lanes = checksum(&expected);
    expected[..4].copy_from_slice(&lanes);
    Ok(expected)
}

/// Implements CRC-32/IEEE with the standard reflected polynomial and initial/final XOR.
pub fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = u32::MAX;
    for byte in bytes {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0xedb88320 & (0_u32.wrapping_sub(crc & 1)));
        }
    }
    !crc
}

/// Hashes the complete sector rather than only the manufacturing record.
pub fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

/// Constructs the sole 280-byte serial operation from the original complete-sector evidence.
pub fn payload(sector: &Sector, new_serial: &str, reconstruct: bool) -> Result<Vec<u8>> {
    expected_sector(sector, new_serial, reconstruct)?;
    let mut data = vec![0; 280];
    data[..8].copy_from_slice(b"RDXSER01");
    data[8..12].copy_from_slice(&crc32(sector).to_le_bytes());
    data[12] = u8::from(reconstruct);
    data[14..24].copy_from_slice(&new_serial.as_bytes()[2..]);
    data[24..].copy_from_slice(&sector[..256]);
    Ok(data)
}

/// Rejects truncated and oversized sector input before any preparation or device I/O.
pub fn sector_from_bytes(bytes: &[u8]) -> std::result::Result<Sector, &'static str> {
    bytes.try_into().map_err(|_| "serial-sector-length-invalid")
}

/// Produces an offline expected record for review without constructing device or backup evidence.
///
/// This transform cannot create an applicable plan: hardware application still requires the
/// original complete 4096-byte sector, pinned USB identity, and all live admission checks.
pub fn expected_record(
    record: &[u8; 256],
    usb_serial: &str,
    reconstruct: bool,
) -> Result<[u8; 256]> {
    let mut sector = [0; SECTOR_LENGTH];
    sector[..256].copy_from_slice(record);
    let expected = expected_sector(&sector, usb_serial, reconstruct)?;
    Ok(expected[..256]
        .try_into()
        .expect("fixed manufacturing-record range"))
}
