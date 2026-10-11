// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Fixed manufacturing-sector reads and compare-and-replace restore construction.

use super::{Command, DataDirection, ProtocolBuildError};

/// Reads one 128-byte chunk of the fixed manufacturing sector through BOT.
///
/// # Errors
/// Rejects indices outside 0..32; callers cannot select another flash range.
pub fn openrdx_manufacturing_sector_chunk(index: u8) -> Result<Command, ProtocolBuildError> {
    if index >= 32 {
        return Err(ProtocolBuildError::ValueOutOfRange {
            field: "manufacturing sector chunk",
            value: u64::from(index),
            maximum: 31,
        });
    }
    Ok(Command::new(
        [0xe7, 0, 3, 0xe0 + index / 2, (index % 2) * 128, 128],
        DataDirection::FromDevice,
        vec![0; 128],
    ))
}

/// Reads only the fixed mechanism frame containing the physical cartridge sensor.
#[must_use]
pub fn openrdx_mechanism_diagnostics() -> Command {
    Command::new(
        [0xe8, 0, 0, 0, 0, 128],
        DataDirection::FromDevice,
        vec![0; 128],
    )
}

/// Probes restore support without a data phase, flash change, or reset.
#[must_use]
pub fn openrdx_manufacturing_restore_capability() -> Command {
    Command::new(
        [0x3b, 2, 0x4d, 0, 0, 1, 0, 0, 0, 0],
        DataDirection::None,
        vec![],
    )
}

/// Probes the serial extension without sending identity data or changing flash.
/// In receiver 1.10 this query is rejected while the manufacturing-write latch is set.
#[must_use]
pub fn openrdx_serial_capability() -> Command {
    Command::new(
        [0x3b, 2, 0x53, 0, 0, 1, 0, 0, 0, 0],
        DataDirection::None,
        vec![],
    )
}

/// Builds the single fixed 528-byte manufacturing compare-and-replace command.
///
/// The expected record may be damaged or erased so original identity can be
/// recovered. The receiver compares both that raw record and the whole-sector
/// CRC before it preserves the sector's neighbors and replaces its first 256 bytes.
///
/// # Errors
/// Rejects length, magic, reserved fields, erased desired data, and bad checksums.
pub fn openrdx_restore_manufacturing(data: &[u8]) -> Result<Command, ProtocolBuildError> {
    if data.len() != 528 || &data[..8] != b"RDXMFG01" || data[12..16] != [0; 4] {
        return Err(ProtocolBuildError::InvalidManufacturingRestorePayload);
    }
    let desired = &data[272..528];
    let mut lanes = [0x78u8, 0x56, 0x34, 0x12];
    for (index, byte) in desired.iter().enumerate().skip(4) {
        lanes[index & 3] = lanes[index & 3].wrapping_add(*byte);
    }
    if desired.iter().all(|byte| *byte == 0xff) || desired[..4] != lanes {
        return Err(ProtocolBuildError::InvalidManufacturingRestorePayload);
    }
    Command::new(
        [0x3b, 2, 0x4d, 0, 0, 0, 0, 2, 0x10, 0],
        DataDirection::ToDevice,
        data.to_vec(),
    )
    // The receiver may exhaust bounded erase/program/status polling before replying.
    .with_timeout_ms(120_000)
}
