// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

use crate::{TrustError, deny};
use std::{
    collections::HashSet,
    fs::File,
    io::{Read, Seek, SeekFrom},
};

/// Electron's official v1 fuse sentinel; offsets match @electron/fuses config.
const SENTINEL: &[u8] = b"dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX";

/// Verify exactly one canonical v1 wire in every bounded 64-bit Mach-O slice.
/// RunAsNode, NODE_OPTIONS and CLI inspection must be disabled; embedded ASAR
/// integrity and ASAR-only loading must be enabled. This proves fuse content,
/// never an Apple signature or filesystem protection.
pub(crate) fn verify_electron_fuses(file: &mut File) -> Result<(), TrustError> {
    let size = file.metadata()?.len();
    if !(32..=2_147_483_648).contains(&size) {
        return Err(deny("Electron framework size outside bound"));
    }
    let header = read_at(file, 0, 8)?;
    let (little, wide) = match &header[..4] {
        [0xca, 0xfe, 0xba, 0xbe] => (false, false),
        [0xbe, 0xba, 0xfe, 0xca] => (true, false),
        [0xca, 0xfe, 0xba, 0xbf] => (false, true),
        [0xbf, 0xba, 0xfe, 0xca] => (true, true),
        _ => {
            verify_slice(file, 0, size, None)?;
            return Ok(());
        }
    };
    let count = number32(&header, 4, little)? as usize;
    if !(1..=16).contains(&count) {
        return Err(deny("unsupported Mach-O architecture count"));
    }
    let entry_size = if wide { 32 } else { 20 };
    let table_end = 8 + count * entry_size;
    let table = read_at(file, 0, table_end)?;
    let mut ranges = Vec::new();
    let mut cpus = HashSet::new();
    for index in 0..count {
        let entry = 8 + index * entry_size;
        let cpu = number32(&table, entry, little)?;
        if !cpus.insert(cpu) {
            return Err(deny("duplicate Mach-O architecture"));
        }
        let offset = if wide {
            number64(&table, entry + 8, little)?
        } else {
            u64::from(number32(&table, entry + 8, little)?)
        };
        let length = if wide {
            number64(&table, entry + 16, little)?
        } else {
            u64::from(number32(&table, entry + 12, little)?)
        };
        let end = offset
            .checked_add(length)
            .ok_or_else(|| deny("Mach-O slice overflows"))?;
        if offset < table_end as u64
            || length < 32
            || end > size
            || ranges
                .iter()
                .any(|&(start, stop)| offset < stop && end > start)
        {
            return Err(deny("invalid or overlapping Mach-O slice"));
        }
        ranges.push((offset, end));
        verify_slice(file, offset, length, Some(cpu))?;
    }
    Ok(())
}

/// Verify a slice's architecture header and stream its complete fuse sentinel scan.
fn verify_slice(
    file: &mut File,
    start: u64,
    size: u64,
    expected_cpu: Option<u32>,
) -> Result<(), TrustError> {
    let header = read_at(file, start, 32)?;
    let little = match &header[..4] {
        [0xcf, 0xfa, 0xed, 0xfe] => true,
        [0xfe, 0xed, 0xfa, 0xcf] => false,
        _ => return Err(deny("Electron framework is not 64-bit Mach-O")),
    };
    let cpu = number32(&header, 4, little)?;
    if !matches!(cpu, 0x01000007 | 0x0100000c)
        || expected_cpu.is_some_and(|expected| expected != cpu)
    {
        return Err(deny("unsupported or mismatched Mach-O architecture"));
    }
    let end = start
        .checked_add(size)
        .ok_or_else(|| deny("Mach-O slice overflow"))?;
    let mut position = start;
    let mut carry = Vec::new();
    let mut found = false;
    while position < end {
        let amount =
            usize::try_from((end - position).min(65536)).map_err(|_| deny("Mach-O scan bound"))?;
        let chunk = read_at(file, position, amount)?;
        let base = position - carry.len() as u64;
        carry.extend_from_slice(&chunk);
        for offset in 0..=carry.len().saturating_sub(SENTINEL.len()) {
            if carry.get(offset..offset + SENTINEL.len()) != Some(SENTINEL) {
                continue;
            }
            if found {
                return Err(deny("multiple Electron fuse wires in one slice"));
            }
            let wire_start = base + offset as u64 + SENTINEL.len() as u64;
            if wire_start + 2 > end {
                return Err(deny("truncated Electron fuse wire"));
            }
            let metadata = read_at(file, wire_start, 2)?;
            let length = usize::from(metadata[1]);
            if metadata[0] != 1
                || !(6..=64).contains(&length)
                || wire_start + 2 + length as u64 > end
            {
                return Err(deny("unsupported or malformed Electron fuse wire"));
            }
            let wire = read_at(file, wire_start + 2, length)?;
            if !wire
                .iter()
                .all(|state| matches!(*state, b'0' | b'1' | b'r' | 144))
                || [0, 2, 3].iter().any(|&index| wire[index] != b'0')
                || [4, 5].iter().any(|&index| wire[index] != b'1')
            {
                return Err(deny("Electron runtime hardening fuses are unsafe"));
            }
            found = true;
        }
        let keep = carry.len().min(SENTINEL.len() - 1);
        carry = carry[carry.len() - keep..].to_vec();
        position += amount as u64;
    }
    if !found {
        return Err(deny("Electron runtime has no fuse wire"));
    }
    Ok(())
}

/// Read a bounded binary region without relying on a mutable shared cursor.
fn read_at(file: &mut File, offset: u64, size: usize) -> Result<Vec<u8>, TrustError> {
    file.seek(SeekFrom::Start(offset))?;
    let mut bytes = vec![0; size];
    file.read_exact(&mut bytes)?;
    Ok(bytes)
}

/// Decode a checked 32-bit Mach-O field in its declared byte order.
fn number32(bytes: &[u8], offset: usize, little: bool) -> Result<u32, TrustError> {
    let value: [u8; 4] = bytes
        .get(offset..offset + 4)
        .ok_or_else(|| deny("truncated Mach-O field"))?
        .try_into()
        .map_err(|_| deny("invalid Mach-O field"))?;
    Ok(if little {
        u32::from_le_bytes(value)
    } else {
        u32::from_be_bytes(value)
    })
}

/// Decode a checked 64-bit Mach-O field in its declared byte order.
fn number64(bytes: &[u8], offset: usize, little: bool) -> Result<u64, TrustError> {
    let value: [u8; 8] = bytes
        .get(offset..offset + 8)
        .ok_or_else(|| deny("truncated Mach-O field"))?
        .try_into()
        .map_err(|_| deny("invalid Mach-O field"))?;
    Ok(if little {
        u64::from_le_bytes(value)
    } else {
        u64::from_be_bytes(value)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// Build a real byte fixture containing a thin 64-bit Electron-style wire.
    fn thin(wire: Option<&[u8]>) -> Vec<u8> {
        let mut bytes = vec![0; 32];
        bytes[..4].copy_from_slice(&[0xcf, 0xfa, 0xed, 0xfe]);
        bytes[4..8].copy_from_slice(&0x01000007_u32.to_le_bytes());
        if let Some(wire) = wire {
            bytes.extend_from_slice(SENTINEL);
            bytes.extend_from_slice(&[1, wire.len() as u8]);
            bytes.extend_from_slice(wire);
        }
        bytes
    }

    /// Verify a retained real temporary binary, independently of ownership proof.
    fn verify(bytes: &[u8]) -> Result<(), crate::TrustError> {
        let mut file = tempfile::tempfile().unwrap();
        file.write_all(bytes).unwrap();
        verify_electron_fuses(&mut file)
    }

    #[test]
    /// Each mandatory configured state must be read from the actual binary.
    fn requires_all_five_actual_hardened_states() {
        verify(&thin(Some(b"01001111"))).unwrap();
        for index in [0, 2, 3, 4, 5] {
            let mut wire = *b"01001111";
            wire[index] = if wire[index] == b'0' { b'1' } else { b'0' };
            assert!(verify(&thin(Some(&wire))).is_err());
            wire[index] = b'r';
            assert!(verify(&thin(Some(&wire))).is_err());
        }
    }

    #[test]
    /// Missing/default/malformed fuse wires never establish packaged hardening.
    fn rejects_unfused_malformed_and_duplicate_wires() {
        assert!(verify(&thin(None)).is_err());
        assert!(verify(&thin(Some(b"11110011"))).is_err());
        assert!(verify(&thin(Some(b"01001"))).is_err());
        let mut bytes = thin(Some(b"01001111"));
        bytes[32 + SENTINEL.len()] = 2;
        assert!(verify(&bytes).is_err());
        let duplicate = thin(Some(b"01001111"));
        let mut bytes = duplicate.clone();
        bytes.extend_from_slice(&duplicate[32..]);
        assert!(verify(&bytes).is_err());
        assert!(verify(b"not Mach-O").is_err());
    }

    #[test]
    /// A universal binary cannot hide an unsafe or missing second-slice wire.
    fn checks_every_universal_macho_slice() {
        let first = thin(Some(b"01001111"));
        let mut second = thin(Some(b"01001111"));
        second[4..8].copy_from_slice(&0x0100000c_u32.to_le_bytes());
        let mut bytes = vec![0; 48];
        bytes[..4].copy_from_slice(&[0xca, 0xfe, 0xba, 0xbe]);
        bytes[4..8].copy_from_slice(&2_u32.to_be_bytes());
        for (entry, cpu, offset, size) in [
            (8, 0x01000007_u32, 48_u32, first.len() as u32),
            (
                28,
                0x0100000c_u32,
                48 + first.len() as u32,
                second.len() as u32,
            ),
        ] {
            bytes[entry..entry + 4].copy_from_slice(&cpu.to_be_bytes());
            bytes[entry + 8..entry + 12].copy_from_slice(&offset.to_be_bytes());
            bytes[entry + 12..entry + 16].copy_from_slice(&size.to_be_bytes());
        }
        bytes.extend_from_slice(&first);
        bytes.extend_from_slice(&second);
        verify(&bytes).unwrap();
        *bytes.last_mut().unwrap() = b'X';
        assert!(verify(&bytes).is_err());
        *bytes.last_mut().unwrap() = b'1';
        let wire_start = 48 + first.len() + 32 + SENTINEL.len() + 2;
        bytes[wire_start] = b'1';
        assert!(verify(&bytes).is_err());
    }

    #[test]
    /// Streaming scans retain partial sentinels across read boundaries.
    fn finds_fuse_wire_across_stream_chunk_boundary() {
        let mut bytes = thin(None);
        bytes.resize(65520, 0);
        bytes.extend_from_slice(SENTINEL);
        bytes.extend_from_slice(&[1, 8]);
        bytes.extend_from_slice(b"01001111");
        verify(&bytes).unwrap();
    }
}
