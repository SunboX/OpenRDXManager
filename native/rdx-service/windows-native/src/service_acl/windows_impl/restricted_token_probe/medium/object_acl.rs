// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Bounded ordinary-ACE diagnostics. Unsupported encodings are unavailable observations.

/// Validates every ordinary ALLOW/DENY ACE and embedded SID before any kernel access check.
/// Generic-free mode deliberately avoids undocumented process/thread generic mappings.
pub fn validate_acl(bytes: &[u8], generic_free: bool) -> Result<(), ()> {
    if bytes.len() < 8 || !matches!(bytes[0], 2 | 4) {
        return Err(());
    }
    let size = u16::from_le_bytes([bytes[2], bytes[3]]) as usize;
    let count = u16::from_le_bytes([bytes[4], bytes[5]]);
    if size < 8 || size > bytes.len() || size % 4 != 0 {
        return Err(());
    }
    let mut cursor: usize = 8;
    for _ in 0..count {
        if cursor.checked_add(8).is_none_or(|end| end > size) {
            return Err(());
        }
        let ace_size = u16::from_le_bytes([bytes[cursor + 2], bytes[cursor + 3]]) as usize;
        let end = cursor
            .checked_add(ace_size)
            .filter(|end| ace_size >= 16 && ace_size % 4 == 0 && *end <= size)
            .ok_or(())?;
        if !matches!(bytes[cursor], 0 | 1) {
            return Err(());
        }
        let mask = u32::from_le_bytes(bytes[cursor + 4..cursor + 8].try_into().map_err(|_| ())?);
        if generic_free && mask & 0xf000_0000 != 0 {
            return Err(());
        }
        let sid = cursor + 8;
        let sub_authorities = bytes[sid + 1] as usize;
        if bytes[sid] != 1 || sub_authorities > 15 || sid + 8 + sub_authorities * 4 > end {
            return Err(());
        }
        cursor = end;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One synthetic ordinary ACE; its SID is test data and never emitted.
    fn ordinary(kind: u8, mask: u32) -> Vec<u8> {
        let mut bytes = vec![0; 28];
        bytes[0] = 2;
        bytes[2..4].copy_from_slice(&28_u16.to_le_bytes());
        bytes[4..6].copy_from_slice(&1_u16.to_le_bytes());
        bytes[8] = kind;
        bytes[10..12].copy_from_slice(&20_u16.to_le_bytes());
        bytes[12..16].copy_from_slice(&mask.to_le_bytes());
        bytes[16] = 1;
        bytes[17] = 1;
        bytes
    }

    /// Supported ordinary allow/deny and DWORD-aligned padding remain observable.
    #[test]
    fn ordinary_and_padding_are_supported() {
        for kind in [0, 1] {
            assert!(validate_acl(&ordinary(kind, 0x20008), true).is_ok());
        }
        let mut padded = ordinary(0, 8);
        padded.resize(32, 0);
        padded[2..4].copy_from_slice(&32_u16.to_le_bytes());
        padded[10..12].copy_from_slice(&24_u16.to_le_bytes());
        assert!(validate_acl(&padded, true).is_ok());
        assert!(validate_acl(&[2, 0, 8, 0, 0, 0, 0, 0], true).is_ok());
    }

    /// No guessed generic/object/callback mapping is used for process/thread observations.
    #[test]
    fn generic_and_unknown_aces_are_unavailable() {
        for mask in [0x8000_0000, 0x4000_0000, 0x2000_0000, 0x1000_0000] {
            assert!(validate_acl(&ordinary(0, mask), true).is_err());
            assert!(validate_acl(&ordinary(0, mask), false).is_ok());
        }
        for kind in [2, 5, 6, 9, 10, 255] {
            assert!(validate_acl(&ordinary(kind, 8), true).is_err());
        }
    }

    /// Truncated tables/SIDs and unaligned extents cannot become valid observations.
    #[test]
    fn malformed_bounds_are_unavailable() {
        let fixture = ordinary(0, 8);
        for length in 0..fixture.len() {
            assert!(validate_acl(&fixture[..length], true).is_err());
        }
        for (index, value) in [(0, 0), (2, 29), (4, 2), (10, 21), (16, 0), (17, 16)] {
            let mut malformed = fixture.clone();
            malformed[index] = value;
            assert!(validate_acl(&malformed, true).is_err());
        }
    }
}
