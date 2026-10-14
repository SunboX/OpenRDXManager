// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Bounded pure parser for LABEL-only self-relative security descriptors.
//! No SID, raw integrity value or policy word leaves this parser.

/// Closed observations; invalid input never produces implicit-medium evidence.
#[derive(Default)]
pub struct LabelFacts {
    /// At least one structurally valid mandatory ACE was observed.
    pub present: bool,
    /// Exactly one mandatory ACE was observed.
    pub single: bool,
    /// An effective known level or valid implicit-medium absence was observed.
    pub known: bool,
    /// Successful valid absence supplies the documented implicit-medium level.
    pub implicit_medium: bool,
    /// The effective known level is low.
    pub low: bool,
    /// The effective known level is medium, explicit or validly implicit.
    pub medium: bool,
    /// The effective known level is high.
    pub high: bool,
    /// The effective known level is system.
    pub system: bool,
    /// A single applicable ACE's explicit policy contains only documented bits.
    pub policy_known: bool,
    /// A single applicable ACE explicitly contains the no-write-up bit.
    pub no_write_up: bool,
    /// A single applicable ACE explicitly contains the no-read-up bit.
    pub no_read_up: bool,
    /// A single applicable ACE explicitly contains the no-execute-up bit.
    pub no_execute_up: bool,
}

/// Reads one bounded little-endian DWORD without native pointer dereferences.
fn dword(bytes: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        bytes.get(offset..offset.checked_add(4)?)?.try_into().ok()?,
    ))
}
/// Reads one bounded little-endian WORD without native pointer dereferences.
fn word(bytes: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_le_bytes(
        bytes.get(offset..offset.checked_add(2)?)?.try_into().ok()?,
    ))
}
/// Successful valid absence has the documented implicit-medium semantics only.
fn absent() -> LabelFacts {
    LabelFacts {
        known: true,
        implicit_medium: true,
        medium: true,
        ..Default::default()
    }
}

/// Parses only bounded mandatory-label ACEs; unknown/multiple labels never infer a level.
pub fn parse(bytes: &[u8]) -> Option<LabelFacts> {
    if !(20..=65_536).contains(&bytes.len()) || bytes[0] != 1 || word(bytes, 2)? & 0x8000 == 0 {
        return None;
    }
    let sacl = dword(bytes, 12)? as usize;
    if sacl == 0 {
        return Some(absent());
    }
    if word(bytes, 2)? & 0x10 == 0 || sacl < 20 || sacl % 4 != 0 {
        return None;
    }
    let revision = *bytes.get(sacl)?;
    if !matches!(revision, 2 | 4) {
        return None;
    }
    let size = word(bytes, sacl.checked_add(2)?)? as usize;
    let end = sacl
        .checked_add(size)
        .filter(|end| size >= 8 && size % 4 == 0 && *end <= bytes.len())?;
    let count = word(bytes, sacl.checked_add(4)?)?;
    if count == 0 {
        return Some(absent());
    }
    let mut cursor = sacl + 8;
    let mut observed = None;
    for _ in 0..count {
        let ace_size = word(bytes, cursor.checked_add(2)?)? as usize;
        let ace_end = cursor
            .checked_add(ace_size)
            .filter(|limit| ace_size >= 20 && ace_size % 4 == 0 && *limit <= end)?;
        let ace = bytes.get(cursor..ace_end)?;
        // LABEL-only query must return mandatory ACEs with a complete fixed authority SID.
        if ace[0] != 0x11
            || ace[1] & !0x1f != 0
            || ace[8] != 1
            || ace[9] != 1
            || ace[10..16] != [0, 0, 0, 0, 0, 16]
        {
            return None;
        }
        let level = dword(ace, 16)?;
        let policy = dword(ace, 4)?;
        // Inherit-only labels cannot establish the effective object's level here.
        observed = Some((level, policy, ace[1] & 0x08 == 0));
        cursor = ace_end;
    }
    let mut facts = LabelFacts {
        present: true,
        single: count == 1,
        ..Default::default()
    };
    if count != 1 {
        return Some(facts);
    }
    let (level, policy, applies) = observed?;
    facts.known = applies && matches!(level, 0x1000 | 0x2000 | 0x3000 | 0x4000);
    facts.low = facts.known && level == 0x1000;
    facts.medium = facts.known && level == 0x2000;
    facts.high = facts.known && level == 0x3000;
    facts.system = facts.known && level == 0x4000;
    facts.policy_known = applies && policy & !7 == 0;
    facts.no_write_up = applies && policy & 1 != 0;
    facts.no_read_up = applies && policy & 2 != 0;
    facts.no_execute_up = applies && policy & 4 != 0;
    Some(facts)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds fake LABEL-only bytes; no kernel objects or real identities are used.
    fn descriptor(labels: &[(u32, u32)]) -> Vec<u8> {
        let mut bytes = vec![0_u8; 28 + labels.len() * 20];
        bytes[0] = 1;
        bytes[2..4].copy_from_slice(&0x8010_u16.to_le_bytes());
        bytes[12..16].copy_from_slice(&20_u32.to_le_bytes());
        bytes[20] = 2;
        bytes[22..24].copy_from_slice(&(8 + labels.len() as u16 * 20).to_le_bytes());
        bytes[24..26].copy_from_slice(&(labels.len() as u16).to_le_bytes());
        for (index, (level, policy)) in labels.iter().enumerate() {
            let ace = &mut bytes[28 + index * 20..48 + index * 20];
            ace[0] = 0x11;
            ace[2..4].copy_from_slice(&20_u16.to_le_bytes());
            ace[4..8].copy_from_slice(&policy.to_le_bytes());
            ace[8] = 1;
            ace[9] = 1;
            ace[15] = 16;
            ace[16..20].copy_from_slice(&level.to_le_bytes());
        }
        bytes
    }
    /// Known explicit levels and label-policy bits are independent fixed observations.
    #[test]
    fn exact_known_labels() {
        for level in [0x1000, 0x2000, 0x3000, 0x4000] {
            let facts = parse(&descriptor(&[(level, 7)])).unwrap();
            assert!(facts.present && facts.single && facts.known && !facts.implicit_medium);
            assert!(
                facts.policy_known && facts.no_write_up && facts.no_read_up && facts.no_execute_up
            );
            assert!(facts.medium == (level == 0x2000));
        }
        // DWORD-aligned ACE padding and unused ACL capacity remain valid.
        for ace_size in [20_u16, 24] {
            let mut bytes = descriptor(&[(0x2000, 1)]);
            bytes.resize(52, 0);
            bytes[22..24].copy_from_slice(&32_u16.to_le_bytes());
            bytes[30..32].copy_from_slice(&ace_size.to_le_bytes());
            let facts = parse(&bytes).unwrap();
            assert!(facts.known && facts.medium && facts.single);
        }
    }
    /// Only valid absence produces implicit medium, unlike unsupported/malformed responses.
    #[test]
    fn valid_absence_only() {
        let facts = parse(&descriptor(&[])).unwrap();
        assert!(facts.implicit_medium && facts.medium && facts.known && !facts.present);
        let mut bytes = descriptor(&[]);
        bytes[12..16].fill(0);
        assert!(parse(&bytes).unwrap().implicit_medium);
        assert!(parse(&[]).is_none());
    }
    /// Unknown/multiple/inherit-only labels never select a known integrity level.
    #[test]
    fn ambiguous_labels_stay_unknown() {
        for labels in [vec![(0x2500, 1)], vec![(0x2000, 1), (0x3000, 1)]] {
            let facts = parse(&descriptor(&labels)).unwrap();
            assert!(!facts.known && !facts.implicit_medium && !facts.medium);
        }
        let mut bytes = descriptor(&[(0x2000, 1)]);
        bytes[29] = 8;
        assert!(!parse(&bytes).unwrap().known);
        assert!(!parse(&descriptor(&[(0x2000, 8)])).unwrap().policy_known);
    }
    /// Truncation, offset/count/extent corruption and invalid mandatory SIDs are rejected.
    #[test]
    fn malformed_bounds_are_rejected() {
        let original = descriptor(&[(0x2000, 1)]);
        // A complete buffer cannot make misaligned ACL/ACE extents valid.
        for (acl_size, ace_size) in [(29_u16, 21_u16), (29, 20), (32, 21)] {
            let mut bytes = original.clone();
            bytes.resize(20 + acl_size as usize, 0);
            bytes[22..24].copy_from_slice(&acl_size.to_le_bytes());
            bytes[30..32].copy_from_slice(&ace_size.to_le_bytes());
            assert!(parse(&bytes).is_none());
        }
        for length in 0..original.len() {
            assert!(parse(&original[..length]).is_none());
        }
        for (offset, value) in [
            (0, 0),
            (13, 255),
            (20, 0),
            (22, 255),
            (24, 255),
            (28, 1),
            (30, 255),
            (36, 2),
            (37, 2),
            (43, 15),
        ] {
            let mut bytes = original.clone();
            bytes[offset] = value;
            assert!(parse(&bytes).is_none());
        }
    }
}
