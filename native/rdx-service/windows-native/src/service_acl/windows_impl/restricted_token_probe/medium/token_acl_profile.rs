// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Private ACL difference profile; semantic observations never replace byte-exact child admission.
use super::{Components, ObjectRole, object_acl, sid};

/// Cardinalities/header/sequence/padding are booleans only; private ACE/SID/mask bytes never implement Debug.
pub struct Profile {
    pub grants: [[bool; 3]; 3],
    pub comparison: [[bool; 4]; 2],
    pub old_aces: bool,
    pub denials: bool,
    pub one_addition: bool,
    pub preserved: [bool; 4],
}

/// Privately separates used ACEs from allocation padding after complete bounded validation.
struct Parts<'a> {
    header: &'a [u8],
    aces: Vec<&'a [u8]>,
    padding: &'a [u8],
}
/// No unsupported/generic/callback ACE, unaligned extent or unbounded SID is interpreted.
fn parts(bytes: &[u8]) -> Result<Parts<'_>, ()> {
    object_acl::validate_acl(bytes, true)?;
    if bytes.len() != u16::from_le_bytes([bytes[2], bytes[3]]) as usize
        || bytes[1] != 0
        || bytes[6..8] != [0, 0]
    {
        return Err(());
    }
    let count = u16::from_le_bytes([bytes[4], bytes[5]]);
    let mut cursor = 8;
    let mut aces = Vec::new();
    for _ in 0..count {
        let size = u16::from_le_bytes([bytes[cursor + 2], bytes[cursor + 3]]) as usize;
        if bytes[cursor + 1] & !0x1f != 0 {
            return Err(());
        }
        aces.push(&bytes[cursor..cursor + size]);
        cursor += size;
    }
    Ok(Parts {
        header: &bytes[..8],
        aces,
        padding: &bytes[cursor..],
    })
}
/// Exact trustee/type/noninherit/SDK-mask spec, with any valid aligned ACE allocation padding private.
fn grant(ace: &[u8], user: &[u8]) -> bool {
    ace[0] == 0
        && ace[1] == 0
        && u32::from_le_bytes(ace[4..8].try_into().unwrap_or([0; 4])) == ObjectRole::Token.mask()
        && sid(&ace[8..]).is_ok_and(|value| value == user)
}
/// Reports only absent/single/duplicate; no count or principal escapes memory.
fn multiplicity(parts: &Parts<'_>, user: &[u8]) -> [bool; 3] {
    let count = parts.aces.iter().filter(|ace| grant(ace, user)).count();
    [count == 0, count == 1, count > 1]
}
/// Checks byte-identical old ACEs in the same order, independently of additional new ACEs.
fn retained(actual: &[&[u8]], baseline: &[&[u8]]) -> bool {
    let mut cursor = 0;
    for ace in actual {
        if baseline.get(cursor).is_some_and(|old| *old == *ace) {
            cursor += 1;
        }
    }
    cursor == baseline.len()
}
/// Exactly one canonical added ACE is relative to baseline, which can already contain identical grants.
fn one_addition(actual: &Parts<'_>, baseline: &Parts<'_>, user: &[u8]) -> bool {
    if actual.aces.len() != baseline.aces.len() + 1 {
        return false;
    }
    let mut added = vec![0_u8; 8 + user.len()];
    let length = added.len() as u16;
    added[2..4].copy_from_slice(&length.to_le_bytes());
    added[4..8].copy_from_slice(&ObjectRole::Token.mask().to_le_bytes());
    added[8..].copy_from_slice(user);
    actual.aces.iter().enumerate().any(|(index, ace)| {
        *ace == added
            && actual
                .aces
                .iter()
                .enumerate()
                .filter(|(position, _)| *position != index)
                .map(|(_, ace)| *ace)
                .eq(baseline.aces.iter().copied())
    })
}
/// Profiles only ordinary bounded generic-free ACLs for the already verified user and fixed token mask.
pub fn observe(
    actual: &Components,
    baseline: &Components,
    expected: &Components,
    user: &[u8],
) -> Result<Profile, ()> {
    if sid(user)? != user {
        return Err(());
    }
    for descriptor in [actual, baseline, expected] {
        descriptor.bytes()?;
    }
    let (a, b, e) = (
        parts(&actual.dacl)?,
        parts(&baseline.dacl)?,
        parts(&expected.dacl)?,
    );
    let comparison = |other: &Parts<'_>, bytes: &[u8]| {
        [
            actual.dacl == bytes,
            a.aces == other.aces,
            a.header == other.header,
            a.padding == other.padding,
        ]
    };
    Ok(Profile {
        grants: [
            multiplicity(&b, user),
            multiplicity(&e, user),
            multiplicity(&a, user),
        ],
        comparison: [
            comparison(&b, &baseline.dacl),
            comparison(&e, &expected.dacl),
        ],
        old_aces: retained(&a.aces, &b.aces),
        denials: a
            .aces
            .iter()
            .filter(|ace| ace[0] == 1)
            .eq(b.aces.iter().filter(|ace| ace[0] == 1)),
        one_addition: one_addition(&a, &b, user),
        preserved: actual.preservation(baseline),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    /// Synthetic private SID, not an actual principal.
    fn user(value: u8) -> Vec<u8> {
        vec![1, 1, 0, 0, 0, 0, 0, 5, value, 0, 0, 0]
    }
    /// Two old ACEs include a denial and an allowance to another synthetic principal.
    fn baseline() -> Components {
        let mut dacl = vec![2, 0, 48, 0, 2, 0, 0, 0];
        for kind in [1, 0] {
            dacl.extend([kind, 0, 20, 0, 8, 0, 0, 0]);
            dacl.extend(user(9));
        }
        Components {
            control: 0x8004,
            owner: user(7),
            group: user(8),
            dacl,
            label: None,
        }
    }
    /// Missing/single/duplicate observations and exactly one added ACE are relative to baseline cardinality.
    #[test]
    fn multiplicity_and_relative_addition_are_exact() {
        let base = baseline();
        let expected = base.with_user_allow(&user(7), ObjectRole::Token).unwrap();
        let absent = observe(&base, &base, &expected, &user(7)).unwrap();
        assert!(
            absent.grants[0] == [true, false, false] && absent.grants[2] == [true, false, false]
        );
        assert!(!absent.one_addition && absent.comparison[0][0]);
        let single = observe(&expected, &base, &expected, &user(7)).unwrap();
        assert!(
            single.grants[2] == [false, true, false]
                && single.one_addition
                && single.old_aces
                && single.denials
        );
        let duplicate = expected
            .with_user_allow(&user(7), ObjectRole::Token)
            .unwrap();
        let relative = observe(&duplicate, &expected, &duplicate, &user(7)).unwrap();
        assert!(
            relative.grants[0] == [false, true, false]
                && relative.grants[2] == [false, false, true]
                && relative.one_addition
        );
        assert!(
            !observe(&duplicate, &base, &expected, &user(7))
                .unwrap()
                .one_addition
        );
    }
    /// Kernel allocation padding differences remain distinguishable from a matching used ACE sequence.
    #[test]
    fn header_and_padding_do_not_hide_sequence_equality() {
        let base = baseline();
        let expected = base.with_user_allow(&user(7), ObjectRole::Token).unwrap();
        let mut padded = expected.clone();
        padded.dacl.extend([0, 0, 0, 0]);
        let length = padded.dacl.len() as u16;
        padded.dacl[2..4].copy_from_slice(&length.to_le_bytes());
        let profile = observe(&padded, &base, &expected, &user(7)).unwrap();
        assert!(profile.one_addition && profile.comparison[1][1]);
        assert!(
            !profile.comparison[1][0] && !profile.comparison[1][2] && !profile.comparison[1][3]
        );
    }
    /// Old denials and exact byte order stay observable independently of a new matching allowance.
    #[test]
    fn missing_or_reordered_denials_are_distinct() {
        let base = baseline();
        let expected = base.with_user_allow(&user(7), ObjectRole::Token).unwrap();
        let mut changed = expected.clone();
        changed.dacl[12] ^= 1;
        let profile = observe(&changed, &base, &expected, &user(7)).unwrap();
        assert!(!profile.denials && !profile.old_aces && !profile.one_addition);
        let mut reordered = expected.clone();
        let deny = reordered.dacl[8..28].to_vec();
        reordered.dacl.drain(8..28);
        reordered.dacl.extend(deny);
        let profile = observe(&reordered, &base, &expected, &user(7)).unwrap();
        assert!(profile.denials && !profile.old_aces && !profile.one_addition);
    }
    /// Unknown/generic/callback/nonaligned/truncated data or an invalid trustee never yields level facts.
    #[test]
    fn unsupported_profiles_are_unavailable() {
        let base = baseline();
        let expected = base.with_user_allow(&user(7), ObjectRole::Token).unwrap();
        for kind in [5, 9, 255] {
            let mut bad = expected.clone();
            bad.dacl[8] = kind;
            assert!(observe(&bad, &base, &expected, &user(7)).is_err());
        }
        let mut generic = expected.clone();
        generic.dacl[15] |= 0x80;
        assert!(observe(&generic, &base, &expected, &user(7)).is_err());
        let mut unaligned = expected.clone();
        unaligned.dacl[2] += 1;
        assert!(observe(&unaligned, &base, &expected, &user(7)).is_err());
        assert!(observe(&expected, &base, &expected, &[]).is_err());
        for length in 0..expected.dacl.len() {
            let mut bad = expected.clone();
            bad.dacl.truncate(length);
            assert!(observe(&bad, &base, &expected, &user(7)).is_err());
        }
    }
}
