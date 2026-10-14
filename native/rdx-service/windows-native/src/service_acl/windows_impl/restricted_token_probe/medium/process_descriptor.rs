// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Private bounded descriptor components and one exactly scoped ordinary process ACE.
use super::{mandatory_label, object_acl};

/// Canonical components contain private identities and intentionally never implement Debug.
#[derive(Clone, PartialEq)]
pub struct Components {
    control: u16,
    owner: Vec<u8>,
    group: Vec<u8>,
    dacl: Vec<u8>,
    label: Option<Vec<u8>>,
}

/// Compiled object roles select exact public SDK masks; callers cannot supply arbitrary rights.
#[derive(Clone, Copy)]
pub enum ObjectRole {
    Process,
    Thread,
    Token,
}
impl ObjectRole {
    /// Concrete SDK ALL_ACCESS values, checked against platform constants by the native control.
    fn mask(self) -> u32 {
        match self {
            Self::Process | Self::Thread => 0x001f_ffff,
            Self::Token => 0x000f_01ff,
        }
    }
}

/// Validates bounded source-default ACL bytes without interpreting pointer-bearing token headers.
pub fn validate_default_acl(bytes: &[u8]) -> Result<(), ()> {
    object_acl::validate_acl(bytes, false)
}

/// Reads one bounded DWORD, avoiding untrusted pointer dereferences.
fn dword(bytes: &[u8], offset: usize) -> Result<u32, ()> {
    Ok(u32::from_le_bytes(
        bytes
            .get(offset..offset + 4)
            .ok_or(())?
            .try_into()
            .map_err(|_| ())?,
    ))
}

/// Validates a complete SID extent inside initialized input; no identity is emitted.
fn sid(bytes: &[u8]) -> Result<&[u8], ()> {
    if bytes.len() < 8 || bytes[0] != 1 || bytes[1] > 15 {
        return Err(());
    }
    bytes.get(..8 + bytes[1] as usize * 4).ok_or(())
}

/// Bounds a relative offset and returns initialized component bytes only.
fn tail(bytes: &[u8], offset: u32) -> Result<&[u8], ()> {
    if offset < 20 || offset % 4 != 0 {
        return Err(());
    }
    bytes.get(offset as usize..).ok_or(())
}

/// Bounds one DWORD-aligned ACL allocation independently of ACE counts/pointers.
fn acl(bytes: &[u8]) -> Result<&[u8], ()> {
    if bytes.len() < 8 {
        return Err(());
    }
    let length = u16::from_le_bytes([bytes[2], bytes[3]]) as usize;
    if length < 8 || length % 4 != 0 {
        return Err(());
    }
    bytes.get(..length).ok_or(())
}

impl Components {
    /// Parses complete nonoverlapping ordinary DACL and LABEL-only components privately.
    pub fn parse(bytes: &[u8]) -> Result<Self, ()> {
        if !(20..=65_536).contains(&bytes.len()) || bytes[0] != 1 || bytes[1] != 0 {
            return Err(());
        }
        let control = u16::from_le_bytes([bytes[2], bytes[3]]);
        if control & 0x8004 != 0x8004 {
            return Err(());
        }
        let owner_offset = dword(bytes, 4)?;
        let group_offset = dword(bytes, 8)?;
        let label_offset = dword(bytes, 12)?;
        let dacl_offset = dword(bytes, 16)?;
        let owner = sid(tail(bytes, owner_offset)?)?.to_vec();
        let group = sid(tail(bytes, group_offset)?)?.to_vec();
        let dacl = acl(tail(bytes, dacl_offset)?)?.to_vec();
        object_acl::validate_acl(&dacl, true)?;
        let label = if label_offset == 0 {
            None
        } else {
            Some(acl(tail(bytes, label_offset)?)?.to_vec())
        };
        let facts = mandatory_label::parse(bytes).ok_or(())?;
        if !facts.known || (facts.present && (!facts.single || !facts.policy_known)) {
            return Err(());
        }
        let mut ranges = vec![
            (owner_offset as usize, owner.len()),
            (group_offset as usize, group.len()),
            (dacl_offset as usize, dacl.len()),
        ];
        if let Some(label) = &label {
            ranges.push((label_offset as usize, label.len()));
        }
        ranges.sort_unstable_by_key(|range| range.0);
        if ranges
            .windows(2)
            .any(|range| range[0].0 + range[0].1 > range[1].0)
        {
            return Err(());
        }
        Ok(Self {
            control,
            owner,
            group,
            dacl,
            label,
        })
    }

    /// Adds exactly one explicit noninheriting ALLOW ACE, preserving every old byte/denial/order.
    pub fn with_user_process_allow(&self, user: &[u8], mask: u32) -> Result<Self, ()> {
        if mask != ObjectRole::Process.mask() {
            return Err(());
        }
        self.with_user_allow(user, ObjectRole::Process)
    }

    /// Adds one exact verified-user ACE with the compiled object-specific mask only.
    pub fn with_user_allow(&self, user: &[u8], role: ObjectRole) -> Result<Self, ()> {
        let mask = role.mask();
        if sid(user)? != user {
            return Err(());
        }
        let count = u16::from_le_bytes([self.dacl[4], self.dacl[5]]);
        let added_size = 8 + user.len();
        let length = self
            .dacl
            .len()
            .checked_add(added_size)
            .filter(|length| *length <= u16::MAX as usize)
            .ok_or(())?;
        let count = count.checked_add(1).ok_or(())?;
        let mut cursor = 8;
        let mut insertion = None;
        let mut rank = 0;
        for _ in 0..count - 1 {
            let kind = self.dacl[cursor];
            let flags = self.dacl[cursor + 1];
            if flags & !0x1f != 0 {
                return Err(());
            }
            let current = if flags & 0x10 != 0 {
                2
            } else if kind == 1 {
                0
            } else {
                1
            };
            if current < rank {
                return Err(());
            }
            rank = current;
            if current == 2 && insertion.is_none() {
                insertion = Some(cursor);
            }
            cursor += u16::from_le_bytes([self.dacl[cursor + 2], self.dacl[cursor + 3]]) as usize;
        }
        let insertion = insertion.unwrap_or(cursor);
        let mut ace = vec![0_u8; added_size];
        ace[2..4].copy_from_slice(&(added_size as u16).to_le_bytes());
        ace[4..8].copy_from_slice(&mask.to_le_bytes());
        ace[8..].copy_from_slice(user);
        let mut result = self.clone();
        result.dacl.splice(insertion..insertion, ace);
        result.dacl[2..4].copy_from_slice(&(length as u16).to_le_bytes());
        result.dacl[4..6].copy_from_slice(&count.to_le_bytes());
        object_acl::validate_acl(&result.dacl, true)?;
        Ok(result)
    }

    /// Compares owner/group/control/LABEL separately from the intended process DACL change.
    pub fn same_other_components(&self, other: &Self) -> bool {
        self.control == other.control
            && self.owner == other.owner
            && self.group == other.group
            && self.label == other.label
    }

    /// Returns only owner/group/LABEL/control equality, never private component contents.
    pub fn preservation(&self, other: &Self) -> [bool; 4] {
        [
            self.owner == other.owner,
            self.group == other.group,
            self.label == other.label,
            self.control == other.control,
        ]
    }

    /// Serializes validated canonical components into a bounded DWORD-aligned relative descriptor.
    pub fn bytes(&self) -> Result<Vec<u8>, ()> {
        let mut bytes = vec![0; 20];
        bytes[0] = 1;
        bytes[2..4].copy_from_slice(&self.control.to_le_bytes());
        for (slot, part) in [
            (4, Some(&self.owner)),
            (8, Some(&self.group)),
            (12, self.label.as_ref()),
            (16, Some(&self.dacl)),
        ] {
            if let Some(part) = part {
                let offset = bytes.len() as u32;
                bytes[slot..slot + 4].copy_from_slice(&offset.to_le_bytes());
                bytes.extend(part);
            }
        }
        if bytes.len() > 65_536 {
            return Err(());
        }
        Self::parse(&bytes)?;
        Ok(bytes)
    }
}

#[cfg(test)]
mod process_descriptor_tests {
    use super::*;

    /// Synthetic private SID bytes, never actual identities/output.
    fn user(value: u8) -> Vec<u8> {
        vec![1, 1, 0, 0, 0, 0, 0, 5, value, 0, 0, 0]
    }
    /// Synthetic canonical descriptor with a denial followed by allowance and a medium label.
    fn sample() -> Components {
        let mut dacl = vec![2, 0, 48, 0, 2, 0, 0, 0];
        for kind in [1, 0] {
            dacl.extend([kind, 0, 20, 0, 8, 0, 0, 0]);
            dacl.extend(user(9));
        }
        let mut label = vec![2, 0, 28, 0, 1, 0, 0, 0, 0x11, 0, 20, 0, 3, 0, 0, 0];
        label.extend([1, 1, 0, 0, 0, 0, 0, 16, 0, 32, 0, 0]);
        Components {
            control: 0x8014,
            owner: user(7),
            group: user(8),
            dacl,
            label: Some(label),
        }
    }
    /// Exact user/mask/flags and every previous ACE/denial/component remain preserved.
    #[test]
    fn exact_one_user_grant_preserves_original() {
        let baseline = sample();
        let original = baseline.dacl.clone();
        let granted = baseline
            .with_user_process_allow(&user(7), 0x1fffff)
            .unwrap();
        assert!(baseline.dacl == original);
        assert!(granted.dacl[8..48] == original[8..]);
        assert!(granted.dacl[48..56] == [0, 0, 20, 0, 255, 255, 31, 0]);
        assert!(granted.dacl[56..] == user(7));
        assert!(granted.same_other_components(&baseline));
        assert!(Components::parse(&granted.bytes().unwrap()).unwrap() == granted);
    }
    /// A token-object control needs its exact concrete SDK mask, never process rights.
    #[test]
    fn token_user_grant_preserves_original() {
        let baseline = sample();
        for role in [ObjectRole::Process, ObjectRole::Thread, ObjectRole::Token] {
            let granted = baseline.with_user_allow(&user(7), role).unwrap();
            assert!(granted.same_other_components(&baseline));
            assert!(granted.dacl[8..48] == baseline.dacl[8..]);
            assert!(granted.dacl[48] == 0 && granted.dacl[49] == 0);
            assert!(granted.dacl[52..56] == role.mask().to_le_bytes());
            assert!(granted.dacl[56..] == user(7));
            assert!(Components::parse(&granted.bytes().unwrap()).unwrap() == granted);
        }
        assert!(
            baseline
                .with_user_process_allow(&user(7), 0x000f_01ff)
                .is_err()
        );
    }
    /// New grants precede inherited ACEs while retaining every denial/flag/mask byte unchanged.
    #[test]
    fn inherited_ace_bytes_and_invalid_trustees_are_preserved() {
        let mut baseline = sample();
        baseline.dacl[29] = 0x10;
        let original = baseline.dacl.clone();
        for role in [ObjectRole::Process, ObjectRole::Thread, ObjectRole::Token] {
            let granted = baseline.with_user_allow(&user(7), role).unwrap();
            assert!(granted.dacl[8..28] == original[8..28]);
            assert!(granted.dacl[28..32] == [0, 0, 20, 0]);
            assert!(granted.dacl[32..36] == role.mask().to_le_bytes());
            assert!(granted.dacl[36..48] == user(7));
            assert!(granted.dacl[48..68] == original[28..48]);
            for malformed in [
                vec![],
                vec![1, 16, 0, 0, 0, 0, 0, 5],
                [user(7), vec![0]].concat(),
            ] {
                assert!(baseline.with_user_allow(&malformed, role).is_err());
            }
        }
    }
    /// Unsupported/truncated/overlapping/null and nonaligned components never become usable.
    #[test]
    fn malformed_components_fail_closed() {
        let bytes = sample().bytes().unwrap();
        for length in 0..bytes.len() {
            assert!(Components::parse(&bytes[..length]).is_err());
        }
        for (slot, value) in [(4, 0), (4, 21), (8, 20), (16, 0), (12, u32::MAX)] {
            let mut bad = bytes.clone();
            bad[slot..slot + 4].copy_from_slice(&value.to_le_bytes());
            assert!(Components::parse(&bad).is_err());
        }
    }
    /// Changing any preserved component or preexisting ACE is distinguishable in canonical readback.
    #[test]
    fn changed_components_never_compare_equal() {
        let baseline = sample();
        let expected = baseline
            .with_user_process_allow(&user(7), 0x1fffff)
            .unwrap();
        for change in 0..5 {
            let mut bad = expected.clone();
            match change {
                0 => bad.owner[8] ^= 1,
                1 => bad.group[8] ^= 1,
                2 => bad.control ^= 0x1000,
                3 => bad.label.as_mut().unwrap()[12] ^= 1,
                _ => bad.dacl[12] ^= 1,
            }
            assert!(bad != expected);
            if change < 4 {
                assert!(!bad.same_other_components(&baseline));
            }
        }
    }
    /// Unknown/callback/generic ACEs, invalid SID/mask and noncanonical denial order remain unavailable.
    #[test]
    fn unsupported_grants_and_aces_fail_closed() {
        let baseline = sample();
        for mask in [0, 8, 0x10000000, 0xffffffff] {
            assert!(baseline.with_user_process_allow(&user(7), mask).is_err());
        }
        assert!(
            baseline
                .with_user_process_allow(&[1, 16], 0x1fffff)
                .is_err()
        );
        for kind in [5, 9, 255] {
            let mut bad = baseline.bytes().unwrap();
            let offset = dword(&bad, 16).unwrap() as usize;
            bad[offset + 8] = kind;
            assert!(Components::parse(&bad).is_err());
        }
        let mut bad = baseline.clone();
        bad.dacl[8] = 0;
        bad.dacl[28] = 1;
        assert!(bad.with_user_process_allow(&user(7), 0x1fffff).is_err());
    }
}
