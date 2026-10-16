// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Bounded pointer-free policy for preserving object security while adding query rights.

use super::{FixedServiceSid, NativeError, Object};

/// Fixed BUILTIN\\Users identity, S-1-5-32-545; never accepted from external input.
const BUILTIN_USERS: [u8; 16] = [1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 33, 2, 0, 0];

/// Canonical components; security identities and raw ACLs are deliberately not Debug.
#[derive(Clone, PartialEq)]
pub(super) struct Descriptor {
    control: u16,
    owner: Vec<u8>,
    group: Vec<u8>,
    label: Option<Vec<u8>>,
    dacl: Vec<u8>,
}

impl Descriptor {
    /// Plans only the fixed service SID's query right on the current Manager process.
    pub(super) fn with_manager_query_access(
        &self,
        sid: &FixedServiceSid,
    ) -> Result<Self, NativeError> {
        self.with_allow(&sid.0, Object::Process.query_mask(), true)
    }

    /// Parses bounded self-relative security evidence; unsupported encodings fail closed.
    pub(super) fn parse(bytes: &[u8]) -> Result<Self, NativeError> {
        if !(20..=65_536).contains(&bytes.len()) || bytes[0] != 1 || bytes[1] != 0 {
            return Err(NativeError::AccessDenied);
        }
        let control = word(bytes, 2)?;
        if control & 0x8004 != 0x8004 || control & !0xbf3f != 0 {
            return Err(NativeError::AccessDenied);
        }
        let mut ranges = Vec::new();
        let mut component = |slot, is_acl, label| -> Result<Vec<u8>, NativeError> {
            let offset = dword(bytes, slot)? as usize;
            if offset < 20 || offset % 4 != 0 {
                return Err(NativeError::AccessDenied);
            }
            let tail = bytes.get(offset..).ok_or(NativeError::AccessDenied)?;
            let length = if is_acl {
                acl_length(tail)?
            } else {
                sid_length(tail)?
            };
            let part = tail.get(..length).ok_or(NativeError::AccessDenied)?;
            let mut copied = part.to_vec();
            if is_acl {
                let used = validate_acl(part, label)?;
                if !label {
                    // Allocation slack is not security policy. Compare the complete
                    // ACE sequence exactly even if the kernel changes zero capacity.
                    copied.truncate(used);
                    copied[2..4].copy_from_slice(&(used as u16).to_le_bytes());
                }
            }
            ranges.push((offset, offset + length));
            Ok(copied)
        };
        let owner = component(4, false, false)?;
        let group = component(8, false, false)?;
        let label = if dword(bytes, 12)? == 0 {
            None
        } else {
            if control & 0x10 == 0 {
                return Err(NativeError::AccessDenied);
            }
            Some(component(12, true, true)?)
        };
        let dacl = component(16, true, false)?;
        ranges.sort_unstable();
        if ranges.windows(2).any(|pair| pair[0].1 > pair[1].0) {
            return Err(NativeError::AccessDenied);
        }
        Ok(Self {
            control,
            owner,
            group,
            label,
            dacl,
        })
    }

    /// Adds one explicit noninheriting query-only BUILTIN\\Users ACE, preserving prior ACEs.
    pub(super) fn with_query_access(&self, object: Object) -> Result<Self, NativeError> {
        self.with_allow(&BUILTIN_USERS, object.query_mask(), false)
    }

    /// Adds a closed role's compiled grant; reconnects may retain an exact existing ACE.
    fn with_allow(&self, trustee: &[u8], mask: u32, idempotent: bool) -> Result<Self, NativeError> {
        let count = word(&self.dacl, 4)?;
        let mut cursor = 8;
        let mut insertion = None;
        let mut rank = 0;
        let mut exact = false;
        for _ in 0..count {
            let current = if self.dacl[cursor + 1] & 0x10 != 0 {
                2
            } else if self.dacl[cursor] == 1 {
                0
            } else {
                1
            };
            if current < rank {
                return Err(NativeError::AccessDenied);
            }
            rank = current;
            if current == 2 && insertion.is_none() {
                insertion = Some(cursor);
            }
            let size = usize::from(word(&self.dacl, cursor + 2)?);
            exact |= self.dacl[cursor] == 0
                && self.dacl[cursor + 1] == 0
                && dword(&self.dacl, cursor + 4)? == mask
                && self.dacl[cursor + 8..cursor + size] == *trustee;
            cursor += size;
        }
        if idempotent && exact {
            return Ok(self.clone());
        }
        if count >= 128 {
            return Err(NativeError::ResourceLimit);
        }
        let insertion = insertion.unwrap_or(cursor);
        // Keep all old ACE bytes/order, but unused ACL capacity is not an ACE.
        let mut result = self.clone();
        result.dacl.truncate(cursor);
        let mut ace = vec![0, 0];
        ace.extend(((8 + trustee.len()) as u16).to_le_bytes());
        ace.extend(mask.to_le_bytes());
        ace.extend(trustee);
        result.dacl.splice(insertion..insertion, ace);
        let length = u16::try_from(result.dacl.len()).map_err(|_| NativeError::ResourceLimit)?;
        result.dacl[2..4].copy_from_slice(&length.to_le_bytes());
        result.dacl[4..6].copy_from_slice(&(count + 1).to_le_bytes());
        validate_acl(&result.dacl, false)?;
        Ok(result)
    }

    /// Supplies only the validated DACL to the Windows DACL-only setter.
    #[cfg(windows)]
    pub(super) fn dacl(&self) -> &[u8] {
        &self.dacl
    }
}

/// Reads a little-endian WORD only from initialized bounded bytes.
fn word(bytes: &[u8], offset: usize) -> Result<u16, NativeError> {
    Ok(u16::from_le_bytes(
        bytes
            .get(offset..offset + 2)
            .ok_or(NativeError::AccessDenied)?
            .try_into()
            .map_err(|_| NativeError::AccessDenied)?,
    ))
}

/// Reads a little-endian DWORD only from initialized bounded bytes.
fn dword(bytes: &[u8], offset: usize) -> Result<u32, NativeError> {
    Ok(u32::from_le_bytes(
        bytes
            .get(offset..offset + 4)
            .ok_or(NativeError::AccessDenied)?
            .try_into()
            .map_err(|_| NativeError::AccessDenied)?,
    ))
}

/// Validates a complete bounded revision-one SID before any native pointer use.
fn sid_length(bytes: &[u8]) -> Result<usize, NativeError> {
    if bytes.len() < 8 || bytes[0] != 1 || bytes[1] > 15 {
        return Err(NativeError::AccessDenied);
    }
    let length = 8 + usize::from(bytes[1]) * 4;
    bytes.get(..length).ok_or(NativeError::AccessDenied)?;
    Ok(length)
}

/// Bounds a complete DWORD-aligned Windows ACL including its reserved header fields.
fn acl_length(bytes: &[u8]) -> Result<usize, NativeError> {
    if bytes.len() < 8 || !matches!(bytes[0], 2 | 4) || bytes[1] != 0 || word(bytes, 6)? != 0 {
        return Err(NativeError::AccessDenied);
    }
    let length = usize::from(word(bytes, 2)?);
    if length < 8 || length % 4 != 0 || length > bytes.len() {
        return Err(NativeError::AccessDenied);
    }
    Ok(length)
}

/// Accepts bounded ordinary ALLOW/DENY DACLs or mandatory-label-only SACL evidence.
fn validate_acl(bytes: &[u8], label: bool) -> Result<usize, NativeError> {
    let length = acl_length(bytes)?;
    let count = word(bytes, 4)?;
    if count > 128 || (label && count > 1) {
        return Err(NativeError::ResourceLimit);
    }
    let mut cursor = 8;
    for _ in 0..count {
        let size = usize::from(word(bytes, cursor + 2)?);
        let ace = bytes
            .get(cursor..cursor + size)
            .filter(|ace| ace.len() >= 16 && size % 4 == 0 && cursor + size <= length)
            .ok_or(NativeError::AccessDenied)?;
        if ace[1] & !0x1f != 0 || (label && ace[0] != 0x11) || (!label && !matches!(ace[0], 0 | 1))
        {
            return Err(NativeError::AccessDenied);
        }
        let sid = &ace[8..];
        if sid_length(sid)? != sid.len() {
            return Err(NativeError::AccessDenied);
        }
        if label
            && (sid.len() != 12
                || sid[..8] != [1, 1, 0, 0, 0, 0, 0, 16]
                || dword(ace, 4)? & !7 != 0)
        {
            return Err(NativeError::AccessDenied);
        }
        cursor += size;
    }
    // Zeroed unused ACL capacity is harmless; opaque nonzero bytes are unsupported.
    if bytes[cursor..length].iter().any(|byte| *byte != 0) {
        return Err(NativeError::AccessDenied);
    }
    Ok(cursor)
}
