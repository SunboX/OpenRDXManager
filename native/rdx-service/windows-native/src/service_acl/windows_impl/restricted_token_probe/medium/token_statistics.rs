// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Query-only exact SDK statistics; never token rights changes, instance-origin claims or numeric output.
use super::*;
#[path = "token_identity.rs"]
mod token_identity;
use token_identity::{Identity, comparison, layout};
use windows::Win32::Security::{TOKEN_STATISTICS, TokenStatistics};

/// Separates bounded API-reader success, exact structure validity and privately copied metadata.
#[derive(Clone, Copy)]
pub(super) struct Statistics {
    pub(super) query_ok: bool,
    pub(super) layout_valid: bool,
    identity: Option<Identity>,
}
impl Statistics {
    /// Copies only initialized fixed fields after exact compiled SDK size and alignment checks.
    pub(super) fn read(token: &OwnedHandle) -> Self {
        let buffer = TokenBuffer::read(token, TokenStatistics);
        let mut result = Self {
            query_ok: buffer.is_ok(),
            layout_valid: false,
            identity: None,
        };
        let Ok(buffer) = buffer else {
            return result;
        };
        if !layout(
            buffer.length,
            buffer.storage.as_ptr() as usize,
            size_of::<TOKEN_STATISTICS>(),
            std::mem::align_of::<TOKEN_STATISTICS>(),
        ) {
            return result;
        }
        let Ok(stats) = buffer.header::<TOKEN_STATISTICS>() else {
            return result;
        };
        // TokenId identifies this token object instance; AuthenticationId is shared by a logon session.
        // ModifiedId may change even when temporarily enabled privileges are later restored.
        // https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-token_statistics
        let ids = [stats.TokenId, stats.AuthenticationId, stats.ModifiedId]
            .map(|id| [id.LowPart, id.HighPart as u32]);
        result.layout_valid = true;
        result.identity = Some(Identity::copied(ids));
        result
    }
    /// Returns known/token/logon/modified equality only; no API provenance or ownership follows from equality.
    pub(super) fn compare(self, other: Self) -> [bool; 4] {
        comparison(self.identity, other.identity)
    }
}
