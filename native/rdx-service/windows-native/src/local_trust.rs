// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Fixed administrator enrollment and complete Windows runtime ACL policy.
use crate::NativeError;

#[cfg(any(windows, test))]
mod storage_parent_policy;

/// The sole locally enrolled runtime root; portable copies cannot select policy.
#[cfg(windows)]
pub const LOCAL_RUNTIME_ROOT: &str = r"C:\Program Files\OpenRDXManager";
/// Protected administrator-owned enrollment; never selected by environment or IPC.
#[cfg(windows)]
pub const LOCAL_ENROLLMENT_ROOT: &str = r"C:\ProgramData\OpenRDXManager\LocalTrust";
/// Exact installed native service path.
#[cfg(windows)]
pub const LOCAL_SERVICE_BINARY: &str =
    r"C:\Program Files\OpenRDXManager\resources\native\windows\openrdx-hardware.exe";

/// One completely decoded standard access-control entry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeAce {
    /// Canonical kernel-derived SID text.
    pub sid: String,
    /// Exact concrete access mask.
    pub mask: u32,
    /// Exact ACE inheritance/control flags.
    pub flags: u8,
    /// Whether this standard ACE grants access.
    pub allowed: bool,
}
/// Retained object metadata and entire owner/DACL evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeAclEvidence {
    /// Canonical object owner SID.
    pub owner: String,
    /// Whether inheritance is protected.
    pub protected: bool,
    /// Whether the retained object is any reparse point.
    pub reparse: bool,
    /// Whether the retained object is a directory.
    pub directory: bool,
    /// Number of hard links reported by the retained handle.
    pub links: u32,
    /// Every DACL ACE in canonical order.
    pub entries: Vec<RuntimeAce>,
}
/// Validates every runtime ACE rather than accepting a broad read-only assertion.
///
/// # Errors
/// Rejects foreign ownership, inherited/noncanonical permissions, links and reparses.
pub fn validate_runtime_acl(evidence: &RuntimeAclEvidence) -> Result<(), NativeError> {
    if !matches!(evidence.owner.as_str(), "S-1-5-32-544" | "S-1-5-18")
        || !evidence.protected
        || evidence.reparse
        || (!evidence.directory && evidence.links != 1)
        || evidence.entries.len() != 4
    {
        return Err(NativeError::AccessDenied);
    }
    let flags = if evidence.directory { 3 } else { 0 };
    for (ace, (sid, mask)) in evidence.entries.iter().zip([
        ("S-1-5-18", 0x001f01ff),
        ("S-1-5-32-544", 0x001f01ff),
        ("S-1-5-19", 0x001200a9),
        ("S-1-5-32-545", 0x001200a9),
    ]) {
        if !ace.allowed || ace.sid != sid || ace.mask != mask || ace.flags != flags {
            return Err(NativeError::AccessDenied);
        }
    }
    Ok(())
}

/// Validates the exact read-only inherited policy left by interrupted NSIS extraction.
/// This evidence is usable only by elevated repair after protected history proof.
/// Runtime IPC always requires `validate_runtime_acl` instead.
///
/// # Errors
/// Rejects foreign owners, writes, extra ACEs, reparses and hardlinks.
pub fn validate_interrupted_runtime_acl(evidence: &RuntimeAclEvidence) -> Result<(), NativeError> {
    if evidence.protected {
        return validate_runtime_acl(evidence);
    }
    let expected = if evidence.directory { 19 } else { 16 };
    let mut normalized = evidence.clone();
    for ace in &mut normalized.entries {
        if ace.flags != expected {
            return Err(NativeError::AccessDenied);
        }
        ace.flags &= !16;
    }
    normalized.protected = true;
    validate_runtime_acl(&normalized)
}

#[cfg(windows)]
pub(crate) mod bootstrap;

mod client_ffi;
pub use client_ffi::{
    openrdx_local_trust_close, openrdx_local_trust_open, openrdx_local_trust_service_sid,
};

#[cfg(windows)]
pub(crate) mod windows;
#[cfg(windows)]
pub(crate) use windows::{
    commit_enrollment, prepare_runtime, remove_enrollment, verify_owned_runtime_lease,
    verify_packaged_runtime_lease, verify_runtime_lease,
};

/// Verifies the complete fixed enrollment and runtime with retained native handles.
///
/// # Errors
/// Missing, foreign, writable, malformed, copied or changed runtime fails closed.
pub fn verify_installed_local_trust() -> Result<(), NativeError> {
    #[cfg(windows)]
    {
        let _lease = windows::verify_runtime_lease()?;
        Ok(())
    }
    #[cfg(not(windows))]
    {
        Err(NativeError::UnsupportedPlatform)
    }
}
