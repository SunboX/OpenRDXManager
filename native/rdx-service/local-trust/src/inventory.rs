// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

use crate::{TrustError, deny};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// Maximum encoded enrollment bytes, checked before deserialization.
pub const MAX_INVENTORY_BYTES: usize = 1_048_576;
/// Maximum combined file/link entries; paths have a separate byte bound.
pub const MAX_ENTRIES: usize = 20_000;
/// Maximum path or link target length, avoiding pathological traversal work.
const MAX_PATH_BYTES: usize = 4096;

/// Strict inventory v1. Fields are public for native ACL adapters; verification
/// validates them again so constructing a struct cannot bypass the schema.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeInventory {
    /// Must equal one.
    pub schema_version: u32,
    /// Must match the native consumer's platform.
    pub platform: String,
    /// Every regular runtime file, excluding the fixed Windows self-inventory.
    pub files: Vec<RuntimeFile>,
    /// Explicit macOS framework symlinks with pinned literal relative targets.
    pub links: Vec<RuntimeLink>,
    /// Manager CodeDirectory hash (40 lowercase hex on macOS, empty on Windows).
    pub manager_cd_hash: String,
    /// Helper CodeDirectory hash (40 lowercase hex on macOS, empty on Windows).
    pub helper_cd_hash: String,
}

/// A file's complete content identity within the fixed application root.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeFile {
    /// Canonical forward-slash relative path.
    pub path: String,
    /// Exact size in bytes.
    pub size: u64,
    /// Lowercase SHA-256 hexadecimal digest.
    pub sha256: String,
}

/// One approved internal framework link, never an arbitrary runtime redirect.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeLink {
    /// Canonical relative path below Contents/Frameworks in a .framework bundle.
    pub path: String,
    /// Literal bounded relative link target, resolving within the app root.
    pub target: String,
}

/// Parse and validate strict bounded inventory v1 for the native platform.
/// Rejects malformed/unknown/duplicate JSON fields, noncanonical paths,
/// duplicate entry paths, unsupported platforms and escaping framework links.
pub fn parse_inventory(bytes: &[u8], platform: &str) -> Result<RuntimeInventory, TrustError> {
    if bytes.len() > MAX_INVENTORY_BYTES {
        return Err(deny("inventory exceeds byte bound"));
    }
    let inventory: RuntimeInventory =
        serde_json::from_slice(bytes).map_err(|_| deny("invalid inventory schema"))?;
    validate_inventory(&inventory, platform)?;
    Ok(inventory)
}

/// Revalidate public structs so content verification cannot bypass parsing.
pub(crate) fn validate_inventory(
    inventory: &RuntimeInventory,
    platform: &str,
) -> Result<(), TrustError> {
    if inventory.schema_version != 1
        || !matches!(platform, "macos" | "windows")
        || inventory.platform != platform
    {
        return Err(deny("unsupported inventory version or platform"));
    }
    if inventory.files.is_empty()
        || inventory.files.len().saturating_add(inventory.links.len()) > MAX_ENTRIES
    {
        return Err(deny("invalid runtime entry count"));
    }
    let cdhash_valid = if platform == "macos" {
        valid_hex(&inventory.manager_cd_hash, 40) && valid_hex(&inventory.helper_cd_hash, 40)
    } else {
        inventory.manager_cd_hash.is_empty()
            && inventory.helper_cd_hash.is_empty()
            && inventory.links.is_empty()
    };
    if !cdhash_valid {
        return Err(deny("invalid platform code hashes or links"));
    }
    let mut paths = HashSet::new();
    for file in &inventory.files {
        validate_path(&file.path)?;
        if !valid_hex(&file.sha256, 64) || !paths.insert(&file.path) {
            return Err(deny("invalid digest or duplicate runtime path"));
        }
    }
    for link in &inventory.links {
        validate_path(&link.path)?;
        if !paths.insert(&link.path)
            || !link.path.starts_with("Contents/Frameworks/")
            || !link
                .path
                .split('/')
                .any(|component| component.ends_with(".framework"))
        {
            return Err(deny("duplicate or non-framework runtime link"));
        }
        resolve_target(&link.path, &link.target)?;
    }
    // Windows paths are case-insensitive; aliases must not select one file twice.
    if platform == "windows" {
        let mut folded = HashSet::new();
        for path in paths {
            if !folded.insert(path.to_lowercase()) {
                return Err(deny("case-aliased Windows runtime paths"));
            }
        }
    }
    Ok(())
}

/// Check the portable spelling of an inventory path.
pub(crate) fn validate_path(path: &str) -> Result<(), TrustError> {
    if path.is_empty()
        || path.len() > MAX_PATH_BYTES
        || path.contains(['\\', ':', '\0'])
        || path.split('/').any(|component| {
            component.is_empty()
                || component == "."
                || component == ".."
                || component.ends_with([' ', '.'])
        })
    {
        return Err(deny("noncanonical runtime path"));
    }
    Ok(())
}

/// Confine a relative literal symlink target without following the filesystem.
pub(crate) fn resolve_target(path: &str, target: &str) -> Result<String, TrustError> {
    if target.is_empty()
        || target.len() > MAX_PATH_BYTES
        || target.starts_with('/')
        || target.contains(['\\', ':', '\0'])
    {
        return Err(deny("invalid runtime link target"));
    }
    let mut parts: Vec<&str> = path.split('/').collect();
    parts.pop();
    for component in target.split('/') {
        match component {
            "" | "." => return Err(deny("noncanonical runtime link target")),
            ".." => {
                if parts.pop().is_none() {
                    return Err(deny("runtime link escapes root"));
                }
            }
            value => parts.push(value),
        }
    }
    if parts.is_empty() {
        return Err(deny("runtime link resolves to root"));
    }
    Ok(parts.join("/"))
}

/// Accept only canonical lowercase hexadecimal values of the exact length.
fn valid_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
