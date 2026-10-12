// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

use crate::{
    MAX_ENTRIES, MAX_INVENTORY_BYTES, RuntimeFile, RuntimeInventory, RuntimeLink, TrustError, deny,
    runtime_handle_requirement, verify_protected_descriptor, verify_protected_directory,
    verify_protected_runtime,
};
use sha2::{Digest, Sha256};
use std::{fs, io::Read, os::unix::fs::MetadataExt, path::Path, sync::Mutex};

/// Fixed signed installation root; no IPC or environment input can select it.
const APP_ROOT: &str = "/Applications/OpenRDXManager.app";
/// Canonical Electron framework payload used by the packaged runtime.
const ELECTRON_FRAMEWORK: &str =
    "Contents/Frameworks/Electron Framework.framework/Versions/A/Electron Framework";

/// Verify protection/content stability and the five actual Electron hardening
/// fuses for the fixed signed macOS installation. Raises only this process's
/// soft descriptor limit within its existing hard limit, never global policy.
/// The caller MUST authenticate Apple code plus the compiled Team requirement,
/// including strict nested-resource seals, before AND after this check. A fresh
/// snapshot supplies no historical enrollment or publisher authority by itself.
/// Local enrollment failure MUST NOT fall back to this separate signed route.
pub fn verify_protected_signed_macos_runtime() -> Result<(), TrustError> {
    let root = Path::new(APP_ROOT);
    let inventory = snapshot(root)?;
    ensure_process_descriptor_budget(runtime_handle_requirement(&inventory)?)?;
    verify_protected_runtime(root, &inventory)?;
    let expected = inventory
        .files
        .iter()
        .find(|file| file.path == ELECTRON_FRAMEWORK)
        .ok_or_else(|| deny("signed runtime is missing canonical Electron framework"))?;
    let path = root.join(ELECTRON_FRAMEWORK);
    let mut file = crate::runtime::open_nofollow(&path, false)?;
    let before = file.metadata()?;
    verify_protected_descriptor(&file)?;
    crate::fuses::verify_electron_fuses(&mut file)?;
    crate::runtime::assert_same(&before, &file.metadata()?)?;
    crate::runtime::assert_same(&before, &fs::symlink_metadata(&path)?)?;
    // Bind the inspected fuse payload back to the complete retained snapshot,
    // rejecting any replacement/change between content and fuse verification.
    crate::unix::verify_protected_file(&path, &expected.sha256, expected.size)
}

/// Snapshot bounded actual root-protected files and pinned framework literals.
/// Each directory's no-follow ancestors and each retained regular descriptor
/// pass production protection before hashing; no fixture ownership bypass exists.
fn snapshot(root: &Path) -> Result<RuntimeInventory, TrustError> {
    verify_protected_directory(root)?;
    let mut inventory = RuntimeInventory {
        schema_version: 1,
        platform: "macos".into(),
        files: Vec::new(),
        links: Vec::new(),
        // Schema placeholders are not authorization pins. Apple/team seal
        // authority is supplied independently by the native caller twice.
        manager_cd_hash: "0".repeat(40),
        helper_cd_hash: "0".repeat(40),
    };
    let mut pending = vec![(root.to_owned(), String::new(), 0_usize)];
    let mut objects = 0_usize;
    let mut budget = 256_usize;
    while let Some((directory, relative, depth)) = pending.pop() {
        if depth > 128 {
            return Err(deny("signed runtime depth exceeds bound"));
        }
        verify_protected_directory(&directory)?;
        for entry in fs::read_dir(&directory)? {
            objects += 1;
            if objects > 100_000 {
                return Err(deny("signed runtime object count exceeds bound"));
            }
            let entry = entry?;
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| deny("non-UTF8 signed runtime name"))?;
            let path = if relative.is_empty() {
                name
            } else {
                format!("{relative}/{name}")
            };
            crate::inventory::validate_path(&path)?;
            let metadata = fs::symlink_metadata(entry.path())?;
            if metadata.file_type().is_symlink() {
                if metadata.uid() != 0 {
                    return Err(deny("signed runtime link is foreign-owned"));
                }
                let target = fs::read_link(entry.path())?
                    .into_os_string()
                    .into_string()
                    .map_err(|_| deny("non-UTF8 signed runtime target"))?;
                crate::inventory::resolve_target(&path, &target)?;
                budget = budget
                    .checked_add(path.len() + target.len() + 64)
                    .ok_or_else(|| deny("signed inventory size overflow"))?;
                inventory.links.push(RuntimeLink { path, target });
            } else if metadata.is_dir() {
                pending.push((entry.path(), path, depth + 1));
            } else if metadata.is_file() {
                budget = budget
                    .checked_add(path.len() + 128)
                    .ok_or_else(|| deny("signed inventory size overflow"))?;
                if budget > MAX_INVENTORY_BYTES {
                    return Err(deny("signed inventory exceeds byte bound"));
                }
                let mut file = crate::runtime::open_nofollow(&entry.path(), false)?;
                crate::runtime::assert_same(&metadata, &file.metadata()?)?;
                verify_protected_descriptor(&file)?;
                let mut hash = Sha256::new();
                let mut bytes = [0_u8; 65536];
                let mut size = 0_u64;
                loop {
                    let count = file.read(&mut bytes)?;
                    if count == 0 {
                        break;
                    }
                    size = size
                        .checked_add(count as u64)
                        .ok_or_else(|| deny("signed runtime size overflow"))?;
                    if size > metadata.len() {
                        return Err(deny("signed runtime grew during snapshot"));
                    }
                    hash.update(&bytes[..count]);
                }
                if size != metadata.len() {
                    return Err(deny("signed runtime size changed"));
                }
                crate::runtime::assert_same(&metadata, &file.metadata()?)?;
                crate::runtime::assert_same(&metadata, &fs::symlink_metadata(entry.path())?)?;
                inventory.files.push(RuntimeFile {
                    path,
                    size,
                    sha256: format!("{:x}", hash.finalize()),
                });
            } else {
                return Err(deny("signed runtime contains unsupported object"));
            }
            if budget > MAX_INVENTORY_BYTES
                || inventory.files.len() + inventory.links.len() > MAX_ENTRIES
            {
                return Err(deny("signed inventory exceeds bound"));
            }
        }
    }
    let encoded =
        serde_json::to_vec(&inventory).map_err(|_| deny("signed inventory encoding failed"))?;
    crate::parse_inventory(&encoded, "macos")
}

/// Raise this process's soft file limit only, serialized and bounded by hard limit.
fn ensure_process_descriptor_budget(required: usize) -> Result<(), TrustError> {
    static LIMIT_LOCK: Mutex<()> = Mutex::new(());
    let _guard = LIMIT_LOCK
        .lock()
        .map_err(|_| deny("descriptor budget lock unavailable"))?;
    let required = libc::rlim_t::try_from(required)
        .map_err(|_| deny("descriptor budget exceeds native limit"))?;
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // getrlimit initializes this owned struct and does not alter system policy.
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) } != 0 || required > limit.rlim_max
    {
        return Err(deny("descriptor budget unavailable"));
    }
    if limit.rlim_cur < required {
        limit.rlim_cur = required;
        // Preserve the existing hard limit; only the calling process changes.
        if unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &limit) } != 0 {
            return Err(deny("process descriptor budget cannot be raised"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    /// A real user-owned app-like tree cannot supply a signed runtime snapshot.
    fn snapshot_rejects_user_owned_runtime() {
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("runtime"), b"foreign").unwrap();
        // Use the real canonical path so /var's system symlink does not mask
        // the production ownership/permission rejection of the temporary tree.
        assert!(snapshot(&root.path().canonicalize().unwrap()).is_err());
    }
}
