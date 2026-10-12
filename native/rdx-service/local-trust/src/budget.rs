// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

use crate::{
    RuntimeInventory, TrustError, deny,
    inventory::validate_inventory,
    runtime::{assert_same, open_nofollow, reject_hardlink},
    unix::{check_protected, verify_protected_directory},
};
use std::{
    collections::{HashMap, HashSet},
    fs,
    os::unix::fs::MetadataExt,
    path::Path,
};

/// Count every actual protected runtime object, including empty directories,
/// plus 128 process descriptors of headroom. Traversal validates no-follow
/// ancestors, root ownership, modes, ACLs, regular single-link files and pinned
/// literal links, with metadata rechecked around each directory and retained
/// file inspection. Uses a bounded number of temporary descriptors so it works
/// before the caller raises its own process soft limit. Establishes a budget
/// only: callers MUST still run full retained content verification afterward,
/// which rejects any intervening tree or content change. Never alters limits.
pub fn protected_runtime_handle_requirement(
    root: &Path,
    inventory: &RuntimeInventory,
) -> Result<usize, TrustError> {
    count_runtime_handles(root, inventory, true)
}

/// Bounded sequential protection traversal; content-only mode is used by fixtures.
fn count_runtime_handles(
    root: &Path,
    inventory: &RuntimeInventory,
    protected: bool,
) -> Result<usize, TrustError> {
    validate_inventory(inventory, &inventory.platform)?;
    if protected {
        verify_protected_directory(root)?;
    }
    let root_handle = open_nofollow(root, true)?;
    let root_metadata = root_handle.metadata()?;
    assert_same(&root_metadata, &fs::symlink_metadata(root)?)?;
    let files: HashSet<_> = inventory
        .files
        .iter()
        .map(|entry| entry.path.as_str())
        .collect();
    let links: HashMap<_, _> = inventory
        .links
        .iter()
        .map(|entry| (entry.path.as_str(), entry.target.as_str()))
        .collect();
    let mut seen = HashSet::new();
    let mut objects = 1_usize;
    let mut pending = vec![(root.to_owned(), String::new(), 0_usize)];
    while let Some((directory, relative, depth)) = pending.pop() {
        if depth > 128 {
            return Err(deny("runtime directory depth exceeds bound"));
        }
        if protected {
            verify_protected_directory(&directory)?;
        }
        let directory_handle = open_nofollow(&directory, true)?;
        let directory_metadata = directory_handle.metadata()?;
        assert_same(&directory_metadata, &fs::symlink_metadata(&directory)?)?;
        if protected {
            check_protected(&directory_handle, &directory_metadata)?;
        }
        for entry in fs::read_dir(&directory)? {
            objects += 1;
            if objects > 100_000 {
                return Err(deny("runtime object count exceeds bound"));
            }
            let entry = entry?;
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| deny("non-UTF8 runtime name"))?;
            let path = if relative.is_empty() {
                name
            } else {
                format!("{relative}/{name}")
            };
            crate::inventory::validate_path(&path)?;
            let absolute = root.join(&path);
            let metadata = fs::symlink_metadata(&absolute)?;
            if metadata.file_type().is_symlink() {
                let target = links
                    .get(path.as_str())
                    .ok_or_else(|| deny("unlisted runtime symlink"))?;
                if fs::read_link(&absolute)?.to_str() != Some(*target)
                    || protected && metadata.uid() != 0
                {
                    return Err(deny("runtime link target or owner mismatch"));
                }
                assert_same(&metadata, &fs::symlink_metadata(&absolute)?)?;
                seen.insert(path);
            } else if metadata.is_dir() {
                let handle = open_nofollow(&absolute, true)?;
                assert_same(&metadata, &handle.metadata()?)?;
                if protected {
                    check_protected(&handle, &metadata)?;
                }
                assert_same(&metadata, &fs::symlink_metadata(&absolute)?)?;
                pending.push((absolute, path, depth + 1));
            } else if metadata.is_file() {
                if !files.contains(path.as_str()) {
                    return Err(deny("unlisted runtime file"));
                }
                reject_hardlink(&metadata)?;
                let handle = open_nofollow(&absolute, false)?;
                assert_same(&metadata, &handle.metadata()?)?;
                if protected {
                    check_protected(&handle, &metadata)?;
                }
                assert_same(&metadata, &handle.metadata()?)?;
                assert_same(&metadata, &fs::symlink_metadata(&absolute)?)?;
                seen.insert(path);
            } else {
                return Err(deny("runtime contains a non-regular object"));
            }
        }
        assert_same(&directory_metadata, &directory_handle.metadata()?)?;
        assert_same(&directory_metadata, &fs::symlink_metadata(&directory)?)?;
        if protected {
            verify_protected_directory(&directory)?;
        }
    }
    if inventory
        .files
        .iter()
        .any(|entry| !seen.contains(&entry.path))
        || inventory
            .links
            .iter()
            .any(|entry| !seen.contains(&entry.path))
    {
        return Err(deny("runtime inventory entry missing"));
    }
    assert_same(&root_metadata, &root_handle.metadata()?)?;
    assert_same(&root_metadata, &fs::symlink_metadata(root)?)?;
    Ok(objects + 128)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    /// Empty directories require retained handles even without inventory records.
    fn actual_budget_includes_empty_directories() {
        let root = tempfile::tempdir().unwrap();
        fs::write(root.path().join("app"), b"sealed").unwrap();
        let inventory = crate::parse_inventory(&serde_json::to_vec(&serde_json::json!({"schemaVersion":1,"platform":"macos","files":[{"path":"app","size":6,"sha256":format!("{:x}",sha2::Sha256::digest(b"sealed"))}],"links":[],"managerCdHash":"a".repeat(40),"helperCdHash":"b".repeat(40)})).unwrap(),"macos").unwrap();
        let initial = count_runtime_handles(root.path(), &inventory, false).unwrap();
        fs::create_dir_all(root.path().join("empty/another")).unwrap();
        let actual = count_runtime_handles(root.path(), &inventory, false).unwrap();
        assert_eq!(actual, initial + 2);
        assert_eq!(
            actual,
            crate::runtime_handle_requirement(&inventory).unwrap() + 2
        );
        assert!(protected_runtime_handle_requirement(root.path(), &inventory).is_err());
    }

    use sha2::Digest;
}
