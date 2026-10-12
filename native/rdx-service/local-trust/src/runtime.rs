// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

use crate::{
    RuntimeInventory, TrustError, deny,
    inventory::{resolve_target, validate_inventory},
};
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, HashSet},
    fs::{self, File, Metadata, OpenOptions},
    io::Read,
    path::{Path, PathBuf},
};

/// A retained filesystem identity checked again after all content is hashed.
struct Retained {
    path: PathBuf,
    metadata: Metadata,
    handle: Option<File>,
}

/// Verify exact content with no trust in file owners or directory permissions.
/// This fixture-friendly layer rejects unlisted inputs, wrong sizes/digests,
/// hardlinks on Unix and undeclared links. Native Windows callers must retain
/// their no-reparse, owner/DACL and single-link protection handles throughout.
pub fn verify_runtime(root: &Path, inventory: &RuntimeInventory) -> Result<(), TrustError> {
    verify_tree(root, inventory, false, true)
}

/// Estimate retained handles from declared files/links and unique parent directories,
/// plus 128 descriptors reserved for the caller, protected ancestors and setup
/// artifacts. Unix verification preflights the current process soft limit;
/// installers may raise only their own process limit before calling verification.
/// This inventory-only estimate omits empty directories; Unix installed callers
/// must use `protected_runtime_handle_requirement` before raising their limit.
/// Actual retained capacity remains bounded during full verification.
pub fn runtime_handle_requirement(inventory: &RuntimeInventory) -> Result<usize, TrustError> {
    validate_inventory(inventory, &inventory.platform)?;
    let mut directories = HashSet::new();
    for path in inventory
        .files
        .iter()
        .map(|file| file.path.as_str())
        .chain(inventory.links.iter().map(|link| link.path.as_str()))
    {
        let mut parent = path;
        let mut depth = 0;
        while let Some((ancestor, _)) = parent.rsplit_once('/') {
            directories.insert(ancestor);
            parent = ancestor;
            depth += 1;
            if depth > 128 {
                return Err(deny("runtime directory depth exceeds bound"));
            }
        }
    }
    Ok(inventory.files.len() + inventory.links.len() + directories.len() + 129)
}

/// Read the process soft descriptor limit without changing any process/system policy.
fn handle_capacity() -> Result<usize, TrustError> {
    #[cfg(unix)]
    {
        let mut limit = std::mem::MaybeUninit::<libc::rlimit>::uninit();
        // getrlimit initializes this struct on success and has no policy side effect.
        if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, limit.as_mut_ptr()) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        let limit = unsafe { limit.assume_init() };
        Ok(usize::try_from(limit.rlim_cur).unwrap_or(usize::MAX))
    }
    #[cfg(not(unix))]
    {
        Ok(usize::MAX)
    }
}

/// Walk and retain the complete runtime, optionally applying Unix protection.
pub(crate) fn verify_tree(
    root: &Path,
    inventory: &RuntimeInventory,
    protected: bool,
    content: bool,
) -> Result<(), TrustError> {
    validate_inventory(inventory, &inventory.platform)?;
    let capacity = handle_capacity()?;
    if runtime_handle_requirement(inventory)? > capacity {
        return Err(deny(
            "process file-handle limit insufficient for runtime verification",
        ));
    }
    let root_metadata = fs::symlink_metadata(root)?;
    if !root_metadata.is_dir() || root_metadata.file_type().is_symlink() {
        return Err(deny("runtime root is not a regular directory"));
    }
    let root_handle = open_nofollow(root, true)?;
    assert_same(&root_metadata, &root_handle.metadata()?)?;
    check_protection(&root_handle, &root_metadata, protected)?;
    let mut retained = vec![Retained {
        path: root.to_owned(),
        metadata: root_metadata,
        handle: Some(root_handle),
    }];
    let files: HashMap<&str, _> = inventory
        .files
        .iter()
        .map(|file| (file.path.as_str(), file))
        .collect();
    let links: HashMap<&str, _> = inventory
        .links
        .iter()
        .map(|link| (link.path.as_str(), link))
        .collect();
    let mut seen = HashSet::new();
    let mut directories = HashSet::new();
    let mut pending = vec![(root.to_owned(), String::new(), 0_usize)];
    while let Some((directory, relative, depth)) = pending.pop() {
        if depth > 128 {
            return Err(deny("runtime directory depth exceeds bound"));
        }
        for entry in fs::read_dir(&directory)? {
            if retained.len().saturating_add(129) > capacity {
                return Err(deny(
                    "process file-handle limit insufficient for runtime verification",
                ));
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
            reject_reparse(&metadata)?;
            if metadata.file_type().is_symlink() {
                let expected = links
                    .get(path.as_str())
                    .ok_or_else(|| deny("unlisted runtime symlink"))?;
                let target = fs::read_link(&absolute)?;
                if target.to_str() != Some(expected.target.as_str()) {
                    return Err(deny("runtime link target mismatch"));
                }
                #[cfg(unix)]
                if protected && std::os::unix::fs::MetadataExt::uid(&metadata) != 0 {
                    return Err(deny("runtime link is not root-owned"));
                }
                retained.push(Retained {
                    path: absolute,
                    metadata,
                    handle: None,
                });
                seen.insert(path);
            } else if metadata.is_dir() {
                let handle = open_nofollow(&absolute, true)?;
                assert_same(&metadata, &handle.metadata()?)?;
                check_protection(&handle, &metadata, protected)?;
                directories.insert(path.clone());
                pending.push((absolute.clone(), path, depth + 1));
                retained.push(Retained {
                    path: absolute,
                    metadata,
                    handle: Some(handle),
                });
            } else if metadata.is_file() {
                reject_hardlink(&metadata)?;
                let mut handle = open_nofollow(&absolute, false)?;
                assert_same(&metadata, &handle.metadata()?)?;
                check_protection(&handle, &metadata, protected)?;
                if content {
                    if let Some(expected) = files.get(path.as_str()) {
                        verify_file_content(&mut handle, expected.size, &expected.sha256)?;
                    } else if !windows_installer_file(&path, inventory) {
                        return Err(deny("unlisted runtime file"));
                    }
                }
                retained.push(Retained {
                    path: absolute,
                    metadata,
                    handle: Some(handle),
                });
                seen.insert(path);
            } else {
                return Err(deny("runtime contains a non-regular object"));
            }
            if retained.len() > 100_000 {
                return Err(deny("runtime object count exceeds bound"));
            }
        }
    }
    if content
        && (inventory
            .files
            .iter()
            .any(|file| !seen.contains(&file.path))
            || inventory
                .links
                .iter()
                .any(|link| !seen.contains(&link.path)))
    {
        return Err(deny("runtime inventory entry missing"));
    }
    for link in &inventory.links {
        // Ownership-only repair/removal never follows links; an exact pinned
        // root-confined literal remains safe to remove if its target is absent.
        if !content {
            continue;
        }
        let mut resolved = resolve_target(&link.path, &link.target)?;
        let mut visited = HashSet::new();
        // Resolve every path component through declared links only, including
        // framework Versions/Current aliases embedded in another link target.
        for _ in 0..64 {
            if !visited.insert(resolved.clone()) {
                return Err(deny("runtime link cycle"));
            }
            let components: Vec<_> = resolved.split('/').collect();
            let mut replacement = None;
            for count in 1..=components.len() {
                let prefix = components[..count].join("/");
                if let Some(alias) = links.get(prefix.as_str()) {
                    if !seen.contains(&prefix) {
                        return Err(deny("runtime link resolves through absent alias"));
                    }
                    let target = resolve_target(&prefix, &alias.target)?;
                    replacement = Some(if count == components.len() {
                        target
                    } else {
                        format!("{target}/{}", components[count..].join("/"))
                    });
                    break;
                }
            }
            if let Some(target) = replacement {
                resolved = target;
                continue;
            }
            if !files.contains_key(resolved.as_str()) && !directories.contains(&resolved) {
                return Err(deny("runtime link target is not inventoried content"));
            }
            break;
        }
        if visited.len() == 64 {
            return Err(deny("runtime link resolution exceeds bound"));
        }
    }
    for object in &retained {
        assert_same(&object.metadata, &fs::symlink_metadata(&object.path)?)?;
        if let Some(handle) = &object.handle {
            assert_same(&object.metadata, &handle.metadata()?)?;
            check_protection(handle, &object.metadata, protected)?;
        }
    }
    Ok(())
}

/// Permit only fixed NSIS administration artifacts outside app execution.
fn windows_installer_file(path: &str, inventory: &RuntimeInventory) -> bool {
    inventory.platform == "windows"
        && matches!(
            path,
            "resources/local-trust/runtime.json"
                | "Uninstall OpenRDXManager.exe"
                | "uninstallerIcon.ico"
        )
}

/// Hash a retained regular file, checking exact length before and after reading.
pub(crate) fn verify_file_content(
    file: &mut File,
    size: u64,
    expected: &str,
) -> Result<(), TrustError> {
    if file.metadata()?.len() != size {
        return Err(deny("runtime file size mismatch"));
    }
    let mut digest = Sha256::new();
    let mut bytes = 0_u64;
    let mut buffer = [0_u8; 65536];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        bytes = bytes
            .checked_add(count as u64)
            .ok_or_else(|| deny("runtime file size overflow"))?;
        if bytes > size {
            return Err(deny("runtime file grew during verification"));
        }
        digest.update(&buffer[..count]);
    }
    if bytes != size || format!("{:x}", digest.finalize()) != expected {
        return Err(deny("runtime file digest mismatch"));
    }
    Ok(())
}

/// Open one no-follow object; complete ancestor protection is a separate gate.
pub(crate) fn open_nofollow(path: &Path, directory: bool) -> Result<File, TrustError> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(
            libc::O_CLOEXEC
                | libc::O_NOFOLLOW
                | if directory {
                    libc::O_DIRECTORY
                } else {
                    libc::O_NONBLOCK
                },
        );
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.custom_flags(0x00200000 | if directory { 0x02000000 } else { 0 });
    }
    Ok(options.open(path)?)
}

/// Compare retained object identity and mutation-sensitive metadata.
pub(crate) fn assert_same(before: &Metadata, after: &Metadata) -> Result<(), TrustError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if (
            before.dev(),
            before.ino(),
            before.mode(),
            before.uid(),
            before.gid(),
            before.nlink(),
            before.len(),
            before.mtime(),
            before.mtime_nsec(),
            before.ctime(),
            before.ctime_nsec(),
        ) != (
            after.dev(),
            after.ino(),
            after.mode(),
            after.uid(),
            after.gid(),
            after.nlink(),
            after.len(),
            after.mtime(),
            after.mtime_nsec(),
            after.ctime(),
            after.ctime_nsec(),
        ) {
            return Err(deny("filesystem identity changed during verification"));
        }
    }
    #[cfg(not(unix))]
    if before.len() != after.len()
        || before.modified().ok() != after.modified().ok()
        || before.file_type() != after.file_type()
    {
        return Err(deny("filesystem metadata changed during verification"));
    }
    Ok(())
}

/// Reject multiple directory names for a regular Unix file.
pub(crate) fn reject_hardlink(metadata: &Metadata) -> Result<(), TrustError> {
    #[cfg(unix)]
    if std::os::unix::fs::MetadataExt::nlink(metadata) != 1 {
        return Err(deny("runtime file is hard-linked"));
    }
    #[cfg(not(unix))]
    let _ = metadata;
    Ok(())
}

/// Refuse every Windows reparse object, even one not exposed as a symlink.
fn reject_reparse(metadata: &Metadata) -> Result<(), TrustError> {
    #[cfg(windows)]
    if std::os::windows::fs::MetadataExt::file_attributes(metadata) & 0x400 != 0 {
        return Err(deny("runtime contains a reparse point"));
    }
    #[cfg(not(windows))]
    let _ = metadata;
    Ok(())
}

/// Apply production ownership/ACL rules without weakening fixture verification.
fn check_protection(handle: &File, metadata: &Metadata, protected: bool) -> Result<(), TrustError> {
    #[cfg(unix)]
    if protected {
        crate::unix::check_protected(handle, metadata)?;
    }
    #[cfg(not(unix))]
    let _ = (handle, metadata, protected);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    /// Repair's ownership traversal may ignore hashes while authentication cannot.
    fn ownership_traversal_does_not_relax_content_authentication() {
        let root = tempfile::tempdir().unwrap();
        fs::write(root.path().join("app"), b"tampered").unwrap();
        fs::write(
            root.path().join("new-root-owned-in-production-file"),
            b"new payload",
        )
        .unwrap();
        let inventory = crate::parse_inventory(&serde_json::to_vec(&serde_json::json!({"schemaVersion":1,"platform":"macos","files":[{"path":"app","size":6,"sha256":format!("{:x}",Sha256::digest(b"sealed"))}],"links":[],"managerCdHash":"a".repeat(40),"helperCdHash":"b".repeat(40)})).unwrap(),"macos").unwrap();
        // Fixture content-only mode avoids weakening the production owner gate:
        // the public ownership API always enables protected verification.
        verify_tree(root.path(), &inventory, false, false).unwrap();
        assert!(verify_runtime(root.path(), &inventory).is_err());
    }

    #[cfg(unix)]
    #[test]
    /// A dangling pinned link can be removed safely but cannot authorize a runtime.
    fn ownership_traversal_can_remove_dangling_pinned_links() {
        let root = tempfile::tempdir().unwrap();
        fs::write(root.path().join("app"), b"sealed").unwrap();
        let framework = "Contents/Frameworks/Test.framework";
        fs::create_dir_all(root.path().join(framework)).unwrap();
        std::os::unix::fs::symlink("Absent", root.path().join(framework).join("Current")).unwrap();
        let inventory = crate::parse_inventory(&serde_json::to_vec(&serde_json::json!({"schemaVersion":1,"platform":"macos","files":[{"path":"app","size":6,"sha256":format!("{:x}",Sha256::digest(b"sealed"))}],"links":[{"path":format!("{framework}/Current"),"target":"Absent"}],"managerCdHash":"a".repeat(40),"helperCdHash":"b".repeat(40)})).unwrap(),"macos").unwrap();
        verify_tree(root.path(), &inventory, false, false).unwrap();
        assert!(verify_runtime(root.path(), &inventory).is_err());
    }
}
