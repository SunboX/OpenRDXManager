// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later
//! Retained proof of the administrator-approved package's fixed sibling manifest.

use rdx_local_trust::{MAX_INVENTORY_BYTES, RuntimeInventory, parse_inventory};
use sha2::{Digest, Sha256};
use std::{
    ffi::{CString, OsStr},
    fs::{self, File, Metadata},
    io::Read,
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{ffi::OsStrExt, fs::MetadataExt},
    },
    path::{Component, Path, PathBuf},
};

/// One no-follow source component retained until both sibling files are checked.
struct SourceNode {
    path: PathBuf,
    file: File,
    original: Metadata,
    immediate: bool,
}

/// Read ONLY pending-runtime.json beside the current package setup executable.
/// Every ancestor is root-owned/no-write/ACL protected; only /private/tmp may be
/// exactly root:wheel01777 and cannot be the immediate source directory. Sticky
/// semantics prevent ordinary users deleting/replacing its root-owned child.
/// This historical record NEVER becomes runtime.json or authenticates an IPC peer.
pub(super) fn read_package_record() -> Result<Vec<u8>, String> {
    let executable = std::env::current_exe().map_err(|error| error.to_string())?;
    if executable.file_name() != Some(OsStr::new("openrdx-local-install")) {
        return Err("package setup executable has an unexpected fixed filename".into());
    }
    let parent = executable
        .parent()
        .ok_or("package setup has no source directory")?;
    let mut nodes = retain_source_directories(parent)?;
    let directory = &nodes.last().ok_or("package source is unavailable")?.file;
    let mut manifest = open_child(directory, "pending-runtime.json")?;
    let manifest_metadata = manifest.metadata().map_err(|error| error.to_string())?;
    if manifest_metadata.len() > MAX_INVENTORY_BYTES as u64 {
        return Err("package inventory exceeds its bound".into());
    }
    let mut bytes = Vec::new();
    (&mut manifest)
        .take(MAX_INVENTORY_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    let inventory = parse_inventory(&bytes, "macos").map_err(|error| error.to_string())?;
    verify_setup_pin(directory, &inventory, parent)?;
    recheck_file(
        &manifest,
        &manifest_metadata,
        &parent.join("pending-runtime.json"),
    )?;
    for node in &mut nodes {
        recheck_directory(node)?;
    }
    Ok(bytes)
}

/// Retain root and each source ancestor using openat(O_NOFOLLOW), rejecting aliases.
fn retain_source_directories(path: &Path) -> Result<Vec<SourceNode>, String> {
    if !path.is_absolute() {
        return Err("package source must be absolute".into());
    }
    let components: Vec<_> = path.components().collect();
    if components
        .iter()
        .any(|component| !matches!(component, Component::RootDir | Component::Normal(_)))
    {
        return Err("package source is not canonical".into());
    }
    let root = unsafe {
        libc::open(
            c"/".as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if root < 0 {
        return Err("cannot retain package source root".into());
    }
    let root = unsafe { File::from_raw_fd(root) };
    let original = root.metadata().map_err(|error| error.to_string())?;
    let mut nodes = vec![SourceNode {
        path: PathBuf::from("/"),
        file: root,
        original,
        immediate: components.len() == 1,
    }];
    recheck_directory(&nodes[0])?;
    for (index, component) in components.iter().enumerate().skip(1) {
        let Component::Normal(name) = component else {
            return Err("invalid source component".into());
        };
        let name = CString::new(name.as_bytes()).map_err(|_| "invalid package source name")?;
        let previous = nodes.last().expect("root source handle exists");
        let descriptor = unsafe {
            libc::openat(
                previous.file.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if descriptor < 0 {
            return Err("package source ancestor is unavailable or a link".into());
        }
        let file = unsafe { File::from_raw_fd(descriptor) };
        let original = file.metadata().map_err(|error| error.to_string())?;
        let node = SourceNode {
            path: previous.path.join(OsStr::from_bytes(name.as_bytes())),
            file,
            original,
            immediate: index + 1 == components.len(),
        };
        recheck_directory(&node)?;
        nodes.push(node);
    }
    Ok(nodes)
}

/// Validate permissions/ACLs and retained directory identities, including the temp exception.
fn recheck_directory(node: &SourceNode) -> Result<(), String> {
    let held = node.file.metadata().map_err(|error| error.to_string())?;
    let named = fs::symlink_metadata(&node.path).map_err(|error| error.to_string())?;
    for metadata in [&node.original, &held, &named] {
        if !openrdx_macos_local_install::package_directory_allowed(
            &node.path,
            metadata.uid(),
            metadata.gid(),
            metadata.mode(),
            node.immediate,
        ) {
            return Err(format!(
                "package source directory is foreign, writable or an alias: {} (uid={}, gid={}, mode={:#o}, immediate={})",
                node.path.display(),
                metadata.uid(),
                metadata.gid(),
                metadata.mode(),
                node.immediate
            ));
        }
        if metadata.dev() != node.original.dev()
            || metadata.ino() != node.original.ino()
            || metadata.uid() != node.original.uid()
            || metadata.gid() != node.original.gid()
            || metadata.mode() != node.original.mode()
        {
            return Err("package source directory was replaced".into());
        }
    }
    rdx_local_trust::verify_descriptor_acl(&node.file).map_err(|error| error.to_string())
}

/// Open one fixed sibling as a root-protected regular single-link file, without following links.
fn open_child(directory: &File, name: &str) -> Result<File, String> {
    let name = CString::new(name).map_err(|_| "invalid fixed sibling name")?;
    let descriptor = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
        )
    };
    if descriptor < 0 {
        return Err("package manifest/setup sibling is unavailable or a link".into());
    }
    let file = unsafe { File::from_raw_fd(descriptor) };
    rdx_local_trust::verify_protected_descriptor(&file).map_err(|error| error.to_string())?;
    Ok(file)
}

/// Bind the sidecar's generation to the exact package setup executable being run.
fn verify_setup_pin(
    directory: &File,
    inventory: &RuntimeInventory,
    parent: &Path,
) -> Result<(), String> {
    let pin = inventory
        .files
        .iter()
        .find(|file| file.path == "Contents/Resources/native/macos/openrdx-local-install")
        .ok_or("package inventory does not pin its installer setup executable")?;
    let mut file = open_child(directory, "openrdx-local-install")?;
    let metadata = file.metadata().map_err(|error| error.to_string())?;
    if metadata.len() != pin.size {
        return Err("package setup executable size does not match inventory".into());
    }
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 65536];
    loop {
        let count = file.read(&mut buffer).map_err(|error| error.to_string())?;
        if count == 0 {
            break;
        }
        digest.update(&buffer[..count]);
    }
    if format!("{:x}", digest.finalize()) != pin.sha256 {
        return Err("package setup executable does not match approved generation".into());
    }
    recheck_file(&file, &metadata, &parent.join("openrdx-local-install"))
}

/// Reject manifest replacement or content mutation after bounded parsing and pin verification.
fn recheck_file(file: &File, original: &Metadata, path: &Path) -> Result<(), String> {
    rdx_local_trust::verify_protected_descriptor(file).map_err(|error| error.to_string())?;
    for metadata in [
        file.metadata().map_err(|error| error.to_string())?,
        fs::symlink_metadata(path).map_err(|error| error.to_string())?,
    ] {
        if metadata.dev() != original.dev()
            || metadata.ino() != original.ino()
            || metadata.len() != original.len()
            || metadata.mtime() != original.mtime()
            || metadata.mtime_nsec() != original.mtime_nsec()
            || metadata.ctime() != original.ctime()
            || metadata.ctime_nsec() != original.ctime_nsec()
        {
            return Err("package manifest changed during verification".into());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Actual root system source directories retain their native no-follow/ACL proof.
    #[test]
    fn source_retains_existing_root_installer_namespace() {
        let path = Path::new("/Library/InstallerSandboxes");
        if path.exists() {
            assert!(retain_source_directories(path).is_ok());
        }
    }

    /// A writable/foreign temporary source is refused even below the sticky exception.
    #[test]
    fn source_refuses_actual_foreign_temporary_directory() {
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        let directory = tempfile::tempdir_in("/private/tmp").unwrap();
        let error = retain_source_directories(directory.path()).err().unwrap();
        assert!(error.contains(&directory.path().display().to_string()));
        assert!(error.contains("uid="));
        assert!(error.contains("gid="));
        assert!(error.contains("mode="));
    }

    /// Fixed sibling symlinks are rejected by openat itself before reading any target.
    #[test]
    fn source_refuses_actual_sibling_symlink() {
        use std::os::unix::fs::symlink;
        let directory = tempfile::tempdir().unwrap();
        fs::write(directory.path().join("foreign.json"), b"{}").unwrap();
        symlink(
            "foreign.json",
            directory.path().join("pending-runtime.json"),
        )
        .unwrap();
        let parent = File::open(directory.path()).unwrap();
        let error = open_child(&parent, "pending-runtime.json").unwrap_err();
        assert!(error.contains("unavailable or a link"));
    }
}
