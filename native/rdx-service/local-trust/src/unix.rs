// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

use crate::{
    MAX_INVENTORY_BYTES, RuntimeInventory, TrustError, deny, parse_inventory,
    runtime::{assert_same, reject_hardlink, verify_file_content, verify_tree},
};
use std::{
    ffi::CString,
    fs::{self, File, Metadata},
    io::Read,
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::MetadataExt,
    },
    path::{Component, Path, PathBuf},
};

/// Retained no-follow ancestor handles, anchoring the final protected object.
struct ProtectedPath {
    nodes: Vec<(PathBuf, File, Metadata)>,
}

impl ProtectedPath {
    /// Return the final retained object without reopening its path.
    fn file(&mut self) -> &mut File {
        &mut self.nodes.last_mut().expect("root handle always exists").1
    }

    /// Reject replacements, permission changes and changed ACLs after reads.
    fn recheck(&self) -> Result<(), TrustError> {
        for (path, file, metadata) in &self.nodes {
            assert_same(metadata, &file.metadata()?)?;
            assert_same(metadata, &fs::symlink_metadata(path)?)?;
            check_ancestor_protection(path, file, metadata)?;
        }
        Ok(())
    }
}

/// Verify complete Unix runtime protection and content without a test bypass.
/// Requires absolute no-follow root-owned ancestors (the exact OS /Applications
/// root/admin 0775 ancestor is permitted), no group/other runtime writes or
/// extended allow ACLs, single-link regular files and exact declared content.
/// Native platform callers must supply their fixed production runtime location.
pub fn verify_protected_runtime(
    root: &Path,
    inventory: &RuntimeInventory,
) -> Result<(), TrustError> {
    let path = open_protected(root, true)?;
    verify_tree(root, inventory, true, true)?;
    path.recheck()
}

/// Verify actual tree ownership for an administrator-authorized repair/remove.
/// Ignores regular-file digests, sizes and missing/added regular-file inventory
/// entries; every actual object still requires retained root ownership, mode,
/// ACL and no-follow proof. Links must match the previous strict inventory and
/// be lexically confined inside this tree; pinned dangling links are safe to
/// replace/remove without following them. NEVER use this to authenticate IPC peers,
/// enroll a new generation, or claim runtime integrity; those require content.
pub fn verify_protected_tree_ownership(
    root: &Path,
    previous_inventory: &RuntimeInventory,
) -> Result<(), TrustError> {
    if previous_inventory.platform != "macos" {
        return Err(deny("native macOS ownership inventory required"));
    }
    let path = open_protected(root, true)?;
    verify_tree(root, previous_inventory, true, false)?;
    path.recheck()
}

/// Verify a native installer's fixed setup directory before replacing payloads.
/// Retains protected no-follow ancestors and validates owner, mode and complete
/// ACL policy again. Does not create paths, repair foreign state or enroll trust.
pub fn verify_protected_directory(path: &Path) -> Result<(), TrustError> {
    open_protected(path, true)?.recheck()
}

/// Verify a caller-retained Unix regular file's root owner, single link, mode
/// and complete ACL policy, with metadata checked again after ACL inspection.
/// This does not prove pathname/ancestor protection: callers must independently
/// retain and verify their fixed namespace (for example a hardware/setup lease).
pub fn verify_protected_descriptor(file: &File) -> Result<(), TrustError> {
    let metadata = file
        .metadata()
        .map_err(|error| syscall_error("retained descriptor metadata", error))?;
    if !metadata.is_file() {
        return Err(deny("protected descriptor is not a regular file"));
    }
    reject_hardlink(&metadata)?;
    check_protected(file, &metadata)?;
    let current = file
        .metadata()
        .map_err(|error| syscall_error("retained descriptor metadata recheck", error))?;
    assert_same(&metadata, &current)
}

/// Verify one protected helper outside the app using its enrolled digest/size.
/// No-follow ancestors and the regular single-link file remain retained across
/// hashing and final mutation/ACL checks. Rejects malformed SHA-256 pins.
pub fn verify_protected_file(
    path: &Path,
    expected_sha256: &str,
    expected_size: u64,
) -> Result<(), TrustError> {
    if expected_sha256.len() != 64
        || !expected_sha256
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(deny("invalid protected file digest"));
    }
    let mut protected = open_protected(path, false)?;
    verify_file_content(protected.file(), expected_size, expected_sha256)?;
    protected.recheck()
}

/// Read a protected pending or final macOS inventory during native installation.
/// This establishes file protection/content only; endpoint enrollment must use
/// `verify_enrollment`, which additionally pins the final policy location.
pub fn read_protected_inventory(
    path: &Path,
    platform: &str,
) -> Result<RuntimeInventory, TrustError> {
    if platform != "macos" {
        return Err(deny("native macOS protected inventory required"));
    }
    let mut protected = open_protected(path, false)?;
    if protected.file().metadata()?.len() > MAX_INVENTORY_BYTES as u64 {
        return Err(deny("enrollment exceeds byte bound"));
    }
    let mut bytes = Vec::new();
    protected
        .file()
        .take(MAX_INVENTORY_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    let inventory = parse_inventory(&bytes, platform)?;
    protected.recheck()?;
    Ok(inventory)
}

/// Open root and every ancestor with openat(O_NOFOLLOW), retaining identities.
fn open_protected(path: &Path, directory: bool) -> Result<ProtectedPath, TrustError> {
    if !path.is_absolute() || path.as_os_str().as_encoded_bytes().contains(&0) {
        return Err(deny("protected path must be absolute"));
    }
    let components: Vec<_> = path.components().collect();
    if components
        .iter()
        .any(|component| !matches!(component, Component::RootDir | Component::Normal(_)))
    {
        return Err(deny("noncanonical protected path"));
    }
    let root = crate::runtime::open_nofollow(Path::new("/"), true)?;
    let root_metadata = root.metadata()?;
    check_protected(&root, &root_metadata)?;
    let mut result = ProtectedPath {
        nodes: vec![(PathBuf::from("/"), root, root_metadata)],
    };
    for (index, component) in components.iter().enumerate().skip(1) {
        let Component::Normal(name) = component else {
            return Err(deny("invalid protected path component"));
        };
        let name = CString::new(name.as_encoded_bytes())
            .map_err(|_| deny("invalid protected path name"))?;
        let is_directory = index + 1 != components.len() || directory;
        let flags = libc::O_RDONLY
            | libc::O_CLOEXEC
            | libc::O_NOFOLLOW
            | if is_directory {
                libc::O_DIRECTORY
            } else {
                libc::O_NONBLOCK
            };
        // The parent's retained descriptor forbids pathname ancestor substitution.
        let descriptor = unsafe { libc::openat(result.file().as_raw_fd(), name.as_ptr(), flags) };
        if descriptor < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        // Successful openat transfers ownership of this unique descriptor.
        let file = unsafe { File::from_raw_fd(descriptor) };
        let metadata = file.metadata()?;
        if is_directory && !metadata.is_dir() || !is_directory && !metadata.is_file() {
            return Err(deny("protected object has wrong type"));
        }
        if !is_directory {
            reject_hardlink(&metadata)?;
        }
        let absolute = result
            .nodes
            .last()
            .expect("retained parent exists")
            .0
            .join(std::ffi::OsStr::from_bytes(name.as_bytes()));
        check_ancestor_protection(&absolute, &file, &metadata)?;
        assert_same(&metadata, &fs::symlink_metadata(&absolute)?)?;
        result.nodes.push((absolute, file, metadata));
    }
    Ok(result)
}

/// Reject mutable/foreign ownership and extended grants on the retained object.
pub(crate) fn check_protected(file: &File, metadata: &Metadata) -> Result<(), TrustError> {
    if metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
        return Err(deny("protected object is foreign-owned or writable"));
    }
    check_acl(file)
}

/// Inspect only a retained descriptor's ACL, rejecting extended allow entries.
/// This establishes no owner/mode/type/namespace trust. Native callers must
/// separately validate those properties and retain/recheck the fixed namespace;
/// the installer uses this for its explicitly approved sticky-temp ancestor.
pub fn verify_descriptor_acl(file: &File) -> Result<(), TrustError> {
    check_acl(file)
}

/// Label a captured original IO failure once, without rereading errno, retrying
/// a syscall or including paths/content. The IO display retains its OS code.
fn syscall_error(operation: &'static str, original: std::io::Error) -> TrustError {
    TrustError(format!("{operation}: {original}"))
}

/// Admit only the OS-standard /Applications admin-write ancestor. The admin
/// group is already the installation authority; app objects still require
/// root ownership and no group/other writes. This never admits foreign ACLs.
fn check_ancestor_protection(
    path: &Path,
    file: &File,
    metadata: &Metadata,
) -> Result<(), TrustError> {
    #[cfg(target_os = "macos")]
    if is_trusted_applications_ancestor(path, metadata.uid(), metadata.gid(), metadata.mode()) {
        return check_acl(file);
    }
    #[cfg(not(target_os = "macos"))]
    let _ = path;
    check_protected(file, metadata)
}

/// Match one fixed root/admin macOS system directory, with no ordinary writes.
#[cfg(target_os = "macos")]
fn is_trusted_applications_ancestor(path: &Path, uid: u32, gid: u32, mode: u32) -> bool {
    path == Path::new("/Applications")
        && uid == 0
        && gid == 80
        && mode == (u32::from(libc::S_IFDIR) | 0o775)
}

#[cfg(target_os = "macos")]
unsafe extern "C" {
    fn acl_get_fd_np(fd: libc::c_int, kind: libc::c_int) -> *mut libc::c_void;
    fn acl_get_entry(
        acl: *mut libc::c_void,
        entry_id: libc::c_int,
        entry: *mut *mut libc::c_void,
    ) -> libc::c_int;
    fn acl_get_tag_type(entry: *mut libc::c_void, tag: *mut libc::c_int) -> libc::c_int;
    fn acl_valid(acl: *mut libc::c_void) -> libc::c_int;
    fn acl_free(pointer: *mut libc::c_void) -> libc::c_int;
}

/// Inspect the ACL on the retained descriptor; reject every extended allow ACE.
/// Deny-only macOS ACLs (for example the default /Applications delete deny) are
/// safe to retain. Installers need no allow ACE on a root-owned readable tree.
#[cfg(target_os = "macos")]
fn check_acl(file: &File) -> Result<(), TrustError> {
    // ACL_TYPE_EXTENDED is the documented Darwin ACL type (0x100).
    let acl = unsafe { acl_get_fd_np(file.as_raw_fd(), 0x100) };
    if acl.is_null() {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::ENOENT) {
            return Ok(());
        }
        return Err(syscall_error("acl_get_fd_np", error));
    }
    let result = inspect_acl(acl);
    // acl_get_fd_np returns one allocation owned by this call.
    unsafe { acl_free(acl) };
    result
}

/// Walk Darwin ACL entries, accepting only extended deny tags, bounded at 1,024.
#[cfg(target_os = "macos")]
fn inspect_acl(acl: *mut libc::c_void) -> Result<(), TrustError> {
    if unsafe { acl_valid(acl) } != 0 {
        return Err(deny("invalid filesystem ACL"));
    }
    let mut entry = std::ptr::null_mut();
    let mut selector = 0; // ACL_FIRST_ENTRY; subsequent reads use ACL_NEXT_ENTRY.
    for _ in 0..1024 {
        let result = unsafe { acl_get_entry(acl, selector, &mut entry) };
        if result != 0 {
            let error = std::io::Error::last_os_error();
            // Darwin returns EINVAL past the last entry. The ACL was validated
            // and selectors are fixed here, excluding its other EINVAL causes.
            if error.raw_os_error() == Some(libc::EINVAL) {
                return Ok(());
            }
            return Err(syscall_error("acl_get_entry", error));
        }
        let mut tag = 0;
        if unsafe { acl_get_tag_type(entry, &mut tag) } != 0 {
            let original = std::io::Error::last_os_error();
            return Err(syscall_error("acl_get_tag_type", original));
        }
        if tag != 2 {
            return Err(deny("protected object has an extended allow ACL"));
        }
        selector = -1;
    }
    Err(deny("ACL entry count exceeds bound"))
}

/// Linux extended POSIX ACLs require a native policy adapter; do not approximate.
#[cfg(target_os = "linux")]
fn check_acl(file: &File) -> Result<(), TrustError> {
    let name = c"system.posix_acl_access";
    let size = unsafe { libc::fgetxattr(file.as_raw_fd(), name.as_ptr(), std::ptr::null_mut(), 0) };
    if size >= 0 {
        return Err(deny("protected object has an extended POSIX ACL"));
    }
    let error = std::io::Error::last_os_error();
    if matches!(error.raw_os_error(), Some(libc::ENODATA | libc::ENOTSUP)) {
        return Ok(());
    }
    Err(error.into())
}

/// Fail closed on Unix platforms whose ACL interface has not been implemented.
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn check_acl(_file: &File) -> Result<(), TrustError> {
    Err(deny("native ACL verification unavailable"))
}

use std::os::unix::ffi::OsStrExt;

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::*;

    #[test]
    /// A diagnostic label preserves the captured original failure and OS code.
    fn operation_label_preserves_original_error() {
        let original = std::io::Error::from_raw_os_error(libc::EINVAL);
        let text = original.to_string();
        let error = syscall_error("acl_get_fd_np", original);
        assert_eq!(error.to_string(), format!("acl_get_fd_np: {text}"));
        assert!(error.to_string().contains("os error 22"));
    }

    unsafe extern "C" {
        fn acl_from_text(text: *const libc::c_char) -> *mut libc::c_void;
        fn acl_set_fd(fd: libc::c_int, acl: *mut libc::c_void) -> libc::c_int;
    }

    /// Install a real ACL onto a temporary file owned by the current test user.
    fn set_acl(file: &File, text: &std::ffi::CStr) {
        let acl = unsafe { acl_from_text(text.as_ptr()) };
        assert!(!acl.is_null());
        let result = unsafe { acl_set_fd(file.as_raw_fd(), acl) };
        unsafe { acl_free(acl) };
        assert_eq!(result, 0, "{}", std::io::Error::last_os_error());
    }

    #[test]
    /// ACL grants are tested on actual named files, without ownership bypasses.
    fn empty_acl_and_deny_only_acl_are_safe_but_allow_acl_is_not() {
        let file = tempfile::NamedTempFile::new().unwrap();
        check_acl(file.as_file()).unwrap();
        set_acl(
            file.as_file(),
            c"!#acl 1\nuser:FFFFEEEE-DDDD-CCCC-BBBB-AAAA00000000:root:0:deny:delete\n",
        );
        check_acl(file.as_file()).unwrap();
        set_acl(
            file.as_file(),
            c"!#acl 1\nuser:FFFFEEEE-DDDD-CCCC-BBBB-AAAA00000000:root:0:allow:write\n",
        );
        assert_eq!(
            check_acl(file.as_file()).unwrap_err().to_string(),
            "protected object has an extended allow ACL"
        );
    }

    #[test]
    /// Temporary fixtures cannot weaken the production root ownership gate.
    fn production_protection_does_not_accept_user_owned_temp_files() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("helper");
        fs::write(&path, b"helper").unwrap();
        assert!(
            verify_protected_file(&path, &format!("{:x}", sha2::Sha256::digest(b"helper")), 6)
                .is_err()
        );
    }

    #[test]
    /// Only the documented macOS installation-authority ancestor is exempted.
    fn applications_exception_is_exactly_the_root_admin_system_ancestor() {
        assert!(is_trusted_applications_ancestor(
            Path::new("/Applications"),
            0,
            80,
            0o040775
        ));
        for (path, uid, gid, mode) in [
            ("/Library/Applications", 0, 80, 0o040775),
            ("/Applications/OpenRDXManager.app", 0, 80, 0o040775),
            ("/Applications", 501, 80, 0o040775),
            ("/Applications", 0, 20, 0o040775),
            ("/Applications", 0, 80, 0o040777),
            ("/Applications", 0, 80, 0o0401775),
            ("/Applications", 0, 80, 0o100775),
        ] {
            assert!(!is_trusted_applications_ancestor(
                Path::new(path),
                uid,
                gid,
                mode
            ));
        }
    }

    use sha2::Digest;
}
