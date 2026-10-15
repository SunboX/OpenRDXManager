// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Installer-only migration of the existing private manufacturing container.
use super::{ancestors, evidence, open};
use crate::NativeError;
use crate::local_trust::storage_parent_policy::{StorageRole, validate_private_storage_acl};
use std::fs::File;
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::AsRawHandle;
use std::path::Path;
use windows::Win32::Foundation::{GENERIC_READ, GENERIC_WRITE, HANDLE};
use windows::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, GetSecurityInfo, SDDL_REVISION_1,
    SE_FILE_OBJECT, SetSecurityInfo,
};
use windows::Win32::Security::{
    DACL_SECURITY_INFORMATION, GROUP_SECURITY_INFORMATION, GetSecurityDescriptorDacl,
    PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID,
};
use windows::Win32::Storage::FileSystem::{
    BY_HANDLE_FILE_INFORMATION, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
    FILE_SHARE_READ, GetFileInformationByHandle, READ_CONTROL, WRITE_DAC,
};
use windows::core::PCWSTR;

/// Pins the fixed data parent; only absent-service bootstrap may invoke this.
pub(in crate::local_trust) fn prepare_storage_parent() -> Result<Vec<File>, NativeError> {
    migrate_parent_at(
        Path::new(r"C:\ProgramData\OpenRDXManager"),
        Path::new(crate::local_trust::LOCAL_RUNTIME_ROOT),
    )
}

/// Migrates one verified private parent without modifying its protected backup leaf.
fn migrate_parent_at(parent: &Path, runtime: &Path) -> Result<Vec<File>, NativeError> {
    let mut pins = ancestors(runtime)?;
    pins.extend(ancestors(parent)?);
    if !parent.try_exists().map_err(|_| NativeError::AccessDenied)? {
        return Ok(pins);
    }
    let reader = open(parent, false)?;
    let before = evidence(&reader)?;
    if super::validate_runtime_acl(&before).is_ok() {
        pins.push(reader);
        return Ok(pins);
    }
    validate_private_storage_acl(&before, StorageRole::Parent)?;
    require_absent(runtime)?;
    require_absent(&parent.join("LocalTrust"))?;
    let generation = identity(&reader)?;
    let parent_group = group(&reader)?;
    drop(reader);

    // Request data-write access as well as WRITE_DAC so existing read-only
    // manufacturing ancestry leases prevent this transition. Never retry with
    // broader sharing or weaker access; this is not a generic ACL repair path.
    let writer = std::fs::OpenOptions::new()
        .access_mode(GENERIC_READ.0 | GENERIC_WRITE.0 | READ_CONTROL.0 | WRITE_DAC.0)
        .share_mode(FILE_SHARE_READ.0)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS.0 | FILE_FLAG_OPEN_REPARSE_POINT.0)
        .open(parent)
        .map_err(|error| {
            if error.raw_os_error() == Some(32) {
                NativeError::Busy
            } else {
                NativeError::AccessDenied
            }
        })?;
    if identity(&writer)? != generation
        || evidence(&writer)? != before
        || group(&writer)? != parent_group
    {
        return Err(NativeError::AccessDenied);
    }
    let backup = open(&parent.join("manufacturing-backups"), false)?;
    let backup_before = evidence(&backup)?;
    validate_private_storage_acl(&backup_before, StorageRole::Backup)?;
    let backup_group = group(&backup)?;
    require_only_backup(parent)?;
    require_absent(runtime)?;
    require_absent(&parent.join("LocalTrust"))?;
    set_parent_policy(&writer)?;

    // The protected leaf blocks propagation of the parent's inheritable ACEs.
    // Its bytes are never opened or rewritten. A later failure retains the
    // canonical parent rather than restoring LocalService's broader rights.
    if identity(&writer)? != generation
        || evidence(&writer)?.owner != before.owner
        || group(&writer)? != parent_group
        || evidence(&backup)? != backup_before
        || group(&backup)? != backup_group
    {
        return Err(NativeError::AccessDenied);
    }
    require_only_backup(parent)?;
    require_absent(runtime)?;
    require_absent(&parent.join("LocalTrust"))?;
    drop(writer);
    let reader = open(parent, false)?;
    if identity(&reader)? != generation {
        return Err(NativeError::AccessDenied);
    }
    super::validate_runtime_acl(&evidence(&reader)?)?;
    pins.extend([reader, backup]);
    Ok(pins)
}

/// Absence must be positively observed; inaccessible paths and reparses are not absent.
fn require_absent(path: &Path) -> Result<(), NativeError> {
    match std::fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        _ => Err(NativeError::AccessDenied),
    }
}

/// No unknown or unprotected child may inherit a changed parent policy.
fn require_only_backup(parent: &Path) -> Result<(), NativeError> {
    let mut entries = std::fs::read_dir(parent).map_err(|_| NativeError::AccessDenied)?;
    let first = entries
        .next()
        .ok_or(NativeError::AccessDenied)?
        .map_err(|_| NativeError::AccessDenied)?;
    if first.file_name() != "manufacturing-backups" || entries.next().is_some() {
        return Err(NativeError::AccessDenied);
    }
    Ok(())
}

/// Identifies the retained inode across the write-to-read lease transition.
fn identity(file: &File) -> Result<(u32, u64), NativeError> {
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    unsafe { GetFileInformationByHandle(HANDLE(file.as_raw_handle()), &mut info) }
        .map_err(|_| NativeError::AccessDenied)?;
    Ok((
        info.dwVolumeSerialNumber,
        (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow),
    ))
}

/// Reads the retained descriptor's group so the migration can prove it unchanged.
fn group(file: &File) -> Result<String, NativeError> {
    let mut descriptor = PSECURITY_DESCRIPTOR::default();
    let mut sid = PSID::default();
    unsafe {
        GetSecurityInfo(
            HANDLE(file.as_raw_handle()),
            SE_FILE_OBJECT,
            GROUP_SECURITY_INFORMATION,
            None,
            Some(&mut sid),
            None,
            None,
            Some(&mut descriptor),
        )
    }
    .ok()
    .map_err(|_| NativeError::AccessDenied)?;
    let _owned = super::Allocation(descriptor.0);
    super::sid_text(sid)
}

/// Changes only this verified parent's DACL; owner, group and children are preserved.
fn set_parent_policy(file: &File) -> Result<(), NativeError> {
    let text: Vec<u16> = super::DIRECTORY_SDDL.encode_utf16().chain([0]).collect();
    let mut descriptor = PSECURITY_DESCRIPTOR::default();
    unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            PCWSTR(text.as_ptr()),
            SDDL_REVISION_1,
            &mut descriptor,
            None,
        )
    }
    .map_err(|_| NativeError::AccessDenied)?;
    let owned = super::Allocation(descriptor.0);
    let mut present = false.into();
    let mut defaulted = false.into();
    let mut dacl = std::ptr::null_mut();
    unsafe {
        GetSecurityDescriptorDacl(
            PSECURITY_DESCRIPTOR(owned.0),
            &mut present,
            &mut dacl,
            &mut defaulted,
        )
    }
    .map_err(|_| NativeError::AccessDenied)?;
    unsafe {
        SetSecurityInfo(
            HANDLE(file.as_raw_handle()),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(dacl),
            None,
        )
    }
    .ok()
    .map_err(|_| NativeError::AccessDenied)?;
    super::validate_runtime_acl(&evidence(file)?)
}

#[cfg(test)]
mod tests {
    use super::super::create_protected_directory;
    use super::*;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};
    static NEXT: AtomicUsize = AtomicUsize::new(0);

    /// Owns only an atomically created disposable Program Files namespace.
    struct Fixture {
        root: PathBuf,
        parent: PathBuf,
        backup: PathBuf,
        runtime: PathBuf,
    }
    impl Fixture {
        /// Seeds exact private directories and bytes without touching installed paths.
        fn new() -> Self {
            let root = Path::new(r"C:\Program Files").join(format!(
                "openrdx-storage-parent-test-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            create_protected_directory(&root).unwrap();
            // Construct cleanup only after owning the new root, before fallible setup.
            let fixture = Self {
                runtime: root.join("absent-runtime"),
                parent: root.join("data"),
                backup: root.join("data/manufacturing-backups"),
                root,
            };
            create_protected_directory(&fixture.parent).unwrap();
            create_protected_directory(&fixture.backup).unwrap();
            std::fs::write(
                fixture.backup.join("retained-backup.bin"),
                b"private manufacturing backup fixture",
            )
            .unwrap();
            set_legacy(&fixture.backup);
            set_legacy(&fixture.parent);
            fixture
        }
    }
    impl Drop for Fixture {
        /// Removes only this test's owned namespace after its retained leases close.
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    /// Creates the observed legacy descriptor only on a disposable fixture directory.
    fn set_legacy(path: &Path) {
        use std::os::windows::ffi::OsStrExt;
        use windows::Win32::Security::Authorization::{
            ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
        };
        use windows::Win32::Security::{
            DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION,
            PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, SetFileSecurityW,
        };
        use windows::core::PCWSTR;
        let text: Vec<u16> = "O:BAD:P(A;;FA;;;SY)(A;;FA;;;LS)(A;;FA;;;BA)"
            .encode_utf16()
            .chain([0])
            .collect();
        let mut descriptor = PSECURITY_DESCRIPTOR::default();
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                PCWSTR(text.as_ptr()),
                SDDL_REVISION_1,
                &mut descriptor,
                None,
            )
        }
        .unwrap();
        let owned = super::super::Allocation(descriptor.0);
        let path: Vec<u16> = path.as_os_str().encode_wide().chain([0]).collect();
        assert!(
            unsafe {
                SetFileSecurityW(
                    PCWSTR(path.as_ptr()),
                    OWNER_SECURITY_INFORMATION
                        | DACL_SECURITY_INFORMATION
                        | PROTECTED_DACL_SECURITY_INFORMATION,
                    PSECURITY_DESCRIPTOR(owned.0),
                )
            }
            .as_bool()
        );
    }

    /// The real NTFS transition preserves the private leaf descriptor and seeded bytes.
    #[test]
    fn migrates_only_parent_and_preserves_private_backup() {
        let f = Fixture::new();
        let before = evidence(&open(&f.backup, false).unwrap()).unwrap();
        let lease =
            migrate_parent_at(&f.parent, &f.runtime).expect("exact legacy container must migrate");
        super::super::validate_runtime_acl(&evidence(&open(&f.parent, false).unwrap()).unwrap())
            .unwrap();
        assert_eq!(evidence(&open(&f.backup, false).unwrap()).unwrap(), before);
        assert_eq!(
            std::fs::read(f.backup.join("retained-backup.bin")).unwrap(),
            b"private manufacturing backup fixture"
        );
        drop(lease);
    }

    /// An active ancestry lease blocks mutation rather than selecting broader sharing.
    #[test]
    fn refuses_active_parent_lease_without_changing_its_descriptor() {
        let f = Fixture::new();
        let held = open(&f.parent, false).unwrap();
        let before = evidence(&held).unwrap();
        assert!(migrate_parent_at(&f.parent, &f.runtime).is_err());
        assert_eq!(evidence(&held).unwrap(), before);
    }

    /// Unknown contents and preexisting trust/runtime state never authorize migration.
    #[test]
    fn refuses_unknown_children_and_existing_trust_or_runtime() {
        for kind in ["unknown", "LocalTrust", "runtime"] {
            let f = Fixture::new();
            let path = if kind == "runtime" {
                f.runtime.clone()
            } else {
                f.parent.join(kind)
            };
            std::fs::create_dir(&path).unwrap();
            assert!(migrate_parent_at(&f.parent, &f.runtime).is_err());
            validate_private_storage_acl(
                &evidence(&open(&f.parent, false).unwrap()).unwrap(),
                StorageRole::Parent,
            )
            .unwrap();
        }
    }
}
