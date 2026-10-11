// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Process-global macOS hardware mutation ownership.

use std::fs::{File, OpenOptions};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::PathBuf;

use crate::NativeError;

const OWNERSHIP_PATH: &str = "/var/run/openrdx-hardware.lock";
const OWNERSHIP_MODE: u32 = 0o600;

/// Immutable installation contract for the macOS ownership file.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HardwareOwnershipContract {
    /// Fixed root-controlled ownership file.
    pub path: &'static str,
    /// Required file owner.
    pub owner_uid: u32,
    /// Required private permission bits.
    pub mode: u32,
    /// Whether acquisition always fails immediately when another owner exists.
    pub nonblocking: bool,
    /// Whether symbolic-link traversal is rejected by the open itself.
    pub reject_symlinks: bool,
}

/// Retained namespace file proving the service initialized the fixed boundary.
#[derive(Debug)]
pub struct HardwareOwnershipNamespace {
    _file: File,
}

/// One process-global exclusive hardware execution lease.
#[derive(Debug)]
pub struct HardwareOwnershipGuard(File);

/// Exact file target and authority expected by the ownership implementation.
struct HardwareOwnershipTarget {
    path: PathBuf,
    owner_uid: u32,
}

impl HardwareOwnershipTarget {
    /// Creates the fixed production target.
    fn production() -> Self {
        Self {
            path: PathBuf::from(OWNERSHIP_PATH),
            owner_uid: 0,
        }
    }

    /// Creates a current-user target only for native lock behavior tests.
    #[cfg(test)]
    fn for_test(path: PathBuf) -> Self {
        // SAFETY: `geteuid` takes no pointers and has no side effects.
        let owner_uid = unsafe { libc::geteuid() };
        Self { path, owner_uid }
    }
}

impl Drop for HardwareOwnershipGuard {
    /// Releases only this owned file-description lock.
    fn drop(&mut self) {
        // SAFETY: the guard owns a live descriptor until this drop completes.
        let _ = unsafe { libc::flock(self.0.as_raw_fd(), libc::LOCK_UN) };
    }
}

/// Returns the immutable macOS process-global ownership contract.
#[must_use]
pub const fn hardware_ownership_contract() -> HardwareOwnershipContract {
    HardwareOwnershipContract {
        path: OWNERSHIP_PATH,
        owner_uid: 0,
        mode: OWNERSHIP_MODE,
        nonblocking: true,
        reject_symlinks: true,
    }
}

/// Creates or validates the root-owned namespace before accepting clients.
///
/// # Errors
///
/// Rejects symlinks, non-regular files, foreign ownership, extra links,
/// broadened permissions, or native open failures.
pub fn initialize_hardware_ownership_namespace() -> Result<HardwareOwnershipNamespace, NativeError>
{
    initialize_hardware_ownership_namespace_at(&HardwareOwnershipTarget::production())
}

/// Acquires the exact namespace without waiting for another process.
///
/// # Errors
///
/// Returns [`NativeError::Busy`] when another service or CLI owns execution,
/// and fails closed for invalid namespace evidence.
pub fn try_acquire_hardware_ownership() -> Result<HardwareOwnershipGuard, NativeError> {
    try_acquire_hardware_ownership_at(&HardwareOwnershipTarget::production())
}

/// Opens and validates one exact ownership file.
fn open_validated(target: &HardwareOwnershipTarget) -> Result<File, NativeError> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(OWNERSHIP_MODE)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(&target.path)
        .map_err(map_open_error)?;
    validate_file(&file, target.owner_uid)?;
    Ok(file)
}

/// Retains one validated namespace file without taking its mutation lock.
fn initialize_hardware_ownership_namespace_at(
    target: &HardwareOwnershipTarget,
) -> Result<HardwareOwnershipNamespace, NativeError> {
    open_validated(target).map(|file| HardwareOwnershipNamespace { _file: file })
}

/// Locks one validated namespace file using the kernel process boundary.
fn try_acquire_hardware_ownership_at(
    target: &HardwareOwnershipTarget,
) -> Result<HardwareOwnershipGuard, NativeError> {
    let file = open_validated(target)?;
    // SAFETY: the file is a validated live regular-file descriptor.
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err(map_lock_error());
    }
    Ok(HardwareOwnershipGuard(file))
}

/// Verifies the already-open inode rather than trusting pathname metadata.
fn validate_file(file: &File, owner_uid: u32) -> Result<(), NativeError> {
    let metadata = file
        .metadata()
        .map_err(|_| NativeError::EvidenceIncomplete)?;
    if !metadata.file_type().is_file()
        || metadata.uid() != owner_uid
        || metadata.nlink() != 1
        || metadata.mode() & 0o7777 != OWNERSHIP_MODE
    {
        return Err(NativeError::EvidenceIncomplete);
    }
    Ok(())
}

/// Maps open failures without retaining paths or operating-system text.
fn map_open_error(error: std::io::Error) -> NativeError {
    match error.raw_os_error() {
        Some(libc::EACCES | libc::EPERM | libc::ELOOP) => NativeError::AccessDenied,
        _ => NativeError::Other,
    }
}

/// Maps one failed nonblocking `flock` without retaining errno text.
fn map_lock_error() -> NativeError {
    match std::io::Error::last_os_error().raw_os_error() {
        Some(libc::EAGAIN) => NativeError::Busy,
        Some(libc::EACCES | libc::EPERM) => NativeError::AccessDenied,
        _ => NativeError::Other,
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::{PermissionsExt, symlink};

    use tempfile::tempdir;

    use super::{
        HardwareOwnershipTarget, hardware_ownership_contract,
        initialize_hardware_ownership_namespace_at, try_acquire_hardware_ownership_at,
    };
    use crate::NativeError;

    /// A second macOS process-equivalent owner must fail without waiting.
    #[test]
    fn exact_lock_serializes_processes_without_waiting() {
        let directory = tempdir().unwrap();
        let target = HardwareOwnershipTarget::for_test(directory.path().join("owner.lock"));
        let namespace = initialize_hardware_ownership_namespace_at(&target).unwrap();
        let first = try_acquire_hardware_ownership_at(&target).unwrap();

        assert!(matches!(
            try_acquire_hardware_ownership_at(&target),
            Err(NativeError::Busy)
        ));

        drop(first);
        assert!(try_acquire_hardware_ownership_at(&target).is_ok());
        drop(namespace);
    }

    /// Symlink substitution never creates an independent ownership domain.
    #[test]
    fn ownership_namespace_rejects_symlinks() {
        let directory = tempdir().unwrap();
        let destination = directory.path().join("destination");
        fs::write(&destination, b"").unwrap();
        let link = directory.path().join("owner.lock");
        symlink(&destination, &link).unwrap();
        let target = HardwareOwnershipTarget::for_test(link);

        assert!(matches!(
            initialize_hardware_ownership_namespace_at(&target),
            Err(NativeError::AccessDenied | NativeError::EvidenceIncomplete)
        ));
    }

    /// Setuid, setgid, and sticky bits invalidate an otherwise private file.
    #[test]
    fn ownership_namespace_rejects_every_special_permission_bit() {
        for special in [0o4000, 0o2000, 0o1000] {
            let directory = tempdir().unwrap();
            let path = directory.path().join("owner.lock");
            fs::write(&path, b"").unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600 | special)).unwrap();
            let target = HardwareOwnershipTarget::for_test(path);

            assert!(matches!(
                initialize_hardware_ownership_namespace_at(&target),
                Err(NativeError::EvidenceIncomplete)
            ));
        }
    }

    /// The installed macOS namespace is fixed, root-owned, and private.
    #[test]
    fn production_contract_is_fixed_and_private() {
        let contract = hardware_ownership_contract();

        assert_eq!(contract.path, "/var/run/openrdx-hardware.lock");
        assert_eq!(contract.owner_uid, 0);
        assert_eq!(contract.mode, 0o600);
        assert!(contract.nonblocking);
        assert!(contract.reject_symlinks);
    }
}
