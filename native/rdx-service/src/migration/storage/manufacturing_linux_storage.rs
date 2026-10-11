// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Fixed root-owned Linux backup store; no desktop or renderer path is accepted.

use super::super::*;
use super::user_storage;

/// Opens validated root-owned system ancestry and prepares the private service store.
pub(super) fn service_directory() -> Result<File, MigrationError> {
    if !rustix::process::geteuid().is_root() {
        return Err(MigrationError::StorageUnavailable);
    }
    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let mut parent = File::from(fs::open("/", flags, Mode::empty()).map_err(storage_error)?);
    validate_owned_directory(&parent, 0)?;
    for name in ["var", "lib"] {
        parent =
            File::from(fs::openat(&parent, name, flags, Mode::empty()).map_err(storage_error)?);
        validate_owned_directory(&parent, 0)?;
    }
    directory_under(&parent, 0)
}

/// Creates only the fixed private child without adopting unsafe existing storage.
fn directory_under(parent: &File, owner: u32) -> Result<File, MigrationError> {
    validate_owned_directory(parent, owner)?;
    let directory = user_storage::ensure_child(parent, "OpenRDXManager", owner)?;
    user_storage::validate_directory(&directory)?;
    Ok(directory)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};

    /// The fixed Linux child supports complete private persistence and independent load.
    #[test]
    fn linux_backup_store_persists_and_independently_reopens_original_bytes() {
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let parent = open_directory(&root.path().canonicalize().unwrap(), true).unwrap();
        let owner = rustix::process::geteuid().as_raw();
        let directory = directory_under(&parent, owner).unwrap();
        let id = crate::model::DeviceId::new("rdx:linux-storage-fixture").unwrap();
        let bytes = [0x37; 256];
        super::super::persist_parent(&directory, &id, &bytes, None).unwrap();
        let inventory = super::super::inventory_parent(&directory, &id).unwrap();
        assert_eq!(inventory.len(), 1);
        let loaded = super::super::read_backup(&directory, &inventory[0].backup_id).unwrap();
        assert_eq!(loaded.bytes.as_ref(), &bytes);
        assert_eq!(loaded.summary.device_id, id);
        for path in [
            root.path().join("OpenRDXManager"),
            root.path().join("OpenRDXManager/manufacturing-backups"),
        ] {
            let metadata = path.metadata().unwrap();
            assert_eq!(metadata.uid(), owner);
            assert_eq!(metadata.mode() & 0o7777, 0o700);
        }
    }

    /// Existing writable ancestry, public children, symlinks and files fail without repair.
    #[test]
    fn linux_backup_store_rejects_unsafe_existing_paths_without_repair() {
        for variant in 0..4 {
            let root = tempfile::tempdir().unwrap();
            let child = root.path().join("OpenRDXManager");
            match variant {
                0 => std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o777))
                    .unwrap(),
                1 => {
                    std::fs::create_dir(&child).unwrap();
                    std::fs::set_permissions(&child, std::fs::Permissions::from_mode(0o755))
                        .unwrap();
                }
                2 => symlink(root.path(), &child).unwrap(),
                _ => std::fs::write(&child, b"retained evidence").unwrap(),
            }
            let parent = File::open(root.path()).unwrap();
            assert!(directory_under(&parent, rustix::process::geteuid().as_raw()).is_err());
            if variant == 1 {
                assert_eq!(child.metadata().unwrap().mode() & 0o7777, 0o755);
            }
            if variant == 3 {
                assert_eq!(std::fs::read(child).unwrap(), b"retained evidence");
            }
        }
    }

    /// Production Linux storage cannot create any fixed directories for an unprivileged process.
    #[test]
    fn linux_backup_store_requires_privileged_process_authority() {
        if !rustix::process::geteuid().is_root() {
            assert!(service_directory().is_err());
        }
    }
}
