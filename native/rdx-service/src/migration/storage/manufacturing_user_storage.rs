// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Descriptor-relative manufacturing storage owned by the authenticated desktop account.
//! Recovery storage retains its separate root-owned helpers and location.

use super::super::*;
#[path = "manufacturing_relocation.rs"]
#[cfg(any(target_os = "macos", test))]
mod relocation;
#[cfg(any(target_os = "macos", test))]
pub(super) use relocation::relocate_from;

/// Moves old service-owned records into the one desktop store; no legacy read fallback remains.
#[cfg(target_os = "macos")]
pub(super) fn move_legacy_backups(destination: &File) -> Result<(), MigrationError> {
    let system = secure_system_parent()?;
    let old = match fs::openat(
        &system,
        "OpenRDXManager",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(fd) => File::from(fd),
        Err(rustix::io::Errno::NOENT) => return relocation::finish_pending(destination),
        Err(error) => return Err(storage_error(error)),
    };
    validate_owned_directory(&old, 0)?;
    relocate_from(&old, destination)
}

/// Resolves only the OS account's fixed application-data directory.
#[cfg(target_os = "macos")]
pub(super) fn desktop_directory(owner: u32) -> Result<File, MigrationError> {
    let home = rdx_macos_native::user_home_directory(owner).map_err(storage_error)?;
    let directory = open_directory(&home, false)?;
    validate_owned_directory(&directory, owner)?;
    let library = ensure_child(&directory, "Library", owner)?;
    let support = ensure_child(&library, "Application Support", owner)?;
    ensure_child(&support, "OpenRDXManager", owner)
}

/// Requires owner-private content directories, independent of the elevated writer's UID.
pub(super) fn validate_directory(directory: &File) -> Result<(), MigrationError> {
    let info = directory.metadata().map_err(storage_error)?;
    if !info.is_dir() || info.mode() & 0o7777 != 0o700 {
        return Err(MigrationError::StorageUnavailable);
    }
    Ok(())
}

/// Assigns only a newly created descriptor to the already validated parent owner.
pub(super) fn inherit_owner(file: &File, parent: &File) -> Result<(), MigrationError> {
    let owner = parent.metadata().map_err(storage_error)?.uid();
    if file.metadata().map_err(storage_error)?.uid() != owner {
        fs::fchown(file, Some(rustix::process::Uid::from_raw(owner)), None)
            .map_err(storage_error)?;
    }
    Ok(())
}

/// Creates a private child without following symlinks or rewriting existing permissions.
pub(super) fn ensure_child(parent: &File, name: &str, owner: u32) -> Result<File, MigrationError> {
    let created = match fs::mkdirat(parent, name, PRIVATE_DIRECTORY) {
        Ok(()) => true,
        Err(rustix::io::Errno::EXIST) => false,
        Err(error) => return Err(storage_error(error)),
    };
    let child = File::from(
        fs::openat(
            parent,
            name,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(storage_error)?,
    );
    // mkdir and ownership transfer cannot be atomic. Only an empty private
    // root-owned child can be an interrupted creation; existing data is never adopted here.
    let interrupted = !created
        && rustix::process::geteuid().is_root()
        && owner != 0
        && child.metadata().map_err(storage_error)?.uid() == 0
        && child.metadata().map_err(storage_error)?.mode() & 0o7777 == 0o700
        && directory_is_empty(&child)?;
    if created || interrupted {
        if child.metadata().map_err(storage_error)?.uid() != owner {
            fs::fchown(&child, Some(rustix::process::Uid::from_raw(owner)), None)
                .map_err(storage_error)?;
        }
        fs::fchmod(&child, PRIVATE_DIRECTORY).map_err(storage_error)?;
    }
    validate_owned_directory(&child, owner)?;
    child.sync_all().map_err(storage_error)?;
    parent.sync_all().map_err(storage_error)?;
    Ok(child)
}

/// Reopens a private child under its exact parent's ownership.
pub(super) fn open_child(parent: &File, name: &str) -> Result<File, MigrationError> {
    let child = File::from(
        fs::openat(
            parent,
            name,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(storage_error)?,
    );
    validate_directory(&child)?;
    if child.metadata().map_err(storage_error)?.uid()
        != parent.metadata().map_err(storage_error)?.uid()
    {
        return Err(MigrationError::StorageUnavailable);
    }
    Ok(child)
}

/// Validates bounded private files against the containing record's ownership.
fn file_metadata(file: &File, parent: &File, maximum: usize) -> Result<Metadata, MigrationError> {
    let info = file.metadata().map_err(storage_error)?;
    if !info.is_file()
        || info.nlink() != 1
        || info.len() == 0
        || info.len() > maximum as u64
        || info.mode() & 0o7777 != 0o600
        || info.uid() != parent.metadata().map_err(storage_error)?.uid()
    {
        return Err(MigrationError::StorageUnavailable);
    }
    Ok(info)
}

/// Reads a fixed file through anchored descriptors and rejects changes during readback.
pub(super) fn read_file(
    parent: &File,
    name: &str,
    maximum: usize,
) -> Result<Vec<u8>, MigrationError> {
    let mut file = File::from(
        fs::openat(
            parent,
            name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(storage_error)?,
    );
    let before = file_metadata(&file, parent, maximum)?;
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(maximum as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(storage_error)?;
    let after = file_metadata(&file, parent, maximum)?;
    if identity(&before) != identity(&after) || bytes.len() as u64 != before.len() {
        return Err(MigrationError::StorageUnavailable);
    }
    Ok(bytes)
}

/// Creates an exclusive private file owned by the desktop user, then durably flushes it.
pub(super) fn write_file(parent: &File, name: &str, bytes: &[u8]) -> Result<(), MigrationError> {
    let mut file = File::from(
        fs::openat(
            parent,
            name,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            PRIVATE_FILE,
        )
        .map_err(storage_error)?,
    );
    inherit_owner(&file, parent)?;
    fs::fchmod(&file, PRIVATE_FILE).map_err(storage_error)?;
    file.write_all(bytes).map_err(storage_error)?;
    file.sync_all().map_err(storage_error)
}

/// Detects an empty anchored directory without treating read errors as permission to adopt it.
fn directory_is_empty(directory: &File) -> Result<bool, MigrationError> {
    for entry in fs::Dir::read_from(directory).map_err(storage_error)? {
        let entry = entry.map_err(storage_error)?;
        if ![b".".as_slice(), b"..".as_slice()].contains(&entry.file_name().to_bytes()) {
            return Ok(false);
        }
    }
    Ok(true)
}
