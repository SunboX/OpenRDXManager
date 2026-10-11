// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Crash-resumable relocation into the single desktop backup store.

use super::super::creation_time;
use super::*;

const FILES: [(&str, usize); 3] = [
    ("manufacturing.bin", 256),
    ("sector.bin", 4096),
    ("manifest.json", MAX_METADATA),
];

/// Opens a record without assuming it has finished changing from service to desktop ownership.
fn open_record(parent: &File, name: &str) -> Result<File, MigrationError> {
    let directory = File::from(
        fs::openat(
            parent,
            name,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(storage_error)?,
    );
    validate_directory(&directory)?;
    Ok(directory)
}

/// Enumerates the bounded fixed record namespace without following any entry.
fn names(parent: &File) -> Result<Vec<String>, MigrationError> {
    let mut names = Vec::new();
    for entry in fs::Dir::read_from(parent).map_err(storage_error)? {
        let entry = entry.map_err(storage_error)?;
        let bytes = entry.file_name().to_bytes();
        if bytes == b"." || bytes == b".." {
            continue;
        }
        names.push(
            std::str::from_utf8(bytes)
                .map_err(storage_error)?
                .to_owned(),
        );
        if names.len() > 4096 {
            return Err(MigrationError::StorageUnavailable);
        }
    }
    names.sort();
    Ok(names)
}

/// Removes only an owned relocation record's closed file set, never arbitrary recursive paths.
fn remove_record(parent: &File, name: &str) -> Result<(), MigrationError> {
    let record = open_record(parent, name)?;
    if record.metadata().map_err(storage_error)?.uid() != rustix::process::geteuid().as_raw() {
        return Err(MigrationError::StorageUnavailable);
    }
    for (file, _) in FILES {
        match fs::unlinkat(&record, file, fs::AtFlags::empty()) {
            Ok(()) | Err(rustix::io::Errno::NOENT) => {}
            Err(error) => return Err(storage_error(error)),
        }
    }
    record.sync_all().map_err(storage_error)?;
    fs::unlinkat(parent, name, fs::AtFlags::REMOVEDIR).map_err(storage_error)?;
    parent.sync_all().map_err(storage_error)
}

/// Completes ownership transfer only while the root-owned record directory still excludes the desktop user.
fn adopt_record(parent: &File, name: &str) -> Result<(), MigrationError> {
    creation_time(name)?;
    let record = open_record(parent, name)?;
    let owner = parent.metadata().map_err(storage_error)?.uid();
    let writer = rustix::process::geteuid().as_raw();
    let record_owner = record.metadata().map_err(storage_error)?.uid();
    if record_owner == owner {
        return Ok(());
    }
    if record_owner != writer {
        return Err(MigrationError::StorageUnavailable);
    }
    for (name, maximum) in FILES {
        let file = match fs::openat(
            &record,
            name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        ) {
            Ok(fd) => File::from(fd),
            Err(rustix::io::Errno::NOENT) => continue,
            Err(error) => return Err(storage_error(error)),
        };
        let info = file.metadata().map_err(storage_error)?;
        if !info.is_file()
            || info.nlink() != 1
            || info.mode() & 0o7777 != 0o600
            || info.len() > maximum as u64
            || (info.uid() != writer && info.uid() != owner)
        {
            return Err(MigrationError::StorageUnavailable);
        }
        inherit_owner(&file, parent)?;
        file.sync_all().map_err(storage_error)?;
    }
    inherit_owner(&record, parent)?;
    record.sync_all().map_err(storage_error)?;
    parent.sync_all().map_err(storage_error)
}

/// Repairs an interrupted move before inventory is admitted; incomplete cross-volume staging is discarded.
pub(super) fn finish_pending(destination: &File) -> Result<(), MigrationError> {
    let owner = destination.metadata().map_err(storage_error)?.uid();
    let parent = ensure_child(destination, "manufacturing-backups", owner)?;
    validate_directory(&parent)?;
    for name in names(&parent)? {
        if let Some(record) = name.strip_prefix("moving-") {
            creation_time(record)?;
            remove_record(&parent, &name)?;
        } else if name.starts_with("record-") {
            adopt_record(&parent, &name)?;
        }
    }
    Ok(())
}

/// Compares all fixed files before removing an identical source left by an interrupted cross-volume move.
fn same_record(source: &File, destination: &File, name: &str) -> Result<bool, MigrationError> {
    let old = open_record(source, name)?;
    let new = open_record(destination, name)?;
    for (file, limit) in FILES {
        if let Some(left) = read_artifact(&old, file, limit)? {
            if Some(left) != read_artifact(&new, file, limit)? {
                return Ok(false);
            }
        }
    }
    Ok(true)
}

/// Preserves even empty interrupted-write evidence while rejecting aliased or unsafe files.
fn read_artifact(
    parent: &File,
    name: &str,
    maximum: usize,
) -> Result<Option<Vec<u8>>, MigrationError> {
    let mut file = match fs::openat(
        parent,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(fd) => File::from(fd),
        Err(rustix::io::Errno::NOENT) => return Ok(None),
        Err(error) => return Err(storage_error(error)),
    };
    let before = file.metadata().map_err(storage_error)?;
    if !before.is_file()
        || before.nlink() != 1
        || before.mode() & 0o7777 != 0o600
        || before.len() > maximum as u64
        || before.uid() != parent.metadata().map_err(storage_error)?.uid()
    {
        return Err(MigrationError::StorageUnavailable);
    }
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(maximum as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(storage_error)?;
    if bytes.len() as u64 != before.len()
        || identity(&before) != identity(&file.metadata().map_err(storage_error)?)
    {
        return Err(MigrationError::StorageUnavailable);
    }
    Ok(Some(bytes))
}

/// Moves original evidence, using verified staging only when source and destination are on different filesystems.
pub(in super::super) fn relocate_from(
    source: &File,
    destination: &File,
) -> Result<(), MigrationError> {
    finish_pending(destination)?;
    let old = match fs::openat(
        source,
        "manufacturing-backups",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(fd) => File::from(fd),
        Err(rustix::io::Errno::NOENT) => return Ok(()),
        Err(error) => return Err(storage_error(error)),
    };
    validate_directory(&old)?;
    if old.metadata().map_err(storage_error)?.uid() != rustix::process::geteuid().as_raw() {
        return Err(MigrationError::StorageUnavailable);
    }
    let new = open_child(destination, "manufacturing-backups")?;
    let unique = names(&old)?
        .into_iter()
        .chain(names(&new)?)
        .filter(|name| name.starts_with("record-"))
        .collect::<std::collections::BTreeSet<_>>();
    if unique.len() > 4096 {
        return Err(MigrationError::StorageUnavailable);
    }
    for name in names(&old)? {
        if !name.starts_with("record-") {
            continue;
        }
        creation_time(&name)?;
        let record = open_child(&old, &name)?;
        for (file, limit) in FILES {
            read_artifact(&record, file, limit)?;
        }
        match fs::renameat_with(&old, &name, &new, &name, fs::RenameFlags::NOREPLACE) {
            Ok(()) => {}
            Err(rustix::io::Errno::EXIST) => {
                if !same_record(&old, &new, &name)? {
                    return Err(MigrationError::StorageUnavailable);
                }
                remove_record(&old, &name)?;
            }
            Err(rustix::io::Errno::XDEV) => {
                let staging = format!("moving-{name}");
                let stage = ensure_child(&new, &staging, rustix::process::geteuid().as_raw())?;
                let record = open_child(&old, &name)?;
                for (file, limit) in FILES {
                    if let Some(bytes) = read_artifact(&record, file, limit)? {
                        write_file(&stage, file, &bytes)?;
                    }
                }
                stage.sync_all().map_err(storage_error)?;
                fs::renameat_with(&new, &staging, &new, &name, fs::RenameFlags::NOREPLACE)
                    .map_err(storage_error)?;
                new.sync_all().map_err(storage_error)?;
                if !same_record(&old, &new, &name)? {
                    return Err(MigrationError::StorageUnavailable);
                }
                remove_record(&old, &name)?;
            }
            Err(error) => return Err(storage_error(error)),
        }
        new.sync_all().map_err(storage_error)?;
        old.sync_all().map_err(storage_error)?;
        adopt_record(&new, &name)?;
    }
    match fs::unlinkat(source, "manufacturing-backups", fs::AtFlags::REMOVEDIR) {
        Ok(()) | Err(rustix::io::Errno::NOTEMPTY) => {}
        Err(error) => return Err(storage_error(error)),
    }
    source.sync_all().map_err(storage_error)
}
