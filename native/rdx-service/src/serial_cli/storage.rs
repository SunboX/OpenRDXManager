// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Private durable evidence with descriptor-relative, no-symlink, no-overwrite I/O.

#[cfg(unix)]
use rustix::fs::{Mode, OFlags, mkdirat, open, openat};
use std::fs::File;
use std::io::{Read, Write};
#[cfg(unix)]
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path};

use super::{
    Result,
    plan::Plan,
    record::{Sector, sector_from_bytes},
};

/// Retains the exact private directory inode throughout validation and application.
pub(super) struct Evidence {
    directory: File,
}

/// Opens each absolute directory component independently without traversing a symlink.
#[cfg(unix)]
fn directory(path: &Path) -> Result<File> {
    if !path.is_absolute() {
        return Err("serial-path-must-be-absolute");
    }
    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let mut owner =
        File::from(open("/", flags, Mode::empty()).map_err(|_| "serial-private-path-unavailable")?);
    for component in path.components() {
        match component {
            Component::RootDir => {}
            Component::Normal(name) => {
                owner = File::from(
                    openat(&owner, name, flags, Mode::empty())
                        .map_err(|_| "serial-private-path-unavailable")?,
                );
            }
            _ => return Err("serial-private-path-unavailable"),
        }
    }
    Ok(owner)
}

/// Rejects writable-by-others, linked, or nonregular evidence after opening the inode.
#[cfg(unix)]
fn private_file(file: &File) -> Result<()> {
    let metadata = file
        .metadata()
        .map_err(|_| "serial-private-file-unavailable")?;
    if !private_identity_is_valid(
        metadata.is_file(),
        metadata.nlink(),
        metadata.mode(),
        metadata.uid(),
        rustix::process::geteuid().as_raw(),
    ) {
        return Err("serial-private-file-permissions-invalid");
    }
    Ok(())
}

/// Requires current ownership, a single regular-file link, and no extra permission bits.
fn private_identity_is_valid(
    regular: bool,
    links: u64,
    mode: u32,
    owner: u32,
    current: u32,
) -> bool {
    regular && links == 1 && mode & 0o7777 == 0o600 && owner == current
}

impl Evidence {
    /// Creates a new private directory and fsyncs parent ownership before storing evidence.
    #[cfg(unix)]
    pub fn create(path: &Path, plan: &Plan, sector: &Sector) -> Result<Self> {
        plan.validate(sector)?;
        let parent = directory(path.parent().ok_or("serial-private-path-unavailable")?)?;
        let name = path.file_name().ok_or("serial-private-path-unavailable")?;
        mkdirat(&parent, name, Mode::from_raw_mode(0o700))
            .map_err(|_| "serial-output-exists-or-unavailable")?;
        let directory = File::from(
            openat(
                &parent,
                name,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|_| "serial-private-path-unavailable")?,
        );
        let evidence = Self { directory };
        evidence.write_new("sector.bin", sector)?;
        evidence.write_new(
            "plan.json",
            &serde_json::to_vec_pretty(plan).map_err(|_| "serial-plan-invalid")?,
        )?;
        evidence
            .directory
            .sync_all()
            .map_err(|_| "serial-backup-sync-failed")?;
        parent.sync_all().map_err(|_| "serial-backup-sync-failed")?;
        Ok(evidence)
    }

    /// Opens a prepared private directory without accepting symlinked parent components.
    #[cfg(unix)]
    pub fn open(path: &Path) -> Result<Self> {
        let directory = directory(path)?;
        let metadata = directory
            .metadata()
            .map_err(|_| "serial-private-path-unavailable")?;
        if metadata.mode() & 0o7777 != 0o700
            || metadata.uid() != rustix::process::geteuid().as_raw()
        {
            return Err("serial-private-directory-permissions-invalid");
        }
        Ok(Self { directory })
    }

    /// Reads fixed named evidence from one pinned directory, with a hard allocation bound.
    #[cfg(unix)]
    fn read(&self, name: &str, maximum: u64) -> Result<Vec<u8>> {
        let file = File::from(
            openat(
                &self.directory,
                name,
                OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|_| "serial-private-file-unavailable")?,
        );
        private_file(&file)?;
        let mut bytes = Vec::new();
        file.take(maximum + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| "serial-private-file-unavailable")?;
        if bytes.len() as u64 > maximum {
            return Err("serial-private-file-oversized");
        }
        Ok(bytes)
    }

    /// Opens an exclusive private file and syncs its data and directory entry before return.
    #[cfg(unix)]
    pub fn write_new(&self, name: &str, bytes: &[u8]) -> Result<()> {
        let mut file = File::from(
            openat(
                &self.directory,
                name,
                OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::from_raw_mode(0o600),
            )
            .map_err(|_| "serial-evidence-exists-or-unavailable")?,
        );
        private_file(&file)?;
        file.write_all(bytes)
            .and_then(|()| file.sync_all())
            .map_err(|_| "serial-backup-sync-failed")?;
        self.directory
            .sync_all()
            .map_err(|_| "serial-backup-sync-failed")
    }

    /// Validates the plan against the entire original sector before opening any hardware.
    #[cfg(unix)]
    pub fn load(&self) -> Result<(Plan, Sector)> {
        let plan: Plan = serde_json::from_slice(&self.read("plan.json", 16_384)?)
            .map_err(|_| "serial-plan-invalid")?;
        let sector = sector_from_bytes(&self.read("sector.bin", 4096)?)?;
        plan.validate(&sector)?;
        Ok((plan, sector))
    }
}

/// Reads exactly one offline sector from an ordinary no-symlink file, with no device access.
#[cfg(unix)]
pub(super) fn read_offline_sector(path: &Path) -> Result<Sector> {
    let parent = directory(path.parent().ok_or("serial-private-path-unavailable")?)?;
    let name = path.file_name().ok_or("serial-private-path-unavailable")?;
    let file = File::from(
        openat(
            &parent,
            name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| "serial-sector-input-unavailable")?,
    );
    if !file
        .metadata()
        .map_err(|_| "serial-sector-input-unavailable")?
        .is_file()
    {
        return Err("serial-sector-input-unavailable");
    }
    let mut bytes = Vec::new();
    file.take(4097)
        .read_to_end(&mut bytes)
        .map_err(|_| "serial-sector-input-unavailable")?;
    sector_from_bytes(&bytes)
}

#[cfg(test)]
mod tests {
    use super::private_identity_is_valid;

    /// Foreign owners, special permissions, hard links, and nonfiles are never private evidence.
    #[test]
    fn evidence_owner_and_mode_policy_rejects_foreign_inodes() {
        assert!(private_identity_is_valid(true, 1, 0o100600, 501, 501));
        for (regular, links, mode, owner) in [
            (true, 1, 0o600, 502),
            (true, 2, 0o600, 501),
            (true, 1, 0o640, 501),
            (true, 1, 0o4600, 501),
            (false, 1, 0o600, 501),
        ] {
            assert!(!private_identity_is_valid(regular, links, mode, owner, 501));
        }
    }
}
