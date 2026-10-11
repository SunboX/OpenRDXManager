// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Fixed local manufacturing store with retained ancestry and exact private ACLs.

use crate::NativeError;
use std::fs::File;
use std::io::{Read, Write};
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::FromRawHandle;
use std::path::{Component, Path, PathBuf};
use windows::Win32::Foundation::{CloseHandle, GENERIC_READ, GENERIC_WRITE, HANDLE};
use windows::Win32::Storage::FileSystem::*;
use windows::Win32::System::Com::CoTaskMemFree;
use windows::Win32::UI::Shell::{FOLDERID_ProgramData, KF_FLAG_DEFAULT, SHGetKnownFolderPath};
use windows::core::PCWSTR;

mod acl;
use acl::Policy;

const MAX_RECORDS: usize = 4096;
const MAX_MANIFEST: usize = 65536;

/// One closed file vocabulary; never accepts an arbitrary filename or stream.
#[derive(Clone, Copy)]
pub enum BackupFile {
    /// Exact 256-byte factory record.
    Record,
    /// Optional complete 4096-byte erase-sector evidence.
    Sector,
    /// Bounded immutable JSON manifest published after data files.
    Manifest,
}

impl BackupFile {
    /// Returns a fixed leaf and read/write bound.
    fn fields(self) -> (&'static str, usize) {
        match self {
            Self::Record => ("manufacturing.bin", 256),
            Self::Sector => ("sector.bin", 4096),
            Self::Manifest => ("manifest.json", MAX_MANIFEST),
        }
    }
}

/// Owns a non-inheritable kernel handle exactly once.
struct OwnedHandle(HANDLE);

impl Drop for OwnedHandle {
    /// Closes the retained handle after all descendants or I/O have completed.
    fn drop(&mut self) {
        // SAFETY: successful construction transferred this unique handle.
        let _ = unsafe { CloseHandle(self.0) };
    }
}

/// Opaque directory lease; all ancestors deny write/delete sharing.
pub struct ManufacturingStore {
    path: PathBuf,
    _ancestors: Vec<OwnedHandle>,
    policy: Policy,
}

impl ManufacturingStore {
    /// Opens only an explicitly supplied disposable fixture store with a current-user ACL.
    /// This test-only entry point is absent from normal hardware-service builds.
    ///
    /// # Errors
    /// Retains production path, type, ancestry, size and permission validation.
    #[cfg(any(test, feature = "test-hooks"))]
    pub fn open_for_test(path: &Path) -> Result<Self, NativeError> {
        Self::open_at(path, Policy::current_user()?)
    }
    /// Opens or creates the fixed ProgramData store using the privileged ACL.
    ///
    /// # Errors
    /// Rejects remote/removable volumes, reparse ancestry, unsafe existing ACLs,
    /// missing privileges, or any inconsistent handle/path evidence. Never repairs
    /// existing objects or accepts a caller-controlled root.
    pub fn open() -> Result<Self, NativeError> {
        // SAFETY: fixed system-known folder, no caller token or pathname input.
        let allocated =
            unsafe { SHGetKnownFolderPath(&FOLDERID_ProgramData, KF_FLAG_DEFAULT, None) }
                .map_err(|_| NativeError::EvidenceIncomplete)?;
        // SAFETY: successful API result is terminated UTF-16 and task allocated.
        let path = unsafe { allocated.to_string() };
        // SAFETY: SHGetKnownFolderPath transfers this CoTaskMem allocation.
        unsafe { CoTaskMemFree(Some(allocated.0.cast())) };
        let path = PathBuf::from(path.map_err(|_| NativeError::EvidenceIncomplete)?)
            .join("OpenRDXManager")
            .join("manufacturing-backups");
        Self::open_at(&path, Policy::production()?)
    }

    /// Pins every local component before resolving the next; only the last two
    /// service components may be created, always with the exact private policy.
    fn open_at(path: &Path, policy: Policy) -> Result<Self, NativeError> {
        let parts: Vec<_> = path.components().collect();
        if parts.len() < 4 || parts.len() > 128 {
            return Err(NativeError::InvalidRequest);
        }
        let Some(Component::Prefix(prefix)) = parts.first() else {
            return Err(NativeError::InvalidRequest);
        };
        if !matches!(prefix.kind(), std::path::Prefix::Disk(_)) || parts[1] != Component::RootDir {
            return Err(NativeError::InvalidRequest);
        }
        let mut current = PathBuf::from(prefix.as_os_str());
        current.push(r"\");
        let drive_name = wide(&current);
        // SAFETY: terminated drive-root path is borrowed for this query only.
        if unsafe { GetDriveTypeW(PCWSTR(drive_name.as_ptr())) } != 3 {
            return Err(NativeError::EvidenceIncomplete);
        }
        let volume = open_directory(&current)?;
        let mut flags = 0u32;
        // SAFETY: volume is a retained root handle and flags is writable output.
        unsafe {
            GetVolumeInformationByHandleW(volume.0, None, None, None, Some(&mut flags), None)
        }
        .map_err(|_| NativeError::EvidenceIncomplete)?;
        // FILE_PERSISTENT_ACLS is the documented volume-capability bit 0x8.
        if flags & 0x8 == 0 {
            return Err(NativeError::EvidenceIncomplete);
        }
        current = final_path(volume.0)?;
        if !current
            .as_os_str()
            .to_string_lossy()
            .starts_with(r"\\?\Volume{")
        {
            return Err(NativeError::EvidenceIncomplete);
        }
        let mut ancestors = vec![volume];
        for (index, part) in parts.iter().enumerate().skip(2) {
            let Component::Normal(name) = part else {
                return Err(NativeError::InvalidRequest);
            };
            validate_component(name)?;
            current.push(name);
            let directory = match open_directory(&current) {
                Ok(directory) => directory,
                Err(NativeError::NoMedia) if index + 2 >= parts.len() => {
                    let name = wide(&current);
                    let attributes = policy.attributes();
                    // SAFETY: checked parent is pinned; explicit private creation ACL.
                    unsafe { CreateDirectoryW(PCWSTR(name.as_ptr()), Some(&attributes)) }
                        .map_err(|_| NativeError::AccessDenied)?;
                    open_directory(&current)?
                }
                Err(error) => return Err(error),
            };
            if index + 1 == parts.len() {
                policy.verify(directory.0)?;
            }
            ancestors.push(directory);
        }
        Ok(Self {
            path: current,
            _ancestors: ancestors,
            policy,
        })
    }

    /// Lists at most 4096 canonical immutable IDs while retaining root authority.
    ///
    /// # Errors
    /// Rejects overfull/unreadable storage instead of deleting historical evidence.
    pub fn names(&self) -> Result<Vec<String>, NativeError> {
        let mut names = Vec::new();
        let mut count = 0;
        for entry in std::fs::read_dir(&self.path).map_err(io_error)? {
            let entry = entry.map_err(io_error)?;
            count += 1;
            if count > MAX_RECORDS {
                return Err(NativeError::ResourceLimit);
            }
            let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
                continue;
            };
            if valid_id(&name) {
                names.push(name);
            }
        }
        Ok(names)
    }

    /// Creates one immutable bundle exclusively, flushes each file, and reopens
    /// every byte for comparison. The manifest is created last; partial bundles
    /// remain recoverable evidence and are never accepted as complete backups.
    ///
    /// # Errors
    /// Fails on ID collision, invalid bounds, non-private storage, or failed I/O.
    pub fn persist(
        &self,
        id: &str,
        record: &[u8; 256],
        sector: Option<&[u8; 4096]>,
        manifest: &[u8],
    ) -> Result<(), NativeError> {
        if !valid_id(id)
            || manifest.is_empty()
            || manifest.len() > MAX_MANIFEST
            || sector.is_some_and(|sector| sector[..256] != record[..])
        {
            return Err(NativeError::InvalidRequest);
        }
        if std::fs::read_dir(&self.path)
            .map_err(io_error)?
            .take(MAX_RECORDS)
            .count()
            >= MAX_RECORDS
        {
            return Err(NativeError::ResourceLimit);
        }
        let path = self.path.join(id);
        let name = wide(&path);
        let attributes = self.policy.attributes();
        // SAFETY: all ancestors remain pinned and only canonical generated IDs pass.
        unsafe { CreateDirectoryW(PCWSTR(name.as_ptr()), Some(&attributes)) }
            .map_err(|_| NativeError::AccessDenied)?;
        let directory = self.record_directory(id)?;
        self.write(&path, BackupFile::Record, record)?;
        if let Some(sector) = sector {
            self.write(&path, BackupFile::Sector, sector)?;
        }
        self.write(&path, BackupFile::Manifest, manifest)?;
        drop(directory);
        if self.read(id, BackupFile::Record)? != record
            || self.read(id, BackupFile::Manifest)? != manifest
        {
            return Err(NativeError::EvidenceIncomplete);
        }
        if let Some(sector) = sector
            && self.read(id, BackupFile::Sector)? != sector
        {
            return Err(NativeError::EvidenceIncomplete);
        }
        Ok(())
    }

    /// Reads a bounded fixed file with no write/delete sharing and verified ACL.
    ///
    /// # Errors
    /// Rejects reparse points, extra hardlinks, partial files and foreign ACLs.
    pub fn read(&self, id: &str, kind: BackupFile) -> Result<Vec<u8>, NativeError> {
        let _directory = self.record_directory(id)?;
        let (leaf, maximum) = kind.fields();
        let path = self.path.join(id).join(leaf);
        let handle = self.file(&path, false)?;
        let file = into_file(handle);
        let length = file.metadata().map_err(io_error)?.len();
        if length == 0
            || length > maximum as u64
            || (!matches!(kind, BackupFile::Manifest) && length != maximum as u64)
        {
            return Err(NativeError::EvidenceIncomplete);
        }
        let mut bytes = Vec::new();
        file.take(maximum as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(io_error)?;
        if bytes.len() as u64 != length {
            return Err(NativeError::EvidenceIncomplete);
        }
        Ok(bytes)
    }

    /// Retains and verifies one generated record directory, never a caller path.
    fn record_directory(&self, id: &str) -> Result<OwnedHandle, NativeError> {
        if !valid_id(id) {
            return Err(NativeError::InvalidRequest);
        }
        let directory = open_directory(&self.path.join(id))?;
        self.policy.verify(directory.0)?;
        Ok(directory)
    }

    /// Publishes a single new fixed leaf with write-through plus checked flush.
    fn write(&self, directory: &Path, kind: BackupFile, bytes: &[u8]) -> Result<(), NativeError> {
        let handle = self.file(&directory.join(kind.fields().0), true)?;
        let mut file = into_file(handle);
        file.write_all(bytes).map_err(io_error)?;
        file.sync_all().map_err(io_error)
    }

    /// Opens a non-shareable writer or shared-read-only immutable reader.
    fn file(&self, path: &Path, create: bool) -> Result<OwnedHandle, NativeError> {
        let path_wide = wide(path);
        let attributes = self.policy.attributes();
        // SAFETY: terminated path under pinned ancestors; explicit bounds and policy.
        let handle = unsafe {
            CreateFileW(
                PCWSTR(path_wide.as_ptr()),
                GENERIC_READ.0 | if create { GENERIC_WRITE.0 } else { 0 } | READ_CONTROL.0,
                if create {
                    FILE_SHARE_MODE(0)
                } else {
                    FILE_SHARE_READ
                },
                Some(&attributes),
                if create { CREATE_NEW } else { OPEN_EXISTING },
                FILE_FLAG_OPEN_REPARSE_POINT
                    | if create {
                        FILE_FLAG_WRITE_THROUGH
                    } else {
                        FILE_FLAGS_AND_ATTRIBUTES(0)
                    },
                None,
            )
        }
        .map_err(|_| NativeError::AccessDenied)?;
        let handle = OwnedHandle(handle);
        validate_type(handle.0, false)?;
        verify_path(handle.0, path)?;
        self.policy.verify(handle.0)?;
        Ok(handle)
    }
}

/// Accepts only canonical lowercase hex generated record IDs, with bounded size.
fn valid_id(id: &str) -> bool {
    let Some((time, sequence)) = id
        .strip_prefix("record-")
        .and_then(|tail| tail.split_once('-'))
    else {
        return false;
    };
    if id.len() > 64 {
        return false;
    }
    let (Ok(time_value), Ok(sequence_value)) = (
        u128::from_str_radix(time, 16),
        u64::from_str_radix(sequence, 16),
    ) else {
        return false;
    };
    id == format!("record-{time_value:x}-{sequence_value:x}")
}

/// Rejects Windows-normalized components, streams, device names and traversal.
fn validate_component(value: &std::ffi::OsStr) -> Result<(), NativeError> {
    let text = value.to_str().ok_or(NativeError::InvalidRequest)?;
    let stem = text.split('.').next().unwrap_or("").to_ascii_uppercase();
    if text.is_empty()
        || text.len() > 255
        || text.ends_with(['.', ' '])
        || text.chars().any(|c| c < ' ' || "<>:\"/\\|?*".contains(c))
        || matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || stem.starts_with("COM")
        || stem.starts_with("LPT")
    {
        return Err(NativeError::InvalidRequest);
    }
    Ok(())
}

/// Opens a directory without following links or allowing replacement/conversion.
fn open_directory(path: &Path) -> Result<OwnedHandle, NativeError> {
    let name = wide(path);
    // SAFETY: terminated pathname; no write access or inherited handle requested.
    let handle = unsafe {
        CreateFileW(
            PCWSTR(name.as_ptr()),
            GENERIC_READ.0 | READ_CONTROL.0 | FILE_READ_ATTRIBUTES.0,
            FILE_SHARE_READ,
            None,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            None,
        )
    }
    .map_err(|error| {
        if matches!(error.code().0 as u32, 0x80070002 | 0x80070003) {
            NativeError::NoMedia
        } else {
            NativeError::AccessDenied
        }
    })?;
    let handle = OwnedHandle(handle);
    validate_type(handle.0, true)?;
    if path
        .as_os_str()
        .to_string_lossy()
        .starts_with(r"\\?\Volume{")
    {
        verify_path(handle.0, path)?;
    }
    Ok(handle)
}

/// Proves disk object type, no reparse attribute, and exactly one file hardlink.
fn validate_type(handle: HANDLE, directory: bool) -> Result<(), NativeError> {
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: retained handle plus exact writable metadata structure.
    unsafe { GetFileInformationByHandle(handle, &mut info) }
        .map_err(|_| NativeError::EvidenceIncomplete)?;
    // SAFETY: query-only call on the same retained handle.
    if unsafe { GetFileType(handle) } != FILE_TYPE_DISK
        || info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0
        || (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY.0 != 0) != directory
        || (!directory && info.nNumberOfLinks != 1)
    {
        return Err(NativeError::EvidenceIncomplete);
    }
    Ok(())
}

/// Resolves the actual retained handle using a local volume GUID, not a drive alias.
fn final_path(handle: HANDLE) -> Result<PathBuf, NativeError> {
    let mut buffer = vec![0u16; 32768];
    // SAFETY: fixed bounded writable output and a retained handle.
    let length =
        unsafe { GetFinalPathNameByHandleW(handle, &mut buffer, VOLUME_NAME_GUID) } as usize;
    if length == 0 || length >= buffer.len() {
        return Err(NativeError::EvidenceIncomplete);
    }
    let text =
        String::from_utf16(&buffer[..length]).map_err(|_| NativeError::EvidenceIncomplete)?;
    Ok(PathBuf::from(text))
}

/// Rejects a resolved target different from the path under pinned ancestry.
fn verify_path(handle: HANDLE, expected: &Path) -> Result<(), NativeError> {
    if !final_path(handle)?
        .as_os_str()
        .to_string_lossy()
        .eq_ignore_ascii_case(&expected.as_os_str().to_string_lossy())
    {
        return Err(NativeError::EvidenceIncomplete);
    }
    Ok(())
}

/// Transfers ownership once into Rust's file for bounded synchronous I/O.
fn into_file(handle: OwnedHandle) -> File {
    let handle = std::mem::ManuallyDrop::new(handle);
    // SAFETY: unique live file handle; ManuallyDrop prevents a second close.
    unsafe { File::from_raw_handle(handle.0.0) }
}

/// Converts a trusted local path into terminated UTF-16.
fn wide(path: &Path) -> Vec<u16> {
    path.as_os_str().encode_wide().chain([0]).collect()
}

/// Sanitizes storage errors without publishing paths or factory data.
fn io_error(_: std::io::Error) -> NativeError {
    NativeError::EvidenceIncomplete
}

#[cfg(test)]
mod tests;
